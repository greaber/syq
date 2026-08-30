//! Root-anchored filesystem primitives for guarded receivers.
//!
//! `Root` follows the explicitly selected root path once, opens that directory,
//! and uses only the resulting descriptor afterward. Descendant paths are raw
//! Unix bytes split into validated relative components. Every intermediate
//! component is opened relative to the preceding descriptor with
//! `O_DIRECTORY | O_NOFOLLOW`; leaf operations are performed relative to a
//! held parent descriptor. There is no pathname fallback.
//!
//! Native guarded placements use these operations for every descendant
//! mutation; the unrestricted rsync-shaped implementation remains separate.
//! Existing roots, regular-file I/O, leaf creation/replacement, metadata, and
//! non-recursive unlink/rmdir are supported. Recursive removal stays outside
//! this layer. Directory authority descriptors need search permission, not
//! read permission.
//!
//! Linux currently uses the same component walk as other Unix platforms. An
//! `openat2` fast path should be added only with tests proving that it has
//! exactly the same root-symlink, descendant-symlink, and mount semantics.
//!
//! The guarantee is pathname confinement. A hard link beneath the root may
//! still refer to an inode with another name outside the root. As with all
//! descriptor-based traversal, an already-open descendant remains the selected
//! object if another process subsequently renames it.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
const DIRECTORY_SEARCH_FLAGS: libc::c_int = libc::O_PATH | libc::O_DIRECTORY;
#[cfg(target_os = "macos")]
const DIRECTORY_SEARCH_FLAGS: libc::c_int = libc::O_SEARCH;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const DIRECTORY_SEARCH_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY;

#[cfg(target_os = "linux")]
const MODE_TYPE_MASK: u32 = libc::S_IFMT;
#[cfg(not(target_os = "linux"))]
const MODE_TYPE_MASK: u32 = libc::S_IFMT as u32;
#[cfg(target_os = "linux")]
const MODE_DIRECTORY: u32 = libc::S_IFDIR;
#[cfg(not(target_os = "linux"))]
const MODE_DIRECTORY: u32 = libc::S_IFDIR as u32;
#[cfg(target_os = "linux")]
const MODE_REGULAR: u32 = libc::S_IFREG;
#[cfg(not(target_os = "linux"))]
const MODE_REGULAR: u32 = libc::S_IFREG as u32;
#[cfg(target_os = "linux")]
const MODE_SYMLINK: u32 = libc::S_IFLNK;
#[cfg(not(target_os = "linux"))]
const MODE_SYMLINK: u32 = libc::S_IFLNK as u32;
#[cfg(target_os = "linux")]
const MODE_FIFO: u32 = libc::S_IFIFO;
#[cfg(not(target_os = "linux"))]
const MODE_FIFO: u32 = libc::S_IFIFO as u32;

/// Stable identity of an opened root. Independent helper processes can reopen
/// the configured path and require this identity before serving requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RootMetadata {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) nlink: u64,
    pub(crate) len: u64,
}

impl RootMetadata {
    pub(crate) fn is_dir(self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_DIRECTORY
    }

    pub(crate) fn is_file(self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_REGULAR
    }

    pub(crate) fn is_symlink(self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_SYMLINK
    }

    pub(crate) fn file_type(self) -> u32 {
        self.mode & MODE_TYPE_MASK
    }
}

/// A syntactically safe descendant path. Empty means the opened root itself;
/// operations that need a leaf reject it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelativePath {
    components: Vec<Vec<u8>>,
}

impl RelativePath {
    pub(crate) fn new(path: &[u8]) -> Result<Self> {
        if path.starts_with(b"/") {
            bail!("confined path must be relative");
        }
        if path.contains(&0) {
            bail!("confined path contains NUL");
        }
        if path.is_empty() {
            return Ok(Self {
                components: Vec::new(),
            });
        }

        let mut components = Vec::new();
        for component in path.split(|byte| *byte == b'/') {
            if component.is_empty() {
                bail!("confined path contains an empty component");
            }
            if component == b"." || component == b".." {
                bail!("confined path contains forbidden component");
            }
            components.push(component.to_vec());
        }
        Ok(Self { components })
    }

    fn leaf(&self) -> Result<(&[Vec<u8>], &[u8])> {
        let (leaf, parents) = self
            .components
            .split_last()
            .context("operation requires a descendant path")?;
        Ok((parents, leaf))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    fn label(&self) -> String {
        if self.components.is_empty() {
            return ".".into();
        }
        self.components
            .iter()
            .map(|component| String::from_utf8_lossy(component))
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// An existing directory opened once as the authority boundary.
pub(crate) struct Root {
    directory: File,
    identity: RootIdentity,
}

impl Root {
    /// Open an explicit root. Symlinks in this user-selected path are followed;
    /// symlinks in every later descendant path are rejected.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let name = CString::new(path.as_os_str().as_bytes()).context("root path contains NUL")?;
        let directory = open_at(
            libc::AT_FDCWD,
            &name,
            DIRECTORY_SEARCH_FLAGS | libc::O_CLOEXEC,
            0,
        )
        .with_context(|| format!("open confined root {}", path.display()))?;
        let metadata = directory
            .metadata()
            .with_context(|| format!("stat confined root {}", path.display()))?;
        if !metadata.is_dir() {
            bail!("confined root {} is not a directory", path.display());
        }
        Ok(Self {
            directory,
            identity: RootIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
        })
    }

    /// Reopen a root for another process and reject path replacement.
    pub(crate) fn open_verified(path: &Path, expected: RootIdentity) -> Result<Self> {
        let root = Self::open(path)?;
        if root.identity != expected {
            bail!(
                "confined root {} changed identity (expected {}:{}, found {}:{})",
                path.display(),
                expected.dev,
                expected.ino,
                root.identity.dev,
                root.identity.ino
            );
        }
        Ok(root)
    }

    pub(crate) fn identity(&self) -> RootIdentity {
        self.identity
    }

    /// Open the root or a descendant directory without following any
    /// descendant symlink.
    pub(crate) fn open_directory(&self, path: &RelativePath) -> Result<File> {
        let mut directory = self.directory.try_clone().context("duplicate root fd")?;
        for component in &path.components {
            directory = open_directory_at(&directory, component)
                .with_context(|| format!("open confined directory {}", path.label()))?;
        }
        Ok(directory)
    }

    pub(crate) fn open_regular_read(&self, path: &RelativePath) -> Result<File> {
        self.open_regular(path, libc::O_RDONLY, false)
    }

    /// Open an existing regular file for mutation. Truncation occurs only after
    /// the opened descriptor has been verified as a regular file.
    pub(crate) fn open_regular_write(&self, path: &RelativePath, truncate: bool) -> Result<File> {
        self.open_regular(path, libc::O_WRONLY, truncate)
    }

    pub(crate) fn open_regular_read_write(&self, path: &RelativePath) -> Result<File> {
        self.open_regular(path, libc::O_RDWR, false)
    }

    pub(crate) fn open_metadata(&self, path: &RelativePath) -> Result<File> {
        let parent = self.resolve_parent(path)?;
        #[cfg(target_os = "linux")]
        let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        #[cfg(target_os = "macos")]
        let flags = libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        open_at(parent.directory.as_raw_fd(), &parent.leaf, flags, 0)
            .with_context(|| format!("open confined metadata handle {}", path.label()))
    }

    fn open_regular(
        &self,
        path: &RelativePath,
        access: libc::c_int,
        truncate: bool,
    ) -> Result<File> {
        let parent = self.resolve_parent(path)?;
        let file = open_at(
            parent.directory.as_raw_fd(),
            &parent.leaf,
            access | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )
        .with_context(|| format!("open confined regular file {}", path.label()))?;
        require_regular(&file, path)?;
        if truncate {
            file.set_len(0)
                .with_context(|| format!("truncate confined file {}", path.label()))?;
        }
        Ok(file)
    }

    /// Create a new regular leaf. Existing leaves of every type are refused.
    pub(crate) fn create_file(&self, path: &RelativePath, mode: u32) -> Result<File> {
        let parent = self.resolve_parent(path)?;
        let file = open_at(
            parent.directory.as_raw_fd(),
            &parent.leaf,
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            mode & 0o7777,
        )
        .with_context(|| format!("create confined file {}", path.label()))?;
        require_regular(&file, path)?;
        Ok(file)
    }

    /// Create exactly one directory. Parents must already exist and be real
    /// directories beneath this root.
    pub(crate) fn create_directory(&self, path: &RelativePath, mode: u32) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let result = unsafe {
            libc::mkdirat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
            )
        };
        cvt_zero(result).with_context(|| format!("create confined directory {}", path.label()))
    }

    /// Create a directory whose explicit path may have missing parents.
    /// Existing components are opened, and missing components are created,
    /// relative to the preceding held directory descriptor. The identity of
    /// the final directory therefore cannot be rebound through a later lookup
    /// of any public ancestor pathname.
    pub(crate) fn create_path_directory_noreplace(path: &Path, mode: u32) -> Result<RootIdentity> {
        let components: Vec<_> = path.components().collect();
        let prefix_len = components
            .iter()
            .rposition(|component| matches!(component, Component::ParentDir))
            .map_or(0, |index| index + 1);
        let (prefix, suffix) = components.split_at(prefix_len);
        let mut current = if prefix.is_empty() {
            if path.is_absolute() {
                Self::open(Path::new("/"))?
            } else {
                Self::open(Path::new("."))?
            }
        } else {
            let mut explicit = PathBuf::new();
            for component in prefix {
                explicit.push(component.as_os_str());
            }
            // Resolve every parent component in the one explicit root
            // selection. Once creation begins, walking `..` from a held
            // directory would be unsafe because a rename can change that
            // directory's parent.
            Self::open(&explicit)?
        };
        hold_after_parent_prefix_for_test()?;

        let mut suffix = suffix;
        if matches!(suffix.first(), Some(Component::RootDir)) {
            suffix = &suffix[1..];
        }

        let (leaf, parents) = suffix
            .split_last()
            .context("new container path has no leaf name")?;
        let Component::Normal(leaf) = *leaf else {
            bail!("new container path must end in a normal path component");
        };

        for component in parents {
            current = match component {
                Component::CurDir => continue,
                Component::Normal(name) => match current.open_explicit_directory(name.as_bytes()) {
                    Ok(directory) => directory,
                    Err(error) if is_not_found(&error) => {
                        let directory = current.create_child_directory_noreplace(
                            name.as_bytes(),
                            0o777,
                            "parent-directory",
                        )?;
                        hold_after_created_parent_for_test()?;
                        directory
                    }
                    Err(error) => return Err(error),
                },
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    bail!("unexpected root component in new container path")
                }
            };
        }

        current
            .create_child_directory_noreplace(leaf.as_bytes(), mode, "new-directory")
            .map(|directory| directory.identity)
    }

    fn open_explicit_directory(&self, component: &[u8]) -> Result<Self> {
        let directory = open_at(
            self.directory.as_raw_fd(),
            &component_cstring(component),
            DIRECTORY_SEARCH_FLAGS | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )
        .with_context(|| {
            format!(
                "open explicit directory component {}",
                String::from_utf8_lossy(component)
            )
        })?;
        Self::from_directory(directory).with_context(|| {
            format!(
                "validate explicit directory component {}",
                String::from_utf8_lossy(component)
            )
        })
    }

    fn create_child_directory_noreplace(
        &self,
        component: &[u8],
        mode: u32,
        staging_label: &str,
    ) -> Result<Self> {
        let directory =
            create_published_directory_noreplace(&self.directory, component, mode, staging_label)?;
        Self::from_directory(directory)
    }

    fn from_directory(directory: File) -> Result<Self> {
        let metadata = directory.metadata().context("stat held directory")?;
        if !metadata.is_dir() {
            bail!("held object is not a directory");
        }
        Ok(Self {
            identity: RootIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            directory,
        })
    }

    pub(crate) fn metadata(&self, path: &RelativePath) -> Result<RootMetadata> {
        if path.is_empty() {
            return self
                .directory
                .metadata()
                .map(|metadata| root_metadata(&metadata))
                .context("stat confined root");
        }
        let parent = self.resolve_parent(path)?;
        metadata_at(parent.directory.as_raw_fd(), &parent.leaf)
            .with_context(|| format!("stat confined path {}", path.label()))
    }

    pub(crate) fn metadata_optional(&self, path: &RelativePath) -> Result<Option<RootMetadata>> {
        if path.is_empty() {
            return self.metadata(path).map(Some);
        }
        let parent = self.resolve_parent(path)?;
        match metadata_at(parent.directory.as_raw_fd(), &parent.leaf) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("stat confined path {}", path.label()))
            }
        }
    }

    pub(crate) fn create_symlink(&self, path: &RelativePath, target: &[u8]) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let target = CString::new(target).context("symlink target contains NUL")?;
        let result = unsafe {
            libc::symlinkat(
                target.as_ptr(),
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
            )
        };
        cvt_zero(result).with_context(|| format!("create confined symlink {}", path.label()))
    }

    pub(crate) fn create_node(&self, path: &RelativePath, mode: u32, rdev: u64) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let result = unsafe {
            libc::mknodat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                mode as libc::mode_t,
                rdev as libc::dev_t,
            )
        };
        cvt_zero(result).with_context(|| format!("create confined node {}", path.label()))
    }

    pub(crate) fn chmod(&self, path: &RelativePath, mode: u32) -> Result<()> {
        let parent = self.resolve_metadata_target(path)?;
        let result = unsafe {
            libc::fchmodat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
                0,
            )
        };
        cvt_zero(result).with_context(|| format!("chmod confined path {}", path.label()))
    }

    pub(crate) fn chown(
        &self,
        path: &RelativePath,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> io::Result<()> {
        let parent = self
            .resolve_metadata_target(path)
            .map_err(|error| io::Error::other(format!("{error:#}")))?;
        let result = unsafe {
            libc::fchownat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        cvt_zero(result)
    }

    pub(crate) fn set_times(&self, path: &RelativePath, times: &[libc::timespec; 2]) -> Result<()> {
        let parent = self.resolve_metadata_target(path)?;
        let result = unsafe {
            libc::utimensat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        cvt_zero(result).with_context(|| format!("set times on confined path {}", path.label()))
    }

    pub(crate) fn replace_symlink_if_same(
        &self,
        path: &RelativePath,
        target: &[u8],
        expected_dev: u64,
        expected_ino: u64,
    ) -> Result<()> {
        let target = CString::new(target).context("symlink target contains NUL")?;
        self.replace_leaf_if_same(
            path,
            expected_dev,
            expected_ino,
            MODE_SYMLINK,
            |fd, name| {
                let result = unsafe { libc::symlinkat(target.as_ptr(), fd, name.as_ptr()) };
                cvt_zero(result)
            },
        )
    }

    pub(crate) fn replace_node_if_same(
        &self,
        path: &RelativePath,
        mode: u32,
        rdev: u64,
        expected_dev: u64,
        expected_ino: u64,
    ) -> Result<()> {
        self.replace_leaf_if_same(
            path,
            expected_dev,
            expected_ino,
            mode & MODE_TYPE_MASK,
            |fd, name| {
                let result = unsafe {
                    libc::mknodat(fd, name.as_ptr(), mode as libc::mode_t, rdev as libc::dev_t)
                };
                cvt_zero(result)
            },
        )
    }

    fn replace_leaf_if_same(
        &self,
        path: &RelativePath,
        expected_dev: u64,
        expected_ino: u64,
        expected_type: u32,
        create: impl Fn(RawFd, &CString) -> io::Result<()>,
    ) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let before = metadata_at(parent.directory.as_raw_fd(), &parent.leaf)?;
        if before.dev != expected_dev
            || before.ino != expected_ino
            || before.file_type() != expected_type
        {
            bail!(
                "confined target {} changed before replacement",
                path.label()
            );
        }
        hold_after_swap_precondition_for_test()?;
        let (staging_name, staging_directory, _staging_identity) =
            create_temporary_directory(parent.directory.as_raw_fd(), 0o700, "swap-directory")?;
        let replacement = random_staging_name("replacement")?;
        create(staging_directory.as_raw_fd(), &replacement)
            .context("create replacement in private staging directory")?;
        let created = metadata_at(staging_directory.as_raw_fd(), &replacement)
            .context("stat replacement in private staging directory")?;
        hold_after_swap_sidecar_creation_for_test()?;
        let named_before_exchange = metadata_at(staging_directory.as_raw_fd(), &replacement)
            .context("restat replacement before publication")?;
        if named_before_exchange.dev != created.dev
            || named_before_exchange.ino != created.ino
            || named_before_exchange.file_type() != created.file_type()
        {
            bail!(
                "replacement for confined target {} changed before publication; recovery directory {} retained",
                path.label(),
                String::from_utf8_lossy(staging_name.as_bytes())
            );
        }
        if let Err(error) = rename_exchange(
            staging_directory.as_raw_fd(),
            &replacement,
            parent.directory.as_raw_fd(),
            &parent.leaf,
        ) {
            return Err(error).with_context(|| {
                format!(
                    "atomically replace confined path {} (recovery directory {} retained)",
                    path.label(),
                    String::from_utf8_lossy(staging_name.as_bytes())
                )
            });
        }
        let published = metadata_at(parent.directory.as_raw_fd(), &parent.leaf)?;
        let displaced = metadata_at(staging_directory.as_raw_fd(), &replacement)?;
        if published.dev != created.dev
            || published.ino != created.ino
            || published.file_type() != created.file_type()
            || displaced.dev != expected_dev
            || displaced.ino != expected_ino
            || displaced.file_type() != expected_type
        {
            hold_after_swap_mismatch_for_test()?;
            bail!(
                "confined target {} changed during replacement; recovery directory {} retained",
                path.label(),
                String::from_utf8_lossy(staging_name.as_bytes())
            );
        }
        hold_before_swap_cleanup_for_test()?;
        let displaced_before_unlink = metadata_at(staging_directory.as_raw_fd(), &replacement)?;
        if displaced_before_unlink.dev != expected_dev
            || displaced_before_unlink.ino != expected_ino
            || displaced_before_unlink.file_type() != expected_type
        {
            bail!(
                "displaced confined target {} changed before cleanup; recovery directory {} retained",
                path.label(),
                String::from_utf8_lossy(staging_name.as_bytes())
            );
        }
        unlink_at(staging_directory.as_raw_fd(), &replacement, 0)
            .with_context(|| format!("remove displaced confined path {}", path.label()))?;
        hold_after_swap_cleanup_for_test()?;
        // POSIX has no descriptor-relative operation that removes the directory
        // referred to by `staging_directory`. Checking `staging_name` and then
        // calling unlinkat(AT_REMOVEDIR) would let another writer rebind the
        // name between those operations and make us delete an unrelated empty
        // directory. Retain syq's now-empty random 0700 directory instead.
        Ok(())
    }

    /// Rename one leaf to another. Both parents are resolved and retained
    /// beneath this root before the atomic rename. Existing destinations follow
    /// ordinary `rename(2)` replacement rules.
    pub(crate) fn rename(&self, source: &RelativePath, target: &RelativePath) -> Result<()> {
        let source_parent = self.resolve_parent(source)?;
        let target_parent = self.resolve_parent(target)?;
        let result = unsafe {
            libc::renameat(
                source_parent.directory.as_raw_fd(),
                source_parent.leaf.as_ptr(),
                target_parent.directory.as_raw_fd(),
                target_parent.leaf.as_ptr(),
            )
        };
        cvt_zero(result).with_context(|| {
            format!(
                "rename confined path {} to {}",
                source.label(),
                target.label()
            )
        })
    }

    /// Remove a non-directory leaf. Symlinks are removed themselves, never
    /// followed. Directories are refused by the kernel.
    pub(crate) fn unlink(&self, path: &RelativePath) -> Result<()> {
        self.unlink_with_flags(path, 0, "unlink")
    }

    /// Remove one empty directory. Recursive deletion is intentionally not part
    /// of this foundation.
    pub(crate) fn remove_directory(&self, path: &RelativePath) -> Result<()> {
        self.unlink_with_flags(path, libc::AT_REMOVEDIR, "remove directory")
    }

    fn unlink_with_flags(
        &self,
        path: &RelativePath,
        flags: libc::c_int,
        operation: &str,
    ) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let result =
            unsafe { libc::unlinkat(parent.directory.as_raw_fd(), parent.leaf.as_ptr(), flags) };
        cvt_zero(result).with_context(|| format!("{operation} confined path {}", path.label()))
    }

    fn resolve_parent(&self, path: &RelativePath) -> Result<ResolvedParent> {
        let (parents, leaf) = path.leaf()?;
        let mut directory = self.directory.try_clone().context("duplicate root fd")?;
        for component in parents {
            directory = open_directory_at(&directory, component)
                .with_context(|| format!("resolve confined parent for {}", path.label()))?;
        }
        Ok(ResolvedParent {
            directory,
            leaf: component_cstring(leaf),
        })
    }

    fn resolve_metadata_target(&self, path: &RelativePath) -> Result<ResolvedParent> {
        if path.is_empty() {
            return Ok(ResolvedParent {
                directory: self.directory.try_clone().context("duplicate root fd")?,
                leaf: CString::new(".").expect("dot contains no NUL"),
            });
        }
        self.resolve_parent(path)
    }
}

pub(crate) fn create_published_directory_noreplace(
    parent: &File,
    component: &[u8],
    mode: u32,
    staging_label: &str,
) -> Result<File> {
    if component.is_empty() || component == b"." || component == b".." || component.contains(&0) {
        bail!("invalid explicit directory component");
    }
    let leaf = component_cstring(component);
    let (temporary, directory, identity) =
        create_temporary_directory(parent.as_raw_fd(), mode, staging_label)?;
    if let Err(error) = rename_noreplace(parent.as_raw_fd(), &temporary, parent.as_raw_fd(), &leaf)
    {
        drop(directory);
        return Err(error).with_context(|| {
            format!(
                "publish explicit directory component {} (staging directory {} retained)",
                String::from_utf8_lossy(component),
                String::from_utf8_lossy(temporary.as_bytes())
            )
        });
    }
    let named = metadata_at(parent.as_raw_fd(), &leaf)
        .context("verify published explicit directory component")?;
    if named.dev != identity.dev || named.ino != identity.ino || !named.is_dir() {
        bail!(
            "explicit directory component {} changed during publication",
            String::from_utf8_lossy(component)
        );
    }
    Ok(directory)
}

struct ResolvedParent {
    directory: File,
    leaf: CString,
}

fn component_cstring(component: &[u8]) -> CString {
    CString::new(component).expect("RelativePath already rejected NUL")
}

fn open_directory_at(parent: &File, component: &[u8]) -> io::Result<File> {
    open_at(
        parent.as_raw_fd(),
        &component_cstring(component),
        DIRECTORY_SEARCH_FLAGS | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
}

fn open_at(parent: RawFd, name: &CString, flags: libc::c_int, mode: u32) -> io::Result<File> {
    // `mode_t` is narrower than `int` on some platforms (including macOS),
    // so C's default argument promotions require an `int` in this variadic
    // position. Our callers have already restricted modes to 0o7777.
    let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, mode as libc::c_int) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn cvt_zero(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
    })
}

fn metadata_at(parent: RawFd, name: &CString) -> io::Result<RootMetadata> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result =
        unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) };
    cvt_zero(result)?;
    Ok(RootMetadata {
        dev: stat_dev(&stat),
        ino: stat.st_ino,
        mode: stat_mode(&stat),
        nlink: stat_nlink(&stat),
        len: stat.st_size as u64,
    })
}

fn root_metadata(metadata: &std::fs::Metadata) -> RootMetadata {
    RootMetadata {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        len: metadata.len(),
    }
}

#[cfg(target_os = "linux")]
fn stat_dev(stat: &libc::stat) -> u64 {
    stat.st_dev
}

#[cfg(not(target_os = "linux"))]
fn stat_dev(stat: &libc::stat) -> u64 {
    stat.st_dev as u64
}

#[cfg(target_os = "linux")]
fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode
}

#[cfg(not(target_os = "linux"))]
fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode as u32
}

#[cfg(target_os = "linux")]
fn stat_nlink(stat: &libc::stat) -> u64 {
    stat.st_nlink
}

#[cfg(not(target_os = "linux"))]
fn stat_nlink(stat: &libc::stat) -> u64 {
    stat.st_nlink as u64
}

fn unlink_at(parent: RawFd, name: &CString, flags: libc::c_int) -> io::Result<()> {
    cvt_zero(unsafe { libc::unlinkat(parent, name.as_ptr(), flags) })
}

fn create_temporary_directory(
    parent: RawFd,
    mode: u32,
    label: &str,
) -> Result<(CString, File, RootIdentity)> {
    for _ in 0..32 {
        let name = random_staging_name(label)?;
        let result =
            unsafe { libc::mkdirat(parent, name.as_ptr(), (mode & 0o7777) as libc::mode_t) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(error).with_context(|| format!("create {label} staging inode"));
        }

        // The unpredictable name prevents a target-path racer from selecting
        // this inode. Record it immediately, open it without following, and
        // require both names to agree before publication.
        let created =
            metadata_at(parent, &name).with_context(|| format!("stat {label} staging inode"))?;
        let directory = open_at(
            parent,
            &name,
            DIRECTORY_SEARCH_FLAGS | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
        .with_context(|| format!("open {label} staging inode"))?;
        let opened = root_metadata(&directory.metadata()?);
        let named =
            metadata_at(parent, &name).with_context(|| format!("restat {label} staging inode"))?;
        if !created.is_dir()
            || opened.dev != created.dev
            || opened.ino != created.ino
            || named.dev != created.dev
            || named.ino != created.ino
        {
            bail!("{label} staging inode changed before publication");
        }
        return Ok((
            name,
            directory,
            RootIdentity {
                dev: opened.dev,
                ino: opened.ino,
            },
        ));
    }
    bail!("could not allocate a {label} staging name")
}

fn random_staging_name(label: &str) -> Result<CString> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).with_context(|| format!("generate {label} staging name"))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    CString::new(format!(".syq-{label}-{suffix}")).context("generated staging name contains NUL")
}

#[cfg(target_os = "linux")]
fn rename_noreplace(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent,
            old_name.as_ptr(),
            new_parent,
            new_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    cvt_zero(unsafe {
        libc::renameatx_np(
            old_parent,
            old_name.as_ptr(),
            new_parent,
            new_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(
    _old_parent: RawFd,
    _old_name: &CString,
    _new_parent: RawFd,
    _new_name: &CString,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace rename is unavailable",
    ))
}

#[cfg(target_os = "linux")]
fn rename_exchange(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent,
            old_name.as_ptr(),
            new_parent,
            new_name.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn rename_exchange(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    cvt_zero(unsafe {
        libc::renameatx_np(
            old_parent,
            old_name.as_ptr(),
            new_parent,
            new_name.as_ptr(),
            libc::RENAME_SWAP,
        )
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_exchange(
    _old_parent: RawFd,
    _old_name: &CString,
    _new_parent: RawFd,
    _new_name: &CString,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic exchange rename is unavailable",
    ))
}

#[cfg(debug_assertions)]
fn hold_after_swap_precondition_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_SWAP_PRECONDITION_READY_FILE") {
        std::fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_SWAP_PRECONDITION_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_swap_precondition_for_test() -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_after_swap_sidecar_creation_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_SWAP_SIDECAR_READY_FILE") {
        std::fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_SWAP_SIDECAR_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_swap_sidecar_creation_for_test() -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_after_swap_mismatch_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_SWAP_MISMATCH_READY_FILE") {
        std::fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_SWAP_MISMATCH_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_swap_mismatch_for_test() -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_before_swap_cleanup_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_SWAP_CLEANUP_READY_FILE") {
        std::fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_SWAP_CLEANUP_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_before_swap_cleanup_for_test() -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_after_swap_cleanup_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_SWAP_STAGING_RETAINED_READY_FILE") {
        std::fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_SWAP_STAGING_RETAINED_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_swap_cleanup_for_test() -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_after_created_parent_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_CREATED_PARENT_READY_FILE") {
        std::fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_CREATED_PARENT_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_created_parent_for_test() -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_after_parent_prefix_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_PARENT_PREFIX_READY_FILE") {
        std::fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_PARENT_PREFIX_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_parent_prefix_for_test() -> Result<()> {
    Ok(())
}

fn require_regular(file: &File, path: &RelativePath) -> Result<()> {
    if !file.metadata()?.is_file() {
        bail!("confined path {} is not a regular file", path.label());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let n = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("syq-rooted-{name}-{}-{n}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn relative(path: &[u8]) -> RelativePath {
        RelativePath::new(path).unwrap()
    }

    #[test]
    fn validates_raw_relative_components() {
        assert_eq!(relative(b"").components, Vec::<Vec<u8>>::new());
        assert_eq!(
            relative(b"safe/name").components,
            vec![b"safe".to_vec(), b"name".to_vec()]
        );
        assert_eq!(relative(b"non-utf8-\xff").components[0], b"non-utf8-\xff");

        for unsafe_path in [
            &b"/absolute"[..],
            &b"."[..],
            &b".."[..],
            &b"a/../b"[..],
            &b"a/./b"[..],
            &b"a//b"[..],
            &b"a/"[..],
            &b"nul\0name"[..],
        ] {
            assert!(
                RelativePath::new(unsafe_path).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(unsafe_path)
            );
        }
    }

    #[test]
    fn follows_only_the_explicit_root_symlink() {
        let tree = TestDir::new("root-symlink");
        let real = tree.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("inside"), b"data").unwrap();
        symlink(&real, tree.path().join("selected")).unwrap();

        let root = Root::open(&tree.path().join("selected")).unwrap();
        let mut file = root.open_regular_read(&relative(b"inside")).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"data");

        let outside = tree.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        symlink(&outside, real.join("escape")).unwrap();
        assert!(root
            .open_regular_read(&relative(b"escape/sentinel"))
            .is_err());
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
    }

    #[test]
    fn root_identity_detects_path_replacement_but_open_root_stays_stable() {
        let tree = TestDir::new("identity");
        let selected = tree.path().join("selected");
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("old"), b"old").unwrap();
        let root = Root::open(&selected).unwrap();
        let identity = root.identity();

        fs::rename(&selected, tree.path().join("moved")).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("new"), b"new").unwrap();

        assert!(Root::open_verified(&selected, identity).is_err());
        let mut old = root.open_regular_read(&relative(b"old")).unwrap();
        let mut bytes = Vec::new();
        old.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"old");
        assert!(root.open_regular_read(&relative(b"new")).is_err());
    }

    #[test]
    fn search_only_directory_can_be_an_authority_root() {
        let tree = TestDir::new("search-only");
        let root_path = tree.path().join("root");
        fs::create_dir(&root_path).unwrap();
        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o300)).unwrap();

        let root = Root::open(&root_path).unwrap();
        let mut file = root.create_file(&relative(b"created"), 0o600).unwrap();
        file.write_all(b"inside").unwrap();
        drop(file);
        drop(root);

        fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read(root_path.join("created")).unwrap(), b"inside");
    }

    #[test]
    fn confined_primitives_round_trip_non_utf8_names() {
        let tree = TestDir::new("primitives");
        let root = Root::open(tree.path()).unwrap();
        root.create_directory(&relative(b"dir"), 0o700).unwrap();

        let raw_name = std::ffi::OsString::from_vec(b"stage-\xff".to_vec());
        let stage_path = tree.path().join("dir").join(&raw_name);
        let mut stage = root
            .create_file(&relative(b"dir/stage-\xff"), 0o600)
            .unwrap();
        stage.write_all(b"payload").unwrap();
        stage.flush().unwrap();
        assert_eq!(fs::read(&stage_path).unwrap(), b"payload");

        root.rename(&relative(b"dir/stage-\xff"), &relative(b"dir/final"))
            .unwrap();
        assert!(!stage_path.exists());
        let mut final_file = root
            .open_regular_write(&relative(b"dir/final"), false)
            .unwrap();
        final_file.seek(SeekFrom::End(0)).unwrap();
        final_file.write_all(b"-more").unwrap();
        drop(final_file);
        assert_eq!(
            fs::read(tree.path().join("dir/final")).unwrap(),
            b"payload-more"
        );

        root.unlink(&relative(b"dir/final")).unwrap();
        root.remove_directory(&relative(b"dir")).unwrap();
        assert!(!tree.path().join("dir").exists());
    }

    #[test]
    fn owner_write_only_regular_file_can_be_written_without_escaping_root() {
        let tree = TestDir::new("write-only");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(&outside).unwrap();

        let inside = root_path.join("inside");
        let sentinel = outside.join("sentinel");
        fs::write(&inside, b"initial").unwrap();
        fs::write(&sentinel, b"outside").unwrap();
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o200)).unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o200)).unwrap();
        assert_eq!(fs::metadata(&inside).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        symlink(&outside, root_path.join("escape")).unwrap();

        let root = Root::open(&root_path).unwrap();
        let mut file = root
            .open_regular_write(&relative(b"inside"), false)
            .unwrap();
        let descriptor_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(descriptor_flags, -1);
        assert_eq!(descriptor_flags & libc::O_ACCMODE, libc::O_WRONLY);
        file.write_all(b"updated").unwrap();
        drop(file);
        assert!(root
            .open_regular_write(&relative(b"escape/sentinel"), false)
            .is_err());

        fs::set_permissions(&inside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&inside).unwrap(), b"updated");
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
    }

    #[test]
    fn held_parent_does_not_follow_a_replacement_symlink() {
        let tree = TestDir::new("held-parent");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(root_path.join("gate")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        let root = Root::open(&root_path).unwrap();

        let path = relative(b"gate/created");
        let parent = root.resolve_parent(&path).unwrap();
        fs::rename(root_path.join("gate"), root_path.join("parked")).unwrap();
        symlink(&outside, root_path.join("gate")).unwrap();

        let mut file = open_at(
            parent.directory.as_raw_fd(),
            &parent.leaf,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        file.write_all(b"inside").unwrap();
        drop(file);

        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
        assert!(!outside.join("created").exists());
        assert_eq!(
            fs::read(root_path.join("parked/created")).unwrap(),
            b"inside"
        );
        assert!(root.create_file(&path, 0o600).is_err());
    }

    #[test]
    fn concurrent_intermediate_swaps_never_touch_outside_sentinel() {
        let tree = TestDir::new("swap-race");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::create_dir(root_path.join("gate")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let attacker_stop = stop.clone();
        let attacker_root = root_path.clone();
        let attacker_outside = outside.clone();
        let attacker = std::thread::spawn(move || {
            while !attacker_stop.load(Ordering::Relaxed) {
                if fs::rename(attacker_root.join("gate"), attacker_root.join("parked")).is_ok() {
                    let _ = symlink(&attacker_outside, attacker_root.join("gate"));
                    let _ = fs::remove_file(attacker_root.join("gate"));
                    let _ = fs::rename(attacker_root.join("parked"), attacker_root.join("gate"));
                }
            }
        });

        let root = Root::open(&root_path).unwrap();
        let temp = relative(b"gate/work");
        let final_path = relative(b"gate/final");
        for _ in 0..2_000 {
            if let Ok(mut file) = root.create_file(&temp, 0o600) {
                let _ = file.write_all(b"inside");
                drop(file);
                let _ = root.rename(&temp, &final_path);
                let _ = root.unlink(&final_path);
                let _ = root.unlink(&temp);
            }
        }
        stop.store(true, Ordering::Relaxed);
        attacker.join().unwrap();

        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
        assert!(!outside.join("work").exists());
        assert!(!outside.join("final").exists());
    }

    #[test]
    fn leaf_symlink_is_never_opened_but_can_be_unlinked() {
        let tree = TestDir::new("leaf-symlink");
        let root_path = tree.path().join("root");
        let outside = tree.path().join("outside");
        fs::create_dir(&root_path).unwrap();
        fs::write(&outside, b"unchanged").unwrap();
        symlink(&outside, root_path.join("leaf")).unwrap();
        let root = Root::open(&root_path).unwrap();

        assert!(root.open_regular_read(&relative(b"leaf")).is_err());
        assert!(root.open_regular_write(&relative(b"leaf"), true).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
        root.unlink(&relative(b"leaf")).unwrap();
        assert_eq!(fs::read(&outside).unwrap(), b"unchanged");
    }

    #[test]
    fn same_type_symlink_and_special_replacement_exchange_the_expected_inode() {
        let tree = TestDir::new("same-type-replacement");
        let root = Root::open(tree.path()).unwrap();

        let link = relative(b"link");
        root.create_symlink(&link, b"old").unwrap();
        let old_link = root.metadata(&link).unwrap();
        root.replace_symlink_if_same(&link, b"new", old_link.dev, old_link.ino)
            .unwrap();
        let new_link = root.metadata(&link).unwrap();
        assert!(new_link.is_symlink());
        assert_ne!(new_link.ino, old_link.ino);
        assert_eq!(
            fs::read_link(tree.path().join("link")).unwrap(),
            Path::new("new")
        );

        let fifo = relative(b"fifo");
        root.create_node(&fifo, MODE_FIFO | 0o644, 0).unwrap();
        let old_fifo = root.metadata(&fifo).unwrap();
        root.replace_node_if_same(&fifo, MODE_FIFO | 0o600, 0, old_fifo.dev, old_fifo.ino)
            .unwrap();
        let new_fifo = root.metadata(&fifo).unwrap();
        assert_eq!(new_fifo.file_type(), MODE_FIFO);
        assert_ne!(new_fifo.ino, old_fifo.ino);
    }

    #[test]
    fn root_path_cannot_be_used_as_a_mutating_leaf() {
        let tree = TestDir::new("empty-leaf");
        let root = Root::open(tree.path()).unwrap();
        let empty = relative(b"");
        assert!(root.create_file(&empty, 0o600).is_err());
        assert!(root.create_directory(&empty, 0o700).is_err());
        assert!(root.unlink(&empty).is_err());
        assert!(root.remove_directory(&empty).is_err());
        assert!(root.rename(&empty, &relative(b"other")).is_err());
        assert!(root.open_directory(&empty).is_ok());
    }

    #[test]
    fn os_string_conversion_in_test_is_byte_exact() {
        let name = OsStr::from_bytes(b"byte-\xff");
        assert_eq!(name.as_bytes(), b"byte-\xff");
    }
}
