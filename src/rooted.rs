//! Root-anchored filesystem primitives for guarded receivers.
//!
//! `Root` follows the explicitly selected root path once, opens that directory,
//! and uses only the resulting descriptor afterward. Descendant paths are raw
//! Unix bytes split into validated relative components. Every intermediate
//! component is opened relative to the preceding descriptor with
//! `O_DIRECTORY | O_NOFOLLOW`; leaf operations are performed relative to a
//! held parent descriptor. There is no pathname fallback.
//!
//! Native guarded placements and signed receivers use these operations for
//! descendant mutation and inspection; the unrestricted implementation remains
//! separate. Existing roots, directory scans, regular-file I/O, leaf
//! creation/replacement, metadata, and non-recursive unlink/rmdir are supported.
//! Recursive removal and missing-root creation stay outside this layer.
//! Traversal uses search-only descriptors where the platform provides them;
//! directory enumeration separately opens an independent readable descriptor.
//!
//! Linux currently uses the same component walk as other Unix platforms. An
//! `openat2` fast path should be added only with tests proving that it has
//! exactly the same root-symlink, descendant-symlink, and mount semantics.
//!
//! The guarantee is pathname confinement. A hard link beneath the root may
//! still refer to an inode with another name outside the root. As with all
//! descriptor-based traversal, an already-open descendant remains the selected
//! object if another process subsequently renames it.

use crate::proto::OperatorSymlinkPolicy;
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SWAP_NAME: AtomicU64 = AtomicU64::new(0);

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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RootIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootMetadata {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) nlink: u64,
    pub(crate) len: u64,
    pub(crate) mtime: i64,
    pub(crate) mtime_nsec: u32,
    pub(crate) ctime: i64,
    pub(crate) ctime_nsec: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) rdev: u64,
}

/// Whether resolution needs to traverse the last component as a directory or
/// select it as a named entry. Selecting an entry may independently request
/// that a last-component symlink be followed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperatorFinalComponent {
    Directory,
    Entry { follow_symlink: bool },
}

/// One symlink hop taken while resolving an operator path. Callers use this
/// only for diagnostics; authority is carried by the returned descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperatorSymlinkHop {
    pub(crate) component: Vec<u8>,
    pub(crate) target: Vec<u8>,
}

/// An existing named entry selected relative to its retained parent. `object`
/// pins a non-directory object where the platform can open it without
/// following; a selected symlink may have only its parent, name, and observed
/// identity. Directories are pinned separately by `PinnedDirectory`.
pub(crate) struct PinnedLeaf {
    parent: File,
    name: CString,
    metadata: RootMetadata,
    object: Option<File>,
}

impl PinnedLeaf {
    pub(crate) fn metadata(&self) -> RootMetadata {
        self.metadata
    }

    pub(crate) fn into_parts(self) -> (File, CString, RootMetadata, Option<File>) {
        (self.parent, self.name, self.metadata, self.object)
    }
}

/// An existing selected directory. `entry` retains the parent/name used to
/// select it when the directory itself may later need to be renamed or
/// removed; it is absent when resolution ends at the resolver's base.
pub(crate) struct PinnedDirectory {
    directory: File,
    entry: Option<PinnedLeaf>,
    metadata: RootMetadata,
}

impl PinnedDirectory {
    pub(crate) fn metadata(&self) -> RootMetadata {
        self.metadata
    }

    pub(crate) fn into_parts(self) -> (File, Option<PinnedLeaf>) {
        (self.directory, self.entry)
    }
}

/// The nearest retained existing directory and the unresolved suffix beneath
/// it. Creation remains a caller policy; this type supplies only authority.
pub(crate) struct PinnedMissing {
    directory: File,
    components: VecDeque<Vec<u8>>,
}

impl PinnedMissing {
    pub(crate) fn into_parts(self) -> (File, VecDeque<Vec<u8>>) {
        (self.directory, self.components)
    }
}

pub(crate) enum PinnedPath {
    Missing(PinnedMissing),
    Leaf(PinnedLeaf),
    Directory(PinnedDirectory),
}

struct OperatorCursor {
    directory: File,
    entry: Option<OperatorEntry>,
}

/// How the cursor's directory was selected. Intermediate cursors deliberately
/// omit a parent descriptor; only the final capability retains one.
struct OperatorEntry {
    name: CString,
    metadata: RootMetadata,
}

/// Descriptor-retaining component resolver for paths supplied directly by an
/// operator. Descendant transfer paths use `RelativePath` and `Root` instead.
pub(crate) struct OperatorResolver {
    base: File,
    confined: bool,
    relative_input: bool,
    symlink_policy: OperatorSymlinkPolicy,
}

impl OperatorResolver {
    /// Begin at the process root or cwd. Absolute symlink targets may restart
    /// at `/` because this form is not confined beneath a caller-provided base.
    pub(crate) fn resolve_process(
        path: &[u8],
        symlink_policy: OperatorSymlinkPolicy,
        final_component: OperatorFinalComponent,
        allow_missing: bool,
        hops: &mut Vec<OperatorSymlinkHop>,
    ) -> Result<PinnedPath> {
        Self {
            base: open_operator_start(path.starts_with(b"/"))?,
            confined: false,
            relative_input: false,
            symlink_policy,
        }
        .resolve(path, final_component, allow_missing, hops)
    }

    /// Begin at an already-open directory. The supplied path must be relative;
    /// a confined resolver also refuses `..` and symlink targets that would
    /// escape that directory.
    pub(crate) fn beneath(
        base: &File,
        confined: bool,
        symlink_policy: OperatorSymlinkPolicy,
    ) -> Result<Self> {
        Ok(Self {
            base: base.try_clone().context("duplicate operator path base")?,
            confined,
            relative_input: true,
            symlink_policy,
        })
    }

    pub(crate) fn resolve(
        &self,
        path: &[u8],
        final_component: OperatorFinalComponent,
        allow_missing: bool,
        hops: &mut Vec<OperatorSymlinkHop>,
    ) -> Result<PinnedPath> {
        if path.contains(&0) {
            bail!("operator path contains NUL");
        }
        if self.relative_input && path.starts_with(b"/") {
            bail!("path beneath an opened operator base must be relative");
        }
        let mut components = operator_components(path);
        let mut stack = vec![OperatorCursor {
            directory: self
                .base
                .try_clone()
                .context("duplicate operator path base")?,
            entry: None,
        }];
        let mut symlink_count = 0usize;

        loop {
            let Some(component) = components.pop_front() else {
                let current = stack.last().expect("operator resolver stack is nonempty");
                let metadata = root_metadata_from_std(&current.directory.metadata()?)?;
                let entry = if let Some(entry) = &current.entry {
                    let parent = &stack
                        .iter()
                        .rev()
                        .nth(1)
                        .expect("a selected entry has a parent cursor")
                        .directory;
                    Some(PinnedLeaf {
                        parent: parent
                            .try_clone()
                            .context("pin selected directory parent")?,
                        name: entry.name.clone(),
                        metadata: entry.metadata,
                        object: None,
                    })
                } else {
                    None
                };
                return Ok(PinnedPath::Directory(PinnedDirectory {
                    directory: current
                        .directory
                        .try_clone()
                        .context("pin selected directory")?,
                    entry,
                    metadata,
                }));
            };

            if component == b"." {
                continue;
            }
            if component == b".." {
                if stack.len() > 1 {
                    stack.pop();
                } else if self.confined {
                    bail!("operator path resolves outside its confined root");
                } else {
                    stack[0] = OperatorCursor {
                        directory: open_operator_directory_at(&stack[0].directory, b"..")
                            .context("resolve operator path parent")?,
                        entry: None,
                    };
                }
                continue;
            }

            let current = stack.last().expect("operator resolver stack is nonempty");
            let name = operator_component_cstring(&component)?;
            let metadata = match metadata_at(current.directory.as_raw_fd(), &name) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound && allow_missing => {
                    components.push_front(component);
                    return Ok(PinnedPath::Missing(PinnedMissing {
                        directory: current
                            .directory
                            .try_clone()
                            .context("pin nearest existing directory")?,
                        components,
                    }));
                }
                Err(error) => return Err(error).context("inspect operator path component"),
            };
            let final_name = components.is_empty();
            let follow_symlink = !final_name
                || matches!(final_component, OperatorFinalComponent::Directory)
                || matches!(
                    final_component,
                    OperatorFinalComponent::Entry {
                        follow_symlink: true
                    }
                );

            if metadata.is_symlink() {
                if !follow_symlink {
                    let object = open_operator_symlink_at(current.directory.as_raw_fd(), &name)?;
                    if let Some(object) = &object {
                        require_operator_identity(
                            metadata,
                            root_metadata_from_std(&object.metadata()?)?,
                            "operator symlink",
                        )?;
                    }
                    return Ok(PinnedPath::Leaf(PinnedLeaf {
                        parent: current
                            .directory
                            .try_clone()
                            .context("pin selected symlink parent")?,
                        name,
                        metadata,
                        object,
                    }));
                }
                self.authorize_symlink(metadata, &component)?;
                symlink_count += 1;
                if symlink_count > 40 {
                    bail!("too many symlink levels in operator path");
                }
                let target = operator_read_link_at(current.directory.as_raw_fd(), &name)?;
                hops.push(OperatorSymlinkHop {
                    component,
                    target: target.clone(),
                });
                if target.starts_with(b"/") {
                    if self.confined {
                        bail!("operator path has an absolute symlink target outside its root");
                    }
                    stack = vec![OperatorCursor {
                        directory: open_operator_start(true)?,
                        entry: None,
                    }];
                }
                let mut target_components = operator_components(&target);
                target_components.append(&mut components);
                components = target_components;
                continue;
            }

            if metadata.is_dir() {
                let directory = open_operator_directory_at(&current.directory, &component)
                    .context("open operator directory component")?;
                require_operator_identity(
                    metadata,
                    root_metadata_from_std(&directory.metadata()?)?,
                    "operator directory",
                )?;
                if final_name {
                    return Ok(PinnedPath::Directory(PinnedDirectory {
                        directory,
                        entry: Some(PinnedLeaf {
                            parent: current
                                .directory
                                .try_clone()
                                .context("pin selected directory parent")?,
                            name,
                            metadata,
                            object: None,
                        }),
                        metadata,
                    }));
                }
                stack.push(OperatorCursor {
                    directory,
                    entry: Some(OperatorEntry { name, metadata }),
                });
                continue;
            }

            if !final_name || matches!(final_component, OperatorFinalComponent::Directory) {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR).into());
            }
            let object = open_operator_metadata_at(current.directory.as_raw_fd(), &name)
                .context("pin operator path leaf")?;
            require_operator_identity(
                metadata,
                root_metadata_from_std(&object.metadata()?)?,
                "operator leaf",
            )?;
            return Ok(PinnedPath::Leaf(PinnedLeaf {
                parent: current
                    .directory
                    .try_clone()
                    .context("pin selected object parent")?,
                name,
                metadata,
                object: Some(object),
            }));
        }
    }

    fn authorize_symlink(&self, metadata: RootMetadata, component: &[u8]) -> Result<()> {
        let euid = unsafe { libc::geteuid() };
        match self.symlink_policy {
            OperatorSymlinkPolicy::Refuse => bail!(
                "refusing symlink component {:?} in operator path; pass --follow to resolve symlinks",
                String::from_utf8_lossy(component)
            ),
            OperatorSymlinkPolicy::TrustedOwner
                if !operator_symlink_owner_is_trusted(metadata.uid, euid) =>
            {
                bail!(
                    "refusing symlink component {:?} owned by uid {}; expected uid 0 or receiver uid {}",
                    String::from_utf8_lossy(component),
                    metadata.uid,
                    euid
                )
            }
            OperatorSymlinkPolicy::TrustedOwner | OperatorSymlinkPolicy::FollowAll => Ok(()),
        }
    }
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

    pub(crate) fn to_path_buf(&self) -> PathBuf {
        let mut path = PathBuf::new();
        for component in &self.components {
            path.push(OsStr::from_bytes(component));
        }
        path
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
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open confined root {}", path.display()))?;
        Self::from_directory(directory)
            .with_context(|| format!("validate confined root {}", path.display()))
    }

    /// Adopt an already-open directory as the authority boundary. This never
    /// resolves a pathname and therefore preserves the selected object across
    /// renames and namespace replacement.
    pub(crate) fn from_directory(directory: File) -> Result<Self> {
        let metadata = directory
            .metadata()
            .context("stat confined root descriptor")?;
        if !metadata.is_dir() {
            bail!("confined root descriptor is not a directory");
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

    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.directory.as_raw_fd()
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

    /// Open a directory by its root-relative name and require that it is still
    /// the entry previously observed by a caller such as the tree scanner.
    pub(crate) fn open_directory_verified(
        &self,
        path: &RelativePath,
        expected: RootMetadata,
    ) -> Result<File> {
        let directory = self.open_directory(path)?;
        require_metadata_identity(
            expected,
            root_metadata_from_std(&directory.metadata()?)?,
            "confined directory",
        )?;
        Ok(directory)
    }

    /// Open an observed child relative to an already-open parent. This lets a
    /// bounded scanner carry authority forward without rewalking from the
    /// root, while the identity check rejects a rename/replacement race.
    pub(crate) fn open_child_directory_verified(
        &self,
        parent: &File,
        name: &[u8],
        expected: RootMetadata,
    ) -> Result<File> {
        directory_entry_cstring(name)?;
        let directory = open_directory_at(parent, name).context("open confined child directory")?;
        require_metadata_identity(
            expected,
            root_metadata_from_std(&directory.metadata()?)?,
            "confined child directory",
        )?;
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
        let (parent, leaf) = if path.is_empty() {
            (
                self.directory.try_clone().context("duplicate root fd")?,
                component_cstring(b"."),
            )
        } else {
            let parent = self.resolve_parent(path)?;
            (parent.directory, parent.leaf)
        };
        #[cfg(target_os = "linux")]
        let flags =
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
        #[cfg(target_os = "macos")]
        let flags = libc::O_EVTONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_NOCTTY
            | libc::O_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let flags =
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
        open_at(parent.as_raw_fd(), &leaf, flags, 0)
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
            access | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        )
        .with_context(|| format!("open confined regular file {}", path.label()))?;
        require_regular(&file, path)?;
        clear_nonblocking(&file)
            .with_context(|| format!("normalize confined file flags for {}", path.label()))?;
        if truncate {
            file.set_len(0)
                .with_context(|| format!("truncate confined file {}", path.label()))?;
        }
        Ok(file)
    }

    /// Create a new regular leaf. Existing leaves of every type are refused.
    /// Special permission bits require the explicit metadata operations.
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
                | libc::O_NOCTTY
                | libc::O_CLOEXEC,
            mode & 0o777,
        )
        .with_context(|| format!("create confined file {}", path.label()))?;
        require_regular(&file, path)?;
        clear_nonblocking(&file)
            .with_context(|| format!("normalize confined file flags for {}", path.label()))?;
        Ok(file)
    }

    /// Create exactly one directory. Parents must already exist and be real
    /// directories beneath this root.
    pub(crate) fn create_directory(&self, path: &RelativePath, mode: u32) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        retry_zero(|| unsafe {
            libc::mkdirat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                (mode & 0o777) as libc::mode_t,
            )
        })
        .with_context(|| format!("create confined directory {}", path.label()))
    }

    /// Create any missing parents of `path`, walking only through real
    /// directories retained beneath this root. Concurrent creators are
    /// accepted only when the resulting component opens as a directory.
    pub(crate) fn create_missing_parents(&self, path: &RelativePath, mode: u32) -> Result<()> {
        let (parents, _) = path.leaf()?;
        let mut directory = self.directory.try_clone().context("duplicate root fd")?;
        for component in parents {
            match open_directory_at(&directory, component) {
                Ok(child) => {
                    directory = child;
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("resolve confined parent for {}", path.label()));
                }
            }
            let component = component_cstring(component);
            loop {
                let result = unsafe {
                    libc::mkdirat(
                        directory.as_raw_fd(),
                        component.as_ptr(),
                        (mode & 0o777) as libc::mode_t,
                    )
                };
                if result == 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error)
                        .with_context(|| format!("create confined parent for {}", path.label()));
                }
                break;
            }
            directory = open_directory_at(&directory, component.as_bytes())
                .with_context(|| format!("open created confined parent for {}", path.label()))?;
        }
        Ok(())
    }

    pub(crate) fn metadata(&self, path: &RelativePath) -> Result<RootMetadata> {
        if path.is_empty() {
            return root_metadata_from_std(&self.directory.metadata()?);
        }
        let parent = self.resolve_parent(path)?;
        metadata_at(parent.directory.as_raw_fd(), &parent.leaf)
            .with_context(|| format!("stat confined path {}", path.label()))
    }

    /// Inspect a name relative to an already-open directory without following
    /// a symlink in that name.
    pub(crate) fn metadata_in_directory(
        &self,
        directory: &File,
        name: &[u8],
    ) -> Result<RootMetadata> {
        let name = directory_entry_cstring(name)?;
        metadata_at(directory.as_raw_fd(), &name).context("stat confined directory entry")
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

    /// List raw names from an opened descendant directory. The fdopendir walk
    /// owns a duplicate descriptor and never reconstructs a pathname.
    pub(crate) fn read_directory(&self, path: &RelativePath) -> Result<Vec<Vec<u8>>> {
        let directory = self.open_directory(path)?;
        self.read_open_directory(&directory)
            .with_context(|| format!("read confined directory {}", path.label()))
    }

    /// List raw names from a directory already retained by the caller. The
    /// stream gets its own open-file description, so retries and concurrent
    /// scans never share a directory offset.
    pub(crate) fn read_open_directory(&self, directory: &File) -> Result<Vec<Vec<u8>>> {
        // dup()/try_clone() would share the directory open-file-description
        // offset. Reopen `.` so concurrent scans and retries each start with
        // an independent readable stream, including when the authority is an
        // O_PATH/O_SEARCH descriptor.
        let readable = open_readable_directory_at(directory, b".")
            .context("open readable confined directory")?;
        let descriptor = readable.into_raw_fd();
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            let _ = unsafe { libc::close(descriptor) };
            return Err(error).context("open confined directory stream");
        }
        struct DirectoryStream(*mut libc::DIR);
        impl Drop for DirectoryStream {
            fn drop(&mut self) {
                let _ = unsafe { libc::closedir(self.0) };
            }
        }
        let stream = DirectoryStream(stream);
        let mut names = Vec::new();
        loop {
            set_errno(0);
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let errno = get_errno();
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(errno))
                        .context("read confined directory");
                }
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        Ok(names)
    }

    /// Component limit for a sidecar beside `path`. Missing or non-directory
    /// suffixes are walked back to the nearest existing real directory, never
    /// through a symlink.
    pub(crate) fn name_max_for_parent(&self, path: &RelativePath) -> Result<usize> {
        let (parents, _) = path.leaf()?;
        let mut components = parents.to_vec();
        loop {
            let candidate = RelativePath {
                components: components.clone(),
            };
            match self.open_directory(&candidate) {
                Ok(directory) => {
                    set_errno(0);
                    let limit =
                        unsafe { libc::fpathconf(directory.as_raw_fd(), libc::_PC_NAME_MAX) };
                    if limit > 0 {
                        return Ok(limit as usize);
                    }
                    let errno = get_errno();
                    if errno == 0 {
                        return Ok(255);
                    }
                    return Err(io::Error::from_raw_os_error(errno))
                        .context("query confined directory component limit");
                }
                Err(error) if missing_directory_suffix(&error) && !components.is_empty() => {
                    components.pop();
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn read_link(&self, path: &RelativePath) -> Result<Vec<u8>> {
        let parent = self.resolve_parent(path)?;
        self.read_link_in_directory(&parent.directory, parent.leaf.as_bytes())
            .with_context(|| format!("read confined symlink {}", path.label()))
    }

    pub(crate) fn read_link_in_directory(&self, directory: &File, name: &[u8]) -> Result<Vec<u8>> {
        let name = directory_entry_cstring(name)?;
        let mut buffer = vec![0u8; 256];
        loop {
            let read = loop {
                let result = unsafe {
                    libc::readlinkat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                };
                if result >= 0 {
                    break result as usize;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error).context("read confined directory-entry symlink");
                }
            };
            if read < buffer.len() {
                buffer.truncate(read);
                return Ok(buffer);
            }
            if buffer.len() >= 1024 * 1024 {
                bail!("confined symlink target exceeds size limit");
            }
            buffer.resize(buffer.len() * 2, 0);
        }
    }

    pub(crate) fn create_symlink(&self, path: &RelativePath, target: &[u8]) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let target = CString::new(target).context("symlink target contains NUL")?;
        retry_zero(|| unsafe {
            libc::symlinkat(
                target.as_ptr(),
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
            )
        })
        .with_context(|| format!("create confined symlink {}", path.label()))
    }

    pub(crate) fn create_node(&self, path: &RelativePath, mode: u32, rdev: u64) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        retry_zero(|| unsafe {
            libc::mknodat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                mode as libc::mode_t,
                rdev as libc::dev_t,
            )
        })
        .with_context(|| format!("create confined node {}", path.label()))
    }

    pub(crate) fn chown(
        &self,
        path: &RelativePath,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> io::Result<()> {
        let parent = self
            .resolve_parent(path)
            .map_err(|error| io::Error::other(format!("{error:#}")))?;
        retry_zero(|| unsafe {
            libc::fchownat(
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }

    pub(crate) fn set_times(&self, path: &RelativePath, times: &[libc::timespec; 2]) -> Result<()> {
        let (parent, leaf) = if path.is_empty() {
            (
                self.directory.try_clone().context("duplicate root fd")?,
                component_cstring(b"."),
            )
        } else {
            let parent = self.resolve_parent(path)?;
            (parent.directory, parent.leaf)
        };
        retry_zero(|| unsafe {
            libc::utimensat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
        .with_context(|| format!("set times on confined path {}", path.label()))
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
                retry_zero(|| unsafe { libc::symlinkat(target.as_ptr(), fd, name.as_ptr()) })
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
                retry_zero(|| unsafe {
                    libc::mknodat(fd, name.as_ptr(), mode as libc::mode_t, rdev as libc::dev_t)
                })
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
        let temporary = create_temporary(&parent, create)?;
        if let Err(error) = rename_exchange(
            parent.directory.as_raw_fd(),
            &temporary,
            parent.directory.as_raw_fd(),
            &parent.leaf,
        ) {
            let _ = unlink_at(parent.directory.as_raw_fd(), &temporary, 0);
            return Err(error)
                .with_context(|| format!("atomically replace confined path {}", path.label()));
        }
        let swapped = metadata_at(parent.directory.as_raw_fd(), &temporary)?;
        if swapped.dev != expected_dev
            || swapped.ino != expected_ino
            || swapped.file_type() != expected_type
        {
            rename_exchange(
                parent.directory.as_raw_fd(),
                &temporary,
                parent.directory.as_raw_fd(),
                &parent.leaf,
            )
            .with_context(|| format!("restore raced target {}", path.label()))?;
            unlink_at(parent.directory.as_raw_fd(), &temporary, 0)?;
            bail!(
                "confined target {} changed during replacement",
                path.label()
            );
        }
        unlink_at(parent.directory.as_raw_fd(), &temporary, 0)
            .with_context(|| format!("remove replaced confined path {}", path.label()))
    }

    /// Rename one leaf to another. Both parents are resolved and retained
    /// beneath this root before the atomic rename. Existing destinations follow
    /// ordinary `rename(2)` replacement rules.
    pub(crate) fn rename(&self, source: &RelativePath, target: &RelativePath) -> Result<()> {
        let source_parent = self.resolve_parent(source)?;
        let target_parent = self.resolve_parent(target)?;
        retry_zero(|| unsafe {
            libc::renameat(
                source_parent.directory.as_raw_fd(),
                source_parent.leaf.as_ptr(),
                target_parent.directory.as_raw_fd(),
                target_parent.leaf.as_ptr(),
            )
        })
        .with_context(|| {
            format!(
                "rename confined path {} to {}",
                source.label(),
                target.label()
            )
        })
    }

    /// Atomically publish a staged regular file with ordinary rename
    /// replacement semantics. Both parents are retained before the rename, so
    /// a concurrent ancestor replacement cannot redirect either side. A later
    /// writer is never rolled back: post-rename validation can report a race,
    /// but it must not mutate the target name again.
    pub(crate) fn rename_regular_if_same(
        &self,
        source: &RelativePath,
        target: &RelativePath,
        staged_identity: (u64, u64),
    ) -> Result<()> {
        let (staged_dev, staged_ino) = staged_identity;
        let (source_parent, target_parent) = self.resolve_publish_parents(source, target)?;
        let staged = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        require_safe_staged_identity(staged, staged_dev, staged_ino, source)?;
        retry_zero(|| unsafe {
            libc::renameat(
                source_parent.directory.as_raw_fd(),
                source_parent.leaf.as_ptr(),
                target_parent.directory.as_raw_fd(),
                target_parent.leaf.as_ptr(),
            )
        })
        .with_context(|| format!("publish confined path {}", target.label()))?;
        #[cfg(test)]
        run_publication_test_hook(self.identity, target, PublicationTestPoint::AfterAnyRename);
        let published = metadata_at(target_parent.directory.as_raw_fd(), &target_parent.leaf)?;
        if !is_safe_staged_identity(published, staged_dev, staged_ino) {
            bail!(
                "confined staged path {} changed during publication",
                source.label()
            );
        }
        Ok(())
    }

    /// Publish a staged regular file only if the target name is still absent.
    /// The hard link makes the final name visible atomically without replacing
    /// a raced target; removing the staged name leaves one link on success.
    pub(crate) fn publish_new_regular(
        &self,
        source: &RelativePath,
        target: &RelativePath,
        staged_identity: (u64, u64),
    ) -> Result<()> {
        let (staged_dev, staged_ino) = staged_identity;
        let (source_parent, target_parent) = self.resolve_publish_parents(source, target)?;
        let staged = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        require_safe_staged_identity(staged, staged_dev, staged_ino, source)?;
        retry_zero(|| unsafe {
            libc::linkat(
                source_parent.directory.as_raw_fd(),
                source_parent.leaf.as_ptr(),
                target_parent.directory.as_raw_fd(),
                target_parent.leaf.as_ptr(),
                0,
            )
        })
        .with_context(|| {
            format!(
                "publish new confined path {} as {}",
                source.label(),
                target.label()
            )
        })?;
        #[cfg(test)]
        run_publication_test_hook(self.identity, target, PublicationTestPoint::AfterAbsentLink);
        let published = metadata_at(target_parent.directory.as_raw_fd(), &target_parent.leaf)?;
        if !is_safe_staged_identity_after_link(published, staged_dev, staged_ino) {
            bail!(
                "confined staged path {} changed during publication",
                source.label()
            );
        }
        unlink_at(source_parent.directory.as_raw_fd(), &source_parent.leaf, 0)
            .with_context(|| format!("remove staged confined path {}", source.label()))
    }

    /// Atomically replace exactly one previously observed regular-file inode.
    /// The exchange retains the displaced inode under the staged name long
    /// enough to verify it. A raced target is exchanged back and left intact.
    pub(crate) fn replace_regular_if_same(
        &self,
        source: &RelativePath,
        target: &RelativePath,
        expected_dev: u64,
        expected_ino: u64,
        expected_ctime: Option<(i64, u32)>,
    ) -> Result<()> {
        let source_parent = self.resolve_parent(source)?;
        let target_parent = self.resolve_parent(target)?;
        let staged = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        if !staged.is_file() {
            bail!(
                "confined staged path {} is not a regular file",
                source.label()
            );
        }
        let before = metadata_at(target_parent.directory.as_raw_fd(), &target_parent.leaf)?;
        let has_expected_identity = |metadata: RootMetadata| {
            metadata.is_file() && metadata.dev == expected_dev && metadata.ino == expected_ino
        };
        if !has_expected_identity(before)
            || !expected_ctime.is_none_or(|(ctime, ctime_nsec)| {
                (before.ctime, before.ctime_nsec) == (ctime, ctime_nsec)
            })
        {
            bail!(
                "confined target {} changed before publication",
                target.label()
            );
        }
        rename_exchange(
            source_parent.directory.as_raw_fd(),
            &source_parent.leaf,
            target_parent.directory.as_raw_fd(),
            &target_parent.leaf,
        )
        .with_context(|| format!("atomically publish confined path {}", target.label()))?;
        let displaced = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        // The exchange itself may update the displaced inode's ctime. Its
        // dev/inode identity cannot be recycled while the link still exists,
        // so the pre-exchange fingerprint plus this identity check is enough.
        if !has_expected_identity(displaced) {
            rename_exchange(
                source_parent.directory.as_raw_fd(),
                &source_parent.leaf,
                target_parent.directory.as_raw_fd(),
                &target_parent.leaf,
            )
            .with_context(|| format!("restore raced target {}", target.label()))?;
            bail!(
                "confined target {} changed during publication",
                target.label()
            );
        }
        unlink_at(source_parent.directory.as_raw_fd(), &source_parent.leaf, 0)
            .with_context(|| format!("remove displaced confined path {}", target.label()))
    }

    fn resolve_publish_parents(
        &self,
        source: &RelativePath,
        target: &RelativePath,
    ) -> Result<(ResolvedParent, ResolvedParent)> {
        let (source_parents, _) = source.leaf()?;
        let (target_parents, target_leaf) = target.leaf()?;
        let source_parent = self.resolve_parent(source)?;
        let target_parent = if source_parents == target_parents {
            ResolvedParent {
                directory: source_parent
                    .directory
                    .try_clone()
                    .context("duplicate publication parent fd")?,
                leaf: component_cstring(target_leaf),
            }
        } else {
            self.resolve_parent(target)?
        };
        Ok((source_parent, target_parent))
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
        retry_zero(|| unsafe {
            libc::unlinkat(parent.directory.as_raw_fd(), parent.leaf.as_ptr(), flags)
        })
        .with_context(|| format!("{operation} confined path {}", path.label()))
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
}

struct ResolvedParent {
    directory: File,
    leaf: CString,
}

fn component_cstring(component: &[u8]) -> CString {
    CString::new(component).expect("RelativePath already rejected NUL")
}

fn directory_entry_cstring(name: &[u8]) -> Result<CString> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        bail!("confined directory entry must be one non-dot component");
    }
    CString::new(name).context("confined directory entry contains NUL")
}

fn operator_components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn operator_component_cstring(component: &[u8]) -> Result<CString> {
    CString::new(component).context("operator path component contains NUL")
}

fn operator_directory_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
}

fn open_operator_start(absolute: bool) -> Result<File> {
    let name = CString::new(if absolute { "/" } else { "." })
        .expect("fixed operator start contains no NUL");
    open_operator_directory_fd(libc::AT_FDCWD, &name)
}

fn open_operator_directory_at(parent: &File, component: &[u8]) -> Result<File> {
    let component = operator_component_cstring(component)?;
    open_operator_directory_fd(parent.as_raw_fd(), &component)
}

fn open_operator_directory_fd(parent: RawFd, component: &CString) -> Result<File> {
    let directory = open_at(parent, component, operator_directory_flags(), 0)?;
    if !directory.metadata()?.is_dir() {
        bail!("operator path component is not a directory");
    }
    Ok(directory)
}

fn open_operator_metadata_at(parent: RawFd, name: &CString) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    let flags =
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags =
        libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let flags =
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    open_at(parent, name, flags, 0)
}

fn open_operator_symlink_at(parent: RawFd, name: &CString) -> Result<Option<File>> {
    #[cfg(target_os = "linux")]
    {
        open_at(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        )
        .map(Some)
        .context("pin operator symlink")
    }
    #[cfg(target_os = "macos")]
    {
        open_at(
            parent,
            name,
            libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        )
        .map(Some)
        .context("pin operator symlink")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Ok(None)
    }
}

fn operator_read_link_at(parent: RawFd, name: &CString) -> Result<Vec<u8>> {
    read_link_bytes(|target, capacity| unsafe {
        libc::readlinkat(parent, name.as_ptr(), target, capacity)
    })
}

/// Read raw target bytes through an already-open symlink object. `None` means
/// the running platform lacks a descriptor-bound API; security-sensitive
/// callers must fail closed instead of reopening the symlink by name.
pub(crate) fn read_open_symlink(object: &File) -> Result<Option<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    {
        let empty = c"";
        read_link_bytes(|target, capacity| unsafe {
            libc::readlinkat(object.as_raw_fd(), empty.as_ptr(), target, capacity)
        })
        .map(Some)
    }
    #[cfg(target_os = "macos")]
    {
        // `freadlink` was added in macOS 13. Resolve it dynamically so a binary
        // that otherwise runs on an older release does not gain a hard loader
        // dependency. Callers reject `None` rather than re-address by name.
        type Freadlink =
            unsafe extern "C" fn(libc::c_int, *mut libc::c_char, libc::size_t) -> libc::ssize_t;
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"freadlink".as_ptr()) };
        if symbol.is_null() {
            return Ok(None);
        }
        let freadlink: Freadlink = unsafe { std::mem::transmute(symbol) };
        read_link_bytes(|target, capacity| unsafe {
            freadlink(object.as_raw_fd(), target, capacity)
        })
        .map(Some)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = object;
        Ok(None)
    }
}

fn read_link_bytes(mut read: impl FnMut(*mut libc::c_char, usize) -> isize) -> Result<Vec<u8>> {
    let mut capacity = 256usize;
    loop {
        let mut target = Vec::<u8>::with_capacity(capacity);
        let length = read(target.as_mut_ptr().cast(), capacity);
        if length < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("read operator symlink");
        }
        let length = length as usize;
        if length < capacity {
            unsafe { target.set_len(length) };
            return Ok(target);
        }
        capacity = capacity
            .checked_mul(2)
            .filter(|next| *next <= libc::PATH_MAX as usize * 2)
            .context("operator symlink target is too long")?;
    }
}

fn require_operator_identity(
    expected: RootMetadata,
    actual: RootMetadata,
    label: &str,
) -> Result<()> {
    if (actual.dev, actual.ino, actual.file_type())
        != (expected.dev, expected.ino, expected.file_type())
    {
        bail!("{label} changed identity during resolution");
    }
    Ok(())
}

fn require_metadata_identity(
    expected: RootMetadata,
    actual: RootMetadata,
    label: &str,
) -> Result<()> {
    if (actual.dev, actual.ino, actual.file_type())
        != (expected.dev, expected.ino, expected.file_type())
    {
        bail!("{label} changed identity");
    }
    Ok(())
}

fn operator_symlink_owner_is_trusted(owner: u32, euid: u32) -> bool {
    owner == 0 || owner == euid
}

fn open_directory_at(parent: &File, component: &[u8]) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    let access = libc::O_PATH;
    #[cfg(target_os = "macos")]
    let access = libc::O_SEARCH;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let access = libc::O_RDONLY;
    open_at(
        parent.as_raw_fd(),
        &component_cstring(component),
        access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC,
        0,
    )
}

fn open_readable_directory_at(parent: &File, component: &[u8]) -> io::Result<File> {
    open_at(
        parent.as_raw_fd(),
        &component_cstring(component),
        libc::O_RDONLY
            | libc::O_DIRECTORY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_NOCTTY
            | libc::O_CLOEXEC,
        0,
    )
}

fn missing_directory_suffix(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|errno| matches!(errno, libc::ENOENT | libc::ENOTDIR | libc::ELOOP))
    })
}

fn open_at(parent: RawFd, name: &CString, flags: libc::c_int, mode: u32) -> io::Result<File> {
    // `mode_t` is narrower than `int` on some platforms (including macOS),
    // so C's default argument promotions require an `int` in this variadic
    // position. Callers restrict ordinary creation modes before reaching here.
    loop {
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags, mode as libc::c_int) };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn clear_nonblocking(file: &File) -> io::Result<()> {
    let flags = loop {
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags >= 0 {
            break flags;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    if flags & libc::O_NONBLOCK == 0 {
        return Ok(());
    }
    retry_zero(|| unsafe {
        libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK)
    })
}

fn retry_zero(mut operation: impl FnMut() -> libc::c_int) -> io::Result<()> {
    loop {
        if operation() == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn metadata_at(parent: RawFd, name: &CString) -> io::Result<RootMetadata> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    retry_zero(|| unsafe {
        libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW)
    })?;
    Ok(RootMetadata {
        dev: stat_dev(&stat),
        ino: stat.st_ino,
        mode: stat_mode(&stat),
        nlink: stat_nlink(&stat),
        len: stat.st_size as u64,
        mtime: stat_mtime(&stat),
        mtime_nsec: stat_mtime_nsec(&stat),
        ctime: stat_ctime(&stat),
        ctime_nsec: stat_ctime_nsec(&stat),
        uid: stat.st_uid,
        gid: stat.st_gid,
        rdev: stat_rdev(&stat),
    })
}

pub(crate) fn root_metadata_from_std(metadata: &std::fs::Metadata) -> Result<RootMetadata> {
    Ok(RootMetadata {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: u32::try_from(metadata.mtime_nsec()).context("negative mtime nanoseconds")?,
        ctime: metadata.ctime(),
        ctime_nsec: u32::try_from(metadata.ctime_nsec()).context("negative ctime nanoseconds")?,
        uid: metadata.uid(),
        gid: metadata.gid(),
        rdev: metadata.rdev(),
    })
}

fn stat_mtime(stat: &libc::stat) -> i64 {
    stat.st_mtime
}

fn stat_mtime_nsec(stat: &libc::stat) -> u32 {
    stat.st_mtime_nsec as u32
}

fn stat_ctime(stat: &libc::stat) -> i64 {
    stat.st_ctime
}

fn stat_ctime_nsec(stat: &libc::stat) -> u32 {
    stat.st_ctime_nsec as u32
}

#[cfg(target_os = "linux")]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
fn get_errno() -> libc::c_int {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn get_errno() -> libc::c_int {
    unsafe { *libc::__error() }
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

/// `st_nlink` is `u64` on x86-64 Linux, `u32` on AArch64 Linux, and `u16`
/// on macOS, so the cast is only redundant on one of the release targets.
#[allow(clippy::unnecessary_cast)]
fn stat_nlink(stat: &libc::stat) -> u64 {
    stat.st_nlink as u64
}

#[cfg(target_os = "linux")]
fn stat_rdev(stat: &libc::stat) -> u64 {
    stat.st_rdev
}

#[cfg(not(target_os = "linux"))]
fn stat_rdev(stat: &libc::stat) -> u64 {
    stat.st_rdev as u64
}

fn unlink_at(parent: RawFd, name: &CString, flags: libc::c_int) -> io::Result<()> {
    retry_zero(|| unsafe { libc::unlinkat(parent, name.as_ptr(), flags) })
}

fn create_temporary(
    parent: &ResolvedParent,
    create: impl Fn(RawFd, &CString) -> io::Result<()>,
) -> Result<CString> {
    for _ in 0..32 {
        let counter = NEXT_SWAP_NAME.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!(".syq-swap-{}-{counter}", std::process::id()))
            .expect("generated swap name contains no NUL");
        match create(parent.directory.as_raw_fd(), &name) {
            Ok(()) => return Ok(name),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("create replacement sidecar"),
        }
    }
    bail!("could not allocate a replacement sidecar name")
}

#[cfg(target_os = "linux")]
fn rename_exchange(
    old_parent: RawFd,
    old_name: &CString,
    new_parent: RawFd,
    new_name: &CString,
) -> io::Result<()> {
    let result = loop {
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
        if result == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break result;
        }
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
    retry_zero(|| unsafe {
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

fn require_regular(file: &File, path: &RelativePath) -> Result<()> {
    if !file.metadata()?.is_file() {
        bail!("confined path {} is not a regular file", path.label());
    }
    Ok(())
}

fn is_safe_staged_identity(metadata: RootMetadata, expected_dev: u64, expected_ino: u64) -> bool {
    metadata.is_file()
        && metadata.nlink == 1
        && metadata.dev == expected_dev
        && metadata.ino == expected_ino
}

fn is_safe_staged_identity_after_link(
    metadata: RootMetadata,
    expected_dev: u64,
    expected_ino: u64,
) -> bool {
    metadata.is_file()
        && metadata.nlink == 2
        && metadata.dev == expected_dev
        && metadata.ino == expected_ino
}

fn require_safe_staged_identity(
    metadata: RootMetadata,
    expected_dev: u64,
    expected_ino: u64,
    path: &RelativePath,
) -> Result<()> {
    if !is_safe_staged_identity(metadata, expected_dev, expected_ino) {
        bail!(
            "confined staged path {} is not the expected singly-linked regular file",
            path.label()
        );
    }
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum PublicationTestPoint {
    AfterAnyRename,
    AfterAbsentLink,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PublicationTestHookKey {
    root: RootIdentity,
    target: RelativePath,
    point: PublicationTestPoint,
}

#[cfg(test)]
type PublicationTestAction = Box<dyn FnOnce() + Send + 'static>;

#[cfg(test)]
fn publication_test_hooks() -> &'static std::sync::Mutex<
    std::collections::HashMap<PublicationTestHookKey, PublicationTestAction>,
> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PublicationTestHookKey, PublicationTestAction>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
struct PublicationTestHookGuard(PublicationTestHookKey);

#[cfg(test)]
impl Drop for PublicationTestHookGuard {
    fn drop(&mut self) {
        publication_test_hooks()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.0);
    }
}

#[cfg(test)]
fn install_publication_test_hook(
    root: RootIdentity,
    target: &RelativePath,
    point: PublicationTestPoint,
    action: impl FnOnce() + Send + 'static,
) -> PublicationTestHookGuard {
    let key = PublicationTestHookKey {
        root,
        target: target.clone(),
        point,
    };
    let previous = publication_test_hooks()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(key.clone(), Box::new(action));
    assert!(previous.is_none(), "duplicate publication test hook");
    PublicationTestHookGuard(key)
}

#[cfg(test)]
fn run_publication_test_hook(
    root: RootIdentity,
    target: &RelativePath,
    point: PublicationTestPoint,
) {
    let key = PublicationTestHookKey {
        root,
        target: target.clone(),
        point,
    };
    let action = publication_test_hooks()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&key);
    if let Some(action) = action {
        action();
    }
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
    use std::process::Command;
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
    fn operator_resolver_selects_a_last_component_symlink_without_following_it() {
        let tree = TestDir::new("operator-leaf-link");
        let outside = tree.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        let selected = tree.path().join("selected");
        symlink(&outside, &selected).unwrap();
        let original = fs::symlink_metadata(&selected).unwrap();

        let base = File::open(tree.path()).unwrap();
        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        let mut hops = Vec::new();
        let result = resolver
            .resolve(
                b"selected",
                OperatorFinalComponent::Entry {
                    follow_symlink: false,
                },
                false,
                &mut hops,
            )
            .unwrap();
        let PinnedPath::Leaf(leaf) = result else {
            panic!("last-component symlink was not selected as a leaf");
        };
        assert!(leaf.metadata().is_symlink());
        let (_, name, _, object) = leaf.into_parts();
        assert_eq!(name.as_bytes(), b"selected");
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let object = object.expect("supported platform should pin the symlink object");
            fs::rename(&selected, tree.path().join("moved")).unwrap();
            symlink("replacement", &selected).unwrap();
            let pinned = object.metadata().unwrap();
            let replacement = fs::symlink_metadata(&selected).unwrap();
            assert_eq!(
                (pinned.dev(), pinned.ino()),
                (original.dev(), original.ino())
            );
            assert_ne!(
                (pinned.dev(), pinned.ino()),
                (replacement.dev(), replacement.ino())
            );
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(object.is_none());
        assert!(hops.is_empty());
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
    }

    #[test]
    fn operator_resolver_follows_only_components_requested_by_the_caller() {
        let tree = TestDir::new("operator-follow");
        let real = tree.path().join("real");
        fs::create_dir(&real).unwrap();
        let outside = tree.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink("real", tree.path().join("container")).unwrap();
        symlink(&outside, real.join("leaf")).unwrap();
        let base = File::open(tree.path()).unwrap();

        let mut hops = Vec::new();
        let refusing =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        assert!(refusing
            .resolve(
                b"container/leaf",
                OperatorFinalComponent::Entry {
                    follow_symlink: false,
                },
                false,
                &mut hops,
            )
            .is_err());

        let following =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::FollowAll).unwrap();
        let result = following
            .resolve(
                b"container/leaf",
                OperatorFinalComponent::Entry {
                    follow_symlink: false,
                },
                false,
                &mut hops,
            )
            .unwrap();
        let PinnedPath::Leaf(leaf) = result else {
            panic!("last-component symlink was unexpectedly followed");
        };
        assert!(leaf.metadata().is_symlink());
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].component, b"container");
        assert_eq!(hops[0].target, b"real");
    }

    #[test]
    fn operator_resolver_reports_the_missing_suffix_from_a_retained_parent() {
        let tree = TestDir::new("operator-missing");
        let base = File::open(tree.path()).unwrap();
        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        let mut hops = Vec::new();
        let result = resolver
            .resolve(
                b"new/nested",
                OperatorFinalComponent::Directory,
                true,
                &mut hops,
            )
            .unwrap();
        let PinnedPath::Missing(missing) = result else {
            panic!("missing suffix was not returned");
        };
        let (directory, components) = missing.into_parts();
        let metadata = directory.metadata().unwrap();
        let expected = fs::metadata(tree.path()).unwrap();
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (expected.dev(), expected.ino())
        );
        assert_eq!(
            components,
            VecDeque::from([b"new".to_vec(), b"nested".to_vec()])
        );
        assert!(hops.is_empty());
    }

    #[test]
    fn operator_symlink_trust_is_root_or_receiver_ownership() {
        assert!(operator_symlink_owner_is_trusted(0, 1000));
        assert!(operator_symlink_owner_is_trusted(1000, 1000));
        assert!(!operator_symlink_owner_is_trusted(1001, 1000));
        assert!(!operator_symlink_owner_is_trusted(1000, 0));
    }

    #[test]
    fn confined_operator_resolver_rejects_relative_and_absolute_link_escapes() {
        let tree = TestDir::new("operator-confined");
        let base_path = tree.path().join("base");
        let outside = tree.path().join("outside");
        fs::create_dir(&base_path).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink("../outside", base_path.join("relative")).unwrap();
        symlink(&outside, base_path.join("absolute")).unwrap();
        let base = File::open(&base_path).unwrap();
        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::FollowAll).unwrap();

        let mut hops = Vec::new();
        assert!(resolver
            .resolve(
                b"/absolute-input",
                OperatorFinalComponent::Directory,
                false,
                &mut hops,
            )
            .is_err());

        for selected in [&b"relative"[..], &b"absolute"[..]] {
            let mut hops = Vec::new();
            assert!(resolver
                .resolve(
                    selected,
                    OperatorFinalComponent::Directory,
                    false,
                    &mut hops,
                )
                .is_err());
        }
    }

    #[test]
    fn selected_operator_directory_remains_pinned_after_rename() {
        let tree = TestDir::new("operator-directory-pin");
        let selected = tree.path().join("selected");
        fs::create_dir(&selected).unwrap();
        let original = fs::metadata(&selected).unwrap();
        let base = File::open(tree.path()).unwrap();
        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        let mut hops = Vec::new();
        let result = resolver
            .resolve(
                b"selected/.",
                OperatorFinalComponent::Directory,
                false,
                &mut hops,
            )
            .unwrap();
        let PinnedPath::Directory(directory) = result else {
            panic!("directory was not selected");
        };

        fs::rename(&selected, tree.path().join("moved")).unwrap();
        fs::create_dir(&selected).unwrap();
        let replacement = fs::metadata(&selected).unwrap();
        let (directory, entry) = directory.into_parts();
        let pinned = directory.metadata().unwrap();
        assert_eq!(
            (pinned.dev(), pinned.ino()),
            (original.dev(), original.ino())
        );
        assert_ne!(
            (pinned.dev(), pinned.ino()),
            (replacement.dev(), replacement.ino())
        );
        assert!(entry.is_some());
    }

    #[test]
    fn operator_resolver_handles_deep_path_with_low_fd_limit() {
        const CHILD_ENV: &str = "SYQ_TEST_OPERATOR_RESOLVER_LOW_FD_CHILD";
        const TEST_NAME: &str =
            "rooted::tests::operator_resolver_handles_deep_path_with_low_fd_limit";

        if std::env::var_os(CHILD_ENV).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success(), "low-FD resolver subprocess failed");
            return;
        }

        let tree = TestDir::new("operator-low-fd");
        let path = (0..40)
            .map(|index| format!("component-{index:02}"))
            .collect::<Vec<_>>()
            .join("/");
        fs::create_dir_all(tree.path().join(&path)).unwrap();
        let base = File::open(tree.path()).unwrap();

        let mut limits: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
            0
        );
        assert!(
            limits.rlim_max >= 64,
            "hard file-descriptor limit is below 64"
        );
        limits.rlim_cur = 64;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);

        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        let result = resolver
            .resolve(
                path.as_bytes(),
                OperatorFinalComponent::Directory,
                false,
                &mut Vec::new(),
            )
            .unwrap();
        let PinnedPath::Directory(directory) = result else {
            panic!("deep directory was not selected");
        };
        assert!(directory.metadata().is_dir());
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
    fn opened_directory_apis_reject_non_component_names() {
        let tree = TestDir::new("opened-directory-name");
        let root = Root::open(tree.path()).unwrap();
        let empty = relative(b"");
        let directory = root.open_directory(&empty).unwrap();
        let expected = root.metadata(&empty).unwrap();

        for unsafe_name in [
            &b""[..],
            &b"."[..],
            &b".."[..],
            &b"child/grandchild"[..],
            &b"nul\0name"[..],
        ] {
            assert!(root.metadata_in_directory(&directory, unsafe_name).is_err());
            assert!(root
                .read_link_in_directory(&directory, unsafe_name)
                .is_err());
            assert!(root
                .open_child_directory_verified(&directory, unsafe_name, expected)
                .is_err());
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
    fn adopted_operator_descriptor_stays_stable_and_can_be_enumerated_repeatedly() {
        let tree = TestDir::new("adopted-root");
        let selected = tree.path().join("selected");
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("first"), b"first").unwrap();
        fs::write(selected.join("second"), b"second").unwrap();
        let pinned = OperatorResolver::resolve_process(
            selected.as_os_str().as_bytes(),
            OperatorSymlinkPolicy::Refuse,
            OperatorFinalComponent::Directory,
            false,
            &mut Vec::new(),
        )
        .unwrap();
        let PinnedPath::Directory(directory) = pinned else {
            panic!("operator directory was not pinned");
        };
        let root = Root::from_directory(directory.into_parts().0).unwrap();

        fs::rename(&selected, tree.path().join("moved")).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("replacement"), b"replacement").unwrap();

        let mut first = root.read_directory(&relative(b"")).unwrap();
        let mut second = root.read_directory(&relative(b"")).unwrap();
        first.sort();
        second.sort();
        assert_eq!(first, [b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(second, first);
        assert!(root.metadata(&relative(b"replacement")).is_err());
    }

    #[test]
    fn descendant_traversal_needs_search_but_not_read_permission() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tree = TestDir::new("search-only");
        let child = tree.path().join("child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("file"), b"contents").unwrap();
        let root = Root::open(tree.path()).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o111)).unwrap();

        let metadata = root.metadata(&relative(b"child/file")).unwrap();
        assert!(metadata.is_file());
        let mut file = root.open_regular_read(&relative(b"child/file")).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"contents");

        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
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
    fn any_publication_never_rolls_back_a_later_writer() {
        let tree = TestDir::new("any-publication-race");
        let root = Root::open(tree.path()).unwrap();
        let staged = relative(b"staged");
        let target = relative(b"target");
        fs::write(tree.path().join("staged"), b"staged").unwrap();
        fs::write(tree.path().join("target"), b"old").unwrap();
        let staged_file = File::open(tree.path().join("staged")).unwrap();
        let metadata = staged_file.metadata().unwrap();

        let target_path = tree.path().join("target");
        let _hook = install_publication_test_hook(
            root.identity(),
            &target,
            PublicationTestPoint::AfterAnyRename,
            move || {
                fs::remove_file(&target_path).unwrap();
                fs::write(&target_path, b"later").unwrap();
            },
        );
        let error = root
            .rename_regular_if_same(&staged, &target, (metadata.dev(), metadata.ino()))
            .unwrap_err();

        assert!(format!("{error:#}").contains("changed during publication"));
        assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"later");
        assert!(!tree.path().join("staged").exists());
        assert_eq!(metadata.ino(), staged_file.metadata().unwrap().ino());
    }

    #[test]
    fn absent_publication_never_unlinks_a_later_writer() {
        let tree = TestDir::new("absent-publication-race");
        let root = Root::open(tree.path()).unwrap();
        let staged = relative(b"staged");
        let target = relative(b"target");
        fs::write(tree.path().join("staged"), b"staged").unwrap();
        let metadata = fs::metadata(tree.path().join("staged")).unwrap();

        let target_path = tree.path().join("target");
        let _hook = install_publication_test_hook(
            root.identity(),
            &target,
            PublicationTestPoint::AfterAbsentLink,
            move || {
                fs::remove_file(&target_path).unwrap();
                fs::write(&target_path, b"later").unwrap();
            },
        );
        let error = root
            .publish_new_regular(&staged, &target, (metadata.dev(), metadata.ino()))
            .unwrap_err();

        assert!(format!("{error:#}").contains("changed during publication"));
        assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"later");
        assert_eq!(fs::read(tree.path().join("staged")).unwrap(), b"staged");
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
