//! Root-anchored filesystem primitives for guarded receivers.
//!
//! `Root` follows the explicitly selected root path once, opens that directory,
//! and uses only the resulting descriptor afterward. Descendant paths are raw
//! Unix bytes split into validated relative components. The kernel resolves
//! each intermediate component without following symlinks, and leaf operations
//! are performed relative to a held parent descriptor. There is no pathname
//! fallback.
//!
//! Native guarded placements and signed receivers use these operations for
//! descendant mutation and inspection; the unrestricted implementation remains
//! separate. Existing roots, directory scans, regular-file I/O, leaf
//! creation/replacement, metadata, and non-recursive unlink/rmdir are supported.
//! Recursive removal and missing-root creation stay outside this layer.
//! Traversal uses search-only descriptors where the platform provides them;
//! directory enumeration separately opens an independent readable descriptor.
//!
//! Linux uses `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` to
//! resolve a validated path and open its directory or regular-file leaf in
//! one syscall. Kernels or
//! sandboxes without that syscall retain the same component-by-component
//! descriptor walk used on other Unix platforms; neither path falls back to
//! an unconfined pathname.
//!
//! The guarantee is pathname confinement. A hard link beneath the root may
//! still refer to an inode with another name outside the root. As with all
//! descriptor-based traversal, an already-open descendant remains the selected
//! object if another process subsequently renames it.

#[cfg(target_os = "macos")]
use crate::fsops::CopyLocalOutcome;
use crate::proto::OperatorSymlinkPolicy;
use crate::sys::{
    absent_or_nondirectory, directory_names, get_errno, open_at, retry_zero, set_errno, stat_dev,
    stat_mode, COMMON_NAME_MAX, MODE_DIRECTORY, MODE_FIFO, MODE_REGULAR, MODE_SYMLINK,
    MODE_TYPE_MASK, NAME_MAX_CACHE_CAP,
};
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(all(test, target_os = "macos"))]
#[path = "../tests/support/macos_clone.rs"]
mod macos_clone_support;

#[cfg(any(target_os = "linux", test))]
mod directory_gate;
mod operator;

pub(crate) use operator::*;

static NEXT_SWAP_NAME: AtomicU64 = AtomicU64::new(0);

pub(crate) const OPERATOR_SYMLINK_FOLLOW_ADVICE: &str = "pass --follow-src for source paths, --follow-dst for destination paths, or --follow for all directly supplied filesystem paths";

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
    pub(crate) atime: crate::inode_metadata::Timestamp,
    pub(crate) ctime: i64,
    pub(crate) ctime_nsec: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) rdev: u64,
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

    pub(crate) fn is_fifo(self) -> bool {
        self.mode & MODE_TYPE_MASK == MODE_FIFO
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

/// Marks the lifetime of a scheduler-owned namespace burst. This only skips
/// redundant legacy admission; all confined resolution and identity checks run.
pub(crate) struct MutationBurst {
    #[cfg(any(target_os = "linux", test))]
    _scope: directory_gate::Burst,
}
impl MutationBurst {
    pub(crate) fn enter() -> Self {
        Self {
            #[cfg(any(target_os = "linux", test))]
            _scope: directory_gate::Burst::enter(),
        }
    }
}

/// An existing directory opened once as the authority boundary.
pub(crate) struct Root {
    directory: File,
    identity: RootIdentity,
    #[cfg(target_os = "linux")]
    partial_name_limits: OnceLock<Mutex<HashMap<Vec<Vec<u8>>, usize>>>,
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) test_name_limit: std::sync::atomic::AtomicUsize,
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) test_name_queries: std::sync::atomic::AtomicUsize,
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
            #[cfg(target_os = "linux")]
            partial_name_limits: OnceLock::new(),
            #[cfg(all(test, target_os = "linux"))]
            test_name_limit: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(all(test, target_os = "linux"))]
            test_name_queries: std::sync::atomic::AtomicUsize::new(0),
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

    #[cfg(any(target_os = "linux", test))]
    fn mutation_permit(&self, path: &RelativePath) -> Result<directory_gate::Permit> {
        let (parents, _) = path.leaf()?;
        Ok(directory_gate::acquire(self.identity, parents))
    }

    pub(crate) fn identity(&self) -> RootIdentity {
        self.identity
    }

    /// Borrow the selected root during a caller-owned descriptor transfer.
    pub(crate) fn directory_descriptor(&self) -> &File {
        &self.directory
    }

    /// Open the root or a descendant directory without following any
    /// descendant symlink.
    pub(crate) fn open_directory(&self, path: &RelativePath) -> Result<File> {
        open_directory_components(&self.directory, &path.components)
            .with_context(|| format!("open confined directory {}", path.label()))
    }

    /// Open the longest directory prefix without following a descendant
    /// symlink. The count identifies how many components that prefix consumed.
    /// A component that is missing, is not a directory, or cannot be inspected
    /// ends the walk so best-effort callers can use the retained ancestor.
    pub(crate) fn open_nearest_directory(&self, path: &RelativePath) -> Result<(File, usize)> {
        let mut directory = self.directory.try_clone().context("duplicate root fd")?;
        let mut consumed = 0;
        for component in &path.components {
            let Ok(next) = open_operator_directory_at(&directory, component) else {
                break;
            };
            directory = next;
            consumed += 1;
        }
        Ok((directory, consumed))
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
                DirectoryHandle::Borrowed(&self.directory),
                component_cstring(b"."),
            )
        } else {
            let parent = self.resolve_parent(path)?;
            (parent.directory, parent.leaf)
        };
        ResolvedParent {
            directory: parent,
            leaf,
        }
        .open_metadata()
        .with_context(|| format!("open confined metadata handle {}", path.label()))
    }

    // The Linux syscall resolves the parent and opens the leaf under the same
    // no-symlink restrictions, without allocating a temporary parent fd. Keep
    // the descriptor walk for unsupported syscalls and paths it cannot handle
    // (for example, paths longer than a single syscall accepts).
    fn open_leaf(&self, path: &RelativePath, flags: libc::c_int, mode: u32) -> Result<File> {
        #[cfg(all(test, target_os = "linux"))]
        self.check_test_name_limit(path)?;
        path.leaf()?;
        #[cfg(target_os = "linux")]
        match open_components_openat2(&self.directory, &path.components, flags, mode) {
            Ok(file) => return Ok(file),
            Err(error) if expected_open_failure(&error) => return Err(error.into()),
            Err(_) => {}
        }
        let parent = self.resolve_parent(path)?;
        open_at(parent.directory.as_raw_fd(), &parent.leaf, flags, mode).map_err(Into::into)
    }

    fn open_regular(
        &self,
        path: &RelativePath,
        access: libc::c_int,
        truncate: bool,
    ) -> Result<File> {
        let file = self
            .open_leaf(
                path,
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
        #[cfg(any(target_os = "linux", test))]
        let permit = self.mutation_permit(path)?;
        // O_CREAT | O_EXCL either creates a new regular file or fails. Unlike
        // opening an existing leaf, this cannot open a FIFO/device or follow a
        // raced symlink, so no nonblocking flag or file-type check is needed.
        let file = self
            .open_leaf(
                path,
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
                mode & 0o777,
            )
            .with_context(|| format!("create confined file {}", path.label()))?;
        #[cfg(any(target_os = "linux", test))]
        drop(permit);
        Ok(file)
    }

    /// Create an ACL-copy sidecar without ever exposing a readable file through
    /// an inherited ACL. Clearing an ACL after file creation would leave a window
    /// in which another account could open it and retain access to later writes.
    #[cfg(target_os = "macos")]
    pub(crate) fn create_private_file(&self, path: &RelativePath) -> Result<File> {
        let parent = self.resolve_parent(path)?;
        match metadata_at(parent.directory.as_raw_fd(), &parent.leaf) {
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let temporary = create_temporary(&parent, |fd, name| {
            retry_zero(|| unsafe { libc::mkdirat(fd, name.as_ptr(), 0o700) })
        })?;
        let leaf = c"data";
        let mut held_directory = None;
        let result = (|| -> Result<File> {
            // Event-only access lets the owner repair an empty directory even
            // when umask removed search permission. Descendant creation below
            // still requires search access after its permissions are restored.
            let directory = open_at(
                parent.directory.as_raw_fd(),
                &temporary,
                libc::O_EVTONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )?;
            let metadata = directory.metadata()?;
            anyhow::ensure!(
                metadata.uid() == unsafe { libc::geteuid() },
                "staging directory owner changed"
            );
            held_directory = Some(directory);
            let directory = held_directory.as_ref().unwrap();
            // Preserve the destination parent's setgid inheritance.
            let mode = 0o700 | (metadata.mode() & 0o2000);
            crate::inode_metadata::make_staging_private(directory, mode)?;
            anyhow::ensure!(
                directory.metadata()?.mode() & 0o777 == 0o700
                    && crate::inode_metadata::staging_acl_is_empty(directory)?,
                "filesystem cannot make an ACL staging directory private"
            );
            // No file exists until the directory is private. Holding a directory
            // fd from before the ACL change does not bypass child search checks.
            let file = open_at(
                directory.as_raw_fd(),
                leaf,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            retry_zero(|| unsafe {
                libc::renameatx_np(
                    directory.as_raw_fd(),
                    leaf.as_ptr(),
                    parent.directory.as_raw_fd(),
                    parent.leaf.as_ptr(),
                    libc::RENAME_EXCL,
                )
            })?;
            Ok(file)
        })();
        let cleanup = (|| -> Result<()> {
            if result.is_err() {
                if let Some(directory) = held_directory.as_ref() {
                    match unlink_at(directory.as_raw_fd(), leaf, 0) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error).context("remove unpublished ACL stage"),
                    }
                }
            }
            unlink_at(parent.directory.as_raw_fd(), &temporary, libc::AT_REMOVEDIR)
                .context("remove private ACL staging directory")
        })();
        match (result, cleanup) {
            (Err(error), Err(cleanup)) => {
                Err(error.context(format!("ACL staging cleanup failed: {cleanup:#}")))
            }
            (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
            (Ok(file), Ok(())) => Ok(file),
        }
    }

    /// Clone data into a new private sidecar, removing copied xattrs and user
    /// flags to match byte-copy metadata behavior.
    /// The private directory hides the source mode until it has been normalized.
    #[cfg(target_os = "macos")]
    pub(crate) fn clone_file(
        &self,
        source: &File,
        source_metadata: &std::fs::Metadata,
        path: &RelativePath,
        size: u64,
    ) -> Result<CopyLocalOutcome> {
        if !clone_flags_can_be_removed(source_metadata) {
            return Ok(CopyLocalOutcome::Unsupported);
        }
        let fallback = |error: anyhow::Error| {
            if crate::output::debug() {
                crate::output::diagnostic!(
                    "syq: clone {} unavailable; using byte copying: {error:#}",
                    path.label()
                );
            }
            Ok(CopyLocalOutcome::Unsupported)
        };
        let parent = match self.resolve_parent(path) {
            Ok(parent) => parent,
            Err(error) => return fallback(error),
        };
        // Reuse the held parent for the partial check and clone publication.
        // RENAME_EXCL below also protects a partial created after this check.
        match metadata_at(parent.directory.as_raw_fd(), &parent.leaf) {
            Ok(_) => return Ok(CopyLocalOutcome::Unsupported),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return fallback(error.into()),
        }
        // Inspect the actual destination parent: a descendant mount can differ
        // from the root, and a device number can be reused after a remount.
        let parent_metadata = match parent.directory.metadata() {
            Ok(metadata) => metadata,
            Err(error) => return fallback(error.into()),
        };
        if source_metadata.dev() != parent_metadata.dev() {
            return Ok(CopyLocalOutcome::Unsupported);
        }
        // Reject non-APFS destinations before inspecting ACLs or staging data.
        let supported = match filesystem_is(&parent.directory, b"apfs") {
            Ok(supported) => supported,
            Err(error) => {
                return fallback(anyhow::Error::new(error).context("inspect clone filesystem"));
            }
        };
        #[cfg(debug_assertions)]
        let supported =
            supported && std::env::var_os("SYQ_TEST_CLONE_UNSUPPORTED_VOLUME").is_none();
        if !supported {
            return Ok(CopyLocalOutcome::Unsupported);
        }
        // An extra staging directory must not change destination ACL inheritance.
        match clone_directory_has_no_inheritable_acl(&parent.directory) {
            Ok(true) => {}
            Ok(false) => return Ok(CopyLocalOutcome::Unsupported),
            Err(error) => return fallback(error),
        }
        let temporary = match create_temporary(&parent, |fd, name| {
            #[cfg(debug_assertions)]
            fail_clone_for_test("SYQ_TEST_CLONE_MKDIR_ERROR")?;
            retry_zero(|| unsafe { libc::mkdirat(fd, name.as_ptr(), 0o700) })
        }) {
            Ok(temporary) => temporary,
            Err(error) => return fallback(error.context("create private clone directory")),
        };
        let leaf = c"data";
        let mut trusted_directory = None;
        let result = (|| -> Result<CopyLocalOutcome> {
            #[cfg(debug_assertions)]
            fail_clone_for_test("SYQ_TEST_FAIL_CLONE_AFTER_MKDIR")
                .context("test clone directory failure")?;
            // Open with search access, then restore owner permissions on the
            // empty directory. If umask also removed search access, opening can
            // fail; cleanup below still removes it before byte copying begins.
            let directory = open_directory_at(&parent.directory, temporary.as_bytes())
                .context("open private clone directory")?;
            let metadata = directory.metadata()?;
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Ok(CopyLocalOutcome::Unsupported);
            }
            // Preserve inherited setgid while restoring owner access.
            let private_mode = 0o700 | (metadata.mode() as libc::mode_t & 0o2000);
            retry_zero(|| unsafe { libc::fchmod(directory.as_raw_fd(), private_mode) })
                .context("set private clone directory permissions")?;
            #[cfg(debug_assertions)]
            make_clone_directory_public_for_test(&directory)?;
            if directory.metadata()?.mode() & 0o7777 != u32::from(private_mode) {
                // Some filesystems synthesize permissions. Fall back without
                // putting source data into a directory we cannot keep private.
                return Ok(CopyLocalOutcome::Unsupported);
            }
            trusted_directory = Some(directory);
            let directory = trusted_directory.as_ref().unwrap();
            // CLONE_NOOWNERCOPY from <sys/clonefile.h>; libc exposes the
            // function but not this constant. Do not request source ACLs.
            const CLONE_NOOWNERCOPY: u32 = 0x0002;
            #[cfg(debug_assertions)]
            record_clone_attempt_for_test().context("clone local file")?;
            let cloned = unsafe {
                libc::fclonefileat(
                    source.as_raw_fd(),
                    directory.as_raw_fd(),
                    leaf.as_ptr(),
                    CLONE_NOOWNERCOPY,
                )
            };
            if cloned != 0 {
                // The device/filesystem probe established volume eligibility.
                // Even an unsupported errno here may describe just this inode;
                // it must not disable cloning for other files on the volume.
                return Err(io::Error::last_os_error()).context("clone local file");
            }
            // Clear inherited flags before chmod or opening another descriptor:
            // descriptor pressure must not leave an immutable, undeletable clone.
            // The private directory and fixed leaf keep this operation confined.
            clear_clone_flags_at(directory, leaf)?;
            retry_zero(|| unsafe {
                libc::fchmodat(
                    directory.as_raw_fd(),
                    leaf.as_ptr(),
                    0o600,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })
            .context("set private clone permissions")?;
            let file = open_clone_for_copy(directory, leaf).context("open normalized clone")?;
            if !strip_clone_xattrs(&file)? {
                return Ok(CopyLocalOutcome::Unsupported);
            }
            if file.metadata()?.len() != size {
                // Streaming and the final source re-stat handle concurrent
                // growth/shrinkage using the same retry policy as other copies.
                return Ok(CopyLocalOutcome::Unsupported);
            }
            #[cfg(debug_assertions)]
            fail_clone_for_test("SYQ_TEST_FAIL_CLONE_AFTER_CREATE")
                .context("test clone failure")?;
            retry_zero(|| unsafe { libc::futimens(file.as_raw_fd(), std::ptr::null()) })?;
            // Do not replace an existing resumable partial, including one that
            // appeared after the caller checked. Both directory fds stay pinned.
            let published = unsafe {
                libc::renameatx_np(
                    directory.as_raw_fd(),
                    leaf.as_ptr(),
                    parent.directory.as_raw_fd(),
                    parent.leaf.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            if published != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    return Ok(CopyLocalOutcome::Unsupported);
                }
                return Err(error).context("stage cloned local file");
            }
            Ok(CopyLocalOutcome::Copied)
        })();
        let cleanup = (|| -> Result<()> {
            if let Some(directory) =
                trusted_directory.filter(|_| !matches!(result, Ok(CopyLocalOutcome::Copied)))
            {
                match unlink_at(directory.as_raw_fd(), leaf, 0) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("remove unpublished clone"),
                }
            }
            // Also runs when opening or checking the new directory failed.
            // rmdir cannot traverse a replacement or delete its contents.
            #[cfg(debug_assertions)]
            fail_clone_for_test("SYQ_TEST_FAIL_CLONE_RMDIR")
                .context("test clone staging rmdir failure")?;
            unlink_at(parent.directory.as_raw_fd(), &temporary, libc::AT_REMOVEDIR)
                .context("remove private clone directory")
        })();
        #[cfg(debug_assertions)]
        let cleanup = cleanup.and_then(|()| {
            fail_clone_for_test("SYQ_TEST_FAIL_CLONE_CLEANUP").context("test clone cleanup failure")
        });
        match (result, cleanup) {
            (Err(copy_error), Err(cleanup_error)) => {
                let original = format!("{copy_error:#}");
                Err(copy_error.context(format!(
                    "{original}; additionally, clone cleanup failed: {cleanup_error:#}"
                )))
            }
            // Publication here only names the resumable partial, not the final
            // destination. Keep cleanup failure visible; rerunning verifies and
            // finishes that partial through the ordinary resume path.
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            // Cloning is optional, but falling back is safe only once its
            // unpublished data and private directory have been removed.
            (Err(copy_error), Ok(())) => fallback(copy_error),
            (Ok(outcome), Ok(())) => Ok(outcome),
        }
    }

    /// Create exactly one directory. Parents must already exist and be real
    /// directories beneath this root.
    pub(crate) fn create_directory(&self, path: &RelativePath, mode: u32) -> Result<()> {
        self.resolve_parent(path)?
            .create_directory(mode)
            .with_context(|| format!("create confined directory {}", path.label()))
    }

    /// Create any missing parents of `path`, walking only through real
    /// directories retained beneath this root. Concurrent creators are
    /// accepted only when the resulting component opens as a directory.
    pub(crate) fn create_missing_parents(&self, path: &RelativePath, mode: u32) -> Result<()> {
        self.resolve_parent_creating(path, mode).map(drop)
    }

    /// Keep the parent opened while creating missing ancestors so the caller
    /// can create the leaf without resolving and opening that parent again.
    pub(crate) fn resolve_parent_creating(
        &self,
        path: &RelativePath,
        mode: u32,
    ) -> Result<ResolvedParent<'_>> {
        let (parents, leaf) = path.leaf()?;
        if parents.is_empty() {
            return self.resolve_parent(path);
        }
        #[cfg(all(test, target_os = "linux"))]
        self.check_test_name_limit(path)?;
        if let Ok(directory) = open_directory_components_fast(&self.directory, parents) {
            return Ok(ResolvedParent {
                directory: DirectoryHandle::Owned(directory),
                leaf: component_cstring(leaf),
            });
        }
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
        Ok(ResolvedParent {
            directory: DirectoryHandle::Owned(directory),
            leaf: component_cstring(leaf),
        })
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
        directory_names(readable).context("read confined directory")
    }

    /// Start with the common Linux limit, independent of previous failures.
    /// Some filesystems report a conservative limit but accept longer names;
    /// learning a limit must not change a name that already opened successfully.
    pub(crate) fn partial_name_max(&self, path: &RelativePath) -> Result<usize> {
        path.leaf()?;
        #[cfg(target_os = "linux")]
        {
            Ok(COMMON_NAME_MAX)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.name_max_for_parent(path)
        }
    }

    /// Query or reuse the smaller limit only after ENAMETOOLONG. The cache
    /// belongs to this retained root, so separate mount views cannot share it.
    pub(crate) fn rejected_partial_name_max(&self, path: &RelativePath) -> Result<usize> {
        #[cfg(target_os = "linux")]
        {
            let (parents, _) = path.leaf()?;
            if let Some(limit) = self
                .partial_name_limits
                .get()
                .and_then(|limits| limits.lock().unwrap().get(parents).copied())
            {
                return Ok(limit);
            }
        }
        let actual = self.name_max_for_parent(path)?;
        #[cfg(target_os = "linux")]
        if actual < COMMON_NAME_MAX {
            let (parents, _) = path.leaf()?;
            let mut limits = self
                .partial_name_limits
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .unwrap();
            if limits.len() >= NAME_MAX_CACHE_CAP {
                limits.clear();
            }
            limits.insert(parents.to_vec(), actual);
        }
        Ok(actual)
    }

    #[cfg(all(test, target_os = "linux"))]
    fn check_test_name_limit(&self, path: &RelativePath) -> Result<()> {
        let limit = self.test_name_limit.load(Ordering::Relaxed);
        if limit != 0 && path.components.iter().any(|part| part.len() > limit) {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG).into());
        }
        Ok(())
    }

    /// Component limit for a sidecar beside `path`. Missing or non-directory
    /// suffixes are walked back to the nearest existing real directory, never
    /// through a symlink.
    pub(crate) fn name_max_for_parent(&self, path: &RelativePath) -> Result<usize> {
        #[cfg(all(test, target_os = "linux"))]
        {
            self.test_name_queries.fetch_add(1, Ordering::Relaxed);
            let limit = self.test_name_limit.load(Ordering::Relaxed);
            if limit != 0 {
                return Ok(limit);
            }
        }
        static CACHE: OnceLock<Mutex<HashMap<u64, usize>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        self.name_max_for_parent_cached(path, cache, &|directory| {
            set_errno(0);
            let limit = unsafe { libc::fpathconf(directory.as_raw_fd(), libc::_PC_NAME_MAX) };
            if limit > 0 {
                return Ok(limit as usize);
            }
            let errno = get_errno();
            if errno == 0 {
                return Ok(COMMON_NAME_MAX);
            }
            Err(io::Error::from_raw_os_error(errno))
                .context("query confined directory component limit")
        })
    }

    fn name_max_for_parent_cached(
        &self,
        path: &RelativePath,
        cache: &Mutex<HashMap<u64, usize>>,
        query: &impl Fn(&File) -> Result<usize>,
    ) -> Result<usize> {
        let (parents, _) = path.leaf()?;
        let mut components = parents.to_vec();
        loop {
            let candidate = RelativePath {
                components: components.clone(),
            };
            #[cfg(not(target_os = "macos"))]
            let directory = if candidate.is_empty() {
                Ok(DirectoryHandle::Borrowed(&self.directory))
            } else {
                self.open_directory(&candidate).map(DirectoryHandle::Owned)
            };
            #[cfg(target_os = "macos")]
            let directory = if candidate.is_empty() {
                Ok(DirectoryHandle::Borrowed(&self.directory))
            } else {
                self.resolve_parent(&candidate).and_then(|parent| {
                    open_directory_metadata_at(&parent.directory, parent.leaf.as_bytes())
                        .map(DirectoryHandle::Owned)
                        .map_err(anyhow::Error::from)
                })
            };
            match directory {
                Ok(directory) => {
                    // The retained root's device cannot change while its
                    // descriptor is open. Only newly opened descendants need
                    // another stat to identify their filesystem.
                    let device = match &directory {
                        DirectoryHandle::Borrowed(_) => self.identity.dev,
                        DirectoryHandle::Owned(directory) => directory.metadata()?.dev(),
                    };
                    // Serialize the first query too: PartialPaths resolves a
                    // batch in parallel, and every worker must reuse the first
                    // fpathconf result instead of issuing the same filesystem
                    // round trip concurrently.
                    let mut cache = cache.lock().unwrap();
                    if let Some(limit) = cache.get(&device).copied() {
                        return Ok(limit);
                    }
                    let limit = query(&directory)?;
                    if cache.len() >= NAME_MAX_CACHE_CAP {
                        cache.clear();
                    }
                    cache.insert(device, limit);
                    return Ok(limit);
                }
                Err(error) if absent_or_nondirectory(&error) && !components.is_empty() => {
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
        let (directory, leaf) = if path.is_empty() {
            (
                DirectoryHandle::Borrowed(&self.directory),
                component_cstring(b"."),
            )
        } else {
            let parent = self
                .resolve_parent(path)
                .map_err(|error| io::Error::other(format!("{error:#}")))?;
            (parent.directory, parent.leaf)
        };
        retry_zero(|| unsafe {
            libc::fchownat(
                directory.as_raw_fd(),
                leaf.as_ptr(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }

    pub(crate) fn set_times(&self, path: &RelativePath, times: &[libc::timespec; 2]) -> Result<()> {
        let (parent, leaf) = if path.is_empty() {
            (
                DirectoryHandle::Borrowed(&self.directory),
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

    pub(crate) fn replace_symlink(&self, path: &RelativePath, target: &[u8]) -> Result<()> {
        let target = CString::new(target).context("symlink target contains NUL")?;
        self.replace_entry(path, |fd, name| {
            retry_zero(|| unsafe { libc::symlinkat(target.as_ptr(), fd, name.as_ptr()) })
        })
    }

    pub(crate) fn replace_node(&self, path: &RelativePath, mode: u32, rdev: u64) -> Result<()> {
        self.replace_entry(path, |fd, name| {
            retry_zero(|| unsafe {
                libc::mknodat(fd, name.as_ptr(), mode as libc::mode_t, rdev as libc::dev_t)
            })
        })
    }

    fn replace_entry(
        &self,
        path: &RelativePath,
        create: impl Fn(RawFd, &CString) -> io::Result<()>,
    ) -> Result<()> {
        let parent = self.resolve_parent(path)?;
        let before = metadata_at(parent.directory.as_raw_fd(), &parent.leaf)?;
        if before.is_dir() {
            bail!(
                "cannot replace directory {} with a non-directory",
                path.label()
            );
        }
        // Stage the new leaf before touching the old one. renameat also refuses
        // a directory that appears at the destination after the check above.
        let temporary = create_temporary(&parent, create)?;
        let result = retry_zero(|| unsafe {
            libc::renameat(
                parent.directory.as_raw_fd(),
                temporary.as_ptr(),
                parent.directory.as_raw_fd(),
                parent.leaf.as_ptr(),
            )
        });
        if result.is_err() {
            let _ = unlink_at(parent.directory.as_raw_fd(), &temporary, 0);
        }
        result.with_context(|| format!("publish replacement for {}", path.label()))
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
                "confined destination {} changed before replacement",
                path.label()
            );
        }
        let temporary = create_temporary(&parent, create)?;
        let replacement = metadata_at(parent.directory.as_raw_fd(), &temporary)?;
        if replacement.file_type() != expected_type || replacement.nlink != 1 {
            let _ = unlink_at(parent.directory.as_raw_fd(), &temporary, 0);
            bail!("confined replacement for {} is not safe", path.label());
        }
        #[cfg(test)]
        run_publication_test_hook(
            self.identity,
            path,
            PublicationTestPoint::BeforeMatchedExchange,
        );
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
        #[cfg(test)]
        run_publication_test_hook(
            self.identity,
            path,
            PublicationTestPoint::AfterMatchedExchange,
        );
        let published = metadata_at(parent.directory.as_raw_fd(), &parent.leaf)?;
        let swapped = metadata_at(parent.directory.as_raw_fd(), &temporary)?;
        if published.dev != replacement.dev
            || published.ino != replacement.ino
            || published.file_type() != expected_type
            || published.nlink != 1
        {
            // The replacement name was raced before the exchange, or another
            // writer has already updated the target. Either way, the target
            // name must not be touched again.
            bail!(
                "confined replacement for {} changed during replacement",
                path.label()
            );
        }
        if swapped.dev != expected_dev
            || swapped.ino != expected_ino
            || swapped.file_type() != expected_type
        {
            // Another writer may already have replaced `path` after our
            // exchange. Never mutate that name again: a compensating exchange
            // could remove the later writer's result. Preserve the displaced
            // entry under the temporary name and report the race.
            bail!(
                "confined destination {} changed during replacement",
                path.label()
            );
        }
        unlink_at(parent.directory.as_raw_fd(), &temporary, 0)
            .with_context(|| format!("remove replaced confined path {}", path.label()))
    }

    /// Rename one leaf to another. Both parents are resolved and retained
    /// beneath this root before the atomic rename. Existing destinations follow
    /// ordinary `rename(2)` replacement rules.
    #[cfg(test)]
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

    /// Link a representative through a held object, then publish its new name.
    /// This deliberately does not use the single-link staging-file helpers.
    pub(crate) fn publish_hardlink(
        &self,
        source: &RelativePath,
        target: &RelativePath,
        identity: (u64, u64),
    ) -> Result<()> {
        let file = self.open_metadata(source)?;
        let opened = root_metadata_from_std(&file.metadata()?)?;
        if !opened.is_file() || (opened.dev, opened.ino) != identity {
            bail!(
                "hardlink representative {} changed before publication",
                source.label()
            );
        }
        let parent = self.resolve_parent(target)?;
        match metadata_at(parent.directory.as_raw_fd(), &parent.leaf) {
            Ok(existing) if (existing.dev, existing.ino) == identity => return Ok(()),
            Ok(existing) if existing.is_dir() => {
                bail!("hardlink destination {} is a directory", target.label())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(target_os = "linux")]
        let source_name = CString::new(crate::sys::proc_fd_path(&file))?;
        #[cfg(not(target_os = "linux"))]
        let source_parent = self.resolve_parent(source)?;
        #[cfg(any(target_os = "linux", test))]
        let _permit = self.mutation_permit(target)?;
        let temporary = create_temporary(&parent, |fd, name| {
            #[cfg(target_os = "linux")]
            let result = retry_zero(|| unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    source_name.as_ptr(),
                    fd,
                    name.as_ptr(),
                    libc::AT_SYMLINK_FOLLOW,
                )
            });
            #[cfg(not(target_os = "linux"))]
            let result = retry_zero(|| unsafe {
                libc::linkat(
                    source_parent.directory.as_raw_fd(),
                    source_parent.leaf.as_ptr(),
                    fd,
                    name.as_ptr(),
                    0,
                )
            });
            result
        })?;
        let result = (|| {
            // On platforms without fd-relative link creation, a raced source
            // name can create a different temporary inode. Never publish it.
            let linked = metadata_at(parent.directory.as_raw_fd(), &temporary)?;
            if !linked.is_file() || (linked.dev, linked.ino) != identity {
                bail!(
                    "hardlink representative {} changed while linking",
                    source.label()
                );
            }
            retry_zero(|| unsafe {
                libc::renameat(
                    parent.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    parent.directory.as_raw_fd(),
                    parent.leaf.as_ptr(),
                )
            })
            .with_context(|| format!("publish hardlink {}", target.label()))
        })();
        if result.is_err() {
            let _ = unlink_at(parent.directory.as_raw_fd(), &temporary, 0);
        }
        result
    }

    /// Atomically publish a staged regular file with ordinary rename
    /// replacement semantics. Both parents are retained before the rename, so
    /// a concurrent ancestor replacement cannot redirect either side. A later
    /// writer may replace this complete file immediately after publication.
    pub(crate) fn rename_regular_if_same(
        &self,
        source: &RelativePath,
        target: &RelativePath,
        staged_identity: (u64, u64),
    ) -> Result<()> {
        let (staged_dev, staged_ino) = staged_identity;
        let source_parent = self.resolve_parent(source)?;
        let target_parent = self.resolve_publish_target(source, &source_parent, target)?;
        let staged = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        require_safe_staged_identity(staged, staged_dev, staged_ino, source)?;
        #[cfg(any(target_os = "linux", test))]
        let permit = self.mutation_permit(target)?;
        retry_zero(|| unsafe {
            libc::renameat(
                source_parent.directory.as_raw_fd(),
                source_parent.leaf.as_ptr(),
                target_parent.directory.as_raw_fd(),
                target_parent.leaf.as_ptr(),
            )
        })
        .with_context(|| format!("publish confined path {}", target.label()))?;
        #[cfg(any(target_os = "linux", test))]
        drop(permit);
        #[cfg(test)]
        run_publication_test_hook(self.identity, target, PublicationTestPoint::AfterAnyRename);
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
        let source_parent = self.resolve_parent(source)?;
        let target_parent = self.resolve_publish_target(source, &source_parent, target)?;
        let staged = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        require_safe_staged_identity(staged, staged_dev, staged_ino, source)?;
        #[cfg(any(target_os = "linux", test))]
        let permit = self.mutation_permit(target)?;
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
        #[cfg(any(target_os = "linux", test))]
        drop(permit);
        #[cfg(test)]
        run_publication_test_hook(self.identity, target, PublicationTestPoint::AfterAbsentLink);
        let published = metadata_at(target_parent.directory.as_raw_fd(), &target_parent.leaf)?;
        if !is_safe_staged_identity_after_link(published, staged_dev, staged_ino) {
            bail!(
                "confined staged path {} changed during publication",
                source.label()
            );
        }
        #[cfg(any(target_os = "linux", test))]
        let _permit = self.mutation_permit(source)?;
        unlink_at(source_parent.directory.as_raw_fd(), &source_parent.leaf, 0)
            .with_context(|| format!("remove staged confined path {}", source.label()))
    }

    /// Atomically replace exactly one previously observed regular-file inode.
    /// The exchange retains the displaced inode under the staged name long
    /// enough to verify it. After the exchange, mismatch handling never
    /// touches the target name again, so a later writer cannot be rolled back.
    pub(crate) fn replace_regular_if_same(
        &self,
        source: &RelativePath,
        target: &RelativePath,
        staged_identity: (u64, u64),
        expected_dev: u64,
        expected_ino: u64,
        expected_ctime: Option<(i64, u32)>,
    ) -> Result<()> {
        let (staged_dev, staged_ino) = staged_identity;
        let source_parent = self.resolve_parent(source)?;
        let target_parent = self.resolve_publish_target(source, &source_parent, target)?;
        let staged = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        require_safe_staged_identity(staged, staged_dev, staged_ino, source)?;
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
                "confined destination {} changed before publication",
                target.label()
            );
        }
        #[cfg(test)]
        run_publication_test_hook(
            self.identity,
            target,
            PublicationTestPoint::BeforeMatchedExchange,
        );
        #[cfg(any(target_os = "linux", test))]
        let permit = self.mutation_permit(target)?;
        rename_exchange(
            source_parent.directory.as_raw_fd(),
            &source_parent.leaf,
            target_parent.directory.as_raw_fd(),
            &target_parent.leaf,
        )
        .with_context(|| format!("atomically publish confined path {}", target.label()))?;
        #[cfg(any(target_os = "linux", test))]
        drop(permit);
        #[cfg(test)]
        run_publication_test_hook(
            self.identity,
            target,
            PublicationTestPoint::AfterMatchedExchange,
        );
        let published = metadata_at(target_parent.directory.as_raw_fd(), &target_parent.leaf)?;
        let displaced = metadata_at(source_parent.directory.as_raw_fd(), &source_parent.leaf)?;
        if !is_safe_staged_identity(published, staged_dev, staged_ino) {
            bail!(
                "confined staged path {} changed during publication",
                source.label()
            );
        }
        // The exchange itself may update the displaced inode's ctime. Its
        // dev/inode identity cannot be recycled while the link still exists,
        // so the pre-exchange fingerprint plus this identity check is enough.
        if !has_expected_identity(displaced) {
            // The target may already contain a still-later writer's result.
            // Never exchange it again after publication; retain the displaced
            // entry under the staged name and report the race.
            bail!(
                "confined destination {} changed during publication",
                target.label()
            );
        }
        #[cfg(any(target_os = "linux", test))]
        let _permit = self.mutation_permit(source)?;
        unlink_at(source_parent.directory.as_raw_fd(), &source_parent.leaf, 0)
            .with_context(|| format!("remove displaced confined path {}", target.label()))
    }

    fn resolve_publish_target<'a>(
        &'a self,
        source: &RelativePath,
        source_parent: &'a ResolvedParent<'_>,
        target: &RelativePath,
    ) -> Result<ResolvedParent<'a>> {
        let (source_parents, _) = source.leaf()?;
        let (target_parents, target_leaf) = target.leaf()?;
        if source_parents == target_parents {
            Ok(ResolvedParent {
                directory: DirectoryHandle::Borrowed(&source_parent.directory),
                leaf: component_cstring(target_leaf),
            })
        } else {
            self.resolve_parent(target)
        }
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

    pub(crate) fn resolve_parent(&self, path: &RelativePath) -> Result<ResolvedParent<'_>> {
        #[cfg(all(test, target_os = "linux"))]
        self.check_test_name_limit(path)?;
        let (parents, leaf) = path.leaf()?;
        let directory = if parents.is_empty() {
            DirectoryHandle::Borrowed(&self.directory)
        } else {
            DirectoryHandle::Owned(
                open_directory_components(&self.directory, parents)
                    .with_context(|| format!("resolve confined parent for {}", path.label()))?,
            )
        };
        Ok(ResolvedParent {
            directory,
            leaf: component_cstring(leaf),
        })
    }
}

// A leaf directly under the retained root needs no new descriptor. Borrowing
// keeps that root alive for the operation; descendants still resolve afresh.
enum DirectoryHandle<'a> {
    Borrowed(&'a File),
    Owned(File),
}

impl std::ops::Deref for DirectoryHandle<'_> {
    type Target = File;

    fn deref(&self) -> &File {
        match self {
            Self::Borrowed(file) => file,
            Self::Owned(file) => file,
        }
    }
}

pub(crate) struct ResolvedParent<'a> {
    directory: DirectoryHandle<'a>,
    leaf: CString,
}

// An operation-local parent handle. Callers that check the final pathname must
// still resolve it from Root; retaining this handle must not hide replacement
// of an ancestor during a metadata update.
impl ResolvedParent<'_> {
    pub(crate) fn metadata(&self) -> io::Result<RootMetadata> {
        metadata_at(self.directory.as_raw_fd(), &self.leaf)
    }

    pub(crate) fn open_metadata(&self) -> io::Result<File> {
        #[cfg(target_os = "linux")]
        let flags =
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
        #[cfg(target_os = "macos")]
        // O_NOFOLLOW would override O_SYMLINK and reject a link on macOS.
        let flags =
            libc::O_EVTONLY | libc::O_SYMLINK | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let flags =
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
        open_at(self.directory.as_raw_fd(), &self.leaf, flags, 0)
    }

    pub(crate) fn create_directory(&self, mode: u32) -> io::Result<()> {
        retry_zero(|| unsafe {
            libc::mkdirat(
                self.directory.as_raw_fd(),
                self.leaf.as_ptr(),
                (mode & 0o777) as libc::mode_t,
            )
        })
    }

    pub(crate) fn set_times(&self, times: &[libc::timespec; 2]) -> io::Result<()> {
        retry_zero(|| unsafe {
            libc::utimensat(
                self.directory.as_raw_fd(),
                self.leaf.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }

    pub(crate) fn chown(&self, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
        retry_zero(|| unsafe {
            libc::fchownat(
                self.directory.as_raw_fd(),
                self.leaf.as_ptr(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        })
    }
}

#[cfg(all(target_os = "macos", debug_assertions))]
fn fail_clone_for_test(variable: &str) -> io::Result<()> {
    let Some(name) = std::env::var_os(variable) else {
        return Ok(());
    };
    let code = match name.to_str() {
        Some("EACCES") => libc::EACCES,
        Some("EIO") => libc::EIO,
        Some("EMFILE") => libc::EMFILE,
        Some("EMLINK") => libc::EMLINK,
        Some("ENOSPC") => libc::ENOSPC,
        Some("ENOSYS") => libc::ENOSYS,
        Some("ENOTSUP") => libc::ENOTSUP,
        Some("EPERM") => libc::EPERM,
        Some("EXDEV") => libc::EXDEV,
        _ => panic!("unknown clone test errno {name:?} in {variable}"),
    };
    Err(io::Error::from_raw_os_error(code))
}

#[cfg(all(target_os = "macos", debug_assertions))]
fn make_clone_directory_public_for_test(directory: &File) -> Result<()> {
    if std::env::var_os("SYQ_TEST_CLONE_PUBLIC_DIRECTORY").is_some() {
        retry_zero(|| unsafe { libc::fchmod(directory.as_raw_fd(), 0o755) })?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", debug_assertions))]
fn record_clone_attempt_for_test() -> io::Result<()> {
    crate::fsops::record_test_event("SYQ_TEST_CLONE_ATTEMPTS", format_args!("clone"))?;
    if std::env::var_os("SYQ_TEST_CLONE_ERROR").is_some() {
        if let Some(once) = std::env::var_os("SYQ_TEST_CLONE_ERROR_ONCE") {
            match OpenOptions::new().write(true).create_new(true).open(once) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        return fail_clone_for_test("SYQ_TEST_CLONE_ERROR");
    }
    Ok(())
}

// Darwin's ACL functions and constants from <sys/acl.h> are not exposed by
// libc. Keep the opaque allocation within this function and release it once.
#[cfg(target_os = "macos")]
fn clone_directory_has_no_inheritable_acl(directory: &File) -> Result<bool> {
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_flagset_np(
            entry: *mut libc::c_void,
            flags: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_flag_np(flags: *mut libc::c_void, flag: libc::c_int) -> libc::c_int;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }
    const ACL_TYPE_EXTENDED: libc::c_int = 0x100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    let acl = unsafe { acl_get_fd_np(directory.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // acl_get_fd_np uses ENOENT when the held inode has no ACL property.
        // This is distinct from an allocated ACL with zero entries below.
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(true);
        }
        if matches!(error.raw_os_error(), Some(libc::ENOTSUP | libc::EACCES)) {
            return Ok(false);
        }
        return Err(error).context("inspect clone destination ACL");
    }
    let result = (|| -> Result<bool> {
        let mut entry = std::ptr::null_mut();
        let mut entry_id = ACL_FIRST_ENTRY;
        loop {
            if unsafe { acl_get_entry(acl, entry_id, &mut entry) } != 0 {
                let error = io::Error::last_os_error();
                // Darwin ends iteration with -1/EINVAL, including empty ACLs.
                return if error.raw_os_error() == Some(libc::EINVAL) {
                    Ok(true)
                } else {
                    Err(error).context("inspect clone destination ACL entry")
                };
            }
            const ACL_NEXT_ENTRY: libc::c_int = -1;
            entry_id = ACL_NEXT_ENTRY;
            let mut flags = std::ptr::null_mut();
            retry_zero(|| unsafe { acl_get_flagset_np(entry, &mut flags) })?;
            // Non-inheritable entries (such as Downloads' deny-delete ACL)
            // cannot change the ACL of either the staging directory or clone.
            for flag in [1 << 5, 1 << 6] {
                // FILE_INHERIT, DIRECTORY_INHERIT
                match unsafe { acl_get_flag_np(flags, flag) } {
                    0 => {}
                    1 => return Ok(false),
                    _ => return Err(io::Error::last_os_error()).context("inspect ACL inheritance"),
                }
            }
        }
    })();
    unsafe {
        acl_free(acl);
    }
    result
}

#[cfg(target_os = "macos")]
fn clear_clone_flags_at(directory: &File, leaf: &CStr) -> Result<()> {
    #[cfg(debug_assertions)]
    fail_clone_for_test("SYQ_TEST_FAIL_CLONE_CLEAR_FLAGS")
        .context("test clear clone flags failure")?;
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_FLAGS,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut flags = 0u32;
    retry_zero(|| unsafe {
        libc::setattrlistat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            (&mut attributes as *mut libc::attrlist).cast(),
            (&mut flags as *mut u32).cast(),
            std::mem::size_of_val(&flags),
            libc::FSOPT_NOFOLLOW,
        )
    })
    .context("clear private clone flags")
}

#[cfg(target_os = "macos")]
fn open_clone_for_copy(directory: &File, leaf: &CStr) -> io::Result<File> {
    #[cfg(debug_assertions)]
    fail_clone_for_test("SYQ_TEST_CLONE_OPEN_EMFILE")?;
    open_at(
        directory.as_raw_fd(),
        leaf,
        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

#[cfg(target_os = "macos")]
fn clone_flags_can_be_removed(metadata: &std::fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt;
    // Compressed-file xattrs can hold the actual data, so stripping them is
    // not equivalent to copying logical bytes. System flags may require root
    // to clear, including flags that prevent deleting an unpublished clone.
    let flags = metadata.st_flags();
    flags & (!libc::UF_SETTABLE | libc::UF_COMPRESSED) == 0
}

#[cfg(target_os = "macos")]
fn strip_clone_xattrs(file: &File) -> Result<bool> {
    let count = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0, 0) };
    if count < 0 {
        let error = io::Error::last_os_error();
        return Err(error).context("list cloned extended attributes");
    }
    if count == 0 {
        return Ok(true);
    }
    let mut names = vec![0u8; count as usize];
    let count =
        unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error()).context("read cloned extended attributes");
    }
    // The source can acquire filesystem compression after its initial stat.
    // Its cloned compression payload must never be stripped and published as
    // ordinary bytes, even though the private clone's flags are already clear.
    if names[..count as usize]
        .split(|&byte| byte == 0)
        .any(|name| name == b"com.apple.decmpfs")
    {
        return Ok(false);
    }
    for name in names[..count as usize]
        .split(|&byte| byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = component_cstring(name);
        if unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            return Err(error).context("remove cloned extended attribute");
        }
    }
    Ok(true)
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

/// Inspect a directory's naming rules before search permission is repaired.
/// macOS O_SEARCH requires search permission on the directory being opened;
/// Use O_SEARCH for searchable directories, then O_EVTONLY when only read
/// permission is available. Neither changes permissions during inspection.
/// Descendant lookups still enforce search permission and never follow links.
#[cfg(target_os = "macos")]
fn open_directory_metadata_at(parent: &File, component: &[u8]) -> io::Result<File> {
    match open_directory_at(parent, component) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => open_at(
            parent.as_raw_fd(),
            &component_cstring(component),
            libc::O_EVTONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ),
        result => result,
    }
}

// Missing entries and exclusive-create collisions already answer the lookup.
// Retrying them with a descriptor walk adds allocation and close contention.
// Preserve fallback for other errors, including unavailable syscalls, long paths,
// and resolution races that the component walk can handle independently.
#[cfg(target_os = "linux")]
fn expected_open_failure(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::EEXIST))
}

fn open_directory_components(parent: &File, components: &[Vec<u8>]) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        match open_directory_components_fast(parent, components) {
            Ok(directory) => Ok(directory),
            Err(error) if expected_open_failure(&error) => Err(error),
            Err(_) => open_directory_components_one_at_a_time(parent, components),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        open_directory_components_one_at_a_time(parent, components)
    }
}

fn open_directory_components_one_at_a_time(
    parent: &File,
    components: &[Vec<u8>],
) -> io::Result<File> {
    let Some((first, remaining)) = components.split_first() else {
        return parent.try_clone();
    };
    let mut directory = open_directory_at(parent, first)?;
    for component in remaining {
        directory = open_directory_at(&directory, component)?;
    }
    Ok(directory)
}

fn open_directory_components_fast(parent: &File, components: &[Vec<u8>]) -> io::Result<File> {
    if components.is_empty() {
        return parent.try_clone();
    }
    #[cfg(target_os = "linux")]
    {
        open_directory_components_openat2(parent, components)
    }
    #[cfg(not(target_os = "linux"))]
    {
        open_directory_components_one_at_a_time(parent, components)
    }
}

#[cfg(target_os = "linux")]
fn open_directory_components_openat2(parent: &File, components: &[Vec<u8>]) -> io::Result<File> {
    open_components_openat2(
        parent,
        components,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
}

#[cfg(target_os = "linux")]
fn open_components_openat2(
    parent: &File,
    components: &[Vec<u8>],
    flags: libc::c_int,
    mode: u32,
) -> io::Result<File> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    // linux/openat2.h. libc exposes SYS_openat2 but not open_how or these
    // resolve flags on every supported target.
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    let path_len = components.iter().map(Vec::len).sum::<usize>() + components.len() - 1;
    let mut path = Vec::with_capacity(path_len);
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            path.push(b'/');
        }
        path.extend_from_slice(component);
    }
    let path = CString::new(path).expect("RelativePath already rejected NUL");
    let how = OpenHow {
        flags: flags as u64,
        mode: mode as u64,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };
    loop {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd as RawFd) });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
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

/// Identify the filesystem of a held descriptor without resolving its path.
#[cfg(target_os = "macos")]
pub(crate) fn filesystem_is(file: &File, name: &[u8]) -> io::Result<bool> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fstatfs initializes the supplied structure on success, including
    // its NUL-terminated filesystem type name. Retry an interrupted probe.
    retry_zero(|| unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) })?;
    let stats = unsafe { stats.assume_init() };
    Ok(unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) }.to_bytes() == name)
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
        atime: crate::inode_metadata::Timestamp {
            seconds: stat.st_atime,
            nanoseconds: stat.st_atime_nsec as u32,
        },
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
        atime: crate::inode_metadata::Timestamp {
            seconds: metadata.atime(),
            nanoseconds: metadata.atime_nsec() as u32,
        },
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

fn unlink_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<()> {
    retry_zero(|| unsafe { libc::unlinkat(parent, name.as_ptr(), flags) })
}

fn create_temporary(
    parent: &ResolvedParent<'_>,
    create: impl Fn(RawFd, &CString) -> io::Result<()>,
) -> Result<CString> {
    for _ in 0..32 {
        let counter = NEXT_SWAP_NAME.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(crate::fsops::recovery_name(std::process::id(), counter))
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
    // SAFETY: both names are NUL-terminated and outlive the call; the
    // descriptors are only read. The typed wrapper avoids passing `c_int`
    // arguments through `syscall(2)`'s `long` varargs.
    retry_zero(|| unsafe {
        libc::renameat2(
            old_parent,
            old_name.as_ptr(),
            new_parent,
            new_name.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    })
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
    BeforeMatchedExchange,
    AfterMatchedExchange,
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
mod tests;
