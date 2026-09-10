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
//! open a validated multi-component directory path in one syscall. Kernels or
//! sandboxes without that syscall retain the same component-by-component
//! descriptor walk used on other Unix platforms; neither path falls back to
//! an unconfined pathname.
//!
//! The guarantee is pathname confinement. A hard link beneath the root may
//! still refer to an inode with another name outside the root. As with all
//! descriptor-based traversal, an already-open descendant remains the selected
//! object if another process subsequently renames it.

use crate::proto::OperatorSymlinkPolicy;
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, VecDeque};
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(all(test, target_os = "macos"))]
#[path = "../tests/support/macos_clone.rs"]
mod macos_clone_support;

static NEXT_SWAP_NAME: AtomicU64 = AtomicU64::new(0);
const COMMON_NAME_MAX: usize = 255;
const NAME_MAX_CACHE_CAP: usize = 1024;

pub(crate) const OPERATOR_SYMLINK_FOLLOW_ADVICE: &str = "pass --follow-src for source paths, --follow-dst for destination paths, or --follow for all directly supplied filesystem paths";

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
    Entry {
        follow_symlink: bool,
    },
    /// An input file whose final procfs magic link may be opened relative to
    /// its retained procfs parent instead of interpreting its synthetic target
    /// bytes as an ordinary symlink path.
    ReadableEntry {
        follow_symlink: bool,
    },
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
    resolved_relative: Option<Vec<u8>>,
}

impl PinnedLeaf {
    pub(crate) fn metadata(&self) -> RootMetadata {
        self.metadata
    }

    pub(crate) fn into_parts(self) -> (File, CString, RootMetadata, Option<File>) {
        (self.parent, self.name, self.metadata, self.object)
    }

    /// Canonical components from the resolver's initial directory to this
    /// selection, or `None` while an unconfined walk is outside that base.
    pub(crate) fn resolved_relative(&self) -> Option<&[u8]> {
        self.resolved_relative.as_deref()
    }

    /// Open the selected identity for input without resolving its
    /// pathname again. The metadata handle retained by the resolver prevents
    /// inode reuse until the newly opened descriptor has been checked.
    pub(crate) fn open_read(self) -> Result<File> {
        if self.metadata.is_dir() || self.metadata.is_symlink() {
            bail!("operator path does not select a readable file");
        }
        if self.metadata.is_fifo() {
            #[cfg(target_os = "linux")]
            if let Some(object) = &self.object {
                if let Some(file) = reopen_pinned_object_for_read(object)? {
                    let actual = root_metadata_from_std(&file.metadata()?)?;
                    require_operator_identity(self.metadata, actual, "operator FIFO")?;
                    return Ok(file);
                }
            }
            bail!(
                "selected FIFO control input cannot be reopened through an exact descriptor on this platform; use --files-from - or --mapping -, or materialize ignore rules in a regular file"
            );
        }
        // A pathname replacement must not make the candidate open block before
        // its identity is checked. The selected object is not a FIFO here, but
        // its replacement may be one. Restore ordinary blocking I/O only after
        // the opened object has been validated.
        let flags =
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let file = open_at(self.parent.as_raw_fd(), &self.name, flags, 0)
            .context("open selected operator file")?;
        let actual = root_metadata_from_std(&file.metadata()?)?;
        require_operator_identity(self.metadata, actual, "operator file")?;
        clear_nonblocking(&file).context("normalize selected operator file flags")?;
        Ok(file)
    }

    /// Open the selected identity for ordinary output, validating it before
    /// truncation so a namespace replacement cannot redirect the write.
    pub(crate) fn open_regular_write(self, truncate: bool) -> Result<File> {
        self.open_regular(libc::O_WRONLY, truncate)
    }

    fn open_regular(self, access: libc::c_int, truncate: bool) -> Result<File> {
        if !self.metadata.is_file() {
            bail!("operator path does not select a regular file");
        }
        let file = open_at(
            self.parent.as_raw_fd(),
            &self.name,
            access | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        )
        .context("open selected operator file")?;
        let actual = root_metadata_from_std(&file.metadata()?)?;
        require_operator_identity(self.metadata, actual, "operator file")?;
        clear_nonblocking(&file).context("normalize selected operator file flags")?;
        if truncate {
            file.set_len(0).context("truncate selected operator file")?;
        }
        Ok(file)
    }
}

/// An existing selected directory. `entry` retains the parent/name used to
/// select it when the directory itself may later need to be renamed or
/// removed; it is absent when resolution ends at the resolver's base.
pub(crate) struct PinnedDirectory {
    directory: File,
    entry: Option<PinnedLeaf>,
    metadata: RootMetadata,
    resolved_relative: Option<Vec<u8>>,
}

impl PinnedDirectory {
    pub(crate) fn metadata(&self) -> RootMetadata {
        self.metadata
    }

    pub(crate) fn into_parts(self) -> (File, Option<PinnedLeaf>) {
        (self.directory, self.entry)
    }

    /// Canonical components from the resolver's initial directory to this
    /// selection. See `PinnedLeaf::resolved_relative` for unconfined walks.
    pub(crate) fn resolved_relative(&self) -> Option<&[u8]> {
        self.resolved_relative.as_deref()
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

    /// Create a single missing regular-file leaf relative to the retained
    /// parent. Missing parents are deliberately not created for control paths.
    pub(crate) fn create_regular(self, mode: u32) -> Result<File> {
        let mut components = self.components;
        if components.len() != 1 {
            return Err(io::Error::from_raw_os_error(libc::ENOENT).into());
        }
        let name = operator_component_cstring(
            &components
                .pop_front()
                .expect("one missing operator component was checked"),
        )?;
        let file = open_at(
            self.directory.as_raw_fd(),
            &name,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_NOCTTY
                | libc::O_CLOEXEC,
            mode & 0o777,
        )
        .context("create selected operator file")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("created operator path is not a regular file");
        }
        clear_nonblocking(&file).context("normalize selected operator file flags")?;
        Ok(file)
    }
}

pub(crate) enum PinnedPath {
    Missing(PinnedMissing),
    Leaf(PinnedLeaf),
    Directory(PinnedDirectory),
    /// A readable object opened directly through a retained procfs magic-link
    /// parent. This is used only for final control-file inputs.
    OpenFile(File),
}

struct OperatorCursor {
    directory: File,
    entry: Option<OperatorEntry>,
    /// Canonical components beneath the resolver's original base. `None`
    /// means an unconfined walk is currently outside that base.
    resolved_relative: Option<Vec<u8>>,
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
    base_identity: OperatorDirectoryIdentity,
    base_is_process_root: bool,
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
        let base = open_operator_start(path.starts_with(b"/"))?;
        let base_identity = operator_directory_identity(&base)?;
        let base_is_process_root = operator_base_is_process_root(base_identity)?;
        Self {
            base,
            base_identity,
            base_is_process_root,
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
        let base = base.try_clone().context("duplicate operator path base")?;
        let base_identity = operator_directory_identity(&base)?;
        let base_is_process_root = operator_base_is_process_root(base_identity)?;
        Ok(Self {
            base,
            base_identity,
            base_is_process_root,
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
            resolved_relative: Some(Vec::new()),
        }];
        let mut symlink_count = 0usize;

        loop {
            let Some(component) = components.pop_front() else {
                let current = stack.last().expect("operator resolver stack is nonempty");
                let metadata = root_metadata_from_std(&current.directory.metadata()?)?;
                let resolved_relative = current.resolved_relative.clone();
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
                        resolved_relative: resolved_relative.clone(),
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
                    resolved_relative,
                }));
            };

            if component == b"." {
                continue;
            }
            if component == b".." {
                if stack.len() > 1 {
                    stack.pop();
                } else if self.confined {
                    if !self.base_is_process_root {
                        bail!("operator path resolves outside its confined root");
                    }
                } else {
                    let directory = open_operator_directory_at(&stack[0].directory, b"..")
                        .context("resolve operator path parent")?;
                    stack[0] = OperatorCursor {
                        resolved_relative: self.relative_if_base(&directory)?,
                        directory,
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
                    } | OperatorFinalComponent::ReadableEntry {
                        follow_symlink: true
                    }
                );

            if metadata.is_symlink() {
                if !follow_symlink {
                    let resolved_relative =
                        append_operator_component(current.resolved_relative.as_deref(), &component);
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
                        resolved_relative,
                    }));
                }
                // Refusal needs no second observation. Policies that follow
                // the link pin it first so ownership and target bytes come
                // from the same symlink object.
                if self.symlink_policy == OperatorSymlinkPolicy::Refuse {
                    self.authorize_symlink(metadata, &component)?;
                    unreachable!("the refusing policy always returns an error for a symlink");
                }
                symlink_count += 1;
                if symlink_count > 40 {
                    bail!("too many symlink levels in operator path");
                }
                let object = open_operator_symlink_at(current.directory.as_raw_fd(), &name)?;
                let target = if let Some(object) = object {
                    let opened_metadata = root_metadata_from_std(&object.metadata()?)?;
                    require_operator_identity(metadata, opened_metadata, "operator symlink")?;
                    self.authorize_symlink(opened_metadata, &component)?;
                    hold_open_operator_symlink_for_test(&component)?;
                    match operator_read_open_link(&object)? {
                        Some(target) => {
                            #[cfg(target_os = "linux")]
                            if final_name
                                && matches!(
                                    final_component,
                                    OperatorFinalComponent::ReadableEntry { .. }
                                )
                                && operator_descriptor_is_procfs(&object)?
                            {
                                let file = open_at(
                                    current.directory.as_raw_fd(),
                                    &name,
                                    libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
                                    0,
                                )
                                .context("open selected procfs magic-link input")?;
                                let after = operator_read_open_link(&object)?
                                    .context("procfs magic link lost descriptor-bound access")?;
                                if after != target {
                                    bail!("procfs magic-link target changed during selection");
                                }
                                let metadata = root_metadata_from_std(&file.metadata()?)?;
                                if metadata.is_dir() || metadata.is_symlink() {
                                    bail!("operator path does not select a readable file");
                                }
                                hops.push(OperatorSymlinkHop { component, target });
                                return Ok(PinnedPath::OpenFile(file));
                            }
                            target
                        }
                        None => {
                            require_operator_link_fallback_allowed(self.symlink_policy)?;
                            operator_read_link_at(current.directory.as_raw_fd(), &name)?
                        }
                    }
                } else {
                    self.authorize_symlink(metadata, &component)?;
                    require_operator_link_fallback_allowed(self.symlink_policy)?;
                    operator_read_link_at(current.directory.as_raw_fd(), &name)?
                };
                hops.push(OperatorSymlinkHop {
                    component,
                    target: target.clone(),
                });
                if target.starts_with(b"/") {
                    if self.confined {
                        bail!("operator path has an absolute symlink target outside its root");
                    }
                    let directory = open_operator_start(true)?;
                    stack = vec![OperatorCursor {
                        resolved_relative: self.relative_if_base(&directory)?,
                        directory,
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
                let resolved_relative = if let Some(path) = current.resolved_relative.as_deref() {
                    Some(join_operator_component(path, &component))
                } else if self.directory_is_base(&directory)? {
                    Some(Vec::new())
                } else {
                    None
                };
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
                            resolved_relative: resolved_relative.clone(),
                        }),
                        metadata,
                        resolved_relative,
                    }));
                }
                stack.push(OperatorCursor {
                    directory,
                    entry: Some(OperatorEntry { name, metadata }),
                    resolved_relative,
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
                resolved_relative: append_operator_component(
                    current.resolved_relative.as_deref(),
                    &component,
                ),
            }));
        }
    }

    fn relative_if_base(&self, directory: &File) -> Result<Option<Vec<u8>>> {
        Ok(self.directory_is_base(directory)?.then(Vec::new))
    }

    fn directory_is_base(&self, directory: &File) -> Result<bool> {
        let identity = operator_directory_identity(directory)?;
        Ok(operator_directory_identities_match(
            identity,
            self.base_identity,
        ))
    }

    fn authorize_symlink(&self, metadata: RootMetadata, component: &[u8]) -> Result<()> {
        let euid = unsafe { libc::geteuid() };
        match self.symlink_policy {
            OperatorSymlinkPolicy::Refuse => bail!(
                "refusing symlink component {:?} in operator path; {OPERATOR_SYMLINK_FOLLOW_ADVICE}",
                String::from_utf8_lossy(component),
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

#[derive(Clone, Copy, Debug)]
struct OperatorDirectoryIdentity {
    dev: u64,
    ino: u64,
    #[cfg(target_os = "linux")]
    mount_id: Option<u64>,
}

fn operator_directory_identity(directory: &File) -> Result<OperatorDirectoryIdentity> {
    let metadata = root_metadata_from_std(&directory.metadata()?)?;
    Ok(OperatorDirectoryIdentity {
        dev: metadata.dev,
        ino: metadata.ino,
        #[cfg(target_os = "linux")]
        mount_id: operator_mount_id(directory)?,
    })
}

fn operator_directory_identities_match(
    left: OperatorDirectoryIdentity,
    right: OperatorDirectoryIdentity,
) -> bool {
    if left.dev != right.dev || left.ino != right.ino {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        matches!((left.mount_id, right.mount_id), (Some(left), Some(right)) if left == right)
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

#[cfg(target_os = "linux")]
fn operator_mount_id(directory: &File) -> Result<Option<u64>> {
    let mut status = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let result = unsafe {
        libc::statx(
            directory.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            status.as_mut_ptr(),
        )
    };
    if result == 0 {
        let status = unsafe { status.assume_init() };
        return Ok(((status.stx_mask & libc::STATX_MNT_ID) != 0).then_some(status.stx_mnt_id));
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP | libc::EPERM)
    ) {
        return Ok(None);
    }
    Err(error).context("identify operator directory mount")
}

fn operator_base_is_process_root(identity: OperatorDirectoryIdentity) -> Result<bool> {
    let root = open_operator_start(true)?;
    Ok(operator_directory_identities_match(
        operator_directory_identity(&root)?,
        identity,
    ))
}

fn append_operator_component(path: Option<&[u8]>, component: &[u8]) -> Option<Vec<u8>> {
    path.map(|path| join_operator_component(path, component))
}

fn join_operator_component(path: &[u8], component: &[u8]) -> Vec<u8> {
    let mut joined = path.to_vec();
    if !joined.is_empty() {
        joined.push(b'/');
    }
    joined.extend_from_slice(component);
    joined
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
    ) -> Result<CloneOutcome> {
        let mut cleanup_failed = false;
        let attempt = (|| -> Result<CloneOutcome> {
            let parent = self.resolve_parent(path)?;
            // Reuse the held parent for the partial check and clone publication.
            // RENAME_EXCL below also protects a partial created after this check.
            match metadata_at(parent.directory.as_raw_fd(), &parent.leaf) {
                Ok(_) => return Ok(CloneOutcome::Unsupported),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect clone partial"),
            }
            // A descendant mount can differ from the root device. Resolve and
            // inspect the actual parent even for cached unsupported pairs; a root
            // device shortcut would incorrectly reject eligible mounted volumes.
            let pair = (source_metadata.dev(), parent.directory.metadata()?.dev());
            // Process-local capability cache: file metadata and directory ACL failures
            // are not properties of a filesystem pair and must never enter it.
            let pairs = clone_volume_pairs();
            let cached = pairs.lock().unwrap().get(&pair).copied();
            let supported = if let Some(supported) = cached {
                supported
            } else {
                // This optimization targets APFS. Reject exFAT/SMB and other
                // destinations before probing ACLs or creating staging directories.
                let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
                let supported = if pair.0 != pair.1 {
                    false
                } else {
                    retry_zero(|| unsafe {
                        libc::fstatfs(parent.directory.as_raw_fd(), stats.as_mut_ptr())
                    })?;
                    let stats = unsafe { stats.assume_init() };
                    unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) }.to_bytes()
                        == b"apfs"
                };
                pairs.lock().unwrap().insert(pair, supported);
                supported
            };
            if !supported {
                return Ok(CloneOutcome::UnsupportedVolume(pair.0));
            }
            if !clone_flags_can_be_removed(source_metadata) {
                return Ok(CloneOutcome::Unsupported);
            }
            // An extra staging directory must not change destination ACL inheritance.
            if !clone_directory_has_no_inheritable_acl(&parent.directory)? {
                return Ok(CloneOutcome::Unsupported);
            }
            let temporary = create_temporary(&parent, |fd, name| {
                #[cfg(debug_assertions)]
                fail_clone_mkdir_for_test()?;
                retry_zero(|| unsafe { libc::mkdirat(fd, name.as_ptr(), 0o700) })
            })?;
            let leaf = &c"data".to_owned();
            let mut trusted_directory = None;
            let mut unsupported_volume = false;
            let result = (|| -> Result<Option<File>> {
                #[cfg(debug_assertions)]
                fail_clone_for_test(
                    "SYQ_TEST_FAIL_CLONE_AFTER_MKDIR",
                    libc::EIO,
                    "test clone directory failure",
                )?;
                let directory = open_directory_at(&parent.directory, temporary.as_bytes())
                    .context("open private clone directory")?;
                #[cfg(debug_assertions)]
                make_clone_directory_public_for_test(&directory)?;
                let metadata = directory.metadata()?;
                if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o5777 != 0o700
                {
                    // Some filesystems synthesize permissions. Fall back without
                    // putting source data into a directory we cannot keep private.
                    return Ok(None);
                }
                if !clone_directory_has_no_inheritable_acl(&directory)? {
                    return Ok(None);
                }
                trusted_directory = Some(directory);
                let directory = trusted_directory.as_ref().unwrap();
                // CLONE_NOOWNERCOPY from <sys/clonefile.h>; libc exposes the
                // function but not this constant. Do not request source ACLs.
                const CLONE_NOOWNERCOPY: u32 = 0x0002;
                #[cfg(debug_assertions)]
                if record_clone_attempt_for_test()? {
                    pairs.lock().unwrap().insert(pair, false);
                    unsupported_volume = true;
                    return Ok(None);
                }
                let cloned = unsafe {
                    libc::fclonefileat(
                        source.as_raw_fd(),
                        directory.as_raw_fd(),
                        leaf.as_ptr(),
                        CLONE_NOOWNERCOPY,
                    )
                };
                if cloned != 0 {
                    let error = io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(libc::EXDEV | libc::ENOTSUP | libc::ENOSYS) => {
                            pairs.lock().unwrap().insert(pair, false);
                            unsupported_volume = true;
                            return Ok(None);
                        }
                        _ => return Err(error).context("clone local file"),
                    }
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
                    return Ok(None);
                }
                if file.metadata()?.len() != size {
                    // Streaming and the final source re-stat handle concurrent
                    // growth/shrinkage using the same retry policy as other copies.
                    return Ok(None);
                }
                #[cfg(debug_assertions)]
                fail_clone_for_test(
                    "SYQ_TEST_FAIL_CLONE_AFTER_CREATE",
                    libc::ENOSPC,
                    "test clone failure",
                )?;
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
                        return Ok(None);
                    }
                    return Err(error).context("stage cloned local file");
                }
                Ok(Some(file))
            })();
            let cleanup = (|| -> Result<()> {
                if let Some(directory) =
                    trusted_directory.filter(|_| !matches!(result, Ok(Some(_))))
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
                fail_clone_for_test(
                    "SYQ_TEST_FAIL_CLONE_RMDIR",
                    libc::EACCES,
                    "test clone staging rmdir failure",
                )?;
                unlink_at(parent.directory.as_raw_fd(), &temporary, libc::AT_REMOVEDIR)
                    .context("remove private clone directory")
            })();
            #[cfg(debug_assertions)]
            let cleanup = cleanup.and_then(|()| {
                fail_clone_for_test(
                    "SYQ_TEST_FAIL_CLONE_CLEANUP",
                    libc::EACCES,
                    "test clone cleanup failure",
                )
            });
            cleanup_failed = cleanup.is_err();
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
                (result, Ok(())) => result.map(|file| match file {
                    Some(file) => CloneOutcome::Copied(file),
                    None if unsupported_volume => CloneOutcome::UnsupportedVolume(pair.0),
                    None => CloneOutcome::Unsupported,
                }),
            }
        })();
        // Cloning is optional. Only fall back after cleanup succeeded; a
        // system-immutable clone that we cannot remove must remain a visible
        // failure rather than silently leaving an undeletable copy behind.
        match attempt {
            Err(_) if !cleanup_failed => Ok(CloneOutcome::Unsupported),
            result => result,
        }
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
        if open_directory_components_fast(&self.directory, parents).is_ok() {
            return Ok(());
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
            match self.open_directory(&candidate) {
                Ok(directory) => {
                    let device = directory.metadata()?.dev();
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
        let (source_parent, target_parent) = self.resolve_publish_parents(source, target)?;
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
        rename_exchange(
            source_parent.directory.as_raw_fd(),
            &source_parent.leaf,
            target_parent.directory.as_raw_fd(),
            &target_parent.leaf,
        )
        .with_context(|| format!("atomically publish confined path {}", target.label()))?;
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
        let directory = open_directory_components(&self.directory, parents)
            .with_context(|| format!("resolve confined parent for {}", path.label()))?;
        Ok(ResolvedParent {
            directory,
            leaf: component_cstring(leaf),
        })
    }
}

#[cfg(target_os = "macos")]
pub(crate) enum CloneOutcome {
    Copied(File),
    Unsupported,
    UnsupportedVolume(u64),
}

#[cfg(all(target_os = "macos", test))]
impl CloneOutcome {
    fn copied(self) -> Option<File> {
        match self {
            Self::Copied(file) => Some(file),
            Self::Unsupported | Self::UnsupportedVolume(_) => None,
        }
    }
}

struct ResolvedParent {
    directory: File,
    leaf: CString,
}

#[cfg(all(target_os = "macos", debug_assertions))]
fn fail_clone_for_test(variable: &str, code: libc::c_int, context: &str) -> Result<()> {
    if std::env::var_os(variable).is_some() {
        return Err(io::Error::from_raw_os_error(code)).context(context.to_owned());
    }
    Ok(())
}

#[cfg(all(target_os = "macos", debug_assertions))]
fn fail_clone_mkdir_for_test() -> io::Result<()> {
    if let Ok(error) = std::env::var("SYQ_TEST_CLONE_MKDIR_ERROR") {
        return Err(io::Error::from_raw_os_error(match error.as_str() {
            "EACCES" => libc::EACCES,
            "EPERM" => libc::EPERM,
            "EMLINK" => libc::EMLINK,
            _ => libc::EIO,
        }));
    }
    Ok(())
}

#[cfg(all(target_os = "macos", debug_assertions))]
fn make_clone_directory_public_for_test(directory: &File) -> Result<()> {
    if std::env::var_os("SYQ_TEST_CLONE_PUBLIC_DIRECTORY").is_some() {
        retry_zero(|| unsafe { libc::fchmod(directory.as_raw_fd(), 0o755) })?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", debug_assertions))]
fn record_clone_attempt_for_test() -> Result<bool> {
    if let Some(events) = std::env::var_os("SYQ_TEST_CLONE_ATTEMPTS") {
        use std::io::Write;
        writeln!(
            OpenOptions::new().create(true).append(true).open(events)?,
            "clone"
        )?;
    }
    Ok(std::env::var_os("SYQ_TEST_COPY_LOCAL_EXDEV").is_some())
}

// APFS eligibility uses device pairs, whereas Linux offload distinguishes
// mounts and their NFS/synchronous traits. Keep this clone-specific cache here:
// file metadata and ACL refusals must not disable other files on the volume.
#[cfg(target_os = "macos")]
fn clone_volume_pairs() -> &'static Mutex<HashMap<(u64, u64), bool>> {
    static PAIRS: OnceLock<Mutex<HashMap<(u64, u64), bool>>> = OnceLock::new();
    PAIRS.get_or_init(|| Mutex::new(HashMap::new()))
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
fn clear_clone_flags_at(directory: &File, leaf: &CString) -> Result<()> {
    #[cfg(debug_assertions)]
    fail_clone_for_test(
        "SYQ_TEST_FAIL_CLONE_CLEAR_FLAGS",
        libc::EPERM,
        "test clear clone flags failure",
    )?;
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
fn open_clone_for_copy(directory: &File, leaf: &CString) -> io::Result<File> {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_CLONE_OPEN_EMFILE").is_some() {
        return Err(io::Error::from_raw_os_error(libc::EMFILE));
    }
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

#[cfg(debug_assertions)]
fn hold_open_operator_symlink_for_test(component: &[u8]) -> Result<()> {
    let Some(expected) = std::env::var_os("SYQ_TEST_OPERATOR_SYMLINK_COMPONENT") else {
        return Ok(());
    };
    if expected.as_encoded_bytes() != component {
        return Ok(());
    }
    if let Some(ready) = std::env::var_os("SYQ_TEST_OPERATOR_SYMLINK_READY_FILE") {
        std::fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write operator-symlink-ready signal {}",
                Path::new(&ready).display()
            )
        })?;
    }
    let Some(release) = std::env::var_os("SYQ_TEST_OPERATOR_SYMLINK_RELEASE_FILE") else {
        return Ok(());
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !Path::new(&release).exists() {
        if std::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for operator-symlink release signal {}",
                Path::new(&release).display()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_open_operator_symlink_for_test(_component: &[u8]) -> Result<()> {
    Ok(())
}

/// Read target bytes through an already-open symlink when the platform has a
/// descriptor-bound API. `None` means that only the insecure pathname API is
/// available; callers enforcing trusted-owner traversal must fail closed.
fn operator_read_open_link(object: &File) -> Result<Option<Vec<u8>>> {
    read_open_symlink(object)
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

fn require_operator_link_fallback_allowed(policy: OperatorSymlinkPolicy) -> Result<()> {
    if policy == OperatorSymlinkPolicy::TrustedOwner {
        bail!(
            "trusted-owner symlink traversal requires descriptor-bound link reads on this platform"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn operator_descriptor_is_procfs(file: &File) -> Result<bool> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    loop {
        if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } == 0 {
            let stats = unsafe { stats.assume_init() };
            return Ok(stats.f_type as u32 == libc::PROC_SUPER_MAGIC as u32);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error).context("identify operator descriptor filesystem");
        }
    }
}

/// Upgrade a retained Linux `O_PATH` object to a readable descriptor without
/// consulting its former pathname. A verified procfs directory makes the
/// decimal entry an exact reference to `object`, even after namespace rename.
#[cfg(target_os = "linux")]
fn reopen_pinned_object_for_read(object: &File) -> Result<Option<File>> {
    let proc_path = CString::new("/proc/self/fd").expect("fixed procfs path contains no NUL");
    let proc_fd = match open_at(
        libc::AT_FDCWD,
        &proc_path,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    ) {
        Ok(proc_fd) => proc_fd,
        Err(_) => return Ok(None),
    };
    if !operator_descriptor_is_procfs(&proc_fd)? {
        return Ok(None);
    }
    let name = CString::new(object.as_raw_fd().to_string())
        .expect("decimal file descriptor contains no NUL");
    open_at(
        proc_fd.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        0,
    )
    .map(Some)
    .context("reopen selected FIFO through its retained descriptor")
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

fn open_directory_components(parent: &File, components: &[Vec<u8>]) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        match open_directory_components_fast(parent, components) {
            Ok(directory) => Ok(directory),
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
    let mut directory = parent.try_clone()?;
    for component in components {
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
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
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
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let n = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = crate::test_support::temp_dir()
                .join(format!("syq-rooted-{name}-{}-{n}", std::process::id()));
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

    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_clone_is_private_independent_and_never_replaces_a_partial() {
        if !macos_clone_support::available() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let t = TestDir::new("clone");
        // A setgid destination may pass its group and setgid bit to the
        // private directory; that does not make the directory public.
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o2700)).unwrap();
        let source_path = t.path().join("source");
        fs::write(&source_path, b"original data").unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o444)).unwrap();
        let source = File::open(&source_path).unwrap();
        let root = Root::open(t.path()).unwrap();
        let clone = root
            .clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"partial"),
                13,
            )
            .unwrap()
            .copied()
            .expect("macOS clone tests require a clone-capable filesystem (APFS)");
        assert_eq!(clone.metadata().unwrap().mode() & 0o7777, 0o600);
        assert_ne!(
            source.metadata().unwrap().ino(),
            clone.metadata().unwrap().ino()
        );
        assert!(root
            .clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"partial"),
                13
            )
            .unwrap()
            .copied()
            .is_none());
        (&clone).write_all(b"changed clone").unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), b"original data");
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2);
        for planned_size in [12, 14] {
            assert!(root
                .clone_file(
                    &source,
                    &source.metadata().unwrap(),
                    &relative(b"wrong-size"),
                    planned_size
                )
                .unwrap()
                .copied()
                .is_none());
        }
        assert!(!t.path().join("wrong-size").exists());
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_clone_strips_xattrs_and_user_flags_without_changing_source() {
        use std::os::macos::fs::MetadataExt;
        if !macos_clone_support::available() {
            return;
        }
        let t = TestDir::new("clone-metadata");
        let source_path = t.path().join("source");
        fs::write(&source_path, b"data").unwrap();
        let source = File::open(&source_path).unwrap();
        let root = Root::open(t.path()).unwrap();
        for (name, value) in [
            (c"com.apple.quarantine", b"0081;66000000;syq;".as_slice()),
            (
                c"com.apple.FinderInfo",
                b"TEXTttxt000000000000000000000000".as_slice(),
            ),
        ] {
            assert_eq!(
                unsafe {
                    libc::fsetxattr(
                        source.as_raw_fd(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                        0,
                    )
                },
                0
            );
        }
        for flags in [libc::UF_NODUMP, libc::UF_IMMUTABLE, libc::UF_APPEND] {
            assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), flags) }, 0);
            let result = root.clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"partial"),
                4,
            );
            let source_flags = source.metadata().unwrap().st_flags();
            // Restore fixture mutability even if cloning failed.
            assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), 0) }, 0);
            let clone = result
                .unwrap()
                .copied()
                .expect("ordinary xattrs and user flags must allow cloning");
            assert_eq!(source_flags, flags);
            assert_eq!(clone.metadata().unwrap().st_flags(), 0);
            assert_eq!(
                unsafe { libc::flistxattr(clone.as_raw_fd(), std::ptr::null_mut(), 0, 0) },
                0
            );
            assert!(
                unsafe { libc::flistxattr(source.as_raw_fd(), std::ptr::null_mut(), 0, 0) } > 0
            );
            (&clone).write_all(b"copy").unwrap();
            assert_eq!(fs::read(&source_path).unwrap(), b"data");
            fs::remove_file(t.path().join("partial")).unwrap();
        }
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_clone_refuses_compression_added_after_source_snapshot() {
        if !macos_clone_support::available() {
            return;
        }
        use std::os::macos::fs::MetadataExt;
        let t = TestDir::new("clone-raced-compression");
        let original = t.path().join("original");
        let compressed = t.path().join("compressed");
        let data = b"compressible test data\n".repeat(250_000);
        fs::write(&original, &data).unwrap();
        let snapshot = fs::metadata(&original).unwrap();
        assert!(Command::new("/usr/bin/ditto")
            .arg("--hfsCompression")
            .arg(&original)
            .arg(&compressed)
            .status()
            .unwrap()
            .success());
        let source = File::open(&compressed).unwrap();
        assert_ne!(
            source.metadata().unwrap().st_flags() & libc::UF_COMPRESSED,
            0
        );
        // Model a source compressed between the prelude stat and cloning.
        let root = Root::open(t.path()).unwrap();
        assert!(root
            .clone_file(&source, &snapshot, &relative(b"partial"), data.len() as u64)
            .unwrap()
            .copied()
            .is_none());
        assert_eq!(fs::read(&compressed).unwrap(), data);
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_clone_falls_back_for_destination_acl_inheritance() {
        if !macos_clone_support::available() {
            return;
        }
        let t = TestDir::new("clone-acl");
        fs::write(t.path().join("source"), b"data").unwrap();
        let source = File::open(t.path().join("source")).unwrap();
        let root = Root::open(t.path()).unwrap();
        for rule in [
            "everyone allow read,readattr,readextattr,readsecurity,file_inherit",
            "everyone allow read,readattr,readextattr,readsecurity,directory_inherit",
        ] {
            assert!(Command::new("/bin/chmod")
                .args(["+a", "everyone deny delete"])
                .arg(t.path())
                .status()
                .unwrap()
                .success());
            assert!(root
                .clone_file(
                    &source,
                    &source.metadata().unwrap(),
                    &relative(b"noninherited"),
                    4
                )
                .unwrap()
                .copied()
                .is_some());
            fs::remove_file(t.path().join("noninherited")).unwrap();
            assert!(Command::new("/bin/chmod")
                .args(["+a", rule])
                .arg(t.path())
                .status()
                .unwrap()
                .success());
            assert!(root
                .clone_file(
                    &source,
                    &source.metadata().unwrap(),
                    &relative(b"partial"),
                    4
                )
                .unwrap()
                .copied()
                .is_none());
            assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
            assert!(Command::new("/bin/chmod")
                .arg("-N")
                .arg(t.path())
                .status()
                .unwrap()
                .success());
            // Ineligibility is per-directory, never cached for the volume.
            assert!(root
                .clone_file(
                    &source,
                    &source.metadata().unwrap(),
                    &relative(b"after-acl"),
                    4
                )
                .unwrap()
                .copied()
                .is_some());
            fs::remove_file(t.path().join("after-acl")).unwrap();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_clone_normalizes_mode_before_opening() {
        if !macos_clone_support::available() {
            return;
        }
        let t = TestDir::new("clone-owner-mode");
        let path = t.path().join("source");
        fs::write(&path, b"data").unwrap();
        // ACL read access lets us reproduce a caller-readable source whose
        // owner bits forbid reading, without requiring a second OS account.
        assert!(Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o044)).unwrap();
        let source = File::open(&path).unwrap();
        let root = Root::open(t.path()).unwrap();
        assert!(Command::new("/bin/chmod")
            .arg("-N")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/bin/chmod")
            .args([
                "+a",
                "everyone allow read,readattr,readextattr,readsecurity"
            ])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert_eq!(
            unsafe { libc::fchflags(source.as_raw_fd(), libc::UF_IMMUTABLE) },
            0
        );
        let locked = root.clone_file(
            &source,
            &source.metadata().unwrap(),
            &relative(b"locked"),
            4,
        );
        assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), 0) }, 0);
        let locked = locked
            .unwrap()
            .copied()
            .expect("flags are cleared before owner access");
        assert_eq!(locked.metadata().unwrap().mode() & 0o777, 0o600);
        fs::remove_file(t.path().join("locked")).unwrap();
        let clone = root
            .clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"partial"),
                4,
            )
            .unwrap()
            .copied()
            .unwrap();
        assert_eq!(clone.metadata().unwrap().mode() & 0o777, 0o600);
        (&clone).write_all(b"copy").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"data");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apfs_clone_noownercopy_does_not_copy_source_acl() {
        if !macos_clone_support::available() {
            return;
        }
        let t = TestDir::new("clone-source-acl");
        let path = t.path().join("source");
        fs::write(&path, b"data").unwrap();
        for rule in [
            "everyone deny write,append",
            "everyone allow read,readattr,readextattr,readsecurity",
        ] {
            assert!(Command::new("/bin/chmod")
                .args(["+a", rule])
                .arg(&path)
                .status()
                .unwrap()
                .success());
        }
        let source = File::open(&path).unwrap();
        let parent = File::open(t.path()).unwrap();
        // Independent API check, before syq performs any normalization.
        assert_eq!(
            unsafe {
                libc::fclonefileat(
                    source.as_raw_fd(),
                    parent.as_raw_fd(),
                    c"raw-clone".as_ptr(),
                    2,
                )
            },
            0
        );
        let source_acl = Command::new("/bin/ls")
            .arg("-le")
            .arg(&path)
            .output()
            .unwrap();
        let clone_acl = Command::new("/bin/ls")
            .arg("-le")
            .arg(t.path().join("raw-clone"))
            .output()
            .unwrap();
        assert!(source_acl.status.success() && clone_acl.status.success());
        let source_acl = String::from_utf8(source_acl.stdout).unwrap();
        let clone_acl = String::from_utf8(clone_acl.stdout).unwrap();
        eprintln!("source ACL:\n{source_acl}raw CLONE_NOOWNERCOPY clone:\n{clone_acl}");
        assert!(source_acl.contains("deny") && source_acl.contains("allow"));
        assert!(
            !clone_acl.contains("deny") && !clone_acl.contains("allow"),
            "{clone_acl}"
        );
        OpenOptions::new()
            .write(true)
            .open(t.path().join("raw-clone"))
            .unwrap();
        let root = Root::open(t.path()).unwrap();
        let clone = root
            .clone_file(
                &source,
                &source.metadata().unwrap(),
                &relative(b"normalized"),
                4,
            )
            .unwrap()
            .copied()
            .unwrap();
        (&clone).write_all(b"copy").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"data");
    }

    #[cfg(target_os = "linux")]
    fn require_test_openat2(result: io::Result<File>) -> Option<File> {
        match result {
            Ok(file) => Some(file),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS | libc::EPERM | libc::EACCES)
                ) =>
            {
                // Production retains the secure component walker when the
                // running kernel or its syscall policy does not allow openat2.
                None
            }
            Err(error) => panic!("openat2 fast path failed unexpectedly: {error}"),
        }
    }

    #[test]
    fn rooted_name_max_queries_each_filesystem_once() {
        let tree = TestDir::new("name-max-cache");
        fs::create_dir_all(tree.path().join("first")).unwrap();
        fs::create_dir_all(tree.path().join("second")).unwrap();
        let root = Root::open(tree.path()).unwrap();
        let cache = Mutex::new(HashMap::new());
        let queries = AtomicUsize::new(0);
        let query = |_directory: &File| {
            queries.fetch_add(1, Ordering::Relaxed);
            Ok(143)
        };

        assert_eq!(
            root.name_max_for_parent_cached(&relative(b"first/missing/file"), &cache, &query,)
                .unwrap(),
            143
        );
        assert_eq!(
            root.name_max_for_parent_cached(&relative(b"second/file"), &cache, &query)
                .unwrap(),
            143
        );
        assert_eq!(queries.load(Ordering::Relaxed), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_directory_walk_matches_component_walk() {
        let tree = TestDir::new("openat2-directory-walk");
        fs::create_dir_all(tree.path().join("first/second/third")).unwrap();
        let base = File::open(tree.path()).unwrap();
        let components = relative(b"first/second/third").components;

        let Some(fast) =
            require_test_openat2(open_directory_components_openat2(&base, &components))
        else {
            return;
        };
        let component_walk = open_directory_components_one_at_a_time(&base, &components).unwrap();
        let fast_metadata = fast.metadata().unwrap();
        let component_metadata = component_walk.metadata().unwrap();

        assert_eq!(fast_metadata.dev(), component_metadata.dev());
        assert_eq!(fast_metadata.ino(), component_metadata.ino());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_directory_walk_refuses_intermediate_symlink() {
        let tree = TestDir::new("openat2-directory-symlink");
        fs::create_dir_all(tree.path().join("real/child")).unwrap();
        symlink("real", tree.path().join("link")).unwrap();
        let base = File::open(tree.path()).unwrap();
        let supported = relative(b"real/child").components;
        if require_test_openat2(open_directory_components_openat2(&base, &supported)).is_none() {
            return;
        }
        let components = relative(b"link/child").components;

        assert!(open_directory_components_openat2(&base, &components).is_err());
        let component_error =
            open_directory_components_one_at_a_time(&base, &components).unwrap_err();
        let selected_error = open_directory_components(&base, &components).unwrap_err();
        assert_eq!(
            selected_error.raw_os_error(),
            component_error.raw_os_error()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn openat2_directory_walk_allows_nested_mounts() {
        if !Path::new("/proc/sys").is_dir() {
            return;
        }
        let base = File::open("/").unwrap();
        let components = relative(b"proc/sys").components;

        let Some(fast) =
            require_test_openat2(open_directory_components_openat2(&base, &components))
        else {
            return;
        };
        let component_walk = open_directory_components_one_at_a_time(&base, &components).unwrap();
        let fast_metadata = fast.metadata().unwrap();
        let component_metadata = component_walk.metadata().unwrap();

        assert_eq!(fast_metadata.dev(), component_metadata.dev());
        assert_eq!(fast_metadata.ino(), component_metadata.ino());
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
    fn trusted_owner_never_falls_back_to_a_second_pathname_lookup() {
        assert!(
            require_operator_link_fallback_allowed(OperatorSymlinkPolicy::TrustedOwner).is_err()
        );
        assert!(require_operator_link_fallback_allowed(OperatorSymlinkPolicy::FollowAll).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_fifo_reopens_exactly_and_waits_for_a_writer() {
        use std::sync::mpsc;
        use std::time::Duration;

        let tree = TestDir::new("operator-fifo-read");
        let fifo = tree.path().join("rules");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let base = File::open(tree.path()).unwrap();
        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        let selected = resolver
            .resolve(
                b"rules",
                OperatorFinalComponent::ReadableEntry {
                    follow_symlink: true,
                },
                false,
                &mut Vec::new(),
            )
            .unwrap();
        let PinnedPath::Leaf(leaf) = selected else {
            panic!("FIFO was not selected as a leaf");
        };

        let (opened_tx, opened_rx) = mpsc::sync_channel(1);
        let opener = std::thread::spawn(move || opened_tx.send(leaf.open_read()).unwrap());
        assert!(matches!(
            opened_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        let mut writer = File::options().write(true).open(&fifo).unwrap();
        writer.write_all(b"drop\n").unwrap();
        drop(writer);
        let mut reader = opened_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("exact FIFO reopen did not rendezvous with its writer")
            .unwrap();
        let mut contents = Vec::new();
        reader.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"drop\n");
        opener.join().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn selected_fifo_fails_closed_without_an_exact_reopen() {
        let tree = TestDir::new("operator-fifo-cutout");
        let fifo = tree.path().join("rules");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let base = File::open(tree.path()).unwrap();
        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        let selected = resolver
            .resolve(
                b"rules",
                OperatorFinalComponent::ReadableEntry {
                    follow_symlink: true,
                },
                false,
                &mut Vec::new(),
            )
            .unwrap();
        let PinnedPath::Leaf(leaf) = selected else {
            panic!("FIFO was not selected as a leaf");
        };
        let error = leaf.open_read().unwrap_err().to_string();
        assert!(error.contains("exact descriptor"), "{error}");
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
        assert!(resolver
            .resolve(
                b"../outside",
                OperatorFinalComponent::Directory,
                false,
                &mut Vec::new(),
            )
            .is_err());
    }

    #[test]
    fn unconfined_operator_resolver_tracks_exit_and_reentry() {
        let tree = TestDir::new("operator-unconfined-relative");
        let base_path = tree.path().join("base");
        let inside = base_path.join("inside");
        let outside = tree.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&inside, base_path.join("absolute-reentry")).unwrap();
        let base = File::open(&base_path).unwrap();
        let resolver =
            OperatorResolver::beneath(&base, false, OperatorSymlinkPolicy::FollowAll).unwrap();

        let select_directory = |path: &[u8]| {
            let selected = resolver
                .resolve(
                    path,
                    OperatorFinalComponent::Directory,
                    false,
                    &mut Vec::new(),
                )
                .unwrap();
            let PinnedPath::Directory(directory) = selected else {
                panic!("directory was not selected");
            };
            directory.resolved_relative().map(<[u8]>::to_vec)
        };

        assert_eq!(select_directory(b"../outside"), None);
        assert_eq!(
            select_directory(b"../base/inside"),
            Some(b"inside".to_vec())
        );
        assert_eq!(
            select_directory(b"absolute-reentry"),
            Some(b"inside".to_vec())
        );
    }

    #[test]
    fn confined_process_root_accepts_parent_components_that_stay_at_root() {
        let base = File::open("/").unwrap();
        let resolver =
            OperatorResolver::beneath(&base, true, OperatorSymlinkPolicy::Refuse).unwrap();
        let selected = resolver
            .resolve(
                b"..",
                OperatorFinalComponent::Directory,
                false,
                &mut Vec::new(),
            )
            .unwrap();
        let PinnedPath::Directory(directory) = selected else {
            panic!("process root was not selected as a directory");
        };
        assert_eq!(directory.resolved_relative(), Some(&b""[..]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn operator_directory_identity_does_not_conflate_mount_contexts() {
        let identity = OperatorDirectoryIdentity {
            dev: 7,
            ino: 11,
            mount_id: Some(13),
        };
        assert!(!operator_directory_identities_match(
            identity,
            OperatorDirectoryIdentity {
                mount_id: Some(17),
                ..identity
            }
        ));
        assert!(!operator_directory_identities_match(
            identity,
            OperatorDirectoryIdentity {
                mount_id: None,
                ..identity
            }
        ));
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

        let mut limits = crate::fsops::nofile_limits().unwrap();
        assert!(
            limits.rlim_max >= 64,
            "hard file-descriptor limit is below 64"
        );
        limits.rlim_cur = 64;
        crate::fsops::set_nofile_limits(&limits).unwrap();

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
        if !crate::test_support::filesystem_accepts_non_utf8_names() {
            eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
            return;
        }
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
    fn matched_publication_authenticates_the_held_staged_inode() {
        let tree = TestDir::new("matched-publication-staged-identity");
        let root = Root::open(tree.path()).unwrap();
        let staged = relative(b"staged");
        let target = relative(b"target");
        fs::write(tree.path().join("staged"), b"staged").unwrap();
        fs::write(tree.path().join("target"), b"old").unwrap();
        let staged_file = File::open(tree.path().join("staged")).unwrap();
        let staged_metadata = staged_file.metadata().unwrap();
        let target_metadata = root.metadata(&target).unwrap();

        fs::rename(tree.path().join("staged"), tree.path().join("held-staged")).unwrap();
        fs::write(tree.path().join("staged"), b"impostor").unwrap();
        let error = root
            .replace_regular_if_same(
                &staged,
                &target,
                (staged_metadata.dev(), staged_metadata.ino()),
                target_metadata.dev,
                target_metadata.ino,
                None,
            )
            .unwrap_err();

        assert!(format!("{error:#}").contains("not the expected singly-linked regular file"));
        assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"old");
        assert_eq!(fs::read(tree.path().join("staged")).unwrap(), b"impostor");
        assert_eq!(
            staged_metadata.ino(),
            fs::metadata(tree.path().join("held-staged")).unwrap().ino()
        );
    }

    #[test]
    fn matched_publication_detects_a_staged_race_during_exchange() {
        let tree = TestDir::new("matched-publication-staged-race");
        let root = Root::open(tree.path()).unwrap();
        let staged = relative(b"staged");
        let target = relative(b"target");
        fs::write(tree.path().join("staged"), b"staged").unwrap();
        fs::write(tree.path().join("target"), b"old").unwrap();
        let staged_file = File::open(tree.path().join("staged")).unwrap();
        let staged_metadata = staged_file.metadata().unwrap();
        let target_metadata = root.metadata(&target).unwrap();

        let staged_path = tree.path().join("staged");
        let held_staged_path = tree.path().join("held-staged");
        let _before_exchange = install_publication_test_hook(
            root.identity(),
            &target,
            PublicationTestPoint::BeforeMatchedExchange,
            move || {
                fs::rename(&staged_path, &held_staged_path).unwrap();
                fs::write(&staged_path, b"impostor").unwrap();
            },
        );
        let error = root
            .replace_regular_if_same(
                &staged,
                &target,
                (staged_metadata.dev(), staged_metadata.ino()),
                target_metadata.dev,
                target_metadata.ino,
                None,
            )
            .unwrap_err();

        assert!(format!("{error:#}").contains("staged path staged changed during publication"));
        assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"impostor");
        assert_eq!(fs::read(tree.path().join("staged")).unwrap(), b"old");
        assert_eq!(
            fs::read(tree.path().join("held-staged")).unwrap(),
            b"staged"
        );
    }

    #[test]
    fn matched_publication_never_rolls_back_a_later_writer() {
        let tree = TestDir::new("matched-publication-race");
        let root = Root::open(tree.path()).unwrap();
        let staged = relative(b"staged");
        let target = relative(b"target");
        fs::write(tree.path().join("staged"), b"staged").unwrap();
        fs::write(tree.path().join("target"), b"old").unwrap();
        let staged_metadata = fs::metadata(tree.path().join("staged")).unwrap();
        let target_metadata = root.metadata(&target).unwrap();

        let target_path = tree.path().join("target");
        let old_target_path = tree.path().join("old-target");
        let _before_exchange = install_publication_test_hook(
            root.identity(),
            &target,
            PublicationTestPoint::BeforeMatchedExchange,
            move || {
                fs::rename(&target_path, &old_target_path).unwrap();
                fs::write(&target_path, b"raced-before-exchange").unwrap();
            },
        );
        let target_path = tree.path().join("target");
        let published_staged_path = tree.path().join("published-staged");
        let _after_exchange = install_publication_test_hook(
            root.identity(),
            &target,
            PublicationTestPoint::AfterMatchedExchange,
            move || {
                fs::rename(&target_path, &published_staged_path).unwrap();
                fs::write(&target_path, b"later").unwrap();
            },
        );
        let error = root
            .replace_regular_if_same(
                &staged,
                &target,
                (staged_metadata.dev(), staged_metadata.ino()),
                target_metadata.dev,
                target_metadata.ino,
                None,
            )
            .unwrap_err();

        assert!(format!("{error:#}").contains("changed during publication"));
        assert_eq!(fs::read(tree.path().join("target")).unwrap(), b"later");
        assert_eq!(
            fs::read(tree.path().join("staged")).unwrap(),
            b"raced-before-exchange"
        );
        assert_eq!(fs::read(tree.path().join("old-target")).unwrap(), b"old");
        assert_eq!(
            fs::read(tree.path().join("published-staged")).unwrap(),
            b"staged"
        );
    }

    #[test]
    fn matched_leaf_replacement_never_rolls_back_a_later_writer() {
        let tree = TestDir::new("matched-leaf-race");
        let root = Root::open(tree.path()).unwrap();
        let target = relative(b"target");
        root.create_symlink(&target, b"old").unwrap();
        let target_metadata = root.metadata(&target).unwrap();

        let target_path = tree.path().join("target");
        let old_target_path = tree.path().join("old-target");
        let _before_exchange = install_publication_test_hook(
            root.identity(),
            &target,
            PublicationTestPoint::BeforeMatchedExchange,
            move || {
                fs::rename(&target_path, &old_target_path).unwrap();
                symlink("raced-before-exchange", &target_path).unwrap();
            },
        );
        let target_path = tree.path().join("target");
        let published_replacement_path = tree.path().join("published-replacement");
        let _after_exchange = install_publication_test_hook(
            root.identity(),
            &target,
            PublicationTestPoint::AfterMatchedExchange,
            move || {
                fs::rename(&target_path, &published_replacement_path).unwrap();
                symlink("later", &target_path).unwrap();
            },
        );
        let error = root
            .replace_symlink_if_same(
                &target,
                b"replacement",
                target_metadata.dev,
                target_metadata.ino,
            )
            .unwrap_err();

        assert!(format!("{error:#}").contains("changed during replacement"));
        assert_eq!(
            fs::read_link(tree.path().join("target")).unwrap(),
            Path::new("later")
        );
        assert_eq!(
            fs::read_link(tree.path().join("old-target")).unwrap(),
            Path::new("old")
        );
        assert_eq!(
            fs::read_link(tree.path().join("published-replacement")).unwrap(),
            Path::new("replacement")
        );
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
