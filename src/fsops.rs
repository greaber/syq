//! Local filesystem operations. Used directly by the local endpoint and
//! by `syq --server` for remote endpoints, so both sides behave identically.

use crate::descriptor_broker::{
    DescriptorSessionSlot, DescriptorTicket, RegisteredRootId, DEFAULT_MAX_ROOTS,
};
use crate::proto::*;
use crate::rooted::{
    read_open_symlink, root_metadata_from_std, OperatorFinalComponent, OperatorResolver,
    PinnedPath, RelativePath, Root, RootIdentity, RootMetadata,
};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Write;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

pub const PARTIAL_MARKER: &str = ".syq-part.";
const FD_CACHE_MAX: usize = 16;
const SOURCE_FD_RESERVE: usize = 32;
// A shared worker may fill its source file cache, retain five copies of its
// transport socket in a TCP serving process, and open one uncached source file
// for HashBlocks or FileHash. Those operations are sequential per worker, so
// one uncached descriptor is the peak. Local source workers have no transport
// themselves and retain only three client-side copies of a destination TCP
// socket, but budget the larger remote-source shape for both shared variants.
const SOURCE_TCP_TRANSPORT_FDS: usize = 5;
const SOURCE_UNCACHED_FILE_FDS: usize = 1;
const SOURCE_SHARED_WORKER_FD_RESERVE: usize =
    FD_CACHE_MAX + SOURCE_TCP_TRANSPORT_FDS + SOURCE_UNCACHED_FILE_FDS;
const COMMON_NAME_MAX: usize = 255;
const COMPACT_HASH_BYTES: usize = 10;
const NAME_MAX_CACHE_CAP: usize = 1024;

pub(crate) fn content_digest(data: &[u8]) -> ContentDigest {
    *blake3::hash(data).as_bytes()
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Default)]
struct FileSystemTraits {
    is_nfs: bool,
    synchronous: bool,
    measured_local_source: bool,
}

#[derive(Clone, Copy)]
struct CopyLocalPolicy {
    inplace: bool,
    allow_sequential_nfs_fallback: bool,
}

#[cfg(target_os = "linux")]
fn file_system_traits(file: &File) -> FileSystemTraits {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    unsafe {
        if libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) != 0 {
            return FileSystemTraits::default();
        }
        let stats = stats.assume_init();
        let file_system_type = stats.f_type as u32;
        let mut mount_stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // Unknown mount flags are treated as synchronous so a metadata-query
        // failure cannot opt an unmeasured topology into the shortcut.
        let synchronous = if libc::fstatvfs(file.as_raw_fd(), mount_stats.as_mut_ptr()) == 0 {
            mount_stats.assume_init().f_flag & libc::ST_SYNCHRONOUS != 0
        } else {
            true
        };
        FileSystemTraits {
            is_nfs: file_system_type == libc::NFS_SUPER_MAGIC as u32,
            synchronous,
            // Keep the automatic optimization confined to the source
            // filesystems actually exercised by the ext-family and XFS NFS
            // benchmarks. Unknown or network-backed sources retain adaptive
            // range reads until measured independently.
            measured_local_source: matches!(
                file_system_type,
                t if t == libc::EXT4_SUPER_MAGIC as u32
                    || t == libc::XFS_SUPER_MAGIC as u32
            ),
        }
    }
}

#[cfg(target_os = "linux")]
const MODE_DIR: u32 = libc::S_IFDIR;
#[cfg(not(target_os = "linux"))]
const MODE_DIR: u32 = libc::S_IFDIR as u32;
#[cfg(target_os = "linux")]
const MODE_FILE: u32 = libc::S_IFREG;
#[cfg(not(target_os = "linux"))]
const MODE_FILE: u32 = libc::S_IFREG as u32;
#[cfg(target_os = "linux")]
const MODE_LINK: u32 = libc::S_IFLNK;
#[cfg(not(target_os = "linux"))]
const MODE_LINK: u32 = libc::S_IFLNK as u32;
#[cfg(target_os = "linux")]
const MODE_FIFO: u32 = libc::S_IFIFO;
#[cfg(not(target_os = "linux"))]
const MODE_FIFO: u32 = libc::S_IFIFO as u32;
#[cfg(target_os = "linux")]
const MODE_SOCKET: u32 = libc::S_IFSOCK;
#[cfg(not(target_os = "linux"))]
const MODE_SOCKET: u32 = libc::S_IFSOCK as u32;
#[cfg(target_os = "linux")]
const MODE_CHAR: u32 = libc::S_IFCHR;
#[cfg(not(target_os = "linux"))]
const MODE_CHAR: u32 = libc::S_IFCHR as u32;
#[cfg(target_os = "linux")]
const MODE_BLOCK: u32 = libc::S_IFBLK;
#[cfg(not(target_os = "linux"))]
const MODE_BLOCK: u32 = libc::S_IFBLK as u32;

pub fn resolve(p: &[u8]) -> PathBuf {
    if p.is_empty() {
        return PathBuf::from(".");
    }
    if p == b"~" || p.starts_with(b"~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut pb = PathBuf::from(home);
            if p.len() > 2 {
                pb.push(OsStr::from_bytes(&p[2..]));
            }
            return pb;
        }
    }
    PathBuf::from(OsStr::from_bytes(p))
}

/// A receiver-side selection retained from the ownership walk until it is
/// either created or made the connection's working directory. Keeping the fd,
/// rather than just its identity, closes the post-check pathname race.
struct OperatorDirectorySelection {
    path: PathBytes,
    directory: File,
    missing: VecDeque<Vec<u8>>,
}

impl OperatorDirectorySelection {
    fn anchor(&self) -> Result<DirectoryAnchor> {
        let metadata = self.directory.metadata()?;
        Ok(DirectoryAnchor {
            path: self.path.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn create_missing(&mut self, mode: u32, require_absent: bool) -> Result<DirectoryAnchor> {
        while let Some(component) = self.missing.pop_front() {
            if component == b"." {
                continue;
            }
            if component == b".." {
                self.directory = open_operator_directory_at(&self.directory, b"..")?;
                continue;
            }
            let final_component = self.missing.is_empty();
            match operator_lstat_at(&self.directory, &component) {
                Ok(metadata)
                    if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR
                        && !(final_component && require_absent) => {}
                Ok(metadata) if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR => {
                    bail!("destination directory appeared after the new-target precondition")
                }
                Ok(_) => bail!(
                    "destination path component {:?} appeared with an unsafe type while creating the destination",
                    OsStr::from_bytes(&component)
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // Match create_dir_all's historical behavior: intermediate
                    // components start at 0777 (subject to umask), while the
                    // requested mode applies to the selected destination root.
                    let component_mode = if self.missing.is_empty() { mode } else { 0o777 };
                    match mkdir_operator_directory_at(
                        &self.directory,
                        &component,
                        component_mode,
                    ) {
                        Ok(()) => {}
                        Err(error)
                            if error.kind() == io::ErrorKind::AlreadyExists
                                && final_component
                                && require_absent =>
                        {
                            bail!("destination directory appeared after the new-target precondition")
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            match operator_lstat_at(&self.directory, &component) {
                                Ok(metadata)
                                    if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
                                Ok(_) => bail!(
                                    "destination path component {:?} appeared with an unsafe type while creating the destination",
                                    OsStr::from_bytes(&component)
                                ),
                                Err(error) => return Err(error.into()),
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
            self.directory = open_operator_directory_at(&self.directory, &component)?;
        }
        self.anchor()
    }
}

/// Resolve an operator-selected directory under the requested symlink policy.
/// The descriptor remains in the returned selection.
fn select_operator_directory(
    path: &[u8],
    allow_missing: bool,
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<(OperatorDirectorySelection, Option<DirectoryAnchor>)> {
    let path = resolve(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let raw = path.as_os_str().as_bytes();
    if raw.contains(&0) {
        bail!("destination path contains NUL");
    }
    let mut hops = Vec::new();
    match OperatorResolver::resolve_process(
        raw,
        symlink_policy,
        OperatorFinalComponent::Directory,
        allow_missing,
        &mut hops,
    )? {
        PinnedPath::Directory(directory) => {
            let (directory, _) = directory.into_parts();
            let selection = OperatorDirectorySelection {
                path: path_bytes(&path),
                directory,
                missing: VecDeque::new(),
            };
            let anchor = selection.anchor()?;
            Ok((selection, Some(anchor)))
        }
        PinnedPath::Missing(missing) => {
            let (directory, missing) = missing.into_parts();
            Ok((
                OperatorDirectorySelection {
                    path: path_bytes(&path),
                    directory,
                    missing,
                },
                None,
            ))
        }
        PinnedPath::Leaf(_) => bail!("destination path is not a directory"),
    }
}

/// Check the current spelling of an operator-supplied local path without
/// traversing a symlink. This is semantic preflight for orchestrator-local
/// control files; retaining their opened identity belongs to the broader
/// descriptor-root migration.
pub(crate) fn check_operator_path_no_symlinks(
    path: &[u8],
    allow_final_symlink: bool,
    allow_missing_final: bool,
) -> Result<()> {
    let path = resolve(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let raw = path.as_os_str().as_bytes();
    if raw.contains(&0) {
        bail!("operator path contains NUL");
    }
    let mut hops = Vec::new();
    match OperatorResolver::resolve_process(
        raw,
        OperatorSymlinkPolicy::Refuse,
        OperatorFinalComponent::Entry {
            follow_symlink: false,
        },
        allow_missing_final,
        &mut hops,
    )? {
        PinnedPath::Directory(_) => Ok(()),
        PinnedPath::Leaf(leaf) if !leaf.metadata().is_symlink() || allow_final_symlink => Ok(()),
        PinnedPath::Leaf(_) => bail!(
            "operator path encounters a last-component symlink; pass --follow to resolve symlinks"
        ),
        PinnedPath::Missing(missing) => {
            let (_, components) = missing.into_parts();
            if components.len() == 1 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(libc::ENOENT).into())
            }
        }
    }
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

fn open_operator_directory_at(parent: &File, component: &[u8]) -> Result<File> {
    let component = CString::new(component).expect("path component was checked for NUL");
    open_operator_directory_fd(parent.as_raw_fd(), &component)
}

fn open_operator_directory_fd(parent: libc::c_int, component: &CStr) -> Result<File> {
    loop {
        let fd = unsafe { libc::openat(parent, component.as_ptr(), operator_directory_flags()) };
        if fd >= 0 {
            let file = unsafe { File::from_raw_fd(fd) };
            if !file.metadata()?.is_dir() {
                bail!("destination path component is not a directory");
            }
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn mkdir_operator_directory_at(parent: &File, component: &[u8], mode: u32) -> io::Result<()> {
    let component = CString::new(component).expect("path component was checked for NUL");
    loop {
        let result = unsafe {
            libc::mkdirat(
                parent.as_raw_fd(),
                component.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn operator_lstat_at(parent: &File, component: &[u8]) -> io::Result<libc::stat> {
    let component = CString::new(component).expect("path component was checked for NUL");
    loop {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                component.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(unsafe { metadata.assume_init() });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub fn path_bytes(p: &Path) -> PathBytes {
    p.as_os_str().as_bytes().to_vec()
}

pub fn join(root: &[u8], rel: &[u8]) -> PathBytes {
    if rel.is_empty() {
        return root.to_vec();
    }
    if root.is_empty() {
        return rel.to_vec();
    }
    let mut v = root.to_vec();
    if !v.ends_with(b"/") {
        v.push(b'/');
    }
    v.extend_from_slice(rel);
    v
}

fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bits = 0u32;
    let mut nbits = 0u8;
    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits != 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

fn name_max(parent: &Path) -> usize {
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let key = parent.to_path_buf();
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(limit) = cache.lock().unwrap().get(&key).copied() {
        return limit;
    }
    // Preflight often runs before mapped destination subdirectories have been
    // created. Query the nearest existing directory on the same path instead
    // of silently assuming 255; absent a concurrent mount change, descendants
    // inherit that filesystem's component limit.
    let query_parent = nearest_existing_directory(parent);
    let Ok(c_parent) = cstr(&query_parent) else {
        return COMMON_NAME_MAX;
    };
    let limit = unsafe { libc::pathconf(c_parent.as_ptr(), libc::_PC_NAME_MAX) };
    let limit = if limit > 0 {
        limit as usize
    } else {
        COMMON_NAME_MAX
    };
    let mut cache = cache.lock().unwrap();
    if cache.len() >= NAME_MAX_CACHE_CAP {
        cache.clear();
    }
    cache.insert(key, limit);
    limit
}

fn nearest_existing_directory(path: &Path) -> PathBuf {
    let mut candidate = if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path.to_path_buf()
    };
    loop {
        // An in-tree symlink is replaced during planning, not traversed. Use
        // lstat semantics here too so preflight and the eventual worker query
        // the containing filesystem rather than the symlink target.
        if fs::symlink_metadata(&candidate).is_ok_and(|metadata| metadata.is_dir()) {
            return candidate;
        }
        if !candidate.pop() || candidate.as_os_str().is_empty() {
            return PathBuf::from(".");
        }
    }
}

fn safe_prefix_len(name: &[u8], requested: usize) -> usize {
    let mut keep = requested.min(name.len());
    if let Ok(name) = std::str::from_utf8(name) {
        while !name.is_char_boundary(keep) {
            keep -= 1;
        }
    }
    keep
}

fn path_component_budget(parent: &Path, component_limit: usize) -> usize {
    let parent_len = parent.as_os_str().as_bytes().len();
    let separator = usize::from(
        !parent.as_os_str().is_empty() && !parent.as_os_str().as_bytes().ends_with(b"/"),
    );
    let path_limit = libc::PATH_MAX as usize;
    let path_budget = path_limit
        .saturating_sub(1)
        .saturating_sub(parent_len)
        .saturating_sub(separator);
    component_limit.min(path_budget)
}

/// Adjacent deterministic sidecar for this logical job. The common form keeps
/// both the destination basename and job ID visible. Long basenames are
/// truncated and disambiguated; near PATH_MAX a compact combined digest keeps
/// a little more of rsync's practical path reach.
pub fn partial_path(final_: &Path, partial_id: &PartialId) -> Result<PathBuf> {
    let parent = final_.parent().unwrap_or_else(|| Path::new(""));
    partial_path_with_name_max(final_, partial_id, name_max(parent))
}

pub(crate) fn partial_path_with_name_max(
    final_: &Path,
    partial_id: &PartialId,
    component_limit: usize,
) -> Result<PathBuf> {
    let name = final_.file_name().map(OsStr::as_bytes).unwrap_or(b"root");
    let job_id = base32(partial_id);
    let mut normal = Vec::with_capacity(1 + name.len() + PARTIAL_MARKER.len() + job_id.len());
    normal.push(b'.');
    normal.extend_from_slice(name);
    normal.extend_from_slice(PARTIAL_MARKER.as_bytes());
    normal.extend_from_slice(job_id.as_bytes());

    let parent = final_.parent().unwrap_or_else(|| Path::new(""));
    let budget = path_component_budget(parent, component_limit);
    let component = if normal.len() <= budget {
        normal
    } else {
        let basename_hash = Sha256::digest(name);
        let basename_hash = base32(&basename_hash[..12]);
        let overhead = 1 + 1 + basename_hash.len() + PARTIAL_MARKER.len() + job_id.len();
        if budget > overhead {
            let keep = safe_prefix_len(name, budget - overhead);
            let mut shortened = Vec::with_capacity(budget);
            shortened.push(b'.');
            shortened.extend_from_slice(&name[..keep]);
            shortened.push(b'.');
            shortened.extend_from_slice(basename_hash.as_bytes());
            shortened.extend_from_slice(PARTIAL_MARKER.as_bytes());
            shortened.extend_from_slice(job_id.as_bytes());
            shortened
        } else {
            let mut hash = Sha256::new();
            hash.update(partial_id);
            hash.update([0]);
            hash.update(name);
            let digest = hash.finalize();
            let compact = format!("{PARTIAL_MARKER}{}", base32(&digest[..COMPACT_HASH_BYTES]));
            if compact.len() > budget {
                bail!(
                    "cannot create a safe partial name beside {}: path is too long",
                    final_.display()
                );
            }
            compact.into_bytes()
        }
    };
    let component = OsString::from_vec(component);
    Ok(if parent.as_os_str().is_empty() {
        PathBuf::from(component)
    } else {
        parent.join(component)
    })
}

pub fn is_partial_name(name: &OsStr) -> bool {
    let b = name.as_bytes();
    let valid_id = |id: &[u8], len: usize| {
        id.len() == len
            && id
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    };
    if !b.starts_with(b".") {
        return false;
    }
    if let Some(pos) = b
        .windows(PARTIAL_MARKER.len())
        .rposition(|part| part == PARTIAL_MARKER.as_bytes())
    {
        let id = &b[pos + PARTIAL_MARKER.len()..];
        return if pos == 0 {
            valid_id(id, 16)
        } else {
            valid_id(id, 26)
        };
    }
    false
}

/// Absolute, normalized form of a path, resolved the way the kernel resolves
/// it: component by component, symlinks followed as they are met, so `..`
/// after a symlink pops the link's *target*. Once a component does not exist
/// the rest is normalized lexically. Stable across spellings of one place.
pub fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::from("/");
    let mut exists = true;
    for c in abs.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(name);
                if exists {
                    match fs::canonicalize(&out) {
                        Ok(real) => out = real,
                        Err(_) => exists = false,
                    }
                }
            }
        }
    }
    out
}

pub fn entry_from_meta(rel: PathBytes, full: &Path, md: &fs::Metadata) -> Entry {
    let ft = md.file_type();
    let kind = if ft.is_dir() {
        Kind::Dir
    } else if ft.is_file() {
        Kind::File
    } else if ft.is_symlink() {
        Kind::Symlink
    } else {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            Kind::Fifo
        } else if ft.is_socket() {
            Kind::Socket
        } else if ft.is_char_device() {
            Kind::CharDev
        } else if ft.is_block_device() {
            Kind::BlockDev
        } else {
            Kind::Other
        }
    };
    let link = if kind == Kind::Symlink {
        fs::read_link(full)
            .ok()
            .map(|t| t.into_os_string().into_vec())
    } else {
        None
    };
    Entry {
        path: rel,
        kind,
        size: if kind == Kind::File { md.len() } else { 0 },
        mtime: md.mtime(),
        mtime_nsec: md.mtime_nsec() as u32,
        mode: md.mode(),
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev(),
        dev: md.dev(),
        ino: md.ino(),
        ctime: md.ctime(),
        ctime_nsec: md.ctime_nsec() as u32,
        link,
    }
}

pub(crate) fn rooted_entry(
    root: &Root,
    relative: &RelativePath,
    path: PathBytes,
    metadata: RootMetadata,
) -> Result<Entry> {
    let kind = match metadata.file_type() {
        MODE_DIR => Kind::Dir,
        MODE_FILE => Kind::File,
        MODE_LINK => Kind::Symlink,
        MODE_FIFO => Kind::Fifo,
        MODE_SOCKET => Kind::Socket,
        MODE_CHAR => Kind::CharDev,
        MODE_BLOCK => Kind::BlockDev,
        _ => Kind::Other,
    };
    let link = if kind == Kind::Symlink {
        let target = root.read_link(relative)?;
        let after = root.metadata(relative)?;
        if (after.dev, after.ino, after.file_type())
            != (metadata.dev, metadata.ino, metadata.file_type())
        {
            bail!("symlink changed while reading its target");
        }
        Some(target)
    } else {
        None
    };
    Ok(entry_from_root_metadata(path, metadata, kind, link))
}

/// Build an entry for a registered source. An exact symlink's target is the
/// descriptor-bound registration snapshot: reading it through `relative`
/// would let a same-inode A -> B -> A name race return B's target.
pub(crate) fn rooted_source_entry(
    root: &Root,
    relative: &RelativePath,
    path: PathBytes,
    metadata: RootMetadata,
    expected: Option<&SourceLeafIdentity>,
) -> Result<Entry> {
    let Some(expected) = expected else {
        return rooted_entry(root, relative, path, metadata);
    };
    require_source_leaf_identity(expected, metadata)?;
    if metadata.is_symlink() {
        let target = expected
            .symlink_target
            .clone()
            .context("registered source symlink is missing its pinned target")?;
        return Ok(entry_from_root_metadata(
            path,
            metadata,
            Kind::Symlink,
            Some(target),
        ));
    }
    if expected.symlink_target.is_some() {
        bail!("registered non-symlink source carries a symlink target");
    }
    rooted_entry(root, relative, path, metadata)
}

/// Build an entry relative to a directory already opened by a descriptor
/// scanner. Symlink target reads and the confirming stat use that same parent
/// descriptor, so neither operation has to rewalk a possibly renamed path.
pub(crate) fn rooted_entry_in_directory(
    root: &Root,
    directory: &File,
    name: &[u8],
    path: PathBytes,
    metadata: RootMetadata,
) -> Result<Entry> {
    let kind = match metadata.file_type() {
        MODE_DIR => Kind::Dir,
        MODE_FILE => Kind::File,
        MODE_LINK => Kind::Symlink,
        MODE_FIFO => Kind::Fifo,
        MODE_SOCKET => Kind::Socket,
        MODE_CHAR => Kind::CharDev,
        MODE_BLOCK => Kind::BlockDev,
        _ => Kind::Other,
    };
    let link = if kind == Kind::Symlink {
        let target = root.read_link_in_directory(directory, name)?;
        let after = root.metadata_in_directory(directory, name)?;
        if (after.dev, after.ino, after.file_type())
            != (metadata.dev, metadata.ino, metadata.file_type())
        {
            bail!("symlink changed while reading its target");
        }
        Some(target)
    } else {
        None
    };
    Ok(entry_from_root_metadata(path, metadata, kind, link))
}

fn entry_from_root_metadata(
    path: PathBytes,
    metadata: RootMetadata,
    kind: Kind,
    link: Option<PathBytes>,
) -> Entry {
    Entry {
        path,
        kind,
        size: if kind == Kind::File { metadata.len } else { 0 },
        mtime: metadata.mtime,
        mtime_nsec: metadata.mtime_nsec,
        mode: metadata.mode,
        uid: metadata.uid,
        gid: metadata.gid,
        rdev: metadata.rdev,
        dev: metadata.dev,
        ino: metadata.ino,
        ctime: metadata.ctime,
        ctime_nsec: metadata.ctime_nsec,
        link,
    }
}

pub fn lstat_entry(rel: PathBytes, full: &Path) -> io::Result<Entry> {
    let md = fs::symlink_metadata(full)?;
    Ok(entry_from_meta(rel, full, &md))
}

fn errstr(e: &anyhow::Error) -> String {
    format!("{e:#}")
}

fn cstr(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| anyhow!("path contains NUL"))
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn process_initial_cwd() -> PathBuf {
    static INITIAL_CWD: OnceLock<PathBuf> = OnceLock::new();
    INITIAL_CWD
        .get_or_init(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .clone()
}

fn source_descriptor_requirement(
    current_open: usize,
    root_count: usize,
    shared_workers: usize,
    independent_workers: usize,
) -> Result<usize> {
    // Conservatively treat every selection as an exact leaf. The registry,
    // control connection, and each shared worker then retain both its parent
    // and object. Independent SSH workers retain those descriptors in their
    // own processes, but each concurrent broker claim transiently costs this
    // process an accepted socket, tracked socket clone, and descriptor clone.
    root_count
        .checked_mul(
            shared_workers
                .checked_add(2)
                .context("source worker count overflow")?,
        )
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| {
            SOURCE_SHARED_WORKER_FD_RESERVE
                .checked_mul(shared_workers)
                .and_then(|workers| count.checked_add(workers))
        })
        .and_then(|count| {
            independent_workers
                .checked_mul(3)
                .and_then(|claims| count.checked_add(claims))
        })
        .and_then(|count| count.checked_add(SOURCE_FD_RESERVE))
        .and_then(|count| count.checked_add(current_open))
        .context("source descriptor requirement overflow")
}

/// Count a snapshot of the process's live descriptors. Reading an fd directory keeps
/// the common Linux and Darwin paths proportional to the number of open
/// descriptors. Its directory descriptor is visible in the listing, which is
/// a harmless conservative overcount. The portable fallback scans the finite
/// descriptor range and treats unexpected `fcntl` errors as open.
fn current_open_descriptor_count(soft_limit: libc::rlim_t) -> Result<usize> {
    for fd_directory in ["/proc/self/fd", "/dev/fd"] {
        if let Ok(entries) = fs::read_dir(fd_directory) {
            return Ok(entries.count());
        }
    }

    let limit = usize::try_from(soft_limit).context("open-file limit does not fit usize")?;
    let max_fd = usize::try_from(libc::c_int::MAX).expect("c_int maximum fits usize");
    if limit > max_fd {
        bail!("cannot conservatively inspect {limit} possible open descriptors on this platform");
    }
    let mut open = 0usize;
    for fd in 0..limit {
        let fd = fd as libc::c_int;
        loop {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
                open += 1;
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() != Some(libc::EBADF) {
                open += 1;
            }
            break;
        }
    }
    Ok(open)
}

fn require_source_descriptor_capacity(
    root_count: usize,
    shared_workers: usize,
    independent_workers: usize,
) -> Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error()).context("read source endpoint file limit");
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return Ok(());
    }
    let current_open = current_open_descriptor_count(limit.rlim_cur)?;
    let required = source_descriptor_requirement(
        current_open,
        root_count,
        shared_workers,
        independent_workers,
    )?;
    if required as u128 > limit.rlim_cur as u128 {
        bail!(
            "source setup needs about {required} open-file slots ({current_open} currently open) for {root_count} roots, {shared_workers} shared workers, and {independent_workers} independent workers, but this endpoint permits {}; reduce the number of source selectors or use a smaller explicit --connections value",
            limit.rlim_cur
        );
    }
    Ok(())
}

pub struct FsOps {
    fds: HashMap<FdKey, File>,
    fd_order: Vec<FdKey>,
    /// One final-file descriptor retained between the hash response and the
    /// controller's decision to repair or accept that exact inode.
    held_basis: Option<HeldBasis>,
    operator_selection: Option<OperatorDirectorySelection>,
    descriptor_session: DescriptorSessionSlot,
    source_roots: HashMap<RegisteredRootId, SourceRootHandle>,
    allow_unconfined_source_paths: bool,
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<PathBytes>,
    initial_cwd: PathBuf,
}

struct HeldBasis {
    path: PathBuf,
    partial_id: PartialId,
    file: File,
}

struct SourceRootHandle {
    root: Arc<Root>,
    /// Each worker retains its own exact-object clone for the entire worker
    /// lifetime. Content opens compare the opened name with both the serialized
    /// identity and this retained object, preventing inode reuse while the
    /// literal name is checked.
    _leaf_object: Option<Arc<File>>,
    /// An empty selection authorizes the whole registered directory. A
    /// non-empty selection is one exact leaf beneath the registered parent.
    selection: PathBytes,
    expected_leaf: Option<SourceLeafIdentity>,
}

struct RegisteredSourceTarget {
    root: Arc<Root>,
    relative: RelativePath,
    expected_leaf: Option<SourceLeafIdentity>,
    leaf_object: Option<Arc<File>>,
}

pub(crate) struct SourceScanRoot {
    pub(crate) root: Arc<Root>,
    pub(crate) relative: PathBytes,
    pub(crate) expected_leaf: Option<SourceLeafIdentity>,
}

pub(crate) fn require_source_leaf_identity(
    expected: &SourceLeafIdentity,
    metadata: RootMetadata,
) -> Result<()> {
    if (metadata.dev, metadata.ino, metadata.file_type())
        != (expected.dev, expected.ino, expected.file_type)
    {
        bail!(
            "registered source leaf changed identity (expected {}:{} type {:#o}, found {}:{} type {:#o})",
            expected.dev,
            expected.ino,
            expected.file_type,
            metadata.dev,
            metadata.ino,
            metadata.file_type()
        );
    }
    Ok(())
}

/// Open one registered regular source without following any component. For an
/// exact operator-selected leaf, validating the opened descriptor is the
/// decisive check: once it matches, the descriptor itself pins that object for
/// the whole read even if its name is replaced concurrently.
fn open_registered_source(target: &RegisteredSourceTarget) -> Result<File> {
    let file = target.root.open_regular_read(&target.relative)?;
    match (&target.expected_leaf, &target.leaf_object) {
        (Some(expected), Some(object)) => {
            let opened = root_metadata_from_std(&file.metadata()?)?;
            let retained = root_metadata_from_std(&object.metadata()?)?;
            require_source_leaf_identity(expected, retained)?;
            require_source_leaf_identity(expected, opened)?;
        }
        (None, None) => {}
        _ => bail!("registered source leaf identity and retained object disagree"),
    }
    Ok(file)
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct FdKey {
    /// A registered source root is part of the cache identity. Parallel
    /// legacy path spellings never alias a confined source descriptor.
    source_root: Option<RegisteredRootId>,
    path: PathBuf,
    /// Source files and partials get a fresh cache entry after a source-change
    /// retry. An old descriptor may point at an inode that was renamed away.
    attempt: u32,
    /// Keep a validated sidecar from sharing an unchecked cache entry.
    private: bool,
}

struct PartialTarget<'a> {
    path: &'a [u8],
    id: &'a PartialId,
    guard: Option<&'a ContainerGuard>,
}

struct HashTarget<'a> {
    path: &'a [u8],
    source: Option<&'a RegisteredPath>,
    guard: Option<&'a ContainerGuard>,
}

struct TargetMutation<'a> {
    condition: TargetCondition,
    guard: Option<&'a ContainerGuard>,
}

impl Default for FsOps {
    fn default() -> Self {
        Self::new()
    }
}

impl FsOps {
    pub fn new() -> Self {
        Self::with_descriptor_session(DescriptorSessionSlot::default())
    }

    pub(crate) fn with_descriptor_session(descriptor_session: DescriptorSessionSlot) -> Self {
        FsOps {
            fds: HashMap::new(),
            fd_order: Vec::new(),
            held_basis: None,
            operator_selection: None,
            descriptor_session,
            source_roots: HashMap::new(),
            allow_unconfined_source_paths: false,
            destination_root: None,
            destination_prefix: None,
            initial_cwd: process_initial_cwd(),
        }
    }

    fn check_operator_directory(
        &mut self,
        path: &[u8],
        allow_missing: bool,
        symlink_policy: OperatorSymlinkPolicy,
    ) -> Result<Option<DirectoryAnchor>> {
        let (selection, anchor) = select_operator_directory(path, allow_missing, symlink_policy)?;
        self.operator_selection = Some(selection);
        Ok(anchor)
    }

    fn create_operator_directory(
        &mut self,
        mode: u32,
        require_absent: bool,
    ) -> Result<DirectoryAnchor> {
        self.operator_selection
            .as_mut()
            .context("no checked destination directory to create")?
            .create_missing(mode, require_absent)
    }

    fn anchor_destination(
        &mut self,
        expected_dev: u64,
        expected_ino: u64,
        request_prefix: &[u8],
    ) -> Result<DescriptorTicket> {
        let selection = self
            .operator_selection
            .take()
            .context("destination directory was not checked on this connection")?;
        if !selection.missing.is_empty() {
            bail!("destination directory has not been created");
        }
        let anchor = selection.anchor()?;
        if (anchor.dev, anchor.ino) != (expected_dev, expected_ino) {
            bail!(
                "destination root changed identity (expected {expected_dev}:{expected_ino}, found {}:{})",
                anchor.dev,
                anchor.ino
            );
        }
        let ticket = self.descriptor_session.register(selection.directory)?;
        let directory = self.descriptor_session.acquire(&ticket)?;
        self.install_destination(directory, request_prefix)?;

        #[cfg(debug_assertions)]
        {
            if let Some(ready) = std::env::var_os("SYQ_TEST_DESTINATION_ANCHORED_FILE") {
                fs::write(&ready, b"ready").with_context(|| {
                    format!(
                        "write destination-anchor-ready signal {}",
                        Path::new(&ready).display()
                    )
                })?;
            }
            if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_DESTINATION_ANCHOR_MS") {
                if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                }
            }
        }
        Ok(ticket)
    }

    /// Install the exact control-session root delivered during worker
    /// initialization. A same-process TCP worker clones it from the shared
    /// registry; an independent worker claims it with SCM_RIGHTS.
    pub(crate) fn initialize_destination(&mut self, destination: &DestinationRoot) -> Result<()> {
        let directory = self.descriptor_session.acquire(&destination.ticket)?;
        self.install_destination(directory, &destination.request_prefix)
    }

    /// Resolve a batch completely before registering any of it. Each result is
    /// represented by the smallest registration directory that preserves the
    /// operator selection: the selected directory itself, or a selected
    /// leaf's opened parent plus its literal name.
    fn register_source_roots(
        &mut self,
        selections: &[SourceRootSelection],
        symlink_policy: OperatorSymlinkPolicy,
        allow_unconfined_paths: bool,
        shared_workers: usize,
        independent_workers: usize,
    ) -> Result<Vec<RegisteredSourceRoot>> {
        if !self.source_roots.is_empty() {
            bail!("source roots are already registered on this control connection");
        }
        if selections.is_empty() {
            bail!("source registration requires at least one selection");
        }
        if selections.len() > DEFAULT_MAX_ROOTS {
            bail!(
                "source root count ({}) exceeds the endpoint-session limit ({DEFAULT_MAX_ROOTS})",
                selections.len()
            );
        }
        require_source_descriptor_capacity(selections.len(), shared_workers, independent_workers)?;
        let mut resolved = Vec::with_capacity(selections.len());
        for selection in selections {
            let path = resolve(&selection.path);
            let path = if path.is_absolute() {
                path
            } else {
                self.initial_cwd.join(path)
            };
            let mut hops = Vec::new();
            let pinned = OperatorResolver::resolve_process(
                path.as_os_str().as_bytes(),
                symlink_policy,
                OperatorFinalComponent::Entry {
                    follow_symlink: selection.follow_root,
                },
                false,
                &mut hops,
            )
            .with_context(|| format!("resolve source selection {}", path.display()))?;
            match pinned {
                PinnedPath::Directory(directory) => {
                    let (directory, _) = directory.into_parts();
                    resolved.push((directory, Vec::new(), None, None));
                }
                PinnedPath::Leaf(leaf) => {
                    let (parent, name, metadata, object) = leaf.into_parts();
                    let object = object
                        .context("this platform cannot retain the selected source leaf safely")?;
                    let symlink_target = if metadata.is_symlink() {
                        Some(
                            read_open_symlink(&object)?
                                .context("this platform cannot snapshot a selected source symlink through its pinned object (macOS 13 or newer is required on Darwin)")?,
                        )
                    } else {
                        None
                    };
                    resolved.push((
                        parent,
                        name.as_bytes().to_vec(),
                        Some(SourceLeafIdentity {
                            dev: metadata.dev,
                            ino: metadata.ino,
                            file_type: metadata.file_type(),
                            symlink_target,
                        }),
                        Some(object),
                    ));
                }
                PinnedPath::Missing(_) => {
                    unreachable!("source resolution did not allow a missing suffix")
                }
            }
        }

        let registrations: Vec<_> = resolved
            .iter()
            .map(|(_, relative, expected_leaf, _)| (relative.clone(), expected_leaf.clone()))
            .collect();
        let tickets = self.descriptor_session.register_source_handles(
            resolved
                .into_iter()
                .map(|(directory, _, _, object)| (directory, object))
                .collect(),
        )?;
        let registered: Vec<_> = tickets
            .into_iter()
            .zip(registrations)
            .map(|((ticket, leaf_ticket), (relative, expected_leaf))| {
                let selection = RegisteredPath::new(ticket.root_id(), relative)?;
                Ok(RegisteredSourceRoot {
                    ticket,
                    leaf_ticket,
                    selection,
                    expected_leaf,
                    allow_unconfined_paths,
                })
            })
            .collect::<Result<_>>()?;
        self.initialize_sources(&registered)?;
        #[cfg(debug_assertions)]
        {
            if let Some(ready) = std::env::var_os("SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE") {
                fs::write(&ready, b"ready").with_context(|| {
                    format!(
                        "write source-registration-ready signal {}",
                        Path::new(&ready).display()
                    )
                })?;
            }
            if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_SOURCE_ROOTS_MS") {
                if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                }
            }
        }
        Ok(registered)
    }

    /// Acquire every registered source root before acknowledging worker
    /// readiness. Local and same-process TCP workers clone from the shared
    /// process registry; fresh SSH workers claim while still single-threaded.
    /// Build the new table off to the side so a bad ticket cannot leave a
    /// partially initialized worker.
    pub(crate) fn initialize_sources(&mut self, sources: &[RegisteredSourceRoot]) -> Result<()> {
        if sources.is_empty() {
            bail!("source worker requires at least one registered root");
        }
        if sources.len() > DEFAULT_MAX_ROOTS {
            bail!(
                "source worker root count ({}) exceeds the endpoint-session limit ({DEFAULT_MAX_ROOTS})",
                sources.len()
            );
        }
        let mut roots = HashMap::with_capacity(sources.len());
        let endpoint_ticket = &sources[0].ticket;
        let allow_unconfined_paths = sources[0].allow_unconfined_paths;
        for source in sources {
            source.validate()?;
            if !source.ticket.same_session(endpoint_ticket) {
                bail!("source roots belong to different endpoint sessions");
            }
            if source.allow_unconfined_paths != allow_unconfined_paths {
                bail!("source worker received inconsistent unconfined-path permissions");
            }
            let id = source.selection.root();
            if roots.contains_key(&id) {
                bail!(
                    "source worker received duplicate registered root {}",
                    id.get()
                );
            }
            let directory = self.descriptor_session.acquire(&source.ticket)?;
            let leaf_object = match (&source.leaf_ticket, &source.expected_leaf) {
                (Some(ticket), Some(expected)) => {
                    let object = self.descriptor_session.acquire(ticket)?;
                    let metadata = root_metadata_from_std(
                        &object
                            .metadata()
                            .context("inspect registered exact source object")?,
                    )?;
                    require_source_leaf_identity(expected, metadata)?;
                    match (metadata.is_symlink(), expected.symlink_target.as_ref()) {
                        (true, Some(expected_target)) => {
                            let target = read_open_symlink(&object)?.context(
                                "this platform cannot validate a registered source symlink through its pinned object (macOS 13 or newer is required on Darwin)",
                            )?;
                            if &target != expected_target {
                                bail!("registered source symlink target does not match its pinned capability");
                            }
                        }
                        (true, None) => {
                            bail!("registered source symlink capability is missing its target")
                        }
                        (false, Some(_)) => {
                            bail!("registered non-symlink source carries a symlink target")
                        }
                        (false, None) => {}
                    }
                    Some(object)
                }
                (None, None) => None,
                _ => bail!("source root leaf selection and object ticket disagree"),
            };
            roots.insert(
                id,
                SourceRootHandle {
                    root: Arc::new(Root::from_directory(directory)?),
                    _leaf_object: leaf_object.map(Arc::new),
                    selection: source.selection.relative.clone(),
                    expected_leaf: source.expected_leaf.clone(),
                },
            );
        }
        self.source_roots = roots;
        self.allow_unconfined_source_paths = allow_unconfined_paths;
        Ok(())
    }

    #[cfg(test)]
    fn source_root_identity(&self, id: RegisteredRootId) -> Option<RootIdentity> {
        self.source_roots
            .get(&id)
            .map(|source| source.root.identity())
    }

    fn registered_source_target(&self, source: &RegisteredPath) -> Result<RegisteredSourceTarget> {
        let handle = self
            .source_roots
            .get(&source.root())
            .with_context(|| format!("unknown registered source root {}", source.root().get()))?;
        if !handle.selection.is_empty() && source.relative != handle.selection {
            bail!("registered source leaf does not authorize the requested path");
        }
        Ok(RegisteredSourceTarget {
            root: handle.root.clone(),
            relative: RelativePath::new(&source.relative)?,
            expected_leaf: handle.expected_leaf.clone(),
            leaf_object: handle._leaf_object.clone(),
        })
    }

    /// Resolve a source scan to its retained root. Once source roots exist,
    /// omission is never an implicit fallback: only a registration carrying
    /// the explicit `--insecure-links` permission may use the legacy pathname.
    pub(crate) fn source_scan_root(
        &self,
        source: Option<&RegisteredPath>,
    ) -> Result<Option<SourceScanRoot>> {
        if let Some(source) = source {
            let target = self.registered_source_target(source)?;
            return Ok(Some(SourceScanRoot {
                root: target.root,
                relative: source.relative.clone(),
                expected_leaf: target.expected_leaf,
            }));
        }
        if self.source_roots.is_empty() {
            return Ok(None);
        }
        if self.allow_unconfined_source_paths {
            return Ok(None);
        }
        bail!("source scan omitted its registered source reference")
    }

    /// A source worker never accepts destination-style caller guards. Those
    /// guards carry a fresh pathname root and would otherwise bypass the
    /// endpoint-session source capabilities, even on request variants whose
    /// source-reference cutover has not landed yet.
    pub(crate) fn validate_source_session_request(&self, request: &Request) -> Result<()> {
        if self.source_roots.is_empty() {
            return Ok(());
        }
        let has_guard = match request {
            Request::Scan { guard, .. }
            | Request::StatMany { guard, .. }
            | Request::PartialPaths { guard, .. }
            | Request::Apply { guard, .. }
            | Request::PlanBatch { guard, .. }
            | Request::ProbePartial { guard, .. }
            | Request::Prepare { guard, .. }
            | Request::HashAndHold { guard, .. }
            | Request::FinishBasis { guard, .. }
            | Request::SeedBasis { guard, .. }
            | Request::HashBlocks { guard, .. }
            | Request::WriteRange { guard, .. }
            | Request::Finalize { guard, .. }
            | Request::FileHash { guard, .. }
            | Request::Canonicalize { guard, .. } => guard.is_some(),
            Request::PutSmallBatch(puts) => puts.iter().any(|put| put.guard.is_some()),
            _ => false,
        };
        if has_guard {
            bail!("an initialized source session rejects caller-supplied guards");
        }
        Ok(())
    }

    /// Resolve one source-content request. A destination worker must never
    /// service source-only read families, and a confined source session never
    /// treats an omitted registered reference as pathname authority.
    fn source_content_target(
        &self,
        source: Option<&RegisteredPath>,
    ) -> Result<Option<(RegisteredRootId, RegisteredSourceTarget)>> {
        if self.destination_root.is_some() {
            bail!("source content request is not valid on a destination worker");
        }
        if let Some(source) = source {
            let target = self.registered_source_target(source)?;
            return Ok(Some((source.root(), target)));
        }
        if self.source_roots.is_empty() {
            return Ok(None);
        }
        if self.allow_unconfined_source_paths {
            return Ok(None);
        }
        bail!("source content request omitted its registered source reference")
    }

    fn install_destination(&mut self, directory: File, request_prefix: &[u8]) -> Result<()> {
        let root = Arc::new(Root::from_directory(directory)?);
        // Destination operations are still pathname-based in this transitional
        // path for operation families not migrated to Root yet, so enter the
        // exact received descriptor as their base. Stacked slices replace the
        // remaining operations and then remove process-wide cwd dependence.
        loop {
            if unsafe { libc::fchdir(root.as_raw_fd()) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("enter retained destination root");
            }
        }
        self.fds.clear();
        self.fd_order.clear();
        self.held_basis.take();
        self.destination_prefix = Some(request_prefix.to_vec());
        self.destination_root = Some(root);
        Ok(())
    }

    fn destination_relative(&self, path: &[u8]) -> Result<PathBytes> {
        let Some(prefix) = self.destination_prefix.as_deref() else {
            return Ok(path.to_vec());
        };
        let relative = if prefix == b"." {
            if path == b"." {
                b"".as_slice()
            } else if path.starts_with(b"/") {
                bail!("destination path is outside the retained root");
            } else {
                path.strip_prefix(b"./").unwrap_or(path)
            }
        } else if path == prefix {
            b"".as_slice()
        } else if prefix == b"/" {
            path.strip_prefix(b"/")
                .context("destination path is outside the retained root")?
        } else {
            path.strip_prefix(prefix)
                .and_then(|suffix| suffix.strip_prefix(b"/"))
                .context("destination path is outside the retained root")?
        };
        if relative.starts_with(b"/")
            || relative.contains(&0)
            || relative.split(|byte| *byte == b'/').any(|component| {
                !relative.is_empty()
                    && (component.is_empty() || component == b"." || component == b"..")
            })
        {
            bail!("destination path contains an unsafe relative component");
        }
        Ok(relative.to_vec())
    }

    fn destination_full(&self, relative: &[u8]) -> PathBytes {
        let prefix = self
            .destination_prefix
            .as_deref()
            .expect("relative response requires an active destination root");
        join(prefix, relative)
    }

    fn partial_path(&self, final_path: &Path, partial_id: &PartialId) -> Result<PathBuf> {
        if self.destination_prefix.is_none() {
            return partial_path(final_path, partial_id);
        }
        let relative = path_bytes(final_path);
        let strict_relative = RelativePath::new(&relative)?;
        let logical = PathBuf::from(OsStr::from_bytes(&self.destination_full(&relative)));
        let component_limit = self
            .destination_root
            .as_ref()
            .context("destination prefix has no retained root")?
            .name_max_for_parent(&strict_relative)?;
        let logical_partial = partial_path_with_name_max(&logical, partial_id, component_limit)?;
        Ok(PathBuf::from(OsStr::from_bytes(
            &self.destination_relative(logical_partial.as_os_str().as_bytes())?,
        )))
    }

    fn logical_destination_path(&self, relative: &Path) -> PathBuf {
        if self.destination_prefix.is_some() {
            PathBuf::from(OsStr::from_bytes(
                &self.destination_full(relative.as_os_str().as_bytes()),
            ))
        } else {
            relative.to_path_buf()
        }
    }

    fn initial_absolute(&self, path: &[u8]) -> PathBytes {
        let path = resolve(path);
        let absolute = if path.is_absolute() {
            path
        } else {
            self.initial_cwd.join(path)
        };
        path_bytes(&absolute)
    }

    fn map_request(&self, req: &Request) -> Result<Request> {
        if self.destination_prefix.is_none() {
            return Ok(req.clone());
        }
        let mut req = req.clone();
        let map = |path: &mut PathBytes| -> Result<()> {
            *path = self.destination_relative(path)?;
            Ok(())
        };
        match &mut req {
            Request::Scan { root, guard, .. } => {
                if guard.is_none() {
                    map(root)?;
                }
            }
            Request::StatMany { paths, guard, .. } | Request::PartialPaths { paths, guard, .. } => {
                if guard.is_none() {
                    for path in paths {
                        map(path)?;
                    }
                }
            }
            Request::PlanBatch {
                partial_paths,
                directories,
                others,
                guard,
                ..
            } => {
                if guard.is_none() {
                    for path in partial_paths.iter_mut().chain(directories).chain(others) {
                        map(path)?;
                    }
                }
            }
            Request::Apply { ops, guard } => {
                if guard.is_none() {
                    for op in ops {
                        let path = match op {
                            Op::Mkdir { path, .. }
                            | Op::Symlink { path, .. }
                            | Op::Mknod { path, .. }
                            | Op::SetMeta { path, .. }
                            | Op::SetFileMetaIfSame { path, .. }
                            | Op::Remove { path }
                            | Op::Rmdir { path }
                            | Op::Unlink { path } => path,
                        };
                        map(path)?;
                    }
                }
            }
            Request::ProbePartial { path, guard, .. }
            | Request::Prepare { path, guard, .. }
            | Request::HashAndHold { path, guard, .. }
            | Request::FinishBasis { path, guard, .. }
            | Request::SeedBasis { path, guard, .. }
            | Request::HashBlocks { path, guard, .. }
            | Request::WriteRange { path, guard, .. }
            | Request::Finalize { path, guard, .. }
            | Request::FileHash { path, guard, .. }
            | Request::Canonicalize { path, guard } => {
                if guard.is_none() {
                    map(path)?;
                }
            }
            Request::ReadRange { path, .. } => map(path)?,
            Request::CopyLocal { src, dst, .. } => {
                *src = self.initial_absolute(src);
                map(dst)?;
            }
            Request::ReadSmallBatch(reads) => {
                for read in reads {
                    map(&mut read.path)?;
                }
            }
            Request::PutSmallBatch(puts) => {
                for put in puts {
                    if put.guard.is_none() {
                        map(&mut put.path)?;
                    }
                }
            }
            Request::Hello { .. }
            | Request::TcpListen { .. }
            | Request::NativeRemove { .. }
            | Request::CheckOperatorDirectory { .. }
            | Request::RegisterSourceRoots { .. }
            | Request::CreateOperatorDirectory { .. }
            | Request::AnchorDestination { .. }
            | Request::TransportStats
            | Request::Receipt
            | Request::Shutdown => {}
        }
        Ok(req)
    }

    pub fn scan_root(&self, root: &[u8]) -> Result<PathBytes> {
        self.destination_relative(root)
    }

    /// Return the retained destination capability and a strict path beneath it
    /// when this connection has adopted a destination root. Callers must use
    /// this instead of resolving the rebased spelling through process cwd.
    pub(crate) fn destination_scan_root(
        &self,
        requested: &[u8],
    ) -> Result<Option<(Arc<Root>, PathBytes)>> {
        let Some(root) = &self.destination_root else {
            return Ok(None);
        };
        let relative = self.destination_relative(requested)?;
        RelativePath::new(&relative)?;
        Ok(Some((root.clone(), relative)))
    }

    fn rebase_response(&self, response: Response) -> Response {
        if self.destination_prefix.is_none() {
            return response;
        }
        match response {
            Response::PathResults(paths) => Response::PathResults(
                paths
                    .into_iter()
                    .map(|path| path.map(|path| self.destination_full(&path)))
                    .collect(),
            ),
            Response::BatchPlan {
                partial_paths,
                directories,
                others,
            } => Response::BatchPlan {
                partial_paths: partial_paths
                    .into_iter()
                    .map(|path| path.map(|path| self.destination_full(&path)))
                    .collect(),
                directories,
                others,
            },
            response => response,
        }
    }

    fn cached(&mut self, p: &Path, write: bool, attempt: u32, private: bool) -> Result<&File> {
        let key = FdKey {
            source_root: None,
            path: p.to_path_buf(),
            attempt,
            private,
        };
        if !self.fds.contains_key(&key) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            let f = open_existing_regular(p, write)?;
            if private {
                require_safe_partial(&f, p)?;
            }
            self.fds.insert(key.clone(), f);
            self.fd_order.push(key.clone());
        }
        Ok(self.fds.get(&key).unwrap())
    }

    fn uncache(&mut self, p: &Path) -> Option<File> {
        let mut removed = None;
        self.fd_order.retain(|key| {
            if key.path == p {
                removed = self.fds.remove(key).or(removed.take());
                false
            } else {
                true
            }
        });
        removed
    }

    fn cached_rooted(
        &mut self,
        label: &Path,
        root: &Root,
        relative: &RelativePath,
        attempt: u32,
        private: bool,
    ) -> Result<&File> {
        let key = FdKey {
            source_root: None,
            path: label.to_path_buf(),
            attempt,
            private,
        };
        if !self.fds.contains_key(&key) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            let file = root.open_regular_write(relative, false)?;
            if private {
                require_safe_partial(&file, label)?;
                let named = root.metadata(relative)?;
                let opened = file.metadata()?;
                if opened.dev() != named.dev || opened.ino() != named.ino {
                    bail!("partial {} changed while opening it", label.display());
                }
            }
            self.fds.insert(key.clone(), file);
            self.fd_order.push(key.clone());
        }
        Ok(self.fds.get(&key).unwrap())
    }

    fn cached_source_read(
        &mut self,
        root_id: RegisteredRootId,
        relative_bytes: &[u8],
        target: &RegisteredSourceTarget,
        attempt: u32,
    ) -> Result<&File> {
        let key = FdKey {
            source_root: Some(root_id),
            path: PathBuf::from(OsStr::from_bytes(relative_bytes)),
            attempt,
            private: false,
        };
        if !self.fds.contains_key(&key) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            self.fds
                .insert(key.clone(), open_registered_source(target)?);
            self.fd_order.push(key.clone());
        }
        Ok(self.fds.get(&key).unwrap())
    }

    /// Batches are statted on several threads: on network filesystems each
    /// lstat is a round trip and the planner would otherwise starve the workers.
    pub fn stat_many(
        &mut self,
        paths: &[PathBytes],
        follow: bool,
        guard: Option<&ContainerGuard>,
    ) -> Vec<Option<Entry>> {
        if let Some(guard) = guard {
            if follow {
                return vec![None; paths.len()];
            }
            return parallel_map(paths, |path| {
                let target = guarded_target(path, guard).ok()?;
                let metadata = target.root.metadata(&target.relative).ok()?;
                rooted_entry(&target.root, &target.relative, Vec::new(), metadata).ok()
            });
        }
        if let Some(root) = self.destination_root.clone() {
            if follow {
                return vec![None; paths.len()];
            }
            return parallel_map(paths, |path| {
                let relative = RelativePath::new(path).ok()?;
                let metadata = root.metadata(&relative).ok()?;
                rooted_entry(&root, &relative, Vec::new(), metadata).ok()
            });
        }
        parallel_map(paths, |p| {
            let full = resolve(p);
            let md = if follow {
                fs::metadata(&full)
            } else {
                fs::symlink_metadata(&full)
            };
            md.ok().map(|md| entry_from_meta(Vec::new(), &full, &md))
        })
    }

    fn stat_many_request(
        &mut self,
        paths: &[PathBytes],
        sources: Option<&[RegisteredPath]>,
        follow: bool,
        guard: Option<&ContainerGuard>,
    ) -> Result<Vec<Option<Entry>>> {
        if guard.is_some() && sources.is_some() {
            bail!("a guarded destination stat cannot carry source references");
        }
        if let Some(sources) = sources {
            if sources.len() != paths.len() {
                bail!("source stat capability count does not match path count");
            }
            let targets = sources
                .iter()
                .map(|source| self.registered_source_target(source))
                .collect::<Result<Vec<_>>>()?;
            // `follow` describes the legacy pathname request. A registered
            // selection has already applied the operator-root policy, and no
            // descendant component gains symlink-traversal authority here.
            return parallel_map(&targets, |target| {
                let Some(expected) = target.expected_leaf.as_ref() else {
                    let Some(metadata) = target.root.metadata(&target.relative).ok() else {
                        return Ok(None);
                    };
                    return Ok(
                        rooted_entry(&target.root, &target.relative, Vec::new(), metadata).ok(),
                    );
                };
                let metadata = target
                    .root
                    .metadata(&target.relative)
                    .context("inspect registered source leaf")?;
                require_source_leaf_identity(expected, metadata)?;
                let entry = rooted_source_entry(
                    &target.root,
                    &target.relative,
                    Vec::new(),
                    metadata,
                    Some(expected),
                )?;
                let after = target
                    .root
                    .metadata(&target.relative)
                    .context("recheck registered source leaf")?;
                require_source_leaf_identity(expected, after)?;
                Ok(Some(entry))
            })
            .into_iter()
            .collect();
        }
        if !self.source_roots.is_empty() && !self.allow_unconfined_source_paths {
            bail!("source stat omitted its registered source references");
        }
        Ok(self.stat_many(paths, follow, guard))
    }

    pub fn partial_paths(
        &mut self,
        paths: &[PathBytes],
        partial_id: &PartialId,
        guard: Option<&ContainerGuard>,
    ) -> Vec<std::result::Result<PathBytes, String>> {
        parallel_map(paths, |path| {
            if let Some(guard) = guard {
                guarded_target(path, guard)?;
            }
            let requested = Path::new(OsStr::from_bytes(path));
            let resolved = if guard.is_some() {
                partial_path_with_name_max(&resolve(path), partial_id, COMMON_NAME_MAX)
            } else {
                self.partial_path(&resolve(path), partial_id)
            }?;
            let name = resolved.file_name().expect("partial always has a name");
            let parent = requested.parent().unwrap_or_else(|| Path::new(""));
            Ok(path_bytes(&parent.join(name)))
        })
        .into_iter()
        .map(|result: Result<PathBytes>| result.map_err(|error| format!("{error:#}")))
        .collect()
    }

    /// Ops within a batch are independent (the planner orders batches so that
    /// parents come first), so they run in parallel too.
    pub fn apply(&mut self, ops: &[Op], guard: Option<&ContainerGuard>) -> Vec<Option<String>> {
        // SetMeta depends on the object existing, so create everything first,
        // then apply metadata — otherwise a parallel SetMeta can beat its
        // Symlink/Mknod/Mkdir. Both phases still run in parallel internally.
        let is_meta = |op: &Op| matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. });
        let is_guarded_create = |op: &Op| match op {
            Op::Mkdir { condition, .. }
            | Op::Symlink { condition, .. }
            | Op::Mknod { condition, .. } => *condition != TargetCondition::Any,
            _ => false,
        };
        let guarded_idx: Vec<usize> = (0..ops.len())
            .filter(|&i| !is_meta(&ops[i]) && is_guarded_create(&ops[i]))
            .collect();
        let create_idx: Vec<usize> = (0..ops.len())
            .filter(|&i| !is_meta(&ops[i]) && !is_guarded_create(&ops[i]))
            .collect();
        let meta_idx: Vec<usize> = (0..ops.len()).filter(|&i| is_meta(&ops[i])).collect();
        let destination_root = self.destination_root.clone();
        let destination_prefix = self.destination_prefix.as_deref();
        let mut out: Vec<Option<String>> = vec![None; ops.len()];
        let gres = parallel_map(&guarded_idx, |&i| {
            apply_one(&ops[i], guard, destination_root.clone(), destination_prefix)
                .err()
                .as_ref()
                .map(errstr)
        });
        for (i, r) in guarded_idx.iter().zip(gres) {
            out[*i] = r;
        }
        if guarded_idx.iter().any(|&i| out[i].is_some()) {
            for i in create_idx.iter().chain(meta_idx.iter()) {
                out[*i] =
                    Some("operation skipped because the placement-root precondition failed".into());
            }
            return out;
        }
        let cres = parallel_map(&create_idx, |&i| {
            apply_one(&ops[i], guard, destination_root.clone(), destination_prefix)
                .err()
                .as_ref()
                .map(errstr)
        });
        for (i, r) in create_idx.iter().zip(cres) {
            out[*i] = r;
        }
        let mres = parallel_map(&meta_idx, |&i| {
            apply_one(&ops[i], guard, destination_root.clone(), destination_prefix)
                .err()
                .as_ref()
                .map(errstr)
        });
        for (i, r) in meta_idx.iter().zip(mres) {
            out[*i] = r;
        }
        out
    }

    fn _unused_apply_one(&mut self, op: &Op) -> Result<()> {
        apply_one(op, None, None, None)
    }
}

fn op_path(op: &Op) -> &[u8] {
    match op {
        Op::Mkdir { path, .. }
        | Op::Symlink { path, .. }
        | Op::Mknod { path, .. }
        | Op::SetMeta { path, .. }
        | Op::SetFileMetaIfSame { path, .. }
        | Op::Remove { path }
        | Op::Rmdir { path }
        | Op::Unlink { path } => path,
    }
}

fn apply_one(
    op: &Op,
    guard: Option<&ContainerGuard>,
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
) -> Result<()> {
    let registered_target = if let Some(root) = destination_root {
        let path = op_path(op);
        let relative = RelativePath::new(path)?;
        let label = PathBuf::from(OsStr::from_bytes(
            &destination_prefix.map_or_else(|| path.to_vec(), |prefix| join(prefix, path)),
        ));
        Some(RootedTarget {
            root,
            relative,
            label,
            create_missing_parents: true,
        })
    } else {
        None
    };
    #[cfg(debug_assertions)]
    if matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. }) {
        fail_set_meta_for_test(
            registered_target
                .as_ref()
                .map_or_else(|| resolve(op_path(op)), |target| target.label.clone())
                .as_path(),
        )?;
    }
    if matches!(op, Op::SetFileMetaIfSame { .. }) {
        hold_before_quick_metadata_for_test()?;
    }
    if let Some(guard) = guard {
        let target = guarded_target(op_path(op), guard)?;
        return apply_one_rooted(op, &target.as_rooted());
    }
    if let Some(target) = registered_target {
        return apply_one_rooted(op, &target);
    }
    apply_one_unrooted(op)
}

fn apply_one_unrooted(op: &Op) -> Result<()> {
    {
        match op {
            Op::Mkdir {
                path,
                mode,
                condition,
            } => {
                let p = resolve(path);
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        fs::create_dir_all(parent)?;
                    }
                }
                // The orchestrator resolves an explicitly supplied root
                // symlink. Symlinks found inside the destination tree are
                // payload conflicts and must be replaced, never traversed.
                match condition {
                    TargetCondition::Absent => mkdir(&p, *mode).map_err(Into::into),
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let md = require_target_condition(&p, *condition)?
                            .expect("matching target condition returns metadata");
                        if !md.is_dir() {
                            bail!(
                                "target {} cannot change type under --as-existing",
                                p.display()
                            );
                        }
                        make_dir_writable(&p, &md)
                    }
                    TargetCondition::Any => match fs::symlink_metadata(&p) {
                        Ok(md) if md.is_dir() => make_dir_writable(&p, &md),
                        Ok(_) => {
                            fs::remove_file(&p)?;
                            mkdir_or_existing_dir(&p, *mode)
                        }
                        Err(_) => mkdir_or_existing_dir(&p, *mode),
                    },
                }
                .with_context(|| format!("mkdir {}", p.display()))
            }
            Op::Symlink {
                path,
                target,
                condition,
            } => {
                let p = resolve(path);
                match condition {
                    TargetCondition::Any => match fs::symlink_metadata(&p) {
                        Ok(md) if md.is_dir() => fs::remove_dir(&p)?,
                        Ok(_) => fs::remove_file(&p)?,
                        Err(_) => {}
                    },
                    TargetCondition::Absent => {}
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let metadata = require_target_condition(&p, *condition)?
                            .expect("matching target condition returns metadata");
                        if !metadata.file_type().is_symlink() {
                            bail!(
                                "target {} cannot change type under --as-existing",
                                p.display()
                            );
                        }
                        replace_exact_symlink(&p, target, *condition)?;
                        return Ok(());
                    }
                }
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &p)
                    .with_context(|| format!("symlink {}", p.display()))
            }
            Op::Mknod {
                path,
                mode,
                rdev,
                condition,
            } => {
                let p = resolve(path);
                match condition {
                    TargetCondition::Any => match fs::symlink_metadata(&p) {
                        Ok(md) if md.is_dir() => fs::remove_dir(&p)?,
                        Ok(_) => fs::remove_file(&p)?,
                        Err(_) => {}
                    },
                    TargetCondition::Absent => {}
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let metadata = require_target_condition(&p, *condition)?
                            .expect("matching target condition returns metadata");
                        if file_type_bits(metadata.mode()) != file_type_bits(*mode) {
                            bail!(
                                "target {} cannot change type under --as-existing",
                                p.display()
                            );
                        }
                        replace_exact_node(&p, *mode, *rdev, *condition)?;
                        return Ok(());
                    }
                }
                let c = cstr(&p)?;
                let r =
                    unsafe { libc::mknod(c.as_ptr(), *mode as libc::mode_t, *rdev as libc::dev_t) };
                if r != 0 {
                    return Err(io::Error::last_os_error())
                        .with_context(|| format!("mknod {}", p.display()));
                }
                Ok(())
            }
            Op::SetMeta {
                path,
                meta,
                flags,
                condition,
            } => {
                let p = resolve(path);
                match condition {
                    TargetCondition::Any => set_meta_path(&p, meta, *flags),
                    TargetCondition::Absent => {
                        bail!("target {} appeared before metadata update", p.display())
                    }
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let file = OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                            .open(&p)
                            .with_context(|| format!("open {} for metadata", p.display()))?;
                        require_open_target(&file, &p, *condition)?;
                        set_meta_file(&file, meta, *flags)
                    }
                }
                .with_context(|| format!("set metadata {}", p.display()))
            }
            Op::SetFileMetaIfSame {
                path,
                condition,
                meta,
                flags,
            } => {
                let p = resolve(path);
                let file = match open_metadata_handle(&p) {
                    Ok(file) => file,
                    Err(open_error) => {
                        // Preserve the useful open error only while the
                        // planner's target is still present.
                        require_target_condition(&p, *condition)?;
                        return Err(open_error)
                            .with_context(|| format!("open {} for metadata repair", p.display()));
                    }
                };
                let md = file.metadata()?;
                if !md.file_type().is_file() {
                    bail!("destination {} changed before metadata repair", p.display());
                }
                require_open_target(&file, &p, *condition)?;
                set_meta_handle(&file, meta, *flags)
                    .with_context(|| format!("set metadata {}", p.display()))?;
                require_named_target_identity(&file, &p, *condition)
            }
            Op::Rmdir { path } => {
                let p = resolve(path);
                match fs::remove_dir(&p) {
                    // Already gone (a concurrent removal): the desired end state.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    r => r.with_context(|| format!("rmdir {}", p.display())),
                }
            }
            // Remove follows the path's current type and may recurse. Planned
            // deletion paths use Unlink/Rmdir below so a type change fails
            // safely instead of broadening the selected deletion scope.
            Op::Remove { path } => {
                let p = resolve(path);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => fs::remove_dir_all(&p)?,
                    Ok(_) => fs::remove_file(&p)?,
                    Err(_) => {}
                }
                Ok(())
            }
            Op::Unlink { path } => {
                let p = resolve(path);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => {
                        bail!("{}: is now a directory; not deleting it", p.display())
                    }
                    Ok(_) => {
                        fs::remove_file(&p).with_context(|| format!("unlink {}", p.display()))?
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).with_context(|| format!("unlink {}", p.display())),
                }
                Ok(())
            }
        }
    }
}

struct GuardedTarget {
    root: Arc<Root>,
    root_path: PathBuf,
    relative: RelativePath,
    label: PathBuf,
}

struct RootedTarget {
    root: Arc<Root>,
    relative: RelativePath,
    label: PathBuf,
    create_missing_parents: bool,
}

impl GuardedTarget {
    fn as_rooted(&self) -> RootedTarget {
        RootedTarget {
            root: self.root.clone(),
            relative: self.relative.clone(),
            label: self.label.clone(),
            create_missing_parents: false,
        }
    }
}

fn guarded_target(path: &[u8], guard: &ContainerGuard) -> Result<GuardedTarget> {
    hold_before_guarded_mutation_for_test(path)?;
    let root_path = resolve(&guard.root);
    let target = resolve(path);
    let relative = relative_under(&root_path, &target)?;
    let root = Arc::new(Root::open_verified(
        &root_path,
        RootIdentity {
            dev: guard.dev,
            ino: guard.ino,
        },
    )?);
    Ok(GuardedTarget {
        root,
        root_path,
        relative,
        label: target,
    })
}

fn relative_under(root: &Path, target: &Path) -> Result<RelativePath> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "target {} is outside guarded root {}",
            target.display(),
            root.display()
        )
    })?;
    RelativePath::new(relative.as_os_str().as_bytes())
}

/// Observe the object at a guarded path and hold it to the planner's
/// condition. `Absent` requires nothing there (the following `*at` creation
/// then fails atomically if something appears); the matching conditions
/// require the observed identity. `Any` accepts whatever is found.
fn observe_rooted_condition(
    target: &RootedTarget,
    condition: TargetCondition,
) -> Result<Option<crate::rooted::RootMetadata>> {
    let observed = target.root.metadata_optional(&target.relative)?;
    let label = &target.label;
    match (condition, observed) {
        (TargetCondition::Any, observed) => Ok(observed),
        (TargetCondition::Absent, None) => Ok(None),
        (TargetCondition::Absent, Some(_)) => {
            bail!(
                "target {} appeared before no-replace creation",
                label.display()
            )
        }
        (TargetCondition::Matches { dev, ino }, Some(metadata))
            if metadata.dev == dev && metadata.ino == ino =>
        {
            Ok(Some(metadata))
        }
        (
            TargetCondition::MatchesFingerprint {
                dev,
                ino,
                ctime,
                ctime_nsec,
            },
            Some(metadata),
        ) if metadata.dev == dev
            && metadata.ino == ino
            && metadata.ctime == ctime
            && metadata.ctime_nsec == ctime_nsec =>
        {
            Ok(Some(metadata))
        }
        (TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }, _) => {
            bail!(
                "target {} changed before it could be replaced",
                label.display()
            )
        }
    }
}

fn apply_one_rooted(op: &Op, target: &RootedTarget) -> Result<()> {
    let root = &target.root;
    let path = &target.relative;
    match op {
        Op::Mkdir {
            mode, condition, ..
        } => {
            if path.is_empty() {
                if *condition == TargetCondition::Absent {
                    bail!("destination root {} already exists", target.label.display());
                }
                let metadata = root.metadata(path)?;
                require_rooted_condition(metadata, *condition, &target.label)?;
                if metadata.mode & 0o700 != 0o700 {
                    let directory = root.open_metadata(path)?;
                    require_rooted_metadata(&directory, metadata, &target.label)?;
                    set_mode_handle(&directory, metadata.mode | 0o700)?;
                }
                return Ok(());
            }
            if target.create_missing_parents {
                root.create_missing_parents(path, 0o777)?;
            }
            match observe_rooted_condition(target, *condition)? {
                Some(metadata) if metadata.is_dir() => {
                    if metadata.mode & 0o700 != 0o700 {
                        let directory = root.open_metadata(path)?;
                        require_rooted_metadata(&directory, metadata, &target.label)?;
                        set_mode_handle(&directory, metadata.mode | 0o700)?;
                    }
                    Ok(())
                }
                Some(_) if *condition != TargetCondition::Any => bail!(
                    "target {} cannot change type under a matched condition",
                    target.label.display()
                ),
                Some(_) => {
                    root.unlink(path)?;
                    create_rooted_directory_or_existing(target, *mode)
                }
                None => create_rooted_directory_or_existing(target, *mode),
            }
        }
        Op::Symlink {
            target: link,
            condition,
            ..
        } => match observe_rooted_condition(target, *condition)? {
            // A matched replacement swaps the new leaf in atomically, so a
            // concurrent replacement of the observed object is refused
            // rather than deleted.
            Some(metadata) if *condition != TargetCondition::Any => {
                if !metadata.is_symlink() {
                    bail!(
                        "target {} cannot change type under a matched condition",
                        target.label.display()
                    );
                }
                root.replace_symlink_if_same(path, link, metadata.dev, metadata.ino)
            }
            Some(metadata) => {
                if metadata.is_dir() {
                    root.remove_directory(path)?;
                } else {
                    root.unlink(path)?;
                }
                root.create_symlink(path, link)
            }
            None => root.create_symlink(path, link),
        },
        Op::Mknod {
            mode,
            rdev,
            condition,
            ..
        } => match observe_rooted_condition(target, *condition)? {
            Some(metadata) if *condition != TargetCondition::Any => {
                if file_type_bits(metadata.mode) != file_type_bits(*mode) {
                    bail!(
                        "target {} cannot change type under a matched condition",
                        target.label.display()
                    );
                }
                root.replace_node_if_same(path, *mode, *rdev, metadata.dev, metadata.ino)
            }
            Some(metadata) => {
                if metadata.is_dir() {
                    root.remove_directory(path)?;
                } else {
                    root.unlink(path)?;
                }
                root.create_node(path, *mode, *rdev)
            }
            None => root.create_node(path, *mode, *rdev),
        },
        Op::SetMeta {
            meta,
            flags,
            condition,
            ..
        } => set_meta_rooted(target, meta, *flags, *condition),
        Op::SetFileMetaIfSame {
            condition,
            meta,
            flags,
            ..
        } => {
            let file = root.open_metadata(path)?;
            if !file.metadata()?.file_type().is_file() {
                bail!(
                    "destination {} changed before metadata repair",
                    target.label.display()
                );
            }
            require_open_target(&file, &target.label, *condition)?;
            set_meta_handle(&file, meta, *flags)?;
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                &file,
                *condition,
            )
        }
        Op::Rmdir { .. } => match root.metadata_optional(path)? {
            None => Ok(()),
            Some(_) => root.remove_directory(path),
        },
        Op::Unlink { .. } => match root.metadata_optional(path)? {
            None => Ok(()),
            Some(metadata) if metadata.is_dir() => {
                bail!(
                    "{}: is now a directory; not deleting it",
                    target.label.display()
                )
            }
            Some(_) => root.unlink(path),
        },
        Op::Remove { .. } => bail!("recursive remove cannot use a confined destination root"),
    }
}

fn set_meta_rooted(
    target: &RootedTarget,
    meta: &Meta,
    flags: u8,
    condition: TargetCondition,
) -> Result<()> {
    if target.relative.is_empty() {
        let metadata = target.root.metadata(&target.relative)?;
        require_rooted_condition(metadata, condition, &target.label)?;
        let handle = target.root.open_metadata(&target.relative)?;
        require_rooted_metadata(&handle, metadata, &target.label)?;
        require_open_target(&handle, &target.label, condition)?;
        set_meta_handle(&handle, meta, flags & !flags::TIMES)?;
        if flags & flags::TIMES != 0 {
            let times = [
                timespec(0, libc::UTIME_OMIT as u32),
                timespec(meta.mtime, meta.mtime_nsec),
            ];
            target.root.set_times(&target.relative, &times)?;
        }
        return require_rooted_named_identity(
            &target.root,
            &target.relative,
            &target.label,
            &handle,
            condition,
        );
    }
    let metadata = target.root.metadata(&target.relative)?;
    if metadata.is_symlink() {
        require_rooted_condition(metadata, condition, &target.label)?;
        apply_owner(flags, meta, |uid, gid| {
            target.root.chown(&target.relative, uid, gid)
        })?;
    } else {
        let handle = target.root.open_metadata(&target.relative)?;
        require_rooted_metadata(&handle, metadata, &target.label)?;
        require_open_target(&handle, &target.label, condition)?;
        // Timestamp mutation is performed separately with no-follow
        // descriptor-relative semantics. All other metadata is applied to
        // the stable opened inode, so a raced leaf symlink cannot redirect it.
        set_meta_handle(&handle, meta, flags & !flags::TIMES)?;
    }
    if flags & flags::TIMES != 0 {
        let times = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        target.root.set_times(&target.relative, &times)?;
    }
    if metadata.is_symlink() {
        let after = target.root.metadata(&target.relative)?;
        require_rooted_identity(after, condition, &target.label)?;
    } else {
        let handle = target.root.open_metadata(&target.relative)?;
        require_rooted_named_identity(
            &target.root,
            &target.relative,
            &target.label,
            &handle,
            condition,
        )?;
    }
    Ok(())
}

/// `TargetCondition::Any` mkdir operations can race each other because apply
/// batches are parallel and deeper paths create implicit parents. Accept the
/// winner only when the conflicting name is a real directory beneath the
/// retained root; a symlink or any other type remains an error.
fn create_rooted_directory_or_existing(target: &RootedTarget, mode: u32) -> Result<()> {
    match target
        .root
        .create_directory(&target.relative, (mode & 0o7777) | 0o700)
    {
        Ok(()) => Ok(()),
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
            }) =>
        {
            let metadata = target.root.metadata(&target.relative)?;
            if !metadata.is_dir() {
                return Err(error);
            }
            if metadata.mode & 0o700 != 0o700 {
                let directory = target.root.open_metadata(&target.relative)?;
                require_rooted_metadata(&directory, metadata, &target.label)?;
                set_mode_handle(&directory, metadata.mode | 0o700)?;
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn require_rooted_identity(
    metadata: RootMetadata,
    condition: TargetCondition,
    label: &Path,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => {
            bail!("target {} appeared before metadata update", label.display())
        }
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. }
            if (metadata.dev, metadata.ino) == (dev, ino) =>
        {
            Ok(())
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            bail!("target {} changed during metadata update", label.display())
        }
    }
}

fn require_rooted_condition(
    metadata: RootMetadata,
    condition: TargetCondition,
    label: &Path,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => {
            bail!("target {} appeared before metadata update", label.display())
        }
        TargetCondition::Matches { dev, ino } if (metadata.dev, metadata.ino) == (dev, ino) => {
            Ok(())
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } if (
            metadata.dev,
            metadata.ino,
            metadata.ctime,
            metadata.ctime_nsec,
        ) == (dev, ino, ctime, ctime_nsec) =>
        {
            Ok(())
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            bail!("target {} changed before metadata update", label.display())
        }
    }
}

fn require_rooted_metadata(file: &File, expected: RootMetadata, label: &Path) -> Result<()> {
    let opened = file.metadata()?;
    if opened.dev() != expected.dev || opened.ino() != expected.ino {
        bail!(
            "confined target {} changed while opening it",
            label.display()
        );
    }
    Ok(())
}

fn require_rooted_named_identity(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    file: &File,
    condition: TargetCondition,
) -> Result<()> {
    let (dev, ino) = match condition {
        TargetCondition::Any => {
            let metadata = file.metadata()?;
            (metadata.dev(), metadata.ino())
        }
        TargetCondition::Absent => bail!("new target unexpectedly received metadata repair"),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => (dev, ino),
    };
    let opened = file.metadata()?;
    let named = root.metadata(relative)?;
    if opened.dev() != dev || opened.ino() != ino || named.dev != dev || named.ino != ino {
        bail!("target {} changed during update", label.display());
    }
    Ok(())
}

fn condition_identity(condition: TargetCondition) -> Result<(u64, u64)> {
    match condition {
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => Ok((dev, ino)),
        TargetCondition::Any | TargetCondition::Absent => {
            bail!("target condition does not identify an existing object")
        }
    }
}

#[cfg(target_os = "linux")]
fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT
}

#[cfg(not(target_os = "linux"))]
fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT as u32
}

fn exact_parent(path: &Path) -> Result<(Root, RelativePath)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let leaf = path
        .file_name()
        .context("exact replacement target has no leaf name")?;
    Ok((Root::open(parent)?, RelativePath::new(leaf.as_bytes())?))
}

fn replace_exact_symlink(path: &Path, link: &[u8], condition: TargetCondition) -> Result<()> {
    let (dev, ino) = condition_identity(condition)?;
    let (root, relative) = exact_parent(path)?;
    root.replace_symlink_if_same(&relative, link, dev, ino)
}

fn replace_exact_node(path: &Path, mode: u32, rdev: u64, condition: TargetCondition) -> Result<()> {
    let (dev, ino) = condition_identity(condition)?;
    let (root, relative) = exact_parent(path)?;
    root.replace_node_if_same(&relative, mode, rdev, dev, ino)
}

#[cfg(debug_assertions)]
fn hold_before_guarded_mutation_for_test(path: &[u8]) -> Result<()> {
    let Some(suffix) = std::env::var_os("SYQ_TEST_GUARDED_MUTATION_SUFFIX") else {
        return Ok(());
    };
    if !path.ends_with(suffix.as_bytes()) {
        return Ok(());
    }
    if let Some(ready) = std::env::var_os("SYQ_TEST_GUARDED_MUTATION_READY_FILE") {
        fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_GUARDED_MUTATION_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_before_guarded_mutation_for_test(_path: &[u8]) -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_before_quick_metadata_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_QUICK_META_READY_FILE") {
        fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write quick-metadata-ready signal {}",
                Path::new(&ready).display()
            )
        })?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_QUICK_META_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_before_quick_metadata_for_test() -> Result<()> {
    Ok(())
}

fn require_target_condition(
    path: &Path,
    condition: TargetCondition,
) -> Result<Option<fs::Metadata>> {
    match condition {
        TargetCondition::Any => Ok(fs::symlink_metadata(path).ok()),
        TargetCondition::Absent => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Ok(_) => bail!(
                "target {} appeared after the new-path precondition was checked",
                path.display()
            ),
            Err(error) => Err(error).with_context(|| format!("stat {}", path.display())),
        },
        TargetCondition::Matches { dev, ino } => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.dev() == dev && metadata.ino() == ino => Ok(Some(metadata)),
            Ok(_) | Err(_) => bail!(
                "target {} changed after the existing-path precondition was checked",
                path.display()
            ),
        },
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.dev() == dev
                    && metadata.ino() == ino
                    && metadata.ctime() == ctime
                    && metadata.ctime_nsec() as u32 == ctime_nsec =>
            {
                Ok(Some(metadata))
            }
            Ok(_) | Err(_) => bail!(
                "target {} changed after the existing-path precondition was checked",
                path.display()
            ),
        },
    }
}

fn require_open_target(file: &File, path: &Path, condition: TargetCondition) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "target {} appeared after the new-path precondition was checked",
            path.display()
        ),
        TargetCondition::Matches { dev, ino } => {
            let metadata = file.metadata()?;
            if metadata.dev() != dev || metadata.ino() != ino {
                bail!(
                    "target {} changed after the existing-path precondition was checked",
                    path.display()
                );
            }
            Ok(())
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => {
            let metadata = file.metadata()?;
            if metadata.dev() != dev
                || metadata.ino() != ino
                || metadata.ctime() != ctime
                || metadata.ctime_nsec() as u32 != ctime_nsec
            {
                bail!(
                    "target {} changed after the existing-path precondition was checked",
                    path.display()
                );
            }
            Ok(())
        }
    }
}

/// Confirm that a pathname still names the held object after this operation
/// has intentionally changed that object's ctime.
fn require_named_target_identity(
    file: &File,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "new-target condition cannot validate an in-place update of {}",
            path.display()
        ),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => {
            let opened = file.metadata()?;
            let named =
                fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
            if opened.dev() != dev
                || opened.ino() != ino
                || named.dev() != dev
                || named.ino() != ino
            {
                bail!(
                    "target {} changed during the existing-path update",
                    path.display()
                );
            }
            Ok(())
        }
    }
}

/// Open a stable reference suitable for metadata-only repair without reading
/// file contents. O_NONBLOCK prevents a concurrent FIFO/device replacement
/// from hanging before fstat can reject it.
fn open_metadata_handle(path: &Path) -> Result<File> {
    let path = cstr(path)?;
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn set_meta_handle(file: &File, meta: &Meta, flags: u8) -> Result<()> {
    let fd = file.as_raw_fd();
    let empty = c"";
    // Owner first: chown clears setuid/setgid, so mode must follow it.
    apply_owner(flags, meta, |uid, gid| {
        let r = unsafe {
            libc::fchownat(
                fd,
                empty.as_ptr(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_EMPTY_PATH,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })?;
    if flags & flags::MODE_MASK != 0 {
        let current = file.metadata()?.mode() & 0o7777;
        let wanted = meta.mode & 0o7777;
        if current != wanted || (flags & (flags::OWNER | flags::GROUP) != 0 && wanted & 0o6000 != 0)
        {
            set_mode_handle(file, wanted)?;
        }
    }
    if flags & flags::TIMES != 0 {
        bail!("metadata-only O_PATH repair does not support timestamp changes");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_meta_handle(file: &File, meta: &Meta, flags: u8) -> Result<()> {
    set_meta_file(file, meta, flags)
}

#[cfg(target_os = "linux")]
fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    let fd = file.as_raw_fd();
    let r = unsafe { libc::fchmodat(fd, c"".as_ptr(), mode as libc::mode_t, libc::AT_EMPTY_PATH) };
    if r == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    ) {
        return Err(error.into());
    }
    // Older libc/kernel combinations do not expose fchmodat2's AT_EMPTY_PATH
    // support. procfs still resolves this stable O_PATH descriptor, never the
    // possibly replaced pathname.
    fs::set_permissions(
        PathBuf::from("/proc/self/fd").join(fd.to_string()),
        fs::Permissions::from_mode(mode),
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(debug_assertions)]
fn fail_set_meta_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_SETMETA") {
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            return Err(anyhow!("set metadata {}: injected failure", p.display()));
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn fail_put_small_before_rename_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME") {
        // Model interruption after the sidecar is complete but before it
        // becomes the final name.
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            bail!("put small {}: injected failure before rename", p.display());
        }
    }
    Ok(())
}

const PAR_THREADS: usize = 32;
const PAR_MIN: usize = 32;

fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if items.len() < PAR_MIN {
        return items.iter().map(&f).collect();
    }
    let chunk = items.len().div_ceil(PAR_THREADS).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|c| s.spawn(|| c.iter().map(&f).collect::<Vec<R>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("stat thread"))
            .collect()
    })
}

/// Hash exactly `len` bytes in fixed blocks. A short reader contributes the
/// bytes it has and empty hashes for the missing blocks, matching both source
/// and destination behavior through one implementation.
fn hash_reader(reader: &mut impl Read, block: u64, len: u64) -> Result<Vec<ContentDigest>> {
    if !hash_response_fits(block, len) {
        bail!("hash block size or response count is outside protocol limits");
    }
    let n = usize::try_from(len.div_ceil(block)).context("hash count exceeds this platform")?;
    let mut hashes = Vec::with_capacity(n);
    let mut buf = vec![0u8; block as usize];
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(block) as usize;
        let mut got = 0;
        while got < want {
            let read = reader.read(&mut buf[got..want])?;
            if read == 0 {
                break;
            }
            got += read;
        }
        hashes.push(content_digest(&buf[..got]));
        if got < want {
            while hashes.len() < n {
                hashes.push(content_digest(&[]));
            }
            break;
        }
        remaining -= want as u64;
    }
    Ok(hashes)
}

impl FsOps {
    pub fn probe_partial(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        guard: Option<&ContainerGuard>,
    ) -> Result<Response> {
        let p = resolve(path);
        if let Some(guard) = guard {
            let pp = partial_path(&p, partial_id)?;
            let target = guarded_target(path, guard)?;
            let relative = relative_under(&target.root_path, &pp)?;
            let partial_size = target
                .root
                .metadata_optional(&relative)?
                .filter(|metadata| is_safe_rooted_partial(*metadata))
                .map(|metadata| metadata.len);
            return Ok(Response::PartialSize(partial_size));
        }
        let pp = self.partial_path(&p, partial_id)?;
        let partial_size = match fs::symlink_metadata(&pp) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Ok(metadata) if is_safe_partial(&metadata) => Some(metadata.len()),
            Ok(_) => None,
            Err(error) => return Err(error).with_context(|| format!("stat {}", pp.display())),
        };
        Ok(Response::PartialSize(partial_size))
    }

    /// Open this job's adjacent sidecar without following symlinks or modifying
    /// hardlinked files. A crash may leave final metadata (including 0444) on
    /// the sidecar, so make a safe regular leftover writable before reuse.
    fn open_private_partial(&mut self, pp: &Path) -> Result<(File, Option<u64>)> {
        self.uncache(pp);
        let mut repaired_permissions = false;
        for _ in 0..8 {
            match fs::symlink_metadata(pp) {
                Ok(md) if is_safe_partial(&md) => {
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(pp)
                    {
                        Ok(file) => {
                            let fd_meta = file.metadata()?;
                            let path_meta = fs::symlink_metadata(pp)?;
                            if !is_safe_partial(&fd_meta)
                                || !is_safe_partial(&path_meta)
                                || fd_meta.dev() != path_meta.dev()
                                || fd_meta.ino() != path_meta.ino()
                            {
                                continue;
                            }
                            if fd_meta.mode() & 0o7777 != 0o600 {
                                let repair = (|| -> Result<()> {
                                    fail_partial_chmod_for_test()?;
                                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                                    Ok(())
                                })();
                                if let Err(error) = repair {
                                    drop(file);
                                    discard_safe_partial_if_same(pp, &fd_meta).with_context(
                                        || {
                                            format!(
                                                "replace partial {} after chmod failed: {error:#}",
                                                pp.display()
                                            )
                                        },
                                    )?;
                                    continue;
                                }
                            }
                            return Ok((file, Some(fd_meta.len())));
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                            if repaired_permissions {
                                discard_safe_partial_if_same(pp, &md).with_context(|| {
                                    format!(
                                        "replace partial {} after it remained unreadable",
                                        pp.display()
                                    )
                                })?;
                                repaired_permissions = false;
                                continue;
                            }
                            // Open a metadata-only descriptor and chmod that,
                            // not the pathname: this works for mode-000 files
                            // and a co-writer cannot redirect the repair to a
                            // symlink target between lstat and chmod.
                            let handle = match open_metadata_handle(pp) {
                                Ok(handle) => handle,
                                Err(repair_error) => {
                                    discard_safe_partial_if_same(pp, &md).with_context(|| {
                                        format!(
                                            "replace partial {} after permission repair failed: {repair_error:#}",
                                            pp.display()
                                        )
                                    })?;
                                    continue;
                                }
                            };
                            let fd_meta = handle.metadata()?;
                            let path_meta = fs::symlink_metadata(pp)?;
                            if !is_safe_partial(&fd_meta)
                                || !is_safe_partial(&path_meta)
                                || fd_meta.dev() != md.dev()
                                || fd_meta.ino() != md.ino()
                                || fd_meta.dev() != path_meta.dev()
                                || fd_meta.ino() != path_meta.ino()
                            {
                                continue;
                            }
                            let repair = (|| -> Result<()> {
                                fail_partial_chmod_for_test()?;
                                set_mode_handle(&handle, 0o600)?;
                                Ok(())
                            })();
                            if let Err(error) = repair {
                                drop(handle);
                                discard_safe_partial_if_same(pp, &fd_meta).with_context(|| {
                                    format!(
                                        "replace partial {} after chmod failed: {error:#}",
                                        pp.display()
                                    )
                                })?;
                                continue;
                            }
                            repaired_permissions = true;
                            continue;
                        }
                        Err(error) => {
                            return Err(error).with_context(|| format!("open {}", pp.display()))
                        }
                    }
                }
                Ok(_) => {
                    fs::remove_file(pp).with_context(|| format!("replace {}", pp.display()))?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(pp)
                    {
                        Ok(file) => {
                            require_safe_partial(&file, pp)?;
                            Ok((file, None))
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            Err(error).with_context(|| format!("create {}", pp.display()))
                        }
                    };
                }
                Err(error) => return Err(error).with_context(|| format!("stat {}", pp.display())),
            }
        }
        bail!(
            "partial {} changed repeatedly while opening it",
            pp.display()
        )
    }

    fn open_private_partial_rooted(
        &mut self,
        root: &Root,
        relative: &RelativePath,
        label: &Path,
    ) -> Result<(File, Option<u64>)> {
        self.uncache(label);
        for _ in 0..8 {
            match root.metadata_optional(relative)? {
                Some(metadata) if is_safe_rooted_partial(metadata) => {
                    match root.open_regular_read_write(relative) {
                        Ok(file) => {
                            let opened = file.metadata()?;
                            let named = root.metadata(relative)?;
                            if !is_safe_partial(&opened)
                                || opened.dev() != named.dev
                                || opened.ino() != named.ino
                            {
                                continue;
                            }
                            if opened.mode() & 0o7777 != 0o600 {
                                fail_partial_chmod_for_test()?;
                                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                            }
                            return Ok((file, Some(opened.len())));
                        }
                        Err(error)
                            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                error.kind() == io::ErrorKind::PermissionDenied
                            }) =>
                        {
                            fail_partial_chmod_for_test()?;
                            let handle = root.open_metadata(relative)?;
                            require_rooted_metadata(&handle, metadata, label)?;
                            set_mode_handle(&handle, 0o600)?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Some(_) => root.unlink(relative)?,
                None => match root.create_file(relative, 0o600) {
                    Ok(file) => return Ok((file, None)),
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
                    {
                        continue
                    }
                    Err(error) => return Err(error),
                },
            }
        }
        bail!(
            "partial {} changed repeatedly while opening it",
            label.display()
        )
    }

    pub fn prepare(
        &mut self,
        path: &[u8],
        size: u64,
        inplace: bool,
        partial_id: &PartialId,
        mode: u32,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let p = resolve(path);
        if let Some(guard) = guard {
            if inplace {
                self.uncache(&p);
                let target = guarded_target(path, guard)?;
                for _ in 0..8 {
                    match target.root.metadata_optional(&target.relative)? {
                        Some(metadata) if metadata.is_file() => {
                            let file = target.root.open_regular_write(&target.relative, false)?;
                            require_rooted_metadata(&file, metadata, &target.label)?;
                            file.set_len(size).with_context(|| {
                                format!("resize confined file {}", target.label.display())
                            })?;
                            return Ok(());
                        }
                        Some(metadata) if metadata.is_dir() => {
                            bail!("destination {} is a directory", target.label.display())
                        }
                        Some(_) => target.root.unlink(&target.relative)?,
                        None => match target.root.create_file(&target.relative, mode) {
                            Ok(file) => {
                                file.set_len(size).with_context(|| {
                                    format!("resize confined file {}", target.label.display())
                                })?;
                                return Ok(());
                            }
                            Err(error)
                                if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                    error.kind() == io::ErrorKind::AlreadyExists
                                }) =>
                            {
                                continue
                            }
                            Err(error) => return Err(error),
                        },
                    }
                }
                bail!(
                    "destination {} changed repeatedly while opening it",
                    target.label.display()
                );
            }
            let target = guarded_target(path, guard)?;
            let pp = partial_path(&p, partial_id)?;
            let relative = relative_under(&target.root_path, &pp)?;
            let (file, basis_size) =
                self.open_private_partial_rooted(&target.root, &relative, &pp)?;
            if basis_size.is_none() {
                preallocate(&file, size)?;
            }
            file.set_len(size)?;
            return Ok(());
        }
        if inplace {
            self.uncache(&p);
            // A stale partial from an interrupted run would otherwise be orphaned.
            if let Ok(pp) = self.partial_path(&p, partial_id) {
                let _ = fs::remove_file(pp);
            }
            let f = open_regular_write(&p, mode, false)?;
            f.set_len(size)?;
            return Ok(());
        }
        let pp = self.partial_path(&p, partial_id)?;
        let (f, basis_size) = self.open_private_partial(&pp)?;
        if basis_size.is_some() {
            f.set_len(size)?;
            return Ok(());
        }
        preallocate(&f, size)?;
        f.set_len(size)?; // exact length: fallocate never shrinks an already-longer file
        #[cfg(debug_assertions)]
        if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_PARTIAL_MS") {
            if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        Ok(())
    }

    pub fn hash_and_hold(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        block: u64,
        len: u64,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<(Vec<ContentDigest>, u64)> {
        let p = resolve(path);
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_HASH_BASIS").is_some() {
            bail!("injected retained-basis hash failure");
        }
        let mut file = if let Some(guard) = guard {
            let target = guarded_target(path, guard)?;
            target.root.open_regular_read(&target.relative)?
        } else {
            open_existing_regular(&p, false)
                .with_context(|| format!("open {} as repair basis", p.display()))?
        };
        require_open_target(&file, &p, condition)?;
        let hashes = hash_reader(&mut file, block, len)?;
        self.held_basis = Some(HeldBasis {
            path: p,
            partial_id: *partial_id,
            file,
        });
        #[cfg(debug_assertions)]
        if let Some(ready) = std::env::var_os("SYQ_TEST_BASIS_READY_FILE") {
            fs::write(&ready, b"ready").with_context(|| {
                format!("write basis-ready signal {}", Path::new(&ready).display())
            })?;
        }
        #[cfg(debug_assertions)]
        if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_BASIS_MS") {
            if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        // Hashing is intentionally limited to the source length. Report the
        // retained inode's length afterward so a file that grew since the
        // planner's stat cannot be mistaken for an exact content match.
        let held_len = self
            .held_basis
            .as_ref()
            .expect("basis retained above")
            .file
            .metadata()?
            .len();
        Ok((hashes, held_len))
    }

    fn take_held_basis(&mut self, path: &[u8], partial_id: &PartialId) -> Result<HeldBasis> {
        let expected = resolve(path);
        let held = self
            .held_basis
            .take()
            .context("no retained destination basis")?;
        if held.path != expected || held.partial_id != *partial_id {
            bail!("retained destination basis does not match requested file");
        }
        Ok(held)
    }

    pub fn finish_basis(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let held = self.take_held_basis(path, partial_id)?;
        require_open_target(&held.file, &held.path, condition)?;
        set_meta_file(&held.file, meta, flags)
            .with_context(|| format!("set metadata on basis {}", held.path.display()))?;
        if let Some(guard) = guard {
            let target = guarded_target(path, guard)?;
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                &held.file,
                condition,
            )?;
        } else {
            require_named_target_identity(&held.file, &held.path, condition)?;
        }
        Ok(())
    }

    pub fn seed_basis(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        len: u64,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let mut held = self.take_held_basis(path, partial_id)?;
        let dst = if let Some(guard) = guard {
            let pp = partial_path(&held.path, partial_id)?;
            let target = guarded_target(path, guard)?;
            let relative = relative_under(&target.root_path, &pp)?;
            self.open_private_partial_rooted(&target.root, &relative, &pp)?
                .0
        } else {
            let pp = self.partial_path(&held.path, partial_id)?;
            self.open_private_partial(&pp)?.0
        };
        dst.set_len(0)?;
        preallocate(&dst, len)?;
        dst.set_len(len)?;
        held.file.seek(SeekFrom::Start(0))?;
        let mut writer = &dst;
        writer.seek(SeekFrom::Start(0))?;
        io::copy(&mut held.file.take(len), &mut writer)
            .with_context(|| format!("seed partial from {}", held.path.display()))?;
        dst.set_len(len)?;
        Ok(())
    }

    /// Copy a whole same-machine file without routing its bytes through the
    /// transport. Prefer copy_file_range; when a cross-mount copy into NFS
    /// cannot be offloaded, use one sequential userspace writer instead. Other
    /// unsupported filesystems return "EXDEV" for the parallel streaming path.
    #[cfg(target_os = "linux")]
    fn copy_local(
        &mut self,
        src: &[u8],
        dst: &[u8],
        policy: CopyLocalPolicy,
        partial_id: &PartialId,
        size: u64,
        mode: u32,
    ) -> Result<()> {
        let CopyLocalPolicy {
            inplace,
            allow_sequential_nfs_fallback,
        } = policy;
        let sp = resolve(src);
        let s = open_existing_regular(&sp, false)?;
        // The kernel copy reads the source through the page cache, so the
        // larger readahead window this hint enables is what keeps a cold
        // source disk streaming (cp does the same; measured 10-20 % faster
        // on a cold 4 GiB file). Advisory only: a failure changes nothing.
        unsafe {
            libc::posix_fadvise(s.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
        let dp = resolve(dst);
        // Never truncate the source: if the destination resolves to the same
        // file (same path, a hardlink, or a symlink pointing back), refuse.
        if let (Ok(sm), Ok(dm)) = (s.metadata(), fs::metadata(&dp)) {
            if sm.dev() == dm.dev() && sm.ino() == dm.ino() {
                bail!("source and destination are the same file: {}", dp.display());
            }
        }
        self.uncache(&dp);
        let target = if inplace {
            dp.clone()
        } else {
            self.partial_path(&dp, partial_id)?
        };
        self.uncache(&target);
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).ok();
            }
        }
        let d = if inplace {
            open_regular_write(&target, mode, true)?
        } else {
            let (d, _) = self.open_private_partial(&target)?;
            // Only discard stale content. ext4 treats any truncate to zero,
            // even of an empty file, as "replace via truncate" and then
            // flushes every dirty page of the file on close (auto_da_alloc),
            // which put the whole writeback of a 4 GiB copy (about 1.8 s on
            // NVMe) on the critical path before the rename.
            if d.metadata()?.len() > 0 {
                d.set_len(0)?;
            }
            d
        };
        let source_fs = file_system_traits(&s);
        let destination_fs = file_system_traits(&d);
        #[cfg(debug_assertions)]
        let source_fs = FileSystemTraits {
            is_nfs: source_fs.is_nfs
                || std::env::var_os("SYQ_TEST_COPY_LOCAL_SOURCE_NFS").is_some(),
            measured_local_source: source_fs.measured_local_source
                || std::env::var_os("SYQ_TEST_COPY_LOCAL_SOURCE_DISK").is_some(),
            ..source_fs
        };
        #[cfg(debug_assertions)]
        let destination_fs = FileSystemTraits {
            is_nfs: destination_fs.is_nfs || std::env::var_os("SYQ_TEST_COPY_LOCAL_NFS").is_some(),
            synchronous: destination_fs.synchronous
                || std::env::var_os("SYQ_TEST_COPY_LOCAL_NFS_SYNC").is_some(),
            ..destination_fs
        };
        // The measured fast path is a local filesystem feeding an ordinary
        // asynchronous NFS mount. NFS reads can benefit from parallelism, and
        // a synchronous destination makes every write syscall wait for the
        // server, so let the normal adaptive range path handle either case.
        let use_sequential_nfs_fallback = allow_sequential_nfs_fallback
            && !source_fs.is_nfs
            && source_fs.measured_local_source
            && destination_fs.is_nfs
            && !destination_fs.synchronous;
        let mut userspace_fallback = false;
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_COPY_LOCAL_EXDEV").is_some() {
            if use_sequential_nfs_fallback {
                userspace_fallback = true;
            } else {
                drop(d);
                if !inplace {
                    fs::remove_file(&target)
                        .with_context(|| format!("remove {}", target.display()))?;
                }
                bail!("EXDEV");
            }
        }
        let mut off: i64 = 0;
        let mut remaining = size;
        while remaining > 0 && !userspace_fallback {
            let n = unsafe {
                libc::copy_file_range(
                    s.as_raw_fd(),
                    &mut off as *mut i64 as *mut _,
                    d.as_raw_fd(),
                    &mut off as *mut i64 as *mut _,
                    remaining as usize,
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                let raw = e.raw_os_error().unwrap_or(0);
                // First-block failure with a "can't offload" errno: signal fallback.
                if remaining == size
                    && matches!(
                        raw,
                        libc::EXDEV | libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL
                    )
                {
                    if use_sequential_nfs_fallback {
                        userspace_fallback = true;
                        continue;
                    }
                    drop(d);
                    if !inplace {
                        // The planner probed before this empty sidecar existed.
                        // A content-identical fallback completes through its
                        // retained basis fd and would otherwise orphan it.
                        fs::remove_file(&target)
                            .with_context(|| format!("remove {}", target.display()))?;
                    }
                    bail!("EXDEV");
                }
                if raw == libc::EINTR {
                    continue;
                }
                return Err(e).with_context(|| {
                    format!("copy_file_range {} -> {}", sp.display(), target.display())
                });
            }
            if n == 0 {
                break; // source shorter than expected; finalize what we have
            }
            remaining -= n as u64;
        }
        if userspace_fallback {
            let mut source = &s;
            let mut destination = &d;
            source.seek(SeekFrom::Start(0))?;
            destination.seek(SeekFrom::Start(0))?;
            let mut buffer = vec![0u8; 1 << 20];
            let mut remaining = size;
            while remaining > 0 {
                let want = remaining.min(buffer.len() as u64) as usize;
                let n = source
                    .read(&mut buffer[..want])
                    .with_context(|| format!("read {}", sp.display()))?;
                if n == 0 {
                    bail!("source shortened while copying {}", sp.display());
                }
                destination
                    .write_all(&buffer[..n])
                    .with_context(|| format!("write {}", target.display()))?;
                remaining -= n as u64;
            }
            d.set_len(size)?;
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn copy_local(
        &mut self,
        _src: &[u8],
        _dst: &[u8],
        _policy: CopyLocalPolicy,
        _partial_id: &PartialId,
        _size: u64,
        _mode: u32,
    ) -> Result<()> {
        bail!("EXDEV")
    }

    /// Write a whole small file through its deterministic sidecar and atomically
    /// rename it into place. Keeping this as one request preserves pipelining;
    /// unlike an in-place write, no partial final-named file is ever visible.
    fn put_small(
        &mut self,
        target: PartialTarget<'_>,
        data: &[u8],
        hash: ContentDigest,
        meta: &Meta,
        flags: u8,
        condition: TargetCondition,
    ) -> Result<()> {
        if content_digest(data) != hash {
            bail!("block hash mismatch on receive");
        }
        let p = resolve(target.path);
        self.uncache(&p);
        if let Some(guard) = target.guard {
            let guarded = guarded_target(target.path, guard)?;
            let pp = partial_path(&p, target.id)?;
            let relative = relative_under(&guarded.root_path, &pp)?;
            self.uncache(&pp);
            let (file, _) = self.open_private_partial_rooted(&guarded.root, &relative, &pp)?;
            file.set_len(0)?;
            file.write_all_at(data, 0)
                .with_context(|| format!("write {}", pp.display()))?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", pp.display()))?;
            #[cfg(debug_assertions)]
            fail_put_small_before_rename_for_test(&p)?;
            publish_partial_rooted(&guarded.root, &relative, &guarded.relative, condition)?;
            return Ok(());
        }
        if matches!(
            condition,
            TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
        ) {
            let file = open_existing_regular(&p, true)?;
            require_open_target(&file, &p, condition)?;
            file.set_len(0)?;
            file.write_all_at(data, 0)
                .with_context(|| format!("write existing {}", p.display()))?;
            file.set_len(data.len() as u64)?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", p.display()))?;
            require_named_target_identity(&file, &p, condition)?;
            return Ok(());
        }
        let pp = self.partial_path(&p, target.id)?;
        self.uncache(&pp);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).ok();
            }
        }
        let (f, _) = self.open_private_partial(&pp)?;
        f.set_len(0)?;
        f.write_all_at(data, 0)
            .with_context(|| format!("write {}", pp.display()))?;
        set_meta_file(&f, meta, flags).with_context(|| format!("set metadata {}", pp.display()))?;
        #[cfg(debug_assertions)]
        fail_put_small_before_rename_for_test(&self.logical_destination_path(&p))?;
        publish_partial(&pp, &p, condition)?;
        drop(f);
        Ok(())
    }

    fn hash_blocks(
        &mut self,
        target: HashTarget<'_>,
        which: Which,
        partial_id: &PartialId,
        block: u64,
        len: u64,
    ) -> Result<Vec<ContentDigest>> {
        if target.source.is_some() || !self.source_roots.is_empty() {
            if target.guard.is_some() {
                bail!("source block hash cannot carry a destination guard");
            }
            if which != Which::Final {
                bail!("source block hash is only valid for the final source file");
            }
            if let Some((_, source_target)) = self.source_content_target(target.source)? {
                let mut file = open_registered_source(&source_target)?;
                return hash_reader(&mut file, block, len);
            }
            // Only an explicitly unconfined rsync source session can reach
            // this legacy branch after source roots have been initialized.
        }
        let p = resolve(target.path);
        let p = if which == Which::Partial {
            if target.guard.is_some() {
                partial_path(&p, partial_id)?
            } else {
                self.partial_path(&p, partial_id)?
            }
        } else {
            p
        };
        if let Some(guard) = target.guard {
            let guarded = guarded_target(target.path, guard)?;
            let relative = relative_under(&guarded.root_path, &p)?;
            let mut file = guarded.root.open_regular_read(&relative)?;
            if which == Which::Partial && !is_safe_rooted_partial(guarded.root.metadata(&relative)?)
            {
                bail!(
                    "partial {} is not a singly-linked regular file",
                    p.display()
                );
            }
            return hash_reader(&mut file, block, len);
        }
        let mut f = open_existing_regular(&p, false)?;
        if which == Which::Partial {
            require_safe_partial(&f, &p)?;
        }
        hash_reader(&mut f, block, len)
    }

    pub fn read_range(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        attempt: u32,
        off: u64,
        len: u32,
    ) -> Result<Response> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_READ_RANGE").is_some() {
            bail!("test read-range failure");
        }
        let target = self.source_content_target(source)?;
        let p = resolve(path);
        let f = if let Some((root_id, target)) = target {
            let relative_bytes = &source
                .expect("rooted source target requires a registered reference")
                .relative;
            self.cached_source_read(root_id, relative_bytes, &target, attempt)?
        } else {
            // This is either a pre-registration test/control operation or the
            // explicit rsync --insecure-links compatibility path.
            self.cached(&p, false, attempt, false)?
        };
        let mut data = vec![0u8; len as usize];
        f.read_exact_at(&mut data, off)
            .with_context(|| format!("read {} @{off}+{len}", p.display()))?;
        let hash = content_digest(&data);
        Ok(Response::Block { off, hash, data })
    }

    fn write_range(
        &mut self,
        target: PartialTarget<'_>,
        inplace: bool,
        attempt: u32,
        off: u64,
        hash: ContentDigest,
        data: &[u8],
    ) -> Result<()> {
        if content_digest(data) != hash {
            bail!("block hash mismatch on receive @{off}");
        }
        let p = resolve(target.path);
        let p = if inplace {
            p
        } else if target.guard.is_some() {
            partial_path(&p, target.id)?
        } else {
            self.partial_path(&p, target.id)?
        };
        let f = if let Some(guard) = target.guard {
            if inplace {
                let final_target = guarded_target(target.path, guard)?;
                self.cached_rooted(
                    &p,
                    &final_target.root,
                    &final_target.relative,
                    attempt,
                    false,
                )?
            } else {
                let final_target = guarded_target(target.path, guard)?;
                let relative = relative_under(&final_target.root_path, &p)?;
                self.cached_rooted(&p, &final_target.root, &relative, attempt, true)?
            }
        } else {
            self.cached(&p, true, attempt, !inplace)?
        };
        f.write_all_at(data, off)
            .with_context(|| format!("write {} @{off}", p.display()))
    }

    fn finalize(
        &mut self,
        path: &[u8],
        inplace: bool,
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
        mutation: TargetMutation<'_>,
    ) -> Result<()> {
        if mutation.guard.is_some() {
            return self.finalize_rooted(path, inplace, partial_id, meta, flags, mutation);
        }
        let TargetMutation { condition, .. } = mutation;
        let p = resolve(path);
        let src = if inplace {
            p.clone()
        } else {
            self.partial_path(&p, partial_id)?
        };
        let f = self
            .uncache(&src)
            .map(Ok)
            .unwrap_or_else(|| open_existing_regular(&src, true))?;
        if inplace {
            if !f.metadata()?.file_type().is_file() {
                bail!("destination {} is not a regular file", src.display());
            }
            require_open_target(&f, &p, condition)?;
        } else {
            require_safe_partial(&f, &src)?;
        }
        if !inplace
            && matches!(
                condition,
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
            )
        {
            // Range writes cache the private sidecar write-only. Retain that
            // descriptor while opening the same safe inode for reading, so a
            // pathname swap cannot substitute bytes before copy-back.
            let staged_metadata = f.metadata()?;
            let mut staged = open_existing_regular(&src, false)?;
            let reopened_metadata = staged.metadata()?;
            require_safe_partial(&staged, &src)?;
            if staged_metadata.dev() != reopened_metadata.dev()
                || staged_metadata.ino() != reopened_metadata.ino()
            {
                bail!("partial {} changed before publication", src.display());
            }
            self.uncache(&p);
            let mut target = open_existing_regular(&p, true)?;
            require_open_target(&target, &p, condition)?;
            let size = reopened_metadata.len();
            target.set_len(0)?;
            staged.seek(SeekFrom::Start(0))?;
            target.seek(SeekFrom::Start(0))?;
            io::copy(&mut staged, &mut target)
                .with_context(|| format!("update existing {}", p.display()))?;
            target.set_len(size)?;
            set_meta_file(&target, meta, flags)
                .with_context(|| format!("set metadata {}", p.display()))?;
            require_named_target_identity(&target, &p, condition)?;
            fs::remove_file(&src).with_context(|| format!("remove {}", src.display()))?;
            return Ok(());
        }
        set_meta_file(&f, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        if !inplace {
            if fs::symlink_metadata(&p).is_ok_and(|metadata| metadata.is_dir()) {
                bail!("destination {} is a directory", p.display());
            }
            publish_partial(&src, &p, condition)?;
        } else {
            require_named_target_identity(&f, &p, condition)?;
        }
        drop(f);
        Ok(())
    }

    fn finalize_rooted(
        &mut self,
        path: &[u8],
        inplace: bool,
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
        mutation: TargetMutation<'_>,
    ) -> Result<()> {
        let TargetMutation {
            condition,
            guard: Some(guard),
        } = mutation
        else {
            unreachable!("rooted finalization requires a container guard")
        };
        let target = guarded_target(path, guard)?;
        if inplace {
            let file = self
                .uncache(&target.label)
                .map(Ok)
                .unwrap_or_else(|| target.root.open_regular_write(&target.relative, false))?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", target.label.display()))?;
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                &file,
                condition,
            )?;
            return Ok(());
        }
        let src = partial_path(&target.label, partial_id)?;
        let src_relative = relative_under(&target.root_path, &src)?;
        let file = self
            .uncache(&src)
            .map(Ok)
            .unwrap_or_else(|| target.root.open_regular_write(&src_relative, false))?;
        let opened = file.metadata()?;
        let named = target.root.metadata(&src_relative)?;
        if !is_safe_partial(&opened)
            || !is_safe_rooted_partial(named)
            || opened.dev() != named.dev
            || opened.ino() != named.ino
        {
            bail!("partial {} changed before publication", src.display());
        }
        set_meta_file(&file, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        if target
            .root
            .metadata_optional(&target.relative)?
            .is_some_and(RootMetadata::is_dir)
        {
            bail!("destination {} is a directory", target.label.display());
        }
        publish_partial_rooted(&target.root, &src_relative, &target.relative, condition)?;
        Ok(())
    }

    pub fn file_hash(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        guard: Option<&ContainerGuard>,
    ) -> Result<Response> {
        let mut f = if source.is_some() || !self.source_roots.is_empty() {
            if guard.is_some() {
                bail!("source file hash cannot carry a destination guard");
            }
            if let Some((_, target)) = self.source_content_target(source)? {
                open_registered_source(&target)?
            } else {
                // Explicit rsync --insecure-links compatibility path.
                open_existing_regular(&resolve(path), false)?
            }
        } else if let Some(guard) = guard {
            let target = guarded_target(path, guard)?;
            target.root.open_regular_read(&target.relative)?
        } else if let Some(root) = &self.destination_root {
            root.open_regular_read(&RelativePath::new(path)?)?
        } else {
            open_existing_regular(&resolve(path), false)?
        };
        let mut h = blake3::Hasher::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut size = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            size += n as u64;
        }
        Ok(Response::FileHash {
            size,
            hash: *h.finalize().as_bytes(),
        })
    }

    /// Dispatch a request that has a single response (everything except Scan).
    pub fn handle(&mut self, req: &Request) -> Response {
        if let Err(error) = self.validate_source_session_request(req) {
            return Response::Err(errstr(&error));
        }
        let req = match self.map_request(req) {
            Ok(req) => req,
            Err(error) => return Response::Err(errstr(&error)),
        };
        // HashAndHold's next request must consume the retained descriptor.
        // Any other request means the controller abandoned that comparison
        // (for example because the source hash failed), so release it here.
        if !matches!(
            &req,
            Request::FinishBasis { .. } | Request::SeedBasis { .. }
        ) {
            self.held_basis.take();
        }
        let r: Result<Response> = match &req {
            Request::StatMany {
                paths,
                sources,
                follow,
                guard,
            } => self
                .stat_many_request(paths, sources.as_deref(), *follow, guard.as_ref())
                .map(Response::Stats),
            Request::CheckOperatorDirectory {
                path,
                allow_missing,
                symlink_policy,
            } => self
                .check_operator_directory(path, *allow_missing, *symlink_policy)
                .with_context(|| format!("resolve operator directory {}", resolve(path).display()))
                .map(Response::DirectorySelection),
            Request::RegisterSourceRoots {
                selections,
                symlink_policy,
                allow_unconfined_paths,
                shared_workers,
                independent_claim_workers,
            } => self
                .register_source_roots(
                    selections,
                    *symlink_policy,
                    *allow_unconfined_paths,
                    *shared_workers,
                    *independent_claim_workers,
                )
                .map(Response::SourceRootsRegistered),
            Request::CreateOperatorDirectory {
                mode,
                require_absent,
            } => self
                .create_operator_directory(*mode, *require_absent)
                .map(|anchor| Response::DirectorySelection(Some(anchor))),
            Request::AnchorDestination {
                expected_dev,
                expected_ino,
                request_prefix,
            } => self
                .anchor_destination(*expected_dev, *expected_ino, request_prefix)
                .map(Response::DestinationRegistered),
            Request::PartialPaths {
                paths,
                partial_id,
                guard,
            } => Ok(Response::PathResults(self.partial_paths(
                paths,
                partial_id,
                guard.as_ref(),
            ))),
            Request::PlanBatch {
                partial_paths,
                partial_id,
                directories,
                others,
                guard,
            } => {
                let guard = guard.as_ref();
                let partial_paths = self.partial_paths(partial_paths, partial_id, guard);
                let directories = self.stat_many(directories, false, guard);
                let safe_to_stat_others = directories.iter().all(|entry| {
                    entry
                        .as_ref()
                        .is_some_and(|entry| entry.kind == Kind::Dir && entry.mode & 0o700 == 0o700)
                });
                let others = safe_to_stat_others.then(|| self.stat_many(others, false, guard));
                Ok(Response::BatchPlan {
                    partial_paths,
                    directories,
                    others,
                })
            }
            Request::Apply { ops, guard } => Ok(Response::Applied(self.apply(ops, guard.as_ref()))),
            Request::ProbePartial {
                path,
                partial_id,
                guard,
            } => self.probe_partial(path, partial_id, guard.as_ref()),
            Request::Prepare {
                path,
                size,
                inplace,
                partial_id,
                mode,
                guard,
            } => self
                .prepare(path, *size, *inplace, partial_id, *mode, guard.as_ref())
                .map(|_| Response::Ok),
            Request::HashAndHold {
                path,
                partial_id,
                block,
                len,
                condition,
                guard,
            } => self
                .hash_and_hold(path, partial_id, *block, *len, *condition, guard.as_ref())
                .map(|(hashes, len)| Response::HeldHashes { hashes, len }),
            Request::FinishBasis {
                path,
                partial_id,
                meta,
                flags,
                condition,
                guard,
            } => self
                .finish_basis(path, partial_id, meta, *flags, *condition, guard.as_ref())
                .map(|_| Response::Ok),
            Request::SeedBasis {
                path,
                partial_id,
                len,
                guard,
            } => self
                .seed_basis(path, partial_id, *len, guard.as_ref())
                .map(|_| Response::Ok),
            Request::CopyLocal {
                src,
                dst,
                inplace,
                allow_sequential_nfs_fallback,
                partial_id,
                size,
                mode,
            } => self
                .copy_local(
                    src,
                    dst,
                    CopyLocalPolicy {
                        inplace: *inplace,
                        allow_sequential_nfs_fallback: *allow_sequential_nfs_fallback,
                    },
                    partial_id,
                    *size,
                    *mode,
                )
                .map(|_| Response::Ok),
            Request::PutSmallBatch(puts) => Ok(Response::Applied(
                puts.iter()
                    .map(|put| {
                        self.put_small(
                            PartialTarget {
                                path: &put.path,
                                id: &put.partial_id,
                                guard: put.guard.as_ref(),
                            },
                            &put.data,
                            put.hash,
                            &put.meta,
                            put.flags,
                            put.condition,
                        )
                        .err()
                        .map(|error| errstr(&error))
                    })
                    .collect(),
            )),
            Request::HashBlocks {
                path,
                source,
                which,
                partial_id,
                block,
                len,
                guard,
                ..
            } => self
                .hash_blocks(
                    HashTarget {
                        path,
                        source: source.as_ref(),
                        guard: guard.as_ref(),
                    },
                    *which,
                    partial_id,
                    *block,
                    *len,
                )
                .map(Response::Hashes),
            Request::ReadRange {
                path,
                source,
                attempt,
                off,
                len,
                ..
            } => self.read_range(path, source.as_ref(), *attempt, *off, *len),
            Request::ReadSmallBatch(reads) => Ok(Response::SmallBlocks(
                reads
                    .iter()
                    .map(|read| {
                        match self.read_range(
                            &read.path,
                            read.source.as_ref(),
                            read.attempt,
                            0,
                            read.len,
                        ) {
                            Ok(Response::Block { data, hash, .. }) => Ok(SmallBlock { data, hash }),
                            Ok(other) => Err(format!("unexpected response {other:?}")),
                            Err(error) => Err(errstr(&error)),
                        }
                    })
                    .collect(),
            )),
            Request::WriteRange {
                path,
                inplace,
                partial_id,
                attempt,
                off,
                hash,
                data,
                guard,
            } => self
                .write_range(
                    PartialTarget {
                        path,
                        id: partial_id,
                        guard: guard.as_ref(),
                    },
                    *inplace,
                    *attempt,
                    *off,
                    *hash,
                    data,
                )
                .map(|_| Response::Ok),
            Request::Finalize {
                path,
                inplace,
                partial_id,
                meta,
                flags,
                condition,
                guard,
            } => self
                .finalize(
                    path,
                    *inplace,
                    partial_id,
                    meta,
                    *flags,
                    TargetMutation {
                        condition: *condition,
                        guard: guard.as_ref(),
                    },
                )
                .map(|_| Response::Ok),
            Request::FileHash {
                path,
                source,
                guard,
            } => self.file_hash(path, source.as_ref(), guard.as_ref()),
            Request::Canonicalize { path, guard } => {
                if let Some(guard) = guard {
                    guarded_target(path, guard)
                        .map(|target| Response::Path(path_bytes(&target.label)))
                } else {
                    Ok(Response::Path(path_bytes(&normalize(&resolve(path)))))
                }
            }
            Request::Hello { .. }
            | Request::Scan { .. }
            | Request::NativeRemove { .. }
            | Request::TransportStats
            | Request::Receipt
            | Request::Shutdown
            | Request::TcpListen { .. } => Err(anyhow!("unexpected request")),
        };
        match r {
            Ok(resp) => self.rebase_response(resp),
            Err(e) => Response::Err(errstr(&e)),
        }
    }
}

fn publish_partial(src: &Path, dst: &Path, condition: TargetCondition) -> Result<()> {
    match condition {
        TargetCondition::Any => fs::rename(src, dst)
            .with_context(|| format!("publish {} as destination {}", src.display(), dst.display())),
        TargetCondition::Absent => {
            // The sidecar is adjacent to the destination, so hard-linking it
            // creates the final name atomically and fails with EEXIST instead
            // of replacing a target that raced the planner.
            fs::hard_link(src, dst).with_context(|| {
                format!(
                    "publish new {} as destination {} without replacement",
                    src.display(),
                    dst.display()
                )
            })?;
            fs::remove_file(src).with_context(|| format!("remove {}", src.display()))
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            bail!("internal error: matched publication must update the held target inode")
        }
    }
}

fn publish_partial_rooted(
    root: &Root,
    source: &RelativePath,
    target: &RelativePath,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => root.rename(source, target),
        TargetCondition::Absent => root.publish_new_regular(source, target),
        TargetCondition::Matches { dev, ino } => {
            root.replace_regular_if_same(source, target, dev, ino, None)
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => root.replace_regular_if_same(source, target, dev, ino, Some((ctime, ctime_nsec))),
    }
}

/// Open `target` for writing as a regular file, replacing any existing
/// symlink/dir/special and refusing to follow a symlink (O_NOFOLLOW), then
/// verify the opened fd is a regular file. Used for every write target so a
/// malicious or stale `.syq-part` symlink can't redirect the write.
fn open_regular_write(target: &Path, mode: u32, truncate: bool) -> Result<File> {
    for _ in 0..8 {
        match fs::symlink_metadata(target) {
            Ok(md) if md.is_file() => {
                // Do not pass O_CREAT for an existing file. Linux
                // fs.protected_regular can reject that combination in a
                // sticky directory even when the caller is allowed to open
                // and update the inode (rsync's --inplace case).
                match OpenOptions::new()
                    .write(true)
                    .truncate(truncate)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(target)
                {
                    Ok(file) if file.metadata()?.file_type().is_file() => return Ok(file),
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        return Err(error).with_context(|| format!("open {}", target.display()))
                    }
                }
            }
            Ok(md) if md.is_dir() => {
                bail!("destination {} is a directory", target.display())
            }
            Ok(_) => {
                fs::remove_file(target).with_context(|| format!("replace {}", target.display()))?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .truncate(truncate)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .mode(mode & 0o7777)
                    .open(target)
                {
                    Ok(file) if file.metadata()?.file_type().is_file() => return Ok(file),
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).with_context(|| format!("create {}", target.display()))
                    }
                }
            }
            Err(error) => return Err(error).with_context(|| format!("stat {}", target.display())),
        }
    }
    bail!(
        "destination {} changed repeatedly while opening it",
        target.display()
    )
}

/// Open an existing leaf without following a last-component symlink. Parent
/// component confinement is a separate, root-fd-based design problem.
fn open_existing_regular(target: &Path, write: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(!write)
        .write(write)
        // Validate the opened type below. O_NONBLOCK ensures a concurrent FIFO
        // or device replacement cannot hang us before that validation.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(target)
        .with_context(|| format!("open {}", target.display()))?;
    if !file.metadata()?.file_type().is_file() {
        bail!("{} is not a regular file", target.display());
    }
    Ok(file)
}

fn require_safe_partial(file: &File, target: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !is_safe_partial(&metadata) {
        bail!(
            "partial {} is not a singly-linked regular file",
            target.display()
        );
    }
    Ok(())
}

fn is_safe_partial(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && metadata.nlink() == 1
}

fn is_safe_rooted_partial(metadata: RootMetadata) -> bool {
    metadata.is_file() && metadata.nlink == 1
}

/// Remove only the same safe sidecar that was just inspected. If the pathname
/// changed, let the caller retry the normal validation loop instead.
fn discard_safe_partial_if_same(path: &Path, expected: &fs::Metadata) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(current)
            if is_safe_partial(&current)
                && current.dev() == expected.dev()
                && current.ino() == expected.ino() =>
        {
            fs::remove_file(path).with_context(|| format!("replace {}", path.display()))?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn fail_partial_chmod_for_test() -> Result<()> {
    if std::env::var_os("SYQ_TEST_FAIL_PARTIAL_CHMOD").is_some() {
        bail!("injected partial chmod failure");
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn fail_partial_chmod_for_test() -> Result<()> {
    Ok(())
}

fn mkdir(p: &Path, mode: u32) -> io::Result<()> {
    std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), (mode & 0o7777) | 0o700)
        .create(p)
}

fn followed_metadata(p: &Path) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(p).map(|md| {
        if md.file_type().is_symlink() {
            fs::metadata(p).unwrap_or(md)
        } else {
            md
        }
    })
}

fn make_dir_writable(p: &Path, md: &fs::Metadata) -> Result<()> {
    if md.mode() & 0o700 != 0o700 {
        fs::set_permissions(p, fs::Permissions::from_mode(md.mode() | 0o700))?;
    }
    Ok(())
}

fn mkdir_or_existing_dir(p: &Path, mode: u32) -> Result<()> {
    match mkdir(p, mode) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => match followed_metadata(p) {
            Ok(md) if md.is_dir() => make_dir_writable(p, &md),
            _ => Err(err.into()),
        },
        Err(err) => Err(err.into()),
    }
}

fn preallocate(f: &File, size: u64) -> Result<()> {
    if size == 0 {
        f.set_len(0)?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let r = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, size as libc::off_t) };
        if r == 0 {
            return Ok(());
        }
        // Unsupported filesystem (tmpfs, some NFS): fall through to sparse.
    }
    // Portable fallback (also macOS): a sparse file of the right size.
    f.set_len(size)?;
    Ok(())
}

fn timespec(sec: i64, nsec: u32) -> libc::timespec {
    libc::timespec {
        tv_sec: sec as libc::time_t,
        tv_nsec: nsec as libc::c_long,
    }
}

fn set_meta_file(f: &File, meta: &Meta, flags: u8) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // Owner first: chown clears setuid/setgid, so mode must be set afterwards.
    apply_owner(flags, meta, |uid, gid| {
        std::os::unix::fs::fchown(f, uid, gid)
    })?;
    if flags & flags::MODE_MASK != 0 {
        // On network filesystems every setattr is a round trip; skip it when
        // the mode is already right (but always run it after a chown that could
        // have cleared setuid/setgid bits we need to restore).
        let cur = f.metadata().map(|m| m.mode() & 0o7777).unwrap_or(u32::MAX);
        let want = meta.mode & 0o7777;
        if cur != want || (flags & (flags::OWNER | flags::GROUP) != 0 && want & 0o6000 != 0) {
            f.set_permissions(fs::Permissions::from_mode(want))?;
        }
    }
    if flags & flags::TIMES != 0 {
        let ts = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        let r = unsafe { libc::futimens(f.as_raw_fd(), ts.as_ptr()) };
        if r != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_meta_path(p: &Path, meta: &Meta, flags: u8) -> Result<()> {
    let md = fs::symlink_metadata(p)?;
    let is_link = md.file_type().is_symlink();
    // Owner first: chown clears setuid/setgid, so mode is applied afterwards.
    apply_owner(flags, meta, |uid, gid| {
        std::os::unix::fs::lchown(p, uid, gid)
    })?;
    if flags & flags::MODE_MASK != 0 && !is_link {
        fs::set_permissions(p, fs::Permissions::from_mode(meta.mode & 0o7777))?;
    }
    if flags & flags::TIMES != 0 {
        let ts = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        let c = cstr(p)?;
        let r = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                ts.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Owner only as root; group as anyone (may fail with EPERM, which we ignore
/// like rsync does for groups the user isn't a member of).
fn apply_owner(
    flags: u8,
    meta: &Meta,
    chown: impl Fn(Option<u32>, Option<u32>) -> io::Result<()>,
) -> Result<()> {
    let uid = if flags & flags::OWNER != 0 && is_root() {
        Some(meta.uid)
    } else {
        None
    };
    let gid = if flags & flags::GROUP != 0 {
        Some(meta.gid)
    } else {
        None
    };
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    match chown(uid, gid) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && uid.is_none() => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::{symlink, FileTypeExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "syq-fsops-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn registered_source_worker(
        selections: &[&Path],
        allow_unconfined_paths: bool,
    ) -> (FsOps, Vec<RegisteredPath>, FsOps) {
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: selections
                .iter()
                .map(|path| SourceRootSelection {
                    path: path.as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                })
                .collect(),
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths,
            shared_workers: 0,
            independent_claim_workers: 0,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        let selections = roots.iter().map(|root| root.selection.clone()).collect();
        let mut worker = FsOps::with_descriptor_session(session);
        worker.initialize_sources(&roots).unwrap();
        // Return the control endpoint so tests retain the complete session
        // lifecycle in addition to each worker's own root and leaf clones.
        (worker, selections, control)
    }

    #[test]
    fn existing_regular_open_does_not_follow_leaf_symlinks() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let file = dir.join("file");
        let link = dir.join("link");
        fs::write(&file, b"data").unwrap();
        symlink(&file, &link).unwrap();

        let regular_opened = open_existing_regular(&file, false).is_ok();
        let link_rejected = open_existing_regular(&link, false).is_err();
        fs::remove_dir_all(&dir).unwrap();

        assert!(regular_opened);
        assert!(link_rejected);
    }

    #[test]
    fn guarded_inplace_updates_are_confined_and_keep_the_target_inode() {
        let dir = test_dir();
        let root_path = dir.join("root");
        let outside = dir.join("outside");
        fs::create_dir_all(&root_path).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let target = root_path.join("file");
        let sentinel = outside.join("sentinel");
        fs::write(&target, b"old").unwrap();
        fs::write(&sentinel, b"outside").unwrap();
        symlink(&outside, root_path.join("escape")).unwrap();

        let root = Root::open(&root_path).unwrap();
        let identity = root.identity();
        let guard = ContainerGuard {
            root: root_path.as_os_str().as_bytes().to_vec(),
            dev: identity.dev,
            ino: identity.ino,
        };
        let target_bytes = target.as_os_str().as_bytes();
        let partial_id = [7; 16];
        let inode = fs::metadata(&target).unwrap().ino();
        let mut operations = FsOps::new();
        operations
            .prepare(target_bytes, 3, true, &partial_id, 0o600, Some(&guard))
            .unwrap();
        operations
            .write_range(
                PartialTarget {
                    path: target_bytes,
                    id: &partial_id,
                    guard: Some(&guard),
                },
                true,
                0,
                0,
                content_digest(b"new"),
                b"new",
            )
            .unwrap();
        operations
            .finalize(
                target_bytes,
                true,
                &partial_id,
                &Meta {
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                0,
                TargetMutation {
                    condition: TargetCondition::Any,
                    guard: Some(&guard),
                },
            )
            .unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(fs::metadata(&target).unwrap().ino(), inode);
        let escaped = root_path.join("escape/sentinel");
        assert!(operations
            .prepare(
                escaped.as_os_str().as_bytes(),
                1,
                true,
                &partial_id,
                0o600,
                Some(&guard),
            )
            .is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn operator_directory_walk_follows_owned_links_and_reports_missing_suffixes() {
        let dir = test_dir();
        let real = dir.join("real/nested");
        fs::create_dir_all(&real).unwrap();
        symlink("real", dir.join("relative-link")).unwrap();
        symlink(dir.join("real"), dir.join("absolute-link")).unwrap();

        let expected = fs::metadata(&real).unwrap();
        for selected in [
            dir.join("relative-link/nested"),
            dir.join("absolute-link/nested"),
        ] {
            let (_, anchor) = select_operator_directory(
                selected.as_os_str().as_bytes(),
                false,
                OperatorSymlinkPolicy::TrustedOwner,
            )
            .unwrap();
            let anchor = anchor.unwrap();
            assert_eq!((anchor.dev, anchor.ino), (expected.dev(), expected.ino()));
        }
        assert!(select_operator_directory(
            dir.join("relative-link/missing/deeper")
                .as_os_str()
                .as_bytes(),
            true,
            OperatorSymlinkPolicy::TrustedOwner,
        )
        .unwrap()
        .1
        .is_none());
        assert!(select_operator_directory(
            dir.join("relative-link/missing").as_os_str().as_bytes(),
            false,
            OperatorSymlinkPolicy::TrustedOwner,
        )
        .is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn operator_directory_walk_can_refuse_every_symlink() {
        let dir = test_dir();
        fs::create_dir_all(dir.join("real")).unwrap();
        symlink("real", dir.join("link")).unwrap();

        let error = select_operator_directory(
            dir.join("link").as_os_str().as_bytes(),
            false,
            OperatorSymlinkPolicy::Refuse,
        )
        .err()
        .expect("no-follow policy must refuse an owned symlink");
        assert!(error.to_string().contains("pass --follow"), "{error:#}");

        let (_, anchor) = select_operator_directory(
            dir.join("link").as_os_str().as_bytes(),
            false,
            OperatorSymlinkPolicy::FollowAll,
        )
        .unwrap();
        assert!(anchor.is_some());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_operator_directory_is_created_under_retained_ancestor() {
        let dir = test_dir();
        fs::create_dir_all(dir.join("parent")).unwrap();
        fs::create_dir_all(dir.join("outside")).unwrap();
        let (mut selection, anchor) = select_operator_directory(
            dir.join("parent/missing/deeper").as_os_str().as_bytes(),
            true,
            OperatorSymlinkPolicy::TrustedOwner,
        )
        .unwrap();
        assert!(anchor.is_none());

        fs::rename(dir.join("parent"), dir.join("selected-and-moved")).unwrap();
        symlink(dir.join("outside"), dir.join("parent")).unwrap();
        selection.create_missing(0o755, false).unwrap();

        assert!(dir.join("selected-and-moved/missing/deeper").is_dir());
        assert!(!dir.join("outside/missing").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_operator_directory_creation_reuses_the_real_directory() {
        let dir = test_dir();
        fs::create_dir_all(dir.join("parent")).unwrap();
        let selected = dir.join("parent/missing/deeper");
        let (mut first, first_anchor) = select_operator_directory(
            selected.as_os_str().as_bytes(),
            true,
            OperatorSymlinkPolicy::TrustedOwner,
        )
        .unwrap();
        let (mut second, second_anchor) = select_operator_directory(
            selected.as_os_str().as_bytes(),
            true,
            OperatorSymlinkPolicy::TrustedOwner,
        )
        .unwrap();
        assert!(first_anchor.is_none());
        assert!(second_anchor.is_none());

        let first_anchor = first.create_missing(0o755, false).unwrap();
        let second_anchor = second.create_missing(0o755, false).unwrap();
        assert_eq!(
            (first_anchor.dev, first_anchor.ino),
            (second_anchor.dev, second_anchor.ino)
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_operator_directory_rejects_a_concurrently_created_final_component() {
        let dir = test_dir();
        fs::create_dir_all(dir.join("parent")).unwrap();
        let selected = dir.join("parent/new");
        let (mut selection, anchor) = select_operator_directory(
            selected.as_os_str().as_bytes(),
            true,
            OperatorSymlinkPolicy::TrustedOwner,
        )
        .unwrap();
        assert!(anchor.is_none());

        fs::create_dir(&selected).unwrap();
        let error = selection.create_missing(0o755, true).unwrap_err();
        assert!(error
            .to_string()
            .contains("appeared after the new-target precondition"));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn existing_regular_open_does_not_block_on_fifo() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let fifo = dir.join("fifo");
        let fifo_c = cstr(&fifo).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        let started = std::time::Instant::now();
        let read_result = open_existing_regular(&fifo, false);
        let write_result = open_existing_regular(&fifo, true);
        fs::remove_dir_all(&dir).unwrap();

        assert!(read_result.is_err());
        assert!(write_result.is_err());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "opening a FIFO must not wait for a reader"
        );
    }

    #[test]
    fn matching_condition_can_replace_a_same_type_special_file() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let fifo = dir.join("fifo");
        let fifo_c = cstr(&fifo).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o644) }, 0);
        let before = fs::symlink_metadata(&fifo).unwrap();

        let errors = FsOps::new().apply(
            &[Op::Mknod {
                path: path_bytes(&fifo),
                mode: file_type_bits(before.mode()) | 0o600,
                rdev: 0,
                condition: TargetCondition::Matches {
                    dev: before.dev(),
                    ino: before.ino(),
                },
            }],
            None,
        );
        let after = fs::symlink_metadata(&fifo).unwrap();
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(errors, vec![None]);
        assert!(after.file_type().is_fifo());
        assert_ne!(after.ino(), before.ino());
        assert_eq!(after.mode() & 0o777, 0o600);
    }

    #[test]
    fn safe_partial_must_have_one_link() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let file = dir.join("partial");
        let alias = dir.join("alias");
        fs::write(&file, b"data").unwrap();
        fs::hard_link(&file, &alias).unwrap();

        let opened = open_existing_regular(&file, true).unwrap();
        let rejected = require_safe_partial(&opened, &file).is_err();
        drop(opened);
        fs::remove_dir_all(&dir).unwrap();

        assert!(rejected);
    }

    #[test]
    fn unlink_never_recurses_into_a_directory() {
        let dir = std::env::temp_dir().join(format!("syq-unlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("d/inside")).unwrap();
        fs::write(dir.join("f"), b"f").unwrap();
        let mut ops = FsOps::new();
        let path = |n: &str| path_bytes(&dir.join(n));
        let errs = ops.apply(
            &[
                Op::Unlink { path: path("d") },
                Op::Unlink { path: path("f") },
                Op::Unlink {
                    path: path("missing"),
                },
            ],
            None,
        );
        assert!(errs[0]
            .as_deref()
            .is_some_and(|e| e.contains("is now a directory")));
        assert!(
            dir.join("d/inside").is_dir(),
            "the directory and its contents survive"
        );
        assert!(errs[1].is_none() && !dir.join("f").exists());
        assert!(errs[2].is_none(), "a vanished leaf is not an error");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_batch_only_stats_leaves_below_ready_directories() {
        let root = test_dir();
        let ready = root.join("ready");
        let leaf = ready.join("leaf");
        fs::create_dir_all(&ready).unwrap();
        fs::write(&leaf, b"data").unwrap();
        let mut ops = FsOps::new();
        let request = |directory: &Path| Request::PlanBatch {
            partial_paths: vec![path_bytes(&leaf)],
            partial_id: [7; 16],
            directories: vec![path_bytes(directory)],
            others: vec![path_bytes(&leaf)],
            guard: None,
        };

        let Response::BatchPlan {
            partial_paths,
            directories,
            others,
        } = ops.handle(&request(&ready))
        else {
            panic!("expected a batch plan");
        };
        assert!(partial_paths[0].is_ok());
        assert_eq!(directories[0].as_ref().unwrap().kind, Kind::Dir);
        assert_eq!(others.unwrap()[0].as_ref().unwrap().kind, Kind::File);

        let Response::BatchPlan {
            directories,
            others,
            ..
        } = ops.handle(&request(&root.join("missing")))
        else {
            panic!("expected a batch plan");
        };
        assert!(directories[0].is_none());
        assert!(
            others.is_none(),
            "leaf stats must wait for directory repair"
        );

        fs::set_permissions(&ready, fs::Permissions::from_mode(0o500)).unwrap();
        let Response::BatchPlan {
            directories,
            others,
            ..
        } = ops.handle(&request(&ready))
        else {
            panic!("expected a batch plan");
        };
        assert_eq!(directories[0].as_ref().unwrap().kind, Kind::Dir);
        assert!(
            others.is_none(),
            "leaf stats must wait until the directory is writable"
        );
        fs::set_permissions(&ready, fs::Permissions::from_mode(0o700)).unwrap();

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn partial_name_keeps_job_id_and_fits_name_max() {
        let id = [7u8; 16];
        let short = partial_path(Path::new("file"), &id).unwrap();
        let short_name = short.file_name().unwrap();
        assert!(short_name.to_string_lossy().starts_with(".file.syq-part."));
        assert!(is_partial_name(short_name));

        let long = PathBuf::from("n".repeat(240));
        let partial = partial_path(&long, &id).unwrap();
        let name = partial.file_name().unwrap();
        assert!(name.as_bytes().len() <= COMMON_NAME_MAX);
        assert!(is_partial_name(name));
        assert!(name.to_string_lossy().ends_with(&base32(&id)));
    }

    #[test]
    fn partial_name_honors_filesystems_with_smaller_name_max() {
        let id = [8u8; 16];
        let final_path = PathBuf::from("dir").join("n".repeat(120));
        let partial = partial_path_with_name_max(&final_path, &id, 143).unwrap();
        let name = partial.file_name().unwrap();
        assert!(name.as_bytes().len() <= 143);
        assert!(is_partial_name(name));
        assert!(name.to_string_lossy().ends_with(&base32(&id)));
    }

    #[test]
    fn shortened_partial_name_preserves_utf8_boundaries() {
        let id = [10u8; 16];
        let final_path = PathBuf::from("dir").join("界".repeat(80));
        let partial = partial_path_with_name_max(&final_path, &id, 143).unwrap();
        let name = partial.file_name().unwrap();

        assert!(name.as_bytes().len() <= 143);
        assert!(name.to_str().is_some());
        assert!(is_partial_name(name));
    }

    #[test]
    fn destination_observation_uses_the_adopted_root_not_its_old_name() {
        let dir = test_dir();
        let selected = dir.join("selected");
        fs::create_dir_all(&selected).unwrap();
        fs::write(selected.join("marker"), b"original").unwrap();
        let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
        let mut operations = FsOps::new();
        operations.destination_root = Some(root);
        operations.destination_prefix = Some(b"logical".to_vec());

        fs::rename(&selected, dir.join("moved")).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("marker"), b"replacement").unwrap();

        let stats = operations.stat_many(&[b"marker".to_vec()], false, None);
        assert_eq!(stats[0].as_ref().unwrap().size, 8);
        let Response::FileHash { size, hash } =
            operations.file_hash(b"marker", None, None).unwrap()
        else {
            panic!("unexpected hash response");
        };
        assert_eq!(size, 8);
        assert_eq!(hash, content_digest(b"original"));

        let partial =
            operations.partial_paths(&[b"missing/deeper/marker".to_vec()], &[12; 16], None);
        assert!(partial[0]
            .as_ref()
            .unwrap()
            .starts_with(b"missing/deeper/.marker.syq-part."));
        assert!(operations.partial_paths(&[b"../outside".to_vec()], &[12; 16], None)[0].is_err());
        assert!(operations.file_hash(b"../outside", None, None).is_err());
        assert!(operations.stat_many(&[b"../outside".to_vec()], false, None)[0].is_none());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn destination_apply_uses_the_adopted_root_not_its_old_name() {
        let dir = test_dir();
        let selected = dir.join("selected");
        fs::create_dir_all(selected.join("empty")).unwrap();
        fs::write(selected.join("remove"), b"remove").unwrap();
        fs::write(selected.join("repair"), b"repair").unwrap();
        let repair_before = fs::symlink_metadata(selected.join("repair")).unwrap();
        let (selection, anchor) = select_operator_directory(
            selected.as_os_str().as_bytes(),
            false,
            OperatorSymlinkPolicy::Refuse,
        )
        .unwrap();
        assert!(anchor.is_some());
        let root = Arc::new(Root::from_directory(selection.directory).unwrap());
        let mut operations = FsOps::new();
        operations.destination_root = Some(root);
        operations.destination_prefix = Some(path_bytes(&selected));

        let moved = dir.join("moved");
        fs::rename(&selected, &moved).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("sentinel"), b"replacement").unwrap();

        let meta = |mode| Meta {
            mode,
            uid: 0,
            gid: 0,
            mtime: 1_700_000_000,
            mtime_nsec: 123_456_789,
        };
        let errors = operations.apply(
            &[
                Op::Mkdir {
                    path: b"created".to_vec(),
                    mode: 0o755,
                    condition: TargetCondition::Any,
                },
                Op::Mkdir {
                    path: b"nested/parent/created".to_vec(),
                    mode: 0o755,
                    condition: TargetCondition::Any,
                },
                Op::Symlink {
                    path: b"link".to_vec(),
                    target: b"target".to_vec(),
                    condition: TargetCondition::Any,
                },
                Op::Mknod {
                    path: b"pipe".to_vec(),
                    mode: MODE_FIFO | 0o600,
                    rdev: 0,
                    condition: TargetCondition::Any,
                },
                Op::Unlink {
                    path: b"remove".to_vec(),
                },
                Op::Rmdir {
                    path: b"empty".to_vec(),
                },
                Op::SetFileMetaIfSame {
                    path: b"repair".to_vec(),
                    condition: TargetCondition::MatchesFingerprint {
                        dev: repair_before.dev(),
                        ino: repair_before.ino(),
                        ctime: repair_before.ctime(),
                        ctime_nsec: repair_before.ctime_nsec() as u32,
                    },
                    meta: meta(0o640),
                    flags: flags::MODE,
                },
                Op::SetMeta {
                    path: b"link".to_vec(),
                    meta: meta(0),
                    flags: flags::TIMES,
                    condition: TargetCondition::Any,
                },
                Op::SetMeta {
                    path: Vec::new(),
                    meta: meta(0o701),
                    flags: flags::MODE | flags::TIMES,
                    condition: TargetCondition::Any,
                },
            ],
            None,
        );
        assert_eq!(errors, vec![None; 9]);

        assert!(moved.join("created").is_dir());
        assert!(moved.join("nested/parent/created").is_dir());
        assert_eq!(
            fs::read_link(moved.join("link")).unwrap(),
            Path::new("target")
        );
        assert!(fs::symlink_metadata(moved.join("pipe"))
            .unwrap()
            .file_type()
            .is_fifo());
        assert!(!moved.join("remove").exists());
        assert!(!moved.join("empty").exists());
        assert_eq!(
            fs::symlink_metadata(moved.join("repair")).unwrap().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::symlink_metadata(&moved).unwrap().mode() & 0o777, 0o701);
        assert_eq!(fs::read(selected.join("sentinel")).unwrap(), b"replacement");
        assert_eq!(fs::read_dir(&selected).unwrap().count(), 1);

        let outside = dir.join("outside");
        fs::write(&outside, b"outside").unwrap();
        let errors = operations.apply(
            &[
                Op::Unlink {
                    path: b"../outside".to_vec(),
                },
                Op::Remove {
                    path: b"created".to_vec(),
                },
            ],
            None,
        );
        assert!(errors.iter().all(Option::is_some));
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
        assert!(moved.join("created").is_dir());

        let outside_directory = dir.join("outside-directory");
        fs::create_dir(&outside_directory).unwrap();
        symlink(&outside_directory, moved.join("redirect")).unwrap();
        let errors = operations.apply(
            &[Op::Mkdir {
                path: b"redirect/escaped".to_vec(),
                mode: 0o755,
                condition: TargetCondition::Any,
            }],
            None,
        );
        assert!(errors[0].is_some());
        assert!(!outside_directory.join("escaped").exists());

        fs::set_permissions(&moved, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rooted_mkdir_race_accepts_only_an_existing_real_directory() {
        let dir = test_dir();
        let selected = dir.join("selected");
        let outside = dir.join("outside");
        fs::create_dir_all(selected.join("winner")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, selected.join("link")).unwrap();
        let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
        let target = |path: &[u8]| RootedTarget {
            root: root.clone(),
            relative: RelativePath::new(path).unwrap(),
            label: PathBuf::from(OsStr::from_bytes(path)),
            create_missing_parents: true,
        };

        assert!(create_rooted_directory_or_existing(&target(b"winner"), 0o755).is_ok());
        assert!(create_rooted_directory_or_existing(&target(b"link"), 0o755).is_err());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn name_limit_uses_nearest_existing_ancestor() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let missing = dir.join("not-yet-created/deeper");
        let target = dir.join("symlink-target");
        let link = dir.join("in-tree-link");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert_eq!(nearest_existing_directory(&missing), dir);
        assert_eq!(nearest_existing_directory(&link.join("deeper")), dir);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compact_partial_name_is_recognized() {
        let name = OsStr::from_bytes(b".syq-part.aaaaaaaaaaaaaaaa");
        assert!(is_partial_name(name));
        assert!(!is_partial_name(OsStr::from_bytes(b".syq-part.notes")));

        let id = [9u8; 16];
        let parent_len = libc::PATH_MAX as usize - 28;
        let final_path = PathBuf::from("a".repeat(parent_len)).join("x");
        let partial = partial_path(&final_path, &id).unwrap();
        assert_eq!(partial.file_name().unwrap().as_bytes().len(), 26);
        assert!(is_partial_name(partial.file_name().unwrap()));

        let too_deep = PathBuf::from("a".repeat(parent_len + 1)).join("x");
        assert!(partial_path(&too_deep, &id).is_err());
    }

    #[test]
    fn shared_block_hasher_handles_short_readers_consistently() {
        let block = MIN_HASH_BLOCK_BYTES as usize;
        let mut data = vec![b'a'; block];
        data.extend(vec![b'b'; block]);
        data.extend(b"tail");
        let hashes = hash_reader(&mut &data[..], block as u64, (block * 4) as u64).unwrap();
        assert_eq!(
            hashes,
            vec![
                content_digest(&vec![b'a'; block]),
                content_digest(&vec![b'b'; block]),
                content_digest(b"tail"),
                content_digest(b""),
            ]
        );
        assert!(hash_reader(&mut &b"x"[..], 0, 1).is_err());
        assert!(hash_reader(&mut &b"x"[..], 1, 1).is_err());
    }

    #[test]
    fn content_digest_is_full_blake3() {
        assert_eq!(
            content_digest(b""),
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62,
            ]
        );
    }

    #[test]
    fn source_workers_adopt_registered_descriptor_after_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("original"), b"original").unwrap();
        let identity = fs::metadata(&selected).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 0,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        let id = roots[0].selection.root();

        let moved = temporary.path().join("moved");
        let replacement = temporary.path().join("replacement");
        fs::rename(&selected, &moved).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(replacement.join("replacement"), b"replacement").unwrap();
        std::os::unix::fs::symlink(&replacement, &selected).unwrap();

        let mut shared = FsOps::with_descriptor_session(session);
        shared.initialize_sources(&roots).unwrap();
        let mut fresh = FsOps::new();
        fresh.initialize_sources(&roots).unwrap();
        for worker in [&mut shared, &mut fresh] {
            let adopted = worker.source_root_identity(id).unwrap();
            assert_eq!((adopted.dev, adopted.ino), (identity.dev(), identity.ino()));
            let original = roots[0].selection.join(b"original").unwrap();
            let response = worker.handle(&Request::StatMany {
                paths: vec![selected.join("original").as_os_str().as_bytes().to_vec()],
                sources: Some(vec![original]),
                follow: false,
                guard: None,
            });
            assert!(matches!(response, Response::Stats(stats) if stats[0].is_some()));
            let replacement = roots[0].selection.join(b"replacement").unwrap();
            let response = worker.handle(&Request::StatMany {
                paths: vec![selected.join("replacement").as_os_str().as_bytes().to_vec()],
                sources: Some(vec![replacement]),
                follow: false,
                guard: None,
            });
            assert!(matches!(response, Response::Stats(stats) if stats[0].is_none()));
        }
        assert_ne!(
            (
                fs::metadata(&replacement).unwrap().dev(),
                fs::metadata(&replacement).unwrap().ino()
            ),
            (identity.dev(), identity.ino())
        );
    }

    #[test]
    fn source_initialization_rejects_mismatched_bad_and_excess_roots_atomically() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![
                SourceRootSelection {
                    path: first.as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                },
                SourceRootSelection {
                    path: second.as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                },
            ],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 0,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };

        let mut mismatched = roots[0].clone();
        mismatched.selection = roots[1].selection.clone();
        let mut worker = FsOps::with_descriptor_session(session.clone());
        assert!(worker.initialize_sources(&[mismatched]).is_err());
        assert!(worker.source_roots.is_empty());

        let mut malformed = roots[0].clone();
        malformed.expected_leaf = Some(SourceLeafIdentity {
            dev: 1,
            ino: 2,
            file_type: 0,
            symlink_target: None,
        });
        assert!(worker.initialize_sources(&[malformed]).is_err());
        assert!(worker.source_roots.is_empty());

        session.close();
        assert!(worker.initialize_sources(&roots).is_err());
        assert!(worker.source_roots.is_empty());

        let excess = vec![roots[0].clone(); DEFAULT_MAX_ROOTS + 1];
        let error = worker.initialize_sources(&excess).unwrap_err();
        assert!(error.to_string().contains("root count"));
        assert!(worker.source_roots.is_empty());
    }

    #[test]
    fn source_initialization_rejects_missing_mistyped_and_cross_session_leaf_tickets() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let register = |control: &mut FsOps, path: &Path| {
            let response = control.handle(&Request::RegisterSourceRoots {
                selections: vec![SourceRootSelection {
                    path: path.as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                }],
                symlink_policy: OperatorSymlinkPolicy::Refuse,
                allow_unconfined_paths: false,
                shared_workers: 0,
                independent_claim_workers: 0,
            });
            let Response::SourceRootsRegistered(roots) = response else {
                panic!("unexpected source registration response: {response:?}")
            };
            roots.into_iter().next().unwrap()
        };

        let mut first_control = FsOps::new();
        let first_root = register(&mut first_control, &first);
        let mut second_control = FsOps::new();
        let second_root = register(&mut second_control, &second);
        assert_eq!(
            first_root.selection.root(),
            second_root.selection.root(),
            "independent registries should exercise coincident numeric IDs"
        );

        let mut worker = FsOps::new();
        let mut missing = first_root.clone();
        missing.leaf_ticket = None;
        assert!(worker.initialize_sources(&[missing]).is_err());
        assert!(worker.source_roots.is_empty());

        let mut mistyped = first_root.clone();
        mistyped.leaf_ticket = Some(mistyped.ticket.clone());
        assert!(worker.initialize_sources(&[mistyped]).is_err());
        assert!(worker.source_roots.is_empty());

        let mut nested = first_root.clone();
        nested.selection =
            RegisteredPath::new(nested.selection.root(), b"nested/leaf".to_vec()).unwrap();
        assert!(worker.initialize_sources(&[nested]).is_err());
        assert!(worker.source_roots.is_empty());

        let mut impossible_target = first_root.clone();
        impossible_target
            .expected_leaf
            .as_mut()
            .unwrap()
            .symlink_target = Some(b"not-a-regular-file-property".to_vec());
        assert!(worker.initialize_sources(&[impossible_target]).is_err());
        assert!(worker.source_roots.is_empty());

        let mut cross_session_pair = first_root.clone();
        cross_session_pair.leaf_ticket = second_root.leaf_ticket.clone();
        assert!(worker.initialize_sources(&[cross_session_pair]).is_err());
        assert!(worker.source_roots.is_empty());

        // All roots in one Hello must come from the same endpoint session,
        // even when each root/leaf pair is internally consistent.
        assert!(worker
            .initialize_sources(&[first_root, second_root])
            .is_err());
        assert!(worker.source_roots.is_empty());
    }

    #[test]
    fn independent_source_worker_keeps_exact_object_after_control_and_broker_close() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::write(&selected, b"original").unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 1,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        let expected = roots[0].expected_leaf.clone().unwrap();

        // An empty slot exercises the independent-worker broker claim path.
        let mut worker = FsOps::new();
        worker.initialize_sources(&roots).unwrap();
        drop(control);
        session.close();

        let original = temporary.path().join("original-unlinked");
        fs::rename(&selected, &original).unwrap();
        fs::remove_file(&original).unwrap();
        fs::write(&selected, b"replacement").unwrap();
        let held = worker.source_roots[&roots[0].selection.root()]
            ._leaf_object
            .as_ref()
            .unwrap()
            .metadata()
            .unwrap();
        assert_eq!((held.dev(), held.ino()), (expected.dev, expected.ino));
        assert_eq!(held.nlink(), 0);

        let response = worker.handle(&Request::StatMany {
            paths: vec![selected.as_os_str().as_bytes().to_vec()],
            sources: Some(vec![roots[0].selection.clone()]),
            follow: false,
            guard: None,
        });
        assert!(matches!(
            response,
            Response::Err(error) if error.contains("registered source leaf changed identity")
        ));
    }

    #[test]
    fn repeated_source_registration_keeps_the_original_root_and_leaf_pin() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let mut control = FsOps::new();
        let register = |path: &Path| Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: path.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 0,
        };
        let response = control.handle(&register(&first));
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        let original_id = roots[0].selection.root();
        let expected = roots[0].expected_leaf.clone().unwrap();
        assert_eq!(control.source_roots.len(), 1);
        assert!(control.source_roots[&original_id]._leaf_object.is_some());

        let response = control.handle(&register(&second));
        assert!(matches!(
            response,
            Response::Err(error) if error.contains("already registered")
        ));
        assert_eq!(control.source_roots.len(), 1);
        let pin = control.source_roots[&original_id]
            ._leaf_object
            .as_ref()
            .unwrap();
        let metadata = pin.metadata().unwrap();
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (expected.dev, expected.ino)
        );

        let response = control.handle(&Request::StatMany {
            paths: vec![first.as_os_str().as_bytes().to_vec()],
            sources: Some(vec![roots[0].selection.clone()]),
            follow: false,
            guard: None,
        });
        assert!(matches!(response, Response::Stats(stats) if stats[0].is_some()));
    }

    #[test]
    fn source_stat_enforces_exact_leaf_authority_and_ignores_parallel_path() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::write(&selected, b"selected").unwrap();
        fs::write(temporary.path().join("sibling"), b"sibling").unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 0,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        assert_eq!(roots[0].selection.relative, b"selected");
        assert!(roots[0].expected_leaf.is_some());
        assert!(control.source_roots[&roots[0].selection.root()]
            ._leaf_object
            .is_some());

        let mut worker = FsOps::with_descriptor_session(session);
        worker.initialize_sources(&roots).unwrap();
        let response = worker.handle(&Request::StatMany {
            // A contradictory display spelling cannot redirect the registered
            // selected leaf.
            paths: vec![temporary
                .path()
                .join("sibling")
                .as_os_str()
                .as_bytes()
                .to_vec()],
            sources: Some(vec![roots[0].selection.clone()]),
            follow: false,
            guard: None,
        });
        assert!(matches!(response, Response::Stats(stats) if stats[0].is_some()));

        let sibling = RegisteredPath::new(roots[0].selection.root(), b"sibling".to_vec()).unwrap();
        let response = worker.handle(&Request::StatMany {
            paths: vec![temporary
                .path()
                .join("sibling")
                .as_os_str()
                .as_bytes()
                .to_vec()],
            sources: Some(vec![sibling]),
            follow: false,
            guard: None,
        });
        assert!(matches!(response, Response::Err(error) if error.contains("does not authorize")));

        let response = worker.handle(&Request::StatMany {
            paths: vec![selected.as_os_str().as_bytes().to_vec()],
            sources: None,
            follow: false,
            guard: None,
        });
        assert!(matches!(response, Response::Err(error) if error.contains("omitted")));

        fs::rename(&selected, temporary.path().join("selected-original")).unwrap();
        fs::write(&selected, b"replacement").unwrap();
        let response = worker.handle(&Request::StatMany {
            paths: vec![selected.as_os_str().as_bytes().to_vec()],
            sources: Some(vec![roots[0].selection.clone()]),
            follow: false,
            guard: None,
        });
        assert!(matches!(
            response,
            Response::Err(error) if error.contains("registered source leaf changed identity")
        ));
    }

    #[test]
    fn source_scan_rejects_a_replaced_exact_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("target-a"), b"a").unwrap();
        fs::write(temporary.path().join("target-b"), b"b").unwrap();
        let selected = temporary.path().join("selected");
        std::os::unix::fs::symlink("target-a", &selected).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session);
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 0,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        assert!(control.source_roots[&roots[0].selection.root()]
            ._leaf_object
            .is_some());

        let mut worker = FsOps::new();
        worker.initialize_sources(&roots).unwrap();
        fs::rename(&selected, temporary.path().join("selected-original")).unwrap();
        std::os::unix::fs::symlink("target-b", &selected).unwrap();
        let source = worker
            .source_scan_root(Some(&roots[0].selection))
            .unwrap()
            .unwrap();
        let error = crate::scan::scan_descriptor(
            source.root,
            &source.relative,
            source.expected_leaf,
            false,
            false,
            &[],
            false,
            &mut |_| Ok(()),
            &mut |_| Ok(()),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("registered source leaf changed identity"),
            "{error:#}"
        );
    }

    #[test]
    fn exact_symlink_scan_uses_the_descriptor_bound_raw_target_snapshot() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let target = OsString::from_vec(b"raw-target-\xff".to_vec());
        symlink(Path::new(&target), &selected).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session);
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 1,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        assert_eq!(
            roots[0]
                .expected_leaf
                .as_ref()
                .unwrap()
                .symlink_target
                .as_deref(),
            Some(target.as_bytes())
        );

        let mut worker = FsOps::new();
        worker.initialize_sources(&roots).unwrap();
        // Temporarily replace the name, then restore the original symlink
        // object. The emitted target belongs to that pinned object; discovery
        // never obtains it with readlinkat(parent, name).
        let original = temporary.path().join("selected-original");
        fs::rename(&selected, &original).unwrap();
        symlink("different-target", &selected).unwrap();
        fs::remove_file(&selected).unwrap();
        fs::rename(&original, &selected).unwrap();

        let source = worker
            .source_scan_root(Some(&roots[0].selection))
            .unwrap()
            .unwrap();
        let mut entries = Vec::new();
        crate::scan::scan_descriptor(
            source.root,
            &source.relative,
            source.expected_leaf,
            false,
            false,
            &[],
            false,
            &mut |batch| {
                entries.extend(batch);
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, Kind::Symlink);
        assert_eq!(entries[0].link.as_deref(), Some(target.as_bytes()));
    }

    #[test]
    fn source_stat_does_not_follow_intermediate_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let outside = temporary.path().join("outside");
        fs::create_dir(&selected).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink("../outside", selected.join("link")).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_claim_workers: 0,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        let secret = roots[0].selection.join(b"link/secret").unwrap();
        let mut worker = FsOps::with_descriptor_session(session);
        worker.initialize_sources(&roots).unwrap();
        let response = worker.handle(&Request::StatMany {
            paths: vec![selected.join("link/secret").as_os_str().as_bytes().to_vec()],
            sources: Some(vec![secret]),
            follow: true,
            guard: None,
        });
        assert!(
            matches!(response, Response::Stats(stats) if stats.len() == 1 && stats[0].is_none())
        );
    }

    #[test]
    fn source_content_uses_registered_directory_after_name_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let replacement = temporary.path().join("replacement");
        fs::create_dir(&selected).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(selected.join("marker"), b"original").unwrap();
        fs::write(replacement.join("marker"), b"replacement").unwrap();
        let raw_name = OsString::from_vec(b"raw-\xff".to_vec());
        fs::write(selected.join(&raw_name), b"raw-original").unwrap();

        let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
        let marker = selections[0].join(b"marker").unwrap();
        let raw = selections[0].join(raw_name.as_bytes()).unwrap();
        fs::rename(&selected, temporary.path().join("moved")).unwrap();
        symlink(&replacement, &selected).unwrap();
        let parallel_marker = selected.join("marker").as_os_str().as_bytes().to_vec();
        assert_eq!(fs::read(selected.join("marker")).unwrap(), b"replacement");

        let response = worker.handle(&Request::ReadRange {
            path: parallel_marker.clone(),
            source: Some(marker.clone()),
            attempt: 0,
            off: 0,
            len: 8,
        });
        assert!(matches!(response, Response::Block { data, .. } if data == b"original"));

        let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
            path: parallel_marker.clone(),
            source: Some(marker.clone()),
            attempt: 0,
            len: 8,
        }]));
        assert!(matches!(
            response,
            Response::SmallBlocks(blocks)
                if matches!(&blocks[..], [Ok(SmallBlock { data, .. })] if data == b"original")
        ));

        let response = worker.handle(&Request::HashBlocks {
            path: parallel_marker.clone(),
            source: Some(marker.clone()),
            which: Which::Final,
            partial_id: [0; 16],
            block: MIN_HASH_BLOCK_BYTES,
            len: 8,
            guard: None,
        });
        assert!(
            matches!(response, Response::Hashes(hashes) if hashes == vec![content_digest(b"original")])
        );

        let response = worker.handle(&Request::FileHash {
            path: parallel_marker,
            source: Some(marker),
            guard: None,
        });
        assert!(
            matches!(response, Response::FileHash { size: 8, hash } if hash == content_digest(b"original"))
        );

        let response = worker.handle(&Request::ReadRange {
            path: b"/parallel/path/is/not/authority".to_vec(),
            source: Some(raw),
            attempt: 0,
            off: 0,
            len: 12,
        });
        assert!(matches!(response, Response::Block { data, .. } if data == b"raw-original"));
    }

    #[test]
    fn source_content_rejects_a_replaced_exact_leaf() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::write(&selected, b"original").unwrap();
        let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
        fs::rename(&selected, temporary.path().join("selected-original")).unwrap();
        fs::write(&selected, b"replaced").unwrap();

        for response in [
            worker.handle(&Request::ReadRange {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: Some(selections[0].clone()),
                attempt: 0,
                off: 0,
                len: 8,
            }),
            worker.handle(&Request::HashBlocks {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: Some(selections[0].clone()),
                which: Which::Final,
                partial_id: [0; 16],
                block: MIN_HASH_BLOCK_BYTES,
                len: 8,
                guard: None,
            }),
            worker.handle(&Request::FileHash {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: Some(selections[0].clone()),
                guard: None,
            }),
        ] {
            assert!(
                matches!(response, Response::Err(error) if error.contains("registered source leaf changed identity"))
            );
        }
        let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: Some(selections[0].clone()),
            attempt: 0,
            len: 8,
        }]));
        assert!(
            matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(error)] if error.contains("registered source leaf changed identity")))
        );
    }

    #[test]
    fn source_content_refuses_symlink_intermediates() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let outside = temporary.path().join("outside");
        fs::create_dir(&selected).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"secret").unwrap();
        symlink("../outside", selected.join("link")).unwrap();
        let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
        let secret = selections[0].join(b"link/secret").unwrap();
        let label = selected.join("link/secret").as_os_str().as_bytes().to_vec();

        for response in [
            worker.handle(&Request::ReadRange {
                path: label.clone(),
                source: Some(secret.clone()),
                attempt: 0,
                off: 0,
                len: 6,
            }),
            worker.handle(&Request::HashBlocks {
                path: label.clone(),
                source: Some(secret.clone()),
                which: Which::Final,
                partial_id: [0; 16],
                block: MIN_HASH_BLOCK_BYTES,
                len: 6,
                guard: None,
            }),
            worker.handle(&Request::FileHash {
                path: label.clone(),
                source: Some(secret.clone()),
                guard: None,
            }),
        ] {
            assert!(matches!(response, Response::Err(_)));
        }
        let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
            path: label,
            source: Some(secret),
            attempt: 0,
            len: 6,
        }]));
        assert!(
            matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(_)]))
        );
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"secret");
    }

    #[test]
    fn source_read_cache_keys_root_and_attempt() {
        let temporary = tempfile::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("same"), b"first").unwrap();
        fs::write(second.join("same"), b"other").unwrap();
        let (mut worker, selections, _control) =
            registered_source_worker(&[&first, &second], false);
        let first_source = selections[0].join(b"same").unwrap();
        let second_source = selections[1].join(b"same").unwrap();

        for (source, expected) in [
            (&first_source, &b"first"[..]),
            (&second_source, &b"other"[..]),
        ] {
            let response = worker.handle(&Request::ReadRange {
                path: b"same-parallel-label".to_vec(),
                source: Some(source.clone()),
                attempt: 0,
                off: 0,
                len: 5,
            });
            assert!(matches!(response, Response::Block { data, .. } if data == expected));
        }

        fs::rename(first.join("same"), first.join("old")).unwrap();
        fs::write(first.join("same"), b"newer").unwrap();
        let same_attempt = worker.handle(&Request::ReadRange {
            path: Vec::new(),
            source: Some(first_source.clone()),
            attempt: 0,
            off: 0,
            len: 5,
        });
        assert!(matches!(same_attempt, Response::Block { data, .. } if data == b"first"));
        let retry = worker.handle(&Request::ReadRange {
            path: Vec::new(),
            source: Some(first_source),
            attempt: 1,
            off: 0,
            len: 5,
        });
        assert!(matches!(retry, Response::Block { data, .. } if data == b"newer"));
    }

    #[test]
    fn confined_source_content_requires_exact_registered_references() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::write(&selected, b"selected").unwrap();
        fs::write(temporary.path().join("sibling"), b"sibling!").unwrap();
        let (mut worker, selections, _control) = registered_source_worker(&[&selected], false);
        let forged = RegisteredPath::new(selections[0].root(), b"sibling".to_vec()).unwrap();

        for source in [None, Some(forged)] {
            let response = worker.handle(&Request::ReadRange {
                path: selected.as_os_str().as_bytes().to_vec(),
                source,
                attempt: 0,
                off: 0,
                len: 8,
            });
            assert!(matches!(response, Response::Err(_)));
        }

        for response in [
            worker.handle(&Request::HashBlocks {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: None,
                which: Which::Final,
                partial_id: [0; 16],
                block: MIN_HASH_BLOCK_BYTES,
                len: 8,
                guard: None,
            }),
            worker.handle(&Request::FileHash {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: None,
                guard: None,
            }),
        ] {
            assert!(matches!(response, Response::Err(error) if error.contains("omitted")));
        }
        let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: None,
            attempt: 0,
            len: 8,
        }]));
        assert!(
            matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(error)] if error.contains("omitted")))
        );

        let response = worker.handle(&Request::HashBlocks {
            path: selected.as_os_str().as_bytes().to_vec(),
            source: Some(selections[0].clone()),
            which: Which::Partial,
            partial_id: [0; 16],
            block: MIN_HASH_BLOCK_BYTES,
            len: 8,
            guard: None,
        });
        assert!(
            matches!(response, Response::Err(error) if error.contains("only valid for the final source"))
        );
    }

    #[test]
    fn unconfined_source_content_uses_only_the_explicit_legacy_path() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let sibling = temporary.path().join("sibling");
        fs::write(&selected, b"selected").unwrap();
        fs::write(&sibling, b"legacy!!").unwrap();
        let (mut worker, _, _control) = registered_source_worker(&[&selected], true);
        let response = worker.handle(&Request::ReadRange {
            path: sibling.as_os_str().as_bytes().to_vec(),
            source: None,
            attempt: 0,
            off: 0,
            len: 8,
        });
        assert!(matches!(response, Response::Block { data, .. } if data == b"legacy!!"));

        let response = worker.handle(&Request::HashBlocks {
            path: sibling.as_os_str().as_bytes().to_vec(),
            source: None,
            which: Which::Final,
            partial_id: [0; 16],
            block: MIN_HASH_BLOCK_BYTES,
            len: 8,
            guard: None,
        });
        assert!(
            matches!(response, Response::Hashes(hashes) if hashes == vec![content_digest(b"legacy!!")])
        );
        let response = worker.handle(&Request::FileHash {
            path: sibling.as_os_str().as_bytes().to_vec(),
            source: None,
            guard: None,
        });
        assert!(
            matches!(response, Response::FileHash { size: 8, hash } if hash == content_digest(b"legacy!!"))
        );
    }

    #[test]
    fn destination_worker_rejects_source_only_content_requests() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("marker"), b"marker").unwrap();
        let mut worker = FsOps::new();
        worker.destination_root = Some(Arc::new(Root::open(temporary.path()).unwrap()));
        worker.destination_prefix = Some(b".".to_vec());

        let response = worker.handle(&Request::ReadRange {
            path: b"marker".to_vec(),
            source: None,
            attempt: 0,
            off: 0,
            len: 6,
        });
        assert!(matches!(response, Response::Err(error) if error.contains("destination worker")));
        let response = worker.handle(&Request::ReadSmallBatch(vec![SmallRead {
            path: b"marker".to_vec(),
            source: None,
            attempt: 0,
            len: 6,
        }]));
        assert!(
            matches!(response, Response::SmallBlocks(blocks) if matches!(&blocks[..], [Err(error)] if error.contains("destination worker")))
        );
    }

    #[test]
    fn source_legacy_stat_requires_explicit_unconfined_registration() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let sibling = temporary.path().join("sibling");
        fs::write(&selected, b"selected").unwrap();
        fs::write(&sibling, b"sibling").unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: true,
            shared_workers: 0,
            independent_claim_workers: 0,
        });
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        let mut worker = FsOps::with_descriptor_session(session);
        worker.initialize_sources(&roots).unwrap();
        let response = worker.handle(&Request::StatMany {
            paths: vec![sibling.as_os_str().as_bytes().to_vec()],
            sources: None,
            follow: false,
            guard: None,
        });
        assert!(
            matches!(response, Response::Stats(stats) if stats.len() == 1 && stats[0].is_some())
        );
    }

    #[test]
    fn source_descriptor_budget_accounts_for_registry_control_and_workers() {
        assert_eq!(SOURCE_SHARED_WORKER_FD_RESERVE, 16 + 5 + 1);
        assert_eq!(
            source_descriptor_requirement(7, 4, 3, 2).unwrap(),
            7 + SOURCE_FD_RESERVE + 2 * 4 * 5 + SOURCE_SHARED_WORKER_FD_RESERVE * 3 + 3 * 2
        );
        assert!(source_descriptor_requirement(0, usize::MAX, usize::MAX, usize::MAX).is_err());
    }

    #[test]
    fn live_descriptor_snapshot_includes_this_process() {
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
            0
        );
        if limits.rlim_cur != libc::RLIM_INFINITY {
            assert!(current_open_descriptor_count(limits.rlim_cur).unwrap() >= 3);
        }
    }
}
