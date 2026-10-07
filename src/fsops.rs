//! Local filesystem operations. Used directly by the local endpoint and
//! by `syq --server` for remote endpoints, so both sides behave identically.

use crate::descriptor_broker::{
    acquire_descriptor, DescriptorSessionSlot, DescriptorTicket, RegisteredRootId,
    DEFAULT_MAX_ROOTS,
};
use crate::proto::*;
use crate::rooted::{
    open_operator_directory_at, read_open_symlink, root_metadata_from_std, OperatorFinalComponent,
    OperatorResolver, PinnedPath, RelativePath, Root, RootIdentity, RootMetadata,
};
use crate::sys::{
    absent_or_nondirectory, COMMON_NAME_MAX, MODE_BLOCK, MODE_CHAR, MODE_DIRECTORY, MODE_FIFO,
    MODE_REGULAR, MODE_SOCKET, MODE_SYMLINK, NAME_MAX_CACHE_CAP,
};
use crate::write_gate::CachedFile;
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Write;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

mod apply;
mod basis_copy;
#[cfg(target_os = "linux")]
mod btrfs;
mod entry;
mod limits;
mod operator;
mod partial;
mod paths;
mod receiver_mode;
mod sidecars;
mod small_batch;

pub(crate) use apply::*;
pub(crate) use entry::*;
pub(crate) use limits::*;
pub(crate) use operator::*;
pub(crate) use partial::*;
pub(crate) use paths::*;
use sidecars::Sidecar;
pub(crate) use sidecars::{sweep as sweep_sidecars, track as track_sidecars, Swept};

/// Compare at the decimal precision suggested by the destination timestamp.
/// Trailing zeros may reflect either filesystem truncation or a round timestamp;
/// this is the size/mtime shortcut, not a content verification.
pub(crate) fn destination_fraction_matches(source: u32, destination: u32) -> bool {
    if destination == 0 {
        return true;
    }
    let mut precision = 1;
    let mut fraction = destination;
    while fraction.is_multiple_of(10) {
        precision *= 10;
        fraction /= 10;
    }
    source / precision == destination / precision
}

pub const PARTIAL_MARKER: &str = ".syq-tmp.";
pub(crate) const FD_CACHE_MAX: usize = 16;
const PARTIAL_DIRECTORY_CACHE_MAX: usize = 64;
const PARTIAL_CANDIDATES_MAX: usize = 256;
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
/// A destination mutation names a path only relative to an authority: a
/// registered destination root or a receiver's guard.
const UNROOTED_MUTATION: &str = "destination mutation before a destination root was registered";
/// The refusal of any request but the open streamed patch's data and end.
pub(crate) const OPEN_PATCH_STREAM: &str =
    "only the open streamed patch's data and end are valid until it ends";

#[cfg(debug_assertions)]
pub(crate) fn record_test_event(variable: &str, event: std::fmt::Arguments<'_>) -> io::Result<()> {
    use std::io::Write;
    if let Some(path) = std::env::var_os(variable) {
        // Format the whole record before writing so concurrent event fields
        // are not emitted as separate writes.
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(format!("{event}\n").as_bytes())?;
    }
    Ok(())
}

/// Tests simulate data corrupted in transit: the first received payload whose
/// check runs after `SYQ_TEST_CORRUPT_PAYLOAD_ONCE` names a missing file fails
/// its check, and that file is created so later payloads pass.
#[cfg(debug_assertions)]
fn test_corrupt_payload_once() -> bool {
    std::env::var_os("SYQ_TEST_CORRUPT_PAYLOAD_ONCE").is_some_and(|marker| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)
            .is_ok()
    })
}

#[cfg(any(test, debug_assertions))]
pub(crate) fn test_race_barrier(ready_env: &str, continue_env: &str, label: &str) -> Result<()> {
    let ready = std::env::var_os(ready_env);
    let continuation = std::env::var_os(continue_env);
    if continuation.is_some() && ready.is_none() {
        bail!("{continue_env} requires {ready_env}");
    }
    if let Some(ready) = ready {
        fs::write(&ready, b"ready")
            .with_context(|| format!("write {label} signal {}", Path::new(&ready).display()))?;
    }
    if let Some(continuation) = continuation {
        // Some race tests finish a competing copy before releasing this worker.
        // Leave room for that work under suite load, especially on macOS. This
        // is a deadlock safety bound, not an assertion about transfer speed.
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(60);
        let mut next_progress = started + std::time::Duration::from_secs(5);
        loop {
            match File::open(&continuation) {
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "open {label} continuation {}",
                            Path::new(&continuation).display()
                        )
                    })
                }
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "timed out waiting for {label} continuation {}",
                    Path::new(&continuation).display()
                );
            }
            if std::time::Instant::now() >= next_progress {
                eprintln!(
                    "syq: waiting for {label} continuation {}",
                    Path::new(&continuation).display()
                );
                next_progress += std::time::Duration::from_secs(5);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) type AccessObserver = Box<dyn FnMut(&File)>;

#[cfg(test)]
thread_local! {
    /// Runs after each change this thread makes to who may open a file:
    /// its owner, its mode or an ACL.
    pub(crate) static ACCESS_CHANGED: std::cell::RefCell<Option<AccessObserver>> =
        const { std::cell::RefCell::new(None) };
}

/// Let a test see `file` after a change to its owner, its mode or an ACL.
#[inline]
pub(crate) fn access_changed(file: &File) {
    #[cfg(test)]
    ACCESS_CHANGED.with(|observer| {
        if let Some(observer) = observer.borrow_mut().as_mut() {
            observer(file);
        }
    });
    let _ = file;
}

#[cfg(test)]
pub(crate) fn content_digest(data: &[u8]) -> ContentDigest {
    *blake3::hash(data).as_bytes()
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FileSystemTraits {
    is_nfs: bool,
    /// None on other filesystems; btrfs also checks each file's inherited flags.
    btrfs_compression: Option<btrfs::Compression>,
    /// NFS, SMB, Ceph, or a FUSE mount such as sshfs: each operation waits
    /// for a network round trip.
    network: bool,
    synchronous: bool,
    measured_local_source: bool,
    local_userspace_copy: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum FileSystemKey {
    Mount(u64),
    Device(u64),
}

// Whole-file copying uses Linux offload or macOS cloning.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct CopyLocalPolicy<'a> {
    inplace: bool,
    replace_partial: bool,
    allow_sequential_nfs_fallback: bool,
    allow_sequential_local_fallback: bool,
    progress: &'a mut dyn FnMut(u64) -> Result<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) enum CopyLocalOutcome {
    Copied,
    Unsupported,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn discard_rooted_copy_partial(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    expected_dev: u64,
    expected_ino: u64,
) -> Result<()> {
    #[cfg(debug_assertions)]
    record_test_event("SYQ_TEST_COPY_LOCAL_DISCARDS", format_args!("discard"))?;
    match root.metadata_optional(relative)? {
        Some(current)
            if is_safe_rooted_partial(current)
                && current.dev == expected_dev
                && current.ino == expected_ino =>
        {
            root.unlink(relative)
                .with_context(|| format!("remove {}", label.display()))?;
            sidecars::forget((expected_dev, expected_ino));
        }
        Some(_) | None => {}
    }
    Ok(())
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
fn hold_copy_local_before_destination_open_for_test() -> Result<()> {
    test_race_barrier(
        "SYQ_TEST_COPY_LOCAL_READY_FILE",
        "SYQ_TEST_COPY_LOCAL_OPEN_CONTINUE_FILE",
        "local-copy destination open",
    )
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
fn reject_copy_source_claim_for_test() -> Result<()> {
    if std::env::var_os("SYQ_TEST_REJECT_COPY_SOURCES").is_some() {
        bail!("test rejected unnecessary copy-source capabilities");
    }
    Ok(())
}

/// No pathname re-resolution, subprocess or additional remote round trip.
/// f_fsid is an OS/filesystem hint, not a globally unique storage identifier.
fn filesystem_hint(file: &File) -> Option<FilesystemHint> {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: the syscall initializes stats; zero initialization also covers padding.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    let fsid = unsafe {
        std::slice::from_raw_parts(
            (&stats.f_fsid as *const libc::fsid_t).cast::<u8>(),
            std::mem::size_of_val(&stats.f_fsid),
        )
    };
    if fsid.iter().all(|b| *b == 0) {
        return None;
    }
    #[cfg(target_os = "linux")]
    let kind = match stats.f_type as u64 {
        0xef53 => "ext",
        0x58465342 => "xfs",
        0x01021994 => "tmpfs",
        0x6969 => "nfs",
        0x9123683e => "btrfs",
        0x794c7630 => "overlay",
        _ => "other",
    }
    .to_string();
    #[cfg(target_os = "macos")]
    let kind = String::from_utf8_lossy(
        &stats
            .f_fstypename
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as u8)
            .collect::<Vec<_>>(),
    )
    .into_owned();
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind.as_bytes());
    hasher.update(fsid);
    Some(FilesystemHint {
        identity: hasher.finalize().to_hex().to_string(),
        kind,
        device: file.metadata().ok()?.dev(),
    })
}

/// Filesystems where each operation can cost a network round trip. Local
/// disk and memory filesystems (ext4, XFS, Btrfs, ZFS, tmpfs) are not.
#[cfg(target_os = "linux")]
fn network_file_system_type(file_system_type: u32) -> bool {
    [
        libc::NFS_SUPER_MAGIC as u32,
        libc::FUSE_SUPER_MAGIC as u32,
        libc::SMB_SUPER_MAGIC as u32,
        0xfe53_4d42, // SMB2
        0xff53_4d42, // CIFS
        0x00c3_6400, // Ceph
    ]
    .contains(&file_system_type)
}

#[cfg(target_os = "linux")]
fn inspect_file_system(file: &File, key: FileSystemKey) -> FileSystemTraits {
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
            btrfs_compression: (file_system_type == libc::BTRFS_SUPER_MAGIC as u32)
                .then(|| btrfs::Compression::for_mount(file, key)),
            network: network_file_system_type(file_system_type),
            synchronous,
            // Keep unknown and network-backed filesystems on adaptive ranges.
            // tmpfs also provides a real cross-filesystem control for this path.
            local_userspace_copy: matches!(
                file_system_type,
                t if t == libc::EXT4_SUPER_MAGIC as u32
                    || t == libc::XFS_SUPER_MAGIC as u32
                    || t == libc::TMPFS_MAGIC as u32
            ),
            // Preserve the independently measured ext-family/XFS -> NFS scope.
            measured_local_source: matches!(
                file_system_type,
                t if t == libc::EXT4_SUPER_MAGIC as u32
                    || t == libc::XFS_SUPER_MAGIC as u32
            ),
        }
    }
}

/// The mount `file` was opened through, on kernels that name mounts.
#[cfg(target_os = "linux")]
fn mount_id(file: &File) -> Option<u64> {
    let mut stat = std::mem::MaybeUninit::<libc::statx>::uninit();
    let result = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if result != 0 {
        return None;
    }
    let stat = unsafe { stat.assume_init() };
    (stat.stx_mask & libc::STATX_MNT_ID != 0).then_some(stat.stx_mnt_id)
}

#[cfg(target_os = "linux")]
fn file_system_key(file: &File, dev: u64) -> FileSystemKey {
    mount_id(file).map_or(FileSystemKey::Device(dev), FileSystemKey::Mount)
}

/// The filesystem of an opened file or directory, with its cached traits.
#[cfg(target_os = "linux")]
fn opened_file_system(file: &File) -> io::Result<(FileSystemKey, FileSystemTraits)> {
    let key = match mount_id(file) {
        Some(mount) => FileSystemKey::Mount(mount),
        None => FileSystemKey::Device(file.metadata()?.dev()),
    };
    Ok((key, file_system_traits(file, key)))
}

/// Physical preallocation would prevent these writes from being compressed.
#[cfg(target_os = "linux")]
pub(crate) fn uses_btrfs_compression(file: &File) -> bool {
    opened_file_system(file).is_ok_and(|(_, traits)| traits.uses_btrfs_compression(file))
}

#[cfg(target_os = "linux")]
impl FileSystemTraits {
    fn uses_btrfs_compression(self, file: &File) -> bool {
        self.btrfs_compression
            .is_some_and(|compression| compression.enabled_for(file))
    }
}

#[cfg(target_os = "linux")]
fn file_system_traits(file: &File, key: FileSystemKey) -> FileSystemTraits {
    static FILE_SYSTEMS: OnceLock<Mutex<HashMap<FileSystemKey, FileSystemTraits>>> =
        OnceLock::new();
    let file_systems = FILE_SYSTEMS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(traits) = file_systems.lock().unwrap().get(&key).copied() {
        return traits;
    }
    let traits = inspect_file_system(file, key);
    file_systems.lock().unwrap().insert(key, traits);
    traits
}

#[cfg(target_os = "linux")]
fn unsupported_copy_pairs() -> &'static Mutex<HashSet<(FileSystemKey, FileSystemKey)>> {
    static PAIRS: OnceLock<Mutex<HashSet<(FileSystemKey, FileSystemKey)>>> = OnceLock::new();
    PAIRS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Whether `file`, on device `dev`, lies on a network filesystem.
pub(crate) fn on_network_file_system(file: &File, dev: u64) -> bool {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_NETWORK_FILESYSTEM").is_some() {
        return true;
    }
    // Tests mount nothing: they name the one directory that counts as a
    // network filesystem mounted where it is.
    #[cfg(all(debug_assertions, target_os = "linux"))]
    if let Some(directory) = std::env::var_os("SYQ_TEST_NETWORK_DIRECTORY") {
        if fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .is_ok_and(|path| path.as_os_str() == directory)
        {
            return true;
        }
    }
    #[cfg(target_os = "linux")]
    {
        file_system_traits(file, file_system_key(file, dev)).network
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (file, dev);
        false
    }
}

/// Whether a test names a directory to treat as a network filesystem mounted
/// on the same device (`SYQ_TEST_NETWORK_DIRECTORY`).
pub(crate) fn network_directory_named_for_test() -> bool {
    cfg!(all(debug_assertions, target_os = "linux"))
        && std::env::var_os("SYQ_TEST_NETWORK_DIRECTORY").is_some()
}

/// One file of a small copy, staged but not yet published.
struct StagedSmallFile {
    root: Arc<Root>,
    partial: RelativePath,
    target: RelativePath,
    file: File,
}

/// The single directory entry a small-copy file names beneath the request
/// prefix. Nested paths are the ordinary engine's business.
fn small_copy_leaf<'a>(request_prefix: &[u8], path: &'a [u8]) -> Result<&'a [u8]> {
    let mut prefix_len = request_prefix.len();
    while prefix_len > 1 && request_prefix[prefix_len - 1] == b'/' {
        prefix_len -= 1;
    }
    let leaf = match path.strip_prefix(&request_prefix[..prefix_len]) {
        Some(rest) if prefix_len == 0 || &request_prefix[..prefix_len] == b"/" => rest,
        Some(rest) if rest.first() == Some(&b'/') => &rest[1..],
        _ => bail!("small copy path is not beneath the request prefix"),
    };
    if leaf.is_empty() || leaf == b"." || leaf == b".." || leaf.contains(&b'/') || leaf.contains(&0)
    {
        bail!("small copy path must name one entry beneath the destination directory");
    }
    Ok(leaf)
}

fn errstr(e: &anyhow::Error) -> String {
    format!("{e:#}")
}

pub(crate) fn wire_error(error: &anyhow::Error) -> WireError {
    if let Some(wire) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<WireError>())
    {
        return WireError {
            message: errstr(error),
            io_kind: wire.io_kind,
            raw_os_error: wire.raw_os_error,
        };
    }
    let io_error = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>());
    WireError {
        message: errstr(error),
        io_kind: io_error.map(wire_io_kind),
        raw_os_error: io_error.and_then(io::Error::raw_os_error),
    }
}

fn wire_io_kind(error: &io::Error) -> WireIoKind {
    match error.raw_os_error() {
        Some(libc::ENOSPC) => WireIoKind::NoSpace,
        Some(libc::EDQUOT) => WireIoKind::QuotaExceeded,
        Some(libc::EROFS) => WireIoKind::ReadOnly,
        _ => match error.kind() {
            io::ErrorKind::NotFound => WireIoKind::NotFound,
            io::ErrorKind::PermissionDenied => WireIoKind::PermissionDenied,
            io::ErrorKind::AlreadyExists => WireIoKind::AlreadyExists,
            io::ErrorKind::InvalidInput => WireIoKind::InvalidInput,
            _ => WireIoKind::Other,
        },
    }
}

fn statvfs_counter<T: Into<u64>>(value: T) -> u64 {
    value.into()
}

/// Widen only an owned existing directory and report an actual change. The
/// opened metadata handle pins the inode; a supplied identity prevents a stale
/// plan from chmodding a replacement. No group/other bits are added.
pub(crate) fn widen_directory(
    root: &Root,
    path: &RelativePath,
    condition: TargetCondition,
    label: &Path,
) -> Result<Option<crate::proto::DirectoryMode>> {
    let metadata = root.metadata(path)?;
    apply::require_rooted_condition(metadata, condition, label)?;
    anyhow::ensure!(metadata.is_dir(), "{} is not a directory", label.display());
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || uid != metadata.uid || metadata.mode & 0o700 == 0o700 {
        return Ok(None);
    }
    let directory = root.open_metadata(path)?;
    apply::require_rooted_metadata(&directory, metadata, label)?;
    set_mode_handle(&directory, metadata.mode | 0o700)?;
    Ok(Some(crate::proto::DirectoryMode {
        mode: metadata.mode & 0o7777,
        dev: metadata.dev,
        ino: metadata.ino,
    }))
}

pub(crate) fn restore_directory_mode(
    root: &Root,
    path: &RelativePath,
    saved: crate::proto::DirectoryMode,
    label: &Path,
) -> Result<()> {
    let directory = root.open_metadata(path)?;
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.is_dir() && (metadata.dev(), metadata.ino()) == (saved.dev, saved.ino),
        "directory {} changed before restoring permissions",
        label.display()
    );
    set_mode_handle(&directory, saved.mode)
}

/// Diagnose only a failed operation; the successful path does no extra stats.
/// Search is needed on ancestors, and `parent_access` on the containing directory.
pub(crate) fn directory_permission_hint(
    root: &Root,
    path: &RelativePath,
    parent_access: u32,
) -> Option<String> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return None;
    }
    let bytes = path.to_path_buf().into_os_string().into_vec();
    let parent_end = bytes.iter().rposition(|&c| c == b'/').unwrap_or(0);
    let mut prefixes = vec![0];
    prefixes.extend(
        bytes[..parent_end]
            .iter()
            .enumerate()
            .filter_map(|(i, &c)| (c == b'/').then_some(i)),
    );
    if parent_end != 0 {
        prefixes.push(parent_end);
    }
    for end in prefixes {
        let relative = RelativePath::new(&bytes[..end]).ok()?;
        let metadata = root.metadata(&relative).ok()?;
        let required = if end == parent_end {
            parent_access
        } else {
            0o100
        };
        if metadata.is_dir() && metadata.uid == uid && metadata.mode & required != required {
            return Some(
                "an owned destination directory lacks the required owner permissions".into(),
            );
        }
    }
    None
}

fn is_superuser() -> bool {
    unsafe { libc::geteuid() == 0 }
}

struct PreparedSmallCopy {
    request: SmallCopyRequest,
    anchor: DirectoryAnchor,
    root: Arc<Root>,
    destinations: Vec<Option<libc::stat>>,
    permitted: Vec<bool>,
    unchanged: Vec<bool>,
}

pub struct FsOps {
    deletions: Option<crate::deletion::Batch>,
    prepared_small_copy: Option<PreparedSmallCopy>,
    /// The patch whose new data is arriving in pieces, between `PatchBegin`
    /// and `PatchEnd`.
    patch_stream: Option<Box<small_batch::PatchStream>>,
    inode_preservation: crate::inode_metadata::Selection,
    sparse: bool,
    descriptor_copy: crate::descriptor_copy::Session,
    stream_worker: Option<crate::descriptor_copy::FileWorker>,
    stream_ticket: Option<crate::descriptor_broker::DescriptorTicket>,
    hash_policy: crate::hashing::HashPolicy,
    pub(crate) observations: Arc<crate::transfer_observations::Registry>,
    operation: Arc<crate::transfer_observations::Actor>,
    #[cfg(target_os = "linux")]
    read_ahead: crate::read_ahead::ReadAhead,
    fds: HashMap<FdKey, CachedFile>,
    fd_order: Vec<FdKey>,
    /// One final-file descriptor retained between the hash response and the
    /// controller's decision to repair or accept that exact inode.
    held_basis: Option<HeldBasis>,
    comparison_window: Option<ComparisonWindow>,
    partial_candidates: HashMap<FileLocation, HashMap<PathBytes, Vec<PathBytes>>>,
    partial_directory_order: VecDeque<FileLocation>,
    /// Devices this connection has probed for whether a new file can be
    /// narrowed below the mode it came out with (`note_created_mode`).
    fixed_wide_mode_devices: HashMap<u64, bool>,
    /// Directories this connection created private or widened, for the
    /// modes it chooses for them later.
    receiver_directories: receiver_mode::ReceiverDirectories,
    /// A new directory whose mode lacks owner access, as `syq rsync` creates
    /// one, gets that mode only after its contents.
    narrow_new_directories: bool,
    /// The permission bits each directory's default ACL lets new files
    /// have, by root and directory, read once per connection.
    creation_permissions: Mutex<receiver_mode::CreationPermissions>,
    operator_selection: Option<OperatorDirectorySelection>,
    descriptor_session: DescriptorSessionSlot,
    source_roots: HashMap<RegisteredRootId, SourceRootHandle>,
    allow_unconfined_source_paths: bool,
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<PathBytes>,
    /// Whether each destination root, and each directory directly beneath
    /// one, lies on a network filesystem; the root itself has an empty name.
    network_entries: HashMap<(RootIdentity, Vec<u8>), bool>,
    /// Names asked about so far in each directory of the destination, to
    /// decide when one is worth listing before its stats; `None` once it has
    /// been listed or turned out not to be on NFS.
    #[cfg(target_os = "linux")]
    listing_requests: HashMap<PathBytes, Option<usize>>,
}

struct ComparisonWindow {
    location: FileLocation,
    copy_id: CopyId,
    attempt: u32,
    blocks: Vec<(u64, Vec<u8>)>,
    sparse: bool,
}

struct HeldBasis {
    location: FileLocation,
    label: PathBuf,
    copy_id: CopyId,
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
fn open_registered_source(target: &RegisteredSourceTarget, noatime: bool) -> Result<File> {
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
    crate::inode_metadata::prepare_read(&file, noatime);
    Ok(file)
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum FileLocation {
    Path(PathBuf),
    /// Keep distinct source capabilities distinct even when two descriptors
    /// happen to report the same device/inode through different mount views.
    RegisteredSource {
        root: RegisteredRootId,
        relative: PathBytes,
    },
    Rooted {
        root: RootIdentity,
        relative: RelativePath,
    },
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct FdKey {
    location: FileLocation,
    /// Source files and partials get a fresh cache entry after a source-change
    /// retry. An old descriptor may point at an inode that was renamed away.
    attempt: u32,
    /// Keep a validated sidecar from sharing an unchecked cache entry.
    private: bool,
}

struct PartialTarget<'a> {
    path: &'a [u8],
    id: &'a CopyId,
    guard: Option<&'a ContainerGuard>,
}

struct PrepareOptions {
    size: u64,
    inplace: bool,
    mode: u32,
    attempt: u32,
    create_if_missing: bool,
    /// What the sender's scan found at the path.
    scanned: ScannedDestination,
}

struct HashOptions {
    off: u64,
    which: Which,
    block: u64,
    len: u64,
    attempt: u32,
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
    pub(crate) fn set_hash_policy(&mut self, policy: crate::hashing::HashPolicy) {
        self.hash_policy = policy;
    }

    fn observed_payload_hash(&self, bytes: &[u8]) -> ContentDigest {
        let _hash = self
            .operation
            .span(crate::transfer_observations::Stage::Hashing);
        #[cfg(debug_assertions)]
        if test_corrupt_payload_once() {
            return self
                .hash_policy
                .payload_algorithm()
                .hash(&[bytes, b"corrupted"].concat());
        }
        self.hash_policy.payload_algorithm().hash(bytes)
    }

    pub fn new() -> Self {
        Self::with_descriptor_session(DescriptorSessionSlot::default())
    }

    pub(crate) fn with_descriptor_session(descriptor_session: DescriptorSessionSlot) -> Self {
        let observations = Arc::new(crate::transfer_observations::Registry::default());
        let operation = observations.actor("filesystem");
        FsOps {
            deletions: Default::default(),
            inode_preservation: Default::default(),
            sparse: false,
            descriptor_copy: Default::default(),
            stream_worker: None,
            stream_ticket: None,
            hash_policy: crate::hashing::HashPolicy {
                algorithm: crate::hashing::HashAlgorithm::Blake3,
                transfer_integrity: true,
                transfer_hash_type: None,
            },
            observations: observations.clone(),
            operation: operation.clone(),
            #[cfg(target_os = "linux")]
            read_ahead: crate::read_ahead::ReadAhead::observed(observations, operation),
            fds: HashMap::new(),
            fd_order: Vec::new(),
            held_basis: None,
            comparison_window: None,
            partial_candidates: HashMap::new(),
            partial_directory_order: VecDeque::new(),
            fixed_wide_mode_devices: HashMap::new(),
            receiver_directories: Default::default(),
            narrow_new_directories: false,
            creation_permissions: Default::default(),
            prepared_small_copy: None,
            patch_stream: None,
            operator_selection: None,
            descriptor_session,
            source_roots: HashMap::new(),
            allow_unconfined_source_paths: false,
            destination_root: None,
            destination_prefix: None,
            network_entries: HashMap::new(),
            #[cfg(target_os = "linux")]
            listing_requests: HashMap::new(),
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

    fn check_operator_directory_ancestry(
        &self,
        checks: &[DirectoryAncestryCheck],
    ) -> Result<Vec<Vec<DirectoryRelation>>> {
        if checks.len() > DEFAULT_MAX_ROOTS {
            bail!(
                "destination ancestry source count ({}) exceeds the endpoint-session limit ({DEFAULT_MAX_ROOTS})",
                checks.len()
            );
        }
        let registered_selection;
        let selection = if let Some(selection) = &self.operator_selection {
            selection
        } else {
            let root = self
                .destination_root
                .as_ref()
                .context("destination directory was not checked on this connection")?;
            registered_selection = OperatorDirectorySelection {
                path: Vec::new(),
                directory: root.open_directory(&RelativePath::new(b"")?)?,
                missing: VecDeque::new(),
            };
            &registered_selection
        };
        checks
            .iter()
            .map(|check| {
                if !check.source_root.is_directory() {
                    bail!("destination ancestry requires a source directory ticket");
                }
                let source = acquire_descriptor(&check.source_root)
                    .context("claim exact source directory for destination ancestry")?;
                check
                    .suffixes
                    .iter()
                    .map(|suffix| {
                        let relation = selection.relation_to_source(&source, suffix)?;
                        Ok(if check.source_is_directory {
                            relation
                        } else {
                            match relation {
                                DirectoryRelation::Same => DirectoryRelation::Ancestor,
                                DirectoryRelation::Descendant => DirectoryRelation::Separate,
                                other => other,
                            }
                        })
                    })
                    .collect()
            })
            .collect()
    }

    fn create_operator_directory(
        &mut self,
        mode: u32,
        require_absent: bool,
    ) -> Result<DirectoryAnchor> {
        // It has owner access while it is filled, as any new directory has.
        let anchor = self
            .operator_selection
            .as_mut()
            .context("no checked destination directory to create")?
            .create_missing(mode | 0o700, require_absent)?;
        // A destination created private is opened once its metadata is set,
        // and under `syq rsync` one whose mode lacks owner access is narrowed
        // once it is filled.
        let narrowing = self.narrow_new_directories && mode & 0o700 != 0o700;
        if mode & 0o7777 == 0o700 || narrowing {
            let created = self
                .operator_selection
                .as_ref()
                .context("no checked destination directory")?
                .directory
                .metadata()?;
            self.receiver_directories
                .created((anchor.dev, anchor.ino), created.mode(), narrowing);
        }
        Ok(anchor)
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
        test_race_barrier(
            "SYQ_TEST_DESTINATION_ANCHORED_FILE",
            "SYQ_TEST_DESTINATION_ANCHOR_CONTINUE_FILE",
            "destination-anchor-ready",
        )?;
        Ok(ticket)
    }

    /// Configure hashing and retain the destination and metadata observations.
    /// Rejected and quick-checked entries never need source payload reads.
    /// Unsupported target types decline before installing session state.
    #[allow(clippy::unnecessary_cast)] // libc stat field widths differ on Darwin.
    fn prepare_small_files(&mut self, request: &SmallCopyRequest) -> Result<Response> {
        if self.operator_selection.is_some()
            || self.destination_root.is_some()
            || self.destination_prefix.is_some()
            || !self.source_roots.is_empty()
        {
            bail!("small copy is valid only on a fresh control session");
        }
        if request.files.is_empty() || request.files.len() > SMALL_COPY_MAX_FILES {
            bail!(
                "small copy carries {} files; the limit is {SMALL_COPY_MAX_FILES}",
                request.files.len()
            );
        }
        let mut total = 0u64;
        let mut names: Vec<&[u8]> = Vec::with_capacity(request.files.len());
        for file in &request.files {
            let bytes = file.size;
            if bytes > SMALL_COPY_MAX_FILE_BYTES {
                bail!("small copy file exceeds {SMALL_COPY_MAX_FILE_BYTES} bytes");
            }
            total = total
                .checked_add(bytes)
                .filter(|total| *total <= SMALL_COPY_MAX_TOTAL_BYTES)
                .context("small copy exceeds its total byte limit")?;
            let name = small_copy_leaf(&request.request_prefix, &file.path)?;
            if names.contains(&name) {
                bail!("small copy names one destination twice");
            }
            names.push(name);
        }
        self.hash_policy = request.hash_policy;
        let condition = request
            .copy_if
            .as_ref()
            .map(|(text, _)| {
                crate::expression::Expression::compile(text, true).context("--copy-if")
            })
            .transpose()?;

        let (selection, anchor) =
            select_operator_directory(&request.directory, false, request.symlink_policy)?;
        let anchor = anchor.context("destination directory is missing")?;
        // Inspect through the retained directory before installing state,
        // so unsupported type replacements can use the general engine.
        let mut destinations = Vec::with_capacity(names.len());
        for name in &names {
            match operator_lstat_at(&selection.directory, name) {
                Ok(stat) if stat.st_mode & libc::S_IFMT == libc::S_IFREG => {
                    destinations.push(Some(stat));
                }
                Ok(_) => {
                    return Ok(Response::SmallFilesCopied(SmallCopyResponse {
                        anchor,
                        outcome: SmallCopyOutcome::UnsupportedTarget,
                    }))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => destinations.push(None),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "inspect destination entry {}",
                            String::from_utf8_lossy(name)
                        )
                    })
                }
            }
        }
        // Evaluate against the same observations used for comparison, before
        // staging any content or repairing any destination metadata.
        let permitted: Vec<bool> = request
            .files
            .iter()
            .zip(&destinations)
            .zip(&names)
            .map(|((file, stat), name)| -> Result<bool> {
                let Some(expression) = &condition else {
                    return Ok(true);
                };
                let (source, source_path) = file
                    .expression_source
                    .as_ref()
                    .context("small copy condition requires source metadata")?;
                let destination = stat
                    .as_ref()
                    .map(|stat| crate::expression::File {
                        exists: true,
                        kind: Some(Kind::File),
                        size: Some(stat.st_size as u64),
                        mtime: Some((stat.st_mtime as i64, stat.st_mtime_nsec as u32)),
                        ctime: Some((stat.st_ctime as i64, stat.st_ctime_nsec as u32)),
                        s3_last_modified: None,
                        mode: Some(stat.st_mode as u32 & 0o7777),
                        uid: Some(stat.st_uid),
                        gid: Some(stat.st_gid),
                        device: Some(stat.st_dev as u64),
                        inode: Some(stat.st_ino as u64),
                        nlink: Some(stat.st_nlink as u64),
                        link_target: None,
                    })
                    .unwrap_or_default();
                expression
                    .evaluate(
                        source,
                        source_path,
                        &destination,
                        name,
                        request.copy_if.as_ref().unwrap().1,
                    )
                    .context("--copy-if")
            })
            .collect::<Result<_>>()?;
        // This fused path serves native copies: share the planner's inferred
        // destination precision so dispatch does not change the skip decision.
        let unchanged: Vec<bool> = request
            .files
            .iter()
            .zip(&destinations)
            .zip(&permitted)
            .map(|((file, stat), permitted)| {
                !permitted
                    || stat.as_ref().is_some_and(|stat| {
                        request.flags & flags::TIMES != 0
                            && stat.st_size as u64 == file.size
                            && stat.st_mtime == file.meta.mtime
                            && destination_fraction_matches(
                                file.meta.mtime_nsec,
                                stat.st_mtime_nsec as u32,
                            )
                    })
            })
            .collect();
        if request.if_exists == crate::cli::IfExists::Error
            && destinations
                .iter()
                .zip(&permitted)
                .any(|(entry, permitted)| *permitted && entry.is_some())
        {
            return Ok(Response::SmallFilesCopied(SmallCopyResponse {
                anchor,
                outcome: SmallCopyOutcome::UnsupportedTarget,
            }));
        }
        // The offer contains whole-file payloads. Only existing files that
        // need content work can benefit from multi-block reuse; keep new
        // files, rejected entries and quick-check matches on this path.
        if request.reuse_block_size.is_some_and(|block| {
            request.files.iter().zip(&destinations).zip(&unchanged).any(
                |((file, destination), unchanged)| {
                    destination.is_some() && !unchanged && file.size > block
                },
            )
        }) {
            return Ok(Response::SmallFilesCopied(SmallCopyResponse {
                anchor,
                outcome: SmallCopyOutcome::NeedsBlockReuse,
            }));
        }
        let ticket = self.descriptor_session.register(selection.directory)?;
        let directory = self.descriptor_session.acquire(&ticket)?;
        self.install_destination(directory, &request.request_prefix)?;

        let needed = unchanged
            .iter()
            .map(|unchanged| !unchanged)
            .collect::<Vec<_>>();
        self.prepared_small_copy = Some(PreparedSmallCopy {
            request: request.clone(),
            anchor,
            root: self.destination_root.as_ref().unwrap().clone(),
            destinations,
            permitted,
            unchanged,
        });
        if needed.iter().any(|needed| *needed) {
            Ok(Response::SmallFilesPrepared(needed))
        } else {
            // An all-rejected/quick-checked batch completes in this first turn.
            self.copy_small_files(&[])
        }
    }

    #[allow(clippy::unnecessary_cast)] // libc stat field widths differ on Darwin.
    fn copy_small_files(&mut self, payloads: &[SmallCopyPayload]) -> Result<Response> {
        let PreparedSmallCopy {
            request,
            anchor,
            root,
            destinations,
            permitted,
            mut unchanged,
        } = self
            .prepared_small_copy
            .take()
            .context("small copy was not prepared")?;
        if !self
            .destination_root
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &root))
            || self.hash_policy != request.hash_policy
        {
            bail!("small copy session changed after preparation");
        }
        let copy_id = request.identity.copy_id;
        let mut data: Vec<Option<&[u8]>> = vec![None; request.files.len()];
        for payload in payloads {
            let index = payload.index as usize;
            let file = request
                .files
                .get(index)
                .context("small copy payload index is out of bounds")?;
            if unchanged[index] || data[index].is_some() {
                bail!("unexpected or duplicate small copy payload");
            }
            if payload.data.len() as u64 != file.size {
                bail!("small copy payload size differs from its offer");
            }
            if self.hash_policy.transfer_integrity
                && self.observed_payload_hash(&payload.data) != payload.hash
            {
                bail!("block hash mismatch on receive");
            }
            data[index] = Some(&payload.data);
        }
        if unchanged
            .iter()
            .zip(&data)
            .any(|(unchanged, data)| !unchanged && data.is_none())
        {
            bail!("small copy is missing a requested payload");
        }
        // Existing files with different mtimes may still have identical
        // content. Compare one bounded block locally, as the worker does,
        // without another data connection or a rewrite of the destination.
        let mut matched_content: Vec<Option<(RootedTarget, File)>> =
            (0..request.files.len()).map(|_| None).collect();
        for (i, file) in request.files.iter().enumerate() {
            if (request.reuse_block_size.is_none()
                && request.if_exists != crate::cli::IfExists::ErrorIfDifferent)
                || unchanged[i]
                || destinations[i]
                    .as_ref()
                    .is_none_or(|stat| stat.st_size as u64 != file.size)
            {
                continue;
            }
            let check = (|| -> Result<Option<(RootedTarget, File)>> {
                let path = self.destination_relative(&file.path)?;
                let target = self
                    .rooted_destination_target(&path, None)?
                    .context("small copy requires a destination root")?;
                let mut opened = target.root.open_regular_read(&target.relative)?;
                let stat = destinations[i].as_ref().unwrap();
                require_open_target(
                    &opened,
                    &target.label,
                    TargetCondition::Matches {
                        dev: stat.st_dev as u64,
                        ino: stat.st_ino as u64,
                    },
                )?;
                let mut bytes = Vec::with_capacity(file.size as usize);
                Read::by_ref(&mut opened)
                    .take(file.size + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 != file.size {
                    return Ok(None);
                }
                Ok((bytes.as_slice() == data[i].unwrap()).then_some((target, opened)))
            })();
            match check {
                Ok(Some(held)) => {
                    unchanged[i] = true;
                    matched_content[i] = Some(held);
                }
                Ok(None) => {}
                Err(error) => {
                    return Ok(Response::SmallFilesCopied(SmallCopyResponse {
                        anchor,
                        outcome: SmallCopyOutcome::StagingFailed(wire_error(&error)),
                    }))
                }
            }
        }

        if request.if_exists == crate::cli::IfExists::ErrorIfDifferent
            && destinations
                .iter()
                .zip(&unchanged)
                .any(|(destination, same)| destination.is_some() && !same)
        {
            return Ok(Response::SmallFilesCopied(SmallCopyResponse {
                anchor,
                outcome: SmallCopyOutcome::StagingFailed(wire_error(&anyhow::anyhow!(
                    "destination contents differ (--if-exists=error-if-different)"
                ))),
            }));
        }

        // Stage everything before publishing any final files. A staging
        // failure keeps all sidecars for the fallback engine to resume.
        let mut staged = Vec::with_capacity(request.files.len());
        for (i, (file, unchanged)) in request.files.iter().zip(&unchanged).enumerate() {
            if *unchanged {
                staged.push(None);
                continue;
            }
            // The file it replaces is the one inspected above.
            let replaced = match &destinations[i] {
                Some(stat) => crate::proto::ScannedDestination::File(stat.st_mode as u32 & 0o7777),
                None => crate::proto::ScannedDestination::Absent,
            };
            match self.stage_small_file(
                &file.path,
                &copy_id,
                data[i].unwrap(),
                file.meta.clone(),
                request.flags,
                replaced,
            ) {
                Ok(item) => staged.push(Some(item)),
                Err(error) => {
                    return Ok(Response::SmallFilesCopied(SmallCopyResponse {
                        anchor,
                        outcome: SmallCopyOutcome::StagingFailed(wire_error(&error)),
                    }));
                }
            }
        }
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_SMALL_COPY_READY_FILE",
            "SYQ_TEST_SMALL_COPY_CONTINUE_FILE",
            "small copy staged",
        )?;
        // Each publication/metadata repair has its own outcome. Unchanged
        // files keep their inode and reconcile only requested mode/ownership.
        let results = request
            .files
            .iter()
            .zip(destinations)
            .zip(staged)
            .zip(matched_content)
            .enumerate()
            .map(|(i, (((file, destination), item), matched_content))| {
                if !permitted[i] {
                    return SmallCopyFileResult {
                        disposition: SmallCopyDisposition::Excluded,
                        error: None,
                    };
                }
                let condition = destination
                    .as_ref()
                    .map_or(TargetCondition::Absent, |stat| TargetCondition::Matches {
                        dev: stat.st_dev as u64,
                        ino: stat.st_ino as u64,
                    });
                match item {
                    Some(item) => SmallCopyFileResult {
                        disposition: SmallCopyDisposition::Copied,
                        error: publish_partial_rooted(
                            &item.root,
                            &item.partial,
                            &item.target,
                            &item.file,
                            if matches!(
                                request.if_exists,
                                crate::cli::IfExists::Error
                                    | crate::cli::IfExists::ErrorIfDifferent
                            ) {
                                TargetCondition::Absent
                            } else {
                                TargetCondition::Any
                            },
                        )
                        .err()
                        .map(|error| wire_error(&error)),
                    },
                    None => {
                        let stat = destination.expect("unchanged file has a destination");
                        let mut repair = if matched_content.is_some() {
                            request.matching_flags & flags::TIMES
                        } else {
                            0
                        };
                        if request.flags & flags::MODE != 0
                            && stat.st_mode as u32 & 0o7777 != file.meta.mode & 0o7777
                        {
                            repair |= flags::MODE;
                        }
                        if request.flags & flags::OWNER != 0 && stat.st_uid != file.meta.uid {
                            repair |= flags::OWNER;
                        }
                        if request.flags & flags::GROUP != 0 && stat.st_gid != file.meta.gid {
                            repair |= flags::GROUP;
                        }
                        let disposition = if matched_content.is_some() {
                            SmallCopyDisposition::ContentMatched
                        } else {
                            SmallCopyDisposition::QuickChecked
                        };
                        let error = if let Some((target, held)) = matched_content {
                            // A content match repairs timestamps through the
                            // readable inode that was hashed; O_PATH metadata
                            // handles intentionally cannot change timestamps.
                            (|| -> Result<()> {
                                require_rooted_named_identity(
                                    &target.root,
                                    &target.relative,
                                    &target.label,
                                    &held,
                                    condition,
                                )?;
                                set_meta_file(&held, &file.meta, repair)?;
                                require_rooted_named_identity(
                                    &target.root,
                                    &target.relative,
                                    &target.label,
                                    &held,
                                    condition,
                                )
                            })()
                            .err()
                            .map(|error| wire_error(&error))
                        } else if repair == 0 {
                            None
                        } else {
                            match self.destination_relative(&file.path) {
                                Ok(path) => self
                                    .apply(
                                        &[Op::SetFileMetaIfSame {
                                            path,
                                            condition,
                                            meta: file.meta.clone(),
                                            flags: repair,
                                        }],
                                        None,
                                    )
                                    .pop()
                                    .flatten(),
                                Err(error) => Some(wire_error(&error)),
                            }
                        };
                        SmallCopyFileResult { disposition, error }
                    }
                }
            })
            .collect();
        Ok(Response::SmallFilesCopied(SmallCopyResponse {
            anchor,
            outcome: SmallCopyOutcome::Published(results),
        }))
    }

    /// Stage one small file as a private sidecar beneath the destination
    /// root, ready to publish: the staging half of `put_small`'s default path.
    fn stage_small_file(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        data: &[u8],
        mut meta: Meta,
        mut flags: u8,
        replaced: crate::proto::ScannedDestination,
    ) -> Result<StagedSmallFile> {
        let path = self.destination_relative(path)?;
        let rooted = self
            .rooted_destination_target(&path, None)?
            .context("small copy requires the destination root")?;
        self.resolve_publication(&rooted, &mut meta, &mut flags, &mut None, replaced)?;
        let meta = &meta;
        self.uncache_rooted(&rooted.root, &rooted.relative);
        let creation = sidecars::begin()?;
        let staged = staged_file_mode(meta, flags);
        let (partial, label, opened) = with_rooted_partial(&rooted, copy_id, |partial, label| {
            self.open_private_partial_rooted(
                &rooted.root,
                partial,
                label,
                true,
                staged,
                Some(staged),
            )
        })?;
        let (file, opened) = opened.context("sidecar creation was requested")?;
        creation.register_with(&rooted.root, &partial, Sidecar::Stage, || {
            match opened.identity() {
                Some(identity) => Ok(identity),
                None => file
                    .metadata()
                    .map(|metadata| (metadata.dev(), metadata.ino())),
            }
        })?;
        if opened.basis_size().is_some() {
            file.set_len(0)?;
        }
        observed_write(&self.operation, &file, data, 0, false)
            .with_context(|| format!("write {}", label.display()))?;
        check_destination_writes(&file, &label)?;
        set_meta_file(&file, meta, flags)
            .with_context(|| format!("set metadata {}", label.display()))?;
        // `publish_partial_rooted` re-checks the staged name against the open
        // descriptor immediately before the rename.
        #[cfg(any(test, debug_assertions))]
        fail_put_small_before_rename_for_test(&rooted.label)?;
        Ok(StagedSmallFile {
            root: rooted.root,
            partial,
            target: rooted.relative,
            file,
        })
    }

    /// Install the exact control-session root delivered during worker
    /// initialization. A same-process TCP worker clones it from the shared
    /// registry; an independent worker claims it with SCM_RIGHTS.
    pub(crate) fn initialize_stream(
        &mut self,
        ticket: &crate::descriptor_broker::DescriptorTicket,
        settings: crate::descriptor_copy::Settings,
    ) -> Result<()> {
        if let Some(original) = &self.stream_ticket {
            anyhow::ensure!(
                original.same_session(ticket),
                "stream worker cannot change endpoint sessions"
            );
        }
        let write = ticket.stream_write()?;
        let file = self.descriptor_session.acquire(ticket)?;
        self.stream_worker = Some(crate::descriptor_copy::FileWorker::new(
            file, write, settings,
        )?);
        self.stream_ticket = Some(ticket.clone());
        Ok(())
    }

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
        base: &SourceRootBase,
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
        base.validate()?;
        require_source_descriptor_capacity(selections.len(), shared_workers, independent_workers)?;
        let paths = selections
            .iter()
            .map(|selection| {
                if selection.path.is_empty() {
                    bail!("source selectors may not be empty");
                }
                if selection.path.contains(&0) {
                    bail!("source selector contains NUL");
                }
                Ok(resolve(&selection.path))
            })
            .collect::<Result<Vec<_>>>()?;
        let needs_base = base.confined || paths.iter().any(|path| !path.is_absolute());
        let relative_resolver = if needs_base {
            let base_path = resolve(base.path.as_deref().unwrap_or(b"."));
            let mut base_hops = Vec::new();
            let base_directory = match OperatorResolver::resolve_process(
                base_path.as_os_str().as_bytes(),
                symlink_policy,
                OperatorFinalComponent::Directory,
                false,
                &mut base_hops,
            )
            .with_context(|| format!("resolve source base {}", base_path.display()))?
            {
                PinnedPath::Directory(directory) => directory.into_parts().0,
                PinnedPath::Leaf(_) | PinnedPath::OpenFile(_) => {
                    bail!("source base {} is not a directory", base_path.display())
                }
                PinnedPath::Missing(_) => {
                    unreachable!("source base resolution requires an existing directory")
                }
            };
            Some(OperatorResolver::beneath(
                &base_directory,
                base.confined,
                symlink_policy,
            )?)
        } else {
            None
        };
        let mut resolved = Vec::with_capacity(selections.len());
        for (selection, path) in selections.iter().zip(paths) {
            let mut hops = Vec::new();
            let pinned = if path.is_absolute() {
                if base.confined {
                    bail!(
                        "source selector {} beneath --root must be relative",
                        path.display()
                    );
                }
                OperatorResolver::resolve_process(
                    path.as_os_str().as_bytes(),
                    symlink_policy,
                    OperatorFinalComponent::Entry {
                        follow_symlink: selection.follow_root,
                    },
                    false,
                    &mut hops,
                )
            } else {
                relative_resolver
                    .as_ref()
                    .expect("relative source selection requires a pinned base")
                    .resolve(
                        path.as_os_str().as_bytes(),
                        OperatorFinalComponent::Entry {
                            follow_symlink: selection.follow_root,
                        },
                        false,
                        &mut hops,
                    )
            };
            let pinned =
                pinned.with_context(|| format!("resolve source selection {}", path.display()))?;
            match pinned {
                PinnedPath::Directory(directory) => {
                    let (directory, _) = directory.into_parts();
                    resolved.push((directory, Vec::new(), None, None));
                }
                PinnedPath::Leaf(leaf) => {
                    let (parent, name, metadata, object) = leaf.into_parts();
                    if object.is_none() && !metadata.is_fifo() {
                        bail!("this platform cannot retain the selected source leaf safely");
                    }
                    let symlink_target = if metadata.is_symlink() {
                        Some(
                            read_open_symlink(object.as_ref().expect("symlink object was checked"))?
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
                            symlink_atime: (metadata.is_symlink()
                                && self.inode_preservation.atimes)
                                .then_some(metadata.atime),
                            symlink_target,
                        }),
                        object,
                    ));
                }
                PinnedPath::Missing(_) => {
                    unreachable!("source resolution did not allow a missing suffix")
                }
                PinnedPath::OpenFile(_) => {
                    unreachable!("source resolution never opens a procfs control input")
                }
            }
        }

        let registrations: Vec<_> = resolved
            .iter()
            .map(|(directory, relative, expected_leaf, object)| {
                (
                    relative.clone(),
                    expected_leaf.clone(),
                    filesystem_hint(object.as_ref().unwrap_or(directory)),
                )
            })
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
            .map(
                |((ticket, leaf_ticket), (relative, expected_leaf, filesystem))| {
                    let selection = RegisteredPath::new(ticket.root_id(), relative)?;
                    Ok(RegisteredSourceRoot {
                        filesystem,
                        ticket,
                        leaf_ticket,
                        selection,
                        expected_leaf,
                        allow_unconfined_paths,
                    })
                },
            )
            .collect::<Result<_>>()?;
        self.initialize_sources(&registered)?;
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE",
            "SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE",
            "source-registration-ready",
        )?;
        Ok(registered)
    }

    /// Acquire every registered source root before acknowledging worker
    /// readiness. Local and same-process TCP workers clone from the shared
    /// process registry; fresh SSH workers claim while still single-threaded.
    /// Build the new table off to the side so a bad ticket cannot leave a
    /// partially initialized worker.
    pub(crate) fn initialize_sources(&mut self, sources: &[RegisteredSourceRoot]) -> Result<()> {
        self.initialize_source_capabilities(sources, false)
    }

    /// Install the source half of a same-machine copy worker. These tickets
    /// intentionally belong to the source endpoint session rather than this
    /// destination endpoint, so claim their exact descriptors from that
    /// session's private broker during worker initialization.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn initialize_copy_sources(
        &mut self,
        sources: &[RegisteredSourceRoot],
    ) -> Result<()> {
        #[cfg(debug_assertions)]
        reject_copy_source_claim_for_test()?;
        if self.destination_root.is_none() {
            bail!("local copy sources require a registered destination root");
        }
        if sources.iter().any(|source| source.allow_unconfined_paths) {
            bail!("local copy sources must be confined registered capabilities");
        }
        self.initialize_source_capabilities(sources, true)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(crate) fn initialize_copy_sources(
        &mut self,
        _sources: &[RegisteredSourceRoot],
    ) -> Result<()> {
        bail!("same-machine local copy capabilities require Linux or macOS")
    }

    fn initialize_source_capabilities(
        &mut self,
        sources: &[RegisteredSourceRoot],
        claim_foreign_session: bool,
    ) -> Result<()> {
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
            let acquire = |ticket: &DescriptorTicket| {
                if claim_foreign_session {
                    acquire_descriptor(ticket)
                } else {
                    self.descriptor_session.acquire(ticket)
                }
            };
            let directory = acquire(&source.ticket)?;
            let root = Arc::new(Root::from_directory(directory)?);
            let leaf_object = match (&source.leaf_ticket, &source.expected_leaf) {
                (Some(ticket), Some(expected)) => {
                    let object = acquire(ticket)?;
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
                (None, Some(expected)) if expected.file_type == crate::sys::MODE_FIFO => {
                    // Platforms without an inert FIFO descriptor retain its
                    // parent and observed identity, never a stream reader.
                    let metadata =
                        root.metadata(&RelativePath::new(source.selection.relative())?)?;
                    require_source_leaf_identity(expected, metadata)?;
                    None
                }
                (None, None) => None,
                _ => bail!("source root leaf selection and object ticket disagree"),
            };
            roots.insert(
                id,
                SourceRootHandle {
                    root,
                    _leaf_object: leaf_object.map(Arc::new),
                    selection: source.selection.relative().to_vec(),
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

    fn registered_source_handle(&self, source: &RegisteredPath) -> Result<&SourceRootHandle> {
        let handle = self
            .source_roots
            .get(&source.root())
            .with_context(|| format!("unknown registered source root {}", source.root().get()))?;
        if !handle.selection.is_empty() && source.relative() != handle.selection {
            bail!("registered source leaf does not authorize the requested path");
        }
        Ok(handle)
    }

    fn registered_source_target(&self, source: &RegisteredPath) -> Result<RegisteredSourceTarget> {
        let handle = self.registered_source_handle(source)?;
        Ok(RegisteredSourceTarget {
            root: handle.root.clone(),
            relative: RelativePath::new(source.relative())?,
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
        if self.destination_root.is_some() {
            if source.is_some() {
                bail!("source scan is not valid on a destination worker");
            }
            return Ok(None);
        }
        if let Some(source) = source {
            let target = self.registered_source_target(source)?;
            return Ok(Some(SourceScanRoot {
                root: target.root,
                relative: source.relative().to_vec(),
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
        if self.source_roots.is_empty() || self.destination_root.is_some() {
            return Ok(());
        }
        let has_guard = match request {
            Request::Scan { guard, .. }
            | Request::StatMany { guard, .. }
            | Request::PartialPaths { guard, .. }
            | Request::PruneLookup { guard, .. }
            | Request::WidenDirectories { guard, .. }
            | Request::Apply { guard, .. }
            | Request::PlanBatch { guard, .. }
            | Request::ProbePartial { guard, .. }
            | Request::Prepare { guard, .. }
            | Request::HashAndHold { guard, .. }
            | Request::FinishBasis { guard, .. }
            | Request::SeedBasis { guard, .. }
            | Request::StageBasis { guard, .. }
            | Request::ReuseComparedRange { guard, .. }
            | Request::HashBlocks { guard, .. }
            | Request::HashWindow { guard, .. }
            | Request::WriteRange { guard, .. }
            | Request::Finalize { guard, .. }
            | Request::FileHash { guard, .. }
            | Request::ValidateDigest { guard, .. }
            | Request::Canonicalize { guard, .. } => guard.is_some(),
            Request::PutSmallBatch(puts) => puts.iter().any(|put| put.guard.is_some()),
            Request::HashExistingBatch { files, .. } => {
                files.iter().any(|file| file.guard.is_some())
            }
            Request::PatchSmallBatch(patches) => patches.iter().any(|patch| patch.guard.is_some()),
            Request::PatchBegin { patch, .. } => patch.guard.is_some(),
            _ => false,
        };
        if has_guard {
            bail!("an initialized source session rejects caller-supplied guards");
        }
        Ok(())
    }

    /// A destination mutation needs an authority before it may touch the
    /// filesystem: the directory a control connection registered with
    /// `AnchorDestination`, the registered root a destination worker was
    /// initialized with, or the guard a command-restricted receiver attaches
    /// from its signed grant. Until one of those exists, a request naming an
    /// arbitrary pathname is refused.
    pub(crate) fn validate_destination_session_request(&self, request: &Request) -> Result<()> {
        if self.destination_root.is_some() {
            return Ok(());
        }
        let unrooted = match request {
            Request::Apply { guard, .. }
            | Request::WidenDirectories { guard, .. }
            | Request::Prepare { guard, .. }
            | Request::SeedBasis { guard, .. }
            | Request::StageBasis { guard, .. }
            | Request::ReuseComparedRange { guard, .. }
            | Request::FinishBasis { guard, .. }
            | Request::WriteRange { guard, .. }
            | Request::Finalize { guard, .. } => guard.is_none(),
            Request::PutSmallBatch(puts) => puts.iter().any(|put| put.guard.is_none()),
            Request::HashExistingBatch { files, .. } => {
                files.iter().any(|file| file.guard.is_none())
            }
            Request::PatchSmallBatch(patches) => patches.iter().any(|patch| patch.guard.is_none()),
            Request::PatchBegin { patch, .. } => patch.guard.is_none(),
            Request::CopyLocal { .. } => true,
            _ => false,
        };
        if unrooted {
            bail!("{UNROOTED_MUTATION}");
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

    /// A destination worker rooted at `directory`, whose requests name files
    /// by their paths there, for other modules' tests.
    #[cfg(test)]
    pub(crate) fn test_destination(directory: &Path) -> Self {
        let mut ops = Self::new();
        ops.install_destination(
            File::open(directory).unwrap(),
            directory.as_os_str().as_bytes(),
        )
        .unwrap();
        ops
    }

    fn install_destination(&mut self, directory: File, request_prefix: &[u8]) -> Result<()> {
        let root = Arc::new(Root::from_directory(directory)?);
        self.fds.clear();
        self.fd_order.clear();
        self.held_basis.take();
        self.destination_prefix = Some(request_prefix.to_vec());
        self.destination_root = Some(root);
        #[cfg(target_os = "linux")]
        self.listing_requests.clear();
        Ok(())
    }

    fn destination_filesystem_info(
        &self,
        check_empty: bool,
        target: Option<&DestinationFilesystemTarget>,
    ) -> Result<DestinationFilesystemInfo> {
        let target_directory = if let Some(target) = target {
            if target.relative_path.is_empty()
                || target.relative_path.contains(&0)
                || target.relative_path.contains(&b'/')
                || matches!(target.relative_path.as_slice(), b"." | b"..")
            {
                bail!("destination filesystem target is not one relative path component");
            }
            let directory = if let Some(base) = &self.destination_root {
                base.open_directory(&RelativePath::new(&target.relative_path)?)?
            } else {
                let selection = self
                    .operator_selection
                    .as_ref()
                    .context("destination directory has not been selected")?;
                open_operator_directory_at(&selection.directory, &target.relative_path)?
            };
            let metadata = directory.metadata()?;
            if (metadata.dev(), metadata.ino()) != (target.dev, target.ino) {
                bail!("destination filesystem target changed while inspecting capacity");
            }
            Some(directory)
        } else {
            None
        };
        let directory = if let Some(directory) = target_directory {
            directory
        } else if let Some(directory) = &self.destination_root {
            directory.open_directory(&RelativePath::new(b"")?)?
        } else {
            let selection = self
                .operator_selection
                .as_ref()
                .context("destination directory has not been selected")?;
            selection
                .directory
                .try_clone()
                .context("duplicate selected destination directory")?
        };
        let metadata = directory.metadata()?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(directory.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error()).context("inspect destination filesystem");
        }
        let stats = unsafe { stats.assume_init() };
        let fragment_size = if stats.f_frsize == 0 {
            statvfs_counter(stats.f_bsize)
        } else {
            statvfs_counter(stats.f_frsize)
        };
        let blocks_available = statvfs_counter(stats.f_bavail);
        let files = statvfs_counter(stats.f_files);
        let files_available = statvfs_counter(stats.f_favail);
        let available_bytes = blocks_available.saturating_mul(fragment_size);
        let available_inodes = (files != 0 && files_available <= files).then_some(files_available);
        #[cfg(target_os = "macos")]
        let available_inodes = available_inodes.and_then(|available| {
            // macOS exFAT reports f_files=1 and f_favail=0 even while new
            // files can be created. That is unavailable inode accounting,
            // not exhaustion. Keep zero authoritative on other filesystems.
            (!crate::rooted::filesystem_is(&directory, b"exfat").ok()?).then_some(available)
        });
        #[cfg(debug_assertions)]
        let available_bytes = match std::env::var_os("SYQ_TEST_AVAILABLE_BYTES") {
            Some(value) => value
                .to_string_lossy()
                .parse()
                .context("parse SYQ_TEST_AVAILABLE_BYTES")?,
            None => available_bytes,
        };
        #[cfg(debug_assertions)]
        let available_inodes = match std::env::var_os("SYQ_TEST_AVAILABLE_INODES") {
            Some(value) => Some(
                value
                    .to_string_lossy()
                    .parse()
                    .context("parse SYQ_TEST_AVAILABLE_INODES")?,
            ),
            None => available_inodes,
        };
        let empty = check_empty
            .then(|| Self::selected_directory_empty(&directory))
            .flatten();
        Ok(DestinationFilesystemInfo {
            filesystem: filesystem_hint(&directory),
            device: metadata.dev(),
            available_bytes,
            available_inodes,
            empty,
            network: on_network_file_system(&directory, metadata.dev()),
        })
    }

    /// Inspect emptiness through the retained directory itself. The result can
    /// become stale like every unlocked capacity preflight observation, but a
    /// namespace replacement cannot redirect the read outside the capability.
    fn selected_directory_empty(directory: &File) -> Option<bool> {
        let root = Root::from_directory(directory.try_clone().ok()?).ok()?;
        root.open_directory_is_empty(directory).ok()
    }

    fn destination_relative(&self, path: &[u8]) -> Result<PathBytes> {
        let Some(prefix) = self.destination_prefix.as_deref() else {
            return Ok(path.to_vec());
        };
        destination_relative_to(prefix, path)
    }

    fn destination_full(&self, relative: &[u8]) -> PathBytes {
        let prefix = self
            .destination_prefix
            .as_deref()
            .expect("relative response requires an active destination root");
        join(prefix, relative)
    }

    fn partial_path(&self, final_path: &Path, copy_id: &CopyId) -> Result<PathBuf> {
        if self.destination_prefix.is_none() {
            return partial_path(final_path, copy_id);
        }
        let relative = path_bytes(final_path);
        let strict_relative = RelativePath::new(&relative)?;
        let logical = PathBuf::from(OsStr::from_bytes(&self.destination_full(&relative)));
        let component_limit = self
            .destination_root
            .as_ref()
            .context("destination prefix has no retained root")?
            .partial_name_max(&strict_relative)?;
        let logical_partial = partial_path_with_name_max(&logical, copy_id, component_limit)?;
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

    fn rooted_destination_target(
        &self,
        path: &[u8],
        guard: Option<&ContainerGuard>,
    ) -> Result<Option<RootedTarget>> {
        if guard.is_some() && self.destination_root.is_some() {
            bail!("destination request mixes registered and guarded root authorities");
        }
        if let Some(guard) = guard {
            return guarded_target(path, guard).map(|target| Some(target.as_rooted()));
        }
        let Some(root) = &self.destination_root else {
            return Ok(None);
        };
        let relative = RelativePath::new(path)?;
        Ok(Some(RootedTarget {
            root: root.clone(),
            relative,
            label: self.logical_destination_path(Path::new(OsStr::from_bytes(path))),
            // The plan/apply phase owns directory creation. Regular-file
            // requests must not silently expand either a registered root or a
            // signed receiver's mutation authority.
            create_missing_parents: false,
            query_partial_name_limit: false,
        }))
    }

    /// Resolve the authority a destination mutation acts under.
    fn destination_mutation_target(
        &self,
        path: &[u8],
        guard: Option<&ContainerGuard>,
    ) -> Result<RootedTarget> {
        let Some(target) = self.rooted_destination_target(path, guard)? else {
            bail!("{UNROOTED_MUTATION}");
        };
        Ok(target)
    }

    fn map_request(&self, req: &mut Request) -> Result<()> {
        if self.destination_prefix.is_none() {
            return Ok(());
        }
        let map = |path: &mut PathBytes| -> Result<()> {
            *path = self.destination_relative(path)?;
            Ok(())
        };
        match req {
            Request::DescriptorCopy(_) | Request::BindStream(_) => {
                bail!("descriptor copies require a separate unrestricted control session")
            }
            Request::Scan { root, guard, .. } => {
                if guard.is_none() {
                    map(root)?;
                }
            }
            Request::StatMany { paths, guard, .. }
            | Request::PartialPaths { paths, guard, .. }
            | Request::PruneLookup { paths, guard } => {
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
            Request::WidenDirectories {
                directories, guard, ..
            } => {
                if guard.is_none() {
                    for (path, _) in directories {
                        map(path)?;
                    }
                }
            }
            Request::Apply { ops, guard } => {
                if guard.is_none() {
                    for op in ops {
                        if let Op::Hardlink { source, .. } = op {
                            map(source)?;
                        }
                        let path = match op {
                            Op::Mkdir { path, .. }
                            | Op::Symlink { path, .. }
                            | Op::Mknod { path, .. }
                            | Op::Hardlink { path, .. }
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
            | Request::StageBasis { path, guard, .. }
            | Request::ReuseComparedRange { path, guard, .. }
            | Request::HashWindow { path, guard, .. }
            | Request::HashBlocks { path, guard, .. }
            | Request::WriteRange { path, guard, .. }
            | Request::Finalize { path, guard, .. }
            | Request::FileHash { path, guard, .. }
            | Request::ValidateDigest { path, guard, .. }
            | Request::Canonicalize { path, guard } => {
                if guard.is_none() {
                    map(path)?;
                }
            }
            Request::ReadRange { path, .. } | Request::ReadComparedRange { path, .. } => map(path)?,
            Request::CopyLocal { dst, .. } => map(dst)?,
            Request::ReadSmallBatch(reads) => {
                for read in reads {
                    map(&mut read.path)?;
                }
            }
            Request::ReadDifferingBatch { reads, .. } => {
                for read in reads {
                    map(&mut read.path)?;
                }
            }
            Request::PatchSmallBatch(patches) => {
                for patch in patches {
                    if patch.guard.is_none() {
                        map(&mut patch.path)?;
                    }
                }
            }
            Request::PatchBegin { patch, .. } => {
                if patch.guard.is_none() {
                    map(&mut patch.path)?;
                }
            }
            Request::HashExistingBatch { files, .. } => {
                for file in files {
                    if file.guard.is_none() {
                        map(&mut file.path)?;
                    }
                }
            }
            Request::PutSmallBatch(puts) => {
                for put in puts {
                    if put.guard.is_none() {
                        map(&mut put.path)?;
                    }
                }
            }
            Request::ConfigureHashing(_)
            | Request::Hello { .. }
            | Request::TcpListen { .. }
            | Request::ListDir { .. }
            | Request::ListDirDetails { .. }
            | Request::ListDirNoFollowFinal { .. }
            | Request::NativeMap(_)
            | Request::NativeRemove { .. }
            | Request::CheckOperatorDirectory { .. }
            | Request::CheckOperatorDirectoryAncestry { .. }
            | Request::RegisterSourceRoots { .. }
            | Request::CreateOperatorDirectory { .. }
            | Request::AnchorDestination { .. }
            | Request::DestinationFilesystemInfo { .. }
            | Request::TransportStats
            | Request::Receipt
            | Request::Shutdown
            | Request::PrepareSmallFiles(_)
            | Request::CopySmallFiles(_)
            | Request::ReadStream(_)
            | Request::WriteStreamFence
            | Request::ShrinkReadStream { .. }
            | Request::MappingChunk { .. }
            | Request::ConfigurePreservation { .. }
            | Request::CreateSendBudget { .. }
            | Request::PatchData { .. }
            | Request::PatchEnd { .. }
            | Request::StopReadStream => {}
        }
        Ok(())
    }

    pub fn scan_root(&self, root: &[u8]) -> Result<PathBytes> {
        self.destination_relative(root)
    }

    fn completion_entries(
        directory: &[u8],
        confined_root: Option<&[u8]>,
        prefix: &[u8],
        requested_limit: u16,
        symlink_policy: OperatorSymlinkPolicy,
        detailed: bool,
        follow_final_symlinks: bool,
    ) -> Result<Response> {
        const MAX_COMPLETION_ENTRIES: usize = 1_000;
        if directory.contains(&0)
            || confined_root.is_some_and(|root| root.contains(&0))
            || prefix.contains(&0)
            || prefix.contains(&b'/')
        {
            bail!("invalid completion directory or prefix");
        }
        check_completion_directory(directory, confined_root, symlink_policy)?;
        let limit = usize::from(requested_limit).min(MAX_COMPLETION_ENTRIES);
        if limit == 0 {
            return Ok(if detailed {
                Response::DetailedDirectoryEntries {
                    entries: Vec::new(),
                    details: Vec::new(),
                    truncated: false,
                }
            } else {
                Response::DirectoryEntries {
                    entries: Vec::new(),
                    truncated: false,
                }
            });
        }
        let mut entries = Vec::new();
        let mut truncated = false;
        for item in std::fs::read_dir(resolve(directory))? {
            let item = item?;
            let name = item.file_name().into_vec();
            if name == b"." || name == b".." || !name.starts_with(prefix) {
                continue;
            }
            if !prefix.starts_with(b".") && name.starts_with(b".") {
                continue;
            }
            if entries.len() == limit {
                truncated = true;
                break;
            }
            let file_type = item.file_type()?;
            let directory = file_type.is_dir()
                || (file_type.is_symlink()
                    && follow_final_symlinks
                    && check_completion_directory(
                        item.path().as_os_str().as_bytes(),
                        confined_root,
                        symlink_policy,
                    )
                    .is_ok());
            entries.push(CompletionEntry { name, directory });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        if detailed {
            let details = crate::completion_details::describe(&resolve(directory), &entries);
            Ok(Response::DetailedDirectoryEntries {
                entries,
                details,
                truncated,
            })
        } else {
            Ok(Response::DirectoryEntries { entries, truncated })
        }
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

    fn cached(&mut self, p: &Path, attempt: u32) -> Result<&CachedFile> {
        let key = FdKey {
            location: FileLocation::Path(p.to_path_buf()),
            attempt,
            private: false,
        };
        if !self.fds.contains_key(&key) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            let f = open_existing_regular(p, false)?;
            crate::inode_metadata::prepare_read(&f, self.inode_preservation.open_noatime);
            self.fds.insert(key.clone(), CachedFile::new(f));
            self.fd_order.push(key.clone());
        }
        Ok(self.fds.get(&key).unwrap())
    }

    fn cache_file(&mut self, location: FileLocation, attempt: u32, private: bool, file: File) {
        self.cache_entry(location, attempt, private, CachedFile::new(file));
    }

    /// Cache a descriptor with the metadata read when it opened or created
    /// its file, before any write.
    fn cache_opened_file(
        &mut self,
        location: FileLocation,
        attempt: u32,
        private: bool,
        file: File,
        metadata: fs::Metadata,
    ) {
        self.cache_entry(
            location,
            attempt,
            private,
            CachedFile::opened(file, metadata),
        );
    }

    fn cache_entry(
        &mut self,
        location: FileLocation,
        attempt: u32,
        private: bool,
        entry: CachedFile,
    ) {
        self.uncache_location(&location);
        if self.fds.len() >= FD_CACHE_MAX {
            let victim = self.fd_order.remove(0);
            self.fds.remove(&victim);
        }
        let key = FdKey {
            location,
            attempt,
            private,
        };
        self.fds.insert(key.clone(), entry);
        self.fd_order.push(key);
    }

    fn cached_clone(
        &self,
        location: FileLocation,
        attempt: u32,
        private: bool,
    ) -> io::Result<Option<File>> {
        let key = FdKey {
            location,
            attempt,
            private,
        };
        self.fds
            .get(&key)
            .map(|file| file.file().try_clone())
            .transpose()
    }

    fn uncache_rooted(&mut self, root: &Root, relative: &RelativePath) -> Option<File> {
        self.uncache_rooted_entry(root, relative)
            .map(CachedFile::into_file)
    }

    /// The cached descriptor with the metadata read when it opened its
    /// file, if that was kept.
    fn uncache_rooted_opened(
        &mut self,
        root: &Root,
        relative: &RelativePath,
    ) -> Option<(File, Option<fs::Metadata>)> {
        self.uncache_rooted_entry(root, relative)
            .map(CachedFile::into_parts)
    }

    fn uncache_rooted_entry(&mut self, root: &Root, relative: &RelativePath) -> Option<CachedFile> {
        self.uncache_entry(&FileLocation::Rooted {
            root: root.identity(),
            relative: relative.clone(),
        })
    }

    fn uncache_location(&mut self, location: &FileLocation) -> Option<File> {
        self.uncache_entry(location).map(CachedFile::into_file)
    }

    fn uncache_entry(&mut self, location: &FileLocation) -> Option<CachedFile> {
        let mut removed = None;
        self.fd_order.retain(|key| {
            if &key.location == location {
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
    ) -> Result<&CachedFile> {
        let key = FdKey {
            location: FileLocation::Rooted {
                root: root.identity(),
                relative: relative.clone(),
            },
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
            self.fds.insert(key.clone(), CachedFile::new(file));
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
            location: FileLocation::RegisteredSource {
                root: root_id,
                relative: relative_bytes.to_vec(),
            },
            attempt,
            private: false,
        };
        if !self.fds.contains_key(&key) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            self.fds.insert(
                key.clone(),
                CachedFile::new(open_registered_source(
                    target,
                    self.inode_preservation.open_noatime,
                )?),
            );
            self.fd_order.push(key.clone());
        }
        Ok(self.fds.get(&key).unwrap().file())
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
            let minimum = self.destination_parallel_minimum(
                Some(guard),
                paths.len(),
                paths.iter().map(Vec::as_slice),
            );
            return parallel_map_from(minimum, paths, |path| {
                let target = guarded_target(path, guard).ok()?;
                let metadata = target.root.metadata(&target.relative).ok()?;
                rooted_entry(&target.root, &target.relative, Vec::new(), metadata).ok()
            });
        }
        if let Some(root) = self.destination_root.clone() {
            if follow {
                return vec![None; paths.len()];
            }
            #[cfg(target_os = "linux")]
            list_nfs_directories_before_stats(&root, paths, &mut self.listing_requests);
            let minimum = self.destination_parallel_minimum(
                None,
                paths.len(),
                paths.iter().map(Vec::as_slice),
            );
            return parallel_map_init_from(
                minimum,
                paths,
                || None,
                |parent, path| stat_with_parent(&root, parent, path),
            );
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

    fn prune_lookup(
        &mut self,
        paths: &[PathBytes],
        guard: Option<&ContainerGuard>,
    ) -> Result<Vec<Option<Entry>>> {
        let minimum =
            self.destination_parallel_minimum(guard, paths.len(), paths.iter().map(Vec::as_slice));
        parallel_map_from(minimum, paths, |path| {
            // Resolve authority before classifying missing paths. An invalid
            // root/guard must never be mistaken for a missing child.
            let target = self.rooted_destination_target(path, guard)?;
            let result: Result<Entry> = (|| {
                if let Some(target) = target {
                    let metadata = target.root.metadata(&target.relative)?;
                    rooted_entry(&target.root, &target.relative, Vec::new(), metadata)
                } else {
                    let path = resolve(path);
                    let metadata = fs::symlink_metadata(&path)?;
                    Ok(entry_from_meta(Vec::new(), &path, &metadata))
                }
            })();
            match result {
                Ok(entry) => Ok(Some(entry)),
                Err(error)
                    if error.downcast_ref::<io::Error>().is_some_and(|error| {
                        matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
                    }) =>
                {
                    Ok(None)
                }
                // Callers name the purpose (pruning, --copy-if, the root check).
                Err(error) => {
                    Err(error).with_context(|| format!("inspect {}", resolve(path).display()))
                }
            }
        })
        .into_iter()
        .collect()
    }

    fn stat_many_unadorned_request(
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
            if self.destination_root.is_some() {
                bail!("source stat is not valid on a destination worker");
            }
            if sources.len() != paths.len() {
                bail!("source stat capability count does not match path count");
            }
            // Validate capability authority eagerly. RegisteredPath construction
            // and deserialization guarantee valid relative path bytes.
            let mut targets = sources
                .iter()
                .enumerate()
                .map(|(index, source)| {
                    let handle = self.registered_source_handle(source)?;
                    let parent = source
                        .relative()
                        .rsplitn(2, |b| *b == b'/')
                        .nth(1)
                        .unwrap_or(b"");
                    Ok(((source.root().get(), parent), index, source, handle))
                })
                .collect::<Result<Vec<_>>>()?;
            // Group only metadata lookups; data-job scheduling stays unchanged.
            targets.sort_unstable_by_key(|(key, ..)| *key);
            // `follow` describes the legacy pathname request. A registered
            // selection has already applied the operator-root policy, and no
            // descendant component gains symlink-traversal authority here.
            let results = parallel_map_init(
                &targets,
                || None,
                |parent, (_, _, source, target)| {
                    let Some(expected) = target.expected_leaf.as_ref() else {
                        return Ok(stat_with_parent(&target.root, parent, source.relative()));
                    };
                    let relative = RelativePath::new(source.relative())?;
                    let metadata = target
                        .root
                        .metadata(&relative)
                        .context("inspect registered source leaf")?;
                    require_source_leaf_identity(expected, metadata)?;
                    let entry = rooted_source_entry(
                        &target.root,
                        &relative,
                        Vec::new(),
                        metadata,
                        Some(expected),
                    )?;
                    let after = target
                        .root
                        .metadata(&relative)
                        .context("recheck registered source leaf")?;
                    require_source_leaf_identity(expected, after)?;
                    Ok(Some(entry))
                },
            );
            // Scatter before collecting so the first error, as well as each
            // successful entry, follows request order rather than lookup order.
            debug_assert_eq!(targets.len(), sources.len());
            debug_assert_eq!(results.len(), targets.len());
            let mut ordered: Vec<_> = (0..sources.len()).map(|_| Ok(None)).collect();
            for ((_, index, ..), result) in targets.into_iter().zip(results) {
                ordered[index] = result;
            }
            return ordered.into_iter().collect();
        }
        if self.destination_root.is_none()
            && !self.source_roots.is_empty()
            && !self.allow_unconfined_source_paths
        {
            bail!("source stat omitted its registered source references");
        }
        Ok(self.stat_many(paths, follow, guard))
    }

    pub fn partial_paths(
        &mut self,
        paths: &[PathBytes],
        copy_id: &CopyId,
        guard: Option<&ContainerGuard>,
    ) -> Vec<std::result::Result<PathBytes, String>> {
        parallel_map_init(paths, PartialNameLimits::default, |limits, path| {
            let requested = Path::new(OsStr::from_bytes(path));
            let resolved = if let Some(target) = self.rooted_destination_target(path, guard)? {
                let relative = target.relative.to_path_buf();
                // Validate the leaf even on a cache hit: an empty relative path
                // names the root, not a file for which we can make a sidecar.
                let parent = relative
                    .parent()
                    .context("operation requires a descendant path")?;
                let limit =
                    limits.get_or_query(&target.root, parent, || target.partial_name_max())?;
                partial_path_with_name_max(&target.label, copy_id, limit)?
            } else {
                self.partial_path(&resolve(path), copy_id)?
            };
            let name = resolved.file_name().expect("partial always has a name");
            let parent = requested.parent().unwrap_or_else(|| Path::new(""));
            Ok(path_bytes(&parent.join(name)))
        })
        .into_iter()
        .map(|result: Result<PathBytes>| result.map_err(|error| format!("{error:#}")))
        .collect()
    }

    fn annotate_permission_failure(
        &self,
        path: &[u8],
        guard: Option<&ContainerGuard>,
        access: u32,
        error: &mut WireError,
    ) {
        if error.io_kind != Some(WireIoKind::PermissionDenied) {
            return;
        }
        let Ok(Some(target)) = self.rooted_destination_target(path, guard) else {
            return;
        };
        if let Some(hint) = directory_permission_hint(&target.root, &target.relative, access) {
            error.io_kind = Some(WireIoKind::OwnedDirectoryPermissions);
            error.message.push_str("; ");
            error.message.push_str(&hint);
        }
    }

    /// Whether operations on `paths` reach a network filesystem: the one the
    /// destination root that `guard`, or else the registered root, lies on,
    /// or one mounted on a directory directly beneath it, such as the target
    /// of an exact placement. Mounts deeper in the tree are not looked for.
    fn destination_on_network_file_system(
        &mut self,
        guard: Option<&ContainerGuard>,
        paths: &[&[u8]],
    ) -> bool {
        let (identity, guard_root) = match guard {
            Some(guard) => (
                RootIdentity {
                    dev: guard.dev,
                    ino: guard.ino,
                },
                Some(resolve(&guard.root)),
            ),
            None => match &self.destination_root {
                Some(root) => (root.identity(), None),
                None => return false,
            },
        };
        let mut entries: Vec<Vec<u8>> = paths
            .iter()
            .filter_map(|path| match &guard_root {
                Some(root) => relative_under(root, &resolve(path)).ok(),
                None => RelativePath::new(path).ok(),
            })
            .map(|relative| relative.first().unwrap_or_default().to_vec())
            .collect();
        entries.sort_unstable();
        entries.dedup();
        if self.network_entries.len() > NETWORK_ENTRIES_MAX {
            self.network_entries.clear();
        }
        let mut opened: Option<Option<Arc<Root>>> = None;
        for entry in std::iter::once(Vec::new()).chain(entries) {
            let key = (identity, entry);
            let network = match self.network_entries.get(&key) {
                Some(&network) => network,
                None => {
                    let root = match &guard_root {
                        None => self.destination_root.clone(),
                        Some(path) => opened
                            .get_or_insert_with(|| {
                                Root::open_verified(path, identity).ok().map(Arc::new)
                            })
                            .clone(),
                    };
                    let Some(root) = root else {
                        return false;
                    };
                    let network = if key.1.is_empty() {
                        root.on_network_file_system()
                    } else {
                        root.entry_on_network_file_system(&key.1)
                    };
                    self.network_entries.insert(key, network);
                    network
                }
            };
            if network {
                return true;
            }
        }
        false
    }

    /// The fewest of `count` destination lookups or changes, on `paths`, that
    /// run in parallel (see `parallel_minimum`).
    fn destination_parallel_minimum<'a>(
        &mut self,
        guard: Option<&ContainerGuard>,
        count: usize,
        paths: impl Iterator<Item = &'a [u8]>,
    ) -> usize {
        let short = (2..PAR_MIN).contains(&count);
        parallel_minimum(
            short && self.destination_on_network_file_system(guard, &paths.collect::<Vec<_>>()),
        )
    }

    /// Ops within a batch run in parallel, except that a creation waits for
    /// its parent's Mkdir in the same batch. Creations in a wave share each
    /// directory between at most two threads. A short phase runs on this
    /// thread unless its operations reach a network filesystem.
    pub fn apply(&mut self, ops: &[Op], guard: Option<&ContainerGuard>) -> Vec<Option<WireError>> {
        if ops
            .iter()
            .all(|op| matches!(op, Op::Unlink { .. } | Op::Rmdir { .. }))
        {
            let selected = apply::selected_removals(
                ops,
                guard,
                self.destination_root.clone(),
                self.destination_prefix.as_deref(),
            );
            return self
                .deletions
                .get_or_insert_with(Default::default)
                .run(selected)
                .map(|results| {
                    results
                        .into_iter()
                        .map(|result| result.err().as_ref().map(wire_error))
                        .collect()
                })
                .unwrap_or_else(|error| {
                    (0..ops.len()).map(|_| Some(wire_error(&error))).collect()
                });
        }
        let narrow = self.narrow_new_directories;
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
        let waves = creation_waves(ops, &create_idx);
        let short: Vec<&[u8]> = [&guarded_idx, &meta_idx]
            .into_iter()
            .chain(&waves)
            .filter(|phase| (2..PAR_MIN).contains(&phase.len()))
            .flatten()
            .map(|&index| op_path(&ops[index]))
            .collect();
        let minimum = parallel_minimum(
            !short.is_empty() && self.destination_on_network_file_system(guard, &short),
        );
        let directories = &self.receiver_directories;
        let destination_root = self.destination_root.clone();
        let destination_prefix = self.destination_prefix.as_deref();
        let mut out: Vec<Option<WireError>> = vec![None; ops.len()];
        // A directory this request creates and then gives a group starts
        // private when its starting group may differ, so that group cannot
        // open it, and list what is created in it, before the change. Its
        // metadata below then gives it the mode it would have been created
        // with. Otherwise its creation mode is no wider than its final one.
        let groups: HashMap<&[u8], u32> = meta_idx
            .iter()
            .filter_map(|&i| match &ops[i] {
                Op::SetMeta {
                    path, meta, flags, ..
                } if flags & flags::GROUP != 0 => Some((path.as_slice(), meta.gid)),
                _ => None,
            })
            .collect();
        let parents = apply::CreationParents::default();
        // Only directories this request actually created, by identity.
        let private = std::sync::Mutex::new(HashMap::<Vec<u8>, (u32, (u64, u64))>::new());
        let create = |op: &Op| {
            let result = match op {
                Op::Mkdir { path, mode, .. }
                    if groups.get(path.as_slice()).is_some_and(|&group| {
                        apply::starting_group_may_differ(
                            path,
                            group,
                            &parents,
                            guard,
                            destination_root.clone(),
                            destination_prefix,
                        )
                    }) =>
                {
                    apply::create_identified_directory(
                        op,
                        guard,
                        destination_root.clone(),
                        destination_prefix,
                        true,
                    )
                    .map(|created| {
                        if let Some((dev, ino, created)) = created {
                            private
                                .lock()
                                .unwrap()
                                .insert(path.clone(), (*mode, (dev, ino)));
                            if narrow && mode & 0o700 != 0o700 {
                                directories.created((dev, ino), created, true);
                            }
                        }
                    })
                }
                // A later receiver-chosen mode opens a directory created
                // private, as the planner opens the destination root (one
                // created for a group change is opened above), and under
                // `syq rsync` narrows one whose proposal lacks the owner
                // access it is created with to fill it.
                Op::Mkdir { mode, .. }
                    if mode & 0o7777 == 0o700 || (narrow && mode & 0o700 != 0o700) =>
                {
                    let narrowing = mode & 0o700 != 0o700;
                    apply::create_identified_directory(
                        op,
                        guard,
                        destination_root.clone(),
                        destination_prefix,
                        !narrowing,
                    )
                    .map(|created| {
                        if let Some((dev, ino, created)) = created {
                            directories.created((dev, ino), created, narrowing);
                        }
                    })
                }
                _ => apply_one(op, guard, destination_root.clone(), destination_prefix),
            };
            result.err().as_ref().map(wire_error)
        };
        let gres = parallel_map_from(minimum, &guarded_idx, |&i| create(&ops[i]));
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
        for wave in waves {
            let cres = parallel_by_directory(minimum, ops, &wave, create);
            for (i, r) in wave.iter().zip(cres) {
                out[*i] = r;
            }
        }
        let private = private.into_inner().unwrap();
        let mres = parallel_map_from(minimum, &meta_idx, |&i| {
            // A receiver-chosen mode is decided here, in parallel, once the
            // request's creations are done.
            let op = directories.resolve_op(
                &ops[i],
                guard,
                destination_root.clone(),
                destination_prefix,
            );
            let result = apply_one(&op, guard, destination_root.clone(), destination_prefix);
            // After its group change, even a refused one, as creating it
            // directly and then changing its group would have left it.
            let opened = match &ops[i] {
                Op::SetMeta { path, .. } => private.get(path).map(|&(proposed, created)| {
                    apply::open_created_directory(
                        path,
                        proposed,
                        created,
                        guard,
                        destination_root.clone(),
                        destination_prefix,
                    )
                }),
                _ => None,
            };
            result
                .and(opened.unwrap_or(Ok(())))
                .err()
                .as_ref()
                .map(wire_error)
        });
        for (i, r) in meta_idx.iter().zip(mres) {
            out[*i] = r;
        }
        out
    }
}

// Retain only the last parent in a metadata chunk. Like descriptor scanning,
// this observes the selected directory if it is renamed during the chunk.
// Symlink reads and identity checks use that same parent; the next chunk or
// request starts without a retained handle and resolves the path again.
struct HeldMetadataParent {
    // Device/inode can coincide across bind-mount views. Retain the actual
    // opened root so its distinct object identity cannot be recycled.
    root: Arc<Root>,
    path: PathBytes,
    directory: File,
}

/// A directory is listed before its entries are stat'ed once at least this
/// many of them have been asked about.
#[cfg(target_os = "linux")]
const LISTING_MIN_NAMES: usize = 16;
/// A listing costs the client a few microseconds for every entry it reads,
/// about what a lookup costs per name when lookups run in parallel on a
/// fast network, so a directory is listed only when its size says it is
/// not much larger than the names asked about so far: at most this many
/// bytes per name plus one block, against 25 to 60 bytes per entry on most
/// filesystems.
#[cfg(target_os = "linux")]
const LISTING_BYTES_PER_NAME: u64 = 256;
#[cfg(target_os = "linux")]
const LISTING_SLACK_BYTES: u64 = 4 << 10;
/// ZFS reports a directory's entry count as its size, so the space the
/// directory occupies is checked too. That space includes overhead, 8 to
/// 17 KiB for a ZFS directory of up to several hundred entries, so it gets a
/// larger allowance.
#[cfg(target_os = "linux")]
const LISTING_ALLOCATED_SLACK_BYTES: u64 = 16 << 10;
/// Whatever size the filesystem reports (ZFS reports its entry count), the
/// listing stops after this many entries per name, enough to reach the end
/// of any directory the size allows.
#[cfg(target_os = "linux")]
const LISTING_ENTRIES_PER_NAME: usize = 16;
/// Directories remembered for listing before the record starts over.
#[cfg(target_os = "linux")]
const LISTING_DIRECTORIES_MAX: usize = 1 << 16;

/// Count the given relative paths into `requests` by parent directory, and
/// return the directories now asked about often enough to be listed, each
/// with this batch's first path in it and the names asked about so far.
/// Absolute paths are left to the stat itself.
#[cfg(target_os = "linux")]
fn directories_to_list<'a>(
    paths: &'a [PathBytes],
    requests: &mut HashMap<PathBytes, Option<usize>>,
) -> Vec<(&'a [u8], &'a [u8], usize)> {
    let mut batch: HashMap<&[u8], (&[u8], usize)> = HashMap::new();
    for path in paths {
        if path.starts_with(b"/") {
            continue;
        }
        let parent = match path.iter().rposition(|byte| *byte == b'/') {
            Some(separator) => &path[..separator],
            None => &b""[..],
        };
        batch.entry(parent).or_insert((path.as_slice(), 0)).1 += 1;
    }
    if requests.len() > LISTING_DIRECTORIES_MAX {
        requests.clear();
    }
    let mut candidates = Vec::new();
    for (parent, (first, names)) in batch {
        let Some(asked) = requests.entry(parent.to_vec()).or_insert(Some(0)) else {
            continue;
        };
        *asked += names;
        if *asked >= LISTING_MIN_NAMES {
            candidates.push((parent, first, *asked));
        }
    }
    candidates
}

/// Whether a directory of `size` reported bytes occupying `blocks` 512-byte
/// blocks is small enough to list for `names` requested names.
#[cfg(target_os = "linux")]
fn small_enough_to_list(names: usize, size: u64, blocks: u64) -> bool {
    let expected = LISTING_BYTES_PER_NAME.saturating_mul(names as u64);
    size <= expected.saturating_add(LISTING_SLACK_BYTES)
        && blocks.saturating_mul(512) <= expected.saturating_add(LISTING_ALLOCATED_SLACK_BYTES)
}

/// List each NFS directory that enough of the paths about to be stat'ed
/// are in. The first stat of a name that another process created makes the
/// NFS client confirm the entry with the server, one LOOKUP per name; a
/// listing confirms every entry it reads in one request per few hundred and
/// leaves their stats to the client's cache. A local filesystem answers
/// either from memory, so only NFS directories are listed. A listing tells
/// the client nothing about names that do not exist, so a directory is
/// listed only when the first requested name is there. Each directory is
/// listed at most once per destination.
#[cfg(target_os = "linux")]
fn list_nfs_directories_before_stats(
    root: &Arc<Root>,
    paths: &[PathBytes],
    requests: &mut HashMap<PathBytes, Option<usize>>,
) {
    let candidates = directories_to_list(paths, requests);
    // Whether the directory is settled: listed, or not on NFS.
    let list = |(parent, first, names): &(&[u8], &[u8], usize)| -> bool {
        let Ok(relative) = RelativePath::new(parent) else {
            return true;
        };
        let Ok(directory) = root.open_directory(&relative) else {
            return false;
        };
        let Ok((_, traits)) = opened_file_system(&directory) else {
            return false;
        };
        if !traits.is_nfs {
            return true;
        }
        let Ok(metadata) = directory.metadata() else {
            return false;
        };
        if !small_enough_to_list(*names, metadata.len(), metadata.blocks()) {
            return false;
        }
        let Ok(first) = RelativePath::new(first) else {
            return false;
        };
        if !matches!(root.metadata_optional(&first), Ok(Some(_))) {
            return false;
        }
        let _ =
            root.walk_open_directory(&directory, names.saturating_mul(LISTING_ENTRIES_PER_NAME));
        true
    };
    let settled: Vec<bool> = if candidates.len() < 2 {
        candidates.iter().map(list).collect()
    } else if let Some(pool) = metadata_pool() {
        use rayon::prelude::*;
        pool.install(|| candidates.par_iter().map(list).collect())
    } else {
        candidates.iter().map(list).collect()
    };
    for ((parent, _, _), settled) in candidates.iter().zip(settled) {
        if settled {
            requests.insert(parent.to_vec(), None);
        }
    }
}

fn stat_with_parent(
    root: &Arc<Root>,
    parent: &mut Option<HeldMetadataParent>,
    path: &[u8],
) -> Option<Entry> {
    if path.starts_with(b"/") {
        return None;
    }
    let Some(separator) = path.iter().rposition(|byte| *byte == b'/') else {
        *parent = None;
        let relative = RelativePath::new(path).ok()?;
        let metadata = root.metadata(&relative).ok()?;
        return rooted_entry(root, &relative, Vec::new(), metadata).ok();
    };
    let parent_path = &path[..separator];
    let name = &path[separator + 1..];
    if parent
        .as_ref()
        .is_none_or(|held| !Arc::ptr_eq(&held.root, root) || held.path != parent_path)
    {
        *parent = None;
        let directory = root
            .open_directory(&RelativePath::new(parent_path).ok()?)
            .ok()?;
        *parent = Some(HeldMetadataParent {
            root: root.clone(),
            path: parent_path.to_vec(),
            directory,
        });
    }
    // The held parent's key was validated when opened. This operation validates
    // the leaf, so siblings do not need an allocated RelativePath for validation.
    let directory = &parent.as_ref()?.directory;
    let metadata = root.metadata_in_directory(directory, name).ok()?;
    rooted_entry_in_directory(root, directory, name, Vec::new(), metadata, true).ok()
}

const PAR_THREADS: usize = 32;
const PAR_MIN: usize = 32;
/// Destination entries remembered as on or off a network filesystem before
/// the record starts over.
const NETWORK_ENTRIES_MAX: usize = 4096;

fn metadata_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| crate::resources::optional_pool("syq-metadata", PAR_THREADS))
        .as_ref()
}

/// The fewest operations that run in parallel. On a network filesystem each
/// one waits a round trip, so even two finish sooner together; locally a
/// short batch is faster on the calling thread.
fn parallel_minimum(network: bool) -> usize {
    if network {
        2
    } else {
        PAR_MIN
    }
}

fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    parallel_map_from(PAR_MIN, items, f)
}

/// `parallel_map` for batches of at least `minimum` items.
fn parallel_map_from<T: Sync, R: Send>(
    minimum: usize,
    items: &[T],
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    parallel_map_init_from(minimum, items, || (), |_, item| f(item))
}

/// Split creations so that each runs after the Mkdir of its parent in the
/// same request. Otherwise a child resolving its missing parent would create
/// that parent with default permissions first, and the parent's own Mkdir
/// would then accept it with permissions wider than the copy planned. A
/// request without such a pair keeps one wave.
fn creation_waves(ops: &[Op], selected: &[usize]) -> Vec<Vec<usize>> {
    let directories: HashMap<&[u8], usize> = selected
        .iter()
        .filter_map(|&index| match &ops[index] {
            Op::Mkdir { path, .. } => Some((path.as_slice(), index)),
            _ => None,
        })
        .collect();
    let parent = |path: &[u8]| -> Option<usize> {
        let separator = path.iter().rposition(|byte| *byte == b'/')?;
        directories.get(&path[..separator]).copied()
    };
    if !selected
        .iter()
        .any(|&index| parent(op_path(&ops[index])).is_some())
    {
        return vec![selected.to_vec()];
    }
    let mut levels = HashMap::<usize, usize>::new();
    fn level(
        index: usize,
        ops: &[Op],
        parent: &dyn Fn(&[u8]) -> Option<usize>,
        levels: &mut HashMap<usize, usize>,
    ) -> usize {
        if let Some(level) = levels.get(&index) {
            return *level;
        }
        // Paths are unique per Mkdir, so a parent is always a shorter path.
        let level = parent(op_path(&ops[index])).map_or(0, |parent_index| {
            1 + level(parent_index, ops, parent, levels)
        });
        levels.insert(index, level);
        level
    }
    let mut waves: Vec<Vec<usize>> = Vec::new();
    for &index in selected {
        let level = level(index, ops, &parent, &mut levels);
        if waves.len() <= level {
            waves.resize_with(level + 1, Vec::new);
        }
        waves[level].push(index);
    }
    waves
}

/// Run the selected operations, which add or remove directory entries. The
/// kernel adds one directory's entries one at a time, so threads beyond the
/// second only contend for it: directories spread over the pool, and each is
/// worked on by at most two of its threads. Removals keep the pool's plain
/// distribution; the work of freeing a removed file's blocks happens after
/// the directory is unlocked and does spread over threads.
fn parallel_by_directory<R: Send>(
    minimum: usize,
    ops: &[Op],
    selected: &[usize],
    f: impl Fn(&Op) -> R + Sync,
) -> Vec<R> {
    if selected.len() < minimum {
        return selected.iter().map(|&index| f(&ops[index])).collect();
    }
    let Some(pool) = metadata_pool() else {
        return selected.iter().map(|&index| f(&ops[index])).collect();
    };
    let mut directories = HashMap::<&[u8], Vec<usize>>::new();
    let mut removals = Vec::new();
    for (position, &index) in selected.iter().enumerate() {
        let op = &ops[index];
        if matches!(op, Op::Remove { .. } | Op::Unlink { .. } | Op::Rmdir { .. }) {
            removals.push(position);
            continue;
        }
        let path = op_path(op);
        let directory = path
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(&path[..0], |separator| &path[..separator]);
        directories.entry(directory).or_default().push(position);
    }
    let removal_chunk = removals.len().div_ceil(PAR_THREADS).max(1);
    let shares: Vec<Vec<usize>> = removals
        .chunks(removal_chunk)
        .map(<[usize]>::to_vec)
        .chain(directories.into_values().flat_map(|mut positions| {
            if positions.len() < 2 * PAR_MIN {
                return vec![positions];
            }
            // XFS gives each new directory the next allocation group in turn,
            // and the files of a directory allocate from its group. Workers
            // fill neighbouring directories at the same time, so directories
            // created in name order would put them into the same few groups
            // together. A scattered order leaves no pattern to fall into.
            positions.sort_unstable_by_key(|position| {
                (*position as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            });
            let second = positions.split_off(positions.len() / 2);
            vec![positions, second]
        }))
        .collect();
    use rayon::prelude::*;
    let done: Vec<Vec<(usize, R)>> = pool.install(|| {
        shares
            .par_iter()
            .map(|share| {
                share
                    .iter()
                    .map(|&position| (position, f(&ops[selected[position]])))
                    .collect()
            })
            .collect()
    });
    let mut results: Vec<Option<R>> = selected.iter().map(|_| None).collect();
    for (position, result) in done.into_iter().flatten() {
        results[position] = Some(result);
    }
    results
        .into_iter()
        .map(|result| result.expect("every selected operation ran"))
        .collect()
}

// State belongs to one bounded input chunk and is discarded before returning.
// Metadata lookups can reuse a held parent for adjacent siblings, while later
// requests resolve the namespace afresh. No state is shared between workers.
fn parallel_map_init<T: Sync, R: Send, S>(
    items: &[T],
    init: impl Fn() -> S + Sync,
    f: impl Fn(&mut S, &T) -> R + Sync,
) -> Vec<R> {
    parallel_map_init_from(PAR_MIN, items, init, f)
}

fn parallel_map_init_from<T: Sync, R: Send, S>(
    minimum: usize,
    items: &[T],
    init: impl Fn() -> S + Sync,
    f: impl Fn(&mut S, &T) -> R + Sync,
) -> Vec<R> {
    if items.len() < minimum {
        let mut state = init();
        return items.iter().map(|item| f(&mut state, item)).collect();
    }
    let Some(pool) = metadata_pool() else {
        let mut state = init();
        return items.iter().map(|item| f(&mut state, item)).collect();
    };
    let chunk = items.len().div_ceil(PAR_THREADS).max(1);
    use rayon::prelude::*;
    pool.install(|| {
        items
            .par_chunks(chunk)
            .flat_map_iter(|chunk| {
                let mut state = init();
                let f = &f;
                chunk.iter().map(move |item| f(&mut state, item))
            })
            .collect()
    })
}

/// Hash exactly `len` bytes in fixed blocks. A short reader contributes the
/// bytes it has and empty hashes for the missing blocks, matching both source
/// and destination behavior through one implementation.
#[cfg(test)]
fn hash_reader(reader: &mut impl Read, block: u64, len: u64) -> Result<Vec<ContentDigest>> {
    hash_reader_observed(
        reader,
        block,
        len,
        None,
        crate::hashing::HashAlgorithm::Blake3,
    )
}
fn observed_write(
    actor: &Arc<crate::transfer_observations::Actor>,
    file: &File,
    data: &[u8],
    off: u64,
    sparse: bool,
) -> std::io::Result<()> {
    let writing = actor.span(crate::transfer_observations::Stage::DestinationWrite);
    write_data(file, data, off, sparse)?;
    writing.bytes(data.len() as u64);
    Ok(())
}

/// Write a file's whole new contents from its start over `old_len` bytes of
/// old contents that may lie there, as an in-place update does. Sparse zero
/// runs over old bytes clear them rather than being skipped. The caller sets
/// the final length afterwards, so the old contents are never cut first.
fn observed_overwrite(
    actor: &Arc<crate::transfer_observations::Actor>,
    file: &File,
    data: &[u8],
    old_len: u64,
    sparse: bool,
) -> std::io::Result<()> {
    let writing = actor.span(crate::transfer_observations::Stage::DestinationWrite);
    #[cfg(debug_assertions)]
    fail_inplace_write_for_test()?;
    if sparse {
        crate::sparse::write_at(file, data, 0, old_len > 0)?;
    } else {
        file.write_all_at(data, 0)?;
    }
    writing.bytes(data.len() as u64);
    Ok(())
}

/// Tests make in-place small-file writes fail, as a destination that
/// refuses writes to existing files does.
#[cfg(debug_assertions)]
fn fail_inplace_write_for_test() -> std::io::Result<()> {
    if std::env::var_os("SYQ_TEST_FAIL_INPLACE_PUT").is_some() {
        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

/// `observed_write` for a caller that records the write itself.
fn write_data(file: &File, data: &[u8], off: u64, sparse: bool) -> std::io::Result<()> {
    if sparse {
        crate::sparse::write_at(file, data, off, false)?;
        crate::sparse::set_len(file, off + data.len() as u64)
    } else {
        file.write_all_at(data, off)
    }
}
fn hash_reader_observed(
    reader: &mut impl Read,
    block: u64,
    len: u64,
    actor: Option<&Arc<crate::transfer_observations::Actor>>,
    algorithm: crate::hashing::HashAlgorithm,
) -> Result<Vec<ContentDigest>> {
    if !hash_response_fits(block, len) {
        bail!("hash block size or response count is outside protocol limits");
    }
    let n = usize::try_from(len.div_ceil(block)).context("hash count exceeds this platform")?;
    let mut hashes = Vec::with_capacity(n);
    let mut buf = vec![0u8; block.min(len) as usize];
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(block) as usize;
        let mut got = 0;
        while got < want {
            let read = {
                let reading =
                    actor.map(|a| a.span(crate::transfer_observations::Stage::SourceRead));
                let n = reader.read(&mut buf[got..want])?;
                if let Some(reading) = reading {
                    reading.bytes(n as u64);
                }
                n
            };
            if read == 0 {
                break;
            }
            got += read;
        }
        {
            let _hash = actor.map(|a| a.span(crate::transfer_observations::Stage::Hashing));
            hashes.push(algorithm.hash(&buf[..got]));
        }
        if got < want {
            while hashes.len() < n {
                hashes.push(algorithm.hash(&[]));
            }
            break;
        }
        remaining -= want as u64;
    }
    Ok(hashes)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod completion_details_tests {
    use super::*;

    #[test]
    fn detailed_listing_is_bounded_and_obeys_directory_confinement() {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("alpha"), b"hello").unwrap();
        std::fs::write(root.join("alpine"), b"other").unwrap();
        let request = |directory: &Path, limit| Request::ListDirDetails {
            directory: directory.as_os_str().as_bytes().to_vec(),
            confined_root: Some(root.as_os_str().as_bytes().to_vec()),
            prefix: b"al".to_vec(),
            limit,
            symlink_policy: OperatorSymlinkPolicy::Refuse,
        };
        let response = FsOps::new().handle(&request(&root, 1));
        let Response::DetailedDirectoryEntries {
            entries,
            details,
            truncated,
        } = response
        else {
            panic!("{response:?}");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(details.len(), 1);
        assert!(details[0].contains("5 B"));
        assert!(truncated);
        assert!(
            matches!(FsOps::new().handle(&request(&root, 0)), Response::DetailedDirectoryEntries { entries, details, truncated: false } if entries.is_empty() && details.is_empty())
        );
        assert!(matches!(
            FsOps::new().handle(&request(temporary.path(), 10)),
            Response::Err(_) | Response::EndpointError(_)
        ));
        let link = temporary.path().join("link");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert!(matches!(
            FsOps::new().handle(&request(&link, 10)),
            Response::Err(_) | Response::EndpointError(_)
        ));
    }
}

#[cfg(test)]
#[path = "fsops_dispatch_tests.rs"]
mod dispatch_tests;
