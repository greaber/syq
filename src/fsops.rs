//! Local filesystem operations. Used directly by the local endpoint and
//! by `syq --server` for remote endpoints, so both sides behave identically.

use crate::descriptor_broker::{
    claim_descriptor, DescriptorSessionSlot, DescriptorTicket, RegisteredRootId, DEFAULT_MAX_ROOTS,
};
use crate::proto::*;
use crate::rooted::{
    read_open_symlink, root_metadata_from_std, OperatorFinalComponent, OperatorResolver,
    PinnedPath, RelativePath, Root, RootIdentity, RootMetadata,
};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
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

#[cfg(debug_assertions)]
fn test_race_barrier(
    ready_env: &str,
    continue_env: &str,
    hold_env: &str,
    label: &str,
) -> Result<()> {
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
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
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
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    if let Some(ms) = std::env::var_os(hold_env) {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[derive(Default)]
struct NameMaxCache {
    paths: HashMap<PathBuf, usize>,
    devices: HashMap<u64, usize>,
}

pub(crate) fn content_digest(data: &[u8]) -> ContentDigest {
    *blake3::hash(data).as_bytes()
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FileSystemTraits {
    is_nfs: bool,
    synchronous: bool,
    measured_local_source: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum FileSystemKey {
    Mount(u64),
    Device(u64),
}

// The same-machine copy fast path exists only on Linux; other platforms
// report every request as unsupported without reading the policy.
#[derive(Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct CopyLocalPolicy {
    inplace: bool,
    allow_sequential_nfs_fallback: bool,
}

#[derive(Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum CopyLocalOutcome {
    Copied,
    Unsupported,
}

#[cfg(target_os = "linux")]
fn discard_rooted_copy_partial(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    expected_dev: u64,
    expected_ino: u64,
) -> Result<()> {
    match root.metadata_optional(relative)? {
        Some(current)
            if is_safe_rooted_partial(current)
                && current.dev == expected_dev
                && current.ino == expected_ino =>
        {
            root.unlink(relative)
                .with_context(|| format!("remove {}", label.display()))?;
        }
        Some(_) | None => {}
    }
    Ok(())
}

#[cfg(all(debug_assertions, target_os = "linux"))]
fn hold_copy_local_before_destination_open_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_COPY_LOCAL_READY_FILE") {
        fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write local-copy-ready signal {}",
                Path::new(&ready).display()
            )
        })?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_COPY_LOCAL_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn inspect_file_system(file: &File) -> FileSystemTraits {
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
fn file_system_key(file: &File, dev: u64) -> FileSystemKey {
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
    if result == 0 {
        let stat = unsafe { stat.assume_init() };
        if stat.stx_mask & libc::STATX_MNT_ID != 0 {
            return FileSystemKey::Mount(stat.stx_mnt_id);
        }
    }
    FileSystemKey::Device(dev)
}

#[cfg(target_os = "linux")]
fn file_system_traits(file: &File, key: FileSystemKey) -> FileSystemTraits {
    static FILE_SYSTEMS: OnceLock<Mutex<HashMap<FileSystemKey, FileSystemTraits>>> =
        OnceLock::new();
    let file_systems = FILE_SYSTEMS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(traits) = file_systems.lock().unwrap().get(&key).copied() {
        return traits;
    }
    let traits = inspect_file_system(file);
    file_systems.lock().unwrap().insert(key, traits);
    traits
}

#[cfg(target_os = "linux")]
fn unsupported_copy_pairs() -> &'static Mutex<HashSet<(FileSystemKey, FileSystemKey)>> {
    static PAIRS: OnceLock<Mutex<HashSet<(FileSystemKey, FileSystemKey)>>> = OnceLock::new();
    PAIRS.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(target_os = "linux")]
fn copy_destination_mounts() -> &'static Mutex<HashMap<PathBuf, FileSystemKey>> {
    static MOUNTS: OnceLock<Mutex<HashMap<PathBuf, FileSystemKey>>> = OnceLock::new();
    MOUNTS.get_or_init(|| Mutex::new(HashMap::new()))
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
                    bail!("destination directory appeared after the new-path precondition")
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
                            bail!("destination directory appeared after the new-path precondition")
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

    /// Compare an effective directory beneath this retained operator
    /// selection with an exact opened source directory. Existing components
    /// are opened without following symlinks. Once a missing or non-directory
    /// component is reached, the remaining virtual suffix is interpreted
    /// component by component so `.` and `..` retain kernel path semantics.
    fn relation_to_source(&self, source: &File, suffix: &[u8]) -> Result<DirectoryRelation> {
        if suffix.starts_with(b"/") {
            bail!("destination ancestry suffix must be relative");
        }
        if suffix.contains(&0) {
            bail!("destination ancestry suffix contains NUL");
        }

        let source_metadata = source
            .metadata()
            .context("inspect source directory capability")?;
        if !source_metadata.is_dir() {
            bail!("destination ancestry source capability is not a directory");
        }

        let mut directory = self
            .directory
            .try_clone()
            .context("duplicate retained destination directory")?;
        let mut components = self.missing.clone();
        components.extend(
            suffix
                .split(|byte| *byte == b'/')
                .filter(|component| !component.is_empty())
                .map(<[u8]>::to_vec),
        );
        let mut virtual_components: Vec<Vec<u8>> = Vec::new();

        while let Some(component) = components.pop_front() {
            if component == b"." {
                continue;
            }
            if component == b".." {
                if virtual_components.pop().is_none() {
                    directory = open_operator_directory_at(&directory, b"..")
                        .context("open retained destination parent")?;
                }
                continue;
            }
            if !virtual_components.is_empty() {
                virtual_components.push(component);
                continue;
            }
            match open_operator_directory_at(&directory, &component) {
                Ok(child) => directory = child,
                Err(error) if absent_or_nondirectory(&error) => {
                    // A missing entry, regular file, or symlink will either be
                    // replaced as a directory beneath this parent or make the
                    // copy fail. It must never be followed for this decision.
                    virtual_components.push(component);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "inspect effective destination component {:?}",
                            OsStr::from_bytes(&component)
                        )
                    })
                }
            }
        }

        opened_directory_relation(
            directory,
            source_metadata.dev(),
            source_metadata.ino(),
            !virtual_components.is_empty(),
        )
    }
}

fn absent_or_nondirectory(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|errno| matches!(errno, libc::ENOENT | libc::ENOTDIR | libc::ELOOP))
    })
}

/// Walk parents from an already-open destination directory. The source
/// descriptor stays open for the whole query, so device/inode reuse cannot
/// turn the comparison into pathname authority.
fn opened_directory_relation(
    mut directory: File,
    source_dev: u64,
    source_ino: u64,
    virtual_descendant: bool,
) -> Result<DirectoryRelation> {
    let mut below_candidate = virtual_descendant;
    loop {
        let metadata = directory
            .metadata()
            .context("inspect effective destination directory")?;
        if (metadata.dev(), metadata.ino()) == (source_dev, source_ino) {
            return Ok(if below_candidate {
                DirectoryRelation::Descendant
            } else {
                DirectoryRelation::Same
            });
        }
        let parent = open_operator_directory_at(&directory, b"..")
            .context("walk effective destination ancestry")?;
        let parent_metadata = parent
            .metadata()
            .context("inspect effective destination parent")?;
        if (parent_metadata.dev(), parent_metadata.ino()) == (metadata.dev(), metadata.ino()) {
            return Ok(DirectoryRelation::Separate);
        }
        directory = parent;
        below_candidate = true;
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
        PinnedPath::OpenFile(_) => {
            unreachable!("directory selection never opens a procfs input")
        }
    }
}

fn resolve_operator_entry(
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
    allow_missing_final: bool,
    follow_final_symlink: bool,
    readable_final: bool,
) -> Result<(PathBuf, PinnedPath)> {
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
    let selected = OperatorResolver::resolve_process(
        raw,
        symlink_policy,
        if readable_final {
            OperatorFinalComponent::ReadableEntry {
                follow_symlink: follow_final_symlink,
            }
        } else {
            OperatorFinalComponent::Entry {
                follow_symlink: follow_final_symlink,
            }
        },
        allow_missing_final,
        &mut hops,
    )?;
    Ok((path, selected))
}

#[cfg(debug_assertions)]
fn hold_operator_control_path_for_test(path: &Path) -> Result<()> {
    let Some(expected) = std::env::var_os("SYQ_TEST_CONTROL_PATH") else {
        return Ok(());
    };
    if expected.as_bytes() != path.as_os_str().as_bytes() {
        return Ok(());
    }
    if let Some(ready) = std::env::var_os("SYQ_TEST_CONTROL_PATH_READY_FILE") {
        fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write control-path-ready signal {}",
                Path::new(&ready).display()
            )
        })?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_CONTROL_PATH_MS") {
        let ms = ms
            .to_string_lossy()
            .parse::<u64>()
            .context("parse SYQ_TEST_HOLD_CONTROL_PATH_MS")?;
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_operator_control_path_for_test(_path: &Path) -> Result<()> {
    Ok(())
}

/// Open an existing operator-supplied input and retain the identity
/// selected by the component walk. A namespace replacement after resolution
/// is reported rather than followed.
pub(crate) fn open_operator_file_read(
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<File> {
    if path.ends_with(b"/") {
        bail!("operator file path has a trailing slash");
    }
    let (path, selected) = resolve_operator_entry(path, symlink_policy, false, true, true)?;
    hold_operator_control_path_for_test(&path)?;
    match selected {
        PinnedPath::Leaf(leaf) => leaf.open_read(),
        PinnedPath::OpenFile(file) => Ok(file),
        PinnedPath::Directory(_) => bail!("operator path selects a directory, not a regular file"),
        PinnedPath::Missing(_) => Err(io::Error::from_raw_os_error(libc::ENOENT).into()),
    }
}

/// Select an operator-supplied ordinary output and create it through retained
/// descriptors. An existing final entry is always refused; a missing entry is
/// created exclusively beneath its pinned parent.
pub(crate) fn create_operator_file(
    path: &[u8],
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<File> {
    if path.ends_with(b"/") {
        bail!("operator file path has a trailing slash");
    }
    let (path, selected) = resolve_operator_entry(path, symlink_policy, true, true, false)?;
    hold_operator_control_path_for_test(&path)?;
    match selected {
        PinnedPath::Leaf(_) | PinnedPath::Directory(_) => {
            Err(io::Error::from(io::ErrorKind::AlreadyExists).into())
        }
        PinnedPath::Missing(missing) => missing.create_regular(0o666),
        PinnedPath::OpenFile(_) => unreachable!("output resolution never opens a procfs input"),
    }
}

fn operator_directory_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(target_os = "macos")]
    {
        libc::O_SEARCH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
            // O_DIRECTORY is the kernel-enforced type check. Repeating it with
            // fstat costs another metadata operation on network filesystems.
            return Ok(unsafe { File::from_raw_fd(fd) });
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
    static CACHE: OnceLock<Mutex<NameMaxCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(NameMaxCache::default()));
    name_max_cached(parent, cache, |_candidate, directory| {
        let limit = unsafe { libc::fpathconf(directory.as_raw_fd(), libc::_PC_NAME_MAX) };
        if limit > 0 {
            limit as usize
        } else {
            COMMON_NAME_MAX
        }
    })
}

fn name_max_cached(
    parent: &Path,
    cache: &Mutex<NameMaxCache>,
    query: impl Fn(&Path, &File) -> usize,
) -> usize {
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let key = lexical_absolute(parent);
    if let Some(limit) = cache.lock().unwrap().paths.get(&key).copied() {
        return limit;
    }

    // Resolve from a retained root one component at a time. A pathname lstat
    // would still follow symlinks in intermediate components when a descendant
    // exists. Planning replaces such a symlink instead, so descendants inherit
    // the containing real directory's filesystem limit.
    let Ok(root) = Root::open(Path::new("/")) else {
        return COMMON_NAME_MAX;
    };
    let Ok(relative) = key.strip_prefix(Path::new("/")) else {
        return COMMON_NAME_MAX;
    };
    let Ok(relative) = RelativePath::new(relative.as_os_str().as_bytes()) else {
        return COMMON_NAME_MAX;
    };
    let Ok((directory, consumed)) = root.open_nearest_directory(&relative) else {
        return COMMON_NAME_MAX;
    };
    let mut candidate = PathBuf::from("/");
    for component in key
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => Some(component),
            _ => None,
        })
        .take(consumed)
    {
        candidate.push(component);
    }
    let Ok(metadata) = directory.metadata() else {
        return COMMON_NAME_MAX;
    };
    let dev = metadata.dev();
    let cached = cache.lock().unwrap().devices.get(&dev).copied();
    let limit = cached.unwrap_or_else(|| query(&candidate, &directory));
    let mut cache = cache.lock().unwrap();
    if cache.paths.len() >= NAME_MAX_CACHE_CAP {
        cache.paths.clear();
    }
    cache.devices.entry(dev).or_insert(limit);
    cache.paths.insert(candidate, limit);
    cache.paths.insert(key, limit);
    limit
}

fn lexical_absolute(path: &Path) -> PathBuf {
    use std::path::Component;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    normalized
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

fn cstr(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| anyhow!("path contains NUL"))
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

static PROCESS_UMASK: OnceLock<u32> = OnceLock::new();

/// Record the file-creation mask while the process is still single-threaded.
/// `main` calls this before anything can spawn a thread, so the portable
/// probe in `read_process_umask` never races another file creation.
pub(crate) fn capture_process_umask() {
    PROCESS_UMASK.get_or_init(read_process_umask);
}

/// The process file-creation mask captured at startup. A caller that runs
/// without `main`, such as a unit test, reads it lazily instead.
pub(crate) fn process_umask() -> u32 {
    *PROCESS_UMASK.get_or_init(read_process_umask)
}

/// Linux publishes the mask in `/proc/self/status` (kernel 4.7 and later),
/// which avoids the umask(2) set-and-restore window during which another
/// thread would create files with the probe mask. Elsewhere the probe is the
/// only option, so it must run while the process is single-threaded.
fn read_process_umask() -> u32 {
    #[cfg(target_os = "linux")]
    if let Some(mask) = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_proc_status_umask(&status))
    {
        return mask;
    }
    probe_umask()
}

#[cfg(target_os = "linux")]
fn parse_proc_status_umask(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
        .filter(|mask| *mask <= 0o777)
}

fn probe_umask() -> u32 {
    // SAFETY: umask(2) only exchanges the process mask and the original is
    // restored at once; `capture_process_umask` runs this before any thread
    // exists, so no other file creation can observe the probe value.
    unsafe {
        let mask = libc::umask(0o022);
        libc::umask(mask);
        mask as u32
    }
}

/// Read this process's open-file limits.
pub(crate) fn nofile_limits() -> io::Result<libc::rlimit> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only into the local struct passed by pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(limits)
}

/// Replace this process's open-file limits.
pub(crate) fn set_nofile_limits(limits: &libc::rlimit) -> io::Result<()> {
    // SAFETY: setrlimit only reads the struct behind the pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, limits) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    let limit = nofile_limits().context("read source endpoint file limit")?;
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
}

struct HeldBasis {
    location: FileLocation,
    label: PathBuf,
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
    id: &'a PartialId,
    guard: Option<&'a ContainerGuard>,
}

struct PrepareOptions {
    size: u64,
    inplace: bool,
    mode: u32,
    attempt: u32,
    create_if_missing: bool,
}

struct HashOptions {
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
        let selection = self
            .operator_selection
            .as_ref()
            .context("destination directory was not checked on this connection")?;
        checks
            .iter()
            .map(|check| {
                if !check.source_root.is_directory() {
                    bail!("destination ancestry requires a source directory ticket");
                }
                let source = claim_descriptor(&check.source_root)
                    .context("claim exact source directory for destination ancestry")?;
                check
                    .suffixes
                    .iter()
                    .map(|suffix| selection.relation_to_source(&source, suffix))
                    .collect()
            })
            .collect()
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
        test_race_barrier(
            "SYQ_TEST_DESTINATION_ANCHORED_FILE",
            "SYQ_TEST_DESTINATION_ANCHOR_CONTINUE_FILE",
            "SYQ_TEST_HOLD_DESTINATION_ANCHOR_MS",
            "destination-anchor-ready",
        )?;
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
                PinnedPath::OpenFile(_) => {
                    unreachable!("source resolution never opens a procfs control input")
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
        test_race_barrier(
            "SYQ_TEST_SOURCE_ROOTS_REGISTERED_FILE",
            "SYQ_TEST_SOURCE_ROOTS_CONTINUE_FILE",
            "SYQ_TEST_HOLD_SOURCE_ROOTS_MS",
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
    #[cfg(target_os = "linux")]
    pub(crate) fn initialize_copy_sources(
        &mut self,
        sources: &[RegisteredSourceRoot],
    ) -> Result<()> {
        if self.destination_root.is_none() {
            bail!("local copy sources require a registered destination root");
        }
        if sources.iter().any(|source| source.allow_unconfined_paths) {
            bail!("local copy sources must be confined registered capabilities");
        }
        self.initialize_source_capabilities(sources, true)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn initialize_copy_sources(
        &mut self,
        _sources: &[RegisteredSourceRoot],
    ) -> Result<()> {
        bail!("same-machine local copy capabilities require Linux")
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
                    claim_descriptor(ticket)
                } else {
                    self.descriptor_session.acquire(ticket)
                }
            };
            let directory = acquire(&source.ticket)?;
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
        if self.source_roots.is_empty() || self.destination_root.is_some() {
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
        self.fds.clear();
        self.fd_order.clear();
        self.held_basis.take();
        self.destination_prefix = Some(request_prefix.to_vec());
        self.destination_root = Some(root);
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
            device: metadata.dev(),
            available_bytes,
            available_inodes,
            empty,
        })
    }

    /// Inspect emptiness through the retained directory itself. The result can
    /// become stale like every unlocked capacity preflight observation, but a
    /// namespace replacement cannot redirect the read outside the capability.
    fn selected_directory_empty(directory: &File) -> Option<bool> {
        let root = Root::from_directory(directory.try_clone().ok()?).ok()?;
        root.read_open_directory(directory)
            .ok()
            .map(|entries| entries.is_empty())
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
        }))
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
            Request::CopyLocal { dst, .. } => map(dst)?,
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
            | Request::ListDir { .. }
            | Request::NativeRemove { .. }
            | Request::CheckOperatorDirectory { .. }
            | Request::CheckOperatorDirectoryAncestry { .. }
            | Request::RegisterSourceRoots { .. }
            | Request::CreateOperatorDirectory { .. }
            | Request::AnchorDestination { .. }
            | Request::DestinationFilesystemInfo { .. }
            | Request::TransportStats
            | Request::Receipt
            | Request::Shutdown => {}
        }
        Ok(req)
    }

    pub fn scan_root(&self, root: &[u8]) -> Result<PathBytes> {
        self.destination_relative(root)
    }

    fn completion_entries(
        &self,
        directory: &[u8],
        confined_root: Option<&[u8]>,
        prefix: &[u8],
        requested_limit: u16,
    ) -> Result<Response> {
        const MAX_COMPLETION_ENTRIES: usize = 1_000;
        if directory.contains(&0)
            || confined_root.is_some_and(|root| root.contains(&0))
            || prefix.contains(&0)
            || prefix.contains(&b'/')
        {
            bail!("invalid completion directory or prefix");
        }
        if let Some(root) = confined_root {
            let resolved_root = std::fs::canonicalize(resolve(root))?;
            let resolved_directory = std::fs::canonicalize(resolve(directory))?;
            if !resolved_directory.starts_with(&resolved_root) {
                bail!("completion directory is outside the requested root");
            }
        }
        let limit = usize::from(requested_limit).min(MAX_COMPLETION_ENTRIES);
        if limit == 0 {
            return Ok(Response::DirectoryEntries {
                entries: Vec::new(),
                truncated: false,
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
                    && std::fs::metadata(item.path()).is_ok_and(|metadata| metadata.is_dir()));
            entries.push(CompletionEntry { name, directory });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(Response::DirectoryEntries { entries, truncated })
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
            location: FileLocation::Path(p.to_path_buf()),
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

    fn cache_file(&mut self, location: FileLocation, attempt: u32, private: bool, file: File) {
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
        self.fds.insert(key.clone(), file);
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
        self.fds.get(&key).map(File::try_clone).transpose()
    }

    fn uncache(&mut self, p: &Path) -> Option<File> {
        self.uncache_location(&FileLocation::Path(p.to_path_buf()))
    }

    fn uncache_rooted(&mut self, root: &Root, relative: &RelativePath) -> Option<File> {
        self.uncache_location(&FileLocation::Rooted {
            root: root.identity(),
            relative: relative.clone(),
        })
    }

    fn uncache_location(&mut self, location: &FileLocation) -> Option<File> {
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
    ) -> Result<&File> {
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
            if self.destination_root.is_some() {
                bail!("source stat is not valid on a destination worker");
            }
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
        partial_id: &PartialId,
        guard: Option<&ContainerGuard>,
    ) -> Vec<std::result::Result<PathBytes, String>> {
        parallel_map(paths, |path| {
            let requested = Path::new(OsStr::from_bytes(path));
            let resolved = if let Some(target) = self.rooted_destination_target(path, guard)? {
                rooted_partial_target(&target, partial_id)?.1
            } else {
                self.partial_path(&resolve(path), partial_id)?
            };
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
    pub fn apply(&mut self, ops: &[Op], guard: Option<&ContainerGuard>) -> Vec<Option<WireError>> {
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
        let mut out: Vec<Option<WireError>> = vec![None; ops.len()];
        let gres = parallel_map(&guarded_idx, |&i| {
            apply_one(&ops[i], guard, destination_root.clone(), destination_prefix)
                .err()
                .as_ref()
                .map(wire_error)
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
                .map(wire_error)
        });
        for (i, r) in create_idx.iter().zip(cres) {
            out[*i] = r;
        }
        let mres = parallel_map(&meta_idx, |&i| {
            apply_one(&ops[i], guard, destination_root.clone(), destination_prefix)
                .err()
                .as_ref()
                .map(wire_error)
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
    fail_apply_capacity_for_test(
        registered_target
            .as_ref()
            .map_or_else(|| resolve(op_path(op)), |target| target.label.clone())
            .as_path(),
    )?;
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

fn error_is_kind(error: &anyhow::Error, kind: io::ErrorKind) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .is_some_and(|error| error.kind() == kind)
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
                // The coordinator resolves an explicitly supplied root
                // symlink. Symlinks found inside the destination tree are
                // payload conflicts and must be replaced, never traversed.
                match condition {
                    TargetCondition::Absent => mkdir_with_parent_fallback(&p, *mode),
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let md = require_target_condition(&p, *condition)?
                            .expect("matching destination condition returns metadata");
                        if !md.is_dir() {
                            bail!(
                                "destination {} cannot change type under --as-existing",
                                p.display()
                            );
                        }
                        make_dir_writable(&p, &md)
                    }
                    TargetCondition::Any => mkdir_or_existing_dir(&p, *mode),
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
                    TargetCondition::Any => return create_symlink_any(&p, target),
                    TargetCondition::Absent => {}
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let metadata = require_target_condition(&p, *condition)?
                            .expect("matching destination condition returns metadata");
                        if !metadata.file_type().is_symlink() {
                            bail!(
                                "destination {} cannot change type under --as-existing",
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
                    TargetCondition::Any => return create_node_any(&p, *mode, *rdev),
                    TargetCondition::Absent => {}
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let metadata = require_target_condition(&p, *condition)?
                            .expect("matching destination condition returns metadata");
                        if file_type_bits(metadata.mode()) != file_type_bits(*mode) {
                            bail!(
                                "destination {} cannot change type under --as-existing",
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
                        bail!(
                            "destination {} appeared before metadata update",
                            p.display()
                        )
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
                require_open_target_known(&md, &p, *condition)?;
                set_meta_handle_known_portable(&file, meta, *flags, &md)
                    .with_context(|| format!("set metadata {}", p.display()))?;
                require_named_target_identity_known(&md, &p, *condition)
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
    relative: RelativePath,
    label: PathBuf,
}

struct RootedTarget {
    root: Arc<Root>,
    relative: RelativePath,
    label: PathBuf,
    create_missing_parents: bool,
}

impl RootedTarget {
    fn location(&self) -> FileLocation {
        FileLocation::Rooted {
            root: self.root.identity(),
            relative: self.relative.clone(),
        }
    }
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

fn rooted_partial_target(
    target: &RootedTarget,
    partial_id: &PartialId,
) -> Result<(RelativePath, PathBuf)> {
    let relative_path = target.relative.to_path_buf();
    let component_limit = target.root.name_max_for_parent(&target.relative)?;
    // Derive the visible component from the logical command-line spelling so
    // PartialPaths and every state-machine request keep one stable sidecar
    // name, including the PATH_MAX compact form. Only the resulting component
    // is placed beneath the retained root.
    let label = partial_path_with_name_max(&target.label, partial_id, component_limit)?;
    let name = label
        .file_name()
        .context("partial path has no final component")?;
    let relative_partial = relative_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(name);
    Ok((
        RelativePath::new(relative_partial.as_os_str().as_bytes())?,
        label,
    ))
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
        relative,
        label: target,
    })
}

fn relative_under(root: &Path, target: &Path) -> Result<RelativePath> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "destination {} is outside guarded root {}",
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
                "destination {} appeared before no-replace creation",
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
                "destination {} changed before it could be replaced",
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
            if matches!(condition, TargetCondition::Any | TargetCondition::Absent) {
                match root.create_directory(path, (*mode & 0o7777) | 0o700) {
                    Ok(()) => return Ok(()),
                    Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                        if *condition == TargetCondition::Absent {
                            bail!(
                                "destination {} appeared before no-replace creation",
                                target.label.display()
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
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
                    "destination {} cannot change type under a matched condition",
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
        } => {
            if matches!(condition, TargetCondition::Any | TargetCondition::Absent) {
                match root.create_symlink(path, link) {
                    Ok(()) => return Ok(()),
                    Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                        if *condition == TargetCondition::Absent {
                            bail!(
                                "destination {} appeared before no-replace creation",
                                target.label.display()
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            match observe_rooted_condition(target, *condition)? {
                // A matched replacement swaps the new leaf in atomically, so a
                // concurrent replacement of the observed object is refused
                // rather than deleted.
                Some(metadata) if *condition != TargetCondition::Any => {
                    if !metadata.is_symlink() {
                        bail!(
                            "destination {} cannot change type under a matched condition",
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
            }
        }
        Op::Mknod {
            mode,
            rdev,
            condition,
            ..
        } => {
            if matches!(condition, TargetCondition::Any | TargetCondition::Absent) {
                match root.create_node(path, *mode, *rdev) {
                    Ok(()) => return Ok(()),
                    Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                        if *condition == TargetCondition::Absent {
                            bail!(
                                "destination {} appeared before no-replace creation",
                                target.label.display()
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            match observe_rooted_condition(target, *condition)? {
                Some(metadata) if *condition != TargetCondition::Any => {
                    if file_type_bits(metadata.mode) != file_type_bits(*mode) {
                        bail!(
                            "destination {} cannot change type under a matched condition",
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
            }
        }
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
            let opened = file.metadata()?;
            if !opened.file_type().is_file() {
                bail!(
                    "destination {} changed before metadata repair",
                    target.label.display()
                );
            }
            require_open_target_known(&opened, &target.label, *condition)?;
            set_meta_handle_known_portable(&file, meta, *flags, &opened)?;
            require_rooted_named_identity_known(
                &target.root,
                &target.relative,
                &target.label,
                &opened,
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
        let opened = handle.metadata()?;
        require_open_target_known(&opened, &target.label, condition)?;
        set_meta_handle_known_portable(&handle, meta, flags & !flags::TIMES, &opened)?;
        if flags & flags::TIMES != 0
            && (metadata.mtime != meta.mtime || metadata.mtime_nsec != meta.mtime_nsec)
        {
            let times = [
                timespec(0, libc::UTIME_OMIT as u32),
                timespec(meta.mtime, meta.mtime_nsec),
            ];
            target.root.set_times(&target.relative, &times)?;
        }
        return require_rooted_named_identity_known(
            &target.root,
            &target.relative,
            &target.label,
            &opened,
            condition,
        );
    }
    let metadata = target.root.metadata(&target.relative)?;
    require_rooted_condition(metadata, condition, &target.label)?;
    let is_link = metadata.is_symlink();
    let owner_differs = (flags & flags::OWNER != 0 && is_root() && metadata.uid != meta.uid)
        || (flags & flags::GROUP != 0 && metadata.gid != meta.gid);
    let mode_differs =
        flags & flags::MODE_MASK != 0 && !is_link && metadata.mode & 0o7777 != meta.mode & 0o7777;
    let time_differs = flags & flags::TIMES != 0
        && (metadata.mtime != meta.mtime || metadata.mtime_nsec != meta.mtime_nsec);
    if !owner_differs && !mode_differs && !time_differs {
        return Ok(());
    }
    if is_link {
        apply_owner_if_changed(flags, meta, metadata.uid, metadata.gid, |uid, gid| {
            target.root.chown(&target.relative, uid, gid)
        })?;
    } else {
        let handle = target.root.open_metadata(&target.relative)?;
        let opened = handle.metadata()?;
        if opened.dev() != metadata.dev || opened.ino() != metadata.ino {
            bail!(
                "confined destination {} changed while opening it",
                target.label.display()
            );
        }
        require_open_target_known(&opened, &target.label, condition)?;
        // Timestamp mutation is performed separately with no-follow
        // descriptor-relative semantics. All other metadata is applied to
        // the stable opened inode, so a raced leaf symlink cannot redirect it.
        set_meta_handle_known_portable(&handle, meta, flags & !flags::TIMES, &opened)?;
        if time_differs {
            let times = [
                timespec(0, libc::UTIME_OMIT as u32),
                timespec(meta.mtime, meta.mtime_nsec),
            ];
            target.root.set_times(&target.relative, &times)?;
        }
        return require_rooted_named_identity_known(
            &target.root,
            &target.relative,
            &target.label,
            &opened,
            condition,
        );
    }
    if time_differs {
        let times = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        target.root.set_times(&target.relative, &times)?;
    }
    let after = target.root.metadata(&target.relative)?;
    require_rooted_identity(after, condition, &target.label)
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
            bail!(
                "destination {} appeared before metadata update",
                label.display()
            )
        }
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. }
            if (metadata.dev, metadata.ino) == (dev, ino) =>
        {
            Ok(())
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            bail!(
                "destination {} changed during metadata update",
                label.display()
            )
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
            bail!(
                "destination {} appeared before metadata update",
                label.display()
            )
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
            bail!(
                "destination {} changed before metadata update",
                label.display()
            )
        }
    }
}

fn require_rooted_metadata(file: &File, expected: RootMetadata, label: &Path) -> Result<()> {
    let opened = file.metadata()?;
    if opened.dev() != expected.dev || opened.ino() != expected.ino {
        bail!(
            "confined destination {} changed while opening it",
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
    let opened = file.metadata()?;
    require_rooted_named_identity_known(root, relative, label, &opened, condition)
}

fn require_rooted_named_identity_known(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    opened: &fs::Metadata,
    condition: TargetCondition,
) -> Result<()> {
    let (dev, ino) = match condition {
        TargetCondition::Any => (opened.dev(), opened.ino()),
        TargetCondition::Absent => bail!("new destination unexpectedly received metadata repair"),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => (dev, ino),
    };
    let named = root.metadata(relative)?;
    if opened.dev() != dev || opened.ino() != ino || named.dev != dev || named.ino != ino {
        bail!("destination {} changed during update", label.display());
    }
    Ok(())
}

fn condition_identity(condition: TargetCondition) -> Result<(u64, u64)> {
    match condition {
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => Ok((dev, ino)),
        TargetCondition::Any | TargetCondition::Absent => {
            bail!("destination condition does not identify an existing object")
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
        .context("exact replacement destination has no leaf name")?;
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
    test_race_barrier(
        "SYQ_TEST_GUARDED_MUTATION_READY_FILE",
        "SYQ_TEST_GUARDED_MUTATION_CONTINUE_FILE",
        "SYQ_TEST_HOLD_GUARDED_MUTATION_MS",
        "guarded-mutation-ready",
    )
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
                "destination {} appeared after the new-path precondition was checked",
                path.display()
            ),
            Err(error) => Err(error).with_context(|| format!("stat {}", path.display())),
        },
        TargetCondition::Matches { dev, ino } => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.dev() == dev && metadata.ino() == ino => Ok(Some(metadata)),
            Ok(_) | Err(_) => bail!(
                "destination {} changed after the existing-path precondition was checked",
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
                "destination {} changed after the existing-path precondition was checked",
                path.display()
            ),
        },
    }
}

fn require_open_target(file: &File, path: &Path, condition: TargetCondition) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "destination {} appeared after the new-path precondition was checked",
            path.display()
        ),
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            require_open_target_known(&file.metadata()?, path, condition)
        }
    }
}

fn require_open_target_known(
    metadata: &fs::Metadata,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "destination {} appeared after the new-path precondition was checked",
            path.display()
        ),
        TargetCondition::Matches { dev, ino } => {
            if metadata.dev() != dev || metadata.ino() != ino {
                bail!(
                    "destination {} changed after the existing-path precondition was checked",
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
            if metadata.dev() != dev
                || metadata.ino() != ino
                || metadata.ctime() != ctime
                || metadata.ctime_nsec() as u32 != ctime_nsec
            {
                bail!(
                    "destination {} changed after the existing-path precondition was checked",
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
    let metadata = file.metadata()?;
    require_named_target_identity_known(&metadata, path, condition)
}

fn require_named_target_identity_known(
    opened: &fs::Metadata,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "new-destination condition cannot validate an in-place update of {}",
            path.display()
        ),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => {
            let named =
                fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
            if opened.dev() != dev
                || opened.ino() != ino
                || named.dev() != dev
                || named.ino() != ino
            {
                bail!(
                    "destination {} changed during the existing-path update",
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
fn set_meta_handle_known(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    let fd = file.as_raw_fd();
    let empty = c"";
    // Owner first: chown clears setuid/setgid, so mode must follow it.
    let owner_changed =
        apply_owner_if_changed(flags, meta, current.uid(), current.gid(), |uid, gid| {
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
        let current = current.mode() & 0o7777;
        let wanted = meta.mode & 0o7777;
        if current != wanted || (owner_changed && wanted & 0o6000 != 0) {
            set_mode_handle(file, wanted)?;
        }
    }
    if flags & flags::TIMES != 0 {
        bail!("metadata-only O_PATH repair does not support timestamp changes");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_meta_handle_known_portable(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    set_meta_handle_known(file, meta, flags, current)
}

#[cfg(not(target_os = "linux"))]
fn set_meta_handle_known_portable(
    file: &File,
    meta: &Meta,
    flags: u8,
    _current: &fs::Metadata,
) -> Result<()> {
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
fn fail_apply_capacity_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_APPLY_ENOSPC") {
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC))
                .with_context(|| format!("apply {}: injected capacity failure", p.display()));
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
        if let Some(target) = self.rooted_destination_target(path, guard)? {
            let (relative, _) = rooted_partial_target(&target, partial_id)?;
            let partial_size = target
                .root
                .metadata_optional(&relative)?
                .filter(|metadata| is_safe_rooted_partial(*metadata))
                .map(|metadata| metadata.len);
            return Ok(Response::PartialSize(partial_size));
        }
        let p = resolve(path);
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
    fn open_private_partial(
        &mut self,
        pp: &Path,
        create_if_missing: bool,
    ) -> Result<Option<(File, Option<u64>)>> {
        self.uncache(pp);
        if create_if_missing {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(pp)
            {
                Ok(file) => {
                    require_safe_partial(&file, pp)?;
                    return Ok(Some((file, None)));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("create {}", pp.display()))
                }
            }
        }
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
                            return Ok(Some((file, Some(fd_meta.len()))));
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
                Ok(_) if !create_if_missing => return Ok(None),
                Ok(_) => {
                    fs::remove_file(pp).with_context(|| format!("replace {}", pp.display()))?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if !create_if_missing {
                        return Ok(None);
                    }
                    return match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(pp)
                    {
                        Ok(file) => {
                            require_safe_partial(&file, pp)?;
                            Ok(Some((file, None)))
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
        create_if_missing: bool,
    ) -> Result<Option<(File, Option<u64>)>> {
        self.uncache_rooted(root, relative);
        let mut repaired_permissions = false;
        if create_if_missing {
            match root.create_file(relative, 0o600) {
                Ok(file) => return Ok(Some((file, None))),
                Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error),
            }
        }
        for _ in 0..8 {
            match root.metadata_optional(relative)? {
                Some(metadata) if is_safe_rooted_partial(metadata) => {
                    match root.open_regular_read_write(relative) {
                        Ok(file) => {
                            let opened = file.metadata()?;
                            let named = root.metadata(relative)?;
                            if !is_safe_partial(&opened)
                                || !is_safe_rooted_partial(named)
                                || opened.dev() != named.dev
                                || opened.ino() != named.ino
                            {
                                continue;
                            }
                            if opened.mode() & 0o7777 != 0o600 {
                                let repair = (|| -> Result<()> {
                                    fail_partial_chmod_for_test()?;
                                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                                    Ok(())
                                })();
                                if let Err(error) = repair {
                                    drop(file);
                                    discard_safe_rooted_partial_if_same(
                                        root,
                                        relative,
                                        opened.dev(),
                                        opened.ino(),
                                        label,
                                    )
                                    .with_context(|| {
                                        format!(
                                            "replace partial {} after chmod failed: {error:#}",
                                            label.display()
                                        )
                                    })?;
                                    continue;
                                }
                            }
                            return Ok(Some((file, Some(opened.len()))));
                        }
                        Err(error)
                            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                error.kind() == io::ErrorKind::PermissionDenied
                            }) =>
                        {
                            if repaired_permissions {
                                discard_safe_rooted_partial_if_same(
                                    root,
                                    relative,
                                    metadata.dev,
                                    metadata.ino,
                                    label,
                                )
                                .with_context(|| {
                                    format!(
                                        "replace partial {} after it remained unreadable",
                                        label.display()
                                    )
                                })?;
                                repaired_permissions = false;
                                continue;
                            }
                            let handle = match root.open_metadata(relative) {
                                Ok(handle) => handle,
                                Err(repair_error) => {
                                    discard_safe_rooted_partial_if_same(
                                        root,
                                        relative,
                                        metadata.dev,
                                        metadata.ino,
                                        label,
                                    )
                                    .with_context(|| {
                                        format!(
                                            "replace partial {} after permission repair failed: {repair_error:#}",
                                            label.display()
                                        )
                                    })?;
                                    continue;
                                }
                            };
                            require_rooted_metadata(&handle, metadata, label)?;
                            let repair = (|| -> Result<()> {
                                fail_partial_chmod_for_test()?;
                                set_mode_handle(&handle, 0o600)?;
                                Ok(())
                            })();
                            if let Err(error) = repair {
                                drop(handle);
                                discard_safe_rooted_partial_if_same(
                                    root,
                                    relative,
                                    metadata.dev,
                                    metadata.ino,
                                    label,
                                )
                                .with_context(|| {
                                    format!(
                                        "replace partial {} after chmod failed: {error:#}",
                                        label.display()
                                    )
                                })?;
                                continue;
                            }
                            repaired_permissions = true;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Some(_) if !create_if_missing => return Ok(None),
                Some(_) => root.unlink(relative)?,
                None if !create_if_missing => return Ok(None),
                None => match root.create_file(relative, 0o600) {
                    Ok(file) => return Ok(Some((file, None))),
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

    fn preallocate_new_partial(&mut self, file: &File, size: u64) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let dev = file.metadata()?.dev();
            let key = file_system_key(file, dev);
            let traits = file_system_traits(file, key);
            #[cfg(debug_assertions)]
            let traits = FileSystemTraits {
                is_nfs: traits.is_nfs || std::env::var_os("SYQ_TEST_DESTINATION_NFS").is_some(),
                ..traits
            };
            preallocate_new_file(file, size, traits)
        }
        #[cfg(not(target_os = "linux"))]
        {
            preallocate_new_file(file, size)
        }
    }

    fn prepare(
        &mut self,
        target: PartialTarget<'_>,
        options: PrepareOptions,
    ) -> Result<Option<u64>> {
        let PartialTarget {
            path,
            id: partial_id,
            guard,
        } = target;
        let PrepareOptions {
            size,
            inplace,
            mode,
            attempt,
            create_if_missing,
        } = options;
        if let Some(target) = self.rooted_destination_target(path, guard)? {
            if inplace {
                self.uncache_rooted(&target.root, &target.relative);
                // An interrupted non-inplace run must not strand this job's
                // adjacent sidecar when the retry switches to --inplace.
                if let Ok((partial, _)) = rooted_partial_target(&target, partial_id) {
                    let _ = target.root.unlink(&partial);
                }
                for _ in 0..8 {
                    match target.root.metadata_optional(&target.relative)? {
                        Some(metadata) if metadata.is_file() => {
                            // Retain a descriptor that can service the
                            // immediately following destination hash as well
                            // as range writes.
                            let file = target.root.open_regular_read_write(&target.relative)?;
                            require_rooted_metadata(&file, metadata, &target.label)?;
                            file.set_len(size).with_context(|| {
                                format!("resize confined file {}", target.label.display())
                            })?;
                            self.cache_file(target.location(), attempt, false, file);
                            return Ok(None);
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
                                self.cache_file(target.location(), attempt, false, file);
                                return Ok(None);
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
            let (relative, label) = rooted_partial_target(&target, partial_id)?;
            let Some((file, basis_size)) = self.open_private_partial_rooted(
                &target.root,
                &relative,
                &label,
                create_if_missing,
            )?
            else {
                return Ok(None);
            };
            if let Some(old_size) = basis_size {
                if old_size > size {
                    file.set_len(size)?;
                }
            } else {
                self.preallocate_new_partial(&file, size)?;
            }
            #[cfg(debug_assertions)]
            test_race_barrier(
                "SYQ_TEST_PARTIAL_READY_FILE",
                "SYQ_TEST_PARTIAL_CONTINUE_FILE",
                "SYQ_TEST_HOLD_PARTIAL_MS",
                "partial-ready",
            )?;
            self.cache_file(
                FileLocation::Rooted {
                    root: target.root.identity(),
                    relative,
                },
                attempt,
                true,
                file,
            );
            return Ok(basis_size);
        }
        let p = resolve(path);
        if inplace {
            self.uncache(&p);
            // A stale partial from an interrupted run would otherwise be orphaned.
            if let Ok(pp) = self.partial_path(&p, partial_id) {
                let _ = fs::remove_file(pp);
            }
            // Prepare retains this descriptor for both the destination hash
            // and subsequent range writes.
            let f = open_regular_read_write(&p, mode, false)?;
            f.set_len(size)?;
            self.cache_file(FileLocation::Path(p.clone()), attempt, false, f);
            return Ok(None);
        }
        let pp = self.partial_path(&p, partial_id)?;
        let Some((f, basis_size)) = self.open_private_partial(&pp, create_if_missing)? else {
            return Ok(None);
        };
        if let Some(old_size) = basis_size {
            if old_size > size {
                f.set_len(size)?;
            }
        } else {
            self.preallocate_new_partial(&f, size)?;
        }
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_PARTIAL_READY_FILE",
            "SYQ_TEST_PARTIAL_CONTINUE_FILE",
            "SYQ_TEST_HOLD_PARTIAL_MS",
            "partial-ready",
        )?;
        self.cache_file(FileLocation::Path(pp), attempt, true, f);
        Ok(basis_size)
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
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_HASH_BASIS").is_some() {
            bail!("injected retained-basis hash failure");
        }
        let rooted = self.rooted_destination_target(path, guard)?;
        let (mut file, location, label) = if let Some(target) = &rooted {
            (
                target.root.open_regular_read(&target.relative)?,
                target.location(),
                target.label.clone(),
            )
        } else {
            let p = resolve(path);
            open_existing_regular(&p, false)
                .with_context(|| format!("open {} as repair basis", p.display()))
                .map(|file| (file, FileLocation::Path(p.clone()), p))?
        };
        require_open_target(&file, &label, condition)?;
        let hashes = hash_reader(&mut file, block, len)?;
        self.held_basis = Some(HeldBasis {
            location,
            label,
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

    fn take_held_basis(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        guard: Option<&ContainerGuard>,
    ) -> Result<(HeldBasis, Option<RootedTarget>)> {
        let held = self
            .held_basis
            .take()
            .context("no retained destination basis")?;
        let rooted = self.rooted_destination_target(path, guard)?;
        let expected = rooted
            .as_ref()
            .map(RootedTarget::location)
            .unwrap_or_else(|| FileLocation::Path(resolve(path)));
        if held.location != expected || held.partial_id != *partial_id {
            bail!("retained destination basis does not match requested file");
        }
        Ok((held, rooted))
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
        let (held, rooted) = self.take_held_basis(path, partial_id, guard)?;
        require_open_target(&held.file, &held.label, condition)?;
        set_meta_file(&held.file, meta, flags)
            .with_context(|| format!("set metadata on basis {}", held.label.display()))?;
        if let Some(target) = rooted {
            if guard.is_some() {
                // A signed receiver keeps the pre-existing guarded behavior:
                // even an `Any` update must still be attached to its enrolled
                // name. An unrestricted content-identical repair preserves
                // the ordinary retry semantics below, where `Any` may finish
                // through the retained inode after a concurrent publication.
                require_rooted_named_identity(
                    &target.root,
                    &target.relative,
                    &target.label,
                    &held.file,
                    condition,
                )?;
            } else if condition != TargetCondition::Any {
                require_rooted_named_identity(
                    &target.root,
                    &target.relative,
                    &target.label,
                    &held.file,
                    condition,
                )?;
            }
        } else {
            require_named_target_identity(&held.file, &held.label, condition)?;
        }
        Ok(())
    }

    pub fn seed_basis(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        len: u64,
        attempt: u32,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let (mut held, rooted) = self.take_held_basis(path, partial_id, guard)?;
        let (dst, basis_size, location) = if let Some(target) = rooted {
            let (relative, label) = rooted_partial_target(&target, partial_id)?;
            let opened = self
                .open_private_partial_rooted(&target.root, &relative, &label, true)?
                .context("sidecar creation was requested")?;
            (
                opened.0,
                opened.1,
                FileLocation::Rooted {
                    root: target.root.identity(),
                    relative,
                },
            )
        } else {
            let pp = self.partial_path(&held.label, partial_id)?;
            let opened = self
                .open_private_partial(&pp, true)?
                .context("sidecar creation was requested")?;
            (opened.0, opened.1, FileLocation::Path(pp))
        };
        if basis_size.is_some_and(|size| size > 0) {
            dst.set_len(0)?;
        }
        self.preallocate_new_partial(&dst, len)?;
        held.file.seek(SeekFrom::Start(0))?;
        let mut writer = &dst;
        writer.seek(SeekFrom::Start(0))?;
        io::copy(&mut held.file.take(len), &mut writer)
            .with_context(|| format!("seed partial from {}", held.label.display()))?;
        self.cache_file(location, attempt, true, dst);
        Ok(())
    }

    /// Copy a whole same-machine file without routing its bytes through the
    /// transport. Prefer copy_file_range; when a cross-mount copy into NFS
    /// cannot be offloaded, use one sequential userspace writer instead. Other
    /// unsupported filesystems return `CopyLocalOutcome::Unsupported` for the
    /// parallel streaming path.
    #[cfg(target_os = "linux")]
    fn copy_local(
        &mut self,
        source: &RegisteredPath,
        dst: &[u8],
        policy: CopyLocalPolicy,
        partial_id: &PartialId,
        size: u64,
        mode: u32,
    ) -> Result<CopyLocalOutcome> {
        let CopyLocalPolicy {
            inplace,
            allow_sequential_nfs_fallback,
        } = policy;
        let source_target = self
            .registered_source_target(source)
            .context("resolve registered local-copy source")?;
        let source_label = PathBuf::from(OsStr::from_bytes(&source.relative));
        let s = open_registered_source(&source_target)
            .with_context(|| format!("open registered source {}", source_label.display()))?;
        // The kernel copy reads the source through the page cache, so the
        // larger readahead window this hint enables is what keeps a cold
        // source disk streaming (cp does the same; measured 10-20 % faster
        // on a cold 4 GiB file). Advisory only: a failure changes nothing.
        unsafe {
            libc::posix_fadvise(s.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
        let destination_root = self
            .destination_root
            .clone()
            .context("local copy requires a registered destination root")?;
        let dp = PathBuf::from(OsStr::from_bytes(dst));
        let destination_relative = RelativePath::new(dst)?;
        let destination_label = self.logical_destination_path(&dp);
        let destination_parent = destination_label
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        #[cfg(debug_assertions)]
        hold_copy_local_before_destination_open_for_test()?;
        let source_metadata = s.metadata()?;
        // A staged copy could safely replace a hard-linked destination, but a
        // command that names the same file is still a self-copy and should not
        // silently replace its own selected source. The in-place open repeats
        // this check against the exact descriptor before truncation.
        if destination_root
            .metadata_optional(&destination_relative)?
            .is_some_and(|metadata| {
                metadata.is_file()
                    && metadata.dev == source_metadata.dev()
                    && metadata.ino == source_metadata.ino()
            })
        {
            bail!(
                "source and destination are the same file: {}",
                destination_label.display()
            );
        }
        let source_key = file_system_key(&s, source_metadata.dev());
        if !allow_sequential_nfs_fallback {
            let known_destination = copy_destination_mounts()
                .lock()
                .unwrap()
                .get(&destination_parent)
                .copied();
            if known_destination.is_some_and(|destination_key| {
                unsupported_copy_pairs()
                    .lock()
                    .unwrap()
                    .contains(&(source_key, destination_key))
            }) {
                return Ok(CopyLocalOutcome::Unsupported);
            }
        }
        self.uncache_rooted(&destination_root, &destination_relative);
        let (target_relative, target_label) = if inplace {
            (destination_relative, destination_label)
        } else {
            let target = RootedTarget {
                root: destination_root.clone(),
                relative: destination_relative,
                label: destination_label,
                create_missing_parents: false,
            };
            rooted_partial_target(&target, partial_id)?
        };
        self.uncache_rooted(&destination_root, &target_relative);
        let d = if inplace {
            let mut opened = None;
            for _ in 0..8 {
                match destination_root.metadata_optional(&target_relative)? {
                    Some(metadata) if metadata.is_file() => {
                        let file = destination_root.open_regular_write(&target_relative, false)?;
                        require_rooted_metadata(&file, metadata, &target_label)?;
                        let metadata = file.metadata()?;
                        if metadata.dev() == source_metadata.dev()
                            && metadata.ino() == source_metadata.ino()
                        {
                            bail!(
                                "source and destination are the same file: {}",
                                target_label.display()
                            );
                        }
                        file.set_len(0).with_context(|| {
                            format!("truncate confined file {}", target_label.display())
                        })?;
                        opened = Some(file);
                        break;
                    }
                    Some(metadata) if metadata.is_dir() => {
                        bail!("destination {} is a directory", target_label.display())
                    }
                    Some(_) => destination_root.unlink(&target_relative)?,
                    None => match destination_root.create_file(&target_relative, mode) {
                        Ok(file) => {
                            opened = Some(file);
                            break;
                        }
                        Err(error)
                            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                error.kind() == io::ErrorKind::AlreadyExists
                            }) => {}
                        Err(error) => return Err(error),
                    },
                }
            }
            opened.with_context(|| {
                format!(
                    "destination {} changed repeatedly while opening it",
                    target_label.display()
                )
            })?
        } else {
            let (d, basis_size) = self
                .open_private_partial_rooted(
                    &destination_root,
                    &target_relative,
                    &target_label,
                    true,
                )?
                .context("sidecar creation was requested")?;
            if basis_size.is_some() {
                // Preserve resumable data. The streaming path will hash and
                // reuse it after CopyLocal reports that it is unavailable.
                return Ok(CopyLocalOutcome::Unsupported);
            }
            d
        };
        let destination_metadata = d.metadata()?;
        let destination_dev = destination_metadata.dev();
        let destination_key = file_system_key(&d, destination_dev);
        copy_destination_mounts()
            .lock()
            .unwrap()
            .insert(destination_parent, destination_key);
        let source_fs = file_system_traits(&s, source_key);
        let destination_fs = file_system_traits(&d, destination_key);
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
        let copy_pair = (source_key, destination_key);
        let copy_pair_unsupported = unsupported_copy_pairs()
            .lock()
            .unwrap()
            .contains(&copy_pair);
        let mut userspace_fallback = copy_pair_unsupported && use_sequential_nfs_fallback;
        if copy_pair_unsupported && !use_sequential_nfs_fallback {
            let partial_metadata = d.metadata()?;
            drop(d);
            if !inplace {
                discard_rooted_copy_partial(
                    &destination_root,
                    &target_relative,
                    &target_label,
                    partial_metadata.dev(),
                    partial_metadata.ino(),
                )?;
            }
            return Ok(CopyLocalOutcome::Unsupported);
        }
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_COPY_LOCAL_EXDEV").is_some() {
            if use_sequential_nfs_fallback {
                userspace_fallback = true;
            } else {
                let partial_metadata = d.metadata()?;
                drop(d);
                if !inplace {
                    discard_rooted_copy_partial(
                        &destination_root,
                        &target_relative,
                        &target_label,
                        partial_metadata.dev(),
                        partial_metadata.ino(),
                    )?;
                }
                return Ok(CopyLocalOutcome::Unsupported);
            }
        }
        let mut source_offset: libc::off64_t = 0;
        let mut destination_offset: libc::off64_t = 0;
        let mut remaining = size;
        while remaining > 0 && !userspace_fallback {
            // SAFETY: each offset is its own local that outlives the call, so
            // the kernel reads and advances the two through distinct pointers.
            let n = unsafe {
                libc::copy_file_range(
                    s.as_raw_fd(),
                    &mut source_offset,
                    d.as_raw_fd(),
                    &mut destination_offset,
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
                    if matches!(raw, libc::EXDEV | libc::ENOSYS | libc::EOPNOTSUPP) {
                        unsupported_copy_pairs().lock().unwrap().insert(copy_pair);
                    }
                    if use_sequential_nfs_fallback {
                        userspace_fallback = true;
                        continue;
                    }
                    let partial_metadata = d.metadata()?;
                    drop(d);
                    if !inplace {
                        // The planner probed before this empty sidecar existed.
                        // A content-identical fallback completes through its
                        // retained basis fd and would otherwise orphan it.
                        discard_rooted_copy_partial(
                            &destination_root,
                            &target_relative,
                            &target_label,
                            partial_metadata.dev(),
                            partial_metadata.ino(),
                        )?;
                    }
                    return Ok(CopyLocalOutcome::Unsupported);
                }
                if raw == libc::EINTR {
                    continue;
                }
                return Err(e).with_context(|| {
                    format!(
                        "copy_file_range {} -> {}",
                        source_label.display(),
                        target_label.display()
                    )
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
                    .with_context(|| format!("read {}", source_label.display()))?;
                if n == 0 {
                    bail!("source shortened while copying {}", source_label.display());
                }
                destination
                    .write_all(&buffer[..n])
                    .with_context(|| format!("write {}", target_label.display()))?;
                remaining -= n as u64;
            }
            d.set_len(size)?;
        }
        Ok(CopyLocalOutcome::Copied)
    }

    #[cfg(not(target_os = "linux"))]
    fn copy_local(
        &mut self,
        _source: &RegisteredPath,
        _dst: &[u8],
        _policy: CopyLocalPolicy,
        _partial_id: &PartialId,
        _size: u64,
        _mode: u32,
    ) -> Result<CopyLocalOutcome> {
        Ok(CopyLocalOutcome::Unsupported)
    }

    /// Write a whole small file through its deterministic sidecar and atomically
    /// rename it into place. Keeping this as one request preserves pipelining;
    /// unlike an in-place write, no partial final-named file is ever visible.
    fn put_small(&mut self, put: &SmallPut) -> Result<()> {
        let target = PartialTarget {
            path: &put.path,
            id: &put.partial_id,
            guard: put.guard.as_ref(),
        };
        let data = &put.data;
        let hash = put.hash;
        let meta = &put.meta;
        let flags = put.flags;
        let inplace = put.inplace;
        let condition = put.condition;
        if content_digest(data) != hash {
            bail!("block hash mismatch on receive");
        }
        if let Some(rooted) = self.rooted_destination_target(target.path, target.guard)? {
            self.uncache_rooted(&rooted.root, &rooted.relative);
            if inplace {
                if target.guard.is_some() {
                    bail!("guarded small-file updates require atomic publication");
                }
                let file = match condition {
                    TargetCondition::Absent => rooted
                        .root
                        .create_file(&rooted.relative, meta.mode)
                        .with_context(|| format!("create {}", rooted.label.display()))?,
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let file = rooted.root.open_regular_write(&rooted.relative, false)?;
                        require_open_target(&file, &rooted.label, condition)?;
                        file.set_len(0)?;
                        file
                    }
                    TargetCondition::Any => {
                        let mut opened = None;
                        for _ in 0..8 {
                            match rooted.root.metadata_optional(&rooted.relative)? {
                                Some(metadata) if metadata.is_file() => {
                                    let file =
                                        rooted.root.open_regular_write(&rooted.relative, false)?;
                                    require_rooted_metadata(&file, metadata, &rooted.label)?;
                                    file.set_len(0)?;
                                    opened = Some(file);
                                    break;
                                }
                                Some(metadata) if metadata.is_dir() => {
                                    bail!("destination {} is a directory", rooted.label.display())
                                }
                                Some(_) => rooted.root.unlink(&rooted.relative)?,
                                None => {
                                    match rooted.root.create_file(&rooted.relative, meta.mode) {
                                        Ok(file) => {
                                            opened = Some(file);
                                            break;
                                        }
                                        Err(error)
                                            if error_is_kind(
                                                &error,
                                                io::ErrorKind::AlreadyExists,
                                            ) => {}
                                        Err(error) => return Err(error),
                                    }
                                }
                            }
                        }
                        opened.with_context(|| {
                            format!(
                                "destination {} changed repeatedly while opening it",
                                rooted.label.display()
                            )
                        })?
                    }
                };
                file.write_all_at(data, 0)
                    .with_context(|| format!("write {}", rooted.label.display()))?;
                file.set_len(data.len() as u64)?;
                set_meta_file(&file, meta, flags)
                    .with_context(|| format!("set metadata {}", rooted.label.display()))?;
                if matches!(
                    condition,
                    TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
                ) {
                    require_rooted_named_identity(
                        &rooted.root,
                        &rooted.relative,
                        &rooted.label,
                        &file,
                        condition,
                    )?;
                }
                return Ok(());
            }
            if target.guard.is_none()
                && matches!(
                    condition,
                    TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
                )
            {
                // Ordinary existing-file updates preserve the selected inode.
                // Validate before truncation, then prove the rooted name still
                // identifies that descriptor after the update.
                let file = rooted.root.open_regular_write(&rooted.relative, false)?;
                require_open_target(&file, &rooted.label, condition)?;
                file.set_len(0)?;
                file.write_all_at(data, 0)
                    .with_context(|| format!("write existing {}", rooted.label.display()))?;
                file.set_len(data.len() as u64)?;
                set_meta_file(&file, meta, flags)
                    .with_context(|| format!("set metadata {}", rooted.label.display()))?;
                require_rooted_named_identity(
                    &rooted.root,
                    &rooted.relative,
                    &rooted.label,
                    &file,
                    condition,
                )?;
                return Ok(());
            }

            // New/replace small files, and the existing guarded-receiver
            // policy, stage through the same private rooted sidecar as ranged
            // writes do.
            let (relative, label) = rooted_partial_target(&rooted, target.id)?;
            let (file, _) = self
                .open_private_partial_rooted(&rooted.root, &relative, &label, true)?
                .context("sidecar creation was requested")?;
            file.set_len(0)?;
            file.write_all_at(data, 0)
                .with_context(|| format!("write {}", label.display()))?;
            file.set_len(data.len() as u64)?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", label.display()))?;
            require_safe_rooted_named_partial(&rooted.root, &relative, &label, &file)?;
            #[cfg(debug_assertions)]
            fail_put_small_before_rename_for_test(&rooted.label)?;
            publish_partial_rooted(&rooted.root, &relative, &rooted.relative, &file, condition)?;
            return Ok(());
        }
        let p = resolve(target.path);
        self.uncache(&p);
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
        let (f, basis_size) = self
            .open_private_partial(&pp, true)?
            .context("sidecar creation was requested")?;
        if basis_size.is_some() {
            f.set_len(0)?;
        }
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
        options: HashOptions,
        partial_id: &PartialId,
    ) -> Result<Vec<ContentDigest>> {
        let HashOptions {
            which,
            block,
            len,
            attempt,
        } = options;
        if target.source.is_some()
            || (self.destination_root.is_none() && !self.source_roots.is_empty())
        {
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
        if let Some(target) = self.rooted_destination_target(target.path, target.guard)? {
            let (relative, label) = if which == Which::Partial {
                rooted_partial_target(&target, partial_id)?
            } else {
                (target.relative.clone(), target.label.clone())
            };
            let location = FileLocation::Rooted {
                root: target.root.identity(),
                relative: relative.clone(),
            };
            let mut file = self
                .cached_clone(location, attempt, which == Which::Partial)?
                .map(Ok)
                .unwrap_or_else(|| target.root.open_regular_read(&relative))?;
            file.seek(SeekFrom::Start(0))?;
            if which == Which::Partial {
                require_safe_rooted_named_partial(&target.root, &relative, &label, &file)?;
            }
            return hash_reader(&mut file, block, len);
        }
        let p = resolve(target.path);
        let p = if which == Which::Partial {
            self.partial_path(&p, partial_id)?
        } else {
            p
        };
        let mut f = self
            .cached_clone(
                FileLocation::Path(p.clone()),
                attempt,
                which == Which::Partial,
            )?
            .map(Ok)
            .unwrap_or_else(|| open_existing_regular(&p, false))?;
        f.seek(SeekFrom::Start(0))?;
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
        if let Some(rooted) = self.rooted_destination_target(target.path, target.guard)? {
            let (relative, label) = if inplace {
                (rooted.relative.clone(), rooted.label.clone())
            } else {
                rooted_partial_target(&rooted, target.id)?
            };
            let file = self.cached_rooted(&label, &rooted.root, &relative, attempt, !inplace)?;
            return file
                .write_all_at(data, off)
                .with_context(|| format!("write {} @{off}", label.display()));
        }
        let p = resolve(target.path);
        let p = if inplace {
            p
        } else {
            self.partial_path(&p, target.id)?
        };
        let f = self.cached(&p, true, attempt, !inplace)?;
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
        if let Some(target) = self.rooted_destination_target(path, mutation.guard)? {
            return self.finalize_rooted(&target, inplace, partial_id, meta, flags, mutation);
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
            publish_partial(&src, &p, condition)?;
        } else {
            require_named_target_identity(&f, &p, condition)?;
        }
        drop(f);
        Ok(())
    }

    fn finalize_rooted(
        &mut self,
        target: &RootedTarget,
        inplace: bool,
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
        mutation: TargetMutation<'_>,
    ) -> Result<()> {
        let TargetMutation { condition, guard } = mutation;
        let guarded = guard.is_some();
        if inplace {
            let file = self
                .uncache_rooted(&target.root, &target.relative)
                .map(Ok)
                .unwrap_or_else(|| target.root.open_regular_write(&target.relative, false))?;
            require_open_target(&file, &target.label, condition)?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", target.label.display()))?;
            if guarded || condition != TargetCondition::Any {
                require_rooted_named_identity(
                    &target.root,
                    &target.relative,
                    &target.label,
                    &file,
                    condition,
                )?;
            }
            return Ok(());
        }
        let (src_relative, src) = rooted_partial_target(target, partial_id)?;
        let file = self
            .uncache_rooted(&target.root, &src_relative)
            .map(Ok)
            .unwrap_or_else(|| target.root.open_regular_write(&src_relative, false))?;
        require_safe_rooted_named_partial(&target.root, &src_relative, &src, &file)?;

        if !guarded
            && matches!(
                condition,
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
            )
        {
            // Ordinary identity-conditioned staged updates preserve the
            // existing destination inode.
            // Keep the cached writer pinned while independently opening the
            // exact same named sidecar for reading.
            let staged_metadata = file.metadata()?;
            let mut staged = target.root.open_regular_read(&src_relative)?;
            require_safe_rooted_named_partial(&target.root, &src_relative, &src, &staged)?;
            let reopened_metadata = staged.metadata()?;
            if staged_metadata.dev() != reopened_metadata.dev()
                || staged_metadata.ino() != reopened_metadata.ino()
            {
                bail!("partial {} changed before publication", src.display());
            }

            self.uncache_rooted(&target.root, &target.relative);
            let mut destination = target.root.open_regular_write(&target.relative, false)?;
            require_open_target(&destination, &target.label, condition)?;
            let size = reopened_metadata.len();
            destination.set_len(0)?;
            staged.seek(SeekFrom::Start(0))?;
            destination.seek(SeekFrom::Start(0))?;
            io::copy(&mut staged, &mut destination)
                .with_context(|| format!("update existing {}", target.label.display()))?;
            destination.set_len(size)?;
            set_meta_file(&destination, meta, flags)
                .with_context(|| format!("set metadata {}", target.label.display()))?;
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                &destination,
                condition,
            )?;
            discard_safe_rooted_partial_if_same(
                &target.root,
                &src_relative,
                staged_metadata.dev(),
                staged_metadata.ino(),
                &src,
            )?;
            return Ok(());
        }

        set_meta_file(&file, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        require_safe_rooted_named_partial(&target.root, &src_relative, &src, &file)?;
        if target
            .root
            .metadata_optional(&target.relative)?
            .is_some_and(RootMetadata::is_dir)
        {
            bail!("destination {} is a directory", target.label.display());
        }
        publish_partial_rooted(
            &target.root,
            &src_relative,
            &target.relative,
            &file,
            condition,
        )?;
        Ok(())
    }

    pub fn file_hash(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        guard: Option<&ContainerGuard>,
    ) -> Result<Response> {
        let mut f = if source.is_some()
            || (self.destination_root.is_none() && !self.source_roots.is_empty())
        {
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
            Err(error) => return Response::EndpointError(wire_error(&error)),
        };
        // HashAndHold's next request must consume the retained descriptor.
        // Any other request means the controller abandoned that comparison
        // (for example because the source hash failed), so release it here.
        let r: Result<Response> = match &req {
            Request::ListDir {
                directory,
                confined_root,
                prefix,
                limit,
            } => self.completion_entries(directory, confined_root.as_deref(), prefix, *limit),
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
            Request::CheckOperatorDirectoryAncestry { checks } => self
                .check_operator_directory_ancestry(checks)
                .map(Response::DirectoryRelations),
            Request::RegisterSourceRoots {
                base,
                selections,
                symlink_policy,
                allow_unconfined_paths,
                shared_workers,
                independent_claim_workers,
            } => self
                .register_source_roots(
                    base,
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
            Request::DestinationFilesystemInfo {
                check_empty,
                target,
            } => self
                .destination_filesystem_info(*check_empty, target.as_ref())
                .map(Response::DestinationFilesystemInfo),
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
                attempt,
                create_if_missing,
                guard,
            } => self
                .prepare(
                    PartialTarget {
                        path,
                        id: partial_id,
                        guard: guard.as_ref(),
                    },
                    PrepareOptions {
                        size: *size,
                        inplace: *inplace,
                        mode: *mode,
                        attempt: *attempt,
                        create_if_missing: *create_if_missing,
                    },
                )
                .map(Response::PartialSize),
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
                attempt,
                guard,
            } => self
                .seed_basis(path, partial_id, *len, *attempt, guard.as_ref())
                .map(|_| Response::Ok),
            Request::CopyLocal {
                source,
                dst,
                inplace,
                allow_sequential_nfs_fallback,
                partial_id,
                size,
                mode,
            } => self
                .copy_local(
                    source,
                    dst,
                    CopyLocalPolicy {
                        inplace: *inplace,
                        allow_sequential_nfs_fallback: *allow_sequential_nfs_fallback,
                    },
                    partial_id,
                    *size,
                    *mode,
                )
                .map(|outcome| match outcome {
                    CopyLocalOutcome::Copied => Response::Ok,
                    CopyLocalOutcome::Unsupported => Response::CopyLocalUnsupported,
                }),
            Request::PutSmallBatch(puts) => Ok(Response::Applied(
                puts.iter()
                    .map(|put| self.put_small(put).err().as_ref().map(wire_error))
                    .collect(),
            )),
            Request::HashBlocks {
                path,
                source,
                which,
                partial_id,
                block,
                len,
                attempt,
                guard,
                ..
            } => self
                .hash_blocks(
                    HashTarget {
                        path,
                        source: source.as_ref(),
                        guard: guard.as_ref(),
                    },
                    HashOptions {
                        which: *which,
                        block: *block,
                        len: *len,
                        attempt: *attempt,
                    },
                    partial_id,
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
                } else if self.destination_root.is_some() {
                    Err(anyhow!(
                        "canonicalize is not valid after destination capability activation"
                    ))
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
            Err(e) => Response::EndpointError(wire_error(&e)),
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
            bail!("internal error: matched publication must update the held destination inode")
        }
    }
}

fn publish_partial_rooted(
    root: &Root,
    source: &RelativePath,
    target: &RelativePath,
    staged: &File,
    condition: TargetCondition,
) -> Result<()> {
    let metadata = staged.metadata()?;
    if !is_safe_partial(&metadata) {
        bail!("confined partial is not a private regular file");
    }
    let staged_dev = metadata.dev();
    let staged_ino = metadata.ino();
    let staged_identity = (staged_dev, staged_ino);
    match condition {
        TargetCondition::Any => root.rename_regular_if_same(source, target, staged_identity),
        TargetCondition::Absent => root.publish_new_regular(source, target, staged_identity),
        TargetCondition::Matches { dev, ino } => {
            root.replace_regular_if_same(source, target, staged_identity, dev, ino, None)
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => root.replace_regular_if_same(
            source,
            target,
            staged_identity,
            dev,
            ino,
            Some((ctime, ctime_nsec)),
        ),
    }
}

/// Open `target` read/write as a regular file without following symlinks. The
/// caller retains the descriptor for a block hash before writing ranges.
fn open_regular_read_write(target: &Path, mode: u32, truncate: bool) -> Result<File> {
    open_regular_for_write(target, mode, truncate, true)
}

fn open_regular_for_write(target: &Path, mode: u32, truncate: bool, read: bool) -> Result<File> {
    // The overwhelmingly common fresh-file case needs no preceding lookup.
    // O_EXCL both proves creation and refuses symlinks or raced entries.
    match OpenOptions::new()
        .read(read)
        .write(true)
        .create_new(true)
        .truncate(truncate)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(mode & 0o7777)
        .open(target)
    {
        Ok(file) if file.metadata()?.file_type().is_file() => return Ok(file),
        Ok(_) => bail!(
            "created destination {} is not a regular file",
            target.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("create {}", target.display())),
    }
    for _ in 0..8 {
        match fs::symlink_metadata(target) {
            Ok(md) if md.is_file() => {
                // Do not pass O_CREAT for an existing file. Linux
                // fs.protected_regular can reject that combination in a
                // sticky directory even when the caller is allowed to open
                // and update the inode (rsync's --inplace case).
                match OpenOptions::new()
                    .read(read)
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
                    .read(read)
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
    open_existing_regular_with_metadata(target, write).map(|(file, _)| file)
}

fn open_existing_regular_with_metadata(target: &Path, write: bool) -> Result<(File, fs::Metadata)> {
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
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("{} is not a regular file", target.display());
    }
    Ok((file, metadata))
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

fn require_safe_rooted_named_partial(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    file: &File,
) -> Result<()> {
    let opened = file.metadata()?;
    let named = root.metadata(relative)?;
    if !is_safe_partial(&opened)
        || !is_safe_rooted_partial(named)
        || opened.dev() != named.dev
        || opened.ino() != named.ino
    {
        bail!(
            "partial {} is not the opened singly-linked regular file",
            label.display()
        );
    }
    Ok(())
}

/// Best-effort cleanup of a private job sidecar that still names the inspected
/// inode. POSIX has no identity-conditioned unlink, so a writer of this same
/// retained parent can replace the random sidecar between the observation and
/// `unlinkat`. The operation remains confined to the retained parent; callers
/// must not use this helper for a final destination name whose later writer
/// needs compare-and-swap semantics.
fn discard_safe_rooted_partial_if_same(
    root: &Root,
    relative: &RelativePath,
    expected_dev: u64,
    expected_ino: u64,
    label: &Path,
) -> Result<()> {
    match root.metadata_optional(relative)? {
        Some(current)
            if is_safe_rooted_partial(current)
                && current.dev == expected_dev
                && current.ino == expected_ino =>
        {
            root.unlink(relative)
                .with_context(|| format!("replace {}", label.display()))?;
        }
        Some(_) | None => {}
    }
    Ok(())
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

fn mkdir_with_parent_fallback(p: &Path, mode: u32) -> Result<()> {
    match mkdir(p, mode) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = p.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
                mkdir(p, mode)?;
                Ok(())
            } else {
                Err(error.into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn remove_non_directory_or_empty_directory(p: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(p)?;
    if metadata.is_dir() {
        fs::remove_dir(p)?;
    } else {
        fs::remove_file(p)?;
    }
    Ok(())
}

fn create_symlink_any(path: &Path, target: &[u8]) -> Result<()> {
    let target = OsStr::from_bytes(target);
    match std::os::unix::fs::symlink(target, path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            remove_non_directory_or_empty_directory(path)?;
            std::os::unix::fs::symlink(target, path)
                .with_context(|| format!("symlink {}", path.display()))
        }
        Err(error) => Err(error).with_context(|| format!("symlink {}", path.display())),
    }
}

fn create_node_any(path: &Path, mode: u32, rdev: u64) -> Result<()> {
    let create = || -> Result<()> {
        let path = cstr(path)?;
        let result =
            unsafe { libc::mknod(path.as_ptr(), mode as libc::mode_t, rdev as libc::dev_t) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error().into())
        }
    };
    match create() {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
        {
            remove_non_directory_or_empty_directory(path)?;
            create().with_context(|| format!("mknod {}", path.display()))
        }
        Err(error) => Err(error).with_context(|| format!("mknod {}", path.display())),
    }
}

fn make_dir_writable(p: &Path, md: &fs::Metadata) -> Result<()> {
    if md.mode() & 0o700 != 0o700 {
        fs::set_permissions(p, fs::Permissions::from_mode(md.mode() | 0o700))?;
    }
    Ok(())
}

fn mkdir_or_existing_dir(p: &Path, mode: u32) -> Result<()> {
    match mkdir_with_parent_fallback(p, mode) {
        Ok(()) => Ok(()),
        Err(err)
            if err
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
        {
            match fs::symlink_metadata(p) {
                Ok(md) if md.is_dir() => make_dir_writable(p, &md),
                Ok(_) => {
                    fs::remove_file(p)?;
                    mkdir_with_parent_fallback(p, mode)
                }
                Err(_) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "linux")]
fn preallocate_new_file(f: &File, size: u64, traits: FileSystemTraits) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    // NFS writes grow the sidecar naturally, avoiding separate ALLOCATE and
    // SETATTR operations. Unsupported local filesystems retain the portable
    // sparse-sizing fallback.
    if traits.is_nfs {
        return Ok(());
    }
    let fallocate_error = if let Some(raw) = test_fallocate_errno() {
        Some(io::Error::from_raw_os_error(raw))
    } else {
        let length = libc::off_t::try_from(size).context("file is too large to preallocate")?;
        let result = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, length) };
        (result != 0).then(io::Error::last_os_error)
    };
    match fallocate_error {
        None => return Ok(()),
        Some(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL)
            ) => {}
        Some(error) => return Err(error).context("preallocate destination file"),
    }
    f.set_len(size)?;
    Ok(())
}

#[cfg(all(target_os = "linux", debug_assertions))]
fn test_fallocate_errno() -> Option<i32> {
    let value = std::env::var_os("SYQ_TEST_FALLOCATE_ERRNO")?;
    match value.to_string_lossy().as_ref() {
        "unsupported" => Some(libc::EOPNOTSUPP),
        "no_space" => Some(libc::ENOSPC),
        "quota" => Some(libc::EDQUOT),
        value => value.parse().ok(),
    }
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn test_fallocate_errno() -> Option<i32> {
    None
}

#[cfg(not(target_os = "linux"))]
fn preallocate_new_file(f: &File, size: u64) -> Result<()> {
    if size > 0 {
        f.set_len(size)?;
    }
    Ok(())
}

fn timespec(sec: i64, nsec: u32) -> libc::timespec {
    libc::timespec {
        tv_sec: sec as libc::time_t,
        tv_nsec: nsec as libc::c_long,
    }
}

fn set_meta_file(f: &File, meta: &Meta, flags: u8) -> Result<()> {
    if flags & (flags::MODE_MASK | flags::OWNER | flags::GROUP | flags::TIMES) == 0 {
        return Ok(());
    }
    let current = f.metadata()?;
    set_meta_file_known(f, meta, flags, &current)
}

fn set_meta_file_known(f: &File, meta: &Meta, flags: u8, current: &fs::Metadata) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // Owner first: chown clears setuid/setgid, so mode must be set afterwards.
    let owner_changed =
        apply_owner_if_changed(flags, meta, current.uid(), current.gid(), |uid, gid| {
            std::os::unix::fs::fchown(f, uid, gid)
        })?;
    if flags & flags::MODE_MASK != 0 {
        // On network filesystems every setattr is a round trip; skip it when
        // the mode is already right (but always run it after a chown that could
        // have cleared setuid/setgid bits we need to restore).
        let cur = current.mode() & 0o7777;
        let want = meta.mode & 0o7777;
        if cur != want || (owner_changed && want & 0o6000 != 0) {
            f.set_permissions(fs::Permissions::from_mode(want))?;
        }
    }
    if flags & flags::TIMES != 0
        && (current.mtime() != meta.mtime || current.mtime_nsec() as u32 != meta.mtime_nsec)
    {
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
    let owner_changed = apply_owner_if_changed(flags, meta, md.uid(), md.gid(), |uid, gid| {
        std::os::unix::fs::lchown(p, uid, gid)
    })?;
    if flags & flags::MODE_MASK != 0 && !is_link {
        let want = meta.mode & 0o7777;
        if md.mode() & 0o7777 != want || (owner_changed && want & 0o6000 != 0) {
            fs::set_permissions(p, fs::Permissions::from_mode(want))?;
        }
    }
    if flags & flags::TIMES != 0
        && (md.mtime() != meta.mtime || md.mtime_nsec() as u32 != meta.mtime_nsec)
    {
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

/// Apply only ownership fields whose requested values differ from the
/// metadata already observed. Returns whether a chown ran, since it may clear
/// set-id mode bits that a following chmod must restore.
fn apply_owner_if_changed(
    flags: u8,
    meta: &Meta,
    current_uid: u32,
    current_gid: u32,
    chown: impl Fn(Option<u32>, Option<u32>) -> io::Result<()>,
) -> Result<bool> {
    let uid = if flags & flags::OWNER != 0 && is_root() && current_uid != meta.uid {
        Some(meta.uid)
    } else {
        None
    };
    let gid = if flags & flags::GROUP != 0 && current_gid != meta.gid {
        Some(meta.gid)
    } else {
        None
    };
    if uid.is_none() && gid.is_none() {
        return Ok(false);
    }
    match chown(uid, gid) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && uid.is_none() => Ok(false),
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
        crate::test_support::temp_dir().join(format!(
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
            base: SourceRootBase::default(),
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
            .prepare(
                PartialTarget {
                    path: target_bytes,
                    id: &partial_id,
                    guard: Some(&guard),
                },
                PrepareOptions {
                    size: 3,
                    inplace: true,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
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
                PartialTarget {
                    path: escaped.as_os_str().as_bytes(),
                    id: &partial_id,
                    guard: Some(&guard),
                },
                PrepareOptions {
                    size: 1,
                    inplace: true,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn confinement_matrix_guarded_receiver_refuses_root_and_parent_swaps() {
        const CHILD_ENV: &str = "SYQ_TEST_GUARDED_MUTATION_CHILD";
        const ROOT_ENV: &str = "SYQ_TEST_GUARDED_MUTATION_ROOT";
        const TEST_NAME: &str =
            "fsops::tests::confinement_matrix_guarded_receiver_refuses_root_and_parent_swaps";

        if std::env::var_os(CHILD_ENV).is_some() {
            let root_path = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
            let identity = Root::open(&root_path).unwrap().identity();
            let guard = ContainerGuard {
                root: root_path.as_os_str().as_bytes().to_vec(),
                dev: identity.dev,
                ino: identity.ino,
            };
            let target = root_path.join("target/parent/escaped");
            let errors = FsOps::new().apply(
                &[Op::Mkdir {
                    path: target.as_os_str().as_bytes().to_vec(),
                    mode: 0o755,
                    condition: TargetCondition::Any,
                }],
                Some(&guard),
            );
            assert!(
                errors[0].is_some(),
                "guarded mutation followed a raced namespace"
            );
            return;
        }

        for swap_root in [false, true] {
            let temporary = crate::test_support::tempdir().unwrap();
            let root_path = temporary.path().join("root");
            let outside = temporary.path().join("outside");
            fs::create_dir_all(root_path.join("target/parent")).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("sentinel"), b"outside").unwrap();
            let ready = temporary.path().join("guarded-ready");
            let continuation = temporary.path().join("guarded-continue");

            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(CHILD_ENV, "1")
                .env(ROOT_ENV, &root_path)
                .env("SYQ_TEST_GUARDED_MUTATION_SUFFIX", "parent/escaped")
                .env("SYQ_TEST_GUARDED_MUTATION_READY_FILE", &ready)
                .env("SYQ_TEST_GUARDED_MUTATION_CONTINUE_FILE", &continuation)
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !ready.exists() && std::time::Instant::now() < deadline {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "guarded-mutation child exited before its race window"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(ready.exists(), "guarded-mutation race window timed out");

            if swap_root {
                fs::rename(&root_path, temporary.path().join("displaced-root")).unwrap();
                symlink(&outside, &root_path).unwrap();
            } else {
                fs::rename(
                    root_path.join("target/parent"),
                    root_path.join("target/displaced-parent"),
                )
                .unwrap();
                symlink(&outside, root_path.join("target/parent")).unwrap();
            }
            fs::write(&continuation, b"continue").unwrap();

            assert!(
                child.wait().unwrap().success(),
                "guarded-mutation child failed for swap_root={swap_root}"
            );
            assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
            assert!(!outside.join("escaped").exists());
        }
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
    fn retained_operator_directory_reports_source_ancestry_without_following_suffix_links() {
        let dir = test_dir();
        let source = dir.join("source");
        let child = source.join("child");
        let sibling = dir.join("sibling");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        symlink(&source, sibling.join("link-to-source")).unwrap();
        let source = File::open(&source).unwrap();

        let select = |path: &Path, allow_missing| {
            select_operator_directory(
                path.as_os_str().as_bytes(),
                allow_missing,
                OperatorSymlinkPolicy::Refuse,
            )
            .unwrap()
            .0
        };
        assert_eq!(
            select(&dir.join("source"), false)
                .relation_to_source(&source, b"")
                .unwrap(),
            DirectoryRelation::Same
        );
        assert_eq!(
            select(&child, false)
                .relation_to_source(&source, b"")
                .unwrap(),
            DirectoryRelation::Descendant
        );
        assert_eq!(
            select(&dir.join("source/missing/deeper"), true)
                .relation_to_source(&source, b"")
                .unwrap(),
            DirectoryRelation::Descendant
        );
        assert_eq!(
            select(&sibling, false)
                .relation_to_source(&source, b"link-to-source")
                .unwrap(),
            DirectoryRelation::Separate,
            "a generated destination suffix must not follow a symlink"
        );
        assert_eq!(
            select(&child, false)
                .relation_to_source(&source, b"..")
                .unwrap(),
            DirectoryRelation::Same
        );

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
            .contains("appeared after the new-path precondition"));

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
        let dir =
            crate::test_support::temp_dir().join(format!("syq-unlink-{}", std::process::id()));
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
            .as_ref()
            .map(WireError::as_str)
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
    fn destination_activation_does_not_change_process_cwd() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let before = std::env::current_dir().unwrap();
        let mut operations = FsOps::new();

        operations
            .install_destination(File::open(&dir).unwrap(), b"logical")
            .unwrap();

        assert_eq!(std::env::current_dir().unwrap(), before);
        let response = operations.handle(&Request::Canonicalize {
            path: b"logical".to_vec(),
            guard: None,
        });
        assert!(
            matches!(response, Response::EndpointError(error) if error.message.contains(
                "canonicalize is not valid after destination capability activation"
            ))
        );
        fs::remove_dir_all(&dir).unwrap();
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
    fn destination_file_state_uses_the_adopted_root_and_refuses_symlink_parents() {
        let dir = test_dir();
        let selected = dir.join("selected");
        let moved = dir.join("moved");
        let outside = dir.join("outside");
        fs::create_dir_all(&selected).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(selected.join("basis"), b"held").unwrap();
        fs::write(selected.join("inplace"), b"original").unwrap();
        let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
        let mut operations = FsOps::new();
        operations.destination_root = Some(root);
        operations.destination_prefix = Some(path_bytes(&selected));

        fs::rename(&selected, &moved).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("basis"), b"replacement").unwrap();
        fs::write(selected.join("inplace"), b"replacement").unwrap();

        let partial_id = [31; 16];
        let (hashes, held_len) = operations
            .hash_and_hold(
                b"basis",
                &partial_id,
                MIN_HASH_BLOCK_BYTES,
                4,
                TargetCondition::Any,
                None,
            )
            .unwrap();
        assert_eq!(hashes, vec![content_digest(b"held")]);
        assert_eq!(held_len, 4);
        operations
            .seed_basis(b"basis", &partial_id, 4, 0, None)
            .unwrap();
        let basis_partial = partial_path(&moved.join("basis"), &partial_id).unwrap();
        assert_eq!(fs::read(&basis_partial).unwrap(), b"held");
        let Response::PartialSize(partial_size) = operations
            .probe_partial(b"basis", &partial_id, None)
            .unwrap()
        else {
            panic!("unexpected partial probe response");
        };
        assert_eq!(partial_size, Some(4));
        assert_eq!(
            operations
                .hash_blocks(
                    HashTarget {
                        path: b"basis",
                        source: None,
                        guard: None,
                    },
                    HashOptions {
                        which: Which::Partial,
                        block: MIN_HASH_BLOCK_BYTES,
                        len: 4,
                        attempt: 0,
                    },
                    &partial_id,
                )
                .unwrap(),
            vec![content_digest(b"held")]
        );

        operations
            .hash_and_hold(
                b"basis",
                &partial_id,
                MIN_HASH_BLOCK_BYTES,
                4,
                TargetCondition::Any,
                None,
            )
            .unwrap();
        operations
            .finish_basis(
                b"basis",
                &partial_id,
                &Meta {
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                flags::MODE,
                TargetCondition::Any,
                None,
            )
            .unwrap();
        assert_eq!(
            fs::metadata(moved.join("basis")).unwrap().mode() & 0o777,
            0o600
        );
        assert_ne!(
            fs::metadata(selected.join("basis")).unwrap().mode() & 0o777,
            0o600
        );

        let stale = partial_path(&moved.join("inplace"), &partial_id).unwrap();
        fs::write(&stale, b"stale").unwrap();
        operations
            .prepare(
                PartialTarget {
                    path: b"inplace",
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 2,
                    inplace: true,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .unwrap();
        assert_eq!(fs::metadata(moved.join("inplace")).unwrap().len(), 2);
        assert!(!stale.exists());
        assert_eq!(fs::read(selected.join("inplace")).unwrap(), b"replacement");

        symlink(&outside, moved.join("redirect")).unwrap();
        assert!(operations
            .prepare(
                PartialTarget {
                    path: b"redirect/escaped",
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 1,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .is_err());
        assert!(operations
            .hash_blocks(
                HashTarget {
                    path: b"redirect/escaped",
                    source: None,
                    guard: None,
                },
                HashOptions {
                    which: Which::Final,
                    block: MIN_HASH_BLOCK_BYTES,
                    len: 1,
                    attempt: 0,
                },
                &partial_id,
            )
            .is_err());
        assert!(!outside.join("escaped").exists());
        assert!(operations
            .probe_partial(b"../outside", &partial_id, None)
            .is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn destination_writes_publish_inside_the_adopted_root() {
        let dir = test_dir();
        let selected = dir.join("selected");
        let moved = dir.join("moved");
        let outside = dir.join("outside");
        fs::create_dir_all(&selected).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(selected.join("existing"), b"old").unwrap();
        fs::write(selected.join("inplace"), b"old").unwrap();
        let root = Arc::new(Root::from_directory(File::open(&selected).unwrap()).unwrap());
        let mut operations = FsOps::new();
        operations.destination_root = Some(root);
        operations.destination_prefix = Some(path_bytes(&selected));

        fs::rename(&selected, &moved).unwrap();
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("small"), b"replacement-root").unwrap();
        fs::write(selected.join("existing"), b"replacement-root").unwrap();
        fs::write(selected.join("inplace"), b"replacement-root").unwrap();

        let meta = Meta {
            mode: 0o600,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        };
        let partial_id = [41; 16];
        operations
            .put_small(&SmallPut {
                path: b"small".to_vec(),
                partial_id,
                data: b"small-data".to_vec(),
                hash: content_digest(b"small-data"),
                meta,
                flags: 0,
                inplace: false,
                condition: TargetCondition::Absent,
                guard: None,
            })
            .unwrap();
        assert_eq!(fs::read(moved.join("small")).unwrap(), b"small-data");
        assert_eq!(
            fs::read(selected.join("small")).unwrap(),
            b"replacement-root"
        );

        let existing = fs::metadata(moved.join("existing")).unwrap();
        operations
            .put_small(&SmallPut {
                path: b"existing".to_vec(),
                partial_id,
                data: b"new".to_vec(),
                hash: content_digest(b"new"),
                meta,
                flags: 0,
                inplace: false,
                condition: TargetCondition::Matches {
                    dev: existing.dev(),
                    ino: existing.ino(),
                },
                guard: None,
            })
            .unwrap();
        assert_eq!(fs::read(moved.join("existing")).unwrap(), b"new");
        assert_eq!(
            fs::metadata(moved.join("existing")).unwrap().ino(),
            existing.ino()
        );
        assert_eq!(
            fs::read(selected.join("existing")).unwrap(),
            b"replacement-root"
        );

        operations
            .prepare(
                PartialTarget {
                    path: b"ranged",
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 6,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .unwrap();
        operations
            .write_range(
                PartialTarget {
                    path: b"ranged",
                    id: &partial_id,
                    guard: None,
                },
                false,
                0,
                0,
                content_digest(b"ranged"),
                b"ranged",
            )
            .unwrap();
        operations
            .finalize(
                b"ranged",
                false,
                &partial_id,
                &meta,
                0,
                TargetMutation {
                    condition: TargetCondition::Absent,
                    guard: None,
                },
            )
            .unwrap();
        assert_eq!(fs::read(moved.join("ranged")).unwrap(), b"ranged");
        assert!(!selected.join("ranged").exists());

        operations
            .prepare(
                PartialTarget {
                    path: b"inplace",
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 7,
                    inplace: true,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .unwrap();
        operations
            .write_range(
                PartialTarget {
                    path: b"inplace",
                    id: &partial_id,
                    guard: None,
                },
                true,
                0,
                0,
                content_digest(b"inplace"),
                b"inplace",
            )
            .unwrap();
        operations
            .finalize(
                b"inplace",
                true,
                &partial_id,
                &meta,
                0,
                TargetMutation {
                    condition: TargetCondition::Any,
                    guard: None,
                },
            )
            .unwrap();
        assert_eq!(fs::read(moved.join("inplace")).unwrap(), b"inplace");
        assert_eq!(
            fs::read(selected.join("inplace")).unwrap(),
            b"replacement-root"
        );

        symlink(&outside, moved.join("redirect")).unwrap();
        assert!(operations
            .put_small(&SmallPut {
                path: b"redirect/escaped".to_vec(),
                partial_id,
                data: b"bad".to_vec(),
                hash: content_digest(b"bad"),
                meta,
                flags: 0,
                inplace: false,
                condition: TargetCondition::Absent,
                guard: None,
            })
            .is_err());
        assert!(!outside.join("escaped").exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rooted_ranged_write_does_not_follow_a_swapped_parent() {
        let dir = test_dir();
        let root_path = dir.join("root");
        let outside = dir.join("outside");
        fs::create_dir_all(root_path.join("parent")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("file"), b"outside").unwrap();
        let root = Arc::new(Root::open(&root_path).unwrap());
        let mut operations = FsOps::new();
        operations.destination_root = Some(root);
        operations.destination_prefix = Some(path_bytes(&root_path));
        let partial_id = [42; 16];

        operations
            .prepare(
                PartialTarget {
                    path: b"parent/file",
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 4,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .unwrap();
        operations
            .write_range(
                PartialTarget {
                    path: b"parent/file",
                    id: &partial_id,
                    guard: None,
                },
                false,
                0,
                0,
                content_digest(b"safe"),
                b"safe",
            )
            .unwrap();
        fs::rename(root_path.join("parent"), root_path.join("parked")).unwrap();
        symlink(&outside, root_path.join("parent")).unwrap();

        // The cached descriptor remains the parked sidecar, while reopening
        // the swapped parent for finalization fails rather than following it.
        operations
            .write_range(
                PartialTarget {
                    path: b"parent/file",
                    id: &partial_id,
                    guard: None,
                },
                false,
                0,
                0,
                content_digest(b"held"),
                b"held",
            )
            .unwrap();
        assert!(operations
            .finalize(
                b"parent/file",
                false,
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
                    condition: TargetCondition::Absent,
                    guard: None,
                },
            )
            .is_err());
        let parked_partial = partial_path(&root_path.join("parked/file"), &partial_id).unwrap();
        assert_eq!(fs::read(parked_partial).unwrap(), b"held");
        assert_eq!(fs::read(outside.join("file")).unwrap(), b"outside");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rooted_finalize_rejects_replacement_of_the_opened_partial() {
        let dir = test_dir();
        let root_path = dir.join("root");
        fs::create_dir_all(&root_path).unwrap();
        let root = Arc::new(Root::open(&root_path).unwrap());
        let mut operations = FsOps::new();
        operations.destination_root = Some(root);
        operations.destination_prefix = Some(path_bytes(&root_path));
        let partial_id = [43; 16];

        operations
            .prepare(
                PartialTarget {
                    path: b"file",
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 4,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .unwrap();
        operations
            .write_range(
                PartialTarget {
                    path: b"file",
                    id: &partial_id,
                    guard: None,
                },
                false,
                0,
                0,
                content_digest(b"safe"),
                b"safe",
            )
            .unwrap();
        let partial = partial_path(&root_path.join("file"), &partial_id).unwrap();
        let displaced = root_path.join("displaced-partial");
        fs::rename(&partial, &displaced).unwrap();
        fs::write(&partial, b"attacker").unwrap();

        assert!(operations
            .finalize(
                b"file",
                false,
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
                    condition: TargetCondition::Absent,
                    guard: None,
                },
            )
            .is_err());
        assert!(!root_path.join("file").exists());
        assert_eq!(fs::read(&partial).unwrap(), b"attacker");
        assert_eq!(fs::read(&displaced).unwrap(), b"safe");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rooted_partial_hash_rejects_opened_and_named_inode_mismatch() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let named = dir.join("partial");
        fs::write(&named, b"old").unwrap();
        let root = Root::open(&dir).unwrap();
        let relative = RelativePath::new(b"partial").unwrap();
        let opened = root.open_regular_read(&relative).unwrap();

        fs::rename(&named, dir.join("old-partial")).unwrap();
        fs::write(&named, b"new").unwrap();

        assert!(require_safe_rooted_named_partial(&root, &relative, &named, &opened).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rooted_descriptor_cache_distinguishes_roots_with_the_same_relative_name() {
        let dir = test_dir();
        let first = dir.join("first");
        let second = dir.join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("same"), b"first").unwrap();
        fs::write(second.join("same"), b"second").unwrap();
        let first_root = Root::open(&first).unwrap();
        let second_root = Root::open(&second).unwrap();
        let relative = RelativePath::new(b"same").unwrap();
        let mut operations = FsOps::new();

        let first_inode = operations
            .cached_rooted(Path::new("same"), &first_root, &relative, 0, false)
            .unwrap()
            .metadata()
            .unwrap()
            .ino();
        let second_inode = operations
            .cached_rooted(Path::new("same"), &second_root, &relative, 0, false)
            .unwrap()
            .metadata()
            .unwrap()
            .ino();

        assert_ne!(first_inode, second_inode);
        assert_eq!(operations.fds.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retained_basis_cannot_be_consumed_under_another_root() {
        let dir = test_dir();
        let first = dir.join("first");
        let second = dir.join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::write(first.join("basis"), b"same").unwrap();
        fs::write(second.join("basis"), b"same").unwrap();
        let first_root = Arc::new(Root::open(&first).unwrap());
        let second_root = Arc::new(Root::open(&second).unwrap());
        let mut operations = FsOps::new();
        operations.destination_root = Some(first_root);
        operations.destination_prefix = Some(b"logical".to_vec());
        let partial_id = [32; 16];

        operations
            .hash_and_hold(
                b"basis",
                &partial_id,
                MIN_HASH_BLOCK_BYTES,
                4,
                TargetCondition::Any,
                None,
            )
            .unwrap();
        operations.destination_root = Some(second_root);
        assert!(operations
            .finish_basis(
                b"basis",
                &partial_id,
                &Meta {
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                flags::MODE,
                TargetCondition::Any,
                None,
            )
            .is_err());
        assert_ne!(
            fs::metadata(first.join("basis")).unwrap().mode() & 0o777,
            0o600
        );
        assert_ne!(
            fs::metadata(second.join("basis")).unwrap().mode() & 0o777,
            0o600
        );

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
    fn name_limit_discovery_does_not_follow_an_intermediate_symlink() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let target = dir.join("symlink-target");
        let existing = target.join("existing");
        let link = dir.join("in-tree-link");
        fs::create_dir_all(&existing).unwrap();
        symlink(&target, &link).unwrap();
        let cache = Mutex::new(NameMaxCache::default());
        let queried = Mutex::new(Vec::new());
        let expected = fs::metadata(&dir).unwrap();

        let limit = name_max_cached(&link.join("existing"), &cache, |candidate, directory| {
            let metadata = directory.metadata().unwrap();
            queried
                .lock()
                .unwrap()
                .push((candidate.to_path_buf(), metadata.dev(), metadata.ino()));
            143
        });

        assert_eq!(limit, 143);
        assert_eq!(
            *queried.lock().unwrap(),
            vec![(lexical_absolute(&dir), expected.dev(), expected.ino())]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn name_limit_discovery_uses_the_nearest_existing_directory() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let cache = Mutex::new(NameMaxCache::default());
        let queried = Mutex::new(Vec::new());

        let limit = name_max_cached(
            &dir.join("not-yet-created/deeper"),
            &cache,
            |candidate, _directory| {
                queried.lock().unwrap().push(candidate.to_path_buf());
                143
            },
        );

        assert_eq!(limit, 143);
        assert_eq!(*queried.lock().unwrap(), vec![lexical_absolute(&dir)]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn observation_only_prepare_does_not_create_a_sidecar() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let target = dir.join("file");
        let partial_id = [11; 16];
        let partial = partial_path(&target, &partial_id).unwrap();
        let mut operations = FsOps::new();

        let observed = operations
            .prepare(
                PartialTarget {
                    path: target.as_os_str().as_bytes(),
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 1024,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: false,
                },
            )
            .unwrap();
        assert_eq!(observed, None);
        assert!(!partial.exists());

        operations
            .prepare(
                PartialTarget {
                    path: target.as_os_str().as_bytes(),
                    id: &partial_id,
                    guard: None,
                },
                PrepareOptions {
                    size: 1024,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: true,
                },
            )
            .unwrap();
        assert!(partial.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn observation_only_prepare_preserves_unsafe_sidecars() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let target = dir.join("file");
        let partial_id = [12; 16];
        let partial = partial_path(&target, &partial_id).unwrap();
        let external = dir.join("external");
        fs::write(&external, b"sentinel").unwrap();
        let mut operations = FsOps::new();
        let observe = |operations: &mut FsOps| {
            operations
                .prepare(
                    PartialTarget {
                        path: target.as_os_str().as_bytes(),
                        id: &partial_id,
                        guard: None,
                    },
                    PrepareOptions {
                        size: 1024,
                        inplace: false,
                        mode: 0o600,
                        attempt: 0,
                        create_if_missing: false,
                    },
                )
                .unwrap()
        };

        symlink(&external, &partial).unwrap();
        let before = fs::symlink_metadata(&partial).unwrap();
        assert_eq!(observe(&mut operations), None);
        let after = fs::symlink_metadata(&partial).unwrap();
        assert!(after.file_type().is_symlink());
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(fs::read_link(&partial).unwrap(), external);
        fs::remove_file(&partial).unwrap();

        fs::hard_link(&external, &partial).unwrap();
        let before = fs::symlink_metadata(&partial).unwrap();
        assert_eq!(before.nlink(), 2);
        assert_eq!(observe(&mut operations), None);
        let after = fs::symlink_metadata(&partial).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.nlink(), 2);
        assert_eq!(fs::read(&external).unwrap(), b"sentinel");
        fs::remove_file(&partial).unwrap();

        create_node_any(&partial, MODE_FIFO | 0o600, 0).unwrap();
        let before = fs::symlink_metadata(&partial).unwrap();
        assert!(before.file_type().is_fifo());
        assert_eq!(observe(&mut operations), None);
        let after = fs::symlink_metadata(&partial).unwrap();
        assert!(after.file_type().is_fifo());
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn observation_only_rooted_prepare_preserves_an_unsafe_sidecar() {
        let dir = test_dir();
        let root_path = dir.join("root");
        fs::create_dir_all(&root_path).unwrap();
        let root = Root::open(&root_path).unwrap();
        let identity = root.identity();
        let guard = ContainerGuard {
            root: root_path.as_os_str().as_bytes().to_vec(),
            dev: identity.dev,
            ino: identity.ino,
        };
        let target = root_path.join("file");
        let partial_id = [13; 16];
        let partial = partial_path(&target, &partial_id).unwrap();
        symlink("unsafe-target", &partial).unwrap();
        let before = fs::symlink_metadata(&partial).unwrap();
        let mut operations = FsOps::new();

        let observed = operations
            .prepare(
                PartialTarget {
                    path: target.as_os_str().as_bytes(),
                    id: &partial_id,
                    guard: Some(&guard),
                },
                PrepareOptions {
                    size: 1024,
                    inplace: false,
                    mode: 0o600,
                    attempt: 0,
                    create_if_missing: false,
                },
            )
            .unwrap();

        assert_eq!(observed, None);
        let after = fs::symlink_metadata(&partial).unwrap();
        assert!(after.file_type().is_symlink());
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(fs::read_link(&partial).unwrap(), Path::new("unsafe-target"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fresh_nfs_partial_is_not_allocated_or_sized_before_writes() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let path = dir.join("partial");
        let file = File::create(&path).unwrap();
        preallocate_new_file(
            &file,
            1024 * 1024,
            FileSystemTraits {
                is_nfs: true,
                ..FileSystemTraits::default()
            },
        )
        .unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);

        file.write_all_at(b"payload", 1024).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 1031);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn identical_path_metadata_does_not_change_ctime() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let current = fs::symlink_metadata(&dir).unwrap();
        let meta = Meta {
            mode: current.mode(),
            uid: current.uid(),
            gid: current.gid(),
            mtime: current.mtime(),
            mtime_nsec: current.mtime_nsec() as u32,
        };
        let before = (current.ctime(), current.ctime_nsec());
        std::thread::sleep(std::time::Duration::from_millis(10));
        set_meta_path(&dir, &meta, flags::MODE | flags::TIMES).unwrap();
        let after = fs::symlink_metadata(&dir).unwrap();

        assert_eq!((after.ctime(), after.ctime_nsec()), before);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn guarded_root_metadata_updates_once_then_becomes_a_noop() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let root = Root::open(&dir).unwrap();
        let identity = root.identity();
        let guard = ContainerGuard {
            root: dir.as_os_str().as_bytes().to_vec(),
            dev: identity.dev,
            ino: identity.ino,
        };
        let target = guarded_target(dir.as_os_str().as_bytes(), &guard)
            .unwrap()
            .as_rooted();
        let current = fs::symlink_metadata(&dir).unwrap();
        let meta = Meta {
            mode: current.mode(),
            uid: current.uid(),
            gid: current.gid(),
            mtime: 1_600_000_000,
            mtime_nsec: 0,
        };

        set_meta_rooted(
            &target,
            &meta,
            flags::MODE | flags::TIMES,
            TargetCondition::Any,
        )
        .unwrap();
        let before = fs::symlink_metadata(&dir).unwrap();
        assert_eq!((before.mtime(), before.mtime_nsec()), (meta.mtime, 0));

        std::thread::sleep(std::time::Duration::from_millis(10));
        set_meta_rooted(
            &target,
            &meta,
            flags::MODE | flags::TIMES,
            TargetCondition::Any,
        )
        .unwrap();
        let after = fs::symlink_metadata(&dir).unwrap();
        assert_eq!(
            (after.ctime(), after.ctime_nsec()),
            (before.ctime(), before.ctime_nsec())
        );
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
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::create_dir(&selected).unwrap();
        fs::write(selected.join("original"), b"original").unwrap();
        let identity = fs::metadata(&selected).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn destination_worker_claims_copy_sources_from_the_foreign_session() {
        let temporary = crate::test_support::tempdir().unwrap();
        let source = temporary.path().join("source");
        let destination = temporary.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("file"), b"source").unwrap();
        fs::write(destination.join("file"), b"destination").unwrap();

        let source_session = DescriptorSessionSlot::default();
        let mut source_control = FsOps::with_descriptor_session(source_session);
        let response = source_control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
            selections: vec![SourceRootSelection {
                path: source.as_os_str().as_bytes().to_vec(),
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

        // Initialize an unrelated endpoint session so the copy worker cannot
        // accidentally clone the source root from its own registry.
        let destination_session = DescriptorSessionSlot::default();
        destination_session
            .register(File::open(&destination).unwrap())
            .unwrap();
        let mut worker = FsOps::with_descriptor_session(destination_session);
        worker.destination_root = Some(Arc::new(Root::open(&destination).unwrap()));
        worker.destination_prefix = Some(b".".to_vec());
        worker.initialize_copy_sources(&roots).unwrap();

        assert_eq!(worker.source_roots.len(), 1);
        assert_eq!(
            worker.source_root_identity(roots[0].selection.root()),
            source_control.source_root_identity(roots[0].selection.root())
        );
        let response = worker.handle(&Request::FileHash {
            path: b"file".to_vec(),
            source: None,
            guard: None,
        });
        assert!(
            matches!(response, Response::FileHash { size: 11, hash } if hash == content_digest(b"destination"))
        );
    }

    #[test]
    fn source_initialization_rejects_mismatched_bad_and_excess_roots_atomically() {
        let temporary = crate::test_support::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
        let temporary = crate::test_support::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let register = |control: &mut FsOps, path: &Path| {
            let response = control.handle(&Request::RegisterSourceRoots {
                base: SourceRootBase::default(),
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
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::write(&selected, b"original").unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
            Response::EndpointError(error) if error.message.contains("registered source leaf changed identity")
        ));
    }

    #[test]
    fn repeated_source_registration_keeps_the_original_root_and_leaf_pin() {
        let temporary = crate::test_support::tempdir().unwrap();
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let mut control = FsOps::new();
        let register = |path: &Path| Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
            Response::EndpointError(error) if error.message.contains("already registered")
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
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        fs::write(&selected, b"selected").unwrap();
        fs::write(temporary.path().join("sibling"), b"sibling").unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
        assert!(
            matches!(response, Response::EndpointError(error) if error.message.contains("does not authorize"))
        );

        let response = worker.handle(&Request::StatMany {
            paths: vec![selected.as_os_str().as_bytes().to_vec()],
            sources: None,
            follow: false,
            guard: None,
        });
        assert!(
            matches!(response, Response::EndpointError(error) if error.message.contains("omitted"))
        );

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
            Response::EndpointError(error) if error.message.contains("registered source leaf changed identity")
        ));
    }

    #[test]
    fn source_scan_rejects_a_replaced_exact_symlink() {
        let temporary = crate::test_support::tempdir().unwrap();
        fs::write(temporary.path().join("target-a"), b"a").unwrap();
        fs::write(temporary.path().join("target-b"), b"b").unwrap();
        let selected = temporary.path().join("selected");
        std::os::unix::fs::symlink("target-a", &selected).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session);
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let target = OsString::from_vec(b"raw-target-\xff".to_vec());
        symlink(Path::new(&target), &selected).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session);
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let outside = temporary.path().join("outside");
        fs::create_dir(&selected).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink("../outside", selected.join("link")).unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let replacement = temporary.path().join("replacement");
        fs::create_dir(&selected).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(selected.join("marker"), b"original").unwrap();
        fs::write(replacement.join("marker"), b"replacement").unwrap();
        // Exercise a raw byte name where the filesystem allows one.
        let raw_name = OsString::from_vec(
            if crate::test_support::filesystem_accepts_non_utf8_names() {
                b"raw-\xff".to_vec()
            } else {
                b"raw-plain".to_vec()
            },
        );
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
            attempt: 0,
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
        let temporary = crate::test_support::tempdir().unwrap();
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
                attempt: 0,
                guard: None,
            }),
            worker.handle(&Request::FileHash {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: Some(selections[0].clone()),
                guard: None,
            }),
        ] {
            assert!(
                matches!(response, Response::EndpointError(error) if error.message.contains("registered source leaf changed identity"))
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
        let temporary = crate::test_support::tempdir().unwrap();
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
                attempt: 0,
                guard: None,
            }),
            worker.handle(&Request::FileHash {
                path: label.clone(),
                source: Some(secret.clone()),
                guard: None,
            }),
        ] {
            assert!(matches!(response, Response::EndpointError(_)));
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
        let temporary = crate::test_support::tempdir().unwrap();
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
        let temporary = crate::test_support::tempdir().unwrap();
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
            assert!(matches!(response, Response::EndpointError(_)));
        }

        for response in [
            worker.handle(&Request::HashBlocks {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: None,
                which: Which::Final,
                partial_id: [0; 16],
                block: MIN_HASH_BLOCK_BYTES,
                len: 8,
                attempt: 0,
                guard: None,
            }),
            worker.handle(&Request::FileHash {
                path: selected.as_os_str().as_bytes().to_vec(),
                source: None,
                guard: None,
            }),
        ] {
            assert!(
                matches!(response, Response::EndpointError(error) if error.message.contains("omitted"))
            );
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
            attempt: 0,
            guard: None,
        });
        assert!(
            matches!(response, Response::EndpointError(error) if error.message.contains("only valid for the final source"))
        );
    }

    #[test]
    fn unconfined_source_content_uses_only_the_explicit_legacy_path() {
        let temporary = crate::test_support::tempdir().unwrap();
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
            attempt: 0,
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
        let temporary = crate::test_support::tempdir().unwrap();
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
        assert!(
            matches!(response, Response::EndpointError(error) if error.message.contains("destination worker"))
        );
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
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let sibling = temporary.path().join("sibling");
        fs::write(&selected, b"selected").unwrap();
        fs::write(&sibling, b"sibling").unwrap();
        let session = DescriptorSessionSlot::default();
        let mut control = FsOps::with_descriptor_session(session.clone());
        let response = control.handle(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
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
        let limits = nofile_limits().unwrap();
        if limits.rlim_cur != libc::RLIM_INFINITY {
            assert!(current_open_descriptor_count(limits.rlim_cur).unwrap() >= 3);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_status_umask_parses_only_the_kernel_line() {
        assert_eq!(
            parse_proc_status_umask("Name:\tsyq\nUmask:\t0022\nState:\tR (running)\n"),
            Some(0o022)
        );
        assert_eq!(parse_proc_status_umask("Umask:\t0077\n"), Some(0o077));
        assert_eq!(parse_proc_status_umask("Name:\tsyq\n"), None);
        assert_eq!(parse_proc_status_umask("Umask:\t8\n"), None);
        assert_eq!(parse_proc_status_umask("Umask:\t01777\n"), None);
    }

    #[test]
    fn process_umask_matches_file_creation() {
        let temp = crate::test_support::tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o777)
            .open(temp.path().join("probe"))
            .unwrap();
        let created = file.metadata().unwrap().mode() & 0o777;
        assert_eq!(created, 0o777 & !process_umask());
    }
}
