//! Thin wrappers over the libc calls the descriptor-relative filesystem code
//! shares: interrupted-call retry, `openat`, `errno`, `stat` field widths, and
//! directory streams.

use std::ffi::CStr;
use std::fs::File;
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};

/// Wait until `fd` is readable or `timeout` passes. If `poll` itself fails,
/// sleep for the timeout instead, so a caller's retry loop cannot spin.
pub(crate) fn wait_readable(fd: RawFd, timeout: std::time::Duration) {
    // The accept loops call this on every idle wake; keep it allocation-free.
    poll_readable(
        &mut [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }],
        timeout,
    );
}

/// Wait until any of `fds` is readable or `timeout` passes, as
/// [`wait_readable`] does for one descriptor.
pub(crate) fn wait_any_readable(fds: &[RawFd], timeout: std::time::Duration) {
    let mut ready: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    poll_readable(&mut ready, timeout);
}

fn poll_readable(ready: &mut [libc::pollfd], timeout: std::time::Duration) {
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: ready is a live array of initialized pollfd entries.
    if unsafe { libc::poll(ready.as_mut_ptr(), ready.len() as libc::nfds_t, millis) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
    {
        std::thread::sleep(timeout);
    }
}

#[cfg(target_os = "linux")]
pub(crate) const MODE_TYPE_MASK: u32 = libc::S_IFMT;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_TYPE_MASK: u32 = libc::S_IFMT as u32;
#[cfg(target_os = "linux")]
pub(crate) const MODE_DIRECTORY: u32 = libc::S_IFDIR;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_DIRECTORY: u32 = libc::S_IFDIR as u32;
#[cfg(target_os = "linux")]
pub(crate) const MODE_REGULAR: u32 = libc::S_IFREG;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_REGULAR: u32 = libc::S_IFREG as u32;
#[cfg(target_os = "linux")]
pub(crate) const MODE_SYMLINK: u32 = libc::S_IFLNK;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_SYMLINK: u32 = libc::S_IFLNK as u32;
#[cfg(target_os = "linux")]
pub(crate) const MODE_FIFO: u32 = libc::S_IFIFO;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_FIFO: u32 = libc::S_IFIFO as u32;

#[cfg(target_os = "linux")]
pub(crate) const MODE_SOCKET: u32 = libc::S_IFSOCK;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_SOCKET: u32 = libc::S_IFSOCK as u32;
#[cfg(target_os = "linux")]
pub(crate) const MODE_CHAR: u32 = libc::S_IFCHR;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_CHAR: u32 = libc::S_IFCHR as u32;
#[cfg(target_os = "linux")]
pub(crate) const MODE_BLOCK: u32 = libc::S_IFBLK;
#[cfg(not(target_os = "linux"))]
pub(crate) const MODE_BLOCK: u32 = libc::S_IFBLK as u32;

/// The component limit assumed when a filesystem does not report one.
pub(crate) const COMMON_NAME_MAX: usize = 255;
/// Entries kept by each per-filesystem component-limit cache.
pub(crate) const NAME_MAX_CACHE_CAP: usize = 1024;

/// The calling thread's descriptor directory. Every thread resolving
/// `/proc/self/fd` walks the thread-group leader's procfs entries, which
/// concurrent workers then contend for; `thread-self` gives each its own.
#[cfg(target_os = "linux")]
pub(crate) const PROC_FD_DIRECTORY: &str = "/proc/thread-self/fd";

/// Name the object `file` holds. The path is valid only while `file` stays
/// open, and only within this process: never hand it to a subprocess.
#[cfg(target_os = "linux")]
pub(crate) fn proc_fd_path(file: &impl AsRawFd) -> String {
    format!("{PROC_FD_DIRECTORY}/{}", file.as_raw_fd())
}

/// Run a call that reports success as zero, retrying while it is interrupted.
pub(crate) fn retry_zero(mut operation: impl FnMut() -> libc::c_int) -> io::Result<()> {
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

/// Whether a lookup failed because the name is absent or a component on
/// the way is not a directory that may be traversed.
pub(crate) fn absent_or_nondirectory(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|errno| matches!(errno, libc::ENOENT | libc::ENOTDIR | libc::ELOOP))
    })
}

pub(crate) fn open_at(
    parent: RawFd,
    name: &CStr,
    flags: libc::c_int,
    mode: u32,
) -> io::Result<File> {
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

/// The entry names of a directory, without `.` and `..`. The stream takes
/// over `directory`'s open file description and its read offset, so pass a
/// descriptor opened for this listing rather than a shared one.
pub(crate) fn directory_names(directory: File) -> io::Result<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    read_directory_entries_until(directory, |name| {
        names.push(name.to_vec());
        true
    })?;
    Ok(names)
}

/// How a directory may treat two different names as one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameFolding {
    /// Names are compared byte for byte.
    Exact,
    /// Names differing only in how Unicode composes their characters may
    /// be one entry (case-sensitive APFS); ASCII names are exact.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Normalization,
    /// Names may differ in case, Unicode composition or more (a case-folding
    /// directory, or one that cannot be told apart from it).
    Case,
}

/// How `directory` may fold names, as far as the system says.
#[cfg(target_os = "macos")]
pub(crate) fn name_folding(directory: &File) -> NameFolding {
    // APFS compares names without regard to how Unicode composes them.
    match unsafe { libc::fpathconf(directory.as_raw_fd(), libc::_PC_CASE_SENSITIVE) } {
        1 => NameFolding::Normalization,
        _ => NameFolding::Case,
    }
}

/// How `directory` may fold names, as far as the system says.
#[cfg(target_os = "linux")]
pub(crate) fn name_folding(directory: &File) -> NameFolding {
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(directory.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return NameFolding::Case;
    }
    let file_system = unsafe { stats.assume_init() }.f_type as u32;
    // GETFLAGS encodes sizeof(long) in its request but returns an int.
    let mut flags: libc::c_int = 0;
    let flags = (unsafe { libc::ioctl(directory.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) }
        == 0)
        .then_some(flags);
    let xfs_flags = (file_system == XFS_MAGIC)
        .then(|| xfs_geometry_flags(directory))
        .flatten();
    linux_name_folding(file_system, flags, xfs_flags)
}

#[cfg(target_os = "linux")]
const XFS_MAGIC: u32 = 0x5846_5342;
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: u32 = 0x0102_1994;

/// The flags of the XFS filesystem holding `directory`, from its geometry
/// (`XFS_IOC_FSGEOMETRY_V1`, which every kernel answers).
#[cfg(target_os = "linux")]
fn xfs_geometry_flags(directory: &File) -> Option<u32> {
    const XFS_IOC_FSGEOMETRY_V1: libc::c_ulong = 0x8070_5864;
    // struct xfs_fsop_geom_v1: 112 bytes, `flags` at byte 92.
    let mut geometry = [0u64; 14];
    let result = unsafe {
        libc::ioctl(
            directory.as_raw_fd(),
            XFS_IOC_FSGEOMETRY_V1 as _,
            geometry.as_mut_ptr(),
        )
    };
    (result == 0).then(|| {
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(geometry.as_ptr().cast(), 112) };
        u32::from_ne_bytes(bytes[92..96].try_into().expect("four bytes"))
    })
}

/// How a directory on the Linux filesystem `file_system` (its statfs type)
/// may fold names, given its inode flags and, on XFS, the filesystem's
/// geometry flags, each if they could be read. ext2/3/4, xfs, btrfs, f2fs
/// and tmpfs compare names byte for byte, unless the directory has the
/// casefold flag, or an XFS filesystem was made case-insensitive (`mkfs.xfs
/// -n version=ci`, which sets no flag on directories). Any other filesystem
/// may fold names, so is treated as folding case.
#[cfg(target_os = "linux")]
fn linux_name_folding(
    file_system: u32,
    flags: Option<libc::c_int>,
    xfs_flags: Option<u32>,
) -> NameFolding {
    const FS_CASEFOLD_FL: libc::c_int = 0x4000_0000;
    const XFS_FSOP_GEOM_FLAGS_DIRV2CI: u32 = 0x1000;
    let byte_for_byte = matches!(
        file_system,
        0xef53 // ext2, ext3, ext4
            | XFS_MAGIC
            | 0x9123_683e // btrfs
            | TMPFS_MAGIC
            | 0xf2f5_2010 // f2fs
    );
    if !byte_for_byte {
        return NameFolding::Case;
    }
    if file_system == XFS_MAGIC
        && xfs_flags.is_none_or(|flags| flags & XFS_FSOP_GEOM_FLAGS_DIRV2CI != 0)
    {
        return NameFolding::Case;
    }
    match flags {
        Some(flags) if flags & FS_CASEFOLD_FL != 0 => NameFolding::Case,
        Some(_) => NameFolding::Exact,
        // tmpfs answers no flags unless it supports casefolding.
        None if file_system == TMPFS_MAGIC => NameFolding::Exact,
        None => NameFolding::Case,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn name_folding(_directory: &File) -> NameFolding {
    NameFolding::Case
}

/// How many entries of a directory name each inode, as the directory lists
/// them. Takes over `directory` like [`directory_names`].
pub(crate) fn directory_entries_by_inode(
    directory: File,
) -> io::Result<std::collections::HashMap<u64, u64>> {
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            let _ = unsafe { libc::closedir(self.0) };
        }
    }

    let descriptor = directory.into_raw_fd();
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        let _ = unsafe { libc::close(descriptor) };
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    let mut counts = std::collections::HashMap::new();
    loop {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = get_errno();
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            return Ok(counts);
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            *counts.entry(unsafe { (*entry).d_ino } as u64).or_insert(0) += 1;
        }
    }
}

/// Whether a directory has no entries but `.` and `..`, reading no further
/// than the first one. Takes over `directory` like [`directory_names`].
pub(crate) fn directory_is_empty(directory: File) -> io::Result<bool> {
    let mut empty = true;
    let stop = |_: &[u8]| {
        empty = false;
        false
    };
    #[cfg(target_os = "linux")]
    read_directory_in_steps(&directory, 8 << 10, stop)?;
    #[cfg(not(target_os = "linux"))]
    read_directory_entries_until(directory, stop)?;
    Ok(empty)
}

/// Read about `limit` entries of a directory without keeping them, and
/// return how many it read. The read itself is the point: on NFS it
/// refreshes the client's entries and attributes for what it read. The
/// Linux NFS client fetches attributes with the entries only for a read
/// that starts at the beginning of the directory, so this is one read
/// sized for the limit; with longer names it returns fewer entries.
#[cfg(target_os = "linux")]
pub(crate) fn walk_directory_entries(directory: File, limit: usize) -> io::Result<usize> {
    let mut buffer = vec![0u8; limit.saturating_mul(32).clamp(8 << 10, 16 << 20)];
    let mut seen = 0;
    read_directory_step(&directory, &mut buffer, &mut |_| {
        seen += 1;
        seen < limit
    })?;
    Ok(seen)
}

/// Call `each` with every entry but `.` and `..`, stopping when it returns
/// false, reading `step` bytes of entries at a time. The C library reads a
/// directory in buffers as large as the filesystem's block size, a megabyte
/// on NFS, where every entry read costs the client time; a smaller step
/// leaves the rest of a large directory unread when the caller stops early.
#[cfg(target_os = "linux")]
fn read_directory_in_steps(
    directory: &File,
    step: usize,
    mut each: impl FnMut(&[u8]) -> bool,
) -> io::Result<()> {
    let mut buffer = vec![0u8; step];
    while read_directory_step(directory, &mut buffer, &mut each)? {}
    Ok(())
}

/// Read one buffer of entries and call `each` with every entry but `.` and
/// `..`. Returns whether more may follow: false at the end of the directory
/// or once `each` returns false.
#[cfg(target_os = "linux")]
fn read_directory_step(
    directory: &File,
    buffer: &mut [u8],
    each: &mut impl FnMut(&[u8]) -> bool,
) -> io::Result<bool> {
    let read = loop {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if read >= 0 {
            break read as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    if read == 0 {
        return Ok(false);
    }
    // Each record holds an 8-byte inode, an 8-byte offset, its 16-bit
    // length, a type byte, and the NUL-terminated name.
    let mut offset = 0;
    while offset + 19 < read {
        let length = usize::from(u16::from_ne_bytes([
            buffer[offset + 16],
            buffer[offset + 17],
        ]));
        if length < 20 || offset + length > read {
            break;
        }
        let field = &buffer[offset + 19..offset + length];
        let name = &field[..field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(field.len())];
        offset += length;
        if name != b"." && name != b".." && !each(name) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Call `each` with every entry but `.` and `..`, stopping when it returns
/// false.
fn read_directory_entries_until(
    directory: File,
    mut each: impl FnMut(&[u8]) -> bool,
) -> io::Result<()> {
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            let _ = unsafe { libc::closedir(self.0) };
        }
    }

    let descriptor = directory.into_raw_fd();
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        let _ = unsafe { libc::close(descriptor) };
        return Err(error);
    }
    let stream = DirectoryStream(stream);
    loop {
        set_errno(0);
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = get_errno();
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(errno));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." && !each(name) {
            break;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn set_errno(value: libc::c_int) {
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
pub(crate) fn get_errno() -> libc::c_int {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
pub(crate) fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
pub(crate) fn get_errno() -> libc::c_int {
    unsafe { *libc::__error() }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn set_errno(_value: libc::c_int) {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn get_errno() -> libc::c_int {
    0
}

#[cfg(target_os = "linux")]
pub(crate) fn stat_dev(stat: &libc::stat) -> u64 {
    stat.st_dev
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn stat_dev(stat: &libc::stat) -> u64 {
    stat.st_dev as u64
}

#[cfg(target_os = "linux")]
pub(crate) fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn stat_mode(stat: &libc::stat) -> u32 {
    stat.st_mode as u32
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn proc_fd_path_names_the_held_object_from_any_thread() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("held");
        std::fs::write(&path, b"held").unwrap();
        let file = File::open(&path).unwrap();
        // The name follows the descriptor, not the pathname it was opened by.
        std::fs::rename(&path, dir.path().join("moved")).unwrap();
        assert_eq!(std::fs::read(proc_fd_path(&file)).unwrap(), b"held");
        let read = std::thread::scope(|scope| {
            scope
                .spawn(|| std::fs::read(proc_fd_path(&file)))
                .join()
                .unwrap()
        });
        assert_eq!(read.unwrap(), b"held");
    }

    #[test]
    fn directory_reads_in_steps_see_every_name_and_stop_when_asked() {
        let dir = crate::test_support::tempdir().unwrap();
        for index in 0..1000 {
            File::create(dir.path().join(format!("f{index:04}"))).unwrap();
        }
        let open = || File::open(dir.path()).unwrap();
        assert_eq!(walk_directory_entries(open(), usize::MAX).unwrap(), 1000);
        assert_eq!(walk_directory_entries(open(), 10).unwrap(), 10);
        assert!(!directory_is_empty(open()).unwrap());
        let empty = crate::test_support::tempdir().unwrap();
        assert!(directory_is_empty(File::open(empty.path()).unwrap()).unwrap());
        let mut names = Vec::new();
        read_directory_in_steps(&open(), 8 << 10, |name| {
            names.push(name.to_vec());
            true
        })
        .unwrap();
        names.sort();
        let expected: Vec<Vec<u8>> = (0..1000)
            .map(|index| format!("f{index:04}").into_bytes())
            .collect();
        assert_eq!(names, expected);

        // The walk is a single read: with long names it returns fewer
        // entries than the limit rather than reading on.
        let long = crate::test_support::tempdir().unwrap();
        for index in 0..300 {
            File::create(long.path().join(format!("{index:0200}"))).unwrap();
        }
        let read = walk_directory_entries(File::open(long.path()).unwrap(), 300).unwrap();
        assert!((1..300).contains(&read), "{read}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod name_folding_tests {
    use super::*;

    #[test]
    fn linux_directories_fold_names_as_their_filesystem_does() {
        use NameFolding::{Case, Exact};
        const EXT4: u32 = 0xef53;
        const ZFS: u32 = 0x2fc1_2fc1;
        const CASEFOLD: libc::c_int = 0x4000_0000;
        const DIRV2CI: u32 = 0x1000;
        for (file_system, flags, xfs, expected) in [
            (EXT4, Some(0), None, Exact),
            (EXT4, Some(CASEFOLD), None, Case),
            (EXT4, None, None, Case),
            (TMPFS_MAGIC, None, None, Exact),
            (TMPFS_MAGIC, Some(CASEFOLD), None, Case),
            (XFS_MAGIC, Some(0), Some(0x7f_cecb), Exact),
            (XFS_MAGIC, Some(0), Some(0x7f_cecb | DIRV2CI), Case),
            (XFS_MAGIC, Some(0), None, Case),
            (ZFS, Some(0), None, Case),
        ] {
            assert_eq!(
                linux_name_folding(file_system, flags, xfs),
                expected,
                "{file_system:#x} {flags:?} {xfs:?}"
            );
        }
    }

    /// The geometry of an XFS filesystem, where the tests run on one.
    #[test]
    fn xfs_geometry_reads_where_a_filesystem_is_xfs() {
        for path in ["/", "/tmp", "/var/tmp"] {
            let Ok(directory) = File::open(path) else {
                continue;
            };
            let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
            if unsafe { libc::fstatfs(directory.as_raw_fd(), stats.as_mut_ptr()) } != 0
                || unsafe { stats.assume_init() }.f_type as u32 != XFS_MAGIC
            {
                continue;
            }
            assert!(xfs_geometry_flags(&directory).is_some(), "{path}");
            return;
        }
        eprintln!("no XFS filesystem here; nothing to check");
    }
}
