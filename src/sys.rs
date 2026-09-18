//! Thin wrappers over the libc calls the descriptor-relative filesystem code
//! shares: interrupted-call retry, `openat`, `errno`, `stat` field widths, and
//! directory streams.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};

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
    let mut names = Vec::new();
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
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    Ok(names)
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
