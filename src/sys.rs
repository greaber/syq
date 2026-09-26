//! Thin wrappers over the libc calls the descriptor-relative filesystem code
//! shares: interrupted-call retry, `openat`, `errno`, `stat` field widths, and
//! directory streams.

use std::ffi::CStr;
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
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

/// Resolve descriptor numbers in the calling thread's table. `/proc/self/fd`
/// selects the thread-group leader, which can have a different table after
/// CLONE_FILES is unshared. Do not cache an opened fd directory across threads.
#[cfg(target_os = "linux")]
pub(crate) const PROC_FD_DIRECTORY: &str = "/proc/thread-self/fd";

/// This path is only valid while `file` is held and on the calling thread's
/// descriptor table. It must not be sent to another executor or subprocess.
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn proc_fd_path_selects_the_calling_threads_table() {
        let dir = crate::test_support::tempdir().unwrap();
        let original_path = dir.path().join("original");
        let replacement_path = dir.path().join("replacement");
        std::fs::write(&original_path, b"original").unwrap();
        std::fs::write(&replacement_path, b"replacement").unwrap();
        let original = File::open(&original_path).unwrap();
        let replacement = File::open(&replacement_path).unwrap();
        let result = std::thread::scope(|scope| {
            scope
                .spawn(|| -> io::Result<Vec<u8>> {
                    // Only this temporary thread gets a private table. Borrow
                    // the parent-owned Files; never drop them in the child.
                    // The kernel releases the copied table when the thread exits.
                    retry_zero(|| unsafe { libc::unshare(libc::CLONE_FILES) })?;
                    let replaced =
                        unsafe { libc::dup2(replacement.as_raw_fd(), original.as_raw_fd()) };
                    if replaced < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // The same descriptor number now names a different inode
                    // here, while the original remains open in the shared table.
                    std::fs::read(proc_fd_path(&original))
                })
                .join()
                .unwrap()
        });
        assert_eq!(result.unwrap(), b"replacement");
        assert_eq!(std::fs::read(proc_fd_path(&original)).unwrap(), b"original");
    }
}
