//! Linux direct data-copy operations. File creation, authorization, metadata
//! and publication stay with FsOps; source preparation is shared with reads.
use std::fs::File;
use std::os::fd::AsRawFd;

/// Try the exact planned range before scheduling any physical source reads.
/// Both descriptors have already passed the local copy's identity checks.
pub(crate) fn try_clone(source: &File, destination: &File, size: u64) -> bool {
    if size == 0 {
        return true;
    }
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_LOCAL_READ_AHEAD").is_some() {
        return false;
    }
    let range = libc::file_clone_range {
        src_fd: source.as_raw_fd().into(),
        src_offset: 0,
        src_length: size,
        dest_offset: 0,
    };
    // SAFETY: range has the UAPI layout and remains alive for the ioctl;
    // both fds are live. A failed clone is followed by copying from offset zero.
    unsafe { libc::ioctl(destination.as_raw_fd(), libc::FICLONERANGE, &range) == 0 }
}
