//! Linux direct data-copy operations and their read-preparation policy.
//! File creation, authorization, metadata and publication stay with FsOps.
use crate::read_ahead::ReadAhead;
use std::fs::File;
use std::os::fd::AsRawFd;

pub(crate) const BLOCK: u64 = 1 << 20;

/// Local kernel copies use observed filesystem input as their activation
/// signal. A streaming sender can supply its own queue feedback directly to
/// ReadAhead without inheriting this disk-specific policy.
pub(crate) struct SourcePreparation {
    read_ahead: ReadAhead,
    previous_input: Option<libc::c_long>,
}

impl SourcePreparation {
    pub(crate) fn new(size: u64) -> Self {
        Self {
            read_ahead: ReadAhead::new(0..size),
            previous_input: input_activity(),
        }
    }
    pub(crate) fn advance(&mut self, source: &File, copied: u64) {
        self.read_ahead.advance(source, copied, || {
            let current = input_activity();
            let input = self
                .previous_input
                .zip(current)
                .is_some_and(|(before, after)| after > before);
            self.previous_input = current;
            #[cfg(debug_assertions)]
            let input = input || std::env::var_os("SYQ_TEST_LOCAL_READ_AHEAD").is_some();
            input
        });
    }
}

fn input_activity() -> Option<libc::c_long> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the complete structure on success.
    if unsafe { libc::getrusage(libc::RUSAGE_THREAD, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    Some(unsafe { usage.assume_init() }.ru_inblock)
}

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
