use super::*;

pub(super) static PROCESS_UMASK: OnceLock<u32> = OnceLock::new();

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
pub(super) fn read_process_umask() -> u32 {
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
pub(super) fn parse_proc_status_umask(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Umask:"))
        .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
        .filter(|mask| *mask <= 0o777)
}

pub(super) fn probe_umask() -> u32 {
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

/// Reserve initial headroom after informational exits, before worker threads.
/// Source setup reserves more when its descriptor budget needs it.
pub(crate) fn reserve_startup_descriptors() {
    reserve_descriptor_capacity(16 * 1024);
}

/// Prepare Linux's descriptor table without keeping files open or changing
/// limits. Growing a table shared by threads can wait for an RCU grace period;
/// reserve initial headroom before threads start, then use known source demand
/// to consolidate larger growth. This is only an optimization: allocation can
/// fail, and later work may still exceed the reserved capacity.
#[cfg(target_os = "linux")]
pub(crate) fn reserve_descriptor_capacity(wanted: usize) {
    use std::os::fd::{FromRawFd, OwnedFd};

    let Ok(limits) = nofile_limits() else {
        return;
    };
    let slots = (wanted as u128).min(limits.rlim_cur as u128);
    let Some(last) = slots
        .checked_sub(1)
        .and_then(|last| libc::c_int::try_from(last).ok())
    else {
        return;
    };
    // An occupied slot already proves the table is large enough. Never use
    // dup2: the target could be an inherited descriptor owned by our caller.
    if unsafe { libc::fcntl(last, libc::F_GETFD) } >= 0 {
        return;
    }
    let Ok(file) = File::open("/dev/null") else {
        return;
    };
    // SAFETY: file remains live, and F_DUPFD_CLOEXEC creates a new descriptor
    // without replacing any existing one. Closing it leaves table capacity
    // intact in this process; forked children must prepare their own tables.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, last) };
    if fd >= 0 {
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn reserve_descriptor_capacity(_wanted: usize) {}

pub(super) fn source_descriptor_requirement(
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

/// Count a snapshot of the calling thread's live descriptors. Reading an fd directory keeps
/// the common Linux and Darwin paths proportional to the number of open
/// descriptors. Its directory descriptor is visible in the listing, which is
/// a harmless conservative overcount. The portable fallback scans the finite
/// descriptor range and treats unexpected `fcntl` errors as open.
pub(crate) fn current_open_descriptor_count(soft_limit: libc::rlim_t) -> Result<usize> {
    #[cfg(target_os = "linux")]
    let fd_directory = crate::sys::PROC_FD_DIRECTORY;
    #[cfg(not(target_os = "linux"))]
    let fd_directory = "/dev/fd";
    if let Ok(entries) = fs::read_dir(fd_directory) {
        return Ok(entries.count());
    }
    // On Linux /dev/fd normally selects /proc/self/fd, so it is not a valid
    // fallback for a private table. fcntl always consults the current table.

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

pub(crate) fn require_source_descriptor_capacity(
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
            "source setup needs about {required} open-file slots ({current_open} currently open) for {root_count} roots, {shared_workers} shared workers, and {independent_workers} independent workers, but this endpoint permits {}; reduce the number of source selectors or use a smaller performance-tuning workers value",
            limit.rlim_cur
        );
    }
    reserve_descriptor_capacity(required);
    Ok(())
}
