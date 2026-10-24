//! Read leases on the existing files a grouped comparison may build patches
//! from, on Linux.
//!
//! A patch whose stage clones or copies the file it replaces keeps that
//! file's reused blocks unread, so it must know that nothing wrote the file
//! between its comparison and the copy. The file's fingerprint does not show
//! every such write: where change times are coarse a write can keep the
//! change time it found, and a store through a shared mapping of a page
//! that is already dirty changes nothing that `stat` reports. A read lease
//! does show them. The kernel grants one only while no one has the file
//! open for writing, a writable shared mapping included, and begins to
//! break it as soon as anyone opens the file for writing or truncates it.
//! So a lease taken before the comparison reads the file, and still held
//! once the stage holds its copy, shows that nothing wrote the file in
//! between.
//!
//! An open that breaks a lease waits until the holder releases it, or until
//! `/proc/sys/fs/lease-break-time` (45 s by default) has passed. One thread
//! of the process checks every held lease each `POLL_INTERVAL` and releases
//! those being broken, so a program that opens one of these files for
//! writing waits about that long at most; the file's patch then checks the
//! blocks it reuses instead. A break also signals the holder. Each lease
//! asks for `SIGURG`, which is ignored unless handled, rather than the
//! default `SIGIO`, which ends the process.
//!
//! Leases show only what reaches a file through this kernel, so they are
//! trusted only on the local filesystems where that holds
//! (`fs_caps::leases_show_writers`). Elsewhere, and on macOS, whose kernel
//! refuses leases to every process (`EPERM`), the fingerprint alone vouches
//! for a file.

#[cfg(not(target_os = "linux"))]
use std::fs::File;

/// The smallest existing file, and source, whose comparison takes a lease:
/// a patch reuses at least this much before its stage clones or copies the
/// file it replaces (`small_batch::CLONE_MIN_REUSED`). A smaller patch reads
/// and checks every block it reuses.
pub(super) const LEASE_MIN_BYTES: u64 = 1 << 20;

#[cfg(target_os = "linux")]
pub(super) use linux::{release_broken, ReadLease};

/// No lease is ever taken outside Linux.
#[cfg(not(target_os = "linux"))]
pub(super) enum ReadLease {}

#[cfg(not(target_os = "linux"))]
impl ReadLease {
    pub(super) fn file(&self) -> &File {
        match *self {}
    }

    pub(super) fn intact(&self) -> bool {
        match *self {}
    }

    pub(super) fn release(&self) {
        match *self {}
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn release_broken() {}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
    use std::time::Duration;

    /// `F_SETSIG`, which the libc crate does not name for every target.
    const F_SETSIG: libc::c_int = 10;

    /// How often held leases are checked for breaks.
    const POLL_INTERVAL: Duration = Duration::from_millis(20);

    /// A read lease, held through a descriptor of its own until it is
    /// released or dropped.
    pub(in crate::fsops) struct ReadLease(Arc<Held>);

    struct Held {
        file: File,
        released: AtomicBool,
    }

    impl Held {
        fn holds(&self) -> bool {
            // SAFETY: F_GETLEASE only reads the lease of a live descriptor.
            !self.released.load(Ordering::Acquire)
                && unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETLEASE) } == libc::F_RDLCK
        }

        fn release(&self) {
            if !self.released.swap(true, Ordering::AcqRel) {
                // SAFETY: F_SETLEASE only changes the lease of a live
                // descriptor; one already gone or broken is left as it is.
                unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) };
            }
        }
    }

    impl Drop for Held {
        fn drop(&mut self) {
            // Closing the descriptor would release the lease too, unless a
            // duplicate of it, as a patch's source may hold, stays open.
            self.release();
        }
    }

    impl ReadLease {
        /// Take a read lease on the file `file` reads. Refused when someone
        /// has the file open for writing (`EAGAIN`), when this process
        /// neither owns the file nor has `CAP_LEASE` (`EACCES`), when leases
        /// are disabled (`EINVAL`), or when no thread can be started to
        /// release broken leases.
        pub(in crate::fsops) fn take(file: &File) -> io::Result<Self> {
            #[cfg(debug_assertions)]
            if std::env::var_os("SYQ_TEST_LEASES").is_some_and(|value| value == "refuse") {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            let poller = poller().ok_or_else(|| {
                io::Error::other("no thread could be started to release broken leases")
            })?;
            let file = file.try_clone()?;
            let fd = file.as_raw_fd();
            // SAFETY: both calls only set fields of the open file behind a
            // live descriptor. The signal comes first, so that no break can
            // send the default one.
            if unsafe { libc::fcntl(fd, F_SETSIG, libc::SIGURG) } != 0
                || unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let held = Arc::new(Held {
                file,
                released: AtomicBool::new(false),
            });
            poller.watch(&held);
            Ok(Self(held))
        }

        /// The leased descriptor.
        pub(in crate::fsops) fn file(&self) -> &File {
            &self.0.file
        }

        /// Whether the lease is still held: no one has opened the file for
        /// writing, or truncated it, since it was taken. A lease being
        /// broken is no longer intact, and never is again.
        pub(in crate::fsops) fn intact(&self) -> bool {
            self.0.holds()
        }

        /// Let the lease go, once it has served.
        pub(in crate::fsops) fn release(&self) {
            self.0.release();
        }
    }

    struct Poller {
        held: Mutex<Vec<Weak<Held>>>,
        wake: Condvar,
    }

    impl Poller {
        fn watch(&self, held: &Arc<Held>) {
            let mut list = self.held.lock().unwrap();
            list.push(Arc::downgrade(held));
            if list.len() == 1 {
                self.wake.notify_one();
            }
        }

        /// Release each lease a break has begun on, and forget those
        /// released or dropped.
        fn sweep(&self) {
            self.held.lock().unwrap().retain(|held| {
                held.upgrade().is_some_and(|held| {
                    let holds = held.holds();
                    if !holds {
                        held.release();
                    }
                    holds
                })
            });
        }

        fn run(&self) {
            loop {
                {
                    let mut list = self.held.lock().unwrap();
                    while list.is_empty() {
                        list = self.wake.wait(list).unwrap();
                    }
                }
                std::thread::sleep(POLL_INTERVAL);
                self.sweep();
            }
        }
    }

    static POLLER: OnceLock<Option<&'static Poller>> = OnceLock::new();

    /// The process's poller, started with the first lease; None when the
    /// system refuses its thread, and leases are not taken.
    fn poller() -> Option<&'static Poller> {
        *POLLER.get_or_init(|| {
            let poller: &'static Poller = Box::leak(Box::new(Poller {
                held: Mutex::new(Vec::new()),
                wake: Condvar::new(),
            }));
            std::thread::Builder::new()
                .name("syq-leases".into())
                .spawn(move || poller.run())
                .ok()
                .map(|_| poller)
        })
    }

    /// Release at once, rather than at the next check, every lease of this
    /// process that a break has begun on: one that this process's own
    /// write-open has just begun to break, as when `--in-place=update` opens
    /// a file whose comparison still holds its lease.
    pub(in crate::fsops) fn release_broken() {
        if let Some(Some(poller)) = POLLER.get() {
            poller.sweep();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::Instant;

        /// A file of this process's own on the test filesystem, and whether
        /// that filesystem's leases are trusted there.
        fn leasable() -> (tempfile::TempDir, std::path::PathBuf, bool) {
            let directory = crate::test_support::tempdir().unwrap();
            let path = directory.path().join("file");
            std::fs::write(&path, vec![7; 1 << 16]).unwrap();
            let trusted = crate::fsops::fs_caps::leases_show_writers(&File::open(&path).unwrap());
            if !trusted {
                eprintln!("note: the test filesystem's leases are not trusted");
            }
            (directory, path, trusted)
        }

        #[test]
        fn a_writer_waits_for_the_poller_and_breaks_the_lease_for_good() {
            let (_directory, path, trusted) = leasable();
            if !trusted {
                return;
            }
            let file = File::open(&path).unwrap();
            let lease = ReadLease::take(&file).unwrap();
            assert!(lease.intact());
            let started = Instant::now();
            let writer = {
                let path = path.clone();
                std::thread::spawn(move || OpenOptions::new().write(true).open(path).map(drop))
            };
            writer.join().unwrap().unwrap();
            let waited = started.elapsed();
            // Well within the kernel's break time (45 s by default): the
            // poller released the lease.
            assert!(waited < Duration::from_secs(5), "{waited:?}");
            assert!(!lease.intact());
            // A later check does not find it held again.
            std::thread::sleep(POLL_INTERVAL * 2);
            assert!(!lease.intact());
        }

        #[test]
        fn a_lease_is_refused_while_the_file_is_open_or_mapped_for_writing() {
            let (_directory, path, trusted) = leasable();
            if !trusted {
                return;
            }
            let reader = File::open(&path).unwrap();
            let writer = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let refused = ReadLease::take(&reader).err().unwrap();
            assert_eq!(refused.raw_os_error(), Some(libc::EAGAIN));
            // A writable shared mapping keeps the file open for writing after
            // its descriptor is closed.
            // SAFETY: a fresh shared mapping of a live descriptor, unmapped
            // below.
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    writer.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            drop(writer);
            let refused = ReadLease::take(&reader).err().unwrap();
            assert_eq!(refused.raw_os_error(), Some(libc::EAGAIN));
            // SAFETY: the mapping made above.
            assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);
            assert!(ReadLease::take(&reader).unwrap().intact());
        }

        #[test]
        fn a_released_lease_lets_this_process_open_the_file_for_writing() {
            let (_directory, path, trusted) = leasable();
            if !trusted {
                return;
            }
            let write_now = || {
                OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&path)
            };
            let file = File::open(&path).unwrap();
            let lease = ReadLease::take(&file).unwrap();
            lease.release();
            assert!(!lease.intact());
            write_now().unwrap();
            // A non-blocking open breaks a lease still held, and fails; the
            // broken lease is released at once, and the open can be retried.
            let lease = ReadLease::take(&file).unwrap();
            let refused = write_now().err().unwrap();
            assert_eq!(refused.raw_os_error(), Some(libc::EAGAIN));
            release_broken();
            write_now().unwrap();
            assert!(!lease.intact());
        }
    }
}
