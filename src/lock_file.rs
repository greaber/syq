//! Advisory locks on files syq owns. Every lock syq takes is a `flock` lock,
//! which other syq versions on the same machine take on the same paths, so
//! this must stay `flock` and never become an `fcntl` lock.
//!
//! A `flock` lock belongs to the open file description, and a child forked
//! while the lock is held keeps a copy of that description until it execs.
//! Closing our descriptor alone could leave the lock held by that child, so
//! [`LockFile`] releases the lock explicitly when it is dropped, including
//! after a probe.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

/// How long a process that starts a single-instance service keeps retrying
/// a lock that is held. A probe (`is_held`) holds a lock for the moment
/// between taking and releasing it, which a starting service must not take
/// for another running copy. Older syq builds probe without releasing
/// explicitly, so a child they fork meanwhile can hold the probe a little
/// longer, until it execs.
pub(crate) const PROBE_GRACE: Duration = Duration::from_millis(100);

/// An open file used as a lock. Dropping it releases any lock it holds.
#[derive(Debug)]
#[must_use = "dropping a LockFile releases its lock"]
pub(crate) struct LockFile(File);

impl LockFile {
    /// Open the dedicated lock file at `path`, creating it with mode 0600 when
    /// `create` is set. The last component must not be a symbolic link, and
    /// the file must be a regular file owned by this user. One whose mode lets
    /// others in is restricted to the owner (an older build or a user could
    /// have left it so); `flock` itself needs only an open descriptor, so the
    /// mode is what keeps other users from holding it.
    pub(crate) fn open(path: &Path, create: bool) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            // An NFS client implements `flock` with a lock that needs a
            // descriptor open for writing.
            .write(true)
            .create(create)
            .truncate(false)
            .mode(0o600)
            // O_NONBLOCK: a FIFO in the lock's place must not block the open.
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "lock {} must be a regular file owned by the current user",
                    path.display()
                ),
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            crate::sys::retry_zero(|| unsafe { libc::fchmod(file.as_raw_fd(), 0o600) })?;
        }
        Ok(Self(file))
    }

    /// Use `file`, which the caller opened and checked, as a lock: a
    /// directory, a record that doubles as its own lock, or a file opened
    /// relative to a directory descriptor.
    pub(crate) fn adopt(file: File) -> Self {
        Self(file)
    }

    pub(crate) fn file(&self) -> &File {
        &self.0
    }

    /// Take the lock exclusively unless another holds it.
    pub(crate) fn try_exclusive(&self) -> io::Result<bool> {
        self.try_flock(libc::LOCK_EX)
    }

    /// Take the lock shared unless another holds it exclusively.
    pub(crate) fn try_shared(&self) -> io::Result<bool> {
        self.try_flock(libc::LOCK_SH)
    }

    /// Take the lock exclusively, waiting for as long as another holds it.
    pub(crate) fn exclusive(&self) -> io::Result<()> {
        flock(&self.0, libc::LOCK_EX)
    }

    /// Take the lock exclusively, retrying for up to `wait` while another
    /// holds it. A single-instance service takes its lock this way with
    /// [`PROBE_GRACE`], so that a probe cannot make it exit as a duplicate.
    pub(crate) fn try_exclusive_within(&self, wait: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + wait;
        loop {
            if self.try_exclusive()? {
                return Ok(true);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(left.min(Duration::from_millis(5)));
        }
    }

    /// Whether another open file holds this lock. Looking takes a shared
    /// lock for a moment and releases it at once.
    pub(crate) fn held(&self) -> io::Result<bool> {
        if !self.try_shared()? {
            return Ok(true);
        }
        flock(&self.0, libc::LOCK_UN)?;
        Ok(false)
    }

    /// Whether another process holds the dedicated lock file at `path`,
    /// which is not held when it does not exist.
    pub(crate) fn is_held(path: &Path) -> io::Result<bool> {
        match Self::open(path, false) {
            Ok(lock) => lock.held(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Give up this handle without releasing the lock, which a child
    /// process that inherited the descriptor now holds.
    pub(crate) fn into_inherited(self) -> File {
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never used or dropped again.
        unsafe { std::ptr::read(&this.0) }
    }

    fn try_flock(&self, operation: libc::c_int) -> io::Result<bool> {
        match flock(&self.0, operation | libc::LOCK_NB) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = flock(&self.0, libc::LOCK_UN);
    }
}

/// Lock `file` with `operation`, retrying while interrupted. Most callers
/// use [`LockFile`]; this serves one that waits on a copy of its descriptor.
pub(crate) fn flock(file: &impl AsRawFd, operation: libc::c_int) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: the descriptor stays open for the call.
    crate::sys::retry_zero(|| unsafe { libc::flock(fd, operation) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_dropped_lock_is_released_while_a_copy_of_its_descriptor_survives() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("a.lock");
        let lock = LockFile::open(&path, true).unwrap();
        assert!(lock.try_exclusive().unwrap());
        // dup shares the open file description, as fork does.
        let inherited = lock.file().try_clone().unwrap();
        assert!(LockFile::is_held(&path).unwrap());
        drop(lock);
        assert!(!LockFile::is_held(&path).unwrap());
        let next = LockFile::open(&path, false).unwrap();
        assert!(next.try_exclusive().unwrap());
        drop(inherited);
        assert!(LockFile::is_held(&path).unwrap());
    }

    #[test]
    fn a_probe_releases_its_lock_while_a_copy_of_its_descriptor_survives() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("a.lock");
        let probe = LockFile::open(&path, true).unwrap();
        let inherited = probe.file().try_clone().unwrap();
        assert!(!probe.held().unwrap());
        let owner = LockFile::open(&path, false).unwrap();
        assert!(owner.try_exclusive().unwrap());
        assert!(probe.held().unwrap());
        drop(inherited);
    }

    #[test]
    fn a_missing_lock_is_not_held_and_is_not_created_by_a_probe() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("a.lock");
        assert!(!LockFile::is_held(&path).unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn a_loose_lock_file_is_made_private() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("a.lock");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let lock = LockFile::open(&path, false).unwrap();
        assert!(lock.try_exclusive().unwrap());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn links_fifos_and_directories_are_refused() {
        let root = crate::test_support::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"").unwrap();
        let link = root.path().join("link.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(LockFile::open(&link, true).is_err());
        let fifo = root.path().join("fifo.lock");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // O_NONBLOCK keeps this from waiting for a writer.
        assert!(LockFile::open(&fifo, false).is_err());
        assert!(LockFile::open(root.path(), false).is_err());
    }

    #[test]
    fn a_start_waits_out_a_probe_but_not_an_owner() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("a.lock");
        let probe = LockFile::open(&path, true).unwrap();
        assert!(probe.try_shared().unwrap());
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(probe);
        });
        let starting = LockFile::open(&path, false).unwrap();
        assert!(starting.try_exclusive_within(PROBE_GRACE * 10).unwrap());
        release.join().unwrap();

        let other = LockFile::open(&path, false).unwrap();
        let started = Instant::now();
        assert!(!other.try_exclusive_within(PROBE_GRACE).unwrap());
        let elapsed = started.elapsed();
        assert!(
            elapsed >= PROBE_GRACE && elapsed < Duration::from_secs(5),
            "{elapsed:?}"
        );
    }

    #[test]
    fn a_handed_over_lock_stays_held() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("a.lock");
        let lock = LockFile::open(&path, true).unwrap();
        assert!(lock.try_exclusive().unwrap());
        let child = lock.file().try_clone().unwrap();
        drop(lock.into_inherited());
        assert!(LockFile::is_held(&path).unwrap());
        drop(child);
        assert!(!LockFile::is_held(&path).unwrap());
    }
}
