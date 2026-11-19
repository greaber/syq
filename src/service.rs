//! The lifecycle that syq's single-instance services share: the receiving
//! service, the SSH authorization provider and the session pool. Each runs
//! while it holds a private lock file and answers on a Unix socket beside
//! it; each keeps its own requests, replies and handler.
//!
//! Other syq versions on the same machine use the same lock and socket
//! paths, so their names and modes, and the use of `flock`, must not change.

use crate::lock_file::{LockFile, PROBE_GRACE};
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often a client looks again while a service starts or stops.
const POLL: Duration = Duration::from_millis(20);

/// Take the lock at `path` for a starting service, or None when another
/// service holds it. The start retries for [`PROBE_GRACE`], so that a
/// concurrent probe (`LockFile::is_held`) cannot make it exit as a
/// duplicate. A service that removes its lock file as it exits can leave a
/// start that waited holding the lock on a removed file: it then opens the
/// file now named.
pub(crate) fn lock_for_start(path: &Path) -> Result<Option<LockFile>> {
    let deadline = Instant::now() + PROBE_GRACE;
    for _ in 0..8 {
        let lock =
            LockFile::open(path, true).with_context(|| format!("open {}", path.display()))?;
        if !lock
            .try_exclusive_within(deadline.saturating_duration_since(Instant::now()))
            .with_context(|| format!("lock {}", path.display()))?
        {
            return Ok(None);
        }
        let locked = lock.file().metadata()?;
        match fs::symlink_metadata(path) {
            Ok(named) if (named.dev(), named.ino()) == (locked.dev(), locked.ino()) => {
                return Ok(Some(lock));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", path.display()));
            }
        }
    }
    Ok(None)
}

/// Whether the entry at `path` is a socket this user owns.
fn own_socket(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() }
}

/// A service's listening socket, with what wakes the service: a client, a
/// [`Waker`], or a signal that [`Server::stop_on_signals`] registered.
/// Dropping it removes the socket, unless another has replaced it.
pub(crate) struct Server {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
    wake: UnixStream,
    sender: Arc<UnixStream>,
    _signals: Option<crate::process::signals::Owned<crate::process::signals::Registrations>>,
}

impl Server {
    /// Listen at `path`, open to this user only. A stale socket there is
    /// removed only if this user owns it; anything else there is an error.
    pub(crate) fn bind(path: &Path) -> Result<Self> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if own_socket(&metadata) => fs::remove_file(path)
                .with_context(|| format!("remove stale socket {}", path.display()))?,
            Ok(_) => bail!("unexpected entry at {}", path.display()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        }
        let listener =
            UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let metadata = fs::symlink_metadata(path)?;
        let (wake, sender) = crate::process::with_inheritance_guard(UnixStream::pair)?;
        wake.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            identity: (metadata.dev(), metadata.ino()),
            wake,
            sender: Arc::new(sender),
            _signals: None,
        })
    }

    /// Set `stop` on SIGINT or SIGTERM, and wake the service.
    pub(crate) fn stop_on_signals(&mut self, stop: &Arc<AtomicBool>) -> Result<()> {
        let sender = &self.sender;
        self._signals = Some(crate::process::signals::owned(
            &[libc::SIGINT, libc::SIGTERM],
            || {
                let mut registrations = crate::process::signals::Registrations::default();
                for signal in [libc::SIGINT, libc::SIGTERM] {
                    registrations.push(signal_hook::flag::register(signal, stop.clone())?);
                    registrations.push(signal_hook::low_level::pipe::register(
                        signal,
                        sender.try_clone()?,
                    )?);
                }
                Ok(registrations)
            },
        )?);
        Ok(())
    }

    /// What another thread uses to wake the service.
    pub(crate) fn waker(&self) -> Waker {
        Waker(self.sender.clone())
    }

    /// The next client waiting, None when there is none. A client of another
    /// user is turned away. The stream is blocking: the listener's mode is
    /// inherited by accepted sockets on BSD.
    pub(crate) fn accept(&self) -> Result<Option<UnixStream>> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if crate::sys::peer_uid(&stream).ok() != Some(unsafe { libc::geteuid() }) {
                        continue;
                    }
                    stream.set_nonblocking(false)?;
                    return Ok(Some(stream));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("accept on {}", self.path.display()))
                }
            }
        }
    }

    /// Wait until a client connects, the service is woken, or `timeout`
    /// passes (None: no limit), and say whether a client may be waiting.
    pub(crate) fn wait(&mut self, timeout: Option<Duration>) -> Result<bool> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // Round up, so that a wait never ends just before it is due.
        let timeout = timeout.map_or(-1, |timeout| {
            timeout.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as libc::c_int
        });
        let result =
            unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("wait for the service's next event");
            }
        }
        loop {
            match self.wake.read(&mut [0; 128]) {
                Ok(0) => bail!("service wake channel closed"),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(result > 0 && descriptors[0].revents != 0)
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Whether the socket at its path is still this one: a closed scope or
    /// another service may have removed or replaced it.
    pub(crate) fn is_bound(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.identity)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.is_bound() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Wakes a service from [`Server::wait`].
#[derive(Clone)]
pub(crate) struct Waker(Arc<UnixStream>);
impl Waker {
    pub(crate) fn wake(&self) {
        let _ = (&*self.0).write(&[1]);
    }
}

/// A service binds its socket before making it private. A client that
/// requires a private socket does not connect before then; while the
/// service holds its lock, it is still starting.
#[derive(Debug)]
pub(crate) struct NotYetPrivate;
impl std::fmt::Display for NotYetPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("service control socket must be owned and private")
    }
}
impl std::error::Error for NotYetPrivate {}

/// Connect to a service's socket at `path`, with `timeout` for each read
/// and write. The socket must be this user's, and private too when
/// `private` is set.
pub(crate) fn connect(path: &Path, timeout: Duration, private: bool) -> Result<UnixStream> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        own_socket(&metadata),
        "service control socket {} must be a socket owned by the current user",
        path.display()
    );
    if private && metadata.mode() & 0o077 != 0 {
        return Err(NotYetPrivate.into());
    }
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Whether nothing answered on a control socket, as while a locked service
/// is starting or stopping, rather than the service replying with an error.
pub(crate) fn unanswered(error: &anyhow::Error) -> bool {
    use std::io::ErrorKind::*;
    error.is::<NotYetPrivate>()
        || error.chain().any(|cause| {
            cause.downcast_ref::<io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    NotFound
                        | ConnectionRefused
                        | ConnectionReset
                        | BrokenPipe
                        | UnexpectedEof
                        | WouldBlock
                        | TimedOut
                )
            })
        })
}

/// Whether a service holds the lock at `lock`.
pub(crate) fn is_running(lock: &Path) -> Result<bool> {
    LockFile::is_held(lock).with_context(|| format!("inspect {}", lock.display()))
}

/// Ask the service holding `lock` with `query`, giving one that is starting
/// or stopping up to `timeout` to answer; `not_answering` describes one that
/// did not. None once no service holds the lock.
pub(crate) fn answer<T>(
    lock: &Path,
    timeout: Duration,
    mut query: impl FnMut() -> Result<T>,
    not_answering: impl FnOnce() -> String,
) -> Result<Option<T>> {
    let deadline = Instant::now() + timeout;
    while is_running(lock)? {
        match query() {
            Ok(answer) => return Ok(Some(answer)),
            Err(error) if unanswered(&error) => {
                if Instant::now() >= deadline {
                    return Err(error.context(not_answering()));
                }
                std::thread::sleep(POLL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// How waiting for a service to give up its lock is reported.
pub(crate) struct Ending {
    pub lock: PathBuf,
    pub timeout: Duration,
    /// The error once `timeout` has passed.
    pub stuck: String,
    /// What to say every five seconds meanwhile, if anything.
    pub progress: Option<String>,
}

impl Ending {
    /// Wait while a service holds the lock, calling `step` each time
    /// first, until it says the wait is over.
    fn wait(&self, mut step: impl FnMut() -> bool) -> Result<()> {
        let deadline = Instant::now() + self.timeout;
        let mut progress = Instant::now();
        while is_running(&self.lock)? {
            if step() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("{}", self.stuck);
            }
            if let Some(say) = &self.progress {
                if progress.elapsed() >= Duration::from_secs(5) {
                    crate::output::diagnostic!("syq: {say}");
                    progress = Instant::now();
                }
            }
            std::thread::sleep(POLL);
        }
        Ok(())
    }

    /// Ask whichever service holds the lock to stop with `request`, given
    /// the time left, until none holds it.
    pub(crate) fn stop(&self, mut request: impl FnMut(Duration) -> Result<()>) -> Result<()> {
        let deadline = Instant::now() + self.timeout;
        self.wait(|| {
            let left = deadline.saturating_duration_since(Instant::now());
            if !left.is_zero() {
                let _ = request(left);
            }
            false
        })
    }

    /// Wait for service process `pid`, which is stopping, to give up the
    /// lock: until it has exited, or another service answers `pid_of`.
    pub(crate) fn await_exit(
        &self,
        pid: u32,
        mut pid_of: impl FnMut() -> Result<u32>,
    ) -> Result<()> {
        self.wait(|| match pid_of() {
            Ok(answered) => answered != pid,
            Err(_) => !process_alive(pid),
        })
    }
}

/// Whether process `pid` still runs, and is not a zombie.
pub(crate) fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0
        || (unsafe { libc::kill(pid, 0) } != 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::EPERM))
    {
        return false;
    }
    #[cfg(target_os = "linux")]
    if fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z'))
    }) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn a_server_replaces_its_own_stale_socket_privately_and_removes_it() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("s.sock");
        drop(UnixListener::bind(&path).unwrap());
        let server = Server::bind(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert!(server.is_bound());
        drop(server);
        assert!(!path.exists());
    }

    #[test]
    fn a_server_refuses_what_is_not_a_socket_and_keeps_a_replacement() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("s.sock");
        fs::write(&path, b"").unwrap();
        assert!(Server::bind(&path).is_err());
        assert!(path.is_file());
        fs::remove_file(&path).unwrap();
        let server = Server::bind(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        assert!(!server.is_bound());
        drop(server);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        drop(replacement);
    }

    #[test]
    fn a_server_wakes_for_a_client_a_waker_or_its_time() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("s.sock");
        let mut server = Server::bind(&path).unwrap();
        let started = Instant::now();
        assert!(!server.wait(Some(Duration::from_millis(50))).unwrap());
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(server.accept().unwrap().is_none());

        let waker = server.waker();
        let woken = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            waker.wake();
        });
        assert!(!server.wait(Some(Duration::from_secs(30))).unwrap());
        woken.join().unwrap();

        let _client = connect(&path, Duration::from_secs(5), true).unwrap();
        assert!(server.wait(Some(Duration::from_secs(30))).unwrap());
        let accepted = server.accept().unwrap().unwrap();
        // Blocking, whatever the listener's mode on this platform.
        accepted
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let error = (&accepted).read(&mut [0]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(server.accept().unwrap().is_none());
    }

    #[test]
    fn a_client_waits_for_a_socket_that_is_not_yet_private_only_when_asked() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("s.sock");
        let missing = connect(&path, Duration::from_secs(1), false).unwrap_err();
        assert!(unanswered(&missing), "{missing:#}");
        let _listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let error = connect(&path, Duration::from_secs(1), true).unwrap_err();
        assert!(error.is::<NotYetPrivate>());
        assert!(unanswered(&error));
        connect(&path, Duration::from_secs(1), false).unwrap();
        let file = root.path().join("file");
        fs::write(&file, b"").unwrap();
        let error = connect(&file, Duration::from_secs(1), false).unwrap_err();
        assert!(!unanswered(&error), "{error:#}");
    }

    #[test]
    fn a_stop_asks_again_until_the_lock_is_free_and_gives_up_in_time() {
        let root = crate::test_support::short_tempdir().unwrap();
        let lock_path = root.path().join("s.lock");
        let lock = lock_for_start(&lock_path).unwrap().unwrap();
        let ending = Ending {
            lock: lock_path.clone(),
            timeout: Duration::from_millis(200),
            stuck: "stuck".into(),
            progress: None,
        };
        let mut asked = 0;
        let error = ending
            .stop(|_| {
                asked += 1;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "stuck");
        assert!(asked > 1);
        let mut lock = Some(lock);
        ending
            .stop(|_| {
                drop(lock.take());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn a_lock_removed_while_a_start_waits_is_taken_again_by_its_new_name() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("s.lock");
        let owner = lock_for_start(&path).unwrap().unwrap();
        let exiting = std::thread::spawn(move || {
            std::thread::sleep(PROBE_GRACE / 4);
            fs::remove_file(&root.path().join("s.lock")).unwrap();
            drop(owner);
            root
        });
        let lock = lock_for_start(&path).unwrap().unwrap();
        let root = exiting.join().unwrap();
        let named = fs::metadata(root.path().join("s.lock")).unwrap();
        let locked = lock.file().metadata().unwrap();
        assert_eq!((named.dev(), named.ino()), (locked.dev(), locked.ino()));
    }
}
