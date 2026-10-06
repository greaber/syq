//! Work a process finishes before SIGINT or SIGTERM ends it.
//!
//! The first such signal runs every registered cleanup on a thread of its
//! own: first those added with `add_first`, then the rest, each group in
//! the order they were added. Together they get at most `CAP`; then the
//! process ends by that signal, so its exit status is the one the signal
//! alone would give. Signals that arrive meanwhile change nothing. A
//! signal the process inherited as ignored, as a background job does, stays
//! ignored.
//!
//! Once a cleanup has been added, the process keeps these listeners: a
//! signal with no cleanup left still ends it the same way.
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering::SeqCst};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// How long cleanup may hold an interrupted process. A copy coordinator's
/// process group given SIGTERM is killed one second later, so this stays
/// well inside that.
const CAP: Duration = Duration::from_millis(500);

/// The exit status of a process whose cleanup outside a signal did not
/// finish within the cap.
const STALLED: i32 = 1;

type Action = Arc<dyn Fn(Instant) + Send + Sync>;

static STARTED: AtomicBool = AtomicBool::new(false);
static RECEIVED: AtomicI32 = AtomicI32::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
/// Keyed by whether the cleanup runs after the `add_first` ones, then by
/// the order of adding.
static CLEANUPS: Mutex<BTreeMap<(bool, u64), Action>> = Mutex::new(BTreeMap::new());
static LISTENING: OnceLock<io::Result<()>> = OnceLock::new();

fn cleanups() -> std::sync::MutexGuard<'static, BTreeMap<(bool, u64), Action>> {
    CLEANUPS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn cap() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(cap) = std::env::var("SYQ_TEST_TERMINATION_CAP_MS")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        return Duration::from_millis(cap);
    }
    CAP
}

/// Start a thread that runs or bounds cleanup. Cleanup is best effort: a
/// caller whose thread the system refuses skips it rather than running it
/// unbounded.
fn spawn(name: &str, work: impl FnOnce() + Send + 'static) -> io::Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var_os("SYQ_TEST_REFUSE_TERMINATION_THREADS").is_some() {
        return Err(io::Error::from_raw_os_error(libc::EAGAIN));
    }
    std::thread::Builder::new()
        .name(name.into())
        .spawn(work)
        .map(drop)
}

/// A cleanup registered with `add`. Dropping it removes it.
pub(crate) struct Cleanup((bool, u64));

impl Drop for Cleanup {
    fn drop(&mut self) {
        let removed = cleanups().remove(&self.0);
        drop(removed);
    }
}

/// Run `action` before a termination signal ends this process, after any
/// added with `add_first`. It receives the time by which it should stop.
pub(crate) fn add(action: impl Fn(Instant) + Send + Sync + 'static) -> io::Result<Cleanup> {
    insert(true, Arc::new(action))
}

/// Like `add`, for quick cleanup that must not wait behind slower work,
/// such as removing a private socket directory.
pub(crate) fn add_first(action: impl Fn(Instant) + Send + Sync + 'static) -> io::Result<Cleanup> {
    insert(false, Arc::new(action))
}

fn insert(later: bool, action: Action) -> io::Result<Cleanup> {
    listen()?;
    let key = (later, NEXT.fetch_add(1, SeqCst));
    cleanups().insert(key, action);
    Ok(Cleanup(key))
}

/// Run `work` on this thread with the cap enforced: unless a termination
/// signal is ending the process anyway, a watchdog ends it with status 1
/// if the work has not finished by then. `work` receives the time by which
/// it should stop. When no watchdog can be started the work is skipped.
pub(crate) fn bounded(work: impl FnOnce(Instant)) {
    let started = Instant::now();
    let cap = cap();
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let watchdog = spawn("cleanup-watchdog", move || {
        if finished.recv_timeout(cap) == Err(RecvTimeoutError::Timeout) && !STARTED.load(SeqCst) {
            unsafe { libc::_exit(STALLED) }
        }
    });
    if watchdog.is_err() {
        return;
    }
    work(started + cap * 4 / 5);
    drop(done);
}

/// While a termination signal is being handled, wait for its cleanup to end
/// the process, so that the process ends by that signal and reports nothing
/// about what the cleanup interrupted.
pub(crate) fn wait_if_terminating() {
    if STARTED.load(SeqCst) {
        loop {
            std::thread::park();
        }
    }
}

fn listen() -> io::Result<()> {
    let result = LISTENING.get_or_init(|| {
        let mut signals = Vec::new();
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if !super::signals::inherited_is_ignored(signal)? {
                signals.push(signal);
            }
        }
        if signals.is_empty() {
            return Ok(());
        }
        let (wait, wake) = super::with_inheritance_guard(std::os::unix::net::UnixStream::pair)?;
        wake.set_nonblocking(true)?;
        let fd = wake.as_raw_fd();
        let listeners = super::signals::owned(&signals, || {
            let mut registrations = super::signals::Registrations::default();
            for &signal in &signals {
                // Only atomics and write(2) run here.
                let action = move || {
                    if STARTED.swap(true, SeqCst) {
                        return;
                    }
                    RECEIVED.store(signal, SeqCst);
                    unsafe { libc::write(fd, b"!".as_ptr().cast(), 1) };
                };
                registrations.push(unsafe { signal_hook::low_level::register(signal, action) }?);
            }
            Ok(registrations)
        })?;
        std::thread::Builder::new()
            .name("termination".into())
            .spawn(move || {
                let mut wait = wait;
                let mut byte = [0u8];
                loop {
                    match wait.read(&mut byte) {
                        // A child forked by this process shares the socket
                        // until it execs, so the signal may have been that
                        // child's: act only on one this process received.
                        Ok(1) if STARTED.load(SeqCst) => break,
                        Ok(1) => {}
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        _ => return,
                    }
                }
                terminate(RECEIVED.load(SeqCst))
            })?;
        // The listeners and their wake-up socket serve the rest of the process.
        std::mem::forget(listeners);
        std::mem::forget(wake);
        Ok(())
    });
    result.as_ref().map(|_| ()).map_err(|error| {
        error
            .raw_os_error()
            .map(io::Error::from_raw_os_error)
            .unwrap_or_else(|| io::Error::new(error.kind(), error.to_string()))
    })
}

fn terminate(signal: i32) -> ! {
    let started = Instant::now();
    let cap = cap();
    let deadline = started + cap * 4 / 5;
    let actions: Vec<Action> = cleanups().values().cloned().collect();
    // Cleanup runs on its own thread, so that a filesystem that stops
    // answering cannot hold the process past the cap. Without that thread
    // there is nothing to bound it, so it is skipped.
    let (done, finished) = std::sync::mpsc::channel();
    let running = spawn("termination-cleanup", move || {
        for action in actions {
            action(deadline);
        }
        let _ = done.send(());
    });
    if running.is_ok() {
        let _ = finished.recv_timeout(cap.saturating_sub(started.elapsed()));
    }
    let _ = signal_hook::low_level::emulate_default_handler(signal);
    // Not reached: both signals end a process by default.
    unsafe { libc::_exit(128 + signal) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    const CHILD: &str = "SYQ_TEST_TERMINATION";
    const MARKER: &str = "SYQ_TEST_TERMINATION_MARKER";

    fn raise(signal: i32) {
        assert_eq!(unsafe { libc::raise(signal) }, 0);
    }

    /// A cleanup that appends `text` to the marker file.
    fn mark(text: &'static str) -> impl Fn(Instant) + Send + Sync + 'static {
        let marker = std::path::PathBuf::from(std::env::var_os(MARKER).unwrap());
        move |_| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&marker)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap()
        }
    }

    fn stall(_: Instant) {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    fn termination_subprocess() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        let mut cleanups = Vec::new();
        match mode.as_str() {
            "cleanup" | "inherited-ignore" => cleanups.push(add(mark("cleaned")).unwrap()),
            "removed" => {
                drop(add(mark("cleaned")).unwrap());
                cleanups.push(add(|_| {}).unwrap());
            }
            "first" => {
                cleanups.push(add(mark("later")).unwrap());
                cleanups.push(add_first(mark("first,")).unwrap());
            }
            "repeated" => cleanups.push(
                add(|deadline| {
                    std::thread::sleep(Duration::from_millis(300));
                    mark("cleaned")(deadline)
                })
                .unwrap(),
            ),
            "cap" | "refused" => cleanups.push(add(stall).unwrap()),
            "watchdog" => {
                bounded(stall);
                panic!("the watchdog did not end the process");
            }
            "watchdog-finished" | "watchdog-refused" => {
                bounded(mark("cleaned"));
                std::process::exit(7);
            }
            _ => panic!("unknown termination test mode"),
        }
        match mode.as_str() {
            "inherited-ignore" => {
                // Ignored, it runs nothing; the next SIGTERM still cleans up.
                raise(libc::SIGINT);
                std::thread::sleep(Duration::from_millis(200));
                raise(libc::SIGTERM);
            }
            "repeated" => {
                // A second interrupt does not cut the cleanup short.
                raise(libc::SIGINT);
                std::thread::sleep(Duration::from_millis(50));
                raise(libc::SIGINT);
            }
            _ => raise(libc::SIGTERM),
        }
        std::thread::sleep(Duration::from_secs(30));
        panic!("the signal did not end the process");
    }

    enum Ending {
        Signal(i32),
        Code(i32),
    }

    #[test]
    fn termination_runs_cleanup_and_ends_by_the_signal() {
        use Ending::*;
        for (mode, ending, marked, cap_ms, refused) in [
            (
                "cleanup",
                Signal(libc::SIGTERM),
                Some("cleaned"),
                None,
                false,
            ),
            ("removed", Signal(libc::SIGTERM), None, None, false),
            (
                "inherited-ignore",
                Signal(libc::SIGTERM),
                Some("cleaned"),
                None,
                false,
            ),
            (
                "first",
                Signal(libc::SIGTERM),
                Some("first,later"),
                None,
                false,
            ),
            (
                "repeated",
                Signal(libc::SIGINT),
                Some("cleaned"),
                None,
                false,
            ),
            ("cap", Signal(libc::SIGTERM), None, Some(200), false),
            // Unbounded, the stalled cleanup would hold the process for
            // longer than the test waits.
            ("refused", Signal(libc::SIGTERM), None, Some(60_000), true),
            ("watchdog", Code(STALLED), None, Some(200), false),
            ("watchdog-finished", Code(7), Some("cleaned"), None, false),
            ("watchdog-refused", Code(7), None, None, true),
        ] {
            let directory = crate::test_support::tempdir().unwrap();
            let marker = directory.path().join("cleaned");
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "process::termination::tests::termination_subprocess",
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .env(MARKER, &marker);
            if let Some(cap) = cap_ms {
                command.env("SYQ_TEST_TERMINATION_CAP_MS", cap.to_string());
            }
            if refused {
                command.env("SYQ_TEST_REFUSE_TERMINATION_THREADS", "1");
            }
            if mode == "inherited-ignore" {
                use std::os::unix::process::CommandExt;
                unsafe {
                    command.pre_exec(|| {
                        if libc::signal(libc::SIGINT, libc::SIG_IGN) == libc::SIG_ERR {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            // Well short of the child's own 30-second wait and of a stalled
            // cleanup's minute.
            let output = super::super::capture_output_bounded(
                &mut command,
                Instant::now() + Duration::from_secs(20),
                &|| false,
                64 * 1024,
            )
            .unwrap();
            let context = format!(
                "{mode}: status={:?}, stdout={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            match ending {
                Signal(signal) => assert_eq!(output.status.signal(), Some(signal), "{context}"),
                Code(code) => assert_eq!(output.status.code(), Some(code), "{context}"),
            }
            assert_eq!(
                std::fs::read_to_string(&marker).ok().as_deref(),
                marked,
                "{mode}"
            );
        }
    }
}
