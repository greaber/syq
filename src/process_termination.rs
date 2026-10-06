//! Work a process finishes before SIGINT or SIGTERM ends it.
//!
//! The first such signal runs every registered cleanup, in the order they
//! were added, on a thread of its own. Together they get at most `CAP`;
//! then the process ends by that signal, so its exit status is the one the
//! signal alone would give. A second SIGINT ends it at once, whatever the
//! cleanup has reached. A signal the process inherited as ignored, as a
//! background job does, stays ignored.
//!
//! Once a cleanup has been added, the process keeps these listeners: a
//! signal with no cleanup left still ends it the same way.
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// How long cleanup may hold an interrupted process. A copy coordinator's
/// process group given SIGTERM is killed one second later, so this stays
/// well inside that.
const CAP: Duration = Duration::from_millis(500);

type Action = Arc<dyn Fn(Instant) + Send + Sync>;

static STARTED: AtomicBool = AtomicBool::new(false);
static RECEIVED: AtomicI32 = AtomicI32::new(0);
static NEXT: AtomicU64 = AtomicU64::new(0);
static CLEANUPS: Mutex<BTreeMap<u64, Action>> = Mutex::new(BTreeMap::new());
static LISTENING: OnceLock<io::Result<()>> = OnceLock::new();

fn cleanups() -> std::sync::MutexGuard<'static, BTreeMap<u64, Action>> {
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

/// When cleanup that starts now must stop: four fifths of the cap, leaving
/// the rest for ending the process.
pub(crate) fn cleanup_deadline() -> Instant {
    Instant::now() + cap() * 4 / 5
}

/// A cleanup registered with `add`. Dropping it removes it.
pub(crate) struct Cleanup(u64);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let removed = cleanups().remove(&self.0);
        drop(removed);
    }
}

/// Run `action` before a termination signal ends this process. It receives
/// the time by which it should stop.
pub(crate) fn add(action: impl Fn(Instant) + Send + Sync + 'static) -> io::Result<Cleanup> {
    listen()?;
    let id = NEXT.fetch_add(1, SeqCst);
    cleanups().insert(id, Arc::new(action));
    Ok(Cleanup(id))
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
                // Only atomics, write(2) and signal-hook's signal-safe
                // default emulation run here.
                let action = move || {
                    if STARTED.swap(true, SeqCst) {
                        if signal == libc::SIGINT {
                            let _ = signal_hook::low_level::emulate_default_handler(signal);
                        }
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
                        Ok(1) => break,
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
    // answering cannot hold the process past the cap.
    let (done, finished) = std::sync::mpsc::channel();
    let running = {
        let actions = actions.clone();
        std::thread::Builder::new()
            .name("termination-cleanup".into())
            .spawn(move || {
                for action in actions {
                    action(deadline);
                }
                let _ = done.send(());
            })
    };
    match running {
        Ok(_) => {
            let _ = finished.recv_timeout(cap.saturating_sub(started.elapsed()));
        }
        Err(_) => {
            for action in actions {
                action(deadline);
            }
        }
    }
    let _ = signal_hook::low_level::emulate_default_handler(signal);
    // Not reached: both signals end a process by default.
    unsafe { libc::_exit(128 + signal) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    const CHILD: &str = "SYQ_TEST_TERMINATION";
    const MARKER: &str = "SYQ_TEST_TERMINATION_MARKER";

    fn raise(signal: i32) {
        assert_eq!(unsafe { libc::raise(signal) }, 0);
    }

    #[test]
    fn termination_subprocess() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        let marker = std::path::PathBuf::from(std::env::var_os(MARKER).unwrap());
        let mark = move |_: Instant| std::fs::write(&marker, b"cleaned").unwrap();
        let _cleanup = match mode.as_str() {
            "cleanup" | "inherited-ignore" => add(mark).unwrap(),
            "removed" => {
                drop(add(mark).unwrap());
                add(|_| {}).unwrap()
            }
            // A cleanup that never finishes: only the cap or a second
            // interrupt ends the process.
            "cap" | "second-interrupt" => add(|_| loop {
                std::thread::sleep(Duration::from_secs(60));
            })
            .unwrap(),
            _ => panic!("unknown termination test mode"),
        };
        match mode.as_str() {
            "inherited-ignore" => {
                // Ignored, it runs nothing; the next SIGTERM still cleans up.
                raise(libc::SIGINT);
                std::thread::sleep(Duration::from_millis(200));
                raise(libc::SIGTERM);
            }
            "second-interrupt" => {
                raise(libc::SIGINT);
                std::thread::sleep(Duration::from_millis(200));
                raise(libc::SIGINT);
            }
            _ => raise(libc::SIGTERM),
        }
        std::thread::sleep(Duration::from_secs(30));
        panic!("the signal did not end the process");
    }

    #[test]
    fn termination_runs_cleanup_and_ends_by_the_signal() {
        for (mode, signal, cleaned, cap_ms) in [
            ("cleanup", libc::SIGTERM, true, None),
            ("removed", libc::SIGTERM, false, None),
            ("inherited-ignore", libc::SIGTERM, true, None),
            ("cap", libc::SIGTERM, false, Some(200)),
            ("second-interrupt", libc::SIGINT, false, Some(60_000)),
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
            let started = Instant::now();
            // Well short of the child's own 30-second wait and of the
            // minute-long cap the second interrupt has to cut short.
            let output = super::super::capture_output_bounded(
                &mut command,
                started + Duration::from_secs(20),
                &|| false,
                64 * 1024,
            )
            .unwrap();
            assert_eq!(
                output.status.signal(),
                Some(signal),
                "{mode}: status={:?}, stdout={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(marker.exists(), cleaned, "{mode}");
        }
    }
}
