//! Process-wide termination defaults while no operation owns a signal.
//!
//! signal-hook and Tokio keep their OS handlers after a listener is dropped.
//! Each listener therefore needs an ownership lease: a permanent fallback
//! applies the normal termination action when no live operation handles it.
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

struct State {
    signal: i32,
    owners: AtomicUsize,
    fallback: OnceLock<io::Result<signal_hook::SigId>>,
}
impl State {
    const fn new(signal: i32) -> Self {
        Self {
            signal,
            owners: AtomicUsize::new(0),
            fallback: OnceLock::new(),
        }
    }
    fn install(&'static self) -> io::Result<()> {
        let result = self.fallback.get_or_init(|| {
            // Preserve inherited ignore/custom dispositions. signal-hook
            // already chains a previous custom handler; only an original
            // default disposition needs our fallback after listeners vanish.
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(self.signal, std::ptr::null(), &mut previous) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let default = previous.sa_sigaction == libc::SIG_DFL;
            // The action uses only atomics and signal-hook's signal-safe
            // default emulation. It must outlive every individual listener.
            unsafe {
                signal_hook::low_level::register(self.signal, move || {
                    if default && self.owners.load(Ordering::Acquire) == 0 {
                        let _ = signal_hook::low_level::emulate_default_handler(self.signal);
                    }
                })
            }
        });
        result.as_ref().map(|_| ()).map_err(|error| {
            error
                .raw_os_error()
                .map(io::Error::from_raw_os_error)
                .unwrap_or_else(|| io::Error::new(error.kind(), error.to_string()))
        })
    }
}
static INTERRUPT: State = State::new(libc::SIGINT);
static TERMINATE: State = State::new(libc::SIGTERM);
static HANGUP: State = State::new(libc::SIGHUP);

pub(crate) struct Owned<T> {
    listeners: T,
    states: Vec<&'static State>,
}
impl<T> Deref for Owned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.listeners
    }
}
impl<T> DerefMut for Owned<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.listeners
    }
}
impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // Release ownership before unregistering/dropping the listeners.
        // A signal during teardown still has either another owner or its
        // default action; there is no interval with neither one.
        for state in &self.states {
            state.owners.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Install listeners before claiming their signals. Until installation has
/// succeeded, default termination (or an existing owner) remains responsible.
/// The install closure must clean up partial registrations on failure.
pub(crate) fn owned<T>(
    signals: &[i32],
    install: impl FnOnce() -> io::Result<T>,
) -> io::Result<Owned<T>> {
    let mut states = Vec::new();
    for signal in signals {
        let state = match *signal {
            libc::SIGINT => &INTERRUPT,
            libc::SIGTERM => &TERMINATE,
            libc::SIGHUP => &HANGUP,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported termination signal",
                ))
            }
        };
        if !states.iter().any(|old: &&State| old.signal == state.signal) {
            state.install()?;
            states.push(state);
        }
    }
    let listeners = install()?;
    for state in &states {
        state.owners.fetch_add(1, Ordering::AcqRel);
    }
    Ok(Owned { listeners, states })
}

/// Drop all successfully installed signal-hook registrations, including when
/// a later registration in the same operation fails.
#[derive(Default)]
pub(crate) struct Registrations(Vec<signal_hook::SigId>);
impl Registrations {
    pub(crate) fn push(&mut self, id: signal_hook::SigId) {
        self.0.push(id);
    }
}
impl Drop for Registrations {
    fn drop(&mut self) {
        for id in &self.0 {
            signal_hook::low_level::unregister(*id);
        }
    }
}

/// Construct both Tokio listeners eagerly. `ctrl_c()` registers only when
/// polled, which would leave a gap after ownership had already been claimed.
pub(crate) fn interrupt_and_terminate(
) -> io::Result<Owned<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>> {
    use tokio::signal::unix::{signal, SignalKind};
    owned(&[libc::SIGINT, libc::SIGTERM], || {
        Ok((
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::sync::{atomic::AtomicBool, Arc};
    use std::time::{Duration, Instant};

    const CHILD: &str = "SYQ_TEST_SIGNAL_OWNERSHIP";
    fn listener(flag: Arc<AtomicBool>) -> Owned<Registrations> {
        owned(&[libc::SIGTERM], || {
            let mut registrations = Registrations::default();
            registrations.push(signal_hook::flag::register(libc::SIGTERM, flag)?);
            Ok(registrations)
        })
        .unwrap()
    }
    fn terminate() {
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    }

    #[test]
    fn ownership_subprocess() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        let first = Arc::new(AtomicBool::new(false));
        let initial = listener(first.clone());
        match mode.as_str() {
            "short" => drop(initial),
            "next" => {
                drop(initial);
                let second = Arc::new(AtomicBool::new(false));
                let owner = listener(second.clone());
                terminate();
                assert!(second.load(Ordering::Acquire));
                assert!(!first.load(Ordering::Acquire));
                drop(owner);
            }
            "first-drop" | "last-drop" => {
                let second = Arc::new(AtomicBool::new(false));
                let other = listener(second.clone());
                if mode == "first-drop" {
                    drop(initial);
                    terminate();
                    assert!(second.load(Ordering::Acquire));
                    assert!(!first.load(Ordering::Acquire));
                    drop(other);
                } else {
                    drop(other);
                    terminate();
                    assert!(first.load(Ordering::Acquire));
                    assert!(!second.load(Ordering::Acquire));
                    drop(initial);
                }
            }
            "inherited-ignore" => {
                let flag = Arc::new(AtomicBool::new(false));
                let owner = owned(&[libc::SIGHUP], || {
                    let mut registrations = Registrations::default();
                    registrations.push(signal_hook::flag::register(libc::SIGHUP, flag.clone())?);
                    Ok(registrations)
                })
                .unwrap();
                assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
                assert!(flag.load(Ordering::Acquire));
                drop(owner);
                assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
                drop(initial);
            }
            "failed-install" => {
                drop(initial);
                let result = owned(&[libc::SIGTERM], || {
                    let mut registrations = Registrations::default();
                    registrations.push(signal_hook::flag::register(libc::SIGTERM, first)?);
                    Err::<Registrations, _>(io::Error::other("incomplete listener setup"))
                });
                assert!(result.is_err());
            }
            "tokio" => {
                drop(initial);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let mut signals = interrupt_and_terminate().unwrap();
                    terminate();
                    tokio::time::timeout(Duration::from_secs(2), signals.1.recv())
                        .await
                        .unwrap()
                        .unwrap();
                });
            }
            _ => panic!("unknown signal test mode"),
        }
        terminate();
        panic!("termination default was not restored");
    }

    #[test]
    fn listeners_restore_defaults_without_displacing_live_owners() {
        for mode in [
            "short",
            "next",
            "first-drop",
            "last-drop",
            "failed-install",
            "tokio",
            "inherited-ignore",
        ] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "process::signals::tests::ownership_subprocess",
                    "--nocapture",
                ])
                .env(CHILD, mode);
            if mode == "inherited-ignore" {
                use std::os::unix::process::CommandExt;
                unsafe {
                    command.pre_exec(|| {
                        if libc::signal(libc::SIGHUP, libc::SIG_IGN) == libc::SIG_ERR {
                            return Err(io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            let output = crate::process::capture_output_bounded(
                &mut command,
                Instant::now() + Duration::from_secs(5),
                &|| false,
                64 * 1024,
            )
            .unwrap();
            assert_eq!(
                output.status.signal(),
                Some(libc::SIGTERM),
                "{mode}: status={:?}, stdout={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
