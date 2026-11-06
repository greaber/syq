//! Taking over a receiving connection from the service a switch replaces
//! without logging in twice (`switch`). The switch starts the new service
//! first. It logs in to the server for each receiving name while the old
//! service still receives, and the server holds each new registration until
//! the old one lets go of the name (`destination::TAKE_OVER`). Only once
//! every login worked does the switch stop the old service, and then the new
//! one takes its lock and goes on with the connections it already has. A
//! login that fails or waits for the user leaves the old service receiving,
//! and the new one logs out and exits. So does one the switch stops waiting
//! for, or a switch that ends: the new service hears it as the end of its
//! input.
//!
//! The switch and the service it starts are always the same build, as is
//! the helper on the server: the switch installs and runs its own.
use super::{
    lock_for_start, preferences, serve, suffixed, switch, try_lock, ProfileWorker, ServiceSpec,
    RECORD,
};
use crate::persistence::Domain;
use crate::process::CommandExt as _;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// How the service that takes over runs: `ARG CONTROL [STARTED_FROM]`, as
/// `--receive-service`.
pub(super) const ARG: &str = "--receive-successor";

/// What the new service tells the switch once it has logged in, or could
/// not.
#[derive(Serialize, Deserialize)]
enum LoggedIn {
    Yes,
    /// Whether the user is needed, as when the server rejected the login,
    /// and what ssh said.
    No {
        needs_user: bool,
        error: String,
    },
}

/// The new service, while the switch decides whether it takes over. Dropped
/// without taking over, it logs out and exits.
pub(super) struct Successor {
    child: Option<Child>,
    input: Option<ChildStdin>,
}

impl Successor {
    /// Start the service that receives as `spec` says in place of the one at
    /// `control`, and wait until it has logged in to the server `label`
    /// names, by the switch's deadline (`switch::login_deadline`). A login that
    /// needs the user, including one that did not finish in time, is
    /// `switch::LoginNeeded`.
    pub(super) fn start(control: &Path, spec: &ServiceSpec, label: &str) -> Result<Self> {
        let mut command = crate::process::self_command()?;
        // Its own switches are not a command's (`switch::STARTED_BY_COMMAND`).
        command
            .arg(ARG)
            .arg(control)
            .env_remove(switch::STARTED_BY_COMMAND);
        if let Some(path) = crate::process::started_from() {
            command.arg(path);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // It outlives the switch, whose group ends with it.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn_guarded()
            .context("start background receiving")?;
        let output = child.stdout.take().context("successor output")?;
        let mut successor = Self {
            input: child.stdin.take(),
            child: Some(child),
        };
        let input = successor.input.as_mut().context("successor input")?;
        input.write_all(format!("{}\n", serde_json::to_string(spec)?).as_bytes())?;
        let deadline = switch::login_deadline();
        let logged_in = match read_line_by(output, deadline)? {
            Some(line) => serde_json::from_str(&line)?,
            None => LoggedIn::No {
                needs_user: true,
                error: switch::NO_ANSWER.into(),
            },
        };
        match logged_in {
            LoggedIn::Yes => Ok(successor),
            LoggedIn::No {
                needs_user: true,
                error,
            } => {
                drop(successor);
                switch::defer_after_login(control);
                Err(anyhow::anyhow!("{error}").context(switch::LoginNeeded(label.to_owned())))
            }
            LoggedIn::No { error, .. } => bail!("receiving could not log in to {label}: {error}"),
        }
    }

    /// Once the service it replaces has stopped: take over, as `spec` says,
    /// which the control's record keeps from now on.
    pub(super) fn take_over(mut self, control: &Path, spec: &ServiceSpec) -> Result<()> {
        super::atomic_json(&suffixed(control, RECORD), spec)?;
        let mut input = self.input.take().context("successor input")?;
        input.write_all(b"go\n")?;
        drop(input);
        if let Some(mut child) = self.child.take() {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Ok(())
    }
}

impl Drop for Successor {
    fn drop(&mut self) {
        // The end of its input tells it to log out and exit. Wait a moment
        // for that, so that its logins are gone when the switch says how it
        // went, but not past the switch's own time limit: it gets there by
        // itself.
        drop(self.input.take());
        let Some(mut child) = self.child.take() else {
            return;
        };
        let deadline = Instant::now() + EXIT_WAIT;
        while matches!(child.try_wait(), Ok(None)) {
            if Instant::now() >= deadline {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
/// How long a switch waits for a new service that does not take over to
/// exit: well within the time a switch keeps after its login
/// (`switch::login_deadline`).
const EXIT_WAIT: Duration = Duration::from_secs(1);

/// One line from `output`, without its newline, or None if none came by
/// `deadline`.
fn read_line_by(mut output: ChildStdout, deadline: Instant) -> Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(None);
        }
        if !crate::sys::readable_within(output.as_raw_fd(), left) {
            continue;
        }
        let mut buffer = [0u8; 4096];
        let count = output.read(&mut buffer)?;
        if count == 0 {
            bail!("background receiving ended before it logged in");
        }
        line.extend_from_slice(&buffer[..count]);
        if let Some(end) = line.iter().position(|&byte| byte == b'\n') {
            line.truncate(end);
            return Ok(Some(String::from_utf8(line)?));
        }
        anyhow::ensure!(
            line.len() <= 64 * 1024,
            "background receiving said too much"
        );
    }
}

/// The service a switch starts (`Successor`): log in for each receiving name
/// on the endpoint its input names, say how that went, and once told to,
/// take the control's lock and receive.
pub(super) fn run(domain: &Domain, control: &Path, started_from: Option<PathBuf>) -> Result<()> {
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    anyhow::ensure!(
        Domain::select(Some(scope))? == *domain,
        "receiving control belongs to a different persistence domain"
    );
    let mut input = std::io::stdin().lock();
    let mut line = String::new();
    input.read_line(&mut line)?;
    let spec: ServiceSpec = serde_json::from_str(&line)?;
    let config = preferences(domain)?;
    let released = Arc::new(AtomicBool::new(false));
    let (report, reports) = mpsc::channel();
    let workers: Vec<ProfileWorker> = config
        .profiles
        .iter()
        .filter(|profile| profile.allows_server(&spec.endpoint.label()))
        .map(|profile| {
            ProfileWorker::new(
                domain,
                profile.clone(),
                spec.clone(),
                Some(crate::destination::Handover {
                    report: report.clone(),
                    released: released.clone(),
                }),
            )
        })
        .collect();
    drop(report);
    let mut left = workers.len();
    let logged_in = loop {
        if left == 0 {
            break LoggedIn::Yes;
        }
        match reports.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(())) => left -= 1,
            Ok(Err((needs_user, error))) => break LoggedIn::No { needs_user, error },
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break LoggedIn::No {
                    needs_user: false,
                    error: "receiving stopped before it logged in".into(),
                }
            }
        }
        // The switch gave up waiting, or ended.
        if crate::sys::readable_within(libc::STDIN_FILENO, Duration::ZERO) {
            return Ok(());
        }
    };
    let ready = matches!(logged_in, LoggedIn::Yes);
    let mut output = std::io::stdout().lock();
    output.write_all(format!("{}\n", serde_json::to_string(&logged_in)?).as_bytes())?;
    output.flush()?;
    drop(output);
    line.clear();
    if !ready || input.read_line(&mut line)? == 0 || line.trim_end() != "go" {
        return Ok(());
    }
    drop(input);
    // Nobody reads or writes these any more.
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        unsafe { libc::dup2(null.as_raw_fd(), fd) };
    }
    released.store(true, Ordering::Release);
    // The service it replaces has stopped. Another that started meanwhile,
    // as for a command, keeps the connection.
    let Some(_lock) = lock_for_start(|| try_lock(control, true))? else {
        return Ok(());
    };
    serve(domain, control, started_from, spec, workers)
}
