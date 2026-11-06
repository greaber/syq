//! Taking over a receiving connection from the service a switch replaces
//! without logging in twice (`switch`). The switch starts the new service
//! first. It logs in to the server for each receiving name while the old
//! service still receives, and the server proves each new connection the
//! receiver and then holds it (`destination::TAKE_OVER`). Only once every
//! login worked does the switch stop the old service, and then the new one
//! takes its lock, tells the server to take each name as soon as the old
//! registration lets go of it, and goes on with the connections it already
//! has.
//!
//! A login that fails or waits for the user, or a connection lost before
//! the switch stops the old service, leaves the old service receiving, and
//! the new one logs out and exits. So does one the switch stops waiting
//! for, or a switch that ends: the new service hears it as the end of its
//! input. A new service that finds another one holding the lock once told
//! to take over leaves it the connection, never having taken a name.
//!
//! The switch and the service it starts are always the same build, as is
//! the helper on the server: the switch installs and runs its own.
use super::{
    lock_for_start, preferences, protect_followed_program, serve, suffixed, switch, try_lock,
    ProfileWorker, ServiceSpec, RECORD,
};
use crate::destination::{Handover, Prepared};
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

/// What the new service tells the switch: once whether it has logged in,
/// and then, should it lose a connection before the switch decides, that
/// it no longer can take over.
#[derive(Serialize, Deserialize)]
enum LoggedIn {
    Yes,
    /// Whether the user is needed, as when the server rejected the login,
    /// and what went wrong.
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
    output: Option<ChildStdout>,
}

impl Successor {
    /// Start the service that receives as `spec` says in place of the one at
    /// `control`, and wait until it has logged in to the server `label`
    /// names, by the switch's deadline (`switch::login_deadline`). A login
    /// that needs the user, including one that did not finish in time, is
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
        let mut successor = Self {
            input: child.stdin.take(),
            output: child.stdout.take(),
            child: Some(child),
        };
        let input = successor.input.as_mut().context("successor input")?;
        input.write_all(format!("{}\n", serde_json::to_string(spec)?).as_bytes())?;
        let output = successor.output.as_mut().context("successor output")?;
        let logged_in = match read_line_by(output, switch::login_deadline())? {
            Some(line) => serde_json::from_str(&line)?,
            None => LoggedIn::No {
                needs_user: true,
                error: switch::NO_ANSWER.into(),
            },
        };
        successor.settle(logged_in, control, label)?;
        Ok(successor)
    }

    /// Just before the switch stops the service this one replaces: an error
    /// if it lost a connection meanwhile, as `start` says.
    pub(super) fn still_logged_in(&mut self, control: &Path, label: &str) -> Result<()> {
        let output = self.output.as_mut().context("successor output")?;
        if !crate::sys::readable_within(output.as_raw_fd(), Duration::ZERO) {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        let logged_in = match read_line_by(output, deadline)? {
            Some(line) => serde_json::from_str(&line)?,
            None => bail!("background receiving did not say how it stands"),
        };
        self.settle(logged_in, control, label)
    }

    fn settle(&mut self, logged_in: LoggedIn, control: &Path, label: &str) -> Result<()> {
        match logged_in {
            LoggedIn::Yes => Ok(()),
            LoggedIn::No {
                needs_user: true,
                error,
            } => {
                self.end();
                switch::defer_after_login(control);
                Err(anyhow::anyhow!("{error}").context(switch::LoginNeeded(label.to_owned())))
            }
            LoggedIn::No { error, .. } => {
                self.end();
                bail!("receiving could not connect to {label}: {error}")
            }
        }
    }

    /// Once the service it replaces has stopped: take over, as `spec` says,
    /// which the control's record keeps from now on.
    pub(super) fn take_over(mut self, control: &Path, spec: &ServiceSpec) -> Result<()> {
        super::atomic_json(&suffixed(control, RECORD), spec)?;
        let mut input = self.input.take().context("successor input")?;
        input.write_all(b"go\n")?;
        drop(input);
        drop(self.output.take());
        if let Some(mut child) = self.child.take() {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Ok(())
    }

    /// Without taking over: the end of its input tells it to log out and
    /// exit. Wait a moment for that, so that its logins are gone when the
    /// switch says how it went, but not past the switch's own time limit:
    /// it gets there by itself.
    fn end(&mut self) {
        drop(self.input.take());
        drop(self.output.take());
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

impl Drop for Successor {
    fn drop(&mut self) {
        self.end();
    }
}
/// How long a switch waits for a new service that does not take over to
/// exit: well within the time a switch keeps after its login
/// (`switch::login_deadline`).
const EXIT_WAIT: Duration = Duration::from_secs(1);

/// One line from `output`, without its newline, or None if none came by
/// `deadline`. It reads one byte at a time, leaving any later line unread.
fn read_line_by(output: &mut ChildStdout, deadline: Instant) -> Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(None);
        }
        if !crate::sys::readable_within(output.as_raw_fd(), left) {
            continue;
        }
        let mut byte = [0u8];
        if output.read(&mut byte)? == 0 {
            bail!("background receiving ended before it could take over");
        }
        if byte[0] == b'\n' {
            return Ok(Some(String::from_utf8(line)?));
        }
        line.push(byte[0]);
        anyhow::ensure!(
            line.len() <= 64 * 1024,
            "background receiving said too much"
        );
    }
}

/// What the new service has once its connections are starting.
struct Preparing {
    spec: ServiceSpec,
    workers: Vec<ProfileWorker>,
    reports: mpsc::Receiver<(usize, Prepared)>,
    taken_over: Arc<AtomicBool>,
}

/// The service a switch starts (`Successor`): log in for each receiving name
/// on the endpoint its input names, say how that went, and once told to,
/// take the control's lock and receive.
pub(super) fn run(domain: &Domain, control: &Path, started_from: Option<PathBuf>) -> Result<()> {
    let mut input = std::io::stdin().lock();
    let say = |logged_in: &LoggedIn| -> Result<()> {
        let mut output = std::io::stdout().lock();
        output.write_all(format!("{}\n", serde_json::to_string(logged_in)?).as_bytes())?;
        output.flush()?;
        Ok(())
    };
    // The switch reports why this could not start.
    let preparing = match prepare(domain, control, started_from.as_deref(), &mut input) {
        Ok(preparing) => preparing,
        Err(error) => {
            return say(&LoggedIn::No {
                needs_user: false,
                error: format!("{error:#}"),
            })
        }
    };
    let Preparing {
        spec,
        workers,
        reports,
        taken_over,
    } = preparing;
    // Each connection logged in, or never started for a reason on this
    // machine, which a newly started service would show too.
    let mut settled = vec![false; workers.len()];
    let lost = |prepared: Prepared| match prepared {
        Prepared::Lost { needs_user, error } => Some(LoggedIn::No { needs_user, error }),
        _ => None,
    };
    loop {
        if settled.iter().all(|settled| *settled) {
            break;
        }
        match reports.recv_timeout(Duration::from_millis(100)) {
            Ok((id, prepared)) => {
                if let Some(no) = lost(prepared) {
                    return say(&no);
                }
                if let Some(settled) = settled.get_mut(id) {
                    *settled = true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return say(&LoggedIn::No {
                    needs_user: false,
                    error: "receiving stopped before it logged in".into(),
                })
            }
        }
        // The switch gave up waiting, or ended.
        if crate::sys::readable_within(libc::STDIN_FILENO, Duration::ZERO) {
            return Ok(());
        }
    }
    say(&LoggedIn::Yes)?;
    // Until the switch decides, say if a connection is lost: it then leaves
    // the old service receiving. Told to take over anyway, as when it had
    // stopped the old one already, take over: that connection reconnects.
    let mut told = false;
    while !crate::sys::readable_within(libc::STDIN_FILENO, Duration::from_millis(100)) {
        while let Ok((_, prepared)) = reports.try_recv() {
            // The switch may have stopped reading, having said `go`.
            if let Some(no) = lost(prepared).filter(|_| !told) {
                told = true;
                let _ = say(&no);
            }
        }
    }
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 || line.trim_end() != "go" {
        return Ok(());
    }
    drop(input);
    drop(reports);
    // Nobody reads or writes these any more.
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        unsafe { libc::dup2(null.as_raw_fd(), fd) };
    }
    // The service it replaces has stopped. Another that started meanwhile,
    // as for a command, keeps the connection; the server never gave this one
    // the name.
    let Some(_lock) = lock_for_start(|| try_lock(control, true))? else {
        return Ok(());
    };
    taken_over.store(true, Ordering::Release);
    for worker in &workers {
        worker.wake();
    }
    serve(domain, control, started_from, spec, workers)
}

/// Read the service record from `input`, and start a connection for each
/// receiving name on its endpoint that prepares to take over.
fn prepare(
    domain: &Domain,
    control: &Path,
    started_from: Option<&Path>,
    input: &mut impl BufRead,
) -> Result<Preparing> {
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    anyhow::ensure!(
        Domain::select(Some(scope))? == *domain,
        "receiving control belongs to a different persistence domain"
    );
    let mut line = String::new();
    input.read_line(&mut line)?;
    let spec: ServiceSpec = serde_json::from_str(&line).context("read the service record")?;
    let config = preferences(domain)?;
    // A server can use a connection's return socket before the service
    // takes over.
    protect_followed_program(started_from);
    let taken_over = Arc::new(AtomicBool::new(false));
    let (report, reports) = mpsc::channel();
    let workers = config
        .profiles
        .iter()
        .filter(|profile| profile.allows_server(&spec.endpoint.label()))
        .enumerate()
        .map(|(id, profile)| {
            ProfileWorker::new(
                domain,
                profile.clone(),
                spec.clone(),
                Some(Handover {
                    id,
                    report: report.clone(),
                    taken_over: taken_over.clone(),
                }),
            )
        })
        .collect();
    Ok(Preparing {
        spec,
        workers,
        reports,
        taken_over,
    })
}
