//! Following syq updates. A receiving service, or the SSH authorization
//! provider, remembers the path it was started from: the path the user runs,
//! such as a Homebrew link, not the file it resolves to. Every few seconds it
//! looks at that path. Once the path holds another build and nothing is in
//! progress, the service runs that build's own command to replace it, as
//! `syq persist connect` does by hand: the new build installs its helper on
//! the server, stops this service once it is still idle, and starts its own.
//!
//! Loops. A service follows only changes made to its path while it runs:
//! whatever the path held when it started is its baseline, and a file that
//! reports this same build becomes the new baseline. The service a switch
//! starts takes the new file as its baseline, so it never switches again
//! until the file changes again, even when the path is a wrapper that starts
//! some other build. Two installed copies do not fight either: each service
//! follows only its own path, and commands replace a service from another
//! build only when it cannot follow its path by itself or its path holds
//! the command's own file (`receive_service::Replace`). Running `persist
//! connect` by hand still replaces any build at once.
//!
//! A switch that fails leaves this service running and says why in its
//! status, then tries again with growing waits.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Seek};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::process::CommandExt as _;

/// How often a service looks at the file it was started from: one stat.
const CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// The first wait after a failed switch, and the longest, which later waits
/// double up to. Each attempt logs in to the server once.
const RETRY_FIRST: Duration = Duration::from_secs(30);
const RETRY_MAX: Duration = Duration::from_secs(600);
/// How long a switch may run before it counts as failed.
const SWITCH_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a receiving connection must have had no request before it
/// counts as idle: one copy's steps, such as identifying the receiver,
/// asking for approval and opening the copy, arrive as separate requests a
/// network round trip apart.
const QUIET: Duration = Duration::from_secs(5);

/// Tests shorten the waits to see a switch happen.
fn test_override(name: &str, default: Duration) -> Duration {
    #[cfg(debug_assertions)]
    if let Some(millis) = std::env::var(name)
        .ok()
        .and_then(|millis| millis.parse().ok())
    {
        return Duration::from_millis(millis);
    }
    let _ = name;
    default
}
fn check_interval() -> Duration {
    test_override("SYQ_TEST_SWITCH_CHECK_MS", CHECK_INTERVAL)
}
fn retry_first() -> Duration {
    test_override("SYQ_TEST_SWITCH_RETRY_MS", RETRY_FIRST)
}
pub(crate) fn quiet() -> Duration {
    test_override("SYQ_TEST_SWITCH_QUIET_MS", QUIET)
}

/// The wait before attempt `attempts + 1`, after `attempts` failed.
fn retry_after(first: Duration, attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(16);
    (first * 2u32.pow(doublings)).min(RETRY_MAX.max(first))
}

/// What a status shows about following an update.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Report {
    /// The build the followed file now holds, when known.
    #[serde(default)]
    pub(crate) to: Option<String>,
    /// `waiting` until nothing is in progress, `switching`, or `failed`.
    pub(crate) phase: String,
    #[serde(default)]
    pub(crate) error: Option<String>,
}

impl Report {
    /// One clause for a status line, such as "switching to syq v0.8.1 once
    /// idle".
    pub(crate) fn describe(&self) -> String {
        let to = self
            .to
            .as_deref()
            .map_or_else(|| "another syq".to_owned(), |build| format!("syq {build}"));
        match self.phase.as_str() {
            "waiting" => format!("switches to {to} once idle"),
            "switching" => format!("switching to {to}"),
            _ => format!(
                "cannot switch to {to}: {}",
                self.error.as_deref().unwrap_or("unknown error")
            ),
        }
    }
}

/// The file at `path`, following links, or None when nothing is there.
fn file_at(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| crate::process::file_identity(&metadata))
}

/// The file at `path` and when it last changed, to notice a replacement
/// even where a new file reuses the old one's inode number.
type Seen = ((u64, u64), (i64, i64));
fn seen_at(path: &Path) -> Option<Seen> {
    std::fs::metadata(path).ok().map(|metadata| {
        (
            crate::process::file_identity(&metadata),
            (metadata.ctime(), metadata.ctime_nsec()),
        )
    })
}

/// What a service whose status names `started_from` follows, as this
/// process sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Follows {
    /// Nothing: the service predates following updates, or its path is
    /// gone. Commands replace it (`receive_service::refresh_outdated`).
    Nothing,
    /// The file this process runs, so it switches to this build by itself.
    ThisFile,
    /// Another file, as when two copies of syq are installed: commands
    /// leave it, so that the two never take turns replacing its service.
    OtherFile,
}
pub(crate) fn follows(started_from: Option<&str>) -> Follows {
    let Some(file) = started_from.and_then(|path| file_at(Path::new(path))) else {
        return Follows::Nothing;
    };
    if crate::process::running_image() == Some(file) {
        Follows::ThisFile
    } else {
        Follows::OtherFile
    }
}
pub(crate) fn follows_other_file(started_from: Option<&str>) -> bool {
    follows(started_from) == Follows::OtherFile
}

/// Refuse to run a file that someone other than this user or root could
/// have put there, as the binary store refuses its releases: the file and
/// the directories holding it and any link to it must belong to this user or
/// root, and nobody else may write them. A directory with the sticky bit,
/// such as /tmp, may be writable by others, who cannot replace its entries.
pub(crate) fn check_runnable(path: &Path) -> Result<()> {
    let user = unsafe { libc::geteuid() };
    let file =
        std::fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))?;
    let metadata =
        std::fs::metadata(&file).with_context(|| format!("inspect {}", file.display()))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.mode() & 0o111 != 0,
        "{} is not an executable file",
        file.display()
    );
    let owner = |metadata: &std::fs::Metadata| metadata.uid() == user || metadata.uid() == 0;
    anyhow::ensure!(
        owner(&metadata) && metadata.mode() & 0o022 == 0,
        "{} must belong to you or root, and nobody else may write it",
        file.display()
    );
    let link_directory = path
        .parent()
        .map(std::fs::canonicalize)
        .transpose()
        .with_context(|| format!("resolve the directory of {}", path.display()))?;
    for directory in file.parent().into_iter().chain(link_directory.as_deref()) {
        let metadata = std::fs::metadata(directory)
            .with_context(|| format!("inspect {}", directory.display()))?;
        let sticky = metadata.mode() & 0o1000 != 0;
        anyhow::ensure!(
            owner(&metadata) && (metadata.mode() & 0o022 == 0 || sticky),
            "the directory {} must belong to you or root, and nobody else may write it",
            directory.display()
        );
    }
    Ok(())
}

/// A started switch: the command's exit, and its process group.
struct Running {
    build: String,
    done: mpsc::Receiver<std::result::Result<(), String>>,
    group: libc::pid_t,
    started: Instant,
    killed: bool,
}

enum State {
    /// Nothing to follow now.
    Current,
    /// Asking the changed file for its build.
    Probing(mpsc::Receiver<(Option<Seen>, Result<String>)>),
    /// The file holds `build`; switch once idle.
    Waiting {
        build: String,
    },
    Switching(Running),
    /// The last attempt failed; look again at `retry`.
    Failed {
        build: Option<String>,
        error: String,
        retry: Instant,
    },
}

/// Follows the file a service was started from (see the module comment).
pub(crate) struct Follower {
    path: PathBuf,
    /// What the path held when the service started, or later held with this
    /// same build.
    baseline: Option<Seen>,
    next_check: Instant,
    attempts: u32,
    state: State,
}

impl Follower {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            baseline: seen_at(&path),
            path,
            next_check: Instant::now() + check_interval(),
            attempts: 0,
            state: State::Current,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Look at the path when due. When it holds another build and `idle`
    /// says nothing is in progress, run `args` with that build to switch.
    pub(crate) fn tick(&mut self, idle: &dyn Fn() -> bool, args: &[OsString]) {
        let now = Instant::now();
        let state = std::mem::replace(&mut self.state, State::Current);
        self.state = match state {
            State::Current => {
                if now < self.next_check {
                    State::Current
                } else {
                    self.next_check = now + check_interval();
                    match seen_at(&self.path) {
                        // Nothing there, perhaps while an update replaces
                        // it: keep running this build.
                        None => State::Current,
                        Some(file) if Some(file) == self.baseline => State::Current,
                        Some(_) => self.probe(),
                    }
                }
            }
            State::Probing(result) => match result.try_recv() {
                Err(mpsc::TryRecvError::Empty) => State::Probing(result),
                Err(mpsc::TryRecvError::Disconnected) => State::Current,
                Ok((file, Ok(build))) if build == crate::identity::build() => {
                    // A reinstall of this same build.
                    self.baseline = file;
                    self.attempts = 0;
                    State::Current
                }
                Ok((_, Ok(build))) => State::Waiting { build },
                Ok((_, Err(error))) => self.failed(
                    None,
                    format!("will not run {}: {error:#}", self.path.display()),
                ),
            },
            State::Waiting { build } => {
                if !idle() {
                    State::Waiting { build }
                } else {
                    match start(&self.path, args) {
                        Ok((done, group)) => State::Switching(Running {
                            build,
                            done,
                            group,
                            started: now,
                            killed: false,
                        }),
                        Err(error) => self.failed(Some(build), format!("{error:#}")),
                    }
                }
            }
            State::Switching(mut running) => match running.done.try_recv() {
                Err(mpsc::TryRecvError::Empty) => {
                    if !running.killed && running.started.elapsed() >= SWITCH_TIMEOUT {
                        unsafe { libc::kill(-running.group, libc::SIGKILL) };
                        running.killed = true;
                    }
                    State::Switching(running)
                }
                _ if running.killed => self.failed(
                    Some(running.build),
                    format!(
                        "switching took longer than {} minutes",
                        SWITCH_TIMEOUT.as_secs() / 60
                    ),
                ),
                // The command ended and this service still runs: it was
                // busy again, another command is replacing it, or the file
                // changed again. Look again after a while.
                Ok(Ok(())) => {
                    self.attempts += 1;
                    self.next_check = now + retry_after(retry_first(), self.attempts);
                    State::Current
                }
                Ok(Err(error)) => self.failed(Some(running.build), error),
                Err(mpsc::TryRecvError::Disconnected) => self.failed(
                    Some(running.build),
                    "the switching command ended without a result".into(),
                ),
            },
            State::Failed {
                build,
                error,
                retry,
            } => {
                if now < retry {
                    State::Failed {
                        build,
                        error,
                        retry,
                    }
                } else {
                    // Ask the file again: it may have changed meanwhile.
                    self.next_check = now;
                    State::Current
                }
            }
        };
    }

    fn probe(&self) -> State {
        let path = self.path.clone();
        let (sender, result) = mpsc::channel();
        std::thread::spawn(move || {
            let file = seen_at(&path);
            let build = check_runnable(&path)
                .and_then(|()| crate::process::file_build(&path).map_err(anyhow::Error::from));
            let _ = sender.send((file, build));
        });
        State::Probing(result)
    }

    fn failed(&mut self, build: Option<String>, error: String) -> State {
        self.attempts += 1;
        State::Failed {
            build,
            error,
            retry: Instant::now() + retry_after(retry_first(), self.attempts),
        }
    }

    /// What a status shows, when following an update.
    pub(crate) fn report(&self) -> Option<Report> {
        match &self.state {
            State::Current | State::Probing(_) => None,
            State::Waiting { build } => Some(Report {
                to: Some(build.clone()),
                phase: "waiting".into(),
                error: None,
            }),
            State::Switching(running) => Some(Report {
                to: Some(running.build.clone()),
                phase: "switching".into(),
                error: None,
            }),
            State::Failed {
                build,
                error,
                retry,
            } => Some(Report {
                to: build.clone(),
                phase: "failed".into(),
                error: Some(format!(
                    "{error}; trying again in {}",
                    crate::destination::retry_wait(retry.saturating_duration_since(Instant::now()))
                )),
            }),
        }
    }
}

/// Start `args` with the build at `path`, detached into a session of its
/// own: it stops this service, which must not take it along. Its output goes
/// to an unnamed temporary file, read for the reason if it fails.
fn start(
    path: &Path,
    args: &[OsString],
) -> Result<(mpsc::Receiver<std::result::Result<(), String>>, libc::pid_t)> {
    check_runnable(path).with_context(|| format!("will not run {}", path.display()))?;
    let mut output = tempfile::tempfile().context("create a temporary file for its output")?;
    let mut command = Command::new(path);
    command
        .args(args)
        .env("SYQ_NO_UPDATE_CHECK", "1")
        // Without a terminal, ssh would otherwise ask through a desktop
        // dialog. A login that needs the user fails and says so instead.
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output.try_clone()?);
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
        .with_context(|| format!("start {}", path.display()))?;
    let group = child.id() as libc::pid_t;
    let (sender, done) = mpsc::channel();
    std::thread::spawn(move || {
        let result = match child.wait() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(last_line(&mut output).unwrap_or_else(|| status.to_string())),
            Err(error) => Err(error.to_string()),
        };
        let _ = sender.send(result);
    });
    Ok((done, group))
}

/// The last line a failed command printed, which says why.
fn last_line(output: &mut File) -> Option<String> {
    const TAIL: u64 = 8192;
    let length = output.metadata().ok()?.len();
    output
        .seek(std::io::SeekFrom::Start(length.saturating_sub(TAIL)))
        .ok()?;
    let mut tail = Vec::new();
    output.read_to_end(&mut tail).ok()?;
    let tail = String::from_utf8_lossy(&tail);
    let line = tail
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())?
        .trim();
    let line = line.strip_prefix("syq persist: ").unwrap_or(line);
    Some(line.chars().take(1000).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_wait_longer_each_time_up_to_the_limit() {
        let first = Duration::from_secs(30);
        let waits: Vec<_> = (1..=7)
            .map(|attempts| retry_after(first, attempts))
            .collect();
        assert_eq!(
            waits,
            [30, 60, 120, 240, 480, 600, 600].map(Duration::from_secs)
        );
        assert_eq!(retry_after(first, u32::MAX), RETRY_MAX);
        // A test's short first wait still grows.
        let short = Duration::from_millis(10);
        assert_eq!(retry_after(short, 3), Duration::from_millis(40));
    }

    /// Install a script reporting `build` at `path`, replacing any file there
    /// by a rename, as installers do.
    fn script(path: &Path, build: &str) {
        let new = path.with_extension("new");
        crate::test_support::write_executable(
            &new,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --build-identity ]; then echo {build}; exit 0; fi\n\
                 printf '%s\\n' \"$*\" >> \"$0.log\"\nexit 0\n"
            ),
            0o755,
        );
        std::fs::rename(&new, path).unwrap();
    }

    /// Tick until `done`, with a deadline.
    fn tick_until(
        follower: &mut Follower,
        idle: &dyn Fn() -> bool,
        mut done: impl FnMut(&Follower) -> bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !done(follower) {
            assert!(Instant::now() < deadline, "{:?}", follower.report());
            follower.next_check = Instant::now();
            follower.tick(idle, &["persist".into(), "connect".into()]);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn switches(path: &Path) -> usize {
        std::fs::read_to_string(path.with_extension("log"))
            .map(|log| log.lines().count())
            .unwrap_or(0)
    }

    /// A service follows only what changes at its path after it starts. The
    /// file there when it started, even another build such as a wrapper, and
    /// a reinstall of this same build, start nothing; another build that
    /// replaces it starts the switch, once idle.
    #[test]
    fn only_another_build_installed_while_running_starts_a_switch() {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("syq");
        script(&path, "v0.0.0-wrapper");
        let mut follower = Follower::new(path.clone());
        for _ in 0..3 {
            follower.next_check = Instant::now();
            follower.tick(&|| true, &[]);
            assert!(matches!(follower.state, State::Current));
        }

        // The same build installed again becomes the new baseline.
        script(&path, crate::identity::build());
        tick_until(&mut follower, &|| true, |follower| {
            follower.baseline == seen_at(&path)
        });
        assert!(follower.report().is_none());

        // Another build waits while the service is busy...
        script(&path, "v99.0.0");
        tick_until(&mut follower, &|| false, |follower| {
            matches!(follower.state, State::Waiting { .. })
        });
        for _ in 0..20 {
            follower.tick(&|| false, &[]);
        }
        assert_eq!(switches(&path), 0);
        assert_eq!(
            follower.report().unwrap().describe(),
            "switches to syq v99.0.0 once idle"
        );
        // ...and switches once it is idle.
        tick_until(&mut follower, &|| true, |_| switches(&path) == 1);
        assert_eq!(
            std::fs::read_to_string(path.with_extension("log")).unwrap(),
            "persist connect\n"
        );
    }

    /// A switch that fails says why and tries again after a wait; one that
    /// ends while the service still runs, as when it was busy again, also
    /// waits before trying again.
    #[test]
    fn a_failed_switch_is_reported_and_retried_after_a_wait() {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("syq");
        script(&path, crate::identity::build());
        let mut follower = Follower::new(path.clone());
        let new = path.with_extension("new");
        crate::test_support::write_executable(
            &new,
            "#!/bin/sh\nif [ \"$1\" = --build-identity ]; then echo v99.0.0; exit 0; fi\n\
             printf '%s\\n' \"$*\" >> \"$0.log\"\necho 'syq persist: cannot reach the server' >&2\nexit 1\n",
            0o755,
        );
        std::fs::rename(&new, &path).unwrap();
        tick_until(&mut follower, &|| true, |follower| {
            matches!(follower.state, State::Failed { .. })
        });
        let report = follower.report().unwrap();
        assert_eq!(report.phase, "failed");
        assert_eq!(report.to.as_deref(), Some("v99.0.0"));
        let error = report.error.unwrap();
        assert!(
            error.starts_with("cannot reach the server; trying again in 30 s"),
            "{error}"
        );
        // Nothing runs again before the wait is over.
        for _ in 0..20 {
            follower.tick(&|| true, &[]);
        }
        assert_eq!(switches(&path), 1);
        assert_eq!(follower.attempts, 1);
        // Once it is over, the next attempt runs, and fails again with a
        // longer wait.
        let State::Failed { retry, .. } = &mut follower.state else {
            panic!()
        };
        *retry = Instant::now();
        tick_until(&mut follower, &|| true, |_| switches(&path) == 2);
        tick_until(&mut follower, &|| true, |follower| {
            matches!(follower.state, State::Failed { .. })
        });
        assert_eq!(follower.attempts, 2);
        assert!(follower
            .report()
            .unwrap()
            .error
            .unwrap()
            .contains("trying again in 60 s"));
    }

    #[test]
    fn a_file_others_could_write_is_not_run() {
        use std::os::unix::fs::PermissionsExt;
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("syq");
        script(&path, "v99.0.0");
        check_runnable(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775)).unwrap();
        let error = check_runnable(&path).unwrap_err().to_string();
        assert!(error.contains("nobody else may write it"), "{error}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let shared = directory.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        // A link in a directory others can write could be pointed elsewhere.
        let link = shared.join("syq");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let error = check_runnable(&link).unwrap_err().to_string();
        assert!(error.contains("the directory"), "{error}");
        // With the sticky bit, others cannot replace it.
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
        check_runnable(&link).unwrap();
        let error = check_runnable(&directory.path().join("missing"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("resolve"), "{error}");

        // The follower reports a refused file instead of running it.
        let mut follower = Follower::new(path.clone());
        script(&path, "v99.0.0");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        tick_until(&mut follower, &|| true, |follower| {
            matches!(follower.state, State::Failed { .. })
        });
        assert!(follower
            .report()
            .unwrap()
            .describe()
            .contains("will not run"));
        assert_eq!(switches(&path), 0);
    }

    #[test]
    fn commands_leave_services_that_follow_another_installed_file() {
        let directory = crate::test_support::tempdir().unwrap();
        let other = directory.path().join("syq");
        script(&other, "v99.0.0");
        // Services that cannot follow their path, or whose path is gone.
        assert_eq!(follows(None), Follows::Nothing);
        let missing = directory.path().join("missing");
        assert_eq!(follows(Some(missing.to_str().unwrap())), Follows::Nothing);
        // One following another file.
        assert_eq!(follows(Some(other.to_str().unwrap())), Follows::OtherFile);
        // One following the file this process runs.
        let running = std::env::current_exe().unwrap();
        assert_eq!(follows(Some(running.to_str().unwrap())), Follows::ThisFile);
    }
}
