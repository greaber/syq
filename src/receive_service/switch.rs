//! Following syq updates. A receiving service, or the SSH authorization
//! provider, remembers the path it was started from: the path given to
//! exec, such as a Homebrew link, not the file it resolves to. A script
//! that runs syq, such as a version manager's shim, is never that path: the
//! script's own exec of syq is. Every few seconds the service looks at that
//! path. Once the path holds another build and nothing is in progress, the
//! service runs that build's own command to replace it, as `syq persist
//! connect` does by hand: the new build installs its helper on the server,
//! stops this service once it is still idle, and starts its own.
//!
//! Loops. The service a switch starts runs the file at its path, which is
//! its baseline, so it switches again only once that file changes again. A
//! service started while its path already held another file, as when an
//! update landed during a switch, asks that file for its build once and
//! switches if it is another. A file reporting this same build becomes the
//! new baseline. Two installed copies do not fight: each service follows
//! only its own path, and commands replace a service from another build only
//! when it cannot follow its path by itself, its path holds the command's
//! own file and its switch failed, or nothing follows (`Replace`,
//! `refresh_outdated`). A version manager that keeps each version in its
//! own directory therefore looks like a second installed copy, and its
//! services switch only by `syq persist connect`. Running that by hand
//! still replaces any build at once.
//!
//! A switch that fails leaves this service running and says why in its
//! status. One that could not log in to the server without the user is not
//! tried again by the service: it waits until a syq command run at a
//! terminal tries it, with the user at hand to touch a security key or
//! approve an agent's request, at most every ten minutes
//! (`receive_service::refresh_outdated`). Its status says so. A live
//! control connection is no sign of the user: it can outlast them, and the
//! switch's own login check does not use it. Other failures are tried again
//! with growing waits.
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
/// How long a switch may run before it ends itself, with everything it
/// started in its process group (`end_switch_at`).
const SWITCH_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) fn switch_timeout() -> Duration {
    test_override("SYQ_TEST_SWITCH_TIMEOUT_MS", SWITCH_TIMEOUT)
}
/// How long after that the service that started a switch ends it, in case
/// the switch could not.
const SWITCH_BACKSTOP: Duration = Duration::from_secs(60);

/// End this switch, a `persist connect --when-idle` that leads its own
/// process group, once it has run for `switch_timeout`: kill that group,
/// which holds this process and what it started that stays there, such as
/// ssh, after `before` records why. Nobody may be waiting for it to answer.
pub(crate) fn end_switch_at(before: impl FnOnce() + Send + 'static) {
    let _ = ENDS.set(Instant::now() + switch_timeout());
    std::thread::spawn(move || {
        std::thread::sleep(switch_timeout());
        before();
        unsafe {
            if libc::getpgrp() == libc::getpid() {
                libc::kill(0, libc::SIGKILL);
            }
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
    });
}

/// When this process, a switch, ends by itself (`end_switch_at`).
static ENDS: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
/// How long a switch's login check may take.
const LOGIN_CHECK: Duration = Duration::from_secs(60);
/// The time a switch keeps after its login check, to say how it went.
const LOGIN_CHECK_MARGIN: Duration = Duration::from_secs(2);

/// Why a switch's login that ran out of time needs the user.
pub(crate) const NO_ANSWER: &str =
    "ssh did not finish logging in by itself in time, as when it waits for a touch of your security key";

/// When a login check must end, and whether it runs in this process's
/// group. In a switch, it ends before the switch does: a check that ran out
/// of time, as when ssh waits for a touch of a security key that nobody
/// gave, then ends the switch as one that needs the user (`LoginNeeded`),
/// which only a command at a terminal tries again, not as a failure the
/// service would retry by itself, touching the key again. It also runs in
/// the switch's group, which `end_switch_at` ends, so that nothing outlives
/// the switch. `LoginWatch` bounds the switch's control connection's login
/// the same way.
pub(crate) fn login_check() -> (Instant, bool) {
    let now = Instant::now();
    let Some(ends) = ENDS.get() else {
        return (now + LOGIN_CHECK, false);
    };
    let by = ends.checked_sub(LOGIN_CHECK_MARGIN).unwrap_or(now).max(now);
    let leads_group = unsafe { libc::getpgrp() == libc::getpid() };
    ((now + LOGIN_CHECK).min(by), leads_group)
}

/// Bounds, in a switch (`end_switch_at`), the login of its control
/// connection to the server, which ssh makes when no connection is live,
/// until dropped once that connection is made or has failed: if it has not
/// finished by the deadline `login_check` gives, and the connection's
/// control socket, which ssh opens once logged in, is still not there, the
/// switch ends at once as one that needs the user (`LOGIN_NEEDED_EXIT`),
/// with what it started in its process group. What follows the login, such
/// as installing the helper, is bound only by the switch's own time limit.
pub(crate) struct LoginWatch(std::sync::Arc<std::sync::Mutex<bool>>);
impl LoginWatch {
    pub(crate) fn start(control: &Path, server: String) -> Self {
        let done = std::sync::Arc::new(std::sync::Mutex::new(false));
        if ENDS.get().is_some() {
            let (deadline, _) = login_check();
            let control = control.to_path_buf();
            let watched = done.clone();
            std::thread::spawn(move || {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                // Held until the process exits, so that the login cannot
                // be taken as done meanwhile.
                let done = watched
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if *done || crate::persistence::socket_is_ready(&control).unwrap_or(false) {
                    return;
                }
                let error = format!("{}: {NO_ANSWER}", LoginNeeded(server));
                super::record_attempt(&control, &super::Attempt::new("login", Some(error.clone())));
                defer_after_login(&control);
                crate::output::diagnostic!("syq persist: {error}");
                end_own_group();
                unsafe { libc::_exit(LOGIN_NEEDED_EXIT) }
            });
        }
        Self(done)
    }
}
impl Drop for LoginWatch {
    fn drop(&mut self) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
    }
}

/// Before a switch exits as needing the user: end what it started that
/// stays in its process group, such as a ProxyJump ssh or `ssh-sk-helper`
/// still waiting for a touch, but not this process itself. Whoever started
/// the switch also ends the group once it exits, but the command that
/// started one may be gone by then.
pub(crate) fn end_own_group() {
    unsafe {
        if libc::getpgrp() == libc::getpid() {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            libc::kill(0, libc::SIGTERM);
        }
    }
}

/// Wait for `child`, which leads its own process group, then end what it
/// left in that group before reaping it, so that its group ID cannot have
/// been reused by then.
pub(crate) fn wait_and_end_group(
    child: &mut std::process::Child,
) -> std::io::Result<std::process::ExitStatus> {
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if result == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
    child.wait()
}
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

/// Why a switch that ran too long failed.
pub(crate) fn timed_out() -> String {
    format!(
        "switching took longer than {}",
        crate::destination::retry_wait(switch_timeout())
    )
}

/// The wait before attempt `attempts + 1`, after `attempts` failed.
fn retry_after(first: Duration, attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(16);
    (first * 2u32.pow(doublings)).min(RETRY_MAX.max(first))
}

/// How a `persist connect --when-idle` that cannot log in to the server
/// without the user exits. This crosses builds: a service of one build reads
/// it from the command of the build it switches to.
pub(crate) const LOGIN_NEEDED_EXIT: i32 = 78;

/// How long commands wait before starting another switch to a connection
/// whose switch could not log in without the user: each attempt is a
/// failed login in the server's logs.
pub(crate) const LOGIN_RETRY: Duration = Duration::from_secs(600);

/// Set for a switch a command started (`receive_service::refresh_outdated`),
/// as opposed to a service's own; a command passes it to its own build.
pub(crate) const STARTED_BY_COMMAND: &str = "SYQ_SWITCH_BY_COMMAND";

/// After a switch could not log in without the user: when a command
/// started it, keep commands from trying again for `LOGIN_RETRY`, since
/// each attempt is a failed login on the server. A service's own switch
/// sets nothing, so that the user's next command in a terminal tries, as
/// its status says.
pub(crate) fn defer_after_login(control: &Path) {
    if std::env::var_os(STARTED_BY_COMMAND).is_some() {
        crate::persistence::defer_switch_attempts(control, LOGIN_RETRY);
    }
}

/// A switch to a new build could not log in to this server without the user.
#[derive(Debug)]
pub(crate) struct LoginNeeded(pub(crate) String);
impl std::fmt::Display for LoginNeeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "logging in to {} needs you", self.0)
    }
}

/// What a status shows about following an update.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Report {
    /// The build the followed file now holds, when known.
    #[serde(default)]
    pub(crate) to: Option<String>,
    /// `waiting` until nothing is in progress, `switching`, `login` until a
    /// syq command to the server logs in, or `failed`.
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
            "login" => format!(
                "switches to {to} when you next run a syq copy or ssh command, or syq persist status, in a terminal, since it could not log in by itself ({})",
                self.error.as_deref().unwrap_or("login failed")
            ),
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
    /// Nothing: the service predates following updates, its path is gone,
    /// or its path is a release in the binary store, which never changes.
    /// Commands replace it (`receive_service::refresh_outdated`).
    Nothing,
    /// The file this process runs, so it switches to this build by itself.
    ThisFile,
    /// Another file, as when two copies of syq are installed: commands
    /// leave it, so that the two never take turns replacing its service.
    OtherFile,
}
pub(crate) fn follows(started_from: Option<&str>) -> Follows {
    follows_with_store(started_from, crate::user_dirs::binary_store().as_deref())
}
/// `follows`, with the binary store at `store`.
fn follows_with_store(started_from: Option<&str>, store: Option<&Path>) -> Follows {
    let Some(path) = started_from.map(Path::new) else {
        return Follows::Nothing;
    };
    let Some(file) = file_at(path) else {
        return Follows::Nothing;
    };
    if crate::process::running_image() == Some(file) {
        Follows::ThisFile
    } else if store.is_some_and(|store| in_store(path, store)) {
        // A command run with `--use-version` starts its services from the
        // selected release in the store. That file never changes, so they
        // would keep that release through every update of the installed
        // syq; the installed syq replaces them instead.
        Follows::Nothing
    } else {
        Follows::OtherFile
    }
}
/// Whether `path` names a file in the binary store at `store`, as spelled or
/// with its directory resolved: the store may be a link to another disk. A
/// link elsewhere that leads into the store is not in it.
fn in_store(path: &Path, store: &Path) -> bool {
    let resolved = || {
        let directory = std::fs::canonicalize(path.parent()?).ok()?;
        Some(directory.join(path.file_name()?))
    };
    path.starts_with(store)
        || std::fs::canonicalize(store)
            .is_ok_and(|store| resolved().is_some_and(|path| path.starts_with(store)))
}
pub(crate) fn follows_other_file(started_from: Option<&str>) -> bool {
    follows(started_from) == Follows::OtherFile
}

/// Refuse to run a file that an arbitrary other account could have put
/// there, or pointed the path at. Every directory resolving `path` passes
/// through, including through each symbolic link on the way, must belong to
/// this user or root and must not be writable by every account, as
/// `remote_user_install` refuses such directories, nor have a macOS access
/// control list that lets other accounts change it. So must the file, which
/// must also be executable. Group write is allowed: Homebrew's directories,
/// and any directory made under a 002 umask, are group writable, and the
/// user's own commands run syq from them anyway. A directory with the sticky
/// bit, such as /tmp, may be writable by every account, who cannot replace
/// the entries others own there; an entry used in one must belong to this
/// user or root.
pub(crate) fn check_runnable(path: &Path) -> Result<()> {
    use std::ffi::OsStr;
    use std::path::Component;
    let user = unsafe { libc::geteuid() };
    let trusted = |metadata: &std::fs::Metadata| metadata.uid() == user || metadata.uid() == 0;
    // Whether an access control list lets other accounts change `path`,
    // which mode bits do not show on macOS. One for a group, such as the
    // `admin` group of a Homebrew shared by several accounts, counts as
    // group write does, unless it is the group of every account.
    let acl = |path: &Path| -> Result<()> {
        anyhow::ensure!(
            !crate::inode_metadata::acl_lets_others_change(
                path,
                crate::inode_metadata::AclGroups::Trusted
            )?,
            "{} has an access control list that lets other accounts change it",
            path.display()
        );
        Ok(())
    };
    // Whether every account may add entries to `directory`, after refusing
    // it if one could replace them.
    let directory = |directory: &Path| -> Result<bool> {
        let metadata = std::fs::metadata(directory)
            .with_context(|| format!("inspect {}", directory.display()))?;
        let shared = metadata.mode() & 0o002 != 0;
        anyhow::ensure!(
            trusted(&metadata) && (!shared || metadata.mode() & 0o1000 != 0),
            "the directory {} must belong to you or root, and other accounts may not write it",
            directory.display()
        );
        acl(directory)?;
        Ok(shared)
    };
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components = |path: &Path| -> Vec<std::ffi::OsString> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_owned()),
                Component::ParentDir => Some("..".into()),
                _ => None,
            })
            .rev()
            .collect()
    };
    // Names still to resolve, the next one last.
    let mut pending = components(&absolute);
    let mut current = PathBuf::from("/");
    let mut shared = directory(&current)?;
    let mut links = 0;
    while let Some(name) = pending.pop() {
        if name == OsStr::new("..") {
            current.pop();
            shared = directory(&current)?;
            continue;
        }
        let entry = current.join(&name);
        let metadata = std::fs::symlink_metadata(&entry)
            .with_context(|| format!("resolve {}", path.display()))?;
        anyhow::ensure!(
            !shared || trusted(&metadata),
            "{} must belong to you or root, since every account can write {}",
            entry.display(),
            current.display()
        );
        if metadata.file_type().is_symlink() {
            links += 1;
            anyhow::ensure!(
                links <= 40,
                "{} has too many symbolic links",
                path.display()
            );
            let target = std::fs::read_link(&entry)
                .with_context(|| format!("read the link {}", entry.display()))?;
            if target.is_absolute() {
                current = PathBuf::from("/");
                shared = directory(&current)?;
            }
            pending.extend(components(&target));
            continue;
        }
        if pending.is_empty() {
            anyhow::ensure!(
                metadata.is_file() && metadata.mode() & 0o111 != 0,
                "{} is not an executable file",
                entry.display()
            );
            anyhow::ensure!(
                trusted(&metadata) && metadata.mode() & 0o002 == 0,
                "{} must belong to you or root, and other accounts may not write it",
                entry.display()
            );
            acl(&entry)?;
            return Ok(());
        }
        anyhow::ensure!(metadata.is_dir(), "{} is not a directory", entry.display());
        shared = directory(&entry)?;
        current = entry;
    }
    anyhow::bail!("{} is not an executable file", path.display())
}

/// How a switch's command failed: what it said, and whether it could not
/// log in without the user (`LOGIN_NEEDED_EXIT`).
struct Ended {
    error: String,
    login: bool,
}

/// A started switch: the command's exit, and its process group.
struct Running {
    build: String,
    /// The file at the path that reported `build`.
    file: Option<Seen>,
    done: mpsc::Receiver<std::result::Result<(), Ended>>,
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
        file: Option<Seen>,
    },
    Switching(Running),
    /// The last attempt failed; look again at `retry`.
    Failed {
        build: Option<String>,
        error: String,
        retry: Instant,
    },
    /// The last attempt could not log in without the user. Only a command
    /// run at a terminal tries again (see the module comment).
    Login {
        build: String,
        error: String,
        file: Option<Seen>,
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
    /// Follow `path`. When it holds the file this process runs, that is the
    /// baseline; otherwise, as after an update during the switch that
    /// started this service, the file is asked for its build at the first
    /// look.
    pub(crate) fn new(path: PathBuf) -> Self {
        let runs_it = file_at(&path).is_some() && file_at(&path) == crate::process::running_image();
        Self {
            baseline: if runs_it { seen_at(&path) } else { None },
            path,
            next_check: Instant::now() + check_interval(),
            attempts: 0,
            state: State::Current,
        }
    }

    /// How long until `tick` has something to do: a service that sleeps
    /// between requests wakes then.
    pub(crate) fn due(&self) -> Duration {
        let now = Instant::now();
        match &self.state {
            State::Current => self.next_check.saturating_duration_since(now),
            // Nothing to do; a command switches it.
            State::Login { .. } => self.next_check.saturating_duration_since(now),
            State::Failed { retry, .. } => retry.saturating_duration_since(now),
            State::Probing(_) | State::Waiting { .. } | State::Switching(_) => {
                Duration::from_millis(200)
            }
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
                Ok((file, Ok(build))) => State::Waiting { build, file },
                Ok((_, Err(error))) => self.failed(
                    None,
                    format!("will not run {}: {error:#}", self.path.display()),
                ),
            },
            State::Waiting { build, file } => {
                if !idle() {
                    State::Waiting { build, file }
                } else {
                    match start(&self.path, args) {
                        Ok((done, group)) => State::Switching(Running {
                            build,
                            file,
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
                    if !running.killed
                        && running.started.elapsed() >= switch_timeout() + SWITCH_BACKSTOP
                    {
                        unsafe { libc::kill(-running.group, libc::SIGKILL) };
                        running.killed = true;
                    }
                    State::Switching(running)
                }
                _ if running.killed => self.failed(Some(running.build), timed_out()),
                // The command ended and this service still runs: it was
                // busy again, another command is replacing it, or the file
                // changed again. Look again after a while.
                Ok(Ok(())) => {
                    self.attempts += 1;
                    self.next_check = now + retry_after(retry_first(), self.attempts);
                    State::Current
                }
                Ok(Err(Ended { error, login: true })) => {
                    self.next_check = now + check_interval();
                    State::Login {
                        build: running.build,
                        error,
                        file: running.file,
                    }
                }
                Ok(Err(Ended { error, .. })) => self.failed(Some(running.build), error),
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
            // A command run at a terminal tries again; the service only
            // looks whether the path has changed since, as when the
            // update was undone or another one came, and asks it again.
            State::Login { build, error, file } => {
                if now < self.next_check {
                    State::Login { build, error, file }
                } else {
                    self.next_check = now + check_interval();
                    if seen_at(&self.path) == file {
                        State::Login { build, error, file }
                    } else {
                        self.next_check = now;
                        State::Current
                    }
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
            State::Waiting { build, .. } => Some(Report {
                to: Some(build.clone()),
                phase: "waiting".into(),
                error: None,
            }),
            State::Switching(running) => Some(Report {
                to: Some(running.build.clone()),
                phase: "switching".into(),
                error: None,
            }),
            State::Login { build, error, .. } => Some(Report {
                to: Some(build.clone()),
                phase: "login".into(),
                error: Some(error.clone()),
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
) -> Result<(mpsc::Receiver<std::result::Result<(), Ended>>, libc::pid_t)> {
    check_runnable(path).with_context(|| format!("will not run {}", path.display()))?;
    let mut output = tempfile::tempfile().context("create a temporary file for its output")?;
    let mut command = switch_command(path, args);
    command
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
        let result = match wait_and_end_group(&mut child) {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(Ended {
                error: last_line(&mut output).unwrap_or_else(|| status.to_string()),
                login: status.code() == Some(LOGIN_NEEDED_EXIT),
            }),
            Err(error) => Err(Ended {
                error: error.to_string(),
                login: false,
            }),
        };
        let _ = sender.send(result);
    });
    Ok((done, group))
}

/// The command that switches with the build at `path`. It is the
/// service's own switch, even when a command started this service
/// (`STARTED_BY_COMMAND`).
fn switch_command(path: &Path, args: &[OsString]) -> Command {
    let mut command = Command::new(path);
    command
        .args(args)
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .env_remove(STARTED_BY_COMMAND)
        // Without a terminal, ssh would otherwise ask through a desktop
        // dialog. A login that needs the user fails and says so instead.
        .env("SSH_ASKPASS_REQUIRE", "never");
    command
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

    /// Once a switch exits, what it left in its process group ends too.
    #[test]
    fn waiting_for_a_switch_ends_what_it_left_in_its_group() {
        use std::io::Read as _;
        use std::os::unix::process::CommandExt as _;
        let mut child = Command::new("sh")
            .args(["-c", "sleep 600 </dev/null >/dev/null 2>&1 & echo $!"])
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut pid = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut pid)
            .unwrap();
        let pid: libc::pid_t = pid.trim().parse().unwrap();
        assert!(wait_and_end_group(&mut child).unwrap().success());
        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(pid, 0) } == 0
            && !std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, f)| f.starts_with('Z'))
            })
        {
            assert!(Instant::now() < deadline, "the left process still runs");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

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

    /// The file a service runs is its baseline, and starts nothing. A file
    /// of this same build, at the start or installed again later, becomes
    /// the baseline; another build that replaces it starts the switch, once
    /// idle.
    #[test]
    fn only_another_build_at_the_path_starts_a_switch() {
        let running = std::env::current_exe().unwrap();
        assert_eq!(Follower::new(running.clone()).baseline, seen_at(&running));

        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("syq");
        script(&path, crate::identity::build());
        let mut follower = Follower::new(path.clone());
        assert_eq!(follower.baseline, None);
        tick_until(&mut follower, &|| true, |follower| {
            follower.baseline == seen_at(&path)
        });
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

    /// A service started after its path already took another build, as when
    /// an update landed during the switch that started it, switches to that
    /// build too.
    #[test]
    fn another_build_already_at_the_path_at_the_start_starts_a_switch() {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("syq");
        script(&path, "v99.0.0");
        let mut follower = Follower::new(path.clone());
        tick_until(&mut follower, &|| true, |_| switches(&path) == 1);
    }

    /// A Homebrew-style install: the followed path is a link in a group
    /// writable directory, and an update only points it at another
    /// version's directory.
    #[test]
    fn a_link_that_is_pointed_at_another_version_starts_a_switch() {
        use std::os::unix::fs::PermissionsExt;
        let directory = crate::test_support::tempdir().unwrap();
        let bin = directory.path().join("bin");
        let cellar = directory.path().join("Cellar");
        for version in ["1", "2"] {
            std::fs::create_dir_all(cellar.join(version)).unwrap();
        }
        std::fs::create_dir(&bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        script(&cellar.join("1/syq"), crate::identity::build());
        script(&cellar.join("2/syq"), "v99.0.0");
        let path = bin.join("syq");
        std::os::unix::fs::symlink("../Cellar/1/syq", &path).unwrap();
        let mut follower = Follower::new(path.clone());
        tick_until(&mut follower, &|| true, |follower| {
            follower.baseline == seen_at(&path)
        });
        // Relink, as `brew upgrade` does: the old version's file is unchanged.
        std::os::unix::fs::symlink("../Cellar/2/syq", bin.join("syq.new")).unwrap();
        std::fs::rename(bin.join("syq.new"), &path).unwrap();
        // The switch runs the link, which the new service then follows.
        tick_until(&mut follower, &|| true, |_| switches(&path) == 1);
    }

    /// A switch that cannot log in without the user is not tried again by
    /// the service, however long it runs, whether or not a control
    /// connection to the server stays up: only a command run at a terminal
    /// tries again.
    #[test]
    fn a_switch_that_needs_the_user_to_log_in_is_not_tried_again_by_the_service() {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("syq");
        script(&path, crate::identity::build());
        let mut follower = Follower::new(path.clone());
        tick_until(&mut follower, &|| true, |follower| {
            follower.baseline == seen_at(&path)
        });
        let new = path.with_extension("new");
        crate::test_support::write_executable(
            &new,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --build-identity ]; then echo v99.0.0; exit 0; fi\n\
                 printf '%s\\n' \"$*\" >> \"$0.log\"\n\
                 echo 'syq persist: logging in to server needs you: Permission denied (publickey).' >&2\n\
                 exit {LOGIN_NEEDED_EXIT}\n"
            ),
            0o755,
        );
        std::fs::rename(&new, &path).unwrap();
        tick_until(&mut follower, &|| true, |follower| {
            matches!(follower.state, State::Login { .. })
        });
        let report = follower.report().unwrap();
        assert_eq!(report.phase, "login");
        assert!(
            report.describe().starts_with(
                "switches to syq v99.0.0 when you next run a syq copy or ssh command, or syq persist status, in a terminal"
            ),
            "{}",
            report.describe()
        );
        // Idle and due, again and again: no further attempt.
        for _ in 0..50 {
            follower.next_check = Instant::now();
            follower.tick(&|| true, &[]);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(switches(&path), 1);
        assert!(matches!(follower.state, State::Login { .. }));

        // Once the path changes, as when the update is undone, the service
        // asks it again, without logging in: back to its own build, it has
        // nothing more to say.
        script(&path, crate::identity::build());
        tick_until(&mut follower, &|| true, |follower| {
            matches!(follower.state, State::Current) && follower.baseline == seen_at(&path)
        });
        assert!(follower.report().is_none());
        assert_eq!(switches(&path), 1);
    }

    /// A service's own switch is never taken for one a command started,
    /// even in a service that a command's switch started, which passed that
    /// on to it: it would hold commands off after a login that needs the
    /// user, though status says the next one in a terminal tries again.
    #[test]
    fn a_services_own_switch_is_not_taken_for_a_commands() {
        let command = switch_command(Path::new("/nonexistent/syq"), &["persist".into()]);
        assert!(command
            .get_envs()
            .any(|(name, value)| name == STARTED_BY_COMMAND && value.is_none()));
    }

    /// Another update after a switch could not log in is asked about, and
    /// reported, as a new one.
    #[test]
    fn another_update_after_a_login_failure_is_followed() {
        let directory = crate::test_support::tempdir().unwrap();
        let path = directory.path().join("syq");
        script(&path, crate::identity::build());
        let mut follower = Follower::new(path.clone());
        tick_until(&mut follower, &|| true, |follower| {
            follower.baseline == seen_at(&path)
        });
        let new = path.with_extension("new");
        crate::test_support::write_executable(
            &new,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --build-identity ]; then echo v99.0.0; exit 0; fi\n\
                 echo 'syq persist: logging in to server needs you' >&2\nexit {LOGIN_NEEDED_EXIT}\n"
            ),
            0o755,
        );
        std::fs::rename(&new, &path).unwrap();
        tick_until(&mut follower, &|| true, |follower| {
            matches!(follower.state, State::Login { .. })
        });
        script(&path, "v100.0.0");
        // While busy, it only reports the new build.
        tick_until(&mut follower, &|| false, |follower| {
            follower.report().is_some_and(|report| {
                report.phase == "waiting" && report.to.as_deref() == Some("v100.0.0")
            })
        });
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
    fn a_file_another_account_could_replace_is_not_run() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        let directory = crate::test_support::tempdir().unwrap();
        let bin = directory.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let path = bin.join("syq");
        script(&path, "v99.0.0");
        check_runnable(&path).unwrap();
        // Group write, as in Homebrew's directories or under a 002 umask.
        mode(&bin, 0o775);
        mode(&path, 0o775);
        check_runnable(&path).unwrap();
        // Write for every account is refused, for the file and its directory.
        mode(&path, 0o777);
        let error = check_runnable(&path).unwrap_err().to_string();
        assert!(error.contains("other accounts may not write it"), "{error}");
        mode(&path, 0o755);
        mode(&bin, 0o777);
        let error = check_runnable(&path).unwrap_err().to_string();
        assert!(error.contains("the directory"), "{error}");
        mode(&bin, 0o755);

        // A link through a directory every account can write, anywhere on
        // the way, could be pointed elsewhere.
        let shared = directory.path().join("shared");
        let start = directory.path().join("start");
        std::fs::create_dir(&shared).unwrap();
        std::fs::create_dir(&start).unwrap();
        std::os::unix::fs::symlink(&path, shared.join("hop")).unwrap();
        std::os::unix::fs::symlink(shared.join("hop"), start.join("syq")).unwrap();
        check_runnable(&start.join("syq")).unwrap();
        mode(&shared, 0o777);
        let error = check_runnable(&start.join("syq")).unwrap_err().to_string();
        assert!(error.contains(&shared.display().to_string()), "{error}");
        // With the sticky bit, others cannot replace the link this user owns.
        mode(&shared, 0o1777);
        check_runnable(&start.join("syq")).unwrap();
        let error = check_runnable(&directory.path().join("missing"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("resolve"), "{error}");

        // The follower reports a refused file instead of running it.
        let mut follower = Follower::new(path.clone());
        script(&path, "v99.0.0");
        mode(&path, 0o777);
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

    #[test]
    #[cfg(target_os = "macos")]
    fn a_followed_file_that_an_acl_lets_others_change_will_not_run() {
        let directory = crate::test_support::tempdir().unwrap();
        let bin = directory.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let path = bin.join("syq");
        script(&path, "v99.0.0");
        check_runnable(&path).unwrap();
        let chmod = |arguments: &[&std::ffi::OsStr]| {
            assert!(std::process::Command::new("chmod")
                .args(arguments)
                .status()
                .unwrap()
                .success());
        };
        for (entry, changed) in [
            ("everyone allow write", &path),
            ("everyone allow add_file", &bin),
        ] {
            chmod(&["+a".as_ref(), entry.as_ref(), changed.as_os_str()]);
            let error = check_runnable(&path).unwrap_err().to_string();
            assert!(error.contains("access control list"), "{entry}: {error}");
            chmod(&["-N".as_ref(), changed.as_os_str()]);
            check_runnable(&path).unwrap();
        }
        // An entry only for what is created there later changes nothing,
        // and one for a group counts as group write: allowed here.
        for entry in [
            "everyone allow add_file,delete_child,file_inherit,directory_inherit,only_inherit",
            "group:admin allow add_file,delete_child,file_inherit,directory_inherit",
        ] {
            chmod(&["+a".as_ref(), entry.as_ref(), bin.as_os_str()]);
            check_runnable(&path).unwrap();
        }
    }

    #[test]
    fn commands_replace_services_that_follow_a_stored_release() {
        // `--use-version` runs a release from the binary store; a service it
        // starts follows that file, which no update ever changes.
        let directory = crate::test_support::tempdir().unwrap();
        let store = directory.path().join("home/.local/lib/syq");
        let stored = store.join("v0.8.0/linux-x86_64/syq");
        std::fs::create_dir_all(stored.parent().unwrap()).unwrap();
        script(&stored, "v0.8.0");
        let stored = stored.to_str().unwrap();
        assert_eq!(follows_with_store(Some(stored), None), Follows::OtherFile);
        assert_eq!(
            follows_with_store(Some(stored), Some(&store)),
            Follows::Nothing
        );
        // Also when the store is reached through a link, as to another disk.
        let link = directory.path().join("linked-store");
        std::os::unix::fs::symlink(&store, &link).unwrap();
        assert_eq!(
            follows_with_store(Some(stored), Some(&link)),
            Follows::Nothing
        );
        // An installed syq outside the store is still left alone, and so is
        // a link outside it that leads to a stored release.
        let installed = directory.path().join("bin/syq");
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        script(&installed, "v99.0.0");
        assert_eq!(
            follows_with_store(Some(installed.to_str().unwrap()), Some(&store)),
            Follows::OtherFile
        );
        let pinned = directory.path().join("bin/pinned");
        std::os::unix::fs::symlink(stored, &pinned).unwrap();
        assert_eq!(
            follows_with_store(Some(pinned.to_str().unwrap()), Some(&store)),
            Follows::OtherFile
        );
    }
}
