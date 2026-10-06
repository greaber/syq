//! Independent data transports consume an existing account permission. Each
//! native SSH handshake gets its own host-bound agent session; no worker can
//! turn a missing permission into another approval prompt.
use super::{local_config::LocalPlan, persistent, resolution, SessionRequest};
use crate::destination::ssh_auth::{self, ResolvedPolicy, Session};
use crate::persistence::Domain;
use anyhow::{Context, Result};
use std::fmt;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(crate) struct Authorization {
    domain: Domain,
    scope_identity: Option<(u64, u64)>,
    generation: String,
    request: SessionRequest,
    binding: String,
    policy: ResolvedPolicy,
    local: LocalPlan,
    proxy: Option<String>,
    control: PathBuf,
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("endpoint", &self.local.endpoint)
            .finish_non_exhaustive()
    }
}

/// Definitive authorization failures for this frozen copy selection must not
/// become repeated provider requests. Transient setup failures remain ordinary
/// connection errors and use the existing bounded connection retry policy.
#[derive(Debug)]
pub(crate) struct AuthorizationError(pub(crate) anyhow::Error);
impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot authorize independent SSH data connection: {:#}",
            self.0
        )
    }
}
impl std::error::Error for AuthorizationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

fn classify_setup_error(error: anyhow::Error) -> anyhow::Error {
    if error.chain().any(|cause| cause.is::<AuthorizationError>()) {
        return error;
    }
    if ssh_auth::retryable_setup_error(&error) {
        error
    } else {
        AuthorizationError(error).into()
    }
}

impl Authorization {
    pub(super) fn new(
        domain: &Domain,
        request: SessionRequest,
        selected: &resolution::Selection,
        generation: String,
        proxy: Option<String>,
        control: PathBuf,
    ) -> Result<Self> {
        let local = selected
            .local
            .clone()
            .context("approved account lacks requester configuration")?;
        local.validate()?;
        selected.policy.validate()?;
        anyhow::ensure!(
            request.destination == local.requested && selected.policy.endpoint == local.endpoint,
            "approved worker selection does not match the selected account"
        );
        local.route_options(proxy.as_deref())?;
        Ok(Self {
            domain: domain.clone(),
            scope_identity: (!domain.is_default())
                .then(|| domain.identity())
                .transpose()?,
            generation,
            request,
            binding: selected.provider.clone(),
            policy: selected.policy.clone(),
            local,
            proxy,
            control,
        })
    }

    pub(super) fn belongs_to(&self, domain: &Domain) -> bool {
        self.domain == *domain
    }

    fn available(&self) -> Result<()> {
        anyhow::ensure!(
            self.scope_identity
                .is_none_or(|identity| self.domain.is_current(identity))
                && persistent::generation_open(&self.domain, &self.generation)?,
            "approved SSH account scope ended before its data connection started"
        );
        anyhow::ensure!(
            crate::persistence::socket_is_ready(&self.control)
                .context("approved SSH account master is busy or unavailable")?,
            "approved SSH account connection ended before its data connection started"
        );
        Ok(())
    }

    pub(crate) fn begin(&self) -> Result<Login> {
        self.begin_inner().map_err(classify_setup_error)
    }

    fn begin_inner(&self) -> Result<Login> {
        self.available()?;
        let session = ssh_auth::authorize_worker_expected(
            &self.domain,
            &self.request,
            Vec::new(),
            &self.binding,
            &self.policy,
            &self.local,
        )?;
        // Off/revoke may race the provider exchange. It must not create a
        // replacement data login after the owning account has ended.
        self.available()?;
        anyhow::ensure!(
            !session.cancelled(),
            "SSH data authorization ended before use"
        );
        Ok(Login {
            session,
            local: self.local.clone(),
            proxy: self.proxy.clone(),
            control: self.control.clone(),
        })
    }
}

fn worker_command(
    local: &LocalPlan,
    proxy: Option<&str>,
    options: Vec<std::ffi::OsString>,
) -> Result<Command> {
    let mut command = Command::new("ssh");
    command
        .args(local.options())
        .args(local.route_options(proxy)?)
        .args(options)
        .args(["-o", crate::conn::CIPHERS])
        // Helper traffic is binary even if the alias normally opens a shell.
        .args([
            "-o",
            "ForkAfterAuthentication=no",
            "-o",
            "RemoteCommand=none",
            "-T",
            "--",
        ])
        .arg(&local.requested.host);
    // Arbitrary ProxyCommand authentication stays local. The provider socket
    // appears only as OpenSSH's IdentityAgent option, never in its environment.
    Ok(command)
}

pub(crate) struct Login {
    session: Session,
    local: LocalPlan,
    proxy: Option<String>,
    control: PathBuf,
}
impl Login {
    /// Append the exact helper command and configure pipes before spawning.
    pub(crate) fn command(&self) -> Result<Command> {
        worker_command(&self.local, self.proxy.as_deref(), self.session.options())
    }

    /// The child must lead its own process group. Keep this guard until SSH
    /// exits, and drop it BEFORE reaping the child so its PID cannot be reused.
    pub(crate) fn watch(self, child_pid: u32) -> Result<Guard> {
        let Self {
            session, control, ..
        } = self;
        let master =
            MasterWatch::connect(&control).context("watch approved SSH account connection")?;
        Guard::start(
            child_pid,
            move || session.cancelled(),
            move || master.closed(),
        )
    }
}

/// A local mux client occupies no SSH session and needs no network round trip.
/// Keeping it open ties independent workers to the actual master, including
/// when a crash leaves its socket file behind. It also keeps ControlPersist
/// alive while those workers are active. Dropping the guard closes the watch.
struct MasterWatch(socket2::Socket);
impl MasterWatch {
    fn connect(path: &Path) -> std::io::Result<Self> {
        Self::connect_until(path, Instant::now() + Duration::from_millis(250))
    }

    fn connect_until(path: &Path, deadline: Instant) -> std::io::Result<Self> {
        let address = socket2::SockAddr::unix(path)?;
        loop {
            let socket = crate::process::with_inheritance_guard(|| {
                socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
            })?;
            socket.set_nonblocking(true)?;
            match socket.connect(&address) {
                Ok(()) => return Ok(Self(socket)),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    // Linux reports EAGAIN for a full queue; Darwin can report
                    // ECONNREFUSED. Retry only this failed local connect, with
                    // a fresh socket and a short deadline, never a new login.
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "approved SSH master socket {} remained unavailable: {error}",
                                path.display()
                            ),
                        ));
                    }
                    std::thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn closed(&self) -> bool {
        // Drain the unsolicited mux Hello: on Darwin unread data can mask HUP.
        // There are no SSH requests or replies on this local lifetime watch.
        // Bound draining so unexpected input cannot delay cancellation checks.
        let mut bytes = [0u8; 4096];
        for _ in 0..4 {
            let count = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if count == 0 {
                return true;
            }
            if count < 0 {
                match std::io::Error::last_os_error().kind() {
                    std::io::ErrorKind::WouldBlock => return false,
                    std::io::ErrorKind::Interrupted => continue,
                    _ => return true,
                }
            }
        }
        false
    }
}

enum Event {
    Stop,
    Authenticated(mpsc::SyncSender<bool>),
}

pub(crate) struct Guard {
    stop: mpsc::Sender<Event>,
    watcher: Option<JoinHandle<()>>,
}
impl fmt::Debug for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovedWorkerGuard")
            .finish_non_exhaustive()
    }
}
impl Guard {
    fn start(
        child_pid: u32,
        authorization_cancelled: impl Fn() -> bool + Send + 'static,
        master_closed: impl Fn() -> bool + Send + 'static,
    ) -> Result<Self> {
        let pid = i32::try_from(child_pid).context("invalid SSH child PID")?;
        anyhow::ensure!(pid > 1, "invalid SSH child PID");
        let (stop, receiver) = mpsc::channel();
        let watcher = std::thread::Builder::new()
            .name("syq-ssh-worker".into())
            .spawn(move || {
                let mut authorization = Some(authorization_cancelled);
                loop {
                    let event = receiver.recv_timeout(Duration::from_millis(100));
                    if matches!(
                        event,
                        Ok(Event::Stop) | Err(mpsc::RecvTimeoutError::Disconnected)
                    ) {
                        break;
                    }
                    let cancelled =
                        master_closed() || authorization.as_ref().is_some_and(|closed| closed());
                    if cancelled {
                        // This is our dedicated SSH group, including its local
                        // ProxyCommand transport. The caller still owns reaping.
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        if let Ok(Event::Authenticated(reply)) = event {
                            let _ = reply.send(false);
                        }
                        break;
                    }
                    if let Ok(Event::Authenticated(reply)) = event {
                        // Exact helper Hello proves SSH authentication finished.
                        // Release its one-login broker and provider admission slot;
                        // the original approved master still owns account lifetime.
                        drop(authorization.take());
                        let _ = reply.send(true);
                    }
                }
            })?;
        Ok(Self {
            stop,
            watcher: Some(watcher),
        })
    }

    /// Call only after accepting the exact helper's Hello. The acknowledgement
    /// ensures local signing resources are released before another worker starts.
    pub(crate) fn authenticated(&self) -> Result<()> {
        let result = (|| {
            let (reply, receive) = mpsc::sync_channel(1);
            self.stop
                .send(Event::Authenticated(reply))
                .context("SSH worker authorization ended before helper authentication completed")?;
            anyhow::ensure!(
                receive.recv_timeout(Duration::from_secs(5)).context(
                    "SSH worker did not release its signing session after authentication"
                )?,
                "SSH account ended before helper authentication completed"
            );
            Ok(())
        })();
        result.map_err(|error| AuthorizationError(error).into())
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.stop.send(Event::Stop);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::local_config::Route;
    use super::*;
    use crate::cli::NativeEndpoint;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Instant;

    fn local() -> LocalPlan {
        LocalPlan {
            requested: NativeEndpoint {
                user: None,
                host: "configured-alias".into(),
                port: None,
            },
            endpoint: NativeEndpoint {
                user: Some("approved-user".into()),
                host: "192.0.2.8".into(),
                port: Some(2200),
            },
            host_key_alias: None,
            config_digest: "a".repeat(64),
            route: Route::Direct,
            host_key_algorithms: "ssh-ed25519".into(),
            hop: None,
        }
    }

    #[test]
    fn master_watch_detects_death_with_unread_hello_and_stale_socket() {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("master");
        let listener =
            crate::process::with_inheritance_guard(|| UnixListener::bind(&path)).unwrap();
        let watch = MasterWatch::connect(&path).unwrap();
        let (mut master, _) = crate::process::with_inheritance_guard(|| listener.accept()).unwrap();
        master.write_all(b"mux hello").unwrap();
        assert!(!watch.closed());
        // closed() drains available bytes. Leave fresh bytes unread when the
        // master exits so this continues covering Darwin's buffered-EOF case.
        master.write_all(b"remaining mux hello").unwrap();
        drop(master);
        drop(listener);
        // A child that another test forked before these drops keeps the master
        // open until it execs. Wait for the hangup without reading, so the
        // bytes above are still unread when closed() runs.
        #[cfg(target_os = "linux")]
        {
            let mut hangup = libc::pollfd {
                fd: watch.0.as_raw_fd(),
                events: libc::POLLRDHUP,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut hangup, 1, 10_000) }, 1);
        }
        assert!(path.exists());
        assert!(watch.closed());
    }

    fn full_queue(path: &Path) -> (socket2::Socket, Vec<socket2::Socket>) {
        let listener = crate::process::with_inheritance_guard(|| {
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        })
        .unwrap();
        let address = socket2::SockAddr::unix(path).unwrap();
        listener.bind(&address).unwrap();
        listener.listen(1).unwrap();
        let mut clients = Vec::new();
        for _ in 0..16 {
            let client = crate::process::with_inheritance_guard(|| {
                socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
            })
            .unwrap();
            client.set_nonblocking(true).unwrap();
            match client.connect(&address) {
                Ok(()) => clients.push(client),
                Err(error) => {
                    assert!(
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::ConnectionRefused
                        ),
                        "{error}"
                    );
                    return (listener, clients);
                }
            }
        }
        panic!("test socket did not reach its one-entry listen backlog");
    }

    #[test]
    fn master_watch_retries_a_full_queue_until_it_drains() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("master");
        let (listener, _clients) = full_queue(&path);
        let (finished, finish) = mpsc::channel();
        let accept = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            let _client = crate::process::with_inheritance_guard(|| listener.accept()).unwrap();
            finish.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        let watch = MasterWatch::connect_until(&path, Instant::now() + Duration::from_secs(2));
        finished.send(()).unwrap();
        accept.join().unwrap();
        assert!(
            watch.is_ok(),
            "watch could not connect after queue drained: {:?}",
            watch.err()
        );
    }

    #[test]
    fn master_watch_full_queue_has_a_deadline() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("master");
        let (_listener, _clients) = full_queue(&path);
        let start = Instant::now();
        let error = MasterWatch::connect_until(&path, start + Duration::from_millis(30))
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(error.to_string().contains(path.to_str().unwrap()));
    }

    #[test]
    fn independent_worker_keeps_alias_and_pinned_route_without_master_reuse() {
        let local = local();
        let root = crate::test_support::tempdir().unwrap();
        let config = root.path().join("config");
        std::fs::write(&config, "Host *\n ForkAfterAuthentication yes\n").unwrap();
        let mut command = worker_command(
            &local,
            None,
            vec![
                "-G".into(),
                "-F".into(),
                config.into_os_string(),
                "-o".into(),
                "ControlMaster=no".into(),
                "-o".into(),
                "ControlPath=none".into(),
            ],
        )
        .unwrap();
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let resolved = String::from_utf8(output.stdout).unwrap();
        for line in [
            "host configured-alias",
            "hostname 192.0.2.8",
            "user approved-user",
            "port 2200",
            "controlmaster false",
            "requesttty false",
            "forkafterauthentication no",
        ] {
            assert!(
                resolved.lines().any(|value| value == line),
                "missing {line}: {resolved}"
            );
        }
        assert!(!resolved
            .lines()
            .any(|line| line.starts_with("controlpath ")));
        assert!(!resolved
            .lines()
            .any(|line| line.starts_with("proxycommand ")));
        assert!(!resolved
            .lines()
            .any(|line| line.starts_with("remotecommand ")));
        let mut jumped = local;
        jumped.route = Route::Jump(vec![jumped.requested.clone()]);
        assert!(worker_command(&jumped, None, vec![]).is_err());
        let command = worker_command(
            &jumped,
            Some("ssh -S /private/control -W '[target]:22' jump"),
            vec![],
        )
        .unwrap();
        assert!(command
            .get_args()
            .any(|arg| arg == "ProxyCommand=ssh -S /private/control -W '[target]:22' jump"));
    }

    #[test]
    fn worker_setup_retries_transport_and_capacity_but_not_policy_or_cancellation() {
        fn retryable(error: anyhow::Error) -> bool {
            !classify_setup_error(error)
                .chain()
                .any(|cause| cause.is::<AuthorizationError>())
        }
        for kind in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::UnexpectedEof,
        ] {
            let error =
                anyhow::Error::new(std::io::Error::from(kind)).context("provider transport setup");
            assert!(retryable(error), "{kind:?}");
        }
        assert!(retryable(
            ssh_auth::RetryableSetupError("capacity exhausted".into()).into()
        ));
        assert!(retryable(
            std::io::Error::from_raw_os_error(libc::ECONNABORTED).into()
        ));
        for message in [
            "the account grant ended",
            "provider configuration changed",
            "SSH data authorization ended before use",
        ] {
            assert!(!retryable(anyhow::anyhow!(message)));
        }
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::InvalidData,
            // Bounded policy inspection uses this for explicit cancellation.
            std::io::ErrorKind::ConnectionAborted,
        ] {
            assert!(!retryable(std::io::Error::from(kind).into()), "{kind:?}");
        }
        // Once the helper has authenticated, cancellation stays definitive
        // even if its error chain happens to include a transport error.
        assert!(!retryable(
            AuthorizationError(std::io::Error::from(std::io::ErrorKind::TimedOut).into()).into()
        ));
    }

    fn exited_without_reaping(child: &std::process::Child) -> bool {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        info.si_signo != 0
    }

    fn wait_exited_without_reaping(child: &std::process::Child) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !exited_without_reaping(child) {
            assert!(
                Instant::now() < deadline,
                "SSH worker group survived account cancellation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn provider_disconnect_kills_only_the_owned_worker_group() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let observed = cancelled.clone();
        let mut worker =
            crate::process::group::ProcessGroup::spawn(Command::new("sleep").arg("30")).unwrap();
        let guard = Guard::start(
            worker.child.id(),
            move || observed.load(Ordering::Acquire),
            || false,
        )
        .unwrap();
        cancelled.store(true, Ordering::Release);
        wait_exited_without_reaping(&worker.child);
        drop(guard);
        assert!(!worker.close().unwrap().success());
    }

    #[test]
    fn guard_drop_releases_authorization_before_child_reaping() {
        struct Released(Arc<AtomicBool>);
        impl Drop for Released {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let released = Arc::new(AtomicBool::new(false));
        let lifetime = Released(released.clone());
        let mut worker =
            crate::process::group::ProcessGroup::spawn(Command::new("sleep").arg("30")).unwrap();
        let guard = Guard::start(
            worker.child.id(),
            move || {
                let _ = &lifetime;
                false
            },
            || false,
        )
        .unwrap();
        drop(guard);
        assert!(released.load(Ordering::Acquire));
        assert!(worker.child.try_wait().unwrap().is_none());
        worker.close().unwrap();
    }

    #[test]
    fn authenticated_worker_releases_signing_but_still_follows_master_lifetime() {
        struct Released(Arc<AtomicBool>);
        impl Drop for Released {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let released = Arc::new(AtomicBool::new(false));
        let lifetime = Released(released.clone());
        let source_closed = Arc::new(AtomicBool::new(false));
        let observed_source = source_closed.clone();
        let master_closed = Arc::new(AtomicBool::new(false));
        let observed_master = master_closed.clone();
        let mut worker =
            crate::process::group::ProcessGroup::spawn(Command::new("sleep").arg("30")).unwrap();
        let guard = Guard::start(
            worker.child.id(),
            move || {
                let _ = &lifetime;
                observed_source.load(Ordering::Acquire)
            },
            move || observed_master.load(Ordering::Acquire),
        )
        .unwrap();
        assert!(!released.load(Ordering::Acquire));
        guard.authenticated().unwrap();
        assert!(released.load(Ordering::Acquire));
        // Closing the released signing channel must not kill authenticated SSH.
        source_closed.store(true, Ordering::Release);
        guard.authenticated().unwrap();
        assert!(!exited_without_reaping(&worker.child));
        master_closed.store(true, Ordering::Release);
        wait_exited_without_reaping(&worker.child);
        drop(guard);
        assert!(!worker.close().unwrap().success());
    }

    #[test]
    fn helper_authentication_cannot_revive_a_cancelled_login() {
        let mut worker =
            crate::process::group::ProcessGroup::spawn(Command::new("sleep").arg("30")).unwrap();
        let guard = Guard::start(worker.child.id(), || true, || false).unwrap();
        let error = guard.authenticated().unwrap_err();
        assert!(error.downcast_ref::<AuthorizationError>().is_some());
        wait_exited_without_reaping(&worker.child);
        drop(guard);
        assert!(!worker.close().unwrap().success());
    }
}
