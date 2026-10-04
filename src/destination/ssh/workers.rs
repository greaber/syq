//! Independent data transports consume an existing account permission. Each
//! native SSH handshake gets its own host-bound agent session; no worker can
//! turn a missing permission into another approval prompt.
use super::{local_config::LocalPlan, persistent, resolution, SessionRequest};
use crate::destination::ssh_auth::{self, ResolvedPolicy, Session};
use crate::persistence::Domain;
use anyhow::{Context, Result};
use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

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

/// Authorization failures are deterministic for this frozen copy selection.
/// Connection retry code must not turn them into repeated provider requests.
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
        self.begin_inner()
            .map_err(|error| AuthorizationError(error).into())
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
        .args(["-o", "RemoteCommand=none", "-T", "--"])
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

    pub(crate) fn cancelled(&self) -> bool {
        self.session.cancelled() || !self.control.exists()
    }

    /// The child must lead its own process group. Keep this guard until SSH
    /// exits, and drop it BEFORE reaping the child so its PID cannot be reused.
    pub(crate) fn watch(self, child_pid: u32) -> Result<Guard> {
        Guard::start(child_pid, move || self.cancelled())
    }
}

pub(crate) struct Guard {
    stop: mpsc::Sender<()>,
    watcher: Option<JoinHandle<()>>,
}
impl fmt::Debug for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovedWorkerGuard")
            .finish_non_exhaustive()
    }
}
impl Guard {
    fn start(child_pid: u32, cancelled: impl Fn() -> bool + Send + 'static) -> Result<Self> {
        let pid = i32::try_from(child_pid).context("invalid SSH child PID")?;
        anyhow::ensure!(pid > 1, "invalid SSH child PID");
        let (stop, receiver) = mpsc::channel();
        let watcher = std::thread::Builder::new()
            .name("syq-ssh-worker".into())
            .spawn(move || {
                while matches!(
                    receiver.recv_timeout(Duration::from_millis(100)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    if cancelled() {
                        // This is our dedicated SSH group, including its local
                        // ProxyCommand transport. The caller still owns reaping.
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        break;
                    }
                }
            })?;
        Ok(Self {
            stop,
            watcher: Some(watcher),
        })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.stop.send(());
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
    fn independent_worker_keeps_alias_and_pinned_route_without_master_reuse() {
        let local = local();
        let mut command = worker_command(
            &local,
            None,
            vec![
                "-G".into(),
                "-F".into(),
                "/dev/null".into(),
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
    fn provider_disconnect_kills_only_the_owned_worker_group() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let observed = cancelled.clone();
        let mut worker =
            crate::process::group::ProcessGroup::spawn(Command::new("sleep").arg("30")).unwrap();
        let guard =
            Guard::start(worker.child.id(), move || observed.load(Ordering::Acquire)).unwrap();
        cancelled.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    libc::waitid(
                        libc::P_PID,
                        worker.child.id() as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                },
                0
            );
            if info.si_signo != 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "SSH worker group survived provider cancellation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
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
        let guard = Guard::start(worker.child.id(), move || {
            let _ = &lifetime;
            false
        })
        .unwrap();
        drop(guard);
        assert!(released.load(Ordering::Acquire));
        assert!(worker.child.try_wait().unwrap().is_none());
        worker.close().unwrap();
    }
}
