//! Explicit destination-account authorization over an authenticated return channel.
use super::*;
use crate::agent_broker::{BrokerPolicy, ConstrainedAgentBroker};
use crate::cli::NativeEndpoint;

const HOST_ALIAS: &str = "syq-approved-peer";

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Mode {
    #[default]
    Once,
    Persistent,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    #[serde(default)]
    mode: Mode,
    target: NativeEndpoint,
    command: Vec<Vec<u8>>,
    cwd: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorized {
    endpoint: NativeEndpoint,
    host_algorithms: String,
    known_hosts: String,
}

/// One approved native SSH login. Keep the return channel alive until SSH exits,
/// including after OpenSSH closes its authentication-agent connection.
pub(crate) struct Session {
    stream: UnixStream,
    _broker: PrivateBroker,
    endpoint: NativeEndpoint,
    options: Vec<OsString>,
}

impl Session {
    pub(crate) fn endpoint(&self) -> &NativeEndpoint {
        &self.endpoint
    }

    pub(crate) fn options(&self) -> Vec<OsString> {
        self.options.clone()
    }

    pub(crate) fn cancelled(&self) -> bool {
        disconnected(&self.stream)
    }
}

fn disconnected(socket: &UnixStream) -> bool {
    let mut byte = 0u8;
    let result = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    // Authentication replies belong to the agent relay. Peeking must neither
    // consume them nor mistake a pending reply for session cancellation.
    result == 0
        || (result < 0
            && !matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ))
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        // Closing the stream wakes any agent request before broker drop joins it.
    }
}

pub(crate) fn authorize(request: &ssh::SessionRequest) -> Result<Session> {
    authorize_mode(request, Mode::Once, None)
}

pub(crate) fn prepare_persistent(request: &ssh::SessionRequest) -> Result<()> {
    let selection = handoff::Selection::new(
        request.authorizer.clone(),
        load_registration(&request.authorizer)?,
        handoff::Kind::SshPersistent,
        None,
    );
    handoff::maybe_exec(&selection)
}

pub(crate) fn authorize_persistent(
    request: &ssh::SessionRequest,
    command: Vec<Vec<u8>>,
) -> Result<Session> {
    authorize_mode(request, Mode::Persistent, Some(command))
}

fn authorize_mode(
    request: &ssh::SessionRequest,
    mode: Mode,
    command: Option<Vec<Vec<u8>>>,
) -> Result<Session> {
    crate::conn::require_constrained_openssh("ssh", "on this machine")?;
    let selection = handoff::Selection::new(
        request.authorizer.clone(),
        load_registration(&request.authorizer)?,
        if mode == Mode::Once {
            handoff::Kind::Ssh
        } else {
            handoff::Kind::SshPersistent
        },
        None,
    );
    if mode == Mode::Once {
        handoff::maybe_exec(&selection)?;
    } else if selection.registration.identity != crate::identity::build() {
        bail!("receiving connection changed while starting the persistent SSH login; retry persist connect");
    }
    crate::output::diagnostic!(
        "syq: requesting SSH account access from @{}; approve on that machine",
        request.authorizer
    );
    let (mut stream, reply) = exchange(
        &selection.registration,
        Message::Ssh(Request {
            mode,
            target: request.destination.clone(),
            command: command
                .map(Ok)
                .unwrap_or_else(crate::approval_command::current)?,
            cwd: crate::approval_command::current_directory(),
        }),
        REQUEST_TIMEOUT + Duration::from_secs(30),
        Some(Duration::from_secs(120)),
    )?;
    if !matches!(reply, Reply::Ready) {
        bail!("unexpected SSH approval response");
    }
    let approved: Authorized = read_message(&mut stream)?;
    request.ssh_arguments(&approved.endpoint)?;
    let channel = Mutex::new(Some(stream.try_clone()?));
    let broker = PrivateBroker::start_managed(
        PrivateBrokerConfig {
            directory_prefix: "syq-ssh-",
            socket_name: "agent",
            listener_thread: "syq-ssh-agent",
            client_thread: "syq-ssh-sign",
            max_connections: 1,
            io_timeout: Duration::from_secs(120),
        },
        move |mut local, registry| {
            let Some(remote) = channel.lock().unwrap().take() else {
                return;
            };
            if let Ok(mut remote) = registry.track(remote) {
                let _ = crate::agent_broker::relay_frames(&mut local, &mut remote);
            }
        },
    )?;
    let known_hosts = broker.socket_path().with_file_name("known_hosts");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&known_hosts)?;
    file.write_all(approved.known_hosts.as_bytes())?;
    let options = ssh_options(
        broker.socket_path(),
        &known_hosts,
        &approved.host_algorithms,
    )?;
    Ok(Session {
        stream,
        _broker: broker,
        endpoint: approved.endpoint,
        options,
    })
}

fn ssh_options(agent: &Path, known_hosts: &Path, algorithms: &str) -> Result<Vec<OsString>> {
    let agent = agent.to_str().context("agent socket path is not UTF-8")?;
    let known_hosts = known_hosts
        .to_str()
        .context("known-hosts path is not UTF-8")?;
    // OpenSSH expands configuration tokens even in command-line values. A
    // surprising temporary-directory spelling must fail instead of changing
    // the authentication socket or trusted host file.
    for path in [agent, known_hosts] {
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-+:@,=".contains(&b))
        {
            bail!("SSH authorization requires a temporary-directory path without whitespace or SSH expansion tokens");
        }
    }
    if algorithms.is_empty()
        || !algorithms
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_,.@".contains(&b))
    {
        bail!("invalid approved host-key algorithms");
    }
    let mut options: Vec<OsString> = ["-F", "/dev/null", "-a", "-x", "-k"]
        .into_iter()
        .map(Into::into)
        .collect();
    for option in [
        "IdentitiesOnly=no".to_owned(),
        "IdentityFile=none".into(),
        "CertificateFile=none".into(),
        "PKCS11Provider=none".into(),
        "PubkeyAuthentication=host-bound".into(),
        "PreferredAuthentications=publickey".into(),
        "BatchMode=yes".into(),
        "ForwardAgent=no".into(),
        "ForwardX11=no".into(),
        "PermitLocalCommand=no".into(),
        "ClearAllForwardings=yes".into(),
        "ControlMaster=no".into(),
        "ControlPath=none".into(),
        "ProxyJump=none".into(),
        "ProxyCommand=none".into(),
        "StrictHostKeyChecking=yes".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "UpdateHostKeys=no".into(),
        "CheckHostIP=no".into(),
        "ServerAliveInterval=15".into(),
        "ServerAliveCountMax=3".into(),
        format!("HostKeyAlias={HOST_ALIAS}"),
        format!("IdentityAgent={agent}"),
        format!("UserKnownHostsFile={known_hosts}"),
        format!("HostKeyAlgorithms={algorithms}"),
    ] {
        options.extend(["-o".into(), option.into()]);
    }
    Ok(options)
}

impl Receiver {
    pub(super) fn authorize_ssh(&self, request: Request, mut stream: TrackedStream) -> Result<()> {
        if request.command.len() > 256
            || request.command.iter().map(Vec::len).sum::<usize>() > 16 * 1024
        {
            bail!("SSH approval command exceeds its limits");
        }
        let command: Vec<OsString> = request
            .command
            .iter()
            .cloned()
            .map(OsString::from_vec)
            .collect();
        let parsed = match request.mode {
            Mode::Once => {
                if command.first().is_none_or(|arg| arg != "ssh") {
                    bail!("SSH approval needs the requesting syq ssh command");
                }
                ssh::parse_for_approval(&command, &self.name)?
            }
            Mode::Persistent => crate::persistence::parse_account_connect(&command, &self.name)?,
        };
        if parsed.destination != request.target || parsed.authorizer != self.name {
            bail!("SSH destination or authorizer does not match the shown command");
        }
        let request_lock = self
            .request_lock
            .try_lock()
            .map_err(|_| anyhow::anyhow!("another request is awaiting approval"))?;
        let count = self.exec_count.fetch_add(1, Ordering::AcqRel);
        struct Slot<'a>(&'a AtomicU64);
        impl Drop for Slot<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _slot = Slot(&self.exec_count);
        if count >= 8 {
            bail!("too many active SSH sessions or commands");
        }
        let (generation, _tracked) = {
            let _sessions = self.sessions.lock().unwrap();
            (
                self.generation.load(Ordering::Acquire),
                self.active_streams.track(stream.try_clone()?)?,
            )
        };
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
                || requester_closed(&socket)
        };
        let policy = crate::agent_broker::resolve_host_policy_at(
            "ssh",
            request.target.user.as_deref(),
            &request.target.host,
            request.target.port,
        )?;
        let endpoint = NativeEndpoint {
            user: Some(policy.login_user.clone()),
            host: policy.connection_host().into(),
            port: Some(policy.port()),
        };
        self.approvals.request_ssh(
            &self.requester,
            &request.command,
            &request.cwd,
            &endpoint,
            request.mode == Mode::Persistent,
            self.notifications,
            cancelled,
        )?;
        if cancelled() {
            bail!("SSH request disconnected before authorization");
        }
        drop(request_lock);
        let approved = Authorized {
            endpoint,
            host_algorithms: policy.host_key_algorithms(),
            known_hosts: policy.known_hosts(HOST_ALIAS)?,
        };
        let broker = ConstrainedAgentBroker::start(BrokerPolicy::direct(policy), 1)?;
        let mut upstream = UnixStream::connect(broker.socket_path())?;
        upstream.set_read_timeout(Some(Duration::from_secs(120)))?;
        upstream.set_write_timeout(Some(Duration::from_secs(120)))?;
        // Quiet sessions may last indefinitely. Revocation closes the tracked
        // return socket and wakes this read, including after authentication.
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(Some(Duration::from_secs(120)))?;
        write_message(&mut stream, &Reply::Ready)?;
        write_message(&mut stream, &approved)?;
        crate::agent_broker::relay_frames(&mut stream, &mut upstream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_replies_do_not_cancel_the_ssh_session() {
        let (mut local, mut remote) = UnixStream::pair().unwrap();
        assert!(!disconnected(&local));
        remote.write_all(b"reply").unwrap();
        assert!(!disconnected(&local));
        let mut reply = [0; 5];
        local.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
        assert!(!disconnected(&local));
        remote.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(disconnected(&local));
    }

    #[test]
    fn native_ssh_uses_only_the_approved_agent_and_host_policy() {
        let options = ssh_options(
            Path::new("/tmp/private/agent"),
            Path::new("/tmp/private/hosts"),
            "ssh-ed25519",
        )
        .unwrap();
        for required in [
            "IdentityAgent=/tmp/private/agent",
            "UserKnownHostsFile=/tmp/private/hosts",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
            "PubkeyAuthentication=host-bound",
            "ControlPath=none",
        ] {
            assert!(options.iter().any(|value| value == required), "{required}");
        }
        for path in ["/tmp/a b/agent", "/tmp/%h/agent", "/tmp/${HOME}/agent"] {
            assert!(ssh_options(Path::new(path), Path::new("/tmp/hosts"), "ssh-ed25519").is_err());
        }
    }
}
