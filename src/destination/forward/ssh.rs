//! Lazy, per-copy SSH workers. Only an ephemeral forced-command key reaches
//! the requesting server; the laptop's credentials never do.
use super::*;
use crate::private_broker::{PrivateBroker, PrivateBrokerConfig};
use std::os::fd::AsFd;

const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    socket: PathBuf,
    secret: String,
}
impl Ticket {
    fn encode(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?))
    }
    fn decode(encoded: &str) -> Result<Self> {
        if encoded.len() > 4096 {
            bail!("copy worker admission is too long");
        }
        let ticket: Self = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?,
        )?;
        if !ticket.socket.is_absolute() || ticket.secret.len() != 43 {
            bail!("invalid copy worker admission");
        }
        Ok(ticket)
    }
    fn connect(&self) -> Result<UnixStream> {
        let mut stream = connect_socket(&self.socket, Instant::now() + TIMEOUT, Some(TIMEOUT))?;
        stream.write_all(self.secret.as_bytes())?;
        Ok(stream)
    }
}

fn authenticate(stream: &mut (impl Read + AsRawFd), expected: &str) -> Result<()> {
    use subtle::ConstantTimeEq;
    let mut secret = [0u8; 43];
    DeadlineIo {
        inner: stream,
        deadline: Instant::now() + TIMEOUT,
        cancelled: None,
    }
    .read_exact(&mut secret)?;
    anyhow::ensure!(
        bool::from(secret.as_slice().ct_eq(expected.as_bytes())),
        "invalid copy worker admission"
    );
    Ok(())
}

/// Destination state. The setup socket exists while its one-copy control
/// connection is open; SSH authorization is installed only when requested.
pub(super) struct Server {
    // Close setup clients before dropping their shared worker state.
    _broker: PrivateBroker,
    _state: Arc<Mutex<Option<Admission>>>,
    ticket: Ticket,
}
struct Admission {
    public_key: String,
    // Invalidate the socket before removing the forced authorization. A stale
    // authorized_keys line can therefore never enter a later copy.
    _workers: PrivateBroker,
    _key: crate::restricted::TemporaryKey,
}
impl Server {
    pub(super) fn start(authority: Arc<crate::restricted::RestrictedAuthority>) -> Result<Self> {
        Self::start_with(authority, crate::restricted::TemporaryKey::install)
    }
    fn start_with(
        authority: Arc<crate::restricted::RestrictedAuthority>,
        install: impl Fn(&str, &str) -> Result<crate::restricted::TemporaryKey> + Send + Sync + 'static,
    ) -> Result<Self> {
        let secret = random_token()?;
        let expected = secret.clone();
        let state: Arc<Mutex<Option<Admission>>> = Arc::new(Mutex::new(None));
        let shared = state.clone();
        let broker =
            PrivateBroker::start_managed(config("syq-copy-setup-", 1), move |mut stream, _| {
                let result = (|| {
                    authenticate(&mut stream, &expected)?;
                    let public_key: String =
                        read_socket_message(&mut stream.try_clone()?, TIMEOUT)?;
                    let public_key = canonical_key(&public_key)?;
                    anyhow::ensure!(
                        authority.control_is_open(),
                        "transfer control is closed or expired"
                    );
                    let mut current = shared.lock().unwrap();
                    if let Some(admission) = &*current {
                        anyhow::ensure!(
                            admission.public_key == public_key,
                            "copy SSH key was already selected"
                        );
                    } else {
                        *current = Some(Admission::start(authority.clone(), public_key, &install)?);
                    }
                    write_message(&mut stream, &Reply::Ready)
                })();
                if let Err(error) = result {
                    let _ = write_message(&mut stream, &Reply::Error(format!("{error:#}")));
                }
            })?;
        let ticket = Ticket {
            socket: broker.socket_path().to_path_buf(),
            secret,
        };
        Ok(Self {
            _broker: broker,
            _state: state,
            ticket,
        })
    }
    pub(super) fn ticket(&self) -> Result<String> {
        self.ticket.encode()
    }
}
fn config(prefix: &'static str, max_connections: usize) -> PrivateBrokerConfig<'static> {
    PrivateBrokerConfig {
        directory_prefix: prefix,
        socket_name: "s",
        listener_thread: "copy-ssh-listener",
        client_thread: "copy-ssh-client",
        max_connections,
        io_timeout: TIMEOUT,
    }
}
impl Admission {
    fn start(
        authority: Arc<crate::restricted::RestrictedAuthority>,
        public_key: String,
        install: &impl Fn(&str, &str) -> Result<crate::restricted::TemporaryKey>,
    ) -> Result<Self> {
        let secret = random_token()?;
        let expected = secret.clone();
        let workers =
            PrivateBroker::start_managed(config("syq-copy-worker-", 128), move |mut stream, _| {
                let result = (|| -> Result<()> {
                    authenticate(&mut stream, &expected)?;
                    let _permit = crate::server::ConnectionPermit::acquire(authority.clone())?;
                    let writer = stream.try_clone()?;
                    crate::server::run_named(stream, writer, authority.clone(), false)
                })();
                // Refused workers observe EOF; unauthenticated clients cannot fill
                // a diagnostic pipe or obtain a useful error oracle.
                let _ = result;
            })?;
        let ticket = Ticket {
            socket: workers.socket_path().to_path_buf(),
            secret,
        }
        .encode()?;
        let key = install(&public_key, &ticket)
            .context("SSH data transport needs writable destination ~/.ssh/authorized_keys")?;
        Ok(Self {
            public_key,
            _workers: workers,
            _key: key,
        })
    }
}

fn canonical_key(value: &str) -> Result<String> {
    anyhow::ensure!(value.len() <= 1024, "copy SSH public key is too long");
    let key = ssh_key::PublicKey::from_openssh(value).context("invalid copy SSH public key")?;
    anyhow::ensure!(
        key.algorithm() == ssh_key::Algorithm::Ed25519,
        "copy SSH key must use Ed25519"
    );
    ssh_key::PublicKey::new(key.key_data().clone(), "")
        .to_openssh()
        .map_err(Into::into)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRequest {
    identity: String,
    ticket: String,
    public_key: String,
}

/// Entered with the laptop's own SSH authentication, never the copy key.
pub(super) fn setup() -> Result<i32> {
    let result = (|| {
        let mut input = File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
        let request: SetupRequest = read_message(&mut DeadlineIo {
            inner: &mut input,
            deadline: Instant::now() + TIMEOUT,
            cancelled: None,
        })?;
        anyhow::ensure!(
            request.identity == crate::identity::build(),
            "copy SSH setup build mismatch"
        );
        let mut socket = Ticket::decode(&request.ticket)?.connect()?;
        write_message(&mut socket, &canonical_key(&request.public_key)?)?;
        read_socket_message::<Reply>(&mut socket, TIMEOUT)
    })();
    match result {
        Ok(reply) => write_message(&mut std::io::stdout(), &reply)?,
        Err(error) => write_message(&mut std::io::stdout(), &Reply::Error(format!("{error:#}")))?,
    }
    Ok(0)
}

pub(in crate::destination) fn setup_over_spec(
    spec: &crate::conn::RemoteSpec,
    ticket: &str,
    public_key: &str,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let request = SetupRequest {
        identity: crate::identity::build().into(),
        ticket: ticket.into(),
        public_key: canonical_key(public_key)?,
    };
    anyhow::ensure!(!cancelled(), "peer copy closed before SSH setup");
    // Setup is a short control operation on the approved account master.
    // Its separate helper channel shares that master's ordinary session limit.
    let (_child, reply) =
        ForwardChild::over_spec(spec, "--return-ssh-setup", &request, deadline, cancelled)
            .context("set up direct SSH data workers over the approved account connection")?;
    anyhow::ensure!(
        matches!(reply, Reply::Ready),
        "invalid peer SSH setup response"
    );
    anyhow::ensure!(
        !cancelled() && Instant::now() < deadline,
        "peer copy closed during SSH setup"
    );
    Ok(())
}

/// sshd ignores the caller's requested command and runs exactly this worker.
pub(super) fn worker(encoded: &str) -> Result<i32> {
    let mut socket = Ticket::decode(encoded)?.connect()?;
    socket.set_write_timeout(None)?;
    socket.set_read_timeout(None)?;
    let mut input = socket.try_clone()?;
    std::thread::spawn(move || {
        let _ = pump(&mut std::io::stdin().lock(), &mut input);
        let _ = input.shutdown(std::net::Shutdown::Write);
    });
    let mut output = File::from(std::io::stdout().as_fd().try_clone_to_owned()?);
    let result = pump(&mut socket, &mut output);
    let _ = socket.shutdown(std::net::Shutdown::Both);
    result?;
    Ok(0)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Peer {
    host: String,
    user: String,
    port: u16,
    known_hosts: String,
    algorithms: String,
}
impl Peer {
    pub(crate) fn resolved_policy(&self) -> Result<super::super::ssh_auth::ResolvedPolicy> {
        super::super::ssh_auth::ResolvedPolicy::new(
            crate::cli::NativeEndpoint {
                user: Some(self.user.clone()),
                host: self.host.clone(),
                port: Some(self.port),
            },
            &self.known_hosts,
            &self.algorithms,
        )
    }

    pub(crate) fn from_approved(
        endpoint: &crate::cli::NativeEndpoint,
        known_hosts: &str,
        algorithms: &str,
    ) -> Result<Self> {
        anyhow::ensure!(
            known_hosts.len() <= 64 * 1024,
            "approved host keys are too long"
        );
        let mut normalized = String::new();
        for line in known_hosts.lines() {
            let (alias, key) = line.split_once(' ').context("invalid approved host key")?;
            anyhow::ensure!(
                matches!(alias, "syq-approved-peer" | "syq-copy-peer"),
                "invalid approved host-key alias"
            );
            let key = ssh_key::PublicKey::from_openssh(key)?;
            normalized.push_str("syq-copy-peer ");
            normalized.push_str(&key.to_openssh()?);
            normalized.push('\n');
        }
        let peer = Self {
            host: endpoint.host.clone(),
            user: endpoint
                .user
                .clone()
                .context("approved peer has no login user")?,
            port: endpoint.port.context("approved peer has no port")?,
            known_hosts: normalized,
            algorithms: algorithms.into(),
        };
        peer.validate_endpoint(endpoint)?;
        Ok(peer)
    }

    pub(crate) fn validate_endpoint(&self, endpoint: &crate::cli::NativeEndpoint) -> Result<()> {
        super::super::validate_data_hostname(&self.host)?;
        anyhow::ensure!(
            self.host == endpoint.host
                && endpoint.user.as_deref() == Some(&self.user)
                && endpoint.port == Some(self.port)
                && self.port != 0,
            "approved SSH peer differs from account endpoint"
        );
        anyhow::ensure!(
            !self.user.is_empty()
                && self.user.len() <= 1024
                && !self.user.bytes().any(|b| b.is_ascii_control()),
            "invalid approved SSH user"
        );
        anyhow::ensure!(
            !self.algorithms.is_empty()
                && self.algorithms.len() <= 4096
                && self
                    .algorithms
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_,.@".contains(&b)),
            "invalid approved SSH algorithms"
        );
        anyhow::ensure!(
            !self.known_hosts.is_empty() && self.known_hosts.len() <= 64 * 1024,
            "invalid approved SSH host keys"
        );
        for line in self.known_hosts.lines() {
            let key = line
                .strip_prefix("syq-copy-peer ")
                .context("invalid approved host-key alias")?;
            ssh_key::PublicKey::from_openssh(key).context("invalid approved host key")?;
        }
        Ok(())
    }

    fn resolve(target: &str, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<Self> {
        let endpoint = target_endpoint(target)?;
        let policy = crate::agent_broker::resolve_host_policy_at_bounded(
            "ssh",
            endpoint.user.as_deref(),
            &endpoint.host,
            endpoint.port,
            deadline,
            cancelled,
        )?;
        Ok(Self {
            host: policy.connection_host().into(),
            user: policy.login_user.clone(),
            port: policy.port(),
            known_hosts: policy.known_hosts("syq-copy-peer")?,
            algorithms: policy.host_key_algorithms(),
        })
    }
}

pub(crate) struct Session {
    target: String,
    ticket: String,
    generation: u64,
    setup: Mutex<SetupMemo>,
}

/// An explicit remote refusal cannot improve during this copy. Transport
/// failures remain ordinary errors so a lost setup reply can be retried.
#[derive(Debug)]
pub(crate) struct SetupRefusal(pub(crate) String);
impl std::fmt::Display for SetupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SetupRefusal {}

#[derive(Default)]
pub(in crate::destination) struct SetupMemo {
    completed: Option<(String, std::result::Result<Peer, String>)>,
}
impl SetupMemo {
    pub(in crate::destination) fn resolve(
        &mut self,
        public_key: &str,
        setup: impl FnOnce() -> Result<std::result::Result<Peer, String>>,
    ) -> Result<Peer> {
        if self.completed.is_none() {
            // Transport errors may hide an already-installed key, so they
            // remain retryable with that same key. A destination's explicit
            // refusal is definitive for this copy and never repeats a login.
            self.completed = Some((public_key.into(), setup()?));
        }
        let (selected, result) = self.completed.as_ref().unwrap();
        anyhow::ensure!(selected == public_key, "copy SSH key was already selected");
        result.clone().map_err(|error| SetupRefusal(error).into())
    }
}

pub(super) struct SessionGuard<'a> {
    receiver: &'a Receiver,
    token: String,
}
impl<'a> SessionGuard<'a> {
    pub(super) fn insert(
        receiver: &'a Receiver,
        target: String,
        ticket: String,
        generation: u64,
    ) -> Result<Self> {
        let token = random_token()?;
        receiver.forward_sessions.lock().unwrap().insert(
            token.clone(),
            Arc::new(Session {
                target,
                ticket,
                generation,
                setup: Mutex::new(SetupMemo::default()),
            }),
        );
        Ok(Self { receiver, token })
    }
    pub(super) fn token(&self) -> String {
        self.token.clone()
    }
}
impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.receiver
            .forward_sessions
            .lock()
            .unwrap()
            .remove(&self.token);
    }
}
impl Receiver {
    pub(in crate::destination) fn forward_ssh(
        &self,
        token: String,
        public_key: String,
        mut stream: TrackedStream,
    ) -> Result<()> {
        let public_key = canonical_key(&public_key)?;
        let session = self
            .forward_sessions
            .lock()
            .unwrap()
            .get(&token)
            .cloned()
            .context("copy SSH authorization has closed or is unknown")?;
        let mut setup = session
            .setup
            .try_lock()
            .map_err(|_| anyhow::anyhow!("copy SSH setup is already running"))?;
        let _channel = self.active_streams.track(stream.try_clone()?)?;
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != session.generation
                || requester_closed(&socket)
                || !self.forward_sessions.lock().unwrap().contains_key(&token)
        };
        anyhow::ensure!(!cancelled(), "copy SSH authorization has closed");
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let peer = setup.resolve(&public_key, || {
            let peer = Peer::resolve(&session.target, deadline, &cancelled)?;
            let encoded =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session.target.as_bytes());
            let mut command = Command::new(std::env::current_exe()?);
            command.args(["--return-ssh-connect", &encoded]);
            let mut child = ForwardChild::spawn_command(command)?;
            let result = (|| {
                write_message(
                    &mut DeadlineIo {
                        inner: child.child.stdin.as_mut().unwrap(),
                        deadline,
                        cancelled: Some(&cancelled),
                    },
                    &SetupRequest {
                        identity: crate::identity::build().into(),
                        ticket: session.ticket.clone(),
                        public_key: public_key.clone(),
                    },
                )?;
                let reply: Reply = read_message(&mut DeadlineIo {
                    inner: child.child.stdout.as_mut().unwrap(),
                    deadline,
                    cancelled: Some(&cancelled),
                })?;
                match reply {
                    Reply::Ready => Ok(Ok(peer)),
                    Reply::Error(error) => Ok(Err(format!(
                        "destination refused SSH data transport: {error}"
                    ))),
                    _ => bail!("invalid copy SSH setup response"),
                }
            })();
            result.with_context(|| format!("copy SSH setup failed: {}", child.errors()))
        })?;
        anyhow::ensure!(!cancelled(), "copy SSH authorization has closed");
        write_message(&mut stream, &Reply::ForwardSsh(peer))
    }
}

/// Requester state. Debug deliberately excludes registration credentials,
/// private-key paths, and all contents of the key.
pub(crate) struct Client {
    setup: Setup,
    state: Mutex<Option<Ready>>,
}
enum Setup {
    Return {
        registration: Registration,
        token: String,
    },
    PeerBridge(super::super::peer_bridge::Ticket),
}
struct Ready {
    directory: tempfile::TempDir,
    public_key: String,
    peer: Option<Peer>,
}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopySshWorkers").finish_non_exhaustive()
    }
}
impl Client {
    pub(in crate::destination) fn new(registration: Registration, token: String) -> Self {
        Self {
            setup: Setup::Return {
                registration,
                token,
            },
            state: Mutex::new(None),
        }
    }
    pub(in crate::destination) fn peer_bridge(ticket: super::super::peer_bridge::Ticket) -> Self {
        Self {
            setup: Setup::PeerBridge(ticket),
            state: Mutex::new(None),
        }
    }
    pub(crate) fn command(&self) -> Result<Command> {
        self.command_with(|public_key| {
            let Setup::Return {
                registration,
                token,
            } = &self.setup
            else {
                let Setup::PeerBridge(ticket) = &self.setup else {
                    unreachable!()
                };
                return ticket.ssh(public_key);
            };
            let (_, reply) = exchange(
                registration,
                Message::ForwardSsh {
                    token: token.clone(),
                    public_key: public_key.to_owned(),
                },
                SETUP_TIMEOUT + Duration::from_secs(10),
                None,
            )?;
            let Reply::ForwardSsh(peer) = reply else {
                bail!("unexpected copy SSH authorization response");
            };
            Ok(peer)
        })
    }
    fn command_with(&self, setup: impl FnOnce(&str) -> Result<Peer>) -> Result<Command> {
        let mut state = self.state.lock().unwrap();
        if state.is_none() {
            let directory = crate::private_broker::private_temp_dir("syq-copy-key-")?;
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)?;
            let pair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
            seed.fill(0);
            let key = ssh_key::PrivateKey::new(pair.into(), "syq-copy")?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.path().join("key"))?;
            file.write_all(key.to_openssh(ssh_key::LineEnding::LF)?.as_bytes())?;
            // Keep the same key when a setup reply is lost after the destination
            // installed it. The live destination only accepts idempotent retries.
            *state = Some(Ready {
                directory,
                public_key: key.public_key().to_openssh()?,
                peer: None,
            });
        }
        let ready = state.as_mut().unwrap();
        if ready.peer.is_none() {
            let peer = setup(&ready.public_key)?;
            fs::write(
                ready.directory.path().join("known_hosts"),
                &peer.known_hosts,
            )?;
            ready.peer = Some(peer);
        }
        let peer = ready.peer.as_ref().unwrap();
        let mut command = Command::new("ssh");
        command.args(["-F", "/dev/null", "-a", "-x", "-k", "-T"]);
        for option in [
            "IdentityAgent=none",
            "IdentitiesOnly=yes",
            "CertificateFile=none",
            "PKCS11Provider=none",
            "PreferredAuthentications=publickey",
            "BatchMode=yes",
            "ControlMaster=no",
            "ControlPath=none",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "ProxyJump=none",
            "ProxyCommand=none",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
            "UpdateHostKeys=no",
            "HostKeyAlias=syq-copy-peer",
            "ConnectTimeout=10",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=3",
        ] {
            command.args(["-o", option]);
        }
        command.arg("-o").arg(format!(
            "UserKnownHostsFile={}",
            ready.directory.path().join("known_hosts").display()
        ));
        command
            .arg("-o")
            .arg(format!("HostKeyAlgorithms={}", peer.algorithms));
        command.arg("-i").arg(ready.directory.path().join("key"));
        command
            .arg("-l")
            .arg(&peer.user)
            .arg("-p")
            .arg(peer.port.to_string());
        command.arg("--").arg(&peer.host).arg("syq-copy-worker");
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ConnectionRole, FrameReader, FrameWriter, Request, Response};

    fn public_key(seed: u8) -> String {
        ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]).into(),
            "test",
        )
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
    }
    fn setup_key(ticket: &Ticket, public: &str) -> Reply {
        let mut socket = ticket.connect().unwrap();
        write_message(&mut socket, &public).unwrap();
        read_socket_message(&mut socket, TIMEOUT).unwrap()
    }
    fn worker_connection(
        ticket: &Ticket,
        role: ConnectionRole,
    ) -> Result<(FrameReader<UnixStream>, FrameWriter<UnixStream>)> {
        let socket = ticket.connect()?;
        let mut writer = FrameWriter::new(socket.try_clone()?, false);
        writer.write_msg(&Request::Hello {
            identity: crate::identity::build().into(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role,
        })?;
        let mut reader = FrameReader::new(socket);
        anyhow::ensure!(
            matches!(reader.read_msg::<Response>()?, Response::HelloOk { .. }),
            "worker rejected"
        );
        Ok((reader, writer))
    }
    fn role() -> ConnectionRole {
        ConnectionRole::DestinationWorker {
            destination: None,
            copy_sources: Vec::new(),
        }
    }

    #[test]
    fn lazy_ssh_key_is_scoped_to_one_copy_and_removed_at_close() {
        let root = crate::test_support::tempdir().unwrap();
        let home = root.path().join("home");
        fs::create_dir(&home).unwrap();
        let args = crate::destination::tests::args(&root.path().join("source"), "output");
        let (mut request, _) = crate::destination::tests::request(&args);
        request.copy.options.compressed_transport = false;
        let request = constrain(request, &root.path().join("output"), 1024, 100, 0).unwrap();
        let (authority, _) = crate::restricted::named_authority(root.path(), request).unwrap();
        let install_home = home.clone();
        let server = Server::start_with(authority.clone(), move |key, ticket| {
            crate::restricted::TemporaryKey::install_at(
                &install_home,
                Path::new("/usr/bin/syq"),
                key,
                ticket,
            )
        })
        .unwrap();
        assert!(
            !home.join(".ssh").exists(),
            "TCP setup must not write authorized_keys"
        );
        let setup = Ticket::decode(&server.ticket().unwrap()).unwrap();
        let mut wrong = setup.clone();
        wrong.secret = "x".repeat(43);
        assert!(matches!(setup_key(&wrong, &public_key(1)), Reply::Error(_)));
        assert!(!home.join(".ssh").exists());
        assert!(matches!(setup_key(&setup, &public_key(1)), Reply::Ready));
        let keys = home.join(".ssh/authorized_keys");
        let original = fs::read_to_string(&keys).unwrap();
        assert!(matches!(setup_key(&setup, &public_key(1)), Reply::Ready));
        assert!(matches!(setup_key(&setup, &public_key(2)), Reply::Error(_)));
        assert_eq!(fs::read_to_string(&keys).unwrap(), original);
        let encoded = original
            .split("--return-ssh-worker ")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let worker = Ticket::decode(encoded).unwrap();
        assert!(worker_connection(&worker, ConnectionRole::Control).is_err());
        assert!(worker_connection(
            &worker,
            ConnectionRole::SourceWorker {
                roots: Vec::new(),
                send_budget: None
            }
        )
        .is_err());
        let (mut reader, mut writer) = worker_connection(&worker, role()).unwrap();
        writer
            .write_msg(&Request::StatMany {
                paths: vec![root.path().join("outside").as_os_str().as_bytes().to_vec()],
                sources: None,
                follow: false,
                guard: None,
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(_)
        ));
        writer.write_msg(&Request::Receipt).unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(_)
        ));
        authority.close_control();
        assert!(worker_connection(&worker, role()).is_err());
        assert!(matches!(setup_key(&setup, &public_key(1)), Reply::Error(_)));
        drop(server);
        assert!(!worker.socket.exists());
        assert!(!setup.socket.exists());
        assert_eq!(fs::read(&keys).unwrap(), b"");
        assert!(
            worker_connection(&worker, role()).is_err(),
            "stolen key/ticket must not survive copy closure"
        );
        assert!(reader.read_msg::<Response>().is_err());
    }

    #[test]
    fn requester_keeps_same_copy_key_after_a_lost_setup_reply() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, _receiver, registration, _) =
            crate::destination::tests::broker(root.path(), Approval::Always);
        let client = Client::new(registration, "copy".into());
        let mut first = String::new();
        assert!(client
            .command_with(|key| {
                first = key.into();
                bail!("reply lost after installing key")
            })
            .is_err());
        client
            .command_with(|key| {
                assert_eq!(key, first);
                Ok(Peer {
                    host: "backup".into(),
                    user: "copy".into(),
                    port: 22,
                    known_hosts: "pinned host key".into(),
                    algorithms: "ssh-ed25519".into(),
                })
            })
            .unwrap();
        let command = client
            .command_with(|_| panic!("ready copy must reuse setup"))
            .unwrap();
        assert!(!command
            .get_args()
            .any(|arg| arg.to_string_lossy().starts_with("RequiredRSASize=")));
    }

    #[test]
    fn setup_memo_caches_refusal_but_retries_lost_replies() {
        let mut memo = SetupMemo::default();
        assert!(memo.resolve("key", || bail!("reply lost")).is_err());
        assert!(memo.completed.is_none());
        let error = memo
            .resolve("key", || Ok(Err("destination home is unwritable".into())))
            .unwrap_err();
        assert!(error.to_string().contains("unwritable"));
        let error = memo
            .resolve("key", || panic!("definitive refusal repeated SSH setup"))
            .unwrap_err();
        assert!(error.to_string().contains("unwritable"));
    }

    #[test]
    fn setup_memo_reuses_ready_peer_only_for_selected_key() {
        let mut memo = SetupMemo::default();
        memo.resolve("key", || {
            Ok(Ok(Peer {
                host: "backup".into(),
                user: "copy".into(),
                port: 22,
                known_hosts: "pinned".into(),
                algorithms: "ssh-ed25519".into(),
            }))
        })
        .unwrap();
        assert_eq!(
            memo.resolve("key", || panic!("ready setup repeated login"))
                .unwrap()
                .host,
            "backup"
        );
        assert!(memo
            .resolve("different", || panic!("different key started setup"))
            .is_err());
    }

    #[test]
    fn closed_return_copy_cannot_start_ssh_setup() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) =
            crate::destination::tests::broker(root.path(), Approval::Always);
        let guard = SessionGuard::insert(&receiver, "backup".into(), "unused".into(), 0).unwrap();
        let token = guard.token();
        drop(guard);
        let error = exchange(
            &registration,
            Message::ForwardSsh {
                token,
                public_key: public_key(1),
            },
            TIMEOUT,
            Some(TIMEOUT),
        )
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains("closed or is unknown"));
    }
}
