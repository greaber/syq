//! Direct server-to-server copies using already approved account connections.
//! The coordinator receives only one copy's peer control and worker admission.
use super::*;
use crate::cli::{Args, AuthFrom, CoordinateAt, Interface, Location, NativeEndpoint, PeerAuth};
use crate::conn::{Endpoint, RemoteSpec};
use crate::destination::ssh::persistent::Cached;
use std::os::fd::AsFd;
use std::process::{ChildStdout, ExitStatus};
use subtle::ConstantTimeEq;

const VERSION: u16 = 1;
const ENV: &str = "SYQ_INTERNAL_PEER_BRIDGE";
pub(crate) const GRANT: &str = "peer-control-v1";
const SETUP: Duration = Duration::from_secs(60);
const ADMISSION: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct Selection {
    coordinator: Arc<Cached>,
    peer: Arc<Cached>,
}

impl std::fmt::Debug for Selection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Selection")
            .field("coordinator", self.coordinator.endpoint())
            .field("peer", self.peer.endpoint())
            .finish()
    }
}

fn requested(location: &Location) -> NativeEndpoint {
    NativeEndpoint {
        user: location.user.clone(),
        host: location.host.clone().unwrap(),
        port: location.port,
    }
}

/// This path never creates account authority. Missing automatic selections
/// leave the ordinary native route unchanged; an explicit authorizer fails closed.
pub(crate) fn select(args: &Args) -> Result<Option<Selection>> {
    let Some((destination, sources)) = args.locations.split_last() else {
        return Ok(None);
    };
    let Some(source) = sources.first() else {
        return Ok(None);
    };
    if args.interface != Interface::NativeCp
        || args.restricted_grant.is_some()
        || args.coordinate_at == CoordinateAt::Local
        || !source.is_remote()
        || !destination.is_remote()
        || source.host.as_deref().is_some_and(|h| h.starts_with('@'))
        || destination
            .host
            .as_deref()
            .is_some_and(|h| h.starts_with('@'))
    {
        return Ok(None);
    }
    let mode = |location: &Location| {
        crate::auth_from::resolve(
            location.host.as_deref().unwrap(),
            args.auth_from_explicit.then(|| args.auth_from.clone()),
        )
    };
    let source_mode = mode(source)?;
    let destination_mode = mode(destination)?;
    let named = matches!(source_mode, AuthFrom::Return(_))
        || matches!(destination_mode, AuthFrom::Return(_));
    if args.rsh.is_some()
        || args.pscope_explicit
        || args.detach
        || args.peer_auth != PeerAuth::Restricted
        || !matches!(args.coordinate_at, CoordinateAt::Auto | CoordinateAt::Src)
        || source.same_host(destination)
        || sources.iter().any(|s| !s.same_host(source))
    {
        anyhow::ensure!(!named, "approved direct peer copies require distinct SSH endpoints, source coordination, and restricted peer authentication; --rsh, --pscope, and --detach are not supported");
        return Ok(None);
    }
    let coordinator = ssh::persistent::select_cached(&requested(source), &source_mode)?;
    let peer = ssh::persistent::select_cached(&requested(destination), &destination_mode)?;
    match (coordinator, peer) {
        (Some(coordinator), Some(peer)) => Ok(Some(Selection {
            coordinator: Arc::new(coordinator),
            peer: Arc::new(peer),
        })),
        _ if matches!(source_mode, AuthFrom::Return(_))
            || matches!(destination_mode, AuthFrom::Return(_)) =>
        {
            bail!("direct server-to-server copying needs approved account connections for both endpoints; run syq persist connect ENDPOINT --auth-from @NAME for each endpoint first")
        }
        _ => Ok(None),
    }
}

fn remote_spec(args: &Args, location: &Location, cached: &Cached) -> Result<RemoteSpec> {
    let mut options = args.clone();
    options.auth_from_explicit = false;
    options.rsh = Some(shell_words::join(
        std::iter::once("ssh".to_owned()).chain(
            cached
                .options()
                .into_iter()
                .map(|option| {
                    option
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("approved SSH option is not UTF-8"))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    ));
    let mut location = location.clone();
    location.user = cached.endpoint().user.clone();
    location.host = Some(cached.endpoint().host.clone());
    location.port = cached.endpoint().port;
    let Endpoint::Remote(spec) = crate::transfer::endpoint(&location, &options)? else {
        unreachable!()
    };
    Ok(spec)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ticket {
    version: u16,
    identity: String,
    socket: PathBuf,
    secret: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Action {
    Control,
    Ssh { public_key: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRequest {
    version: u16,
    identity: String,
    secret: String,
    action: Action,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum AdmissionReply {
    Control,
    Ssh(forward::ssh::Peer),
    Error(String),
}

impl Ticket {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == VERSION && self.identity == crate::identity::build(),
            "peer bridge helper build mismatch"
        );
        socket_path(&self.socket)?;
        anyhow::ensure!(self.secret.len() == 43, "invalid peer bridge admission");
        Ok(())
    }
    fn connect(&self, action: Action) -> Result<(UnixStream, AdmissionReply)> {
        self.validate()?;
        let mut stream = connect_socket(&self.socket, Instant::now() + ADMISSION, Some(ADMISSION))?;
        write_message(
            &mut stream,
            &AdmissionRequest {
                version: self.version,
                identity: self.identity.clone(),
                secret: self.secret.clone(),
                action,
            },
        )?;
        let reply = read_socket_message(&mut stream, SETUP + ADMISSION)?;
        if let AdmissionReply::Error(error) = reply {
            bail!("peer bridge: {error}");
        }
        Ok((stream, reply))
    }
    fn control(&self) -> Result<UnixStream> {
        let (stream, reply) = self.connect(Action::Control)?;
        anyhow::ensure!(
            matches!(reply, AdmissionReply::Control),
            "invalid peer control reply"
        );
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }
    pub(super) fn ssh(&self, public_key: &str) -> Result<forward::ssh::Peer> {
        let (_, reply) = self.connect(Action::Ssh {
            public_key: public_key.into(),
        })?;
        let AdmissionReply::Ssh(peer) = reply else {
            bail!("invalid peer SSH reply")
        };
        Ok(peer)
    }
}

fn socket_path(path: &Path) -> Result<()> {
    let text = path.to_str().context("peer socket path is not UTF-8")?;
    anyhow::ensure!(path.is_absolute() && text.len() < 100 && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)),
        "peer forwarding requires a short absolute temporary-directory path without SSH expansion characters");
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorReady {
    version: u16,
    identity: String,
    socket: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorContext {
    ticket: Ticket,
    endpoint: NativeEndpoint,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorStart {
    context: CoordinatorContext,
    command: String,
    mapping: bool,
}

pub(crate) struct Prepared {
    selection: Selection,
    pub(crate) coordinator: RemoteSpec,
    pub(crate) peer: NativeEndpoint,
    pub(crate) approved: Approved,
    pub(crate) receipt_secret: Option<crate::receipt::RecipientSecret>,
    pub(crate) receipt_policy: crate::receipt::ReceiptPolicy,
    secret: String,
    closed: Arc<AtomicBool>,
    stop_coordinator: Arc<AtomicBool>,
    broker: Option<PrivateBroker>,
    child: Arc<Mutex<Option<forward::ForwardChild>>>,
    forwarding: Mutex<Option<ScopedForward>>,
}

impl Selection {
    pub(crate) fn prepare(
        self,
        args: &Args,
        sources: &[Location],
        destination: &Location,
    ) -> Result<Prepared> {
        anyhow::ensure!(
            !args.no_tcp_encryption,
            "restricted peer copies require encrypted TCP or SSH"
        );
        let peer_policy = self.peer.peer()?;
        let coordinator = remote_spec(args, &sources[0], &self.coordinator)?;
        let peer_spec = remote_spec(args, destination, &self.peer)?;
        let (secret, recipient_public_key) = crate::receipt::generate_recipient()?;
        let policy = crate::receipt::ReceiptPolicy {
            required: true,
            hashed: args.receiver_receipt == Some(crate::cli::ReceiptDetail::Hashes),
            max_records: crate::receipt::DEFAULT_MAX_RECORDS,
            max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
            delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
                suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key,
            },
        };
        let request = crate::restricted::named_request(args, policy.clone())?;
        let (child, approved) =
            forward::peer_receiver(&peer_spec, request, Instant::now() + SETUP)?;
        let child = Arc::new(Mutex::new(Some(child)));
        let remaining = child.clone();
        let closed = Arc::new(AtomicBool::new(false));
        let stopped = closed.clone();
        let stop_coordinator = Arc::new(AtomicBool::new(false));
        let stop_owned_coordinator = stop_coordinator.clone();
        let control_started = Arc::new(AtomicBool::new(false));
        let secret_token = random_token()?;
        let admission_secret = secret_token.clone();
        let setup_ticket = approved.token.clone();
        let setup_lock = Mutex::new(());
        let broker = PrivateBroker::start_managed(
            PrivateBrokerConfig {
                directory_prefix: "syq-peer-",
                socket_name: "s",
                listener_thread: "peer-bridge",
                client_thread: "peer-control",
                max_connections: 3,
                io_timeout: ADMISSION,
            },
            move |mut stream, _| {
                let result = (|| {
                    let request: AdmissionRequest = read_message(&mut forward::DeadlineIo {
                        inner: &mut stream,
                        deadline: Instant::now() + ADMISSION,
                        cancelled: None,
                    })?;
                    anyhow::ensure!(
                        request.version == VERSION
                            && request.identity == crate::identity::build()
                            && bool::from(
                                request.secret.as_bytes().ct_eq(admission_secret.as_bytes())
                            ),
                        "invalid peer bridge admission"
                    );
                    anyhow::ensure!(!stopped.load(Ordering::Acquire), "peer copy is closed");
                    match request.action {
                        Action::Control => {
                            let mut child = remaining
                                .lock()
                                .unwrap()
                                .take()
                                .context("peer control was already opened")?;
                            control_started.store(true, Ordering::Release);
                            let input = child.child.stdin.take().unwrap();
                            let output = child.child.stdout.take().unwrap();
                            write_message(&mut stream, &AdmissionReply::Control)?;
                            let socket = stream.try_clone()?;
                            socket.set_read_timeout(None)?;
                            socket.set_write_timeout(None)?;
                            let result = forward::relay_peer(
                                socket,
                                input,
                                output,
                                || stopped.load(Ordering::Acquire),
                                &mut child,
                            );
                            stopped.store(true, Ordering::Release);
                            if !matches!(result, Ok(true)) {
                                stop_owned_coordinator.store(true, Ordering::Release);
                            }
                            result.map(|_| ())
                        }
                        Action::Ssh { public_key } => {
                            anyhow::ensure!(
                                control_started.load(Ordering::Acquire),
                                "peer control has not started"
                            );
                            anyhow::ensure!(
                                public_key.len() <= 1024,
                                "peer SSH public key is too long"
                            );
                            let _setup = setup_lock
                                .try_lock()
                                .map_err(|_| anyhow::anyhow!("peer SSH setup is already active"))?;
                            forward::ssh::setup_over_spec(
                                &peer_spec,
                                &setup_ticket,
                                &public_key,
                                &|| stopped.load(Ordering::Acquire),
                            )?;
                            write_message(&mut stream, &AdmissionReply::Ssh(peer_policy.clone()))
                        }
                    }
                })();
                if let Err(error) = result {
                    let _ =
                        write_message(&mut stream, &AdmissionReply::Error(format!("{error:#}")));
                }
            },
        )?;
        socket_path(broker.socket_path())?;
        Ok(Prepared {
            peer: self.peer.endpoint().clone(),
            selection: self,
            coordinator,
            approved,
            receipt_secret: Some(secret),
            receipt_policy: policy,
            secret: secret_token,
            closed,
            stop_coordinator,
            broker: Some(broker),
            child,
            forwarding: Mutex::new(None),
        })
    }
}

impl Prepared {
    /// Read the remote helper's startup before forwarding any capability.
    pub(crate) fn run<T: Send + 'static>(
        &self,
        command: &str,
        mapping: Option<Arc<crate::mapping::Input>>,
        receive: impl FnOnce(ChildStdout) -> Result<T> + Send + 'static,
    ) -> Result<(ExitStatus, T)> {
        let deadline = Instant::now() + SETUP;
        let mut ready_child = None;
        for install in [false, true] {
            if install {
                self.coordinator.install_helper()?;
            }
            let mut child = forward::ForwardChild::spawn_streaming_command(
                self.coordinator
                    .helper_command(&["--peer-coordinator".into()]),
            )?;
            let ready: Result<CoordinatorReady> = read_message(&mut forward::DeadlineIo {
                inner: child.child.stdout.as_mut().unwrap(),
                deadline,
                cancelled: Some(&|| self.closed.load(Ordering::Acquire)),
            });
            match ready {
                Ok(ready) => {
                    ready_child = Some((child, ready));
                    break;
                }
                Err(error) => {
                    let status =
                        child.wait_for_exit(deadline, &|| self.closed.load(Ordering::Acquire));
                    if !install
                        && self.coordinator.bootstrap_helper
                        && status
                            .as_ref()
                            .is_ok_and(|s| crate::remote_helper::needs_install(s.code()))
                    {
                        continue;
                    }
                    return Err(error).context("start approved peer coordinator");
                }
            }
        }
        let (mut child, ready) = ready_child.context("peer coordinator did not become ready")?;
        anyhow::ensure!(
            ready.version == VERSION && ready.identity == crate::identity::build(),
            "peer coordinator build mismatch"
        );
        socket_path(&ready.socket)?;
        let forwarding = ScopedForward::start(
            self.selection.coordinator.clone(),
            ready.socket.clone(),
            self.broker.as_ref().unwrap().socket_path(),
        )?;
        *self.forwarding.lock().unwrap() = Some(forwarding);
        let start = CoordinatorStart {
            context: CoordinatorContext {
                ticket: Ticket {
                    version: VERSION,
                    identity: crate::identity::build().into(),
                    socket: ready.socket,
                    secret: self.secret.clone(),
                },
                endpoint: self.peer.clone(),
            },
            command: command.into(),
            mapping: mapping.is_some(),
        };
        write_message(
            &mut forward::DeadlineIo {
                inner: child.child.stdin.as_mut().unwrap(),
                deadline,
                cancelled: None,
            },
            &start,
        )?;
        let mut input = child.child.stdin.take().unwrap();
        let upload =
            mapping.map(|mapping| std::thread::spawn(move || input.write_all(&mapping.contents)));
        let output = child.child.stdout.take().unwrap();
        let output = std::thread::spawn(move || receive(output));
        let status = child.wait_until_exit(None, &|| self.stop_coordinator.load(Ordering::Acquire));
        // Even an unexpected wait error must close stdout before joining its reader.
        drop(child);
        let result = output
            .join()
            .map_err(|_| anyhow::anyhow!("coordinator output reader panicked"))?;
        let uploaded = upload
            .map(|upload| {
                upload
                    .join()
                    .map_err(|_| anyhow::anyhow!("mapping sender panicked"))
            })
            .transpose()?;
        let status = status?;
        if status.success() {
            if let Some(uploaded) = uploaded {
                uploaded?;
            }
        }
        Ok((status, result?))
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        drop(self.broker.take());
        self.child.lock().unwrap().take();
        self.forwarding.lock().unwrap().take();
    }
}

struct ScopedForward {
    account: Arc<Cached>,
    specification: String,
}
impl ScopedForward {
    fn start(account: Arc<Cached>, remote: PathBuf, local: &Path) -> Result<Self> {
        socket_path(&remote)?;
        socket_path(local)?;
        let forwarding = Self {
            account,
            specification: format!("{}:{}", remote.display(), local.display()),
        };
        forwarding.command("forward")?;
        Ok(forwarding)
    }
    fn command(&self, operation: &str) -> Result<()> {
        let mut command = Command::new("ssh");
        // Only this explicit socket forward is enabled. All authentication,
        // agent forwarding and connection fallback prohibitions remain intact.
        command.args(self.account.options().into_iter().map(|word| {
            if word == "ClearAllForwardings=yes" {
                OsString::from("ClearAllForwardings=no")
            } else {
                word
            }
        }));
        command
            .args([
                "-o",
                "StreamLocalBindUnlink=no",
                "-o",
                "ExitOnForwardFailure=yes",
                "-O",
                operation,
                "-R",
            ])
            .arg(&self.specification)
            .arg("--")
            .arg(&self.account.endpoint().host);
        let mut child = forward::ForwardChild::spawn_command(command)?;
        let status = child.wait_for_exit(Instant::now() + Duration::from_secs(10), &|| false)?;
        anyhow::ensure!(
            status.success(),
            "approved coordinator does not allow the copy's SSH Unix-socket forwarding: {}",
            child.errors()
        );
        Ok(())
    }
}
impl Drop for ScopedForward {
    fn drop(&mut self) {
        let _ = self.command("cancel");
    }
}

/// Configure only the fixed peer capability supplied by this copy's parent.
pub(super) fn configure(args: &mut Args) -> Result<bool> {
    let Some(encoded) = std::env::var_os(ENV) else {
        return Ok(false);
    };
    if args.restricted_grant.as_deref() == Some(GRANT) && args.direct_destination.is_some() {
        return Ok(true);
    }
    anyhow::ensure!(
        args.delegated && args.restricted_grant.as_deref() == Some(GRANT),
        "peer bridge requires its delegated copy"
    );
    let encoded = encoded.to_str().context("invalid peer bridge startup")?;
    anyhow::ensure!(encoded.len() <= 16384, "peer bridge startup is too long");
    let context: CoordinatorContext =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?)?;
    context.ticket.validate()?;
    let destination = args.locations.last().context("peer destination missing")?;
    anyhow::ensure!(destination.is_remote(), "peer destination is not remote");
    anyhow::ensure!(
        requested(destination) == context.endpoint,
        "peer endpoint differs from its approved account"
    );
    let stream = context.ticket.control()?;
    let client = forward::ssh::Client::peer_bridge(context.ticket);
    let mut options = args.clone();
    options.auth_from_explicit = false;
    let Endpoint::Remote(mut spec) = crate::transfer::endpoint(destination, &options)? else {
        bail!("peer destination is not remote")
    };
    spec.forwarded = Some(ReturnConnection::peer(
        stream,
        client,
        context.endpoint.host,
    )?);
    spec.ssh_multiplexer = None;
    args.direct_destination = Some(Box::new(spec));
    Ok(true)
}

pub(super) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    (argv.len() == 2 && argv[1] == "--peer-coordinator").then(coordinator)
}
fn coordinator() -> Result<i32> {
    let directory = crate::private_broker::private_temp_dir("syq-peer-")?;
    let socket = directory.path().join("control");
    socket_path(&socket)?;
    write_message(
        &mut std::io::stdout(),
        &CoordinatorReady {
            version: VERSION,
            identity: crate::identity::build().into(),
            socket: socket.clone(),
        },
    )?;
    let mut input = fs::File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let start: CoordinatorStart = read_message(&mut forward::DeadlineIo {
        inner: &mut input,
        deadline: Instant::now() + SETUP,
        cancelled: None,
    })?;
    start.context.ticket.validate()?;
    anyhow::ensure!(
        start.context.ticket.socket == socket,
        "peer coordinator socket differs from startup"
    );
    anyhow::ensure!(
        !start.command.contains('\0') && start.command.len() <= 128 * 1024,
        "invalid peer coordinator command"
    );
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&start.context)?);
    let status = Command::new("sh")
        .args(["-c", &start.command])
        .env(ENV, encoded)
        .stdin(if start.mapping {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .status_guarded()?;
    Ok(status.code().unwrap_or(1))
}
