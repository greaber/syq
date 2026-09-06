//! Named, permission-checked return channels over laptop-initiated SSH.
//!
//! This protocol uses transient advertisements maintained by persistence,
//! independent of durable receiver enrollments. The remote account is the requester identity: shells
//! and jobs under that account intentionally share access to its registrations.
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant};

use crate::delegation::{CopyOperation, DestinationPlacement, GrantConstraints};
use crate::private_broker::{PrivateBroker, PrivateBrokerConfig, TrackedStream};

mod forward;

const VERSION: u16 = 2;
const MAX_MESSAGE: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const START_TIMEOUT: Duration = Duration::from_secs(60);
const PREFIX: &str = "named-v2:";
const REQUEST_ROOT: &[u8] = b"/SYQ-RECEIVE";
const RECONNECT_PENDING: i32 = 75;

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
enum Approval {
    Ask,
    Always,
}

#[derive(Parser)]
#[command(
    name = "syq destination",
    about = "Inspect named destinations available to this server account"
)]
struct Destinations {
    #[command(subcommand)]
    action: DestinationAction,
}
#[derive(Subcommand)]
enum DestinationAction {
    /// Print registrations and whether their receiving laptop responds
    List,
    /// Remove an offline destination name so another laptop can register it
    Forget { name: String },
    /// Wait for a destination to respond; exit nonzero after the deadline
    Wait {
        name: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
}

pub(crate) fn destination_help() -> clap::Command {
    crate::help::configure(Destinations::command())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CopyRequest {
    pub destination: Vec<u8>,
    pub copy: CopyOperation,
    pub constraints: GrantConstraints,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approved {
    pub token: String,
    pub destination: Vec<u8>,
    pub enrollment: crate::enrollment::EnrollmentId,
    pub request: crate::delegation::RequestId,
    pub digest: [u8; 32],
    pub receipt_key: String,
}

#[derive(Debug)]
pub(crate) struct NamedReceipt {
    control: Mutex<Option<UnixStream>>,
    secret: crate::receipt::RecipientSecret,
    approved: Approved,
    policy: crate::receipt::ReceiptPolicy,
}

impl NamedReceipt {
    pub(crate) fn take_control(&self) -> Result<UnixStream> {
        self.control
            .lock()
            .unwrap()
            .take()
            .context("approved return control connection was already consumed")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u16,
    identity: String,
    secret: String,
    message: Message,
}
#[derive(Serialize, Deserialize)]
enum Message {
    Ping,
    Request(Box<CopyRequest>),
    Forward {
        target: String,
        request: Box<CopyRequest>,
    },
    Open {
        token: String,
        control: bool,
    },
}
#[derive(Serialize, Deserialize)]
enum Reply {
    Ready,
    Approved(Approved),
    Error(String),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    version: u16,
    identity: String,
    socket: PathBuf,
    secret: String,
}
#[derive(Serialize, Deserialize)]
struct Route {
    registration: Registration,
    token: String,
}

pub(crate) fn write_message(writer: &mut impl Write, message: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_MESSAGE {
        bail!("named destination message exceeds size limit");
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}
pub(crate) fn read_message<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        bail!("invalid named destination message size");
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
/// A complete incoming envelope has an absolute deadline, including clients
/// trickling bytes. Timeout budgets cannot be renewed by partial progress.
pub(crate) fn read_socket_message<T: DeserializeOwned>(
    socket: &mut UnixStream,
    timeout: Duration,
) -> Result<T> {
    struct DeadlineReader<'a> {
        socket: &'a mut UnixStream,
        deadline: Instant,
    }
    impl Read for DeadlineReader<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|time| !time.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "return channel handshake timed out",
                    )
                })?;
            self.socket.set_read_timeout(Some(remaining))?;
            self.socket.read(bytes)
        }
    }
    let previous = socket.read_timeout()?;
    let result = read_message(&mut DeadlineReader {
        socket,
        deadline: Instant::now() + timeout,
    });
    socket.set_read_timeout(previous)?;
    result
}

fn random_token() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}
pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("destination name must contain 1–64 letters, digits, hyphens, or underscores");
    }
    Ok(())
}

fn registry() -> Result<PathBuf> {
    private_directory(".syq-destinations-v2")
}
fn private_directory(name: &str) -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?);
    let path = home.join(name);
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        bail!("destination registry must be an owned directory with mode 0700");
    }
    Ok(path)
}
/// Completion only lists local names; it never creates state or asks a laptop
/// for file listings without a transfer approval.
pub(crate) fn registered_names() -> Vec<String> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let directory = PathBuf::from(home).join(".syq-destinations-v2");
    let Ok(metadata) = fs::symlink_metadata(&directory) else {
        return Vec::new();
    };
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .filter_map(|entry| {
            let name = entry
                .ok()?
                .file_name()
                .to_str()?
                .strip_suffix(".json")?
                .to_owned();
            validate_name(&name).ok()?;
            Some(name)
        })
        .collect();
    names.sort();
    names
}

fn load_registration(name: &str) -> Result<Registration> {
    validate_name(name)?;
    let path = registry()?.join(format!("{name}.json"));
    let encoded = crate::delegation::read_private_regular(&path, "named destination", MAX_MESSAGE)
        .with_context(|| {
            format!("destination @{name} is unavailable; connect from the laptop with syq while persist is on")
        })?;
    let registration: Registration = serde_json::from_slice(&encoded)?;
    if registration.version != VERSION || registration.identity != crate::identity::build() {
        bail!("named destination build differs; use matching syq builds and restart receiving");
    }
    Ok(registration)
}
fn exchange(
    registration: &Registration,
    message: Message,
    timeout: Duration,
) -> Result<(UnixStream, Reply)> {
    let mut stream = UnixStream::connect(&registration.socket)
        .context("receiving laptop is offline; it must reconnect before this transfer can start")?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_message(
        &mut stream,
        &Envelope {
            version: VERSION,
            identity: crate::identity::build().into(),
            secret: registration.secret.clone(),
            message,
        },
    )?;
    let reply = read_message(&mut stream)?;
    if let Reply::Error(error) = &reply {
        bail!("receiving laptop: {error}");
    }
    Ok((stream, reply))
}

/// All requester paths use a synthetic root until the laptop chooses its real
/// directory. Reject traversal rather than normalizing authority to a sibling.
pub(crate) fn request_path(path: &[u8]) -> Result<Vec<u8>> {
    if path.len() > 4096
        || path.starts_with(b"/")
        || path.contains(&0)
        || path.split(|b| *b == b'/').any(|p| p == b"..")
    {
        bail!("named destination paths must be relative and cannot contain '..'");
    }
    let mut result = REQUEST_ROOT.to_vec();
    for component in path
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty() && *p != b".")
    {
        result.push(b'/');
        result.extend_from_slice(component);
    }
    Ok(result)
}
fn rebase(path: &[u8], root: &Path) -> Result<Vec<u8>> {
    let relative = if path == REQUEST_ROOT {
        &b""[..]
    } else {
        path.strip_prefix(REQUEST_ROOT)
            .and_then(|p| p.strip_prefix(b"/"))
            .context("copy scope outside named destination")?
    };
    if request_path(relative)? != path {
        bail!("noncanonical named destination scope");
    }
    let mut result = root.as_os_str().as_bytes().to_vec();
    if !relative.is_empty() {
        result.push(b'/');
        result.extend_from_slice(relative);
    }
    Ok(result)
}

/// Resolve the operator's starting directory separately from containment. The
/// final entry is not followed: replacing a symlink replaces the entry itself.
fn resolve_destination(cwd: &Path, root: Option<&Path>, path: &[u8]) -> Result<(PathBuf, PathBuf)> {
    if path.len() > 4096 || path.contains(&0) {
        bail!("invalid receiving destination path");
    }
    if let Some(root) = root {
        let destination = PathBuf::from(OsString::from_vec(rebase(&request_path(path)?, cwd)?));
        let container = root
            .parent()
            .context("receiving root must not be filesystem root")?
            .to_path_buf();
        return Ok((destination, container));
    }
    let path = cwd.join(OsString::from_vec(path.to_vec()));
    let components: Vec<_> = path.components().collect();
    let mut destination = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        use std::path::Component;
        match component {
            Component::RootDir => destination.push("/"),
            Component::CurDir => {}
            Component::ParentDir => {
                destination.pop();
            }
            Component::Normal(name) => {
                destination.push(name);
                if index + 1 < components.len() {
                    match fs::canonicalize(&destination) {
                        Ok(path) => {
                            if !path.is_dir() {
                                bail!("receiving path ancestor is not a directory");
                            }
                            destination = path;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Component::Prefix(_) => unreachable!("Unix path"),
        }
    }
    let mut container = destination
        .parent()
        .context("cannot replace filesystem root")?
        .to_path_buf();
    loop {
        match fs::canonicalize(&container) {
            Ok(path) => {
                container = path;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !container.pop() {
                    return Err(e.into());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok((destination, container))
}

fn constrain(
    mut request: CopyRequest,
    destination: &Path,
    max_bytes: u64,
    max_entries: u64,
    max_delete: u64,
) -> Result<CopyRequest> {
    if request.copy.mutation_scopes.len() > 1024 {
        bail!("too many copy scopes");
    }
    request.copy.destination = rebase(&request.copy.destination, destination)?;
    for scope in &mut request.copy.mutation_scopes {
        scope.path = rebase(&scope.path, destination)?;
    }
    for filter_root in &mut request.constraints.filters.destination_roots {
        *filter_root = rebase(filter_root, destination)?;
    }
    if request.copy.options.preserve_owner
        || request.copy.options.preserve_group
        || request.copy.options.preserve_devices
        || request.copy.policy.publication == crate::delegation::PublicationPolicy::InPlace
    {
        bail!(
            "named destinations do not accept ownership, special-file preservation, or --inplace"
        );
    }
    if request.copy.limits.max_deletions > max_delete {
        bail!("requested deletion limit exceeds laptop --max-delete={max_delete}");
    }
    request.copy.limits.max_total_bytes = request.copy.limits.max_total_bytes.min(max_bytes);
    request.copy.limits.max_file_bytes = request.copy.limits.max_file_bytes.min(max_bytes);
    request.copy.limits.max_entries = request.copy.limits.max_entries.min(max_entries);
    request.copy.limits.max_connections = request.copy.limits.max_connections.min(32);
    Ok(request)
}

pub(crate) fn is_named(grant: &Option<String>) -> bool {
    grant.as_deref().is_some_and(|s| s.starts_with(PREFIX))
}

pub(crate) fn prepare(args: &mut crate::cli::Args) -> Result<()> {
    if args.via.is_some() {
        return forward::prepare(args);
    }
    let Some(destination) = args.locations.last() else {
        return Ok(());
    };
    let Some(host) = destination.host.as_deref() else {
        return Ok(());
    };
    let explicit = host.starts_with('@');
    let name = host.strip_prefix('@').unwrap_or(host).to_owned();
    // A normal SSH endpoint with a user/port remains explicit SSH. Bare names
    // opt into lookup only when this process can actually send a return copy.
    let registration = if explicit {
        load_registration(&name)?
    } else {
        if destination.user.is_some()
            || destination.port.is_some()
            || args.interface != crate::cli::Interface::NativeCp
            || args.locations[..args.locations.len() - 1]
                .iter()
                .any(|l| l.is_remote())
            || !registered_names().contains(&name)
        {
            return Ok(());
        }
        let registration = load_registration(&name)?;
        if exchange(&registration, Message::Ping, Duration::from_secs(2)).is_err() {
            return Ok(());
        }
        registration
    };
    if args.interface != crate::cli::Interface::NativeCp
        || args.locations[..args.locations.len() - 1]
            .iter()
            .any(|l| l.is_remote())
    {
        bail!("named destinations require syq cp with local sources");
    }
    if args.syq_path.is_some()
        || args.rsh.is_some()
        || args.pscope_explicit
        || args.detach
        || args.restricted_grant.is_some()
        || args.tcp_plain
        || args.peer_auth != crate::cli::PeerAuth::Restricted
    {
        bail!("named destinations own their connection; --syq-path, --rsh, --pscope, --detach, --peer-auth, and --tcp-plain cannot be combined with them");
    }
    if args.connections_opt.is_some() && args.connections > 32 {
        bail!("named destinations support at most 32 workers per transfer");
    }
    let (secret, public) = crate::receipt::generate_recipient()?;
    let policy = crate::receipt::ReceiptPolicy {
        required: true,
        hashed: args.receiver_receipt == Some(crate::cli::ReceiptDetail::Digests),
        max_records: crate::receipt::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
            suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key: public,
        },
    };
    let request = crate::restricted::named_request(args, policy.clone())?;
    crate::output::diagnostic!("syq: requesting permission from @{name} (up to 300 seconds; approve on the receiving machine with its desktop prompt or syq recv pending)");
    let (_, reply) = exchange(
        &registration,
        Message::Request(Box::new(request)),
        REQUEST_TIMEOUT + Duration::from_secs(10),
    )?;
    let Reply::Approved(approved) = reply else {
        bail!("unexpected named destination response");
    };
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.locations.last_mut().unwrap().host = Some(format!("@{name}"));
    args.restricted_grant = Some(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Route {
            registration,
            token: approved.token.clone()
        })?)
    ));
    args.named_receipt = Some(Arc::new(NamedReceipt {
        control: Mutex::new(None),
        secret,
        approved,
        policy,
    }));
    args.no_tcp = true;
    Ok(())
}

pub(crate) fn connect(grant: &str, control: bool) -> Result<UnixStream> {
    let encoded = grant
        .strip_prefix(PREFIX)
        .context("invalid named destination route")?;
    if encoded.len() > MAX_MESSAGE {
        bail!("named route too large");
    }
    let route: Route =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?)?;
    let (stream, reply) = exchange(
        &route.registration,
        Message::Open {
            token: route.token,
            control,
        },
        START_TIMEOUT,
    )?;
    if !matches!(reply, Reply::Ready) {
        bail!("named transfer channel was not opened");
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

pub(crate) fn finish_receipt(
    expected: &NamedReceipt,
    conn: &mut dyn crate::conn::Conn,
) -> Result<()> {
    use crate::proto::{Request, Response};
    conn.send(Request::Receipt)?;
    // The verifier streams bounded frames through an anonymous spool; it never
    // buffers a complete receipt or trusts the sender's success report.
    let mut ended = false;
    let frames = std::iter::from_fn(|| {
        if ended {
            return None;
        }
        let result = match conn.recv() {
            Ok(Response::Receipt(frame)) => match crate::receipt::receipt_frame_is_end(&frame) {
                Ok(last) => {
                    ended = last;
                    Ok(frame)
                }
                Err(e) => Err(e),
            },
            Ok(Response::Err(error)) => Err(anyhow::anyhow!(error)),
            Ok(_) => Err(anyhow::anyhow!("unexpected receipt response")),
            Err(e) => Err(e),
        };
        if result.is_err() {
            ended = true;
        }
        Some(result)
    });
    let receipt = crate::receipt::open_attached_frames(
        frames,
        &expected.secret,
        &expected.approved.receipt_key,
        expected.approved.enrollment,
        expected.approved.request,
        expected.approved.digest,
        &expected.policy,
    )?;
    if receipt.terminal.status != crate::receipt::ReceiptStatus::Clean {
        bail!("receiving laptop reports {:?}", receipt.terminal.status);
    }
    Ok(())
}

struct Session {
    authority: Arc<crate::restricted::RestrictedAuthority>,
    issued: Instant,
    opened: bool,
    channels: Arc<crate::private_broker::ConnectionRegistry>,
}
#[cfg(test)]
struct Prompt {
    description: String,
    decision: mpsc::SyncSender<bool>,
}
struct Receiver {
    requester: String,
    approval_mode: crate::receive_approval::Mode,
    notifications: crate::receive_approval::Notifications,
    approvals: Arc<crate::receive_approval::Queue>,
    generation: AtomicU64,
    cwd: PathBuf,
    root: Option<PathBuf>,
    secret: String,
    max_bytes: u64,
    max_entries: u64,
    max_delete: u64,
    #[cfg(test)]
    approval: Approval,
    #[cfg(test)]
    prompts: mpsc::SyncSender<Prompt>,
    sessions: Mutex<HashMap<String, Session>>,
    forwarded: Arc<crate::private_broker::ConnectionRegistry>,
    forward_count: std::sync::atomic::AtomicUsize,
    request_lock: Mutex<()>,
    stop: Arc<AtomicBool>,
}

impl Receiver {
    /// Decide locally after scope validation and before issuing a usable token.
    fn authorize_request(
        &self,
        request: &CopyRequest,
        socket: &UnixStream,
        generation: u64,
    ) -> Result<()> {
        #[cfg(test)]
        if matches!(self.approval, Approval::Ask) {
            let (decision, reply) = mpsc::sync_channel(1);
            self.prompts.try_send(Prompt {
                description: "Source contents have not been inspected".into(),
                decision,
            })?;
            if !reply.recv_timeout(Duration::from_secs(5))? {
                bail!("transfer denied");
            }
        }
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
                || requester_closed(socket)
        };
        if cancelled() {
            bail!("receiving stopped or request disconnected");
        }
        if self.approval_mode == crate::receive_approval::Mode::Ask {
            self.approvals
                .request(&self.requester, request, self.notifications, cancelled)?;
        }
        Ok(())
    }
    fn revoke_all(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.forwarded.shutdown_all();
        for (_, session) in sessions.drain() {
            session.authority.close_control();
            session.channels.shutdown_all();
        }
    }

    fn handle(&self, mut stream: TrackedStream) -> Result<()> {
        let envelope: Envelope =
            read_socket_message(&mut stream.try_clone()?, Duration::from_secs(10))?;
        if envelope.version != VERSION || envelope.identity != crate::identity::build() {
            bail!("named destination build mismatch; restart with matching syq builds");
        }
        if envelope.secret != self.secret {
            bail!("named destination authentication failed");
        }
        match envelope.message {
            Message::Ping => write_message(&mut stream, &Reply::Ready),
            Message::Forward { target, request } => self.forward(target, *request, stream),
            Message::Request(request) => {
                let _request = self.request_lock.try_lock().map_err(|_| {
                    anyhow::anyhow!(
                        "another transfer is awaiting approval; retry after it is decided"
                    )
                })?;
                let (destination, container) =
                    resolve_destination(&self.cwd, self.root.as_deref(), &request.destination)?;
                if self.root.as_ref() == Some(&destination)
                    && request.copy.policy.placement == DestinationPlacement::ExactPath
                {
                    bail!("cannot replace the receiving root itself; use --into . or a child path");
                }
                let request = constrain(
                    *request,
                    &destination,
                    self.max_bytes,
                    self.max_entries,
                    self.max_delete,
                )?;
                {
                    let mut sessions = self.sessions.lock().unwrap();
                    sessions.retain(|_, s| s.opened || s.issued.elapsed() < START_TIMEOUT);
                    if sessions.len() >= 8 {
                        bail!("too many active transfers; wait for one to finish");
                    }
                }
                let generation = self.generation.load(Ordering::Acquire);
                // Validate the complete operation before the local policy decision.
                let (authority, approved) =
                    crate::restricted::named_authority(&container, request.clone())?;
                self.authorize_request(&request, &stream.try_clone()?, generation)?;
                // Start the grant clock at approval, including after a long prompt.
                let (authority, mut approved) =
                    if self.approval_mode == crate::receive_approval::Mode::Ask {
                        crate::restricted::named_authority(&container, request)?
                    } else {
                        (authority, approved)
                    };
                let mut sessions = self.sessions.lock().unwrap();
                if self.stop.load(Ordering::Acquire)
                    || self.generation.load(Ordering::Acquire) != generation
                    || requester_closed(&stream.try_clone()?)
                {
                    bail!("copy disconnected before approval could be used");
                }
                approved.token = random_token()?;
                sessions.insert(
                    approved.token.clone(),
                    Session {
                        authority,
                        issued: Instant::now(),
                        opened: false,
                        channels: Arc::new(crate::private_broker::ConnectionRegistry::new(
                            Duration::from_secs(10),
                        )),
                    },
                );
                drop(sessions);
                write_message(&mut stream, &Reply::Approved(approved))
            }
            Message::Open { token, control } => {
                let (authority, channels, _permit, _channel) = {
                    let mut sessions = self.sessions.lock().unwrap();
                    let session = sessions
                        .get_mut(&token)
                        .context("transfer authorization expired or is unknown")?;
                    if control {
                        if session.opened || session.issued.elapsed() >= START_TIMEOUT {
                            bail!("transfer authorization has already been used or expired");
                        }
                    } else if !session.opened {
                        bail!("transfer control channel has not opened");
                    }
                    let permit = if control {
                        None
                    } else {
                        Some(crate::server::ConnectionPermit::acquire(Arc::clone(
                            &session.authority,
                        ))?)
                    };
                    let channel = session.channels.track(stream.try_clone()?)?;
                    if control {
                        session.opened = true;
                    }
                    (
                        Arc::clone(&session.authority),
                        Arc::clone(&session.channels),
                        permit,
                        channel,
                    )
                };
                let result = (|| {
                    write_message(&mut stream, &Reply::Ready)?;
                    let writer = stream.try_clone()?;
                    // Keep the bounded Hello deadline until the server has
                    // validated its complete handshake. Pending workers already
                    // consume their per-transfer connection allowance.
                    crate::server::run_named(stream, writer, Arc::clone(&authority), control)
                })();
                if control {
                    // Opening consumes the token even if the reply fails. Do
                    // not leave an opened session occupying a slot forever.
                    authority.close_control();
                    channels.shutdown_all();
                    self.sessions.lock().unwrap().remove(&token);
                }
                result
            }
        }
    }
}

fn requester_closed(socket: &UnixStream) -> bool {
    let mut byte = 0u8;
    let result = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            (&mut byte as *mut u8).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    // No more bytes are valid on a completed copy request. Treat trailing
    // data as cancellation too, so it cannot hide a subsequent EOF.
    result >= 0
        || !matches!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        )
}

struct OwnedSsh(Child);
impl Drop for OwnedSsh {
    fn drop(&mut self) {
        // The child is always started in a new process group. Kill the entire
        // group, including ProxyCommand helpers, and reap its leader.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}
fn ssh_command(endpoint: &crate::persistence::EndpointRecord) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-a",
        "-x",
        "-T",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ]);
    if let Some(user) = &endpoint.user {
        cmd.arg("-l").arg(user);
    }
    if let Some(port) = endpoint.port {
        cmd.arg("-p").arg(port.to_string());
    }
    cmd
}
pub(crate) fn serve_background(
    config: crate::receive_service::Settings,
    spec: crate::receive_service::ServiceSpec,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<crate::receive_service::ConnectionState>>,
    approvals: Arc<crate::receive_approval::Queue>,
) -> Result<()> {
    #[cfg(test)]
    let (prompts, _requests) = mpsc::sync_channel(1);
    let receiver = Arc::new(Receiver {
        requester: spec.endpoint.label(),
        approval_mode: config.approval,
        notifications: config.notifications,
        approvals,
        generation: AtomicU64::new(0),
        cwd: config.cwd.clone(),
        root: config.root.clone(),
        secret: random_token()?,
        max_bytes: config.max_bytes,
        max_entries: config.max_entries,
        max_delete: config.max_delete,
        #[cfg(test)]
        approval: Approval::Always,
        #[cfg(test)]
        prompts,
        sessions: Mutex::new(HashMap::new()),
        forwarded: Arc::new(crate::private_broker::ConnectionRegistry::new(
            Duration::from_secs(10),
        )),
        forward_count: std::sync::atomic::AtomicUsize::new(0),
        request_lock: Mutex::new(()),
        stop: stop.clone(),
    });
    let handler = receiver.clone();
    let broker = PrivateBroker::start_managed(
        PrivateBrokerConfig {
            directory_prefix: "syq-return-",
            socket_name: "r",
            listener_thread: "syq-return-listener",
            client_thread: "syq-return-client",
            max_connections: 272,
            io_timeout: Duration::from_secs(10),
        },
        move |stream, _| {
            let writer = stream.try_clone();
            if let Err(error) = handler.handle(stream) {
                if let Ok(mut writer) = writer {
                    let _ = write_message(&mut writer, &Reply::Error(format!("{error:#}")));
                }
            }
        },
    )?;
    let result = (|| {
        let mut delay = Duration::from_secs(1);
        while !stop.load(Ordering::Acquire) {
            let socket = format!("/tmp/syq-return-{}.sock", random_token()?);
            let args = [
                "--destination-register".into(),
                config.name.clone(),
                socket.clone(),
                receiver.secret.clone(),
            ];
            let mut command = ssh_command(&spec.endpoint);
            command
                .args([
                    "-o",
                    "ExitOnForwardFailure=yes",
                    "-o",
                    "StreamLocalBindMask=0177",
                ])
                .arg("-R")
                .arg(format!("{socket}:{}", broker.socket_path().display()))
                .arg("--")
                .arg(&spec.endpoint.host)
                .arg(format!("{} {}", spec.program, shell_words::join(&args)))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0);
            let mut child = OwnedSsh(command.spawn().context("start receiving SSH connection")?);
            *state.lock().unwrap() = crate::receive_service::ConnectionState {
                phase: "connecting".into(),
                error: None,
                ssh_pid: Some(child.0.id()),
            };
            let (ready, readiness) = mpsc::sync_channel(1);
            let mut stdout = child.0.stdout.take().unwrap();
            let reader = std::thread::spawn(move || {
                let _ = ready.send(read_message::<Reply>(&mut stdout));
            });
            let mut stderr = child.0.stderr.take().unwrap();
            let errors = Arc::new(Mutex::new(Vec::new()));
            let captured = errors.clone();
            let error_reader = std::thread::spawn(move || {
                let mut buffer = [0u8; 1024];
                while let Ok(count) = stderr.read(&mut buffer) {
                    if count == 0 {
                        break;
                    }
                    let mut bytes = captured.lock().unwrap();
                    bytes.extend_from_slice(&buffer[..count]);
                    let excess = bytes.len().saturating_sub(8192);
                    bytes.drain(..excess);
                }
            });
            let connected = Instant::now();
            let mut online = false;
            while !stop.load(Ordering::Acquire) && child.0.try_wait()?.is_none() {
                if matches!(readiness.try_recv(), Ok(Ok(Reply::Ready))) {
                    online = true;
                    state.lock().unwrap().phase = "online".into();
                }
                if !online && connected.elapsed() >= Duration::from_secs(30) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let exit = child.0.try_wait()?;
            drop(child);
            let _ = reader.join();
            let _ = error_reader.join();
            receiver.revoke_all();
            if stop.load(Ordering::Acquire) {
                break;
            }
            let error = String::from_utf8_lossy(&errors.lock().unwrap())
                .trim()
                .to_owned();
            let error = if error.is_empty() {
                "return connection closed or did not become ready".into()
            } else {
                error
            };
            if exit
                .and_then(|s| s.code())
                .is_some_and(|code| (1..128).contains(&code) && code != RECONNECT_PENDING)
            {
                bail!("server rejected return connection: {error}; reconnect with syq or change recv settings to retry");
            }
            *state.lock().unwrap() = crate::receive_service::ConnectionState {
                phase: "reconnecting".into(),
                error: Some(error),
                ssh_pid: None,
            };
            if online && connected.elapsed() >= Duration::from_secs(60) {
                delay = Duration::from_secs(1);
            }
            let until = Instant::now() + delay;
            while !stop.load(Ordering::Acquire) && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(100));
            }
            delay = (delay * 2).min(Duration::from_secs(30));
        }
        Ok(())
    })();
    receiver.revoke_all();
    drop(broker);
    result
}

struct RegistrationGuard {
    socket: PathBuf,
    socket_identity: (u64, u64),
    record: Option<(PathBuf, (u64, u64))>,
}
impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        if let Some((path, identity)) = &self.record {
            if fs::symlink_metadata(path).is_ok_and(|m| (m.dev(), m.ino()) == *identity) {
                let _ = fs::remove_file(path);
            }
        }
        if fs::symlink_metadata(&self.socket)
            .is_ok_and(|m| (m.dev(), m.ino()) == self.socket_identity)
        {
            let _ = fs::remove_file(&self.socket);
        }
    }
}
fn register(name: &str, socket: &Path, secret: &str) -> Result<i32> {
    validate_name(name)?;
    let metadata = fs::symlink_metadata(socket)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("return socket must be owned and private");
    }
    let mut guard = RegistrationGuard {
        socket: socket.into(),
        socket_identity: (metadata.dev(), metadata.ino()),
        record: None,
    };
    let registration = Registration {
        version: VERSION,
        identity: crate::identity::build().into(),
        socket: socket.into(),
        secret: secret.into(),
    };
    let (_, reply) = exchange(&registration, Message::Ping, Duration::from_secs(10))?;
    if !matches!(reply, Reply::Ready) {
        bail!("receiving laptop handshake failed");
    }
    let directory = registry()?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(format!("{name}.lock")))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        // A laptop may reconnect before the server has noticed the old TCP
        // session died. Only the same ephemeral credential gets a retry; it
        // still cannot displace an active registration or obtain its lock.
        if load_registration(name).is_ok_and(|previous| previous.secret == secret) {
            crate::output::diagnostic!("syq: previous return connection is still closing");
            return Ok(RECONNECT_PENDING);
        }
        bail!("destination @{name} is already registered by another connection");
    }
    let path = directory.join(format!("{name}.json"));
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&serde_json::to_vec(&registration)?)?;
    temporary.persist(&path)?;
    let meta = fs::symlink_metadata(&path)?;
    guard.record = Some((path, (meta.dev(), meta.ino())));
    // Drop the advertisement before releasing its name lock, including on a
    // normal disconnect. A crash can leave a stale record, never a reservation.
    let _guard = guard;
    write_message(&mut std::io::stdout(), &Reply::Ready)?;
    let mut input = std::io::stdin();
    loop {
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // A quiet, half-open SSH transport must not reserve a name forever.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 15_000) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if ready == 0 {
            let (_, reply) = exchange(&registration, Message::Ping, Duration::from_secs(10))?;
            if !matches!(reply, Reply::Ready) {
                bail!("return connection is no longer ready");
            }
        } else if input.read(&mut [0])? == 0 {
            break;
        }
    }
    Ok(0)
}
fn available(name: &str) -> Result<()> {
    let registration = load_registration(name)?;
    let (_, reply) = exchange(&registration, Message::Ping, Duration::from_secs(1))?;
    if !matches!(reply, Reply::Ready) {
        bail!("destination not ready");
    }
    Ok(())
}
fn destinations(action: DestinationAction) -> Result<i32> {
    match action {
        DestinationAction::List => {
            let mut names = Vec::new();
            for entry in fs::read_dir(registry()?)? {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if let Some(name) = name.strip_suffix(".json") {
                    if validate_name(name).is_ok() {
                        names.push(name.to_owned());
                    }
                }
            }
            names.sort();
            for name in names {
                println!(
                    "@{name}\t{}",
                    if available(&name).is_ok() {
                        "online"
                    } else {
                        "offline"
                    }
                );
            }
            Ok(0)
        }
        DestinationAction::Forget { name } => {
            validate_name(&name)?;
            let directory = registry()?;
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory.join(format!("{name}.lock")))?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!("destination @{name} is still registered; stop its receiver first");
            }
            fs::remove_file(directory.join(format!("{name}.json")))?;
            println!("syq: forgot offline destination @{name}");
            Ok(0)
        }
        DestinationAction::Wait { name, timeout } => {
            validate_name(&name)?;
            if timeout == 0 || timeout > 3600 {
                bail!("timeout must be between 1 and 3600 seconds");
            }
            let deadline = Instant::now() + Duration::from_secs(timeout);
            let mut last_progress = Instant::now();
            loop {
                match available(&name) {
                    Ok(()) => return Ok(0),
                    Err(error) if Instant::now() >= deadline => {
                        return Err(error).context("timed out waiting for named destination")
                    }
                    Err(error) if last_progress.elapsed() >= Duration::from_secs(5) => {
                        crate::output::diagnostic!("syq: waiting for @{name}: {error:#}");
                        last_progress = Instant::now();
                    }
                    Err(_) => {}
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}
pub(crate) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    match argv.get(1).and_then(|s| s.to_str())? {
        "destination" => Some((|| {
            let matches = destination_help()
                .try_get_matches_from(&argv[1..])
                .unwrap_or_else(|e| e.exit());
            destinations(Destinations::from_arg_matches(&matches)?.action)
        })()),
        "--destination-register" => Some((|| {
            if argv.len() != 5 {
                bail!("invalid destination registration arguments");
            }
            register(
                argv[2].to_str().context("invalid name")?,
                Path::new(&argv[3]),
                argv[4].to_str().context("invalid credential")?,
            )
        })()),
        _ => forward::dispatch(argv),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Args, Interface, Location, Placement};
    use crate::conn::Conn;
    use crate::proto::{Request, Response};

    pub(super) fn args(source: &Path, destination: &str) -> Args {
        let mut args =
            Args::try_parse_from(["syq", "-rlt", "--no-progress", "src", "dst"]).unwrap();
        args.interface = Interface::NativeCp;
        args.placement = Placement::Into;
        args.locations = vec![
            Location::parse(source.to_str().unwrap()).unwrap(),
            Location::parse(&format!("server:{destination}")).unwrap(),
        ];
        args.connections_opt = Some(2);
        args.connections = 2;
        args.normalize();
        args
    }
    pub(super) fn request(args: &Args) -> (CopyRequest, crate::receipt::RecipientSecret) {
        let (secret, public) = crate::receipt::generate_recipient().unwrap();
        let policy = crate::receipt::ReceiptPolicy {
            required: true,
            hashed: false,
            max_records: crate::receipt::DEFAULT_MAX_RECORDS,
            max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
            delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
                suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
                recipient_public_key: public,
            },
        };
        (
            crate::restricted::named_request(args, policy).unwrap(),
            secret,
        )
    }
    pub(super) fn broker(
        root: &Path,
        approval: Approval,
    ) -> (
        PrivateBroker,
        Arc<Receiver>,
        Registration,
        mpsc::Receiver<Prompt>,
    ) {
        let (prompts, requests) = mpsc::sync_channel(1);
        let receiver = Arc::new(Receiver {
            requester: "test-server".into(),
            approval_mode: crate::receive_approval::Mode::Always,
            notifications: crate::receive_approval::Notifications::Off,
            approvals: Arc::new(crate::receive_approval::Queue::default()),
            generation: AtomicU64::new(0),
            cwd: root.into(),
            root: Some(root.into()),
            secret: random_token().unwrap(),
            max_bytes: 10_000_000,
            max_entries: 1000,
            max_delete: 0,
            approval,
            prompts,
            sessions: Mutex::new(HashMap::new()),
            forwarded: Arc::new(crate::private_broker::ConnectionRegistry::new(
                Duration::from_secs(10),
            )),
            forward_count: std::sync::atomic::AtomicUsize::new(0),
            request_lock: Mutex::new(()),
            stop: Arc::new(AtomicBool::new(false)),
        });
        let handler = Arc::clone(&receiver);
        let broker = PrivateBroker::start_managed(
            PrivateBrokerConfig {
                directory_prefix: "syq-named-test-",
                socket_name: "s",
                listener_thread: "named-test-listener",
                client_thread: "named-test-client",
                max_connections: 16,
                io_timeout: Duration::from_secs(2),
            },
            move |stream, _| {
                let mut writer = stream.try_clone().unwrap();
                if let Err(error) = handler.handle(stream) {
                    let _ = write_message(&mut writer, &Reply::Error(format!("{error:#}")));
                }
            },
        )
        .unwrap();
        let registration = Registration {
            version: VERSION,
            identity: crate::identity::build().into(),
            socket: broker.socket_path().into(),
            secret: receiver.secret.clone(),
        };
        (broker, receiver, registration, requests)
    }
    fn approve(registration: &Registration, request: CopyRequest) -> Approved {
        let (_, reply) = exchange(
            registration,
            Message::Request(Box::new(request)),
            Duration::from_secs(10),
        )
        .unwrap();
        match reply {
            Reply::Approved(approved) => approved,
            _ => panic!("no approval"),
        }
    }
    fn route(registration: Registration, token: String) -> String {
        format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Route {
                    registration,
                    token
                })
                .unwrap()
            )
        )
    }
    fn control(registration: Registration, approved: &Approved) -> crate::conn::RemoteConn {
        let mut spec = crate::conn::RemoteSpec::local_receiver(true);
        spec.restricted_grant = Some(route(registration, approved.token.clone()));
        spec.connect_with(false, false).unwrap()
    }

    #[test]
    fn pending_request_disconnect_and_trailing_data_are_detected_without_blocking() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        assert!(!requester_closed(&socket));
        peer.write_all(b"unexpected data").unwrap();
        assert!(requester_closed(&socket));
        drop(peer);
        assert!(requester_closed(&socket));
        let (socket, peer) = UnixStream::pair().unwrap();
        drop(peer);
        assert!(requester_closed(&socket));
    }

    #[test]
    fn named_paths_reject_traversal_and_ambiguous_names() {
        for name in ["", "../x", "a/b", "a:b", "a@b", "a\n"] {
            assert!(validate_name(name).is_err());
        }
        for path in [
            &b"../escape"[..],
            b"a/../escape",
            b"/absolute",
            b"bad\0name",
        ] {
            assert!(request_path(path).is_err());
        }
        assert_eq!(request_path(b"./a//b").unwrap(), b"/SYQ-RECEIVE/a/b");
        assert!(rebase(b"/SYQ-RECEIVE-other/file", Path::new("/tmp/root")).is_err());
        assert!(rebase(b"/SYQ-RECEIVE/../escape", Path::new("/tmp/root")).is_err());
    }

    #[test]
    fn named_parser_rejects_oversize_truncated_and_wrong_generation() {
        assert!(read_message::<Envelope>(&mut &u32::MAX.to_be_bytes()[..]).is_err());
        assert!(read_message::<Envelope>(&mut &b"\0\0\0\x10{}"[..]).is_err());
        let root = tempfile::tempdir().unwrap();
        let (_broker, _receiver, mut registration, _) = broker(root.path(), Approval::Always);
        registration.secret = "wrong".into();
        assert!(exchange(&registration, Message::Ping, Duration::from_secs(2)).is_err());
        let mut stream = UnixStream::connect(&registration.socket).unwrap();
        write_message(
            &mut stream,
            &Envelope {
                version: 999,
                identity: crate::identity::build().into(),
                secret: registration.secret,
                message: Message::Ping,
            },
        )
        .unwrap();
        assert!(matches!(
            read_message::<Reply>(&mut stream).unwrap(),
            Reply::Error(_)
        ));
    }

    #[test]
    fn named_denial_does_not_issue_authority_or_touch_destination() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, prompts) = broker(&root, Approval::Ask);
        let (request, _) = request(&args(Path::new("source"), "."));
        let caller = std::thread::spawn(move || {
            exchange(
                &registration,
                Message::Request(Box::new(request)),
                Duration::from_secs(5),
            )
            .is_err()
        });
        let prompt = prompts.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(prompt.description.contains("not been inspected"));
        prompt.decision.send(false).unwrap();
        assert!(caller.join().unwrap());
        assert!(receiver.sessions.lock().unwrap().is_empty());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn named_control_cannot_be_replayed_and_cannot_listen_on_tcp() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let mut args = args(Path::new("source"), ".");
        args.compress = false;
        let (request, _) = request(&args);
        let approved = approve(&registration, request);
        let mut conn = control(registration.clone(), &approved);
        assert!(exchange(
            &registration,
            Message::Open {
                token: approved.token.clone(),
                control: true
            },
            Duration::from_secs(2)
        )
        .is_err());
        conn.send(Request::TcpListen {
            key: Some(vec![0; 32]),
            token: vec![1; 32],
            port_lo: 0,
            port_hi: 0,
            congestion_control: None,
        })
        .unwrap();
        assert!(matches!(conn.recv().unwrap(), Response::Err(_)));
        drop(conn);
        // Closing the control revokes workers regardless of retained tokens.
        let deadline = Instant::now() + Duration::from_secs(2);
        while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(exchange(
            &registration,
            Message::Open {
                token: approved.token,
                control: false
            },
            Duration::from_secs(2)
        )
        .is_err());
    }

    fn worker_stream(registration: &Registration, approved: &Approved) -> UnixStream {
        let (stream, reply) = exchange(
            registration,
            Message::Open {
                token: approved.token.clone(),
                control: false,
            },
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(matches!(reply, Reply::Ready));
        let mut writer = crate::proto::FrameWriter::new(stream.try_clone().unwrap(), false);
        writer
            .write_msg(&Request::Hello {
                identity: crate::identity::build().into(),
                compress: false,
                debug: false,
                token: Vec::new(),
                role: crate::proto::ConnectionRole::DestinationWorker {
                    destination: None,
                    copy_sources: Vec::new(),
                },
            })
            .unwrap();
        let mut reader = crate::proto::FrameReader::new(stream.try_clone().unwrap());
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::HelloOk { .. }
        ));
        stream
    }

    #[test]
    fn named_control_closure_revokes_connected_workers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let mut args = args(Path::new("source"), ".");
        args.compress = false;
        let (request, _) = request(&args);
        let approved = approve(&registration, request);
        let conn = control(registration.clone(), &approved);
        let mut worker = worker_stream(&registration, &approved);
        // macOS may reject SO_RCVTIMEO after the peer has shut down.
        worker
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let authority = receiver
            .sessions
            .lock()
            .unwrap()
            .get(&approved.token)
            .unwrap()
            .authority
            .clone();
        drop(conn);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(receiver.sessions.lock().unwrap().is_empty());
        assert_eq!(
            worker.read(&mut [0u8; 1]).unwrap(),
            0,
            "connected worker was not closed"
        );
        let mut request = Request::Apply {
            ops: vec![crate::proto::Op::Mkdir {
                path: root.join("source").as_os_str().as_bytes().to_vec(),
                mode: 0o755,
                condition: crate::proto::TargetCondition::Any,
            }],
            guard: None,
        };
        assert!(authority
            .authorize(&mut request, false)
            .unwrap_err()
            .to_string()
            .contains("control is closed"));
        assert!(!root.join("source").exists());
    }

    #[test]
    fn named_pending_hello_is_bounded_and_does_not_block_readiness() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let mut args = args(Path::new("source"), ".");
        args.compress = false;
        let (request, _) = request(&args);
        let approved = approve(&registration, request);
        let _control = control(registration.clone(), &approved);
        receiver
            .sessions
            .lock()
            .unwrap()
            .get_mut(&approved.token)
            .unwrap()
            .channels = Arc::new(crate::private_broker::ConnectionRegistry::new(
            Duration::from_millis(200),
        ));
        let mut pending = Vec::new();
        for _ in 0..2 {
            let (stream, reply) = exchange(
                &registration,
                Message::Open {
                    token: approved.token.clone(),
                    control: false,
                },
                Duration::from_secs(2),
            )
            .unwrap();
            assert!(matches!(reply, Reply::Ready));
            pending.push(stream);
        }
        assert!(exchange(
            &registration,
            Message::Open {
                token: approved.token.clone(),
                control: false,
            },
            Duration::from_secs(2)
        )
        .is_err());
        assert!(matches!(
            exchange(&registration, Message::Ping, Duration::from_secs(1))
                .unwrap()
                .1,
            Reply::Ready
        ));
        for mut stream in pending {
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream.read_to_end(&mut Vec::new()).unwrap();
        }
        // Expired handshakes release their worker allowance while control stays live.
        let _worker = worker_stream(&registration, &approved);
    }

    #[test]
    fn named_abandoned_open_releases_its_session() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let (request, _) = request(&args(Path::new("source"), "."));
        let approved = approve(&registration, request);
        let (stream, reply) = exchange(
            &registration,
            Message::Open {
                token: approved.token,
                control: true,
            },
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(matches!(reply, Reply::Ready));
        // Ready confirms the receiver consumed Open. Closing sooner can discard
        // the envelope on macOS, leaving an unused token to expire normally.
        // Abandon before Hello; the consumed session must still be revoked.
        drop(stream);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(receiver.sessions.lock().unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn named_failed_open_reply_releases_its_session() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let (request, _) = request(&args(Path::new("source"), "."));
        let approved = approve(&registration, request);
        let mut stream = UnixStream::connect(&registration.socket).unwrap();
        // Linux SHUT_RD reliably refuses the opening reply while the client
        // remains connected, exercising the failed-reply cleanup specifically.
        stream.shutdown(std::net::Shutdown::Read).unwrap();
        write_message(
            &mut stream,
            &Envelope {
                version: VERSION,
                identity: crate::identity::build().into(),
                secret: registration.secret,
                message: Message::Open {
                    token: approved.token,
                    control: true,
                },
            },
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(receiver.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn named_copy_uses_confined_workers_and_verifies_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let source = fs::canonicalize(temp.path()).unwrap().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("hello"), b"hello laptop").unwrap();
        fs::write(source.join("large"), vec![42; 5_000_000]).unwrap();
        std::os::unix::fs::symlink("hello", source.join("link")).unwrap();
        let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
        let mut args = args(&source, ".");
        let (request, secret) = request(&args);
        let policy = request.constraints.receipt_policy.clone();
        let approved = approve(&registration, request);
        args.locations.last_mut().unwrap().path = approved.destination.clone();
        args.restricted_grant = Some(route(registration, approved.token.clone()));
        args.named_receipt = Some(Arc::new(NamedReceipt {
            control: Mutex::new(None),
            secret,
            approved,
            policy,
        }));
        args.no_tcp = true;
        assert_eq!(crate::transfer::run(args).unwrap(), 0);
        assert_eq!(
            fs::read(root.join("source/hello")).unwrap(),
            b"hello laptop"
        );
        assert_eq!(
            fs::read(root.join("source/large")).unwrap(),
            vec![42; 5_000_000]
        );
        assert_eq!(
            fs::read_link(root.join("source/link")).unwrap(),
            Path::new("hello")
        );
    }

    #[test]
    fn named_authorization_expires_before_control_opens() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let (request, _) = request(&args(Path::new("source"), "."));
        let approved = approve(&registration, request);
        receiver
            .sessions
            .lock()
            .unwrap()
            .get_mut(&approved.token)
            .unwrap()
            .issued = Instant::now() - START_TIMEOUT;
        assert!(exchange(
            &registration,
            Message::Open {
                token: approved.token,
                control: true
            },
            Duration::from_secs(2)
        )
        .is_err());
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn named_limits_and_scope_validation_precede_approval() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
        let (mut request, _) = request(&args(Path::new("source"), "."));
        request.copy.mutation_scopes[0].path = b"/SYQ-RECEIVE/../outside".to_vec();
        assert!(exchange(
            &registration,
            Message::Request(Box::new(request)),
            Duration::from_secs(2)
        )
        .is_err());
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    }
    #[test]
    fn receiving_cwd_allows_other_paths_but_root_confines_them() {
        let temp = tempfile::tempdir().unwrap();
        let temp = fs::canonicalize(temp.path()).unwrap();
        let cwd = temp.join("downloads");
        fs::create_dir(&cwd).unwrap();
        let outside = temp.join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, cwd.join("link")).unwrap();
        assert_eq!(
            resolve_destination(&cwd, None, b"../file").unwrap().0,
            temp.join("file")
        );
        assert_eq!(
            resolve_destination(&cwd, None, outside.join("file").as_os_str().as_bytes())
                .unwrap()
                .0,
            outside.join("file")
        );
        assert_eq!(
            resolve_destination(&cwd, None, b"link/file").unwrap().0,
            outside.join("file")
        );
        assert_eq!(
            resolve_destination(&cwd, None, b"link/../file").unwrap().0,
            temp.join("file")
        );
        assert_eq!(
            resolve_destination(&cwd, None, b"link").unwrap().0,
            cwd.join("link")
        );
        assert!(resolve_destination(&cwd, Some(&cwd), b"../file").is_err());
        assert!(resolve_destination(&cwd, Some(&cwd), outside.as_os_str().as_bytes()).is_err());
        assert_eq!(
            resolve_destination(&cwd, Some(&cwd), b"child/file")
                .unwrap()
                .0,
            cwd.join("child/file")
        );
    }
    #[test]
    fn initial_envelope_deadline_is_not_extended_by_partial_bytes() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for byte in 0..30 {
                if writer.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let start = Instant::now();
        assert!(read_socket_message::<Envelope>(&mut reader, Duration::from_millis(100)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(reader);
        sender.join().unwrap();
    }
}
