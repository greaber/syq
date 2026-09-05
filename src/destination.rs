//! Named, permission-checked return channels over laptop-initiated SSH.
//!
//! This v1 protocol and registry are independent of SSH persistence and durable
//! receiver enrollments. The remote account is the requester identity: shells
//! and jobs under that account intentionally share access to its registrations.
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant};

use crate::delegation::{CopyOperation, DestinationPlacement, GrantConstraints};
use crate::private_broker::{PrivateBroker, PrivateBrokerConfig, TrackedStream};

const VERSION: u16 = 1;
const MAX_MESSAGE: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const START_TIMEOUT: Duration = Duration::from_secs(60);
const PREFIX: &str = "named-v1:";
const REQUEST_ROOT: &[u8] = b"/SYQ-RECEIVE";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Approval {
    Ask,
    Always,
}

#[derive(Parser, Debug)]
#[command(
    name = "syq receive",
    about = "Make a directory available to copies initiated on a server. Keep running to maintain and reconnect the outbound SSH connection."
)]
struct Receive {
    /// SSH server account whose shells and jobs can request transfers
    #[arg(long)]
    via: String,
    /// Destination name on that server; send with syq cp ... --to @NAME
    #[arg(long)]
    name: String,
    /// Existing laptop directory that may receive files
    #[arg(long)]
    into: PathBuf,
    /// Ask in this terminal for each copy, or authorize copies automatically (including overwrites)
    #[arg(long, value_enum, default_value = "ask")]
    approve: Approval,
    /// Maximum bytes a single transfer may reserve/write, including partial files
    #[arg(long, default_value = "100G")]
    max_bytes: String,
    /// Maximum entries one transfer may touch
    #[arg(long, default_value_t = 1_000_000)]
    max_entries: u64,
    /// Permit pruning up to this many destination entries per transfer; default forbids deletion
    #[arg(long, default_value_t = 0)]
    max_delete: u64,
    /// Exact syq helper on the server (otherwise use the managed helper)
    #[arg(long)]
    syq_path: Option<String>,
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

pub(crate) fn receive_help() -> clap::Command {
    crate::help::configure(Receive::command())
}
pub(crate) fn destination_help() -> clap::Command {
    crate::help::configure(Destinations::command())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CopyRequest {
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
    secret: crate::receipt::RecipientSecret,
    approved: Approved,
    policy: crate::receipt::ReceiptPolicy,
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
    Open { token: String, control: bool },
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

fn write_message(writer: &mut impl Write, message: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_MESSAGE {
        bail!("named destination message exceeds size limit");
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}
fn read_message<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
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
    private_directory(".syq-destinations-v1")
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
fn receiving_identity(config: &Receive, root: &Path) -> Result<String> {
    let key = serde_json::to_vec(&(VERSION, &config.via, &config.name, root))?;
    let name = format!("{}.key", blake3::hash(&key).to_hex());
    let path = private_directory(".syq-receive-v1")?.join(name);
    let secret = random_token()?;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(secret.as_bytes())?;
            file.sync_all()?;
            Ok(secret)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes = crate::delegation::read_private_regular(&path, "receiving identity", 128)?;
            let secret = String::from_utf8(bytes)?;
            if secret.len() != 43 {
                bail!("invalid receiving identity; restore its saved file or forget the offline remote name before creating a new identity");
            }
            Ok(secret)
        }
        Err(error) => Err(error.into()),
    }
}

/// Completion only lists local names; it never creates state or asks a laptop
/// for file listings without a transfer approval.
pub(crate) fn registered_names() -> Vec<String> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let directory = PathBuf::from(home).join(".syq-destinations-v1");
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
            format!("destination @{name} is unavailable; start syq receive on the laptop")
        })?;
    let registration: Registration = serde_json::from_slice(&encoded)?;
    if registration.version != VERSION || registration.identity != crate::identity::build() {
        bail!("named destination build differs; use matching syq builds and restart syq receive");
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

fn constrain(
    mut request: CopyRequest,
    root: &Path,
    max_bytes: u64,
    max_entries: u64,
    max_delete: u64,
) -> Result<CopyRequest> {
    if request.copy.mutation_scopes.len() > 1024 {
        bail!("too many copy scopes");
    }
    request.copy.destination = rebase(&request.copy.destination, root)?;
    if request.copy.destination == root.as_os_str().as_bytes()
        && request.copy.policy.placement == DestinationPlacement::ExactPath
    {
        bail!("cannot replace the receiving directory itself; use --into . or a child path");
    }
    for scope in &mut request.copy.mutation_scopes {
        scope.path = rebase(&scope.path, root)?;
    }
    for filter_root in &mut request.constraints.filters.destination_roots {
        *filter_root = rebase(filter_root, root)?;
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
    let Some(destination) = args.locations.last() else {
        return Ok(());
    };
    let Some(name) = destination
        .host
        .as_deref()
        .and_then(|h| h.strip_prefix('@'))
    else {
        if args
            .locations
            .iter()
            .any(|l| l.host.as_deref().is_some_and(|h| h.starts_with('@')))
        {
            bail!("named destinations can only be used with cp --to @NAME");
        }
        return Ok(());
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
    let registration = load_registration(name)?;
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
    crate::output::diagnostic!("syq: requesting permission from @{name} (up to 300 seconds)");
    let (_, reply) = exchange(
        &registration,
        Message::Request(Box::new(request)),
        REQUEST_TIMEOUT + Duration::from_secs(10),
    )?;
    let Reply::Approved(approved) = reply else {
        bail!("unexpected named destination response");
    };
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Route {
            registration,
            token: approved.token.clone()
        })?)
    ));
    args.named_receipt = Some(Arc::new(NamedReceipt {
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
}
struct Prompt {
    description: String,
    deadline: Instant,
    decision: mpsc::SyncSender<bool>,
}
struct Receiver {
    requester: String,
    root: PathBuf,
    secret: String,
    max_bytes: u64,
    max_entries: u64,
    max_delete: u64,
    approval: Approval,
    prompts: mpsc::SyncSender<Prompt>,
    sessions: Mutex<HashMap<String, Session>>,
    request_lock: Mutex<()>,
    stop: Arc<AtomicBool>,
}

impl Receiver {
    fn handle(&self, mut stream: TrackedStream) -> Result<()> {
        let envelope: Envelope = read_message(&mut stream)?;
        if envelope.version != VERSION || envelope.identity != crate::identity::build() {
            bail!("named destination build mismatch; restart with matching syq builds");
        }
        if envelope.secret != self.secret {
            bail!("named destination authentication failed");
        }
        match envelope.message {
            Message::Ping => write_message(&mut stream, &Reply::Ready),
            Message::Request(request) => {
                let _request = self.request_lock.try_lock().map_err(|_| {
                    anyhow::anyhow!(
                        "another transfer is awaiting approval; retry after it is decided"
                    )
                })?;
                let request = constrain(
                    *request,
                    &self.root,
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
                // Validate the complete operation before displaying an approval.
                let (authority, mut approved) =
                    crate::restricted::named_authority(&self.root, request.clone())?;
                if matches!(self.approval, Approval::Ask) {
                    let permission = if request.copy.options.dry_run {
                        "preview only; no changes"
                    } else if request.copy.options.verify_only {
                        "compare contents only; no changes"
                    } else {
                        match request.copy.policy.existing {
                            crate::delegation::ExistingDestinationPolicy::Replace => {
                                "may create and overwrite matching entries"
                            }
                            crate::delegation::ExistingDestinationPolicy::Skip => {
                                "keep existing entries; may create new entries"
                            }
                            crate::delegation::ExistingDestinationPolicy::MustExist => {
                                "may update existing entries only"
                            }
                            crate::delegation::ExistingDestinationPolicy::UpdateIfOlder => {
                                unreachable!("validated receiver policy")
                            }
                        }
                    };
                    let description = format!(
                        "Copy request from {:?}\nDestination: {:?}\nPermission: {permission}. Deletion ceiling: {} entries.\nLimits: {} bytes, {} entries. Preserve permissions: {}.\nSource contents and file sizes have not been inspected by this laptop.",
                        self.requester, String::from_utf8_lossy(&request.copy.destination), request.copy.limits.max_deletions, request.copy.limits.max_total_bytes, request.copy.limits.max_entries, request.copy.options.preserve_permissions,
                    );
                    let (decision, reply) = mpsc::sync_channel(1);
                    let deadline = Instant::now() + REQUEST_TIMEOUT;
                    self.prompts
                        .try_send(Prompt {
                            description,
                            deadline,
                            decision,
                        })
                        .context("approval terminal is busy")?;
                    loop {
                        if self.stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                            bail!("approval timed out or receiver stopped");
                        }
                        match reply.recv_timeout(Duration::from_millis(200)) {
                            Ok(true)
                                if Instant::now() < deadline
                                    && !self.stop.load(Ordering::Relaxed) =>
                            {
                                break
                            }
                            Ok(_) => bail!("transfer denied or approval expired"),
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                approved.token = random_token()?;
                self.sessions.lock().unwrap().insert(
                    approved.token.clone(),
                    Session {
                        authority,
                        issued: Instant::now(),
                        opened: false,
                    },
                );
                write_message(&mut stream, &Reply::Approved(approved))
            }
            Message::Open { token, control } => {
                let authority = {
                    let mut sessions = self.sessions.lock().unwrap();
                    let session = sessions
                        .get_mut(&token)
                        .context("transfer authorization expired or is unknown")?;
                    if control {
                        if session.opened || session.issued.elapsed() >= START_TIMEOUT {
                            bail!("transfer authorization has already been used or expired");
                        }
                        session.opened = true;
                    } else if !session.opened {
                        bail!("transfer control channel has not opened");
                    }
                    Arc::clone(&session.authority)
                };
                write_message(&mut stream, &Reply::Ready)?;
                let writer = stream.try_clone()?;
                // Active streams die when SSH detects disconnect, when the
                // receiver stops, or at the executor's fixed transfer deadline.
                writer.set_read_timeout(None)?;
                writer.set_write_timeout(None)?;
                let result = crate::server::run_named(stream, writer, authority, control);
                if control {
                    self.sessions.lock().unwrap().remove(&token);
                }
                result
            }
        }
    }
}

struct StopOnDrop {
    stop: Arc<AtomicBool>,
    signals: [signal_hook::SigId; 2],
}
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for signal in self.signals {
            signal_hook::low_level::unregister(signal);
        }
    }
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
fn ssh_command(endpoint: &crate::cli::NativeEndpoint) -> Command {
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
fn receive(config: Receive) -> Result<i32> {
    validate_name(&config.name)?;
    let root = fs::canonicalize(&config.into).context("receiving directory must already exist")?;
    if !root.is_dir() {
        bail!("receiving path is not a directory");
    }
    let max_bytes = crate::cli::parse_size(&config.max_bytes)?;
    if max_bytes == 0
        || max_bytes > crate::delegation::MAX_COPY_BYTES
        || config.max_entries == 0
        || config.max_entries > crate::delegation::MAX_ENTRIES
    {
        bail!("invalid receiving limits");
    }
    let endpoint = crate::cli::parse_native_endpoint(Some(&config.via))?.unwrap();
    if endpoint.host.starts_with('@') || endpoint.host.starts_with('-') {
        bail!("--via requires an SSH endpoint");
    }
    let mut tty = match config.approve {
        Approval::Ask => Some(OpenOptions::new().read(true).write(true).open("/dev/tty").context("approval needs a terminal; --approve always explicitly permits automatic copies and overwrites")?),
        Approval::Always => None,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let sigint = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop))?;
    let sigterm = signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    let (prompts, requests) = mpsc::sync_channel(1);
    let secret = receiving_identity(&config, &root)?;
    let receiver = Arc::new(Receiver {
        requester: config.via.clone(),
        root,
        secret,
        max_bytes,
        max_entries: config.max_entries,
        max_delete: config.max_delete,
        approval: config.approve,
        prompts,
        sessions: Mutex::new(HashMap::new()),
        request_lock: Mutex::new(()),
        stop: Arc::clone(&stop),
    });
    let handler = Arc::clone(&receiver);
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
            let error_writer = stream.try_clone();
            if let Err(error) = handler.handle(stream) {
                if let Ok(mut writer) = error_writer {
                    let _ = write_message(&mut writer, &Reply::Error(format!("{error:#}")));
                }
            }
        },
    )?;
    let _stop_on_drop = StopOnDrop {
        stop: Arc::clone(&stop),
        signals: [sigint, sigterm],
    };
    let mut spec = crate::conn::RemoteSpec::local_receiver(false);
    spec.local_process = false;
    spec.host = endpoint.host.clone();
    spec.user = endpoint.user.clone();
    spec.port = endpoint.port;
    spec.rsh = vec![
        "ssh".into(),
        "-a".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ClearAllForwardings=yes".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
    ];
    spec.syq_path = config.syq_path.clone();
    spec.bootstrap_helper = config.syq_path.is_none();
    // Use the existing exact-build helper bootstrap once before publishing a
    // registration. Reconnect attempts thereafter only invoke that helper.
    drop(spec.connect_completion()?);
    let mut delay = Duration::from_secs(1);
    while !stop.load(Ordering::Relaxed) {
        let socket = format!("/tmp/syq-return-{}.sock", random_token()?);
        let args = vec![
            "--destination-register".into(),
            config.name.clone(),
            socket.clone(),
            receiver.secret.clone(),
        ];
        let mut command = ssh_command(&endpoint);
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
            .arg(&endpoint.host)
            .arg(spec.program_command(&args))
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .process_group(0);
        crate::output::diagnostic!(
            "syq: connecting @{0} through {1}; Ctrl-C revokes availability",
            config.name,
            config.via
        );
        let mut child = OwnedSsh(command.spawn().context("start receiving SSH connection")?);
        let connected_at = Instant::now();
        while !stop.load(Ordering::Relaxed) && child.0.try_wait()?.is_none() {
            if let Ok(prompt) = requests.try_recv() {
                let allowed = if let Some(tty) = tty.as_mut() {
                    approve_terminal(tty, &prompt.description, prompt.deadline, &stop, || {
                        child.0.try_wait().map_or(true, |status| status.is_some())
                    })?
                } else {
                    false
                };
                let _ = prompt.decision.send(allowed);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let exit = child.0.try_wait()?;
        drop(child);
        if !stop.load(Ordering::Relaxed)
            && exit
                .and_then(|s| s.code())
                .is_some_and(|code| (1..128).contains(&code))
        {
            bail!("server rejected the named destination registration; fix the reported error and restart syq receive");
        }
        // Pending approvals cannot turn into usable grants after a lost link.
        for (_, session) in receiver.sessions.lock().unwrap().drain() {
            session.authority.close_control();
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if connected_at.elapsed() > Duration::from_secs(60) {
            delay = Duration::from_secs(1);
        }
        crate::output::diagnostic!(
            "syq: @{0} disconnected; laptop reconnects in {1}s; interrupted copies must be rerun",
            config.name,
            delay.as_secs()
        );
        let until = Instant::now() + delay;
        while !stop.load(Ordering::Relaxed) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        delay = (delay * 2).min(Duration::from_secs(30));
    }
    stop.store(true, Ordering::Relaxed);
    drop(broker);
    Ok(0)
}

fn approve_terminal(
    tty: &mut File,
    description: &str,
    deadline: Instant,
    stop: &AtomicBool,
    mut disconnected: impl FnMut() -> bool,
) -> Result<bool> {
    // A pasted or delayed answer to an earlier request cannot approve this one.
    if unsafe { libc::tcflush(tty.as_raw_fd(), libc::TCIFLUSH) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    writeln!(
        tty,
        "\n{description}\nAllow this transfer once? [y/N] (expires in 300s)"
    )?;
    tty.flush()?;
    let mut line = Vec::new();
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) && !disconnected() {
        let mut descriptor = libc::pollfd {
            fd: tty.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 200) };
        if result < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        if result == 0 {
            continue;
        }
        if Instant::now() >= deadline || stop.load(Ordering::Relaxed) || disconnected() {
            return Ok(false);
        }
        let mut byte = [0];
        if tty.read(&mut byte)? == 0 {
            return Ok(false);
        }
        if byte[0] == b'\n' {
            return Ok(line == b"y" || line == b"yes");
        }
        if line.len() >= 16 {
            return Ok(false);
        }
        line.push(byte[0].to_ascii_lowercase());
    }
    writeln!(tty, "Request expired or receiver stopped.")?;
    Ok(false)
}

struct RegistrationGuard {
    socket: PathBuf,
    socket_identity: (u64, u64),
}
impl Drop for RegistrationGuard {
    fn drop(&mut self) {
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
    let _guard = RegistrationGuard {
        socket: socket.into(),
        socket_identity: (metadata.dev(), metadata.ino()),
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
        bail!("destination @{name} is already registered by another connection");
    }
    let path = directory.join(format!("{name}.json"));
    if path.exists() {
        let bytes = crate::delegation::read_private_regular(
            &path,
            "destination registration",
            MAX_MESSAGE,
        )?;
        let previous: Registration = serde_json::from_slice(&bytes)?;
        if previous.secret != secret {
            bail!("destination @{name} belongs to another receiving configuration; choose a different name or explicitly run syq destination forget {name} while it is offline");
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&serde_json::to_vec(&registration)?)?;
    temporary.persist(&path)?;
    println!("syq: @{name} is available from any shell on this server");
    // EOF belongs to the laptop's owned SSH process. Its exit withdraws the
    // live socket. Keep the identity record so another laptop cannot silently
    // take over the name while this laptop is reconnecting.
    let mut byte = [0];
    while std::io::stdin().read(&mut byte)? != 0 {}
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
        "receive" => Some((|| {
            let matches = receive_help()
                .try_get_matches_from(&argv[1..])
                .unwrap_or_else(|e| e.exit());
            receive(Receive::from_arg_matches(&matches)?)
        })()),
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Args, Interface, Location, Placement};
    use crate::conn::Conn;
    use crate::proto::{Request, Response};

    fn args(source: &Path, destination: &str) -> Args {
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
    fn request(args: &Args) -> (CopyRequest, crate::receipt::RecipientSecret) {
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
    fn broker(
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
            root: root.into(),
            secret: random_token().unwrap(),
            max_bytes: 10_000_000,
            max_entries: 1000,
            max_delete: 0,
            approval,
            prompts,
            sessions: Mutex::new(HashMap::new()),
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

    #[test]
    fn named_copy_uses_confined_workers_and_verifies_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let source = temp.path().join("source");
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
    fn named_terminal_requires_a_fresh_answer_and_cancels_on_disconnect() {
        use std::os::fd::FromRawFd;
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master) };
        let mut slave = unsafe { File::from_raw_fd(slave) };
        // A stale pretyped yes is discarded before this request is displayed.
        master.write_all(b"yes\n").unwrap();
        let response = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut output = Vec::new();
            while Instant::now() < deadline {
                let mut poll = libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 100) } <= 0 {
                    continue;
                }
                let mut bytes = [0; 256];
                let count = master.read(&mut bytes).unwrap();
                output.extend_from_slice(&bytes[..count]);
                if output.windows(5).any(|w| w == b"[y/N]") {
                    master.write_all(b"no\n").unwrap();
                    return master;
                }
            }
            panic!("approval prompt did not arrive before deadline");
        });
        let stop = AtomicBool::new(false);
        assert!(!approve_terminal(
            &mut slave,
            "test request",
            Instant::now() + Duration::from_secs(3),
            &stop,
            || false
        )
        .unwrap());
        let _master = response.join().unwrap();
        assert!(!approve_terminal(
            &mut slave,
            "disconnected",
            Instant::now() + Duration::from_secs(3),
            &stop,
            || true
        )
        .unwrap());
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
}
