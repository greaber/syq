//! Named, permission-checked return channels over laptop-initiated SSH.
//!
//! Persistence maintains transient advertisements and durable name ownership,
//! independent of restricted receiver enrollments. The remote account is the
//! requester identity: shells and jobs under it share access to registrations.
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{CommandFactory, Parser, Subcommand};
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

pub(crate) mod exec;
mod forward;
pub(crate) mod handoff;
mod identity;

// Discovery is independent of the build-pinned request protocol. Keep the
// Ping/Ready and Identify/Identity JSON envelopes stable across helper wire changes.
const DISCOVERY_VERSION: u16 = 2;
const VERSION: u16 = 2;
const REGISTRATION_VERSION: u16 = 3;
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

#[derive(Parser, Debug)]
#[command(
    name = "destinations",
    about = "Inspect named destinations available to this server account"
)]
pub(crate) struct Destinations {
    #[command(subcommand)]
    action: DestinationAction,
}
#[derive(Subcommand, Debug)]
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

pub(crate) fn run_command(command: Destinations) -> Result<i32> {
    destinations(command.action)
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
    Identify {
        name: String,
        challenge: String,
    },
    Exec(exec::ExecRequest),
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
    Identity(identity::Proof),
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
    program: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Route {
    registration: Registration,
    token: String,
}

pub(crate) fn write_message(writer: &mut impl Write, message: &impl Serialize) -> Result<()> {
    write_framed(writer, message, MAX_MESSAGE, "named destination message")
}
pub(crate) fn read_message<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    read_framed(reader, MAX_MESSAGE, "named destination message")
}
/// One JSON value behind a four-byte big-endian length. `what` names the
/// message in size errors.
pub(crate) fn write_framed(
    writer: &mut impl Write,
    message: &impl Serialize,
    limit: usize,
    what: &str,
) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > limit {
        bail!("{what} exceeds size limit");
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}
pub(crate) fn read_framed<T: DeserializeOwned>(
    reader: &mut impl Read,
    limit: usize,
    what: &str,
) -> Result<T> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > limit {
        bail!("invalid {what} size");
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn deadline_remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "return channel exchange timed out",
            )
        })
}

fn wait_fd(
    fd: std::os::fd::RawFd,
    events: i16,
    deadline: Instant,
    cancelled: Option<&dyn Fn() -> bool>,
) -> std::io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        if cancelled.is_some_and(|check| check()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "return request cancelled",
            ));
        }
        // Only cancellation needs periodic wakeups. Socket and handshake waits
        // can sleep until readiness or their deadline, including human approval.
        let cap = if cancelled.is_some() { 100 } else { i32::MAX };
        let milliseconds = deadline_remaining(deadline)?
            .as_millis()
            .clamp(1, cap as u128) as i32;
        // The caller keeps the descriptor alive and descriptor is writable during
        // poll. Signals and spurious wakeups never renew the deadline.
        let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready > 0 {
            return Ok(());
        }
    }
}

struct DeadlineSocket<'a> {
    socket: &'a mut UnixStream,
    deadline: Instant,
}
impl Read for DeadlineSocket<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            deadline_remaining(self.deadline)?;
            // recv writes at most bytes.len() bytes into this live mutable
            // slice. Per-call nonblocking mode does not affect socket clones.
            let count = unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {
                    wait_fd(self.socket.as_raw_fd(), libc::POLLIN, self.deadline, None)?
                }
                _ => return Err(error),
            }
        }
    }
}
impl Write for DeadlineSocket<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            deadline_remaining(self.deadline)?;
            // Darwin's Unix-stream send path checks the kernel-private
            // MSG_NBIO flag, not MSG_DONTWAIT, while waiting for buffer space.
            // This per-call flag avoids toggling O_NONBLOCK on a descriptor
            // shared with socket clones. MSG_NBIO has been 0x20000 in XNU.
            #[cfg(target_vendor = "apple")]
            let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL | 0x20000;
            #[cfg(not(target_vendor = "apple"))]
            let flags = libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL;
            match socket2::SockRef::from(&*self.socket).send_with_flags(bytes, flags) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    wait_fd(self.socket.as_raw_fd(), libc::POLLOUT, self.deadline, None)?
                }
                Err(error) => return Err(error),
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        deadline_remaining(self.deadline)?;
        Ok(())
    }
}

/// A complete incoming envelope has an absolute deadline, including clients
/// trickling bytes. Timeout budgets cannot be renewed by partial progress.
pub(crate) fn read_socket_message<T: DeserializeOwned>(
    socket: &mut UnixStream,
    timeout: Duration,
) -> Result<T> {
    read_message(&mut DeadlineSocket {
        socket,
        deadline: Instant::now() + timeout,
    })
}

fn connect_socket(path: &Path, deadline: Instant) -> std::io::Result<UnixStream> {
    use socket2::{Domain, SockAddr, Socket, Type};
    deadline_remaining(deadline)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    // Unix stream connect completes immediately or fails. In particular,
    // Linux reports EAGAIN for a full listen queue, with no connection pending.
    socket.connect(&SockAddr::unix(path)?)?;
    socket.set_nonblocking(false)?;
    let descriptor: std::os::fd::OwnedFd = socket.into();
    Ok(descriptor.into())
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

/// Protect the actual identity location, including an explicitly supplied HOME.
/// Merely computing the path must not create receiver state.
pub(crate) fn receiver_identity_directory() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is unset")?;
    Ok(fs::canonicalize(home)?.join(".syq-receiver-identity"))
}

fn registry() -> Result<PathBuf> {
    private_directory(".syq-destinations-v3")
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
    local_names(true)
}

/// Connection records only, for completion routing without network probes.
pub(crate) fn connection_names() -> Vec<String> {
    local_names(false)
}

fn local_names(include_offline: bool) -> Vec<String> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let directory = PathBuf::from(home).join(".syq-destinations-v3");
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
            let file = entry.ok()?.file_name();
            let file = file.to_str()?;
            let name = file
                .strip_suffix(".json")
                .or_else(|| {
                    include_offline
                        .then(|| file.strip_suffix(".owner"))
                        .flatten()
                })?
                .to_owned();
            validate_name(&name).ok()?;
            Some(name)
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn read_registration(name: &str) -> Result<Registration> {
    validate_name(name)?;
    let path = registry()?.join(format!("{name}.json"));
    let encoded = match crate::delegation::read_private_regular(&path, "named destination", MAX_MESSAGE) {
        Ok(encoded) => encoded,
        Err(error) if error.chain().any(|cause| cause.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)) => {
            if identity::owner(&registry()?, name)?.is_some() {
                bail!("receiving machine @{name} is offline; reconnect its original receiver with `syq persist connect SERVER`, or release the name on this server with `syq persist destinations forget {name}`");
            }
            let names = registered_names();
            let advice = if names.is_empty() {
                "On the receiving machine, run `syq persist connect SERVER`, using the SSH endpoint for this server account.".to_owned()
            } else {
                let shown = names.iter().take(8).map(|name| format!("@{name}")).collect::<Vec<_>>().join(", ");
                format!("Registered names: {shown}{}. Use one of these names, or connect another receiving machine with `syq persist connect SERVER`.", if names.len() > 8 { ", ..." } else { "" })
            };
            bail!("no receiving machine named @{name} is registered for this account.\n{advice}\nRun `syq persist destinations list` to see names and connection status.");
        }
        Err(error) => return Err(error).with_context(|| format!("cannot read the registration for @{name}; check its permissions or reconnect from the receiving machine")),
    };
    let registration: Registration = serde_json::from_slice(&encoded)?;
    if registration.version != REGISTRATION_VERSION {
        bail!("unsupported destination registration; reconnect from the receiving machine");
    }
    if !Path::new(std::ffi::OsStr::from_bytes(&registration.program)).is_absolute()
        || registration.program.contains(&0)
        || registration.identity.is_empty()
    {
        bail!("invalid destination helper registration; reconnect from the receiving machine");
    }
    Ok(registration)
}

fn load_registration(name: &str) -> Result<Registration> {
    let registration = read_registration(name)?;
    if let Some(owner) = identity::owner(&registry()?, name)? {
        identity::verify_receiver(name, &registration, Some(&owner))?;
    }
    Ok(registration)
}
fn exchange(
    registration: &Registration,
    message: Message,
    timeout: Duration,
) -> Result<(UnixStream, Reply)> {
    if !matches!(message, Message::Ping | Message::Identify { .. })
        && registration.identity != crate::identity::build()
    {
        bail!(
            "named destination requires its matching helper; reconnect from the receiving machine"
        );
    }
    let deadline = Instant::now() + timeout;
    let mut stream = connect_socket(&registration.socket, deadline).map_err(|error| {
        let message = if error.kind() == std::io::ErrorKind::WouldBlock {
            "receiving machine is busy; try again shortly"
        } else {
            "could not connect to receiving machine; it may be busy or its connection may have ended; try again, or run `syq persist connect SERVER` on the receiving machine to connect to this server account"
        };
        anyhow::Error::new(error).context(message)
    })?;
    // Configure the next protocol phase before the peer can close after its
    // reply. macOS may reject socket timeout changes after peer shutdown.
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut io = DeadlineSocket {
        socket: &mut stream,
        deadline,
    };
    write_message(
        &mut io,
        &Envelope {
            version: if matches!(message, Message::Ping | Message::Identify { .. }) {
                DISCOVERY_VERSION
            } else {
                VERSION
            },
            // Discovery and identity proofs are stable across builds. Copy,
            // command, and forwarding requests still require a matching helper.
            identity: registration.identity.clone(),
            secret: registration.secret.clone(),
            message,
        },
    )?;
    let reply = read_message(&mut io)?;
    if let Reply::Error(error) = &reply {
        bail!("receiving machine: {error}");
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
    request.copy.limits.max_connections = request
        .copy
        .limits
        .max_connections
        .min(crate::delegation::MAX_CONNECTIONS);
    Ok(request)
}

pub(crate) fn is_named(grant: &Option<String>) -> bool {
    grant.as_deref().is_some_and(|s| s.starts_with(PREFIX))
}

fn select_copy(args: &crate::cli::Args) -> Result<Option<handoff::Selection>> {
    match &args.auth_from {
        crate::cli::AuthFrom::Return(_) => return forward::select(args),
        crate::cli::AuthFrom::Ssh => {
            let (destination, sources) = args
                .locations
                .split_last()
                .context("copy endpoints missing")?;
            if args.interface != crate::cli::Interface::NativeCp
                || sources.iter().any(|source| source.is_remote())
                || !destination.is_remote()
                || destination
                    .host
                    .as_deref()
                    .is_some_and(|host| host.starts_with('@'))
            {
                bail!(
                    "--auth-from ssh requires local sources and an ordinary SSH --to destination"
                );
            }
            return Ok(None);
        }
        crate::cli::AuthFrom::Auto => {}
    }
    let Some(destination) = args.locations.last() else {
        return Ok(None);
    };
    let Some(host) = destination.host.as_deref() else {
        return Ok(None);
    };
    let Some(name) = host.strip_prefix('@') else {
        if handoff::selected_name(handoff::Kind::Copy).is_some() {
            bail!("receiver destinations require @NAME; retry the command with --to @NAME");
        }
        return forward::select(args);
    };
    let name = name.to_owned();
    let registration = load_registration(&name)?;
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
    if args.connections_opt.is_some()
        && args.connections > usize::from(crate::delegation::MAX_CONNECTIONS)
    {
        bail!(
            "named destinations support at most {} workers per transfer",
            crate::delegation::MAX_CONNECTIONS
        );
    }
    Ok(Some(handoff::Selection::new(
        name,
        registration,
        handoff::Kind::Copy,
        None,
    )))
}

pub(crate) fn prepare(args: &mut crate::cli::Args) -> Result<()> {
    let selection = match args.return_selection.take() {
        Some(selection) => selection,
        None => select_copy(args)?,
    };
    let Some(selection) = selection else {
        return Ok(());
    };
    handoff::check_selection(&selection)?;
    if selection.kind == handoff::Kind::Forward {
        return forward::prepare(args, selection);
    }
    let handoff::Selection {
        name, registration, ..
    } = selection;
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
    crate::output::diagnostic!("syq: requesting permission from @{name} (up to 300 seconds; approve on the receiving machine with its desktop prompt or syq persist receive pending)");
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
        bail!("receiving machine reports {:?}", receipt.terminal.status);
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
    name: String,
    identity_key: ssh_key::PrivateKey,
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
    active_streams: Arc<crate::private_broker::ConnectionRegistry>,
    exec_count: AtomicU64,
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
        self.active_streams.shutdown_all();
        for (_, session) in sessions.drain() {
            session.authority.close_control();
            session.channels.shutdown_all();
        }
    }

    fn handle(&self, mut stream: TrackedStream) -> Result<()> {
        let envelope: Envelope =
            read_socket_message(&mut stream.try_clone()?, Duration::from_secs(10))?;
        let version = if matches!(envelope.message, Message::Ping | Message::Identify { .. }) {
            DISCOVERY_VERSION
        } else {
            VERSION
        };
        if envelope.version != version
            || (!matches!(envelope.message, Message::Identify { .. })
                && envelope.identity != crate::identity::build())
        {
            bail!("named destination build mismatch; restart with matching syq builds");
        }
        if envelope.secret != self.secret {
            bail!("named destination authentication failed");
        }
        match envelope.message {
            Message::Exec(request) => self.execute(request, stream),
            Message::Ping => write_message(&mut stream, &Reply::Ready),
            Message::Identify { name, challenge } => {
                if name != self.name {
                    bail!("receiver identity requested for a different profile");
                }
                let proof = identity::prove(&self.identity_key, &name, &challenge, &self.secret)?;
                write_message(&mut stream, &Reply::Identity(proof))
            }
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
const RETURN_SSH_OPTIONS: &[&str] = &[
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
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=3",
];
fn ssh_command(endpoint: &crate::persistence::EndpointRecord) -> Command {
    let mut cmd = Command::new("ssh");
    // This connection installs a remote forward and follows the user's host-key
    // policy. The outbound return-authorized connection adds stricter options of its own.
    cmd.args(RETURN_SSH_OPTIONS)
        .args(["-o", "ControlMaster=no", "-o", "ControlPath=none"]);
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
        name: config.name.clone(),
        identity_key: identity::load_key()?,
        requester: format!(
            "{} (receiving profile @{})",
            spec.endpoint.label(),
            config.name
        ),
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
        active_streams: Arc::new(crate::private_broker::ConnectionRegistry::new(
            Duration::from_secs(10),
        )),
        exec_count: AtomicU64::new(0),
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
                bail!("server rejected return connection: {error}; run syq persist connect {} on the receiving machine to retry", shell_words::quote(&spec.endpoint.label()));
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
    match register_inner(name, socket, secret) {
        Err(error)
            if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::NotConnected
                )
            }) =>
        {
            // Socket timeouts are WouldBlock on Unix. A failed handshake or
            // heartbeat is a transport interruption, not a policy rejection.
            // Reuse the retry status understood by existing return clients.
            crate::output::diagnostic!("syq: return connection interrupted: {error:#}");
            Ok(RECONNECT_PENDING)
        }
        result => result,
    }
}

fn register_inner(name: &str, socket: &Path, secret: &str) -> Result<i32> {
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
        version: REGISTRATION_VERSION,
        program: std::env::current_exe()?.as_os_str().as_bytes().to_vec(),
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
        // A responsive holder is a duplicate, even when a copied home directory
        // gives both machines the same identity. Never replace a held lock.
        if read_registration(name).is_ok_and(|previous| {
            exchange(&previous, Message::Ping, Duration::from_secs(1))
                .is_ok_and(|(_, reply)| matches!(reply, Reply::Ready))
        }) {
            bail!("destination @{name} is already connected; choose another receiver name to use both connections at the same time");
        }
        // The old transport may be dying. Its heartbeat releases the lock;
        // only the same connection or verified owner may wait to reconnect.
        if read_registration(name).is_ok_and(|previous| previous.secret == secret) {
            crate::output::diagnostic!("syq: previous return connection is still closing");
            return Ok(RECONNECT_PENDING);
        }
        if let Some(owner) = identity::owner(&directory, name)? {
            // A restarted service has a new connection credential but keeps
            // its receiver key. Verify it before allowing reconnect retries.
            identity::verify_receiver(name, &registration, Some(&owner))?;
            crate::output::diagnostic!("syq: previous return connection is still closing");
            return Ok(RECONNECT_PENDING);
        }
        bail!("destination @{name} is already registered by another connection");
    }
    let owner = identity::owner(&directory, name)?;
    let public_key = identity::verify_receiver(name, &registration, owner.as_deref())?;
    identity::claim(&directory, name, &public_key)?;
    let path = directory.join(format!("{name}.json"));
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&serde_json::to_vec(&registration)?)?;
    temporary.persist(&path)?;
    let meta = fs::symlink_metadata(&path)?;
    guard.record = Some((path, (meta.dev(), meta.ino())));
    // Drop the advertisement before releasing its name lock, including on a
    // normal disconnect. Ownership survives; a crash cannot keep the live lock.
    let _guard = guard;
    write_message(&mut std::io::stdout(), &Reply::Ready)?;
    let mut input = std::io::stdin();
    loop {
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // A quiet, half-open SSH transport must not block reconnection forever.
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
fn available(name: &str, timeout: Duration) -> Result<Registration> {
    let registration = read_registration(name)?;
    if let Some(owner) = identity::owner(&registry()?, name)? {
        identity::verify_receiver_with_timeout(name, &registration, Some(&owner), timeout)?;
    } else {
        let (_, reply) = exchange(&registration, Message::Ping, timeout)?;
        if !matches!(reply, Reply::Ready) {
            bail!("destination not ready");
        }
    }
    Ok(registration)
}
fn destinations(action: DestinationAction) -> Result<i32> {
    match action {
        DestinationAction::List => {
            let mut names = Vec::new();
            for entry in fs::read_dir(registry()?)? {
                let file = entry?.file_name();
                let file = file.to_string_lossy();
                if let Some(name) = file
                    .strip_suffix(".json")
                    .or_else(|| file.strip_suffix(".owner"))
                {
                    if validate_name(name).is_ok() {
                        names.push(name.to_owned());
                    }
                }
            }
            names.sort();
            names.dedup();
            for name in names {
                println!(
                    "@{name}\t{}",
                    if available(&name, Duration::from_secs(1)).is_ok() {
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
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(directory.join(format!("{name}.lock")))?;
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!("destination @{name} is still registered; stop its receiver first");
            }
            identity::forget(&directory, &name)?;
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
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    bail!("timed out waiting for named destination");
                }
                let error = match available(&name, remaining.min(Duration::from_secs(1))) {
                    Ok(_) => return Ok(0),
                    Err(error) => error,
                };
                if last_progress.elapsed() >= Duration::from_secs(5) {
                    crate::output::diagnostic!("syq: waiting for @{name}: {error:#}");
                    last_progress = Instant::now();
                }
                std::thread::sleep(
                    Duration::from_millis(200)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
                if Instant::now() >= deadline {
                    return Err(error).context("timed out waiting for named destination");
                }
            }
        }
    }
}
pub(crate) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    match argv.get(1).and_then(|s| s.to_str())? {
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
mod tests;
