//! A fail-closed SSH-agent proxy for live direct remote-to-remote transfers.
//!
//! The source host sees public identities from the caller's ambient agent, but
//! signatures are released only for one hostA -> user@hostB SSH authentication
//! path. OpenSSH's session-bind messages prove the two SSH sessions and the
//! host-bound userauth request binds the signature to B's host key and login
//! user. The broker never accepts key-management or opaque signing requests.

use anyhow::{anyhow, bail, Context, Result};
use ssh_agent_lib::proto::extension::{MessageExtension, SessionBind};
use ssh_agent_lib::proto::{Request, Response, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_agent_lib::ssh_key::{public::KeyData, PublicKey};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Agent messages are normally only a few KiB. This accommodates large
/// identity lists without allowing a peer to force an unbounded allocation.
const MAX_AGENT_FRAME: usize = 256 * 1024;
/// syq establishes at most 32 SSH handshakes concurrently. Keep a hard broker
/// cap as a second bound against a source host that opens idle agent channels.
const MAX_BROKER_CONNECTIONS: usize = 32;

const SSH_AGENT_FAILURE: &[u8] = &[5];
const SSH_AGENT_SUCCESS: &[u8] = &[6];
const SSH_AGENT_EXTENSION_FAILURE: &[u8] = &[28];

#[derive(Clone, Debug)]
pub struct HostPolicy {
    pub login_user: String,
    host_keys: Vec<KeyData>,
    known_hosts_name: String,
}

#[derive(Clone, Debug)]
pub struct BrokerPolicy {
    delegate: HostPolicy,
    destination: HostPolicy,
}

impl BrokerPolicy {
    pub fn new(delegate: HostPolicy, destination: HostPolicy) -> Self {
        Self {
            delegate,
            destination,
        }
    }
}

/// Resolve the effective user and exact, already trusted plain host keys using
/// the caller's OpenSSH configuration and known_hosts files. Host certificates
/// are deliberately rejected for now: treating a CA key as the presented host
/// key would silently weaken the name/principal checks OpenSSH performs.
pub fn resolve_host_policy(
    ssh_program: &str,
    explicit_user: Option<&str>,
    host: &str,
) -> Result<HostPolicy> {
    let mut command = Command::new(ssh_program);
    command.arg("-G");
    if let Some(user) = explicit_user {
        command.args(["-l", user]);
    }
    command.args(["--", host]).env("LC_ALL", "C");
    let output = command
        .output()
        .with_context(|| format!("inspect SSH configuration for {host}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "could not inspect SSH configuration for {host}{}",
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        );
    }
    let config = parse_ssh_config(&output.stdout)
        .with_context(|| format!("parse `ssh -G` output for {host}"))?;
    let keygen = ssh_keygen_for(ssh_program);
    let (host_keys, saw_ca) = read_known_host_keys(&keygen, &config.lookup, &config.files)?;
    if host_keys.is_empty() {
        if saw_ca {
            bail!(
                "{host} is trusted only through an SSH host certificate; constrained agent forwarding currently requires an exact plain host key in known_hosts"
            );
        }
        bail!(
            "no exact trusted host key for {host} ({}) was found in the configured known_hosts files; connect once with ssh to record it, use --relay, or use --no-forward-agent with credentials on the source host",
            config.lookup
        );
    }
    Ok(HostPolicy {
        login_user: config.user,
        host_keys,
        known_hosts_name: config.lookup,
    })
}

#[derive(Debug)]
struct EffectiveSshConfig {
    user: String,
    lookup: String,
    files: Vec<PathBuf>,
}

fn parse_ssh_config(output: &[u8]) -> Result<EffectiveSshConfig> {
    let output = std::str::from_utf8(output).context("SSH configuration was not UTF-8")?;
    let mut user = None;
    let mut hostname = None;
    let mut port = None;
    let mut hostkey_alias = None;
    let mut files = Vec::new();
    for line in output.lines() {
        let Some((name, value)) = line.split_once(' ') else {
            continue;
        };
        let value = value.trim();
        match name {
            "user" => user = Some(value.to_string()),
            "hostname" => hostname = Some(value.to_string()),
            "port" => port = Some(value.parse::<u16>().context("invalid SSH port")?),
            "hostkeyalias" if value != "none" => hostkey_alias = Some(value.to_string()),
            "userknownhostsfile" | "globalknownhostsfile" => {
                for path in value
                    .split_ascii_whitespace()
                    .filter(|path| *path != "none")
                {
                    if path.contains('%') || path.starts_with('~') {
                        bail!("unexpanded known_hosts path {path:?} in `ssh -G` output");
                    }
                    files.push(PathBuf::from(path));
                }
            }
            _ => {}
        }
    }
    let user = user
        .filter(|value| !value.is_empty())
        .context("missing SSH user")?;
    let hostname = hostname
        .filter(|value| !value.is_empty())
        .context("missing SSH hostname")?;
    let port = port.context("missing SSH port")?;
    let lookup = match hostkey_alias {
        Some(alias) => alias,
        None if port == 22 => hostname,
        None => format!("[{hostname}]:{port}"),
    };
    files.sort();
    files.dedup();
    Ok(EffectiveSshConfig {
        user,
        lookup,
        files,
    })
}

fn ssh_keygen_for(ssh_program: &str) -> OsString {
    let path = Path::new(ssh_program);
    if path.components().count() > 1 {
        let mut sibling = path.to_path_buf();
        sibling.set_file_name("ssh-keygen");
        sibling.into_os_string()
    } else {
        OsString::from("ssh-keygen")
    }
}

fn read_known_host_keys(
    keygen: &OsString,
    lookup: &str,
    files: &[PathBuf],
) -> Result<(Vec<KeyData>, bool)> {
    let mut trusted = Vec::new();
    let mut revoked = Vec::new();
    let mut saw_ca = false;
    for file in files {
        if !file.exists() {
            continue;
        }
        let output = Command::new(keygen)
            .args(["-F", lookup, "-f"])
            .arg(file)
            .env("LC_ALL", "C")
            .output()
            .with_context(|| format!("search {} for {lookup}", file.display()))?;
        if !output.status.success() {
            if output.status.code() == Some(1)
                && output.stdout.is_empty()
                && output.stderr.is_empty()
            {
                continue;
            }
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            bail!(
                "could not search {} for {lookup}{}",
                file.display(),
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            );
        }
        let text = std::str::from_utf8(&output.stdout)
            .with_context(|| format!("{} contained non-UTF-8 key text", file.display()))?;
        parse_known_host_output(text, file, &mut trusted, &mut revoked, &mut saw_ca)?;
    }
    trusted.retain(|key| !revoked.contains(key));
    Ok((trusted, saw_ca))
}

fn parse_known_host_output(
    text: &str,
    file: &Path,
    trusted: &mut Vec<KeyData>,
    revoked: &mut Vec<KeyData>,
    saw_ca: &mut bool,
) -> Result<()> {
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let (marker, offset) = if fields[0].starts_with('@') {
            (Some(fields[0]), 1)
        } else {
            (None, 0)
        };
        if fields.len() < offset + 3 {
            bail!("malformed known_hosts result from {}", file.display());
        }
        if marker == Some("@cert-authority") {
            *saw_ca = true;
            continue;
        }
        let public =
            PublicKey::from_openssh(&format!("{} {}", fields[offset + 1], fields[offset + 2]))
                .with_context(|| format!("parse host key from {}", file.display()))?;
        let key = public.key_data().clone();
        if marker == Some("@revoked") {
            revoked.push(key);
        } else if marker.is_none() && !trusted.contains(&key) {
            trusted.push(key);
        } else if marker.is_some() {
            bail!(
                "unsupported known_hosts marker {} in {}",
                marker.unwrap_or_default(),
                file.display()
            );
        }
    }
    Ok(())
}

/// A running broker. Dropping it closes every active client/upstream socket,
/// joins the listener and workers, and removes the private socket directory.
pub struct ConstrainedAgentBroker {
    ambient_socket: PathBuf,
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    connections: Arc<ConnectionRegistry>,
    listener_thread: Option<JoinHandle<()>>,
    _socket_dir: tempfile::TempDir,
}

impl std::fmt::Debug for ConstrainedAgentBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConstrainedAgentBroker")
            .field("socket_path", &self.socket_path)
            .finish_non_exhaustive()
    }
}

impl ConstrainedAgentBroker {
    pub fn start(policy: BrokerPolicy) -> Result<Self> {
        let ambient = std::env::var_os("SSH_AUTH_SOCK")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .context(
                "SSH_AUTH_SOCK is not set; constrained direct remote-to-remote authentication needs a local SSH agent (or use --relay/--no-forward-agent)",
            )?;
        Self::start_with_socket(ambient, policy)
    }

    fn start_with_socket(ambient_socket: PathBuf, policy: BrokerPolicy) -> Result<Self> {
        if !ambient_socket.is_absolute() {
            bail!("SSH_AUTH_SOCK must be an absolute Unix socket path");
        }
        validate_openssh_option_path(&ambient_socket, "SSH_AUTH_SOCK")?;
        let ambient_metadata = std::fs::metadata(&ambient_socket).with_context(|| {
            format!("inspect ambient SSH agent at {}", ambient_socket.display())
        })?;
        if !ambient_metadata.file_type().is_socket() {
            bail!(
                "SSH_AUTH_SOCK {} is not a Unix socket",
                ambient_socket.display()
            );
        }
        let socket_dir = tempfile::Builder::new()
            .prefix("syq-agent-")
            .tempdir()
            .context("create private constrained-agent directory")?;
        let socket_path = socket_dir.path().join("agent.sock");
        validate_openssh_option_path(&socket_path, "temporary constrained-agent path")?;
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("bind constrained agent at {}", socket_path.display()))?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(ConnectionRegistry::default());
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_connections = Arc::clone(&connections);
        let thread_ambient = ambient_socket.clone();
        let policy = Arc::new(policy);
        let listener_thread = thread::Builder::new()
            .name("syq-agent-listener".into())
            .spawn(move || {
                accept_connections(
                    listener,
                    thread_ambient,
                    policy,
                    thread_shutdown,
                    thread_connections,
                )
            })
            .context("start constrained-agent listener")?;

        Ok(Self {
            ambient_socket,
            socket_path,
            shutdown,
            connections,
            listener_thread: Some(listener_thread),
            _socket_dir: socket_dir,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn ambient_socket(&self) -> &Path {
        &self.ambient_socket
    }
}

fn validate_openssh_option_path(path: &Path, label: &str) -> Result<()> {
    let text = path
        .to_str()
        .with_context(|| format!("{label} is not valid UTF-8"))?;
    if !text.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'.' | b'_' | b'-' | b'+' | b':' | b'@' | b',' | b'='
            )
    }) {
        bail!("{label} contains characters that are unsafe in an OpenSSH command-line option");
    }
    Ok(())
}

impl Drop for ConstrainedAgentBroker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.connections.shutdown_all();
        // Wake accept immediately instead of waiting for the nonblocking poll.
        let _ = UnixStream::connect(&self.socket_path);
        if let Some(listener) = self.listener_thread.take() {
            let _ = listener.join();
        }
    }
}

fn accept_connections(
    listener: UnixListener,
    ambient_socket: PathBuf,
    policy: Arc<BrokerPolicy>,
    shutdown: Arc<AtomicBool>,
    connections: Arc<ConnectionRegistry>,
) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::Acquire) {
        reap_workers(&mut workers);
        match listener.accept() {
            Ok((stream, _)) => {
                if workers.len() >= MAX_BROKER_CONNECTIONS {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let Ok(stream) = connections.track(stream) else {
                    continue;
                };
                let worker_ambient = ambient_socket.clone();
                let worker_policy = Arc::clone(&policy);
                let worker_connections = Arc::clone(&connections);
                match thread::Builder::new()
                    .name("syq-agent-client".into())
                    .spawn(move || {
                        let _ = serve_client(
                            stream,
                            &worker_ambient,
                            &worker_policy,
                            worker_connections,
                        );
                    }) {
                    Ok(worker) => workers.push(worker),
                    Err(_) => continue,
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    connections.shutdown_all();
    for worker in workers {
        let _ = worker.join();
    }
}

fn reap_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

#[derive(Default)]
struct ConnectionRegistry {
    next_id: AtomicU64,
    streams: Mutex<HashMap<u64, UnixStream>>,
}

impl ConnectionRegistry {
    fn track(self: &Arc<Self>, stream: UnixStream) -> io::Result<TrackedStream> {
        let registered = stream.try_clone()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, registered);
        Ok(TrackedStream {
            stream,
            id,
            registry: Arc::clone(self),
        })
    }

    fn shutdown_all(&self) {
        let streams = self
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for stream in streams.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

struct TrackedStream {
    stream: UnixStream,
    id: u64,
    registry: Arc<ConnectionRegistry>,
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.registry
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
    }
}

impl Read for TrackedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buffer)
    }
}

impl Write for TrackedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Default)]
struct BindState {
    bindings: Vec<SessionBind>,
}

impl BindState {
    fn add(&mut self, policy: &BrokerPolicy, binding: SessionBind) -> Result<()> {
        if binding.session_id.is_empty() || binding.session_id.len() > 64 {
            bail!("invalid SSH session identifier length");
        }
        binding
            .verify_signature()
            .context("invalid session-bind host-key signature")?;
        match self.bindings.len() {
            0 if binding.is_forwarding && policy.delegate.host_keys.contains(&binding.host_key) => {
            }
            1 if !binding.is_forwarding
                && policy.destination.host_keys.contains(&binding.host_key) => {}
            0 => bail!(
                "first session-bind did not identify trusted delegate {}",
                policy.delegate.known_hosts_name
            ),
            1 => bail!(
                "final session-bind did not identify trusted destination {}",
                policy.destination.known_hosts_name
            ),
            _ => bail!("unexpected extra SSH forwarding hop"),
        }
        if self
            .bindings
            .iter()
            .any(|previous| previous.session_id == binding.session_id)
        {
            bail!("reused SSH session identifier");
        }
        self.bindings.push(binding);
        Ok(())
    }

    fn authorize(&self, policy: &BrokerPolicy, request: &SignRequest) -> Result<()> {
        let [_, destination] = self.bindings.as_slice() else {
            bail!("signature requested before the exact two-hop path was bound");
        };
        let parsed = HostboundUserauth::parse(&request.data)?;
        if parsed.session_id != destination.session_id {
            bail!("userauth session did not match session-bind");
        }
        if parsed.user != policy.destination.login_user.as_bytes() {
            bail!("userauth login user was not authorized");
        }
        if parsed.service != b"ssh-connection" {
            bail!("userauth service was not ssh-connection");
        }
        if parsed.method != b"publickey-hostbound-v00@openssh.com" {
            bail!("legacy or non-host-bound userauth request");
        }
        let mut credential = Vec::new();
        request
            .credential
            .encode(&mut credential)
            .context("encode requested credential")?;
        if parsed.credential != credential {
            bail!("embedded userauth credential did not match sign request");
        }
        let mut host_key = Vec::new();
        destination
            .host_key
            .encode(&mut host_key)
            .context("encode bound host key")?;
        if parsed.host_key != host_key {
            bail!("embedded userauth host key did not match session-bind");
        }
        validate_signature_algorithm(parsed.algorithm, parsed.credential, request.flags)?;
        Ok(())
    }
}

fn serve_client(
    mut downstream: TrackedStream,
    ambient_socket: &Path,
    policy: &BrokerPolicy,
    connections: Arc<ConnectionRegistry>,
) -> Result<()> {
    let mut state = BindState::default();
    let mut upstream: Option<TrackedStream> = None;
    while let Some(frame) = read_frame(&mut downstream)? {
        let Some(message_id) = frame.first().copied() else {
            break;
        };
        match message_id {
            11 if frame.len() == 1 && !state.bindings.is_empty() => {
                let response = upstream_request(
                    &mut upstream,
                    ambient_socket,
                    &connections,
                    &frame,
                    UpstreamResponse::Identities,
                )?;
                write_frame(&mut downstream, &response)?;
            }
            13 => {
                let request = parse_sign_request(&frame);
                let Ok(request) = request else {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                };
                if state.authorize(policy, &request).is_err() {
                    write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                    break;
                }
                let response = upstream_request(
                    &mut upstream,
                    ambient_socket,
                    &connections,
                    &frame,
                    UpstreamResponse::Signature,
                )?;
                write_frame(&mut downstream, &response)?;
            }
            27 => {
                let binding = parse_session_bind(&frame);
                match binding.and_then(|binding| state.add(policy, binding)) {
                    Ok(()) => write_frame(&mut downstream, SSH_AGENT_SUCCESS)?,
                    Err(_) => {
                        write_frame(&mut downstream, SSH_AGENT_EXTENSION_FAILURE)?;
                        break;
                    }
                }
            }
            _ => {
                // Mutations, query/unknown extensions, legacy protocol
                // operations and malformed identity requests all fail closed.
                write_frame(&mut downstream, SSH_AGENT_FAILURE)?;
                break;
            }
        }
    }
    Ok(())
}

fn parse_sign_request(frame: &[u8]) -> Result<SignRequest> {
    let mut input = frame;
    let request = Request::decode(&mut input).context("decode sign request")?;
    if !input.is_empty() {
        bail!("trailing bytes in sign request");
    }
    match request {
        Request::SignRequest(request) => Ok(request),
        _ => bail!("not a sign request"),
    }
}

fn parse_session_bind(frame: &[u8]) -> Result<SessionBind> {
    let mut input = frame;
    let request = Request::decode(&mut input).context("decode agent extension")?;
    if !input.is_empty() {
        bail!("trailing bytes in agent extension");
    }
    let Request::Extension(extension) = request else {
        bail!("not an agent extension");
    };
    if extension.name != SessionBind::NAME {
        bail!("unsupported agent extension");
    }
    let mut details = extension.details.as_ref();
    let binding = SessionBind::decode(&mut details).context("decode session-bind")?;
    if !details.is_empty() {
        bail!("trailing bytes in session-bind");
    }
    Ok(binding)
}

enum UpstreamResponse {
    Identities,
    Signature,
}

fn upstream_request(
    upstream: &mut Option<TrackedStream>,
    ambient_socket: &Path,
    connections: &Arc<ConnectionRegistry>,
    request: &[u8],
    expected: UpstreamResponse,
) -> Result<Vec<u8>> {
    if upstream.is_none() {
        let stream = UnixStream::connect(ambient_socket).with_context(|| {
            format!(
                "connect to ambient SSH agent at {}",
                ambient_socket.display()
            )
        })?;
        *upstream = Some(connections.track(stream)?);
    }
    let stream = upstream.as_mut().context("ambient SSH agent unavailable")?;
    write_frame(stream, request)?;
    let response = read_frame(stream)?.context("ambient SSH agent closed without a response")?;
    validate_upstream_response(&response, expected)?;
    Ok(response)
}

fn validate_upstream_response(frame: &[u8], expected: UpstreamResponse) -> Result<()> {
    let mut input = frame;
    let response = Response::decode(&mut input).context("decode ambient agent response")?;
    if !input.is_empty() {
        bail!("trailing bytes in ambient agent response");
    }
    match (expected, response) {
        (_, Response::Failure)
        | (UpstreamResponse::Identities, Response::IdentitiesAnswer(_))
        | (UpstreamResponse::Signature, Response::SignResponse(_)) => Ok(()),
        _ => bail!("ambient agent returned an unexpected response"),
    }
}

fn read_frame(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    let first = stream.read(&mut length[..1])?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut length[1..])?;
    let length = u32::from_be_bytes(length) as usize;
    if !(1..=MAX_AGENT_FRAME).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SSH agent frame length is outside the allowed range",
        ));
    }
    let mut frame = vec![0u8; length];
    stream.read_exact(&mut frame)?;
    Ok(Some(frame))
}

fn write_frame(stream: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    let length = u32::try_from(frame.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SSH agent frame too large"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()
}

struct HostboundUserauth<'a> {
    session_id: &'a [u8],
    user: &'a [u8],
    service: &'a [u8],
    method: &'a [u8],
    algorithm: &'a [u8],
    credential: &'a [u8],
    host_key: &'a [u8],
}

impl<'a> HostboundUserauth<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let mut input = SshCursor::new(data);
        let session_id = input.string()?;
        if input.byte()? != 50 {
            bail!("signing data was not SSH2_MSG_USERAUTH_REQUEST");
        }
        let user = input.string()?;
        let service = input.string()?;
        let method = input.string()?;
        if input.byte()? != 1 {
            bail!("public-key request did not contain a signature");
        }
        let algorithm = input.string()?;
        let credential = input.string()?;
        let host_key = input.string()?;
        if !input.is_empty() {
            bail!("trailing bytes in host-bound userauth request");
        }
        Ok(Self {
            session_id,
            user,
            service,
            method,
            algorithm,
            credential,
            host_key,
        })
    }
}

fn validate_signature_algorithm(algorithm: &[u8], credential: &[u8], flags: u32) -> Result<()> {
    let mut credential = SshCursor::new(credential);
    let key_type = credential.string()?;
    let expected_flags = match (key_type, algorithm) {
        (b"ssh-rsa", b"ssh-rsa")
        | (b"ssh-rsa-cert-v01@openssh.com", b"ssh-rsa-cert-v01@openssh.com") => 0,
        (b"ssh-rsa", b"rsa-sha2-256")
        | (b"ssh-rsa-cert-v01@openssh.com", b"rsa-sha2-256-cert-v01@openssh.com") => 2,
        (b"ssh-rsa", b"rsa-sha2-512")
        | (b"ssh-rsa-cert-v01@openssh.com", b"rsa-sha2-512-cert-v01@openssh.com") => 4,
        (key_type, algorithm) if key_type == algorithm => 0,
        _ => bail!("userauth signature algorithm did not match credential"),
    };
    if flags != expected_flags {
        bail!("agent signature flags did not match userauth algorithm");
    }
    Ok(())
}

struct SshCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SshCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let value = *self
            .bytes
            .get(self.offset)
            .context("truncated SSH signing data")?;
        self.offset += 1;
        Ok(value)
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(4)
            .context("SSH string offset overflow")?;
        let length: [u8; 4] = self
            .bytes
            .get(self.offset..end)
            .context("truncated SSH string length")?
            .try_into()
            .map_err(|_| anyhow!("invalid SSH string length"))?;
        self.offset = end;
        let end = self
            .offset
            .checked_add(u32::from_be_bytes(length) as usize)
            .context("SSH string length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .context("truncated SSH string")?;
        self.offset = end;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;
    use ssh_agent_lib::proto::{Extension, Identity};
    use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
    use std::sync::mpsc;
    use std::time::Instant;

    fn key(seed: u8) -> (Ed25519Keypair, KeyData) {
        let keypair = Ed25519Keypair::from_seed(&[seed; 32]);
        let public = KeyData::Ed25519(keypair.public);
        (keypair, public)
    }

    fn host_policy(user: &str, name: &str, key: KeyData) -> HostPolicy {
        HostPolicy {
            login_user: user.into(),
            host_keys: vec![key],
            known_hosts_name: name.into(),
        }
    }

    fn policy(delegate: KeyData, destination: KeyData) -> BrokerPolicy {
        BrokerPolicy::new(
            host_policy("source-user", "source", delegate),
            host_policy("backup", "destination", destination),
        )
    }

    fn binding(keypair: &Ed25519Keypair, key: KeyData, id: &[u8], forwarding: bool) -> SessionBind {
        SessionBind {
            host_key: key,
            session_id: id.to_vec(),
            signature: keypair.try_sign(id).unwrap(),
            is_forwarding: forwarding,
        }
    }

    fn encode_request(request: Request) -> Vec<u8> {
        let mut encoded = Vec::new();
        request.encode(&mut encoded).unwrap();
        encoded
    }

    fn bind_request(binding: SessionBind) -> Vec<u8> {
        encode_request(Request::Extension(Extension::new_message(binding).unwrap()))
    }

    fn hostbound_data(
        session_id: &[u8],
        user: &[u8],
        method: &[u8],
        credential: &ssh_agent_lib::proto::PublicCredential,
        host_key: &KeyData,
    ) -> Vec<u8> {
        let mut credential_blob = Vec::new();
        credential.encode(&mut credential_blob).unwrap();
        let mut host_key_blob = Vec::new();
        host_key.encode(&mut host_key_blob).unwrap();
        let mut data = Vec::new();
        session_id.encode(&mut data).unwrap();
        data.push(50);
        for value in [user, b"ssh-connection", method] {
            value.encode(&mut data).unwrap();
        }
        data.push(1);
        b"ssh-ed25519".as_slice().encode(&mut data).unwrap();
        credential_blob.as_slice().encode(&mut data).unwrap();
        host_key_blob.as_slice().encode(&mut data).unwrap();
        data
    }

    fn sign_request(
        session_id: &[u8],
        user: &[u8],
        method: &[u8],
        identity: KeyData,
        host_key: &KeyData,
    ) -> SignRequest {
        let credential = identity.into();
        let data = hostbound_data(session_id, user, method, &credential, host_key);
        SignRequest {
            credential,
            data,
            flags: 0,
        }
    }

    fn read_response(stream: &mut UnixStream) -> Response {
        let frame = read_frame(stream).unwrap().unwrap();
        let mut input = frame.as_slice();
        let response = Response::decode(&mut input).unwrap();
        assert!(input.is_empty());
        response
    }

    fn assert_closed(stream: &mut UnixStream) {
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("agent connection was not closed: {other:?}"),
        }
    }

    fn fake_ambient(
        socket: &Path,
        identity: Ed25519Keypair,
    ) -> (JoinHandle<()>, mpsc::Receiver<Vec<u8>>) {
        let listener = UnixListener::bind(socket).unwrap();
        let (sent, received) = mpsc::channel();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            while let Some(frame) = read_frame(&mut stream).unwrap() {
                sent.send(frame.clone()).unwrap();
                let response = match frame.first() {
                    Some(11) => Response::IdentitiesAnswer(vec![Identity {
                        credential: KeyData::Ed25519(identity.public).into(),
                        comment: "hardware-backed test key".into(),
                    }]),
                    Some(13) => {
                        let request = parse_sign_request(&frame).unwrap();
                        Response::SignResponse(identity.try_sign(&request.data).unwrap())
                    }
                    other => panic!("unexpected upstream request {other:?}"),
                };
                let mut response_frame = Vec::new();
                response.encode(&mut response_frame).unwrap();
                write_frame(&mut stream, &response_frame).unwrap();
            }
        });
        (worker, received)
    }

    #[test]
    fn parses_effective_host_lookup_and_files() {
        let config = parse_ssh_config(
            b"host alias\nuser backup\nhostname vault.internal\nport 2222\nuserknownhostsfile /tmp/one /tmp/two\nglobalknownhostsfile none\n",
        )
        .unwrap();
        assert_eq!(config.user, "backup");
        assert_eq!(config.lookup, "[vault.internal]:2222");
        assert_eq!(
            config.files,
            [PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")]
        );
    }

    #[test]
    fn host_key_alias_is_used_verbatim() {
        let config = parse_ssh_config(
            b"user backup\nhostname vault.internal\nport 2222\nhostkeyalias stable-vault\nuserknownhostsfile /tmp/known\n",
        )
        .unwrap();
        assert_eq!(config.lookup, "stable-vault");
    }

    #[test]
    fn known_hosts_parser_keeps_plain_keys_and_tracks_ca_and_revocation() {
        let (_, plain) = key(51);
        let (_, revoked_key) = key(52);
        let plain_text = PublicKey::new(plain.clone(), "").to_openssh().unwrap();
        let revoked_text = PublicKey::new(revoked_key.clone(), "")
            .to_openssh()
            .unwrap();
        let text = format!(
            "host {plain_text}\n@cert-authority host {plain_text}\n@revoked host {revoked_text}\n"
        );
        let mut trusted = Vec::new();
        let mut revoked = Vec::new();
        let mut saw_ca = false;
        parse_known_host_output(
            &text,
            Path::new("known_hosts"),
            &mut trusted,
            &mut revoked,
            &mut saw_ca,
        )
        .unwrap();
        assert_eq!(trusted, [plain]);
        assert_eq!(revoked, [revoked_key]);
        assert!(saw_ca);
        assert!(parse_known_host_output(
            &format!("@unknown host {plain_text}\n"),
            Path::new("known_hosts"),
            &mut trusted,
            &mut revoked,
            &mut saw_ca,
        )
        .is_err());
    }

    #[test]
    fn signature_algorithm_and_flags_must_match_key_blob() {
        let mut rsa = Vec::new();
        b"ssh-rsa".as_slice().encode(&mut rsa).unwrap();
        rsa.extend_from_slice(b"key fields are irrelevant here");
        validate_signature_algorithm(b"rsa-sha2-512", &rsa, 4).unwrap();
        assert!(validate_signature_algorithm(b"rsa-sha2-256", &rsa, 4).is_err());
        assert!(validate_signature_algorithm(b"ssh-ed25519", &rsa, 0).is_err());
    }

    #[test]
    fn hostbound_parser_rejects_trailing_or_legacy_data() {
        let mut data = Vec::new();
        b"session".as_slice().encode(&mut data).unwrap();
        data.push(50);
        for value in [
            b"user".as_slice(),
            b"ssh-connection".as_slice(),
            b"publickey".as_slice(),
        ] {
            value.encode(&mut data).unwrap();
        }
        data.push(1);
        for value in [
            b"ssh-ed25519".as_slice(),
            b"key".as_slice(),
            b"host".as_slice(),
        ] {
            value.encode(&mut data).unwrap();
        }
        let parsed = HostboundUserauth::parse(&data).unwrap();
        assert_eq!(parsed.method, b"publickey");
        data.push(0);
        assert!(HostboundUserauth::parse(&data).is_err());
    }

    #[test]
    fn bind_state_rejects_bad_signatures_wrong_hosts_and_extra_hops() {
        let (source_private, source) = key(1);
        let (destination_private, destination) = key(2);
        let (other_private, other) = key(3);
        let policy = policy(source.clone(), destination.clone());

        let mut state = BindState::default();
        assert!(state
            .add(
                &policy,
                binding(&other_private, source.clone(), b"bad-signature", true)
            )
            .is_err());
        assert!(state
            .add(
                &policy,
                binding(&other_private, other.clone(), b"wrong-source", true)
            )
            .is_err());
        state
            .add(
                &policy,
                binding(&source_private, source, b"source-session", true),
            )
            .unwrap();
        assert!(state
            .add(
                &policy,
                binding(&other_private, other.clone(), b"wrong-destination", false)
            )
            .is_err());
        state
            .add(
                &policy,
                binding(
                    &destination_private,
                    destination,
                    b"destination-session",
                    false,
                ),
            )
            .unwrap();
        assert!(state
            .add(&policy, binding(&other_private, other, b"third-hop", true))
            .is_err());
    }

    #[test]
    fn authorization_is_exact_for_user_session_host_and_method() {
        let (source_private, source) = key(11);
        let (destination_private, destination) = key(12);
        let (_, identity) = key(13);
        let (_, other_host) = key(14);
        let policy = policy(source.clone(), destination.clone());
        let mut state = BindState::default();
        state
            .add(
                &policy,
                binding(&source_private, source, b"source-session", true),
            )
            .unwrap();
        state
            .add(
                &policy,
                binding(
                    &destination_private,
                    destination.clone(),
                    b"destination-session",
                    false,
                ),
            )
            .unwrap();

        let allowed = sign_request(
            b"destination-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity.clone(),
            &destination,
        );
        state.authorize(&policy, &allowed).unwrap();
        for denied in [
            sign_request(
                b"other-session",
                b"backup",
                b"publickey-hostbound-v00@openssh.com",
                identity.clone(),
                &destination,
            ),
            sign_request(
                b"destination-session",
                b"root",
                b"publickey-hostbound-v00@openssh.com",
                identity.clone(),
                &destination,
            ),
            sign_request(
                b"destination-session",
                b"backup",
                b"publickey",
                identity.clone(),
                &destination,
            ),
            sign_request(
                b"destination-session",
                b"backup",
                b"publickey-hostbound-v00@openssh.com",
                identity,
                &other_host,
            ),
        ] {
            assert!(state.authorize(&policy, &denied).is_err());
        }
    }

    #[test]
    fn broker_forwards_only_list_and_fully_bound_sign_requests() {
        let temp = tempfile::tempdir().unwrap();
        let ambient_socket = temp.path().join("ambient.sock");
        let (identity_private, identity) = key(23);
        let (ambient, requests) = fake_ambient(&ambient_socket, identity_private.clone());
        let (source_private, source) = key(21);
        let (destination_private, destination) = key(22);
        let broker = ConstrainedAgentBroker::start_with_socket(
            ambient_socket,
            policy(source.clone(), destination.clone()),
        )
        .unwrap();
        let broker_path = broker.socket_path().to_path_buf();
        assert_eq!(
            std::fs::metadata(&broker_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut client = UnixStream::connect(&broker_path).unwrap();

        write_frame(
            &mut client,
            &bind_request(binding(&source_private, source, b"source-session", true)),
        )
        .unwrap();
        assert!(matches!(read_response(&mut client), Response::Success));

        write_frame(&mut client, &[11]).unwrap();
        let Response::IdentitiesAnswer(identities) = read_response(&mut client) else {
            panic!("expected identities response")
        };
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].comment, "hardware-backed test key");
        assert_eq!(requests.recv().unwrap(), vec![11]);

        write_frame(
            &mut client,
            &bind_request(binding(
                &destination_private,
                destination.clone(),
                b"destination-session",
                false,
            )),
        )
        .unwrap();
        assert!(matches!(read_response(&mut client), Response::Success));
        let request = sign_request(
            b"destination-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity,
            &destination,
        );
        let encoded = encode_request(Request::SignRequest(request.clone()));
        write_frame(&mut client, &encoded).unwrap();
        let Response::SignResponse(signature) = read_response(&mut client) else {
            panic!("expected signature response")
        };
        assert_eq!(signature, identity_private.try_sign(&request.data).unwrap());
        assert_eq!(requests.recv().unwrap(), encoded);

        drop(client);
        drop(broker);
        ambient.join().unwrap();
        assert!(!broker_path.exists());
    }

    #[test]
    fn unbound_sign_mutation_unknown_extension_and_oversize_never_reach_ambient() {
        let temp = tempfile::tempdir().unwrap();
        let ambient_socket = temp.path().join("ambient.sock");
        let _ambient = UnixListener::bind(&ambient_socket).unwrap();
        let (_, source) = key(31);
        let (_, destination) = key(32);
        let (_, identity) = key(33);
        let broker = ConstrainedAgentBroker::start_with_socket(
            ambient_socket,
            policy(source, destination.clone()),
        )
        .unwrap();

        let request = sign_request(
            b"unbound-session",
            b"backup",
            b"publickey-hostbound-v00@openssh.com",
            identity,
            &destination,
        );
        let cases = [
            (encode_request(Request::SignRequest(request)), false),
            (vec![11], false),
            (vec![17], false),
            (
                encode_request(Request::Extension(Extension {
                    name: "query".into(),
                    details: Vec::new().into(),
                })),
                true,
            ),
        ];
        for (request, extension_failure) in cases {
            let mut client = UnixStream::connect(broker.socket_path()).unwrap();
            write_frame(&mut client, &request).unwrap();
            let response = read_response(&mut client);
            assert!(
                matches!(response, Response::ExtensionFailure) == extension_failure,
                "unexpected response: {response:?}"
            );
            assert!(read_frame(&mut client).unwrap().is_none());
        }

        let mut oversized = UnixStream::connect(broker.socket_path()).unwrap();
        oversized
            .write_all(&((MAX_AGENT_FRAME as u32) + 1).to_be_bytes())
            .unwrap();
        assert!(read_frame(&mut oversized).unwrap().is_none());
    }

    #[test]
    fn broker_bounds_idle_clients_and_drop_closes_them() {
        let temp = tempfile::tempdir().unwrap();
        let ambient_socket = temp.path().join("ambient.sock");
        let _ambient = UnixListener::bind(&ambient_socket).unwrap();
        let (_, source) = key(41);
        let (_, destination) = key(42);
        let broker =
            ConstrainedAgentBroker::start_with_socket(ambient_socket, policy(source, destination))
                .unwrap();
        let path = broker.socket_path().to_path_buf();
        let mut clients = Vec::new();
        for _ in 0..MAX_BROKER_CONNECTIONS {
            let mut client = UnixStream::connect(&path).unwrap();
            client.write_all(&[0]).unwrap(); // keep each worker waiting on its header
            clients.push(client);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while broker
            .connections
            .streams
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
            < MAX_BROKER_CONNECTIONS
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            broker
                .connections
                .streams
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            MAX_BROKER_CONNECTIONS
        );
        let mut excess = UnixStream::connect(&path).unwrap();
        excess
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        excess.write_all(&[0]).unwrap();
        assert_closed(&mut excess);

        drop(broker);
        assert!(!path.exists());
        for mut client in clients {
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_closed(&mut client);
        }
    }
}
