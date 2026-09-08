//! Background return connections owned by a persistence scope. Settings are
//! durable; each endpoint's process and advertisement exist only while enabled.
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

const VERSION: u16 = 2; // Preserve the old daemon stop/status protocol.
const SETTINGS_VERSION: u16 = 3;
const PREFERENCES_VERSION: u16 = 4;
const MAX_PROFILES: usize = 32;
const SOCKET: &[u8] = b".recv";
const LOCK: &[u8] = b".recv-lock";
const RECORD: &[u8] = b".recv-json";
const STOP_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const CLOSING: &str = ".syq-persistence-closing";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub version: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    revision: u64,
    pub enabled: bool,
    pub name: String,
    pub cwd: PathBuf,
    pub root: Option<PathBuf>,
    pub max_bytes: u64,
    pub max_entries: u64,
    pub max_delete: u64,
    #[serde(default)]
    pub approval: crate::receive_approval::Mode,
    #[serde(default)]
    pub notifications: crate::receive_approval::Notifications,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Preferences {
    version: u16,
    // The first profile is the default for commands without --name.
    profiles: Vec<Settings>,
}
impl Preferences {
    fn enabled(&self) -> bool {
        self.profiles.iter().any(|p| p.enabled)
    }
    fn selected(&self, name: Option<&str>) -> Result<usize> {
        match name {
            Some(name) => self
                .profiles
                .iter()
                .position(|p| p.name == name)
                .with_context(|| {
                    format!("no receiving profile named {name}; use syq persist receive status")
                }),
            None => Ok(0),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "receive",
    about = "Configure background receiving for persistent SSH connections. Copies require local approval by default."
)]
pub(crate) struct ReceiveCommand {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand, Debug)]
enum Action {
    /// Show incoming copy and command requests awaiting approval on this machine
    Pending {
        #[arg(long)]
        json: bool,
        /// Wait for an incoming request, with a deadline
        #[arg(long)]
        wait: bool,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Allow one pending request using the ID from persist receive pending
    Approve { id: String },
    /// Deny one pending request using the ID from persist receive pending
    Deny { id: String },
    /// Enable or configure a receiving profile (without --name, use the first profile)
    On(Configure),
    /// Disable receiving and stop its background connections; keep ordinary persistence
    Off {
        /// Stop only this profile; without --name, stop all profiles
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove a saved receiving profile and stop its connections
    Remove { name: String },
    /// Show receiving settings and background connection state
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        name: Option<String>,
    },
    /// Wait until the receiving connection through HOST is ready
    Wait {
        host: String,
        /// Wait for this profile; otherwise wait for every enabled profile
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
}
#[derive(Args, Default, Debug)]
struct Configure {
    /// Require local approval for each copy, or explicitly trust connected servers
    #[arg(long = "approve", value_enum)]
    approval: Option<crate::receive_approval::Mode>,
    /// Show desktop prompts, or use only local pending/approve/deny commands
    #[arg(long = "notify", value_enum)]
    notifications: Option<crate::receive_approval::Notifications>,
    /// Create or update this named profile; omitted means the first profile
    #[arg(long)]
    name: Option<String>,
    /// Default destination directory; absolute paths and .. may select elsewhere
    #[arg(short = 'C', long, conflicts_with = "root")]
    cwd: Option<PathBuf>,
    /// Default directory and confinement boundary; refuse paths escaping it
    #[arg(long)]
    root: Option<PathBuf>,
    /// Maximum bytes one transfer may reserve/write (default: 100G)
    #[arg(long)]
    max_bytes: Option<String>,
    /// Maximum entries one transfer may touch (default: 1000000)
    #[arg(long)]
    max_entries: Option<u64>,
    /// Permit pruning up to N entries per transfer (default: 0)
    #[arg(long)]
    max_delete: Option<u64>,
}

pub(crate) fn config_path() -> Result<PathBuf> {
    Ok(crate::persistence::config_path()
        .context("HOME and XDG_CONFIG_HOME are unset")?
        .with_file_name("receive.json"))
}
fn default_settings() -> Result<Settings> {
    let cwd = fs::canonicalize(std::env::var_os("HOME").context("HOME is unset")?)?;
    let mut hostname = [0u8; 256];
    if unsafe { libc::gethostname(hostname.as_mut_ptr().cast(), hostname.len()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let name: String = hostname
        .iter()
        .copied()
        .take_while(|b| *b != 0 && *b != b'.')
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                b as char
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    crate::destination::validate_name(&name)?;
    Ok(Settings {
        version: SETTINGS_VERSION,
        revision: 0,
        enabled: true,
        name,
        cwd,
        root: None,
        max_bytes: 100 * 1024 * 1024 * 1024,
        max_entries: 1_000_000,
        max_delete: 0,
        approval: Default::default(),
        notifications: Default::default(),
    })
}
fn preferences() -> Result<Preferences> {
    let path = config_path()?;
    let bytes =
        match crate::delegation::read_private_regular(&path, "receive preferences", 512 * 1024) {
            Ok(bytes) => bytes,
            Err(error)
                if error.chain().any(|e| {
                    e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                return Ok(Preferences {
                    version: PREFERENCES_VERSION,
                    profiles: vec![default_settings()?],
                });
            }
            Err(error) => return Err(error),
        };
    decode_preferences(&bytes)
}
fn decode_preferences(bytes: &[u8]) -> Result<Preferences> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let preferences = match value["version"].as_u64() {
        Some(2 | 3) => {
            let mut settings: Settings = serde_json::from_value(value)?;
            if settings.version == 2 {
                settings.version = SETTINGS_VERSION;
                settings.approval = crate::receive_approval::Mode::Ask;
                settings.notifications = crate::receive_approval::Notifications::Desktop;
            }
            Preferences {
                version: PREFERENCES_VERSION,
                profiles: vec![settings],
            }
        }
        Some(4) => serde_json::from_value(value)?,
        _ => bail!("unsupported receive preferences version; use a matching syq build"),
    };
    validate_preferences(&preferences)?;
    Ok(preferences)
}
fn validate_preferences(preferences: &Preferences) -> Result<()> {
    if preferences.version != PREFERENCES_VERSION
        || preferences.profiles.is_empty()
        || preferences.profiles.len() > MAX_PROFILES
    {
        bail!("receive preferences must contain between 1 and {MAX_PROFILES} profiles");
    }
    let mut names = std::collections::HashSet::new();
    for profile in &preferences.profiles {
        validate_settings(profile)?;
        if !names.insert(&profile.name) {
            bail!("duplicate receiving profile {}", profile.name);
        }
    }
    Ok(())
}
pub(crate) fn enabled() -> Result<bool> {
    Ok(preferences()?.enabled())
}
fn validate_settings(settings: &Settings) -> Result<()> {
    if settings.version != SETTINGS_VERSION {
        bail!("unsupported receive preferences version; configure with a matching syq build");
    }
    crate::destination::validate_name(&settings.name)?;
    if !settings.cwd.is_absolute() || settings.cwd.to_str().is_none() {
        bail!("receiving working directory must be an existing absolute UTF-8 directory");
    }
    if settings
        .root
        .as_ref()
        .is_some_and(|root| root != &settings.cwd)
    {
        bail!("receiving root must also be the working directory");
    }
    if settings.max_bytes == 0
        || settings.max_bytes > crate::delegation::MAX_COPY_BYTES
        || settings.max_entries == 0
        || settings.max_entries > crate::delegation::MAX_ENTRIES
    {
        bail!("invalid receiving limits");
    }
    Ok(())
}
fn save_settings(settings: &Preferences) -> Result<()> {
    validate_preferences(settings)?;
    let path = config_path()?;
    fs::create_dir_all(path.parent().unwrap())?;
    atomic_json(&path, settings)
}
fn settings_lock() -> Result<File> {
    let path = config_path()?.with_file_name("receive.lock");
    fs::create_dir_all(path.parent().unwrap())?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        bail!("receive preferences lock must be owned and private");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("receive preferences are being changed; retry shortly");
    }
    Ok(file)
}
fn current_settings_exist() -> Result<bool> {
    let path = config_path()?;
    match crate::delegation::read_private_regular(&path, "receive preferences", 512 * 1024) {
        Ok(bytes) => Ok(
            serde_json::from_slice::<serde_json::Value>(&bytes)?["version"] == PREFERENCES_VERSION,
        ),
        Err(error)
            if error.chain().any(|e| {
                e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            }) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
fn ensure_current_settings() -> Result<Preferences> {
    if current_settings_exist()? {
        return preferences();
    }
    let _lock = settings_lock()?;
    // Re-read under the writer lock. A concurrent receiving command may have already
    // changed policy; initialization must never overwrite that newer choice.
    let config = preferences()?;
    if !current_settings_exist()? {
        atomic_json(&config_path()?, &config)?;
    }
    Ok(config)
}
fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("missing state parent")?)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}
fn suffixed(control: &Path, suffix: &[u8]) -> PathBuf {
    let mut bytes = control.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(suffix);
    PathBuf::from(OsString::from_vec(bytes))
}
pub(crate) fn owned_name(name: &[u8]) -> Option<&[u8]> {
    name.strip_suffix(SOCKET)
        .or_else(|| name.strip_suffix(LOCK))
        .or_else(|| name.strip_suffix(RECORD))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceSpec {
    version: u16,
    identity: String,
    pub endpoint: crate::persistence::EndpointRecord,
    /// A quoted helper launcher with no arguments; append only shell-quoted arguments.
    pub program: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ConnectionState {
    pub phase: String,
    pub error: Option<String>,
    pub ssh_pid: Option<u32>,
}
impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            phase: "starting".into(),
            error: None,
            ssh_pid: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Status {
    version: u16,
    identity: String,
    pid: u32,
    endpoint: String,
    name: String,
    connection: ConnectionState,
    #[serde(default)]
    approval: Option<crate::receive_approval::Mode>,
    #[serde(default)]
    pending: Vec<crate::receive_approval::Summary>,
    #[serde(default)]
    decision_error: Option<String>,
    #[serde(default)]
    profiles: Vec<ProfileStatus>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProfileStatus {
    settings: Settings,
    connection: ConnectionState,
    pending: Vec<crate::receive_approval::Summary>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRequest {
    version: u16,
    stop: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<Decision>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    retry: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: String,
    allow: bool,
    #[serde(
        default,
        skip_serializing_if = "crate::receive_approval::Kind::is_copy"
    )]
    kind: crate::receive_approval::Kind,
}
fn status(control: &Path, stop: bool) -> Result<Status> {
    query(control, stop, None)
}
fn query(control: &Path, stop: bool, decision: Option<Decision>) -> Result<Status> {
    query_retry(control, stop, decision, false)
}
fn query_retry(
    control: &Path,
    stop: bool,
    decision: Option<Decision>,
    retry: bool,
) -> Result<Status> {
    let mut socket = UnixStream::connect(suffixed(control, SOCKET))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    crate::destination::write_message(
        &mut socket,
        &LocalRequest {
            version: VERSION,
            stop,
            decision,
            retry,
        },
    )?;
    let result: Status = read_status(&mut socket)?;
    if result.version != VERSION {
        bail!("unsupported background receive protocol; stop its original build before upgrading");
    }
    Ok(result)
}
// Status contains up to 32 full approval summaries, both aggregated and per
// profile. Keep its local-only bound separate from the remote request envelope.
const MAX_STATUS: usize = 16 * 1024 * 1024;
fn read_status(reader: &mut impl Read) -> Result<Status> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_STATUS {
        bail!("invalid receiving status size");
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn write_status(writer: &mut impl Write, status: &Status) -> Result<()> {
    let bytes = serde_json::to_vec(status)?;
    if bytes.len() > MAX_STATUS {
        bail!("receiving status exceeds size limit");
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

fn try_lock(control: &Path, create: bool) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(suffixed(control, LOCK))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        bail!("background receiving lock must be owned and private");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error.into())
}
pub(crate) fn is_running(control: &Path) -> bool {
    matches!(try_lock(control, false), Ok(None))
}
fn read_spec(control: &Path) -> Result<ServiceSpec> {
    let bytes = crate::delegation::read_private_regular(
        &suffixed(control, RECORD),
        "background receiving endpoint",
        64 * 1024,
    )?;
    let spec: ServiceSpec = serde_json::from_slice(&bytes)?;
    if spec.version != VERSION || spec.identity != crate::identity::build() {
        bail!("background receiving build changed; connect to the server with the current syq build to restart it");
    }
    Ok(spec)
}

/// Called after a successful ordinary persistent SSH control connection. A
/// failed return setup is visible but does not invalidate that ordinary copy.
pub(crate) fn ensure(control: &Path, remote: &crate::conn::RemoteSpec) {
    if let Err(error) = ensure_inner(control, remote) {
        crate::output::diagnostic!(
            "syq: background receiving through {}: {error:#}",
            remote.label()
        );
    }
}
/// Return readiness for one owned endpoint; do not restart a healthy service.
pub(crate) fn ensure_ready(
    control: &Path,
    remote: &crate::conn::RemoteSpec,
    timeout: Duration,
) -> Result<Option<Vec<String>>> {
    if !ensure_inner(control, remote)? {
        return Ok(None);
    }
    let deadline = Instant::now() + timeout;
    let mut progress = Instant::now();
    loop {
        let observed = match status(control, false) {
            Ok(state) if state.connection.phase == "online" => {
                return Ok(Some(if state.profiles.is_empty() {
                    vec![state.name]
                } else {
                    state
                        .profiles
                        .iter()
                        .map(|p| p.settings.name.clone())
                        .collect()
                }))
            }
            Ok(state) => {
                let observed = format!(
                    "{}{}",
                    state.connection.phase,
                    state
                        .connection
                        .error
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                );
                if state.connection.phase == "failed" {
                    bail!("{}: {observed}", remote.label());
                }
                observed
            }
            Err(error) => format!("receiving is starting or unavailable: {error:#}"),
        };
        if Instant::now() >= deadline {
            bail!("{} is not ready: {observed}; check syq persist status (background reconnects continue while enabled)", remote.label());
        }
        if progress.elapsed() >= Duration::from_secs(5) {
            crate::output::diagnostic!("syq: waiting for {}: {observed}", remote.label());
            progress = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) struct ReceivingStatus {
    pub name: String,
    pub connection: ConnectionState,
    pub profiles: Vec<NamedConnection>,
}
#[derive(Serialize)]
pub(crate) struct NamedConnection {
    pub name: String,
    pub connection: ConnectionState,
}
pub(crate) fn connection_status(control: &Path) -> Option<ReceivingStatus> {
    status(control, false).ok().map(|s| ReceivingStatus {
        name: s.name,
        connection: s.connection,
        profiles: s
            .profiles
            .into_iter()
            .map(|p| NamedConnection {
                name: p.settings.name,
                connection: p.connection,
            })
            .collect(),
    })
}
pub(crate) fn profile_names() -> Vec<String> {
    preferences()
        .map(|p| p.profiles.into_iter().map(|p| p.name).collect())
        .unwrap_or_default()
}

fn ensure_inner(control: &Path, remote: &crate::conn::RemoteSpec) -> Result<bool> {
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    // Ephemeral scopes only reuse forward SSH connections. Do not read or
    // create receiving preferences for them.
    if !crate::persistence::is_global_scope(scope)? || !crate::persistence::global_enabled()? {
        return Ok(false);
    }
    if scope.join(CLOSING).exists() {
        bail!("persistence scope is closing");
    }
    // Persist v4 before reuse so older binaries cannot overwrite multiple profiles.
    let config = ensure_current_settings()?;
    if !config.enabled() {
        return Ok(false);
    }
    if is_running(control) {
        let state = status(control, false)?;
        if state.identity != crate::identity::build() {
            stop_inner(control, false)?;
        } else {
            query_retry(control, false, None, true)?;
            return Ok(true);
        }
    }
    let spec = ServiceSpec {
        version: VERSION,
        identity: crate::identity::build().into(),
        endpoint: crate::persistence::EndpointRecord {
            user: remote.user.clone(),
            host: remote.host.clone(),
            port: remote.port,
        },
        program: remote.program_command(&[]),
    };
    atomic_json(&suffixed(control, RECORD), &spec)?;
    spawn(control)?;
    Ok(true)
}
fn spawn(control: &Path) -> Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--receive-service")
        .arg(control)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("start background receiving")?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
/// Stop before deleting a scope or changing its policy; wait for the daemon to
/// drop its lock only after its receiver thread and owned SSH groups have ended.
pub(crate) fn stop(control: &Path) -> Result<()> {
    stop_inner(control, true)
}
fn stop_inner(control: &Path, remove_record: bool) -> Result<()> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    let mut progress = Instant::now();
    while is_running(control) {
        if Instant::now() >= deadline {
            bail!("background receiver did not stop: {}", control.display());
        }
        let _ = status(control, true);
        if progress.elapsed() >= Duration::from_secs(5) {
            crate::output::diagnostic!(
                "syq: waiting for background receiver {} to stop",
                control.display()
            );
            progress = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    for suffix in [SOCKET, RECORD] {
        if suffix == RECORD && !remove_record {
            continue;
        }
        match fs::remove_file(suffixed(control, suffix)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    // Keep the flock inode while the scope survives: a concurrently starting
    // daemon must never lock a replacement inode and become a second owner.
    if remove_record {
        match fs::remove_file(suffixed(control, LOCK)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

struct SocketCleanup {
    path: PathBuf,
    identity: (u64, u64),
}
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.identity) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
struct Worker {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<()>>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct ProfileWorker {
    config: Settings,
    state: Arc<Mutex<ConnectionState>>,
    approvals: Arc<crate::receive_approval::Queue>,
    _worker: Worker,
}
impl ProfileWorker {
    fn new(config: Settings, spec: ServiceSpec) -> Self {
        let state = Arc::new(Mutex::new(ConnectionState::default()));
        let approvals = Arc::new(crate::receive_approval::Queue::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_state, thread_approvals, thread_stop, thread_config) = (
            state.clone(),
            approvals.clone(),
            stop.clone(),
            config.clone(),
        );
        let thread = std::thread::spawn(move || {
            let result = if !thread_config.cwd.is_dir() {
                Err(anyhow::anyhow!(
                    "receiving directory is unavailable: {}",
                    thread_config.cwd.display()
                ))
            } else {
                crate::destination::serve_background(
                    thread_config,
                    spec,
                    thread_stop,
                    thread_state.clone(),
                    thread_approvals,
                )
            };
            if let Err(error) = &result {
                *thread_state.lock().unwrap() = ConnectionState {
                    phase: "failed".into(),
                    error: Some(format!("{error:#}")),
                    ssh_pid: None,
                };
            }
            result
        });
        Self {
            config,
            state,
            approvals,
            _worker: Worker {
                stop,
                thread: Some(thread),
            },
        }
    }
    fn snapshot(&self) -> ProfileStatus {
        ProfileStatus {
            settings: self.config.clone(),
            connection: self.state.lock().unwrap().clone(),
            pending: self.approvals.snapshots(),
        }
    }
}
fn reconcile(
    workers: &mut Vec<ProfileWorker>,
    config: &Preferences,
    spec: &ServiceSpec,
    retry: bool,
) {
    workers.retain(|worker| {
        config
            .profiles
            .iter()
            .any(|p| p.enabled && p == &worker.config)
            && !(retry && worker.state.lock().unwrap().phase == "failed")
    });
    for profile in config.profiles.iter().filter(|p| p.enabled) {
        if !workers.iter().any(|w| w.config.name == profile.name) {
            workers.push(ProfileWorker::new(profile.clone(), spec.clone()));
        }
    }
}
fn aggregate(profiles: &[ProfileStatus]) -> (String, ConnectionState) {
    let name = profiles
        .first()
        .map(|p| p.settings.name.clone())
        .unwrap_or_default();
    let connection = profiles
        .iter()
        .find(|p| p.connection.phase == "failed")
        .or_else(|| profiles.iter().find(|p| p.connection.phase != "online"))
        .or_else(|| profiles.first())
        .map(|p| p.connection.clone())
        .unwrap_or(ConnectionState {
            phase: "disabled".into(),
            error: None,
            ssh_pid: None,
        });
    (name, connection)
}
// Wait until each live supervisor has revoked changed/removed profiles. Healthy
// workers remain in the same process, preserving streams and pending approvals.
fn apply_preferences(config: &Preferences) -> Result<()> {
    for control in all_controls()? {
        if !config.enabled() {
            stop_inner(&control, false)?;
            continue;
        }
        if is_running(&control) {
            let state = status(&control, false)?;
            if state.identity != crate::identity::build() {
                stop_inner(&control, false)?;
            }
        }
        if !is_running(&control)
            && config.enabled()
            && crate::persistence::global_enabled()?
            && read_spec(&control).is_ok()
        {
            spawn(&control)?;
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        let mut progress = Instant::now();
        while is_running(&control) {
            let state = status(&control, false);
            let enabled: Vec<_> = config.profiles.iter().filter(|p| p.enabled).collect();
            if state.as_ref().is_ok_and(|state| {
                state.profiles.len() == enabled.len()
                    && enabled
                        .iter()
                        .all(|p| state.profiles.iter().any(|s| &s.settings == *p))
            }) {
                break;
            }
            if Instant::now() >= deadline {
                bail!("receiving profiles have not been applied; check syq persist receive status");
            }
            if progress.elapsed() >= Duration::from_secs(5) {
                crate::output::diagnostic!("syq: waiting for receiving profiles to be applied");
                progress = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Ok(())
}

fn run(control: &Path) -> Result<()> {
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    if scope.join(CLOSING).exists() || !crate::persistence::is_global_scope(scope)? {
        return Ok(());
    }
    let Some(_lock) = try_lock(control, true)? else {
        return Ok(());
    };
    if scope.join(CLOSING).exists() || !preferences()?.enabled() {
        return Ok(());
    }
    let spec = read_spec(control)?;
    let scope_meta = fs::metadata(scope)?;
    let scope_identity = (scope_meta.dev(), scope_meta.ino());
    let socket = suffixed(control, SOCKET);
    match fs::symlink_metadata(&socket) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(&socket)?,
        Ok(_) => bail!("unexpected entry at receiving control socket"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let meta = fs::symlink_metadata(&socket)?;
    let _cleanup = SocketCleanup {
        path: socket,
        identity: (meta.dev(), meta.ino()),
    };
    let shutdown = Arc::new(AtomicBool::new(false));
    let sigint = signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone())?;
    let sigterm = signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())?;
    let result = (|| {
        let mut workers = Vec::<ProfileWorker>::new();
        let mut config = preferences()?;
        let mut last_check = Instant::now() - Duration::from_secs(1);
        while !shutdown.load(Ordering::Acquire) {
            if !fs::metadata(scope).is_ok_and(|m| (m.dev(), m.ino()) == scope_identity)
                || scope.join(CLOSING).exists()
                || !crate::persistence::global_enabled()?
            {
                break;
            }
            if last_check.elapsed() >= Duration::from_millis(200) {
                config = preferences()?;
                reconcile(&mut workers, &config, &spec, false);
                last_check = Instant::now();
            }
            match listener.accept() {
                Ok((mut client, _)) => {
                    client.set_nonblocking(false)?;
                    client.set_read_timeout(Some(Duration::from_millis(200)))?;
                    client.set_write_timeout(Some(Duration::from_millis(200)))?;
                    if let Ok(request) = crate::destination::read_socket_message::<LocalRequest>(
                        &mut client,
                        Duration::from_millis(200),
                    ) {
                        if request.version == VERSION {
                            if request.stop {
                                shutdown.store(true, Ordering::Release);
                            }
                            if request.retry {
                                reconcile(&mut workers, &config, &spec, true);
                            }
                            let decision_error = request.decision.and_then(|decision| {
                                workers
                                    .iter()
                                    .find(|w| {
                                        w.approvals.snapshots().iter().any(|r| r.id == decision.id)
                                    })
                                    .context("approval is unknown, expired, or already answered")
                                    .and_then(|w| {
                                        w.approvals.decide(
                                            &decision.id,
                                            decision.allow,
                                            decision.kind,
                                        )
                                    })
                                    .err()
                                    .map(|e| e.to_string())
                            });
                            let profiles: Vec<_> =
                                workers.iter().map(ProfileWorker::snapshot).collect();
                            let (name, connection) = aggregate(&profiles);
                            let response = Status {
                                version: VERSION,
                                identity: crate::identity::build().into(),
                                pid: std::process::id(),
                                endpoint: spec.endpoint.label(),
                                name,
                                connection,
                                approval: profiles.first().map(|p| p.settings.approval),
                                pending: profiles.iter().flat_map(|p| p.pending.clone()).collect(),
                                profiles,
                                decision_error,
                            };
                            let _ = write_status(&mut client, &response);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(workers);
        Ok(())
    })();
    signal_hook::low_level::unregister(sigint);
    signal_hook::low_level::unregister(sigterm);
    result
}

fn all_controls() -> Result<Vec<PathBuf>> {
    crate::persistence::receiving_controls()
}
fn statuses() -> Result<Vec<Status>> {
    Ok(all_controls()?
        .into_iter()
        .filter_map(|control| {
            status(&control, false).ok().or_else(|| {
                read_spec(&control).ok().map(|spec| Status {
                    version: VERSION,
                    identity: spec.identity,
                    pid: 0,
                    endpoint: spec.endpoint.label(),
                    name: String::new(),
                    approval: None,
                    pending: Vec::new(),
                    decision_error: None,
                    profiles: Vec::new(),
                    connection: ConnectionState {
                        phase: "inactive".into(),
                        error: None,
                        ssh_pid: None,
                    },
                })
            })
        })
        .collect())
}
fn configure(options: Configure) -> Result<()> {
    let _lock = settings_lock()?;
    let existed = config_path()?.exists();
    let mut preferences = preferences()?;
    let index = if let Some(name) = options.name.as_deref() {
        crate::destination::validate_name(name)?;
        match preferences.profiles.iter().position(|p| p.name == name) {
            Some(index) => index,
            None => {
                let mut profile = default_settings()?;
                profile.name = name.into();
                if !existed {
                    preferences.profiles.clear();
                }
                preferences.profiles.push(profile);
                preferences.profiles.len() - 1
            }
        }
    } else {
        0
    };
    let config = &mut preferences.profiles[index];
    config.enabled = true;
    config.revision = config
        .revision
        .checked_add(1)
        .context("receiving profile revision exhausted")?;
    if let Some(mode) = options.approval {
        config.approval = mode;
    }
    if let Some(notifications) = options.notifications {
        config.notifications = notifications;
    }
    if let Some(name) = options.name {
        config.name = name;
    }
    if let Some(cwd) = options.cwd {
        config.cwd = fs::canonicalize(cwd)?;
        anyhow::ensure!(config.cwd.is_dir(), "--cwd must name a directory");
        config.root = None;
    }
    if let Some(root) = options.root {
        config.cwd = fs::canonicalize(root)?;
        anyhow::ensure!(config.cwd.is_dir(), "--root must name a directory");
        config.root = Some(config.cwd.clone());
    }
    if let Some(bytes) = options.max_bytes {
        config.max_bytes = crate::cli::parse_size(&bytes)?;
    }
    if let Some(entries) = options.max_entries {
        config.max_entries = entries;
    }
    if let Some(deletions) = options.max_delete {
        config.max_delete = deletions;
    }
    let config = config.clone();
    save_settings(&preferences)?;
    apply_preferences(&preferences)?;
    crate::output::human_stdout!("Receiving is on: {} ({})", config.name, config.approval);
    crate::output::human_stdout!("cwd: {}", config.cwd.display());
    if let Some(root) = config.root {
        crate::output::human_stdout!("root: {}", root.display());
    }
    crate::output::human_stdout!(
        "Applies to persistent syq SSH connections; use syq persist on to enable persistence."
    );
    Ok(())
}
fn pending(json: bool, wait: bool, timeout: u64) -> Result<()> {
    if timeout == 0 || timeout > 3600 {
        bail!("timeout must be between 1 and 3600 seconds");
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut progress = Instant::now();
    loop {
        let requests: Vec<_> = statuses()?
            .into_iter()
            .flat_map(|status| status.pending)
            .collect();
        if !wait || !requests.is_empty() {
            if json {
                println!("{}", serde_json::to_string(&requests)?);
            } else if requests.is_empty() {
                crate::output::human_stdout!("No requests awaiting approval");
            } else {
                for request in requests {
                    crate::output::human_stdout!(
                        "{}\n{}\nNotification: {}\n",
                        request.id,
                        request.description(),
                        request.notification
                    );
                }
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for approval requests: none pending");
        }
        if progress.elapsed() >= Duration::from_secs(5) {
            crate::output::diagnostic!("syq: waiting for incoming requests: none pending");
            progress = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn decide(id: &str, allow: bool) -> Result<()> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("use the complete request ID from syq persist receive pending");
    }
    for control in all_controls()? {
        let Ok(state) = status(&control, false) else {
            continue;
        };
        if let Some(request) = state.pending.iter().find(|request| request.id == id) {
            let response = query(
                &control,
                false,
                Some(Decision {
                    id: id.into(),
                    allow,
                    kind: request.kind(),
                }),
            )?;
            if let Some(error) = response.decision_error {
                bail!("{error}");
            }
            crate::output::human_stdout!("{} {id}", if allow { "Approved" } else { "Denied" });
            return Ok(());
        }
    }
    bail!("approval is unknown, expired, or already answered")
}

pub(crate) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    match argv.get(1).and_then(|s| s.to_str())? {
        "--receive-service" => Some((|| {
            if argv.len() != 3 {
                bail!("receive service needs its control path");
            }
            run(Path::new(&argv[2]))?;
            Ok(0)
        })()),
        _ => None,
    }
}

pub(crate) fn run_command(command: ReceiveCommand) -> Result<i32> {
    match command.action {
        Action::On(options) => configure(options)?,
        Action::Pending {
            json,
            wait,
            timeout,
        } => pending(json, wait, timeout)?,
        Action::Approve { id } => decide(&id, true)?,
        Action::Deny { id } => decide(&id, false)?,
        Action::Off { name } => {
            let _lock = settings_lock()?;
            let mut config = preferences()?;
            if let Some(name) = name {
                let index = config.selected(Some(&name))?;
                config.profiles[index].enabled = false;
            } else {
                for profile in &mut config.profiles {
                    profile.enabled = false;
                }
            }
            save_settings(&config)?;
            apply_preferences(&config)?;
            crate::output::human_stdout!(
                "Selected receiving profiles are off; ordinary SSH persistence is unchanged"
            );
        }
        Action::Remove { name } => {
            let _lock = settings_lock()?;
            let mut config = preferences()?;
            let index = config.selected(Some(&name))?;
            if config.profiles.len() == 1 {
                bail!(
                    "cannot remove the last receiving profile; use syq persist receive off instead"
                );
            }
            config.profiles.remove(index);
            save_settings(&config)?;
            apply_preferences(&config)?;
            crate::output::human_stdout!("Removed receiving profile {name}");
        }
        Action::Status { json, name } => {
            let config = preferences()?;
            if let Some(name) = name.as_deref() {
                config.selected(Some(name))?;
            }
            let mut connections = statuses()?;
            if let Some(name) = name.as_ref() {
                connections.retain_mut(|s| {
                    if s.profiles.is_empty() {
                        return &s.name == name;
                    }
                    s.profiles.retain(|p| &p.settings.name == name);
                    if s.profiles.is_empty() {
                        return false;
                    }
                    (s.name, s.connection) = aggregate(&s.profiles);
                    s.approval = s.profiles.first().map(|p| p.settings.approval);
                    s.pending = s.profiles.iter().flat_map(|p| p.pending.clone()).collect();
                    true
                });
            }
            let selected: Vec<_> = config
                .profiles
                .iter()
                .filter(|p| name.as_ref().is_none_or(|n| n == &p.name))
                .collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({ "settings": selected[0], "profiles": selected, "connections": connections })
                    )?
                );
            } else {
                for config in selected {
                    crate::output::human_stdout!(
                        "Receiving is {}: {} ({})",
                        if config.enabled { "on" } else { "off" },
                        config.name,
                        config.approval
                    );
                    crate::output::human_stdout!("cwd: {}", config.cwd.display());
                    if let Some(root) = &config.root {
                        crate::output::human_stdout!("root: {}", root.display());
                    }
                }
                for state in connections {
                    if state.profiles.is_empty() {
                        crate::output::human_stdout!(
                            "  {}: {}{}",
                            state.endpoint,
                            state.connection.phase,
                            state
                                .connection
                                .error
                                .as_ref()
                                .map(|e| format!(" ({e})"))
                                .unwrap_or_default()
                        );
                    }
                    for profile in state
                        .profiles
                        .iter()
                        .filter(|p| name.as_ref().is_none_or(|n| n == &p.settings.name))
                    {
                        crate::output::human_stdout!(
                            "  {} @{}: {} ({}, {} pending){}",
                            state.endpoint,
                            profile.settings.name,
                            profile.connection.phase,
                            profile.settings.approval,
                            profile.pending.len(),
                            profile
                                .connection
                                .error
                                .as_ref()
                                .map(|e| format!(" ({e})"))
                                .unwrap_or_default()
                        );
                    }
                }
            }
        }
        Action::Wait {
            host,
            name,
            timeout,
        } => {
            let config = preferences()?;
            if let Some(name) = name.as_deref() {
                config.selected(Some(name))?;
            }
            let names: Vec<_> = config
                .profiles
                .iter()
                .filter(|p| p.enabled && name.as_ref().is_none_or(|n| n == &p.name))
                .map(|p| p.name.clone())
                .collect();
            if names.is_empty() {
                bail!("no selected receiving profiles are enabled");
            }
            if timeout == 0 || timeout > 3600 {
                bail!("timeout must be between 1 and 3600 seconds");
            }
            let deadline = Instant::now() + Duration::from_secs(timeout);
            let mut progress = Instant::now();
            loop {
                let states: Vec<_> = statuses()?
                    .into_iter()
                    .filter(|s| s.endpoint == host)
                    .collect();
                if names.iter().all(|name| {
                    states.iter().any(|s| {
                        if s.profiles.is_empty() {
                            s.name == *name && s.connection.phase == "online"
                        } else {
                            s.profiles
                                .iter()
                                .any(|p| p.settings.name == *name && p.connection.phase == "online")
                        }
                    })
                }) {
                    break;
                }
                let observed = states
                    .iter()
                    .map(|s| format!("{} {:?}", s.connection.phase, s.connection.error))
                    .collect::<Vec<_>>()
                    .join(", ");
                let observed = if observed.is_empty() {
                    "no connection; connect with syq while persistence is on"
                } else {
                    &observed
                };
                if Instant::now() >= deadline {
                    bail!("timed out waiting for return connection through {host}: {observed}");
                }
                if progress.elapsed() >= Duration::from_secs(5) {
                    crate::output::diagnostic!(
                        "syq: waiting for receiving through {host}: {observed}"
                    );
                    progress = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_profile_status_exceeds_remote_envelope_but_stays_bounded() {
        let config =
            decode_preferences(include_bytes!("../tests/fixtures/receive-v3-v0.5.1.json")).unwrap();
        let profiles: Vec<_> = (0..MAX_PROFILES)
            .map(|i| {
                let mut settings = config.profiles[0].clone();
                settings.name = format!("profile-{i}");
                ProfileStatus {
                    settings,
                    pending: Vec::new(),
                    connection: ConnectionState {
                        phase: "failed".into(),
                        error: Some("e".repeat(8192)),
                        ssh_pid: None,
                    },
                }
            })
            .collect();
        let (name, connection) = aggregate(&profiles);
        let status = Status {
            version: VERSION,
            identity: "test".into(),
            pid: 1,
            endpoint: "server".into(),
            name,
            connection,
            approval: None,
            pending: Vec::new(),
            decision_error: None,
            profiles,
        };
        let mut bytes = Vec::new();
        write_status(&mut bytes, &status).unwrap();
        assert!(bytes.len() > 256 * 1024);
        let decoded = read_status(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.profiles.len(), MAX_PROFILES);
        assert_eq!(
            decoded.profiles[31]
                .connection
                .error
                .as_ref()
                .unwrap()
                .len(),
            8192
        );
        for size in [0, MAX_STATUS as u32 + 1] {
            assert!(read_status(&mut size.to_be_bytes().as_slice()).is_err());
        }
    }

    #[test]
    fn released_copy_decision_remains_copy_only() {
        // Actual v0.4.0 client bytes checked by tests/receive-control-compat.py.
        let old = include_str!("../tests/fixtures/receive-copy-decision-v0.4.0.json").trim();
        let request: LocalRequest = serde_json::from_str(old).unwrap();
        assert_eq!(
            request.decision.as_ref().unwrap().kind,
            crate::receive_approval::Kind::Copy
        );
        assert_eq!(serde_json::to_string(&request).unwrap(), old);
    }

    #[test]
    fn stop_and_status_preserve_the_previous_daemon_request_format() {
        // PR #233 (34eba8d) rejects unknown LocalRequest fields. Keep these
        // bytes unchanged so the current binary can stop an older daemon.
        for (stop, old) in [
            (true, r#"{"version":2,"stop":true}"#),
            (false, r#"{"version":2,"stop":false}"#),
        ] {
            let request = LocalRequest {
                version: VERSION,
                stop,
                decision: None,
                retry: false,
            };
            assert_eq!(serde_json::to_string(&request).unwrap(), old);
            let decoded: LocalRequest = serde_json::from_str(old).unwrap();
            assert_eq!(decoded.stop, stop);
            assert!(decoded.decision.is_none());
        }
    }
}
