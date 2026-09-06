//! Background return connections owned by a persistence scope. Settings are
//! durable; each endpoint's process and advertisement exist only while enabled.
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
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

const VERSION: u16 = 2;
const SOCKET: &[u8] = b".recv";
const LOCK: &[u8] = b".recv-lock";
const RECORD: &[u8] = b".recv-json";
const STOP_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const CLOSING: &str = ".syq-persistence-closing";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    pub version: u16,
    pub enabled: bool,
    pub name: String,
    pub cwd: PathBuf,
    pub root: Option<PathBuf>,
    pub max_bytes: u64,
    pub max_entries: u64,
    pub max_delete: u64,
}

#[derive(Parser)]
#[command(
    name = "syq recv",
    about = "Configure background receiving for persistent SSH connections. Copies are accepted automatically from connected server accounts."
)]
struct ReceiveCommand {
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Enable receiving and optionally change its global settings (enabled by default)
    On(Configure),
    /// Disable receiving and stop its background connections; keep ordinary persistence
    Off,
    /// Show receiving settings and background connection state
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Wait until the receiving connection through HOST is ready
    Wait {
        host: String,
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
}
#[derive(Args, Default)]
struct Configure {
    /// Name advertised on servers (default: this machine's short hostname)
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

pub(crate) fn command_for_help() -> clap::Command {
    crate::help::configure(ReceiveCommand::command())
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
        version: VERSION,
        enabled: true,
        name,
        cwd,
        root: None,
        max_bytes: 100 * 1024 * 1024 * 1024,
        max_entries: 1_000_000,
        max_delete: 0,
    })
}
pub(crate) fn settings() -> Result<Settings> {
    let path = config_path()?;
    let bytes =
        match crate::delegation::read_private_regular(&path, "receive preferences", 16 * 1024) {
            Ok(bytes) => bytes,
            Err(error)
                if error.chain().any(|e| {
                    e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                return default_settings()
            }
            Err(error) => return Err(error),
        };
    let settings: Settings = serde_json::from_slice(&bytes)?;
    validate_settings(&settings)?;
    Ok(settings)
}
fn validate_settings(settings: &Settings) -> Result<()> {
    if settings.version != VERSION {
        bail!("unsupported receive preferences version; configure with a matching syq build");
    }
    crate::destination::validate_name(&settings.name)?;
    if !settings.cwd.is_absolute() || settings.cwd.to_str().is_none() || !settings.cwd.is_dir() {
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
fn save_settings(settings: &Settings) -> Result<()> {
    validate_settings(settings)?;
    let path = config_path()?;
    fs::create_dir_all(path.parent().unwrap())?;
    atomic_json(&path, settings)
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
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRequest {
    version: u16,
    stop: bool,
}
fn status(control: &Path, stop: bool) -> Result<Status> {
    let mut socket = UnixStream::connect(suffixed(control, SOCKET))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    crate::destination::write_message(
        &mut socket,
        &LocalRequest {
            version: VERSION,
            stop,
        },
    )?;
    let result: Status = crate::destination::read_message(&mut socket)?;
    if result.version != VERSION {
        bail!("unsupported background receive protocol; stop its original build before upgrading");
    }
    Ok(result)
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
fn ensure_inner(control: &Path, remote: &crate::conn::RemoteSpec) -> Result<()> {
    if !settings()?.enabled {
        return Ok(());
    }
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    if scope.join(CLOSING).exists() {
        return Ok(());
    }
    if crate::persistence::is_global_scope(scope)? && !crate::persistence::global_enabled()? {
        return Ok(());
    }
    if is_running(control) {
        if status(control, false).is_ok_and(|state| {
            state.identity != crate::identity::build() || state.connection.phase == "failed"
        }) {
            stop_inner(control, false)?;
        } else {
            return Ok(());
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
    spawn(control)
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
pub(crate) fn summary(control: &Path) -> String {
    match status(control, false) {
        Ok(state) => format!(
            ", return {} ({}){}",
            state.name,
            state.connection.phase,
            state
                .connection
                .error
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        ),
        Err(_) if suffixed(control, RECORD).exists() => ", return inactive".into(),
        Err(_) => String::new(),
    }
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
fn run(control: &Path) -> Result<()> {
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    if scope.join(CLOSING).exists() {
        return Ok(());
    }
    let Some(_lock) = try_lock(control, true)? else {
        return Ok(());
    };
    if scope.join(CLOSING).exists() || !settings()?.enabled {
        return Ok(());
    }
    let spec = read_spec(control)?;
    let scope_meta = fs::metadata(scope)?;
    let scope_identity = (scope_meta.dev(), scope_meta.ino());
    let global = crate::persistence::is_global_scope(scope)?;
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
        let mut config = settings()?;
        let state = Arc::new(Mutex::new(ConnectionState::default()));
        let mut worker: Option<Worker> = None;
        let mut last_check = Instant::now() - Duration::from_secs(1);
        while !shutdown.load(Ordering::Acquire) {
            if last_check.elapsed() >= Duration::from_secs(1) {
                if !fs::metadata(scope).is_ok_and(|m| (m.dev(), m.ino()) == scope_identity)
                    || scope.join(CLOSING).exists()
                    || (global && !crate::persistence::global_enabled()?)
                {
                    break;
                }
                let updated = settings()?;
                if !updated.enabled {
                    break;
                }
                if updated != config {
                    worker.take();
                    config = updated;
                }
                if worker.is_none() {
                    let stop = Arc::new(AtomicBool::new(false));
                    let (thread_stop, thread_state, thread_spec, thread_config) =
                        (stop.clone(), state.clone(), spec.clone(), config.clone());
                    let thread = std::thread::spawn(move || {
                        let result = crate::destination::serve_background(
                            thread_config,
                            thread_spec,
                            thread_stop,
                            thread_state.clone(),
                        );
                        if let Err(error) = &result {
                            *thread_state.lock().unwrap() = ConnectionState {
                                phase: "failed".into(),
                                error: Some(format!("{error:#}")),
                                ssh_pid: None,
                            };
                        }
                        result
                    });
                    worker = Some(Worker {
                        stop,
                        thread: Some(thread),
                    });
                }
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
                            let response = Status {
                                version: VERSION,
                                identity: crate::identity::build().into(),
                                pid: std::process::id(),
                                endpoint: spec.endpoint.label(),
                                name: config.name.clone(),
                                connection: state.lock().unwrap().clone(),
                            };
                            let _ = crate::destination::write_message(&mut client, &response);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(worker);
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
    let mut config = settings()?;
    config.enabled = true;
    if let Some(name) = options.name {
        config.name = name;
    }
    if let Some(cwd) = options.cwd {
        config.cwd = fs::canonicalize(cwd)?;
        config.root = None;
    }
    if let Some(root) = options.root {
        config.cwd = fs::canonicalize(root)?;
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
    save_settings(&config)?;
    // Revoke the old policy before returning; wait cannot accidentally report
    // readiness from a connection still using the previous name or directory.
    for control in all_controls()? {
        stop_inner(&control, false)?;
        if read_spec(&control).is_ok() {
            spawn(&control)?;
        }
    }
    println!("Receiving is on: {} (automatic approval)", config.name);
    println!("cwd: {}", config.cwd.display());
    if let Some(root) = config.root {
        println!("root: {}", root.display());
    }
    println!(
        "Applies to persistent syq SSH connections; use syq persist on to enable persistence."
    );
    Ok(())
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
        "recv" => Some((|| {
            let matches = command_for_help()
                .try_get_matches_from(&argv[1..])
                .unwrap_or_else(|e| e.exit());
            match ReceiveCommand::from_arg_matches(&matches)?.action {
                Action::On(options) => configure(options)?,
                Action::Off => {
                    let mut config = settings()?;
                    config.enabled = false;
                    save_settings(&config)?;
                    for control in all_controls()? {
                        stop_inner(&control, false)?;
                    }
                    println!("Receiving is off; ordinary SSH persistence is unchanged");
                }
                Action::Status { json } => {
                    let config = settings()?;
                    let connections = statuses()?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string(
                                &serde_json::json!({ "settings": config, "connections": connections })
                            )?
                        );
                    } else {
                        println!(
                            "Receiving is {}: {} (automatic approval)",
                            if config.enabled { "on" } else { "off" },
                            config.name
                        );
                        println!("cwd: {}", config.cwd.display());
                        if let Some(root) = config.root {
                            println!("root: {}", root.display());
                        }
                        for state in connections {
                            println!(
                                "  {}: {}{}",
                                state.endpoint,
                                state.connection.phase,
                                state
                                    .connection
                                    .error
                                    .map(|e| format!(" ({e})"))
                                    .unwrap_or_default()
                            );
                        }
                    }
                }
                Action::Wait { host, timeout } => {
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
                        if states.iter().any(|s| s.connection.phase == "online") {
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
        })()),
        _ => None,
    }
}
