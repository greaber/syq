//! Background return connections owned by a persistence scope. Settings are
//! durable; each endpoint's process and advertisement exist only while enabled.
pub(crate) mod provider;
pub(crate) mod switch;

use crate::persistence::Domain;
use crate::process::CommandExt as _;
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
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

const VERSION: u16 = 2; // Preserve the old daemon stop/status protocol.
const SETTINGS_VERSION: u16 = 5;
const PREFERENCES_VERSION: u16 = 5;
const MAX_PROFILES: usize = 32;
const SOCKET: &[u8] = b".recv";
const LOCK: &[u8] = b".recv-lock";
const RECORD: &[u8] = b".recv-json";
const STOP_TIMEOUT: Duration = Duration::from_secs(15);
/// A service holds its lock from before it binds its socket until after it
/// removes it, so a locked control may briefly not answer. Between lock and
/// bind a starting service only reads its preferences and endpoint record;
/// a stopping one leaves at most one 1-second query unanswered.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(2);
const ANSWER_POLL: Duration = Duration::from_millis(20);
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
    #[serde(default)]
    pub cwd_explicit: bool,
    pub root: Option<PathBuf>,
    #[serde(default)]
    pub auto_approve_root: Option<PathBuf>,
    #[serde(default)]
    pub servers: Vec<String>,
    pub max_bytes: u64,
    pub max_entries: u64,
    pub max_delete: u64,
    // Accept legacy daemon status without persisting its blanket grant.
    #[serde(default, skip_serializing)]
    pub approval: crate::receive_approval::Mode,
    #[serde(default)]
    pub notifications: crate::receive_approval::Notifications,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}
impl Settings {
    // Notification delivery does not change the authority of a live receiver.
    // Keep the revision comparison: an intervening access change still revokes
    // sessions even when the other fields have returned to their old values.
    fn same_access(&self, other: &Self) -> bool {
        let mut comparable = self.clone();
        comparable.notifications = other.notifications;
        comparable == *other
    }
    fn allows_server(&self, endpoint: &str) -> bool {
        self.enabled && (self.servers.is_empty() || self.servers.iter().any(|s| s == endpoint))
    }
    fn print_paths(&self) {
        crate::output::command_human_stdout!(
            "cwd: {} ({})",
            self.cwd.display(),
            if self.cwd_explicit {
                "explicit"
            } else {
                "automatic"
            }
        );
        if let Some(root) = &self.root {
            crate::output::command_human_stdout!("root: {}", root.display());
        }
        match &self.auto_approve_root {
            Some(root) => {
                crate::output::command_human_stdout!("auto-approve-root: {}", root.display())
            }
            None => {
                crate::output::command_human_stdout!(
                    "auto-approve-root: none (ask for every download)"
                )
            }
        }
        crate::output::command_human_stdout!(
            "connections: {}",
            if self.servers.is_empty() {
                "all".into()
            } else {
                self.servers.join(", ")
            }
        );
    }
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
        /// Print the requests as JSON
        #[arg(long)]
        json: bool,
        /// Wait for an incoming request, with a deadline
        #[arg(long)]
        wait: bool,
        /// With --wait, give up after this many seconds
        #[arg(long, value_name = "SECONDS", default_value_t = 30)]
        timeout: u64,
    },
    /// Allow one pending request using the ID from persist receive pending
    Approve {
        /// Request ID shown by persist receive pending
        id: String,
        /// Remember this SSH account permission for future receiving connections or provider logins
        #[arg(long)]
        remember: bool,
    },
    /// List or remove account permissions remembered on this machine
    Permissions {
        #[command(subcommand)]
        action: PermissionAction,
    },
    /// Deny one pending request using the ID from persist receive pending
    Deny {
        /// Request ID shown by persist receive pending
        id: String,
    },
    /// Enable or configure a receiving profile (without --name, use the first profile)
    On(Configure),
    /// Turn receiving off and close its connections; other persistent connections stay open
    Off {
        /// Stop only this profile; without --name, stop all profiles
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove a saved receiving profile and stop its connections
    Remove {
        /// Profile to remove
        name: String,
    },
    /// Show receiving settings and background connection state
    Status {
        /// Print the settings and state as JSON
        #[arg(long)]
        json: bool,
        /// Show only this profile
        #[arg(long)]
        name: Option<String>,
    },
    /// Replace an SSH authorization provider from another build once idle,
    /// as a provider following a new build asks (`switch`)
    #[command(name = "switch-provider", hide = true)]
    SwitchProvider,
    /// Wait until the receiving connection through HOST is ready
    Wait {
        /// SSH server whose receiving connection to wait for
        host: String,
        /// Wait for this profile; otherwise wait for every enabled profile
        #[arg(long)]
        name: Option<String>,
        /// Give up after this many seconds
        #[arg(long, value_name = "SECONDS", default_value_t = 30)]
        timeout: u64,
    },
}
#[derive(Subcommand, Debug)]
enum PermissionAction {
    /// Show remembered SSH account permissions
    List {
        /// Print the permissions as JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove a remembered permission; sessions already logged in can continue
    Remove {
        /// Permission ID shown by persist receive permissions list
        id: String,
    },
}

#[derive(Args, Default, Debug)]
struct Configure {
    /// Automatically approve downloads confined to this directory
    #[arg(long, value_name = "DIR", conflicts_with = "no_auto_approve_root")]
    auto_approve_root: Option<PathBuf>,
    /// Require approval for every download again
    #[arg(long)]
    no_auto_approve_root: bool,
    /// Replace the allowed connection list and connect these endpoints now (repeat for several)
    #[arg(long, value_name = "ENDPOINT", conflicts_with = "all_connections")]
    connection: Vec<String>,
    /// Make this profile available through every connected SSH account
    #[arg(long)]
    all_connections: bool,
    /// Show desktop prompts, or use only local pending/approve/deny commands
    #[arg(long = "notify", value_enum, value_name = "MODE")]
    notifications: Option<crate::receive_approval::Notifications>,
    /// Create or update this named profile; omitted means the first profile
    #[arg(long)]
    name: Option<String>,
    /// Starting directory for downloads and commands; absolute paths and .. can still reach elsewhere
    #[arg(short = 'C', long, value_name = "DIR", conflicts_with = "auto_cwd")]
    cwd: Option<PathBuf>,
    /// Choose the starting directory automatically: the --root directory, else --auto-approve-root, else your home directory
    #[arg(long)]
    auto_cwd: bool,
    /// Allow downloads only inside DIR, even approved ones
    #[arg(long, value_name = "DIR", conflicts_with = "no_root")]
    root: Option<PathBuf>,
    /// Remove the --root restriction
    #[arg(long)]
    no_root: bool,
    /// Maximum bytes one transfer may write (default: 100G)
    #[arg(long, value_name = "SIZE")]
    max_bytes: Option<String>,
    /// Maximum entries one transfer may change (default: 1000000)
    #[arg(long, value_name = "N")]
    max_entries: Option<u64>,
    /// Permit pruning up to N entries per transfer (default: 0)
    #[arg(long, value_name = "N")]
    max_delete: Option<u64>,
}

pub(crate) fn config_path(domain: &Domain) -> Result<PathBuf> {
    domain.config_file("receive.json")
}
fn default_settings(domain: &Domain) -> Result<Settings> {
    let cwd = match std::env::var_os("HOME") {
        Some(home) => fs::canonicalize(home)?,
        None if !domain.is_default() => std::env::current_dir()?,
        None => bail!("HOME is unset"),
    };
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
        enabled: domain.is_default(),
        name,
        cwd,
        cwd_explicit: false,
        root: None,
        auto_approve_root: None,
        servers: Vec::new(),
        max_bytes: 100 * 1024 * 1024 * 1024,
        max_entries: 1_000_000,
        max_delete: 0,
        approval: Default::default(),
        notifications: Default::default(),
    })
}
fn preferences(domain: &Domain) -> Result<Preferences> {
    let path = config_path(domain)?;
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
                    profiles: vec![default_settings(domain)?],
                });
            }
            Err(error) => return Err(error),
        };
    decode_preferences(&bytes)
}
fn decode_preferences(bytes: &[u8]) -> Result<Preferences> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let legacy = matches!(value["version"].as_u64(), Some(2..=4));
    let mut preferences = match value["version"].as_u64() {
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
        Some(4 | 5) => serde_json::from_value(value)?,
        _ => bail!("unsupported receive preferences version; use a matching syq build"),
    };
    if legacy {
        preferences.version = PREFERENCES_VERSION;
        for profile in &mut preferences.profiles {
            if !matches!(profile.version, 2 | 3 | SETTINGS_VERSION) {
                bail!("unsupported receive profile version; use a matching syq build");
            }
            profile.version = SETTINGS_VERSION;
            profile.cwd_explicit = true;
            profile.approval = crate::receive_approval::Mode::Ask;
            profile.auto_approve_root = None;
            profile.servers.clear();
        }
    }
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
pub(crate) fn enabled_servers(domain: &Domain) -> Result<Vec<Vec<String>>> {
    Ok(preferences(domain)?
        .profiles
        .into_iter()
        .filter(|p| p.enabled)
        .map(|p| p.servers)
        .collect())
}
fn validate_settings(settings: &Settings) -> Result<()> {
    if settings.version != SETTINGS_VERSION {
        bail!("unsupported receive preferences version; configure with a matching syq build");
    }
    crate::destination::validate_name(&settings.name)?;
    if !settings.cwd.is_absolute() || settings.cwd.to_str().is_none() {
        bail!("receiving working directory must be an existing absolute UTF-8 directory");
    }
    for root in [&settings.root, &settings.auto_approve_root]
        .into_iter()
        .flatten()
    {
        if !root.is_absolute() || root.to_str().is_none() {
            bail!("receiving roots must be absolute UTF-8 directories");
        }
    }
    if settings
        .auto_approve_root
        .as_ref()
        .is_some_and(|root| root.parent().is_none())
    {
        bail!("automatic approval root must be below filesystem root");
    }
    if settings
        .root
        .as_ref()
        .is_some_and(|root| !settings.cwd.starts_with(root))
    {
        bail!("receiving working directory must be inside --root; use --auto-cwd or choose --cwd inside it");
    }
    for server in &settings.servers {
        if server.is_empty() || server.starts_with('-') || server.chars().any(char::is_whitespace) {
            bail!("--connection must name an SSH connection destination");
        }
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
fn save_settings(domain: &Domain, settings: &Preferences) -> Result<()> {
    validate_preferences(settings)?;
    let path = config_path(domain)?;
    if domain.is_default() {
        fs::create_dir_all(path.parent().unwrap())?;
    }
    atomic_json(&path, settings)
}
struct SettingsLock(File);
impl Drop for SettingsLock {
    fn drop(&mut self) {
        // A parallel fork retains the same open file description until exec.
        // Release writer ownership now, even if that temporary copy survives.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
fn settings_lock(domain: &Domain) -> Result<SettingsLock> {
    let path = config_path(domain)?.with_file_name("receive.lock");
    if domain.is_default() {
        fs::create_dir_all(path.parent().unwrap())?;
    }
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
    Ok(SettingsLock(file))
}
fn current_settings_exist(domain: &Domain) -> Result<bool> {
    let path = config_path(domain)?;
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
fn ensure_current_settings(domain: &Domain) -> Result<Preferences> {
    if current_settings_exist(domain)? {
        return preferences(domain);
    }
    let _lock = settings_lock(domain)?;
    // Re-read under the writer lock. A concurrent receiving command may have already
    // changed policy; initialization must never overwrite that newer choice.
    let config = preferences(domain)?;
    if !current_settings_exist(domain)? {
        atomic_json(&config_path(domain)?, &config)?;
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
    /// When the connection last started to log in.
    #[serde(skip)]
    pub attempted: Option<Instant>,
    /// When a failed connection tries again by itself, and the rest of the
    /// status's sentence about it. `shown` renders the time left.
    #[serde(skip)]
    pub retry: Option<(Instant, String)>,
}
impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            phase: "starting".into(),
            error: None,
            ssh_pid: None,
            attempted: None,
            retry: None,
        }
    }
}
impl ConnectionState {
    /// The state as a status shows it, with the time left before a retry.
    fn shown(&self) -> Self {
        let mut shown = self.clone();
        if let (Some(error), Some((at, rest))) = (&shown.error, &self.retry) {
            shown.error = Some(format!(
                "{error}; trying again in {}{rest}",
                crate::destination::retry_wait(at.saturating_duration_since(Instant::now()))
            ));
        }
        shown
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
    #[serde(default, skip_serializing)]
    approval: Option<crate::receive_approval::Mode>,
    #[serde(default)]
    pending: Vec<crate::receive_approval::Summary>,
    #[serde(default)]
    decision_error: Option<String>,
    #[serde(default)]
    profiles: Vec<ProfileStatus>,
    /// Requests in progress. Services from before syq followed updates
    /// cannot say, and a status for them has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    busy: Option<Busy>,
    /// The path the service follows to switch to a new syq build by itself
    /// (`switch`), absent when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    started_from: Option<String>,
    /// Its switch to a new build, while waiting for one or after one failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    switch: Option<switch::Report>,
    /// Whether it stops in answer to a `stop_if_idle` request.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stopping: bool,
}
/// What a receiving service has in progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Busy {
    /// Copies, commands and account logins in progress, apart from open
    /// account connections.
    pub(crate) requests: usize,
    /// Requests waiting for approval.
    pub(crate) pending: usize,
    /// Approved account connections open through it: each holds a request
    /// for as long as it lives, whether or not anything runs through it.
    #[serde(default)]
    pub(crate) accounts: usize,
}
impl Busy {
    pub(crate) fn idle(&self) -> bool {
        self.requests == 0 && self.pending == 0 && self.accounts == 0
    }
    /// What stopping it now cuts off, as "1 request in progress and 2
    /// requests waiting for approval". Account connections are named apart,
    /// `on` the server they were opened from when given.
    pub(crate) fn describe(&self, on: Option<&str>) -> String {
        let count = |count: usize, what: &str| {
            format!("{count} {what}{}", if count == 1 { "" } else { "s" })
        };
        let mut parts = Vec::new();
        if self.requests > 0 {
            parts.push(format!("{} in progress", count(self.requests, "request")));
        }
        if self.pending > 0 {
            parts.push(format!(
                "{} waiting for approval",
                count(self.pending, "request")
            ));
        }
        if self.accounts > 0 {
            parts.push(match on {
                Some(server) => format!(
                    "{} on {server}",
                    count(self.accounts, "approved account connection")
                ),
                None => count(self.accounts, "approved account connection"),
            });
        }
        parts.join(" and ")
    }
    /// For a service with open account connections, which do not end by
    /// themselves: that it waits for them, and what to run to switch now.
    /// None without any.
    pub(crate) fn accounts_note(&self, on: Option<&str>, fix: &str) -> Option<String> {
        (self.accounts > 0).then(|| {
            format!(
                "it waits for {} to close; `{fix}` switches now and closes {}",
                Busy {
                    requests: 0,
                    pending: 0,
                    ..*self
                }
                .describe(on),
                if self.accounts == 1 { "it" } else { "them" }
            )
        })
    }
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
    /// Restart failed connections now, whenever they last tried, as
    /// `persist connect` asks. Only a service of the same build receives it
    /// (`ensure_inner`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    restart: bool,
    /// Stop only if nothing is in progress, refusing new requests from then
    /// on, to switch to another build. Only a service whose status reports
    /// what it has in progress (`Status::busy`) receives it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stop_if_idle: bool,
}

/// What a request asks the service to do with its failed connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Retry {
    No,
    /// A command connected to the server: try again if a while has passed
    /// since the last attempt.
    IfDue,
    /// `persist connect`: start a failed connection over at once.
    Now,
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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    remember: bool,
}
fn status(control: &Path, stop: bool) -> Result<Status> {
    query(control, stop, None)
}
fn query(control: &Path, stop: bool, decision: Option<Decision>) -> Result<Status> {
    query_retry(control, stop, decision, Retry::No)
}
fn query_retry(
    control: &Path,
    stop: bool,
    decision: Option<Decision>,
    retry: Retry,
) -> Result<Status> {
    send(
        control,
        &LocalRequest {
            version: VERSION,
            stop,
            decision,
            retry: retry == Retry::IfDue,
            restart: retry == Retry::Now,
            stop_if_idle: false,
        },
    )
}
fn send(control: &Path, request: &LocalRequest) -> Result<Status> {
    let mut socket = UnixStream::connect(suffixed(control, SOCKET))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    crate::destination::write_message(&mut socket, request)?;
    let result: Status = read_status(&mut socket)?;
    if result.version != VERSION {
        bail!("unsupported background receive protocol; stop its original build before upgrading");
    }
    Ok(result)
}
/// Whether nothing answered on a control socket, as while a locked service
/// is starting or stopping, rather than the service replying with an error.
fn unanswered(error: &anyhow::Error) -> bool {
    use std::io::ErrorKind::*;
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                NotFound
                    | ConnectionRefused
                    | ConnectionReset
                    | BrokenPipe
                    | UnexpectedEof
                    | WouldBlock
                    | TimedOut
            )
        })
    })
}
/// Query the service holding this control's lock, waiting up to `timeout` for
/// it to answer while it starts or stops. None once no service holds the lock.
fn running_status(control: &Path, retry: Retry, timeout: Duration) -> Result<Option<Status>> {
    let deadline = Instant::now() + timeout;
    while is_running(control) {
        match query_retry(control, false, None, retry) {
            Ok(state) => return Ok(Some(state)),
            Err(error) if unanswered(&error) => {
                if Instant::now() >= deadline {
                    return Err(error.context(format!(
                        "receiving service is running but not answering at {}",
                        suffixed(control, SOCKET).display()
                    )));
                }
                std::thread::sleep(ANSWER_POLL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}
// Status contains up to 32 full approval summaries, both aggregated and per
// profile. Keep its local-only bound separate from the remote request envelope.
const MAX_STATUS: usize = 16 * 1024 * 1024;
fn read_status(reader: &mut impl Read) -> Result<Status> {
    crate::destination::read_framed(reader, MAX_STATUS, "receiving status")
}
fn write_status(writer: &mut impl Write, status: &Status) -> Result<()> {
    crate::destination::write_framed(writer, status, MAX_STATUS, "receiving status")
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
/// is_running and the provider's check probe a lock by taking it for a
/// moment. A service or provider that starts during such a probe would take
/// the probe for another owner, so it retries for longer than a probe holds
/// the lock before concluding that another copy is running.
const PROBE_GRACE: Duration = Duration::from_millis(100);
fn lock_for_start<T>(mut attempt: impl FnMut() -> Result<Option<T>>) -> Result<Option<T>> {
    let deadline = Instant::now() + PROBE_GRACE;
    loop {
        if let Some(lock) = attempt()? {
            return Ok(Some(lock));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
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

/// Called after a successful ordinary persistent SSH control connection to
/// start receiving through this endpoint when enabled and not running. A
/// failed return setup is visible but does not invalidate that ordinary copy.
/// Returns whether this call started a service process.
pub(crate) fn ensure(domain: &Domain, control: &Path, remote: &crate::conn::RemoteSpec) -> bool {
    match ensure_inner(domain, control, remote, Retry::IfDue, Replace::Leave) {
        Ok(Receiving::Started) => true,
        Ok(Receiving::Other {
            build,
            busy: Some(busy),
            follows_this_file,
        }) => {
            if !remote.quiet {
                crate::output::diagnostic!(
                    "syq: {}",
                    busy_notice(
                        &remote.label(),
                        &build,
                        &busy,
                        follows_this_file,
                        &connect_command(&remote.label(), domain.explicit_path())
                    )
                );
            }
            false
        }
        Ok(_) => false,
        Err(error) => {
            crate::output::diagnostic!(
                "syq: background receiving through {}: {error:#}",
                remote.label()
            );
            false
        }
    }
}
/// What a command says when a receiving service from another build keeps
/// running because it is busy. `fix` replaces it at once.
pub(crate) fn busy_notice(
    endpoint: &str,
    build: &str,
    busy: &Busy,
    follows_this_file: bool,
    fix: &str,
) -> String {
    // Open account connections do not end by themselves.
    if let Some(accounts) = busy.accounts_note(Some(endpoint), fix) {
        if busy.requests == 0 && busy.pending == 0 {
            return format!("receiving through {endpoint} keeps running syq {build}: {accounts}");
        }
    }
    let then = if follows_this_file {
        "it switches to this version by itself once nothing is in progress"
    } else {
        "once nothing is in progress, a syq command run here switches it to this version"
    };
    let mut notice = format!(
        "receiving through {endpoint} keeps running syq {build} for now, with {}; {then}",
        busy.describe(Some(endpoint)),
    );
    if busy.accounts > 0 {
        notice.push_str(&format!(
            "; `{fix}` switches now and closes the account connection{}",
            if busy.accounts == 1 { "" } else { "s" }
        ));
    }
    notice
}
/// Run by syq commands (`main`), so that the services an older syq left
/// running switch to a new build too, not only the one for the server a
/// command talks to. A service from another build is replaced by a detached
/// `persist connect --when-idle` of this build once idle, as a service's
/// own switch does, when it cannot follow its path by itself (it predates
/// that, or its path is gone), or when its path holds this command's own
/// file and its own switch failed. A command that finds every service
/// current reads one directory and each service's small record, and
/// contacts nothing; it contacts a stale one at most once a minute
/// (`claim_switch_attempt`), so a cooling down, busy or unresponsive
/// service costs commands nothing meanwhile. The exception is a service
/// whose switch waits for the user to log in: a command without a terminal
/// gives its claim back, so that the next one with a terminal can try at
/// once, and such commands each ask that service for its status, at most
/// 50 ms (`REFRESH_ANSWER`) and usually about 1 ms.
pub(crate) fn refresh_outdated(domain: &Domain, quiet: bool) {
    if !domain.enabled().unwrap_or(false) {
        return;
    }
    let scope = domain.runtime_path();
    let Ok(entries) = fs::read_dir(&scope) else {
        return;
    };
    /// Only the build; other fields are the service's own.
    #[derive(Deserialize)]
    struct Recorded {
        identity: String,
    }
    let interactive = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let mut notices = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(key) = name.as_bytes().strip_suffix(RECORD) else {
            continue;
        };
        let control = scope.join(std::ffi::OsStr::from_bytes(key));
        let outdated = crate::delegation::read_private_regular(
            &entry.path(),
            "background receiving endpoint",
            64 * 1024,
        )
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Recorded>(&bytes).ok())
        .is_some_and(|recorded| recorded.identity != crate::identity::build());
        if !outdated || !crate::persistence::claim_switch_attempt(&control, SWITCH_ATTEMPT_INTERVAL)
        {
            continue;
        }
        let Some(state) = status_by(&control, Instant::now() + refresh_answer()) else {
            continue;
        };
        if state.identity == crate::identity::build() || !busy_of(&state).idle() {
            continue;
        }
        let phase = switch_report(&control, &state).map(|report| report.phase);
        match switch::follows(state.started_from.as_deref()) {
            switch::Follows::OtherFile => continue,
            // It switches by itself, unless its switch failed.
            switch::Follows::ThisFile if !matches!(phase.as_deref(), Some("failed" | "login")) => {
                continue
            }
            _ => {}
        }
        // Logging in again after a login that needed the user is worth it
        // only with the user at hand, and no more than every ten minutes:
        // each attempt that fails is a failed login on the server.
        let login = phase.as_deref() == Some("login");
        if login {
            if !interactive || quiet {
                // Leave the next attempt to a command run in a terminal,
                // however soon it comes.
                crate::persistence::defer_switch_attempts(&control, Duration::ZERO);
                continue;
            }
            crate::persistence::defer_switch_attempts(&control, switch::LOGIN_RETRY);
        }
        match start_switch(domain, &state.endpoint) {
            Ok(()) => notices.push(if login {
                format!(
                    "logging in to {} in the background to switch receiving there to this version of syq; if your security key blinks, touch it",
                    state.endpoint
                )
            } else if state.busy.is_none() {
                // An older service cannot say whether a copy is in progress.
                format!(
                    "switching receiving through {}, which runs syq {}, to this version of syq in the background (a copy in progress through it would be interrupted); `syq persist status` shows how it goes",
                    state.endpoint, state.identity
                )
            } else {
                format!(
                    "switching receiving through {} to this version of syq in the background; `syq persist status` shows how it goes",
                    state.endpoint
                )
            }),
            Err(error) => record_attempt(
                &control,
                &Attempt::new("failed", Some(format!("could not start the switch: {error:#}"))),
            ),
        }
    }
    if !quiet {
        for notice in notices {
            crate::output::diagnostic!("syq: {notice}");
        }
    }
}

/// How long a command waits for a stale service's status. A healthy one
/// answers within a millisecond; one that does not is skipped until the
/// next claim (`claim_switch_attempt`).
const REFRESH_ANSWER: Duration = Duration::from_millis(50);
fn refresh_answer() -> Duration {
    // Tests on slow runners give stand-in services longer.
    #[cfg(debug_assertions)]
    if let Some(millis) = std::env::var("SYQ_TEST_REFRESH_ANSWER_MS")
        .ok()
        .and_then(|millis| millis.parse().ok())
    {
        return Duration::from_millis(millis);
    }
    REFRESH_ANSWER
}

/// The status of the service at `control`, if it answers by `deadline`:
/// connecting, asking and reading the answer all end by then.
fn status_by(control: &Path, deadline: Instant) -> Option<Status> {
    if !is_running(control) {
        return None;
    }
    let request = LocalRequest {
        version: VERSION,
        stop: false,
        decision: None,
        retry: false,
        restart: false,
        stop_if_idle: false,
    };
    crate::destination::local_exchange::<Status>(
        &suffixed(control, SOCKET),
        &request,
        deadline,
        MAX_STATUS,
        "receiving status",
    )
    .ok()
    .filter(|status| status.version == VERSION)
}

/// The last switch to a new build started for a connection, kept so that
/// status can say how it went even when the service it would replace cannot
/// (`refresh_outdated`, `persist connect --when-idle`). It is the content of
/// the connection's `.recv-lock`, which every syq version only locks and
/// removes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Attempt {
    /// `ATTEMPT_VERSION`; a reader ignores a record of another version.
    #[serde(default)]
    version: u16,
    build: String,
    /// `switching`, `failed`, or `login` (see `switch::Report`).
    phase: String,
    #[serde(default)]
    error: Option<String>,
    pid: u32,
}
const ATTEMPT_VERSION: u16 = 1;
impl Attempt {
    pub(crate) fn new(phase: &str, error: Option<String>) -> Self {
        Self {
            version: ATTEMPT_VERSION,
            build: crate::identity::build().into(),
            phase: phase.into(),
            error,
            pid: std::process::id(),
        }
    }
}
/// Record `attempt` for the connection at `control`, best effort.
pub(crate) fn record_attempt(control: &Path, attempt: &Attempt) {
    let _ = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(suffixed(control, LOCK))?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
        );
        file.set_len(0)?;
        file.write_all(&serde_json::to_vec(attempt)?)?;
        Ok(())
    })();
}
/// Forget the last switch's result, as after one that did not fail.
pub(crate) fn clear_attempt(control: &Path) {
    if let Ok(file) = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(suffixed(control, LOCK))
    {
        let _ = file.set_len(0);
    }
}
fn last_attempt(control: &Path) -> Option<Attempt> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(suffixed(control, LOCK))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(16 * 1024)
        .read_to_end(&mut bytes)
        .ok()?;
    serde_json::from_slice::<Attempt>(&bytes)
        .ok()
        .filter(|attempt| attempt.version == ATTEMPT_VERSION)
}
/// How a service's switch to another build is going: what it reports, or
/// for one that cannot say, the last switch a command started for it.
fn switch_report(control: &Path, state: &Status) -> Option<switch::Report> {
    if let Some(report) = &state.switch {
        return Some(report.clone());
    }
    let attempt = last_attempt(control)?;
    if attempt.build == state.identity {
        return None;
    }
    let (phase, error) = if attempt.phase == "switching" && !process_alive(attempt.pid) {
        (
            "failed".to_owned(),
            Some("the switch ended without a result".to_owned()),
        )
    } else {
        (attempt.phase, attempt.error)
    };
    Some(switch::Report {
        to: Some(attempt.build),
        phase,
        error,
    })
}
/// Whether process `pid` still runs, and is not a zombie.
fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0
        || (unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM))
    {
        return false;
    }
    #[cfg(target_os = "linux")]
    if fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with('Z'))
    }) {
        return false;
    }
    true
}

/// How often commands may start a switch for one connection.
const SWITCH_ATTEMPT_INTERVAL: Duration = Duration::from_secs(60);

/// Start `persist connect --when-idle` of this build for `endpoint`,
/// detached and without prompts: it reports a login that needs the user in
/// its status rather than asking.
fn start_switch(domain: &Domain, endpoint: &str) -> Result<()> {
    let mut command = match crate::process::started_from() {
        Some(path) => std::process::Command::new(path),
        None => crate::process::self_command()?,
    };
    command
        .args(switch_command(domain, endpoint))
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .env(switch::STARTED_BY_COMMAND, "1")
        .env("SSH_ASKPASS_REQUIRE", "never")
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
    let mut child = command.spawn_guarded()?;
    std::thread::spawn(move || {
        let _ = switch::wait_and_end_group(&mut child);
    });
    Ok(())
}

/// Whether a switch to this build should leave the service at `control`
/// running for now: one from another build that is busy, or that follows
/// another installed syq file by itself. Checked before logging in to the
/// server; the service itself decides again when asked to stop.
pub(crate) fn keeps_running(control: &Path) -> Option<Ready> {
    let state = running_status(control, Retry::No, ANSWER_TIMEOUT).ok()??;
    if state.identity == crate::identity::build() {
        return None;
    }
    if switch::follows_other_file(state.started_from.as_deref()) {
        return Some(Ready::Other {
            build: state.identity,
            busy: None,
            follows_this_file: false,
        });
    }
    let busy = busy_of(&state);
    (!busy.idle()).then(|| Ready::Other {
        follows_this_file: switch::follows(state.started_from.as_deref())
            == switch::Follows::ThisFile,
        build: state.identity,
        busy: Some(busy),
    })
}
/// What `persist connect` found.
pub(crate) enum Ready {
    /// Receiving is off for this endpoint.
    Off,
    /// Online as these receiving names.
    Online(Vec<String>),
    /// A service from another build keeps running (`Receiving::Other`).
    Other {
        build: String,
        busy: Option<Busy>,
        follows_this_file: bool,
    },
}
/// Return readiness for one owned endpoint; do not restart a healthy service.
pub(crate) fn ensure_ready(
    domain: &Domain,
    control: &Path,
    remote: &crate::conn::RemoteSpec,
    timeout: Duration,
    replace: Replace,
) -> Result<Ready> {
    match ensure_inner(domain, control, remote, Retry::Now, replace)? {
        Receiving::Off => return Ok(Ready::Off),
        Receiving::Other {
            build,
            busy,
            follows_this_file,
        } => {
            return Ok(Ready::Other {
                build,
                busy,
                follows_this_file,
            })
        }
        Receiving::Running | Receiving::Started => {}
    }
    let deadline = Instant::now() + timeout;
    let mut progress = Instant::now();
    loop {
        let observed = match status(control, false) {
            Ok(state) if state.connection.phase == "online" => {
                return Ok(Ready::Online(if state.profiles.is_empty() {
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
    /// The service's build, and what it says about switching to another.
    pub build: String,
    pub started_from: Option<String>,
    pub switch: Option<switch::Report>,
    pub busy: Option<Busy>,
}
#[derive(Serialize)]
pub(crate) struct NamedConnection {
    pub name: String,
    pub connection: ConnectionState,
}
pub(crate) fn connection_status(control: &Path) -> Option<ReceivingStatus> {
    status(control, false).ok().map(|s| ReceivingStatus {
        switch: switch_report(control, &s),
        busy: s.busy,
        build: s.identity,
        started_from: s.started_from,
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
/// What a status says about a receiving service's build: that it runs
/// another build than this command, and how it is switching to a new one.
/// None for a service of this build with nothing to say. `fix` is the
/// command that replaces it at once; `commands_switch` says whether any syq
/// command switches one that cannot follow its path (`refresh_outdated`).
pub(crate) fn build_note(
    build: &str,
    started_from: Option<&str>,
    switch: Option<&switch::Report>,
    busy: Option<&Busy>,
    on: Option<&str>,
    fix: &str,
    commands_switch: bool,
) -> Option<String> {
    let mut note = Vec::new();
    if build != crate::identity::build() {
        note.push(format!("runs syq {build}"));
        if switch.is_none() {
            note.push(match switch::follows(started_from) {
                switch::Follows::OtherFile => format!(
                    "follows {}; `{fix}` replaces it",
                    started_from.unwrap_or_default()
                ),
                switch::Follows::ThisFile => "switches to this version once idle".into(),
                switch::Follows::Nothing if commands_switch => {
                    "a syq command run here switches it to this version once idle".into()
                }
                switch::Follows::Nothing => format!("`{fix}` switches it to this version"),
            });
        }
    }
    if let Some(switch) = switch {
        let mut line = switch.describe();
        if switch.phase == "failed" {
            line.push_str(&format!(", or run `{fix}`"));
        }
        note.push(line);
    }
    // What waiting for idle waits for, when that is an open account
    // connection, which does not end by itself.
    let waits_for_idle = match switch {
        Some(switch) => switch.phase == "waiting",
        None => match switch::follows(started_from) {
            switch::Follows::ThisFile => true,
            switch::Follows::Nothing => commands_switch,
            switch::Follows::OtherFile => false,
        },
    };
    if build != crate::identity::build() && waits_for_idle {
        if let Some(accounts) = busy.and_then(|busy| busy.accounts_note(on, fix)) {
            note.push(accounts);
        }
    }
    (!note.is_empty()).then(|| note.join("; "))
}
/// The command that connects receiving through `endpoint` at once.
pub(crate) fn connect_command(endpoint: &str, scope: Option<&Path>) -> String {
    let mut command = format!("syq persist connect {}", shell_words::quote(endpoint));
    if let Some(scope) = scope {
        command.push_str(&format!(
            " --pscope {}",
            shell_words::quote(&scope.to_string_lossy())
        ));
    }
    command
}
pub(crate) fn profile_names(domain: &Domain) -> Vec<String> {
    preferences(domain)
        .map(|p| p.profiles.into_iter().map(|p| p.name).collect())
        .unwrap_or_default()
}

/// Whether receiving through an endpoint is on, and whether starting it
/// took a new service process.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Receiving {
    Off,
    Running,
    Started,
    /// A service from another build keeps running: `busy` with requests in
    /// progress, or (None) following another installed syq file
    /// (`switch::follows_other_file`). `follows_this_file` says whether it
    /// switches to this build by itself once idle.
    Other {
        build: String,
        busy: Option<Busy>,
        follows_this_file: bool,
    },
}

/// Whether to replace a running receiving service from another build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Replace {
    /// For commands: never. The service switches by itself, or a switch a
    /// command starts in the background replaces it (`refresh_outdated`),
    /// after checking that the new service can log in.
    Leave,
    /// For the switches services and commands start: only once nothing is
    /// in progress, never one that follows another installed syq file by
    /// itself, so that two installed copies do not take turns replacing each
    /// other's services, and only once the new service could log in
    /// (`switch`).
    WhenIdle,
    /// For `persist connect` run by hand: at once, saying what that cuts off.
    Now,
}

/// What a status says is in progress. A service from before syq followed
/// updates reports only its requests waiting for approval.
fn busy_of(state: &Status) -> Busy {
    state.busy.unwrap_or(Busy {
        requests: 0,
        pending: state.pending.len(),
        accounts: 0,
    })
}

/// Stop a service from another build as `replace` allows, or say why it
/// keeps running.
fn replace_other(
    control: &Path,
    state: &Status,
    replace: Replace,
    remote: &crate::conn::RemoteSpec,
) -> Result<Option<Receiving>> {
    let follows_this_file =
        switch::follows(state.started_from.as_deref()) == switch::Follows::ThisFile;
    let other = |busy| {
        Some(Receiving::Other {
            build: state.identity.clone(),
            busy,
            follows_this_file,
        })
    };
    match replace {
        Replace::Now => {
            let busy = busy_of(state);
            if !busy.idle() {
                crate::output::diagnostic!(
                    "syq: replacing receiving through {}, which runs syq {}, cuts off {}",
                    state.endpoint,
                    state.identity,
                    busy.describe(Some(&state.endpoint))
                );
            }
            stop_inner(control, false)?;
            Ok(None)
        }
        Replace::Leave => {
            let busy = busy_of(state);
            Ok(other((!busy.idle()).then_some(busy)))
        }
        Replace::WhenIdle => {
            if switch::follows_other_file(state.started_from.as_deref()) {
                return Ok(other(None));
            }
            let busy = busy_of(state);
            if !busy.idle() {
                return Ok(other(Some(busy)));
            }
            // The new service logs in separately from the control connection
            // this command used. Make sure it can before stopping a working
            // one: a failure leaves the old service receiving.
            check_login(control, remote)?;
            // That took a while: decide on what the service says now, such
            // as a request that began waiting for approval meanwhile.
            let Some(state) = running_status(control, Retry::No, ANSWER_TIMEOUT)? else {
                return Ok(None);
            };
            if state.identity == crate::identity::build() {
                return Ok(Some(Receiving::Running));
            }
            if switch::follows_other_file(state.started_from.as_deref()) {
                return Ok(other(None));
            }
            if stop_when_idle(control, &state)? {
                Ok(None)
            } else {
                Ok(other(Some(busy_of(&state))))
            }
        }
    }
}

/// Log in as the new receiving service will. A login that needs the user,
/// including one that did not finish in time (`switch::login_check`), is
/// `switch::LoginNeeded`.
fn check_login(control: &Path, remote: &crate::conn::RemoteSpec) -> Result<()> {
    let endpoint = crate::persistence::EndpointRecord {
        user: remote.user.clone(),
        host: remote.host.clone(),
        port: remote.port,
        ssh_options: Vec::new(),
        ssh_options_directory: None,
    };
    let (deadline, in_this_group) = switch::login_check();
    match crate::destination::check_receiving_login(&endpoint, deadline, in_this_group) {
        Ok(()) => Ok(()),
        Err((true, message)) => {
            switch::defer_after_login(control);
            Err(anyhow::anyhow!("{message}").context(switch::LoginNeeded(remote.label())))
        }
        Err((false, message)) => Err(anyhow::anyhow!(
            "receiving could not log in to {}: {message}",
            remote.label()
        )),
    }
}

/// Stop a service only if nothing is in progress. A service that reports
/// what it has in progress decides that itself, refusing new requests from
/// then on, so nothing can start between the check and the stop. For one
/// from before syq followed updates, only its pending approvals are known.
///
/// Either way it then only waits for that process to exit. Another service
/// may take the control meanwhile, and nothing is sent that could stop it;
/// the caller looks again at whoever owns the control.
fn stop_when_idle(control: &Path, state: &Status) -> Result<bool> {
    let request = |stop: bool| LocalRequest {
        version: VERSION,
        stop,
        decision: None,
        retry: false,
        restart: false,
        stop_if_idle: !stop,
    };
    let pid = if state.busy.is_none() {
        if !state.pending.is_empty() {
            return Ok(false);
        }
        // An older service has only an unconditional stop.
        send(control, &request(true))?.pid
    } else {
        let answer = send(control, &request(false))?;
        if !answer.stopping {
            return Ok(false);
        }
        answer.pid
    };
    await_exit(control, pid)?;
    Ok(true)
}

/// Wait for service process `pid`, which is stopping, to give up the
/// control: until it has exited, or another service answers on the control.
fn await_exit(control: &Path, pid: u32) -> Result<()> {
    let deadline = Instant::now() + STOP_TIMEOUT;
    let mut progress = Instant::now();
    while is_running(control) {
        match status(control, false) {
            Ok(state) if state.pid != pid => return Ok(()),
            Ok(_) => {}
            Err(_) if !process_alive(pid) => return Ok(()),
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            bail!("background receiver did not stop: {}", control.display());
        }
        if progress.elapsed() >= Duration::from_secs(5) {
            crate::output::diagnostic!(
                "syq: waiting for background receiver {} to stop",
                control.display()
            );
            progress = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// `retry` is what to do with a failed connection to this server: what a
/// command connecting to it asks (`Retry::IfDue`), or `persist connect`
/// (`Retry::Now`). `replace` is what to do with a service from another build.
fn ensure_inner(
    domain: &Domain,
    control: &Path,
    remote: &crate::conn::RemoteSpec,
    retry: Retry,
    replace: Replace,
) -> Result<Receiving> {
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    anyhow::ensure!(
        Domain::select(Some(scope))? == *domain,
        "receiving control belongs to a different persistence domain"
    );
    if !domain.enabled()? {
        return Ok(Receiving::Off);
    }
    if scope.join(CLOSING).exists() {
        bail!("persistence scope is closing");
    }
    // Persist current preferences before reuse so older binaries cannot weaken policy.
    let config = ensure_current_settings(domain)?;
    let allowed = config
        .profiles
        .iter()
        .any(|p| p.allows_server(&remote.label()));
    if allowed {
        // After a service from another build stops, another may take the
        // control before this one starts; look again at whoever owns it.
        for _ in 0..4 {
            let Some(state) = running_status(control, Retry::No, ANSWER_TIMEOUT)? else {
                break;
            };
            if state.identity == crate::identity::build() {
                if running_status(control, retry, ANSWER_TIMEOUT)?.is_some() {
                    return Ok(Receiving::Running);
                }
                break;
            }
            if let Some(other) = replace_other(control, &state, replace, remote)? {
                return Ok(other);
            }
        }
    }
    let spec = ServiceSpec {
        version: VERSION,
        identity: crate::identity::build().into(),
        endpoint: crate::persistence::EndpointRecord {
            user: remote.user.clone(),
            host: remote.host.clone(),
            port: remote.port,
            ssh_options: Vec::new(),
            ssh_options_directory: None,
        },
        program: remote.program_command(&[]),
    };
    // Keep the connected endpoint even when no profile currently allows it:
    // a later preference change can start receiving without another connect.
    atomic_json(&suffixed(control, RECORD), &spec)?;
    if !allowed {
        return Ok(Receiving::Off);
    }
    spawn(control)?;
    Ok(Receiving::Started)
}
/// A service process this call started. Its reaper drops the sender once the
/// process has exited, which it does at once if another service owns the lock.
struct Started(std::sync::mpsc::Receiver<()>);
impl Started {
    fn alive(&self) -> bool {
        matches!(self.0.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty))
    }
}
fn spawn(control: &Path) -> Result<Started> {
    let mut command = crate::process::self_command()?;
    // Its own switches are not a command's (`switch::STARTED_BY_COMMAND`).
    command
        .arg("--receive-service")
        .arg(control)
        .env_remove(switch::STARTED_BY_COMMAND);
    if let Some(path) = crate::process::started_from() {
        command.arg(path);
    }
    command
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
    let mut child = command
        .spawn_guarded()
        .context("start background receiving")?;
    let (reaped, started) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = child.wait();
        drop(reaped);
    });
    Ok(Started(started))
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
    /// Dropped to wake the thread from its waits as soon as it is stopped.
    wake: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<Result<()>>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        drop(self.wake.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct ProfileWorker {
    config: Settings,
    state: Arc<Mutex<ConnectionState>>,
    approvals: Arc<crate::receive_approval::Queue>,
    activity: Arc<crate::destination::Activity>,
    worker: Worker,
}
impl ProfileWorker {
    fn new(domain: &Domain, config: Settings, spec: ServiceSpec) -> Self {
        let state = Arc::new(Mutex::new(ConnectionState::default()));
        let approvals = Arc::new(crate::receive_approval::Queue::new(domain.clone()));
        approvals.set_notifications(config.notifications);
        let activity = Arc::new(crate::destination::Activity::default());
        let stop = Arc::new(AtomicBool::new(false));
        let (wake, woken) = std::sync::mpsc::channel();
        let (thread_state, thread_approvals, thread_stop, thread_config, thread_activity) = (
            state.clone(),
            approvals.clone(),
            stop.clone(),
            config.clone(),
            activity.clone(),
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
                    woken,
                    thread_state.clone(),
                    thread_approvals,
                    thread_activity,
                )
            };
            if let Err(error) = &result {
                let mut state = thread_state.lock().unwrap();
                state.phase = "failed".into();
                state.error = Some(format!("{error:#}"));
                state.ssh_pid = None;
                state.retry = None;
            }
            result
        });
        Self {
            config,
            state,
            approvals,
            activity,
            worker: Worker {
                stop,
                wake: Some(wake),
                thread: Some(thread),
            },
        }
    }
    fn snapshot(&self) -> ProfileStatus {
        ProfileStatus {
            settings: self.config.clone(),
            connection: self.state.lock().unwrap().shown(),
            pending: self.approvals.snapshots(),
        }
    }
    fn idle(&self) -> bool {
        self.approvals.snapshots().is_empty() && self.activity.idle()
    }
}
/// What these workers have in progress.
fn busy(workers: &[ProfileWorker]) -> Busy {
    let accounts = workers.iter().map(|w| w.activity.accounts()).sum();
    Busy {
        requests: workers
            .iter()
            .map(|w| w.activity.requests())
            .sum::<usize>()
            .saturating_sub(accounts),
        pending: workers.iter().map(|w| w.approvals.snapshots().len()).sum(),
        accounts,
    }
}
/// Refuse new requests on every worker if all are idle, so the service can
/// stop to switch builds without cutting anything off; whether it did.
fn close_if_idle(workers: &[ProfileWorker]) -> bool {
    if workers.iter().any(|w| !w.approvals.snapshots().is_empty()) {
        return false;
    }
    for (index, worker) in workers.iter().enumerate() {
        if !worker.activity.close_if_idle() {
            for closed in &workers[..index] {
                closed.activity.reopen();
            }
            return false;
        }
    }
    true
}
fn reconcile(
    domain: &Domain,
    workers: &mut Vec<ProfileWorker>,
    config: &Preferences,
    spec: &ServiceSpec,
    retry: Retry,
) {
    workers.retain_mut(|worker| {
        let Some(profile) = config.profiles.iter().find(|profile| {
            profile.allows_server(&spec.endpoint.label()) && profile.same_access(&worker.config)
        }) else {
            return false;
        };
        worker.approvals.set_notifications(profile.notifications);
        worker.config = profile.clone();
        let mut state = worker.state.lock().unwrap();
        if state.phase != "failed" {
            return true;
        }
        match retry {
            Retry::No => true,
            // Start over, with the first short wait.
            Retry::Now => false,
            // A command connected: try again at once, but no sooner than a
            // while after the last attempt, since commands such as
            // completion may come every few seconds and each retry of a
            // rejected login is another failed login on the server. A
            // connection still waiting to retry is woken, keeping its
            // growing waits; one that stopped is started over.
            Retry::IfDue => {
                let due = state.attempted.is_none_or(|attempted| {
                    attempted.elapsed() >= crate::destination::command_retry_interval()
                });
                if !due {
                    return true;
                }
                let running = worker
                    .worker
                    .thread
                    .as_ref()
                    .is_some_and(|thread| !thread.is_finished());
                if running
                    && worker
                        .worker
                        .wake
                        .as_ref()
                        .is_some_and(|wake| wake.send(()).is_ok())
                {
                    // Under way: later commands wait for this attempt.
                    state.attempted = Some(Instant::now());
                    return true;
                }
                false
            }
        }
    });
    for profile in config
        .profiles
        .iter()
        .filter(|p| p.allows_server(&spec.endpoint.label()))
    {
        if !workers.iter().any(|w| w.config.name == profile.name) {
            workers.push(ProfileWorker::new(domain, profile.clone(), spec.clone()));
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
            ..Default::default()
        });
    (name, connection)
}
// Wait until each live supervisor has revoked changed/removed profiles. Healthy
// workers remain in the same process, preserving streams and pending approvals.
fn apply_preferences(domain: &Domain, config: &Preferences) -> Result<()> {
    if config.enabled() {
        // A provider from another build may not read these settings, and a
        // profile turned off must still lose access. Replace it with one from
        // this build for the profiles that remain enabled.
        if provider::stop_other_build(domain)? {
            provider::ensure(domain)?;
        } else {
            provider::refresh(domain)?;
        }
    } else {
        provider::stop(domain)?;
    }
    for control in all_controls(domain)? {
        if !config.enabled() {
            stop_inner(&control, false)?;
            continue;
        }
        if running_status(&control, Retry::No, ANSWER_TIMEOUT)?
            .is_some_and(|state| state.identity != crate::identity::build())
        {
            stop_inner(&control, false)?;
        }
        let mut started = None;
        if !is_running(&control)
            && config.enabled()
            && domain.enabled()?
            && read_spec(&control).is_ok()
            // A saved endpoint record is not a request to reconnect it. Only
            // attach receiving to a master that is already running; explicit
            // --connection endpoints are connected separately by configure.
            && crate::persistence::socket_is_ready(&control).unwrap_or(false)
        {
            started = Some(spawn(&control)?);
        }
        let deadline = Instant::now() + STOP_TIMEOUT;
        let mut progress = Instant::now();
        // The service started here may not hold its lock yet; wait for it too.
        while is_running(&control) || started.as_ref().is_some_and(Started::alive) {
            let state = status(&control, false);
            let endpoint = read_spec(&control)?.endpoint.label();
            let enabled: Vec<_> = config
                .profiles
                .iter()
                .filter(|p| p.allows_server(&endpoint))
                .collect();
            if state.as_ref().is_ok_and(|state| {
                state.profiles.len() == enabled.len()
                    && enabled
                        .iter()
                        .all(|p| state.profiles.iter().any(|s| &s.settings == *p))
            }) {
                break;
            }
            if Instant::now() >= deadline {
                let unapplied =
                    "receiving profiles have not been applied; check syq persist receive status";
                return Err(match state {
                    Ok(_) => anyhow::anyhow!(unapplied),
                    Err(error) => error
                        .context(format!(
                            "receiving service is not answering at {}",
                            suffixed(&control, SOCKET).display()
                        ))
                        .context(unapplied),
                });
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

/// The largest control request: a version, flags and one approval decision.
const MAX_CONTROL_REQUEST: usize = 16 * 1024;

/// Read one control request. The service's loop reads them inline, so each
/// has 200 ms and a small size, never what a large copy request may take.
fn read_control_request(client: &mut UnixStream) -> Result<LocalRequest> {
    client.set_nonblocking(false)?;
    client.set_write_timeout(Some(Duration::from_millis(200)))?;
    crate::destination::read_socket_framed(
        client,
        Duration::from_millis(200),
        MAX_CONTROL_REQUEST,
        "receiving control request",
    )
}

/// The command a receiving service runs with a new build at its path to
/// switch to it (`switch`): the new build's own `persist connect`, which
/// installs its helper on the server and replaces this service once idle.
/// `--auth-from ssh` keeps a saved authorization default from choosing
/// anything but this machine's own SSH login.
fn switch_command(domain: &Domain, endpoint: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["persist", "connect", endpoint, "--auth-from", "ssh"]
        .into_iter()
        .map(OsString::from)
        .collect();
    args.push(WHEN_IDLE.into());
    if let Some(scope) = domain.explicit_path() {
        args.extend([OsString::from("--pscope"), scope.into()]);
    }
    args
}
/// The hidden `persist connect` option a switch uses: replace another build
/// only once idle, never prompting (`Replace::WhenIdle`).
pub(crate) const WHEN_IDLE: &str = "--when-idle";

fn run(domain: &Domain, control: &Path, started_from: Option<PathBuf>) -> Result<()> {
    let scope = control.parent().context("persistence scope missing")?;
    crate::persistence::validate_scope(scope)?;
    anyhow::ensure!(
        Domain::select(Some(scope))? == *domain,
        "receiving control belongs to a different persistence domain"
    );
    if scope.join(CLOSING).exists() || !domain.enabled()? {
        return Ok(());
    }
    let Some(_lock) = lock_for_start(|| try_lock(control, true))? else {
        return Ok(());
    };
    if scope.join(CLOSING).exists() || !preferences(domain)?.enabled() {
        return Ok(());
    }
    let spec = read_spec(control)?;
    crate::process::running_receiving_connection(spec.endpoint.label(), domain.explicit_path());
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
    let _signals = crate::process::signals::owned(&[libc::SIGINT, libc::SIGTERM], || {
        let mut registrations = crate::process::signals::Registrations::default();
        for signal in [libc::SIGINT, libc::SIGTERM] {
            registrations.push(signal_hook::flag::register(signal, shutdown.clone())?);
        }
        Ok(registrations)
    })?;
    // Only a UTF-8 path can be reported in a status.
    let mut follower = started_from
        .filter(|path| path.to_str().is_some())
        .map(switch::Follower::new);
    let switch_args = switch_command(domain, &spec.endpoint.label());
    let preferences_path = config_path(domain)?;
    // The preferences file as last read: read it again only once it changed.
    let preferences_file = || {
        fs::symlink_metadata(&preferences_path).ok().map(|m| {
            (
                (m.dev(), m.ino(), m.len()),
                (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()),
            )
        })
    };
    let result = (|| {
        let mut workers = Vec::<ProfileWorker>::new();
        let mut read = preferences_file();
        let mut config = preferences(domain)?;
        let mut last_check = Instant::now() - Duration::from_secs(1);
        while !shutdown.load(Ordering::Acquire) {
            if !fs::metadata(scope).is_ok_and(|m| (m.dev(), m.ino()) == scope_identity)
                || scope.join(CLOSING).exists()
                || !domain.enabled()?
            {
                break;
            }
            if last_check.elapsed() >= Duration::from_millis(200) {
                let file = preferences_file();
                if file.is_none() || file != read {
                    config = preferences(domain)?;
                    read = file;
                }
                reconcile(domain, &mut workers, &config, &spec, Retry::No);
                last_check = Instant::now();
                if let Some(follower) = &mut follower {
                    follower.tick(&|| workers.iter().all(ProfileWorker::idle), &switch_args);
                }
            }
            let mut accepted = false;
            match listener.accept() {
                Ok((mut client, _)) => {
                    accepted = true;
                    // A client may disconnect before accept or during setup.
                    // Its socket errors must not stop the receiving service.
                    if let Ok(request) = read_control_request(&mut client) {
                        if request.version == VERSION {
                            if request.stop || (request.stop_if_idle && close_if_idle(&workers)) {
                                shutdown.store(true, Ordering::Release);
                            }
                            let retry = if request.restart {
                                Retry::Now
                            } else if request.retry {
                                Retry::IfDue
                            } else {
                                Retry::No
                            };
                            if retry != Retry::No {
                                reconcile(domain, &mut workers, &config, &spec, retry);
                            }
                            let decision_error = request.decision.and_then(|decision| {
                                workers
                                    .iter()
                                    .find(|w| {
                                        w.approvals.snapshots().iter().any(|r| r.id == decision.id)
                                    })
                                    .context("approval is unknown, expired, or already answered")
                                    .and_then(|w| {
                                        w.approvals.decide_with_remember(
                                            &decision.id,
                                            decision.allow,
                                            decision.kind,
                                            decision.remember,
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
                                busy: Some(busy(&workers)),
                                started_from: follower.as_ref().and_then(|follower| {
                                    follower.path().to_str().map(str::to_owned)
                                }),
                                switch: follower.as_ref().and_then(switch::Follower::report),
                                stopping: shutdown.load(Ordering::Acquire),
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
            // Answer the next request as soon as it arrives, and otherwise
            // wake for the periodic work above, every 200 ms. A stop is a
            // request, and signals end the wait too.
            if !accepted {
                let mut descriptor = libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut descriptor, 1, 200) };
            }
        }
        drop(workers);
        Ok(())
    })();
    result
}

fn all_controls(domain: &Domain) -> Result<Vec<PathBuf>> {
    crate::persistence::receiving_controls(domain)
}
fn statuses(domain: &Domain) -> Result<Vec<Status>> {
    Ok(all_controls(domain)?
        .into_iter()
        .filter_map(|control| {
            let running = status(&control, false).ok().map(|mut state| {
                state.switch = switch_report(&control, &state);
                state
            });
            running.or_else(|| {
                read_spec(&control).ok().map(|spec| Status {
                    version: VERSION,
                    identity: spec.identity,
                    pid: 0,
                    endpoint: spec.endpoint.label(),
                    name: String::new(),
                    approval: None,
                    pending: Vec::new(),
                    decision_error: None,
                    busy: None,
                    started_from: None,
                    switch: None,
                    stopping: false,
                    profiles: Vec::new(),
                    connection: ConnectionState {
                        phase: "inactive".into(),
                        error: None,
                        ssh_pid: None,
                        ..Default::default()
                    },
                })
            })
        })
        .collect())
}
fn configure_profile(domain: &Domain, options: Configure) -> Result<Settings> {
    // Refuse before saving: a receiving name never names a server to connect to.
    if let Some(name) = options
        .connection
        .iter()
        .find_map(|endpoint| endpoint.strip_prefix('@'))
    {
        bail!("@{name} is a receiving name, not an SSH server: --connection takes the SSH server this machine should connect to, such as `--connection server`");
    }
    let _lock = settings_lock(domain)?;
    let existed = config_path(domain)?.exists();
    let mut preferences = preferences(domain)?;
    let previous_preferences = preferences.clone();
    let index = if let Some(name) = options.name.as_deref() {
        crate::destination::validate_name(name)?;
        match preferences.profiles.iter().position(|p| p.name == name) {
            Some(index) => index,
            None => {
                let mut profile = default_settings(domain)?;
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
    let previous = config.clone();
    config.enabled = true;
    if let Some(notifications) = options.notifications {
        config.notifications = notifications;
    }
    if let Some(name) = options.name {
        config.name = name;
    }
    if let Some(cwd) = options.cwd {
        config.cwd = fs::canonicalize(cwd)?;
        anyhow::ensure!(config.cwd.is_dir(), "--cwd must name a directory");
        config.cwd_explicit = true;
    }
    if options.auto_cwd {
        config.cwd_explicit = false;
    }
    if let Some(root) = options.root {
        let root = fs::canonicalize(root)?;
        anyhow::ensure!(root.is_dir(), "--root must name a directory");
        anyhow::ensure!(
            root.parent().is_some(),
            "--root must be below filesystem root"
        );
        config.root = Some(root);
    }
    if options.no_root {
        config.root = None;
    }
    if let Some(root) = options.auto_approve_root {
        let root = fs::canonicalize(root)?;
        anyhow::ensure!(root.is_dir(), "--auto-approve-root must name a directory");
        config.auto_approve_root = Some(root);
    }
    if options.no_auto_approve_root {
        config.auto_approve_root = None;
    }
    if !options.connection.is_empty() {
        config.servers = options.connection;
    }
    if options.all_connections {
        config.servers.clear();
    }
    if !config.cwd_explicit {
        config.cwd = match config.root.as_ref().or(config.auto_approve_root.as_ref()) {
            Some(root) => root.clone(),
            None => fs::canonicalize(std::env::var_os("HOME").context("HOME is unset")?)?,
        };
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
    if !config.same_access(&previous) {
        config.revision = config
            .revision
            .checked_add(1)
            .context("receiving profile revision exhausted")?;
    }
    let config = config.clone();
    // Repeated on is a no-op for current settings, but an old format must
    // still migrate before receiving starts (including its approval policy).
    if preferences != previous_preferences || !current_settings_exist(domain)? {
        save_settings(domain, &preferences)?;
    }
    drop(_lock);
    domain.enable()?;
    apply_preferences(domain, &preferences)?;
    Ok(config)
}
fn configure(domain: &Domain, options: Configure) -> Result<()> {
    let connections = options.connection.clone();
    let config = configure_profile(domain, options)?;
    provider::ensure(domain)?;
    let mut failures = Vec::new();
    for endpoint in &connections {
        if let Err(error) = crate::persistence::connect_domain(
            domain,
            endpoint,
            None,
            false,
            Duration::from_secs(30),
            Replace::Now,
        ) {
            failures.push(format!("{endpoint}: {error:#}"));
        }
    }
    if !failures.is_empty() {
        bail!(
            "receiving settings saved, but some connections are not ready: {}",
            failures.join("; ")
        );
    }
    crate::output::command_human_stdout!("Receiving is on: {}", config.name);
    config.print_paths();
    Ok(())
}
fn pending(domain: &Domain, json: bool, wait: bool, timeout: u64) -> Result<()> {
    if timeout == 0 || timeout > 3600 {
        bail!("timeout must be between 1 and 3600 seconds");
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut progress = Instant::now();
    loop {
        let mut requests: Vec<_> = statuses(domain)?
            .into_iter()
            .flat_map(|status| status.pending)
            .collect();
        if let Some(provider) = provider::snapshot(domain)? {
            requests.extend(
                provider
                    .profiles
                    .into_iter()
                    .flat_map(|profile| profile.pending),
            );
        }
        if !wait || !requests.is_empty() {
            if json {
                crate::output::command_println!("{}", serde_json::to_string(&requests)?);
            } else if requests.is_empty() {
                crate::output::command_human_stdout!("No requests awaiting approval");
            } else {
                // Dim arguments naming files the server reads and this machine
                // cannot check.
                let terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());
                for request in requests {
                    crate::output::command_human_stdout!(
                        "{}\n{}\nNotification: {}\n",
                        request.id,
                        request.description(domain, |word| if terminal {
                            format!("\x1b[2m{word}\x1b[0m")
                        } else {
                            word.to_owned()
                        }),
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
fn decide(domain: &Domain, id: &str, allow: bool, remember: bool) -> Result<()> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("use the complete request ID from syq persist receive pending");
    }
    for control in all_controls(domain)? {
        let Ok(state) = status(&control, false) else {
            continue;
        };
        if let Some(request) = state.pending.iter().find(|request| request.id == id) {
            anyhow::ensure!(!remember || (allow && request.can_remember()), "--remember applies only to SSH account requests that support remembering; update syq and reconnect receiving if needed");
            let response = query(
                &control,
                false,
                Some(Decision {
                    id: id.into(),
                    allow,
                    kind: request.kind(),
                    remember,
                }),
            )?;
            if let Some(error) = response.decision_error {
                bail!("{error}");
            }
            crate::output::command_human_stdout!(
                "{} {id}",
                if remember {
                    "Approved and remembered"
                } else if allow {
                    "Approved"
                } else {
                    "Denied"
                }
            );
            return Ok(());
        }
    }
    if let Some(provider) = provider::snapshot(domain)? {
        if let Some(request) = provider
            .profiles
            .iter()
            .flat_map(|profile| &profile.pending)
            .find(|request| request.id == id)
        {
            anyhow::ensure!(
                !remember || (allow && request.can_remember()),
                "--remember applies only to SSH account requests that support remembering"
            );
            provider::decide(
                domain,
                Decision {
                    id: id.into(),
                    allow,
                    kind: request.kind(),
                    remember,
                },
            )?;
            crate::output::command_human_stdout!(
                "{} {id}",
                if remember {
                    "Approved and remembered"
                } else if allow {
                    "Approved"
                } else {
                    "Denied"
                }
            );
            return Ok(());
        }
    }
    bail!("approval is unknown, expired, or already answered")
}

pub(crate) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    if let Some(result) = provider::dispatch(argv) {
        return Some(result);
    }
    match argv.get(1).and_then(|s| s.to_str())? {
        "--receive-service" => Some((|| {
            // The control path, and the path the user runs syq by, which
            // the service follows to switch to a new build (`switch`).
            if !(3..=4).contains(&argv.len()) {
                bail!("receive service needs its control path");
            }
            crate::fsops::reserve_startup_descriptors();
            let control = Path::new(&argv[2]);
            let domain =
                Domain::select(Some(control.parent().context("persistence scope missing")?))?;
            run(&domain, control, argv.get(3).map(PathBuf::from))?;
            Ok(0)
        })()),
        _ => None,
    }
}

pub(crate) fn option_migration_hint(argv: &[OsString], mut error: clap::Error) -> clap::Error {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    if error.kind() != ErrorKind::UnknownArgument {
        return error;
    }
    let Some(ContextValue::String(argument)) = error.get(ContextKind::InvalidArg) else {
        return error;
    };
    let option = argument.split('=').next().unwrap_or(argument);
    // Parse the valid prefix using the actual grammar. clap's ignore_errors
    // can discard the nested command that encountered the invalid argument.
    let Some(index) = argv.iter().position(|value| {
        value
            .to_str()
            .is_some_and(|value| value.split('=').next() == Some(option))
    }) else {
        return error;
    };
    let receiving = crate::persistence::command_for_help()
        .try_get_matches_from(&argv[..index])
        .ok()
        .is_some_and(|matches| {
            matches
                .subcommand_matches("receive")
                .is_some_and(|receive| receive.subcommand_matches("on").is_some())
        });
    if !receiving {
        return error;
    }
    let replacement = match option {
        "--server" => "--connection",
        "--all-servers" => "--all-connections",
        _ => return error,
    };
    let hint = format!(
        "the receiving option {option} was renamed to {replacement}; use `syq persist receive on {replacement}`"
    );
    let mut suggestions = match error.remove(ContextKind::Suggested) {
        Some(ContextValue::StyledStrs(suggestions)) => suggestions,
        _ => Vec::new(),
    };
    suggestions.push(hint.into());
    error.insert(
        ContextKind::Suggested,
        ContextValue::StyledStrs(suggestions),
    );
    error
}

fn permission_account_label(
    identity: &crate::receive_approval::accounts::AccountIdentity,
) -> String {
    let trusted = identity.label();
    let route = identity.route_label();
    if trusted == route {
        trusted
    } else {
        format!("{trusted} (route {route})")
    }
}

pub(crate) fn run_command(domain: &Domain, command: ReceiveCommand) -> Result<i32> {
    match command.action {
        Action::On(options) => configure(domain, options)?,
        Action::SwitchProvider => provider::switch_when_idle(domain)?,
        Action::Pending {
            json,
            wait,
            timeout,
        } => pending(domain, json, wait, timeout)?,
        Action::Approve { id, remember } => decide(domain, &id, true, remember)?,
        Action::Deny { id } => decide(domain, &id, false, false)?,
        Action::Permissions { action } => match action {
            PermissionAction::List { json } => {
                let permissions = crate::receive_approval::accounts::list(domain)?;
                let provider_permissions =
                    crate::receive_approval::provider_accounts::list(domain)?;
                if json {
                    // Existing return-permission rows retain their exact shape.
                    let mut rows: Vec<_> = permissions
                        .iter()
                        .map(serde_json::to_value)
                        .collect::<std::result::Result<_, _>>()?;
                    rows.extend(
                        provider_permissions
                            .iter()
                            .map(serde_json::to_value)
                            .collect::<std::result::Result<Vec<_>, _>>()?,
                    );
                    crate::output::command_println!("{}", serde_json::to_string(&rows)?);
                } else if permissions.is_empty() && provider_permissions.is_empty() {
                    crate::output::command_human_stdout!("No remembered account permissions");
                } else {
                    for item in permissions {
                        crate::output::command_human_stdout!(
                            "{}  {} -> {} (receiving profile @{})",
                            item.id,
                            permission_account_label(&item.permission.source),
                            permission_account_label(&item.permission.destination),
                            item.permission.profile
                        );
                    }
                    for item in provider_permissions {
                        crate::output::command_human_stdout!(
                            "{}  {} -> {} (provider profile {})",
                            item.id,
                            item.permission.provider.label(),
                            permission_account_label(&item.permission.destination),
                            item.permission.profile
                        );
                    }
                }
            }
            PermissionAction::Remove { id } => {
                // Validate both stores; never hide corrupt authority state while removing a grant.
                crate::receive_approval::accounts::list(domain)?;
                let provider_permissions =
                    crate::receive_approval::provider_accounts::list(domain)?;
                if provider_permissions.iter().any(|item| item.id == id) {
                    crate::receive_approval::provider_accounts::remove(domain, &id)?;
                } else {
                    // Keep the original store's ID validation and not-found diagnostic.
                    crate::receive_approval::accounts::remove(domain, &id)?;
                }
                crate::output::command_human_stdout!("Removed {id}; future authentications require approval. Already authenticated sessions may continue.");
            }
        },
        Action::Off { name } => {
            let _lock = settings_lock(domain)?;
            let mut config = preferences(domain)?;
            if let Some(name) = name {
                let index = config.selected(Some(&name))?;
                config.profiles[index].enabled = false;
            } else {
                for profile in &mut config.profiles {
                    profile.enabled = false;
                }
            }
            save_settings(domain, &config)?;
            apply_preferences(domain, &config)?;
            crate::output::command_human_stdout!(
                "Selected receiving profiles are off; ordinary SSH persistence is unchanged"
            );
        }
        Action::Remove { name } => {
            let _lock = settings_lock(domain)?;
            let mut config = preferences(domain)?;
            let index = config.selected(Some(&name))?;
            if config.profiles.len() == 1 {
                bail!(
                    "cannot remove the last receiving profile; use syq persist receive off instead"
                );
            }
            config.profiles.remove(index);
            save_settings(domain, &config)?;
            apply_preferences(domain, &config)?;
            crate::output::command_human_stdout!("Removed receiving profile {name}");
        }
        Action::Status { json, name } => {
            let config = preferences(domain)?;
            if let Some(name) = name.as_deref() {
                config.selected(Some(name))?;
            }
            let mut connections = statuses(domain)?;
            let mut local_provider = provider::snapshot(domain)?;
            if let (Some(provider), Some(name)) = (&mut local_provider, &name) {
                provider
                    .profiles
                    .retain(|profile| &profile.settings.name == name);
            }
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
                crate::output::command_println!(
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({ "settings": selected[0], "profiles": selected, "connections": connections, "provider": local_provider })
                    )?
                );
            } else {
                for config in selected {
                    crate::output::command_human_stdout!(
                        "Receiving is {}: {}",
                        if config.enabled { "on" } else { "off" },
                        config.name
                    );
                    config.print_paths();
                }
                if let Some(provider) = local_provider {
                    let mut fix = "syq persist receive on".to_owned();
                    if let Some(scope) = domain.explicit_path() {
                        fix.push_str(&format!(
                            " --pscope {}",
                            shell_words::quote(&scope.to_string_lossy())
                        ));
                    }
                    if let Some(note) = build_note(
                        &provider.build,
                        provider.started_from.as_deref(),
                        provider.switch.as_ref(),
                        provider.busy().as_ref(),
                        None,
                        &fix,
                        false,
                    ) {
                        crate::output::command_human_stdout!("  local SSH provider: {note}");
                    }
                    for profile in provider.profiles {
                        crate::output::command_human_stdout!(
                            "  local SSH provider {}: {} sessions ({} pending)",
                            profile.settings.name,
                            profile.sessions,
                            profile.pending.len()
                        );
                    }
                }
                for state in connections {
                    if let Some(note) = build_note(
                        &state.identity,
                        state.started_from.as_deref(),
                        state.switch.as_ref(),
                        state.busy.as_ref(),
                        Some(&state.endpoint),
                        &connect_command(&state.endpoint, domain.explicit_path()),
                        true,
                    ) {
                        crate::output::command_human_stdout!("  {}: {note}", state.endpoint);
                    }
                    if state.profiles.is_empty() {
                        crate::output::command_human_stdout!(
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
                        crate::output::command_human_stdout!(
                            "  {} @{}: {} ({} pending){}",
                            state.endpoint,
                            profile.settings.name,
                            profile.connection.phase,
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
            let config = preferences(domain)?;
            if let Some(name) = name.as_deref() {
                config.selected(Some(name))?;
            }
            let names: Vec<_> = config
                .profiles
                .iter()
                .filter(|p| p.allows_server(&host) && name.as_ref().is_none_or(|n| n == &p.name))
                .map(|p| p.name.clone())
                .collect();
            if names.is_empty() {
                bail!("no selected receiving profiles are enabled for {host}");
            }
            if timeout == 0 || timeout > 3600 {
                bail!("timeout must be between 1 and 3600 seconds");
            }
            let deadline = Instant::now() + Duration::from_secs(timeout);
            let mut progress = Instant::now();
            loop {
                let states: Vec<_> = statuses(domain)?
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

    /// The service reads control requests inline, so one that claims to be
    /// large, even as large as a copy request may be, is refused at its
    /// header instead of holding the loop while the rest arrives.
    #[test]
    fn an_oversized_control_request_is_refused_at_once() {
        use std::io::Write as _;
        for length in [MAX_CONTROL_REQUEST + 1, 4 << 20] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(&(length as u32).to_be_bytes()).unwrap();
            let started = Instant::now();
            let Err(error) = read_control_request(&mut server) else {
                panic!("an oversized control request of {length} bytes was accepted");
            };
            assert!(started.elapsed() < Duration::from_millis(150), "{length}");
            assert!(
                format!("{error:#}").contains("invalid receiving control request size"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn removed_connection_flags_report_migration_without_accepting_aliases() {
        let parse = |args: &[&str]| {
            let argv: Vec<_> = std::iter::once("syq persist")
                .chain(args.iter().copied())
                .map(OsString::from)
                .collect();
            let error = crate::persistence::command_for_help()
                .try_get_matches_from(&argv)
                .unwrap_err();
            super::option_migration_hint(&argv, error)
        };
        for (args, replacement) in [
            (vec!["receive", "on", "--server", "example"], "--connection"),
            (vec!["receive", "on", "--server=example"], "--connection"),
            (vec!["receive", "on", "--all-servers"], "--all-connections"),
            (
                vec!["--pscope", "/scope", "receive", "on", "--server=example"],
                "--connection",
            ),
            (
                vec!["receive", "--pscope", "/scope", "on", "--server=example"],
                "--connection",
            ),
        ] {
            let error = parse(&args);
            assert_eq!(error.exit_code(), 2);
            assert!(
                error
                    .to_string()
                    .contains(&format!("was renamed to {replacement}")),
                "{error}"
            );
        }
        for args in [
            vec!["receive", "on", "--unrelated"],
            vec!["status", "--server=x"],
            vec!["connect", "receive", "--server=x"],
            vec!["receive", "off", "--server=x"],
        ] {
            let error = parse(&args);
            assert!(!error.to_string().contains("was renamed"), "{error}");
        }
    }

    #[test]
    fn profile_server_scope_matches_only_the_locally_selected_endpoint() {
        let mut settings = default_settings(&Domain::default()).unwrap();
        assert!(settings.allows_server("work"));
        settings.servers = vec!["work".into(), "alice@lab:2222".into()];
        assert!(settings.allows_server("work"));
        assert!(settings.allows_server("alice@lab:2222"));
        for endpoint in ["other", "bob@lab:2222", "alice@lab", "work:22"] {
            assert!(!settings.allows_server(endpoint));
        }
        settings.enabled = false;
        assert!(!settings.allows_server("work"));
    }

    #[test]
    fn notification_refresh_preserves_worker_and_access_changes_revoke_it() {
        let mut settings = default_settings(&Domain::default()).unwrap();
        settings.notifications = crate::receive_approval::Notifications::Desktop;
        let approvals = Arc::new(crate::receive_approval::Queue::default());
        approvals.set_notifications(settings.notifications);
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = vec![ProfileWorker {
            config: settings.clone(),
            state: Arc::new(Mutex::new(ConnectionState {
                phase: "online".into(),
                error: None,
                ssh_pid: Some(42),
                ..Default::default()
            })),
            approvals: approvals.clone(),
            activity: Default::default(),
            worker: Worker {
                stop: stop.clone(),
                wake: None,
                thread: None,
            },
        }];
        let spec = ServiceSpec {
            version: VERSION,
            identity: crate::identity::build().into(),
            endpoint: crate::persistence::EndpointRecord {
                user: None,
                host: "work".into(),
                port: None,
                ssh_options: Vec::new(),
                ssh_options_directory: None,
            },
            program: "syq".into(),
        };
        settings.notifications = crate::receive_approval::Notifications::Off;
        let mut config = Preferences {
            version: PREFERENCES_VERSION,
            profiles: vec![settings],
        };
        reconcile(&Domain::default(), &mut workers, &config, &spec, Retry::No);
        assert_eq!(workers.len(), 1);
        assert!(Arc::ptr_eq(&workers[0].approvals, &approvals));
        assert!(!stop.load(Ordering::Acquire));
        assert_eq!(workers[0].snapshot().connection.ssh_pid, Some(42));
        assert_eq!(
            workers[0].snapshot().settings.notifications,
            crate::receive_approval::Notifications::Off
        );
        assert_eq!(
            approvals.notifications(crate::receive_approval::Notifications::Desktop),
            crate::receive_approval::Notifications::Off
        );

        // Access changes still remove the old worker, including its authority.
        config.profiles[0].servers = vec!["other".into()];
        reconcile(&Domain::default(), &mut workers, &config, &spec, Retry::No);
        assert!(workers.is_empty());
        assert!(stop.load(Ordering::Acquire));
    }

    #[test]
    fn dormant_master_and_full_queue_do_not_block_preference_changes() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("master");
        assert!(!crate::persistence::socket_is_ready(&path).unwrap_or(false));
        let listen = || {
            let listener =
                socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
            listener
                .bind(&socket2::SockAddr::unix(&path).unwrap())
                .unwrap();
            listener.listen(1).unwrap();
            listener
        };
        let listener = listen();
        assert!(crate::persistence::socket_is_ready(&path).unwrap_or(false));
        drop(listener);
        fs::remove_file(&path).unwrap();
        let listener = listen();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut clients = Vec::new();
        let mut full = false;
        for _ in 0..128 {
            let client =
                socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
            client.set_nonblocking(true).unwrap();
            match client.connect(&socket2::SockAddr::unix(&path).unwrap()) {
                Ok(()) => clients.push(client),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::ConnectionRefused
                    ) || error.raw_os_error() == Some(libc::EINPROGRESS) =>
                {
                    full = true;
                    break;
                }
                other => panic!("unexpected local socket connect: {other:?}"),
            }
            assert!(Instant::now() < deadline);
        }
        assert!(full, "local listen queue did not fill");
        assert!(!clients.is_empty());
        // Retain queued clients so Darwin and Linux exercise the same actual
        // saturation. Darwin may report refused rather than WouldBlock.
        assert!(!crate::persistence::socket_is_ready(&path).unwrap_or(false));
        assert!(Instant::now() < deadline);
        drop(listener);
        assert!(!crate::persistence::socket_is_ready(&path).unwrap_or(false));
        drop(clients);
    }

    #[test]
    fn receiving_writer_unlocks_while_an_inherited_description_remains_open() {
        // A short basename leaves room for the domain's OpenSSH control suffix
        // under Darwin's ambient temporary directory.
        let temporary = tempfile::Builder::new()
            .prefix("")
            .tempdir_in(crate::test_support::temp_dir())
            .unwrap();
        crate::persistence::initialize_scope(temporary.path()).unwrap();
        let domain = Domain::select(Some(temporary.path())).unwrap();
        let writer = settings_lock(&domain).unwrap();
        // dup and fork share the open file description that owns flock. This
        // deterministically models another test between fork and close-on-exec.
        let inherited = writer.0.try_clone().unwrap();
        let error = settings_lock(&domain)
            .err()
            .expect("an active writer must still exclude a second writer");
        assert!(error.to_string().contains("preferences are being changed"));
        drop(writer);
        let next = settings_lock(&domain)
            .expect("a finished writer must release ownership before inherited copies close");
        assert!(inherited.metadata().is_ok());
        assert!(
            settings_lock(&domain).is_err(),
            "the next writer still owns the lock"
        );
        drop(inherited);
        assert!(
            settings_lock(&domain).is_err(),
            "closing an old copy must not unlock a new writer"
        );
        drop(next);
        assert!(settings_lock(&domain).is_ok());
    }

    #[test]
    fn receiving_domains_have_fresh_disabled_and_independent_profiles() {
        // Socket paths must fit even when the platform's ambient TMPDIR is long.
        let temporary = crate::test_support::short_tempdir().unwrap();
        let first_path = temporary.path().join("first");
        let second_path = temporary.path().join("second");
        for path in [&first_path, &second_path] {
            crate::persistence::initialize_scope(path).unwrap();
        }
        let first = Domain::select(Some(&first_path)).unwrap();
        let second = Domain::select(Some(&second_path)).unwrap();
        assert!(!preferences(&first).unwrap().enabled());
        assert!(!preferences(&second).unwrap().enabled());
        assert!(!config_path(&first).unwrap().exists());
        assert!(!config_path(&second).unwrap().exists());
        assert!(default_settings(&Domain::default()).unwrap().enabled);

        configure_profile(
            &first,
            Configure {
                name: Some("first-inbox".into()),
                cwd: Some(temporary.path().to_owned()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(profile_names(&first), vec!["first-inbox"]);
        assert!(preferences(&first).unwrap().enabled());
        assert!(!preferences(&second).unwrap().enabled());
        let first_bytes = fs::read(config_path(&first).unwrap()).unwrap();
        let before = preferences(&first).unwrap().profiles.remove(0);
        configure_profile(&first, Configure::default()).unwrap();
        assert_eq!(fs::read(config_path(&first).unwrap()).unwrap(), first_bytes);
        let notified = configure_profile(
            &first,
            Configure {
                notifications: Some(crate::receive_approval::Notifications::Off),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(notified.revision, before.revision);
        let changed = configure_profile(
            &first,
            Configure {
                max_entries: Some(before.max_entries - 1),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(changed.revision, before.revision + 1);
        let first_bytes = fs::read(config_path(&first).unwrap()).unwrap();
        configure_profile(
            &second,
            Configure {
                name: Some("second-inbox".into()),
                cwd: Some(temporary.path().to_owned()),
                ..Default::default()
            },
        )
        .unwrap();
        run_command(
            &second,
            ReceiveCommand {
                action: Action::Off { name: None },
            },
        )
        .unwrap();
        assert!(!preferences(&second).unwrap().enabled());
        assert_eq!(fs::read(config_path(&first).unwrap()).unwrap(), first_bytes);
        assert_eq!(profile_names(&second), vec!["second-inbox"]);
    }

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
                        ..Default::default()
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
            busy: None,
            started_from: None,
            switch: None,
            stopping: false,
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
    fn ordinary_ssh_decision_bytes_are_unchanged_and_remember_is_explicit() {
        let old =
            r#"{"version":2,"stop":false,"decision":{"id":"fixture","allow":true,"kind":"ssh"}}"#;
        let mut request: LocalRequest = serde_json::from_str(old).unwrap();
        assert!(!request.decision.as_ref().unwrap().remember);
        assert_eq!(serde_json::to_string(&request).unwrap(), old);
        request.decision.as_mut().unwrap().remember = true;
        assert_eq!(
            serde_json::to_value(&request).unwrap()["decision"]["remember"],
            true
        );
    }

    #[test]
    fn remembered_permissions_have_local_cli_management() {
        assert!(matches!(
            ReceiveCommand::try_parse_from(["receive", "approve", "request"])
                .unwrap()
                .action,
            Action::Approve {
                remember: false,
                ..
            }
        ));
        assert!(matches!(
            ReceiveCommand::try_parse_from(["receive", "approve", "request", "--remember"])
                .unwrap()
                .action,
            Action::Approve { remember: true, .. }
        ));
        assert!(
            ReceiveCommand::try_parse_from(["receive", "deny", "request", "--remember"]).is_err()
        );
        assert!(matches!(
            ReceiveCommand::try_parse_from(["receive", "permissions", "list", "--json"])
                .unwrap()
                .action,
            Action::Permissions {
                action: PermissionAction::List { json: true }
            }
        ));
        assert!(matches!(
            ReceiveCommand::try_parse_from(["receive", "permissions", "remove", "id"])
                .unwrap()
                .action,
            Action::Permissions {
                action: PermissionAction::Remove { .. }
            }
        ));
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
                restart: false,
                stop_if_idle: false,
            };
            assert_eq!(serde_json::to_string(&request).unwrap(), old);
            let decoded: LocalRequest = serde_json::from_str(old).unwrap();
            assert_eq!(decoded.stop, stop);
            assert!(decoded.decision.is_none());
        }
    }

    /// Hold the control's lock as a service does between taking it and binding
    /// its socket, or after removing the socket while it stops.
    fn locked_control() -> (impl Sized, PathBuf, File) {
        let root = crate::test_support::short_tempdir().unwrap();
        let control = root.path().join("cm-test");
        let lock = try_lock(&control, true).unwrap().unwrap();
        assert!(is_running(&control));
        (root, control, lock)
    }

    #[test]
    fn a_locked_service_is_queried_once_it_binds_its_socket() {
        let (_root, control, _lock) = locked_control();
        let socket = suffixed(&control, SOCKET);
        let service = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut client = loop {
                match listener.accept() {
                    Ok((client, _)) => break client,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "no status query arrived");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            let request = read_control_request(&mut client).unwrap();
            assert!(!request.stop && !request.retry && !request.restart);
            let state = Status {
                version: VERSION,
                identity: crate::identity::build().into(),
                pid: 4242,
                endpoint: "example".into(),
                name: "laptop".into(),
                connection: ConnectionState::default(),
                approval: None,
                pending: Vec::new(),
                decision_error: None,
                busy: None,
                started_from: None,
                switch: None,
                stopping: false,
                profiles: Vec::new(),
            };
            write_status(&mut client, &state).unwrap();
        });
        let state = running_status(&control, Retry::No, ANSWER_TIMEOUT).unwrap();
        service.join().unwrap();
        assert_eq!(state.unwrap().pid, 4242);
    }

    /// A status as the service at `control` answers it.
    /// The service process is this test's own, which lives on after the
    /// stand-in gives up the control, as a stopping service's would not.
    fn answer(identity: &str, busy: Option<Busy>, stopping: bool) -> Status {
        Status {
            version: VERSION,
            identity: identity.into(),
            pid: std::process::id(),
            endpoint: "example".into(),
            name: "laptop".into(),
            connection: ConnectionState::default(),
            approval: None,
            pending: Vec::new(),
            decision_error: None,
            profiles: Vec::new(),
            busy,
            started_from: None,
            switch: None,
            stopping,
        }
    }

    /// Serve a stand-in service on `control` until it is asked to stop, or
    /// agrees to, answering each request with `reply`; return the requests.
    /// Once it has removed its socket, `then` gets its lock, to drop or hand
    /// to a service that takes over.
    fn stand_in(
        control: &Path,
        lock: File,
        reply: impl Fn(&LocalRequest) -> Status + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<String>> {
        stand_in_then(control, lock, reply, drop)
    }
    fn stand_in_then(
        control: &Path,
        lock: File,
        reply: impl Fn(&LocalRequest) -> Status + Send + 'static,
        then: impl FnOnce(File) + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<String>> {
        let socket = suffixed(control, SOCKET);
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut requests = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return requests;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                let request = read_control_request(&mut client).unwrap();
                requests.push(serde_json::to_string(&request).unwrap());
                let answer = reply(&request);
                write_status(&mut client, &answer).unwrap();
                if request.stop || answer.stopping {
                    fs::remove_file(&socket).unwrap();
                    then(lock);
                    return requests;
                }
            }
        })
    }

    /// An approved account connection is reported as what it is, not as a
    /// copy in progress, with what to run to switch now: it does not end by
    /// itself.
    #[test]
    fn open_account_connections_are_reported_apart_from_requests() {
        let fix = "syq persist connect server";
        let accounts = Busy {
            requests: 0,
            pending: 0,
            accounts: 1,
        };
        assert!(!accounts.idle());
        assert_eq!(
            busy_notice("server", "v0.8.0", &accounts, true, fix),
            "receiving through server keeps running syq v0.8.0: it waits for 1 approved account connection on server to close; `syq persist connect server` switches now and closes it"
        );
        let both = Busy {
            requests: 1,
            pending: 0,
            accounts: 2,
        };
        let notice = busy_notice("server", "v0.8.0", &both, true, fix);
        assert_eq!(
            notice,
            "receiving through server keeps running syq v0.8.0 for now, with 1 request in progress and 2 approved account connections on server; it switches to this version by itself once nothing is in progress; `syq persist connect server` switches now and closes the account connections"
        );
        let copies = Busy {
            requests: 1,
            pending: 0,
            accounts: 0,
        };
        assert!(!busy_notice("server", "v0.8.0", &copies, true, fix).contains("account"));

        // Status says the same while the switch waits.
        let started_from = std::env::current_exe().unwrap();
        let started_from = started_from.to_str();
        let waiting = switch::Report {
            to: Some(crate::identity::build().into()),
            phase: "waiting".into(),
            error: None,
        };
        let note = build_note(
            "v0.8.0",
            started_from,
            Some(&waiting),
            Some(&accounts),
            Some("server"),
            fix,
            true,
        )
        .unwrap();
        assert!(
            note.ends_with(
                "; it waits for 1 approved account connection on server to close; `syq persist connect server` switches now and closes it"
            ),
            "{note}"
        );
        assert!(!note.contains("request"), "{note}");
        // The provider names no server.
        let note = build_note(
            "v0.8.0",
            started_from,
            None,
            Some(&accounts),
            None,
            "syq persist receive on",
            false,
        )
        .unwrap();
        assert!(
            note.ends_with(
                "; it waits for 1 approved account connection to close; `syq persist receive on` switches now and closes it"
            ),
            "{note}"
        );
        // Nothing to wait for once the switch failed, or for one that
        // follows another file.
        let failed = switch::Report {
            phase: "failed".into(),
            error: Some("broken".into()),
            ..waiting
        };
        let note = build_note(
            "v0.8.0",
            started_from,
            Some(&failed),
            Some(&accounts),
            Some("server"),
            fix,
            true,
        )
        .unwrap();
        assert!(!note.contains("account"), "{note}");
        let elsewhere = crate::test_support::tempdir().unwrap();
        let other = elsewhere.path().join("syq");
        fs::write(&other, b"").unwrap();
        let note = build_note(
            "v0.8.0",
            other.to_str(),
            None,
            Some(&accounts),
            Some("server"),
            fix,
            true,
        );
        assert!(!note.is_some_and(|note| note.contains("account")));
    }

    /// A service that reports what it has in progress decides itself
    /// whether it is idle enough to stop; one from before syq followed
    /// updates is stopped unless it has requests waiting for approval.
    #[test]
    fn a_service_from_another_build_is_stopped_only_when_idle() {
        let (_root, control, lock) = locked_control();
        let busy = Some(Busy {
            requests: 1,
            pending: 0,
            accounts: 0,
        });
        let service = stand_in(&control, lock, move |_| answer("other", busy, false));
        assert!(!stop_when_idle(&control, &answer("other", busy, false)).unwrap());
        assert!(is_running(&control));
        // An older service cannot read the request; it is never sent one.
        let (_root, old_control, old_lock) = locked_control();
        let old = stand_in(&old_control, old_lock, |_| answer("old", None, false));
        assert!(stop_when_idle(&old_control, &answer("old", None, false)).unwrap());
        assert_eq!(old.join().unwrap(), [r#"{"version":2,"stop":true}"#]);
        assert!(!is_running(&old_control));
        // The busy one was asked once and kept running.
        send(
            &control,
            &LocalRequest {
                version: VERSION,
                stop: true,
                decision: None,
                retry: false,
                restart: false,
                stop_if_idle: false,
            },
        )
        .unwrap();
        assert_eq!(
            service.join().unwrap(),
            [
                r#"{"version":2,"stop":false,"stop_if_idle":true}"#,
                r#"{"version":2,"stop":true}"#
            ]
        );

        // An idle one agrees and stops.
        let (_root, control, lock) = locked_control();
        let service = stand_in(&control, lock, |request| {
            answer("other", Some(Busy::default()), request.stop_if_idle)
        });
        // Its answer to stop_if_idle says it stops, and nothing else is
        // sent while it goes.
        assert!(stop_when_idle(&control, &answer("other", Some(Busy::default()), false)).unwrap());
        assert!(!is_running(&control));
        assert_eq!(
            service.join().unwrap(),
            [r#"{"version":2,"stop":false,"stop_if_idle":true}"#]
        );
    }

    /// Once a service agreed to stop, another may take the control before
    /// the command that asked sees it free. That one is never sent a stop:
    /// the command only waits for the service that agreed, and leaves the
    /// next owner to be looked at again.
    #[test]
    fn a_service_that_takes_over_after_one_agreed_to_stop_is_not_stopped() {
        let (root, control, lock) = locked_control();
        let successor = std::sync::Arc::new(Mutex::new(None));
        let started = successor.clone();
        let next = control.clone();
        let old = stand_in_then(
            &control,
            lock,
            |request| {
                let mut state = answer("other", Some(Busy::default()), request.stop_if_idle);
                state.pid = 1111;
                state
            },
            move |lock| {
                // The next owner, busy, takes the lock as the first lets go,
                // before a probe of the command could.
                *started.lock().unwrap() = Some(stand_in(&next, lock, |_| {
                    let mut state = answer(
                        "another",
                        Some(Busy {
                            requests: 1,
                            pending: 0,
                            accounts: 0,
                        }),
                        false,
                    );
                    state.pid = 2222;
                    state
                }));
            },
        );
        let mut state = answer("other", Some(Busy::default()), false);
        state.pid = 1111;
        assert!(stop_when_idle(&control, &state).unwrap());
        old.join().unwrap();
        // The next owner still runs, and was only asked for its status.
        assert!(is_running(&control));
        assert!(suffixed(&control, SOCKET).exists());
        let next = successor.lock().unwrap().take().unwrap();
        send(
            &control,
            &LocalRequest {
                version: VERSION,
                stop: true,
                decision: None,
                retry: false,
                restart: false,
                stop_if_idle: false,
            },
        )
        .unwrap();
        let requests = next.join().unwrap();
        assert!(
            requests[..requests.len() - 1]
                .iter()
                .all(|request| request == r#"{"version":2,"stop":false}"#),
            "{requests:?}"
        );
        drop(root);
    }

    #[test]
    fn a_locked_service_that_never_answers_fails_with_its_socket() {
        let (_root, control, _lock) = locked_control();
        let started = Instant::now();
        let error = running_status(&control, Retry::No, Duration::from_millis(200)).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(200) && elapsed < Duration::from_secs(5),
            "{elapsed:?}"
        );
        let message = format!("{error:#}");
        assert!(
            message.starts_with(&format!(
                "receiving service is running but not answering at {}: ",
                suffixed(&control, SOCKET).display()
            )),
            "{message}"
        );
        assert!(unanswered(&error), "{message}");
    }

    #[test]
    fn a_service_that_stops_before_answering_is_not_running() {
        let (_root, control, lock) = locked_control();
        let stopped = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(lock);
        });
        assert!(running_status(&control, Retry::No, Duration::from_secs(10))
            .unwrap()
            .is_none());
        stopped.join().unwrap();
    }

    #[test]
    fn a_starting_service_waits_out_a_status_probe() {
        let root = crate::test_support::short_tempdir().unwrap();
        let control = root.path().join("cm-test");
        // A status check holds the lock during the first attempt, then ends.
        let mut probe = Some(try_lock(&control, true).unwrap().unwrap());
        let mut attempts = 0;
        let lock = lock_for_start(|| {
            attempts += 1;
            let attempt = try_lock(&control, true);
            probe.take();
            attempt
        })
        .unwrap();
        assert!(lock.is_some());
        assert_eq!(attempts, 2);
    }

    #[test]
    fn a_service_started_beside_a_running_one_gives_up_after_the_grace() {
        let root = crate::test_support::short_tempdir().unwrap();
        let control = root.path().join("cm-test");
        let _owner = try_lock(&control, true).unwrap().unwrap();
        let started = Instant::now();
        assert!(lock_for_start(|| try_lock(&control, true))
            .unwrap()
            .is_none());
        let elapsed = started.elapsed();
        assert!(
            elapsed >= PROBE_GRACE && elapsed < Duration::from_secs(5),
            "{elapsed:?}"
        );
    }
}
