//! User-managed OpenSSH control-connection persistence.
//!
//! A durable preference selects a well-known per-user runtime scope. Scripts
//! can instead create an ephemeral scope and pass its path back with
//! `--pscope`, avoiding shared configuration state.

use crate::cli::Args;
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::Command;

const CONFIG_FILE: &str = "persistence.json";
const SCOPE_MARKER: &str = ".syq-persistence";
const SCOPE_MARKER_CONTENT: &[u8] = b"syq persistence scope\n";

#[derive(Parser, Debug)]
#[command(
    name = "syq persist",
    about = "Manage reusable SSH connections and helper sessions",
    long_about = "Manage reusable SSH connections and helper sessions. The durable setting applies to later syq transfer commands. An ephemeral scope is isolated from that setting and is selected by passing its printed path back with --pscope."
)]
struct PersistCommand {
    #[command(subcommand)]
    action: PersistAction,
}

#[derive(Subcommand, Debug)]
enum PersistAction {
    /// Enable reusable SSH control connections
    On {
        /// Create an ephemeral scope and print its path instead of changing the user setting
        #[arg(long)]
        ephemeral: bool,
    },
    /// Disable persistence and close its live SSH control connections
    Off {
        /// Operate on this ephemeral persistence scope instead of the user setting
        #[arg(long, value_name = "PATH")]
        pscope: Option<PathBuf>,
    },
    /// Show the configured policy and live SSH control connections
    Status {
        /// Inspect this ephemeral persistence scope instead of the user setting
        #[arg(long, value_name = "PATH")]
        pscope: Option<PathBuf>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistenceConfig {
    enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointRecord {
    pub(crate) user: Option<String>,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

impl EndpointRecord {
    fn new(user: Option<&str>, host: &str, port: Option<u16>) -> Self {
        Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        }
    }

    pub(crate) fn label(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let endpoint = match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        };
        match self.port {
            Some(port) => format!("{endpoint}:{port}"),
            None => endpoint,
        }
    }
}

/// Endpoint records in the persistence scope relevant to the command being
/// completed. Completion is advisory, so an absent global runtime scope is an
/// empty source rather than a reason to create one.
pub(crate) fn completion_endpoints(explicit_scope: Option<&Path>) -> Result<Vec<EndpointRecord>> {
    let scope = match explicit_scope {
        Some(scope) => {
            validate_scope(scope)?;
            scope.to_path_buf()
        }
        None if global_enabled()? => global_scope_path()?,
        None => return Ok(Vec::new()),
    };
    match scope.symlink_metadata() {
        Ok(_) => Ok(scope_records(&scope)?
            .into_iter()
            .map(|(_, record)| record)
            .collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect persistence scope for completion {}",
                scope.display()
            )
        }),
    }
}

pub(crate) fn run(argv: &[OsString]) -> Result<i32> {
    let mut full_argv = vec![OsString::from("syq persist")];
    full_argv.extend_from_slice(argv);
    let matches = command_for_help()
        .try_get_matches_from(full_argv)
        .unwrap_or_else(|error| error.exit());
    let command = PersistCommand::from_arg_matches(&matches)?;
    match command.action {
        PersistAction::On { ephemeral: true } => {
            let scope = create_ephemeral_scope()?;
            // This is a scripting contract: stdout is exactly the native path
            // followed by one newline, with no diagnostic prose mixed in.
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(scope.as_os_str().as_bytes())?;
            stdout.write_all(b"\n")?;
        }
        PersistAction::On { ephemeral: false } => {
            let scope = ensure_global_scope()?;
            write_global_config(true)?;
            println!("SSH connection persistence is on");
            println!("scope: {}", scope.display());
        }
        PersistAction::Off {
            pscope: Some(scope),
        } => {
            if is_global_scope(&scope)? {
                bail!(
                    "the global persistence scope is controlled by `syq persist off` without --pscope"
                );
            }
            close_scope(&scope)?;
            println!("persistence scope closed: {}", scope.display());
        }
        PersistAction::Off { pscope: None } => {
            // Disable first so a later command cannot intentionally join the
            // global scope while its existing masters are being closed.
            write_global_config(false)?;
            let scope = global_scope_path()?;
            match scope.symlink_metadata() {
                Ok(_) => close_scope(&scope)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect global scope {}", scope.display()));
                }
            }
            println!("SSH connection persistence is off");
        }
        PersistAction::Status {
            pscope: Some(scope),
        } => print_scope_status(&scope, Some("ephemeral"))?,
        PersistAction::Status { pscope: None } => {
            let enabled = global_enabled()?;
            println!(
                "SSH connection persistence is {}",
                if enabled { "on" } else { "off" }
            );
            let scope = global_scope_path()?;
            match scope.symlink_metadata() {
                Ok(_) => print_scope_status(&scope, Some("global"))?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    println!("connections: 0");
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect global scope {}", scope.display()));
                }
            }
        }
    }
    Ok(0)
}

/// Remember whether the command explicitly selected a scope without touching
/// configuration or runtime state. Commands that never construct an eligible
/// implicit SSH endpoint must not depend on either location being accessible.
pub(crate) fn mark_explicit_scope(args: &mut Args) {
    args.pscope_explicit = args.pscope.is_some();
}

/// Resolve persistence only for an implicit local SSH edge. Explicit scopes
/// are validated here, and the durable policy is read here, so local commands,
/// custom remote shells, remote coordinators, and restricted receivers do not
/// acquire an unrelated filesystem dependency.
pub(crate) fn scope_for_implicit_ssh(explicit_scope: Option<&Path>) -> Result<Option<PathBuf>> {
    match explicit_scope {
        Some(scope) => {
            validate_scope(scope)?;
            Ok(Some(scope.to_path_buf()))
        }
        None if global_enabled()? => Ok(Some(ensure_global_scope()?)),
        None => Ok(None),
    }
}

/// OpenSSH expands percent tokens in control paths, including paths supplied
/// through `-S`. Double each percent byte so that expansion yields the literal,
/// byte-exact filesystem path. Keeping the path in an `OsString` also avoids
/// lossy UTF-8 conversion and makes whitespace one argv value rather than SSH
/// configuration syntax.
pub(crate) fn openssh_control_path(path: &Path) -> OsString {
    debug_assert!(validate_openssh_control_path(path).is_ok());
    let bytes = path.as_os_str().as_bytes();
    let mut escaped =
        Vec::with_capacity(bytes.len() + bytes.iter().filter(|&&b| b == b'%').count());
    for &byte in bytes {
        if byte == b'%' {
            escaped.push(b'%');
        }
        escaped.push(byte);
    }
    OsString::from_vec(escaped)
}

/// OpenSSH expands a leading `~` and `${ENV}` in `ControlPath` even when the
/// path is supplied as a separate `-S` argument. Those forms have no escaping
/// contract comparable to `%%`, so refuse them before creating or accepting a
/// control directory.
pub(crate) fn validate_openssh_control_path(path: &Path) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() == Some(&b'~') || bytes.windows(2).any(|pair| pair == b"${") {
        bail!(
            "SSH control path {} contains OpenSSH expansion syntax; it may not begin with `~` or contain `${{`",
            path.display()
        );
    }
    Ok(())
}

/// OpenSSH binds a temporary name with a dot and 16 random characters
/// before linking the control socket into place (openssh-portable/mux.c).
/// Account for that name and the terminating NUL, not only the final path.
pub(crate) fn validate_openssh_socket_path(path: &Path) -> Result<()> {
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    validate_openssh_socket_capacity(path, address.sun_path.len())
}

fn validate_openssh_socket_capacity(path: &Path, capacity: usize) -> Result<()> {
    validate_openssh_control_path(path)?;
    let limit = capacity - 18;
    if path.as_os_str().as_bytes().len() > limit {
        bail!(
            "SSH control socket path {} is too long (maximum {limit} bytes, including room for OpenSSH's temporary suffix); use a shorter XDG_RUNTIME_DIR or persistence scope",
            path.display()
        );
    }
    Ok(())
}

/// Return the stable socket path for one endpoint and record enough metadata
/// for `persist status` and `persist off` to inspect or close it later.
pub(crate) fn prepare_endpoint(
    scope: &Path,
    user: Option<&str>,
    host: &str,
    port: Option<u16>,
) -> Result<PathBuf> {
    validate_scope(scope)?;
    let key = endpoint_key(user, host, port);
    let socket = scope.join(&key);
    validate_openssh_socket_path(&socket)?;
    let record_path = scope.join(format!("{key}.json"));
    let expected = EndpointRecord::new(user, host, port);
    let record_bytes = serde_json::to_vec(&expected)?;
    let mut temporary = tempfile::NamedTempFile::new_in(scope)
        .with_context(|| format!("create endpoint record in {}", scope.display()))?;
    temporary
        .write_all(&record_bytes)
        .and_then(|()| temporary.write_all(b"\n"))
        .with_context(|| format!("write endpoint record {}", record_path.display()))?;
    match temporary.persist_noclobber(&record_path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let actual = read_endpoint_record(&record_path)?;
            if actual != expected {
                bail!(
                    "persistence scope endpoint-key collision at {}",
                    record_path.display()
                );
            }
        }
        Err(error) => {
            return Err(error.error)
                .with_context(|| format!("create endpoint record {}", record_path.display()));
        }
    }

    if let Ok(metadata) = socket.symlink_metadata() {
        if !socket_is_live(&socket) {
            if metadata.is_dir() {
                bail!(
                    "SSH control socket path {} is unexpectedly a directory",
                    socket.display()
                );
            }
            std::fs::remove_file(&socket)
                .with_context(|| format!("remove stale SSH control socket {}", socket.display()))?;
        }
    }
    Ok(socket)
}

fn config_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|path| !path.is_empty())
                .map(|home| PathBuf::from(home).join(".config"))
        })
        .map(|root| root.join("syq").join(CONFIG_FILE))
}

fn read_global_config() -> Result<Option<PersistenceConfig>> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "persistence configuration {} must be a regular file owned by the current user",
            path.display()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "persistence configuration {} must not be group- or other-writable",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let config: PersistenceConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse persistence configuration {}", path.display()))?;
    Ok(Some(config))
}

fn global_enabled() -> Result<bool> {
    Ok(read_global_config()?.is_some_and(|config| config.enabled))
}

fn write_global_config(enabled: bool) -> Result<()> {
    let path = config_path()
        .context("cannot change persistence: both XDG_CONFIG_HOME and HOME are unset")?;
    let parent = path.parent().expect("configuration path has a parent");
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create configuration directory {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary configuration in {}", parent.display()))?;
    serde_json::to_writer_pretty(&mut temporary, &PersistenceConfig { enabled })?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace persistence configuration {}", path.display()))?;
    Ok(())
}

fn runtime_parent_path() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Darwin's default TMPDIR is long enough that even the global
            // endpoint socket exceeds sun_path once OpenSSH adds its suffix.
            // This parent is still checked for ownership, mode and symlinks.
            if cfg!(target_os = "macos") {
                PathBuf::from("/tmp")
            } else {
                std::env::temp_dir()
            }
        });
    base.join(format!("syq-persist-{}", unsafe { libc::geteuid() }))
}

fn global_scope_path() -> Result<PathBuf> {
    Ok(runtime_parent_path().join("global"))
}

fn is_global_scope(scope: &Path) -> Result<bool> {
    let global = global_scope_path()?;
    let global = match std::fs::canonicalize(&global) {
        Ok(global) => global,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("resolve global persistence scope {}", global.display()));
        }
    };
    let candidate = std::fs::canonicalize(scope)
        .with_context(|| format!("resolve persistence scope {}", scope.display()))?;
    Ok(candidate == global)
}

fn ensure_runtime_parent() -> Result<PathBuf> {
    let path = runtime_parent_path();
    validate_openssh_control_path(&path)?;
    secure_directory(&path, true, true)?;
    Ok(path)
}

fn ensure_global_scope() -> Result<PathBuf> {
    let parent = ensure_runtime_parent()?;
    let scope = parent.join("global");
    initialize_scope(&scope)?;
    Ok(scope)
}

fn create_ephemeral_scope() -> Result<PathBuf> {
    let parent = ensure_runtime_parent()?;
    let temporary = tempfile::Builder::new()
        .prefix("scope-")
        .tempdir_in(&parent)
        .with_context(|| format!("create persistence scope in {}", parent.display()))?;
    // Validate while TempDir still owns cleanup of a rejected scope.
    initialize_scope(temporary.path())?;
    let scope = temporary.keep();
    if scope.as_os_str().as_bytes().contains(&b'\n') {
        let _ = std::fs::remove_file(scope.join(SCOPE_MARKER));
        let _ = std::fs::remove_dir(&scope);
        bail!("persistence scope path contains a newline and cannot be returned safely");
    }
    Ok(scope)
}

pub(crate) fn initialize_scope(scope: &Path) -> Result<()> {
    validate_openssh_socket_path(&scope.join(endpoint_key(None, "", None)))?;
    secure_directory(scope, true, true)?;
    create_marker(scope)?;
    validate_scope(scope)
}

fn create_marker(scope: &Path) -> Result<()> {
    let path = scope.join(SCOPE_MARKER);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(mut marker) => marker.write_all(SCOPE_MARKER_CONTENT)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create scope marker {}", path.display()));
        }
    }
    Ok(())
}

pub(crate) fn validate_scope(scope: &Path) -> Result<()> {
    validate_openssh_control_path(scope)?;
    secure_directory(scope, false, false)?;
    let marker_path = scope.join(SCOPE_MARKER);
    let mut marker = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&marker_path)
        .with_context(|| {
            format!(
                "open persistence scope marker {} (is this a path printed by `syq persist on --ephemeral`?)",
                marker_path.display()
            )
        })?;
    let metadata = marker.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "persistence scope marker {} must be a regular file owned by the current user",
            marker_path.display()
        );
    }
    let mut content = Vec::new();
    marker.read_to_end(&mut content)?;
    if content != SCOPE_MARKER_CONTENT {
        bail!("invalid persistence scope marker {}", marker_path.display());
    }
    Ok(())
}

/// Open and validate a directory without following a final-component symlink.
/// Only internally selected directories are permission-tightened; an explicit
/// `--pscope` that is too broad is refused without modifying it.
fn secure_directory(path: &Path, create: bool, tighten: bool) -> Result<File> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("persistence directory path contains NUL")?;
    if create && unsafe { libc::mkdir(c_path.as_ptr(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).with_context(|| format!("create {}", path.display()));
        }
    }
    let descriptor = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "open persistence directory {} (symlinks are refused)",
                path.display()
            )
        });
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "persistence directory {} must be owned by the current user",
            path.display()
        );
    }
    if metadata.mode() & 0o077 != 0 {
        if !tighten {
            bail!(
                "persistence directory {} must not be accessible by group or other users",
                path.display()
            );
        }
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("restrict {}", path.display()));
        }
    }
    Ok(directory)
}

fn endpoint_key(user: Option<&str>, host: &str, port: Option<u16>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(user.unwrap_or("").as_bytes());
    hasher.update(b"@");
    hasher.update(host.as_bytes());
    if let Some(port) = port {
        hasher.update(b":");
        hasher.update(port.to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut name = String::from("cm-");
    for byte in &digest[..8] {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

fn read_endpoint_record(path: &Path) -> Result<EndpointRecord> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open endpoint record {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "endpoint record {} must be a regular file owned by the current user",
            path.display()
        );
    }
    let record: EndpointRecord = serde_json::from_reader(file)
        .with_context(|| format!("parse endpoint record {}", path.display()))?;
    Ok(record)
}

fn record_key(name: &OsStr) -> Option<&str> {
    let name = name.to_str()?;
    let key = name.strip_suffix(".json")?;
    valid_endpoint_key(key).then_some(key)
}

fn valid_endpoint_key(name: &str) -> bool {
    name.len() == 19
        && name.starts_with("cm-")
        && name[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn scope_records(scope: &Path) -> Result<Vec<(String, EndpointRecord)>> {
    validate_scope(scope)?;
    let mut records = Vec::new();
    for entry in std::fs::read_dir(scope)
        .with_context(|| format!("read persistence scope {}", scope.display()))?
    {
        let entry = entry?;
        if let Some(key) = record_key(&entry.file_name()) {
            let record = read_endpoint_record(&entry.path())?;
            let expected_key = endpoint_key(record.user.as_deref(), &record.host, record.port);
            if key != expected_key {
                bail!(
                    "endpoint record {} does not match its recorded endpoint {}",
                    entry.path().display(),
                    record.label()
                );
            }
            records.push((key.to_owned(), record));
        }
    }
    records.sort_by(|left, right| left.1.label().cmp(&right.1.label()));
    Ok(records)
}

fn socket_is_live(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

fn print_scope_status(scope: &Path, kind: Option<&str>) -> Result<()> {
    let records = scope_records(scope)?;
    if let Some(kind) = kind {
        println!("scope ({kind}): {}", scope.display());
    } else {
        println!("scope: {}", scope.display());
    }
    println!("connections: {}", records.len());
    for (key, record) in records {
        let control = scope.join(&key);
        let state = if socket_is_live(&control) {
            "live"
        } else {
            "inactive"
        };
        let pool = if crate::session_pool::is_running(&control) {
            ", session pool"
        } else {
            ""
        };
        println!("  {}  {state}{pool}", record.label());
    }
    Ok(())
}

fn close_scope(scope: &Path) -> Result<()> {
    let records = scope_records(scope)?;
    let record_keys: std::collections::HashSet<&str> =
        records.iter().map(|(key, _)| key.as_str()).collect();
    for entry in std::fs::read_dir(scope)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == OsStr::new(SCOPE_MARKER) || record_key(&name).is_some() {
            continue;
        }
        if let Some(name) = name.to_str() {
            if valid_endpoint_key(name) && record_keys.contains(name) {
                continue;
            }
        }
        if let Some(owner) = crate::session_pool::owned_name(name.as_bytes())
            .and_then(|owner| std::str::from_utf8(owner).ok())
        {
            if valid_endpoint_key(owner) && record_keys.contains(owner) {
                continue;
            }
        }
        bail!(
            "refusing to remove persistence scope {} because it contains unrecognized entry {:?}",
            scope.display(),
            name
        );
    }

    for (key, record) in records {
        let socket = scope.join(&key);
        // The pool holds live sessions on the master, so it goes first.
        crate::session_pool::stop(&socket)?;
        if socket_is_live(&socket) {
            close_master(&socket, &record)?;
        }
        if let Ok(metadata) = socket.symlink_metadata() {
            if metadata.is_dir() {
                bail!(
                    "refusing to remove unexpected directory at SSH control path {}",
                    socket.display()
                );
            }
            std::fs::remove_file(&socket)
                .with_context(|| format!("remove SSH control socket {}", socket.display()))?;
        }
        let record_path = scope.join(format!("{key}.json"));
        std::fs::remove_file(&record_path)
            .with_context(|| format!("remove endpoint record {}", record_path.display()))?;
    }
    std::fs::remove_file(scope.join(SCOPE_MARKER))
        .with_context(|| format!("remove persistence marker from {}", scope.display()))?;
    std::fs::remove_dir(scope)
        .with_context(|| format!("remove persistence scope {}", scope.display()))?;
    Ok(())
}

fn close_master(socket: &Path, record: &EndpointRecord) -> Result<()> {
    let output = master_exit_command(socket, record)
        .output()
        .with_context(|| format!("ask SSH master for {} to exit", record.label()))?;
    if output.status.success() || !socket_is_live(socket) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "SSH master for {} refused to exit ({}): {}",
        record.label(),
        output.status,
        stderr.trim()
    )
}

fn master_exit_command(socket: &Path, record: &EndpointRecord) -> Command {
    let mut command = Command::new("ssh");
    command
        .arg("-S")
        .arg(openssh_control_path(socket))
        .args(["-O", "exit"]);
    if let Some(user) = &record.user {
        command.args(["-l", user]);
    }
    if let Some(port) = record.port {
        command.args(["-p", &port.to_string()]);
    }
    command.arg("--").arg(&record.host);
    command
}

pub(crate) fn command_for_help() -> clap::Command {
    crate::help::configure(PersistCommand::command())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn control_socket_budget_includes_openssh_temporary_suffix() {
        let reported = Path::new("/var/folders/bb/zjydfp6x4zsbx55jb_zqhksr0000gn/T/syq-persist-501/global/cm-0123456789abcdef");
        assert_eq!(reported.as_os_str().len(), 91);
        for capacity in [104, 108] {
            assert!(validate_openssh_socket_capacity(reported, capacity).is_err());
            let fits = "/".to_owned() + &"x".repeat(capacity - 19);
            assert!(validate_openssh_socket_capacity(Path::new(&fits), capacity).is_ok());
            assert!(validate_openssh_socket_capacity(Path::new(&(fits + "x")), capacity).is_err());
        }
    }

    #[test]
    fn endpoint_records_are_stable_and_inactive_scopes_close_cleanly() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let scope = temporary.path().join("scope");
        initialize_scope(&scope).unwrap();
        let first = prepare_endpoint(&scope, Some("alice"), "example", None).unwrap();
        let same = prepare_endpoint(&scope, Some("alice"), "example", None).unwrap();
        let alternate = prepare_endpoint(&scope, Some("alice"), "example", Some(2222)).unwrap();
        assert_eq!(first, same);
        assert_ne!(first, alternate);
        assert_eq!(scope_records(&scope).unwrap().len(), 2);
        close_scope(&scope).unwrap();
        assert!(!scope.exists());
    }

    #[test]
    fn over_budget_existing_scope_can_be_inspected_and_closed() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let scope = temporary.path().join("scope");
        initialize_scope(&scope).unwrap();
        prepare_endpoint(&scope, None, "example", None).unwrap();
        // An older version could create this scope; moving a scope can also
        // make a previously valid endpoint path exceed the creation budget.
        let long = temporary.path().join("x".repeat(100));
        std::fs::rename(scope, &long).unwrap();
        assert!(validate_scope(&long).is_ok());
        assert!(print_scope_status(&long, None).is_ok());
        assert!(prepare_endpoint(&long, None, "example", None).is_err());
        close_scope(&long).unwrap();
        assert!(!long.exists());
    }

    #[test]
    fn concurrent_endpoint_registration_publishes_one_complete_record() {
        let temporary = tempfile::tempdir_in("/tmp").unwrap();
        let scope = temporary.path().join("scope");
        initialize_scope(&scope).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let joins: Vec<_> = (0..8)
            .map(|_| {
                let scope = scope.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    prepare_endpoint(&scope, Some("alice"), "example", Some(2222)).unwrap()
                })
            })
            .collect();
        let sockets: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        assert!(sockets.iter().all(|socket| socket == &sockets[0]));
        assert_eq!(scope_records(&scope).unwrap().len(), 1);
    }

    #[test]
    fn explicit_scope_validation_never_follows_or_chmods_a_symlink() {
        let temporary = crate::test_support::tempdir().unwrap();
        let victim = temporary.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let attack = temporary.path().join("scope");
        std::os::unix::fs::symlink(&victim, &attack).unwrap();
        assert!(validate_scope(&attack).is_err());
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn master_exit_targets_the_recorded_endpoint_and_socket() {
        let record = EndpointRecord::new(Some("alice"), "example", Some(2222));
        let command =
            master_exit_command(Path::new("/run/user/1/scope/cm-deadbeefdeadbeef"), &record);
        let args: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "-S",
                "/run/user/1/scope/cm-deadbeefdeadbeef",
                "-O",
                "exit",
                "-l",
                "alice",
                "-p",
                "2222",
                "--",
                "example"
            ]
        );
    }

    #[test]
    fn master_exit_preserves_path_bytes_and_escapes_openssh_percent_tokens() {
        let path = PathBuf::from(OsString::from_vec(
            b"/tmp/scope with space/%h/non-utf8-\xff/socket".to_vec(),
        ));
        let command = master_exit_command(&path, &EndpointRecord::new(None, "example", None));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[0], OsStr::new("-S"));
        assert_eq!(
            args[1].as_bytes(),
            b"/tmp/scope with space/%%h/non-utf8-\xff/socket"
        );
    }

    #[test]
    fn openssh_environment_and_tilde_expansion_forms_are_refused() {
        assert!(validate_openssh_control_path(Path::new("/tmp/scope with space/%h")).is_ok());
        assert!(validate_openssh_control_path(Path::new("~/scope")).is_err());
        assert!(validate_openssh_control_path(Path::new("/tmp/${HOME}/scope")).is_err());
    }
}
