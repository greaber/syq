//! A reusable approved SSH login, owned by a keeper while its laptop is connected.
use super::{foreground, SessionRequest, Tty};
use crate::cli::{AuthFrom, NativeEndpoint};
use crate::process::CommandExt as _;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const INTERNAL: &str = "--approved-ssh-master";
const POLL: Duration = Duration::from_millis(100);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Startup {
    command: Vec<Vec<u8>>,
    authorizer: String,
    scope: PathBuf,
    scope_device: u64,
    scope_inode: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    authorizer: String,
    requested: NativeEndpoint,
    endpoint: NativeEndpoint,
    control: PathBuf,
}

fn directory() -> Result<PathBuf> {
    let parent = crate::persistence::ensure_runtime_parent()?;
    let path = parent.join("authorized-ssh-v1");
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = path.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("SSH authority index must be an owner-only directory");
    }
    Ok(path)
}
fn index_path(authorizer: &str, destination: &NativeEndpoint) -> Result<PathBuf> {
    let identity = serde_json::to_vec(&(authorizer, destination))?;
    Ok(directory()?.join(format!("{}.json", blake3::hash(&identity).to_hex())))
}
fn read_record(path: &Path) -> Result<Option<Record>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 16384
    {
        bail!("SSH authority record must be a bounded owner-only file");
    }
    let record: Record = serde_json::from_reader(file)?;
    if record.version != 1 {
        bail!("unsupported SSH authority record; reconnect with syq persist connect");
    }
    Ok(Some(record))
}
fn master_options(record: &Record) -> Vec<OsString> {
    let mut options: Vec<OsString> = ["-F", "/dev/null", "-a", "-x", "-k", "-S"]
        .into_iter()
        .map(Into::into)
        .collect();
    options.push(crate::persistence::openssh_control_path(&record.control));
    // A missing master must fail, never start another authentication attempt.
    for option in [
        "ControlMaster=no",
        "ProxyCommand=false",
        "ProxyJump=none",
        "PubkeyAuthentication=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
    ] {
        options.extend(["-o".into(), option.into()]);
    }
    options
}
fn master_command(record: &Record) -> Command {
    let mut command = Command::new("ssh");
    command.args(master_options(record));
    command
}
fn validate_record(record: &Record) -> Result<()> {
    let scope = record
        .control
        .parent()
        .context("SSH authority control path has no scope")?;
    if scope.parent() != Some(crate::persistence::runtime_parent_path().as_path())
        || !scope
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("approved-"))
    {
        bail!("SSH authority record has an invalid scope");
    }
    crate::persistence::validate_scope(scope)?;
    crate::persistence::validate_openssh_socket_path(&record.control)?;
    Ok(())
}

pub(crate) struct Cached(Record);
impl Cached {
    pub(crate) fn control(&self) -> &Path {
        &self.0.control
    }
    pub(crate) fn endpoint(&self) -> &NativeEndpoint {
        &self.0.endpoint
    }
    pub(crate) fn options(&self) -> Vec<OsString> {
        master_options(&self.0)
    }
}

pub(crate) fn cached(authorizer: &str, requested: &NativeEndpoint) -> Result<Option<Cached>> {
    if !crate::persistence::global_enabled()? {
        return Ok(None);
    }
    let Some(record) = read_record(&index_path(authorizer, requested)?)? else {
        return Ok(None);
    };
    if record.authorizer != authorizer || record.requested != *requested {
        bail!("SSH authority record does not match the requested login");
    }
    active_record(record)
}

fn active_record(record: Record) -> Result<Option<Cached>> {
    // A crashed keeper can leave an expired index. Never reconnect through it.
    if !record.control.exists() {
        return Ok(None);
    }
    validate_record(&record)?;
    if record
        .control
        .parent()
        .unwrap()
        .join(crate::receive_service::CLOSING)
        .exists()
        || !live(&record)
    {
        return Ok(None);
    }
    Ok(Some(Cached(record)))
}

/// Reuse existing account authority before opening another connection. An
/// explicit authorizer never selects another laptop's approval; native-only
/// mode never consults the authority index. Automatic selection must be unique.
pub(crate) fn select_cached(requested: &NativeEndpoint, mode: &AuthFrom) -> Result<Option<Cached>> {
    match mode {
        AuthFrom::Ssh => return Ok(None),
        AuthFrom::Return(authorizer) => return cached(authorizer, requested),
        AuthFrom::Auto => {}
    }
    let index = crate::persistence::runtime_parent_path().join("authorized-ssh-v1");
    if !index.exists() || !crate::persistence::global_enabled()? {
        return Ok(None);
    }
    // Validate the existing directory before looking at any of its records.
    let index = directory()?;
    let mut selected = None;
    for entry in fs::read_dir(index)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let Some(record) = read_record(&path)? else {
            continue;
        };
        if record.requested != *requested {
            continue;
        }
        if let Some(active) = active_record(record)? {
            anyhow::ensure!(selected.is_none(),
                "more than one laptop has approved this SSH endpoint; select one with --auth-from @NAME or syq persist auth-from @NAME --for {}",
                requested.host);
            selected = Some(active);
        }
    }
    Ok(selected)
}

#[derive(Serialize)]
pub(crate) struct Status {
    authorizer: String,
    requested: NativeEndpoint,
    endpoint: NativeEndpoint,
    control: PathBuf,
    connected: bool,
}
pub(crate) fn status() -> Result<Vec<Status>> {
    if !crate::persistence::runtime_parent_path()
        .join("authorized-ssh-v1")
        .exists()
    {
        return Ok(Vec::new());
    }
    let directory = directory()?;
    let mut rows = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let Some(record) = read_record(&path)? else {
            continue;
        };
        if !record.control.exists() {
            continue;
        }
        validate_record(&record)?;
        let connected = live(&record);
        rows.push(Status {
            authorizer: record.authorizer,
            requested: record.requested,
            endpoint: record.endpoint,
            control: record.control,
            connected,
        });
    }
    rows.sort_by(|a, b| {
        (&a.authorizer, &a.requested.host).cmp(&(&b.authorizer, &b.requested.host))
    });
    Ok(rows)
}
pub(crate) fn print_status(rows: &[Status]) {
    for row in rows {
        crate::output::human_stdout!(
            "  {} through @{}  {} (reusable account access)\n    SSH control socket: {}",
            row.requested.host,
            row.authorizer,
            if row.connected { "ready" } else { "inactive" },
            row.control.display()
        );
    }
}
pub(crate) fn stop_all() -> Result<()> {
    let rows = status()?;
    for row in &rows {
        let record = Record {
            version: 1,
            authorizer: row.authorizer.clone(),
            requested: row.requested.clone(),
            endpoint: row.endpoint.clone(),
            control: row.control.clone(),
        };
        let _ = master_command(&record)
            .args(["-O", "exit", "--", &record.endpoint.host])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status_guarded();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while rows.iter().any(|row| row.control.exists()) {
        if Instant::now() >= deadline {
            bail!("approved SSH connection did not close within 5 seconds");
        }
        std::thread::sleep(POLL);
    }
    Ok(())
}
fn live(record: &Record) -> bool {
    master_command(record)
        .args(["-O", "check", "--", &record.endpoint.host])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status_guarded()
        .is_ok_and(|status| status.success())
}

pub(super) fn command(request: &SessionRequest, mode: &AuthFrom) -> Result<Option<Command>> {
    let Some(cached) = select_cached(&request.destination, mode)? else {
        return Ok(None);
    };
    let mut command = Command::new("ssh");
    command
        .args(cached.options())
        .args(request.ssh_arguments(cached.endpoint())?);
    Ok(Some(command))
}

struct Starting(Option<Child>);
impl Drop for Starting {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
        }
    }
}

pub(crate) fn connect(request: SessionRequest) -> Result<()> {
    super::super::ssh_auth::prepare_persistent(&request)?;
    let scope = crate::persistence::enable_global_scope()?;
    if command(&request, &AuthFrom::Return(request.authorizer.clone()))?.is_some() {
        crate::output::human_stdout!(
            "SSH account connection ready through @{}",
            request.authorizer
        );
        return Ok(());
    }
    let metadata = scope.symlink_metadata()?;
    let startup = Startup {
        command: super::super::handoff::command_line()?
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect(),
        authorizer: request.authorizer,
        scope,
        scope_device: metadata.dev(),
        scope_inode: metadata.ino(),
    };
    let signals = foreground::Signals::new()?;
    let (mut parent, child) = crate::process::with_inheritance_guard(UnixStream::pair)?;
    let mut process = Command::new(std::env::current_exe()?);
    use std::os::unix::process::CommandExt as _;
    process
        .arg(INTERNAL)
        .process_group(0)
        .stdin(Stdio::from(File::from(OwnedFd::from(child.try_clone()?))))
        .stdout(Stdio::from(File::from(OwnedFd::from(child))))
        .stderr(Stdio::null());
    let mut process = Starting(Some(process.spawn_guarded()?));
    super::super::write_message(&mut parent, &startup)?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let result: Result<std::result::Result<String, String>> =
            super::super::read_message(&mut parent);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(360);
    let mut progress = Instant::now();
    let result = loop {
        match receiver.recv_timeout(POLL) {
            Ok(result) => break result,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break Err(anyhow::anyhow!(
                    "SSH connection setup ended without readiness"
                ))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if signals.received.load(Ordering::Acquire) != 0 {
            break Err(anyhow::anyhow!("SSH connection setup interrupted"));
        }
        if Instant::now() >= deadline {
            break Err(anyhow::anyhow!(
                "SSH connection setup exceeded its approval/start deadline"
            ));
        }
        if progress.elapsed() >= Duration::from_secs(5) {
            crate::output::diagnostic!(
                "syq: waiting for persistent SSH approval and connection readiness"
            );
            progress = Instant::now();
        }
    };
    if result.as_ref().is_ok_and(|reply| reply.is_ok()) {
        let mut child = process.0.take().unwrap();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    drop(process);
    let _ = reader.join();
    let endpoint = result?.map_err(anyhow::Error::msg)?;
    crate::output::human_stdout!(
        "{} ready through @{}; account login remains available while the laptop is connected",
        endpoint,
        startup.authorizer
    );
    Ok(())
}

struct Index(PathBuf);
impl Drop for Index {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn global_still_open(startup: &Startup) -> Result<bool> {
    if !crate::persistence::global_enabled()?
        || startup.scope.join(crate::receive_service::CLOSING).exists()
    {
        return Ok(false);
    }
    match startup.scope.symlink_metadata() {
        Ok(metadata) => {
            Ok(metadata.dev() == startup.scope_device && metadata.ino() == startup.scope_inode)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn keeper(startup: Startup) -> Result<()> {
    let command: Vec<OsString> = startup
        .command
        .iter()
        .cloned()
        .map(OsString::from_vec)
        .collect();
    let request = crate::persistence::parse_account_connect(
        command
            .get(1..)
            .context("persistent SSH startup command missing")?,
        &startup.authorizer,
    )?;

    if !crate::persistence::is_global_scope(&startup.scope)? || !global_still_open(&startup)? {
        bail!("persistent SSH scope was disabled before setup");
    }
    crate::persistence::validate_scope(&startup.scope)?;
    let path = index_path(&request.authorizer, &request.destination)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.with_extension("lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("SSH authority lock must be an owner-only file");
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("this approved SSH connection is already starting or open; retry after it is ready");
    }
    let signals = foreground::Signals::new()?;
    let approval_request = request.clone();
    let shown_command = command
        .iter()
        .skip(1)
        .map(|arg| arg.as_bytes().to_vec())
        .collect();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    // The keeper is a dedicated child process. If setup is cancelled, it exits
    // and closes the pending return request even while approval is blocked.
    std::thread::Builder::new()
        .name("syq-ssh-approve".into())
        .spawn(move || {
            let _ = sender.send(super::super::ssh_auth::authorize_persistent(
                &approval_request,
                shown_command,
            ));
        })?;
    let approval_deadline = Instant::now() + Duration::from_secs(330);
    let session = loop {
        if signals.received.load(Ordering::Acquire) != 0 || !global_still_open(&startup)? {
            bail!("persistent SSH setup cancelled before approval");
        }
        match receiver.recv_timeout(POLL) {
            Ok(result) => break result?,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("persistent SSH authorization ended without a result")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if Instant::now() >= approval_deadline {
            bail!("persistent SSH authorization exceeded its deadline");
        }
    };
    let options = session.options();
    // Keep released endpoint records byte-compatible and separate from native masters.
    let scope = tempfile::Builder::new()
        .prefix("approved-")
        .tempdir_in(crate::persistence::ensure_runtime_parent()?)?;
    crate::persistence::initialize_scope(scope.path())?;
    let endpoint = session.endpoint();
    let control = crate::persistence::prepare_endpoint(
        scope.path(),
        endpoint.user.as_deref(),
        &endpoint.host,
        endpoint.port,
        None,
    )?;
    let mut master = Command::new("ssh");
    let mut iter = options.iter();
    while let Some(option) = iter.next() {
        if option == "-o" {
            let value = iter.next().context("incomplete SSH option")?;
            if value == "ControlMaster=no" || value == "ControlPath=none" {
                continue;
            }
            master.arg(option).arg(value);
        } else {
            master.arg(option);
        }
    }
    master
        .args(["-M", "-N", "-S"])
        .arg(crate::persistence::openssh_control_path(&control))
        .args(["-o", "ControlPersist=no"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let connect_request = SessionRequest {
        authorizer: request.authorizer.clone(),
        destination: request.destination.clone(),
        tty: Tty::Disabled,
        command: Vec::new(),
    };
    master.args(connect_request.ssh_arguments(endpoint)?);
    let _lifetime = super::master_lifetime::attach(&mut master)?;
    let mut master = foreground::ForegroundChild::spawn(&mut master, &signals)?;
    let record = Record {
        version: 1,
        authorizer: request.authorizer,
        requested: request.destination,
        endpoint: endpoint.clone(),
        control,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if signals.received.load(Ordering::Acquire) != 0
            || session.cancelled()
            || !global_still_open(&startup)?
        {
            bail!("persistent SSH authorization ended during connection setup");
        }
        if let Some(status) = master.poll()? {
            bail!("persistent SSH client exited before readiness ({status})");
        }
        if live(&record) {
            break;
        }
        if Instant::now() >= deadline {
            bail!("persistent SSH client did not become ready within 30 seconds");
        }
        signals.wait(POLL)?;
    }
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    serde_json::to_writer(&mut temporary, &record)?;
    temporary.write_all(b"\n")?;
    temporary.persist(&path)?;
    let _index = Index(path);
    super::super::write_message(
        &mut std::io::stdout(),
        &Ok::<_, String>(format!(
            "{}@{}:{}; SSH control socket: {}",
            endpoint.user.as_deref().unwrap_or(""),
            endpoint.host,
            endpoint.port.unwrap_or(22),
            record.control.display()
        )),
    )?;
    // Close the startup channel without keeping the original caller's pipe alive.
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
            return Err(std::io::Error::last_os_error())
                .context("detach persistent SSH startup channel");
        }
    }
    while master.poll()?.is_none() {
        if signals.received.load(Ordering::Acquire) != 0
            || session.cancelled()
            || !global_still_open(&startup)?
            || scope.path().join(crate::receive_service::CLOSING).exists()
        {
            break;
        }
        signals.wait(POLL)?;
    }
    master.stop(libc::SIGTERM)?;
    Ok(())
}

pub(crate) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    if argv.len() != 2 || argv[1] != INTERNAL {
        return None;
    }
    Some((|| {
        let result = super::super::read_message(&mut std::io::stdin()).and_then(keeper);
        if let Err(error) = result {
            let _ = super::super::write_message(
                &mut std::io::stdout(),
                &Err::<String, _>(format!("{error:#}")),
            );
            return Err(error);
        }
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn authority_index_rejects_links_public_files_and_unknown_versions() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("record");
        let record = Record {
            version: 1,
            authorizer: "laptop".into(),
            requested: NativeEndpoint {
                user: None,
                host: "alias".into(),
                port: None,
            },
            endpoint: NativeEndpoint {
                user: Some("user".into()),
                host: "server".into(),
                port: Some(22),
            },
            control: root.path().join("socket"),
        };
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_record(&path).unwrap().unwrap().requested.host, "alias");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_record(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_record(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &path,
            serde_json::to_vec(&Record {
                version: 2,
                ..record
            })
            .unwrap(),
        )
        .unwrap();
        assert!(read_record(&path).is_err());
        assert!(read_record(&root.path().join("missing")).unwrap().is_none());
    }

    #[test]
    fn cached_commands_cannot_authenticate_when_the_master_is_gone() {
        let root = crate::test_support::tempdir().unwrap();
        let record = Record {
            version: 1,
            authorizer: "laptop".into(),
            requested: NativeEndpoint {
                user: None,
                host: "alias".into(),
                port: None,
            },
            endpoint: NativeEndpoint {
                user: Some("user".into()),
                host: "127.0.0.1".into(),
                port: Some(1),
            },
            control: root.path().join("missing"),
        };
        let result = master_command(&record)
            .args(["-p", "1", "--", "127.0.0.1", "exit 17"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status_guarded()
            .unwrap();
        assert_eq!(result.code(), Some(255));
    }
}
