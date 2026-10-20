//! An independently authenticated SSH connection to an authorization provider.
//! One attachment session owns Allow grants; Unix forwarding carries further
//! service requests without consuming additional sshd session slots.
use super::{foreground, persistent};
use crate::auth_from::Provider;
use crate::cli::NativeEndpoint;
use crate::destination::forward::DeadlineIo;
use crate::destination::{read_message, write_message};
use crate::persistence::Domain;
use crate::process::CommandExt as _;
use crate::receive_service::provider::{self as service, SessionRequest, Ticket};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const INDEX: &str = "provider-links-v1";
const KEEPER: &str = "--ssh-provider-keeper";
const ATTACH: &str = "--ssh-provider-attach";
const INSTALL: &str = "--ssh-provider-install";
const SETUP: Duration = Duration::from_secs(120);
const MASTER_OPTIONS: &[&str] = &[
    "ControlPersist=no",
    "ForwardAgent=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=3",
    // Later -O forward commands use this master's bind policy. Configured
    // masks can override it, so also normalize the socket after forwarding.
    "StreamLocalBindMask=0177",
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    build: String,
    provider: Provider,
    generation: String,
    scope_identity: (u64, u64),
    directory: PathBuf,
    ticket: Option<Ticket>,
}
impl Record {
    fn control(&self) -> PathBuf {
        self.directory.join("m")
    }
    fn forwarded(&self) -> PathBuf {
        self.directory.join("f")
    }
    fn endpoint(&self) -> Result<&NativeEndpoint> {
        match &self.provider {
            Provider::Ssh { endpoint } => Ok(endpoint),
            Provider::Return(_) => bail!("native provider record contains a return destination"),
        }
    }
    fn binding(&self) -> Result<Option<String>> {
        self.ticket
            .as_ref()
            .map(|ticket| {
                Ok(blake3::hash(&serde_json::to_vec(&(
                    &self.provider,
                    &self.build,
                    &self.generation,
                    self.scope_identity,
                    ticket,
                ))?)
                .to_hex()
                .to_string())
            })
            .transpose()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Startup {
    scope: Option<PathBuf>,
    record: Record,
    lock_fd: i32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attached {
    build: String,
    socket: PathBuf,
    ticket: Ticket,
}

fn key(provider: &Provider) -> Result<String> {
    provider.validate()?;
    anyhow::ensure!(
        matches!(provider, Provider::Ssh { .. }),
        "expected an SSH provider"
    );
    Ok(blake3::hash(&serde_json::to_vec(provider)?)
        .to_hex()
        .to_string())
}
fn index(domain: &Domain) -> PathBuf {
    domain.runtime_path().join(INDEX)
}
fn record_path(domain: &Domain, provider: &Provider) -> Result<PathBuf> {
    Ok(index(domain).join(format!("{}.json", key(provider)?)))
}
fn owned_directory(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "SSH provider directory must be owned and private: {}",
        path.display()
    );
    Ok(true)
}
fn directory(domain: &Domain) -> Result<PathBuf> {
    domain.ensure_runtime()?;
    let path = index(domain);
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    anyhow::ensure!(
        owned_directory(&path)?,
        "SSH provider directory disappeared"
    );
    Ok(path)
}
fn lock_file(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() == 0,
        "SSH provider lock must be an empty owned private file"
    );
    Ok(file)
}
fn try_lock(file: &File) -> Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    Err(error.into())
}
fn lock_is_available(lock: File) -> Result<bool> {
    if !try_lock(&lock)? {
        return Ok(false);
    }
    // A concurrent fork can inherit this open-file description. Closing our
    // descriptor alone would leave that child holding the temporary probe lock.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(true)
}
fn read_record(domain: &Domain, provider: &Provider) -> Result<Option<Record>> {
    if !owned_directory(&index(domain))? {
        return Ok(None);
    }
    let path = record_path(domain, provider)?;
    let bytes =
        match crate::delegation::read_private_regular(&path, "SSH provider record", 16 * 1024) {
            Ok(bytes) => bytes,
            Err(error) if missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
    let record: Record = serde_json::from_slice(&bytes)?;
    validate_record(domain, provider, &record)?;
    Ok(Some(record))
}
fn missing(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    })
}
fn validate_record(domain: &Domain, provider: &Provider, record: &Record) -> Result<()> {
    anyhow::ensure!(
        record.version == 1 && record.provider == *provider,
        "invalid SSH provider record"
    );
    record.endpoint()?;
    anyhow::ensure!(
        record.directory.parent() == Some(domain.runtime_path().as_path())
            && record
                .directory
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("provider-")),
        "SSH provider directory is outside its persistence domain"
    );
    if owned_directory(&record.directory)? {
        let owner = crate::delegation::read_private_regular(
            &record.directory.join("owner"),
            "SSH provider owner",
            64,
        )?;
        anyhow::ensure!(
            owner == key(provider)?.as_bytes(),
            "SSH provider directory owner differs"
        );
    }
    if let Some(ticket) = &record.ticket {
        validate_ticket(ticket)?;
    }
    Ok(())
}
fn validate_ticket(ticket: &Ticket) -> Result<()> {
    anyhow::ensure!(
        ticket.session.len() == 64 && ticket.session.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid provider session ticket"
    );
    crate::destination::validate_name(&ticket.profile)?;
    crate::receive_approval::provider_accounts::ProviderIdentity::new(
        ticket.identity.user.clone(),
        ticket.identity.receiver_identity.clone(),
    )?;
    Ok(())
}
fn write_record(domain: &Domain, record: &Record) -> Result<()> {
    let path = record_path(domain, &record.provider)?;
    let mut file = tempfile::NamedTempFile::new_in(index(domain))?;
    file.write_all(&serde_json::to_vec(record)?)?;
    file.persist(path)?;
    Ok(())
}
fn active(domain: &Domain, record: &Record) -> bool {
    domain.is_current(record.scope_identity)
        && persistent::generation_open(domain, &record.generation).unwrap_or(false)
        && !record_path(domain, &record.provider)
            .is_ok_and(|path| path.with_extension("stop").exists())
}
fn existing(domain: &Domain, provider: &Provider) -> Result<Option<Record>> {
    let Some(record) = read_record(domain, provider)? else {
        return Ok(None);
    };
    if record.build != crate::identity::build()
        || !active(domain, &record)
        || record.ticket.is_none()
    {
        return Ok(None);
    }
    let lock = match lock_file(
        &record_path(domain, provider)?.with_extension("lock"),
        false,
    ) {
        Ok(file) => file,
        Err(error) if missing(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if lock_is_available(lock)? {
        return Ok(None);
    }
    let metadata = match fs::symlink_metadata(record.forwarded()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "SSH provider forward must be an owned private socket"
    );
    Ok(Some(record))
}
pub(crate) fn local_binding(domain: &Domain, provider: &Provider) -> Result<Option<String>> {
    existing(domain, provider)?
        .map(|record| record.binding())
        .transpose()
        .map(Option::flatten)
}
fn endpoint_arguments(endpoint: &NativeEndpoint) -> Vec<OsString> {
    let mut args = Vec::new();
    if let Some(user) = &endpoint.user {
        args.extend(["-l".into(), user.into()]);
    }
    if let Some(port) = endpoint.port {
        args.extend(["-p".into(), port.to_string().into()]);
    }
    args.extend(["--".into(), endpoint.host.clone().into()]);
    args
}
fn strict_options(control: &Path) -> Vec<String> {
    let mut options = vec![
        "-F".into(),
        "/dev/null".into(),
        "-a".into(),
        "-x".into(),
        "-T".into(),
        "-S".into(),
        crate::persistence::openssh_control_path(control)
            .to_string_lossy()
            .into_owned(),
    ];
    for option in [
        "ControlMaster=no",
        "ProxyCommand=false",
        "ProxyJump=none",
        "BatchMode=yes",
        "PubkeyAuthentication=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
        "ForwardAgent=no",
        "PermitLocalCommand=no",
        "ClearAllForwardings=yes",
    ] {
        options.extend(["-o".into(), option.into()]);
    }
    options
}
fn master_command(record: &Record) -> Result<Command> {
    let mut command = Command::new("ssh");
    command.args(strict_options(&record.control()));
    // No reconnect: all callers must fail if this exact master has ended.
    record.endpoint()?;
    Ok(command)
}
fn control_metadata(record: &Record) -> Result<Option<fs::Metadata>> {
    if !owned_directory(&record.directory)? {
        return Ok(None);
    }
    let metadata = match fs::symlink_metadata(record.control()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "SSH provider control must be an owned private Unix socket"
    );
    Ok(Some(metadata))
}

// Only the caller holding the provider index lock can retire this path. On
// Linux a full queue returns EAGAIN, distinct from an abandoned listener's
// ECONNREFUSED. Darwin reports ECONNREFUSED for both; leave that case visible.
fn remove_abandoned_control(record: &Record) -> Result<bool> {
    let Some(before) = control_metadata(record)? else {
        return Ok(true);
    };
    let socket = crate::process::with_inheritance_guard(|| {
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
    })?;
    socket.set_nonblocking(true)?;
    match socket.connect(&socket2::SockAddr::unix(record.control())?) {
        Ok(()) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(control_metadata(record)?.is_none());
        }
        Err(error) if cfg!(target_os = "linux")
            && error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(error).with_context(|| format!(
            "cannot verify whether SSH provider control {} is abandoned; retry shutdown, or remove this socket only after confirming its provider SSH master has stopped",
            record.control().display()
        )),
    }
    let Some(after) = control_metadata(record)? else {
        return Ok(true);
    };
    anyhow::ensure!(
        (before.dev(), before.ino()) == (after.dev(), after.ino()),
        "SSH provider control changed while checking abandonment"
    );
    match fs::remove_file(record.control()) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn stop_master(record: &Record) -> Result<()> {
    if control_metadata(record)?.is_none() {
        return Ok(());
    }
    let mut command = master_command(record)?;
    command
        .args(["-O", "exit"])
        .args(endpoint_arguments(record.endpoint()?));
    let deadline = Instant::now() + Duration::from_secs(5);
    let output =
        crate::process::capture_output_bounded(&mut command, deadline, &|| false, 16 * 1024)?;
    if !output.status.success() && !remove_abandoned_control(record)? {
        bail!(
            "SSH provider refused shutdown: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    while record.control().exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    anyhow::ensure!(
        !record.control().exists(),
        "SSH provider master did not close"
    );
    Ok(())
}
fn remove_record(domain: &Domain, record: &Record) -> Result<()> {
    stop_master(record)?;
    for path in [record.forwarded(), record.directory.join("owner")] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    match fs::remove_dir(&record.directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::remove_file(record_path(domain, &record.provider)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
struct OwnedRecord {
    domain: Domain,
    record: Record,
    armed: bool,
}
impl Drop for OwnedRecord {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = remove_record(&self.domain, &self.record) {
                crate::output::diagnostic!("syq: SSH provider cleanup: {error:#}");
            }
        }
    }
}

fn ensure(domain: &Domain, provider: &Provider) -> Result<Record> {
    if let Some(record) = existing(domain, provider)? {
        return Ok(record);
    }
    directory(domain)?;
    let generation = persistent::ensure_generation(domain)?;
    let identity = domain.identity()?;
    let path = record_path(domain, provider)?;
    let lock = lock_file(&path.with_extension("lock"), true)?;
    let signals = foreground::Signals::new()?;
    let deadline = Instant::now() + SETUP;
    while !try_lock(&lock)? {
        if let Some(record) = existing(domain, provider)? {
            return Ok(record);
        }
        anyhow::ensure!(
            Instant::now() < deadline && signals.received.load(Ordering::Acquire) == 0,
            "SSH provider setup interrupted or exceeded its deadline"
        );
        signals.wait(Duration::from_millis(100))?;
    }
    if let Some(old) = read_record(domain, provider)? {
        remove_record(domain, &old)?;
    }
    match fs::remove_file(path.with_extension("stop")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let directory = tempfile::Builder::new()
        .prefix("provider-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(domain.ensure_runtime()?)?
        .keep();
    let record = Record {
        version: 1,
        build: crate::identity::build().into(),
        provider: provider.clone(),
        generation,
        scope_identity: identity,
        directory,
        ticket: None,
    };
    let mut owner_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(record.directory.join("owner"))?;
    owner_file.write_all(key(provider)?.as_bytes())?;
    let mut owner = OwnedRecord {
        domain: domain.clone(),
        record,
        armed: true,
    };
    crate::persistence::validate_openssh_socket_path(&owner.record.control())?;
    socket_path(&owner.record.forwarded())?;
    write_record(domain, &owner.record)?;
    let cancelled = || {
        signals.received.load(Ordering::Acquire) != 0
            || !active(domain, &owner.record)
            || Instant::now() >= deadline
    };
    anyhow::ensure!(!cancelled(), "SSH provider setup cancelled");
    let mut master = Command::new("ssh");
    master.args(["-a", "-x", "-T", "-M", "-N", "-f", "-S"]).arg(
        crate::persistence::openssh_control_path(&owner.record.control()),
    );
    for option in MASTER_OPTIONS {
        master.args(["-o", *option]);
    }
    master
        .args(endpoint_arguments(owner.record.endpoint()?))
        .stdout(Stdio::null());
    anyhow::ensure!(
        foreground::run_cached(&mut master, cancelled)? == 0,
        "could not authenticate to SSH authorization provider {}",
        provider.label()
    );
    anyhow::ensure!(!cancelled(), "SSH provider setup cancelled");
    let spec = helper_spec(&owner.record)?;
    let mut probe = spec.helper_command(&["--build-identity".into()]);
    let result =
        crate::process::capture_output_bounded(&mut probe, deadline, &cancelled, 16 * 1024)?;
    if crate::remote_helper::needs_install(result.status.code()) {
        let mut install = crate::process::self_command()?;
        install
            .arg(INSTALL)
            .arg(serde_json::to_string(&owner.record)?);
        let result =
            crate::process::capture_output_bounded(&mut install, deadline, &cancelled, 64 * 1024)?;
        anyhow::ensure!(
            result.status.success(),
            "could not install SSH provider helper: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    } else {
        anyhow::ensure!(
            result.status.success()
                && String::from_utf8_lossy(&result.stdout).trim() == crate::identity::build(),
            "SSH provider helper is unavailable or has a different build: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    anyhow::ensure!(!cancelled(), "SSH provider setup cancelled");
    launch_keeper(domain, &owner.record, &lock, deadline, &cancelled)?;
    owner.armed = false;
    drop(lock);
    existing(domain, provider)?.context("SSH provider ended before it became ready")
}

struct Starting(Option<Child>);
impl Drop for Starting {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
        }
    }
}
fn launch_keeper(
    domain: &Domain,
    record: &Record,
    lock: &File,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    let (mut parent, child) = crate::process::with_inheritance_guard(UnixStream::pair)?;
    let mut command = crate::process::self_command()?;
    command
        .arg(KEEPER)
        .process_group(0)
        .stdin(Stdio::from(File::from(OwnedFd::from(child.try_clone()?))))
        .stdout(Stdio::from(File::from(OwnedFd::from(child))))
        .stderr(Stdio::null());
    persistent::protect_keeper_inheritance(&mut command)?;
    let descriptor = lock.as_raw_fd();
    // Only this owned flock descriptor crosses exec in addition to startup IO.
    // fcntl is async-signal-safe; the keeper restores CLOEXEC before spawning.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(descriptor, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut process = Starting(Some(command.spawn_guarded()?));
    write_message(
        &mut parent,
        &Startup {
            scope: domain.explicit_path().map(Path::to_path_buf),
            record: record.clone(),
            lock_fd: descriptor,
        },
    )?;
    let reply: std::result::Result<(), String> = read_message(&mut DeadlineIo {
        inner: &mut parent,
        deadline,
        cancelled: Some(cancelled),
    })?;
    reply.map_err(anyhow::Error::msg)?;
    let mut child = process.0.take().unwrap();
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
fn socket_path(path: &Path) -> Result<()> {
    let value = path
        .to_str()
        .context("SSH provider socket path is not UTF-8")?;
    anyhow::ensure!(path.is_absolute() && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte)),
        "SSH provider Unix forwarding requires a plain absolute socket path without SSH expansion tokens");
    Ok(())
}
fn privatize_forwarded_socket(path: &Path) -> Result<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("open SSH provider forwarding directory")?;
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
        "SSH provider forwarding directory must be owned and private"
    );
    let socket_metadata = || -> Result<libc::stat> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                c"f".as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("inspect SSH provider forward");
        }
        Ok(unsafe { metadata.assume_init() })
    };
    let before = socket_metadata()?;
    anyhow::ensure!(
        before.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && before.st_uid == unsafe { libc::geteuid() },
        "SSH provider forward must be an owned Unix socket"
    );
    // OpenSSH may use a configured StreamLocalBindMask instead of our CLI
    // value. The private parent protects this socket until we set its mode,
    // before publishing the attachment. Never follow a substituted symlink.
    let result = unsafe {
        libc::fchmodat(
            directory.as_raw_fd(),
            c"f".as_ptr(),
            0o600,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("make SSH provider forward private");
    }
    let after = socket_metadata()?;
    anyhow::ensure!(
        (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
            && after.st_mode & 0o777 == 0o600,
        "SSH provider forward changed while setting private permissions"
    );
    Ok(())
}

fn forward_service(record: &Record, remote: &Path) -> Result<()> {
    socket_path(remote)?;
    let mut command = Command::new("ssh");
    command.args(strict_options(&record.control()).into_iter().map(|arg| {
        if arg == "ClearAllForwardings=yes" {
            "ClearAllForwardings=no".into()
        } else {
            arg
        }
    }));
    command
        .args([
            "-o",
            "StreamLocalBindUnlink=no",
            "-o",
            "StreamLocalBindMask=0177",
            "-o",
            "ExitOnForwardFailure=yes",
            "-O",
            "forward",
            "-L",
        ])
        .arg(format!(
            "{}:{}",
            record.forwarded().display(),
            remote.display()
        ))
        .args(endpoint_arguments(record.endpoint()?));
    let output = crate::process::capture_output_bounded(
        &mut command,
        Instant::now() + Duration::from_secs(10),
        &|| false,
        16 * 1024,
    )?;
    anyhow::ensure!(
        output.status.success(),
        "SSH provider requires local Unix socket forwarding: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    privatize_forwarded_socket(&record.directory)?;
    Ok(())
}
fn probe_forwarded(record: &Record, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<()> {
    (|| -> Result<()> {
        let socket = crate::process::with_inheritance_guard(|| {
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        })?;
        socket.set_nonblocking(true)?;
        socket.connect(&socket2::SockAddr::unix(record.forwarded())?)?;
        socket.set_nonblocking(false)?;
        service::probe_forwarded(socket.into(), deadline, cancelled)
    })()
    .with_context(|| {
        format!(
            "verify SSH authorization provider {} through its forwarded socket",
            record.provider
        )
    })
}

fn keeper(startup: Startup) -> Result<()> {
    let deadline = Instant::now() + SETUP;
    let domain = Domain::select(startup.scope.as_deref())?;
    validate_record(&domain, &startup.record.provider, &startup.record)?;
    anyhow::ensure!(startup.lock_fd > 2, "invalid SSH provider startup lock");
    let lock = unsafe { File::from_raw_fd(startup.lock_fd) };
    let expected = lock_file(
        &record_path(&domain, &startup.record.provider)?.with_extension("lock"),
        false,
    )?;
    let actual_metadata = lock.metadata()?;
    let expected_metadata = expected.metadata()?;
    anyhow::ensure!(
        (actual_metadata.dev(), actual_metadata.ino())
            == (expected_metadata.dev(), expected_metadata.ino()),
        "SSH provider startup lock changed"
    );
    anyhow::ensure!(
        unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
        "could not protect SSH provider lock descriptor"
    );
    let mut owner = OwnedRecord {
        domain,
        record: startup.record,
        armed: true,
    };
    let signals = foreground::Signals::new()?;
    let cancelled =
        || signals.received.load(Ordering::Acquire) != 0 || !active(&owner.domain, &owner.record);
    anyhow::ensure!(
        !cancelled(),
        "SSH provider setup cancelled before attachment"
    );
    let mut command = master_command(&owner.record)?;
    command
        .args(endpoint_arguments(owner.record.endpoint()?))
        .arg(crate::remote_helper::launcher(&[ATTACH.into()], None));
    let mut helper = crate::destination::forward::ForwardChild::spawn_command(command)?;
    let mut output = helper
        .child
        .stdout
        .take()
        .context("provider helper stdout")?;
    let hello: std::result::Result<Attached, String> = read_message(&mut DeadlineIo {
        inner: &mut output,
        deadline: Instant::now() + Duration::from_secs(30),
        cancelled: Some(&cancelled),
    })
    .with_context(|| format!("read SSH provider attachment: {}", helper.errors()))?;
    let hello = hello.map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        hello.build == crate::identity::build(),
        "SSH provider attachment uses build {}, but requester uses {}; install the same syq build on both machines and restart receiving locally on the provider",
        hello.build,
        crate::identity::build()
    );
    validate_ticket(&hello.ticket)?;
    forward_service(&owner.record, &hello.socket)?;
    // -O forward only creates the local listener. sshd can still deny the
    // remote Unix channel, so prove the existing service protocol end to end
    // before publishing a reusable binding or reporting successful setup.
    probe_forwarded(&owner.record, deadline, &cancelled)?;
    anyhow::ensure!(
        !cancelled(),
        "SSH provider setup cancelled before readiness"
    );
    owner.record.ticket = Some(hello.ticket);
    write_record(&owner.domain, &owner.record)?;
    write_message(&mut std::io::stdout(), &Ok::<(), String>(()))?;
    // The attachment is a scope-owned service. It is intentionally not an
    // idle native master: its one session stays open until off or disconnect.
    loop {
        if signals.received.load(Ordering::Acquire) != 0 || !active(&owner.domain, &owner.record) {
            break;
        }
        let mut descriptor = libc::pollfd {
            fd: output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, 1000) };
        if ready < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break;
        }
        if ready > 0 {
            break;
        } // The helper only speaks once; EOF ends its lease.
    }
    drop(helper);
    drop(owner);
    drop(lock);
    Ok(())
}

fn attach_helper() -> Result<()> {
    let attachment = service::attach(None)?;
    let hello = Attached {
        build: crate::identity::build().into(),
        socket: attachment.socket_path().into(),
        ticket: attachment.ticket().clone(),
    };
    write_message(&mut std::io::stdout(), &Ok::<_, String>(hello))?;
    loop {
        let mut descriptors = [
            libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: attachment.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        // stdin is lifetime-only. Any EOF/data or provider shutdown ends Allow.
        if ready > 0 {
            return Ok(());
        }
    }
}

pub(crate) fn resolve_connection(domain: &Domain, provider: &Provider) -> Result<String> {
    ensure(domain, provider)?
        .binding()?
        .context("SSH provider has no live attachment")
}
pub(crate) fn open(
    domain: &Domain,
    provider: &Provider,
    binding: &str,
    operation: SessionRequest,
) -> Result<UnixStream> {
    let record = existing(domain, provider)?
        .context("SSH authorization provider connection ended; retry the command")?;
    anyhow::ensure!(
        record.binding()?.as_deref() == Some(binding),
        "SSH authorization provider changed; retry the command"
    );
    let stream = UnixStream::connect(record.forwarded())?;
    service::open_forwarded(
        stream,
        &record
            .ticket
            .context("SSH provider attachment missing")?
            .session,
        operation,
    )
}
fn entry_key(path: &Path, extension: &str) -> bool {
    path.extension().is_some_and(|value| value == extension)
        && path
            .file_stem()
            .and_then(|value| value.to_str())
            .is_some_and(|value| {
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
}
pub(crate) fn stop_all(domain: &Domain) -> Result<()> {
    if !owned_directory(&index(domain))? {
        return Ok(());
    }
    let mut errors = Vec::new();
    let mut locks = Vec::new();
    for entry in fs::read_dir(index(domain))? {
        let path = entry?.path();
        if !entry_key(&path, "lock") {
            continue;
        }
        match lock_file(&path, false) {
            Ok(lock) => {
                if let Err(error) = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path.with_extension("stop"))
                {
                    errors.push(error.to_string());
                }
                locks.push(lock);
            }
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut running = false;
        for lock in &locks {
            match try_lock(lock) {
                Ok(acquired) => running |= !acquired,
                Err(error) => errors.push(format!("{error:#}")),
            }
        }
        if !running {
            break;
        }
        if Instant::now() >= deadline {
            errors.push("SSH provider keepers did not stop within 15 seconds".into());
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}
pub(crate) fn cleanup_domain(domain: &Domain) -> Result<()> {
    if !owned_directory(&index(domain))? {
        return Ok(());
    }
    let mut errors = Vec::new();
    for entry in fs::read_dir(index(domain))? {
        let path = entry?.path();
        if !entry_key(&path, "json") {
            continue;
        }
        let result = (|| -> Result<()> {
            let lock = lock_file(&path.with_extension("lock"), false)?;
            anyhow::ensure!(try_lock(&lock)?, "SSH provider keeper is still active");
            let bytes =
                crate::delegation::read_private_regular(&path, "SSH provider record", 16 * 1024)?;
            let record: Record = serde_json::from_slice(&bytes)?;
            validate_record(domain, &record.provider, &record)?;
            anyhow::ensure!(
                path == record_path(domain, &record.provider)?,
                "SSH provider record name differs"
            );
            remove_record(domain, &record)
        })();
        if let Err(error) = result {
            errors.push(format!("{error:#}"));
        }
    }
    if errors.is_empty() {
        for entry in fs::read_dir(index(domain))? {
            let path = entry?.path();
            anyhow::ensure!(
                entry_key(&path, "lock") || entry_key(&path, "stop"),
                "unrecognized SSH provider state: {}",
                path.display()
            );
            let file = lock_file(&path, false)?;
            anyhow::ensure!(try_lock(&file)?, "SSH provider keeper is still active");
            fs::remove_file(path)?;
        }
        fs::remove_dir(index(domain))?;
    }
    anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

fn helper_spec(record: &Record) -> Result<crate::conn::RemoteSpec> {
    record.provider.validate()?;
    crate::persistence::validate_openssh_socket_path(&record.control())?;
    let mut spec = crate::conn::RemoteSpec::local_receiver(false);
    spec.local_process = false;
    spec.user = record.endpoint()?.user.clone();
    spec.host = record.endpoint()?.host.clone();
    spec.port = record.endpoint()?.port;
    spec.rsh = std::iter::once("ssh".to_owned())
        .chain(strict_options(&record.control()))
        .collect();
    spec.bootstrap_helper = true;
    Ok(spec)
}

pub(crate) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    if argv.len() == 3 && argv[1] == INSTALL {
        return Some((|| {
            let record: Record = serde_json::from_str(
                argv[2]
                    .to_str()
                    .context("invalid provider install request")?,
            )?;
            helper_spec(&record)?.install_helper()?;
            Ok(0)
        })());
    }
    if argv.len() != 2 {
        return None;
    }
    if argv[1] == ATTACH {
        return Some((|| {
            if let Err(error) = attach_helper() {
                let _ = write_message(
                    &mut std::io::stdout(),
                    &Err::<Attached, _>(format!("{error:#}")),
                );
                return Err(error);
            }
            Ok(0)
        })());
    }
    if argv[1] != KEEPER {
        return None;
    }
    Some((|| {
        if let Err(error) = read_message(&mut std::io::stdin()).and_then(keeper) {
            let _ = write_message(&mut std::io::stdout(), &Err::<(), _>(format!("{error:#}")));
            return Err(error);
        }
        Ok(0)
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn provider() -> Provider {
        Provider::Ssh {
            endpoint: NativeEndpoint {
                user: Some("user".into()),
                host: "provider.invalid".into(),
                port: Some(22),
            },
        }
    }

    fn cleanup_fixture() -> (tempfile::TempDir, Domain, Record) {
        let root = crate::test_support::short_tempdir().unwrap();
        let scope = root.path().join("s");
        crate::persistence::initialize_scope(&scope).unwrap();
        let domain = Domain::select(Some(&scope)).unwrap();
        directory(&domain).unwrap();
        let physical = domain.runtime_path().join("provider-test");
        fs::DirBuilder::new().mode(0o700).create(&physical).unwrap();
        let record = Record {
            version: 1,
            build: crate::identity::build().into(),
            provider: provider(),
            generation: persistent::ensure_generation(&domain).unwrap(),
            scope_identity: domain.identity().unwrap(),
            directory: physical,
            ticket: None,
        };
        let mut owner = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(record.directory.join("owner"))
            .unwrap();
        owner
            .write_all(key(&record.provider).unwrap().as_bytes())
            .unwrap();
        write_record(&domain, &record).unwrap();
        (root, domain, record)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn abandoned_provider_socket_does_not_block_shutdown_or_reconnect_cleanup() {
        let (_root, domain, record) = cleanup_fixture();
        let lock = lock_file(
            &record_path(&domain, &record.provider)
                .unwrap()
                .with_extension("lock"),
            true,
        )
        .unwrap();
        assert!(try_lock(&lock).unwrap());
        for path in [record.control(), record.forwarded()] {
            drop(UnixListener::bind(&path).unwrap());
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        validate_record(&domain, &record.provider, &record).unwrap();
        // Exercise the real mux-only `ssh -O exit` refusal, not a mocked status.
        remove_record(&domain, &record).unwrap();
        assert!(!record.directory.exists());
        assert!(!record_path(&domain, &record.provider).unwrap().exists());
        assert!(persistent::generation_open(&domain, &record.generation).unwrap());
    }

    #[test]
    fn provider_cleanup_preserves_live_or_unverified_control_paths() {
        let (_root, _domain, record) = cleanup_fixture();
        let listener = UnixListener::bind(record.control()).unwrap();
        fs::set_permissions(record.control(), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!remove_abandoned_control(&record).unwrap());
        assert!(record.control().exists());
        drop(listener);
        fs::remove_file(record.control()).unwrap();
        fs::write(record.control(), b"not a socket").unwrap();
        assert!(stop_master(&record).is_err());
        assert_eq!(fs::read(record.control()).unwrap(), b"not a socket");
        fs::remove_file(record.control()).unwrap();
        let target = record.directory.join("target");
        let _listener = UnixListener::bind(&target).unwrap();
        std::os::unix::fs::symlink(&target, record.control()).unwrap();
        assert!(stop_master(&record).is_err());
        assert!(target.exists());
        assert!(fs::symlink_metadata(record.control())
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provider_cleanup_does_not_guess_when_refused_is_ambiguous() {
        let (_root, _domain, record) = cleanup_fixture();
        drop(UnixListener::bind(record.control()).unwrap());
        fs::set_permissions(record.control(), fs::Permissions::from_mode(0o600)).unwrap();
        let error = remove_abandoned_control(&record).unwrap_err();
        assert!(error.to_string().contains("only after confirming"));
        assert!(record.control().exists());
    }

    #[test]
    fn provider_master_defaults_to_private_unix_forward_permissions() {
        let root = crate::test_support::tempdir().unwrap();
        let config = root.path().join("config");
        fs::write(&config, "# No configured bind mask\n").unwrap();
        let mut command = Command::new("ssh");
        command.args(["-G", "-MNf", "-F"]).arg(config);
        for option in MASTER_OPTIONS {
            command.args(["-o", *option]);
        }
        let output = command.arg("host.invalid").capture_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config = String::from_utf8(output.stdout).unwrap();
        assert!(
            config
                .lines()
                .any(|line| line == "streamlocalbindmask 0177"),
            "{config}"
        );
        // This provider launcher intentionally daemonizes; only its foreground
        // helpers and approved-account master override configured forking.
        assert!(
            config
                .lines()
                .any(|line| line == "forkafterauthentication yes"),
            "{config}"
        );
    }

    #[test]
    fn provider_forward_normalizes_configured_mask_before_publication() {
        let root = crate::test_support::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.path().join("f");
        let _listener = UnixListener::bind(&socket).unwrap();
        // Model the actual socket created by a master configured with mask 0000.
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o777)).unwrap();
        privatize_forwarded_socket(root.path()).unwrap();
        let metadata = fs::symlink_metadata(&socket).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }

    #[test]
    fn provider_forward_refuses_non_socket_and_non_private_parent() {
        let root = crate::test_support::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.path().join("f");
        let target = root.path().join("target");
        fs::write(&target, b"untouched").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&target, &socket).unwrap();
        assert_eq!(
            privatize_forwarded_socket(root.path())
                .unwrap_err()
                .to_string(),
            "SSH provider forward must be an owned Unix socket"
        );
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
        fs::remove_file(&socket).unwrap();
        fs::write(&socket, b"not a socket").unwrap();
        assert_eq!(
            privatize_forwarded_socket(root.path())
                .unwrap_err()
                .to_string(),
            "SSH provider forward must be an owned Unix socket"
        );
        fs::remove_file(&socket).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            privatize_forwarded_socket(root.path())
                .unwrap_err()
                .to_string(),
            "SSH provider forwarding directory must be owned and private"
        );
        assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o777);
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn absent_local_binding_creates_no_state_or_provider_connection() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("scope");
        let domain = Domain::Explicit(path.clone());
        assert!(local_binding(&domain, &provider()).unwrap().is_none());
        assert!(!path.exists());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);

        crate::persistence::initialize_scope(&path).unwrap();
        let mut before = fs::read_dir(&path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert!(local_binding(&domain, &provider()).unwrap().is_none());
        let mut after = fs::read_dir(&path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        before.sort();
        after.sort();
        assert_eq!(after, before);
        assert!(!index(&domain).exists());
        assert!(!domain.approved_index_path().exists());
    }

    #[test]
    fn availability_probe_releases_lock_with_shared_descriptor_alive() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("provider.lock");
        let probe = lock_file(&path, true).unwrap();
        // A cloned descriptor shares flock ownership just as an inherited one
        // does, without needing a concurrent fork to reproduce the race.
        let inherited = probe.try_clone().unwrap();
        assert!(lock_is_available(probe).unwrap());
        let keeper = lock_file(&path, false).unwrap();
        let acquired = try_lock(&keeper).unwrap();
        let available_while_owned = lock_is_available(lock_file(&path, false).unwrap()).unwrap();
        assert_eq!(unsafe { libc::flock(keeper.as_raw_fd(), libc::LOCK_UN) }, 0);
        drop(inherited);
        assert!(
            acquired,
            "probe lock survived through its shared descriptor"
        );
        assert!(
            !available_while_owned,
            "probe released another owner's lock"
        );
    }

    #[test]
    fn local_binding_requires_live_ownership_and_current_domain_generation() {
        let root = crate::test_support::short_tempdir().unwrap();
        let scope = root.path().join("scope");
        crate::persistence::initialize_scope(&scope).unwrap();
        let domain = Domain::select(Some(&scope)).unwrap();
        directory(&domain).unwrap();
        let provider = provider();
        let physical = tempfile::Builder::new()
            .prefix("provider-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(domain.runtime_path())
            .unwrap();
        let mut owner = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(physical.path().join("owner"))
            .unwrap();
        owner.write_all(key(&provider).unwrap().as_bytes()).unwrap();
        let record = Record {
            version: 1,
            build: crate::identity::build().into(),
            provider: provider.clone(),
            generation: persistent::ensure_generation(&domain).unwrap(),
            scope_identity: domain.identity().unwrap(),
            directory: physical.path().into(),
            ticket: Some(Ticket {
                session: "a".repeat(64),
                profile: "provider".into(),
                identity: crate::receive_approval::provider_accounts::ProviderIdentity::new(
                    "user".into(),
                    ssh_key::Fingerprint::Sha256([1; 32]).to_string(),
                )
                .unwrap(),
            }),
        };
        let socket = UnixListener::bind(record.forwarded()).unwrap();
        socket.set_nonblocking(true).unwrap();
        fs::set_permissions(record.forwarded(), fs::Permissions::from_mode(0o600)).unwrap();
        write_record(&domain, &record).unwrap();
        // A stale record and socket alone cannot prove a live provider lease.
        assert!(local_binding(&domain, &provider).unwrap().is_none());
        let lock = lock_file(
            &record_path(&domain, &provider)
                .unwrap()
                .with_extension("lock"),
            true,
        )
        .unwrap();
        assert!(local_binding(&domain, &provider).unwrap().is_none());
        assert!(try_lock(&lock).unwrap());
        assert_eq!(
            local_binding(&domain, &provider).unwrap(),
            record.binding().unwrap()
        );

        let mut stale = record.clone();
        stale.generation = if record.generation == "b".repeat(64) {
            "c".repeat(64)
        } else {
            "b".repeat(64)
        };
        write_record(&domain, &stale).unwrap();
        assert!(local_binding(&domain, &provider).unwrap().is_none());
        stale = record.clone();
        stale.scope_identity.1 ^= 1;
        write_record(&domain, &stale).unwrap();
        assert!(local_binding(&domain, &provider).unwrap().is_none());
        write_record(&domain, &record).unwrap();
        assert_eq!(
            local_binding(&domain, &provider).unwrap(),
            record.binding().unwrap()
        );
        // Warm lookup has not connected even to the local forwarding socket.
        assert_eq!(
            socket.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
        drop(lock);
        assert!(local_binding(&domain, &provider).unwrap().is_none());
    }
}
