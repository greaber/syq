//! The enrolling machine's side of enrollment: one enrollment per server
//! account, set up and refreshed over the user's own login.
use super::*;
use crate::process::CommandExt as _;
use std::io::BufRead as _;

pub(super) fn local_state_base() -> Result<PathBuf> {
    let (_, home) = current_account()?;
    ensure_private_chain(&home, &LOCAL_STATE).context("validate enrollment state on this machine")
}

pub(super) const ENROLLMENT_FILE: &str = "enrollment.json";
pub(super) const PENDING_FILE: &str = "pending.json";
/// Present while a refresh of an active enrollment has not been confirmed.
/// The server may have applied it, as when the reply was lost, so the next
/// copy logs in to finish it even if the recorded key can still sign.
pub(super) const REFRESH_FILE: &str = "refreshing";

/// Whether an active enrollment must log in again before a copy uses it:
/// it runs another build, or a refresh of it was never confirmed.
pub(super) fn needs_refresh(metadata: &LocalEnrollment, directory: &Path) -> bool {
    metadata.release != crate::identity::build() || directory.join(REFRESH_FILE).exists()
}

/// The records named `file` in the enrollment directories below `base`, of
/// this version only: state that released versions wrote lives elsewhere
/// and is never read.
fn load_records<T: serde::de::DeserializeOwned>(
    base: &Path,
    file: &str,
    label: &str,
    version: impl Fn(&T) -> (u16, EnrollmentId),
) -> Result<Vec<(T, PathBuf)>> {
    let mut records = Vec::new();
    for entry in fs::read_dir(base).with_context(|| format!("list {}", base.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if delegation::validate_private_directory_path(&directory).is_err() {
            continue;
        }
        let Ok(encoded) =
            delegation::read_private_regular(&directory.join(file), label, MAX_STATE_FILE)
        else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<T>(&encoded) else {
            continue;
        };
        let (record_version, id) = version(&record);
        if record_version == CONFIG_VERSION && id.to_string() == entry.file_name().to_string_lossy()
        {
            records.push((record, directory));
        }
    }
    records.sort_by_key(|(record, _)| version(record).1.to_string());
    Ok(records)
}

pub(super) fn load_local_enrollments() -> Result<Vec<(LocalEnrollment, PathBuf)>> {
    load_local_enrollments_in(&local_state_base()?)
}

pub(super) fn load_local_enrollments_in(base: &Path) -> Result<Vec<(LocalEnrollment, PathBuf)>> {
    load_records(
        base,
        ENROLLMENT_FILE,
        "local enrollment",
        |record: &LocalEnrollment| (record.version, record.id),
    )
}

pub(super) fn load_pending_enrollments() -> Result<Vec<(PendingEnrollment, PathBuf)>> {
    load_records(
        &local_state_base()?,
        PENDING_FILE,
        "pending local enrollment",
        |record: &PendingEnrollment| (record.version, record.id),
    )
}

pub(super) fn complete_local_enrollment(
    directory: &Path,
    metadata: &LocalEnrollment,
) -> Result<()> {
    atomic_write(
        directory,
        ENROLLMENT_FILE,
        &serde_json::to_vec(metadata)?,
        0o600,
    )?;
    let directory = open_directory(directory)?;
    lock_directory(&directory)?;
    remove_leaf_locked(&directory, PENDING_FILE)?;
    remove_leaf_locked(&directory, REFRESH_FILE)
}

/// Remove an enrollment's local state, after it was revoked or its server
/// state was found missing.
pub(super) fn remove_local_enrollment(directory: &Path) -> Result<()> {
    delegation::validate_private_directory_path(directory)?;
    fs::remove_dir_all(directory)
        .with_context(|| format!("remove local enrollment {}", directory.display()))
}

#[derive(Debug)]
pub(super) struct EnrollmentSshError {
    pub(super) message: String,
    pub(super) transport: bool,
}

impl fmt::Display for EnrollmentSshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EnrollmentSshError {}

pub(super) fn enrollment_ssh_error(
    target: &SshEndpoint,
    transport: bool,
    message: impl fmt::Display,
) -> anyhow::Error {
    anyhow::Error::new(EnrollmentSshError {
        message: format!(
            "restricted enrollment SSH to {} failed: {message}",
            target.label()
        ),
        transport,
    })
}

pub(super) fn is_enrollment_transport_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<EnrollmentSshError>()
            .is_some_and(|failure| failure.transport)
    })
}

pub(super) fn run_ssh(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    remote_command: &str,
    input: &[u8],
) -> Result<Vec<u8>> {
    let args = enrollment::enrollment_ssh_args_raw(target, route, remote_command);
    let mut command = Command::new("ssh");
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn_guarded()
        .map_err(|error| enrollment_ssh_error(target, true, error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| enrollment_ssh_error(target, true, "stdin unavailable"))?;
    let write_error = stdin.write_all(input).err();
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| enrollment_ssh_error(target, true, error))?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(enrollment_ssh_error(
            target,
            output.status.code() == Some(255),
            format_args!(
                "{}: {}",
                output.status,
                if diagnostic.is_empty() {
                    "no diagnostic"
                } else {
                    &diagnostic
                }
            ),
        ));
    }
    if let Some(error) = write_error {
        return Err(enrollment_ssh_error(target, true, error));
    }
    Ok(output.stdout)
}

/// What a management session runs on the server after the user's login.
/// Installing runs in its own session (`install_over_route`), which also
/// reads the login trace.
#[derive(Clone, Copy)]
pub(super) enum ManagementAction {
    Revoke,
}

impl ManagementAction {
    pub(super) fn argument(self) -> &'static str {
        match self {
            Self::Revoke => "--restricted-revoke",
        }
    }
}

/// Shell commands that make the store's directory `$d` and stage the
/// uploaded syq at `$p` in it, removed again when the shell exits.
/// Directories above the store follow the umask; the store's own are the
/// owner's alone.
fn stage_commands(stage: &str) -> String {
    format!(
        "d=\"$HOME/{store}\"; p=\"$d/{stage}\"; mkdir -p -- \"$HOME/.local/lib\"; umask 077; mkdir -p -- \"$d\"; trap 'rm -f -- \"$p\"' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; cat >\"$p\"; chmod 700 \"$p\"",
        store = crate::user_dirs::BINARY_STORE_IN_HOME,
    )
}

pub(super) fn management_remote_command(
    stage: &str,
    action: ManagementAction,
    request: &[u8],
) -> Result<String> {
    let request = std::str::from_utf8(request).context("management request is not UTF-8")?;
    Ok(format!(
        "set -eu; {}; printf '%s' {} | \"$p\" {}",
        stage_commands(stage),
        shell_words::quote(request),
        action.argument()
    ))
}

pub(super) fn run_management_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    id: EnrollmentId,
    action: ManagementAction,
    input: &[u8],
) -> Result<Vec<u8>> {
    let platform = run_ssh(
        target,
        route.clone(),
        &in_sh("set -eu; uname -s; uname -m"),
        &[],
    )?;
    let platform = std::str::from_utf8(&platform).context("receiver platform is not UTF-8")?;
    let mut lines = platform.lines();
    let os = lines
        .next()
        .context("receiver platform probe returned no operating system")?;
    let arch = lines
        .next()
        .context("receiver platform probe returned no architecture")?;
    let platform = crate::remote_helper::Target::for_bootstrap(os, arch)
        .with_context(|| format!("restricted enrollment does not support {os} {arch}"))?;
    let bytes = management_executable(platform)?;
    let stage = stage_name(id)?;
    let command = in_sh(&management_remote_command(&stage, action, input)?);
    // Upload and invocation share one SSH session. The remote shell installs
    // its cleanup trap before reading the binary and retains it until the
    // management helper exits, so there is no inter-session orphan window or
    // cleanup request that depends on a route which has already failed.
    run_ssh(target, route, &command, &bytes)
}

fn stage_name(id: EnrollmentId) -> Result<String> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).context("generate receiver staging filename")?;
    Ok(format!(
        ".syq-stage-{}-{:016x}",
        id,
        u64::from_le_bytes(nonce)
    ))
}

pub(super) fn management_executable(target: crate::remote_helper::Target) -> Result<Vec<u8>> {
    ManagementBuild::select(target)?.bytes()
}

/// The syq this machine installs on a server of a given platform: this
/// executable, or the official release's helper.
pub(super) enum ManagementBuild {
    Local(File),
    Release(Box<crate::update::TrustedCurrentHelper>),
}

impl ManagementBuild {
    pub(super) fn select(target: crate::remote_helper::Target) -> Result<Self> {
        // A source build opting into release helpers must use the verified
        // upstream helper even on its own platform. Official releases keep
        // their offline path.
        if (crate::identity::uses_release_helpers() && !crate::identity::is_release_build())
            || !target.can_upload_self()
        {
            if crate::identity::uses_release_helpers() {
                return Ok(Self::Release(Box::new(
                    crate::update::trusted_current_helper(target)?,
                )));
            }
            bail!("cannot install a source-built restricted receiver for {} from {}; use an official release or enroll from a compatible host", target.key, crate::identity::platform());
        }
        // Same-platform enrollment and revocation retain their existing
        // offline upload path, including official releases.
        #[cfg(target_os = "linux")]
        let executable = PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let executable = std::env::current_exe().context("resolve local syq executable")?;
        Ok(Self::Local(open_local_management_executable(&executable)?))
    }

    /// Its SHA-256: of this executable, read a block at a time, or as the
    /// release's signed manifest states it, without downloading the helper.
    pub(super) fn sha256(&self) -> Result<String> {
        match self {
            Self::Local(file) => sha256_file(file),
            Self::Release(helper) => Ok(helper.binary_sha256().to_owned()),
        }
    }

    /// Its bytes, only for an upload: this executable read whole, or the
    /// release helper downloaded and verified, or taken from this machine's
    /// store.
    pub(super) fn bytes(self) -> Result<Vec<u8>> {
        match self {
            Self::Local(file) => read_all(&file),
            Self::Release(helper) => crate::update::verified_current_helper(&helper),
        }
    }
}

#[cfg(test)]
pub(super) fn read_local_management_executable(path: &Path) -> Result<Vec<u8>> {
    read_all(&open_local_management_executable(path)?)
}

/// The local syq to upload, opened once: on Linux `/proc/self/exe` opens
/// the running executable itself, whatever has replaced its path since.
pub(super) fn open_local_management_executable(path: &Path) -> Result<File> {
    let binary = File::open(path)
        .with_context(|| format!("open local syq executable {}", path.display()))?;
    let metadata = binary
        .metadata()
        .with_context(|| format!("inspect local syq executable {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "local syq executable {} must be a regular file",
            fs::canonicalize(path)
                .unwrap_or_else(|_| path.to_path_buf())
                .display()
        );
    }
    Ok(binary)
}

/// Read `file` from its start, whatever was read from it before.
fn read_all(file: &File) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt as _;
    let mut bytes = Vec::with_capacity(file.metadata()?.len() as usize);
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        match file.read_at(&mut buffer, bytes.len() as u64) {
            Ok(0) => return Ok(bytes),
            Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("read local syq executable"),
        }
    }
}

/// The SHA-256 of `file`, read a block at a time from its start.
fn sha256_file(file: &File) -> Result<String> {
    use sha2::Digest as _;
    use std::os::unix::fs::FileExt as _;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    let mut offset = 0u64;
    loop {
        match file.read_at(&mut buffer, offset) {
            Ok(0) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                offset += read as u64;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("hash local syq executable"),
        }
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(super) fn endpoint(login: &str, host: &str, port: Option<u16>) -> Result<SshEndpoint> {
    SshEndpoint::from_parts(login, host, port)
}

/// The SSH agent the user's configuration selects for `target`: its
/// `IdentityAgent`, else `SSH_AUTH_SOCK`.
pub(super) fn configured_agent(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
) -> Result<Option<PathBuf>> {
    let output = Command::new("ssh")
        .arg("-G")
        .args(enrollment::enrollment_ssh_args_raw(target, route, ""))
        .capture_output()
        .context("inspect the SSH configuration for the enrollment's login")?;
    if !output.status.success() {
        bail!(
            "could not read the SSH configuration for {}",
            target.label()
        );
    }
    crate::agent_broker::configured_agent_socket(&output.stdout)
}

/// What one enrollment session sets up: a new enrollment, a retry of one
/// whose installation was not confirmed, or a refresh of an existing one.
pub(super) struct Plan {
    pub(super) id: EnrollmentId,
    pub(super) directory: PathBuf,
    /// The entry key, unless a new enrollment makes one for the login key.
    pub(super) entry_key: Option<PrivateKey>,
    pub(super) refresh: bool,
    pub(super) replaces: Option<ReplacedEnrollment>,
}

enum Session {
    Installed(Box<(LocalEnrollment, LoginSigner)>),
    StateMissing,
}

/// What a copy checks once a session knows the server's home directory,
/// before anything is installed: that its destination is not a path the
/// receiver protects.
pub(super) type DestinationCheck<'a> = Option<&'a dyn Fn(&Path, &[PathBuf]) -> Result<()>>;

/// The enrollment for `login@host:port`, set up when there is none, and
/// refreshed when it runs another build or `refresh` asks to find the
/// login key again. Returns the login key's signer when this logged in to
/// the server. With `batch`, SSH neither prompts nor accepts a host key the
/// user has not trusted.
pub(super) fn enroll(
    host: &str,
    port: Option<u16>,
    login: &str,
    (jump, batch): (Option<&SshEndpoint>, bool),
    refresh: bool,
    check: DestinationCheck<'_>,
) -> Result<(LocalEnrollment, PathBuf, Option<LoginSigner>)> {
    // The receiver refuses to run as root; say so before creating anything.
    // An account with another name and user ID 0 is refused when installing.
    if login == "root" {
        bail!(privileged_receiver_message(None));
    }
    let base = local_state_base()?;
    let base_lock = open_directory(&base)?;
    lock_directory(&base_lock)?;
    let account = |metadata_host: &str, metadata_port: Option<u16>, target_login: &str| {
        metadata_host == host && metadata_port == port && target_login == login
    };
    let active = load_local_enrollments()?
        .into_iter()
        .find(|(metadata, _)| account(&metadata.host, metadata.port, &metadata.target_login));
    if let Some((metadata, directory)) = &active {
        if !refresh && !needs_refresh(metadata, directory) {
            return Ok((metadata.clone(), directory.clone(), None));
        }
    }
    let target = endpoint(login, host, port)?;
    let plan = match active {
        Some((metadata, directory)) => Plan {
            id: metadata.id,
            entry_key: Some(load_entry_key(&directory)?),
            directory,
            refresh: true,
            replaces: None,
        },
        None => match load_pending_enrollments()?
            .into_iter()
            .find(|(pending, _)| account(&pending.host, pending.port, &pending.target_login))
        {
            Some((pending, directory)) => Plan {
                id: pending.id,
                entry_key: Some(load_entry_key(&directory)?),
                directory,
                refresh: false,
                replaces: None,
            },
            None => new_plan(&base, None),
        },
    };
    if plan.refresh {
        // Until the server's reply arrives, the server may hold a newer
        // signer and generation than this machine's record.
        atomic_write(&plan.directory, REFRESH_FILE, b"", 0o600)?;
    }
    let lost = (plan.refresh, plan.id, plan.directory.clone());
    let (metadata, directory, signer) =
        match run_session(&target, (jump, batch), (host, port, login), plan, check)? {
            (Session::Installed(installed), directory) => {
                let (metadata, signer) = *installed;
                (metadata, directory, signer)
            }
            (Session::StateMissing, _) => {
                // The server lost this enrollment's state. Enroll under a new ID
                // instead of re-creating the old one, so no grant can be replayed
                // against an empty record, and remove the old line.
                let (_, old_id, old_directory) = lost;
                let old_key = load_entry_key(&old_directory)?;
                crate::output::diagnostic!(
                    "syq: {} has lost the state of enrollment {old_id}; enrolling again",
                    target.label()
                );
                let replaced = ReplacedEnrollment {
                    id: old_id,
                    entry_public_key: old_key.public_key().to_openssh()?,
                };
                let pending = load_pending_enrollments()?
                    .into_iter()
                    .find(|(pending, _)| {
                        account(&pending.host, pending.port, &pending.target_login)
                    });
                match run_session(
                    &target,
                    (jump, batch),
                    (host, port, login),
                    replacement_plan(&base, pending, replaced)?,
                    check,
                )? {
                    (Session::Installed(installed), directory) => {
                        // Keep the old record until its replacement is installed,
                        // so a failure here can still name the line to remove.
                        remove_local_enrollment(&old_directory)?;
                        let (metadata, signer) = *installed;
                        (metadata, directory, signer)
                    }
                    (Session::StateMissing, _) => {
                        bail!("the server reported missing state for a new enrollment")
                    }
                }
            }
        };
    Ok((metadata, directory, Some(signer)))
}

/// The enrollment that replaces one whose server state was lost: one whose
/// installation started before and was never confirmed, as when the reply
/// to an earlier replacement was lost, else a new one. Reusing it keeps a
/// lost reply from leaving another enrollment behind on the server.
pub(super) fn replacement_plan(
    base: &Path,
    pending: Option<(PendingEnrollment, PathBuf)>,
    replaced: ReplacedEnrollment,
) -> Result<Plan> {
    Ok(match pending {
        Some((pending, directory)) => Plan {
            id: pending.id,
            entry_key: Some(load_entry_key(&directory)?),
            directory,
            refresh: false,
            replaces: Some(replaced),
        },
        None => new_plan(base, Some(replaced)),
    })
}

fn new_plan(base: &Path, replaces: Option<ReplacedEnrollment>) -> Plan {
    let id = EnrollmentId::random();
    Plan {
        id,
        directory: base.join(id.to_string()),
        entry_key: None,
        refresh: false,
        replaces,
    }
}

/// Run one enrollment session, directly or, when that cannot connect,
/// through `jump`.
fn run_session(
    target: &SshEndpoint,
    (jump, batch): (Option<&SshEndpoint>, bool),
    account: (&str, Option<u16>, &str),
    plan: Plan,
    check: DestinationCheck<'_>,
) -> Result<(Session, PathBuf)> {
    let retry_state = if plan.refresh {
        "remains active with its previous state; the refresh can be retried"
    } else {
        "remains pending for a safe retry"
    };
    let id = plan.id;
    let direct = install_over_route(
        target,
        EnrollmentRoute::Direct,
        account,
        (&plan, batch),
        check,
    );
    let session = match (direct, jump) {
        (Ok(session), _) => session,
        (Err(direct_error), Some(jump)) if is_enrollment_transport_failure(&direct_error) => {
            install_over_route(
                target,
                EnrollmentRoute::ProxyJump { jump },
                account,
                (&plan, batch),
                check,
            )
            .with_context(|| {
                format!("enrollment {id} {retry_state}; direct enrollment also failed: {direct_error:#}")
            })?
        }
        (Err(error), _) => {
            return Err(error).with_context(|| format!("enrollment {id} {retry_state}"))
        }
    };
    Ok((session, plan.directory))
}

/// Log in to the server with the user's own SSH, find the key that
/// authenticated and check that it can sign, then install. The login stays
/// open throughout: this is the authentication that installs the receiver,
/// not a separate probe that could have selected a different key.
fn install_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    (host, port, login): (&str, Option<u16>, &str),
    (plan, batch): (&Plan, bool),
    check: DestinationCheck<'_>,
) -> Result<Session> {
    let agent = configured_agent(target, route.clone())?;
    let temporary = crate::private_broker::private_temp_dir("syq-enroll-")?;
    let trace_path = temporary.path().join("ssh.log");
    let stage = stage_name(plan.id)?;
    let remote = in_sh(&install_remote_command(&stage));
    let mut command = Command::new("ssh");
    command
        .args(["-vvv", "-o", "FingerprintHash=sha256", "-E"])
        .arg(&trace_path);
    if batch {
        // SSH takes the first value of each option, so these come before
        // the user's configuration.
        command.args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]);
    }
    command
        .args(enrollment::enrollment_ssh_args_raw(
            target,
            route.clone(),
            &remote,
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut group = crate::process_group::ProcessGroup::spawn(&mut command)
        .map_err(|error| enrollment_ssh_error(target, true, error))?;
    let foreground = group
        .foreground()
        .context("give enrollment SSH access to the terminal")?;
    let mut stdout = std::io::BufReader::new(
        group
            .child
            .stdout
            .take()
            .context("enrollment SSH output missing")?,
    );
    let mut input = group
        .child
        .stdin
        .take()
        .context("enrollment SSH input missing")?;
    let mut greeted = false;
    let platform = (|| -> Result<_> {
        // Any output, including an oversized or malformed first line, means
        // the remote command started. Only an empty stream warrants waiting
        // for SSH's transport-failure status before trying another route.
        greeted = !std::io::BufRead::fill_buf(&mut stdout)?.is_empty();
        let os = read_enrollment_line(&mut stdout)?;
        let arch = read_enrollment_line(&mut stdout)?;
        let home = read_enrollment_line(&mut stdout)?;
        let uid = read_enrollment_line(&mut stdout)?;
        let config_home = read_enrollment_line(&mut stdout)?;
        let runtime_dir = read_enrollment_line(&mut stdout)?;
        let tmpdir = read_enrollment_line(&mut stdout)?;
        let stored = read_enrollment_line(&mut stdout)?;
        let receiving = server_receiving_state(
            Path::new(&home),
            &uid,
            &os,
            (&config_home, &runtime_dir, &tmpdir),
        );
        let length: usize = read_enrollment_line(&mut stdout)?
            .parse()
            .context("authorized_keys byte count")?;
        if length > MAX_AUTHORIZED_KEYS {
            bail!("authorized_keys is too large to inspect");
        }
        let mut authorized = vec![0u8; length];
        stdout.read_exact(&mut authorized)?;
        Ok((os, arch, home, receiving, stored, authorized))
    })();
    drop(foreground);
    let (os, arch, home, receiving, stored, authorized) = match platform {
        Ok(platform) => platform,
        Err(error) => {
            drop(input);
            // Before a greeting, EOF means SSH failed to connect/authenticate.
            // Malformed or excessive output after a greeting must be stopped
            // rather than waiting while the SSH pipe could still be full.
            let status = if greeted {
                group.close()?
            } else {
                group.wait()?
            };
            return Err(enrollment_ssh_error(
                target,
                status.code() == Some(255),
                error,
            ));
        }
    };
    // Everything before the request is checked with nothing installed: an
    // error closes the session's input, and the remote shell stops.
    let prepared = (|| -> Result<_> {
        // A destination the receiver would refuse leaves no enrollment.
        if let Some(check) = check {
            check(Path::new(&home), &receiving)?;
        }
        let trace =
            fs::read_to_string(&trace_path).context("read enrollment SSH authentication trace")?;
        keys::require_openssh_server(&trace)?;
        let login_key = keys::discover(
            &trace,
            &authorized,
            agent.as_deref(),
            plan.id.to_string().as_bytes(),
        )?;
        let platform = crate::remote_helper::Target::for_bootstrap(&os, &arch)
            .context("unsupported receiver platform")?;
        // A stored build for this platform is offered to the session with
        // the SHA-256 of the build this machine would install: the session
        // starts the stored one only when it is exactly that build.
        let build = ManagementBuild::select(platform)?;
        let offer = stored
            .split_whitespace()
            .any(|key| key == platform.key)
            .then(|| build.sha256().map(|digest| (platform.key, digest)))
            .transpose()?;
        let entry_key = match &plan.entry_key {
            Some(key) => key.clone(),
            None => {
                let key = keys::generate_entry_key(&login_key.trusted.key()?, plan.id)?;
                // The entry key is durable before installation starts, so a
                // failed installation is retried, or revoked, with it.
                ensure_directory(&plan.directory, 0o700)?;
                keys::store_entry_key(&plan.directory, &key)?;
                atomic_write(
                    &plan.directory,
                    PENDING_FILE,
                    &serde_json::to_vec(&PendingEnrollment {
                        version: CONFIG_VERSION,
                        id: plan.id,
                        host: host.to_owned(),
                        port,
                        target_login: login.to_owned(),
                    })?,
                    0o600,
                )?;
                key
            }
        };
        let request = InstallRequest {
            version: CONFIG_VERSION,
            id: plan.id,
            target_login: login.to_owned(),
            entry_public_key: entry_key.public_key().to_openssh()?,
            signer: login_key.trusted.clone(),
            refresh: plan.refresh,
            replaces: plan.replaces.clone(),
        };
        Ok((login_key, (offer, build), request))
    })();
    let (login_key, (offer, build), request) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            drop(input);
            let _ = group.close();
            return Err(error);
        }
    };
    let write = (|| -> Result<()> {
        let mut build = Some(build);
        serde_json::to_writer(&mut input, &request)?;
        match &offer {
            Some((target, digest)) => writeln!(input, "\n{target}\n{digest}")?,
            None => {
                input.write_all(b"\n\n\n")?;
                // Nothing to compare: the session needs this build.
                let bytes = build.take().expect("the build is sent once").bytes()?;
                input.write_all(&bytes)?;
            }
        }
        input.flush()?;
        // The session says whether it started the stored build or needs
        // this one, which is fetched only then.
        match read_enrollment_line(&mut stdout)?.as_str() {
            "stored" => {}
            "upload" => {
                if let Some(build) = build.take() {
                    input.write_all(&build.bytes()?)?;
                }
            }
            _ => bail!("the enrollment session gave an unexpected answer"),
        }
        Ok(())
    })();
    drop(input);
    let mut response = Vec::new();
    stdout
        .take((MAX_STATE_FILE + 1) as u64)
        .read_to_end(&mut response)?;
    if response.len() > MAX_STATE_FILE {
        bail!("enrollment response too large");
    }
    let status = group.wait()?;
    if !status.success() {
        bail!(
            "installation over SSH failed ({status}); retry, or run `syq receiver revoke {}`",
            plan.id
        );
    }
    write?;
    match serde_json::from_slice(&response).context("decode the enrollment response")? {
        InstallResponse::StateMissing { version, id }
            if version == CONFIG_VERSION && id == plan.id && plan.refresh =>
        {
            Ok(Session::StateMissing)
        }
        InstallResponse::Installed {
            version,
            id,
            target_login,
            remote_home,
            generation,
            release,
            receiver_path,
            results_public_key,
            changed: _,
        } if version == CONFIG_VERSION && id == plan.id && target_login == login => {
            let metadata = LocalEnrollment {
                version: CONFIG_VERSION,
                id,
                host: host.to_owned(),
                port,
                target_login,
                remote_home,
                generation,
                release,
                receiver_path,
                results_public_key,
                signer: login_key.trusted.clone(),
                identity_file: login_key.identity_file.clone(),
                receiving_state: receiving.clone(),
            };
            complete_local_enrollment(&plan.directory, &metadata)?;
            Ok(Session::Installed(Box::new((metadata, login_key.signer))))
        }
        _ => bail!("the enrollment response did not match the request"),
    }
}

/// The enrollment session's commands, for `sh`. The greeting reports the
/// platform, where the account keeps syq's state, the platforms the store
/// has this build for, and `authorized_keys`. The session then reads the
/// request and, when the enrolling machine offers a stored build, its
/// platform and the SHA-256 of the build that machine would install. It
/// answers `stored` when it starts that stored build, or `upload` when it
/// reads the syq that follows and starts that instead.
///
/// A stored build is listed only when it passes the binary store's rules:
/// its directories and file belong to the account and nobody else can write
/// them, and only the store's root may be a symbolic link. Owners and modes
/// show nothing on a filesystem that fixes them when it is mounted, such as
/// SMB or exFAT, so the session also hashes the stored build just before it
/// would start it and starts it only when it is exactly the offered build;
/// without a SHA-256 tool, it asks for the upload. The checks use `test -O`
/// and `test -L`, which dash, bash, zsh and busybox `sh` all have though
/// POSIX does not require `-O`, `find -perm`, and the SHA-256 tools the
/// helper bootstrap uses. The script is one line, so any login shell can
/// pass it to `sh -c`.
pub(super) fn install_remote_command(stage: &str) -> String {
    [
        "set -eu".to_owned(),
        "uname -s".to_owned(),
        "uname -m".to_owned(),
        "printf '%s\\n' \"$HOME\" \"$(id -u)\" \"${XDG_CONFIG_HOME-}\" \"${XDG_RUNTIME_DIR-}\" \"${TMPDIR-}\"".to_owned(),
        format!(
            "r=\"$HOME/{store}\"; s=\"$r/\"{build}",
            store = crate::user_dirs::BINARY_STORE_IN_HOME,
            build = shell_words::quote(crate::identity::build()),
        ),
        "private() { [ -O \"$1\" ] || return 1; w=$(find ${2:+\"$2\"} \"$1\" -prune \\( -perm -020 -o -perm -002 \\) -print) || return 1; [ -z \"$w\" ]; }".to_owned(),
        "stored() { [ -n \"$1\" ] && [ -d \"$r\" ] && private \"$r\" -H || return 1; for q in \"$s\" \"$s/$1\" \"$s/$1/syq\"; do [ ! -L \"$q\" ] && private \"$q\" || return 1; done; [ -f \"$s/$1/syq\" ] && [ -x \"$s/$1/syq\" ]; }".to_owned(),
        "digest() { if command -v sha256sum >/dev/null 2>&1; then o=$(sha256sum < \"$1\") || return 1; elif command -v shasum >/dev/null 2>&1; then o=$(shasum -a 256 < \"$1\") || return 1; elif command -v openssl >/dev/null 2>&1; then o=$(openssl dgst -sha256 < \"$1\") || return 1; o=${o##* }; else return 1; fi; printf '%s' \"${o%%[[:space:]]*}\"; }".to_owned(),
        "for f in \"$s\"/*/syq; do t=${f%/syq}; t=${t##*/}; if stored \"$t\"; then printf '%s ' \"$t\"; fi; done".to_owned(),
        "printf '\\n'".to_owned(),
        "if test -f \"$HOME/.ssh/authorized_keys\"; then wc -c <\"$HOME/.ssh/authorized_keys\"; cat \"$HOME/.ssh/authorized_keys\"; else printf '0\\n'; fi".to_owned(),
        "IFS= read -r request; IFS= read -r target; IFS= read -r expected".to_owned(),
        format!(
            "if [ -n \"$target\" ] && stored \"$target\" && h=$(digest \"$s/$target/syq\") && [ \"$h\" = \"$expected\" ]; then echo stored; printf '%s' \"$request\" | \"$s/$target/syq\" --restricted-install; else echo upload; {stage}; printf '%s' \"$request\" | \"$p\" --restricted-install; fi",
            stage = stage_commands(stage),
        ),
    ]
    .join("; ")
}

/// A command for the account's login shell to run with `sh`, whatever that
/// login shell is: zsh, for one, stops at a glob that matches nothing, and
/// fish and tcsh do not take `sh` syntax at all.
pub(super) fn in_sh(command: &str) -> String {
    format!("sh -c {}", shell_words::quote(command))
}

/// The SHA-256 of `bytes` in lowercase hexadecimal, as `sha256sum` prints it.
#[cfg(test)]
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_enrollment_line(input: &mut impl std::io::BufRead) -> Result<String> {
    let mut line = String::new();
    input.take(1024).read_line(&mut line)?;
    if !line.ends_with('\n') {
        bail!("incomplete receiver enrollment greeting");
    }
    Ok(line.trim().to_owned())
}
