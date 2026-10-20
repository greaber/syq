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
    remove_leaf_locked(&directory, PENDING_FILE)
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
        store = BINARY_STORE,
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
    let platform = run_ssh(target, route.clone(), "set -eu; uname -s; uname -m", &[])?;
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
    let command = management_remote_command(&stage, action, input)?;
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
    // A source build opting into release helpers must use the verified upstream
    // helper even on its own platform. Official releases keep their offline path.
    if (crate::identity::uses_release_helpers() && !crate::identity::is_release_build())
        || !target.can_upload_self()
    {
        if crate::identity::uses_release_helpers() {
            let helper = crate::update::trusted_current_helper(target)?;
            return crate::update::verified_current_helper(&helper);
        }
        bail!("cannot install a source-built restricted receiver for {} from {}; use an official release or enroll from a compatible host", target.key, crate::identity::platform());
    }
    // Same-platform enrollment and revocation retain their existing offline
    // upload path, including official releases.
    #[cfg(target_os = "linux")]
    let executable = PathBuf::from("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let executable = std::env::current_exe().context("resolve local syq executable")?;
    read_local_management_executable(&executable)
}

pub(super) fn read_local_management_executable(path: &Path) -> Result<Vec<u8>> {
    let executable = fs::canonicalize(path)
        .with_context(|| format!("canonicalize local syq executable {}", path.display()))?;
    let mut binary = File::open(&executable)
        .with_context(|| format!("open local syq executable {}", executable.display()))?;
    let metadata = binary
        .metadata()
        .with_context(|| format!("inspect local syq executable {}", executable.display()))?;
    if !metadata.is_file() {
        bail!(
            "local syq executable {} must be a regular file",
            executable.display()
        );
    }
    let mut bytes = Vec::new();
    binary
        .read_to_end(&mut bytes)
        .with_context(|| format!("read local syq executable {}", executable.display()))?;
    Ok(bytes)
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
struct Plan {
    id: EnrollmentId,
    directory: PathBuf,
    /// The entry key, unless a new enrollment makes one for the login key.
    entry_key: Option<PrivateKey>,
    refresh: bool,
    replaces: Option<ReplacedEnrollment>,
}

enum Session {
    Installed(Box<(LocalEnrollment, LoginSigner)>),
    StateMissing,
}

/// The enrollment for `login@host:port`, set up when there is none, and
/// refreshed when it runs another build or `refresh` asks to find the
/// login key again. Returns the login key's signer when this logged in to
/// the server.
pub(super) fn enroll(
    host: &str,
    port: Option<u16>,
    login: &str,
    jump: Option<&SshEndpoint>,
    refresh: bool,
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
        if !refresh && metadata.release == crate::identity::build() {
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
    let lost = (plan.refresh, plan.id, plan.directory.clone());
    let (metadata, directory, signer) = match run_session(&target, jump, host, port, login, plan)? {
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
            remove_local_enrollment(&old_directory)?;
            match run_session(
                &target,
                jump,
                host,
                port,
                login,
                new_plan(&base, Some(replaced)),
            )? {
                (Session::Installed(installed), directory) => {
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
    jump: Option<&SshEndpoint>,
    host: &str,
    port: Option<u16>,
    login: &str,
    plan: Plan,
) -> Result<(Session, PathBuf)> {
    let retry_state = if plan.refresh {
        "remains active with its previous state; the refresh can be retried"
    } else {
        "remains pending for a safe retry"
    };
    let id = plan.id;
    let direct = install_over_route(target, EnrollmentRoute::Direct, host, port, login, &plan);
    let session = match (direct, jump) {
        (Ok(session), _) => session,
        (Err(direct_error), Some(jump)) if is_enrollment_transport_failure(&direct_error) => {
            install_over_route(
                target,
                EnrollmentRoute::ProxyJump { jump },
                host,
                port,
                login,
                &plan,
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
    host: &str,
    port: Option<u16>,
    login: &str,
    plan: &Plan,
) -> Result<Session> {
    let agent = configured_agent(target, route.clone())?;
    let temporary = crate::private_broker::private_temp_dir("syq-enroll-")?;
    let trace_path = temporary.path().join("ssh.log");
    let stage = stage_name(plan.id)?;
    let remote = format!(
        "set -eu; uname -s; uname -m; if test -f \"$HOME/.ssh/authorized_keys\"; then wc -c <\"$HOME/.ssh/authorized_keys\"; cat \"$HOME/.ssh/authorized_keys\"; else printf '0\\n'; fi; IFS= read -r request; {}; printf '%s' \"$request\" | \"$p\" --restricted-install",
        stage_commands(&stage)
    );
    let mut command = Command::new("ssh");
    command
        .args(["-vvv", "-o", "FingerprintHash=sha256", "-E"])
        .arg(&trace_path)
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
        let length: usize = read_enrollment_line(&mut stdout)?
            .parse()
            .context("authorized_keys byte count")?;
        if length > MAX_AUTHORIZED_KEYS {
            bail!("authorized_keys is too large to inspect");
        }
        let mut authorized = vec![0u8; length];
        stdout.read_exact(&mut authorized)?;
        Ok((os, arch, authorized))
    })();
    drop(foreground);
    let (os, arch, authorized) = match platform {
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
        let executable = management_executable(platform)?;
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
        Ok((login_key, executable, request))
    })();
    let (login_key, executable, request) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            drop(input);
            let _ = group.close();
            return Err(error);
        }
    };
    let write = (|| -> Result<()> {
        serde_json::to_writer(&mut input, &request)?;
        input.write_all(b"\n")?;
        input.write_all(&executable)?;
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
            };
            complete_local_enrollment(&plan.directory, &metadata)?;
            Ok(Session::Installed(Box::new((metadata, login_key.signer))))
        }
        _ => bail!("the enrollment response did not match the request"),
    }
}

fn read_enrollment_line(input: &mut impl std::io::BufRead) -> Result<String> {
    let mut line = String::new();
    input.take(1024).read_line(&mut line)?;
    if !line.ends_with('\n') {
        bail!("incomplete receiver enrollment greeting");
    }
    Ok(line.trim().to_owned())
}
