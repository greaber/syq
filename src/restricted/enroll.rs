use super::*;
use crate::process::CommandExt as _;
use std::io::BufRead as _;

pub(super) fn local_state_base() -> Result<PathBuf> {
    let (_, home) = current_account()?;
    ensure_private_chain(&home, &[".local", "state", "syq", "restricted"])
        .context("validate restricted enrollment state on the invoking machine")
}

#[cfg(test)]
pub(super) fn store_pending_files(
    directory: &Path,
    pending: &PendingEnrollment,
    private_key: &PrivateKey,
) -> Result<()> {
    let private = private_key
        .to_openssh(LineEnding::LF)
        .context("encode enrollment private key")?;
    atomic_write(directory, "enrollment-key", private.as_bytes(), 0o600)?;
    atomic_write(
        directory,
        "pending.json",
        &serde_json::to_vec(pending)?,
        0o600,
    )
}

pub(super) fn complete_local_enrollment(
    directory: &Path,
    metadata: &LocalEnrollment,
) -> Result<()> {
    atomic_write(
        directory,
        "metadata.json",
        &serde_json::to_vec(metadata)?,
        0o600,
    )?;
    let directory = open_directory(directory)?;
    lock_directory(&directory)?;
    remove_leaf_locked(&directory, "pending.json")
}

pub(super) fn load_local_enrollments() -> Result<Vec<(LocalEnrollment, PathBuf)>> {
    let base = local_state_base()?;
    let mut enrollments = Vec::new();
    for entry in fs::read_dir(&base).with_context(|| format!("list {}", base.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if delegation::validate_private_directory_path(&directory).is_err() {
            continue;
        }
        let metadata_path = directory.join("metadata.json");
        let Ok(encoded) = delegation::read_private_regular(
            &metadata_path,
            "local enrollment metadata",
            MAX_STATE_FILE,
        ) else {
            continue;
        };
        let Ok(metadata) = serde_json::from_slice::<LocalEnrollment>(&encoded) else {
            continue;
        };
        if supported_config_version(metadata.version)
            && metadata.id.to_string() == entry.file_name().to_string_lossy()
        {
            enrollments.push((metadata, directory));
        }
    }
    Ok(enrollments)
}

pub(super) fn load_pending_enrollments() -> Result<Vec<(PendingEnrollment, PathBuf)>> {
    let base = local_state_base()?;
    let mut enrollments = Vec::new();
    for entry in fs::read_dir(&base).with_context(|| format!("list {}", base.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if delegation::validate_private_directory_path(&directory).is_err() {
            continue;
        }
        let metadata_path = directory.join("pending.json");
        let Ok(encoded) = delegation::read_private_regular(
            &metadata_path,
            "pending local enrollment metadata",
            MAX_STATE_FILE,
        ) else {
            continue;
        };
        let Ok(metadata) = serde_json::from_slice::<PendingEnrollment>(&encoded) else {
            continue;
        };
        if supported_config_version(metadata.version)
            && metadata.id.to_string() == entry.file_name().to_string_lossy()
        {
            enrollments.push((metadata, directory));
        }
    }
    enrollments.sort_by_key(|(metadata, _)| metadata.id.to_string());
    Ok(enrollments)
}

#[cfg(test)]
pub(super) fn load_private_key(directory: &Path) -> Result<PrivateKey> {
    let encoded = delegation::read_private_regular(
        &directory.join("enrollment-key"),
        "enrollment private key",
        128 * 1024,
    )?;
    PrivateKey::from_openssh(&encoded).context("parse enrollment private key")
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

#[derive(Clone, Copy)]
pub(super) enum ManagementAction {
    Install,
    Revoke,
}

impl ManagementAction {
    pub(super) fn argument(self) -> &'static str {
        match self {
            Self::Install => "--restricted-install",
            Self::Revoke => "--restricted-revoke",
        }
    }
}

pub(super) fn management_remote_command(
    stage: &str,
    action: ManagementAction,
    request: &[u8],
) -> Result<String> {
    let request = std::str::from_utf8(request).context("management request is not UTF-8")?;
    Ok(format!(
        "set -eu; d=\"$HOME/.local/libexec\"; p=\"$d/{stage}\"; umask 077; mkdir -p -- \"$d\"; trap 'rm -f -- \"$p\"' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; cat >\"$p\"; chmod 700 \"$p\"; printf '%s' {} | \"$p\" {}",
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
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).context("generate receiver staging filename")?;
    let stage = format!(".syq-receiver-{}-{:016x}", id, u64::from_le_bytes(nonce));
    let command = management_remote_command(&stage, action, input)?;
    // Upload and invocation share one SSH session. The remote shell installs
    // its cleanup trap before reading the binary and retains it until the
    // management helper exits, so there is no inter-session orphan window or
    // cleanup request that depends on a route which has already failed.
    run_ssh(target, route, &command, &bytes)
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

pub(super) fn install_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    request: &InstallRequest,
) -> Result<InstallResponse> {
    let expected_id = request.id;
    let expected_login = request.target_login.clone();
    let request = serde_json::to_vec(request)?;
    let output = run_management_over_route(
        target,
        route,
        expected_id,
        ManagementAction::Install,
        &request,
    )?;
    let response: InstallResponse =
        serde_json::from_slice(&output).context("decode restricted enrollment response")?;
    if response.version != CONFIG_VERSION
        || response.id != expected_id
        || response.target_login != expected_login
    {
        bail!("restricted enrollment response did not match the request");
    }
    Ok(response)
}

pub(super) fn endpoint(login: &str, host: &str, port: Option<u16>) -> Result<SshEndpoint> {
    SshEndpoint::from_parts(login, host, port)
}

pub(super) fn enroll(
    host: &str,
    port: Option<u16>,
    login: &str,
    requested_destination: &str,
    jump: Option<&SshEndpoint>,
    refresh_existing: bool,
) -> Result<(LocalEnrollment, PathBuf, Vec<u8>)> {
    // The receiver refuses to run as root; say so before creating anything.
    // An account with another name and user ID 0 is refused when installing.
    if login == "root" {
        bail!(PRIVILEGED_RECEIVER);
    }
    let base = local_state_base()?;
    let base_lock = open_directory(&base)?;
    lock_directory(&base_lock)?;

    let mut active = None;
    for (metadata, directory) in load_local_enrollments()? {
        if metadata.host == host && metadata.port == port && metadata.target_login == login {
            if let Some(canonical_destination) =
                destination_for(&metadata, requested_destination.as_bytes())?
            {
                active = Some((metadata, directory, canonical_destination));
                break;
            }
        }
    }
    if !refresh_existing {
        if let Some(existing) = active.take() {
            return Ok(existing);
        }
    }
    let retry_state = if active.is_some() {
        "remains active with its previous metadata; the receiver refresh can be retried"
    } else {
        "remains pending for a safe retry"
    };

    let pending = if active.is_none() {
        load_pending_enrollments()?
            .into_iter()
            .find(|(pending, _)| {
                pending.host == host
                    && pending.port == port
                    && pending.target_login == login
                    && pending.requested_destination == requested_destination
            })
    } else {
        None
    };
    let (pending, directory, private_key) = match (active, pending) {
        (Some((metadata, directory, _)), _) => {
            let private_key = load_enrollment_public_key(&directory)?;
            let pending = PendingEnrollment {
                security_key_flags: metadata.security_key_flags,
                version: CONFIG_VERSION,
                id: metadata.id,
                host: metadata.host,
                port: metadata.port,
                target_login: metadata.target_login,
                requested_destination: requested_destination.to_owned(),
            };
            (pending, directory, private_key)
        }
        (None, Some((pending, directory))) => {
            let private_key = load_enrollment_public_key(&directory)?;
            (pending, directory, private_key)
        }
        (None, None) => {
            return create_enrollment(host, port, login, requested_destination, jump);
        }
    };
    let public_key = private_key.to_openssh()?;
    let request = InstallRequest {
        security_key_flags: pending.security_key_flags,
        version: CONFIG_VERSION,
        id: pending.id,
        target_login: login.to_owned(),
        requested_destination: requested_destination.to_owned(),
        public_key,
    };
    let target = endpoint(login, host, port)?;
    let direct = install_over_route(&target, EnrollmentRoute::Direct, &request);
    let response = match (direct, jump) {
        (Ok(response), _) => response,
        (Err(direct_error), Some(jump)) if is_enrollment_transport_failure(&direct_error) => {
            install_over_route(&target, EnrollmentRoute::ProxyJump { jump }, &request)
                .with_context(|| {
                    format!(
                "enrollment {} {retry_state}; direct enrollment also failed: {direct_error:#}",
                pending.id,
            )
                })?
        }
        (Err(error), _) => {
            return Err(error).with_context(|| format!("enrollment {} {retry_state}", pending.id,))
        }
    };
    let metadata = LocalEnrollment {
        security_key_flags: pending.security_key_flags,
        version: CONFIG_VERSION,
        id: pending.id,
        host: host.to_owned(),
        port,
        target_login: login.to_owned(),
        remote_home: response.remote_home,
        requested_parent: response.requested_parent,
        canonical_root: response.canonical_root,
        receiver_path: response.receiver_path,
        receipt_public_key: response.receipt_public_key,
    };
    complete_local_enrollment(&directory, &metadata)?;
    Ok((
        metadata,
        directory,
        response.canonical_destination.into_bytes(),
    ))
}

/// Keep the login open while selecting and creating the credential. This is
/// the authentication that installs the receiver, not a separate probe that
/// could have selected a different key.
fn create_enrollment(
    host: &str,
    port: Option<u16>,
    login: &str,
    destination: &str,
    jump: Option<&SshEndpoint>,
) -> Result<(LocalEnrollment, PathBuf, Vec<u8>)> {
    let target = endpoint(login, host, port)?;
    let id = EnrollmentId::random();
    let direct = create_over_route(
        &target,
        EnrollmentRoute::Direct,
        id,
        host,
        port,
        login,
        destination,
    );
    match (direct, jump) {
        (Ok(enrollment), _) => Ok(enrollment),
        (Err(error), Some(jump)) if is_enrollment_transport_failure(&error) => create_over_route(
            &target,
            EnrollmentRoute::ProxyJump { jump },
            id,
            host,
            port,
            login,
            destination,
        )
        .with_context(|| format!("direct enrollment also failed: {error:#}")),
        (Err(error), _) => Err(error),
    }
}

#[allow(clippy::too_many_arguments)]
fn create_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    id: EnrollmentId,
    host: &str,
    port: Option<u16>,
    login: &str,
    destination: &str,
) -> Result<(LocalEnrollment, PathBuf, Vec<u8>)> {
    let temporary = crate::private_broker::private_temp_dir("syq-enroll-")?;
    let trace_path = temporary.path().join("ssh.log");
    let stage = format!(".syq-receiver-{id}-{}", EnrollmentId::random());
    let remote = format!(
        "set -eu; uname -s; uname -m; if test -f \"$HOME/.ssh/authorized_keys\"; then wc -c <\"$HOME/.ssh/authorized_keys\"; cat \"$HOME/.ssh/authorized_keys\"; else printf '0\\n'; fi; IFS= read -r request; d=\"$HOME/.local/libexec\"; p=\"$d/{stage}\"; umask 077; mkdir -p -- \"$d\"; trap 'rm -f -- \"$p\"' EXIT; trap 'exit 129' HUP; trap 'exit 143' TERM; cat >\"$p\"; chmod 700 \"$p\"; printf '%s' \"$request\" | \"$p\" --restricted-install"
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
    let trace =
        fs::read_to_string(&trace_path).context("read enrollment SSH authentication trace")?;
    let mut template = key_template(&trace, &authorized)?;
    configure_key_agent(&mut template, target, route)?;
    let platform = crate::remote_helper::Target::for_bootstrap(&os, &arch)
        .context("unsupported receiver platform")?;
    let executable = management_executable(platform)?;
    let pending = PendingEnrollment {
        version: CONFIG_VERSION,
        id,
        host: host.to_owned(),
        port,
        target_login: login.to_owned(),
        requested_destination: destination.to_owned(),
        security_key_flags: template.security_key_flags,
    };
    let directory = local_state_base()?.join(id.to_string());
    ensure_directory(&directory, 0o700)?;
    let key = match generate_matching_key(&directory, id, &template) {
        Ok(key) => key,
        Err(error) => {
            let _ = remove_empty_directory(&directory);
            return Err(error);
        }
    };
    atomic_write(
        &directory,
        "pending.json",
        &serde_json::to_vec(&pending)?,
        0o600,
    )?;
    let request = InstallRequest {
        version: CONFIG_VERSION,
        id,
        target_login: login.to_owned(),
        requested_destination: destination.to_owned(),
        public_key: key.to_openssh()?,
        security_key_flags: template.security_key_flags,
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
        // Once a key is durable and installation has started, leave pending
        // state for the ordinary enrollment retry; do not mint another key.
        bail!("enrollment {id} remains pending after SSH installation failed ({status}); retry receiver enroll or revoke it");
    }
    write?;
    let response: InstallResponse = serde_json::from_slice(&response)?;
    if response.version != CONFIG_VERSION || response.id != id || response.target_login != login {
        bail!("restricted enrollment response did not match the request");
    }
    let metadata = LocalEnrollment {
        version: CONFIG_VERSION,
        id,
        host: host.to_owned(),
        port,
        target_login: login.to_owned(),
        remote_home: response.remote_home,
        requested_parent: response.requested_parent,
        canonical_root: response.canonical_root,
        receiver_path: response.receiver_path,
        receipt_public_key: response.receipt_public_key,
        security_key_flags: template.security_key_flags,
    };
    complete_local_enrollment(&directory, &metadata)?;
    Ok((
        metadata,
        directory,
        response.canonical_destination.into_bytes(),
    ))
}

fn read_enrollment_line(input: &mut impl std::io::BufRead) -> Result<String> {
    let mut line = String::new();
    input.take(1024).read_line(&mut line)?;
    if !line.ends_with('\n') {
        bail!("incomplete receiver enrollment greeting");
    }
    Ok(line.trim().to_owned())
}
