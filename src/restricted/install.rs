//! The server side of enrollment: installing or refreshing an enrollment's
//! receiver, state and `authorized_keys` line over the user's own login, and
//! revoking them.
use super::*;

#[cfg(test)]
pub(super) fn generate_test_key(comment: &str) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate test key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), comment).context("construct test key")
}

/// The receiver's own signing key, which signs the header of its results
/// for the invoking machine. It lives only on the server, in the
/// enrollment's state directory, and is generated once per enrollment.
pub(super) fn generate_results_key(id: EnrollmentId) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate results signing key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), format!("syq-results:{id}"))
        .context("construct results signing key")
}

pub(super) const RESULTS_KEY_FILE: &str = "results-key";

/// The enrollment's results key: generated on first install and kept by
/// every later install, so a refresh, or a retry after a lost reply, always
/// reports the key the enrolling machine already holds. Rotation is
/// explicit: revoke, then enroll again.
pub(super) fn ensure_results_key(state: &Path, id: EnrollmentId) -> Result<PrivateKey> {
    let path = state.join(RESULTS_KEY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return load_results_key(state),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", path.display()));
        }
    }
    let key = generate_results_key(id)?;
    atomic_write(
        state,
        RESULTS_KEY_FILE,
        key.to_openssh(LineEnding::LF)
            .context("encode results signing key")?
            .as_bytes(),
        0o600,
    )?;
    Ok(key)
}

pub(super) fn load_results_key(state: &Path) -> Result<PrivateKey> {
    let path = state.join(RESULTS_KEY_FILE);
    let encoded = delegation::read_private_regular(&path, "results signing key", 128 * 1024)?;
    PrivateKey::from_openssh(&encoded).context("parse results signing key")
}

/// The signer a grant names: the enrollment at one generation, so a grant
/// issued before a refresh is refused after it.
pub(super) fn signer_name(id: EnrollmentId, generation: u64) -> String {
    format!("syq-enrollment-{id}-generation-{generation}")
}

pub(super) fn normalize_absolute(path: &std::ffi::OsStr, home: &Path) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let bytes = path.as_bytes();
    let raw = if bytes == b"~" {
        home.to_path_buf()
    } else if let Some(rest) = bytes.strip_prefix(b"~/") {
        home.join(std::ffi::OsStr::from_bytes(rest))
    } else if bytes.starts_with(b"/") {
        PathBuf::from(path)
    } else {
        home.join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in raw.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                bail!("restricted destination must not contain .. components")
            }
            std::path::Component::Prefix(_) => bail!("unsupported destination prefix"),
        }
    }
    Ok(normalized)
}

pub(super) fn requested_parent(destination: &Path) -> &Path {
    destination.parent().unwrap_or_else(|| Path::new("/"))
}

fn path_in(home: &Path, components: &[&str]) -> PathBuf {
    components
        .iter()
        .fold(home.to_path_buf(), |path, component| path.join(component))
}

/// An enrollment's state directory on the server.
pub(super) fn enrollment_state(home: &Path, id: EnrollmentId) -> PathBuf {
    path_in(home, &SERVER_STATE).join(id.to_string())
}

/// The store of versioned syq executables in a home directory. Each release
/// has its own directory, shared by every syq that uses the home.
pub(super) const BINARY_STORE: &str = ".local/lib/syq";

/// This build's executable in the store of `home`, for the platform it runs
/// on.
pub(super) fn store_receiver_path(home: &Path) -> PathBuf {
    let target = crate::remote_helper::Target::key_for_platform(&crate::identity::platform())
        .unwrap_or("self");
    home.join(BINARY_STORE)
        .join(crate::identity::build())
        .join(target)
        .join("syq")
}

/// Put this executable in the store as its release's receiver, unless the
/// store has it already: a stored release was checked when it arrived and
/// runs as it is.
fn install_receiver(home: &Path) -> Result<PathBuf> {
    let receiver = store_receiver_path(home);
    if delegation::validate_regular_executable(&receiver, "stored receiver").is_ok() {
        return Ok(receiver);
    }
    // Directories above the store follow the umask, as other programs'
    // files there do; the store's own directories are the owner's alone.
    let mut directory = home.to_path_buf();
    for component in [".local", "lib"] {
        directory.push(component);
        ensure_directory(&directory, 0o777)?;
    }
    for component in Path::new(BINARY_STORE)
        .strip_prefix(".local/lib")
        .expect("the store is below .local/lib")
        .iter()
        .chain(
            receiver
                .parent()
                .and_then(|parent| parent.strip_prefix(home.join(BINARY_STORE)).ok())
                .expect("the receiver is in the store")
                .iter(),
        )
    {
        directory.push(component);
        ensure_directory(&directory, 0o700)?;
    }
    let running = std::env::current_exe().context("resolve the running syq")?;
    let contents = fs::read(&running)
        .with_context(|| format!("read the running syq {}", running.display()))?;
    let opened = open_directory(&directory)?;
    lock_directory(&opened)?;
    atomic_replace_executable_locked(&opened, "syq", &contents)?;
    delegation::validate_regular_executable(&receiver, "stored receiver")?;
    Ok(receiver)
}

/// Which machine's paths `receiver_control_paths` lists.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlPaths {
    /// This machine's, including receiving state its environment locates.
    Here,
    /// Another machine's, known only by its home directory.
    Elsewhere,
}

/// The paths every receiver refuses to write, by name and by the identity
/// each has in the session: the account's SSH configuration, syq's stored
/// executables, enrollment state on both sides (including the directories
/// released versions used), the receiving machine's approval state, and the
/// directory of the running executable.
pub(super) fn receiver_control_paths(
    home: &Path,
    executable: Option<&Path>,
    machine: ControlPaths,
) -> Result<Vec<ReceiverControlPath>> {
    let mut protected = vec![
        (home.join(".ssh"), "SSH configuration directory"),
        (home.join(BINARY_STORE), "store of syq executables"),
        (path_in(home, &SERVER_STATE), "enrollment state directory"),
        (path_in(home, &LOCAL_STATE), "enrollment state directory"),
        (
            home.join(".local/share/syq/restricted"),
            "released enrollment state directory",
        ),
        (
            home.join(".local/state/syq/restricted"),
            "released enrollment state directory",
        ),
        (
            home.join(".local/libexec"),
            "released receiver executable directory",
        ),
    ];
    if let Some(executable) = executable {
        protected.push((
            executable
                .parent()
                .context("the running syq has no parent directory")?
                .to_path_buf(),
            "receiver executable directory",
        ));
    }
    for directory in [
        ".syq-receive-v1",
        ".syq-destinations-v1",
        ".syq-destinations-v2",
        ".syq-destinations-v3",
    ] {
        protected.push((home.join(directory), "named destination authority state"));
    }
    for path in [
        crate::destination::receiver_identity_directory().ok(),
        crate::receive_service::config_path(&crate::persistence::Domain::default())
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf)),
        Some(crate::persistence::runtime_parent_path()),
    ]
    .into_iter()
    .flatten()
    .filter(|_| machine == ControlPaths::Here)
    {
        protected.push((path, "background receiving control state"));
    }
    Ok(protected
        .into_iter()
        .map(|(path, label)| ReceiverControlPath {
            path: path.as_os_str().as_bytes().to_vec(),
            label,
        })
        .collect())
}

/// Read a request of at most the state-file size from standard input.
fn read_request<T: serde::de::DeserializeOwned>(label: &str) -> Result<T> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_STATE_FILE as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_STATE_FILE {
        bail!("{label} is too large");
    }
    serde_json::from_slice(&encoded).with_context(|| format!("decode {label}"))
}

/// The enrollment's state, when its directory holds any.
pub(super) fn read_receiver_config(state: &Path) -> Result<Option<ReceiverEnrollment>> {
    match fs::symlink_metadata(state.join("config.json")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect the enrollment's state"),
        Ok(_) => {}
    }
    let encoded = delegation::read_private_regular(
        &state.join("config.json"),
        "enrollment state",
        MAX_STATE_FILE,
    )?;
    let config: ReceiverEnrollment =
        serde_json::from_slice(&encoded).context("decode the enrollment's state")?;
    if config.version != CONFIG_VERSION {
        bail!("the enrollment's state is from another syq version");
    }
    Ok(Some(config))
}

/// `authorized_keys` must be writable before anything is installed: the
/// line is written last, and a server that cannot take it should be
/// refused before any state exists.
fn require_writable_authorized_keys(ssh: &Path) -> Result<()> {
    let writable = |path: &Path| {
        let path = CString::new(path.as_os_str().as_bytes()).expect("path without NUL");
        unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
    };
    let file = ssh.join("authorized_keys");
    if !writable(ssh) || (file.exists() && !writable(&file)) {
        bail!(
            "restricted copying needs a writable {}; this account's is not",
            file.display()
        );
    }
    Ok(())
}

pub(crate) fn remote_install() -> Result<()> {
    let request: InstallRequest = read_request("enrollment request")?;
    if request.version != CONFIG_VERSION {
        bail!("this syq cannot handle that enrollment request version");
    }
    request.id.validate()?;
    refuse_privileged_receiver(None)?;
    let (account, home) = current_account()?;
    let response = install_for_account(&request, &account, &home)?;
    serde_json::to_writer(std::io::stdout().lock(), &response)?;
    Ok(())
}

pub(super) fn install_for_account(
    request: &InstallRequest,
    account: &str,
    home: &Path,
) -> Result<InstallResponse> {
    if account != request.target_login {
        bail!("enrollment target login does not match the remote account");
    }
    request.signer.validate()?;
    let entry_key = EnrollmentPublicKey::parse(&request.entry_public_key)?;
    validate_entry_public_key(&ssh_key::PublicKey::from_openssh(
        &request.entry_public_key,
    )?)?;
    let signer = EnrollmentPublicKey::login(&request.signer.public_key)?;
    anyhow::ensure!(
        entry_key != signer,
        "the entry key must differ from the login key"
    );
    let ssh = ensure_directory_chain(home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    // The authorized-keys directory lock is the receiver lifecycle lock too:
    // receivers take it when they start, and revocation holds it.
    lock_directory(&directory)?;
    require_writable_authorized_keys(&ssh)?;
    let state_base = ensure_private_chain(home, &SERVER_STATE)?;
    let state = state_base.join(request.id.to_string());
    let existing = match fs::symlink_metadata(&state) {
        Ok(_) => {
            delegation::validate_private_directory_path(&state)?;
            active::require_not_revoked(&state)?;
            read_receiver_config(&state)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect the enrollment's state"),
    };
    if request.refresh && existing.is_none() {
        // Re-creating the state would start an empty record of used grants,
        // so a grant from the last day could be replayed. Enroll anew.
        return Ok(InstallResponse::StateMissing {
            version: CONFIG_VERSION,
            id: request.id,
        });
    }
    if let Some(existing) = &existing {
        if existing.id != request.id || existing.target_login != request.target_login {
            bail!("the enrollment's state does not match the request");
        }
        if existing.entry_public_key != request.entry_public_key {
            bail!(
                "enrollment {} has a different entry key; revoke it and enroll again",
                request.id
            );
        }
    }
    let receiver_path = install_receiver(home)?;
    let release = crate::identity::build().to_owned();
    let receiver = receiver_path
        .to_str()
        .context("the stored receiver's path is not UTF-8")?
        .to_owned();
    let mut original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    if let Some(replaced) = &request.replaces {
        replaced.id.validate()?;
        // Only an enrollment whose state is gone is replaced; its receiver
        // refuses everything already.
        let replaced_state = state_base.join(replaced.id.to_string());
        let lost = match fs::symlink_metadata(&replaced_state) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error).context("inspect the replaced enrollment's state"),
            Ok(_) => read_receiver_config(&replaced_state)?.is_none(),
        };
        if replaced.id != request.id && lost {
            let key = EnrollmentPublicKey::parse(&replaced.entry_public_key)?;
            original = enrollment::remove_enrollment_line(&original, replaced.id, &key)?.0;
        }
    }
    let results_key = |state: &Path| -> Result<String> {
        ensure_results_key(state, request.id)?
            .public_key()
            .to_openssh()
            .context("encode the results key")
    };
    let respond =
        |generation: u64, results_public_key: String, changed: bool| InstallResponse::Installed {
            version: CONFIG_VERSION,
            id: request.id,
            target_login: request.target_login.clone(),
            remote_home: home.to_string_lossy().into_owned(),
            generation,
            release: release.clone(),
            receiver_path: receiver.clone(),
            results_public_key,
            changed,
        };
    let entry_at = |generation: u64| {
        AuthorizedKeyEntry::enrollment(request.id, &receiver_path, generation, &entry_key, &signer)
    };
    if let Some(existing) = &existing {
        if existing.signer == request.signer
            && existing.release == release
            && existing.receiver_path == receiver
            && request.replaces.is_none()
        {
            let (_, change) =
                enrollment::set_enrollment_line(&original, &entry_at(existing.generation)?)?;
            if change == AuthorizedKeysChange::Unchanged {
                return Ok(respond(existing.generation, results_key(&state)?, false));
            }
        }
    }
    let generation = existing.as_ref().map_or(Ok(1), |existing| {
        existing
            .generation
            .checked_add(1)
            .context("enrollment generation overflow")
    })?;
    let (updated, _) = enrollment::set_enrollment_line(&original, &entry_at(generation)?)?;

    // Write the state first and the line last. A failed preflight cannot
    // leave a usable key, and a later failure leaves only inert private
    // state, or a line for an older generation that refuses new copies,
    // which a retry completes.
    ensure_directory(&state, 0o700)?;
    ensure_directory(&state.join("replay"), 0o700)?;
    let results_public_key = results_key(&state)?;
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id: request.id,
        target_login: request.target_login.clone(),
        generation,
        release: release.clone(),
        receiver_path: receiver.clone(),
        entry_public_key: request.entry_public_key.clone(),
        signer: request.signer.clone(),
    };
    atomic_write(&state, "config.json", &serde_json::to_vec(&config)?, 0o600)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
    Ok(respond(generation, results_public_key, true))
}

pub(crate) fn remote_revoke() -> Result<()> {
    let request: RevokeRequest = read_request("revocation request")?;
    if request.version != CONFIG_VERSION {
        bail!("this syq cannot handle that revocation request version");
    }
    request.id.validate()?;
    let (account, home) = current_account()?;
    revoke_for_account(&request, &account, &home)
}

pub(super) fn revoke_for_account(
    request: &RevokeRequest,
    account: &str,
    home: &Path,
) -> Result<()> {
    if account != request.target_login {
        bail!("revocation target login does not match the remote account");
    }
    let entry_key = EnrollmentPublicKey::parse(&request.entry_public_key)?;
    // Serialize revocation with enrollment updates and receiver admission.
    let ssh = ensure_directory_chain(home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    let state = enrollment_state(home, request.id);
    // Check the state before the line changes, so a failure leaves both.
    let base = state.parent().context("enrollment state has no parent")?;
    if fs::symlink_metadata(base).is_ok() {
        delegation::validate_private_directory_path(base)?;
    }
    let present = match fs::symlink_metadata(&state) {
        Ok(_) => {
            delegation::validate_private_directory_path(&state)?;
            if let Some(config) = read_receiver_config(&state)? {
                if config.target_login != request.target_login
                    || config.entry_public_key != request.entry_public_key
                {
                    bail!("the enrollment's state does not match the revocation request");
                }
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect the enrollment's state"),
    };
    let leases = present.then(|| active::open_leases(&state)).transpose()?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let (updated, change) = enrollment::remove_enrollment_line(&original, request.id, &entry_key)?;
    if change == AuthorizedKeysChange::Revoked {
        atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
    }
    if let Some(leases) = &leases {
        active::revoke(&state, leases)?;
        fs::remove_dir_all(&state)
            .with_context(|| format!("remove revoked receiver state {}", state.display()))?;
    }
    drop(directory);
    println!("revoked {}", request.id);
    Ok(())
}
