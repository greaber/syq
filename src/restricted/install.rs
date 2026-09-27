use super::*;

pub(super) fn generate_enrollment_key(id: EnrollmentId) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate enrollment key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), format!("syq-enrollment:{id}"))
        .context("construct enrollment key")
}

/// The receiver's own signing key for receipts. It lives only on hostB, in
/// the enrollment's state directory, and is generated once per enrollment.
pub(super) fn generate_receipt_key(id: EnrollmentId) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate receipt signing key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), format!("syq-receipt:{id}"))
        .context("construct receipt signing key")
}

pub(super) const RECEIPT_KEY_FILE: &str = "receipt-key";

/// The enrollment's receipt key: generated on first install and kept by
/// every later install, so a refresh after a syq upgrade, or a retry after
/// a lost reply, always reports the key the local side already holds.
/// Rotation is explicit: revoke, then enroll again.
pub(super) fn ensure_receipt_key(state: &Path, id: EnrollmentId) -> Result<PrivateKey> {
    let path = state.join(RECEIPT_KEY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return load_receipt_key(state),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", path.display()));
        }
    }
    let key = generate_receipt_key(id)?;
    atomic_write(
        state,
        RECEIPT_KEY_FILE,
        key.to_openssh(LineEnding::LF)
            .context("encode receipt signing key")?
            .as_bytes(),
        0o600,
    )?;
    Ok(key)
}

/// The receipt signing key installed for this enrollment.
pub(super) fn load_receipt_key(state: &Path) -> Result<PrivateKey> {
    let path = state.join(RECEIPT_KEY_FILE);
    let encoded = delegation::read_private_regular(&path, "receipt signing key", 128 * 1024)?;
    PrivateKey::from_openssh(&encoded).context("parse receipt signing key")
}

pub(super) fn signer_name(id: EnrollmentId) -> String {
    format!("syq-enrollment-{id}")
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

pub(super) fn install_state_paths(
    home: &Path,
    id: EnrollmentId,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let base = ensure_private_chain(home, &[".local", "share", "syq", "restricted"])?;
    let enrollment = base.join(id.to_string());
    ensure_directory(&enrollment, 0o700)?;
    let replay = enrollment.join("replay");
    ensure_directory(&replay, 0o700)?;
    Ok((
        enrollment.clone(),
        enrollment.join("allowed-signers"),
        replay,
    ))
}

pub(super) fn receiver_install_path(home: &Path) -> PathBuf {
    home.join(".local/libexec/syq-receiver")
}

pub(super) fn receiver_control_paths(
    home: &Path,
    receiver: &Path,
    ssh_keygen: Option<&Path>,
) -> Result<Vec<ReceiverControlPath>> {
    let receiver_directory = receiver
        .parent()
        .context("restricted receiver path has no parent directory")?;
    let mut protected = vec![
        ReceiverControlPath {
            path: home.join(".ssh").as_os_str().as_bytes().to_vec(),
            label: "SSH configuration directory",
        },
        ReceiverControlPath {
            path: receiver_directory.as_os_str().as_bytes().to_vec(),
            label: "receiver executable directory",
        },
        ReceiverControlPath {
            path: home
                .join(".local/share/syq/restricted")
                .as_os_str()
                .as_bytes()
                .to_vec(),
            label: "enrollment state directory",
        },
    ];
    if let Some(ssh_keygen) = ssh_keygen {
        protected.push(ReceiverControlPath {
            path: ssh_keygen.as_os_str().as_bytes().to_vec(),
            label: "signature verifier executable",
        });
    }
    Ok(protected)
}

pub(super) fn materialize_receiver(home: &Path, contents: &[u8]) -> Result<PathBuf> {
    let directory_path = ensure_directory_chain(home, &[".local", "libexec"])?;
    let directory = open_directory(&directory_path)?;
    atomic_replace_executable_locked(&directory, "syq-receiver", contents)?;
    let receiver = receiver_install_path(home);
    delegation::validate_regular_executable(&receiver, "restricted receiver")?;
    Ok(receiver)
}

pub(super) fn directory_is_empty(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => delegation::validate_private_directory_path(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    }
    Ok(fs::read_dir(path)
        .with_context(|| format!("list {}", path.display()))?
        .next()
        .transpose()?
        .is_none())
}

pub(super) fn remove_empty_directory(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("remove empty {}", path.display())),
    }
}

pub(super) fn remove_final_enrollment_state_directories(home: &Path) -> Result<()> {
    remove_empty_directory(&home.join(".local/share/syq/restricted"))?;
    remove_empty_directory(&home.join(".local/share/syq"))
}

pub(super) fn contains_managed_enrollment(contents: &[u8]) -> bool {
    const MARKER: &[u8] = b"syq-enrollment:";
    contents.split(|byte| *byte == b'\n').any(|line| {
        let trimmed = line
            .iter()
            .copied()
            .skip_while(u8::is_ascii_whitespace)
            .collect::<Vec<_>>();
        !trimmed.starts_with(b"#")
            && line
                .rsplit(|byte| byte.is_ascii_whitespace())
                .find(|word| !word.is_empty())
                .is_some_and(|word| word.starts_with(MARKER))
    })
}

pub(super) fn resolve_ssh_keygen() -> Result<PathBuf> {
    let candidates = std::iter::once(PathBuf::from("/usr/bin/ssh-keygen")).chain(
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .map(|directory| directory.join("ssh-keygen")),
    );
    for candidate in candidates {
        if candidate.is_absolute()
            && candidate
                .metadata()
                .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        {
            return fs::canonicalize(&candidate)
                .with_context(|| format!("canonicalize {}", candidate.display()));
        }
    }
    bail!("restricted receiver requires ssh-keygen for SSHSIG verification")
}

pub(crate) fn remote_install() -> Result<()> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_STATE_FILE as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_STATE_FILE {
        bail!("restricted enrollment request is too large");
    }
    let request: InstallRequest =
        serde_json::from_slice(&encoded).context("decode restricted enrollment request")?;
    if request.version != CONFIG_VERSION {
        bail!("unsupported restricted enrollment request version");
    }
    request.id.validate()?;
    let (account, home) = current_account()?;
    if account != request.target_login {
        bail!("enrollment target login does not match the remote account");
    }
    let destination =
        normalize_absolute(std::ffi::OsStr::new(&request.requested_destination), &home)?;
    let parent = requested_parent(&destination);
    let canonical_root = fs::canonicalize(parent)
        .with_context(|| format!("resolve restricted destination parent {}", parent.display()))?;
    if !fs::metadata(&canonical_root)?.is_dir() {
        bail!("restricted destination parent is not a directory");
    }
    let leaf = destination
        .file_name()
        .context("restricted destination / is not supported")?;
    let canonical_destination = canonical_root.join(leaf);
    if fs::symlink_metadata(&canonical_destination).is_ok_and(|metadata| metadata.is_symlink()) {
        bail!(
            "command-restricted enrollment does not follow a destination-root symlink; enroll its explicit referent instead"
        );
    }
    let canonical_home = fs::canonicalize(&home)
        .with_context(|| format!("resolve receiver home {}", home.display()))?;
    let ssh_keygen = resolve_ssh_keygen()?;
    let bootstrap_receiver = receiver_install_path(&canonical_home);
    let protected =
        receiver_control_paths(&canonical_home, &bootstrap_receiver, Some(&ssh_keygen))?;
    reject_control_plane_path(canonical_destination.as_os_str().as_bytes(), &protected)?;
    let root = crate::rooted::Root::open(&canonical_root)?;
    let root_identity = root.identity();
    let enrollment_key = EnrollmentPublicKey::parse(&request.public_key)?;
    let signer = signer_name(request.id);
    let public_words: Vec<&str> = request.public_key.split_ascii_whitespace().collect();
    if public_words.len() < 2 {
        bail!("enrollment public key is malformed");
    }
    let running_receiver = std::env::current_exe().context("resolve restricted receiver path")?;
    delegation::validate_regular_executable(&running_receiver, "restricted receiver")?;
    let receiver_contents = fs::read(&running_receiver)
        .with_context(|| format!("read restricted receiver {}", running_receiver.display()))?;
    let ssh = ensure_directory_chain(&home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    // The authorized-keys directory lock is the receiver lifecycle lock too.
    // A concurrent final revoke may unlink the shared executable, but an
    // installer that already started has its bytes and recreates it before
    // publishing the new forced authorization.
    let receiver_path = materialize_receiver(&home, &receiver_contents)?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &enrollment_key)?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, change) = enrollment::install_authorized_key(&normalized, &entry)?;

    // Publish the forced authorization last. A failed preflight therefore
    // cannot leave a usable key, and a later state-write failure leaves only
    // inert private state that an idempotent retry can complete.
    let (state, _allowed_signers, _replay) = install_state_paths(&home, request.id)?;
    active::require_not_revoked(&state)?;
    atomic_write(
        &state,
        "allowed-signers",
        format!("{signer} {} {}\n", public_words[0], public_words[1]).as_bytes(),
        0o600,
    )?;
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id: request.id,
        target_login: request.target_login.clone(),
        signer,
        root: canonical_root
            .to_str()
            .context("canonical restricted root is not UTF-8")?
            .to_owned(),
        root_dev: root_identity.dev,
        root_ino: root_identity.ino,
        ssh_keygen: ssh_keygen
            .to_str()
            .context("ssh-keygen path is not UTF-8")?
            .to_owned(),
        receiver_path: receiver_path
            .to_str()
            .context("restricted receiver path is not UTF-8")?
            .to_owned(),
    };
    let receipt_key = ensure_receipt_key(&state, request.id)?;
    let receipt_public_key = receipt_key
        .public_key()
        .to_openssh()
        .context("encode receipt public key")?;
    atomic_write(&state, "config.json", &serde_json::to_vec(&config)?, 0o600)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;

    let response = InstallResponse {
        version: CONFIG_VERSION,
        id: request.id,
        target_login: request.target_login,
        remote_home: home
            .to_str()
            .context("remote account home is not UTF-8")?
            .to_owned(),
        requested_parent: parent
            .to_str()
            .context("requested destination parent is not UTF-8")?
            .to_owned(),
        canonical_root: config.root,
        canonical_destination: canonical_destination
            .to_str()
            .context("canonical destination is not UTF-8")?
            .to_owned(),
        receiver_path: receiver_path
            .to_str()
            .context("restricted receiver path is not UTF-8")?
            .to_owned(),
        receipt_public_key,
        change: match change {
            AuthorizedKeysChange::Installed => "installed",
            AuthorizedKeysChange::Unchanged => "unchanged",
            AuthorizedKeysChange::Revoked => unreachable!("install cannot revoke"),
        }
        .to_owned(),
    };
    serde_json::to_writer(std::io::stdout().lock(), &response)?;
    Ok(())
}

pub(crate) fn remote_revoke() -> Result<()> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_STATE_FILE as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_STATE_FILE {
        bail!("restricted revocation request is too large");
    }
    let request: RevokeRequest = serde_json::from_slice(&encoded)?;
    if request.version != CONFIG_VERSION {
        bail!("unsupported restricted revocation request version");
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
    // Serialize revocation with both enrollment updates and receiver admission.
    let ssh = ensure_directory_chain(home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    let state_base = home.join(".local/share/syq/restricted");
    let state = state_base.join(request.id.to_string());
    let (receiver_path, remove_state) = match fs::symlink_metadata(&state) {
        Ok(_) => {
            delegation::validate_private_directory_path(&state)?;
            let (config, allowed_signers, _) = receiver_config(request.id)?;
            if config.target_login != request.target_login {
                bail!("revocation target login does not match receiver state");
            }
            let state = allowed_signers
                .parent()
                .context("restricted receiver state has no enrollment directory")?;
            (
                PathBuf::from(config.receiver_path),
                Some(state.to_path_buf()),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (receiver_install_path(home), None)
        }
        Err(error) => return Err(error).context("inspect restricted receiver state"),
    };
    let enrollment_key = EnrollmentPublicKey::parse(&request.public_key)?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &enrollment_key)?;
    // Validate the shared state chain before removing the credential. The
    // second check below determines whether the now-updated state is empty.
    let _ = directory_is_empty(&state_base)?;
    let leases = remove_state
        .as_deref()
        .map(active::open_leases)
        .transpose()?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, _) = enrollment::revoke_authorized_key(&normalized, &entry)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
    if let Some(state) = remove_state {
        active::revoke(&state, leases.as_ref().expect("enrollment lease file"))?;
        fs::remove_dir_all(&state)
            .with_context(|| format!("remove revoked receiver state {}", state.display()))?;
    }
    let last_enrollment =
        !contains_managed_enrollment(&updated) && directory_is_empty(&state_base)?;
    if last_enrollment {
        let installed_receiver = receiver_install_path(home);
        if receiver_path != installed_receiver {
            bail!(
                "refusing to remove unexpected restricted receiver path {}",
                receiver_path.display()
            );
        }
        remove_final_enrollment_state_directories(home)?;
        match fs::symlink_metadata(&installed_receiver) {
            Ok(_) => {
                delegation::validate_regular_executable(
                    &installed_receiver,
                    "restricted receiver",
                )?;
                fs::remove_file(&installed_receiver).with_context(|| {
                    format!(
                        "remove final restricted receiver {}",
                        installed_receiver.display()
                    )
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect {}", installed_receiver.display()))
            }
        }
        // `.local`, `share`, and `libexec` are general account directories.
        // Without a durable record proving syq created them, preserve them
        // even when the final enrollment leaves them empty.
    }
    drop(directory);
    println!("revoked {}", request.id);
    Ok(())
}

pub(super) fn normalize_managed_authorized_keys(original: &[u8], marker: &str) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(original.len());
    for raw in original.split_inclusive(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let trimmed = line
            .iter()
            .copied()
            .skip_while(u8::is_ascii_whitespace)
            .collect::<Vec<_>>();
        let commented_managed = trimmed.starts_with(b"#")
            && line
                .rsplit(|byte| byte.is_ascii_whitespace())
                .find(|word| !word.is_empty())
                == Some(marker.as_bytes());
        if !commented_managed {
            normalized.extend_from_slice(line);
            normalized.push(b'\n');
        }
    }
    normalized
}
