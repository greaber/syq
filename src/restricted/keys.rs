//! Enrollment key protection and local signing. Only the dedicated key is
//! exposed to a coordinating server; the login identity is never forwarded.
use super::*;
use crate::agent_broker::{BrokerPolicy, ConstrainedAgentBroker};
use crate::process::CommandExt as _;
use ssh_key::{Algorithm, PublicKey};
use zeroize::Zeroizing;

mod wrapping;

pub(crate) enum EnrollmentSigningKey {
    Private(PrivateKey),
    Agent {
        key: PublicKey,
        path: PathBuf,
        socket: PathBuf,
        _temporary: tempfile::TempDir,
    },
}

impl EnrollmentSigningKey {
    pub(super) fn sign_grant(&self, payload: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Private(key) => {
                let namespace = delegation::SSHSIG_NAMESPACE;
                let hash = ssh_key::HashAlg::Sha256;
                let data = ssh_key::SshSig::signed_data(namespace, hash, payload)?;
                let flags = if key.key_data().is_rsa() {
                    ssh_agent_lib::proto::signature::RSA_SHA2_512
                } else {
                    0
                };
                let signature = crate::agent_broker::sign_private_key(key, &data, flags)?;
                Ok(ssh_key::SshSig::new(
                    key.public_key().key_data().clone(),
                    namespace,
                    hash,
                    signature,
                )?
                .to_pem(LineEnding::LF)?
                .into_bytes())
            }
            Self::Agent {
                key, path, socket, ..
            } => {
                let signature =
                    agent_signature(key, path, socket, delegation::SSHSIG_NAMESPACE, payload)?;
                Ok(signature.to_vec())
            }
        }
    }

    pub(crate) fn start_broker(
        self,
        policy: BrokerPolicy,
        limit: usize,
    ) -> Result<ConstrainedAgentBroker> {
        match self {
            Self::Private(key) => {
                ConstrainedAgentBroker::start_with_private_key(policy, limit, key)
            }
            Self::Agent { key, socket, .. } => ConstrainedAgentBroker::start_with_agent_key(
                policy,
                limit,
                socket,
                key.key_data().clone(),
            ),
        }
    }
}

pub(super) fn load_signing_key(directory: &Path) -> Result<EnrollmentSigningKey> {
    let encoded = read_enrollment_key(directory)?;
    let key = if let Some(wrapped) = wrapping::WrappedKey::decode(&encoded)? {
        wrapped.unlock()?
    } else {
        PrivateKey::from_openssh(&encoded).context("parse enrollment private key")?
    };
    if !key.is_encrypted()
        && matches!(
            key.algorithm(),
            Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. }
        )
    {
        return Ok(EnrollmentSigningKey::Private(key));
    }
    let public = key.public_key().clone();
    let socket = ensure_agent_key(
        &directory.join("enrollment-key"),
        &public,
        read_key_provider(directory)?.as_deref(),
    )?;
    let temporary = crate::private_broker::private_temp_dir("syq-sign-")?;
    let path = temporary.path().join("key.pub");
    atomic_write(
        temporary.path(),
        "key.pub",
        public.to_openssh()?.as_bytes(),
        0o600,
    )?;
    Ok(EnrollmentSigningKey::Agent {
        key: public,
        path,
        socket,
        _temporary: temporary,
    })
}

pub(super) fn load_enrollment_public_key(directory: &Path) -> Result<PublicKey> {
    let encoded = read_enrollment_key(directory)?;
    if let Some(wrapped) = wrapping::WrappedKey::decode(&encoded)? {
        return PublicKey::from_openssh(&wrapped.header.public_key)
            .context("parse wrapped receiver public key");
    }
    Ok(PrivateKey::from_openssh(&encoded)?.public_key().clone())
}

fn read_enrollment_key(directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(delegation::read_private_regular(
        &directory.join("enrollment-key"),
        "enrollment private key",
        MAX_STATE_FILE,
    )?))
}

fn ensure_agent_key(path: &Path, public: &PublicKey, provider: Option<&str>) -> Result<PathBuf> {
    let socket = std::env::var_os("SSH_AUTH_SOCK")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context(
            "an SSH agent is required to unlock this receiver key; start an agent and retry",
        )?;
    if !agent_has_key(&socket, public)? {
        // ssh-add uses the existing key's normal passphrase/PIN prompt. Syq
        // neither reads that passphrase nor asks for a receiver passphrase.
        let mut command = Command::new("ssh-add");
        if let Some(provider) = provider {
            command.args(["-S", provider]);
        }
        let status = command
            .arg(path)
            .env("SSH_AUTH_SOCK", &socket)
            .status_guarded()
            .context("unlock receiver signing identity with ssh-add")?;
        if !status.success() || !agent_has_key(&socket, public)? {
            bail!("could not unlock the receiver signing identity; load its key with ssh-add and retry");
        }
    }
    Ok(socket)
}

fn agent_signature(
    public: &PublicKey,
    path: &Path,
    socket: &Path,
    namespace: &str,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut child = Command::new("ssh-keygen")
        .args(["-q", "-Y", "sign", "-n", namespace, "-f"])
        .arg(path)
        .env("SSH_AUTH_SOCK", socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn_guarded()
        .context("start SSH agent signer")?;
    let write = child
        .stdin
        .take()
        .context("agent signer input")?
        .write_all(payload);
    let output = child
        .wait_with_output()
        .context("wait for SSH agent signer")?;
    let encoded = Zeroizing::new(output.stdout);
    if !output.status.success() {
        bail!(
            "SSH agent could not sign with the receiver identity ({})",
            output.status
        );
    }
    write.context("write payload to SSH agent signer")?;
    let signature = ssh_key::SshSig::from_pem(&encoded).context("parse agent signature")?;
    public
        .verify(namespace, payload, &signature)
        .context("verify SSH agent signature")?;
    Ok(encoded)
}

fn read_key_provider(directory: &Path) -> Result<Option<String>> {
    let path = directory.join("security-key-provider");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => Ok(Some(String::from_utf8(delegation::read_private_regular(
            &path,
            "security-key provider",
            4096,
        )?)?)),
    }
}

pub(super) fn enrollment_key_provider(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
) -> Result<Option<String>> {
    let output = Command::new("ssh")
        .arg("-G")
        .args(enrollment::enrollment_ssh_args_raw(target, route, ""))
        .capture_output()
        .context("inspect enrollment security-key provider")?;
    if !output.status.success() {
        bail!("could not inspect enrollment security-key provider");
    }
    let config = String::from_utf8(output.stdout)?;
    let provider = config
        .lines()
        .find_map(|line| line.strip_prefix("securitykeyprovider "))
        .context("SSH did not report its security-key provider")?;
    if provider == "internal" {
        Ok(std::env::var("SSH_SK_PROVIDER").ok())
    } else {
        Ok(Some(provider.to_owned()))
    }
}

fn agent_has_key(socket: &Path, key: &PublicKey) -> Result<bool> {
    let output = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", socket)
        .capture_output()
        .context("list SSH agent keys")?;
    match output.status.code() {
        Some(0) => Ok(std::str::from_utf8(&output.stdout)
            .context("SSH agent public keys are not UTF-8")?
            .lines()
            .filter_map(|line| PublicKey::from_openssh(line).ok())
            .any(|candidate| candidate.key_data() == key.key_data())),
        Some(1) => Ok(false),
        _ => bail!(
            "cannot query SSH agent: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    }
}

/// OpenSSH 8.9 verifies SSHSIG cryptography but does not enforce FIDO user
/// presence/verification policy for it. Check these authenticated signature
/// flags before redemption as well as applying the SSH authorized_keys options.
pub(super) fn enforce_grant_security_key_flags(encoded: &[u8], required: Option<u8>) -> Result<()> {
    let Some(required) = required else {
        return Ok(());
    };
    if required & !5 != 0 {
        bail!("unsupported receiver security-key policy");
    }
    let envelope = delegation::SignedGrantEnvelope::decode(encoded)?;
    let signature = ssh_key::SshSig::from_pem(&envelope.signature)?;
    if !matches!(
        signature.algorithm(),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
    ) {
        bail!("receiver grant requires a security-key signature");
    }
    let bytes = signature.signature_bytes();
    let flags = *bytes
        .get(
            bytes
                .len()
                .checked_sub(5)
                .context("truncated security-key signature")?,
        )
        .context("missing security-key signature flags")?;
    if flags & required != required {
        bail!("receiver grant does not satisfy its security-key touch/PIN policy");
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct KeyTemplate {
    pub(super) algorithm: String,
    pub(super) bits: Option<usize>,
    protector: Option<wrapping::Protector>,
    pub(super) provider: Option<String>,
    pub(super) security_key_flags: Option<u8>,
}

/// Use the actual signing event and successful public-key authentication, not
/// an offered key or a server's preliminary acceptance of a public key.
fn login_key_from_trace(trace: &str) -> Result<(PathBuf, String)> {
    let mut candidate = None;
    let mut signed = None;
    for line in trace.lines() {
        if let Some(identity) = line.strip_prefix("debug1: Server accepts key: ") {
            if let Some((name_and_type, rest)) = identity.rsplit_once(" SHA256:") {
                if let Some((path, _kind)) = name_and_type.rsplit_once(' ') {
                    candidate = Some(PathBuf::from(path));
                    signed = None;
                    let _ = rest;
                }
            }
        } else if let Some(path) = line.strip_prefix("debug1: Trying private key: ") {
            candidate = Some(PathBuf::from(path));
            signed = None;
        } else if let Some(detail) =
            line.strip_prefix("debug3: sign_and_send_pubkey: signing using ")
        {
            let mut words = detail.split_ascii_whitespace();
            let algorithm = words.next().context("SSH signing algorithm missing")?;
            let fingerprint = words.next().context("SSH signing fingerprint missing")?;
            if algorithm.contains("-cert-") {
                bail!("automatic receiver key matching does not support SSH certificates");
            }
            if !fingerprint.starts_with("SHA256:") {
                bail!("SSH login key did not report a SHA256 fingerprint");
            }
            signed = Some((
                candidate
                    .clone()
                    .context("SSH login key pathname was not reported")?,
                fingerprint.to_owned(),
            ));
        } else if line.starts_with("Authenticated to ") {
            if !line.ends_with(" using \"publickey\".") {
                bail!(
                    "automatic receiver enrollment requires an identifiable SSH public-key login"
                );
            }
            return signed.context("SSH did not report the key used for enrollment");
        } else if line.contains("Authenticated with partial success")
            || line.contains("with partial success")
        {
            bail!("automatic receiver enrollment cannot reproduce multi-factor SSH authentication");
        }
    }
    bail!("SSH did not report a successful public-key login for receiver enrollment")
}

pub(super) fn key_template(trace: &str, authorized: &[u8]) -> Result<KeyTemplate> {
    let (mut path, fingerprint) = login_key_from_trace(trace)?;
    if path.extension().is_some_and(|extension| extension == "pub") {
        path.set_extension("");
    }
    if !path.is_absolute() {
        bail!("cannot identify the local private-key file for the SSH login; automatic receiver enrollment cannot determine whether this agent key is hardware-backed");
    }
    let encoded = delegation::read_private_regular(&path, "SSH login key", 128 * 1024)
        .context("automatic receiver enrollment needs the login key's local file to preserve its protection; agent-only and PIV/OpenPGP identities are not yet supported")?;
    let private = PrivateKey::from_openssh(&encoded)
        .context("automatic receiver enrollment requires an OpenSSH-format login key")?;
    let public = private.public_key();
    if public.fingerprint(ssh_key::HashAlg::Sha256).to_string() != fingerprint {
        bail!("local key does not match the key that authenticated receiver enrollment");
    }
    let encrypted = private.is_encrypted();
    let (algorithm, bits, flags) = match public.algorithm() {
        Algorithm::Ed25519 => ("ed25519".to_owned(), None, None),
        Algorithm::Rsa { .. } => {
            let n = public
                .key_data()
                .rsa()
                .context("RSA key")?
                .n
                .as_positive_bytes()
                .context("RSA modulus")?;
            let bits = n
                .first()
                .map_or(0, |first| n.len() * 8 - first.leading_zeros() as usize);
            ("rsa".to_owned(), Some(bits.max(3072)), None)
        }
        Algorithm::Ecdsa { curve } => (
            "ecdsa".to_owned(),
            Some(match curve {
                ssh_key::EcdsaCurve::NistP256 => 256,
                ssh_key::EcdsaCurve::NistP384 => 384,
                ssh_key::EcdsaCurve::NistP521 => 521,
            }),
            None,
        ),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256 => {
            if encrypted {
                bail!("automatic enrollment cannot inspect the touch/PIN settings of an encrypted FIDO key handle");
            }
            let flags = private
                .key_data()
                .sk_ed25519()
                .map(|key| key.flags())
                .or_else(|| private.key_data().sk_ecdsa_p256().map(|key| key.flags()))
                .context("FIDO key flags missing")?;
            let options = matching_authorization(authorized, public)?;
            let mut flags = flags & 5;
            if !options.iter().any(|option| option == "no-touch-required") {
                flags |= 1;
            }
            if options.iter().any(|option| option == "verify-required") {
                flags |= 4;
            }
            (
                if public.algorithm() == Algorithm::SkEd25519 {
                    "ed25519-sk"
                } else {
                    "ecdsa-sk"
                }
                .to_owned(),
                None,
                Some(flags),
            )
        }
        _ => bail!("unsupported SSH login key algorithm for receiver enrollment"),
    };
    let protector = if encrypted {
        if !matches!(
            public.algorithm(),
            Algorithm::Ed25519 | Algorithm::Rsa { .. }
        ) {
            bail!("automatic receiver enrollment cannot protect a software key using this login key: passphrase-protected ECDSA is unsupported; use an Ed25519 or RSA login key");
        }
        Some(wrapping::Protector {
            path,
            public_key: public.to_openssh()?,
        })
    } else {
        None
    };
    Ok(KeyTemplate {
        algorithm,
        bits,
        protector,
        provider: None,
        security_key_flags: flags,
    })
}

fn authorization_field(line: &str) -> Result<(&str, &str)> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && character == '\\' {
            escaped = true;
            continue;
        }
        if character == '\"' {
            quoted = !quoted;
        }
        if character.is_ascii_whitespace() && !quoted {
            return Ok((&line[..index], line[index..].trim_start()));
        }
    }
    bail!("incomplete authorized_keys entry")
}

fn authorization_options(options: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in options.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '\"' {
            quoted = !quoted;
        } else if character == ',' && !quoted {
            parts.push(options[start..index].to_owned());
            start = index + 1;
        }
    }
    if quoted || escaped {
        bail!("unterminated authorized_keys option");
    }
    parts.push(options[start..].to_owned());
    if parts.iter().any(String::is_empty) {
        bail!("empty authorized_keys option");
    }
    Ok(parts)
}

fn matching_authorization(authorized: &[u8], public: &PublicKey) -> Result<Vec<String>> {
    let mut found = None;
    for raw in authorized.split(|byte| *byte == b'\n') {
        // Public-key fields and policy option names are ASCII. A comment or
        // command containing other bytes must not hide an otherwise usable key.
        let line = String::from_utf8_lossy(raw);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Ok((first, rest)) = authorization_field(line) else {
            continue;
        };
        let (options, key_text) =
            if first.starts_with("sk-") || first.starts_with("ssh-") || first.starts_with("ecdsa-")
            {
                (None, line)
            } else {
                (Some(first), rest)
            };
        let Ok(key) = PublicKey::from_openssh(key_text) else {
            continue;
        };
        if key.key_data() != public.key_data() {
            continue;
        }
        let options = options
            .map(authorization_options)
            .transpose()?
            .unwrap_or_default();
        if found.is_some() {
            bail!("multiple authorizations match the enrollment login key; cannot infer its touch/PIN policy");
        }
        found = Some(options);
    }
    found.context("the FIDO login key has no matching entry in ~/.ssh/authorized_keys; cannot infer its server touch/PIN policy")
}

pub(super) fn generate_matching_key(
    directory: &Path,
    id: EnrollmentId,
    template: &KeyTemplate,
) -> Result<PublicKey> {
    let key = if template.security_key_flags.is_none() {
        let mut rng = ssh_key::rand_core::OsRng;
        let mut key = match template.algorithm.as_str() {
            "ed25519" => PrivateKey::random(&mut rng, Algorithm::Ed25519)?,
            "rsa" => ssh_key::private::RsaKeypair::random(
                &mut rng,
                template.bits.context("RSA receiver key size")?,
            )?
            .into(),
            "ecdsa" => PrivateKey::random(
                &mut rng,
                Algorithm::Ecdsa {
                    curve: match template.bits {
                        Some(256) => ssh_key::EcdsaCurve::NistP256,
                        Some(384) => ssh_key::EcdsaCurve::NistP384,
                        Some(521) => ssh_key::EcdsaCurve::NistP521,
                        _ => bail!("unsupported receiver ECDSA curve"),
                    },
                },
            )?,
            _ => bail!("unsupported software receiver key algorithm"),
        };
        key.set_comment(format!("syq-enrollment:{id}"));
        key
    } else {
        let staging = crate::private_broker::private_temp_dir("syq-key-")?;
        let path = staging.path().join("key");
        let mut command = Command::new("ssh-keygen");
        command
            .args([
                "-q",
                "-t",
                &template.algorithm,
                "-C",
                &format!("syq-enrollment:{id}"),
                "-f",
            ])
            .arg(&path)
            .args(["-N", ""]);
        if let Some(provider) = &template.provider {
            command.args(["-w", provider]);
        }
        let flags = template
            .security_key_flags
            .context("FIDO receiver key policy")?;
        if flags & 1 == 0 {
            command.args(["-O", "no-touch-required"]);
        }
        if flags & 4 != 0 {
            command.args(["-O", "verify-required"]);
        }
        if !command
            .status_guarded()
            .context("generate hardware receiver key")?
            .success()
        {
            bail!("could not create a matching hardware receiver key; no software-key fallback was installed");
        }
        let encoded = Zeroizing::new(delegation::read_private_regular(
            &path,
            "generated receiver key",
            128 * 1024,
        )?);
        PrivateKey::from_openssh(&encoded)?
    };
    let public = key.public_key().clone();
    // Software keys are wrapped before any durable write. Only FIDO handles
    // and software keys matching an unencrypted login are stored as OpenSSH.
    let stored = if let Some(protector) = &template.protector {
        wrapping::WrappedKey::seal(protector.clone(), &key)?.encode()?
    } else {
        key.to_openssh(LineEnding::LF)?.as_bytes().to_vec()
    };
    let stored = Zeroizing::new(stored);
    if let Some(provider) = &template.provider {
        atomic_write(
            directory,
            "security-key-provider",
            provider.as_bytes(),
            0o600,
        )?;
    }
    atomic_write(directory, "enrollment-key", &stored, 0o600)?;
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    pub(super) fn trace(path: &Path, key: &PublicKey) -> String {
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256);
        format!("debug1: Server accepts key: {} ED25519 {fingerprint} explicit agent\ndebug3: sign_and_send_pubkey: signing using {} {fingerprint}\nAuthenticated to fixture ([127.0.0.1]:22) using \"publickey\".\n", path.display(), key.algorithm())
    }
    fn sk(flags: u8) -> PrivateKey {
        let pair = Ed25519Keypair::from_seed(&[73; 32]);
        let public = ssh_key::public::SkEd25519::new(pair.public, "ssh:");
        ssh_key::private::SkEd25519::new(public, flags, vec![1, 2, 3])
            .unwrap()
            .into()
    }
    #[test]
    fn login_selection_requires_the_successful_signing_key() {
        let key = generate_enrollment_key(EnrollmentId::test_v4(1)).unwrap();
        let path = Path::new("/tmp/key with spaces");
        let log = trace(path, key.public_key());
        assert_eq!(login_key_from_trace(&log).unwrap().0, path);
        assert!(login_key_from_trace(log.split("Authenticated to ").next().unwrap()).is_err());
        assert!(
            login_key_from_trace(&log.replace("using \"publickey\"", "using \"password\""))
                .is_err()
        );
        assert!(login_key_from_trace(&format!(
            "Authenticated using publickey with partial success.\n{log}"
        ))
        .is_err());
    }
    #[test]
    fn fidokey_template_combines_client_and_server_policy() {
        let dir = crate::test_support::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("key");
        for (local, options, expected) in [
            (0, "no-touch-required", 0),
            (1, "no-touch-required", 1),
            (0, "verify-required", 5),
            (4, "no-touch-required", 4),
        ] {
            let key = sk(local);
            atomic_write(
                dir.path(),
                "key",
                key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
                0o600,
            )
            .unwrap();
            let authorized = format!(
                "{options} {} comment\n",
                key.public_key().to_openssh().unwrap()
            );
            let template =
                key_template(&trace(&path, key.public_key()), authorized.as_bytes()).unwrap();
            assert_eq!(template.security_key_flags, Some(expected));
            assert_eq!(template.algorithm, "ed25519-sk");
            assert!(template.protector.is_none());
            assert!(key_template(&trace(&path, key.public_key()), b"").is_err());
        }
    }
    #[test]
    fn public_key_match_and_ambiguous_authorizations_are_rejected() {
        let key = sk(0);
        let entry = format!(
            "command=\"echo no-touch-required\",verify-required {}",
            key.public_key().to_openssh().unwrap()
        );
        let options = matching_authorization(entry.as_bytes(), key.public_key()).unwrap();
        assert!(!options.iter().any(|value| value == "no-touch-required"));
        assert!(options.iter().any(|value| value == "verify-required"));
        assert!(
            matching_authorization(format!("{entry}\n{entry}").as_bytes(), key.public_key())
                .is_err()
        );
        let dir = crate::test_support::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("key");
        let other = generate_enrollment_key(EnrollmentId::test_v4(2)).unwrap();
        atomic_write(
            dir.path(),
            "key",
            other.to_openssh(LineEnding::LF).unwrap().as_bytes(),
            0o600,
        )
        .unwrap();
        assert!(
            key_template(&trace(&path, key.public_key()), entry.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }
    #[test]
    fn authorized_key_entry_preserves_touch_and_verification_requirements() {
        let public = EnrollmentPublicKey::parse(&sk(0).public_key().to_openssh().unwrap()).unwrap();
        let entry = AuthorizedKeyEntry::with_security_key_flags(
            EnrollmentId::test_v4(1),
            Path::new("/opt/syq/receiver"),
            &public,
            Some(4),
        )
        .unwrap();
        assert!(entry
            .line()
            .starts_with("restrict,no-touch-required,verify-required,command="));
        assert!(AuthorizedKeyEntry::new(
            EnrollmentId::test_v4(1),
            Path::new("/opt/syq/receiver"),
            &public
        )
        .is_err());
    }
}
