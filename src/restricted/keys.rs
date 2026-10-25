//! The enrollment's keys.
//!
//! The entry key only starts the receiver. Syq generates it, keeps it on the
//! enrolling machine, and hands it to the coordinating server with each
//! approval; it can authorize nothing. The user's own login key signs every
//! grant, in Rust: through the agent protocol, or from an unencrypted key
//! file. Only the enrolling machine ever holds the login key.
use super::*;
use crate::delegation::{TrustedSigner, SK_USER_PRESENCE, SK_USER_VERIFICATION};
use ssh_key::{Algorithm, PublicKey};
use zeroize::Zeroizing;

mod agent;

/// The namespace of the signature enrollment makes to check that the login
/// key can sign, before anything is installed. No grant uses it.
pub(super) const PROBE_NAMESPACE: &str = "syq-receiver-key-check-v1@greaber.github";

/// The entry key's file in the enrolling machine's enrollment directory.
const ENTRY_KEY_FILE: &str = "entry-key";

/// The oldest OpenSSH server whose `authorized_keys` understands `restrict`.
const MINIMUM_OPENSSH: (u32, u32) = (7, 2);

pub(crate) fn validate_entry_public_key(key: &PublicKey) -> Result<()> {
    anyhow::ensure!(
        matches!(
            key.algorithm(),
            Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. }
        ),
        "an entry key must be a software Ed25519, RSA, or ECDSA key"
    );
    Ok(())
}

/// A new entry key of the login key's kind, so the server accepts it as it
/// accepts the login: ECDSA keeps its curve, Ed25519 and the FIDO types map
/// to software Ed25519 or ECDSA P-256, and RSA has 3,072 bits, or the login
/// key's size up to 4,096. The entry key only gets past sshd, and a larger
/// one would only make enrolling slower.
pub(super) fn generate_entry_key(login: &PublicKey, id: EnrollmentId) -> Result<PrivateKey> {
    let mut rng = ssh_key::rand_core::OsRng;
    let mut key: PrivateKey = match login.algorithm() {
        Algorithm::Rsa { .. } => {
            let modulus = login
                .key_data()
                .rsa()
                .context("RSA login key")?
                .n
                .as_positive_bytes()
                .context("RSA modulus")?;
            let bits = modulus.first().map_or(0, |first| {
                modulus.len() * 8 - first.leading_zeros() as usize
            });
            ssh_key::private::RsaKeypair::random(&mut rng, bits.clamp(3072, 4096))?.into()
        }
        Algorithm::Ecdsa { curve } => PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve })?,
        Algorithm::SkEcdsaSha2NistP256 => PrivateKey::random(
            &mut rng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )?,
        Algorithm::Ed25519 | Algorithm::SkEd25519 => {
            PrivateKey::random(&mut rng, Algorithm::Ed25519)?
        }
        algorithm => bail!("syq cannot make an entry key for a {algorithm} login key"),
    };
    key.set_comment(format!("syq-enrollment:{id}"));
    Ok(key)
}

pub(super) fn store_entry_key(directory: &Path, key: &PrivateKey) -> Result<()> {
    let encoded = Zeroizing::new(key.to_openssh(LineEnding::LF)?);
    atomic_write(directory, ENTRY_KEY_FILE, encoded.as_bytes(), 0o600)
}

pub(super) fn load_entry_key(directory: &Path) -> Result<PrivateKey> {
    let encoded = Zeroizing::new(delegation::read_private_regular(
        &directory.join(ENTRY_KEY_FILE),
        "entry key",
        MAX_STATE_FILE,
    )?);
    parse_entry_key(&encoded)
}

/// An entry key as the enrolling machine stores it and hands it over.
pub(crate) fn parse_entry_key(encoded: &[u8]) -> Result<PrivateKey> {
    let key = PrivateKey::from_openssh(encoded).context("parse the entry key")?;
    anyhow::ensure!(!key.is_encrypted(), "the entry key must not be encrypted");
    validate_entry_public_key(key.public_key())?;
    Ok(key)
}

/// The user's login key, ready to sign.
pub(crate) enum LoginSigner {
    /// Through the SSH agent at `socket`, which holds the key.
    Agent { socket: PathBuf, key: PublicKey },
    /// From an unencrypted software key file.
    File(Box<PrivateKey>),
}

impl LoginSigner {
    pub(super) fn public_key(&self) -> &PublicKey {
        match self {
            Self::Agent { key, .. } => key,
            Self::File(key) => key.public_key(),
        }
    }

    /// An armored SSHSIG over `payload` in `namespace`, hashed with SHA-512
    /// as `ssh-keygen -Y sign` does.
    pub(super) fn sign(&self, namespace: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let hash = ssh_key::HashAlg::Sha512;
        let data = ssh_key::SshSig::signed_data(namespace, hash, payload)?;
        let signature = match self {
            Self::Agent { socket, key } => agent::sign(socket, key, &data).map_err(|error| {
                if error.downcast_ref::<agent::AgentRefused>().is_some() {
                    anyhow!(
                        "your SSH agent refused to sign with the login key {}. A key added with `ssh-add -h` signs only logins; a FIDO key needs a touch, and its PIN needs an SSH_ASKPASS program the agent can run",
                        key.fingerprint(ssh_key::HashAlg::Sha256)
                    )
                } else {
                    error
                }
            })?,
            Self::File(key) => crate::agent_broker::sign_private_key(
                key,
                &data,
                if key.key_data().is_rsa() {
                    ssh_agent_lib::proto::signature::RSA_SHA2_512
                } else {
                    0
                },
            )?,
        };
        delegation::armored_sshsig(self.public_key().key_data(), namespace, hash, &signature)
    }

    /// The signer for a login key enrollment recorded: through `agent` when
    /// it holds the key, else from its unencrypted key file. `None` when
    /// neither can sign, or a certificate it carried has expired, and the
    /// login key must be found again.
    pub(super) fn find(
        trusted: &TrustedSigner,
        agent: Option<&Path>,
        identity_file: Option<&Path>,
        now: i64,
    ) -> Result<Option<Self>> {
        if trusted
            .valid_before
            .is_some_and(|valid_before| u64::try_from(now).map_or(true, |now| now >= valid_before))
        {
            return Ok(None);
        }
        let key = trusted.key()?;
        // An agent that cannot be reached says nothing about the key: report
        // it rather than enroll another login key in its place.
        let mut unreachable = None;
        if let Some(socket) = agent {
            match agent::has_key(socket, &key) {
                Ok(true) => {
                    return Ok(Some(Self::Agent {
                        socket: socket.to_path_buf(),
                        key,
                    }))
                }
                Ok(false) => {}
                Err(error) => unreachable = Some((socket, error)),
            }
        }
        if let Some(path) = identity_file {
            if let Some(private) = read_login_key(path)
                .ok()
                .and_then(|encoded| PrivateKey::from_openssh(&*encoded).ok())
            {
                if !private.is_encrypted()
                    && private.public_key().key_data() == key.key_data()
                    && software_key(&key)
                {
                    return Ok(Some(Self::File(Box::new(private))));
                }
            }
        }
        if let Some((socket, error)) = unreachable {
            return Err(error.context(format!(
                "cannot use the SSH agent at {} to find the login key restricted copying trusts; check SSH_AUTH_SOCK or the IdentityAgent setting",
                socket.display()
            )));
        }
        Ok(None)
    }
}

fn software_key(key: &PublicKey) -> bool {
    matches!(
        key.algorithm(),
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }
    )
}

/// The login key that authenticated enrollment: how to sign with it, what a
/// receiver trusts, and its key file when it has one.
pub(super) struct LoginKey {
    pub(super) signer: LoginSigner,
    pub(super) trusted: TrustedSigner,
    pub(super) identity_file: Option<PathBuf>,
}

/// What an `ssh -vvv` trace says about the login that authenticated.
#[derive(Debug, PartialEq, Eq)]
struct TraceLogin {
    /// The name OpenSSH reported for the key: its file, or an agent key's
    /// comment.
    name: Option<String>,
    fingerprint: String,
    certificate: bool,
}

/// Use the actual signing event and successful public-key authentication, not
/// an offered key or a server's preliminary acceptance of a public key.
fn login_from_trace(trace: &str) -> Result<TraceLogin> {
    let mut candidate = None;
    let mut signed = None;
    for line in trace.lines() {
        if let Some(identity) = line.strip_prefix("debug1: Server accepts key: ") {
            if let Some((name_and_type, _)) = identity.rsplit_once(" SHA256:") {
                if let Some((name, _kind)) = name_and_type.rsplit_once(' ') {
                    candidate = Some(name.to_owned());
                    signed = None;
                }
            }
        } else if let Some(path) = line.strip_prefix("debug1: Trying private key: ") {
            candidate = Some(path.to_owned());
            signed = None;
        } else if let Some(detail) =
            line.strip_prefix("debug3: sign_and_send_pubkey: signing using ")
        {
            let mut words = detail.split_ascii_whitespace();
            let algorithm = words.next().context("SSH signing algorithm missing")?;
            let fingerprint = words.next().context("SSH signing fingerprint missing")?;
            if !fingerprint.starts_with("SHA256:") {
                bail!("SSH did not report the login key's SHA256 fingerprint");
            }
            signed = Some(TraceLogin {
                name: candidate.clone(),
                fingerprint: fingerprint.to_owned(),
                certificate: algorithm.contains("-cert-v01@openssh.com"),
            });
        } else if let Some(rest) = line.strip_prefix("Authenticated to ") {
            if !rest.ends_with(" using \"publickey\".") {
                let method = rest
                    .rsplit_once(" using \"")
                    .and_then(|(_, method)| method.strip_suffix("\"."))
                    .unwrap_or("another method");
                bail!(
                    "restricted copying needs a login with an SSH key, and this login used {method}; set up a key login, or approve copies through account access (--auth-from @NAME)"
                );
            }
            return signed.context("SSH did not report the key that logged in");
        } else if line.contains("Authenticated with partial success")
            || line.contains("with partial success")
        {
            bail!("restricted copying needs a login with an SSH key alone, and this server asked for a second factor; a key alone would drop that factor, so approve copies through account access (--auth-from @NAME)");
        }
    }
    bail!("SSH did not report a successful key login")
}

/// Refuse a server that is not OpenSSH 7.2 or later, which `restrict` in
/// `authorized_keys` needs, as the login trace reports it.
pub(super) fn require_openssh_server(trace: &str) -> Result<()> {
    let software = trace
        .lines()
        .find_map(|line| {
            line.split_once("remote software version ")
                .map(|(_, software)| software.trim())
        })
        .context("SSH did not report the server's software version")?;
    let version = software.strip_prefix("OpenSSH_").with_context(|| {
        format!("restricted copying needs an OpenSSH server, and this server runs {software}")
    })?;
    let numbers: String = version
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect();
    let mut parts = numbers.split('.');
    let major: u32 = parts.next().unwrap_or("").parse().unwrap_or(0);
    let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    if (major, minor) < MINIMUM_OPENSSH {
        bail!(
            "restricted copying needs OpenSSH {}.{} or later on the server, which runs {software}",
            MINIMUM_OPENSSH.0,
            MINIMUM_OPENSSH.1
        );
    }
    Ok(())
}

// Login keys are user-managed input, not syq's mutable state. Read-only
// owner permissions are as private as mode 0600; retain the same descriptor,
// ownership, type and no-symlink checks when inspecting the file.
fn read_login_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .context("open SSH login key")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || !matches!(metadata.permissions().mode() & 0o7777, 0o400 | 0o600)
    {
        bail!("SSH login key must be an owner-owned mode-0400 or mode-0600 regular file");
    }
    let mut encoded = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(128 * 1024 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.is_empty() || encoded.len() > 128 * 1024 {
        bail!("SSH login key size is outside the supported range");
    }
    Ok(encoded)
}

/// A key file OpenSSH named, as its private key and a certificate file
/// beside it: `key`, `key.pub` and `key-cert.pub` all name `key`.
fn key_files(name: &str) -> Option<(PathBuf, PathBuf)> {
    let path = Path::new(name);
    if !path.is_absolute() {
        return None;
    }
    let text = path.to_str()?;
    let private = text
        .strip_suffix("-cert.pub")
        .or_else(|| text.strip_suffix(".pub"))
        .unwrap_or(text);
    Some((
        PathBuf::from(private),
        PathBuf::from(format!("{private}-cert.pub")),
    ))
}

fn read_certificate(path: &Path) -> Option<ssh_key::Certificate> {
    let text = fs::read_to_string(path).ok()?;
    ssh_key::Certificate::from_openssh(text.trim()).ok()
}

/// The certificates that may have authenticated a login: the user
/// certificates for its key, in the agent and beside its key file, that are
/// valid now. OpenSSH's trace names neither which of several certificates
/// it offered nor their IDs, and principals do not tell either, since sshd
/// can map them (`AuthorizedPrincipalsFile`, `principals=`). So syq records
/// what all of them allow together: the earliest expiry and the strictest
/// touch and PIN policy. The record can end sooner, or ask for more, than
/// the login did, never later or for less.
fn valid_certificates(
    certificates: Vec<ssh_key::Certificate>,
    now: i64,
) -> Result<Vec<ssh_key::Certificate>> {
    let now = u64::try_from(now).unwrap_or(0);
    let valid: Vec<_> = certificates
        .into_iter()
        .filter(|certificate| {
            certificate.cert_type().is_user()
                && certificate.valid_after() <= now
                && now < certificate.valid_before()
        })
        .collect();
    if valid.is_empty() {
        bail!("syq cannot find a currently valid certificate for the key that logged in; load the certificate into your SSH agent with its key (ssh-add), then retry");
    }
    Ok(valid)
}

/// Find the key that authenticated the login `trace` records, among the
/// identities of `agent` or in its file, and check that it can sign before
/// anything is installed: the probe signature catches keys added with
/// `ssh-add -h`, FIDO or encrypted keys missing from the agent, a missing
/// askpass for a PIN, and PKCS#11 keys used without an agent.
///
/// A FIDO key's touch and PIN policy combines the server's `authorized_keys`
/// options for the key, or for a certificate login the certificate's own
/// options merged with its authority's line as sshd merges them, with the
/// flags of its key handle, or, when syq cannot read the handle, the flags
/// of the probe signature.
pub(super) fn discover(
    trace: &str,
    authorized: &[u8],
    agent: Option<&Path>,
    probe: &[u8],
) -> Result<LoginKey> {
    let login = login_from_trace(trace)?;
    let matches = |key: &ssh_key::public::KeyData| {
        PublicKey::new(key.clone(), "")
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
            == login.fingerprint
    };
    let mut in_agent = None;
    let mut certificates = Vec::new();
    if let Some(socket) = agent {
        // An agent that is not running holds nothing.
        for blob in agent::identities(socket).unwrap_or_default() {
            if let Ok(key) = PublicKey::from_bytes(&blob) {
                if matches(key.key_data()) {
                    in_agent = Some(key);
                }
            } else if let Ok(certificate) = ssh_key::Certificate::from_bytes(&blob) {
                if matches(certificate.public_key()) {
                    certificates.push(certificate);
                }
            }
        }
    }
    let files = login.name.as_deref().and_then(key_files);
    let mut file_key = None;
    if let Some((private, certificate)) = &files {
        if let Some(key) = read_login_key(private)
            .ok()
            .and_then(|encoded| PrivateKey::from_openssh(&*encoded).ok())
            .filter(|key| matches(key.public_key().key_data()))
        {
            file_key = Some(key);
        }
        for path in [
            Path::new(login.name.as_deref().unwrap_or_default()),
            certificate.as_path(),
        ] {
            if let Some(found) = read_certificate(path).filter(|found| matches(found.public_key()))
            {
                if !certificates.contains(&found) {
                    certificates.push(found);
                }
            }
        }
    }
    let certificates = if login.certificate {
        if certificates.is_empty() {
            bail!("syq cannot find the certificate that logged in; load it into your SSH agent with its key (ssh-add), then retry");
        }
        valid_certificates(certificates, super::now()?)?
    } else {
        Vec::new()
    };
    let key = in_agent
        .clone()
        .or_else(|| file_key.as_ref().map(|key| key.public_key().clone()))
        .or_else(|| {
            certificates
                .first()
                .map(|certificate| PublicKey::new(certificate.public_key().clone(), ""))
        })
        .with_context(|| {
            format!(
                "syq cannot find the key that logged in ({}): it is not in your SSH agent{} and syq found no key file for it. Load it with ssh-add (ssh-add -s PROVIDER for a PKCS#11 key), then retry",
                login.fingerprint,
                agent.map_or(String::new(), |socket| format!(" ({})", socket.display()))
            )
        })?;
    let identity_file = files
        .as_ref()
        .filter(|_| file_key.as_ref().is_some_and(|key| !key.is_encrypted()) && software_key(&key))
        .map(|(private, _)| private.clone());
    let signer = match (in_agent, &file_key) {
        (Some(key), _) => LoginSigner::Agent {
            socket: agent.expect("agent identities").to_path_buf(),
            key,
        },
        (None, Some(private)) if !private.is_encrypted() && software_key(&key) => {
            LoginSigner::File(Box::new(private.clone()))
        }
        (None, _) if !software_key(&key) => bail!(
            "the FIDO login key {} works only through your SSH agent; load it with ssh-add, then retry",
            files.as_ref().map_or_else(String::new, |(path, _)| path.display().to_string())
        ),
        (None, Some(_)) => bail!(
            "the login key {} is passphrase-protected; load it into your SSH agent with ssh-add, then retry",
            files.as_ref().map_or_else(String::new, |(path, _)| path.display().to_string())
        ),
        (None, None) => bail!(
            "syq cannot find the key that logged in ({}) in your SSH agent; load it with ssh-add, then retry",
            login.fingerprint
        ),
    };
    let security_key = matches!(
        key.algorithm(),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
    );
    let signature = signer
        .sign(PROBE_NAMESPACE, probe)
        .context("check that the login key can sign before setting up restricted copying")?;
    let any_flags = TrustedSigner::new(&key, security_key.then_some(0), None)?;
    any_flags
        .verify(PROBE_NAMESPACE, probe, &signature, 0)
        .context("check the login key's signature")?;
    let security_key_flags = if security_key {
        let probe_flags = delegation::security_key_flags(&ssh_key::SshSig::from_pem(&signature)?)?;
        // An unencrypted handle states the authenticator's own policy.
        let handle_flags = file_key
            .as_ref()
            .filter(|key| !key.is_encrypted())
            .and_then(|key| {
                key.key_data()
                    .sk_ed25519()
                    .map(|key| key.flags())
                    .or_else(|| key.key_data().sk_ecdsa_p256().map(|key| key.flags()))
            });
        let has = |options: &[String], name: &str| options.iter().any(|option| option == name);
        let (no_touch, verify) = if certificates.is_empty() {
            let line = matching_authorization(authorized, &key, false)?.unwrap_or_default();
            (
                has(&line, "no-touch-required"),
                has(&line, "verify-required"),
            )
        } else {
            // sshd lets a certificate login skip the touch only when both
            // the certificate and its authority's line allow it, and asks
            // for a PIN when either does. Any certificate may have logged
            // in, so the touch is skipped only when every one allows it.
            // An authority sshd trusts some other way, such as
            // `TrustedUserCAKeys`, has no line here, so its certificates
            // always need a touch.
            let mut no_touch = true;
            let mut verify = false;
            for certificate in &certificates {
                let authority = PublicKey::new(certificate.signature_key().clone(), "");
                let line =
                    matching_authorization(authorized, &authority, true)?.unwrap_or_default();
                no_touch &= has(&line, "no-touch-required")
                    && certificate.extensions().contains_key("no-touch-required");
                verify |= has(&line, "verify-required")
                    || certificate
                        .critical_options()
                        .contains_key("verify-required");
            }
            (no_touch, verify)
        };
        let mut required =
            handle_flags.unwrap_or(probe_flags) & (SK_USER_PRESENCE | SK_USER_VERIFICATION);
        if !no_touch {
            required |= SK_USER_PRESENCE;
        }
        if verify {
            required |= SK_USER_VERIFICATION;
        }
        if probe_flags & required != required {
            bail!(
                "the FIDO login key signed without the {} its policy requires; check the key and retry",
                if required & !probe_flags & SK_USER_PRESENCE != 0 {
                    "touch"
                } else {
                    "PIN"
                }
            );
        }
        Some(required)
    } else {
        None
    };
    Ok(LoginKey {
        signer,
        trusted: TrustedSigner::new(
            &key,
            security_key_flags,
            certificates
                .iter()
                .map(|certificate| certificate.valid_before())
                .min(),
        )?,
        identity_file,
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

/// The options of the `authorized_keys` line that authorizes `public`, or
/// `None` when no line names it. With `authority`, only `cert-authority`
/// lines count, which authorize certificates `public` signed; without it,
/// they do not.
fn matching_authorization(
    authorized: &[u8],
    public: &PublicKey,
    authority: bool,
) -> Result<Option<Vec<String>>> {
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
        if options.iter().any(|option| option == "cert-authority") != authority {
            continue;
        }
        if found.is_some() {
            bail!("several authorized_keys lines name the FIDO login key; syq cannot tell which touch and PIN policy applies");
        }
        found = Some(options);
    }
    Ok(found)
}

#[cfg(test)]
pub(super) mod tests;
