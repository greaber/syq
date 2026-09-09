//! Stable receiver ownership, independent of executable and SSH login keys.
use super::*;
use ssh_key::{private::Ed25519Keypair, HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};

const NAMESPACE: &str = "syq-receiver-identity-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    public_key: String,
    signature: String,
}

pub(super) fn generate_key() -> Result<PrivateKey> {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed)?;
    let pair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    Ok(PrivateKey::new(pair.into(), "syq-receiver")?)
}

pub(super) fn load_key() -> Result<PrivateKey> {
    load_key_from(&private_directory(".syq-receiver-identity")?)
}

fn load_key_from(directory: &Path) -> Result<PrivateKey> {
    let path = directory.join("identity_ed25519");
    // Publish a complete key without overwriting a concurrent creator's key.
    // Invalid or unreadable existing state is never silently regenerated.
    if !path.try_exists()? {
        let key = generate_key()?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        temporary.write_all(key.to_openssh(LineEnding::LF)?.as_bytes())?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => fs::File::open(directory)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let encoded = crate::delegation::read_private_regular(&path, "receiver identity key", 8192)?;
    let key = PrivateKey::from_openssh(encoded).context("read receiver identity key; restore its backup or explicitly replace the server's name assignments")?;
    if key.is_encrypted() || !key.algorithm().is_ed25519() {
        bail!("receiver identity must be an unencrypted Ed25519 key");
    }
    Ok(key)
}

fn payload(name: &str, challenge: &str, secret: &str) -> Result<Vec<u8>> {
    validate_name(name)?;
    if challenge.len() != 43 {
        bail!("invalid receiver identity challenge");
    }
    // Structured fields bind the proof to a fresh challenge, the profile name,
    // and the credential of this particular return connection.
    Ok(serde_json::to_vec(&(name, challenge, secret))?)
}

pub(super) fn prove(key: &PrivateKey, name: &str, challenge: &str, secret: &str) -> Result<Proof> {
    let signature = key.sign(
        NAMESPACE,
        HashAlg::Sha256,
        &payload(name, challenge, secret)?,
    )?;
    Ok(Proof {
        public_key: key.public_key().to_openssh()?,
        signature: signature.to_pem(LineEnding::LF)?,
    })
}

fn verify(
    proof: Proof,
    name: &str,
    challenge: &str,
    secret: &str,
    owner: Option<&str>,
) -> Result<String> {
    let key = PublicKey::from_openssh(&proof.public_key)?;
    if !key.algorithm().is_ed25519() {
        bail!("receiver identity must use Ed25519");
    }
    if let Some(owner) = owner {
        if key.key_data() != PublicKey::from_openssh(owner)?.key_data() {
            bail!("destination @{name} belongs to a different receiver; stop the original receiver and run `syq persist destinations forget {name}` on this server before connecting its replacement");
        }
    }
    key.verify(
        NAMESPACE,
        &payload(name, challenge, secret)?,
        &SshSig::from_pem(&proof.signature)?,
    )
    .context("receiver identity proof does not verify")?;
    Ok(key.to_openssh()?)
}

pub(super) fn verify_receiver(
    name: &str,
    registration: &Registration,
    owner: Option<&str>,
) -> Result<String> {
    let challenge = random_token()?;
    let (_, reply) = exchange(
        registration,
        Message::Identify {
            name: name.into(),
            challenge: challenge.clone(),
        },
        Duration::from_secs(10),
    )
    .context(
        "cannot verify receiver identity; reconnect with an updated syq on the receiving machine",
    )?;
    let Reply::Identity(proof) = reply else {
        bail!("receiver did not provide an identity proof; update syq on the receiving machine and reconnect");
    };
    verify(proof, name, &challenge, &registration.secret, owner)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    version: u16,
    public_key: String,
}

pub(super) fn owner(directory: &Path, name: &str) -> Result<Option<String>> {
    validate_name(name)?;
    let path = directory.join(format!("{name}.owner"));
    let bytes =
        match crate::delegation::read_private_regular(&path, "receiver name ownership", 8192) {
            Ok(bytes) => bytes,
            Err(error)
                if error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
    let owner: Owner = serde_json::from_slice(&bytes)?;
    if owner.version != 1 {
        bail!("unsupported receiver ownership record; use the syq version that created it");
    }
    PublicKey::from_openssh(&owner.public_key)?;
    Ok(Some(owner.public_key))
}

/// Caller holds the same name lock used by live advertisements and forget.
pub(super) fn claim(directory: &Path, name: &str, key: &str) -> Result<()> {
    if let Some(previous) = owner(directory, name)? {
        if PublicKey::from_openssh(&previous)?.key_data()
            != PublicKey::from_openssh(key)?.key_data()
        {
            bail!("destination @{name} belongs to a different receiver");
        }
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(&serde_json::to_vec(&Owner {
        version: 1,
        public_key: key.into(),
    })?)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(directory.join(format!("{name}.owner")))?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

pub(super) fn forget(directory: &Path, name: &str) -> Result<()> {
    let mut removed = false;
    // Remove the advertisement first so a crash never leaves it unowned.
    for extension in ["json", "owner"] {
        match fs::remove_file(directory.join(format!("{name}.{extension}"))) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::File::open(directory)?.sync_all()?;
    }
    if !removed {
        bail!("no destination @{name} is registered");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_across_reloads_and_concurrent_creators() {
        let dir = tempfile::tempdir().unwrap();
        let keys = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        load_key_from(dir.path())
                            .unwrap()
                            .public_key()
                            .to_openssh()
                            .unwrap()
                    })
                })
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(
            keys[0],
            load_key_from(dir.path())
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap()
        );
        fs::write(dir.path().join("identity_ed25519"), b"corrupt").unwrap();
        assert!(load_key_from(dir.path()).is_err());
    }

    #[test]
    fn proof_binds_key_name_challenge_and_connection() {
        let key = generate_key().unwrap();
        let other = generate_key().unwrap().public_key().to_openssh().unwrap();
        let public = key.public_key().to_openssh().unwrap();
        let challenge = random_token().unwrap();
        let proof = || prove(&key, "laptop", &challenge, "connection-one").unwrap();
        assert!(verify(
            proof(),
            "laptop",
            &challenge,
            "connection-one",
            Some(&public)
        )
        .is_ok());
        assert!(verify(
            proof(),
            "laptop",
            &challenge,
            "connection-one",
            Some(&other)
        )
        .is_err());
        assert!(verify(
            proof(),
            "other",
            &challenge,
            "connection-one",
            Some(&public)
        )
        .is_err());
        assert!(verify(
            proof(),
            "laptop",
            &random_token().unwrap(),
            "connection-one",
            Some(&public)
        )
        .is_err());
        assert!(verify(
            proof(),
            "laptop",
            &challenge,
            "connection-two",
            Some(&public)
        )
        .is_err());
    }

    #[test]
    fn proof_works_across_builds_but_not_different_receivers() {
        let dir = tempfile::tempdir().unwrap();
        let (_broker, receiver, mut registration, _) =
            super::super::tests::broker(dir.path(), super::super::Approval::Always);
        let owner = receiver.identity_key.public_key().to_openssh().unwrap();
        registration.identity = "another-syq-version".into();
        assert!(verify_receiver("laptop", &registration, Some(&owner)).is_ok());
        let other = generate_key().unwrap().public_key().to_openssh().unwrap();
        assert!(verify_receiver("laptop", &registration, Some(&other)).is_err());
        assert!(verify_receiver("project", &registration, Some(&owner)).is_err());
    }

    #[test]
    fn released_v052_advertisement_and_ping_still_decode() {
        // Unchanged v0.5.2 wire shapes: ownership is a separate record.
        let registration: Registration = serde_json::from_str(r#"{"version":3,"identity":"old-build","socket":"/tmp/receiver.sock","secret":"old-secret","program":[47,115,121,113]}"#).unwrap();
        assert_eq!(registration.version, REGISTRATION_VERSION);
        let ping: Envelope = serde_json::from_str(
            r#"{"version":2,"identity":"old-build","secret":"old-secret","message":"Ping"}"#,
        )
        .unwrap();
        assert_eq!(ping.version, DISCOVERY_VERSION);
        assert!(matches!(ping.message, Message::Ping));
        let reply: Reply = serde_json::from_str(r#""Ready""#).unwrap();
        assert!(matches!(reply, Reply::Ready));
    }

    #[test]
    fn private_key_and_ownership_reject_unsafe_or_unknown_state() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        load_key_from(dir.path()).unwrap();
        let path = dir.path().join("identity_ed25519");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_key_from(dir.path()).is_err());
        fs::rename(&path, dir.path().join("backup")).unwrap();
        symlink(dir.path().join("backup"), &path).unwrap();
        assert!(load_key_from(dir.path()).is_err());
        let public = generate_key().unwrap().public_key().to_openssh().unwrap();
        claim(dir.path(), "laptop", &public).unwrap();
        fs::write(
            dir.path().join("laptop.owner"),
            br#"{"version":99,"public_key":"invalid"}"#,
        )
        .unwrap();
        assert!(owner(dir.path(), "laptop").is_err());
        assert!(claim(dir.path(), "laptop", &public).is_err());
    }

    #[test]
    fn ownership_survives_disconnect_until_explicit_forget() {
        let dir = tempfile::tempdir().unwrap();
        let first = generate_key().unwrap().public_key().to_openssh().unwrap();
        let second = generate_key().unwrap().public_key().to_openssh().unwrap();
        claim(dir.path(), "laptop", &first).unwrap();
        claim(dir.path(), "laptop", &first).unwrap();
        assert!(claim(dir.path(), "laptop", &second).is_err());
        assert_eq!(owner(dir.path(), "laptop").unwrap(), Some(first));
        forget(dir.path(), "laptop").unwrap();
        claim(dir.path(), "laptop", &second).unwrap();
        assert_eq!(owner(dir.path(), "laptop").unwrap(), Some(second));
    }
}
