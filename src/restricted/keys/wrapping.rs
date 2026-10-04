//! Local wrapping format v1. The login key signs a random challenge in a
//! separate SSHSIG namespace; HKDF-SHA256 derives a ChaCha20-Poly1305 key.
//! Signatures used here are secrets and must never be sent to a remote host.
use super::*;
use aws_lc_rs::{aead, hkdf};

const MAGIC: &[u8] = b"SYQ-RECEIVER-KEY-1\n";
const NAMESPACE: &str = "syq-receiver-key-wrap-v1@greaber.github";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Protector {
    pub(super) path: PathBuf,
    pub(super) public_key: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Header {
    version: u16,
    protector: Protector,
    pub(super) public_key: String,
    challenge: [u8; 32],
    nonce: [u8; 12],
}

#[derive(Serialize, Deserialize)]
pub(super) struct WrappedKey {
    pub(super) header: Header,
    ciphertext: String,
}

impl WrappedKey {
    pub(super) fn decode(encoded: &[u8]) -> Result<Option<Self>> {
        let Some(json) = encoded.strip_prefix(MAGIC) else {
            return Ok(None);
        };
        let wrapped: Self = serde_json::from_slice(json).context("parse wrapped receiver key")?;
        if wrapped.header.version != 1 {
            bail!("unsupported receiver key wrapping version");
        }
        Ok(Some(wrapped))
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let mut encoded = MAGIC.to_vec();
        serde_json::to_writer(&mut encoded, self)?;
        Ok(encoded)
    }

    pub(super) fn seal(protector: Protector, private: &PrivateKey) -> Result<Self> {
        let mut challenge = [0; 32];
        let mut nonce = [0; 12];
        getrandom::fill(&mut challenge)?;
        getrandom::fill(&mut nonce)?;
        let header = Header {
            version: 1,
            protector,
            public_key: private.public_key().to_openssh()?,
            challenge,
            nonce,
        };
        let key = header.agent_wrapping_key()?;
        let private = private.to_openssh(LineEnding::LF)?;
        let mut ciphertext = Zeroizing::new(private.as_bytes().to_vec());
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(header.nonce),
            aead::Aad::from(serde_json::to_vec(&header)?),
            &mut *ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("encrypt receiver key"))?;
        Ok(Self {
            header,
            ciphertext: base64::engine::general_purpose::STANDARD.encode(&*ciphertext),
        })
    }

    pub(super) fn unlock(&self) -> Result<PrivateKey> {
        let key = self.header.agent_wrapping_key()?;
        self.open(&key)
    }

    fn open(&self, key: &aead::LessSafeKey) -> Result<PrivateKey> {
        let mut plaintext =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(&self.ciphertext)?);
        let plaintext = key.open_in_place(
            aead::Nonce::assume_unique_for_key(self.header.nonce),
            aead::Aad::from(serde_json::to_vec(&self.header)?), &mut plaintext,
        ).map_err(|_| anyhow::anyhow!("cannot decrypt receiver key: its wrapping data or unlocking signature changed; re-enroll using an available login key"))?;
        let private = PrivateKey::from_openssh(plaintext)?;
        let public = PublicKey::from_openssh(&self.header.public_key)?;
        if private.is_encrypted() || private.public_key().key_data() != public.key_data() {
            bail!("decrypted receiver key does not match its public identity");
        }
        Ok(private)
    }
}

impl Header {
    fn agent_wrapping_key(&self) -> Result<aead::LessSafeKey> {
        let public = PublicKey::from_openssh(&self.protector.public_key)?;
        if !matches!(
            public.algorithm(),
            Algorithm::Ed25519 | Algorithm::Rsa { .. }
        ) {
            bail!("receiver key wrapping requires a software Ed25519 or RSA login key");
        }
        if !self.protector.path.is_absolute() {
            bail!("receiver unlocking key path must be absolute");
        }
        let socket = ensure_agent_key(&self.protector.path, &public, None)?;
        let temporary = crate::private_broker::private_temp_dir("syq-unlock-")?;
        atomic_write(
            temporary.path(),
            "key.pub",
            self.protector.public_key.as_bytes(),
            0o600,
        )?;
        let encoded = agent_signature(
            &public,
            &temporary.path().join("key.pub"),
            &socket,
            NAMESPACE,
            &self.challenge,
        )?;
        let signature = ssh_key::SshSig::from_pem(&encoded)?;
        let mut bytes = Zeroizing::new(signature.signature_bytes().to_vec());
        match signature.algorithm() {
            Algorithm::Ed25519 => {}
            Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha512),
            } => {
                // Some agents omit leading zero bytes in an RSA signature.
                // Normalize to the modulus length before deriving the key.
                let length = public
                    .key_data()
                    .rsa()
                    .context("RSA protector")?
                    .n
                    .as_positive_bytes()
                    .context("RSA modulus")?
                    .len();
                if bytes.len() > length {
                    bail!("invalid RSA unlocking signature length");
                }
                if bytes.len() < length {
                    let mut padded = Zeroizing::new(vec![0; length - bytes.len()]);
                    padded.extend_from_slice(&bytes);
                    bytes = padded;
                }
            }
            _ => bail!("receiver unlocking requires Ed25519 or RSA-SHA512 signatures"),
        }
        derive_key(&self.challenge, &bytes)
    }
}

fn derive_key(challenge: &[u8; 32], signature: &[u8]) -> Result<aead::LessSafeKey> {
    let secret = hkdf::Salt::new(hkdf::HKDF_SHA256, challenge).extract(signature);
    let mut bytes = Zeroizing::new([0; 32]);
    secret
        .expand(&[NAMESPACE.as_bytes()], hkdf::HKDF_SHA256)
        .map_err(|_| anyhow::anyhow!("derive receiver wrapping key"))?
        .fill(&mut *bytes)
        .map_err(|_| anyhow::anyhow!("derive receiver wrapping key"))?;
    let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &*bytes)
        .map_err(|_| anyhow::anyhow!("initialize receiver wrapping key"))?;
    Ok(aead::LessSafeKey::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn agent_unlocks_wrapped_receiver_without_another_passphrase() {
        const CHILD: &str = "SYQ_TEST_WRAPPED_KEY_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            for algorithm in ["ed25519", "rsa", "ecdsa"] {
                let path = root.join(algorithm);
                let mut generate = Command::new("ssh-keygen");
                generate
                    .args(["-q", "-t", algorithm, "-N", "fixture-unlock", "-f"])
                    .arg(&path);
                if algorithm == "rsa" {
                    generate.args(["-b", "2048"]);
                }
                assert!(generate.status_guarded().unwrap().success());
                let private = PrivateKey::from_openssh(fs::read(&path).unwrap()).unwrap();
                let template = super::super::key_template(
                    &super::super::tests::trace(&path, private.public_key()),
                    b"",
                );
                if algorithm == "ecdsa" {
                    assert!(template
                        .unwrap_err()
                        .to_string()
                        .contains("ECDSA is unsupported"));
                    continue;
                }
                let template = template.unwrap();
                if algorithm == "rsa" {
                    assert_eq!(template.bits, Some(3072));
                }
                let directory = root.join(format!("receiver-{algorithm}"));
                ensure_directory(&directory, 0o700).unwrap();
                let public =
                    generate_matching_key(&directory, EnrollmentId::random(), &template).unwrap();
                assert_ne!(public.key_data(), private.public_key().key_data());
                let encoded = read_enrollment_key(&directory).unwrap();
                assert!(encoded.starts_with(MAGIC));
                assert!(PrivateKey::from_openssh(&encoded).is_err());
                assert_eq!(load_enrollment_public_key(&directory).unwrap(), public);
                let wrapped = WrappedKey::decode(&encoded).unwrap().unwrap();
                let key = wrapped.header.agent_wrapping_key().unwrap();
                let mut tampered: WrappedKey =
                    serde_json::from_slice(&serde_json::to_vec(&wrapped).unwrap()).unwrap();
                tampered.header.protector.path = root.join("different-key");
                assert!(tampered.open(&key).is_err());
                tampered.header.protector.path = path.clone();
                tampered.ciphertext.replace_range(
                    ..1,
                    if tampered.ciphertext.starts_with('A') {
                        "B"
                    } else {
                        "A"
                    },
                );
                assert!(tampered.open(&key).is_err());
                // Only the original login identity lives in the ambient agent.
                let socket = PathBuf::from(std::env::var_os("SSH_AUTH_SOCK").unwrap());
                assert!(agent_has_key(&socket, private.public_key()).unwrap());
                assert!(!agent_has_key(&socket, &public).unwrap());
                // An unlocked agent is sufficient even without the private file.
                let moved = path.with_extension("hidden");
                fs::rename(&path, &moved).unwrap();
                let signer = load_signing_key(&directory).unwrap();
                let signature = signer.sign_grant(b"grant fixture").unwrap();
                public
                    .verify(
                        delegation::SSHSIG_NAMESPACE,
                        b"grant fixture",
                        &ssh_key::SshSig::from_pem(signature).unwrap(),
                    )
                    .unwrap();
                assert!(Command::new("ssh-add")
                    .arg("-d")
                    .arg(path.with_extension("pub"))
                    .status_guarded()
                    .unwrap()
                    .success());
                assert!(load_signing_key(&directory).is_err());
                fs::rename(&moved, &path).unwrap();
                assert!(load_signing_key(&directory).is_ok());
            }
            return;
        }
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.join("agent.sock");
        let mut command = Command::new("ssh-agent");
        command
            .args(["-D", "-a"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut agent = crate::process_group::ProcessGroup::spawn(&mut command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(
                Instant::now() < deadline && agent.poll().unwrap().is_none(),
                "test SSH agent failed to start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let askpass = root.join("askpass");
        fs::write(&askpass, b"#!/bin/sh\nprintf '%s\\n' fixture-unlock\n").unwrap();
        fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700)).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "restricted::keys::wrapping::tests::agent_unlocks_wrapped_receiver_without_another_passphrase", "--nocapture"])
            .env(CHILD, root).env("SSH_AUTH_SOCK", socket)
            .env("SSH_ASKPASS", askpass).env("SSH_ASKPASS_REQUIRE", "force").env("DISPLAY", "fixture")
            .stdin(Stdio::null()).status_guarded().unwrap();
        assert!(status.success());
        agent.close().unwrap();
    }
}
