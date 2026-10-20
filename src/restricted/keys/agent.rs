//! The SSH agent protocol for the user's login key: listing identities and
//! signing. Requests go only to the agent the user's configuration selects.
use super::*;
use signature::Verifier as _;
use ssh_agent_lib::proto::{PublicCredential, Request, Response, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode as _, Encode as _};
use std::os::unix::net::UnixStream;

fn request(socket: &Path, request: Request) -> Result<Zeroizing<Vec<u8>>> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connect to the SSH agent at {}", socket.display()))?;
    let mut frame = Vec::new();
    request.encode(&mut frame)?;
    crate::agent_broker::write_frame(&mut stream, &frame).context("write SSH agent request")?;
    let response = crate::agent_broker::read_frame(&mut stream)
        .context("read SSH agent response")?
        .context("SSH agent closed without a response")?;
    Ok(Zeroizing::new(response))
}

/// The public blobs of the agent's identities: plain keys and certificates.
/// They are matched exactly, without parsing identities syq does not use.
pub(super) fn identities(socket: &Path) -> Result<Vec<Vec<u8>>> {
    let frame = request(socket, Request::RequestIdentities)?;
    let mut input = frame.as_slice();
    match u8::decode(&mut input)? {
        5 if input.is_empty() => return Ok(Vec::new()),
        12 => {}
        _ => bail!("SSH agent returned an unexpected identities response"),
    }
    let count = u32::decode(&mut input)?;
    let mut blobs = Vec::new();
    for _ in 0..count {
        let public = Vec::<u8>::decode(&mut input)?;
        let _comment = Vec::<u8>::decode(&mut input)?;
        blobs.push(public);
    }
    if !input.is_empty() {
        bail!("trailing bytes in SSH agent identities response");
    }
    Ok(blobs)
}

pub(super) fn has_key(socket: &Path, key: &PublicKey) -> Result<bool> {
    let expected = key.to_bytes()?;
    Ok(identities(socket)?.contains(&expected))
}

/// The signature algorithm a key's agent signature must use. RSA keys sign
/// with SHA-512, as `ssh-keygen -Y sign` does.
fn expected_algorithm(key: &PublicKey) -> Result<Algorithm> {
    Ok(match key.algorithm() {
        Algorithm::Rsa { .. } => Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha512),
        },
        algorithm @ (Algorithm::Ed25519
        | Algorithm::Ecdsa { .. }
        | Algorithm::SkEd25519
        | Algorithm::SkEcdsaSha2NistP256) => algorithm,
        algorithm => bail!("syq cannot sign with a {algorithm} login key"),
    })
}

/// Ask the agent to sign `data` with `key`, then check the signature
/// before using it.
pub(super) fn sign(socket: &Path, key: &PublicKey, data: &[u8]) -> Result<ssh_key::Signature> {
    let expected = expected_algorithm(key)?;
    let frame = request(
        socket,
        Request::SignRequest(SignRequest {
            credential: PublicCredential::Key(key.key_data().clone()),
            data: data.to_vec(),
            flags: if key.key_data().is_rsa() {
                ssh_agent_lib::proto::signature::RSA_SHA2_512
            } else {
                0
            },
        }),
    )?;
    let mut input = frame.as_slice();
    let response = Response::decode(&mut input).context("decode SSH agent signing response")?;
    if !input.is_empty() {
        bail!("trailing bytes in SSH agent signing response");
    }
    let Response::SignResponse(mut signature) = response else {
        bail!(AgentRefused);
    };
    if signature.algorithm() != expected {
        bail!(
            "the SSH agent signed with {} instead of {expected}",
            signature.algorithm()
        );
    }
    if let Some(rsa) = key.key_data().rsa() {
        let length = rsa.n.as_positive_bytes().context("RSA modulus")?.len();
        let bytes = signature.as_bytes();
        if bytes.len() > length {
            bail!("invalid RSA signature length");
        }
        if bytes.len() < length {
            // Agents may omit leading zeros. Restore them before verifying.
            let mut padded = vec![0; length];
            padded[length - bytes.len()..].copy_from_slice(bytes);
            signature = ssh_key::Signature::new(signature.algorithm(), padded)?;
        }
    }
    key.key_data()
        .verify(data, &signature)
        .context("the SSH agent's signature does not verify")?;
    Ok(signature)
}

/// The agent answered a signing request with a failure.
#[derive(Debug)]
pub(super) struct AgentRefused;

impl fmt::Display for AgentRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the SSH agent refused to sign with the login key")
    }
}

impl std::error::Error for AgentRefused {}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
    use std::os::unix::net::UnixListener;

    fn with_response<T>(frame: &[u8], check: impl FnOnce(&Path) -> T) -> T {
        let temporary = crate::test_support::short_tempdir().unwrap();
        let socket = temporary.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let frame = frame.to_vec();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            crate::agent_broker::read_frame(&mut stream)
                .unwrap()
                .unwrap();
            crate::agent_broker::write_frame(&mut stream, &frame).unwrap();
        });
        let result = check(&socket);
        worker.join().unwrap();
        result
    }

    #[test]
    fn identity_lookup_matches_exact_public_blobs_without_parsing_other_keys() {
        let key: PrivateKey = Ed25519Keypair::from_seed(&[47; 32]).into();
        let public = key.public_key();
        let mut response = vec![12];
        2u32.encode(&mut response).unwrap();
        b"unknown-key-encoding"
            .as_slice()
            .encode(&mut response)
            .unwrap();
        b"unknown comment".as_slice().encode(&mut response).unwrap();
        public.to_bytes().unwrap().encode(&mut response).unwrap();
        [0xffu8].as_slice().encode(&mut response).unwrap();
        assert!(with_response(&response, |socket| has_key(socket, public)).unwrap());
        let other: PrivateKey = Ed25519Keypair::from_seed(&[48; 32]).into();
        assert!(!with_response(&response, |socket| has_key(socket, other.public_key())).unwrap());
        assert!(!with_response(&[5], |socket| has_key(socket, public)).unwrap());
        for malformed in [&[12, 0, 0, 0, 1][..], &[5, 0], &[6]] {
            assert!(with_response(malformed, |socket| has_key(socket, public)).is_err());
        }
    }

    #[test]
    fn agent_signatures_restore_short_rsa_signatures_before_verifying() {
        // Public test vector from a disposable OpenSSH RSA key. Its RSA-SHA512
        // signature starts with zero; agents may omit that byte on the wire.
        let public = PublicKey::from_openssh(concat!(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCXeiUO2+nW1JAi7fM3OoiYOojgPwX1D1lHsIt3",
            "82/7h/wYWBWjjiHzfaeq+5k3eaakN8lYpeEGujGoY/yJtuQoMyBXZbFlPgNTT4Ip7RxX7Hpr4aU9",
            "RRxqtyzxiPhSVQKYowLmqio6XmLhIcLmWwH1qxTaQ7QtAwVdXFYZ7YTwCQ00Idzas2PXbZkoV3bL",
            "n2DFMDsME9Ja2DPJMjFmrB+tdM8dfCr9SYOZHDgAIQkNR6as+S3+9lcoj4U/y1AFgq9klefu/vq+",
            "XLL3A/MrbHPqjRPubSMQY/fbDa4qD0TvFc8SgZL88LcEoS2xByBGQme/lpO3cAwsHIr57mQnzcPr",
        ))
        .unwrap();
        let payload = b"rsa-leading-zero-fixture-135";
        let data =
            ssh_key::SshSig::signed_data("fixture", ssh_key::HashAlg::Sha512, payload).unwrap();
        let full = base64::engine::general_purpose::STANDARD
            .decode(concat!(
                "AIErXlq+dSgAmHEVT7r0YZZMgUbGNtwap5hct6Rak0Y6+z02iMg7eSzuRIcW3I1/CrH88xMSFp5q",
                "VoXNO4qF3haPuSq6Ma+S58o5uKRgZECd75lsU0/C4A11YeloAsV547mK59WPnQ1brVRRDzFI7bhc",
                "IO1GeNW6N9UGLgHC3dvuilP6doeOiQJ4M0YGDkA1dTB5Gq6YdvI+KO5vWQv11Kq/5I0CdjdNz3+R",
                "Eckco4zu65ANYh+rr7l4Vjwo6hemg8kAWwC1cEETjFsDTKd1V0mxMMEqHOw4bTTdLM34GKnw8JkS",
                "93aybuVVqr6sYJJGT3Q4qqKwuIZNFdKPkq61dg==",
            ))
            .unwrap();
        assert_eq!(full[0], 0);
        assert_ne!(full[1], 0);
        let algorithm = Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha512),
        };
        let check = |bytes: &[u8], algorithm: Algorithm, data: &[u8]| {
            let signature = ssh_key::Signature::new(algorithm, bytes.to_vec()).unwrap();
            let mut response = Vec::new();
            Response::SignResponse(signature)
                .encode(&mut response)
                .unwrap();
            with_response(&response, |socket| sign(socket, &public, data))
        };
        assert_eq!(
            check(&full, algorithm.clone(), &data).unwrap().as_bytes(),
            &full
        );
        assert_eq!(
            check(&full[1..], algorithm.clone(), &data)
                .unwrap()
                .as_bytes(),
            &full
        );

        // Padding must not accept lost nonzero bytes, corrupt signatures,
        // wrong payloads or algorithms, or signatures larger than the modulus.
        assert!(check(&full[2..], algorithm.clone(), &data).is_err());
        assert!(check(&[], algorithm.clone(), &data).is_err());
        let mut corrupt = full.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(check(&corrupt[1..], algorithm.clone(), &data).is_err());
        assert!(check(&full[1..], algorithm.clone(), b"different payload").is_err());
        assert!(check(
            &full[1..],
            Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha256)
            },
            &data
        )
        .is_err());
        let oversized = [vec![0], full].concat();
        assert!(check(&oversized, algorithm, &data).is_err());
    }

    #[test]
    fn agent_signatures_reject_invalid_signatures_and_unexpected_responses() {
        let key: PrivateKey = Ed25519Keypair::from_seed(&[49; 32]).into();
        let signature = key
            .sign("fixture", ssh_key::HashAlg::Sha512, b"other payload")
            .unwrap();
        let mut response = Vec::new();
        Response::SignResponse(signature.signature().clone())
            .encode(&mut response)
            .unwrap();
        let check = |socket: &Path| sign(socket, key.public_key(), b"challenge");
        let error = with_response(&response, check).unwrap_err();
        assert!(error.to_string().contains("does not verify"), "{error:#}");
        let refused = with_response(&[5], check).unwrap_err();
        assert!(refused.downcast_ref::<AgentRefused>().is_some());
        for malformed in [&[6][..], &[14, 0, 0, 0, 0]] {
            assert!(with_response(malformed, check).is_err());
        }
        response.push(0);
        assert!(with_response(&response, check)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes"));
    }
}
