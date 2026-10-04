//! Local requests only: unlocking signatures must never enter the forwarded broker.
use super::*;
use signature::Verifier as _;
use ssh_agent_lib::proto::{Request, Response, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode as _, Encode as _};
use std::os::unix::net::UnixStream;

fn request(socket: &Path, request: Request) -> Result<Zeroizing<Vec<u8>>> {
    let mut stream = UnixStream::connect(socket).context("connect to the selected SSH agent")?;
    let mut frame = Vec::new();
    request.encode(&mut frame)?;
    crate::agent_broker::write_frame(&mut stream, &frame).context("write SSH agent request")?;
    let response = crate::agent_broker::read_frame(&mut stream)
        .context("read SSH agent response")?
        .context("SSH agent closed without a response")?;
    Ok(Zeroizing::new(response))
}

pub(super) fn has_key(socket: &Path, key: &PublicKey) -> Result<bool> {
    let frame = request(socket, Request::RequestIdentities)?;
    let mut input = frame.as_slice();
    match u8::decode(&mut input)? {
        5 if input.is_empty() => return Ok(false),
        12 => {}
        _ => bail!("SSH agent returned an unexpected identities response"),
    }
    let expected = key.to_bytes()?;
    let count = u32::decode(&mut input)?;
    let mut found = false;
    for _ in 0..count {
        // Match the exact public blob without parsing unrelated identities or
        // comments. Agents may contain certificates or algorithms we don't use.
        let public = Vec::<u8>::decode(&mut input)?;
        let _comment = Vec::<u8>::decode(&mut input)?;
        found |= public == expected;
    }
    if !input.is_empty() {
        bail!("trailing bytes in SSH agent identities response");
    }
    Ok(found)
}

pub(super) fn wrapping_signature(
    socket: &Path,
    public: &PublicKey,
    namespace: &str,
    challenge: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let expected_algorithm = match public.algorithm() {
        Algorithm::Ed25519 => Algorithm::Ed25519,
        Algorithm::Rsa { .. } => Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha512),
        },
        _ => bail!("receiver key wrapping requires a software Ed25519 or RSA login key"),
    };
    // Match ssh-keygen -Y sign's SHA-512 default and RSA-SHA512 selection
    // exactly: these bytes protect existing wrapping-format-v1 enrollments.
    let data = ssh_key::SshSig::signed_data(namespace, ssh_key::HashAlg::Sha512, challenge)?;
    let frame = request(
        socket,
        Request::SignRequest(SignRequest {
            credential: public.key_data().clone().into(),
            data: data.clone(),
            flags: if public.key_data().is_rsa() {
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
        bail!("SSH agent could not sign with the receiver unlocking identity");
    };
    if signature.algorithm() != expected_algorithm {
        bail!("SSH agent returned the wrong receiver unlocking signature algorithm");
    }
    if let Some(rsa) = public.key_data().rsa() {
        let length = rsa.n.as_positive_bytes().context("RSA modulus")?.len();
        let bytes = signature.as_bytes();
        if bytes.len() > length {
            bail!("invalid RSA unlocking signature length");
        }
        if bytes.len() < length {
            // Agents may omit leading zeros. Restore them before verification,
            // and return the same modulus-width bytes used by wrapping v1.
            let mut padded = Zeroizing::new(vec![0; length]);
            padded[length - bytes.len()..].copy_from_slice(bytes);
            signature = ssh_key::Signature::new(signature.algorithm(), padded.to_vec())?;
        }
    }
    public
        .key_data()
        .verify(&data, &signature)
        .context("verify SSH agent unlocking signature")?;
    Ok(Zeroizing::new(signature.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_agent_lib::ssh_key::private::Ed25519Keypair;
    use std::os::unix::net::UnixListener;

    fn with_response<T>(frame: &[u8], check: impl FnOnce(&Path) -> T) -> T {
        let temporary = crate::test_support::tempdir().unwrap();
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
    fn unlocking_normalizes_short_rsa_signatures_before_verifying() {
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
        let check = |bytes: &[u8], algorithm: Algorithm, payload: &[u8]| {
            let signature = ssh_key::Signature::new(algorithm, bytes.to_vec()).unwrap();
            let mut response = Vec::new();
            Response::SignResponse(signature)
                .encode(&mut response)
                .unwrap();
            with_response(&response, |socket| {
                wrapping_signature(socket, &public, "fixture", payload)
            })
        };
        assert_eq!(&*check(&full, algorithm.clone(), payload).unwrap(), &full);
        assert_eq!(
            &*check(&full[1..], algorithm.clone(), payload).unwrap(),
            &full
        );

        // Padding must not accept lost nonzero bytes, corrupt signatures,
        // wrong payloads or algorithms, or signatures larger than the modulus.
        assert!(check(&full[2..], algorithm.clone(), payload).is_err());
        assert!(check(&[], algorithm.clone(), payload).is_err());
        let mut corrupt = full.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(check(&corrupt[1..], algorithm.clone(), payload).is_err());
        assert!(check(&full[1..], algorithm.clone(), b"different payload").is_err());
        assert!(check(
            &full[1..],
            Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha256)
            },
            payload
        )
        .is_err());
        let oversized = [vec![0], full].concat();
        assert!(check(&oversized, algorithm, payload).is_err());
    }

    #[test]
    fn unlocking_rejects_invalid_signatures_and_unexpected_responses() {
        let key: PrivateKey = Ed25519Keypair::from_seed(&[49; 32]).into();
        let signature = key
            .sign("fixture", ssh_key::HashAlg::Sha512, b"other payload")
            .unwrap();
        let mut response = Vec::new();
        Response::SignResponse(signature.signature().clone())
            .encode(&mut response)
            .unwrap();
        let check =
            |socket: &Path| wrapping_signature(socket, key.public_key(), "fixture", b"challenge");
        let error = with_response(&response, check).unwrap_err();
        assert!(error
            .to_string()
            .contains("verify SSH agent unlocking signature"));
        for malformed in [&[5][..], &[6], &[14, 0, 0, 0, 0]] {
            assert!(with_response(malformed, check).is_err());
        }
        response.push(0);
        assert!(with_response(&response, check)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes"));
    }
}
