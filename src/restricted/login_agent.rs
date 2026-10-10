//! An isolated agent containing only the receiver's SSH admission key.
//! It has no access to a grant signer or to the user's ordinary agent.
use crate::agent_broker::{parse_sign_request, read_frame, sign_private_key, write_frame};
use crate::private_broker::{PrivateBroker, PrivateBrokerConfig, TrackedStream};
use anyhow::{Context, Result};
use ssh_agent_lib::proto::{Identity, PublicCredential, Response};
use ssh_agent_lib::ssh_encoding::Encode;
use ssh_key::PrivateKey;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct ReceiverAgent(PrivateBroker);

impl ReceiverAgent {
    pub(crate) fn start(key: PrivateKey, max_connections: usize) -> Result<Self> {
        anyhow::ensure!(
            !key.is_encrypted() && key.algorithm() == ssh_key::Algorithm::Ed25519,
            "receiver SSH agent requires an unlocked Ed25519 key"
        );
        let key = Arc::new(key);
        let broker = PrivateBroker::start(
            PrivateBrokerConfig {
                directory_prefix: "syq-agent-",
                socket_name: "agent.sock",
                listener_thread: "syq-receiver-agent",
                client_thread: "syq-receiver-sign",
                inline_on_thread_failure: false,
                max_connections,
                io_timeout: Duration::from_secs(120),
            },
            move |stream, _| {
                let _ = serve(stream, &key);
            },
        )?;
        Ok(Self(broker))
    }

    pub(crate) fn socket_path(&self) -> &Path {
        self.0.socket_path()
    }
}

fn serve(mut stream: TrackedStream, key: &PrivateKey) -> Result<()> {
    let credential = PublicCredential::Key(key.public_key().key_data().clone());
    while let Some(frame) = read_frame(&mut stream)? {
        let response = match frame.first() {
            Some(11) if frame.len() == 1 => Response::IdentitiesAnswer(vec![Identity {
                credential: credential.clone(),
                comment: String::new(),
            }]),
            Some(13) => match parse_sign_request(&frame) {
                Ok(request) if request.credential == credential && request.flags == 0 => {
                    Response::SignResponse(sign_private_key(key, &request.data, 0)?)
                }
                _ => Response::Failure,
            },
            // New clients may try session binding. Like older agents, decline
            // the extension and keep serving ordinary agent requests.
            Some(27) => Response::ExtensionFailure,
            _ => Response::Failure,
        };
        let mut encoded = Vec::new();
        response
            .encode(&mut encoded)
            .context("encode receiver agent response")?;
        write_frame(&mut stream, &encoded)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_agent_lib::proto::{Request, SignRequest};
    use ssh_agent_lib::ssh_encoding::Decode;
    use std::os::unix::net::UnixStream;

    fn exchange(stream: &mut UnixStream, request: Request) -> Response {
        let mut frame = Vec::new();
        request.encode(&mut frame).unwrap();
        write_frame(stream, &frame).unwrap();
        Response::decode(&mut read_frame(stream).unwrap().unwrap().as_slice()).unwrap()
    }

    #[test]
    fn unbound_agent_exposes_only_admission_key_and_cannot_authorize_grants() {
        let signing =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let login = PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let public = login.public_key().clone();
        let agent = ReceiverAgent::start(login, 2).unwrap();
        let mut stream = UnixStream::connect(agent.socket_path()).unwrap();
        let Response::IdentitiesAnswer(identities) =
            exchange(&mut stream, Request::RequestIdentities)
        else {
            panic!("missing identities")
        };
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].credential.key_data(), public.key_data());
        let namespace = crate::delegation::SSHSIG_NAMESPACE;
        let payload = b"source-chosen grant";
        let data =
            ssh_key::SshSig::signed_data(namespace, ssh_key::HashAlg::Sha256, payload).unwrap();
        // Even arbitrary signatures from this agent have no grant authority.
        let Response::SignResponse(signature) = exchange(
            &mut stream,
            Request::SignRequest(SignRequest {
                credential: public.key_data().clone().into(),
                data: data.clone(),
                flags: 0,
            }),
        ) else {
            panic!("ordinary signing failed")
        };
        let forged = ssh_key::SshSig::new(
            public.key_data().clone(),
            namespace,
            ssh_key::HashAlg::Sha256,
            signature,
        )
        .unwrap();
        public.verify(namespace, payload, &forged).unwrap();
        assert!(signing
            .public_key()
            .verify(namespace, payload, &forged)
            .is_err());
        assert!(matches!(
            exchange(
                &mut stream,
                Request::SignRequest(SignRequest {
                    credential: signing.public_key().key_data().clone().into(),
                    data,
                    flags: 0,
                })
            ),
            Response::Failure
        ));
        // Unsupported operations never turn this into a mutable general agent.
        write_frame(&mut stream, &[19]).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().unwrap(), [5]);
        write_frame(&mut stream, &[27]).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().unwrap(), [28]);
        assert!(matches!(
            exchange(&mut stream, Request::RequestIdentities),
            Response::IdentitiesAnswer(_)
        ));
    }
}
