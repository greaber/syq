//! Storage signing sessions end before data transfer. Closing receiving after
//! preparation cannot revoke already issued provider bearer capabilities.
use super::*;
use crate::s3::authorization::{Configuration, Request, Signer, Unsigned};

#[derive(Serialize, Deserialize)]
enum SigningRequest {
    Sign(Vec<Unsigned>),
    Finish,
}
#[derive(Serialize, Deserialize)]
enum SigningReply {
    Configuration(Configuration),
    Signed(Vec<String>),
    Finished,
    Error(String),
}

pub(crate) fn connect(name: &str, request: Request) -> Result<(UnixStream, Configuration)> {
    validate_name(name)?;
    request.validate()?;
    let registration = load_registration(name)?;
    connect_registered(name, &registration, request)
}
fn connect_registered(
    name: &str,
    registration: &Registration,
    request: Request,
) -> Result<(UnixStream, Configuration)> {
    // Unlike existing copies, this new operation cannot be handed to a released
    // helper that predates it. Reject before interpreting any new request bytes.
    if registration.identity != crate::identity::build() {
        bail!("storage authorization requires matching syq builds; reconnect from the authorizing machine with this build");
    }
    super::notices::waiting(&format!("@{name}"), "this storage access");
    let (mut stream, reply) = exchange(
        registration,
        Message::Storage {
            command: crate::approval_command::current()?,
            cwd: crate::approval_command::current_directory(),
            request: Box::new(request),
        },
        REQUEST_TIMEOUT + Duration::from_secs(10),
        Some(Duration::from_secs(60)),
    )?;
    anyhow::ensure!(
        matches!(reply, Reply::Ready),
        "unexpected storage approval response"
    );
    let configuration = match read_message(&mut stream)? {
        SigningReply::Configuration(configuration) => configuration,
        SigningReply::Error(error) => bail!("authorizing machine: {error}"),
        _ => bail!("invalid storage authorization configuration"),
    };
    Ok((stream, configuration))
}
pub(crate) fn sign(stream: &mut UnixStream, requests: &[Unsigned]) -> Result<Vec<String>> {
    // Keep the bounded wire messages, but send them continuously while reading
    // replies. Waiting after each message makes preparation cost one network
    // round trip per 128 requests. Writing all messages before reading instead
    // can deadlock when both socket buffers fill.
    let ranges = batches(requests, |batch| {
        serde_json::to_vec(&SigningRequest::Sign(batch.to_vec()))
    })?;
    let mut writer = stream.try_clone()?;
    std::thread::scope(|scope| {
        let sending = scope.spawn(move || {
            let result = (|| -> Result<()> {
                for range in ranges {
                    write_message(&mut writer, &SigningRequest::Sign(requests[range].to_vec()))?;
                }
                Ok(())
            })();
            if result.is_err() {
                let _ = writer.shutdown(std::net::Shutdown::Both);
            }
            result
        });
        let received = (|| -> Result<Vec<String>> {
            let mut result = Vec::with_capacity(requests.len());
            while result.len() < requests.len() {
                match read_message(stream).context(
                    "authorizing machine disconnected during preparation; reconnect and rerun the copy",
                )? {
                    SigningReply::Signed(urls) => {
                        anyhow::ensure!(
                            !urls.is_empty() && result.len() + urls.len() <= requests.len(),
                            "invalid storage signing response length"
                        );
                        result.extend(urls);
                    }
                    SigningReply::Error(error) => bail!("authorizing machine: {error}"),
                    _ => bail!("invalid storage signing response"),
                }
            }
            Ok(result)
        })();
        if received.is_err() {
            // An early refusal must also release a sender blocked on later
            // requests. This failed signing session cannot be reused.
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let sent = sending
            .join()
            .map_err(|_| anyhow::anyhow!("storage signing sender failed"));
        let urls = received?;
        sent??;
        Ok(urls)
    })
}

fn batches<T>(
    values: &[T],
    encode: impl Fn(&[T]) -> serde_json::Result<Vec<u8>>,
) -> Result<Vec<std::ops::Range<usize>>> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < values.len() {
        let mut end = (start + 128).min(values.len());
        while encode(&values[start..end])?.len() > MAX_MESSAGE {
            anyhow::ensure!(
                end - start > 1,
                "storage request exceeds the signing message limit"
            );
            end = start + (end - start) / 2;
        }
        ranges.push(start..end);
        start = end;
    }
    Ok(ranges)
}
pub(crate) fn finish(stream: &mut UnixStream) -> Result<()> {
    write_message(stream, &SigningRequest::Finish)?;
    anyhow::ensure!(
        matches!(read_message(stream)?, SigningReply::Finished),
        "storage authorization did not finish"
    );
    Ok(())
}

impl Receiver {
    pub(super) fn storage(
        &self,
        command: Vec<Vec<u8>>,
        cwd: String,
        request: Request,
        mut stream: TrackedStream,
    ) -> Result<()> {
        request.validate()?;
        crate::approval_command::check_storage(&command, &request, &self.name)?;
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another request is awaiting approval; retry after it is decided")
        })?;
        let (generation, _channel) = {
            let _sessions = self.sessions.lock().unwrap();
            (
                self.generation.load(Ordering::Acquire),
                self.active_streams.track(stream.try_clone()?)?,
            )
        };
        let socket = stream.try_clone()?;
        let receiving_stopped = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
        };
        let cancelled = || receiving_stopped() || requester_closed(&socket);
        self.approvals.request_storage(
            &self.requester,
            &command,
            &cwd,
            &request,
            self.notifications,
            cancelled,
        )?;
        drop(request_lock);
        anyhow::ensure!(
            !cancelled(),
            "storage authorization cancelled before preparation"
        );
        // A hashing/preparation phase can take longer than a network request.
        // The owned receiver registry closes this stream on cancellation.
        socket.set_read_timeout(None)?;
        write_message(&mut stream, &Reply::Ready)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let signer = runtime.block_on(Signer::new(request))?;
        write_message(
            &mut stream,
            &SigningReply::Configuration(signer.configuration.clone()),
        )?;
        serve_signing(&mut stream, &signer, receiving_stopped)
    }
}

/// Signs each batch the approved requester sends until it finishes. One
/// refused request ends the session without signing the rest of its batch.
pub(crate) fn serve_signing(
    stream: &mut (impl Read + Write),
    signer: &Signer,
    receiving_stopped: impl Fn() -> bool,
) -> Result<()> {
    loop {
        // Once approved, queued bytes are valid pipelined requests. The
        // approval-phase probe treats those bytes as cancellation; rely on
        // read_message for peer EOF and the registry for receiver shutdown.
        anyhow::ensure!(
            !receiving_stopped(),
            "storage authorization cancelled during preparation"
        );
        match read_message(stream)? {
            SigningRequest::Sign(requests) => match (|| -> Result<Vec<String>> {
                anyhow::ensure!(requests.len() <= 128, "oversized storage signing batch");
                requests
                    .iter()
                    .map(|request| signer.sign(request))
                    .collect()
            })() {
                Ok(urls) => {
                    for range in batches(&urls, |batch| {
                        serde_json::to_vec(&SigningReply::Signed(batch.to_vec()))
                    })? {
                        write_message(stream, &SigningReply::Signed(urls[range].to_vec()))?;
                    }
                }
                Err(error) => {
                    write_message(stream, &SigningReply::Error(error.to_string()))?;
                    return Ok(());
                }
            },
            SigningRequest::Finish => {
                write_message(stream, &SigningReply::Finished)?;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_batches_bound_both_descriptions_and_bearer_urls() {
        let urls = vec!["x".repeat(9000); 129];
        let ranges = batches(&urls, |values| {
            serde_json::to_vec(&SigningReply::Signed(values.to_vec()))
        })
        .unwrap();
        assert!(ranges.len() > 4);
        assert_eq!(
            ranges.iter().map(|range| range.len()).sum::<usize>(),
            urls.len()
        );
        let mut end = 0;
        for range in ranges {
            assert_eq!(range.start, end);
            end = range.end;
            assert!(
                serde_json::to_vec(&SigningReply::Signed(urls[range].to_vec()))
                    .unwrap()
                    .len()
                    <= MAX_MESSAGE
            );
        }
        assert!(batches(&["x".repeat(MAX_MESSAGE)], serde_json::to_vec).is_err());
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    fn sockets() -> (UnixStream, UnixStream) {
        let (client, server) = UnixStream::pair().unwrap();
        for socket in [&client, &server] {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        (client, server)
    }
    fn requests() -> Vec<Unsigned> {
        (0..10_000)
            .map(|n| {
                serde_json::from_value(serde_json::json!({
                    "method": "GET", "key": format!("allowed/{n}"), "query": {}, "headers": {},
                }))
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn sends_later_batches_without_waiting_for_earlier_replies() {
        let (mut client, mut server) = sockets();
        let requests = requests();
        let receiver = std::thread::spawn(move || {
            let mut keys = Vec::new();
            // Refuse to reply until every request arrived: this fails for a
            // request/reply loop, independent of machine or network speed.
            while keys.len() < 10_000 {
                let SigningRequest::Sign(batch) = read_message(&mut server).unwrap() else {
                    panic!("expected signing batch")
                };
                assert!(batch.len() <= 128);
                keys.extend(batch.into_iter().map(|r| r.key));
            }
            for range in batches(&keys, |v| {
                serde_json::to_vec(&SigningReply::Signed(v.to_vec()))
            })
            .unwrap()
            {
                write_message(&mut server, &SigningReply::Signed(keys[range].to_vec())).unwrap();
            }
            let SigningRequest::Finish = read_message(&mut server).unwrap() else {
                panic!("expected finish")
            };
            write_message(&mut server, &SigningReply::Finished).unwrap();
        });
        assert_eq!(
            sign(&mut client, &requests).unwrap(),
            requests.into_iter().map(|r| r.key).collect::<Vec<_>>()
        );
        finish(&mut client).unwrap();
        receiver.join().unwrap();
    }

    #[test]
    fn drains_large_replies_while_sending_requests() {
        let (mut client, mut server) = sockets();
        let requests = requests();
        let receiver = std::thread::spawn(move || {
            let mut received = 0;
            while received < 10_000 {
                let SigningRequest::Sign(batch) = read_message(&mut server).unwrap() else {
                    panic!("expected signing batch")
                };
                received += batch.len();
                let urls: Vec<_> = batch
                    .into_iter()
                    .map(|r| format!("{}?{}", r.key, "x".repeat(9000)))
                    .collect();
                for range in batches(&urls, |v| {
                    serde_json::to_vec(&SigningReply::Signed(v.to_vec()))
                })
                .unwrap()
                {
                    write_message(&mut server, &SigningReply::Signed(urls[range].to_vec()))
                        .unwrap();
                }
            }
        });
        let urls = sign(&mut client, &requests).unwrap();
        assert_eq!(urls.len(), 10_000);
        for (request, url) in requests.iter().zip(urls) {
            assert_eq!(url, format!("{}?{}", request.key, "x".repeat(9000)));
        }
        receiver.join().unwrap();
    }

    fn approval() -> Request {
        serde_json::from_value(serde_json::json!({
            "bucket": "fixture", "endpoint": null, "region": null, "profile": null,
            "scopes": [{"key": "allowed", "descendants": true}], "source": null,
            "removal": null, "acl": {}, "upload": false, "delete": false,
            "create_only": false, "lifetime": 60,
        }))
        .unwrap()
    }

    #[test]
    fn authorizing_side_signs_a_full_message_and_refuses_a_larger_one() {
        let (mut client, mut server) = sockets();
        let receiver = std::thread::spawn(move || {
            serve_signing(&mut server, &Signer::fixture(approval()), || false)
        });
        let requests = requests();
        write_message(&mut client, &SigningRequest::Sign(requests[..128].to_vec())).unwrap();
        let mut signed = 0;
        while signed < 128 {
            let SigningReply::Signed(urls) = read_message(&mut client).unwrap() else {
                panic!("expected signed URLs")
            };
            signed += urls.len();
        }
        assert_eq!(signed, 128);
        write_message(&mut client, &SigningRequest::Sign(requests[..129].to_vec())).unwrap();
        let SigningReply::Error(error) = read_message(&mut client).unwrap() else {
            panic!("expected a refusal")
        };
        assert!(error.contains("oversized storage signing batch"), "{error}");
        // The refusal ends the session: nothing more is signed on it.
        receiver.join().unwrap().unwrap();
        assert!(read_message::<SigningReply>(&mut client).is_err());
    }

    #[test]
    fn a_different_build_is_refused_before_anything_is_sent() {
        let directory = crate::test_support::short_tempdir().unwrap();
        let socket = directory.path().join("r.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let registration = Registration {
            version: REGISTRATION_VERSION,
            identity: format!("{}-other", crate::identity::build()),
            socket,
            secret: "test".into(),
            program: b"/test/syq".to_vec(),
        };
        let error = connect_registered("laptop", &registration, approval())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("storage authorization requires matching syq builds"),
            "{error}"
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn early_rejection_stops_the_pending_sender() {
        let (mut client, mut server) = sockets();
        let receiver = std::thread::spawn(move || {
            let _: SigningRequest = read_message(&mut server).unwrap();
            write_message(
                &mut server,
                &SigningReply::Error("outside approved paths".into()),
            )
            .unwrap();
            // Keep the peer open until the client closes the failed session.
            let mut buffer = [0; 4096];
            while std::io::Read::read(&mut server, &mut buffer).unwrap() != 0 {}
        });
        let error = sign(&mut client, &requests()).unwrap_err();
        assert!(
            error.to_string().contains("outside approved paths"),
            "{error:#}"
        );
        receiver.join().unwrap();
    }
}
