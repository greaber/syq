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
/// What the machine that started a copy on a server sends first on the
/// signing session it serves over that copy's SSH session.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Opening {
    pub configuration: Configuration,
    /// The command's `--s3-header` and `--s3-write-header` values, which the
    /// server sends with its own requests. They can hold secrets such as an
    /// encryption key, so they travel here rather than on the server's
    /// command line, which other accounts there can read.
    pub headers: Vec<(String, String)>,
    pub write_headers: Vec<(String, String)>,
}

/// Serves a signing session to the server this machine started a copy on.
/// The command typed here is the approval, so there is no prompt: `signer`
/// holds the request derived from that command and refuses anything outside
/// it, exactly as it does for a request approved on a receiving machine.
pub(crate) fn serve_started_copy(
    stream: &mut (impl Read + Write),
    signer: &Signer,
    headers: Vec<(String, String)>,
    write_headers: Vec<(String, String)>,
) -> Result<Option<String>> {
    write_message(
        stream,
        &Opening {
            configuration: signer.configuration.clone(),
            headers,
            write_headers,
        },
    )?;
    serve_signing(stream, signer, || false)
}

/// How long a receiving machine may leave signing requests unanswered
/// before the copy treats it as gone.
const RELAY_REPLY_TIMEOUT: Duration = Duration::from_secs(60);

/// Passes a signing session between the server this machine started a copy
/// on and the receiving machine `name`, which approved the copy with
/// [`connect`] and signs for it: the server's requests arrive on `requests`,
/// answers go to it on `replies`, and `authority` is the connection to
/// `name`. Each message is decoded and written again, so only signing
/// messages pass; file data has no path through this machine.
///
/// Returns what this machine told the server when the session ended without
/// finishing: `name`'s refusal, or that `name` went away. An error means the
/// server's side ended first. A session that passed nothing on leaves
/// `authority` ready for another attempt to start the server's copy.
pub(crate) fn relay_started_copy(
    requests: &UnixStream,
    replies: &mut impl Write,
    authority: &UnixStream,
    name: &str,
    opening: &Opening,
) -> Result<Option<String>> {
    write_message(replies, opening)?;
    // Answers `name` owes, whether anything reached it, and whether the
    // server's requests ended.
    let owed = AtomicU64::new(0);
    let passed = AtomicBool::new(false);
    let ended = AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| {
            let (mut requests, mut authority) = (requests, authority);
            let _ = (|| -> Result<()> {
                loop {
                    let request: SigningRequest = read_message(&mut requests)?;
                    let (answers, last) = match &request {
                        SigningRequest::Sign(requests) => (requests.len() as u64, false),
                        SigningRequest::Finish => (1, true),
                    };
                    owed.fetch_add(answers, Ordering::AcqRel);
                    passed.store(true, Ordering::Release);
                    write_message(&mut authority, &request)?;
                    if last {
                        return Ok(());
                    }
                }
            })()
            .inspect_err(|_| ended.store(true, Ordering::Release));
        });
        let mut reader = authority;
        let outcome = (|| -> Result<Option<String>> {
            loop {
                if !reply_ready(authority, &owed, &ended)? {
                    bail!("the server ended its storage signing session");
                }
                let reply = match read_message(&mut reader) {
                    Ok(reply) => reply,
                    Err(_) => {
                        let lost = format!("@{name} disconnected before it finished signing this copy's storage requests; reconnect it and run the copy again");
                        write_message(replies, &SigningReply::Error(lost.clone()))?;
                        return Ok(Some(lost));
                    }
                };
                let answers = match &reply {
                    SigningReply::Signed(urls) => urls.len() as u64,
                    SigningReply::Finished | SigningReply::Error(_) => 1,
                    SigningReply::Configuration(_) => bail!("invalid storage signing response"),
                };
                anyhow::ensure!(
                    owed.fetch_sub(answers, Ordering::AcqRel) >= answers,
                    "@{name} answered storage requests the server did not send"
                );
                write_message(replies, &reply)?;
                match reply {
                    SigningReply::Finished => return Ok(None),
                    SigningReply::Error(refusal) => return Ok(Some(refusal)),
                    _ => {}
                }
            }
        })();
        if !matches!(outcome, Ok(None)) {
            // Release the thread reading the server's requests, and end a
            // session with `name` that can no longer finish.
            let _ = requests.shutdown(std::net::Shutdown::Both);
            if passed.load(Ordering::Acquire) {
                let _ = authority.shutdown(std::net::Shutdown::Both);
            }
        }
        outcome
    });
    outcome
}

/// Wait until `authority` has sent something, or closed. Returns `false`
/// once the server's requests have `ended`. While `authority` owes answers
/// it must keep sending; with none owed it may stay silent, since the server
/// can take any time to scan and hash before it asks.
fn reply_ready(authority: &UnixStream, owed: &AtomicU64, ended: &AtomicBool) -> Result<bool> {
    let mut silent = Instant::now();
    loop {
        let mut poll = libc::pollfd {
            fd: authority.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match unsafe { libc::poll(&mut poll, 1, 200) } {
            0 => {}
            ready if ready > 0 => return Ok(true),
            _ => {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error).context("wait for the receiving machine");
                }
            }
        }
        if ended.load(Ordering::Acquire) {
            return Ok(false);
        }
        if owed.load(Ordering::Acquire) == 0 {
            silent = Instant::now();
        } else if silent.elapsed() > RELAY_REPLY_TIMEOUT {
            // Reading reports it as gone.
            return Ok(true);
        }
    }
}

/// Reads what [`serve_started_copy`] sends first.
pub(crate) fn open_started_copy(stream: &mut impl Read) -> Result<Opening> {
    read_message(stream)
}

/// `signer` names the machine that signs, for messages.
pub(crate) fn sign(
    stream: &mut UnixStream,
    requests: &[Unsigned],
    signer: &str,
) -> Result<Vec<String>> {
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
                match read_message(stream).with_context(|| {
                    format!(
                        "{signer} disconnected during preparation; reconnect and rerun the copy"
                    )
                })? {
                    SigningReply::Signed(urls) => {
                        anyhow::ensure!(
                            !urls.is_empty() && result.len() + urls.len() <= requests.len(),
                            "invalid storage signing response length"
                        );
                        result.extend(urls);
                    }
                    SigningReply::Error(error) => bail!("{signer}: {error}"),
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
        serve_signing(&mut stream, &signer, receiving_stopped).map(drop)
    }
}

/// Signs each batch the approved requester sends until it finishes. One
/// refused request ends the session without signing the rest of its batch;
/// the refusal sent to the requester is returned.
pub(crate) fn serve_signing(
    stream: &mut (impl Read + Write),
    signer: &Signer,
    receiving_stopped: impl Fn() -> bool,
) -> Result<Option<String>> {
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
                    let refusal = error.to_string();
                    write_message(stream, &SigningReply::Error(refusal.clone()))?;
                    return Ok(Some(refusal));
                }
            },
            SigningRequest::Finish => {
                write_message(stream, &SigningReply::Finished)?;
                return Ok(None);
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
            sign(&mut client, &requests, "authorizing machine").unwrap(),
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
        let urls = sign(&mut client, &requests, "authorizing machine").unwrap();
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

    /// A copy started on a server whose signing session this machine passes
    /// to a receiving machine: the server's end, this machine's relay, and
    /// the receiving machine's signer.
    struct Relayed {
        server: UnixStream,
        relay: std::thread::JoinHandle<Result<Option<String>>>,
        /// This machine's connection to the receiving machine, as the relay
        /// leaves it.
        authority: UnixStream,
    }
    fn relayed(receiving: impl FnOnce(UnixStream) + Send + 'static) -> Relayed {
        let (server, here) = sockets();
        let (authority, receiver) = sockets();
        std::thread::spawn(move || receiving(receiver));
        let connection = authority.try_clone().unwrap();
        let relay = std::thread::spawn(move || {
            let mut replies = here.try_clone().unwrap();
            relay_started_copy(
                &here,
                &mut replies,
                &connection,
                "laptop",
                &Opening {
                    configuration: Signer::fixture(approval()).configuration,
                    headers: vec![("x-amz-storage-class".into(), "STANDARD_IA".into())],
                    write_headers: vec![],
                },
            )
        });
        Relayed {
            server,
            relay,
            authority,
        }
    }
    fn signs(mut receiver: UnixStream) {
        let _ = serve_signing(&mut receiver, &Signer::fixture(approval()), || false);
    }

    #[test]
    fn a_receiving_machine_signs_through_the_machine_that_started_the_copy() {
        let Relayed {
            mut server, relay, ..
        } = relayed(signs);
        let opening = open_started_copy(&mut server).unwrap();
        assert_eq!(opening.headers.len(), 1);
        // Pipelined batches each way, as the server's copy sends them.
        let requests = requests();
        let urls = sign(&mut server, &requests, "the machine that started this copy").unwrap();
        assert_eq!(urls.len(), requests.len());
        assert!(
            urls[7].starts_with("https://storage.example/fixture/allowed/7?")
                && urls[7].contains("X-Amz-Signature="),
            "{}",
            urls[7]
        );
        finish(&mut server).unwrap();
        assert_eq!(relay.join().unwrap().unwrap(), None);
    }

    #[test]
    fn a_receiving_machines_refusal_reaches_the_server_and_ends_the_session() {
        let Relayed {
            mut server,
            relay,
            authority,
        } = relayed(signs);
        open_started_copy(&mut server).unwrap();
        let outside: Unsigned = serde_json::from_value(serde_json::json!({
            "method": "GET", "key": "elsewhere/secret", "query": {}, "headers": {},
        }))
        .unwrap();
        let error = sign(
            &mut server,
            &[outside],
            "the machine that started this copy",
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "the machine that started this copy: storage request is outside the approved paths"
        );
        assert_eq!(
            relay.join().unwrap().unwrap().as_deref(),
            Some("storage request is outside the approved paths")
        );
        // Nothing more is passed either way.
        let mut authority = authority;
        assert!(read_message::<SigningReply>(&mut authority).is_err());
        assert!(read_message::<SigningReply>(&mut server).is_err());
    }

    #[test]
    fn losing_the_receiving_machine_during_signing_is_named_to_the_server() {
        let Relayed {
            mut server, relay, ..
        } = relayed(|mut receiver| {
            // It takes the first requests and goes away without answering.
            let _: SigningRequest = read_message(&mut receiver).unwrap();
        });
        open_started_copy(&mut server).unwrap();
        let error = sign(
            &mut server,
            &requests(),
            "the machine that started this copy",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("@laptop disconnected before it finished signing"),
            "{error}"
        );
        let ended = relay.join().unwrap().unwrap().unwrap();
        assert!(ended.contains("@laptop disconnected"), "{ended}");
    }

    #[test]
    fn losing_the_server_during_signing_ends_the_receiving_machines_session() {
        let (ended, receiving_ended) = std::sync::mpsc::channel();
        let Relayed {
            mut server, relay, ..
        } = relayed(move |mut receiver| {
            // It holds its answer until the session ends under it.
            let _: SigningRequest = read_message(&mut receiver).unwrap();
            let _ = ended.send(read_message::<SigningRequest>(&mut receiver).is_err());
        });
        open_started_copy(&mut server).unwrap();
        write_message(&mut server, &SigningRequest::Sign(requests()[..3].to_vec())).unwrap();
        // The copy's SSH session drops: the server's requests end.
        server.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(relay.join().unwrap().is_err());
        assert!(receiving_ended
            .recv_timeout(Duration::from_secs(5))
            .unwrap());
    }

    #[test]
    fn an_attempt_that_asked_for_nothing_leaves_the_approval_usable() {
        let Relayed {
            mut server,
            relay,
            authority,
        } = relayed(signs);
        open_started_copy(&mut server).unwrap();
        // The first attempt to start the server's copy ends before it asks.
        drop(server);
        assert!(relay.join().unwrap().is_err());
        // Bytes that are no signing message are not passed on either.
        let (mut server, here) = sockets();
        let mut replies = here.try_clone().unwrap();
        let again = std::thread::spawn(move || {
            relay_started_copy(
                &here,
                &mut replies,
                &authority,
                "laptop",
                &Opening {
                    configuration: Signer::fixture(approval()).configuration,
                    headers: vec![],
                    write_headers: vec![],
                },
            )
        });
        open_started_copy(&mut server).unwrap();
        let requests = requests();
        assert_eq!(
            sign(
                &mut server,
                &requests[..200],
                "the machine that started this copy"
            )
            .unwrap()
            .len(),
            200
        );
        // File data, or anything else that is not a signing message, ends
        // the session instead of reaching the receiving machine.
        write_message(&mut server, &"file data").unwrap();
        assert!(again.join().unwrap().is_err());
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
        let error = sign(&mut client, &requests(), "authorizing machine").unwrap_err();
        assert!(
            error.to_string().contains("outside approved paths"),
            "{error:#}"
        );
        receiver.join().unwrap();
    }
}
