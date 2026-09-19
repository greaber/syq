use super::*;
use crate::cli::{Args, Interface, Location, Placement};
use crate::conn::Conn;
use crate::proto::{Request, Response};

#[cfg(target_os = "linux")]
#[test]
fn full_listen_queue_reports_busy_without_reconnect_advice() {
    use socket2::{Domain, SockAddr, Socket, Type};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("busy.sock");
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
    listener.listen(0).unwrap();
    let mut queued = Vec::new();
    let mut full = false;
    for _ in 0..16 {
        match connect_socket(&path, Instant::now() + Duration::from_secs(1)) {
            Ok(socket) => queued.push(socket),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                full = true;
                break;
            }
            Err(error) => panic!("fill listen queue: {error}"),
        }
    }
    assert!(full, "test did not fill the listen queue");
    let registration = Registration {
        version: REGISTRATION_VERSION,
        identity: crate::identity::build().into(),
        socket: path,
        secret: "test".into(),
        program: b"/test/syq".to_vec(),
    };
    let error = exchange(&registration, Message::Ping, Duration::from_millis(100))
        .err()
        .unwrap();
    assert!(error.to_string().contains("busy"), "{error:#}");
    assert!(!error.to_string().contains("reconnect"), "{error:#}");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn registration_retries_socket_timeout_but_not_peer_rejection() {
    for reject in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("return.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (stop, stopped) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let _: Envelope = read_message(&mut stream).unwrap();
            if reject {
                write_message(
                    &mut stream,
                    &Reply::Error("Resource temporarily unavailable is a rejection here".into()),
                )
                .unwrap();
            } else {
                // Leave the connection open without a reply: read_exact
                // must hit the real Unix socket timeout (EAGAIN/EWOULDBLOCK).
                let _ = stopped.recv_timeout(Duration::from_secs(15));
            }
        });
        let result = register("laptop", &path, "test-credential");
        let _ = stop.send(());
        peer.join().unwrap();
        if reject {
            assert!(format!("{:#}", result.unwrap_err()).contains("receiving machine:"));
        } else {
            assert_eq!(result.unwrap(), RECONNECT_PENDING);
        }
        assert!(!path.exists(), "failed registration must remove its socket");
    }
}

#[test]
fn partial_writes_do_not_renew_the_exchange_deadline() {
    // Encode before starting the short socket deadline.
    let mut message = Vec::new();
    write_message(&mut message, &"x".repeat(MAX_MESSAGE / 2)).unwrap();
    let (mut writer, mut reader) = UnixStream::pair().unwrap();
    socket2::SockRef::from(&writer)
        .set_send_buffer_size(1024)
        .unwrap();
    reader
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let peer = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(2);
        let mut received = 0;
        let mut bytes = [0; 1024];
        while Instant::now() < end {
            match reader.read(&mut bytes) {
                Ok(0) => return received,
                Ok(count) => received += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("{error}"),
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        panic!("peer did not reach EOF after receiving {received} bytes");
    });
    let start = Instant::now();
    let result = DeadlineSocket {
        socket: &mut writer,
        deadline: start + Duration::from_millis(150),
    }
    .write_all(&message);
    let elapsed = start.elapsed();
    // Let the peer drain bytes already accepted by the socket. Stopping
    // it immediately can report zero payload progress when it is delayed.
    drop(writer);
    let received = peer.join().unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(received > 4, "peer made no payload progress");
    assert!(
        elapsed < Duration::from_millis(500),
        "write took {elapsed:?}"
    );
}

pub(super) fn args(source: &Path, destination: &str) -> Args {
    let mut args = Args::try_parse_from(["syq", "-rlt", "--no-progress", "src", "dst"]).unwrap();
    args.interface = Interface::NativeCp;
    args.placement = Placement::Into;
    args.locations = vec![
        Location::parse(source.to_str().unwrap()).unwrap(),
        Location::parse(&format!("server:{destination}")).unwrap(),
    ];
    args.connections_opt = Some(2);
    args.connections = 2;
    args.normalize();
    args
}
pub(super) fn request(args: &Args) -> (CopyRequest, crate::receipt::RecipientSecret) {
    let (secret, public) = crate::receipt::generate_recipient().unwrap();
    let policy = crate::receipt::ReceiptPolicy {
        required: true,
        hashed: false,
        max_records: crate::receipt::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
            suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key: public,
        },
    };
    (
        crate::restricted::named_request(args, policy).unwrap(),
        secret,
    )
}
#[test]
fn named_destination_allows_128_workers_and_preserves_smaller_allowances() {
    let temporary = crate::test_support::tempdir().unwrap();
    let args = args(&temporary.path().join("source"), "output");
    let (request, _) = request(&args);
    for (requested, expected) in [(2, 2), (32, 32), (64, 64), (128, 128), (256, 128)] {
        let mut request = request.clone();
        request.copy.limits.max_connections = requested;
        let constrained = constrain(request, temporary.path(), 1000, 1000, 0).unwrap();
        assert_eq!(constrained.copy.limits.max_connections, expected);
    }
}

pub(super) fn broker(
    root: &Path,
    approval: Approval,
) -> (
    PrivateBroker,
    Arc<Receiver>,
    Registration,
    mpsc::Receiver<Prompt>,
) {
    let (prompts, requests) = mpsc::sync_channel(1);
    let receiver = Arc::new(Receiver {
        name: "laptop".into(),
        identity_key: identity::generate_key().unwrap(),
        requester: "test-server".into(),
        auto_approve_root: Some(root.into()),
        notifications: crate::receive_approval::Notifications::Off,
        approvals: Arc::new(crate::receive_approval::Queue::default()),
        generation: AtomicU64::new(0),
        cwd: root.into(),
        root: Some(root.into()),
        secret: random_token().unwrap(),
        max_bytes: 10_000_000,
        max_entries: 1000,
        max_delete: 0,
        approval,
        prompts,
        sessions: Mutex::new(HashMap::new()),
        active_streams: Arc::new(crate::private_broker::ConnectionRegistry::new(
            Duration::from_secs(10),
        )),
        exec_count: AtomicU64::new(0),
        forward_count: std::sync::atomic::AtomicUsize::new(0),
        request_lock: Mutex::new(()),
        stop: Arc::new(AtomicBool::new(false)),
    });
    let handler = Arc::clone(&receiver);
    let broker = PrivateBroker::start_managed(
        PrivateBrokerConfig {
            directory_prefix: "syq-named-test-",
            socket_name: "s",
            listener_thread: "named-test-listener",
            client_thread: "named-test-client",
            max_connections: 16,
            io_timeout: Duration::from_secs(2),
        },
        move |stream, _| {
            let mut writer = stream.try_clone().unwrap();
            if let Err(error) = handler.handle(stream) {
                let _ = write_message(&mut writer, &Reply::Error(format!("{error:#}")));
            }
        },
    )
    .unwrap();
    let registration = Registration {
        version: REGISTRATION_VERSION,
        program: std::env::current_exe()
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec(),
        identity: crate::identity::build().into(),
        socket: broker.socket_path().into(),
        secret: receiver.secret.clone(),
    };
    (broker, receiver, registration, requests)
}
fn approve(registration: &Registration, request: CopyRequest) -> Approved {
    let (_, reply) = exchange(
        registration,
        Message::Request(Box::new(request)),
        Duration::from_secs(10),
    )
    .unwrap();
    match reply {
        Reply::Approved(approved) => approved,
        _ => panic!("no approval"),
    }
}
fn route(registration: Registration, token: String) -> String {
    format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Route {
                registration,
                token
            })
            .unwrap()
        )
    )
}
fn control(registration: Registration, approved: &Approved) -> crate::conn::RemoteConn {
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, approved.token.clone()));
    spec.connect_with(false, false).unwrap()
}

#[test]
fn pending_request_disconnect_and_trailing_data_are_detected_without_blocking() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    assert!(!requester_closed(&socket));
    peer.write_all(b"unexpected data").unwrap();
    assert!(requester_closed(&socket));
    drop(peer);
    assert!(requester_closed(&socket));
    let (socket, peer) = UnixStream::pair().unwrap();
    drop(peer);
    // Another test's forked child can briefly inherit the peer until exec.
    // Wait for actual EOF rather than assuming our drop closed its last fd.
    let deadline = Instant::now() + Duration::from_secs(1);
    while !requester_closed(&socket) {
        assert!(
            Instant::now() < deadline,
            "disconnected requester did not reach EOF"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn named_paths_reject_traversal_and_ambiguous_names() {
    for name in ["", "../x", "a/b", "a:b", "a@b", "a\n"] {
        assert!(validate_name(name).is_err());
    }
    for path in [
        &b"../escape"[..],
        b"a/../escape",
        b"/absolute",
        b"bad\0name",
    ] {
        assert!(request_path(path).is_err());
    }
    assert_eq!(request_path(b"./a//b").unwrap(), b"/SYQ-RECEIVE/a/b");
    assert!(rebase(b"/SYQ-RECEIVE-other/file", Path::new("/tmp/root")).is_err());
    assert!(rebase(b"/SYQ-RECEIVE/../escape", Path::new("/tmp/root")).is_err());
}

#[test]
fn named_parser_rejects_oversize_truncated_and_wrong_generation() {
    assert!(read_message::<Envelope>(&mut &u32::MAX.to_be_bytes()[..]).is_err());
    assert!(read_message::<Envelope>(&mut &b"\0\0\0\x10{}"[..]).is_err());
    let root = tempfile::tempdir().unwrap();
    let (_broker, _receiver, mut registration, _) = broker(root.path(), Approval::Always);
    registration.secret = "wrong".into();
    assert!(exchange(&registration, Message::Ping, Duration::from_secs(2)).is_err());
    let mut stream = UnixStream::connect(&registration.socket).unwrap();
    write_message(
        &mut stream,
        &Envelope {
            version: 999,
            identity: crate::identity::build().into(),
            secret: registration.secret,
            message: Message::Ping,
        },
    )
    .unwrap();
    assert!(matches!(
        read_message::<Reply>(&mut stream).unwrap(),
        Reply::Error(_)
    ));
}

#[test]
fn named_denial_does_not_issue_authority_or_touch_destination() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, prompts) = broker(&root, Approval::Ask);
    let (request, _) = request(&args(Path::new("source"), "."));
    let caller = std::thread::spawn(move || {
        exchange(
            &registration,
            Message::Request(Box::new(request)),
            Duration::from_secs(5),
        )
        .is_err()
    });
    let prompt = prompts.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(prompt.description.contains("not been inspected"));
    prompt.decision.send(false).unwrap();
    assert!(caller.join().unwrap());
    assert!(receiver.sessions.lock().unwrap().is_empty());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn named_control_cannot_be_replayed_and_cannot_listen_on_tcp() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let mut args = args(Path::new("source"), ".");
    args.compress = false;
    let (request, _) = request(&args);
    let approved = approve(&registration, request);
    let mut conn = control(registration.clone(), &approved);
    assert!(exchange(
        &registration,
        Message::Open {
            token: approved.token.clone(),
            control: true
        },
        Duration::from_secs(2)
    )
    .is_err());
    conn.send(Request::TcpListen {
        key: Some(vec![0; 32]),
        token: vec![1; 32],
        port_lo: 0,
        port_hi: 0,
        congestion_control: None,
    })
    .unwrap();
    assert!(matches!(conn.recv().unwrap(), Response::Err(_)));
    drop(conn);
    // Closing the control revokes workers regardless of retained tokens.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(exchange(
        &registration,
        Message::Open {
            token: approved.token,
            control: false
        },
        Duration::from_secs(2)
    )
    .is_err());
}

fn worker_stream(registration: &Registration, approved: &Approved) -> UnixStream {
    let (stream, reply) = exchange(
        registration,
        Message::Open {
            token: approved.token.clone(),
            control: false,
        },
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(matches!(reply, Reply::Ready));
    let mut writer = crate::proto::FrameWriter::new(stream.try_clone().unwrap(), false);
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().into(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role: crate::proto::ConnectionRole::DestinationWorker {
                destination: None,
                copy_sources: Vec::new(),
            },
        })
        .unwrap();
    let mut reader = crate::proto::FrameReader::new(stream.try_clone().unwrap());
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::HelloOk { .. }
    ));
    stream
}

#[test]
fn named_control_closure_revokes_connected_workers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let mut args = args(Path::new("source"), ".");
    args.compress = false;
    let (request, _) = request(&args);
    let approved = approve(&registration, request);
    let conn = control(registration.clone(), &approved);
    let mut worker = worker_stream(&registration, &approved);
    // macOS may reject SO_RCVTIMEO after the peer has shut down.
    worker
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let authority = receiver
        .sessions
        .lock()
        .unwrap()
        .get(&approved.token)
        .unwrap()
        .authority
        .clone();
    drop(conn);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(receiver.sessions.lock().unwrap().is_empty());
    assert_eq!(
        worker.read(&mut [0u8; 1]).unwrap(),
        0,
        "connected worker was not closed"
    );
    let mut request = Request::Apply {
        ops: vec![crate::proto::Op::Mkdir {
            path: root.join("source").as_os_str().as_bytes().to_vec(),
            mode: 0o755,
            condition: crate::proto::TargetCondition::Any,
        }],
        guard: None,
    };
    assert!(authority
        .authorize(&mut request, false)
        .unwrap_err()
        .to_string()
        .contains("control is closed"));
    assert!(!root.join("source").exists());
}

#[test]
fn named_pending_hello_is_bounded_and_does_not_block_readiness() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let mut args = args(Path::new("source"), ".");
    args.compress = false;
    let (request, _) = request(&args);
    let approved = approve(&registration, request);
    let _control = control(registration.clone(), &approved);
    receiver
        .sessions
        .lock()
        .unwrap()
        .get_mut(&approved.token)
        .unwrap()
        .channels = Arc::new(crate::private_broker::ConnectionRegistry::new(
        Duration::from_millis(200),
    ));
    let mut pending = Vec::new();
    for _ in 0..2 {
        let (stream, reply) = exchange(
            &registration,
            Message::Open {
                token: approved.token.clone(),
                control: false,
            },
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(matches!(reply, Reply::Ready));
        pending.push(stream);
    }
    assert!(exchange(
        &registration,
        Message::Open {
            token: approved.token.clone(),
            control: false,
        },
        Duration::from_secs(2)
    )
    .is_err());
    assert!(matches!(
        exchange(&registration, Message::Ping, Duration::from_secs(1))
            .unwrap()
            .1,
        Reply::Ready
    ));
    for mut stream in pending {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.read_to_end(&mut Vec::new()).unwrap();
    }
    // Expired handshakes release their worker allowance while control stays live.
    let _worker = worker_stream(&registration, &approved);
}

#[test]
fn named_abandoned_open_releases_its_session() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (request, _) = request(&args(Path::new("source"), "."));
    let approved = approve(&registration, request);
    let (stream, reply) = exchange(
        &registration,
        Message::Open {
            token: approved.token,
            control: true,
        },
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(matches!(reply, Reply::Ready));
    // Ready confirms the receiver consumed Open. Closing sooner can discard
    // the envelope on macOS, leaving an unused token to expire normally.
    // Abandon before Hello; the consumed session must still be revoked.
    drop(stream);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(receiver.sessions.lock().unwrap().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn named_failed_open_reply_releases_its_session() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (request, _) = request(&args(Path::new("source"), "."));
    let approved = approve(&registration, request);
    let mut stream = UnixStream::connect(&registration.socket).unwrap();
    // Linux SHUT_RD reliably refuses the opening reply while the client
    // remains connected, exercising the failed-reply cleanup specifically.
    stream.shutdown(std::net::Shutdown::Read).unwrap();
    write_message(
        &mut stream,
        &Envelope {
            version: VERSION,
            identity: crate::identity::build().into(),
            secret: registration.secret,
            message: Message::Open {
                token: approved.token,
                control: true,
            },
        },
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !receiver.sessions.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(receiver.sessions.lock().unwrap().is_empty());
}

#[test]
fn named_copy_uses_confined_workers_and_verifies_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello"), b"hello laptop").unwrap();
    fs::write(source.join("large"), vec![42; 5_000_000]).unwrap();
    std::os::unix::fs::symlink("hello", source.join("link")).unwrap();
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    let mut args = args(&source, ".");
    let (request, secret) = request(&args);
    let policy = request.constraints.receipt_policy.clone();
    let approved = approve(&registration, request);
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, approved.token.clone()));
    args.named_receipt = Some(Arc::new(NamedReceipt {
        control: Mutex::new(None),
        secret,
        approved,
        policy,
    }));
    args.no_tcp = true;
    assert_eq!(crate::transfer::run(args).unwrap(), 0);
    assert_eq!(
        fs::read(root.join("source/hello")).unwrap(),
        b"hello laptop"
    );
    assert_eq!(
        fs::read(root.join("source/large")).unwrap(),
        vec![42; 5_000_000]
    );
    assert_eq!(
        fs::read_link(root.join("source/link")).unwrap(),
        Path::new("hello")
    );
}

#[test]
fn named_authorization_expires_before_control_opens() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (request, _) = request(&args(Path::new("source"), "."));
    let approved = approve(&registration, request);
    receiver
        .sessions
        .lock()
        .unwrap()
        .get_mut(&approved.token)
        .unwrap()
        .issued = Instant::now() - START_TIMEOUT;
    assert!(exchange(
        &registration,
        Message::Open {
            token: approved.token,
            control: true
        },
        Duration::from_secs(2)
    )
    .is_err());
    assert_eq!(fs::read_dir(root).unwrap().count(), 0);
}

#[test]
fn named_limits_and_scope_validation_precede_approval() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    let (mut request, _) = request(&args(Path::new("source"), "."));
    request.copy.mutation_scopes[0].path = b"/SYQ-RECEIVE/../outside".to_vec();
    assert!(exchange(
        &registration,
        Message::Request(Box::new(request)),
        Duration::from_secs(2)
    )
    .is_err());
    assert_eq!(fs::read_dir(root).unwrap().count(), 0);
}
#[test]
fn receiving_cwd_allows_other_paths_but_root_confines_them() {
    let temp = tempfile::tempdir().unwrap();
    let temp = fs::canonicalize(temp.path()).unwrap();
    let cwd = temp.join("downloads");
    fs::create_dir(&cwd).unwrap();
    let outside = temp.join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, cwd.join("link")).unwrap();
    assert_eq!(
        resolve_destination(&cwd, None, b"../file").unwrap().0,
        temp.join("file")
    );
    assert_eq!(
        resolve_destination(&cwd, None, outside.join("file").as_os_str().as_bytes())
            .unwrap()
            .0,
        outside.join("file")
    );
    assert_eq!(
        resolve_destination(&cwd, None, b"link/file").unwrap().0,
        outside.join("file")
    );
    assert_eq!(
        resolve_destination(&cwd, None, b"link/../file").unwrap().0,
        temp.join("file")
    );
    assert_eq!(
        resolve_destination(&cwd, None, b"link").unwrap().0,
        cwd.join("link")
    );
    assert!(resolve_destination(&cwd, Some(&cwd), b"../file").is_err());
    assert!(resolve_destination(&cwd, Some(&cwd), outside.as_os_str().as_bytes()).is_err());
    assert_eq!(
        resolve_destination(&cwd, Some(&cwd), b"child/file")
            .unwrap()
            .0,
        cwd.join("child/file")
    );
}
#[test]
fn initial_envelope_deadline_is_not_extended_by_partial_bytes() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    let sender = std::thread::spawn(move || {
        for byte in 0..30 {
            if writer.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let start = Instant::now();
    assert!(read_socket_message::<Envelope>(&mut reader, Duration::from_millis(100)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(reader);
    sender.join().unwrap();
}
