use super::*;
use crate::cli::{Args, Interface, Location, Placement};
use crate::conn::Conn;
use crate::proto::{Request, Response};

#[test]
fn receiving_pins_preserve_native_identity_and_certificate_alias_tokens() {
    use ssh_agent_lib::ssh_key::{private::Ed25519Keypair, PrivateKey};

    let client = PrivateKey::new(Ed25519Keypair::from_seed(&[41; 32]).into(), "").unwrap();
    let ca = PrivateKey::new(Ed25519Keypair::from_seed(&[42; 32]).into(), "").unwrap();
    let host = PrivateKey::new(Ed25519Keypair::from_seed(&[43; 32]).into(), "").unwrap();
    let mut certificate = ssh_agent_lib::ssh_key::certificate::Builder::new(
        vec![0; 16],
        client.public_key().key_data().clone(),
        0,
        u32::MAX.into(),
    )
    .unwrap();
    certificate.valid_principal("account").unwrap();
    let certificate = certificate.sign(&ca).unwrap().to_openssh().unwrap();

    for alias in [Some("stable-source"), None] {
        let root = crate::test_support::tempdir().unwrap();
        let requested = "source-alias";
        let token = alias.unwrap_or(requested);
        let lookup = alias.unwrap_or("[127.0.0.1]:2200");
        let identity = root.path().join(format!("{token}.pub"));
        let cert = root.path().join(format!("{token}-cert.pub"));
        let known_hosts = root.path().join("known_hosts");
        let config = root.path().join("config");
        let ssh = root.path().join("ssh");
        let ssh_keygen = root.path().join("ssh-keygen");
        fs::write(&identity, client.public_key().to_openssh().unwrap()).unwrap();
        fs::write(&cert, &certificate).unwrap();
        fs::write(
            &known_hosts,
            format!("{lookup} {}\n", host.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        let mut contents = format!(
            "Host {requested}\n HostName 127.0.0.1\n User account\n Port 2200\n IdentityFile {}/%k.pub\n CertificateFile {}/%k-cert.pub\n IdentitiesOnly yes\n UserKnownHostsFile {}\n GlobalKnownHostsFile none\n HostKeyAlgorithms ssh-ed25519\n NoHostAuthenticationForLocalhost yes\n ProxyCommand false\n",
            root.path().display(), root.path().display(), known_hosts.display()
        );
        if let Some(alias) = alias {
            contents.push_str(&format!(" HostKeyAlias {alias}\n"));
        }
        fs::write(&config, contents).unwrap();
        crate::test_support::write_executable(
            &ssh,
            format!(
                "#!/bin/sh\nfor arg in \"$@\"; do\n if [ \"$arg\" = /dev/null ]; then exec ssh \"$@\"; fi\ndone\nexec ssh -F {} \"$@\"\n",
                shell_words::quote(config.to_str().unwrap())
            ),
            0o700,
        );
        crate::test_support::write_executable(
            &ssh_keygen,
            "#!/bin/sh\nexec ssh-keygen \"$@\"\n",
            0o700,
        );
        let policy = crate::agent_broker::resolve_host_policy_at_bounded(
            ssh.to_str().unwrap(),
            None,
            requested,
            None,
            Instant::now() + Duration::from_secs(5),
            &|| false,
        )
        .unwrap();
        let pins = root.path().join("pinned-hosts");
        let mut command = Command::new("ssh");
        command.args(["-vvv", "-F"]).arg(&config);
        let account = pin_receiving_source(&mut command, &policy, &pins).unwrap();
        assert_eq!(account.endpoint.user.as_deref(), Some("account"));
        assert_eq!(account.endpoint.host, "127.0.0.1");
        assert_eq!(account.endpoint.port, Some(2200));
        assert_eq!(account.host_keys, policy.pinned_host_key_fingerprints());
        command.args(["--", requested]);
        let capture = |command: &mut Command| {
            crate::process::capture_output_bounded(
                command,
                Instant::now() + Duration::from_secs(5),
                &|| false,
                64 * 1024,
            )
            .unwrap()
        };
        // ProxyCommand exits locally. The actual OpenSSH startup still expands
        // and loads both credentials; no SSH server or authentication is needed.
        let output = capture(&mut command);
        assert!(!output.status.success());
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        for (kind, path) in [("identity", &identity), ("certificate", &cert)] {
            let prefix = format!("debug1: {kind} file {} type ", path.display());
            // OpenSSH 10.3 reports loaded certificates with their key type
            // and fingerprint instead of the older numeric file-type line.
            let certificate_prefix = format!(
                "debug1: loaded identity cert from {}: ED25519-CERT ",
                path.display()
            );
            let loaded = diagnostics.lines().any(|line| {
                line.strip_prefix(&prefix)
                    .is_some_and(|value| value.parse::<u32>().is_ok())
                    || (kind == "certificate" && line.starts_with(&certificate_prefix))
            });
            assert!(loaded, "configured {kind} was not loaded: {diagnostics}");
        }
        let mut search = Command::new("ssh-keygen");
        search.args(["-F", lookup, "-f"]).arg(&pins);
        assert!(capture(&mut search).status.success());

        let mut effective = Command::new("ssh");
        effective.args(["-G", "-F"]).arg(&config);
        pin_receiving_source(&mut effective, &policy, &pins).unwrap();
        effective.args(["--", requested]);
        let output = capture(&mut effective);
        assert!(output.status.success());
        let config = String::from_utf8(output.stdout).unwrap();
        assert!(config
            .lines()
            .any(|line| line == "nohostauthenticationforlocalhost no"));
        assert!(config
            .lines()
            .any(|line| line == "stricthostkeychecking true"));
        assert!(!config.contains("syq-approved-source"));
    }
}

#[test]
fn approved_source_uses_its_control_channel_without_a_native_ssh_pool() {
    let directory = crate::test_support::tempdir().unwrap();
    let mut args = args(directory.path(), "target");
    args.locations[0].host = Some("source".into());
    args.locations.last_mut().unwrap().host = None;
    let (control, _peer) = UnixStream::pair().unwrap();
    let approved = ReturnConnection::new(control, None);
    args.return_source = Some(approved.clone());
    let crate::conn::Endpoint::Remote(source) =
        crate::transfer::endpoint(&args.locations[0], &args).unwrap()
    else {
        panic!("source must remain remote");
    };
    assert!(Arc::ptr_eq(source.forwarded.as_ref().unwrap(), &approved));
    assert!(source.ssh_multiplexer.is_none());
    assert!(!source.bootstrap_helper);
    assert!(approved.take_control().is_ok());
    assert!(approved.take_control().is_err());
    assert!(approved.ssh_command().is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn full_listen_queue_reports_busy_without_reconnect_advice() {
    use socket2::{Domain, SockAddr, Socket, Type};
    let dir = crate::test_support::tempdir().unwrap();
    let path = dir.path().join("busy.sock");
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
    listener.bind(&SockAddr::unix(&path).unwrap()).unwrap();
    listener.listen(0).unwrap();
    let mut queued = Vec::new();
    let mut full = false;
    for _ in 0..16 {
        match connect_socket(&path, Instant::now() + Duration::from_secs(1), None) {
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
    let error = exchange(
        &registration,
        Message::Ping,
        Duration::from_millis(100),
        Some(Duration::from_millis(100)),
    )
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
        let dir = crate::test_support::tempdir().unwrap();
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
                // Leave the connection open without a reply so the absolute
                // exchange deadline expires even with no socket read timeout.
                let _ = stopped.recv_timeout(Duration::from_secs(15));
            }
        });
        // Only the unanswered handshake needs a short timeout to fail quickly
        // through the exchange deadline. The rejection keeps the
        // production timeout so a slow peer thread cannot turn it into a retry.
        let timeout = if reject {
            REGISTRATION_HANDSHAKE_TIMEOUT
        } else {
            Duration::from_millis(200)
        };
        let result = register("laptop", &path, "test-credential", timeout);
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
/// A copy command to the test receiver, as the requesting server sends it.
/// Unless `options` choose otherwise, it uses two workers.
pub(super) fn command(source: &Path, options: &[&str]) -> Vec<Vec<u8>> {
    let source = source.as_os_str().as_bytes().to_vec();
    let workers: &[&str] = if options.contains(&"--performance-tuning") {
        &[]
    } else {
        &["--performance-tuning", "workers=2"]
    };
    [b"cp".to_vec(), b"--src".to_vec(), source]
        .into_iter()
        .chain(
            // Kernel-assigned ports keep concurrent native fixtures isolated,
            // including wildcard and loopback listeners sharing a macOS host.
            ["--to", "@laptop", "--into", ".", "--tcp-ports", "0-0"]
                .iter()
                .chain(options)
                .chain(workers)
                .map(|arg| arg.as_bytes().to_vec()),
        )
        .collect()
}
/// The request the receiver derives from `command`.
pub(super) fn requested(
    source: &Path,
    options: &[&str],
) -> (Vec<Vec<u8>>, CopyRequest, crate::receipt::RecipientSecret) {
    let command = command(source, options);
    let (request, secret) = request(&crate::approval_command::parse(&command).unwrap());
    (command, request, secret)
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
        tcp_peer: crate::conn::RemoteSpec::local_receiver(false),
        name: "laptop".into(),
        identity_key: identity::generate_key().unwrap(),
        requester: crate::receive_approval::Requester {
            server: "test-server".into(),
            profile: "test".into(),
        },
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
        ssh_count: AtomicU64::new(0),
        account_source: Mutex::new(Err("test source not configured".into())),
        account_sessions: Mutex::new(HashMap::new()),
        forward_count: std::sync::atomic::AtomicUsize::new(0),
        forward_sessions: Mutex::new(HashMap::new()),
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
            inline_on_thread_failure: false,
            max_connections: 16,
            io_timeout: Duration::from_secs(2),
        },
        move |stream, _| {
            let mut writer = stream.try_clone().unwrap();
            if let Err(error) = handler.handle(stream) {
                let _ = ssh_auth::reply_error(&mut writer, &error);
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
fn approve(registration: &Registration, command: Vec<Vec<u8>>, request: CopyRequest) -> Approved {
    let (_, reply) = exchange(
        registration,
        Message::Request {
            cwd: String::new(),
            command,
            request: Box::new(request),
        },
        Duration::from_secs(10),
        Some(Duration::from_secs(10)),
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
    let root = crate::test_support::tempdir().unwrap();
    let (_broker, _receiver, mut registration, _) = broker(root.path(), Approval::Always);
    registration.secret = "wrong".into();
    assert!(exchange(
        &registration,
        Message::Ping,
        Duration::from_secs(2),
        Some(Duration::from_secs(2))
    )
    .is_err());
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
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, prompts) = broker(&root, Approval::Ask);
    let (command, request, _) = requested(Path::new("source"), &[]);
    let caller = std::thread::spawn(move || {
        exchange(
            &registration,
            Message::Request {
                cwd: String::new(),
                command,
                request: Box::new(request),
            },
            Duration::from_secs(5),
            Some(Duration::from_secs(5)),
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
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, request);
    let mut conn = control(registration.clone(), &approved);
    assert!(exchange(
        &registration,
        Message::Open {
            token: approved.token.clone(),
            control: true
        },
        Duration::from_secs(2),
        Some(Duration::from_secs(2))
    )
    .is_err());
    conn.send(Request::TcpListen {
        send_rate: None,
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
        Duration::from_secs(2),
        Some(Duration::from_secs(2))
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
        Some(Duration::from_secs(2)),
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
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, request);
    let conn = control(registration.clone(), &approved);
    let worker = worker_stream(&registration, &approved);
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
        crate::test_support::read_until_closed(&worker, Duration::from_secs(1)).unwrap(),
        Vec::<u8>::new(),
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

/// Open two data channels whose hello never arrives. The registry's I/O
/// timeout decides how long each pending hello holds its worker allowance.
fn pending_hellos(
    io_timeout: Duration,
) -> (
    impl Sized,
    Registration,
    Approved,
    impl Sized,
    Vec<UnixStream>,
) {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, request);
    let control = control(registration.clone(), &approved);
    receiver
        .sessions
        .lock()
        .unwrap()
        .get_mut(&approved.token)
        .unwrap()
        .channels = Arc::new(crate::private_broker::ConnectionRegistry::new(io_timeout));
    let mut pending = Vec::new();
    for _ in 0..2 {
        let (stream, reply) = exchange(
            &registration,
            Message::Open {
                token: approved.token.clone(),
                control: false,
            },
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        assert!(matches!(reply, Reply::Ready));
        pending.push(stream);
    }
    (
        (temp, broker, receiver),
        registration,
        approved,
        control,
        pending,
    )
}

#[test]
fn named_pending_hello_is_bounded_and_does_not_block_readiness() {
    // A long I/O timeout keeps both hellos pending for the whole test, so the
    // bound is checked without racing their expiry.
    let (_fixture, registration, approved, _control, _pending) =
        pending_hellos(Duration::from_secs(60));
    assert!(exchange(
        &registration,
        Message::Open {
            token: approved.token.clone(),
            control: false,
        },
        Duration::from_secs(2),
        Some(Duration::from_secs(2))
    )
    .is_err());
    assert!(matches!(
        exchange(
            &registration,
            Message::Ping,
            Duration::from_secs(1),
            Some(Duration::from_secs(1))
        )
        .unwrap()
        .1,
        Reply::Ready
    ));
}

#[test]
fn named_expired_pending_hellos_release_their_worker_allowance() {
    let (_fixture, registration, approved, _control, pending) =
        pending_hellos(Duration::from_millis(200));
    // The receiver closes each channel when its hello times out; waiting for
    // that close is waiting for the expiry itself, not a fixed delay. Neither
    // socket options nor shared flags change while waiting for an expired peer.
    for stream in pending {
        crate::test_support::read_until_closed(&stream, Duration::from_secs(5)).unwrap();
    }
    // Expired handshakes release their worker allowance while control stays live.
    let _worker = worker_stream(&registration, &approved);
}

#[test]
fn named_abandoned_open_releases_its_session() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(Path::new("source"), &[]);
    let approved = approve(&registration, command, request);
    let (stream, reply) = exchange(
        &registration,
        Message::Open {
            token: approved.token,
            control: true,
        },
        Duration::from_secs(2),
        Some(Duration::from_secs(2)),
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
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(Path::new("source"), &[]);
    let approved = approve(&registration, command, request);
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
    named_copy_with_transport(false);
}

#[test]
fn named_tcp_copy_uses_confined_workers_and_verifies_receipt() {
    named_copy_with_transport(true);
}

fn named_copy_with_transport(tcp: bool) {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello"), b"hello laptop").unwrap();
    fs::write(source.join("large"), vec![42; 5_000_000]).unwrap();
    std::os::unix::fs::symlink("hello", source.join("link")).unwrap();
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, secret) = requested(&source, &[]);
    let mut args = crate::approval_command::parse(&command).unwrap();
    let policy = request.constraints.receipt_policy.clone();
    let approved = approve(&registration, command, request);
    // The route below replaces discovery of the named receiver.
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, approved.token.clone()));
    args.named_receipt = Some(Arc::new(NamedReceipt {
        connection: None,
        secret,
        approved,
        policy,
    }));
    args.no_tcp = !tcp;
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

/// The receiving machine never runs as root, so a laptop download accepts
/// ownership and special files as any copy by an ordinary account does.
#[test]
fn named_copy_accepts_ownership_and_special_files() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("hello"), b"hello laptop").unwrap();
    let fifo = std::ffi::CString::new(source.join("pipe").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o640) }, 0);
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, secret) = requested(
        &source,
        &["--copy-metadata", "mtime,permissions,ownership,specials"],
    );
    let options = &request.copy.options;
    assert!(options.preserve_owner && options.preserve_group && options.preserve_devices);
    let mut args = crate::approval_command::parse(&command).unwrap();
    let policy = request.constraints.receipt_policy.clone();
    let approved = approve(&registration, command, request);
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, approved.token.clone()));
    args.named_receipt = Some(Arc::new(NamedReceipt {
        connection: None,
        secret,
        approved,
        policy,
    }));
    assert_eq!(crate::transfer::run(args).unwrap(), 0);
    assert_eq!(
        fs::read(root.join("source/hello")).unwrap(),
        b"hello laptop"
    );
    let pipe = fs::symlink_metadata(root.join("source/pipe")).unwrap();
    assert!(pipe.file_type().is_fifo());
    assert_eq!(pipe.gid(), fs::metadata(&source).unwrap().gid());
}

#[test]
fn named_requests_keep_inplace_refused_and_need_a_stated_deletion_ceiling() {
    let temporary = crate::test_support::tempdir().unwrap();
    let mut inplace = args(&temporary.path().join("source"), "output");
    inplace.inplace = true;
    let (request, _) = request(&inplace);
    let error = constrain(request, temporary.path(), 1000, 1000, 0).unwrap_err();
    assert!(error.to_string().contains("--inplace"), "{error:#}");

    let mut pruning = args(&temporary.path().join("source"), "output");
    pruning.delete = true;
    let error = require_deletion_ceiling(&pruning).unwrap_err();
    assert!(error.to_string().contains("--max-delete"), "{error:#}");
    pruning.max_delete = Some(3);
    require_deletion_ceiling(&pruning).unwrap();
    pruning.max_delete = None;
    pruning.dry_run = true;
    require_deletion_ceiling(&pruning).unwrap();
}

#[test]
fn named_requests_sign_the_senders_bandwidth_limit() {
    let temporary = crate::test_support::tempdir().unwrap();
    let mut args = args(&temporary.path().join("source"), "output");
    args.bwlimit_bytes = 1 << 20;
    let (request, _) = request(&args);
    assert_eq!(request.constraints.max_file_data_bytes_per_second, 1 << 20);
}

#[test]
fn named_authorization_expires_before_control_opens() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(Path::new("source"), &[]);
    let approved = approve(&registration, command, request);
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
        Duration::from_secs(2),
        Some(Duration::from_secs(2))
    )
    .is_err());
    assert_eq!(fs::read_dir(root).unwrap().count(), 0);
}

#[test]
fn named_limits_and_scope_validation_precede_approval() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    let (command, mut request, _) = requested(Path::new("source"), &[]);
    request.copy.mutation_scopes[0].path = b"/SYQ-RECEIVE/../outside".to_vec();
    assert!(exchange(
        &registration,
        Message::Request {
            cwd: String::new(),
            command,
            request: Box::new(request),
        },
        Duration::from_secs(2),
        Some(Duration::from_secs(2))
    )
    .is_err());
    assert_eq!(fs::read_dir(root).unwrap().count(), 0);
}
#[test]
fn receiving_cwd_allows_other_paths_but_root_confines_them() {
    let temp = crate::test_support::tempdir().unwrap();
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

#[test]
fn named_workers_refuse_mutations_before_transport_shutdown() {
    for tcp in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let (command, request, _) = requested(Path::new("source"), &["--no-compress"]);
        let approved = approve(&registration, command, request);
        let authority = receiver.sessions.lock().unwrap()[&approved.token]
            .authority
            .clone();
        let mut spec = crate::conn::RemoteSpec::local_receiver(true);
        spec.restricted_grant = Some(route(registration, approved.token));
        let mut control = spec.connect_with(false, false).unwrap();
        if tcp {
            let pending = spec
                .begin_tcp_setup(&mut control, false, (0, 0), None, None)
                .unwrap();
            spec.finish_tcp_setup(pending).unwrap();
        }
        let mut worker = crate::conn::Endpoint::Remote(spec.clone())
            .connect_with_copy_capabilities(false, None, Vec::new(), false)
            .unwrap();
        assert_eq!(worker.transport_stats().is_some(), tcp);
        let (finished, observed) = mpsc::channel();
        let task = std::thread::spawn(move || {
            let mkdir = |name: &str| Request::Apply {
                ops: vec![crate::proto::Op::Mkdir {
                    path: root.join(name).as_os_str().as_bytes().to_vec(),
                    mode: 0o700,
                    condition: crate::proto::TargetCondition::Absent,
                }],
                guard: None,
            };
            assert!(matches!(
                worker.call(mkdir("source")).unwrap(),
                Response::Applied(results) if results.len() == 1 && results[0].is_none()
            ));
            assert!(root.join("source").is_dir());

            // Hold both transports open while closing only admission. This
            // forces the interval before the TCP watcher can deliver EOF,
            // without a scheduling delay or a hook in production code.
            authority.close_control();
            for (connection, name) in [
                (&mut *worker as &mut dyn Conn, "source/worker-blocked"),
                (&mut control as &mut dyn Conn, "source/control-blocked"),
            ] {
                let response = connection.call(mkdir(name)).unwrap();
                assert!(
                    matches!(response, Response::Err(ref error)
                        if error.contains("transfer control is closed or expired")),
                    "revoked mutation was not refused: {response:?}"
                );
                assert!(!root.join(name).exists());
            }
            // The token and session still exist and the allowance has room:
            // closed authority itself must refuse new workers on both routes.
            let grant = spec.restricted_grant.as_deref().unwrap();
            let error = connect(grant, false).unwrap_err();
            assert!(format!("{error:#}").contains("control is closed or expired"));
            if tcp {
                let error = tcp::open(grant, vec![7; 32]).unwrap_err();
                assert!(format!("{error:#}").contains("control is closed or expired"));
            }
            assert_eq!(fs::read_dir(root.join("source")).unwrap().count(), 0);
            drop(control);
            assert!(worker.recv().is_err(), "revoked worker did not close");
            finished.send(()).unwrap();
        });
        let result = observed.recv_timeout(Duration::from_secs(3));
        // Release the sockets even when an assertion fails or a reply stalls.
        receiver.revoke_all();
        task.join().unwrap();
        result.expect("revocation checks did not finish");
    }
}

#[test]
fn named_tcp_workers_obey_limits_and_revocation() {
    for stop_profile in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
        let (command, request, _) = requested(
            Path::new("source"),
            &["--no-compress", "--performance-tuning", "workers=1"],
        );
        let approved = approve(&registration, command, request);
        let mut spec = crate::conn::RemoteSpec::local_receiver(true);
        spec.restricted_grant = Some(route(registration, approved.token.clone()));
        let mut control = spec.connect_with(false, false).unwrap();
        let pending = spec
            .begin_tcp_setup(&mut control, false, (0, 0), None, None)
            .unwrap();
        spec.finish_tcp_setup(pending).unwrap();
        assert_eq!(
            spec.data_transport(),
            crate::conn::DataTransport::EncryptedTcp
        );
        let port = spec.tcp.lock().unwrap().as_ref().unwrap().port;
        let mut intruder = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        intruder.write_all(&[1; 32]).unwrap();
        drop(intruder);
        let endpoint = crate::conn::Endpoint::Remote(spec.clone());
        let mut worker = endpoint
            .connect_with_copy_capabilities(false, None, Vec::new(), false)
            .unwrap();
        assert!(
            worker.transport_stats().is_some(),
            "worker must actually use TCP"
        );
        // Both transport types draw from the same approved worker allowance.
        assert!(tcp::open(spec.restricted_grant.as_deref().unwrap(), vec![7; 32]).is_err());
        assert!(connect(spec.restricted_grant.as_deref().unwrap(), false).is_err());
        if stop_profile {
            receiver.revoke_all();
        }
        drop(control);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !receiver.sessions.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "copy did not revoke its workers");
            std::thread::sleep(Duration::from_millis(5));
        }
        // Revocation closes admission before the watcher shuts down TCP. A
        // request racing that watcher can receive a refusal before EOF.
        let (closed, observed) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            if let Ok(response) = worker.call(Request::TransportStats) {
                assert!(
                    matches!(response, Response::Err(ref error)
                        if error.contains("transfer control is closed or expired")),
                    "revoked worker accepted a request: {response:?}"
                );
                assert!(worker.recv().is_err(), "revoked TCP worker did not close");
            }
            closed.send(()).unwrap();
        });
        observed
            .recv_timeout(Duration::from_secs(2))
            .expect("revoked TCP worker did not close");
        reader.join().unwrap();
        assert!(tcp::open(spec.restricted_grant.as_deref().unwrap(), vec![7; 32]).is_err());
        assert!(connect(spec.restricted_grant.as_deref().unwrap(), false).is_err());
    }
}

#[test]
fn named_tcp_connect_failure_uses_approved_ssh_worker() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, request);
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, approved.token.clone()));
    let mut control = spec.connect_with(false, false).unwrap();
    let pending = spec
        .begin_tcp_setup(&mut control, false, (0, 0), None, None)
        .unwrap();
    spec.finish_tcp_setup(pending).unwrap();
    // Replace the selected route with a reserved, non-listening socket. Setup
    // succeeded, but the next connection must use the common SSH fallback.
    let unavailable =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    unavailable
        .bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
    {
        let mut sessions = receiver.sessions.lock().unwrap();
        let info = sessions
            .get_mut(&approved.token)
            .unwrap()
            .tcp
            .as_mut()
            .unwrap();
        info.addrs = vec!["127.0.0.1".into()];
        info.port = unavailable
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap()
            .port();
    }
    let endpoint = crate::conn::Endpoint::Remote(spec.clone());
    let mut worker = endpoint
        .connect_with_copy_capabilities(false, None, Vec::new(), false)
        .unwrap();
    assert_eq!(spec.data_transport(), crate::conn::DataTransport::Ssh);
    assert!(worker.transport_stats().is_none());
    assert!(matches!(
        worker.call(Request::TransportStats).unwrap(),
        Response::TransportStats(_)
    ));
    drop(worker);
    drop(control);
}

#[test]
fn named_tcp_workers_connect_concurrently() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(
        Path::new("source"),
        &["--no-compress", "--performance-tuning", "workers=8"],
    );
    let approved = approve(&registration, command, request);
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, approved.token.clone()));
    let mut control = spec.connect_with(false, false).unwrap();
    let pending = spec
        .begin_tcp_setup(&mut control, false, (0, 0), None, None)
        .unwrap();
    spec.finish_tcp_setup(pending).unwrap();
    let start = Arc::new(std::sync::Barrier::new(8));
    let threads = (0..8)
        .map(|_| {
            let tcp = Arc::clone(&spec.tcp);
            let endpoint = crate::conn::Endpoint::Remote(spec.clone());
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                let mut worker = endpoint
                    .connect_with_copy_capabilities(false, None, Vec::new(), false)
                    .unwrap();
                assert!(
                    worker.transport_stats().is_some(),
                    "worker fell back to SSH: {:?}",
                    tcp.lock()
                        .unwrap()
                        .as_ref()
                        .and_then(|info| info.failure.as_deref())
                );
                worker
            })
        })
        .collect::<Vec<_>>();
    let workers = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(workers.len(), 8);
    drop(workers);
    drop(control);
}

#[test]
fn named_tcp_idle_and_partial_arrivals_do_not_block_worker() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    let (command, request, _) = requested(
        Path::new("source"),
        &["--no-compress", "--performance-tuning", "workers=1"],
    );
    let approved = approve(&registration, command, request);
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, approved.token.clone()));
    let mut control = spec.connect_with(false, false).unwrap();
    let pending = spec
        .begin_tcp_setup(&mut control, false, (0, 0), None, None)
        .unwrap();
    spec.finish_tcp_setup(pending).unwrap();
    let port = spec.tcp.lock().unwrap().as_ref().unwrap().port;
    let _idle = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut partial = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    partial.write_all(&[0; 16]).unwrap();
    let endpoint = crate::conn::Endpoint::Remote(spec);
    let mut worker = endpoint
        .connect_with_copy_capabilities(false, None, Vec::new(), false)
        .unwrap();
    assert!(
        worker.transport_stats().is_some(),
        "worker fell back to SSH"
    );
    assert!(matches!(
        worker.call(Request::TransportStats).unwrap(),
        Response::TransportStats(_)
    ));
    drop(worker);
    drop(control);
}

#[test]
fn source_data_hostname_preserves_laptop_alias_and_never_uses_requester_config() {
    let directory = crate::test_support::tempdir().unwrap();
    let laptop_config = directory.path().join("laptop-config");
    fs::write(&laptop_config, "Match originalhost copy-alias user approved\n    HostName 203.0.113.42\nHost *\n    HostName fallback.invalid\n").unwrap();
    let mut laptop = forward::target_spec("approved@copy-alias").unwrap();
    laptop
        .rsh
        .extend(["-F".into(), laptop_config.to_str().unwrap().into()]);
    let hostname =
        forward::source_data_hostname(&laptop, Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap();
    assert_eq!(hostname, "203.0.113.42");
    let (control, _peer) = UnixStream::pair().unwrap();
    let approved = ReturnConnection::source(control, hostname).unwrap();
    let mut requester = forward::target_spec("copy-alias").unwrap();
    requester.forwarded = Some(approved);
    // A pinned laptop result must not run this requesting machine's command.
    requester.rsh = vec!["/no/such/requester-ssh".into()];
    assert_eq!(
        requester.resolved_hostname().as_deref(),
        Some("203.0.113.42")
    );
    assert_eq!(requester.host, "copy-alias");
}

#[test]
fn source_data_hostname_rejects_options_paths_and_config_syntax() {
    for hostname in ["example.test", "192.0.2.4", "2001:db8::4", "my_ssh_alias"] {
        validate_data_hostname(hostname).unwrap();
    }
    for hostname in [
        "",
        "-oProxyCommand=x",
        "host\nProxyCommand=x",
        "host;echo x",
        "$(command)",
        "/tmp/socket",
        "host:22",
        "[2001:db8::4]",
    ] {
        assert!(validate_data_hostname(hostname).is_err(), "{hostname}");
    }
}
