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

/// A copy from another server that a receiving machine approved reads it
/// through the source's enrolled receiver: the signed directive goes to the
/// source's control, with the SSH command the approval prepared, a
/// connection shared only within this copy and no helper installation.
#[test]
fn an_approved_source_presents_its_directive_on_a_private_connection() {
    let directory = crate::test_support::tempdir().unwrap();
    let mut args = args(directory.path(), "target");
    args.locations[0].host = Some("source".into());
    args.locations.last_mut().unwrap().host = None;
    args.source_directive = Some("signed".into());
    args.rsh = Some(crate::remote_to_remote::receiver_rsh(None));
    let crate::conn::Endpoint::Remote(source) =
        crate::transfer::endpoint(&args.locations[0], &args).unwrap()
    else {
        panic!("source must remain remote");
    };
    assert_eq!(source.restricted_grant.as_deref(), Some("signed"));
    // Its socket is in a private directory of this run's, not a
    // persistence scope.
    use std::os::unix::fs::PermissionsExt as _;
    let multiplexer = source
        .ssh_multiplexer
        .as_ref()
        .expect("a private connection");
    let directory = multiplexer.control_path().parent().unwrap();
    assert!(directory
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("syq-ssh-"));
    assert_eq!(
        std::fs::metadata(directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!source.bootstrap_helper);
    // Each connection's own options choose the copy's connection or none,
    // ahead of this machine's configuration.
    assert!(!source
        .rsh
        .iter()
        .any(|option| option.starts_with("Control")));
    // It does not make this copy's local destination restricted.
    assert!(
        crate::transfer::endpoint(args.locations.last().unwrap(), &args)
            .is_ok_and(|endpoint| !endpoint.is_remote())
    );
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
fn exchange_sends_nothing_to_a_socket_another_user_listens_on() {
    let dir = crate::test_support::short_tempdir().unwrap();
    let path = dir.path().join("r.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        received
    });
    let registration = Registration {
        version: REGISTRATION_VERSION,
        identity: crate::identity::build().into(),
        socket: path,
        secret: "not-for-other-users".into(),
        program: b"/test/syq".to_vec(),
    };
    EXCHANGE_UID.with(|uid| uid.set(Some(unsafe { libc::geteuid() }.wrapping_add(1))));
    let result = exchange(&registration, Message::Ping, Duration::from_secs(5), None);
    EXCHANGE_UID.with(|uid| uid.set(None));
    let error = format!("{:#}", result.err().unwrap());
    assert!(error.contains("another user"), "{error}");
    assert!(error.contains("nothing was sent"), "{error}");
    assert_eq!(peer.join().unwrap(), b"");
}

#[test]
fn registration_reads_only_its_secret_line_from_standard_input() {
    let (mut laptop, server) = UnixStream::pair().unwrap();
    laptop.write_all(b"Abc-_09\nliveness").unwrap();
    assert_eq!(
        read_registration_secret(server.as_raw_fd(), Duration::from_secs(5)).unwrap(),
        "Abc-_09"
    );
    // The rest of the input stays unread for the liveness loop.
    let mut rest = [0; 8];
    (&server).read_exact(&mut rest).unwrap();
    assert_eq!(&rest, b"liveness");

    for (input, kind) in [
        (&b"\n"[..], std::io::ErrorKind::InvalidData),
        (b"secret with spaces\n", std::io::ErrorKind::InvalidData),
        (&[b'a'; 129], std::io::ErrorKind::InvalidData),
        (b"partial", std::io::ErrorKind::UnexpectedEof),
    ] {
        let (mut laptop, server) = UnixStream::pair().unwrap();
        laptop.write_all(input).unwrap();
        drop(laptop);
        let error =
            read_registration_secret(server.as_raw_fd(), Duration::from_secs(5)).unwrap_err();
        assert_eq!(error.kind(), kind, "{input:?}");
    }
    let (_laptop, server) = UnixStream::pair().unwrap();
    let started = Instant::now();
    let error =
        read_registration_secret(server.as_raw_fd(), Duration::from_millis(100)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// A registration that takes over a name takes it only once the laptop
/// says its service has taken over, and then as soon as the registration
/// holding it lets go; it stops waiting when the laptop gives up, and after
/// a while.
#[test]
fn a_registration_that_takes_over_waits_for_its_service_and_the_name() {
    let dir = crate::test_support::tempdir().unwrap();
    let path = dir.path().join("laptop.lock");
    let open = || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap()
    };
    let free = || {
        let probe = open();
        unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
    };
    let hold = || {
        let held = open();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        held
    };
    let timed_out = |error: anyhow::Error| {
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::TimedOut),
            "{error:#}"
        );
    };

    // A free name is not taken before the laptop's word.
    let (laptop, server) = UnixStream::pair().unwrap();
    let lock = open();
    timed_out(take_name(&lock, server.as_raw_fd(), Duration::from_millis(200)).unwrap_err());
    assert!(free(), "taken before the laptop's word");
    drop(laptop);
    assert!(!take_name(&lock, server.as_raw_fd(), Duration::from_secs(10)).unwrap());
    assert!(free());

    // After it, the name is taken the moment the old registration ends.
    let held = hold();
    let (mut laptop, server) = UnixStream::pair().unwrap();
    laptop.write_all(b"\n").unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let releasing = Instant::now();
        drop(held);
        releasing
    });
    let lock = open();
    assert!(take_name(&lock, server.as_raw_fd(), Duration::from_secs(10)).unwrap());
    assert!(
        Instant::now() >= release.join().unwrap(),
        "taken while held"
    );
    assert!(!free(), "the new registration holds the name");
    drop(lock);

    // A laptop that gives up, or a name that stays taken, ends the wait.
    let held = hold();
    let (mut laptop, server) = UnixStream::pair().unwrap();
    laptop.write_all(b"\n").unwrap();
    let giving_up = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(laptop);
    });
    assert!(!take_name(&open(), server.as_raw_fd(), Duration::from_secs(10)).unwrap());
    giving_up.join().unwrap();
    let (mut laptop, server) = UnixStream::pair().unwrap();
    laptop.write_all(b"\n").unwrap();
    timed_out(take_name(&open(), server.as_raw_fd(), Duration::from_millis(200)).unwrap_err());
    drop(held);
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
        let result = register("laptop", &path, "test-credential", timeout, false);
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
    let workers: &[&str] = if options.contains(&"--resource-limits") {
        &[]
    } else {
        &["--resource-limits", "workers=2"]
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
/// What the requesting server sends for a copy of `source` that `options`
/// describe: its command, and what the command read from files, here
/// nothing.
pub(super) fn requested(
    source: &Path,
    options: &[&str],
) -> (Vec<Vec<u8>>, crate::directive::Inputs) {
    (
        command(source, options),
        crate::directive::Inputs::default(),
    )
}
/// The directive the receiving machine issues for `command` under its
/// limits `caps`.
fn issued(
    command: &[Vec<u8>],
    caps: Option<crate::directive::Caps>,
) -> crate::directive::Directive {
    crate::directive::issue_here(
        crate::directive::Binding {
            enrollment: crate::enrollment::EnrollmentId::random(),
            generation: 0,
            account: "@laptop".into(),
            role: crate::directive::Role::Destination,
        },
        command.to_vec(),
        String::new(),
        (crate::directive::Inputs::default(), caps),
        [1; 32],
        START_TIMEOUT,
    )
    .unwrap()
}
/// The rules the receiving machine derives for the copy of `source` that
/// `options` describe, writing at `destination` under its limits
/// `max_entries` and `max_delete`.
fn rules(
    source: &Path,
    options: &[&str],
    destination: &Path,
    (max_entries, max_delete): (u64, u64),
) -> Result<(crate::delegation::Grant, GrantConstraints)> {
    crate::directive::receiving_rules(
        &issued(
            &command(source, options),
            Some(crate::directive::Caps {
                max_bytes: 1000,
                max_entries,
                max_delete,
            }),
        ),
        destination.as_os_str().as_bytes(),
    )
}
/// Every authority for a request works beneath the directory opened when
/// the request arrived: one that replaces that name during the prompt is
/// not where the approved copy goes.
#[test]
fn a_request_keeps_the_receiving_directory_it_opened() {
    let root = crate::test_support::tempdir().unwrap();
    let container_path = root.path().join("container");
    fs::create_dir(&container_path).unwrap();
    let directive = issued(&command(&root.path().join("source"), &[]), None);
    let output = container_path.join("output");
    let rules =
        || crate::directive::receiving_rules(&directive, output.as_os_str().as_bytes()).unwrap();
    let container = crate::restricted::Container::open(&container_path).unwrap();
    let opened = crate::rooted::Root::open(&container_path)
        .unwrap()
        .identity();
    let before = crate::restricted::receiving_authority(&container, &directive, rules()).unwrap();
    fs::rename(&container_path, root.path().join("moved")).unwrap();
    fs::create_dir(&container_path).unwrap();
    let after = crate::restricted::receiving_authority(&container, &directive, rules()).unwrap();
    assert_eq!(before.root_identity_for_test(), opened);
    assert_eq!(after.root_identity_for_test(), opened);
}

#[test]
fn named_destination_allows_128_workers_and_preserves_smaller_allowances() {
    let temporary = crate::test_support::tempdir().unwrap();
    for (requested, expected) in [(2, 2), (32, 32), (64, 64), (128, 128), (256, 128)] {
        let (grant, _) = rules(
            &temporary.path().join("source"),
            &["--resource-limits", &format!("workers={requested}")],
            temporary.path(),
            (1000, 0),
        )
        .unwrap();
        assert_eq!(grant.copy.limits.max_connections, expected);
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
    broker_with_max_delete(root, approval, 0)
}

/// The same, permitting pruning of up to `max_delete` entries per copy.
fn broker_with_max_delete(
    root: &Path,
    approval: Approval,
    max_delete: u64,
) -> (
    PrivateBroker,
    Arc<Receiver>,
    Registration,
    mpsc::Receiver<Prompt>,
) {
    broker_with_limits(root, approval, max_delete, 1000)
}

/// The same, permitting up to `max_entries` changes per copy.
pub(super) fn broker_with_limits(
    root: &Path,
    approval: Approval,
    max_delete: u64,
    max_entries: u64,
) -> (
    PrivateBroker,
    Arc<Receiver>,
    Registration,
    mpsc::Receiver<Prompt>,
) {
    broker_confined(root, approval, max_delete, max_entries, true)
}

/// A receiver starting in `root`, which is also its automatic approval root
/// and, when `confined`, its hard root.
fn broker_confined(
    root: &Path,
    approval: Approval,
    max_delete: u64,
    max_entries: u64,
    confined: bool,
) -> (
    PrivateBroker,
    Arc<Receiver>,
    Registration,
    mpsc::Receiver<Prompt>,
) {
    let (prompts, requests) = mpsc::sync_channel(1);
    let receiver = Arc::new(Receiver {
        tcp_peer: crate::conn::RemoteSpec::local_receiver(false),
        server_user: None,
        name: "laptop".into(),
        identity_key: identity::generate_key().unwrap(),
        requester: crate::receive_approval::Requester {
            server: "test-server".into(),
            profile: "test".into(),
            provider_account: None,
        },
        auto_approve_root: Some(root.into()),
        notifications: crate::receive_approval::Notifications::Off,
        approvals: Arc::new(crate::receive_approval::Queue::default()),
        generation: AtomicU64::new(0),
        cwd: root.into(),
        root: confined.then(|| root.into()),
        secret: random_token().unwrap(),
        max_bytes: 10_000_000,
        max_entries,
        max_delete,
        approval,
        prompts,
        sessions: Mutex::new(HashMap::new()),
        active_streams: Arc::new(crate::private_broker::ConnectionRegistry::new(
            Duration::from_secs(10),
        )),
        exec_count: AtomicU64::new(0),
        ssh_count: AtomicU64::new(0),
        account_relays: AtomicU64::new(0),
        account_links: Default::default(),
        account_source: Mutex::new(Err("test source not configured".into())),
        account_sessions: Mutex::new(HashMap::new()),
        forward_count: std::sync::atomic::AtomicUsize::new(0),
        request_lock: Mutex::new(()),
        stop: Arc::new(AtomicBool::new(false)),
    });
    let handler = Arc::clone(&receiver);
    let broker = PrivateBroker::start_managed(
        PrivateBrokerConfig {
            directory: BrokerDirectory::Temporary {
                prefix: "syq-named-test-",
                socket: "s",
            },
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
fn approve(
    registration: &Registration,
    command: Vec<Vec<u8>>,
    inputs: crate::directive::Inputs,
) -> Approved {
    let (_, reply) = exchange(
        registration,
        Message::Request {
            cwd: String::new(),
            command,
            inputs,
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
fn route(registration: Registration, approved: &Approved) -> String {
    format!(
        "{PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Route {
                registration,
                token: approved.token.clone(),
            })
            .unwrap()
        )
    )
}
fn control(registration: Registration, approved: &Approved) -> crate::conn::RemoteConn {
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, approved));
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
    let (command, inputs) = requested(Path::new("source"), &[]);
    let caller = std::thread::spawn(move || {
        exchange(
            &registration,
            Message::Request {
                cwd: String::new(),
                command,
                inputs,
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
    let (command, inputs) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, inputs);
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
    let (command, inputs) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, inputs);
    let conn = control(registration.clone(), &approved);
    let worker = worker_stream(&registration, &approved);
    let authority = receiver
        .sessions
        .lock()
        .unwrap()
        .get(&approved.token)
        .unwrap()
        .authority
        .receiving();
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
    let (command, inputs) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, inputs);
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
    let (command, inputs) = requested(Path::new("source"), &[]);
    let approved = approve(&registration, command, inputs);
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
    let (command, inputs) = requested(Path::new("source"), &[]);
    let approved = approve(&registration, command, inputs);
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
fn named_copy_uses_confined_workers() {
    named_copy_with_transport(false);
}

#[test]
fn named_tcp_copy_uses_confined_workers() {
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
    let (command, inputs) = requested(&source, &[]);
    let mut args = crate::approval_command::parse(&command).unwrap();
    let approved = approve(&registration, command, inputs);
    // The approval says in full where on this machine the copy goes, here
    // the profile's directory for `--into .`; the server's summary shows it.
    assert_eq!(approved.destination, root.as_os_str().as_bytes());
    // The route below replaces discovery of the named receiver.
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, &approved));
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

/// As many named sources as any copy takes, with names long enough that
/// their request is larger than an ordinary message.
#[test]
fn named_copy_takes_1024_sources_with_long_names() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let base = fs::canonicalize(temp.path()).unwrap().join("sources");
    let names: Vec<String> = (0..1024)
        .map(|i| format!("{i:04}-{}", "n".repeat(95)))
        .collect();
    let mut command = vec![b"cp".to_vec()];
    for name in &names {
        fs::create_dir_all(base.join(name)).unwrap();
        command.push(b"--src".to_vec());
        command.push(base.join(name).into_os_string().into_vec());
    }
    for arg in [
        "--to",
        "@laptop",
        "--into",
        ".",
        "--tcp-ports",
        "0-0",
        "--resource-limits",
        "workers=2",
    ] {
        command.push(arg.as_bytes().to_vec());
    }
    let mut args = crate::approval_command::parse(&command).unwrap();
    let message = serde_json::to_vec(&command).unwrap();
    assert!(message.len() > MAX_MESSAGE, "{}", message.len());
    let (_broker, _receiver, registration, _) =
        broker_with_limits(&root, Approval::Always, 0, 10_000);
    let approved = approve(&registration, command, Default::default());
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, &approved));
    assert_eq!(crate::transfer::run(args).unwrap(), 0);
    for name in &names {
        assert!(root.join(name).is_dir(), "{name}");
    }
}

/// What the receiving machine would refuse in the command alone is refused
/// on the server, before it asks or says that it waits.
#[test]
fn a_named_copy_the_receiving_machine_would_refuse_fails_before_asking() {
    let temp = crate::test_support::tempdir().unwrap();
    let registration = Registration {
        version: REGISTRATION_VERSION,
        program: b"/nonexistent/syq".to_vec(),
        identity: crate::identity::build().into(),
        // Nothing listens here: asking would fail with another error.
        socket: temp.path().join("absent.sock"),
        secret: "test".into(),
    };
    let mut many = vec![b"cp".to_vec()];
    for i in 0..crate::delegation::MAX_MUTATION_SCOPES {
        many.push(b"--src".to_vec());
        many.push(format!("source-{i}").into_bytes());
    }
    many.extend(["--to", "@laptop", "--into", "."].map(|arg| arg.as_bytes().to_vec()));
    for (command, refusal) in [
        (
            command(
                Path::new("source"),
                &["--follow-dst", "--widen-dirs", "all"],
            ),
            "--widen-dirs all cannot be combined with --follow-dst",
        ),
        (many, "its approval can list"),
    ] {
        let mut args = crate::approval_command::parse(&command).unwrap();
        args.return_selection = Some(Some(handoff::Selection::new(
            "laptop".into(),
            registration.clone(),
            handoff::Kind::Copy,
            None,
        )));
        let error = format!("{:#}", prepare(&mut args).unwrap_err());
        assert!(
            error.contains(refusal) && !error.contains("absent.sock"),
            "{error}"
        );
    }
}

/// The rules a server's command read from files may be as large as the
/// request that carries them: the receiving machine keeps the directive it
/// issues for them rather than signing or returning it, so it imposes no
/// smaller limit.
#[test]
fn a_named_copy_takes_ignore_rules_larger_than_a_signed_directive() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("kept"), b"kept").unwrap();
    fs::write(source.join("skip.tmp"), b"skipped").unwrap();
    let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
    // 600 KiB of comments, more than a signed directive's 512 KiB, then one
    // rule.
    let mut ignore: Vec<String> = (0..1024)
        .map(|i| format!("# {i:04} {}", "x".repeat(592)))
        .collect();
    ignore.push("*.tmp".into());
    let (command, _) = requested(&source, &[]);
    let mut args = crate::approval_command::parse(&command).unwrap();
    args.ignore_lines = ignore.clone();
    let approved = approve(
        &registration,
        command,
        crate::directive::Inputs {
            ignore,
            mapping: None,
        },
    );
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, &approved));
    assert_eq!(crate::transfer::run(args).unwrap(), 0);
    assert_eq!(fs::read(root.join("source/kept")).unwrap(), b"kept");
    assert!(!root.join("source/skip.tmp").exists());
}

/// Before a message is authenticated, its sender decides its size. Only a
/// few messages larger than an ordinary one are read at once; another is
/// refused as busy, and an ordinary one is still read.
#[test]
fn only_a_few_large_messages_are_read_at_once() {
    let large = (MAX_MESSAGE as u32 + 1).to_be_bytes();
    let mut held = Vec::new();
    for _ in 0..LARGE_MESSAGE_READS {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&large).unwrap();
        let reader = std::thread::spawn(move || read_message::<String>(&mut server).is_ok());
        held.push((client, reader));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while LARGE_READS.load(Ordering::Acquire) < LARGE_MESSAGE_READS {
        assert!(Instant::now() < deadline, "readers never started");
        std::thread::sleep(Duration::from_millis(5));
    }
    let message = |text: String| {
        let mut bytes = Vec::new();
        write_message(&mut bytes, &text).unwrap();
        bytes
    };
    let big = message("x".repeat(MAX_MESSAGE));
    let error = read_message::<String>(&mut &big[..]).unwrap_err();
    assert!(format!("{error:#}").contains("busy"), "{error:#}");
    assert_eq!(
        read_message::<String>(&mut &message("small".into())[..]).unwrap(),
        "small"
    );
    // A reader that ends gives its place to the next large message.
    let (client, reader) = held.pop().unwrap();
    drop(client);
    assert!(!reader.join().unwrap());
    assert_eq!(
        read_message::<String>(&mut &big[..]).unwrap().len(),
        MAX_MESSAGE
    );
    for (client, reader) in held {
        drop(client);
        assert!(!reader.join().unwrap());
    }
    assert_eq!(LARGE_READS.load(Ordering::Acquire), 0);
}

/// A large message may take longer to arrive than an ordinary one.
#[test]
fn a_large_message_may_arrive_after_the_ordinary_deadline() {
    let mut bytes = Vec::new();
    write_message(&mut bytes, &"x".repeat(MAX_MESSAGE)).unwrap();
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let reader = std::thread::spawn(move || {
        read_socket_request::<String>(&mut server, Duration::from_millis(100))
            .map(|text| text.len())
    });
    client.write_all(&bytes[..4]).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    client.write_all(&bytes[4..]).unwrap();
    assert_eq!(reader.join().unwrap().unwrap(), MAX_MESSAGE);
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
    let options = ["--copy-metadata", "mtime,permissions,ownership,specials"];
    let (grant, _) = rules(&source, &options, &root, (1000, 0)).unwrap();
    let preserved = &grant.copy.options;
    assert!(preserved.preserve_owner && preserved.preserve_group && preserved.preserve_devices);
    let (command, inputs) = requested(&source, &options);
    let mut args = crate::approval_command::parse(&command).unwrap();
    let approved = approve(&registration, command, inputs);
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, &approved));
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
fn named_requests_accept_in_place_new_and_prune_within_the_machines_limit() {
    let temporary = crate::test_support::tempdir().unwrap();
    let source = temporary.path().join("source");
    let derive = |options: &[&str], limits| rules(&source, options, temporary.path(), limits);
    let (accepted, _) = derive(&["--in-place=new"], (1000, 0)).unwrap();
    assert_eq!(
        accepted.copy.policy.publication,
        crate::delegation::PublicationPolicy::InPlaceNew
    );

    // Without --max-delete, the copy may delete what this machine allows.
    let error = derive(&["--prune"], (1000, 0)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("pruning needs a positive --max-delete"),
        "{error:#}"
    );
    let (grant, _) = derive(&["--prune"], (1000, 5)).unwrap();
    assert_eq!(grant.copy.limits.max_deletions, 5);
    let (grant, _) = derive(&["--prune"], (3, 5)).unwrap();
    assert_eq!(grant.copy.limits.max_deletions, 3);
    // The approval carries the ceiling that bounds the rules, for a dry
    // run's read-only rules too, whose own limit is zero.
    let caps = |max_entries| crate::directive::Caps {
        max_bytes: 1000,
        max_entries,
        max_delete: 5,
    };
    let (lower, _) = derive(&["--prune", "--max-delete", "2"], (1000, 5)).unwrap();
    assert_eq!(lower.copy.limits.max_deletions, 2);
    assert_eq!(caps(1000).deletion_ceiling(&lower.copy), 5);
    let (preview, _) = derive(&["--prune", "--dry-run"], (3, 5)).unwrap();
    assert_eq!(preview.copy.limits.max_deletions, 0);
    assert_eq!(caps(3).deletion_ceiling(&preview.copy), 3);

    let mut pruning = args(&source, "output");
    pruning.delete = true;
    // The sender plans against the machine's limit, or its own if lower.
    let approved = Approved {
        token: String::new(),
        destination: Vec::new(),
        max_delete: None,
    };
    for (stated, machine, planned, from_machine) in [
        (None, Some(5), Some(5), true),
        (Some(3), Some(5), Some(3), false),
        (Some(9), Some(5), Some(5), true),
        (None, None, None, false),
        (Some(9), None, Some(9), false),
    ] {
        let mut approved = approved.clone();
        approved.max_delete = machine;
        pruning.max_delete = stated;
        pruning.max_delete_from_approver = false;
        apply_deletion_limit(&mut pruning, approved.max_delete);
        assert_eq!(
            (pruning.max_delete, pruning.max_delete_from_approver),
            (planned, from_machine),
            "{stated:?} {machine:?}"
        );
    }
}

/// Pruning stays all or nothing against the receiving machine's own limit:
/// more planned deletions than it allows remove nothing, as any --max-delete.
#[test]
fn named_pruning_plans_against_the_receiving_machines_limit() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir_all(root.join("source")).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("kept"), b"kept").unwrap();
    for name in ["kept", "extra-1", "extra-2"] {
        fs::write(root.join("source").join(name), b"old").unwrap();
    }
    {
        let (_broker, _receiver, registration, _) =
            broker_with_max_delete(&root, Approval::Always, 1);
        assert_eq!(named_copy(&registration, &source, &["--prune"]), 25);
        assert!(root.join("source/extra-1").exists());
        assert!(root.join("source/extra-2").exists());
    }
    let (_broker, _receiver, registration, _) = broker_with_max_delete(&root, Approval::Always, 2);
    assert_eq!(named_copy(&registration, &source, &["--prune"]), 0);
    assert!(!root.join("source/extra-1").exists());
    assert!(!root.join("source/extra-2").exists());
    assert_eq!(fs::read(root.join("source/kept")).unwrap(), b"kept");
}

/// A dry run asks for a read-only grant, which deletes nothing, yet it
/// plans against the limit a real run would get: the machine's own.
#[test]
fn a_named_pruning_dry_run_plans_against_the_machines_limit() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir_all(root.join("source")).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("kept"), b"kept").unwrap();
    for name in ["kept", "extra-1", "extra-2"] {
        fs::write(root.join("source").join(name), b"old").unwrap();
    }
    {
        let (_broker, _receiver, registration, _) =
            broker_with_max_delete(&root, Approval::Always, 100);
        assert_eq!(
            named_copy(&registration, &source, &["--prune", "--dry-run"]),
            0
        );
    }
    let (_broker, _receiver, registration, _) = broker_with_max_delete(&root, Approval::Always, 1);
    assert_eq!(
        named_copy(&registration, &source, &["--prune", "--dry-run"]),
        25
    );
    for name in ["extra-1", "extra-2"] {
        assert!(root.join("source").join(name).exists());
    }
    assert_eq!(fs::read(root.join("source/kept")).unwrap(), b"old");
}

/// Pruning is off until the machine sets a positive --max-delete. A pruning
/// copy is refused before it is approved, and a dry run of it is refused the
/// same way, even with nothing to delete, so that it predicts the copy.
#[test]
fn a_named_pruning_dry_run_is_refused_where_pruning_is_off() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir_all(root.join("source")).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("kept"), b"kept").unwrap();
    fs::write(root.join("source/kept"), b"kept").unwrap();
    let (_broker, _receiver, registration, _) = broker_with_max_delete(&root, Approval::Always, 0);
    let reply = |options: &[&str]| {
        let (command, inputs) = requested(&source, options);
        exchange(
            &registration,
            Message::Request {
                cwd: String::new(),
                command,
                inputs,
            },
            Duration::from_secs(10),
            Some(Duration::from_secs(10)),
        )
        .map(|(_, reply)| reply)
    };
    let refusal = |options: &[&str]| match reply(options) {
        Err(error) => format!("{error:#}"),
        Ok(_) => panic!("{options:?} was approved"),
    };
    let copy = refusal(&["--prune"]);
    assert!(
        copy.contains("pruning needs a positive --max-delete"),
        "{copy}"
    );
    assert_eq!(refusal(&["--prune", "--dry-run"]), copy);
    // A dry run that does not prune, or whose own --max-delete 0 already
    // forbids deletions, is approved, as the copy would be.
    for options in [
        &["--dry-run"][..],
        &["--prune", "--max-delete", "0", "--dry-run"],
    ] {
        assert!(
            matches!(reply(options), Ok(Reply::Approved(_))),
            "{options:?}"
        );
    }
    assert!(matches!(
        reply(&["--prune", "--max-delete", "0"]),
        Ok(Reply::Approved(_))
    ));
}

/// The sender paces a copy to a receiving machine, on the bytes it sends
/// over the machine's socket or the TCP connections the machine opens: a
/// bandwidth limit is a preference of the command, not part of what the
/// machine approves, and the machine does not pace what it writes. Data
/// that compresses well goes as fast as its compressed bytes allow, which
/// pacing file data would not.
#[test]
fn a_copy_to_a_receiving_machine_is_paced_by_its_sender_on_network_bytes() {
    for tcp in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let root = temp.path().join("receiving");
        fs::create_dir(&root).unwrap();
        let source = fs::canonicalize(temp.path()).unwrap().join("source");
        fs::create_dir(&source).unwrap();
        // 6 MiB that compresses to a few kilobytes, and 512 KiB that does
        // not compress.
        fs::write(
            source.join("compressible"),
            b"syq pacing test\n".repeat(6 << 16),
        )
        .unwrap();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let random: Vec<u8> = (0..512 << 10)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        fs::write(source.join("random"), &random).unwrap();
        let (_broker, _receiver, registration, _) = broker(&root, Approval::Always);
        let (command, inputs) =
            requested(&source, &["--resource-limits", "workers=2,bandwidth=1M"]);
        let mut args = crate::approval_command::parse(&command).unwrap();
        let approved = approve(&registration, command, inputs);
        args.locations.last_mut().unwrap().host = Some("server".into());
        args.locations.last_mut().unwrap().path = approved.destination.clone();
        args.restricted_grant = Some(route(registration, &approved));
        args.no_tcp = !tcp;
        let started = Instant::now();
        assert_eq!(crate::transfer::run(args).unwrap(), 0);
        let elapsed = started.elapsed();
        assert_eq!(fs::read(root.join("source/random")).unwrap(), random);
        assert_eq!(
            fs::metadata(root.join("source/compressible"))
                .unwrap()
                .len(),
            6 << 20
        );
        // At 1 MiB/s the random half-megabyte takes half a second; pacing
        // file data would take more than six seconds for the rest.
        assert!(
            elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(5),
            "tcp {tcp}: {elapsed:?}"
        );
    }
}

/// A capped copy of a few small files to a receiving machine sends them
/// over its control connection in one turn, as an uncapped copy does, and
/// the sender paces that payload to the cap. A payload that would take over
/// a second at the cap goes through the ordinary engine instead.
#[test]
fn a_capped_small_copy_to_a_receiving_machine_takes_one_turn_within_the_cap() {
    // 384 KiB takes three quarters of a second at 512 KiB/s, and a second
    // and a half at 256 KiB/s.
    for (rate, one_turn, least) in [("512K", true, 650), ("256K", false, 1300)] {
        capped_small_copy_to_a_receiving_machine(rate, one_turn, Duration::from_millis(least));
    }
}

fn capped_small_copy_to_a_receiving_machine(rate: &str, one_turn: bool, least: Duration) {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir(&source).unwrap();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut command = vec![b"cp".to_vec()];
    let mut files = Vec::new();
    for name in ["one", "two", "three"] {
        let data: Vec<u8> = (0..128 << 10)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        fs::write(source.join(name), &data).unwrap();
        command.push(b"--src".to_vec());
        command.push(source.join(name).into_os_string().into_vec());
        files.push((name, data));
    }
    let limits = format!("workers=2,bandwidth={rate}");
    for arg in [
        "--to",
        "@laptop",
        "--into",
        ".",
        "--tcp-ports",
        "0-0",
        "--no-compress",
        "--resource-limits",
        &limits,
    ] {
        command.push(arg.as_bytes().to_vec());
    }
    let mut args = crate::approval_command::parse(&command).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let approved = approve(&registration, command, Default::default());
    let channels = Arc::clone(&receiver.sessions.lock().unwrap()[&approved.token].channels);
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration, &approved));
    // Over SSH alone, the ordinary engine's workers would open channels too.
    args.no_tcp = true;
    let started = Instant::now();
    assert_eq!(crate::transfer::run(args).unwrap(), 0);
    let elapsed = started.elapsed();
    for (name, data) in &files {
        assert_eq!(&fs::read(root.join(name)).unwrap(), data, "{rate}: {name}");
    }
    assert_eq!(channels.opened() == 1, one_turn, "{rate}: workers opened");
    assert!(
        elapsed >= least && elapsed < Duration::from_secs(10),
        "{rate}: {elapsed:?}"
    );
}

/// Approve the next copy `receiver` asks about, returning what it showed.
fn approve_pending(receiver: &Arc<Receiver>) -> std::thread::JoinHandle<String> {
    let approvals = receiver.approvals.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(summary) = approvals.snapshots().into_iter().next() {
                let description =
                    summary.description(&crate::persistence::Domain::default(), str::to_owned);
                approvals
                    .decide(&summary.id, true, crate::receive_approval::Kind::Copy)
                    .unwrap();
                return description;
            }
            assert!(Instant::now() < deadline, "no copy approval was requested");
            std::thread::sleep(Duration::from_millis(20));
        }
    })
}

/// Run the copy of `source` that `options` describe through `registration`.
fn named_copy(registration: &Registration, source: &Path, options: &[&str]) -> i32 {
    let (command, inputs) = requested(source, options);
    let mut args = crate::approval_command::parse(&command).unwrap();
    let approved = approve(registration, command, inputs);
    // As `prepare` does with the approval.
    apply_deletion_limit(&mut args, approved.max_delete);
    args.locations.last_mut().unwrap().host = Some("server".into());
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.restricted_grant = Some(route(registration.clone(), &approved));
    crate::transfer::run(args).unwrap()
}

/// Hard links can join files already in the destination, so even a
/// download into the automatically approved directory asks, and the prompt
/// says so. A rerun links a new name to the file the first copy left.
#[test]
fn named_hard_links_ask_and_link_new_names_to_existing_files() {
    use std::os::unix::fs::MetadataExt;
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("a"), b"shared").unwrap();
    fs::hard_link(source.join("a"), source.join("b")).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let options = ["--copy-metadata", "mtime,hardlinks"];

    let shown = approve_pending(&receiver);
    assert_eq!(named_copy(&registration, &source, &options), 0);
    let shown = shown.join().unwrap();
    assert!(
        shown.contains("The server can link new names to files already in the destination."),
        "{shown}"
    );
    let inode = |name: &str| fs::metadata(root.join("source").join(name)).unwrap().ino();
    assert_eq!(inode("a"), inode("b"));

    fs::hard_link(source.join("a"), source.join("c")).unwrap();
    let existing = inode("a");
    let shown = approve_pending(&receiver);
    assert_eq!(named_copy(&registration, &source, &options), 0);
    shown.join().unwrap();
    assert_eq!(
        (inode("a"), inode("b"), inode("c")),
        (existing, existing, existing)
    );
}

/// Keeping existing files, a hard-link group with an existing member ends
/// as rsync leaves it: the existing name and its file untouched, and the
/// group's new names linked to a new file of their own.
#[test]
fn named_hard_links_keep_an_existing_group_member_untouched() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir_all(root.join("source")).unwrap();
    let source = fs::canonicalize(temp.path()).unwrap().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("a"), b"source contents").unwrap();
    fs::hard_link(source.join("a"), source.join("b")).unwrap();
    fs::hard_link(source.join("a"), source.join("c")).unwrap();
    fs::write(root.join("source/a"), b"kept").unwrap();
    fs::set_permissions(root.join("source/a"), fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::metadata(root.join("source/a")).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let shown = approve_pending(&receiver);
    assert_eq!(
        named_copy(
            &registration,
            &source,
            &["--if-exists=keep", "--copy-metadata", "mtime,hardlinks"],
        ),
        0
    );
    shown.join().unwrap();
    let after = fs::metadata(root.join("source/a")).unwrap();
    assert_eq!(fs::read(root.join("source/a")).unwrap(), b"kept");
    assert_eq!(
        (after.ino(), after.mode(), after.nlink(), after.mtime()),
        (before.ino(), before.mode(), 1, before.mtime())
    );
    let new = |name: &str| fs::metadata(root.join("source").join(name)).unwrap();
    assert_eq!(fs::read(root.join("source/b")).unwrap(), b"source contents");
    assert_eq!(new("b").ino(), new("c").ino());
    assert_ne!(new("b").ino(), after.ino());
}

/// Extended attributes reach as an ordinary copy by the same account: the
/// user namespace, with values the source lacks removed.
#[cfg(target_os = "linux")]
#[test]
fn named_extended_attributes_ask_and_reconcile_the_user_namespace() {
    use std::ffi::CString;
    let attributes = |path: &Path| {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut names = vec![0u8; 4096];
        let length =
            unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
        assert!(length >= 0, "{}", std::io::Error::last_os_error());
        names.truncate(length as usize);
        let mut found = names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(|name| {
                let name = CString::new(name).unwrap();
                let mut value = vec![0u8; 4096];
                let length = unsafe {
                    libc::lgetxattr(
                        path.as_ptr(),
                        name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                    )
                };
                assert!(length >= 0);
                value.truncate(length as usize);
                (name.into_bytes(), value)
            })
            .collect::<Vec<_>>();
        found.sort();
        found
    };
    let set = |path: &Path, name: &str, value: &[u8]| {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = CString::new(name).unwrap();
        let result = unsafe {
            libc::lsetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    };
    let temp = crate::test_support::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let source = base.join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), b"attributes").unwrap();
    set(&source.join("file"), "user.kept", b"value");
    let root = base.join("receiving");
    fs::create_dir_all(root.join("source")).unwrap();
    fs::write(root.join("source/file"), b"old").unwrap();
    set(&root.join("source/file"), "user.stale", b"old");
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let shown = approve_pending(&receiver);
    assert_eq!(
        named_copy(&registration, &source, &["--copy-metadata", "mtime,xattrs"]),
        0
    );
    // The prompt says why it asks.
    let shown = shown.join().unwrap();
    assert!(
        shown.contains("The server can set extended attributes, which some programs act on."),
        "{shown}"
    );
    // As `tests/local/inode_metadata.rs` checks for ordinary copies: the
    // source's user attributes, and none the source lacks.
    assert_eq!(
        attributes(&root.join("source/file")),
        [(b"user.kept".to_vec(), b"value".to_vec())]
    );
}

#[test]
fn named_authorization_expires_before_control_opens() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().join("receiving");
    fs::create_dir(&root).unwrap();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, inputs) = requested(Path::new("source"), &[]);
    let approved = approve(&registration, command, inputs);
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
    let ask = |command: Vec<Vec<u8>>, inputs| {
        exchange(
            &registration,
            Message::Request {
                cwd: String::new(),
                command,
                inputs,
            },
            Duration::from_secs(2),
            Some(Duration::from_secs(2)),
        )
        .map(drop)
    };
    // A destination outside the receiving root, an ignore rule out of
    // bounds, and a mapping the command does not name.
    let (outside, inputs) = requested(Path::new("source"), &["--into", "../outside"]);
    assert!(ask(outside, inputs).is_err());
    let (command, _) = requested(Path::new("source"), &[]);
    assert!(ask(
        command.clone(),
        crate::directive::Inputs {
            ignore: vec!["bad\0rule".into()],
            mapping: None,
        }
    )
    .is_err());
    assert!(ask(
        command,
        crate::directive::Inputs {
            ignore: Vec::new(),
            mapping: Some(crate::mapping::Authorization::from_contents(b"{}")),
        }
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
    let resolved = |path: &[u8], follow: bool| {
        resolve_destination(&cwd, None, path, follow, None).map(|(destination, _)| destination)
    };
    for follow in [false, true] {
        assert_eq!(resolved(b"../file", follow).unwrap(), temp.join("file"));
        assert_eq!(
            resolved(outside.join("file").as_os_str().as_bytes(), follow).unwrap(),
            outside.join("file")
        );
        // The final entry is never followed.
        assert_eq!(resolved(b"link", follow).unwrap(), cwd.join("link"));
        assert_eq!(
            resolved(b"missing/deeper/file", follow).unwrap(),
            cwd.join("missing/deeper/file")
        );
    }
    // As in any copy, a symlink above the destination stops it unless the
    // command follows destination paths.
    for path in [
        &b"link/file"[..],
        b"link/../file",
        b"./link/sub/file",
        b"missing/../link/file",
    ] {
        let error = resolved(path, false).unwrap_err().to_string();
        assert!(
            error.starts_with("refusing to follow symlink \"link\" in a path you gave; ")
                && error.contains("--follow-dst"),
            "{error}"
        );
    }
    let through = cwd.join("link/file");
    assert!(resolved(through.as_os_str().as_bytes(), false).is_err());
    assert_eq!(resolved(b"link/file", true).unwrap(), outside.join("file"));
    assert_eq!(resolved(b"link/../file", true).unwrap(), temp.join("file"));
    assert_eq!(
        resolved(through.as_os_str().as_bytes(), true).unwrap(),
        outside.join("file")
    );
    assert!(resolve_destination(&cwd, Some(&cwd), b"../file", false, None).is_err());
    assert!(resolve_destination(
        &cwd,
        Some(&cwd),
        outside.as_os_str().as_bytes(),
        false,
        None
    )
    .is_err());
    assert_eq!(
        resolve_destination(&cwd, Some(&cwd), b"child/file", false, None)
            .unwrap()
            .0,
        cwd.join("child/file")
    );
}

/// With `--follow-dst`, a copy to the laptop follows a link above its
/// destination that another account made in a sticky directory anyone can
/// write to, such as /tmp, only as the kernel would: not at all.
#[test]
fn a_laptop_destination_does_not_follow_another_accounts_link_in_tmp() {
    let temp = crate::test_support::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let Some(shared) = crate::test_support::SharedDirectoryLink::new(&target) else {
        eprintln!("skipped: no sticky directory another account owns");
        return;
    };
    let named = shared.0.join("sub/file");
    let resolve = || {
        resolve_destination(
            Path::new("/"),
            None,
            named.as_os_str().as_bytes(),
            true,
            None,
        )
    };
    assert_eq!(
        resolve().unwrap(),
        (target.join("sub/file"), target.clone())
    );
    let other = crate::rooted::own_uid().wrapping_add(1);
    crate::rooted::FOLLOWER_FOR_TEST.with(|cell| cell.set(Some(other)));
    let refused = resolve();
    crate::rooted::FOLLOWER_FOR_TEST.with(|cell| cell.set(None));
    let error = format!("{:#}", refused.unwrap_err());
    assert!(error.contains("anyone can write to"), "{error}");
}

/// A copy to the laptop refuses a symlink above its destination unless its
/// command passes `--follow-dst`, as any copy does; then the destination is
/// where the link leads, and the prompt says so.
#[test]
fn a_symlink_above_a_laptop_destination_needs_follow_dst() {
    let temp = crate::test_support::tempdir().unwrap();
    let temp = fs::canonicalize(temp.path()).unwrap();
    let cwd = temp.join("downloads");
    fs::create_dir(&cwd).unwrap();
    let outside = temp.join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, cwd.join("link")).unwrap();
    let (_broker, receiver, registration, _) =
        broker_confined(&cwd, Approval::Always, 0, 1000, false);
    let command = |follow: bool| -> Vec<Vec<u8>> {
        [
            "cp", "--src", "source", "--to", "@laptop", "--into", "link/sub",
        ]
        .into_iter()
        .chain(follow.then_some("--follow-dst"))
        .chain(["--tcp-ports", "0-0", "--resource-limits", "workers=2"])
        .map(|arg| arg.as_bytes().to_vec())
        .collect()
    };
    let ask = |command: Vec<Vec<u8>>| {
        let registration = registration.clone();
        std::thread::spawn(move || {
            exchange(
                &registration,
                Message::Request {
                    cwd: String::new(),
                    command,
                    inputs: Default::default(),
                },
                Duration::from_secs(10),
                Some(Duration::from_secs(10)),
            )
        })
    };
    let error = ask(command(false)).join().unwrap().err().unwrap();
    assert!(
        format!("{error:#}").contains("refusing to follow symlink \"link\" in a path you gave"),
        "{error:#}"
    );
    assert!(receiver.approvals.snapshots().is_empty());
    // Following, the copy goes where the link leads, outside the automatic
    // approval root, so it asks.
    let task = ask(command(true));
    let deadline = Instant::now() + Duration::from_secs(5);
    let pending = loop {
        if let Some(summary) = receiver.approvals.snapshots().first() {
            break summary.clone();
        }
        assert!(Instant::now() < deadline, "the copy did not ask");
        std::thread::sleep(Duration::from_millis(5));
    };
    let destination = outside.join("sub");
    assert_eq!(
        serde_json::to_value(&pending).unwrap()["destination"],
        format!("{destination:?}")
    );
    receiver
        .approvals
        .decide(&pending.id, true, crate::receive_approval::Kind::Copy)
        .unwrap();
    let (_, reply) = task.join().unwrap().unwrap();
    let Reply::Approved(approved) = reply else {
        panic!("no approval");
    };
    assert_eq!(approved.destination, destination.as_os_str().as_bytes());
}

/// A path in the home directory starts where the home really is, so links
/// in the home's own path work; a link inside the home still stops the copy.
#[test]
fn receiving_destinations_in_the_home_start_where_it_is() {
    let temp = crate::test_support::tempdir().unwrap();
    let temp = fs::canonicalize(temp.path()).unwrap();
    let real_home = temp.join("var/home/me");
    fs::create_dir_all(real_home.join("inbox")).unwrap();
    std::os::unix::fs::symlink(temp.join("var/home"), temp.join("home")).unwrap();
    let home = temp.join("home/me");
    std::os::unix::fs::symlink(real_home.join("inbox"), real_home.join("linked")).unwrap();
    let cwd = temp.join("downloads");
    fs::create_dir(&cwd).unwrap();
    let resolved = |path: &Path| {
        resolve_destination(
            &cwd,
            None,
            path.as_os_str().as_bytes(),
            false,
            Some((&home, &real_home)),
        )
    };
    let (destination, container) = resolved(&home.join("inbox/file")).unwrap();
    assert_eq!(destination, real_home.join("inbox/file"));
    assert_eq!(container, real_home.join("inbox"));
    let error = resolved(&home.join("linked/file")).unwrap_err().to_string();
    assert!(
        error.starts_with("refusing to follow symlink \"linked\""),
        "{error}"
    );
    // Outside the home, the same link in its path stops the copy.
    fs::create_dir(temp.join("var/home/other")).unwrap();
    let error = resolved(&temp.join("home/other/file"))
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("refusing to follow symlink \"home\""),
        "{error}"
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
    assert!(read_socket_framed::<Envelope>(
        &mut reader,
        Duration::from_millis(100),
        MAX_MESSAGE,
        "named destination message"
    )
    .is_err());
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
        let (command, inputs) = requested(Path::new("source"), &["--no-compress"]);
        let approved = approve(&registration, command, inputs);
        let authority = receiver.sessions.lock().unwrap()[&approved.token]
            .authority
            .receiving();
        let mut spec = crate::conn::RemoteSpec::local_receiver(true);
        spec.restricted_grant = Some(route(registration, &approved));
        let mut control = spec.connect_with(false, false).unwrap();
        if tcp {
            let pending = spec
                .begin_tcp_setup(&mut control, false, (0, 0), None, None)
                .unwrap();
            spec.finish_tcp_setup(pending).unwrap();
        }
        let mut worker = crate::conn::Endpoint::Remote(spec.clone())
            .connect_with_copy_capabilities(false, None, Vec::new(), false, None)
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
        let (command, inputs) = requested(
            Path::new("source"),
            &["--no-compress", "--resource-limits", "workers=1"],
        );
        let approved = approve(&registration, command, inputs);
        let mut spec = crate::conn::RemoteSpec::local_receiver(true);
        spec.restricted_grant = Some(route(registration, &approved));
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
            .connect_with_copy_capabilities(false, None, Vec::new(), false, None)
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
    let (command, inputs) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, inputs);
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, &approved));
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
        .connect_with_copy_capabilities(false, None, Vec::new(), false, None)
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
    let (command, inputs) = requested(
        Path::new("source"),
        &["--no-compress", "--resource-limits", "workers=8"],
    );
    let approved = approve(&registration, command, inputs);
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, &approved));
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
                    .connect_with_copy_capabilities(false, None, Vec::new(), false, None)
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
    let (command, inputs) = requested(
        Path::new("source"),
        &["--no-compress", "--resource-limits", "workers=1"],
    );
    let approved = approve(&registration, command, inputs);
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, &approved));
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
        .connect_with_copy_capabilities(false, None, Vec::new(), false, None)
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
fn data_hostnames_reject_options_paths_and_config_syntax() {
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

/// A copy to a named destination does not follow a destination symlink:
/// its rules never follow one, even with `--follow-dst` (or `--follow`,
/// whose source following stays the sender's). The receiving machine
/// follows the command's links above the destination when it resolves it.
#[test]
fn named_rules_never_follow_the_destination() {
    for follow in ["--follow-dst", "--follow"] {
        let (_, constraints) = rules(
            Path::new("source"),
            &[follow],
            Path::new("/receiving"),
            (1000, 0),
        )
        .unwrap();
        assert!(!constraints.extra_options.follow_dst, "{follow}");
    }
}

#[test]
fn a_rejected_login_waits_longer_each_time_up_to_ten_minutes() {
    let mut wait = super::LOGIN_RETRY_FIRST;
    let mut shown = Vec::new();
    for _ in 0..7 {
        shown.push(super::retry_wait(wait));
        wait = super::next_login_retry(wait);
    }
    assert_eq!(
        shown,
        ["30 s", "60 s", "2 min", "4 min", "8 min", "10 min", "10 min"]
    );
    // Times left are rounded up to whole seconds, then to the nearest
    // minute from two minutes on.
    let wait = |millis| super::retry_wait(std::time::Duration::from_millis(millis));
    assert_eq!(
        [
            wait(0),
            wait(1),
            wait(29_001),
            wait(119_000),
            wait(149_000),
            wait(151_000)
        ],
        ["0 s", "1 s", "30 s", "119 s", "2 min", "3 min"]
    );
}

/// When the receiving machine's probe of a named route reaches none of the
/// coordinator's addresses, it answers with no route rather than an error,
/// so the coordinator says the copy falls back as it does on any route. It
/// waits only as long as the coordinator asks.
#[test]
fn a_named_route_probe_that_reaches_nothing_answers_with_no_route() {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path().to_path_buf();
    let (_broker, receiver, registration, _) = broker(&root, Approval::Always);
    let (command, inputs) = requested(Path::new("source"), &["--no-compress"]);
    let approved = approve(&registration, command, inputs);
    let mut spec = crate::conn::RemoteSpec::local_receiver(true);
    spec.restricted_grant = Some(route(registration, &approved));
    let _control = spec.connect_with(false, false).unwrap();
    // Opening the control channel measured the round trip that bounds the
    // receiving machine's probes, rather than leaving them the full second.
    assert!(spec.diagnostics().route_round_trip.is_some());
    // On Linux a listener whose accept queue is full drops new connections
    // without answering; elsewhere a closed port refuses them.
    #[cfg(target_os = "linux")]
    let (port, _held) = {
        use socket2::{Domain, Socket, Type};
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        listener
            .bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        listener.listen(0).unwrap();
        let address = listener.local_addr().unwrap().as_socket().unwrap();
        let queued =
            std::net::TcpStream::connect_timeout(&address, Duration::from_secs(10)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        (address.port(), Some((listener, queued)))
    };
    #[cfg(not(target_os = "linux"))]
    let (port, _held) = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        (listener.local_addr().unwrap().port(), None::<()>)
    };
    let started = Instant::now();
    let candidates = tcp::probe(
        spec.restricted_grant.as_deref().unwrap(),
        port,
        (0, 0),
        vec![("127.0.0.1".into(), 0)],
        None,
        crate::conn::TCP_PROBE_FLOOR,
    )
    .unwrap();
    let elapsed = started.elapsed();
    receiver.revoke_all();
    assert!(
        candidates.iter().all(|candidate| !candidate.selected),
        "{candidates:?}"
    );
    assert!(elapsed < Duration::from_millis(800), "{elapsed:?}");
}

/// This machine sets up TCP for a copy sent to it only when the copy's
/// command lets the data go over TCP: with `--no-tcp` it refuses to probe
/// the coordinator's listener, so no TCP data connection is made.
#[test]
fn a_copy_sent_here_gets_tcp_only_when_its_command_allows_it() {
    for no_tcp in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(temp.path(), Approval::Always);
        let options: &[&str] = if no_tcp {
            &["--no-compress", "--no-tcp"]
        } else {
            &["--no-compress"]
        };
        let (command, inputs) = requested(Path::new("source"), options);
        let approved = approve(&registration, command, inputs);
        let mut spec = crate::conn::RemoteSpec::local_receiver(true);
        spec.restricted_grant = Some(route(registration, &approved));
        let _control = spec.connect_with(false, false).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let probed = tcp::probe(
            spec.restricted_grant.as_deref().unwrap(),
            listener.local_addr().unwrap().port(),
            (0, 0),
            vec![("127.0.0.1".into(), 0)],
            None,
            crate::conn::TCP_PROBE_FLOOR,
        );
        let set_up = receiver.sessions.lock().unwrap()[&approved.token]
            .tcp
            .is_some();
        receiver.revoke_all();
        if no_tcp {
            let error = probed.unwrap_err();
            assert!(
                format!("{error:#}").contains("passes --no-tcp,"),
                "{error:#}"
            );
            assert!(!set_up);
        } else {
            let candidates = probed.unwrap();
            assert!(
                candidates.iter().any(|candidate| candidate.selected),
                "{candidates:?}"
            );
            assert!(set_up);
        }
    }
}

/// A receiving connection counts as idle, for its service to switch builds,
/// only once no request is in progress and none arrived for a quiet while:
/// one copy's steps arrive as separate requests. Once its service closes it
/// to stop, it refuses new requests.
#[test]
fn a_receiving_connection_is_idle_only_after_its_requests_and_a_quiet_while() {
    let activity = Activity {
        quiet: Duration::from_millis(200),
        ..Default::default()
    };
    assert!(activity.idle());
    let request = activity.begin().unwrap();
    assert_eq!(activity.requests(), 1);
    assert!(!activity.idle());
    assert!(!activity.close_if_idle());
    drop(request);
    assert_eq!(activity.requests(), 0);
    // A copy's next step may still come.
    assert!(!activity.idle());
    assert!(!activity.close_if_idle());
    std::thread::sleep(Duration::from_millis(250));
    assert!(activity.idle());
    assert!(activity.close_if_idle());
    activity.close();
    assert!(activity.begin().is_none());
    activity.reopen();
    assert!(activity.begin().is_some());
}

/// An approved account connection is counted apart from other requests,
/// for as long as its relay runs, so that status can say what keeps the
/// connection busy.
#[test]
fn open_account_connections_are_counted_apart() {
    let temporary = crate::test_support::tempdir().unwrap();
    let (_broker, receiver, _registration, _prompts) = broker(temporary.path(), Approval::Ask);
    let activity = Activity::default();
    *activity.receiver.lock().unwrap() = Arc::downgrade(&receiver);
    assert_eq!(activity.accounts().open, 0);
    // The relay runs within a request.
    let request = activity.begin().unwrap();
    receiver.account_relays.fetch_add(1, Ordering::AcqRel);
    assert_eq!((activity.requests(), activity.accounts().open), (1, 1));
    assert!(!activity.idle());
    receiver.account_relays.fetch_sub(1, Ordering::AcqRel);
    drop(request);
    assert_eq!((activity.requests(), activity.accounts().open), (0, 0));
}

/// An approved account connection that says nothing uses it does not keep
/// the connection busy, and ends when the service stops to switch; one in
/// use keeps it, as before.
#[test]
fn an_account_connection_nothing_uses_ends_at_a_switch() {
    use ssh_auth::{LinkReply, LinkRequest};
    for used in [false, true] {
        let temporary = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, _registration, _prompts) = broker(temporary.path(), Approval::Ask);
        let activity = Activity {
            quiet: Duration::from_millis(200),
            ..Default::default()
        };
        *activity.receiver.lock().unwrap() = Arc::downgrade(&receiver);
        // The relay runs within a request, as the approved login's does.
        let request = activity.begin().unwrap();
        receiver.account_relays.fetch_add(1, Ordering::AcqRel);
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        let end = ours.try_clone().unwrap();
        let answers = Arc::new(AtomicUsize::new(0));
        let answered = answers.clone();
        let keeper = std::thread::spawn(move || {
            let ack = crate::agent_broker::read_frame(&mut theirs)
                .unwrap()
                .unwrap();
            assert!(ack.starts_with(b"\0"));
            while let Ok(Some(frame)) = crate::agent_broker::read_frame(&mut theirs) {
                let request: LinkRequest = serde_json::from_slice(&frame).unwrap();
                let reply = match (request, used) {
                    (_, true) => LinkReply::InUse,
                    (LinkRequest::Query, false) => LinkReply::Idle,
                    (LinkRequest::CloseIfIdle, false) => LinkReply::Closing,
                };
                crate::agent_broker::write_frame(&mut theirs, &serde_json::to_vec(&reply).unwrap())
                    .unwrap();
                answered.fetch_add(1, Ordering::AcqRel);
            }
        });
        let serving = receiver.clone();
        let server = std::thread::spawn(move || {
            let result = serving.account_links.serve(&mut ours, &|| false);
            serving.account_relays.fetch_sub(1, Ordering::AcqRel);
            result
        });
        // Asking how many are idle asks the connection.
        let deadline = Instant::now() + Duration::from_secs(10);
        while answers.load(Ordering::Acquire) == 0 {
            assert!(Instant::now() < deadline);
            activity.accounts();
            std::thread::sleep(Duration::from_millis(10));
        }
        // A copy's next step may still come for a moment after a request.
        std::thread::sleep(Duration::from_millis(250));
        let accounts = activity.accounts();
        assert_eq!((accounts.open, accounts.reporting), (1, 1));
        assert_eq!(accounts.idle, usize::from(!used));
        assert_eq!(activity.idle(), !used);
        assert_eq!(activity.close_if_idle(), !used);
        let close = || {
            activity
                .close_accounts()
                .unwrap()
                .wait(Instant::now() + Duration::from_secs(5))
        };
        if used {
            assert!(!close());
            assert_eq!(receiver.account_links.len(), 1);
            end.shutdown(std::net::Shutdown::Both).unwrap();
        } else {
            assert!(close());
        }
        server.join().unwrap().unwrap();
        drop(end);
        keeper.join().unwrap();
        drop(request);
        assert_eq!(activity.accounts().open, 0);
    }
}

/// A request that arrives while the service tentatively closes the
/// connection waits for the decision: it goes ahead if the connection
/// stays open, and is refused only once it closes for good.
#[test]
fn a_request_during_a_tentative_close_waits_for_the_decision() {
    for stays_open in [true, false] {
        let activity = Arc::new(Activity {
            quiet: Duration::ZERO,
            ..Default::default()
        });
        assert!(activity.close_if_idle());
        let asking = {
            let activity = activity.clone();
            std::thread::spawn(move || activity.begin().is_some())
        };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!asking.is_finished());
        if stays_open {
            activity.reopen();
        } else {
            activity.close();
        }
        assert_eq!(asking.join().unwrap(), stays_open);
    }
}
