use super::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;

fn domain(root: &Path, name: &str) -> Domain {
    let path = root.join(name);
    crate::persistence::initialize_scope(&path).unwrap();
    Domain::select(Some(&path)).unwrap()
}
fn endpoint() -> NativeEndpoint {
    NativeEndpoint {
        user: Some("user".into()),
        host: "host.invalid".into(),
        port: Some(22),
    }
}
fn new_record(domain: &Domain) -> Record {
    let scope = domain.runtime_path().join("approved-test");
    crate::persistence::initialize_scope(&scope).unwrap();
    let endpoint = endpoint();
    let control = crate::persistence::prepare_endpoint(
        &scope,
        endpoint.user.as_deref(),
        &endpoint.host,
        endpoint.port,
        None,
    )
    .unwrap();
    Record {
        version: 1,
        authorizer: Provider::Return("laptop".into()),
        requested: endpoint.clone(),
        endpoint,
        control,
    }
}
fn private_write(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn selected_domains_have_independent_account_generations_and_indices() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let first = domain(root.path(), "a");
    let second = domain(root.path(), "b");
    let first_generation = ensure_generation(&first).unwrap();
    let second_generation = ensure_generation(&second).unwrap();
    assert_ne!(first_generation, second_generation);
    assert_ne!(
        index_path(&first, "laptop", &endpoint()).unwrap(),
        index_path(&second, "laptop", &endpoint()).unwrap()
    );
    assert_eq!(
        Domain::Global.approved_index_path(),
        crate::persistence::runtime_parent_path().join("authorized-ssh-v1")
    );
    stop_all(&first).unwrap();
    assert!(!generation_open(&first, &first_generation).unwrap());
    assert!(generation_open(&second, &second_generation).unwrap());
    assert_ne!(ensure_generation(&first).unwrap(), first_generation);
    assert!(cached(&first, "laptop", &endpoint()).unwrap().is_none());
    assert!(cached(&second, "laptop", &endpoint()).unwrap().is_none());
}

#[test]
fn scoped_records_cannot_borrow_another_scope_or_legacy_generation() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let first = domain(root.path(), "a");
    let second = domain(root.path(), "b");
    let record = new_record(&first);
    validate_record(&first, &record).unwrap();
    assert!(validate_record(&second, &record).is_err());
    assert!(validate_record(&Domain::Global, &record).is_err());
    let _socket = UnixListener::bind(&record.control).unwrap();
    // A new scoped domain has no pre-generation legacy records to reuse.
    assert!(active_record(&first, record).unwrap().is_none());
    let record = new_record(&second);
    let _other_socket = UnixListener::bind(&record.control).unwrap();
    let first_generation = ensure_generation(&first).unwrap();
    ensure_generation(&second).unwrap();
    private_write(
        &record.control.with_extension("generation"),
        first_generation.as_bytes(),
    );
    assert!(active_record(&second, record).unwrap().is_none());
}

#[test]
fn warm_account_lookup_checks_local_socket_readiness() {
    // Nested scopes and OpenSSH's socket suffix exceed Darwin's ambient
    // TMPDIR path budget; use the same short root as other scoped socket tests.
    let root = tempfile::tempdir_in(fs::canonicalize("/tmp").unwrap()).unwrap();
    let domain = domain(root.path(), "a");
    let record = new_record(&domain);
    let control = record.control.clone();
    let generation = ensure_generation(&domain).unwrap();
    private_write(&control.with_extension("generation"), generation.as_bytes());
    let record = || Record {
        version: 1,
        authorizer: Provider::Return("laptop".into()),
        requested: endpoint(),
        endpoint: endpoint(),
        control: control.clone(),
    };
    assert!(active_record(&domain, record()).unwrap().is_none());
    let listen = || {
        let listener = crate::process::with_inheritance_guard(|| {
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        })
        .unwrap();
        listener
            .bind(&socket2::SockAddr::unix(&control).unwrap())
            .unwrap();
        listener.listen(1).unwrap();
        listener
    };
    let listener = listen();
    assert!(active_record(&domain, record()).unwrap().is_some());
    drop(listener);
    fs::remove_file(&control).unwrap();
    let listener = listen();
    let started = Instant::now();
    let mut clients = Vec::new();
    let mut saturated = None;
    for _ in 0..128 {
        let client = crate::process::with_inheritance_guard(|| {
            socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        })
        .unwrap();
        client.set_nonblocking(true).unwrap();
        match client.connect(&socket2::SockAddr::unix(&control).unwrap()) {
            Ok(()) => clients.push(client),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::ConnectionRefused
                ) || error.raw_os_error() == Some(libc::EINPROGRESS) =>
            {
                saturated = Some(error);
                break;
            }
            other => panic!("unexpected local socket connect: {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    let saturated = saturated.expect("fixture listen queue did not fill");
    assert!(!clients.is_empty());
    // Keep connected clients alive: closed, unaccepted connections do not
    // occupy the listen queue consistently across operating systems.
    if saturated.kind() == std::io::ErrorKind::ConnectionRefused {
        // Darwin reports the same errno for a full queue and a stale socket.
        // Preserve its previous refused-connection behavior, without claiming
        // that the local readiness check can distinguish those cases.
        assert!(!crate::persistence::socket_is_ready(&control).unwrap());
        assert!(active_record(&domain, record()).unwrap().is_none());
    } else {
        assert!(crate::persistence::socket_is_ready(&control).is_err());
        let error = active_record(&domain, record())
            .err()
            .expect("busy master must not reconnect");
        assert!(
            error.to_string().contains("temporarily unavailable"),
            "{error:#}"
        );
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(
        control.exists(),
        "unavailable master path must remain intact"
    );
    drop(listener);
    assert!(control.exists());
    // A parallel test may have forked with a copy of this close-on-exec
    // listener. The saturated queue remains busy until that child execs or
    // exits, even though this thread has closed its last descriptor.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut progress = Instant::now();
    loop {
        let state = match active_record(&domain, record()) {
            Ok(None) => break,
            Ok(Some(_)) => "inherited listener still accepts connections".to_owned(),
            Err(error) => {
                assert!(
                    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                        error.kind() == std::io::ErrorKind::WouldBlock
                            || error.raw_os_error() == Some(libc::EINPROGRESS)
                    }),
                    "unexpected stale master error: {error:#}"
                );
                format!("{error:#}")
            }
        };
        assert!(
            Instant::now() < deadline,
            "closed listener did not become stale within five seconds: {state}"
        );
        if progress.elapsed() >= Duration::from_secs(1) {
            eprintln!("waiting for inherited test listener to close: {state}");
            progress = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::remove_file(&control).unwrap();
    assert!(active_record(&domain, record()).unwrap().is_none());
    drop(clients);
}

#[test]
fn scoped_index_refuses_links_to_another_domain() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let first = domain(root.path(), "a");
    let second = domain(root.path(), "b");
    let destination = directory(&first).unwrap();
    std::os::unix::fs::symlink(destination, second.approved_index_path()).unwrap();
    assert!(directory(&second).is_err());
    assert!(cached(&second, "laptop", &endpoint()).is_err());
}

#[test]
fn startup_retains_default_encoding_and_does_not_survive_scoped_recreation() {
    let old = r#"{"command":[],"authorizer":"laptop","requested":{"user":null,"host":"alias","port":null},"generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    let old: Startup = serde_json::from_str(old).unwrap();
    assert!(old.scope.is_none());
    assert!(old.scope_identity.is_none());
    let encoded = serde_json::to_value(old).unwrap();
    assert!(encoded.get("scope").is_none());
    assert!(encoded.get("scope_identity").is_none());
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let domain = domain(root.path(), "a");
    let startup = Startup {
        command: Vec::new(),
        authorizer: Provider::Return("laptop".into()),
        requested: endpoint(),
        generation: ensure_generation(&domain).unwrap(),
        selected: None,
        proxy: None,
        scope: domain.explicit_path().map(Path::to_path_buf),
        scope_identity: Some(domain.identity().unwrap()),
    };
    assert!(startup_open(&domain, &startup).unwrap());
    private_write(
        &domain.runtime_path().join(crate::receive_service::CLOSING),
        b"",
    );
    assert!(!startup_open(&domain, &startup).unwrap());
    fs::rename(domain.runtime_path(), root.path().join("old")).unwrap();
    crate::persistence::initialize_scope(&domain.runtime_path()).unwrap();
    // Even copying the generation cannot resurrect a removed domain identity.
    directory(&domain).unwrap();
    private_write(&generation_path(&domain), startup.generation.as_bytes());
    assert!(!startup_open(&domain, &startup).unwrap());
}

#[test]
fn off_cleans_only_selected_stale_account_state_and_keeps_other_domains() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let first = domain(root.path(), "a");
    let second = domain(root.path(), "b");
    ensure_generation(&first).unwrap();
    let second_generation = ensure_generation(&second).unwrap();
    let record = new_record(&first);
    let control_dir = record.control.parent().unwrap().to_owned();
    // An exited native master can leave a stale socket after a crash.
    drop(UnixListener::bind(&record.control).unwrap());
    private_write(
        &record.control.with_extension("generation"),
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    private_write(&record.control.with_extension("peer.json"), b"{}");
    std::os::unix::fs::symlink(
        record.control.file_name().unwrap(),
        control_dir.join("tool-0123456789abcdef"),
    )
    .unwrap();
    let index = index_path(&first, "laptop", &record.requested).unwrap();
    private_write(&index, &serde_json::to_vec(&record).unwrap());
    private_write(&index.with_extension("lock"), b"");
    private_write(
        &first.runtime_path().join(crate::receive_service::CLOSING),
        b"",
    );
    stop_all(&first).unwrap();
    cleanup_domain(&first).unwrap();
    assert!(!control_dir.exists());
    assert!(!first.approved_index_path().exists());
    assert!(generation_open(&second, &second_generation).unwrap());
    assert!(first.runtime_path().exists());
}

#[test]
fn cleanup_refuses_unrecognized_files_without_recursive_removal() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let domain = domain(root.path(), "a");
    ensure_generation(&domain).unwrap();
    let record = new_record(&domain);
    let unexpected = record.control.parent().unwrap().join("unrelated");
    private_write(&unexpected, b"keep");
    private_write(
        &domain.runtime_path().join(crate::receive_service::CLOSING),
        b"",
    );
    assert!(cleanup_domain(&domain).is_err());
    assert_eq!(fs::read(unexpected).unwrap(), b"keep");
}

#[test]
fn concurrent_keeper_cleanup_is_closed_but_damaged_present_state_still_errors() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let domain = domain(root.path(), "scope");
    let record = new_record(&domain);
    let approved = record.control.parent().unwrap();
    let socket = UnixListener::bind(&record.control).unwrap();
    private_write(&approved.join(".syq-persistence"), b"wrong marker");
    assert!(mark_closing(&domain, &record).is_err());
    drop(socket);
    fs::remove_file(&record.control).unwrap();
    // A damaged marker still reports an error when the socket has disappeared.
    assert!(mark_closing(&domain, &record).is_err());
    fs::remove_dir_all(approved).unwrap();
    // This is the keeper's real cleanup race: its entire temporary scope went
    // away between off's existence check and its validation/open operation.
    assert!(!mark_closing(&domain, &record).unwrap());
}
