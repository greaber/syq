use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc;

struct Session {
    socket: UnixStream,
    reader: FrameReader<UnixStream>,
    writer: FrameWriter<UnixStream>,
    server: Option<std::thread::JoinHandle<Result<()>>>,
}

impl Session {
    fn start(root: &Path, metadata_control: bool) -> Self {
        let authority = Arc::new(crate::restricted::tests::tcp_test_authority(root));
        let (server, socket) = crate::process::with_inheritance_guard(UnixStream::pair).unwrap();
        for stream in [&server, &socket] {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        let worker = std::thread::spawn(move || {
            if metadata_control {
                // Both laptop uploads and three-server bridges enter through
                // this function; exercise its enforced metadata-only policy.
                return run_forwarded(
                    authority,
                    server.try_clone().unwrap(),
                    server,
                    Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    false,
                );
            }
            serve(
                server.try_clone().unwrap(),
                server.try_clone().unwrap(),
                true,
                None,
                None,
                None,
                ServeSession {
                    owns_process: false,
                    handshake_pending: None,
                    ssh_worker_ticket: None,
                    allow_tcp: true,
                    metadata_control,
                    loopback_only: false,
                    named_socket: Some(server),
                    authority: Some(authority),
                    source_authority: None,
                    descriptor_session: DescriptorSessionSlot::default(),
                },
            )
        });
        Self {
            reader: FrameReader::new(socket.try_clone().unwrap()),
            writer: FrameWriter::new(socket.try_clone().unwrap(), true),
            socket,
            server: Some(worker),
        }
    }

    fn request(&mut self, request: Request) -> Response {
        self.writer.write_msg(&request).unwrap();
        self.reader.read_msg().unwrap()
    }

    fn hello(&mut self, role: ConnectionRole) -> Response {
        self.request(Request::Hello {
            identity: crate::identity::build().into(),
            compress: true,
            debug: false,
            token: Vec::new(),
            role,
        })
    }

    fn finish(&mut self) -> Result<()> {
        // macOS reports ENOTCONN if the server already rejected the role
        // and closed its socket; that is the expected end of this session.
        if let Err(error) = self.socket.shutdown(std::net::Shutdown::Both) {
            assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        }
        self.server.take().unwrap().join().unwrap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

#[test]
fn bridged_connection_refuses_worker_roles_before_admission() {
    let root = crate::test_support::tempdir().unwrap();
    for role in [
        ConnectionRole::DestinationWorker {
            destination: None,
            copy_sources: Vec::new(),
        },
        ConnectionRole::SourceWorker {
            roots: Vec::new(),
            send_budget: None,
        },
    ] {
        let mut session = Session::start(root.path(), true);
        assert!(matches!(session.hello(role), Response::Err(message)
            if message.contains("requires the control role")));
        assert!(session.finish().is_err());
    }
}

#[test]
fn bridged_control_accepts_metadata_but_refuses_file_payloads() {
    let root = crate::test_support::tempdir().unwrap();
    let target = root.path().join("target");
    let path = target.as_os_str().as_bytes().to_vec();
    let copy_id = CopyId::default();
    let mut session = Session::start(root.path(), true);
    assert!(matches!(
        session.hello(ConnectionRole::Control),
        Response::HelloOk { .. }
    ));
    assert!(matches!(
        session.request(Request::Prepare {
            path: path.clone(),
            size: 4,
            inplace: false,
            copy_id,
            mode: 0o600,
            flags: 0,
            acl: false,
            scanned: crate::proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            condition: crate::proto::TargetCondition::Any,
            guard: None,
            group: None,
        }),
        Response::Prepared(_)
    ));

    for request in [
        Request::WriteRange {
            path: path.clone(),
            inplace: false,
            copy_id,
            attempt: 0,
            off: 0,
            hash: fsops::content_digest(b"data"),
            data: b"data".to_vec().into(),
            guard: None,
        },
        Request::PutSmallBatch(Vec::new()),
        Request::CopySmallFiles(vec![SmallCopyPayload {
            index: 0,
            data: b"data".to_vec(),
            hash: fsops::content_digest(b"data"),
        }]),
        Request::DescriptorCopy(crate::descriptor_copy::Operation::Abort { entry: 0 }),
        Request::ReadRange {
            path: path.clone(),
            source: None,
            attempt: 0,
            off: 0,
            len: 4,
        },
        Request::ReadComparedRange {
            path: path.clone(),
            source: None,
            attempt: 0,
            off: 0,
            len: 4,
            expected: fsops::content_digest(b"data"),
        },
        Request::ReadSmallBatch(vec![SmallRead {
            path: path.clone(),
            source: None,
            attempt: 0,
            len: 4,
        }]),
        Request::ReadStream(ReadStreamRequest {
            path,
            source: None,
            attempt: 0,
            off: 0,
            end: 4,
            block: 512,
        }),
    ] {
        assert!(matches!(session.request(request), Response::Err(message)
            if message.contains("file payload requires a direct data worker")));
    }
    assert!(matches!(
        session.request(Request::WriteStreamFence),
        Response::WriteStreamDone
    ));
    session.finish().unwrap();
    let partial = fsops::partial_path(&target, &copy_id).unwrap();
    assert_eq!(std::fs::read(partial).unwrap(), [0; 4]);
    assert!(
        !target.exists(),
        "refused control payload must not publish a file"
    );
}

#[test]
fn ordinary_ssh_control_keeps_its_existing_payload_support() {
    let root = crate::test_support::tempdir().unwrap();
    let target = root.path().join("target");
    let path = target.as_os_str().as_bytes().to_vec();
    let copy_id = CopyId::default();
    let mut session = Session::start(root.path(), false);
    assert!(matches!(
        session.hello(ConnectionRole::Control),
        Response::HelloOk { .. }
    ));
    assert!(matches!(
        session.request(Request::Prepare {
            path: path.clone(),
            size: 4,
            inplace: false,
            copy_id,
            mode: 0o600,
            flags: 0,
            acl: false,
            scanned: crate::proto::ScannedDestination::Unknown,
            attempt: 0,
            create_if_missing: true,
            condition: crate::proto::TargetCondition::Any,
            guard: None,
            group: None,
        }),
        Response::Prepared(_)
    ));
    assert!(matches!(
        session.request(Request::WriteRange {
            path,
            inplace: false,
            copy_id,
            attempt: 0,
            off: 0,
            hash: fsops::content_digest(b"data"),
            data: b"data".to_vec().into(),
            guard: None,
        }),
        Response::Ok
    ));
    session.finish().unwrap();
    assert_eq!(
        std::fs::read(fsops::partial_path(&target, &copy_id).unwrap()).unwrap(),
        b"data"
    );
}

#[test]
fn control_hangup_revokes_with_unread_pipe_data() {
    let root = crate::test_support::tempdir().unwrap();
    let authority = Arc::new(crate::restricted::tests::tcp_test_authority(root.path()));
    let (mut input, mut writer) = crate::process::with_inheritance_guard(std::io::pipe).unwrap();
    writer.write_all(b"queued metadata").unwrap();
    let lifetime = ControlLifetime::watch(&input, authority.clone()).unwrap();
    assert!(authority.control_is_open());
    // Let the watcher observe queued data before EOF. A one-shot Darwin
    // poll subscription can otherwise pass by noticing an already-closed pipe.
    std::thread::sleep(Duration::from_millis(50));
    assert!(authority.control_is_open(), "queued data is not a hangup");
    // Keep all queued bytes unread, as when the protocol reader is blocked
    // sending into its full request queue during a long metadata operation.
    drop(writer);
    let deadline = Instant::now() + Duration::from_secs(3);
    while authority.control_is_open() {
        assert!(
            Instant::now() < deadline,
            "control stayed open after pipe writer closed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut queued = Vec::new();
    input.read_to_end(&mut queued).unwrap();
    assert_eq!(
        queued, b"queued metadata",
        "watcher must not consume protocol data"
    );
    drop(lifetime);
}

#[test]
fn control_watcher_drop_wakes_while_upstream_is_still_open() {
    let root = crate::test_support::tempdir().unwrap();
    let authority = Arc::new(crate::restricted::tests::tcp_test_authority(root.path()));
    let (input, writer) = crate::process::with_inheritance_guard(std::io::pipe).unwrap();
    let lifetime = ControlLifetime::watch(&input, authority.clone()).unwrap();
    let (finished, completion) = mpsc::channel();
    let dropping = std::thread::spawn(move || {
        drop(lifetime);
        finished.send(()).unwrap();
    });
    let result = completion.recv_timeout(Duration::from_secs(3));
    // Also unblock a regressed watcher before failing, so no test worker leaks.
    drop(writer);
    dropping.join().unwrap();
    result.expect("dropping the watcher must wake its poll without waiting for upstream EOF");
    assert!(
        authority.control_is_open(),
        "normal watcher teardown must not revoke control"
    );
}
