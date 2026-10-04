use super::*;
use crate::restricted::source::{SourceAuthority, SourcePolicy};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

struct Channel {
    reader: FrameReader<UnixStream>,
    writer: FrameWriter<UnixStream>,
    socket: UnixStream,
    thread: Option<std::thread::JoinHandle<Result<()>>>,
}

impl Channel {
    fn new(socket: UnixStream, thread: std::thread::JoinHandle<Result<()>>) -> Self {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        Self {
            reader: FrameReader::new(socket.try_clone().unwrap()),
            writer: FrameWriter::new(socket.try_clone().unwrap(), false),
            socket,
            thread: Some(thread),
        }
    }

    fn request(&mut self, request: Request) -> Response {
        self.writer.write_msg(&request).unwrap();
        self.reader.read_msg().unwrap()
    }

    fn hello(&mut self, role: ConnectionRole) -> Response {
        self.request(Request::Hello {
            identity: crate::identity::build().into(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role,
        })
    }

    fn shutdown(&mut self) {
        self.writer.write_msg(&Request::Shutdown).unwrap();
        self.socket.shutdown(std::net::Shutdown::Write).unwrap();
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn source_policy(path: &Path) -> SourcePolicy {
    SourcePolicy {
        base: SourceRootBase::default(),
        selections: vec![SourceRootSelection {
            path: path.as_os_str().as_bytes().to_vec(),
            follow_root: false,
        }],
        selection_types: vec![crate::cli::SourceSelection::Named],
        symlink_policy: OperatorSymlinkPolicy::Refuse,
        hashing: crate::hashing::HashPolicy {
            algorithm: crate::hashing::HashAlgorithm::Sha256,
            ..Default::default()
        },
        preservation: Default::default(),
        sparse: false,
        compressed: false,
        tcp: None,
        send_rate: None,
        limits: crate::delegation::CopyLimits {
            max_entries: 100,
            max_total_bytes: 16 << 20,
            max_file_bytes: 16 << 20,
            hash_block_bytes: MIN_HASH_BLOCK_BYTES,
            max_connections: 4,
            max_deletions: 0,
        },
        deadline: Instant::now() + Duration::from_secs(30),
    }
}

fn registration(policy: &SourcePolicy) -> Request {
    Request::RegisterSourceRoots {
        base: policy.base.clone(),
        selections: policy.selections.clone(),
        symlink_policy: policy.symlink_policy,
        allow_unconfined_paths: false,
        shared_workers: 1,
        independent_handoff_workers: 0,
    }
}

struct SourceServer {
    authority: Arc<SourceAuthority>,
    session: DescriptorSessionSlot,
    control: Channel,
    connections: Arc<crate::private_broker::ConnectionRegistry>,
}

impl SourceServer {
    fn new(policy: SourcePolicy) -> Self {
        Self::with_writer(policy, |socket| socket)
    }

    fn with_writer<W: Write + Send + 'static>(
        policy: SourcePolicy,
        writer: impl FnOnce(UnixStream) -> W + Send + 'static,
    ) -> Self {
        let authority = SourceAuthority::new(policy).unwrap();
        let session = DescriptorSessionSlot::default();
        let (client, server) = UnixStream::pair().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        server
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let source = authority.clone();
        let descriptors = session.clone();
        let thread = std::thread::spawn(move || {
            run_authorized_source(
                server.try_clone().unwrap(),
                writer(server),
                source,
                descriptors,
                None,
            )
        });
        let mut control = Channel::new(client, thread);
        assert!(matches!(
            control.hello(ConnectionRole::Control),
            Response::HelloOk { .. }
        ));
        Self {
            authority,
            session,
            control,
            connections: Arc::new(crate::private_broker::ConnectionRegistry::new(
                Duration::from_secs(5),
            )),
        }
    }

    fn register(&mut self, request: Request) -> Vec<RegisteredSourceRoot> {
        match self.control.request(request) {
            Response::SourceRootsRegistered(roots) => roots,
            other => panic!("registration failed: {other:?}"),
        }
    }

    fn worker(&self, role: ConnectionRole) -> (Channel, Response) {
        let (client, server) = UnixStream::pair().unwrap();
        let output = server.try_clone().unwrap();
        let input = self.connections.track(server).unwrap();
        let source = self.authority.clone();
        let descriptors = self.session.clone();
        let thread = std::thread::spawn(move || {
            run_authorized_source_worker(input, output, source, descriptors)
        });
        let mut worker = Channel::new(client, thread);
        let hello = worker.hello(role);
        (worker, hello)
    }
}

impl Drop for SourceServer {
    fn drop(&mut self) {
        self.authority.close();
        self.connections.shutdown_all();
    }
}

fn read(source: Option<RegisteredPath>, length: u32) -> Request {
    Request::ReadRange {
        path: b"/ignored/path".to_vec(),
        source,
        attempt: 0,
        off: 0,
        len: length,
    }
}

#[test]
fn approved_source_control_and_worker_confine_reads_hashes_stats_and_mutation() {
    let temporary = crate::test_support::tempdir().unwrap();
    let approved = temporary.path().join("approved");
    let secret = temporary.path().join("secret");
    fs::write(&approved, b"approved").unwrap();
    fs::write(&secret, b"secret").unwrap();
    let policy = source_policy(&approved);
    let register = registration(&policy);
    let mut server = SourceServer::new(policy);
    assert!(matches!(
        server.control.request(read(None, 6)),
        Response::Err(_)
    ));
    let roots = server.register(register);
    let source = roots[0].selection.clone();
    assert!(
        matches!(server.control.request(read(Some(source.clone()), 8)), Response::Err(error) if error.contains("direct data worker"))
    );
    let (mut worker, hello) = server.worker(ConnectionRole::SourceWorker {
        roots,
        send_budget: None,
    });
    assert!(matches!(hello, Response::HelloOk { .. }));
    assert!(
        matches!(worker.request(read(Some(source.clone()), 8)), Response::Block { data, .. } if data == b"approved")
    );
    assert!(matches!(worker.request(Request::FileHash {
        path: secret.as_os_str().as_bytes().to_vec(), source: Some(source.clone()), guard: None,
    }), Response::FileHash { size: 8, hash } if hash == crate::hashing::HashAlgorithm::Sha256.hash(b"approved")));
    assert!(matches!(worker.request(Request::StatMany {
        paths: vec![secret.as_os_str().as_bytes().to_vec()], sources: Some(vec![source.clone()]), follow: true, guard: None,
    }), Response::Stats(entries) if entries.len() == 1 && entries[0].as_ref().unwrap().size == 8));
    let sibling = RegisteredPath::new(source.root(), b"secret".to_vec()).unwrap();
    for channel in [&mut server.control, &mut worker] {
        assert!(matches!(
            channel.request(read(Some(sibling.clone()), 6)),
            Response::Err(_)
        ));
        assert!(matches!(
            channel.request(Request::Apply {
                ops: vec![Op::Remove {
                    path: approved.as_os_str().as_bytes().to_vec()
                }],
                guard: None,
            }),
            Response::Err(_)
        ));
        assert!(matches!(
            channel.request(Request::Canonicalize {
                path: b"/".to_vec(),
                guard: None
            }),
            Response::Err(_)
        ));
    }
    assert_eq!(fs::read(&approved).unwrap(), b"approved");
    assert_eq!(fs::read(&secret).unwrap(), b"secret");
    worker.shutdown();
    server.control.shutdown();
}

#[test]
fn approved_source_worker_rejects_wrong_roles_and_loses_access_with_control() {
    let temporary = crate::test_support::tempdir().unwrap();
    fs::write(temporary.path().join("file"), b"approved").unwrap();
    let policy = source_policy(temporary.path());
    let register = registration(&policy);
    let mut server = SourceServer::new(policy);
    for role in [
        ConnectionRole::Control,
        ConnectionRole::DestinationWorker {
            destination: None,
            copy_sources: Vec::new(),
        },
    ] {
        let (_worker, hello) = server.worker(role);
        assert!(matches!(hello, Response::Err(_)));
    }
    let roots = server.register(register);
    let source = roots[0].selection.join(b"file").unwrap();
    let (mut worker, hello) = server.worker(ConnectionRole::SourceWorker {
        roots,
        send_budget: None,
    });
    assert!(matches!(hello, Response::HelloOk { .. }));
    server.control.shutdown();
    assert!(server.session.is_closed());
    assert!(matches!(
        worker.request(read(Some(source), 8)),
        Response::Err(_)
    ));
    worker.shutdown();
}

#[test]
fn approved_source_stream_enforces_shared_limit_for_each_chunk() {
    let temporary = crate::test_support::tempdir().unwrap();
    let file = temporary.path().join("file");
    fs::write(&file, vec![7; 2048]).unwrap();
    let mut policy = source_policy(&file);
    policy.limits.max_total_bytes = 512;
    let register = registration(&policy);
    let mut server = SourceServer::new(policy);
    let roots = server.register(register);
    let source = roots[0].selection.clone();
    let (mut worker, hello) = server.worker(ConnectionRole::SourceWorker {
        roots,
        send_budget: None,
    });
    assert!(matches!(hello, Response::HelloOk { .. }));
    assert!(matches!(
        worker.request(Request::ReadStream(ReadStreamRequest {
            path: Vec::new(),
            source: Some(source),
            attempt: 0,
            off: 0,
            end: 2048,
            block: 512,
        })),
        Response::Ok
    ));
    assert!(
        matches!(worker.reader.read_msg::<Response>().unwrap(), Response::Block { data, .. } if data.len() == 512)
    );
    assert!(
        matches!(worker.reader.read_msg::<Response>().unwrap(), Response::Err(error) if error.contains("total-byte"))
    );
    assert!(matches!(
        worker.reader.read_msg::<Response>().unwrap(),
        Response::ReadStreamDone
    ));
    worker.writer.write_msg(&Request::StopReadStream).unwrap();
    worker.shutdown();
    server.control.shutdown();
}

#[test]
fn approved_source_scan_entry_limit_is_enforced_before_emitting_the_batch() {
    let temporary = crate::test_support::tempdir().unwrap();
    fs::write(temporary.path().join("one"), b"one").unwrap();
    fs::write(temporary.path().join("two"), b"two").unwrap();
    let mut policy = source_policy(temporary.path());
    policy.limits.max_entries = 1;
    let register = registration(&policy);
    let mut server = SourceServer::new(policy);
    let roots = server.register(register);
    let source = roots[0].selection.clone();
    server
        .control
        .writer
        .write_msg(&Request::Scan {
            root: b"/unapproved".to_vec(),
            source: Some(source),
            follow_root: false,
            ignore: Vec::new(),
            report_ignored: true,
            guard: None,
        })
        .unwrap();
    loop {
        match server.control.reader.read_msg::<Response>().unwrap() {
            Response::ScanBatch(entries) => {
                assert!(entries.iter().all(|entry| entry.path.is_empty()))
            }
            Response::Err(error) => {
                assert!(error.contains("entry limit"), "{error}");
                break;
            }
            other => panic!("unexpected scan response: {other:?}"),
        }
    }
    server.control.shutdown();
}

#[test]
fn approved_source_tcp_requires_encryption_and_keeps_workers_read_only() {
    let temporary = crate::test_support::tempdir().unwrap();
    let file = temporary.path().join("file");
    fs::write(&file, b"approved").unwrap();
    let mut policy = source_policy(&file);
    policy.tcp = Some(crate::restricted::source::SourceTcpPolicy {
        port_lo: 0,
        port_hi: 0,
        congestion_control: None,
    });
    policy.send_rate = Some(1 << 30);
    let register = registration(&policy);
    let mut server = SourceServer::new(policy);
    let roots = server.register(register);
    let source = roots[0].selection.clone();
    let key = vec![19; crate::tcp_records::KEY_LEN];
    let token = vec![23; 16];
    let listen = |key: Option<Vec<u8>>, send_rate| Request::TcpListen {
        key,
        token: token.clone(),
        port_lo: 0,
        port_hi: 0,
        congestion_control: None,
        send_rate,
    };
    assert!(matches!(
        server.control.request(listen(None, Some(1 << 30))),
        Response::Err(_)
    ));
    assert!(matches!(
        server.control.request(listen(Some(key.clone()), None)),
        Response::Err(_)
    ));
    assert!(matches!(
        server
            .control
            .request(Request::CreateSendBudget { rate: 2 << 30 }),
        Response::Err(_)
    ));
    let Response::SendBudget(budget) = server
        .control
        .request(Request::CreateSendBudget { rate: 1 << 30 })
    else {
        panic!("approved sender budget was not issued")
    };
    let Response::TcpListening { port, .. } = server
        .control
        .request(listen(Some(key.clone()), Some(1 << 30)))
    else {
        panic!("approved listener did not start")
    };
    assert!(matches!(
        server
            .control
            .request(listen(Some(key.clone()), Some(1 << 30))),
        Response::Err(_)
    ));

    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.write_all(&7u32.to_be_bytes()).unwrap();
    let mut writer = FrameWriter::new(
        RecordWriter::new(socket.try_clone().unwrap(), Some(Cipher::new(&key, 7, 1))),
        false,
    );
    let mut reader = FrameReader::new(RecordReader::new(
        socket.try_clone().unwrap(),
        Some(Cipher::new(&key, 7, 2)),
    ));
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().into(),
            compress: false,
            debug: false,
            token,
            role: ConnectionRole::SourceWorker {
                roots,
                send_budget: Some(budget),
            },
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::HelloOk { .. }
    ));
    writer.write_msg(&read(Some(source), 8)).unwrap();
    assert!(
        matches!(reader.read_msg::<Response>().unwrap(), Response::Block { data, .. } if data == b"approved")
    );
    writer
        .write_msg(&Request::Apply {
            ops: vec![Op::Remove {
                path: file.as_os_str().as_bytes().to_vec(),
            }],
            guard: None,
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(_)
    ));
    writer.write_msg(&Request::Shutdown).unwrap();
    socket.shutdown(std::net::Shutdown::Both).unwrap();
    server.control.shutdown();
    assert_eq!(fs::read(file).unwrap(), b"approved");
}

#[test]
fn approved_source_ssh_worker_uses_approved_budget_even_when_ticket_is_omitted() {
    let temporary = crate::test_support::tempdir().unwrap();
    let file = temporary.path().join("file");
    fs::write(&file, b"approved").unwrap();
    let mut policy = source_policy(&file);
    policy.send_rate = Some(1 << 30);
    let register = registration(&policy);
    let mut server = SourceServer::new(policy);
    let roots = server.register(register);
    let source = roots[0].selection.clone();
    let other = DescriptorSessionSlot::default();
    let (_, foreign) = other.send_budget(1 << 30).unwrap();
    let (_rejected, response) = server.worker(ConnectionRole::SourceWorker {
        roots: roots.clone(),
        send_budget: Some(foreign),
    });
    assert!(matches!(response, Response::Err(_)));
    let (mut worker, response) = server.worker(ConnectionRole::SourceWorker {
        roots,
        send_budget: None,
    });
    assert!(matches!(response, Response::HelloOk { .. }));
    let (approved, _) = server
        .authority
        .sending_budget(&server.session)
        .unwrap()
        .unwrap();
    let (session_budget, _) = server.session.send_budget(1 << 30).unwrap();
    assert!(Arc::ptr_eq(&approved, &session_budget));
    approved.close();
    worker.writer.write_msg(&read(Some(source), 8)).unwrap();
    // A closed shared budget stops the response. Omitting the ticket must not
    // leave an unpaced writer that can return file data anyway.
    assert!(worker.reader.read_msg::<Response>().is_err());
    server.control.shutdown();
}

#[test]
fn approved_source_control_disconnect_revokes_tcp_while_control_response_is_busy() {
    use std::sync::{atomic::AtomicBool, atomic::Ordering, mpsc};

    struct PausedWriter {
        inner: UnixStream,
        armed: Arc<AtomicBool>,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for PausedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.armed.swap(false, Ordering::AcqRel) {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            self.inner.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    let temporary = crate::test_support::tempdir().unwrap();
    let file = temporary.path().join("file");
    fs::write(&file, b"approved").unwrap();
    let mut policy = source_policy(&file);
    policy.tcp = Some(crate::restricted::source::SourceTcpPolicy {
        port_lo: 0,
        port_hi: 0,
        congestion_control: None,
    });
    let register = registration(&policy);
    let armed = Arc::new(AtomicBool::new(false));
    let pause = armed.clone();
    let (entered, waiting) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let mut server = SourceServer::with_writer(policy, move |inner| PausedWriter {
        inner,
        armed: pause,
        entered,
        release: released,
    });
    let roots = server.register(register);
    let source = roots[0].selection.clone();
    let role = ConnectionRole::SourceWorker {
        roots,
        send_budget: None,
    };
    // An individual worker's EOF must not revoke the control's authority.
    let (mut worker, hello) = server.worker(role.clone());
    assert!(matches!(hello, Response::HelloOk { .. }));
    worker.shutdown();
    assert!(server.authority.is_open());

    let key = vec![19; crate::tcp_records::KEY_LEN];
    let token = vec![23; 16];
    let Response::TcpListening { port, .. } = server.control.request(Request::TcpListen {
        key: Some(key.clone()),
        token: token.clone(),
        port_lo: 0,
        port_hi: 0,
        congestion_control: None,
        send_rate: None,
    }) else {
        panic!("approved listener did not start")
    };
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket.write_all(&7u32.to_be_bytes()).unwrap();
    let mut writer = FrameWriter::new(
        RecordWriter::new(socket.try_clone().unwrap(), Some(Cipher::new(&key, 7, 1))),
        false,
    );
    let mut reader = FrameReader::new(RecordReader::new(
        socket.try_clone().unwrap(),
        Some(Cipher::new(&key, 7, 2)),
    ));
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().into(),
            compress: false,
            debug: false,
            token,
            role: role.clone(),
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::HelloOk { .. }
    ));
    writer.write_msg(&read(Some(source.clone()), 8)).unwrap();
    assert!(
        matches!(reader.read_msg::<Response>().unwrap(), Response::Block { data, .. } if data == b"approved")
    );

    armed.store(true, Ordering::Release);
    server
        .control
        .writer
        .write_msg(&Request::TransportStats)
        .unwrap();
    waiting.recv_timeout(Duration::from_secs(3)).unwrap();
    server
        .control
        .socket
        .shutdown(std::net::Shutdown::Write)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut report = Instant::now() + Duration::from_secs(1);
    while server.authority.is_open() {
        assert!(
            Instant::now() < deadline,
            "source authority stayed open while control was busy"
        );
        if Instant::now() >= report {
            eprintln!("source disconnect fixture: control is busy; authority is still open");
            report += Duration::from_secs(1);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!server.control.thread.as_ref().unwrap().is_finished());
    assert!(
        !server.session.is_closed(),
        "control must still own its session"
    );
    assert!(server.authority.acquire(&role, false).is_err());
    writer.write_msg(&read(Some(source), 8)).unwrap();
    // The existing encrypted data worker must return no more file payload.
    assert!(reader.read_msg::<Response>().is_err());
    release.send(()).unwrap();
    socket.shutdown(std::net::Shutdown::Both).unwrap();
}
