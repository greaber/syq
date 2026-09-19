#[test]
fn read_stream_shrinks_before_the_next_read_and_fences_late_updates() {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    let reader = super::RequestReader {
        rx: Some(rx),
        thread: None,
        tcp_socket: None,
        named_socket: None,
    };
    let send = |value| {
        tx.send(Ok(crate::wire_budget::Budgeted {
            value,
            hold: crate::wire_budget::Hold::new(),
        }))
        .unwrap();
    };
    let mut limit = 4096;
    send(super::Request::ShrinkReadStream { end: 2048 });
    send(super::Request::ShrinkReadStream { end: 1024 });
    assert!(!reader.stream_stopped(0, &mut limit, false).unwrap());
    assert_eq!(limit, 1024);

    // Even if a block straddled the new end, consume subsequent shrink
    // commands and wait for Stop; never issue another read or consume
    // the next stream's command. A zero limit cancels all future reads.
    send(super::Request::ShrinkReadStream { end: 0 });
    send(super::Request::StopReadStream);
    send(super::Request::Shutdown);
    assert!(reader.stream_stopped(2048, &mut limit, true).unwrap());
    assert_eq!(limit, 0);
    assert!(matches!(
        reader.recv().unwrap().unwrap().value,
        super::Request::Shutdown
    ));

    // Increasing a limit is a protocol error, not new read authority.
    send(super::Request::ShrinkReadStream { end: u64::MAX });
    assert!(reader.stream_stopped(2048, &mut limit, true).is_err());
    assert_eq!(limit, 0);
    drop(tx);
    assert!(reader.stream_stopped(2048, &mut limit, true).is_err());
}

use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

#[test]
fn streaming_fence_survives_revocation_without_authorizing_more_writes() {
    let root = crate::test_support::tempdir().unwrap();
    let authority = Arc::new(crate::restricted::tests::tcp_test_authority(root.path()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server_authority = authority.clone();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        serve(
            socket.try_clone().unwrap(),
            socket.try_clone().unwrap(),
            false,
            None,
            None,
            Some(socket),
            ServeSession {
                handshake_pending: None,
                ssh_worker_ticket: None,
                allow_tcp: true,
                named_socket: None,
                authority: Some(server_authority),
                descriptor_session: DescriptorSessionSlot::default(),
            },
        )
        .unwrap();
    });
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = FrameReader::new(socket.try_clone().unwrap());
    let mut writer = FrameWriter::new(socket.try_clone().unwrap(), true);
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().to_string(),
            compress: true,
            debug: false,
            token: Vec::new(),
            role: ConnectionRole::DestinationWorker {
                destination: None,
                copy_sources: Vec::new(),
            },
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::HelloOk { .. }
    ));
    authority.close_control();
    for _ in 0..2 {
        writer
            .write_msg(&Request::WriteRange {
                path: b"file".to_vec(),
                inplace: false,
                copy_id: CopyId::default(),
                attempt: 0,
                off: 0,
                hash: fsops::content_digest(b"data"),
                data: b"data".to_vec(),
                guard: None,
            })
            .unwrap();
        assert!(
            matches!(reader.read_msg::<Response>().unwrap(), Response::Err(error) if error.contains("closed"))
        );
        writer.write_msg(&Request::WriteStreamFence).unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::WriteStreamDone
        ));
    }
    socket.shutdown(std::net::Shutdown::Both).unwrap();
    server.join().unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

const IP_ADDR_SHOW: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever
2: eth0    inet 172.19.3.10/29 brd 172.19.3.15 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet6 fdaa:0:1:a7b::2/112 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::2/64 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::3/64 scope global tentative \\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::9e6b:ff:fe4e:89ad/64 scope link \\       valid_lft forever preferred_lft forever
3: bond0    inet 10.2.201.45/24 brd 10.2.201.255 scope global bond0\\       valid_lft forever preferred_lft forever
4: tailscale0    inet 100.101.102.103/32 scope global tailscale0\\       valid_lft forever preferred_lft forever
4: tailscale0    inet6 fd7a:115c:a1e0::1234/128 scope global \\       valid_lft forever preferred_lft forever
5: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
";

fn speeds(name: &str) -> u32 {
    match name {
        "bond0" => 25000,
        "eth0" => 1000,
        _ => 0,
    }
}

#[test]
fn advertised_addrs_lists_both_families_with_ssh_arrival_first() {
    let ssh = "fdaa:0:1:a7b::2".parse().ok();
    let both = BoundFamilies { v4: true, v6: true };
    let got = advertised_addrs(IP_ADDR_SHOW, ssh, both, speeds);
    assert_eq!(
        got,
        vec![
            ("fdaa:0:1:a7b::2".to_string(), 1000),
            ("10.2.201.45".to_string(), 25000),
            ("172.19.3.10".to_string(), 1000),
            ("2001:db8::2".to_string(), 1000),
            ("100.101.102.103".to_string(), 0),
            ("fd7a:115c:a1e0::1234".to_string(), 0),
        ]
    );
}

#[test]
fn advertised_addrs_only_names_families_the_listener_bound() {
    let v4 = BoundFamilies {
        v4: true,
        v6: false,
    };
    let got = advertised_addrs(IP_ADDR_SHOW, None, v4, speeds);
    assert!(got
        .iter()
        .all(|(ip, _)| ip.parse::<IpAddr>().unwrap().is_ipv4()));
    assert_eq!(got[0].0, "10.2.201.45");
    // The ssh arrival address is still advertised first, but only when a
    // listener of its family exists.
    let ssh = "fdaa:0:1:a7b::2".parse().ok();
    let got = advertised_addrs(IP_ADDR_SHOW, ssh, v4, speeds);
    assert!(!got.iter().any(|(ip, _)| ip.starts_with("fdaa")));
}

#[test]
fn advertised_addrs_includes_ssh_arrival_address_without_a_listing() {
    let ssh = "203.0.113.7".parse().ok();
    let both = BoundFamilies { v4: true, v6: true };
    assert_eq!(
        advertised_addrs("", ssh, both, speeds),
        vec![("203.0.113.7".to_string(), 0)]
    );
}

#[test]
fn data_listeners_share_one_port_across_families() {
    let (port, listeners) = bind_data_listeners(0, 0).unwrap();
    assert_ne!(port, 0);
    let ports: Vec<u16> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    assert!(ports.iter().all(|p| *p == port), "{ports:?} != {port}");
    for listener in &listeners {
        let local = listener.local_addr().unwrap();
        let target: SocketAddr = if local.is_ipv4() {
            (Ipv4Addr::LOCALHOST, port).into()
        } else {
            (Ipv6Addr::LOCALHOST, port).into()
        };
        TcpStream::connect_timeout(&target, Duration::from_secs(2))
            .unwrap_or_else(|e| panic!("connect {target}: {e}"));
    }
}

struct ExitObserved<R> {
    inner: R,
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl<R: Read> Read for ExitObserved<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl<R> Drop for ExitObserved<R> {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn tcp_server_joins_request_reader_on_shutdown() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let selected = crate::test_support::tempdir().unwrap();
    let marker = selected.path().join("marker");
    std::fs::write(&marker, b"marker").unwrap();
    std::fs::File::create(selected.path().join("stream-large"))
        .unwrap()
        .set_len(8 << 20)
        .unwrap();
    let descriptor_session = DescriptorSessionSlot::default();
    let ticket = descriptor_session
        .register(std::fs::File::open(selected.path()).unwrap())
        .unwrap();
    let selection = RegisteredPath::new(ticket.root_id(), Vec::new()).unwrap();
    let source = RegisteredSourceRoot {
        selection: selection.clone(),
        ticket,
        leaf_ticket: None,
        expected_leaf: None,
        allow_unconfined_paths: false,
    };
    let server_session = descriptor_session.clone();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = dropped.clone();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        serve(
            ExitObserved {
                inner: socket.try_clone().unwrap(),
                dropped: observed,
            },
            socket.try_clone().unwrap(),
            false,
            None,
            None,
            Some(socket),
            ServeSession {
                handshake_pending: None,
                ssh_worker_ticket: None,
                allow_tcp: true,
                named_socket: None,
                authority: None,
                descriptor_session: server_session,
            },
        )
        .unwrap();
    });

    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut writer = FrameWriter::new(socket.try_clone().unwrap(), false);
    let mut reader = FrameReader::new(socket);
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().to_string(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role: ConnectionRole::SourceWorker {
                roots: vec![source],
            },
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::HelloOk { .. }
    ));
    let selected_metadata = std::fs::metadata(selected.path()).unwrap();
    let guard = ContainerGuard {
        root: selected.path().as_os_str().as_bytes().to_vec(),
        dev: selected_metadata.dev(),
        ino: selected_metadata.ino(),
    };
    writer
        .write_msg(&Request::Scan {
            root: selected.path().as_os_str().as_bytes().to_vec(),
            source: None,
            follow_root: false,
            ignore: Vec::new(),
            report_ignored: false,
            guard: Some(guard.clone()),
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(error) if error.contains("source session rejects caller-supplied guards")
    ));
    writer
        .write_msg(&Request::Apply {
            ops: vec![Op::Unlink {
                path: marker.as_os_str().as_bytes().to_vec(),
            }],
            guard: None,
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(error) if error.contains("not valid on a source worker")
    ));
    assert_eq!(std::fs::read(&marker).unwrap(), b"marker");
    writer
        .write_msg(&Request::StatMany {
            paths: vec![selected.path().as_os_str().as_bytes().to_vec()],
            sources: None,
            follow: false,
            guard: Some(guard),
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(error) if error.contains("source session rejects caller-supplied guards")
    ));
    writer
        .write_msg(&Request::ReadRange {
            // This contradictory spelling is diagnostic only; the
            // registered source reference is the read authority.
            path: b"/not/the/source/marker".to_vec(),
            source: Some(selection.join(b"marker").unwrap()),
            attempt: 0,
            off: 0,
            len: 6,
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Block { data, .. } if data == b"marker"
    ));
    writer
        .write_msg(&Request::ReadRange {
            path: selected
                .path()
                .join("marker")
                .as_os_str()
                .as_bytes()
                .to_vec(),
            source: None,
            attempt: 0,
            off: 0,
            len: 6,
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::EndpointError(error) if error.message.contains("omitted")
    ));
    // Streaming must retain the same source capability checks, including
    // after an error and after stopping an interval early.
    for (source, end, expected_error) in [
        (Some(selection.join(b"marker").unwrap()), 6, false),
        (None, 6, true),
        (Some(selection.join(b"marker").unwrap()), 4096, true),
    ] {
        writer
            .write_msg(&Request::ReadStream(ReadStreamRequest {
                path: marker.as_os_str().as_bytes().to_vec(),
                source,
                attempt: 0,
                off: 0,
                end,
                block: 512,
            }))
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Ok
        ));
        let response = reader.read_msg::<Response>().unwrap();
        if expected_error {
            assert!(
                matches!(response, Response::EndpointError(_)),
                "{response:?}"
            );
        } else {
            assert!(matches!(response, Response::Block { data, .. } if data == b"marker"));
        }
        // Completion arrives before Stop, including after a read error.
        // The socket's read deadline makes waiting for Stop fail this test.
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::ReadStreamDone
        ));
        // A shrink can arrive after the final block or an error. It has
        // no reply, does not restart reading, and cannot cross the fence.
        writer
            .write_msg(&Request::ShrinkReadStream { end: 0 })
            .unwrap();
        writer.write_msg(&Request::StopReadStream).unwrap();
        // The next iteration's request must not consume a second Done
        // or a response to the late shrink/stop.
        writer
            .write_msg(&Request::ShrinkReadStream { end: 0 })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(error) if error == "no read stream is active"
        ));
    }
    // A late shrink can exhaust a still-active stream after read-ahead
    // crossed its new boundary. It must produce Done before Stop, just
    // like natural EOF. Small frames keep the stream in flight until the
    // client sends the shrink; the read deadline catches a stop-RTT stall.
    writer
        .write_msg(&Request::ReadStream(ReadStreamRequest {
            path: Vec::new(),
            source: Some(selection.join(b"stream-large").unwrap()),
            attempt: 0,
            off: 0,
            end: 8 << 20,
            block: 512,
        }))
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Ok
    ));
    let mut received = match reader.read_msg::<Response>().unwrap() {
        Response::Block { data, .. } => data.len(),
        other => panic!("expected first streamed block, got {other:?}"),
    };
    writer
        .write_msg(&Request::ShrinkReadStream { end: 0 })
        .unwrap();
    loop {
        match reader.read_msg::<Response>().unwrap() {
            Response::Block { data, .. } => received += data.len(),
            Response::ReadStreamDone => break,
            other => panic!("unexpected late-shrink response: {other:?}"),
        }
    }
    assert!(
        received < 8 << 20,
        "stream ended naturally before the shrink"
    );
    writer
        .write_msg(&Request::ShrinkReadStream { end: 0 })
        .unwrap();
    writer.write_msg(&Request::StopReadStream).unwrap();
    writer
        .write_msg(&Request::ReadStream(ReadStreamRequest {
            path: Vec::new(),
            source: Some(selection.join(b"marker").unwrap()),
            attempt: 0,
            off: 0,
            end: 6,
            block: 0,
        }))
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(_)
    ));
    writer
        .write_msg(&Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
            selections: vec![SourceRootSelection {
                path: b".".to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 0,
            independent_handoff_workers: 0,
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(error) if error.contains("only on the control connection")
    ));
    writer.write_msg(&Request::Shutdown).unwrap();
    server.join().unwrap();
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(Arc::strong_count(&dropped), 1);
}

#[test]
fn rejected_destination_ticket_is_not_acknowledged_as_ready() {
    let selected = crate::test_support::tempdir().unwrap();
    let owner = DescriptorSessionSlot::default();
    let ticket = owner
        .register(std::fs::File::open(selected.path()).unwrap())
        .unwrap();
    owner.close();

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        serve(
            socket.try_clone().unwrap(),
            socket,
            false,
            None,
            None,
            None,
            ServeSession {
                handshake_pending: None,
                ssh_worker_ticket: None,
                allow_tcp: true,
                named_socket: None,
                authority: None,
                descriptor_session: DescriptorSessionSlot::default(),
            },
        )
        .unwrap_err()
    });

    let socket = TcpStream::connect(address).unwrap();
    let mut writer = FrameWriter::new(socket.try_clone().unwrap(), false);
    let mut reader = FrameReader::new(socket);
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().to_string(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role: ConnectionRole::DestinationWorker {
                destination: Some(DestinationRoot {
                    ticket,
                    request_prefix: b"destination".to_vec(),
                }),
                copy_sources: Vec::new(),
            },
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(error) if error.contains("initialize destination worker")
    ));
    server.join().unwrap();
}

#[test]
fn rejected_source_ticket_is_not_acknowledged_as_ready() {
    let selected = crate::test_support::tempdir().unwrap();
    let owner = DescriptorSessionSlot::default();
    let ticket = owner
        .register(std::fs::File::open(selected.path()).unwrap())
        .unwrap();
    let source = RegisteredSourceRoot {
        selection: RegisteredPath::new(ticket.root_id(), Vec::new()).unwrap(),
        ticket,
        leaf_ticket: None,
        expected_leaf: None,
        allow_unconfined_paths: false,
    };
    owner.close();

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        serve(
            socket.try_clone().unwrap(),
            socket,
            false,
            None,
            None,
            None,
            ServeSession {
                handshake_pending: None,
                ssh_worker_ticket: None,
                allow_tcp: true,
                named_socket: None,
                authority: None,
                descriptor_session: DescriptorSessionSlot::default(),
            },
        )
        .unwrap_err()
    });

    let socket = TcpStream::connect(address).unwrap();
    let mut writer = FrameWriter::new(socket.try_clone().unwrap(), false);
    let mut reader = FrameReader::new(socket);
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().to_string(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role: ConnectionRole::SourceWorker {
                roots: vec![source],
            },
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(error) if error.contains("initialize source worker")
    ));
    server.join().unwrap();
}

fn tcp_test_hello(token: &[u8]) -> Request {
    Request::Hello {
        identity: crate::identity::build().to_string(),
        compress: true,
        debug: false,
        token: token.to_vec(),
        role: ConnectionRole::DestinationWorker {
            destination: None,
            copy_sources: Vec::new(),
        },
    }
}

fn tcp_test_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    (client, listener.accept().unwrap().0)
}

#[test]
fn tcp_rejects_replayed_hello_with_high_connection_id_bits() {
    let temporary = crate::test_support::tempdir().unwrap();
    let authority = Arc::new(crate::restricted::tests::tcp_test_authority(
        temporary.path(),
    ));
    let key = vec![7; crate::tcp_records::KEY_LEN];
    let token = b"replay-test";
    let conn_id = 42u32;
    let mut capture = Vec::new();
    FrameWriter::new(
        RecordWriter::new(&mut capture, Some(Cipher::new(&key, conn_id, 1))),
        false,
    )
    .write_msg(&tcp_test_hello(token))
    .unwrap();
    let seen = std::sync::Mutex::new(std::collections::HashSet::new());
    // The original authenticates; changing only the high byte used to
    // bypass the replay set while decrypting exactly the same records.
    for (attempt, high) in [0u32, 1, 2, 128, 255, 0].into_iter().enumerate() {
        let (mut client, server) = tcp_test_pair();
        client
            .write_all(&(conn_id | (high << 24)).to_be_bytes())
            .unwrap();
        client.write_all(&capture).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let result = serve_tcp(
            server,
            0,
            Some(key.clone()),
            token.to_vec(),
            false,
            false,
            &seen,
            Some(authority.clone()),
            DescriptorSessionSlot::default(),
            std::time::Instant::now() + Duration::from_secs(1),
        );
        if high != 0 {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("exceeds nonce space"));
            // Rejection must precede the server's encrypted preamble.
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response);
            assert!(response.is_empty());
        } else if attempt != 0 {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("duplicate connection id"));
        } else {
            result.unwrap();
            assert!(seen.lock().unwrap().contains(&conn_id));
        }
        assert_eq!(
            *seen.lock().unwrap(),
            std::collections::HashSet::from([conn_id])
        );
    }
}

#[test]
fn tcp_partial_handshakes_time_out_without_reserving_ids() {
    for encrypted in [false, true] {
        // Stop inside the ID, after a complete preamble record, and
        // inside the Hello record. None of these authenticates a peer.
        for part in 0..3 {
            let key = encrypted.then(|| vec![9; crate::tcp_records::KEY_LEN]);
            let id = 43u32;
            let mut preamble = Vec::new();
            FrameWriter::new(
                RecordWriter::new(
                    &mut preamble,
                    key.as_ref().map(|key| Cipher::new(key, id, 1)),
                ),
                false,
            )
            .write_preamble()
            .unwrap();
            let mut hello = Vec::new();
            FrameWriter::new(
                RecordWriter::new(&mut hello, key.as_ref().map(|key| Cipher::new(key, id, 1))),
                false,
            )
            .write_msg(&tcp_test_hello(b"timeout-test"))
            .unwrap();
            let mut bytes = id.to_be_bytes().to_vec();
            match part {
                0 => bytes.truncate(1),
                1 => bytes.extend_from_slice(&preamble),
                _ => bytes.extend_from_slice(&hello[..hello.len() - 1]),
            }
            let (mut client, server) = tcp_test_pair();
            client.write_all(&bytes).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let seen = std::sync::Mutex::new(std::collections::HashSet::new());
                let result = serve_tcp(
                    server,
                    0,
                    key,
                    b"timeout-test".to_vec(),
                    false,
                    false,
                    &seen,
                    None,
                    DescriptorSessionSlot::default(),
                    std::time::Instant::now() + Duration::from_millis(100),
                );
                tx.send((result, seen.into_inner().unwrap())).unwrap();
            });
            let result = rx.recv_timeout(Duration::from_secs(3));
            // Ensure a regression never leaves a blocked server thread.
            client.shutdown(std::net::Shutdown::Both).ok();
            worker.join().unwrap();
            let (result, seen) = result.expect("partial TCP Hello held a worker past its deadline");
            assert!(result.is_err());
            assert!(seen.is_empty());
        }
    }
}

#[test]
fn tcp_hello_clears_timeouts_only_after_authentication() {
    let temporary = crate::test_support::tempdir().unwrap();
    let authority = Arc::new(crate::restricted::tests::tcp_test_authority(
        temporary.path(),
    ));
    for encrypted in [false, true] {
        let key = encrypted.then(|| vec![8; crate::tcp_records::KEY_LEN]);
        let server_key = key.clone();
        let authority = authority.clone();
        let (client, server) = tcp_test_pair();
        let observer = server.try_clone().unwrap();
        let worker = std::thread::spawn(move || {
            let seen = std::sync::Mutex::new(std::collections::HashSet::new());
            serve_tcp(
                server,
                0,
                server_key,
                b"valid-token".to_vec(),
                false,
                false,
                &seen,
                Some(authority),
                DescriptorSessionSlot::default(),
                std::time::Instant::now() + Duration::from_millis(100),
            )
        });
        (&client).write_all(&44u32.to_be_bytes()).unwrap();
        let mut writer = FrameWriter::new(
            RecordWriter::new(
                client.try_clone().unwrap(),
                key.as_ref().map(|key| Cipher::new(key, 44, 1)),
            ),
            false,
        );
        let mut reader = FrameReader::new(RecordReader::new(
            client.try_clone().unwrap(),
            key.as_ref().map(|key| Cipher::new(key, 44, 2)),
        ));
        writer.write_msg(&tcp_test_hello(b"valid-token")).unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::HelloOk { .. }
        ));
        // Wait beyond the handshake deadline, then prove the worker is
        // still alive and both shared socket timeouts have been cleared.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(observer.read_timeout().unwrap(), None);
        assert_eq!(observer.write_timeout().unwrap(), None);
        assert!(!worker.is_finished());
        client.shutdown(std::net::Shutdown::Both).unwrap();
        worker.join().unwrap().unwrap();
    }
}

#[test]
fn tcp_handshake_deadline_does_not_reset_after_partial_reads() {
    let (mut client, server) = tcp_test_pair();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut reader = TcpHandshakeReader {
        stream: server,
        pending: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        deadline: std::time::Instant::now() + Duration::from_millis(100),
    };
    client.write_all(b"a").unwrap();
    reader.read_exact(&mut [0]).unwrap();
    assert!(reader.stream.read_timeout().unwrap().is_some());
    std::thread::sleep(Duration::from_millis(150));
    client.write_all(b"b").unwrap();
    assert_eq!(
        reader.read(&mut [0]).unwrap_err().kind(),
        ErrorKind::TimedOut
    );
}

/// Connect to the data listener and complete a token-authenticated Hello
/// as a destination worker. Returns the still-open socket on success so
/// the caller controls when the worker's permit is released.
fn authenticated_worker(port: u16, token: &[u8]) -> std::result::Result<TcpStream, anyhow::Error> {
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let conn_id = TEST_TCP_CONN_ID.fetch_add(1, Relaxed);
    (&socket).write_all(&conn_id.to_be_bytes())?;
    let mut writer = FrameWriter::new(RecordWriter::new(socket.try_clone()?, None), false);
    let mut reader = FrameReader::new(RecordReader::new(socket.try_clone()?, None));
    writer.write_msg(&Request::Hello {
        identity: crate::identity::build().to_string(),
        compress: true,
        debug: false,
        token: token.to_vec(),
        role: ConnectionRole::DestinationWorker {
            destination: None,
            copy_sources: Vec::new(),
        },
    })?;
    match reader.read_msg::<Response>()? {
        Response::HelloOk { .. } => Ok(socket),
        other => bail!("unexpected Hello response {other:?}"),
    }
}

static TEST_TCP_CONN_ID: AtomicU32 = AtomicU32::new(1000);

#[test]
fn unauthenticated_sockets_do_not_consume_signed_worker_permits() {
    let temporary = crate::test_support::tempdir().unwrap();
    let root = temporary.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let authority = Arc::new(crate::restricted::tests::tcp_test_authority(&root));
    let max_workers = usize::from(crate::restricted::tests::TEST_AUTHORITY_MAX_CONNECTIONS);
    let token = b"data-token".to_vec();
    let descriptor_session = DescriptorSessionSlot::default();
    let (port, _, _) = tcp_listen(
        None,
        token.clone(),
        0,
        0,
        false,
        true,
        None,
        Some(authority.clone()),
        descriptor_session.clone(),
    )
    .unwrap();

    // Pending handshakes that never authenticate, held open for the whole
    // test. One of them presents a connection id but never a Hello.
    let mut pending: Vec<TcpStream> = (0..max_workers + 1)
        .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
        .collect();
    pending[0].write_all(&0u32.to_be_bytes()).unwrap();
    // Reachability probes: connect and hang up without sending anything.
    for _ in 0..max_workers + 1 {
        drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
    }
    // Give the accept loop (which polls every 25ms) time to take every
    // pending socket, then confirm each is being served rather than
    // dropped. A socket with no connection id stays silent; the one that
    // supplied an id receives the server's proactive wire preamble.
    std::thread::sleep(Duration::from_millis(200));
    for socket in &pending {
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut byte = [0u8; 1];
        match (&*socket).read(&mut byte) {
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Ok(1) => {}
            other => panic!("pending socket was not held open: {other:?}"),
        }
    }

    // Every granted worker must still authenticate despite the probes and
    // pending sockets above.
    let mut workers: Vec<TcpStream> = (0..max_workers)
        .map(|_| authenticated_worker(port, &token).unwrap())
        .collect();

    // The grant's allowance is exhausted by authenticated workers alone.
    let refused = authenticated_worker(port, &token);
    assert!(
        refused.is_err(),
        "worker beyond the grant limit was accepted"
    );

    // Releasing one worker returns its permit.
    drop(workers.pop());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let replacement = loop {
        match authenticated_worker(port, &token) {
            Ok(socket) => break socket,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("released permit was not reusable: {error:#}"),
        }
    };
    workers.push(replacement);

    drop(pending);
    drop(workers);
    authority.close_control();
    descriptor_session.close();
}

#[test]
fn stream_worker_rebinds_only_live_files_from_its_original_session() {
    use crate::descriptor_copy::Settings;
    use std::fs::File;
    let temporary = crate::test_support::tempdir().unwrap();
    let source = temporary.path().join("source");
    let target = temporary.path().join("target");
    std::fs::write(&source, b"source").unwrap();
    let slot = DescriptorSessionSlot::managed().unwrap();
    let read = slot
        .register_stream(File::open(&source).unwrap(), false)
        .unwrap();
    let write = slot
        .register_stream(File::create(&target).unwrap(), true)
        .unwrap();
    let foreign = DescriptorSessionSlot::managed().unwrap();
    let foreign_ticket = foreign
        .register_stream(File::open(&source).unwrap(), false)
        .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let shared = slot.clone();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        serve(
            socket.try_clone().unwrap(),
            socket.try_clone().unwrap(),
            false,
            None,
            None,
            Some(socket),
            ServeSession {
                handshake_pending: None,
                ssh_worker_ticket: None,
                allow_tcp: false,
                named_socket: None,
                authority: None,
                descriptor_session: shared,
            },
        )
        .unwrap();
    });
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut reader = FrameReader::new(socket.try_clone().unwrap());
    let mut writer = FrameWriter::new(socket.try_clone().unwrap(), true);
    writer
        .write_msg(&Request::Hello {
            identity: crate::identity::build().to_string(),
            compress: true,
            debug: false,
            token: Vec::new(),
            role: ConnectionRole::StreamWorker {
                ticket: read.clone(),
                settings: Settings::default(),
            },
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::HelloOk { .. }
    ));
    let range = Request::ReadRange {
        path: Vec::new(),
        source: None,
        attempt: 0,
        off: 0,
        len: 6,
    };
    writer.write_msg(&range).unwrap();
    assert!(
        matches!(reader.read_msg::<Response>().unwrap(), Response::Block { data, .. } if data == b"source")
    );
    // Pipelined release/rebind must have exactly two checked replies.
    writer.write_msg(&Request::BindStream(None)).unwrap();
    writer
        .write_msg(&Request::BindStream(Some((write, Settings::default()))))
        .unwrap();
    for _ in 0..2 {
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Ok
        ));
    }
    writer
        .write_msg(&Request::WriteRange {
            path: Vec::new(),
            inplace: true,
            copy_id: [0; 16],
            attempt: 0,
            off: 0,
            hash: [0; 32],
            data: b"written".to_vec(),
            guard: None,
        })
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Ok
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"written");
    writer.write_msg(&range).unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(_)
    ));
    writer
        .write_msg(&Request::BindStream(Some((
            foreign_ticket,
            Settings::default(),
        ))))
        .unwrap();
    assert!(
        matches!(reader.read_msg::<Response>().unwrap(), Response::Err(error) if error.contains("sessions"))
    );
    writer.write_msg(&Request::BindStream(None)).unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Ok
    ));
    writer.write_msg(&range).unwrap();
    assert!(
        matches!(reader.read_msg::<Response>().unwrap(), Response::Err(error) if error.contains("no active entry"))
    );
    slot.release_stream(&read);
    writer
        .write_msg(&Request::BindStream(Some((read, Settings::default()))))
        .unwrap();
    assert!(matches!(
        reader.read_msg::<Response>().unwrap(),
        Response::Err(_)
    ));
    socket.shutdown(std::net::Shutdown::Both).unwrap();
    server.join().unwrap();
    slot.close();
    foreign.close();
}
