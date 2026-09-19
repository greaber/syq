#[test]
fn bootstrap_notices_exclude_ssh_noise_and_preserve_individual_lines() {
    let stderr = b"Warning: new host key\nsshd banner\n\nsyq-remote-install-notice:installed syq\n\nrc noise\n\nsyq-remote-install-notice:check SSH PATH\r\n";
    assert_eq!(
        super::install_notices(stderr).collect::<Vec<_>>(),
        ["installed syq", "check SSH PATH"]
    );
    assert_eq!(
        super::output_suffix(stderr),
        ": Warning: new host key\nsshd banner\n\nrc noise"
    );
    assert_eq!(
        super::output_suffix(b"syq-remote-install-notice:installed syq\r\n"),
        ""
    );
    assert_eq!(
        super::output_message(b"syq: error mentions syq-remote-install-notice: tag\n"),
        "error mentions syq-remote-install-notice: tag"
    );
}

#[test]
fn bootstrap_errors_preserve_blank_lines_except_notice_separators() {
    let diagnostic = "syq: first paragraph\n\nsecond paragraph\n\n\nlast paragraph\n";
    assert_eq!(
        super::output_message(diagnostic.as_bytes()),
        diagnostic.trim().strip_prefix("syq: ").unwrap()
    );
    let stderr = b"first\n\n\nsyq-remote-install-notice:installed\n\nsyq-remote-install-notice:PATH hint\nlast\n";
    assert_eq!(super::output_message(stderr), "first\n\nlast");
}

#[test]
fn bootstrap_stderr_preserves_invalid_utf8_in_both_channels() {
    let stderr = b"SSH noise: \xff\nsyq-remote-install-notice:installed at \xfe\r\n";
    assert_eq!(
        super::install_notices(stderr).collect::<Vec<_>>(),
        ["installed at \u{fffd}"]
    );
    assert_eq!(super::output_message(stderr), "SSH noise: \u{fffd}");
}

#[test]
fn advertised_tcp_port_must_match_requested_range() {
    for port in [47_600, 47_650, 47_699] {
        super::validate_advertised_tcp_port(port, (47_600, 47_699)).unwrap();
    }
    for port in [0, 22, 47_599, 47_700, u16::MAX] {
        assert!(super::validate_advertised_tcp_port(port, (47_600, 47_699)).is_err());
    }
    super::validate_advertised_tcp_port(12345, (12345, 12345)).unwrap();
    assert!(super::validate_advertised_tcp_port(12346, (12345, 12345)).is_err());
    // Existing test and local listener callers use (0, 0) for OS allocation.
    for port in [1, 47_650, u16::MAX] {
        super::validate_advertised_tcp_port(port, (0, 0)).unwrap();
    }
    assert!(super::validate_advertised_tcp_port(0, (0, 0)).is_err());
}

#[test]
fn tcp_connection_ids_fail_at_nonce_space_exhaustion() {
    let next = std::sync::atomic::AtomicU32::new(crate::tcp_records::CONNECTION_ID_MAX);
    assert_eq!(super::next_tcp_connection_id(&next).unwrap(), 0x00ff_ffff);
    for _ in 0..3 {
        assert!(super::next_tcp_connection_id(&next)
            .unwrap_err()
            .to_string()
            .contains("restart the copy"));
    }
    assert_eq!(next.load(std::sync::atomic::Ordering::Relaxed), 0x0100_0000);
}

use super::*;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

fn hello_ok() -> Response {
    Response::HelloOk {
        identity: crate::identity::build().into(),
        platform: crate::identity::platform(),
        supports_confined_socket_nodes: crate::identity::supports_confined_socket_nodes(),
        ssh_worker_ticket: None,
    }
}

#[test]
fn response_start_precedes_payload_and_buffered_replies_have_no_wait() {
    // Feed the real reader in separately released chunks. No clock sleeps:
    // the reader announces each blocking input read, so arrival ordering is
    // checked independently of how fast the test machine runs.
    struct Chunks {
        current: std::io::Cursor<Vec<u8>>,
        input: std::sync::mpsc::Receiver<Vec<u8>>,
        waiting: std::sync::mpsc::Sender<()>,
    }
    impl Read for Chunks {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if out.is_empty() {
                return Ok(0);
            }
            loop {
                let n = self.current.read(out)?;
                if n > 0 {
                    return Ok(n);
                }
                self.waiting.send(()).map_err(std::io::Error::other)?;
                match self.input.recv_timeout(std::time::Duration::from_secs(2)) {
                    Ok(chunk) if chunk.is_empty() => {
                        return Err(std::io::ErrorKind::Interrupted.into());
                    }
                    Ok(chunk) => self.current = std::io::Cursor::new(chunk),
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                    Err(error) => return Err(std::io::Error::other(error)),
                }
            }
        }
    }
    let (send, input) = std::sync::mpsc::channel();
    let (waiting, blocked) = std::sync::mpsc::channel();
    let next_read = || {
        blocked
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
    };
    let (rx, reader) = spawn_reader(
        Box::new(Chunks {
            current: std::io::Cursor::new(Vec::new()),
            input,
            waiting,
        }),
        4,
    );
    let mut wire = Vec::new();
    FrameWriter::new(&mut wire, false)
        .write_msg(&hello_ok())
        .unwrap();
    next_read();
    send.send(wire).unwrap();
    assert!(matches!(
        rx.recv().unwrap().unwrap().value,
        Response::HelloOk { .. }
    ));
    let mut wire = Vec::new();
    let mut writer = FrameWriter::with_preamble_written(&mut wire, false);
    let data = vec![42; 1 << 20];
    writer
        .write_msg(&Response::SmallBlocks(vec![Ok(SmallBlock {
            hash: crate::fsops::content_digest(&data),
            data,
        })]))
        .unwrap();
    writer.write_msg(&Response::Ok).unwrap();
    drop(writer);
    next_read();
    send.send(Vec::new()).unwrap(); // Interrupted before the next frame.
    next_read(); // The live reader retries, preserving its next reply.
    let before_header = std::time::Instant::now();
    send.send(wire[..5].to_vec()).unwrap();
    next_read(); // The frame header arrived; the payload is still withheld.
    let before_payload = std::time::Instant::now();
    send.send(wire[5..].to_vec()).unwrap();
    drop(send);
    let reply = rx.recv().unwrap().unwrap();
    assert!(reply.started_at >= before_header);
    assert!(reply.started_at <= before_payload);
    assert!(matches!(reply.value, Response::SmallBlocks(_)));
    reader.join().unwrap(); // The following reply and EOF are already queued.
    let mut conn = RemoteConn {
        observation: Default::default(),
        child: None,
        w: FrameWriter::new(Box::new(std::io::sink()), false),
        rx: Some(rx),
        reader: None,
        label: "reply timing test".into(),
        dead: false,
        rpc_observation: None,
        write_stream: None,
        peer: None,
        tcp_socket: None,
        named_socket: None,
        multiplexed_ssh: false,
        detached: false,
    };
    let (reply, waited) = conn.recv_with_wait().unwrap();
    assert!(matches!(reply, Response::Ok));
    assert_eq!(waited, std::time::Duration::ZERO);
    assert!(
        conn.recv_with_wait().is_err(),
        "EOF remains a transport error"
    );
    assert!(conn.is_dead());
}

#[test]
fn observation_frames_do_not_enter_the_data_queue_or_bypass_identity_pinning() {
    for accepted in [true, false] {
        let mut wire = Vec::new();
        let mut writer = FrameWriter::new(&mut wire, false);
        let mut hello = hello_ok();
        if !accepted {
            if let Response::HelloOk { identity, .. } = &mut hello {
                *identity = "v0.6.0".into();
            }
        }
        writer.write_msg(&hello).unwrap();
        for solicited in [false, false, true] {
            writer
                .write_msg(&Response::TransportStats(Box::new(TransportStatsReply {
                    tcp: None,
                    observation: Some(crate::transfer_observations::Registry::default().snapshot()),
                    solicited,
                })))
                .unwrap();
        }
        writer.write_msg(&Response::Ok).unwrap();
        drop(writer);
        let observation =
            std::sync::Arc::new(crate::transfer_observations::RemoteSample::default());
        let (rx, thread) =
            spawn_observed_reader(Box::new(std::io::Cursor::new(wire)), 1, observation.clone());
        assert!(matches!(
            rx.recv().unwrap().unwrap().value,
            Response::HelloOk { .. }
        ));
        if accepted {
            assert!(matches!(
                rx.recv().unwrap().unwrap().value,
                Response::TransportStats(_)
            ));
            assert!(matches!(rx.recv().unwrap().unwrap().value, Response::Ok));
            assert!(observation.latest.lock().unwrap().is_some());
        } else {
            assert!(rx.recv().is_err());
            assert!(observation.latest.lock().unwrap().is_none());
        }
        drop(rx);
        thread.join().unwrap();
    }
}

#[test]
fn client_handshake_limit_applies_before_reading_the_body() {
    let mut wire = Vec::new();
    FrameWriter::new(&mut wire, false).write_preamble().unwrap();
    wire.extend_from_slice(&((MAX_HANDSHAKE_FRAME + 1) as u32).to_le_bytes());
    let (rx, thread) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
    let error = rx.recv().unwrap().unwrap_err();
    assert!(error.to_string().contains("bad frame length"));
    assert!(rx.recv().is_err());
    thread.join().unwrap();
}

#[test]
fn client_handshake_limit_also_bounds_compressed_output() {
    let mut hello = hello_ok();
    if let Response::HelloOk { platform, .. } = &mut hello {
        *platform = "x".repeat(MAX_HANDSHAKE_FRAME + 1);
    }
    let payload = postcard::to_stdvec(&hello).unwrap();
    let body = zstd::bulk::compress(&payload, 1).unwrap();
    let mut wire = Vec::new();
    FrameWriter::new(&mut wire, false).write_preamble().unwrap();
    wire.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    wire.push(1);
    wire.extend_from_slice(&body);
    let (rx, thread) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
    assert!(rx
        .recv()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("decompressed frame exceeds limit"));
    thread.join().unwrap();
}

#[test]
fn client_reader_requires_accepted_hello_before_large_data() {
    for accepted in [false, true] {
        let mut wire = Vec::new();
        let mut writer = FrameWriter::new(&mut wire, false);
        let mut hello = hello_ok();
        if let Response::HelloOk { identity, .. } = &mut hello {
            if !accepted {
                *identity = "wrong-build".into();
            }
        }
        writer.write_msg(&hello).unwrap();
        writer
            .write_msg(&Response::Block {
                off: 0,
                hash: [0; 32],
                data: vec![7; 2 << 20],
            })
            .unwrap();
        drop(writer);
        let (rx, thread) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
        assert!(matches!(
            rx.recv().unwrap().unwrap().value,
            Response::HelloOk { .. }
        ));
        if accepted {
            assert!(
                matches!(rx.recv().unwrap().unwrap().value, Response::Block { data, .. } if data.len() == 2 << 20)
            );
        } else {
            assert!(rx.recv().is_err());
        }
        drop(rx);
        thread.join().unwrap();
    }
}

#[test]
fn remote_vector_replies_must_match_request_counts() {
    for count in [0, 1, 2] {
        let cases = [
            (
                Request::StatMany {
                    paths: vec![b"file".to_vec()],
                    sources: None,
                    follow: false,
                    guard: None,
                },
                Response::Stats(vec![None; count]),
            ),
            (
                Request::Apply {
                    ops: vec![Op::Unlink {
                        path: b"file".to_vec(),
                    }],
                    guard: None,
                },
                Response::Applied(vec![None; count]),
            ),
            (
                Request::PartialPaths {
                    paths: vec![b"file".to_vec()],
                    copy_id: [0; 16],
                    guard: None,
                },
                Response::PathResults(vec![Ok(b"partial".to_vec()); count]),
            ),
        ];
        for (request, response) in cases {
            let mut bytes = Vec::new();
            let mut writer = FrameWriter::new(&mut bytes, false);
            writer.write_msg(&hello_ok()).unwrap();
            writer.write_msg(&response).unwrap();
            drop(writer);
            let (rx, reader) = spawn_reader(Box::new(std::io::Cursor::new(bytes)), 4);
            let mut conn = RemoteConn {
                observation: Default::default(),
                child: None,
                w: FrameWriter::new(Box::new(std::io::sink()), false),
                rx: Some(rx),
                reader: Some(reader),
                label: "hostile vector reply".into(),
                dead: false,
                rpc_observation: None,
                write_stream: None,
                peer: None,
                tcp_socket: None,
                named_socket: None,
                multiplexed_ssh: false,
                detached: false,
            };
            conn = receive_hello(conn, false).unwrap();
            let result = conn.call(request);
            if count == 1 {
                assert!(result.is_ok());
            } else {
                assert!(result.unwrap_err().to_string().contains("reply count"));
            }
        }
    }
}

#[test]
fn excessive_probe_candidates_fail_before_resolution() {
    let mut candidates: Vec<_> = (0..MAX_ADVERTISED_TCP_ADDRESSES + 2)
        .map(|_| TcpCandidate {
            address: "must-not-resolve.invalid".into(),
            speed_mbps: 0,
            source: DataAddressSource::RemoteInterface,
            reachable: false,
            selected: false,
        })
        .collect();
    assert!(probe_reachable(&mut candidates, 1)
        .unwrap_err()
        .to_string()
        .contains("too many"));
}

struct ExitObserved<R> {
    inner: R,
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[test]
fn local_workers_clone_the_control_descriptor_session_in_process() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    std::fs::create_dir(&selected).unwrap();
    let endpoint = Endpoint::local();
    let mut control = endpoint.connect_control(false).unwrap();
    let response = control
        .call(Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 1,
            independent_handoff_workers: 0,
        })
        .unwrap();
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };

    // Once the socket name is gone, an empty session slot cannot claim the
    // ticket with SCM_RIGHTS. The endpoint clone still succeeds because it
    // reaches the control connection's process-local registry instead.
    std::fs::remove_file(roots[0].ticket.broker_path()).unwrap();
    endpoint
        .connect_with_sources(false, roots.clone(), false)
        .unwrap();
    let error = Endpoint::local()
        .connect_with_sources(false, roots, false)
        .err()
        .expect("a fresh local endpoint must not share another session");
    assert!(format!("{error:#}").contains("connect to descriptor broker"));
}

#[test]
fn local_source_worker_rejects_destination_mutation_requests() {
    let temporary = crate::test_support::tempdir().unwrap();
    let selected = temporary.path().join("selected");
    std::fs::create_dir(&selected).unwrap();
    let marker = selected.join("marker");
    std::fs::write(&marker, b"marker").unwrap();
    let endpoint = Endpoint::local();
    let mut control = endpoint.connect_control(false).unwrap();
    let response = control
        .call(Request::RegisterSourceRoots {
            base: SourceRootBase::default(),
            selections: vec![SourceRootSelection {
                path: selected.as_os_str().as_bytes().to_vec(),
                follow_root: false,
            }],
            symlink_policy: OperatorSymlinkPolicy::Refuse,
            allow_unconfined_paths: false,
            shared_workers: 1,
            independent_handoff_workers: 0,
        })
        .unwrap();
    let Response::SourceRootsRegistered(roots) = response else {
        panic!("unexpected source registration response: {response:?}")
    };
    let source_marker = roots[0].selection.join(b"marker").unwrap();
    let mut source = endpoint.connect_with_sources(false, roots, false).unwrap();

    let response = source
        .call(Request::ReadRange {
            path: b"contradictory-path".to_vec(),
            source: Some(source_marker.clone()),
            attempt: 0,
            off: 0,
            len: 6,
        })
        .unwrap();
    assert!(matches!(response, Response::Block { data, .. } if data == b"marker"));

    for reference in [Some(source_marker.clone()), None] {
        source
            .send(Request::ReadStream(ReadStreamRequest {
                path: marker.as_os_str().as_bytes().to_vec(),
                source: reference.clone(),
                attempt: 0,
                off: 0,
                end: 6,
                block: 512,
            }))
            .unwrap();
        assert!(matches!(source.recv().unwrap(), Response::Ok));
        let response = source.recv().unwrap();
        if reference.is_some() {
            assert!(matches!(response, Response::Block { data, .. } if data == b"marker"));
        } else {
            assert!(matches!(response, Response::EndpointError(_)));
        }
        assert!(matches!(source.recv().unwrap(), Response::ReadStreamDone));
        source.send(Request::ShrinkReadStream { end: 0 }).unwrap();
        source.send(Request::StopReadStream).unwrap();
        assert!(source.recv().is_err(), "Stop queued a second Done");
    }

    // One-way shrinking does not insert a response before the next block.
    // Preserve the original frame boundary even if the new limit cuts it.
    for end in [3, 0] {
        assert!(matches!(
            source
                .call(Request::ReadStream(ReadStreamRequest {
                    path: marker.as_os_str().as_bytes().to_vec(),
                    source: Some(source_marker.clone()),
                    attempt: 0,
                    off: 0,
                    end: 6,
                    block: 512,
                }))
                .unwrap(),
            Response::Ok
        ));
        let range = std::sync::Arc::new(std::sync::Mutex::new(crate::sched::RangeState {
            idx: 0,
            pos: 0,
            end,
        }));
        let mut announced = 6;
        assert!(
            crate::streaming::notify_shrunk_range(&range, &mut announced, &mut *source).unwrap()
        );
        assert_eq!(announced, end);
        assert!(
            !crate::streaming::notify_shrunk_range(&range, &mut announced, &mut *source).unwrap()
        );
        if end > 0 {
            assert!(
                matches!(source.recv().unwrap(), Response::Block { data, .. } if data == b"marker")
            );
        }
        assert!(matches!(source.recv().unwrap(), Response::ReadStreamDone));
        source.send(Request::StopReadStream).unwrap();
        // Invalid controls are ordinary replies outside stream mode on
        // both local and server connections, not local-only send errors.
        assert!(matches!(
            source.call(Request::ShrinkReadStream { end: 0 }).unwrap(),
            Response::Err(error) if error == "no read stream is active"
        ));
    }

    let response = source
        .call(Request::Apply {
            ops: vec![Op::Unlink {
                path: marker.as_os_str().as_bytes().to_vec(),
            }],
            guard: None,
        })
        .unwrap();
    assert!(
        matches!(response, Response::Err(error) if error.contains("not valid on a source worker"))
    );
    assert_eq!(std::fs::read(&marker).unwrap(), b"marker");

    let response = source
        .call(Request::ListDir {
            directory: selected.as_os_str().as_bytes().to_vec(),
            confined_root: None,
            prefix: b"mar".to_vec(),
            limit: 10,
            symlink_policy: crate::proto::OperatorSymlinkPolicy::Refuse,
        })
        .unwrap();
    assert!(
        matches!(response, Response::Err(error) if error.contains("only on the control connection"))
    );

    let selection = [NativeRemoveSelection {
        path: b"marker".to_vec(),
        kind: NativeRemoveKind::File,
    }];
    let mut trace = |_| Ok(());
    let mut sink = |_| Ok(());
    let error = source
        .native_remove(
            Some(selected.as_os_str().as_bytes()),
            None,
            &selection,
            false,
            false,
            1,
            &mut trace,
            &mut sink,
        )
        .unwrap_err();
    assert!(error.to_string().contains("only on the control connection"));
    assert_eq!(std::fs::read(&marker).unwrap(), b"marker");

    // Match the remote server's non-control gate for destination workers
    // too; this direct trait method must not be a role bypass.
    let role = ConnectionRole::DestinationWorker {
        destination: None,
        copy_sources: Vec::new(),
    };
    let mut destination = LocalConn::new(&role, Default::default());
    let error = destination
        .native_remove(
            Some(selected.as_os_str().as_bytes()),
            None,
            &selection,
            false,
            false,
            1,
            &mut trace,
            &mut sink,
        )
        .unwrap_err();
    assert!(error.to_string().contains("only on the control connection"));
    assert_eq!(std::fs::read(&marker).unwrap(), b"marker");
}

impl<R: Read> Read for ExitObserved<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
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
fn openssh_version_banners_parse_and_compare() {
    let parse = |banner: &str| parse_openssh_version(banner.as_bytes());
    assert_eq!(
        parse("OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 30 Jan 2024\n"),
        Some(OpenSshVersion { major: 9, minor: 6 })
    );
    assert_eq!(
        parse("OpenSSH_8.9p1, LibreSSL 3.3.6"),
        Some(CONSTRAINED_OPENSSH_MINIMUM)
    );
    assert_eq!(
        parse("OpenSSH_10.0p2"),
        Some(OpenSshVersion {
            major: 10,
            minor: 0
        })
    );
    assert_eq!(parse("Dropbear v2024.85"), None);
    assert_eq!(parse("OpenSSH_"), None);
    assert!(OpenSshVersion { major: 8, minor: 2 } < CONSTRAINED_OPENSSH_MINIMUM);
    assert!(
        OpenSshVersion {
            major: 8,
            minor: 10
        } > CONSTRAINED_OPENSSH_MINIMUM
    );
    assert!(OpenSshVersion { major: 9, minor: 0 } > CONSTRAINED_OPENSSH_MINIMUM);
    assert_eq!(CONSTRAINED_OPENSSH_MINIMUM.to_string(), "OpenSSH 8.9");
}

#[test]
fn ordinary_range_drain_consumes_errors_but_not_the_next_operation() {
    let mut conn = LocalConn::new(&ConnectionRole::Control, Default::default());
    conn.pending.extend([
        Response::Err("first failed write".into()),
        Response::Err("later failed write".into()),
        Response::Path(b"next operation".to_vec()),
    ]);
    let error = drain_range_replies(&mut conn, 2, "write").unwrap_err();
    assert!(error.to_string().contains("first failed write"));
    assert!(matches!(conn.recv().unwrap(), Response::Path(path) if path == b"next operation"));
    assert!(conn.pending.is_empty());
    conn.begin_streaming_writes(None).unwrap();
    let fence = conn.fence_streaming_writes();
    conn.finish_streaming_writes(0, fence).unwrap();
}

#[test]
fn range_drain_reports_acknowledgements_before_a_receive_failure() {
    let mut conn = LocalConn::new(&ConnectionRole::Control, Default::default());
    conn.pending
        .extend([Response::Err("failed write".into()), Response::Ok]);
    let mut acknowledged = Vec::new();
    // The third receive fails with no pending response. LocalConn does not
    // mark itself dead; draining must still stop at that transport error.
    assert!(drain_range_replies_with(
        &mut conn,
        ["first", "second", "third", "fourth"],
        "write",
        |item| acknowledged.push(item),
    )
    .is_err());
    assert_eq!(acknowledged, ["second"]);
    assert!(!conn.is_dead());
    assert!(conn.pending.is_empty());
}

#[test]
fn inactive_remote_stream_fence_does_not_write_or_take_the_reader() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountWrites(Arc<AtomicUsize>);
    impl Write for CountWrites {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
    let (_tx, rx) = std::sync::mpsc::channel();
    let writes = Arc::new(AtomicUsize::new(0));
    let mut conn = RemoteConn {
        observation: Default::default(),
        child: None,
        w: FrameWriter::new(Box::new(CountWrites(writes.clone())), false),
        rx: Some(rx),
        reader: None,
        label: "inactive stream test".into(),
        dead: false,
        rpc_observation: None,
        write_stream: None,
        peer: None,
        tcp_socket: None,
        named_socket: None,
        multiplexed_ssh: false,
        detached: true,
    };
    let fence = conn.fence_streaming_writes();
    assert!(fence.is_err());
    assert!(conn.finish_streaming_writes(0, fence).is_err());
    assert!(conn.rx.is_some());
    assert!(!conn.dead);
    // Drop normally sends Shutdown; that is outside the operation under test.
    assert_eq!(writes.load(Ordering::Relaxed), 0);
}

#[test]
fn an_old_client_is_not_retried() {
    let error: anyhow::Error = OpenSshVersionError("too old".to_owned()).into();
    assert!(is_non_retryable_connect_error(&error));
    assert!(is_non_retryable_connect_error(
        &error.context("connect to the coordinator")
    ));
    assert!(!is_non_retryable_connect_error(&anyhow!(
        "connection reset"
    )));
}

#[test]
fn only_ssh_named_programs_are_probed_for_a_version() {
    assert_eq!(openssh_version("fake-rsh"), None);
    assert_eq!(openssh_version("/definitely/missing/ssh"), None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn kernel_tcp_stats_are_available_for_a_live_socket() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut byte = [0u8; 1];
        socket.read_exact(&mut byte).unwrap();
        socket.write_all(&byte).unwrap();
        tcp_socket_stats(&socket).unwrap()
    });
    let mut client = TcpStream::connect(address).unwrap();
    client.write_all(&[7]).unwrap();
    let mut byte = [0u8; 1];
    client.read_exact(&mut byte).unwrap();
    let client_stats = tcp_socket_stats(&client).unwrap();
    let server_stats = server.join().unwrap();
    assert_eq!(byte, [7]);
    assert!(
        client_stats.segments_sent.is_some_and(|value| value > 0)
            || client_stats.bytes_sent.is_some_and(|value| value > 0),
        "{client_stats:?}"
    );
    assert!(
        server_stats.segments_sent.is_some_and(|value| value > 0)
            || server_stats.bytes_sent.is_some_and(|value| value > 0),
        "{server_stats:?}"
    );
    #[cfg(target_os = "linux")]
    {
        assert!(client_stats.congestion_control.is_some());
        assert!(server_stats.congestion_control.is_some());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_tcp_congestion_is_set_before_connect_and_inherited_on_accept() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    assert_eq!(
        configure_tcp_congestion(&listener, Some("reno")).unwrap(),
        Some("reno".into())
    );
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        tcp_congestion_control(&socket).unwrap()
    });
    let client =
        connect_tcp_stream(&address, std::time::Duration::from_secs(1), Some("reno")).unwrap();
    assert_eq!(tcp_congestion_control(&client).unwrap(), "reno");
    assert_eq!(server.join().unwrap(), "reno");
}

#[cfg(target_os = "linux")]
#[test]
fn rejected_tcp_congestion_is_classified_separately() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let error = configure_tcp_congestion(&listener, Some("syq_missing_cc")).unwrap_err();
    assert!(is_tcp_congestion_error(&error));
    assert!(error.to_string().contains("kernel rejected"));
}

#[cfg(target_os = "linux")]
#[test]
fn connecting_socket_congestion_rejection_is_attributed_to_coordinator() {
    let spec = RemoteSpec {
        local_process: false,
        user: None,
        host: "remote.example".into(),
        port: None,
        rsh: vec!["ssh".into()],
        syq_path: None,
        bootstrap_helper: false,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: None,
        quiet: false,
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };
    let info = TcpInfo {
        addrs: vec!["127.0.0.1".into()],
        port: 9,
        key: None,
        token: Vec::new(),
        congestion_control: Some("syq_missing_cc".into()),
        failed: false,
        failure: None,
        next: Default::default(),
    };

    let error = spec
        .connect_tcp(
            &info,
            false,
            ConnectionRole::SourceWorker { roots: Vec::new() },
        )
        .expect_err("unregistered congestion control should fail locally");
    let message = format!("{error:#}");
    assert!(is_tcp_congestion_error(&error));
    assert!(message
        .contains("coordinator could not configure the connecting data socket to remote.example"));
}

#[test]
fn tcp_fallback_note_scopes_the_unused_override_to_ssh() {
    assert_eq!(tcp_congestion_fallback_note(None), "");
    assert_eq!(
        tcp_congestion_fallback_note(Some("reno")),
        "; requested congestion control reno is not used by the SSH fallback"
    );
}

#[test]
fn only_the_local_receiver_disables_requested_tcp_compression() {
    for local_process in [false, true] {
        for requested in [false, true] {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut id = [0; 4];
                socket.read_exact(&mut id).unwrap();
                let mut reader =
                    FrameReader::new(RecordReader::new(socket.try_clone().unwrap(), None));
                let Request::Hello { compress, .. } = reader.read_msg().unwrap() else {
                    panic!("expected Hello");
                };
                let mut writer = FrameWriter::new(RecordWriter::new(socket, None), false);
                writer.write_msg(&hello_ok()).unwrap();
                compress
            });
            let mut spec = RemoteSpec::local_receiver(false);
            // Even an explicit SSH endpoint on loopback is not the
            // in-process receiver and keeps the requested compression.
            spec.local_process = local_process;
            let info = TcpInfo {
                addrs: vec!["127.0.0.1".into()],
                port,
                key: None,
                token: Vec::new(),
                congestion_control: None,
                failed: false,
                failure: None,
                next: Default::default(),
            };
            let conn = spec
                .connect_tcp(&info, requested, ConnectionRole::Control)
                .unwrap();
            let expected = requested && !local_process;
            assert_eq!(conn.w.compress, expected);
            assert_eq!(server.join().unwrap(), expected);
        }
    }
}

#[test]
fn rejected_worker_initialization_is_not_a_retryable_transport_error() {
    let error: anyhow::Error = WorkerInitializationError("destination changed".into()).into();
    assert!(is_worker_initialization_error(&error));
    assert!(!is_tcp_congestion_error(&error));
}

#[test]
fn hello_carries_destination_initialization_before_readiness() {
    let temp = crate::test_support::tempdir().unwrap();
    let descriptor_session = crate::descriptor_broker::DescriptorSessionSlot::default();
    let ticket = descriptor_session
        .register(std::fs::File::open(temp.path()).unwrap())
        .unwrap();
    let destination = DestinationRoot {
        ticket,
        request_prefix: b"destination".to_vec(),
    };
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut reader = FrameReader::new(socket.try_clone().unwrap());
        let hello = reader.read_msg::<Request>().unwrap();
        let Request::Hello {
            role:
                ConnectionRole::DestinationWorker {
                    destination: Some(destination),
                    copy_sources,
                },
            ..
        } = hello
        else {
            panic!("destination initialization was not carried in Hello");
        };
        assert!(copy_sources.is_empty());
        assert_eq!(destination.request_prefix, b"destination");

        let mut writer = FrameWriter::new(socket, false);
        writer
            .write_msg(&Response::HelloOk {
                identity: crate::identity::build().to_string(),
                platform: crate::identity::platform(),
                supports_confined_socket_nodes: crate::identity::supports_confined_socket_nodes(),
                ssh_worker_ticket: None,
            })
            .unwrap();
    });

    let socket = TcpStream::connect(address).unwrap();
    let (rx, reader) = spawn_reader(
        Box::new(socket.try_clone().unwrap()),
        crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    );
    let conn = RemoteConn {
        observation: Default::default(),
        child: None,
        w: FrameWriter::new(Box::new(socket), false),
        rx: Some(rx),
        reader: Some(reader),
        label: "pipelined hello test".into(),
        dead: false,
        rpc_observation: None,
        write_stream: None,
        peer: None,
        tcp_socket: None,
        named_socket: None,
        multiplexed_ssh: false,
        detached: false,
    };
    let conn = hello(
        conn,
        false,
        Vec::new(),
        ConnectionRole::DestinationWorker {
            destination: Some(destination),
            copy_sources: Vec::new(),
        },
    )
    .unwrap();
    assert!(conn.peer.is_some());
    drop(conn);
    server.join().unwrap();
    descriptor_session.close();
}

#[test]
fn unexpected_hello_response_reports_version_skew_without_retry() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let mut reader = FrameReader::new(socket.try_clone().unwrap());
        assert!(matches!(
            reader.read_msg::<Request>().unwrap(),
            Request::Hello { .. }
        ));
        FrameWriter::new(socket, false)
            .write_msg(&Response::Ok)
            .unwrap();
    });

    let socket = TcpStream::connect(address).unwrap();
    let (rx, reader) = spawn_reader(
        Box::new(socket.try_clone().unwrap()),
        crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    );
    let conn = RemoteConn {
        observation: Default::default(),
        child: None,
        w: FrameWriter::new(Box::new(socket), false),
        rx: Some(rx),
        reader: Some(reader),
        label: "version-skew test".into(),
        dead: false,
        rpc_observation: None,
        write_stream: None,
        peer: None,
        tcp_socket: None,
        named_socket: None,
        multiplexed_ssh: false,
        detached: false,
    };
    let error = hello(conn, false, Vec::new(), ConnectionRole::Control)
        .expect_err("an operation response is not a valid handshake");
    let message = format!("{error:#}");
    assert!(
        message.contains("unexpected handshake response"),
        "{message}"
    );
    assert!(
        message.contains("remote syq may be a different version"),
        "{message}"
    );
    assert!(is_non_retryable_connect_error(&error));
    server.join().unwrap();
}

#[test]
fn malformed_wire_preamble_is_non_retryable_and_refreshes_a_managed_helper() {
    let error =
        anyhow!("{WIRE_PREAMBLE_PROTOCOL_ERROR}: remote syq sent an invalid build identity");
    assert!(is_non_retryable_connect_error(&error));
    assert!(helper_needs_install(&error));
}

#[test]
fn ssh_exit_255_wins_over_a_missing_wire_preamble() {
    let child = Command::new("/bin/sh")
        .args(["-c", "exit 255"])
        .spawn()
        .unwrap();
    let mut conn = RemoteConn {
        observation: Default::default(),
        child: Some(child),
        w: FrameWriter::new(Box::new(std::io::sink()), false),
        rx: None,
        reader: None,
        label: "retryable SSH test".into(),
        dead: false,
        rpc_observation: None,
        write_stream: None,
        peer: None,
        tcp_socket: None,
        named_socket: None,
        multiplexed_ssh: false,
        detached: false,
    };
    let error = conn.io_err(
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("{WIRE_PREAMBLE_PROTOCOL_ERROR}: read header from remote syq"),
        )
        .into(),
    );
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("exit status: 255"), "{diagnostic}");
    assert!(!diagnostic.contains(WIRE_PREAMBLE_PROTOCOL_ERROR));
    assert!(!is_non_retryable_connect_error(&error));
    assert!(!helper_needs_install(&error));
}

#[test]
fn tuning_pipeline_drains_responses_while_sending_large_requests() {
    use std::os::unix::net::UnixStream;
    // Even a one-deep file pipeline must accommodate control batches.
    for (read_ahead, depth) in [(1, 4), (64, 64)] {
        let (coordinator, helper) = UnixStream::pair().unwrap();
        let timeout = std::time::Duration::from_secs(5);
        for socket in [&coordinator, &helper] {
            socket.set_read_timeout(Some(timeout)).unwrap();
            socket.set_write_timeout(Some(timeout)).unwrap();
        }
        let server = std::thread::spawn(move || {
            let mut requests = FrameReader::new(helper.try_clone().unwrap());
            let mut responses = FrameWriter::new(helper, false);
            responses.write_msg(&hello_ok()).unwrap();
            for _ in 0..depth {
                let Request::ReadRange { off, len, .. } = requests.read_msg().unwrap() else {
                    panic!("expected a range request");
                };
                responses
                    .write_msg(&Response::Block {
                        off,
                        hash: [0; 32],
                        data: vec![7; len as usize],
                    })
                    .unwrap();
            }
        });
        let (responses, reader) =
            spawn_reader(Box::new(coordinator.try_clone().unwrap()), read_ahead);
        assert!(matches!(
            responses.recv_timeout(timeout).unwrap().unwrap().value,
            Response::HelloOk { .. }
        ));
        let mut requests = FrameWriter::new(coordinator, false);
        // Both directions exceed socket buffering. A reader queue stuck at
        // four responses deadlocks against a sequential helper while the
        // coordinator is still sending its 64 requests.
        for i in 0..depth {
            requests
                .write_msg(&Request::ReadRange {
                    path: vec![b'x'; 16 << 10],
                    source: None,
                    attempt: 0,
                    off: i as u64 * (64 << 10),
                    len: 64 << 10,
                })
                .unwrap();
        }
        for i in 0..depth {
            let response = responses
                .recv_timeout(timeout)
                .unwrap()
                .unwrap()
                .into_inner();
            assert!(matches!(response, Response::Block { off, data, .. }
                if off == i as u64 * (64 << 10) && data == vec![7; 64 << 10]));
        }
        drop(responses);
        drop(requests);
        server.join().unwrap();
        reader.join().unwrap();
    }
}

#[test]
fn transport_stats_response_wait_has_a_deadline() {
    let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
    let timeout = std::time::Duration::from_millis(20);
    let start = std::time::Instant::now();
    assert!(receive_transport_stats(&receiver, timeout).is_none());
    assert!(start.elapsed() >= timeout);
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn repeatedly_retiring_timed_out_tcp_connections_joins_their_readers() {
    const CONNECTIONS: usize = 32;
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..CONNECTIONS {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request_bytes = Vec::new();
            socket.read_to_end(&mut request_bytes).unwrap();
            assert!(!request_bytes.is_empty());
        }
    });

    for _ in 0..CONNECTIONS {
        let socket = TcpStream::connect(address).unwrap();
        let writer = socket.try_clone().unwrap();
        let tcp_socket = socket.try_clone().unwrap();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let input = ExitObserved {
            inner: socket,
            dropped: dropped.clone(),
        };
        let (rx, reader) = spawn_reader(
            Box::new(input),
            crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        );
        let mut connection = RemoteConn {
            observation: Default::default(),
            child: None,
            w: FrameWriter::new(Box::new(writer), false),
            rx: Some(rx),
            reader: Some(reader),
            label: "test tcp".into(),
            dead: false,
            rpc_observation: None,
            write_stream: None,
            peer: None,
            tcp_socket: Some(std::sync::Arc::new(tcp_socket)),
            named_socket: None,
            multiplexed_ssh: false,
            detached: false,
        };
        let timeout = std::time::Duration::from_millis(5);
        let start = std::time::Instant::now();
        let _ = connection.transport_stats_with_timeout(timeout);
        assert!(start.elapsed() >= timeout);
        drop(connection);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(std::sync::Arc::strong_count(&dropped), 1);
    }
    server.join().unwrap();
}

fn entry(path: &[u8]) -> Entry {
    Entry {
        path: path.to_vec(),
        kind: Kind::File,
        size: 0,
        mtime: 0,
        mtime_nsec: 0,
        mode: 0,
        uid: 0,
        gid: 0,
        rdev: 0,
        dev: 0,
        ino: 0,
        ctime: 0,
        ctime_nsec: 0,
        link: None,
    }
}

#[test]
fn hostile_scan_cannot_deliver_excluded_entries_to_the_planner() {
    for (path, patterns, allowed) in [
        (b".env".as_slice(), vec![".env"], false),
        (
            b"ignored/keep/file",
            vec!["ignored/", "!ignored/keep/file"],
            false,
        ),
        (b"logs/keep/file", vec!["logs/*", "!logs/keep/"], true),
        (b"nested/.env", vec!["/.env"], true),
    ] {
        let mut wire = Vec::new();
        let mut writer = FrameWriter::new(&mut wire, false);
        writer.write_msg(&hello_ok()).unwrap();
        let mut root = entry(b"");
        root.kind = Kind::Dir;
        writer.write_msg(&Response::ScanBatch(vec![root])).unwrap();
        // No excluded ancestor is sent. Filtering must not depend on the
        // source's claimed tree order or on previous batches.
        writer
            .write_msg(&Response::ScanBatch(vec![entry(path)]))
            .unwrap();
        writer.write_msg(&Response::ScanDone).unwrap();
        drop(writer);
        let (rx, reader) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
        let mut remote = RemoteConn {
            observation: Default::default(),
            child: None,
            w: FrameWriter::new(Box::new(Vec::new()), false),
            rx: Some(rx),
            reader: Some(reader),
            label: "hostile source".into(),
            dead: false,
            rpc_observation: None,
            write_stream: None,
            peer: None,
            tcp_socket: None,
            named_socket: None,
            multiplexed_ssh: false,
            detached: false,
        };
        remote = receive_hello(remote, false).unwrap();
        let mut planned = Vec::new();
        let result = remote.scan(
            b"source",
            None,
            false,
            &patterns.into_iter().map(String::from).collect::<Vec<_>>(),
            false,
            &mut |entries| {
                planned.extend(entries.into_iter().map(|e| e.path));
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |_| {},
        );
        assert_eq!(result.is_ok(), allowed, "{path:?}: {result:?}");
        assert_eq!(planned.contains(&path.to_vec()), allowed);
        if !allowed {
            assert!(format!("{:#}", result.unwrap_err()).contains("excluded path"));
        }
    }
}

#[test]
fn remote_scan_paths_are_rooted_and_normalized() {
    let mut saw_root = false;
    validate_remote_scan_batch(&[entry(b""), entry(b"dir/file")], &mut saw_root, None).unwrap();
    assert!(saw_root);

    for bad in [
        &b"/absolute"[..],
        &b"../escape"[..],
        &b"dir/../escape"[..],
        &b"dir/./file"[..],
        &b"dir//file"[..],
        &b"dir/"[..],
        &b"nul\0byte"[..],
    ] {
        let mut saw_root = true;
        assert!(validate_remote_scan_batch(&[entry(bad)], &mut saw_root, None).is_err());
    }
}

#[test]
fn remote_scan_requires_exactly_one_leading_root() {
    let mut saw_root = false;
    assert!(validate_remote_scan_batch(&[entry(b"file")], &mut saw_root, None).is_err());

    let mut saw_root = true;
    assert!(validate_remote_scan_batch(&[entry(b"")], &mut saw_root, None).is_err());
}

#[test]
fn remote_download_report_rejects_an_oversized_line() {
    let mut input = b"syq-helper-manifest-begin\nsyq-helper-manifest-data:".to_vec();
    input.resize(input.len() + MAX_REPORT_LINE_BYTES + 16, b'x');
    let error = read_remote_download_report(&mut input.as_slice()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("line exceeded"), "{error}");
}

#[test]
fn capped_reads_keep_the_prefix_and_drain_the_rest() {
    let captured = read_capped(std::io::repeat(b'x').take(5000), 100).unwrap();
    assert_eq!(captured.bytes.len(), 100);
    assert!(captured.truncated);
    let captured = read_capped(&b"short"[..], 100).unwrap();
    assert_eq!(captured.bytes, b"short");
    assert!(!captured.truncated);
}

#[test]
fn captured_commands_bound_both_streams_and_feed_input() {
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg("cat >/dev/null; head -c 3000000 /dev/zero; echo boom >&2; exit 3")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run_captured(&mut cmd, Some(b"input")).unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout.bytes.len(), MAX_BOOTSTRAP_OUTPUT_BYTES);
    assert!(out.stdout.truncated);
    assert_eq!(out.stderr.bytes, b"boom\n");
    assert!(!out.stderr.truncated);
    assert!(out.input_error.is_none());
}

#[test]
fn remote_download_report_frames_manifest_and_digest() {
    let digest = "a".repeat(64);
    let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{\nsyq-helper-manifest-data:  \"schema\": 1\nsyq-helper-manifest-data:}}\nsyq-helper-manifest-end\nsyq-helper-sha256:{digest}\nsyq-helper-report-end\n"
        );
    let report = read_remote_download_report(&mut bytes.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(report.manifest, b"{\n  \"schema\": 1\n}\n");
    assert_eq!(report.sha256, digest);
}

#[test]
fn remote_download_report_rejects_unterminated_manifest() {
    let error = read_remote_download_report(
        &mut b"syq-helper-manifest-begin\nsyq-helper-manifest-data:{\"schema\":1}\n".as_slice(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn remote_download_report_keeps_injected_markers_inside_the_manifest() {
    let spoofed = "a".repeat(64);
    let actual = "b".repeat(64);
    let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{\"schema\":1}}\nsyq-helper-manifest-data:syq-helper-manifest-end\nsyq-helper-manifest-data:syq-helper-sha256:{spoofed}\nsyq-helper-manifest-end\nsyq-helper-sha256:{actual}\nsyq-helper-report-end\n"
        );
    let report = read_remote_download_report(&mut bytes.as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(report.sha256, actual);
    assert!(report
        .manifest
        .windows(b"syq-helper-manifest-end".len())
        .any(|window| window == b"syq-helper-manifest-end"));
    assert!(report
        .manifest
        .windows(spoofed.len())
        .any(|window| { window == spoofed.as_bytes() }));
}

#[test]
fn remote_download_report_rejects_data_after_the_digest() {
    let digest = "a".repeat(64);
    let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{}}\nsyq-helper-manifest-end\nsyq-helper-sha256:{digest}\nunexpected\nsyq-helper-report-end\n"
        );
    let error = read_remote_download_report(&mut bytes.as_bytes()).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn ssh_inherits_host_key_policy() {
    let spec = RemoteSpec {
        local_process: false,
        user: None,
        host: "example".to_string(),
        port: None,
        rsh: vec!["ssh".to_string()],
        syq_path: None,
        bootstrap_helper: false,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: None,
        quiet: false,
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };
    let command = spec.ssh_command(SshConnection::Independent, false);
    assert!(!command
        .get_args()
        .any(|arg| arg.to_string_lossy().starts_with("StrictHostKeyChecking=")));

    let mut configured = spec;
    configured.rsh = vec![
        "ssh".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=yes".to_string(),
    ];
    assert!(configured
        .ssh_command(SshConnection::Independent, false)
        .get_args()
        .any(|arg| arg == OsStr::new("StrictHostKeyChecking=yes")));
}

#[test]
fn worker_tcp_fallback_survives_broken_stderr() {
    if !crate::test_support::with_broken_stderr(
        "conn::tests::worker_tcp_fallback_survives_broken_stderr",
    ) {
        return;
    }
    let temporary = crate::test_support::tempdir().unwrap();
    let marker = temporary.path().join("ssh-attempted");
    let spec = RemoteSpec {
        local_process: false,
        user: None,
        host: "unused".into(),
        port: None,
        // The shell records that fallback was reached, then reports a
        // missing helper so no retry or real SSH connection is needed.
        rsh: vec![
            "/bin/sh".into(),
            "-c".into(),
            format!(
                "touch {}; exit 127",
                shell_words::quote(marker.to_str().unwrap())
            ),
        ],
        syq_path: None,
        bootstrap_helper: false,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: None,
        quiet: false,
        tcp: std::sync::Arc::new(std::sync::Mutex::new(Some(TcpInfo {
            addrs: vec!["invalid address".into()], // Fail resolution without DNS or a socket.
            port: 0,
            key: None,
            token: Vec::new(),
            congestion_control: None,
            failed: false,
            failure: None,
            next: Default::default(),
        }))),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };
    let endpoint = Endpoint::Remote(spec.clone());
    assert!(endpoint
        .connect_with_role(
            false,
            ConnectionRole::SourceWorker { roots: Vec::new() },
            false
        )
        .is_err());
    assert!(marker.exists(), "worker never attempted SSH fallback");
    assert!(spec.tcp.lock().unwrap().as_ref().unwrap().failed);
}

#[test]
fn ssh_workers_reuse_the_private_control_socket_only_when_enabled() {
    let multiplexer = std::sync::Arc::new(SshMultiplexer::new().unwrap());
    let control_path = multiplexer.path.to_string_lossy().into_owned();
    let spec = RemoteSpec {
        local_process: false,
        user: None,
        host: "example".into(),
        port: None,
        rsh: vec!["ssh".into()],
        syq_path: None,
        bootstrap_helper: false,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: Some(multiplexer),
        quiet: false,
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };
    let args = |connection| {
        spec.ssh_command(connection, false)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    };

    let control = args(SshConnection::Control);
    assert!(control.iter().any(|arg| arg == "ControlMaster=yes"));
    assert!(control
        .windows(2)
        .any(|pair| pair[0] == "-S" && pair[1] == control_path));
    assert!(control.iter().any(|arg| arg == "ControlPersist=no"));

    let worker = args(spec.ssh_connection(true, false));
    assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
    assert!(worker.iter().any(|arg| arg == "ControlPath=none"));

    let first = args(spec.ssh_connection(true, true));
    assert!(first
        .windows(2)
        .any(|pair| pair[0] == "-S" && pair[1] == control_path));
    assert!(!first.iter().any(|arg| arg == "ControlPath=none"));
    assert_eq!(spec.ssh_connection(false, true), SshConnection::Control);
    // The first worker's preference is per call, not an opt-in for peers.
    assert_eq!(spec.ssh_connection(true, false), SshConnection::Independent);
    let mut custom = spec.clone();
    custom.ssh_multiplexer = None;
    assert_eq!(
        custom.ssh_connection(true, true),
        SshConnection::Independent
    );

    spec.set_ssh_multiplexing(true);
    let worker = args(spec.ssh_connection(true, false));
    assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
    assert!(worker
        .windows(2)
        .any(|pair| pair[0] == "-S" && pair[1] == control_path));
    assert!(!worker.iter().any(|arg| arg == "ControlPath=none"));

    let independent = args(SshConnection::Independent);
    assert!(independent.iter().any(|arg| arg == "ControlPath=none"));
}

#[test]
fn first_ssh_worker_retries_independently_after_mux_rejection() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = crate::test_support::tempdir().unwrap();
    let script = temporary.path().join("ssh");
    let log = temporary.path().join("attempts");
    std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nfor arg do\n  if [ \"$arg\" = -S ]; then\n    echo shared >> {log}\n    exit 255\n  fi\ndone\necho independent >> {log}\nexit 127\n",
                log = shell_words::quote(log.to_str().unwrap()),
            ),
        ).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut spec = RemoteSpec::local_receiver(true);
    spec.local_process = false;
    spec.rsh = vec![script.to_string_lossy().into_owned()];
    spec.ssh_multiplexer = Some(std::sync::Arc::new(SshMultiplexer::new().unwrap()));
    let result = spec.connect_retried(
        false,
        true,
        ConnectionRole::SourceWorker { roots: Vec::new() },
        true,
    );
    assert!(result.is_err()); // The independent attempt reports a missing helper.
    assert_eq!(
        std::fs::read_to_string(&log).unwrap(),
        "shared\nindependent\n"
    );
    // Another startup worker's per-call preference must not override a
    // rejection already observed by a peer sharing this control session.
    let peer = spec.clone();
    peer.set_ssh_multiplexing(true);
    assert_eq!(peer.ssh_connection(true, true), SshConnection::Independent);
    assert_eq!(peer.ssh_connection(true, false), SshConnection::Independent);
    assert_eq!(peer.ssh_connection(false, true), SshConnection::Control);
}

#[test]
fn a_pool_appearing_after_priming_is_not_queried_during_connect() {
    use std::os::unix::net::UnixListener;
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let scope = directory.path().join("scope");
    crate::persistence::initialize_scope(&scope).unwrap();
    let multiplexer = SshMultiplexer::persistent(&scope, None, "example", None).unwrap();
    let socket = crate::session_pool::socket_path(&multiplexer.path);
    let mut spec = RemoteSpec::local_receiver(true);
    spec.local_process = false;
    spec.rsh = vec!["ssh".into()];
    spec.ssh_multiplexer = Some(std::sync::Arc::new(multiplexer));

    // The pool is absent during the main-thread prime, then starts
    // before the parallel connect. The cloned spec must keep that miss.
    spec.prime_pooled_control(true);
    let listener = UnixListener::bind(socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(spec.clone().take_pooled_control(true).is_none());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn persistent_reuse_uses_auto_master_and_never_shares_with_workers() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let base = directory.path().join("scope");
    crate::persistence::initialize_scope(&base).unwrap();
    // The socket name is stable per endpoint, and a dead leftover at the
    // path is cleared so a fresh master can bind.
    let probe = SshMultiplexer::persistent(&base, Some("u"), "example", None).unwrap();
    std::fs::write(&probe.path, b"stale").unwrap();
    let multiplexer = SshMultiplexer::persistent(&base, Some("u"), "example", None).unwrap();
    assert_eq!(probe.path, multiplexer.path);
    let alternate_port =
        SshMultiplexer::persistent(&base, Some("u"), "example", Some(2222)).unwrap();
    assert_ne!(multiplexer.path, alternate_port.path);
    assert!(!multiplexer.path.exists());
    assert_eq!(
        std::fs::metadata(&base).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let control_path = multiplexer.path.to_string_lossy().into_owned();
    let spec = RemoteSpec {
        local_process: false,
        user: Some("u".into()),
        host: "example".into(),
        port: None,
        rsh: vec!["ssh".into()],
        syq_path: None,
        bootstrap_helper: false,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: Some(std::sync::Arc::new(multiplexer)),
        quiet: false,
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };
    let args = |connection| {
        spec.ssh_command(connection, false)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    };
    let control = args(SshConnection::Control);
    assert!(control.iter().any(|arg| arg == "ControlMaster=auto"));
    assert!(control
        .windows(2)
        .any(|pair| pair[0] == "-S" && pair[1] == control_path));
    assert!(control.iter().any(|arg| arg == "ControlPersist=300"));
    // Worker data channels never ride a cross-run master, even when the
    // small-file path asks for in-run multiplexing.
    spec.set_ssh_multiplexing(true);
    let worker = args(spec.ssh_connection(true, false));
    assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
    assert!(worker.iter().any(|arg| arg == "ControlPath=none"));
    assert_eq!(spec.ssh_connection(true, true), SshConnection::Independent);
}

#[test]
fn verbose_ssh_is_limited_to_nonpersistent_unrestricted_helpers() {
    let mut spec = RemoteSpec::local_receiver(false);
    spec.rsh = vec!["ssh".into()];
    let verbose = |spec: &RemoteSpec, diagnostics| {
        spec.ssh_command(SshConnection::Control, diagnostics)
            .get_args()
            .any(|arg| arg == "-v")
    };
    assert!(verbose(&spec, true));
    assert!(!verbose(&spec, false)); // Bootstrap does not request verbosity.
    spec.restricted_grant = Some("test-authorization".into());
    assert!(!verbose(&spec, true));
    spec.restricted_grant = None;
    spec.ssh_multiplexer = Some(std::sync::Arc::new(SshMultiplexer {
        _directory: None,
        path: PathBuf::from("/tmp/syq-test-socket"),
        persistent: true,
        idle_timeout: "300",
        automatic_receiving: false,
        reuse_for_workers: AtomicBool::new(false),
        workers_rejected: AtomicBool::new(false),
    }));
    assert!(!verbose(&spec, true));
    assert!(!spec
        .ssh_command(SshConnection::Independent, true)
        .get_args()
        .any(|arg| arg == "-v"));
}

#[test]
fn persistent_control_path_is_one_byte_exact_openssh_argument() {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let path = PathBuf::from(std::ffi::OsString::from_vec(
        b"/tmp/scope with space/%h/non-utf8-\xff/socket".to_vec(),
    ));
    let multiplexer = SshMultiplexer {
        _directory: None,
        path,
        persistent: true,
        idle_timeout: "300",
        automatic_receiving: false,
        reuse_for_workers: AtomicBool::new(false),
        workers_rejected: AtomicBool::new(false),
    };
    let spec = RemoteSpec {
        local_process: false,
        user: None,
        host: "example".into(),
        port: None,
        rsh: vec!["ssh".into()],
        syq_path: None,
        bootstrap_helper: false,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: Some(std::sync::Arc::new(multiplexer)),
        quiet: false,
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };

    let command = spec.ssh_command(SshConnection::Control, false);
    let args: Vec<_> = command.get_args().collect();
    let control_index = args
        .iter()
        .position(|arg| *arg == OsStr::new("-S"))
        .unwrap();
    assert_eq!(
        args[control_index + 1].as_bytes(),
        b"/tmp/scope with space/%%h/non-utf8-\xff/socket"
    );
}

#[test]
fn probe_reachable_probes_each_socket_address_once() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let via_localhost = ("localhost", port)
        .to_socket_addrs()
        .map(|mut it| it.any(|a| a.ip() == std::net::Ipv4Addr::LOCALHOST))
        .unwrap_or(false);
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepted.clone();
    std::thread::spawn(move || {
        while let Ok((_stream, _)) = listener.accept() {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });
    let candidate = |address: &str| TcpCandidate {
        address: address.to_string(),
        speed_mbps: 0,
        source: DataAddressSource::RemoteInterface,
        reachable: false,
        selected: false,
    };
    let mut candidates = vec![
        candidate("127.0.0.1"),
        candidate("localhost"),
        candidate("127.0.0.1"),
    ];
    probe_reachable(&mut candidates, port).unwrap();
    assert!(candidates[0].reachable);
    assert!(candidates[2].reachable);
    assert_eq!(candidates[1].reachable, via_localhost);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn overlay_addresses_are_recognized_in_both_families() {
    assert!(is_overlay_address("100.101.102.103"));
    assert!(is_overlay_address("fd7a:115c:a1e0::1234"));
    assert!(!is_overlay_address("100.1.2.3"));
    assert!(!is_overlay_address("fdaa:0:1:a7b::2"));
    assert!(!is_overlay_address("192.168.1.2"));
    assert!(!is_overlay_address("gpu01.example.net"));
}
