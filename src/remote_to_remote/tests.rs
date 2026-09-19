use super::*;
use std::ffi::OsStr;

fn args(command: &Command) -> Vec<&OsStr> {
    command.get_args().collect()
}

#[test]
fn helper_selection_stops_at_a_command_restricted_receiver() {
    let mut ordinary = Vec::new();
    append_delegated_helper_selection(&mut ordinary, Some("/opt/syq-dev"), false, false);
    assert_eq!(ordinary, ["--syq-path=/opt/syq-dev"]);

    let mut restricted = Vec::new();
    append_delegated_helper_selection(&mut restricted, Some("/opt/syq-dev"), false, true);
    assert!(restricted.is_empty());

    append_delegated_helper_selection(&mut restricted, None, true, true);
    assert!(restricted.is_empty());
}

#[test]
fn detached_timeout_terminates_the_complete_process_group() {
    let directory = crate::test_support::tempdir().unwrap();
    let pids = directory.path().join("pids");
    let survived = directory.path().join("survived");
    let remote_command = format!(
            "trap '' TERM; (trap '' TERM; sleep 30; printf survived > {}) & child=$!; printf '%s %s\\n' \"$$\" \"$child\" > {}; wait",
            shell_words::quote(survived.to_str().unwrap()),
            shell_words::quote(pids.to_str().unwrap()),
        );
    let launcher = detached_launcher_command(&remote_command, "timeout-test", 1, 1);
    let output = Command::new("sh")
        .args(["-c", &launcher])
        .env("HOME", directory.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did not become ready within 1 seconds"),
        "{stderr}"
    );
    let process_ids: Vec<i32> = std::fs::read_to_string(pids)
        .unwrap()
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert_eq!(process_ids.len(), 2);
    let alive: Vec<i32> = process_ids
        .into_iter()
        .filter(|pid| unsafe { libc::kill(*pid, 0) == 0 })
        .collect();
    for pid in &alive {
        unsafe {
            libc::kill(*pid, libc::SIGKILL);
        }
    }
    assert!(alive.is_empty(), "detached processes survived: {alive:?}");
    assert!(!survived.exists());
}

#[test]
fn default_ssh_controls_agent_forwarding_explicitly() {
    let rsh = vec!["ssh".to_string(), "-p".to_string(), "2222".to_string()];
    let forwarded = direct_command(
        &rsh,
        Some("alice"),
        "source",
        None,
        "syq ...",
        Some(&AgentForwarding::Unrestricted),
    );
    let forwarded = args(&forwarded);
    assert!(forwarded.contains(&OsStr::new("-A")));
    assert!(!forwarded.contains(&OsStr::new("-a")));

    let disabled = direct_command(
        &rsh,
        Some("alice"),
        "source",
        None,
        "syq ...",
        Some(&AgentForwarding::Disabled),
    );
    let disabled = args(&disabled);
    assert!(disabled.contains(&OsStr::new("-a")));
    assert!(!disabled.contains(&OsStr::new("-A")));
}

#[test]
fn constrained_agent_is_forwarded_without_changing_source_authentication() {
    let rsh = vec!["ssh".to_string()];
    let policy = AgentForwarding::Constrained {
        ambient: "/tmp/ambient-agent".into(),
        broker: "/tmp/syq-agent".into(),
    };
    let command = direct_command(&rsh, None, "source", None, "syq ...", Some(&policy));
    let args = args(&command);
    assert!(args.contains(&OsStr::new("IdentityAgent=/tmp/ambient-agent")));
    assert!(args.contains(&OsStr::new("ForwardAgent=/tmp/syq-agent")));
    assert!(args.contains(&OsStr::new("ControlMaster=no")));
    assert!(args.contains(&OsStr::new("ControlPath=none")));
    assert!(args.contains(&OsStr::new("ClearAllForwardings=yes")));
    assert!(args.contains(&OsStr::new("-x")));
    assert!(args.contains(&OsStr::new("-k")));
    assert!(args.contains(&OsStr::new("-T")));
    assert!(args.contains(&OsStr::new("PermitLocalCommand=no")));
    assert!(!args.contains(&OsStr::new("-A")));
    assert!(!args.contains(&OsStr::new("-a")));
}

#[test]
fn setup_and_destination_connections_apply_only_the_selected_agent_policy() {
    let rsh = vec!["ssh".to_string(), "-p".to_string(), "2222".to_string()];
    assert_eq!(source_setup_rsh(&rsh, false), ["ssh", "-p", "2222", "-a"]);
    assert_eq!(source_setup_rsh(&rsh, true), rsh);
    let constrained = AgentForwarding::Constrained {
        ambient: "/tmp/ambient-agent".into(),
        broker: "/tmp/syq-agent".into(),
    };
    let hardened = constrained_destination_rsh(2222, "ssh-ed25519");
    assert_eq!(
        destination_rsh(None, false, Some(&constrained), Some(&hardened)),
        Some(hardened.clone())
    );
    let hardened_words = shell_words::split(&hardened).unwrap();
    for required in [
        "/dev/null",
        "IdentityAgent=SSH_AUTH_SOCK",
        "IdentityFile=none",
        "CertificateFile=none",
        "PKCS11Provider=none",
        "PubkeyAuthentication=host-bound",
        "PreferredAuthentications=publickey",
        "BatchMode=yes",
        "ProxyJump=none",
        "ProxyCommand=none",
        "LogLevel=ERROR",
        "HostKeyAlgorithms=ssh-ed25519",
        "2222",
    ] {
        assert!(hardened_words.iter().any(|word| word == required));
    }
    assert_eq!(
        destination_rsh(None, false, Some(&AgentForwarding::Unrestricted), None),
        Some("ssh -a -o IdentityAgent=SSH_AUTH_SOCK -o IdentitiesOnly=no".into())
    );
    assert_eq!(
        destination_rsh(None, false, Some(&AgentForwarding::Disabled), None),
        Some("ssh -a".into())
    );
    assert_eq!(
        destination_rsh(Some("custom-rsh"), false, None, None),
        Some("custom-rsh".into())
    );
    assert_eq!(
        destination_rsh(Some("ssh -J jump"), false, None, None),
        Some("ssh -J jump".into())
    );
    assert_eq!(
        destination_rsh(None, true, Some(&constrained), Some(&hardened)),
        None
    );
}

#[test]
fn broker_capacity_is_bounded_independently_of_automatic_workers() {
    for restricted in [false, true] {
        assert_eq!(broker_connection_limit(None, restricted).unwrap(), 129);
        assert_eq!(broker_connection_limit(Some(3), restricted).unwrap(), 4);
        assert_eq!(broker_connection_limit(Some(128), restricted).unwrap(), 129);
    }
    assert_eq!(broker_connection_limit(Some(1000), false).unwrap(), 1001);
    assert!(broker_connection_limit(Some(usize::MAX), false).is_err());
    assert_eq!(broker_connection_limit(Some(1000), true).unwrap(), 129);
    assert_eq!(
        broker_connection_limit(Some(usize::MAX), true).unwrap(),
        129
    );
}

#[test]
fn receipt_settlement_preserves_terminal_outcomes() {
    use crate::receipt::ReceiptStatus::{Clean, Failed, Incomplete};

    // Every (status, exit_code) pair matches the automation contract's
    // table: success/0, partial/23, refused/25, failed/1, aborted/1.
    let cases = [
        (Clean, 0, 0, "success", 0, false),
        (Clean, 0, 23, "partial", 23, false),
        (Clean, 0, 25, "refused", 25, false),
        (Clean, 0, 1, "failed", 1, false),
        (Failed, 0, 0, "partial", 23, true),
        (Failed, 0, 23, "partial", 23, false),
        (Failed, 1, 23, "refused", 25, true),
        (Failed, 0, 1, "failed", 1, false),
        (Failed, 1, 1, "failed", 1, true),
        (Incomplete, 0, 0, "aborted", 1, true),
        (Incomplete, 0, 23, "aborted", 1, false),
        (Incomplete, 1, 23, "aborted", 1, true),
        (Incomplete, 0, 1, "aborted", 1, false),
    ];
    for (receipt_status, refusals, coordinator, status, exit_code, rejects) in cases {
        let outcome = receipt_settlement_outcome(receipt_status, refusals, coordinator);
        assert_eq!(outcome.results_status, status);
        assert_eq!(outcome.exit_code, exit_code);
        assert_eq!(outcome.rejects_receipt, rejects);
    }
}

#[test]
fn relay_passes_output_through_and_spools_receipt_frames() {
    // Ordinary output streams through byte for byte, including bytes
    // that are not UTF-8; a stream with no receipt lines captures
    // nothing.
    assert!(relay_stdout(b"plain\n".as_slice()).unwrap().is_none());
    assert!(relay_stdout(b"syq: transferred 1 files\xff\r\n".as_slice())
        .unwrap()
        .is_none());

    // Marker lines are decoded and spooled as separate bounded frames,
    // not accumulated into one receipt allocation.
    let frames = [
        crate::receipt::ReceiptFrame::Start {
            mode: crate::receipt::ReceiptDeliveryKind::DetachedSignedPlaintext,
            encapsulated_key: Vec::new(),
        },
        crate::receipt::ReceiptFrame::Chunk {
            sequence: 0,
            payload: b"stream".to_vec(),
        },
        crate::receipt::ReceiptFrame::End {
            sequence: 1,
            payload: b"terminal".to_vec(),
        },
    ]
    .map(|frame| crate::receipt::encode_receipt_frame(&frame).unwrap());
    let mut output = b"ordinary line\n".to_vec();
    for frame in &frames {
        output.extend_from_slice(crate::receipt::RECEIPT_LINE_PREFIX.as_bytes());
        output.extend_from_slice(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(frame)
                .as_bytes(),
        );
        output.push(b'\n');
    }
    let mut captured = relay_stdout(&output[..])
        .unwrap()
        .expect("captured receipt frames");
    let captured: Vec<Vec<u8>> = captured.frames().unwrap().map(Result::unwrap).collect();
    assert_eq!(captured, frames);

    // An oversized marker line is refused instead of buffered.
    let mut oversized = crate::receipt::RECEIPT_LINE_PREFIX.as_bytes().to_vec();
    oversized.extend(std::iter::repeat_n(b'A', MAX_RECEIPT_LINE_BYTES + 1));
    oversized.push(b'\n');
    assert!(relay_stdout(oversized.as_slice()).is_err());
}

#[test]
fn relay_output_failure_preserves_verified_receipt_and_rejects_corruption() {
    use crate::receipt::*;
    struct FailingOutput {
        flush_only: bool,
    }
    impl Write for FailingOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.flush_only {
                Ok(bytes.len())
            } else {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    let signing_key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[19; 32]).into(),
        "output-test",
    )
    .unwrap();
    let (secret, public) = generate_recipient().unwrap();
    let policy = ReceiptPolicy {
        required: true,
        hashed: false,
        max_records: 32,
        max_plaintext_bytes: 64 * 1024,
        delivery: ReceiptDelivery::AttachedEncrypted {
            suite: HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key: public,
        },
    };
    let enrollment_id = EnrollmentId::random();
    let request_id = RequestId::fresh(1_900_000_000).unwrap();
    let grant_digest = [17; 32];
    let issued = ReceiptStreamWriter::new(&policy)
        .unwrap()
        .finish(ReceiptClosure {
            enrollment_id,
            request_id,
            grant_digest,
            issued_at: 1_900_000_001,
            policy: policy.clone(),
            entries_touched: 0,
            transferred_bytes: 0,
            signing_key: &signing_key,
        })
        .unwrap();
    let mut encoded = Vec::new();
    emit_receipt_frames(issued, |frame| {
        encoded.extend_from_slice(RECEIPT_LINE_PREFIX.as_bytes());
        encoded.extend_from_slice(
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(frame)
                .as_bytes(),
        );
        encoded.push(b'\n');
        Ok(())
    })
    .unwrap();
    let expected = ReceiptExpectation {
        public_key: signing_key.public_key().to_openssh().unwrap(),
        enrollment_id,
        request_id,
        recipient_secret: Some(secret),
        policy,
        grant_digest: Some(grant_digest),
    };
    for flush_only in [false, true] {
        // Fail either before the receipt arrives or after it was captured.
        for human_first in [false, true] {
            let input = if human_first {
                [b"human line\n".as_slice(), &encoded].concat()
            } else {
                [&encoded, b"human line\n".as_slice()].concat()
            };
            let mut output_error = None;
            let mut captured = relay_output(
                input.as_slice(),
                &mut FailingOutput { flush_only },
                &mut output_error,
            )
            .unwrap();
            assert_eq!(output_error.unwrap().kind(), std::io::ErrorKind::BrokenPipe);
            let file = tempfile::tempfile().unwrap();
            let writer = crate::results::ResultsWriter::new(Box::new(file.try_clone().unwrap()));
            assert_eq!(
                settle_receipt(
                    &expected,
                    captured.as_mut(),
                    ReceiptSettlement {
                        src_host: "source",
                        dst_host: "destination",
                        coordinator_exit_code: 0,
                        results: Some(&writer),
                        elapsed_ms: 1,
                        verbose: false,
                        quiet: false,
                    }
                )
                .unwrap(),
                0
            );
            let mut text = String::new();
            let mut file = file;
            file.rewind().unwrap();
            file.read_to_string(&mut text).unwrap();
            let result: serde_json::Value =
                serde_json::from_str(text.lines().last().unwrap()).unwrap();
            assert_eq!(result["exit_code"], 0);
            assert_eq!(result["provenance"], "receiver_attested");
        }
    }
    // Losing human output never disables receipt framing or verification.
    let invalid = format!("human line\n{RECEIPT_LINE_PREFIX}invalid!\n");
    assert!(relay_output(
        invalid.as_bytes(),
        &mut FailingOutput { flush_only: false },
        &mut None
    )
    .is_err());
    let mut captured = relay_output(encoded.as_slice(), &mut Vec::new(), &mut None).unwrap();
    let wrong_expected = ReceiptExpectation {
        grant_digest: Some([99; 32]),
        ..expected
    };
    assert!(settle_receipt(
        &wrong_expected,
        captured.as_mut(),
        ReceiptSettlement {
            src_host: "source",
            dst_host: "destination",
            coordinator_exit_code: 0,
            results: None,
            elapsed_ms: 1,
            verbose: false,
            quiet: true,
        }
    )
    .is_err());
}

#[test]
fn resolved_destination_replaces_host_a_ssh_aliases() {
    let destination = Location::parse("alias:/archive").unwrap();
    assert_eq!(
        endpoint_arg(&destination, Some("backup"), Some("vault.internal")),
        "backup@vault.internal"
    );
    assert_eq!(
        endpoint_arg(&destination, Some("backup"), Some("2001:db8::1")),
        "backup@[2001:db8::1]"
    );
    let destination = Location {
        port: Some(2200),
        ..destination
    };
    assert_eq!(
        endpoint_arg(&destination, Some("backup"), Some("vault.internal")),
        "backup@vault.internal:2200"
    );
}

#[test]
fn explicit_ssh_does_not_get_agent_flags() {
    let rsh = vec!["ssh".to_string(), "-a".to_string()];
    let command = direct_command(&rsh, None, "source", None, "syq ...", None);
    let args = args(&command);
    assert!(!args.contains(&OsStr::new("-A")));
    assert_eq!(
        args.iter().filter(|arg| arg.to_str() == Some("-a")).count(),
        1
    );
}

#[test]
fn custom_remote_shell_does_not_get_ssh_agent_flags() {
    let rsh = vec!["custom-rsh".to_string()];
    let command = direct_command(&rsh, None, "source", None, "syq ...", None);
    let args = args(&command);
    assert!(!args.contains(&OsStr::new("-a")));
    assert!(!args.contains(&OsStr::new("-A")));
}
