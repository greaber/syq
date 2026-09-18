
use super::*;

fn key(seed: u8) -> PrivateKey {
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
    PrivateKey::new(keypair.into(), "syq-receipt-test").unwrap()
}

fn policy(public: [u8; 32]) -> ReceiptPolicy {
    ReceiptPolicy {
        required: true,
        hashed: true,
        max_records: 32,
        max_plaintext_bytes: 64 * 1024,
        delivery: ReceiptDelivery::AttachedEncrypted {
            suite: HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key: public,
        },
    }
}

#[test]
fn attested_failures_emit_matching_error_records() {
    let (secret, public) = generate_recipient().unwrap();
    let policy = policy(public);
    let enrollment_id = EnrollmentId::random();
    let request_id = RequestId::fresh(1_900_000_000).unwrap();
    let grant_digest = [7; 32];
    let signing_key = key(3);
    let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
    stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
        sequence: stream.next_sequence(),
        scope: 0,
        path: b"artifact".to_vec(),
        action: OperationAction::PublishFile {
            size: 3,
            inplace: false,
        },
        disposition: OperationDisposition::Failed,
        code: OutcomeCode::ExecutionFailed,
        diagnostic: Some("short write".to_string()),
    }));
    stream.append(&ReceiptRecord::Refusal(RefusalReceiptRecord {
        sequence: stream.next_sequence(),
        code: OutcomeCode::AuthorizationRefused,
        diagnostic: None,
    }));
    stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
        sequence: stream.next_sequence(),
        scope: 0,
        path: b"artifact".to_vec(),
        object: FinalObject::ObservationFailed {
            code: OutcomeCode::ObservationFailed,
            diagnostic: None,
        },
    }));
    // A present object whose closure hash could not be taken: the object
    // is attested, but the partial observation still counts as an error.
    stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
        sequence: stream.next_sequence(),
        scope: 0,
        path: b"partial".to_vec(),
        object: FinalObject::Present {
            kind: Kind::File,
            size: 4,
            digest: None,
            symlink_target: None,
            metadata: ObjectMetadata {
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                mtime: 5,
                mtime_nsec: 6,
                rdev: 0,
            },
            observation_error: Some("hash final file: boom".to_string()),
        },
    }));
    let issued = stream
        .finish(ReceiptClosure {
            enrollment_id,
            request_id,
            grant_digest,
            issued_at: 1_900_000_001,
            policy: policy.clone(),
            entries_touched: 2,
            transferred_bytes: 0,
            signing_key: &signing_key,
        })
        .unwrap();
    let mut frames = Vec::new();
    emit_receipt_frames(issued, |frame| {
        frames.push(frame);
        Ok(())
    })
    .unwrap();
    let mut verified = open_attached_frames(
        frames.into_iter().map(Ok),
        &secret,
        &signing_key.public_key().to_openssh().unwrap(),
        enrollment_id,
        request_id,
        grant_digest,
        &policy,
    )
    .unwrap();
    assert_eq!(verified.terminal.status, ReceiptStatus::Incomplete);

    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Sink::default();
    let writer = crate::results::ResultsWriter::new(Box::new(sink.clone()));
    let emitted = emit_automation_records(&mut verified, &writer, "aborted", 1, 3).unwrap();
    assert_eq!(emitted.errors, 4);
    let automation = sink.0.lock().unwrap().clone();
    let records: Vec<serde_json::Value> = String::from_utf8(automation)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schemas/automation.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["seq"], index as u64);
        if let Err(error) = validator.validate(record) {
            panic!("line {}: {error}: {record}", index + 1);
        }
    }
    // Each counted failure produces an error record: the failed
    // operation, the refusal, and the failed observation, in stream
    // order, with the failed operation's record preceding its error.
    let types: Vec<&str> = records
        .iter()
        .map(|record| record["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        [
            "operation_result",
            "error",
            "error",
            "error",
            "final_state",
            "error",
            "final_state",
            "result"
        ]
    );
    assert_eq!(records[0]["disposition"], "failed");
    assert_eq!(records[1]["class"], "io");
    assert_eq!(records[1]["code"], "execution_failed");
    assert_eq!(records[1]["message"], "short write");
    assert_eq!(records[2]["class"], "safety_limit");
    assert_eq!(records[2]["code"], "authorization_refused");
    assert_eq!(records[3]["class"], "io");
    assert_eq!(records[3]["code"], "observation_failed");
    assert_eq!(records[4]["object"]["state"], "observation_failed");
    assert_eq!(records[5]["class"], "io");
    assert!(records[5]["message"]
        .as_str()
        .unwrap()
        .contains("hash final file: boom"));
    assert_eq!(records[6]["object"]["state"], "present");
    assert_eq!(
        records[6]["object"]["observation_error"],
        "hash final file: boom"
    );
    let result = records.last().unwrap();
    assert_eq!(result["status"], "aborted");
    assert_eq!(result["receipt_status"], "incomplete");
    assert_eq!(result["exit_code"], 1);
    assert_eq!(result["errors"], 4);
}

#[test]
fn borrowed_receipt_frames_preserve_wire_encoding() {
    let frames = [
        ReceiptFrame::Start {
            mode: ReceiptDeliveryKind::AttachedEncrypted,
            encapsulated_key: vec![3; 32],
        },
        ReceiptFrame::Chunk {
            sequence: u64::MAX,
            payload: vec![5; PLAINTEXT_CHUNK_BYTES],
        },
        ReceiptFrame::End {
            sequence: 17,
            payload: vec![7; 257],
        },
    ];
    for frame in frames {
        let owned = postcard::to_stdvec(&frame).unwrap();
        let borrowed = postcard::to_stdvec(&frame.as_borrowed()).unwrap();
        assert_eq!(borrowed, owned);

        let encoded = encode_receipt_frame(&frame).unwrap();
        assert_eq!(&encoded[HEADER_LEN..], owned);
        assert_eq!(decode_receipt_frame(&encoded).unwrap(), frame);
    }
}

#[test]
fn encrypted_stream_round_trips_and_binds_all_frames() {
    let (secret, public) = generate_recipient().unwrap();
    let policy = policy(public);
    let enrollment_id = EnrollmentId::random();
    let request_id = RequestId::fresh(1_900_000_000).unwrap();
    let grant_digest = [7; 32];
    let signing_key = key(3);
    let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
    stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
        sequence: stream.next_sequence(),
        scope: 0,
        path: b"artifact".to_vec(),
        action: OperationAction::PublishFile {
            size: 3,
            inplace: false,
        },
        disposition: OperationDisposition::Succeeded,
        code: OutcomeCode::None,
        diagnostic: None,
    }));
    stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
        sequence: stream.next_sequence(),
        scope: 0,
        path: b"artifact".to_vec(),
        object: FinalObject::Present {
            kind: Kind::File,
            size: 3,
            digest: Some([9; 32]),
            symlink_target: None,
            metadata: ObjectMetadata {
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                mtime: 5,
                mtime_nsec: 6,
                rdev: 0,
            },
            observation_error: None,
        },
    }));
    let issued = stream
        .finish(ReceiptClosure {
            enrollment_id,
            request_id,
            grant_digest,
            issued_at: 1_900_000_001,
            policy: policy.clone(),
            entries_touched: 1,
            transferred_bytes: 3,
            signing_key: &signing_key,
        })
        .unwrap();
    let mut frames = Vec::new();
    emit_receipt_frames(issued, |frame| {
        frames.push(frame);
        Ok(())
    })
    .unwrap();
    let mut verified = open_attached_frames(
        frames.clone().into_iter().map(Ok),
        &secret,
        &signing_key.public_key().to_openssh().unwrap(),
        enrollment_id,
        request_id,
        grant_digest,
        &policy,
    )
    .unwrap();
    assert_eq!(verified.terminal.status, ReceiptStatus::Clean);
    let mut records = Vec::new();
    verified
        .for_each_record(|record| {
            records.push(record);
            Ok(())
        })
        .unwrap();
    assert_eq!(records.len(), 2);

    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Sink::default();
    let writer = crate::results::ResultsWriter::new(Box::new(sink.clone()));
    emit_automation_records(&mut verified, &writer, "refused", 25, 7).unwrap();
    let automation = sink.0.lock().unwrap().clone();
    let records: Vec<serde_json::Value> = String::from_utf8(automation)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    // The records ride the shared envelope with contiguous sequencing
    // and validate against the committed automation schema.
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schemas/automation.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["seq"], index as u64);
        assert_eq!(record["schema"], "syq.automation");
        if let Err(error) = validator.validate(record) {
            panic!("line {}: {error}: {record}", index + 1);
        }
    }
    assert_eq!(records[0]["type"], "operation_result");
    assert_eq!(records[0]["provenance"], "receiver_attested");
    assert_eq!(records[1]["type"], "final_state");
    assert_eq!(
        records[1]["object"]["digest"]["value"],
        "0909090909090909090909090909090909090909090909090909090909090909"
    );
    assert_eq!(records[1]["object"]["metadata"]["mode"], 0o100644);
    let result = records.last().unwrap();
    assert_eq!(result["type"], "result");
    assert_eq!(result["status"], "refused");
    assert_eq!(result["receipt_status"], "clean");
    assert_eq!(result["exit_code"], 25);
    assert_eq!(result["elapsed_ms"], 7);
    assert_eq!(result["errors"], 0);
    assert_eq!(result["deletions_completed"], 0);
    assert_eq!(result["operations"], 1);
    assert_eq!(result["final_states"], 1);
    assert!(result.get("deletions_planned").is_none());
    assert!(result.get("deletions_blocked").is_none());

    let mut missing = frames;
    missing.remove(1);
    assert!(open_attached_frames(
        missing.into_iter().map(Ok),
        &secret,
        &signing_key.public_key().to_openssh().unwrap(),
        enrollment_id,
        request_id,
        grant_digest,
        &policy,
    )
    .is_err());

    let issued = {
        let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
        stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
            sequence: 0,
            scope: 0,
            path: b"artifact".to_vec(),
            action: OperationAction::EnsureDirectory,
            disposition: OperationDisposition::Succeeded,
            code: OutcomeCode::None,
            diagnostic: None,
        }));
        stream
            .finish(ReceiptClosure {
                enrollment_id,
                request_id,
                grant_digest,
                issued_at: 1_900_000_001,
                policy: policy.clone(),
                entries_touched: 1,
                transferred_bytes: 0,
                signing_key: &signing_key,
            })
            .unwrap()
    };
    let mut tampered = Vec::new();
    emit_receipt_frames(issued, |frame| {
        tampered.push(frame);
        Ok(())
    })
    .unwrap();
    let mut chunk = decode_receipt_frame(&tampered[1]).unwrap();
    let ReceiptFrame::Chunk { payload, .. } = &mut chunk else {
        panic!("expected encrypted stream chunk");
    };
    payload[0] ^= 1;
    tampered[1] = encode_receipt_frame(&chunk).unwrap();
    assert!(open_attached_frames(
        tampered.into_iter().map(Ok),
        &secret,
        &signing_key.public_key().to_openssh().unwrap(),
        enrollment_id,
        request_id,
        grant_digest,
        &policy,
    )
    .is_err());
}

#[test]
fn detached_delivery_is_a_signed_plaintext_stream() {
    let policy = ReceiptPolicy {
        required: true,
        hashed: false,
        max_records: 8,
        max_plaintext_bytes: 4096,
        delivery: ReceiptDelivery::DetachedSignedPlaintext,
    };
    let enrollment_id = EnrollmentId::random();
    let request_id = RequestId::fresh(1_900_000_000).unwrap();
    let signing_key = key(8);
    let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
    stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
        sequence: 0,
        scope: 1,
        path: b"plain".to_vec(),
        action: OperationAction::EnsureDirectory,
        disposition: OperationDisposition::Succeeded,
        code: OutcomeCode::None,
        diagnostic: None,
    }));
    stream.append(&ReceiptRecord::FinalState(FinalStateReceiptRecord {
        sequence: 1,
        scope: 1,
        path: b"plain".to_vec(),
        object: FinalObject::Absent,
    }));
    let issued = stream
        .finish(ReceiptClosure {
            enrollment_id,
            request_id,
            grant_digest: [8; 32],
            issued_at: 1_900_000_001,
            policy,
            entries_touched: 1,
            transferred_bytes: 0,
            signing_key: &signing_key,
        })
        .unwrap();
    let mut frames = Vec::new();
    emit_receipt_frames(issued, |frame| {
        frames.push(decode_receipt_frame(&frame)?);
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        frames[0],
        ReceiptFrame::Start {
            mode: ReceiptDeliveryKind::DetachedSignedPlaintext,
            ref encapsulated_key,
        } if encapsulated_key.is_empty()
    ));
    let ReceiptFrame::Chunk { payload, .. } = &frames[1] else {
        panic!("expected plaintext receipt chunk");
    };
    let mut spool = tempfile::tempfile().unwrap();
    spool.write_all(payload).unwrap();
    let ReceiptFrame::End { payload, .. } = &frames[2] else {
        panic!("expected signed terminal frame");
    };
    let terminal =
        verify_terminal(payload, &signing_key.public_key().to_openssh().unwrap()).unwrap();
    verify_stream(&mut spool, &terminal).unwrap();
}

#[test]
fn limits_fail_closed_without_truncating_into_success() {
    let (_, public) = generate_recipient().unwrap();
    let mut policy = policy(public);
    policy.max_records = 1;
    let mut stream = ReceiptStreamWriter::new(&policy).unwrap();
    for path in [b"a".as_slice(), b"b".as_slice()] {
        stream.append(&ReceiptRecord::Operation(ReceiptOperationRecord {
            sequence: stream.next_sequence(),
            scope: 0,
            path: path.to_vec(),
            action: OperationAction::EnsureDirectory,
            disposition: OperationDisposition::Succeeded,
            code: OutcomeCode::None,
            diagnostic: None,
        }));
    }
    assert!(stream.is_failed());
    let signing_key = key(4);
    let terminal = stream
        .finish(ReceiptClosure {
            enrollment_id: EnrollmentId::random(),
            request_id: RequestId::fresh(1_900_000_000).unwrap(),
            grant_digest: [1; 32],
            issued_at: 1_900_000_001,
            policy,
            entries_touched: 2,
            transferred_bytes: 0,
            signing_key: &signing_key,
        })
        .unwrap();
    assert_eq!(terminal.stream_len, 13);
}

#[test]
fn diagnostics_are_bounded_on_utf8_boundaries() {
    let text = "é".repeat(MAX_DIAGNOSTIC_BYTES);
    let bounded = bounded_diagnostic(&text).unwrap();
    assert!(bounded.len() <= MAX_DIAGNOSTIC_BYTES + '…'.len_utf8());
    assert!(bounded.ends_with('…'));
}
