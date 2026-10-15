use super::*;

fn key(seed: u8) -> PrivateKey {
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]);
    PrivateKey::new(keypair.into(), "syq-results-test").unwrap()
}

fn binding() -> Binding {
    Binding {
        enrollment_id: EnrollmentId::random(),
        request_id: RequestId::fresh(1_900_000_000).unwrap(),
        grant_digest: [7; 32],
    }
}

struct Pair {
    stream: Stream,
    reader: Reader,
}

fn pair(records: bool) -> Pair {
    let (secret, public) = generate_recipient().unwrap();
    let binding = binding();
    let signing = key(3);
    let stream = Stream::start(
        &ReceiptPolicy::for_recipient(public),
        binding,
        &signing,
        records,
    )
    .unwrap();
    let reader = Reader::new(Expectation {
        public_key: signing.public_key().to_openssh().unwrap(),
        binding,
        secret,
        records,
    });
    Pair { stream, reader }
}

/// Every frame the stream produced so far, sealing what is pending.
fn drain(stream: &mut Stream) -> Vec<Vec<u8>> {
    stream
        .take_frames(Instant::now() + SEAL_AFTER + Duration::from_millis(1))
        .unwrap()
}

fn accept_all(reader: &mut Reader, frames: &[Vec<u8>]) -> Result<Vec<serde_json::Value>> {
    let mut records = Vec::new();
    for frame in frames {
        reader.accept(frame, |record| {
            records.push(record);
            Ok(())
        })?;
    }
    Ok(records)
}

/// A copy's stream: header, three batches of records, and the end.
fn sample(records: bool) -> (Reader, Vec<Vec<u8>>) {
    let Pair { mut stream, reader } = pair(records);
    let mut all = drain(&mut stream);
    stream.record(Change::PublishFile { size: 3 }, Some(b"a"), None);
    stream.record(Change::EnsureDirectory, Some(b"dir"), None);
    all.extend(drain(&mut stream));
    stream.record(
        Change::PublishFile { size: 5 },
        Some(b"dir/b"),
        Some("disk full"),
    );
    stream.record(
        Change::SetMetadata {
            kind: crate::proto::Kind::Dir,
        },
        Some(b"dir"),
        None,
    );
    stream.refused(
        "refused: outside the signed destination scopes",
        &[
            (Some(b"x".to_vec()), Change::PublishFile { size: 2 }),
            (None, Change::EnsureDirectory),
        ],
    );
    all.extend(drain(&mut stream));
    stream.record(Change::DeleteNonDirectory, Some(b"old"), None);
    stream.record(Change::LinkFile, Some(b"dir/c"), None);
    stream.finish(8).unwrap();
    all.extend(drain(&mut stream));
    (reader, all)
}

#[test]
fn records_and_totals_round_trip_in_ordinary_form() {
    let (mut reader, frames) = sample(true);
    let records = accept_all(&mut reader, &frames).unwrap();
    let totals = reader.finish().unwrap();
    assert_eq!(
        totals,
        Totals {
            files_transferred: 2,
            bytes_transferred: 8,
            directories_created: 1,
            symlinks_created: 0,
            specials_created: 0,
            deletions_completed: 1,
            failed: 1,
            refused: 1,
        }
    );
    // A successful metadata-only change is not listed, as in ordinary
    // results; each failure and refusal is listed with its error record.
    let summary: Vec<_> = records
        .iter()
        .map(|record| {
            (
                record["type"].as_str().unwrap(),
                record["action"].as_str().unwrap_or_default(),
                record["dst"]["value"].as_str().unwrap_or_default(),
                record["disposition"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("operation_result", "transfer_file", "a", "succeeded"),
            ("operation_result", "create_directory", "dir", "succeeded"),
            ("error", "", "", ""),
            ("operation_result", "transfer_file", "dir/b", "failed"),
            ("error", "", "", ""),
            ("operation_result", "transfer_file", "x", "failed"),
            ("operation_result", "delete", "old", "succeeded"),
            ("operation_result", "transfer_file", "dir/c", "succeeded"),
        ]
    );
    assert_eq!(records[0]["bytes"], 3);
    assert_eq!(records[2]["message"], "syq: dir/b: disk full");
    assert_eq!(records[2]["class"], "io");
    assert_eq!(records[3]["message"], "disk full");
    assert_eq!(records[3]["class"], "io");
    assert!(records[3].get("bytes").is_none());
    assert_eq!(records[4]["class"], "safety_limit");
    assert_eq!(
        records[5]["message"],
        "refused: outside the signed destination scopes"
    );
    assert_eq!(records[5]["class"], "safety_limit");
    assert_eq!(records[7]["bytes"], 0);
    // A removed name's kind is not known.
    assert!(records[6].get("kind").is_none());
}

#[test]
fn a_refusal_without_a_listable_path_is_still_an_error_record() {
    let Pair {
        mut stream,
        mut reader,
    } = pair(true);
    let mut all = drain(&mut stream);
    stream.refused("refused: scan outside the grant", &[]);
    stream.record(
        Change::SetMetadata {
            kind: crate::proto::Kind::Symlink,
        },
        Some(b"link"),
        Some("lchown failed"),
    );
    stream.finish(0).unwrap();
    all.extend(drain(&mut stream));
    let records = accept_all(&mut reader, &all).unwrap();
    assert_eq!(records.len(), 3, "{records:?}");
    assert_eq!(records[0]["type"], "error");
    assert_eq!(
        records[0]["message"],
        "syq: the receiver: refused: scan outside the grant"
    );
    // A failed metadata change is listed as its object's failure.
    assert_eq!(records[2]["action"], "create_symlink");
    assert_eq!(records[2]["disposition"], "failed");
    let totals = reader.finish().unwrap();
    assert_eq!((totals.refused, totals.failed), (1, 1));
}

#[test]
fn frames_may_arrive_in_any_order_after_the_header() {
    let (mut reader, mut frames) = sample(true);
    // The end and the record frames cross on different connections.
    frames[1..].reverse();
    accept_all(&mut reader, &frames).unwrap();
    assert_eq!(reader.finish().unwrap().files_transferred, 2);
}

#[test]
fn a_cut_stream_fails_however_it_ends() {
    // Header only, or any prefix short of the end frame.
    for kept in 0..4 {
        let Pair {
            mut stream,
            mut reader,
        } = pair(true);
        let mut all = frames_of(&mut stream);
        all.truncate(kept);
        let accepted = accept_all(&mut reader, &all);
        assert!(
            accepted.is_err() || reader.finish().is_err(),
            "a stream cut after {kept} frames was accepted"
        );
    }
}

/// A complete stream of four frames: header, two record frames, end.
fn frames_of(stream: &mut Stream) -> Vec<Vec<u8>> {
    let mut all = drain(stream);
    stream.record(Change::PublishFile { size: 1 }, Some(b"x"), None);
    all.extend(drain(stream));
    stream.record(Change::CreateSymlink, Some(b"y"), None);
    all.extend(drain(stream));
    stream.finish(1).unwrap();
    all.extend(drain(stream));
    assert_eq!(all.len(), 4);
    all
}

#[test]
fn dropped_repeated_or_altered_frames_are_detected() {
    let Pair {
        mut stream,
        mut reader,
    } = pair(true);
    let all = frames_of(&mut stream);
    // A record frame repeated in place of another keeps the count.
    let replayed = [
        all[0].clone(),
        all[1].clone(),
        all[1].clone(),
        all[3].clone(),
    ];
    accept_all(&mut reader, &replayed).unwrap();
    assert!(reader.finish().is_err());

    let Pair {
        mut stream,
        mut reader,
    } = pair(true);
    let all = frames_of(&mut stream);
    let dropped = [all[0].clone(), all[2].clone(), all[3].clone()];
    accept_all(&mut reader, &dropped).unwrap();
    assert!(reader.finish().is_err());

    let Pair {
        mut stream,
        mut reader,
    } = pair(true);
    let mut all = frames_of(&mut stream);
    let last = all[1].len() - 20;
    all[1][last] ^= 1;
    assert!(accept_all(&mut reader, &all).is_err());

    // A second end frame, or records before the header, are refused.
    let Pair {
        mut stream,
        mut reader,
    } = pair(true);
    let all = frames_of(&mut stream);
    let twice = [all[0].clone(), all[3].clone(), all[3].clone()];
    assert!(accept_all(&mut reader, &twice).is_err());
    let Pair {
        mut stream,
        mut reader,
    } = pair(true);
    let all = frames_of(&mut stream);
    assert!(accept_all(&mut reader, &all[1..]).is_err());
}

#[test]
fn only_the_destination_key_and_this_grant_start_a_stream() {
    let (secret, public) = generate_recipient().unwrap();
    let binding = binding();
    let policy = ReceiptPolicy::for_recipient(public);
    let mut forged = Stream::start(&policy, binding, &key(9), true).unwrap();
    let mut reader = Reader::new(Expectation {
        public_key: key(3).public_key().to_openssh().unwrap(),
        binding,
        secret,
        records: true,
    });
    // A coordinator holding the grant can run the key exchange, but cannot
    // sign the header with the destination's key.
    let error = reader.accept(&drain(&mut forged)[0], |_| Ok(()));
    assert!(error.is_err());

    let (secret, public) = generate_recipient().unwrap();
    let mut other = Stream::start(
        &ReceiptPolicy::for_recipient(public),
        Binding {
            grant_digest: [8; 32],
            ..binding
        },
        &key(3),
        true,
    )
    .unwrap();
    let mut reader = Reader::new(Expectation {
        public_key: key(3).public_key().to_openssh().unwrap(),
        binding,
        secret,
        records: true,
    });
    assert!(reader.accept(&drain(&mut other)[0], |_| Ok(())).is_err());
}

#[test]
fn the_header_says_whether_changes_are_listed() {
    // Without records only the totals cross; a coordinator cannot turn the
    // listing off unnoticed.
    let (mut reader, frames) = sample(false);
    assert!(accept_all(&mut reader, &frames).unwrap().is_empty());
    assert_eq!(reader.finish().unwrap().refused, 1);
    assert_eq!(frames.len(), 2);

    let (secret, public) = generate_recipient().unwrap();
    let binding = binding();
    let mut stream = Stream::start(
        &ReceiptPolicy::for_recipient(public),
        binding,
        &key(3),
        false,
    )
    .unwrap();
    let mut reader = Reader::new(Expectation {
        public_key: key(3).public_key().to_openssh().unwrap(),
        binding,
        secret,
        records: true,
    });
    assert!(reader.accept(&drain(&mut stream)[0], |_| Ok(())).is_err());
}

#[test]
fn pending_records_wait_for_a_batch_or_a_moment() {
    let Pair { mut stream, .. } = pair(true);
    let now = Instant::now();
    assert_eq!(stream.take_frames(now).unwrap().len(), 1);
    stream.record(Change::PublishFile { size: 1 }, Some(b"x"), None);
    assert!(!stream.due(now));
    assert!(stream.take_frames(now).unwrap().is_empty());
    assert!(stream.due(now + SEAL_AFTER + Duration::from_millis(1)));
    // A large burst seals at once, in frames that split between records.
    let name = vec![b'n'; 200];
    for _ in 0..1000 {
        stream.record(Change::PublishFile { size: 1 }, Some(&name), None);
    }
    let sealed = stream.take_frames(now).unwrap();
    assert!(sealed.len() > 1);
    assert!(sealed.iter().all(|frame| frame.len() <= MAX_FRAME_BYTES));
}

#[test]
fn signed_grant_policy_bytes_are_unchanged() {
    // The policy stays in signed grants byte for byte (v0.4.1 fixture in
    // delegation tests); new grants write these values.
    let policy = ReceiptPolicy::for_recipient([5; 32]);
    policy.validate().unwrap();
    assert_eq!(
        postcard::to_stdvec(&policy).unwrap(),
        [
            [1, 0].as_slice(),
            &[0x80, 0x92, 0xf4, 0x01],
            &[0x80, 0x80, 0x80, 0x80, 0x02],
            &[0, 0],
            &[5; 32],
        ]
        .concat()
    );
}

#[test]
fn diagnostics_are_bounded_on_utf8_boundaries() {
    let long = "é".repeat(MAX_DIAGNOSTIC_BYTES);
    let bounded = bounded_diagnostic(&long).unwrap();
    assert!(bounded.len() <= MAX_DIAGNOSTIC_BYTES + '…'.len_utf8());
    assert!(bounded.ends_with('…'));
    assert_eq!(bounded_diagnostic(""), None);
}
