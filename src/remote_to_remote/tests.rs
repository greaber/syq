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
        .capture_output()
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
    let hardened = constrained_destination_rsh(
        Some(2222),
        DestinationAuthentication::Broker {
            host_key_algorithms: "ssh-ed25519",
        },
    );
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
        "ConnectTimeout=10",
        "HostKeyAlgorithms=ssh-ed25519",
        "StrictHostKeyChecking=no",
        "UserKnownHostsFile=/dev/null",
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
    assert_eq!(broker_connection_limit(None).unwrap(), 129);
    assert_eq!(broker_connection_limit(Some(3)).unwrap(), 4);
    assert_eq!(broker_connection_limit(Some(128)).unwrap(), 129);
    assert_eq!(broker_connection_limit(Some(1000)).unwrap(), 1001);
    assert!(broker_connection_limit(Some(usize::MAX)).is_err());
}

#[test]
fn settlement_preserves_terminal_outcomes() {
    use DestinationStatus::{Clean, Failed};

    // Every (status, exit_code) pair matches the automation contract's
    // table: success/0, partial/23, refused/25, failed/1.
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
        (Clean, 1, 0, "refused", 25, true),
    ];
    for (destination, refusals, coordinator, status, exit_code, rejects) in cases {
        let outcome = settlement_outcome(destination, refusals, coordinator);
        assert_eq!(outcome.results_status, status);
        assert_eq!(outcome.exit_code, exit_code);
        assert_eq!(outcome.rejects, rejects);
    }
}

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// A results writer whose records can be read back.
fn results_file() -> (std::fs::File, std::sync::Arc<crate::results::ResultsWriter>) {
    let file = tempfile::tempfile().unwrap();
    let writer = crate::results::ResultsWriter::new(Box::new(file.try_clone().unwrap()));
    (file, std::sync::Arc::new(writer))
}

fn read_records(mut file: std::fs::File) -> Vec<serde_json::Value> {
    use std::io::Seek;
    let mut text = String::new();
    file.rewind().unwrap();
    file.read_to_string(&mut text).unwrap();
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// One of a remote coordinator's own records as it relays it.
fn coordinator_line(record: serde_json::Value, seq: u64) -> Vec<u8> {
    let mut record = record;
    let object = record.as_object_mut().unwrap();
    object.insert("schema".into(), crate::results::SCHEMA.into());
    object.insert(
        "schema_version".into(),
        crate::results::SCHEMA_VERSION.into(),
    );
    object.insert("seq".into(), seq.into());
    let mut line = crate::destination_results::relay::coordinator_prefix(TOKEN).into_bytes();
    line.extend_from_slice(&serde_json::to_vec(&record).unwrap());
    line.push(b'\n');
    line
}

fn destination_line(frame: &[u8]) -> Vec<u8> {
    let mut line = crate::destination_results::relay::destination_prefix(TOKEN).into_bytes();
    line.extend_from_slice(
        base64::engine::general_purpose::STANDARD_NO_PAD
            .encode(frame)
            .as_bytes(),
    );
    line.push(b'\n');
    line
}

fn settlement(coordinator_exit_code: i32) -> Settlement<'static> {
    Settlement {
        src_host: "source",
        dst_host: "destination",
        coordinator_exit_code,
        elapsed_ms: 1,
        verbose: false,
        quiet: true,
    }
}

fn coordinator_terminal() -> serde_json::Value {
    serde_json::json!({
        "type": "result",
        "status": "success",
        "exit_code": 0,
        "dry_run": false,
        "files_transferred": 99,
        "files_unchanged": 4,
        "files_excluded": 2,
        "directories_created": 0,
        "symlinks_created": 0,
        "specials_created": 0,
        "errors": 0,
        "bytes_transferred": 99,
        "bytes_unchanged": 40,
        "timings": {"total_ms": 5, "transfer_ms": 3},
    })
}

#[test]
fn ordinary_coordinator_results_are_relayed_with_this_machines_sequence() {
    let (file, writer) = results_file();
    writer.emit_value(serde_json::json!({"type": "run", "run_id": "local"}));
    let mut relay = Relay::new(TOKEN, Some(writer), None, (false, false));
    let mut input = b"syq: transferred 1 files\xff\r\n".to_vec();
    input.extend(coordinator_line(
        serde_json::json!({"type": "run", "run_id": "remote"}),
        0,
    ));
    input.extend(coordinator_line(
        serde_json::json!({"type": "operation_result", "action": "transfer_file",
            "dst": {"encoding": "utf-8", "value": "a"}, "kind": "file",
            "disposition": "succeeded", "bytes": 1}),
        1,
    ));
    // A line marked with another copy's token, as a crafted file name
    // printed by -v could be, is ordinary output.
    let forged = b"syq-results-ffffffffffffffffffffffffffffffff:{\"type\":\"error\"}\n";
    input.extend_from_slice(forged);
    input.extend(coordinator_line(coordinator_terminal(), 2));
    input.extend_from_slice(b"last line without a newline");
    let mut human = Vec::new();
    relay_output(input.as_slice(), &mut human, &mut None, &mut relay).unwrap();
    assert_eq!(
        human,
        [
            b"syq: transferred 1 files\xff\r\n".as_slice(),
            forged,
            b"last line without a newline"
        ]
        .concat()
    );
    assert_eq!(settle(relay, settlement(0)).unwrap(), 0);
    let records = read_records(file);
    let kinds: Vec<_> = records.iter().map(|r| r["type"].clone()).collect();
    assert_eq!(kinds, ["run", "operation_result", "result"]);
    assert_eq!(records[0]["run_id"], "local");
    assert_eq!(
        records.iter().map(|r| r["seq"].clone()).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(records[2]["files_transferred"], 99);

    // A coordinator that ends without its final result fails the stream.
    let (file, writer) = results_file();
    let relay = Relay::new(TOKEN, Some(writer), None, (false, false));
    assert!(settle(relay, settlement(0)).is_err());
    let records = read_records(file);
    assert_eq!(records.last().unwrap()["status"], "failed");

    // Another results format, and an oversized line, are refused.
    for line in [
        {
            let mut line =
                crate::destination_results::relay::coordinator_prefix(TOKEN).into_bytes();
            line.extend_from_slice(
                br#"{"type":"error","message":"x","schema":"syq.automation","schema_version":1,"seq":0}"#,
            );
            line.push(b'\n');
            line
        },
        {
            let mut line =
                crate::destination_results::relay::coordinator_prefix(TOKEN).into_bytes();
            line.extend(std::iter::repeat_n(b'A', MAX_RELAYED_LINE_BYTES + 1));
            line.push(b'\n');
            line
        },
    ] {
        let (_, writer) = results_file();
        let mut relay = Relay::new(TOKEN, Some(writer), None, (false, false));
        let mut human = Vec::new();
        let input = [line.as_slice(), b"after\n"].concat();
        relay_output(input.as_slice(), &mut human, &mut None, &mut relay).unwrap();
        // Nothing of a marked line reaches human output.
        assert_eq!(human, b"after\n");
        assert!(settle(relay, settlement(0)).is_err());
    }
}

/// A destination's stream for one copy, with the expectation that reads it.
fn destination(
    records: bool,
) -> (
    crate::destination_results::Stream,
    crate::destination_results::Expectation,
) {
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[19; 32]).into(),
        "results-test",
    )
    .unwrap();
    let (secret, public) = crate::destination_results::generate_recipient().unwrap();
    let binding = crate::destination_results::Binding {
        enrollment_id: crate::enrollment::EnrollmentId::random(),
        request_id: crate::delegation::RequestId::fresh(1_900_000_000).unwrap(),
        grant_digest: [17; 32],
    };
    let stream = crate::destination_results::Stream::start(
        &crate::destination_results::ReceiptPolicy::for_recipient(public),
        binding,
        &key,
        records,
    )
    .unwrap();
    (
        stream,
        crate::destination_results::Expectation {
            public_key: key.public_key().to_openssh().unwrap(),
            binding,
            secret,
            records,
        },
    )
}

/// The destination's frames for a copy that published `a` and created `d`,
/// then refused `refusals` requests, each for one file `r0`, `r1`, ...,
/// as relayed lines.
fn destination_lines(stream: &mut crate::destination_results::Stream, refusals: u64) -> Vec<u8> {
    use crate::destination_results::Change;
    let mut lines = Vec::new();
    let mut take = |stream: &mut crate::destination_results::Stream| {
        for frame in stream
            .take_frames(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .unwrap()
        {
            lines.extend(destination_line(&frame));
        }
    };
    take(stream);
    stream.record(Change::PublishFile { size: 5 }, Some(b"a"), None);
    stream.record(Change::EnsureDirectory, Some(b"d"), None);
    take(stream);
    for index in 0..refusals {
        stream.refused(
            "refused: signed grant entry limit exceeded",
            &[(
                Some(format!("r{index}").into_bytes()),
                Change::PublishFile { size: 1 },
            )],
        );
    }
    stream.finish(5).unwrap();
    take(stream);
    lines
}

#[test]
fn destination_results_supply_its_changes_whatever_the_human_output_does() {
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
    for flush_only in [false, true] {
        let (mut stream, expectation) = destination(true);
        let (file, writer) = results_file();
        let mut relay = Relay::new(TOKEN, Some(writer), Some(expectation), (false, false));
        let mut input = b"human line\n".to_vec();
        // The coordinator's own record of a destination change gives way to
        // the destination's; its error records and totals remain.
        input.extend(coordinator_line(
            serde_json::json!({"type": "operation_result", "action": "transfer_file",
                "dst": {"encoding": "utf-8", "value": "forged"}, "kind": "file",
                "disposition": "succeeded", "bytes": 1}),
            0,
        ));
        input.extend(coordinator_line(
            serde_json::json!({"type": "error", "message": "syq: c: Permission denied"}),
            1,
        ));
        input.extend(destination_lines(&mut stream, 0));
        input.extend(coordinator_line(coordinator_terminal(), 2));
        let mut output_error = None;
        relay_output(
            input.as_slice(),
            &mut FailingOutput { flush_only },
            &mut output_error,
            &mut relay,
        )
        .unwrap();
        assert_eq!(output_error.unwrap().kind(), std::io::ErrorKind::BrokenPipe);
        // The coordinator reported its source failure as a partial copy.
        assert_eq!(settle(relay, settlement(23)).unwrap(), 23);
        let records = read_records(file);
        let operations: Vec<_> = records
            .iter()
            .filter(|record| record["type"] == "operation_result")
            .map(|record| record["dst"]["value"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(operations, ["a", "d"]);
        let terminal = records.last().unwrap();
        assert_eq!(terminal["type"], "result");
        assert_eq!(terminal["status"], "partial");
        assert_eq!(terminal["exit_code"], 23);
        assert_eq!(terminal["files_transferred"], 1);
        assert_eq!(terminal["bytes_transferred"], 5);
        assert_eq!(terminal["directories_created"], 1);
        assert_eq!(terminal["files_unchanged"], 4);
        assert_eq!(terminal["bytes_unchanged"], 40);
        assert_eq!(terminal["errors"], 1);
        assert!(terminal.get("provenance").is_none());
    }
}

#[test]
fn destination_refusals_and_failures_decide_the_outcome() {
    // A refusal makes the copy refused even if the coordinator reported
    // success, and is reported.
    let (mut stream, expectation) = destination(true);
    let (file, writer) = results_file();
    let mut relay = Relay::new(TOKEN, Some(writer), Some(expectation), (false, false));
    let mut input = destination_lines(&mut stream, 2);
    input.extend(coordinator_line(coordinator_terminal(), 0));
    relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
    assert_eq!(settle(relay, settlement(0)).unwrap(), 25);
    let records = read_records(file);
    let terminal = records.last().unwrap();
    assert_eq!(terminal["status"], "refused");
    // One error record for each refused change, from the destination.
    assert_eq!(terminal["errors"], 2);
    for name in ["r0", "r1"] {
        assert!(records.iter().any(|record| record["type"] == "error"
            && record["class"] == "safety_limit"
            && record["message"]
                == format!("syq: {name}: refused: signed grant entry limit exceeded")));
    }

    // Without --results the destination sends only its totals; a refusal
    // still fails the copy.
    let (mut stream, expectation) = destination(false);
    let mut relay = Relay::new(TOKEN, None, Some(expectation), (false, false));
    let input = destination_lines(&mut stream, 1);
    relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
    assert!(settle(relay, settlement(0)).is_err());
    let (mut stream, expectation) = destination(false);
    let mut relay = Relay::new(TOKEN, None, Some(expectation), (false, false));
    let input = destination_lines(&mut stream, 0);
    relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
    assert_eq!(settle(relay, settlement(0)).unwrap(), 0);
}

fn tagged_path(name: &str) -> serde_json::Value {
    serde_json::json!({"encoding": "utf-8", "value": name})
}

/// The coordinator's records of a failure at `name` it counts itself.
fn coordinator_failure(name: &str, message: &str, seq: u64) -> Vec<u8> {
    [
        coordinator_line(
            serde_json::json!({"type": "error", "class": "io",
                "message": format!("syq: {name}: {message}")}),
            seq,
        ),
        coordinator_line(
            serde_json::json!({"type": "operation_result", "action": "transfer_file",
                "dst": tagged_path(name), "kind": "file", "disposition": "failed",
                "retryable": "unknown", "class": "io", "message": message}),
            seq + 1,
        ),
    ]
    .concat()
}

/// What the invoking machine reports about one path.
fn records_about(records: &[serde_json::Value], name: &str) -> Vec<serde_json::Value> {
    records
        .iter()
        .filter(|record| {
            record["dst"] == tagged_path(name)
                || record["diagnostic_for"] == tagged_path(name)
                || record["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with(&format!("syq: {name}:")))
        })
        .cloned()
        .collect()
}

fn schema_validator() -> jsonschema::Validator {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schemas/automation.schema.json")).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

#[test]
fn a_refused_path_appears_once_from_the_receiver_whatever_the_coordinator_claims() {
    let validator = schema_validator();
    let mut reports = Vec::new();
    // The coordinator leaves its own record of the refusal out, or claims
    // the path succeeded; s0 failed reading the source, which only the
    // coordinator saw.
    for coordinator in ["silent", "claims-success"] {
        let (mut stream, expectation) = destination(true);
        let (file, writer) = results_file();
        let mut relay = Relay::new(TOKEN, Some(writer), Some(expectation), (false, false));
        let mut input = Vec::new();
        if coordinator == "claims-success" {
            input.extend(coordinator_line(
                serde_json::json!({"type": "operation_result", "action": "transfer_file",
                    "dst": tagged_path("r0"), "kind": "file", "disposition": "succeeded",
                    "bytes": 1}),
                0,
            ));
        }
        input.extend(coordinator_failure(
            "s0",
            "Permission denied (os error 13)",
            1,
        ));
        input.extend(destination_lines(&mut stream, 1));
        input.extend(coordinator_line(coordinator_terminal(), 3));
        relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
        assert_eq!(settle(relay, settlement(23)).unwrap(), 25, "{coordinator}");
        let records = read_records(file);
        let refused = records_about(&records, "r0");
        // Once, from the receiver: its error record and operation record.
        assert_eq!(
            refused
                .iter()
                .map(|record| (
                    record["type"].as_str().unwrap().to_owned(),
                    record["class"].as_str().unwrap_or_default().to_owned()
                ))
                .collect::<Vec<_>>(),
            [
                ("error".to_owned(), "safety_limit".to_owned()),
                ("operation_result".to_owned(), "safety_limit".to_owned())
            ],
            "{coordinator}: {records:?}"
        );
        assert_eq!(refused[1]["disposition"], "failed");
        // The source failure is the coordinator's, once.
        let source = records_about(&records, "s0");
        assert_eq!(source.len(), 2, "{coordinator}: {records:?}");
        assert_eq!(source[1]["retryable"], "unknown");
        assert_eq!(records.last().unwrap()["errors"], 2, "{coordinator}");
        for record in &records {
            assert!(
                validator.validate(record).is_ok(),
                "{coordinator}: {record}"
            );
        }
        reports.push(
            refused
                .into_iter()
                .map(|mut record| {
                    record.as_object_mut().unwrap().remove("seq");
                    record
                })
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(reports[0], reports[1]);
}

#[test]
fn a_source_failure_explains_a_file_the_receiver_left_unfinished_at_once() {
    let (mut stream, expectation) = destination(true);
    let (file, writer) = results_file();
    let mut relay = Relay::new(TOKEN, Some(writer), Some(expectation), (false, false));
    // A file's destination was prepared, then reading its source failed:
    // the coordinator's error explains the failure as it happens, and the
    // receiver, which cannot know why, lists the file unfinished at the end.
    let input = coordinator_line(
        serde_json::json!({
            "type": "error", "class": "io", "os_kind": "permission_denied",
            "message": "syq: a: read: Permission denied (os error 13)",
            "diagnostic_for": tagged_path("a"),
        }),
        0,
    );
    relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
    // Written already, before the receiver's stream ends.
    let early = read_records(file.try_clone().unwrap());
    assert_eq!(early.len(), 1, "{early:?}");
    assert_eq!(early[0]["os_kind"], "permission_denied");
    let mut input = Vec::new();
    let mut take = |stream: &mut crate::destination_results::Stream| {
        for frame in stream
            .take_frames(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .unwrap()
        {
            input.extend(destination_line(&frame));
        }
    };
    take(&mut stream);
    stream.record(
        crate::destination_results::Change::PublishFile { size: 4096 },
        Some(b"a"),
        Some(crate::destination_results::Failure::io(
            "the file was not finished",
        )),
    );
    stream.finish(0).unwrap();
    take(&mut stream);
    input.extend(coordinator_line(coordinator_terminal(), 1));
    relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
    assert_eq!(settle(relay, settlement(23)).unwrap(), 23);
    let records = read_records(file);
    let about = records_about(&records, "a");
    assert!(
        about[0]["message"]
            .as_str()
            .unwrap()
            .contains("read: Permission denied"),
        "source failure was lost: {records:?}"
    );
    // The file counts once, from the receiver.
    assert_eq!(about.len(), 3, "{records:?}");
    assert_eq!(records.last().unwrap()["errors"], 1, "{records:?}");
    let validator = schema_validator();
    for record in &records {
        assert!(validator.validate(record).is_ok(), "{record}");
    }
}

#[test]
fn records_relayed_before_an_unexpected_exit_are_kept() {
    let (_stream, expectation) = destination(true);
    let (file, writer) = results_file();
    let mut relay = Relay::new(TOKEN, Some(writer), Some(expectation), (false, false));
    let input = coordinator_failure("s0", "Permission denied (os error 13)", 0);
    relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
    // The coordinator's SSH command then ends with a status that is not a
    // copy's, and nothing is settled.
    drop(relay);
    let records = read_records(file);
    assert_eq!(records_about(&records, "s0").len(), 2, "{records:?}");
}

#[test]
fn a_coordinator_leaves_the_failures_the_receiver_lists_to_it() {
    use crate::results::ReceiverListing::{Explained, Listed, Unlisted};
    let file = tempfile::tempfile().unwrap();
    let writer = crate::results::ResultsWriter::new(Box::new(file.try_clone().unwrap()))
        .reporting_destination();
    for (name, listing) in [
        ("listed", Listed),
        ("explained", Explained),
        ("unlisted", Unlisted),
    ] {
        writer.emit_entry_error(
            &format!("syq: {name}: failed"),
            Some("io"),
            None,
            Some((name.as_bytes(), listing)),
        );
        writer.emit_operation_listed(
            &crate::results::OperationRecord {
                action: "transfer_file",
                dst: name.as_bytes(),
                src: None,
                kind: "file",
                disposition: "failed",
                bytes: None,
                attempts: Some(1),
                retryable: Some("unknown"),
                class: Some("io"),
                os_kind: None,
                message: Some("failed"),
            },
            None,
            listing,
        );
    }
    // Its successes are the receiver's to report.
    writer.emit_operation(&crate::results::OperationRecord {
        action: "transfer_file",
        dst: b"copied",
        src: None,
        kind: "file",
        disposition: "succeeded",
        bytes: Some(1),
        attempts: Some(1),
        retryable: None,
        class: None,
        os_kind: None,
        message: None,
    });
    let records = read_records(file);
    let summary: Vec<_> = records
        .iter()
        .map(|record| {
            (
                record["type"].as_str().unwrap(),
                record["dst"]["value"]
                    .as_str()
                    .or(record["diagnostic_for"]["value"].as_str())
                    .unwrap_or_default(),
                record.get("diagnostic_for").is_some(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("error", "explained", true),
            ("error", "", false),
            ("operation_result", "unlisted", false),
        ],
        "{records:?}"
    );
}

#[test]
fn cut_or_altered_destination_results_fail_the_copy() {
    // Each way a relay can spoil the stream: drop its end, drop a frame,
    // alter a frame, or send nothing.
    for spoil in 0..4 {
        let (mut stream, expectation) = destination(true);
        let (file, writer) = results_file();
        let mut relay = Relay::new(TOKEN, Some(writer), Some(expectation), (false, false));
        let lines = destination_lines(&mut stream, 0);
        let mut lines: Vec<Vec<u8>> = lines
            .split_inclusive(|byte| *byte == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        match spoil {
            0 => {
                lines.pop();
            }
            1 => {
                lines.remove(1);
            }
            2 => {
                let line = &mut lines[1];
                let index = line.len() - 5;
                line[index] = if line[index] == b'A' { b'B' } else { b'A' };
            }
            _ => lines.clear(),
        }
        let mut input = lines.concat();
        input.extend(coordinator_line(coordinator_terminal(), 0));
        relay_output(input.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
        assert!(settle(relay, settlement(0)).is_err(), "spoiled {spoil}");
        let records = read_records(file);
        let terminal = records.last().unwrap();
        assert_eq!(terminal["status"], "failed", "spoiled {spoil}");
        assert_eq!(terminal["exit_code"], 1);
        assert!(records
            .iter()
            .any(|record| record["type"] == "error" && record["class"] == "integrity"));
    }
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

#[test]
fn requester_loss_counts_only_input_that_ends_after_the_marker() {
    struct Reads(std::collections::VecDeque<std::io::Result<Vec<u8>>>);
    impl Read for Reads {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let bytes = self.0.pop_front().unwrap_or(Ok(Vec::new()))?;
            buffer[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }
    let interrupted = || Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
    let reset = || Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
    for (reads, lost) in [
        // `ssh -n` or StdinNull: input never reached the coordinator.
        (vec![], false),
        (vec![reset()], false),
        (vec![interrupted()], false),
        // The requester's marker, then its end, however it is reported.
        (vec![Ok(vec![REQUESTER_MARKER])], true),
        (vec![Ok(vec![REQUESTER_MARKER]), reset()], true),
        (
            vec![interrupted(), Ok(vec![REQUESTER_MARKER]), interrupted()],
            true,
        ),
    ] {
        let description = format!("{reads:?}");
        assert_eq!(
            wait_for_requester_loss(&mut Reads(reads.into())),
            lost,
            "{description}"
        );
    }
}

/// `ssh -G` output for a destination, as this machine's own configuration
/// resolves it under the receiver command.
const RECEIVER_CONFIG: &str = "user backup\n\
    hostname backup.example.net\n\
    port 2222\n\
    stricthostkeychecking ask\n\
    userknownhostsfile /home/u/.ssh/known_hosts /home/u/.ssh/known_hosts2\n\
    globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2\n\
    pubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512\n\
    sessiontype default\n\
    stdinnull no\n\
    forkafterauthentication no\n\
    securitykeyprovider internal\n\
    tunnel false\n\
    proxyusefdpass no\n";

/// A stand-in `ssh` in `directory` that prints `output` for `-G`.
fn stand_in_ssh(directory: &std::path::Path, output: &str) -> std::path::PathBuf {
    let path = directory.join("ssh");
    crate::test_support::write_executable(
        &path,
        format!("#!/bin/sh\nprintf '%s' '{output}'\n"),
        0o700,
    );
    path
}

#[test]
fn the_coordinator_adds_only_what_its_own_configuration_needs() {
    let connection = ReceiverConnection::parse(RECEIVER_CONFIG).unwrap();
    // SSH looks the destination up under its address and port.
    assert_eq!(connection.lookup, "[backup.example.net]:2222");
    // Nobody can answer `ask` here: accept a new host, as accept-new does.
    // Everything else stays as configured, and the approving machine's
    // knowledge joins through a command, beside the configured files.
    assert_eq!(connection.hostname, "backup.example.net");
    assert_eq!(connection.accepted_algorithms, "PubkeyAcceptedAlgorithms");
    assert_eq!(
        connection.arguments(Some(std::path::Path::new("/tmp/approving"))),
        [
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "KnownHostsCommand=/usr/bin/env cat /tmp/approving",
        ]
    );
    for configured in ["yes", "true", "no", "false", "accept-new"] {
        let connection = ReceiverConnection::parse(&RECEIVER_CONFIG.replace(
            "stricthostkeychecking ask",
            &format!("stricthostkeychecking {configured}"),
        ))
        .unwrap();
        assert!(
            !connection
                .additions
                .iter()
                .any(|option| option.starts_with("StrictHostKeyChecking")),
            "{configured}"
        );
    }
    // Session options the configuration sets are overridden, and only those.
    let session = ReceiverConnection::parse(
        &(RECEIVER_CONFIG
            .replace("sessiontype default", "sessiontype none")
            .replace("stdinnull no", "stdinnull yes")
            .replace("forkafterauthentication no", "forkafterauthentication yes")
            .replace(
                "securitykeyprovider internal",
                "securitykeyprovider /usr/lib/sk.so",
            )
            .replace("tunnel false", "tunnel point-to-point")
            .replace("proxyusefdpass no", "proxyusefdpass yes")
            + "remotecommand echo hi\n"),
    )
    .unwrap();
    for option in [
        "RemoteCommand=none",
        "SessionType=default",
        "StdinNull=no",
        "ForkAfterAuthentication=no",
        "SecurityKeyProvider=internal",
        "Tunnel=no",
        "ProxyUseFdpass=no",
    ] {
        assert!(session.additions.contains(&option.to_owned()), "{option}");
    }
    // A proxy means the host name is the host as the proxy sees it.
    assert!(!connection.proxied);
    for proxy in ["proxyjump gw.example.net", "proxycommand nc %h %p"] {
        assert!(
            ReceiverConnection::parse(&format!("{RECEIVER_CONFIG}{proxy}\n"))
                .unwrap()
                .proxied
        );
    }
    // An older ssh that reports none of them gets none of them.
    let old = ReceiverConnection::parse("hostname backup\nport 22\n").unwrap();
    assert!(old.additions.is_empty());
    assert_eq!(old.lookup, "backup");
    // A configured alias is the name.
    let aliased =
        ReceiverConnection::parse(&format!("{RECEIVER_CONFIG}hostkeyalias backup-alias\n"))
            .unwrap();
    assert_eq!(aliased.lookup, "backup-alias");
    // Without the approving machine's file, nothing is added.
    assert_eq!(
        connection.arguments(None),
        ["-o", "StrictHostKeyChecking=accept-new"]
    );
    // An older ssh names the accepted algorithms its own way.
    let older =
        ReceiverConnection::parse("hostname backup\nport 22\npubkeyacceptedkeytypes ssh-ed25519\n")
            .unwrap();
    assert_eq!(older.accepted_algorithms, "PubkeyAcceptedKeyTypes");
    assert!(ReceiverConnection::parse("port 22\n").is_err());
}

/// The approving machine's entries join through a KnownHostsCommand, which
/// leaves the configured files as they are. Where the configuration has a
/// command of its own, or this ssh has none, they become one more global
/// file only when the configured value has no whitespace: `ssh -G` prints a
/// list and one quoted name with spaces the same way.
#[test]
fn the_approving_machines_entries_join_without_guessing_file_lists() {
    let approving = Some(std::path::Path::new("/tmp/approving"));
    let joined = |config: &str| {
        let connection = ReceiverConnection::parse(config).unwrap();
        (
            connection.approving_keys(),
            connection
                .arguments(approving)
                .into_iter()
                .filter(|argument| {
                    argument.starts_with("KnownHostsCommand")
                        || argument.starts_with("GlobalKnownHostsFile")
                })
                .collect::<Vec<_>>(),
        )
    };
    assert_eq!(
        joined(RECEIVER_CONFIG),
        (
            ApprovingKeys::Command,
            vec!["KnownHostsCommand=/usr/bin/env cat /tmp/approving".to_owned()]
        )
    );
    // The configuration's own command stays.
    let own = format!("{RECEIVER_CONFIG}knownhostscommand /usr/local/bin/hosts %H\n");
    assert_eq!(joined(&own), (ApprovingKeys::Omitted, Vec::new()));
    // ssh names the command's output by its own label, and a file by its
    // name; an omission says why.
    let label = |config: &str| ReceiverConnection::parse(config).unwrap().approving_label();
    assert_eq!(label(RECEIVER_CONFIG), "KnownHostsCommand-");
    assert_eq!(label(&own), APPROVING_KNOWN_HOSTS);
    assert!(ReceiverConnection::parse(&own)
        .unwrap()
        .omission_cause()
        .starts_with("this machine's configuration has a KnownHostsCommand of its own, "));
    let single = own.replace(
        "globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2",
        "globalknownhostsfile /etc/ssh/ssh_known_hosts",
    );
    assert_eq!(
        joined(&single),
        (
            ApprovingKeys::GlobalFile,
            vec!["GlobalKnownHostsFile=/etc/ssh/ssh_known_hosts /tmp/approving".to_owned()]
        )
    );
    let none = own.replace(
        "globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2",
        "globalknownhostsfile none",
    );
    assert_eq!(
        joined(&none),
        (
            ApprovingKeys::GlobalFile,
            vec!["GlobalKnownHostsFile=/tmp/approving".to_owned()]
        )
    );
    // An ssh older than 8.5 has no KnownHostsCommand.
    let older = RECEIVER_CONFIG.replace(
        "pubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512",
        "pubkeyacceptedkeytypes ssh-ed25519,rsa-sha2-512",
    );
    assert_eq!(joined(&older), (ApprovingKeys::Omitted, Vec::new()));
    assert!(ReceiverConnection::parse(&older)
        .unwrap()
        .omission_cause()
        .starts_with("this machine's ssh is older than OpenSSH 8.5, "));
    assert_eq!(
        joined(&older.replace(
            "globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2",
            "globalknownhostsfile /etc/ssh/ssh_known_hosts",
        ))
        .0,
        ApprovingKeys::GlobalFile
    );
}

/// With real OpenSSH: under the receiver command and what syq adds, a
/// configuration that would weaken the entry key's session keeps none of
/// that, while its host-key checking stands as configured.
#[test]
fn the_entry_key_session_keeps_its_hardening_under_this_machines_configuration() {
    let temporary = crate::test_support::tempdir().unwrap();
    let config = temporary.path().join("config");
    std::fs::write(
        &config,
        "Host backup\n  HostName backup.example.net\n  Port 2222\n  User someone\n  \
         IdentityAgent /tmp/agent\n  ForwardAgent yes\n  ForwardX11 yes\n  \
         ControlMaster auto\n  ControlPath ~/.ssh/cm-%C\n  ProxyJump bastion\n  \
         LocalForward 1234 localhost:22\n  RemoteForward 1235 localhost:22\n  \
         RemoteCommand echo hi\n  RequestTTY yes\n  PKCS11Provider /usr/lib/p11.so\n  \
         SecurityKeyProvider /usr/lib/sk.so\n  PermitLocalCommand yes\n  \
         LocalCommand touch /tmp/x\n  Tunnel yes\n  SessionType none\n  StdinNull yes\n  \
         ForkAfterAuthentication yes\n  ProxyUseFdpass yes\n  BatchMode no\n  \
         IdentitiesOnly no\n  PubkeyAuthentication no\n  PasswordAuthentication yes\n  \
         StrictHostKeyChecking ask\n  UserKnownHostsFile none\n  \
         CASignatureAlgorithms ssh-ed25519\n  KnownHostsCommand /bin/true %H %K\n  \
         PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519\n  \
         HostbasedAuthentication yes\n  KbdInteractiveAuthentication yes\n",
    )
    .unwrap();
    let mut command = shell_words::split(&receiver_rsh(None)).unwrap();
    command.splice(1..1, ["-F".to_owned(), config.display().to_string()]);
    let resolved = |command: &[String]| {
        let output = Command::new(&command[0])
            .args(&command[1..])
            .args(["-G", "-l", "backup", "backup"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    let connection = ReceiverConnection::parse(&resolved(&command)).unwrap();
    command.extend(connection.arguments(Some(std::path::Path::new("/tmp/approving"))));
    command.extend([
        "-o".to_owned(),
        format!("{}=ssh-ed25519", connection.accepted_algorithms),
    ]);
    let effective = resolved(&command);
    let has = |line: &str| effective.lines().any(|candidate| candidate == line);
    for line in [
        "user backup",
        "identityagent none",
        "identitiesonly yes",
        "forwardagent no",
        "forwardx11 no",
        "controlmaster false",
        "requesttty false",
        "securitykeyprovider internal",
        "permitlocalcommand no",
        "tunnel false",
        "sessiontype default",
        "stdinnull no",
        "forkafterauthentication no",
        "proxyusefdpass no",
        "batchmode yes",
        "pubkeyauthentication true",
        "preferredauthentications publickey",
        // Only the entry key's own algorithm: no certificate is offered.
        "pubkeyacceptedalgorithms ssh-ed25519",
        "hostbasedauthentication no",
        "kbdinteractiveauthentication no",
        "passwordauthentication no",
        "clearallforwardings yes",
        // Host-key checking as configured, `ask` accepting a new key.
        "stricthostkeychecking accept-new",
        "userknownhostsfile none",
        "casignaturealgorithms ssh-ed25519",
        // The configuration's own command stays, and its default global
        // list could be one quoted name: the approving machine's entries
        // are left out rather than guessed at.
        "knownhostscommand /bin/true %H %K",
    ] {
        assert!(has(line), "{line}\n{effective}");
    }
    // OpenSSH leaves these settings out when they are off.
    for name in [
        "controlpath ",
        "proxyjump ",
        "proxycommand ",
        "localforward ",
        "remoteforward ",
        "remotecommand ",
        "pkcs11provider ",
    ] {
        assert!(
            !effective.lines().any(|line| line.starts_with(name)),
            "{name}\n{effective}"
        );
    }
    // The entry key comes first; HostKeyAlgorithms stays unset, so OpenSSH
    // still prefers the key types it already knows for the destination.
    assert_eq!(
        effective
            .lines()
            .find(|line| line.starts_with("identityfile ")),
        Some("identityfile none")
    );
    assert!(!command
        .iter()
        .any(|argument| argument.starts_with("HostKeyAlgorithms")));
}

#[test]
fn receiver_ssh_uses_the_entry_key_first_and_checks_host_keys_as_this_machine_does() {
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt as _;
    let mut args = Args::parse_from(["syq", "src", "dst"]);
    args.restricted_grant = Some("signed-grant".into());
    args.locations = vec![Location::parse("backup:/archive").unwrap()];
    let stand_in = crate::test_support::tempdir().unwrap();
    let ssh = stand_in_ssh(stand_in.path(), RECEIVER_CONFIG);
    let mut words = shell_words::split(&receiver_rsh(Some(2222))).unwrap();
    words[0] = ssh.display().to_string();
    let template = shell_words::join(&words);
    args.rsh = Some(template.clone());
    let host =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    let authority =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    let host_key = host.public_key().to_openssh().unwrap();
    let authority_key = authority.public_key().to_openssh().unwrap();
    // What the approving machine knows: a key and a host certificate
    // authority, under its own name for the destination.
    let known_hosts =
        format!("backup-alias {host_key}\n@cert-authority backup-alias {authority_key}\n");
    let entry =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    let entry_key = entry.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let guard = prepare_receiver_ssh_with(&mut args, &known_hosts, entry_key.as_bytes()).unwrap();
    let command = parse_rsh(&args.rsh).unwrap();
    // This machine's own configuration, under the entry-key hardening.
    assert!(!command.contains(&"-F".to_owned()));
    for flag in ["-a", "-x", "-k", "-T"] {
        assert!(command.contains(&flag.to_owned()), "{flag}");
    }
    for option in [
        "IdentityAgent=none",
        "IdentitiesOnly=yes",
        "CertificateFile=none",
        "PKCS11Provider=none",
        "PubkeyAuthentication=yes",
        "PreferredAuthentications=publickey",
        "BatchMode=yes",
        "ControlMaster=no",
        "ControlPath=none",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "PermitLocalCommand=no",
        "ProxyJump=none",
        "ProxyCommand=none",
        "HostbasedAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "PasswordAuthentication=no",
        "StrictHostKeyChecking=accept-new",
        // The entry key's own algorithm only: no certificate first.
        "PubkeyAcceptedAlgorithms=ssh-ed25519",
    ] {
        assert!(command.contains(&option.to_owned()), "{option}");
    }
    for unset in ["UserKnownHostsFile=", "HostKeyAlias=", "HostKeyAlgorithms="] {
        assert!(
            !command.iter().any(|argument| argument.starts_with(unset)),
            "{unset}"
        );
    }
    assert!(!command.contains(&"PubkeyAuthentication=host-bound".into()));
    assert!(!command
        .iter()
        .any(|argument| argument == "IdentityFile=none"));
    let approving = guard.path().join(APPROVING_KNOWN_HOSTS);
    let key = guard.path().join("entry-key");
    assert!(command.contains(&format!(
        "KnownHostsCommand=/usr/bin/env cat {}",
        approving.display()
    )));
    assert!(!command
        .iter()
        .any(|argument| argument.starts_with("GlobalKnownHostsFile")));
    assert!(command.contains(&format!("IdentityFile={}", key.display())));
    // Written under the name this machine's own configuration uses.
    assert_eq!(
        std::fs::read_to_string(&approving).unwrap(),
        format!(
            "[backup.example.net]:2222 {host_key}\n@cert-authority [backup.example.net]:2222 {authority_key}\n"
        )
    );
    assert_eq!(std::fs::read_to_string(&key).unwrap(), entry_key.as_str());
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The copy's TCP data goes to the host this inspection resolved, and a
    // refused key names the approving machine's own name for the host.
    let (dialed, receiver) = args.receiver_host.take().unwrap();
    assert_eq!(dialed, "backup");
    assert_eq!(receiver.hostname, "backup.example.net");
    assert_eq!(
        receiver.approving,
        Some(("KnownHostsCommand-", "backup-alias".to_owned()))
    );
    drop(guard);
    assert!(!approving.exists() && !key.exists());

    // With a KnownHostsCommand of its own and a global value that could be
    // one quoted name, the configuration stays as it is, without the
    // approving machine's entries.
    let configured = crate::test_support::tempdir().unwrap();
    let ssh = stand_in_ssh(
        configured.path(),
        &format!("{RECEIVER_CONFIG}knownhostscommand /usr/local/bin/hosts %H\n"),
    );
    let mut words = shell_words::split(&receiver_rsh(Some(2222))).unwrap();
    words[0] = ssh.display().to_string();
    args.rsh = Some(shell_words::join(&words));
    let guard = prepare_receiver_ssh_with(&mut args, &known_hosts, entry_key.as_bytes()).unwrap();
    let command = parse_rsh(&args.rsh).unwrap();
    assert!(!command.iter().any(|argument| {
        argument.starts_with("GlobalKnownHostsFile") || argument.starts_with("KnownHostsCommand")
    }));
    assert_eq!(args.receiver_host.take().unwrap().1.approving, None);
    drop(guard);
    // Without them, a key the approving machine revokes could be trusted
    // here, so the copy is refused.
    let revoked =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    let revoking = format!(
        "{known_hosts}@revoked backup-alias {}\n",
        revoked.public_key().to_openssh().unwrap()
    );
    args.rsh = Some(shell_words::join(&words));
    let error = prepare_receiver_ssh_with(&mut args, &revoking, entry_key.as_bytes())
        .expect_err("a revocation that cannot be passed on refuses the copy");
    assert!(
        error
            .to_string()
            .contains("revokes a host key for the destination")
            && error.to_string().contains("KnownHostsCommand of its own"),
        "{error:#}"
    );
    // Where it can join, the revocation goes along.
    args.rsh = Some(template.clone());
    let guard = prepare_receiver_ssh_with(&mut args, &revoking, entry_key.as_bytes()).unwrap();
    assert!(
        std::fs::read_to_string(guard.path().join(APPROVING_KNOWN_HOSTS))
            .unwrap()
            .contains("@revoked [backup.example.net]:2222 ")
    );
    drop(guard);

    // An approving machine that knows nothing adds nothing.
    args.rsh = Some(template.clone());
    let guard = prepare_receiver_ssh_with(&mut args, "", entry_key.as_bytes()).unwrap();
    assert!(!guard.path().join(APPROVING_KNOWN_HOSTS).exists());
    let command = parse_rsh(&args.rsh).unwrap();
    assert!(!command.iter().any(|argument| {
        argument.starts_with("GlobalKnownHostsFile") || argument.starts_with("KnownHostsCommand")
    }));
    drop(guard);
    args.rsh = Some(template.clone());
    assert!(
        prepare_receiver_ssh_with(&mut args, "@cert-authority * bad", entry_key.as_bytes())
            .is_err()
    );
    // A name that cannot be shown as it is gives way to the host dialed.
    args.rsh = Some(template.clone());
    let guard = prepare_receiver_ssh_with(
        &mut args,
        &format!("backup\u{1b}[2J {host_key}\n"),
        entry_key.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        args.receiver_host.take().unwrap().1.approving,
        Some(("KnownHostsCommand-", "backup".to_owned()))
    );
    drop(guard);
    // A command that already checks host keys its own way is refused.
    args.rsh = Some(format!("{template} -o StrictHostKeyChecking=no"));
    assert!(prepare_receiver_ssh_with(&mut args, &known_hosts, entry_key.as_bytes()).is_err());
    // A command that would also use an agent never gets the key.
    args.rsh = Some(template.replace("IdentityAgent=none", "IdentityAgent=SSH_AUTH_SOCK"));
    assert!(prepare_receiver_ssh_with(&mut args, &known_hosts, entry_key.as_bytes()).is_err());
    // The broker's command uses an agent, so it never gets the key.
    args.rsh = Some(constrained_destination_rsh(
        Some(2222),
        DestinationAuthentication::Broker {
            host_key_algorithms: "ssh-ed25519",
        },
    ));
    assert!(prepare_receiver_ssh_with(&mut args, &known_hosts, entry_key.as_bytes()).is_err());
}

#[test]
fn the_coordinator_connection_forwards_nothing_when_it_gets_an_entry_key() {
    let ssh = vec!["ssh".to_owned()];
    let with_key = coordinator_rsh(&ssh, true);
    // No `-k`: this connection may become the master later copies share,
    // and GSSAPI delegation belongs to the master's login.
    assert_eq!(with_key, ["ssh", "-x", "-o", "ClearAllForwardings=yes"]);
    // Both the direct command and helper setup start from it; a master
    // connection may still carry it.
    assert!(source_setup_rsh(&with_key, false).ends_with(&["-a".to_owned()]));
    assert_eq!(coordinator_rsh(&ssh, false), ssh);
    // An explicit non-ssh command is the user's own policy.
    let custom = vec!["my-transport".to_owned()];
    assert_eq!(coordinator_rsh(&custom, true), custom);
}

#[test]
fn an_interrupted_coordinator_removes_its_entry_key() {
    use clap::Parser;
    const CHILD: &str = "SYQ_TEST_ENTRY_KEY_CHILD";
    const STAND_IN: &str = "SYQ_TEST_ENTRY_KEY_SSH";
    if let Some(report) = std::env::var_os(CHILD) {
        let mut args = Args::parse_from(["syq", "src", "dst"]);
        args.restricted_grant = Some("signed-grant".into());
        args.locations = vec![Location::parse("backup:/archive").unwrap()];
        // A stand-in `ssh`, so the developer's own configuration plays no
        // part.
        let mut words = shell_words::split(&receiver_rsh(Some(2222))).unwrap();
        words[0] = std::env::var(STAND_IN).unwrap();
        args.rsh = Some(shell_words::join(&words));
        let host = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let entry = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap();
        let directory = prepare_receiver_ssh_with(
            &mut args,
            &format!("backup {}\n", host.public_key().to_openssh().unwrap()),
            entry.as_bytes(),
        )
        .unwrap();
        assert!(directory.path().join("entry-key").is_file());
        std::fs::write(&report, directory.path().as_os_str().as_encoded_bytes()).unwrap();
        unsafe { libc::raise(libc::SIGTERM) };
        std::thread::sleep(std::time::Duration::from_secs(10));
        unreachable!("SIGTERM did not end the coordinator");
    }
    let temporary = crate::test_support::tempdir().unwrap();
    let report = temporary.path().join("directory");
    let ssh = stand_in_ssh(temporary.path(), RECEIVER_CONFIG);
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "remote_to_remote::tests::an_interrupted_coordinator_removes_its_entry_key",
            "--nocapture",
        ])
        .env(CHILD, &report)
        .env(STAND_IN, &ssh)
        .stdin(Stdio::null())
        .status_guarded()
        .unwrap();
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
    let directory = std::path::PathBuf::from(std::fs::read_to_string(&report).unwrap());
    assert!(!directory.exists(), "{} survived", directory.display());
}

/// An enrolled receiver's entry key and directive reach the coordinator on
/// its input; its command line and environment carry only their lengths.
#[test]
fn the_coordinator_gets_the_entry_key_and_directive_only_on_its_input() {
    use base64::Engine as _;
    let directive = b"SYQDIR1\0 signed directive".to_vec();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&directive);
    let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n";
    let (environment, input) = receiver_inputs(Some(&encoded), Some(key)).unwrap();
    assert_eq!(input.as_deref(), Some(directive.as_slice()));
    assert_eq!(
        environment,
        [
            (ENTRY_KEY_STDIN, key.len().to_string()),
            (DIRECTIVE_STDIN, directive.len().to_string()),
        ]
    );
    for (_, value) in &environment {
        assert!(!value.contains(&encoded) && !value.contains("PRIVATE KEY"));
    }
    // A copy between two servers that hostX approved passes its marker.
    let marker = crate::destination::peer_bridge::GRANT;
    let (environment, input) = receiver_inputs(Some(marker), None).unwrap();
    assert_eq!(
        environment,
        [("SYQ_INTERNAL_NATIVE_RESTRICTED_GRANT", marker.to_owned())]
    );
    assert!(input.is_none());
    assert_eq!(receiver_inputs(None, None).unwrap(), (Vec::new(), None));
}

/// The coordinator reads exactly the entry key and the directive from its
/// input, and leaves what follows, the manifest and the requester's marker,
/// for the copy.
#[test]
fn the_coordinator_reads_the_entry_key_and_directive_from_its_input() {
    use base64::Engine as _;
    use clap::Parser;
    const CHILD: &str = "SYQ_TEST_DIRECTIVE_INPUT_CHILD";
    let entry =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap();
    let directive = b"SYQDIR1\0 the copy's directive";
    let stand_in = crate::test_support::tempdir().unwrap();
    crate::test_support::write_executable(
        &stand_in.path().join("ssh"),
        format!("#!/bin/sh\nprintf '%s' '{RECEIVER_CONFIG}'\n"),
        0o700,
    );
    if std::env::var_os(CHILD).is_some() {
        let host = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let mut args = Args::parse_from(["syq", "src", "dst"]);
        args.delegated = true;
        args.entry_key_stdin = Some(
            std::env::var("SYQ_TEST_ENTRY_KEY_LENGTH")
                .unwrap()
                .parse()
                .unwrap(),
        );
        args.directive_stdin = Some(directive.len());
        args.receiver_known_hosts = Some(format!(
            "backup {}\n",
            host.public_key().to_openssh().unwrap()
        ));
        args.rsh = Some(receiver_rsh(Some(2222)));
        // The coordinator reads its own SSH configuration for the receiver,
        // here from the stand-in `ssh` the parent put first on PATH.
        args.locations = vec![Location::parse("backup:/archive").unwrap()];
        let _directory = prepare_receiver_ssh(&mut args).unwrap().unwrap();
        assert_eq!(
            args.restricted_grant.as_deref(),
            Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(directive)
                    .as_str()
            )
        );
        let mut rest = Vec::new();
        std::io::stdin().read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"manifest");
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "remote_to_remote::tests::the_coordinator_reads_the_entry_key_and_directive_from_its_input",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env("SYQ_TEST_ENTRY_KEY_LENGTH", entry.len().to_string())
        .env(
            "PATH",
            format!(
                "{}:{}",
                stand_in.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_guarded()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(entry.as_bytes()).unwrap();
    input.write_all(directive).unwrap();
    input.write_all(b"manifest").unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_coordinator_command_fits_in_one_linux_argument() {
    assert!(ensure_coordinator_command_fits(128 * 1024 - 1, 1).is_ok());
    let error = ensure_coordinator_command_fits(128 * 1024, 900).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("names 900 sources, which make its coordinator's command line 128 KiB"),
        "{error:#}"
    );
}

#[test]
fn unverified_results_are_quiet_only_without_any_results_after_a_failure() {
    // Nothing arrived and the coordinator failed: one short local line.
    assert_eq!(
        unverified_results(false, 1, "source", "destination").as_deref(),
        Some("the receiver on destination sent no results through source")
    );
    // A coordinator that claims success without any results fails loudly.
    assert_eq!(unverified_results(false, 0, "source", "destination"), None);
    // Results that started but did not end are always the full complaint.
    assert_eq!(unverified_results(true, 1, "source", "destination"), None);
    assert_eq!(unverified_results(true, 0, "source", "destination"), None);
}
