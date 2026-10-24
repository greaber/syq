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
    let hardened =
        constrained_destination_rsh(2222, "ssh-ed25519", DestinationAuthentication::Broker);
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

#[test]
fn receiver_ssh_uses_the_entry_key_alone_and_pinned_host_keys() {
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt as _;
    let mut args = Args::parse_from(["syq", "src", "dst"]);
    args.restricted_grant = Some("signed-grant".into());
    let template =
        constrained_destination_rsh(2222, "ssh-ed25519", DestinationAuthentication::Receiver);
    args.rsh = Some(template.clone());
    let host =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    let known_hosts = format!(
        "{RECEIVER_HOST_ALIAS} {}\n",
        host.public_key().to_openssh().unwrap()
    );
    let entry =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    let entry_key = entry.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let guard = prepare_receiver_ssh_with(&mut args, &known_hosts, entry_key.as_bytes()).unwrap();
    let command = parse_rsh(&args.rsh).unwrap();
    // The whole hardening set: no user configuration, agent, control
    // socket, forwarding, proxy or local command, the entry key as the only
    // identity, and only the pinned host keys.
    assert_eq!(&command[..3], ["ssh", "-F", "/dev/null"]);
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
        "PermitLocalCommand=no",
        "ProxyJump=none",
        "ProxyCommand=none",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "UpdateHostKeys=no",
        "HostKeyAlias=syq-enrolled-receiver",
    ] {
        assert!(command.contains(&option.to_owned()), "{option}");
    }
    assert!(!command.contains(&"PubkeyAuthentication=host-bound".into()));
    assert!(!command
        .iter()
        .any(|argument| argument == "IdentityFile=none"));
    let known = guard.path().join("known_hosts");
    let key = guard.path().join("entry-key");
    assert!(command.contains(&format!("UserKnownHostsFile={}", known.display())));
    assert!(command.contains(&format!("IdentityFile={}", key.display())));
    assert_eq!(std::fs::read_to_string(&known).unwrap(), known_hosts);
    assert_eq!(std::fs::read_to_string(&key).unwrap(), entry_key.as_str());
    assert_eq!(
        std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(guard);
    assert!(!known.exists() && !key.exists());

    args.rsh = Some(template.clone());
    assert!(
        prepare_receiver_ssh_with(&mut args, "@cert-authority * bad", entry_key.as_bytes())
            .is_err()
    );
    // A command that would also use an agent never gets the key.
    args.rsh = Some(template.replace("IdentityAgent=none", "IdentityAgent=SSH_AUTH_SOCK"));
    assert!(prepare_receiver_ssh_with(&mut args, &known_hosts, entry_key.as_bytes()).is_err());
    // The broker's command uses an agent, so it never gets the key.
    args.rsh = Some(constrained_destination_rsh(
        2222,
        "ssh-ed25519",
        DestinationAuthentication::Broker,
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
    if let Some(report) = std::env::var_os(CHILD) {
        let mut args = Args::parse_from(["syq", "src", "dst"]);
        args.restricted_grant = Some("signed-grant".into());
        args.rsh = Some(constrained_destination_rsh(
            2222,
            "ssh-ed25519",
            DestinationAuthentication::Receiver,
        ));
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
            &format!(
                "{RECEIVER_HOST_ALIAS} {}\n",
                host.public_key().to_openssh().unwrap()
            ),
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
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "remote_to_remote::tests::an_interrupted_coordinator_removes_its_entry_key",
            "--nocapture",
        ])
        .env(CHILD, &report)
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
            "{RECEIVER_HOST_ALIAS} {}\n",
            host.public_key().to_openssh().unwrap()
        ));
        args.rsh = Some(constrained_destination_rsh(
            2222,
            "ssh-ed25519",
            DestinationAuthentication::Receiver,
        ));
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
