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
        relay_output(line.as_slice(), &mut Vec::new(), &mut None, &mut relay).unwrap();
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

/// The destination's frames for a copy that published `a`, failed `b`,
/// and refused `refusals` requests, as relayed lines.
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
    if refusals > 0 {
        stream.record(Change::PublishFile { size: 1 }, Some(b"b"), Some("refused"));
    }
    for _ in 0..refusals {
        stream.refused();
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
    assert_eq!(terminal["errors"], 1);
    assert!(records.iter().any(|record| record["type"] == "error"
        && record["class"] == "safety_limit"
        && record["message"]
            .as_str()
            .unwrap()
            .contains("refused 2 request(s)")));

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
fn receiver_ssh_uses_ordinary_auth_and_pinned_host_keys() {
    use clap::Parser;
    let mut args = Args::parse_from(["syq", "src", "dst"]);
    args.restricted_grant = Some("signed-grant".into());
    args.rsh = Some(constrained_destination_rsh(
        2222,
        "ssh-ed25519",
        DestinationAuthentication::Receiver,
    ));
    let key =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    let known_hosts = format!(
        "{RECEIVER_HOST_ALIAS} {}\n",
        key.public_key().to_openssh().unwrap()
    );
    let guard = prepare_receiver_ssh_with(&mut args, &known_hosts).unwrap();
    let command = parse_rsh(&args.rsh).unwrap();
    assert!(command.contains(&"StrictHostKeyChecking=yes".into()));
    assert!(command.contains(&"PubkeyAuthentication=yes".into()));
    assert!(!command.contains(&"PubkeyAuthentication=host-bound".into()));
    let path = guard.path().join("known_hosts");
    assert!(command.contains(&format!("UserKnownHostsFile={}", path.display())));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), known_hosts);
    drop(guard);
    assert!(!path.exists());
    assert!(prepare_receiver_ssh_with(&mut args, "@cert-authority * bad").is_err());
}
