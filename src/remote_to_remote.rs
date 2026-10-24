//! Remote-to-remote copies: run the coordinator on one of the remote hosts so data
//! flows source→destination without passing through this machine.

use crate::cli::PeerAuth;
use crate::cli::{parse_rsh, Args, Existence, Interface, Location, Placement, SourceSelection};
use crate::process::CommandExt as _;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::process::{Command, Stdio};

/// What the destination's own results say, for the outcome rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationStatus {
    Clean,
    /// Some change failed or was left unfinished.
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SettlementOutcome {
    results_status: &'static str,
    exit_code: i32,
    /// The destination's results contradict the coordinator's exit status.
    rejects: bool,
}

fn settlement_outcome(
    destination: DestinationStatus,
    refusals: u64,
    coordinator_exit_code: i32,
) -> SettlementOutcome {
    // The destination's results decide whether settlement fails the run: a
    // refusal, or a failed change against a coordinator that claimed
    // success, is a contradiction the exit code must surface.
    let rejects =
        refusals > 0 || (destination != DestinationStatus::Clean && coordinator_exit_code == 0);
    // Status first, then the exit code the automation contract pairs with
    // it — the two can never disagree.
    let results_status = if coordinator_exit_code == 1 {
        // A coordinator-fatal run may hold unsettled entries; the
        // destination's records still describe what did land.
        "failed"
    } else if refusals > 0 || coordinator_exit_code == 25 {
        "refused"
    } else if destination != DestinationStatus::Clean || coordinator_exit_code == 23 {
        "partial"
    } else {
        "success"
    };
    let exit_code = match results_status {
        "success" => 0,
        "partial" => 23,
        "refused" => 25,
        _ => 1,
    };
    SettlementOutcome {
        results_status,
        exit_code,
        rejects,
    }
}

/// An error record the final result counts: not one that only explains a
/// failure another record counts.
fn counted_error(record: &serde_json::Value) -> bool {
    record.get("type").and_then(serde_json::Value::as_str) == Some("error")
        && record.get(crate::results::DIAGNOSTIC_FOR).is_none()
}

/// The longest relayed results line: a coordinator record, or a base64
/// destination frame.
const MAX_RELAYED_LINE_BYTES: usize = 1024 * 1024;

/// Results arriving on a remote coordinator's standard output: its own
/// records and, through a restricted receiver, the destination's frames.
/// Each is written as it arrives; nothing accumulates. Through a restricted
/// receiver, the destination's records of what it changed, refused, or
/// failed are the only ones of their kind: the coordinator leaves out its
/// records of the failures the destination lists, and its claims of success
/// are dropped here.
struct Relay {
    coordinator_prefix: Vec<u8>,
    destination_prefix: Vec<u8>,
    results: Option<std::sync::Arc<crate::results::ResultsWriter>>,
    /// The restricted destination's stream, which also supplies the
    /// operation records for its changes.
    destination: Option<crate::destination_results::Reader>,
    coordinator_terminal: Option<serde_json::Value>,
    /// The run's shape, for a final result this machine writes itself.
    dry_run: bool,
    prune: bool,
    /// Counted error records written to the results so far.
    errors: u64,
    /// The first problem with what arrived; later lines are drained unread.
    failure: Option<anyhow::Error>,
}

impl Relay {
    fn new(
        token: &str,
        results: Option<std::sync::Arc<crate::results::ResultsWriter>>,
        destination: Option<crate::destination_results::Expectation>,
        (dry_run, prune): (bool, bool),
    ) -> Self {
        Self {
            coordinator_prefix: crate::destination_results::relay::coordinator_prefix(token)
                .into_bytes(),
            destination_prefix: crate::destination_results::relay::destination_prefix(token)
                .into_bytes(),
            results,
            destination: destination.map(crate::destination_results::Reader::new),
            coordinator_terminal: None,
            dry_run,
            prune,
            errors: 0,
            failure: None,
        }
    }

    /// Whether a line is one of ours.
    fn marked(&self, line: &[u8]) -> bool {
        line.starts_with(&self.coordinator_prefix) || line.starts_with(&self.destination_prefix)
    }

    fn line(&mut self, line: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        let result = if let Some(record) = line.strip_prefix(self.coordinator_prefix.as_slice()) {
            self.coordinator_record(record)
        } else if let Some(frame) = line.strip_prefix(self.destination_prefix.as_slice()) {
            self.destination_frame(frame)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            self.failure = Some(error);
        }
    }

    fn coordinator_record(&mut self, line: &[u8]) -> Result<()> {
        let Some(writer) = &self.results else {
            bail!("the coordinating server sent results that were not requested");
        };
        let mut record: serde_json::Value =
            serde_json::from_slice(line).context("decode a relayed results record")?;
        let object = record
            .as_object_mut()
            .context("a relayed results record is not an object")?;
        let schema = object.remove("schema");
        let version = object.remove("schema_version");
        object.remove("seq");
        anyhow::ensure!(
            schema.as_ref().and_then(serde_json::Value::as_str) == Some(crate::results::SCHEMA)
                && version.as_ref().and_then(serde_json::Value::as_u64)
                    == Some(writer.schema_version()),
            "the coordinating server writes another results format; use the same syq version on both machines"
        );
        let kind = object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match kind.as_str() {
            // This machine's own run record opened the stream.
            "run" => {}
            "result" => {
                anyhow::ensure!(
                    self.coordinator_terminal.is_none(),
                    "the coordinating server sent two final results"
                );
                self.coordinator_terminal = Some(record);
            }
            // The destination reports the changes it made.
            "operation_result"
                if self.destination.is_some()
                    && object
                        .get("disposition")
                        .and_then(serde_json::Value::as_str)
                        == Some("succeeded") => {}
            _ => {
                anyhow::ensure!(
                    self.coordinator_terminal.is_none(),
                    "the coordinating server sent results after its final result"
                );
                if counted_error(&record) {
                    self.errors += 1;
                }
                writer.emit_value(record);
            }
        }
        Ok(())
    }

    fn destination_frame(&mut self, line: &[u8]) -> Result<()> {
        let reader = self.destination.as_mut().context(
            "the coordinating server relayed destination results that were not expected",
        )?;
        let frame = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(line.trim_ascii())
            .context("decode a relayed destination results frame")?;
        let mut records = Vec::new();
        reader.accept(&frame, |record| {
            records.push(record);
            Ok(())
        })?;
        self.errors += records
            .iter()
            .filter(|record| counted_error(record))
            .count() as u64;
        // A frame's records are written together.
        if let Some(writer) = &self.results {
            writer.emit_values(records);
        }
        Ok(())
    }

    fn error(&mut self, message: &str, class: &'static str) {
        if let Some(writer) = &self.results {
            writer.emit_value(serde_json::json!({
                "type": "error",
                "class": class,
                "message": message,
            }));
            self.errors += 1;
        }
    }
}

/// Pass the coordinator's stdout through byte for byte, handing only lines
/// marked with this copy's results token to `relay`.
fn relay_stdout(stdout: impl std::io::Read, mut relay: Relay) -> Result<Relay> {
    let mut output_error = None;
    let result = relay_output(
        stdout,
        &mut std::io::stdout().lock(),
        &mut output_error,
        &mut relay,
    );
    // Report only after releasing stdout.
    if let Some(error) = output_error {
        crate::output::warn_stdout(&error);
    }
    result.map(|()| relay)
}

fn relay_output(
    stdout: impl std::io::Read,
    out: &mut impl Write,
    output_error: &mut Option<std::io::Error>,
    relay: &mut Relay,
) -> Result<()> {
    let prefix_len = relay
        .coordinator_prefix
        .len()
        .max(relay.destination_prefix.len());
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, stdout);
    // A failed human-output sink must not discard results; keep relaying
    // marked lines after the first write error.
    let mut forward = |bytes: &[u8], flush: bool| {
        if output_error.is_none() {
            let result = out
                .write_all(bytes)
                .and_then(|()| if flush { out.flush() } else { Ok(()) });
            if let Err(error) = result {
                *output_error = Some(error);
            }
        }
    };
    // The first bytes of the current line, held only until the prefix
    // decision; then either the marked line being collected or nothing.
    let mut head: Vec<u8> = Vec::with_capacity(prefix_len);
    let mut decided = false;
    let mut capturing: Option<Vec<u8>> = None;
    // The rest of an oversized marked line, which is dropped.
    let mut discarding = false;
    let finish_line = |relay: &mut Relay, mut line: Vec<u8>| {
        while line
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            line.pop();
        }
        relay.line(&line);
    };
    loop {
        let buffer = reader
            .fill_buf()
            .context("read remote coordinator output")?;
        if buffer.is_empty() {
            break;
        }
        let mut consumed = 0;
        while consumed < buffer.len() {
            let chunk = &buffer[consumed..];
            let (segment, ends_line) = match chunk.iter().position(|byte| *byte == b'\n') {
                Some(index) => (&chunk[..=index], true),
                None => (chunk, false),
            };
            consumed += segment.len();
            if !decided {
                head.extend_from_slice(segment);
                if head.len() >= prefix_len || ends_line {
                    decided = true;
                    if relay.marked(&head) {
                        capturing = Some(std::mem::take(&mut head));
                    } else {
                        forward(&head, false);
                    }
                    head.clear();
                }
            } else if let Some(line) = capturing.as_mut() {
                line.extend_from_slice(segment);
            } else if !discarding {
                forward(segment, false);
            }
            if capturing
                .as_ref()
                .is_some_and(|line| line.len() > MAX_RELAYED_LINE_BYTES)
            {
                capturing = None;
                discarding = true;
                relay.failure.get_or_insert_with(|| {
                    anyhow::anyhow!("a relayed results line exceeds {MAX_RELAYED_LINE_BYTES} bytes")
                });
            }
            if ends_line {
                if let Some(line) = capturing.take() {
                    finish_line(relay, line);
                } else if !discarding {
                    forward(&[], true);
                }
                decided = false;
                discarding = false;
            }
        }
        reader.consume(consumed);
    }
    // Output that ended without a newline.
    if !head.is_empty() && !discarding {
        if relay.marked(&head) {
            capturing = Some(std::mem::take(&mut head));
        } else {
            forward(&head, false);
        }
    }
    if let Some(line) = capturing.take() {
        finish_line(relay, line);
    }
    forward(&[], true);
    Ok(())
}

/// The context relayed results settle against.
struct Settlement<'a> {
    src_host: &'a str,
    dst_host: &'a str,
    coordinator_exit_code: i32,
    elapsed_ms: u64,
    verbose: bool,
    quiet: bool,
}

/// Write the run's final result from what the coordinator and, through a
/// restricted receiver, the destination reported. Returns the process exit
/// code the final result advertises, so the two can never disagree.
fn settle(mut relay: Relay, settlement: Settlement<'_>) -> Result<i32> {
    let Settlement {
        src_host,
        dst_host,
        coordinator_exit_code,
        elapsed_ms,
        verbose,
        quiet,
    } = settlement;
    if let Some(error) = relay.failure.take() {
        let message = format!("the results relayed by {src_host} are unusable: {error:#}");
        relay.error(&message, "integrity");
        fail_results(&relay, elapsed_ms);
        bail!(message);
    }
    let Some(reader) = relay.destination.as_mut() else {
        // An ordinary coordinator's own final result is the run's.
        if let Some(writer) = &relay.results {
            match relay.coordinator_terminal.take() {
                Some(terminal) => writer.emit_terminal_value(terminal),
                None => {
                    relay.error(
                        &format!("the coordinating server on {src_host} sent no final result"),
                        "io",
                    );
                    fail_results(&relay, elapsed_ms);
                    bail!("the coordinating server on {src_host} ended without its results");
                }
            }
        }
        return Ok(coordinator_exit_code);
    };
    let totals = match reader.finish() {
        Ok(totals) => totals,
        Err(error) => {
            let message = format!(
                "the results of the command-restricted receiver on {dst_host}, relayed by {src_host}, could not be verified: {error:#}; what landed is unknown"
            );
            relay.error(&message, "integrity");
            fail_results(&relay, elapsed_ms);
            bail!(message);
        }
    };
    let status = if totals.failed > 0 {
        DestinationStatus::Failed
    } else {
        DestinationStatus::Clean
    };
    let outcome = settlement_outcome(status, totals.refused, coordinator_exit_code);
    let settlement_error = if totals.refused > 0 {
        Some(format!(
            "the receiver on {dst_host} refused {} request(s) from {src_host}",
            totals.refused
        ))
    } else if status != DestinationStatus::Clean && coordinator_exit_code == 0 {
        Some(format!(
            "the receiver on {dst_host} reports {} failed change(s), yet {src_host} reported success",
            totals.failed
        ))
    } else {
        None
    };
    debug_assert_eq!(outcome.rejects, settlement_error.is_some());
    if let Some(writer) = &relay.results {
        // The destination listed each refusal and failure with its error
        // record; the complaint itself goes to stderr.
        let terminal = compose_terminal(&relay, &totals, outcome, elapsed_ms);
        // The coordinator's summary was suppressed: render it from the same
        // final result the machine reads, so the two cannot disagree.
        if !quiet && !relay.dry_run {
            print_summary(&terminal);
        }
        writer.emit_terminal_value(terminal);
        // A stream was settled: the process exits with the code it
        // advertises.
        if let Some(message) = settlement_error {
            crate::output::diagnostic!("syq: {message}");
        }
        return Ok(outcome.exit_code);
    }
    if let Some(message) = settlement_error {
        bail!(message);
    }
    if status != DestinationStatus::Clean {
        crate::output::diagnostic!(
            "syq: warning: the receiver on {dst_host} reports {} failed change(s)",
            totals.failed
        );
    }
    if verbose {
        crate::output::diagnostic!(
            "syq: results from {dst_host} verified: {} files transferred ({}), {} dirs created, {} deleted, {} failed",
            totals.files_transferred,
            crate::progress::human(totals.bytes_transferred),
            totals.directories_created,
            totals.deletions_completed,
            totals.failed
        );
    }
    Ok(coordinator_exit_code)
}

/// The run's final result through a restricted receiver: what changed comes
/// from the destination, the rest from the coordinator.
fn compose_terminal(
    relay: &Relay,
    totals: &crate::destination_results::Totals,
    outcome: SettlementOutcome,
    elapsed_ms: u64,
) -> serde_json::Value {
    let mut terminal = relay
        .coordinator_terminal
        .clone()
        .unwrap_or_else(|| empty_terminal(relay, elapsed_ms));
    let object = terminal
        .as_object_mut()
        .expect("a final result is an object");
    object.insert("status".into(), outcome.results_status.into());
    object.insert("exit_code".into(), outcome.exit_code.into());
    object.insert("errors".into(), relay.errors.into());
    // A dry run changes nothing: its plan is the coordinator's.
    if !relay.dry_run {
        for (key, value) in [
            ("files_transferred", totals.files_transferred),
            ("bytes_transferred", totals.bytes_transferred),
            ("directories_created", totals.directories_created),
            ("symlinks_created", totals.symlinks_created),
            ("specials_created", totals.specials_created),
        ] {
            object.insert(key.into(), value.into());
        }
        if object.contains_key("deletions_completed") {
            object.insert(
                "deletions_completed".into(),
                totals.deletions_completed.into(),
            );
        }
    }
    terminal
}

fn print_summary(terminal: &serde_json::Value) {
    let count = |key: &str| terminal.get(key).and_then(serde_json::Value::as_u64);
    let value = |key: &str| count(key).unwrap_or(0);
    let deletions = match (count("deletions_blocked"), count("deletions_completed")) {
        (Some(blocked), _) if blocked > 0 => format!(
            ", {} planned for deletion (blocked)",
            value("deletions_planned")
        ),
        (_, Some(deleted)) => format!(", {deleted} deleted"),
        _ => String::new(),
    };
    let timings = &terminal["timings"];
    let elapsed_ms = timings["transfer_ms"]
        .as_u64()
        .or_else(|| timings["total_ms"].as_u64())
        .unwrap_or(0);
    crate::transfer::print_transfer_summary(
        &crate::results::ResultRecord {
            status: "",
            exit_code: 0,
            dry_run: false,
            files_transferred: value("files_transferred"),
            files_unchanged: value("files_unchanged"),
            files_excluded: value("files_excluded"),
            directories_created: value("directories_created"),
            symlinks_created: value("symlinks_created"),
            specials_created: value("specials_created"),
            errors: value("errors"),
            bytes_transferred: value("bytes_transferred"),
            bytes_unchanged: value("bytes_unchanged"),
            timings: Default::default(),
            deletions_planned: None,
            deletions_completed: None,
            deletions_blocked: None,
            replaced_not_in_place: terminal
                .get("replaced_not_in_place")
                .and_then(serde_json::Value::as_object)
                .map(|counts| {
                    crate::proto::ReplaceReason::ALL
                        .iter()
                        .map(|reason| {
                            let count =
                                counts.get(reason.key()).and_then(serde_json::Value::as_u64);
                            (*reason, count.unwrap_or(0))
                        })
                        .collect()
                }),
        },
        elapsed_ms as f64 / 1000.0,
        &deletions,
    );
}

/// A final result with every count zero, for a run without the
/// coordinator's own.
fn empty_terminal(relay: &Relay, elapsed_ms: u64) -> serde_json::Value {
    let mut terminal = serde_json::json!({
        "type": "result",
        "status": "failed",
        "exit_code": 1,
        "dry_run": relay.dry_run,
        "files_transferred": 0,
        "files_unchanged": 0,
        "files_excluded": 0,
        "directories_created": 0,
        "symlinks_created": 0,
        "specials_created": 0,
        "errors": relay.errors,
        "bytes_transferred": 0,
        "bytes_unchanged": 0,
        "timings": {"total_ms": elapsed_ms},
    });
    if relay.prune {
        let object = terminal
            .as_object_mut()
            .expect("a final result is an object");
        for key in [
            "deletions_planned",
            "deletions_completed",
            "deletions_blocked",
        ] {
            object.insert(key.into(), 0.into());
        }
    }
    terminal
}

/// Settle a stream whose results could not be trusted: a failed final
/// result keeps the counts nothing vouches for at zero.
fn fail_results(relay: &Relay, elapsed_ms: u64) {
    if let Some(writer) = &relay.results {
        writer.emit_terminal_value(empty_terminal(relay, elapsed_ms));
    }
}

#[derive(Clone, Debug)]
enum AgentForwarding {
    Disabled,
    Unrestricted,
    Constrained { ambient: String, broker: String },
}

fn direct_command(
    rsh: &[String],
    user: Option<&str>,
    host: &str,
    port: Option<u16>,
    remote_cmd: &str,
    default_ssh_forward_agent: Option<&AgentForwarding>,
) -> Command {
    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if rsh[0].ends_with("ssh") {
        // Manage agent forwarding only for syq's implicit `ssh`. An explicit
        // -e/--rsh command is a complete user policy and is left unchanged.
        match default_ssh_forward_agent {
            Some(AgentForwarding::Disabled) => {
                cmd.arg("-a");
            }
            Some(AgentForwarding::Unrestricted) => {
                cmd.arg("-A");
            }
            Some(AgentForwarding::Constrained { ambient, broker }) => {
                // Authenticate this local->A connection normally, but expose a
                // different, filtered agent socket on A. Multiplexing must be
                // off or a compromised coordinator could substitute its agent.
                cmd.args([
                    "-o",
                    &format!("IdentityAgent={ambient}"),
                    "-o",
                    &format!("ForwardAgent={broker}"),
                    "-o",
                    "ControlMaster=no",
                    "-o",
                    "ControlPath=none",
                    "-o",
                    "ClearAllForwardings=yes",
                    "-x",
                    "-k",
                    "-T",
                    "-o",
                    "PermitLocalCommand=no",
                ]);
            }
            None => {}
        }
        if let Some(user) = user {
            cmd.args(["-l", user]);
        }
        if let Some(port) = port {
            cmd.args(["-p", &port.to_string()]);
        }
        cmd.arg("--");
    } else if let Some(user) = user {
        cmd.args(["-l", user]);
    }
    cmd.arg(host).arg(remote_cmd);
    cmd
}

/// The SSH command for this machine's connection to the coordinator. When
/// the coordinator gets an entry key, that session asks for no X11
/// forwarding and none of the port forwardings in the user's configuration.
/// It may reuse, or become, syq's master connection to the coordinator
/// (`ControlMaster=auto`), so it leaves alone what belongs to the master's
/// login, such as GSSAPI credential delegation, which later copies sharing
/// the master may rely on.
fn coordinator_rsh(rsh: &[String], entry_key: bool) -> Vec<String> {
    let mut command = rsh.to_vec();
    if entry_key && rsh.first().is_some_and(|program| program.ends_with("ssh")) {
        command.extend(["-x", "-o", "ClearAllForwardings=yes"].map(String::from));
    }
    command
}

fn source_setup_rsh(rsh: &[String], explicit_rsh: bool) -> Vec<String> {
    let mut setup = rsh.to_vec();
    if !explicit_rsh {
        // Probes and helper installation never need delegated credentials.
        setup.push("-a".into());
    }
    setup
}

fn destination_rsh(
    explicit_rsh: Option<&str>,
    same_host: bool,
    agent_forwarding: Option<&AgentForwarding>,
    constrained_rsh: Option<&str>,
) -> Option<String> {
    if same_host {
        return None;
    }
    if let Some(explicit) = explicit_rsh {
        return Some(explicit.to_owned());
    }
    match agent_forwarding {
        // A uses the broker to authenticate to B, but B must never receive it.
        // The generated command ignores A's SSH configuration and identity
        // files, then uses only the selected forwarded socket.
        Some(AgentForwarding::Constrained { .. }) => constrained_rsh.map(str::to_owned),
        // The explicitly selected unrestricted policy forwards the ambient
        // agent, while preventing it from being forwarded another hop.
        Some(AgentForwarding::Unrestricted) => {
            Some("ssh -a -o IdentityAgent=SSH_AUTH_SOCK -o IdentitiesOnly=no".to_owned())
        }
        // With no forwarded agent, preserve hostA's own IdentityAgent and
        // authentication configuration while preventing another forwarding hop.
        Some(AgentForwarding::Disabled) | None => Some("ssh -a".to_owned()),
    }
}

#[derive(Clone, Copy)]
enum DestinationAuthentication {
    Broker,
    Receiver,
}

/// The SSH command a coordinator uses to reach the destination. With the
/// broker it authenticates through the forwarded, filtered agent. With an
/// enrollment it uses the entry key alone, whose file replaces the
/// `IdentityFile=none` placeholder on the coordinator, with no agent, no
/// control socket, no forwarding, no proxy, and only the pinned host keys.
fn constrained_destination_rsh(
    port: u16,
    host_key_algorithms: &str,
    authentication: DestinationAuthentication,
) -> String {
    let (publickey, checking, agent, only) = match authentication {
        DestinationAuthentication::Broker => ("host-bound", "no", "SSH_AUTH_SOCK", "no"),
        DestinationAuthentication::Receiver => ("yes", "yes", "none", "yes"),
    };
    let mut command = vec![
        "ssh".to_owned(),
        "-F".to_owned(),
        "/dev/null".to_owned(),
        "-a".to_owned(),
        "-x".to_owned(),
        "-k".to_owned(),
        "-T".to_owned(),
        "-o".to_owned(),
        format!("IdentityAgent={agent}"),
        "-o".to_owned(),
        format!("IdentitiesOnly={only}"),
        "-o".to_owned(),
        ENTRY_KEY_PLACEHOLDER.to_owned(),
        "-o".to_owned(),
        "CertificateFile=none".to_owned(),
        "-o".to_owned(),
        "PKCS11Provider=none".to_owned(),
        "-o".to_owned(),
        format!("PubkeyAuthentication={publickey}"),
        "-o".to_owned(),
        "PreferredAuthentications=publickey".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "ControlMaster=no".to_owned(),
        "-o".to_owned(),
        "ControlPath=none".to_owned(),
        "-o".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
        "-o".to_owned(),
        "PermitLocalCommand=no".to_owned(),
        "-o".to_owned(),
        "ProxyJump=none".to_owned(),
        "-o".to_owned(),
        "ProxyCommand=none".to_owned(),
        "-o".to_owned(),
        format!("StrictHostKeyChecking={checking}"),
        "-o".to_owned(),
        "LogLevel=ERROR".to_owned(),
        "-o".to_owned(),
        "UserKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        // Like the other server-to-server SSH paths, fail a stalled connect or
        // handshake in bounded time instead of waiting for the TCP timeout.
        "-o".to_owned(),
        "ConnectTimeout=10".to_owned(),
        "-o".to_owned(),
        format!("HostKeyAlgorithms={host_key_algorithms}"),
        "-p".to_owned(),
        port.to_string(),
    ];
    if matches!(authentication, DestinationAuthentication::Receiver) {
        command.extend(["-o".into(), format!("HostKeyAlias={RECEIVER_HOST_ALIAS}")]);
    }
    // An older helper that ignores the supplied host keys has only /dev/null
    // and strict checking, so the restricted copy fails verification.
    shell_words::join(command)
}

pub(crate) const RECEIVER_KNOWN_HOSTS: &str = "SYQ_INTERNAL_NATIVE_RECEIVER_KNOWN_HOSTS";
/// Set when a remote coordinator's input starts with this many bytes of the
/// enrollment's entry key. The key never appears in arguments or the
/// environment.
pub(crate) const ENTRY_KEY_STDIN: &str = "SYQ_INTERNAL_NATIVE_ENTRY_KEY";
/// Set with the entry key: this many bytes of the copy's signed directive
/// follow it on the coordinator's input.
pub(crate) const DIRECTIVE_STDIN: &str = "SYQ_INTERNAL_NATIVE_DIRECTIVE";
const RECEIVER_HOST_ALIAS: &str = "syq-enrolled-receiver";
/// The identity of the coordinator's SSH command to the receiver until the
/// coordinator puts its copy of the entry key there. An SSH command that
/// keeps it has no identity, and fails.
const ENTRY_KEY_PLACEHOLDER: &str = "IdentityFile=none";
/// The longest entry key a coordinator reads: a 16,384-bit RSA key.
const MAX_ENTRY_KEY_BYTES: usize = 16 * 1024;

/// The coordinator's environment for its receiver, and the directive that
/// follows the entry key on its input.
pub(crate) type ReceiverInputs = (Vec<(&'static str, String)>, Option<Vec<u8>>);

/// What the coordinator learns of the receiver from its environment, and
/// the directive it reads from its input after the entry key. An enrolled
/// receiver's entry key and directive never appear in the coordinator's
/// command line or environment, only their lengths do; a copy between two
/// servers that hostX approved passes only its marker.
pub(crate) fn receiver_inputs(
    restricted_grant: Option<&str>,
    entry_key: Option<&[u8]>,
) -> Result<ReceiverInputs> {
    Ok(match (restricted_grant, entry_key) {
        (Some(directive), Some(key)) => {
            let directive = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(directive)
                .context("decode the copy's directive")?;
            (
                vec![
                    (ENTRY_KEY_STDIN, key.len().to_string()),
                    (DIRECTIVE_STDIN, directive.len().to_string()),
                ],
                Some(directive),
            )
        }
        (Some(marker), None) => (
            vec![("SYQ_INTERNAL_NATIVE_RESTRICTED_GRANT", marker.to_owned())],
            None,
        ),
        (None, _) => (Vec::new(), None),
    })
}

/// Materialize the laptop's trusted destination keys and the entry key on
/// the coordinator, in a private temporary directory that lives through all
/// workers; ordinary OpenSSH verifies every connection with them.
pub(crate) fn prepare_receiver_ssh(
    args: &mut Args,
) -> Result<Option<crate::private_broker::SignalCleanedDir>> {
    let entry_key = args
        .entry_key_stdin
        .take()
        .filter(|_| args.delegated)
        .map(|length| read_input("entry key", length, MAX_ENTRY_KEY_BYTES))
        .transpose()?;
    if let Some(key) = &entry_key {
        crate::restricted::parse_entry_key(key)?;
        // The copy's directive follows the key; this coordinator presents
        // it to the receiver as the first frame of its control connection.
        let length = args
            .directive_stdin
            .take()
            .context("an entry key comes with the copy's directive")?;
        let directive = read_input("directive", length, crate::directive::MAX_SIGNED_BYTES)?;
        args.restricted_grant =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(directive.as_slice()));
    }
    let Some(known_hosts) = args.receiver_known_hosts.take() else {
        anyhow::ensure!(
            entry_key.is_none(),
            "an entry key needs the receiver's host keys"
        );
        return Ok(None);
    };
    let entry_key =
        entry_key.context("a restricted receiver's SSH connections need its entry key")?;
    prepare_receiver_ssh_with(args, &known_hosts, &entry_key).map(Some)
}

/// Read `length` bytes of what the requesting syq sends first on this
/// coordinator's input, before any manifest: the entry key, then the
/// directive.
fn read_input(label: &str, length: usize, maximum: usize) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::os::fd::AsFd;
    anyhow::ensure!((1..=maximum).contains(&length), "invalid {label} length");
    // Read exactly these bytes from the descriptor, without buffering any of
    // the input that follows them.
    let mut input = std::fs::File::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .context("take the requesting syq's input")?,
    );
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    input
        .read_exact(&mut bytes)
        .with_context(|| format!("the requesting syq ended before sending the {label}"))?;
    Ok(bytes)
}

fn prepare_receiver_ssh_with(
    args: &mut Args,
    known_hosts: &str,
    entry_key: &[u8],
) -> Result<crate::private_broker::SignalCleanedDir> {
    anyhow::ensure!(
        args.restricted_grant
            .as_deref()
            .is_some_and(crate::restricted::enrolled_grant),
        "receiver host keys require an enrolled copy grant"
    );
    anyhow::ensure!(
        !known_hosts.is_empty() && known_hosts.len() <= 64 * 1024,
        "invalid receiver known-hosts length"
    );
    for line in known_hosts.lines() {
        let key = line
            .strip_prefix(&format!("{RECEIVER_HOST_ALIAS} "))
            .context("invalid receiver known-hosts alias")?;
        ssh_key::PublicKey::from_openssh(key).context("invalid receiver host key")?;
    }
    let mut command = parse_rsh(&args.rsh)?;
    for required in [
        "IdentityAgent=none",
        "IdentitiesOnly=yes",
        "ControlPath=none",
    ] {
        anyhow::ensure!(
            command.iter().any(|argument| argument == required),
            "receiver SSH command is missing {required}"
        );
    }
    // An interrupted copy removes the entry key too; only SIGKILL leaves it.
    let directory = crate::private_broker::SignalCleanedDir::new("syq-receiver-hosts-")?;
    let path = directory.path().join("known_hosts");
    std::fs::write(&path, known_hosts)?;
    crate::agent_broker::validate_openssh_option_path(&path, "receiver known-hosts file")?;
    let key = directory.path().join("entry-key");
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key)
            .context("write the entry key for the receiver's SSH connections")?;
        file.write_all(entry_key)?;
    }
    crate::agent_broker::validate_openssh_option_path(&key, "entry key file")?;
    let known = command
        .iter_mut()
        .find(|argument| *argument == "UserKnownHostsFile=/dev/null")
        .context("receiver SSH command is missing its known-hosts placeholder")?;
    *known = format!("UserKnownHostsFile={}", path.display());
    let identity = command
        .iter_mut()
        .find(|argument| *argument == ENTRY_KEY_PLACEHOLDER)
        .context("receiver SSH command is missing its entry key placeholder")?;
    *identity = format!("IdentityFile={}", key.display());
    args.rsh = Some(shell_words::join(command));
    Ok(directory)
}

// This bounds unauthenticated clients on the invoking machine independently of
// data-worker tuning. SSH authentication channels need not stay open for the
// lifetime of a data worker.
const DEFAULT_BROKER_CONNECTIONS: usize = 129;

fn broker_connection_limit(worker_limit: Option<usize>) -> Result<usize> {
    match worker_limit {
        Some(workers) => workers
            .checked_add(1)
            .context("SSH connection count is too large for the constrained agent broker"),
        None => Ok(DEFAULT_BROKER_CONNECTIONS),
    }
}

fn append_delegated_helper_selection(
    command: &mut Vec<String>,
    syq_path: Option<&str>,
    no_bootstrap: bool,
    restricted_receiver: bool,
) {
    if restricted_receiver {
        return;
    }
    if no_bootstrap {
        command.push("--no-bootstrap".into());
    }
    if let Some(path) = syq_path {
        command.push(format!("--syq-path={path}"));
    }
}

/// Encode a delegated path operand: standard unpadded base64 of the raw
/// bytes, decoded by the remote coordinator's --delegated-operands-b64
/// handling, so any filename survives the remote shell.
fn delegated_operand(path: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(path)
}

pub(crate) fn endpoint_arg(
    location: &Location,
    login_user: Option<&str>,
    connection_host: Option<&str>,
) -> String {
    let host =
        connection_host.unwrap_or_else(|| location.host.as_deref().expect("remote endpoint"));
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let endpoint = match login_user.or(location.user.as_deref()) {
        Some(user) => format!("{user}@{host}"),
        None => host,
    };
    match location.port {
        Some(port) => format!("{endpoint}:{port}"),
        None => endpoint,
    }
}

fn endpoint_display(location: &Location) -> String {
    endpoint_arg(location, None, None)
}

fn native_placement_arg(args: &Args) -> Result<&'static str> {
    Ok(match (args.placement, args.target_existence) {
        (Placement::Into, Existence::Any) => "--into",
        (Placement::Into, Existence::New) => "--into-new",
        (Placement::Into, Existence::Existing) => "--into-existing",
        (Placement::As, Existence::Any) => "--as",
        (Placement::As, Existence::New) => "--as-new",
        (Placement::As, Existence::Existing) => "--as-existing",
        (Placement::Rsync, _) => bail!("native transfer is missing explicit placement"),
    })
}

fn detached_launcher_command(
    remote_command: &str,
    name: &str,
    readiness_attempts: u32,
    termination_attempts: u32,
) -> String {
    format!(
        "mkdir -p \"$HOME/.syq\" && [ -x /bin/kill ] || {{ echo 'syq: detached launch requires /bin/kill for process-group cleanup' >&2; exit 1; }}; if command -v setsid >/dev/null 2>&1; then new_session() {{ exec setsid \"$@\"; }}; elif command -v perl >/dev/null 2>&1; then new_session() {{ exec perl -MPOSIX -e 'POSIX::setsid() or die \"setsid: $!\\n\"; exec {{ $ARGV[0] }} @ARGV or die \"exec: $!\\n\"' -- \"$@\"; }}; else echo 'syq: detached launch requires setsid or perl to start a new session' >&2; exit 1; fi; log=\"$HOME/.syq/{name}-$(date +%Y%m%d-%H%M%S)-$$.log\" && ready=\"$log.ready\" && rm -f -- \"$ready\" && {{ terminate_group() {{ /bin/kill -TERM -- \"-$pid\" 2>/dev/null || :; j=0; while /bin/kill -0 -- \"-$pid\" 2>/dev/null && [ \"$j\" -lt {termination_attempts} ]; do j=$((j + 1)); sleep 1; done; if /bin/kill -0 -- \"-$pid\" 2>/dev/null; then /bin/kill -KILL -- \"-$pid\" 2>/dev/null || :; fi; wait \"$pid\" 2>/dev/null || :; j=0; while /bin/kill -0 -- \"-$pid\" 2>/dev/null && [ \"$j\" -lt {termination_attempts} ]; do j=$((j + 1)); sleep 1; done; ! /bin/kill -0 -- \"-$pid\" 2>/dev/null; }}; SYQ_INTERNAL_DETACH_READY=\"$ready\" new_session nohup sh -c {} > \"$log\" 2>&1 < /dev/null & pid=$!; i=0; while [ \"$i\" -lt {readiness_attempts} ]; do if [ -f \"$ready\" ]; then rm -f -- \"$ready\"; echo \"$log\"; exit 0; fi; if ! kill -0 \"$pid\" 2>/dev/null; then wait \"$pid\"; status=$?; cat -- \"$log\" >&2; exit \"$status\"; fi; i=$((i + 1)); sleep 1; done; if ! terminate_group; then rm -f -- \"$ready\"; cat -- \"$log\" >&2; echo 'syq: could not terminate timed-out detached coordinator process group' >&2; exit 1; fi; rm -f -- \"$ready\"; cat -- \"$log\" >&2; echo 'syq: detached coordinator did not become ready within {readiness_attempts} seconds' >&2; exit 1; }}",
        shell_words::quote(remote_command)
    )
}

pub fn run(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    results: Option<std::sync::Arc<crate::results::ResultsWriter>>,
) -> Result<i32> {
    if args.interface == Interface::Rsync {
        bail!("syq rsync does not support remote-to-remote transfers");
    }
    run_remote(args, srcs, dst, false, results)
}

pub fn coordinate_at_dst(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    results: Option<std::sync::Arc<crate::results::ResultsWriter>>,
) -> Result<i32> {
    if args.interface == Interface::Rsync {
        bail!("--coordinate-at dst is available only through native copy syntax");
    }
    if !srcs[0].same_host(dst) && args.rsh.is_none() && args.peer_auth == PeerAuth::Restricted {
        bail!(
            "--coordinate-at dst requires a read-restricted source enrollment, which is not implemented yet; use --peer-auth broker, --peer-auth own-credentials with the coordinator's own credentials for the peer, or an explicit --rsh policy"
        );
    }
    run_remote(args, srcs, dst, true, results)
}

fn run_remote(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    coordinator_at_dst: bool,
    results: Option<std::sync::Arc<crate::results::ResultsWriter>>,
) -> Result<i32> {
    let started = std::time::Instant::now();
    let mut peer_bridge = args
        .peer_bridge
        .as_deref()
        .cloned()
        .map(|selected| selected.prepare(args, srcs, dst))
        .transpose()?;
    let mut coordinator = if coordinator_at_dst { dst } else { &srcs[0] }.clone();
    let mut peer = if coordinator_at_dst { &srcs[0] } else { dst }.clone();
    let rsh = if let Some(bridge) = &peer_bridge {
        coordinator.user = bridge.coordinator.user.clone();
        coordinator.host = Some(bridge.coordinator.host.clone());
        coordinator.port = bridge.coordinator.port;
        peer.user = bridge.peer.user.clone();
        peer.host = Some(bridge.peer.host.clone());
        peer.port = bridge.peer.port;
        bridge.coordinator.rsh.clone()
    } else {
        parse_rsh(&args.rsh)?
    };
    let coordinator = &coordinator;
    let peer = &peer;
    let coordinator_host = coordinator.host.clone().unwrap();
    let same_host = srcs[0].same_host(dst);
    if args.detach && args.rsh.is_none() && !same_host && args.peer_auth != PeerAuth::OwnCredentials
    {
        bail!(
            "--detach needs --peer-auth own-credentials with credentials on {coordinator_host}, or an explicit --rsh policy: a restricted copy and the authentication broker both need this syq to stay attached"
        );
    }

    let mut broker_guard = None;
    let mut entry_key = None;
    let mut receiver_known_hosts = None;
    let mut peer_login_user = None;
    let mut peer_connection_host = None;
    let mut constrained_rsh = None;
    let mut restricted_destination_path = None;
    let mut restricted_grant = None;
    // The restricted destination's results: who signs them and which copy.
    let mut destination_results = None;
    let default_ssh_agent_policy = if let Some(bridge) = &mut peer_bridge {
        restricted_destination_path = Some(bridge.approved.destination.clone());
        restricted_grant = Some(crate::destination::peer_bridge::GRANT.into());
        destination_results = Some(crate::destination_results::Expectation {
            public_key: bridge.approved.results_key.clone(),
            binding: crate::destination_results::Binding {
                enrollment_id: bridge.approved.enrollment,
                request_id: bridge.approved.request,
                grant_digest: bridge.approved.digest,
            },
            secret: bridge
                .recipient_secret
                .take()
                .context("the results recipient key is unavailable")?,
            records: results.is_some(),
        });
        Some(AgentForwarding::Disabled)
    } else if args.rsh.is_some() {
        None
    } else if same_host || args.peer_auth == PeerAuth::OwnCredentials {
        Some(AgentForwarding::Disabled)
    } else if args.peer_auth == PeerAuth::FullAgent {
        Some(AgentForwarding::Unrestricted)
    } else {
        if args.peer_auth == PeerAuth::Broker || coordinator_at_dst {
            crate::conn::require_constrained_openssh(&rsh[0], "on this machine")?;
        }
        let coordinator_policy = crate::agent_broker::resolve_host_policy_at(
            &rsh[0],
            coordinator.user.as_deref(),
            &coordinator_host,
            coordinator.port,
        )?;
        let peer_policy = crate::agent_broker::resolve_host_policy_at(
            &rsh[0],
            peer.user.as_deref(),
            peer.host.as_deref().unwrap(),
            peer.port,
        )?;
        peer_login_user = Some(peer_policy.login_user.clone());
        peer_connection_host = Some(peer_policy.connection_host().to_owned());
        constrained_rsh = Some(constrained_destination_rsh(
            peer_policy.port(),
            &peer_policy.host_key_algorithms(),
            DestinationAuthentication::Broker,
        ));
        // Native new/existing placement forms travel in the signed grant as the
        // root-existence precondition, so they use the receiver like any other
        // form instead of silently keeping only the constrained broker.
        let prepared = (!coordinator_at_dst && args.peer_auth != PeerAuth::Broker)
            .then(|| {
                crate::restricted::prepare_transfer(
                    args,
                    crate::approval_command::current()?,
                    srcs,
                    dst,
                    &coordinator_policy.login_user,
                    &peer_policy.login_user,
                    peer_policy.agent_socket(),
                    !args.dry_run,
                )
            })
            .transpose()
            .context(
                "prepare command-restricted destination enrollment; use --peer-auth broker to explicitly request authentication-only confinement",
            )?;
        if let Some(prepared) = prepared {
            // The coordinator gets the entry key on its input and uses it
            // for every SSH connection to the receiver, so the copy needs
            // nothing more from this machine: no agent is forwarded.
            receiver_known_hosts = Some(peer_policy.known_hosts(RECEIVER_HOST_ALIAS)?);
            constrained_rsh = Some(constrained_destination_rsh(
                peer_policy.port(),
                &peer_policy.host_key_algorithms(),
                DestinationAuthentication::Receiver,
            ));
            restricted_destination_path = Some(prepared.destination);
            restricted_grant = Some(prepared.directive);
            destination_results = Some(crate::destination_results::Expectation {
                public_key: prepared.results_public_key.clone(),
                binding: crate::destination_results::Binding {
                    enrollment_id: prepared.enrollment_id,
                    request_id: prepared.request_id,
                    grant_digest: prepared.digest,
                },
                secret: prepared.recipient_secret,
                records: results.is_some(),
            });
            if !args.quiet {
                crate::output::diagnostic!(
                    "syq: using command-restricted destination enrollment {}",
                    prepared.enrollment_id
                );
            }
            entry_key = Some(zeroize::Zeroizing::new(
                prepared
                    .entry_key
                    .to_openssh(ssh_key::LineEnding::LF)?
                    .as_bytes()
                    .to_vec(),
            ));
            Some(AgentForwarding::Disabled)
        } else {
            let limit = broker_connection_limit(args.connections_opt.or_else(|| {
                args.resource_limits
                    .as_ref()
                    .and_then(|limits| limits.workers)
            }))?;
            let policy = crate::agent_broker::BrokerPolicy::new(coordinator_policy, peer_policy);
            let broker = crate::agent_broker::ConstrainedAgentBroker::start(policy, limit)?;
            let ambient = broker.ambient_socket().to_string_lossy().into_owned();
            let socket = broker.socket_path().to_string_lossy().into_owned();
            broker_guard = Some(broker);
            Some(AgentForwarding::Constrained {
                ambient,
                broker: socket,
            })
        }
    };
    if (args.receiver_max_entries.is_some() || args.receiver_max_bytes.is_some())
        && restricted_grant.is_none()
    {
        bail!(
            "--receiver-max-entries and --receiver-max-bytes address the command-restricted receiver, but this transfer does not use the enrolled receiver"
        );
    }
    let coordinator_target = endpoint_display(coordinator);
    let rsh = coordinator_rsh(&rsh, entry_key.is_some());
    let spec = if let Some(bridge) = &peer_bridge {
        bridge.coordinator.clone()
    } else if matches!(
        default_ssh_agent_policy,
        None | Some(AgentForwarding::Disabled)
    ) {
        // Only this machine selects a persistence domain. A native coordinator
        // can reuse its local master; credential-bound forwarding below remains
        // private to this copy. Never send the scope path to the coordinator.
        let crate::conn::Endpoint::Remote(mut spec) = crate::transfer::endpoint(coordinator, args)?
        else {
            unreachable!()
        };
        spec.rsh = source_setup_rsh(&rsh, args.rsh.is_some());
        spec
    } else {
        crate::conn::RemoteSpec {
            local_process: false,
            user: coordinator.user.clone(),
            host: coordinator_host.clone(),
            port: coordinator.port,
            rsh: source_setup_rsh(&rsh, args.rsh.is_some()),
            syq_path: args.syq_path.clone(),
            bootstrap_helper: args.syq_path.is_none() && !args.no_bootstrap,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet: args.quiet,
            pacing: Default::default(),
            tcp: Default::default(),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        }
    };

    // Rebuild the native command for the remote coordinator. Placement stays
    // explicit rather than being translated into trailing-slash heuristics.
    let mut remote: Vec<String> = vec![match args.interface {
        Interface::Rsync => unreachable!("checked above"),
        Interface::NativeCp => "cp",
        Interface::NativeRm => bail!("native rm cannot be a remote-to-remote transfer"),
        Interface::NativeMap => bail!("syq map runs locally and is never remoted"),
    }
    .into()];
    remote.push("--delegated-operands-b64".into());
    if results.is_some() {
        // The coordinator writes its results for this machine to relay.
        remote.push("--relay-results".into());
        if destination_results.is_some() && !args.dry_run {
            // This machine renders the summary from the final result it
            // composes; the coordinator's own summary could disagree.
            remote.push("--suppress-summary".into());
        }
    }
    let mut short = String::new();
    for (flag, on) in [('n', args.dry_run), ('q', args.quiet)] {
        if on {
            short.push(flag);
        }
    }
    for _ in 0..args.verbose {
        short.push('v');
    }
    if !short.is_empty() {
        remote.push(format!("-{short}"));
    }
    if !args.compress {
        remote.push("--no-compress".into());
    }
    if args.hash_or_copy && !args.checksum {
        remote.push("--hash-or-copy".into());
    }
    if args.checksum {
        if args.hash_algorithm == crate::hashing::HashAlgorithm::Blake3 {
            remote.push("--hash".into());
        } else {
            remote.push(format!(
                "--integrity-checking=compare={}",
                args.hash_algorithm
            ));
        }
    }
    remote.push(format!(
        "--integrity-checking=transfer={}",
        if args.transfer_integrity {
            args.transfer_hash_type.unwrap_or_default().to_string()
        } else {
            "off".into()
        }
    ));
    let mut limits = args.resource_limits.clone().unwrap_or_default();
    // The rsync-compatible --bwlimit also lowers to the native coordinator group.
    limits.bandwidth = args.bwlimit.clone();
    if limits != crate::advanced::ResourceLimits::default() {
        remote.push(format!("--resource-limits={limits}"));
    }

    if let Some(policy) = args.if_exists {
        remote.push(format!("--if-exists={}", policy.as_str()));
    }
    if args.existing {
        remote.push("--only-existing".into());
    }
    if let Some(expression) = &args.where_expression {
        remote.push(format!("--where={expression}"));
    }
    if let Some(expression) = &args.copy_if {
        remote.push(format!("--copy-if={expression}"));
    }
    if args.native_follow {
        remote.push("--follow".into());
    } else {
        if args.native_follow_src {
            remote.push("--follow-src".into());
        }
        if args.native_follow_dst {
            remote.push("--follow-dst".into());
        }
    }
    remote.push(format!("--widen-dirs={}", args.widen_dirs.as_str()));
    if args.prune_before {
        remote.push("--prune-before".into());
    } else if args.delete {
        remote.push("--prune".into());
    }
    if args.in_place_update {
        remote.push("--in-place=update".into());
    } else if args.inplace {
        remote.push("--in-place=new".into());
    }
    for line in &args.ignore_lines {
        remote.push(format!("--ignore={line}"));
    }
    if args.copy_mtime_metadata {
        remote.push("--copy-metadata=mtime".into());
    }
    if args.acls {
        remote.push("--copy-metadata=acls".into());
    }
    if args.xattrs {
        remote.push("--copy-metadata=xattrs".into());
    }
    if args.sparse {
        remote.push("--sparse".into());
    }
    if args.open_noatime || args.atimes > 1 {
        remote.push("--open-noatime".into());
    }
    if args.crtimes {
        remote.push("--copy-metadata=crtimes".into());
    }
    if args.atimes > 0 {
        remote.push("--copy-metadata=atimes".into());
    }

    if args.hardlinks {
        remote.push("--copy-metadata=hardlinks".into());
    }
    if args.perms {
        remote.push("--copy-metadata=permissions".into());
    }
    if args.owner || args.group {
        remote.push("--copy-metadata=ownership".into());
    }
    if args.devices {
        remote.push("--copy-metadata=specials".into());
    }
    if let Some(tuning) = args.tuning_options {
        remote.push(format!("--performance-tuning={tuning}"));
    }
    if let Some(strategy) = args.transfer_strategy {
        remote.push(format!("--transfer-strategy={}", strategy.as_str()));
    }
    if args.stats {
        remote.push("--stats".into());
    }
    if let Some(n) = args.max_delete {
        remote.push(format!("--max-delete={n}"));
    }
    // Helper selection applies to ordinary remote syq processes. The local
    // launcher already used it for this coordinator; an enrolled destination
    // is selected by its forced authorized_keys command instead.
    append_delegated_helper_selection(
        &mut remote,
        args.syq_path.as_deref(),
        args.no_bootstrap,
        destination_results.is_some(),
    );
    if args.no_tcp {
        remote.push("--no-tcp".into());
    }
    if args.no_tcp_encryption {
        remote.push("--no-tcp-encryption".into());
    }
    if let Some(algorithm) = &args.tcp_congestion {
        remote.push(format!("--tcp-congestion={algorithm}"));
    }
    remote.push(format!("--tcp-ports={}", args.tcp_ports));
    // With an entry key, the coordinator reaches the receiver with the entry
    // key alone; otherwise the forwarding policy decides.
    let remote_shell = if entry_key.is_some() {
        constrained_rsh.clone()
    } else {
        destination_rsh(
            args.rsh.as_deref(),
            same_host,
            default_ssh_agent_policy.as_ref(),
            constrained_rsh.as_deref(),
        )
    };
    if let Some(remote_shell) = remote_shell {
        remote.push("--rsh".into());
        remote.push(remote_shell);
    }
    if args.no_progress || args.quiet {
        remote.push("--no-progress".into());
    } else if args.progress {
        remote.push("--progress".into());
    }

    if coordinator_at_dst && !same_host {
        remote.push("--from".into());
        remote.push(endpoint_arg(
            &srcs[0],
            peer_login_user.as_deref(),
            peer_connection_host.as_deref(),
        ));
    }
    if let Some(path) = &args.native_source_root {
        remote.push("--root".into());
        remote.push(delegated_operand(path));
    } else if let Some(path) = &args.native_source_cwd {
        remote.push("--cwd".into());
        remote.push(delegated_operand(path));
    }
    if args.mapping_contents.is_some() {
        remote.push("--mapping=-".into());
    } else {
        for source in srcs {
            remote.push(
                match source.selection {
                    SourceSelection::Contents => "--srcs-in",
                    SourceSelection::File => "--src-non-dir",
                    SourceSelection::Directory => "--src-dir",
                    SourceSelection::Named
                    | SourceSelection::NamedNoFollow
                    | SourceSelection::Rsync => "--src",
                }
                .into(),
            );
            remote.push(delegated_operand(&source.path));
        }
    }
    if !coordinator_at_dst && !same_host {
        remote.push("--to".into());
        remote.push(endpoint_arg(
            peer,
            peer_login_user.as_deref(),
            peer_connection_host.as_deref(),
        ));
    }
    remote.push(native_placement_arg(args)?.into());
    remote.push(delegated_operand(
        restricted_destination_path.as_deref().unwrap_or(&dst.path),
    ));

    if args.detach {
        // Detached: keep a text log without a live progress display.
        remote.retain(|a| a != "--progress" && a != "--no-progress" && !a.starts_with("--width="));
        remote.insert(1, "--no-progress".into());
        remote.insert(1, "-v".into());
    }
    // A detached launcher returns before the background syq execs, so a
    // missing helper could otherwise look like a successful start.  Validate
    // and, in automatic mode, install it before detaching.
    if args.detach {
        drop(spec.connect_with(false, false)?);
    }
    let dbg = if crate::output::debug() {
        "SYQ_DEBUG=1 "
    } else {
        ""
    };
    let mut internal_environment = Vec::new();
    // An attached coordinator ends with this process; see follow_requester.
    // Detached copies outlive it by design, and an approved peer bridge
    // watches its own lifetime channel. A mapping arrives on the same input,
    // so only this exact build, which reads just the manifest, can share it.
    let follow_requester = !args.detach
        && peer_bridge.is_none()
        && (args.mapping_contents.is_none() || spec.runs_this_build());
    if follow_requester {
        internal_environment.push((
            REQUESTER_STDIN,
            args.mapping_contents
                .as_ref()
                .map_or(0, |mapping| mapping.contents.len())
                .to_string(),
        ));
    }
    let (receiver_environment, directive) = receiver_inputs(
        restricted_grant.as_deref(),
        entry_key.as_deref().map(Vec::as_slice),
    )?;
    internal_environment.extend(receiver_environment);
    if let Some(known_hosts) = receiver_known_hosts {
        internal_environment.push((RECEIVER_KNOWN_HOSTS, known_hosts));
    }
    // Results come back as lines on the coordinator's output, marked with a
    // token file names printed there cannot guess.
    let results_token = (results.is_some() || destination_results.is_some())
        .then(crate::destination_results::relay::new_token)
        .transpose()?;
    if let Some(token) = &results_token {
        internal_environment.push((crate::destination_results::relay::TOKEN_ENV, token.clone()));
    }
    #[cfg(debug_assertions)]
    internal_environment.extend(crate::destination_results::test_environment());
    if args.dry_run {
        internal_environment.push((
            "SYQ_INTERNAL_NATIVE_PLAN_SOURCE_HOST",
            coordinator_target.clone(),
        ));
    }
    if !args.no_progress && !args.quiet && std::io::stderr().is_terminal() {
        internal_environment.push((
            "SYQ_INTERNAL_NATIVE_PROGRESS_WIDTH",
            crate::progress::term_width().to_string(),
        ));
    }
    let environment = internal_environment
        .into_iter()
        .map(|(name, value)| format!("{name}={}", shell_words::quote(&value)))
        .collect::<Vec<_>>()
        .join(" ");
    let separator = if environment.is_empty() { "" } else { " " };
    let remote_cmd = format!(
        "{dbg}{environment}{separator}{}",
        spec.program_command(&remote)
    );

    let remote_cmd = if args.detach {
        // Survive the loss of this ssh session: new session, no controlling
        // terminal, everything to a log file. A forwarded agent disappears
        // when the launcher session ends, so hostA needs its own credentials
        // for a detached transfer to hostB.
        // The basename is interpolated into a remote shell command; allow only
        // safe characters so a crafted filename can't inject commands.
        let raw = srcs[0]
            .path
            .strip_suffix(b"/")
            .unwrap_or(&srcs[0].path)
            .rsplit(|byte| *byte == b'/')
            .next()
            .unwrap_or(b"syq");
        let name: String = String::from_utf8_lossy(raw)
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let name = if name.trim_matches('.').is_empty() {
            "syq".to_string()
        } else {
            name
        };
        detached_launcher_command(&remote_cmd, &name, 30, 5)
    } else {
        remote_cmd
    };

    let make_command = || {
        if spec.ssh_multiplexer.is_some() {
            return spec.coordinator_command(&remote_cmd);
        }
        direct_command(
            &rsh,
            coordinator.user.as_deref(),
            &coordinator_host,
            coordinator.port,
            &remote_cmd,
            default_ssh_agent_policy.as_ref(),
        )
    };
    if args.peer_auth == PeerAuth::FullAgent {
        crate::output::diagnostic!(
            "syq: warning: --peer-auth full-agent exposes every capability in your SSH agent to {coordinator_host} for this transfer"
        );
    }
    if args.detach {
        let run = || {
            let mut cmd = make_command();
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            cmd.spawn_guarded()
                .and_then(|child| child.wait_with_output())
                .with_context(|| format!("spawn {:?}", rsh[0]))
        };
        let mut out = run()?;
        if helper_missing(out.status.code(), spec.bootstrap_helper) {
            spec.install_helper()?;
            out = run()?;
        }
        let log = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || log.is_empty() {
            bail!("could not start detached transfer on {coordinator_host}");
        }
        // The handoff is the command's result, not chatter: -q trims it to
        // the bare coordinator and log path rather than suppressing it.
        let handoff = if args.quiet {
            format!("{coordinator_target}:{log}")
        } else {
            format!("syq: started on {coordinator_target}, log {log}")
        };
        crate::output::write_stdout(format_args!("{handoff}")).with_context(|| {
            format!("job started on {coordinator_target}, log {log}, but writing its location to stdout failed")
        })?;
        return Ok(0);
    }
    if !args.quiet {
        crate::output::diagnostic!("syq: remote-to-remote: running on {coordinator_host}");
    }
    let relay = results_token.as_deref().map(|token| {
        Relay::new(
            token,
            results.clone(),
            destination_results.take(),
            (args.dry_run, args.delete),
        )
    });
    let run = |relay: Option<Relay>| {
        if let Some(bridge) = &peer_bridge {
            let mapping = args.mapping_contents.clone();
            return match relay {
                Some(relay) => bridge.run(&remote_cmd, mapping, move |stdout| {
                    relay_stdout(stdout, relay).map(Some)
                }),
                None => bridge.run(&remote_cmd, mapping, |mut stdout| {
                    std::io::copy(&mut stdout, &mut std::io::stdout())?;
                    Ok(None)
                }),
            };
        }
        let mut cmd = make_command();
        cmd.stdin(
            if follow_requester || args.mapping_contents.is_some() || entry_key.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            },
        )
        .stderr(Stdio::inherit());
        if relay.is_some() {
            cmd.stdout(Stdio::piped());
        }
        let mut child = cmd
            .spawn_guarded()
            .with_context(|| format!("spawn {:?}", rsh[0]))?;
        // Read stdout while sending the manifest, including for large manifests
        // and setup errors. Reuse the same bytes if helper bootstrap retries.
        // When the coordinator follows this process, keep its input open
        // after the marker until the coordinator has exited.
        let input = child.stdin.take().map(|mut stdin| {
            let mapping = args.mapping_contents.clone();
            let entry_key = entry_key.clone();
            let directive = directive.clone();
            std::thread::spawn(move || {
                // The entry key and the directive come first; the
                // coordinator reads exactly their lengths before anything
                // else reads its input.
                if let (Some(key), Some(directive)) = (entry_key, directive) {
                    stdin.write_all(&key)?;
                    stdin.write_all(&directive)?;
                }
                if let Some(mapping) = mapping {
                    stdin.write_all(&mapping.contents)?;
                }
                if !follow_requester {
                    return Ok(None);
                }
                // Without the marker the coordinator only stops following;
                // failing to write it must not fail the copy.
                let _ = stdin.write_all(&[REQUESTER_MARKER]);
                Ok::<_, std::io::Error>(Some(stdin))
            })
        });
        let relayed = match (child.stdout.take(), relay) {
            (Some(stdout), Some(relay)) => relay_stdout(stdout, relay).map(Some),
            (_, relay) => Ok(relay),
        };
        let status = child
            .wait()
            .with_context(|| format!("wait for {:?}", rsh[0]))?;
        let written = input
            .map(|writer| {
                writer
                    .join()
                    .map_err(|_| anyhow::anyhow!("coordinator input writer panicked"))
                    .and_then(|written| written.map_err(anyhow::Error::from))
            })
            .transpose();
        if status.success() {
            written.context("send mapping to remote coordinator")?;
        }
        Ok::<_, anyhow::Error>((status, relayed?))
    };
    let (mut status, mut relay) = run(relay)?;
    if peer_bridge.is_none() && helper_missing(status.code(), spec.bootstrap_helper) {
        spec.install_helper()?;
        (status, relay) = run(relay)?;
    }
    // Keep the broker alive until the outer SSH connection and all forwarded
    // channels have closed.
    drop(broker_guard);
    let outcome: Result<i32> = match status.code() {
        Some(0) => Ok(0),
        // 1 (fatal), 23 (some files failed) and 25 (--max-delete refused)
        // pass through: they are defined transfer results, the remote's
        // stderr was inherited so its errors are already printed, and
        // settlement below still writes the results that arrived. Other
        // statuses receive source-host connectivity or
        // constrained-authentication context here, and the caller settles
        // the results as failed.
        Some(c @ (1 | 23 | 25)) => Ok(c),
        Some(c) if peer_bridge.is_some() => Err(anyhow::anyhow!(
            "approved server-to-server copy on {coordinator_host} failed (exit {c}); check the preceding SSH error and reconnect the approved account connection if it closed"
        )),
        Some(c) => {
            if peer_bridge.is_none()
                && args.rsh.is_none()
                && args.peer_auth == PeerAuth::Broker
                && !same_host
            {
                bail!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); constrained authentication permits only {}@{} and requires OpenSSH session-bind/host-bound authentication. Use --peer-auth own-credentials with coordinator-host credentials, or explicitly accept full agent exposure with --peer-auth full-agent", peer_login_user.as_deref().unwrap_or("the peer user"), peer.host.as_deref().unwrap_or("the peer"))
            }
            bail!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); {coordinator_host} may not be able to reach the peer endpoint")
        }
        None => Err(anyhow::anyhow!(
            "remote syq on {coordinator_host} killed by signal"
        )),
    };
    let mut code = outcome?;
    if let Some(relay) = relay {
        code = settle(
            relay,
            Settlement {
                src_host: &coordinator_host,
                dst_host: peer.host.as_deref().unwrap_or("the peer endpoint"),
                coordinator_exit_code: code,
                elapsed_ms: started.elapsed().as_millis() as u64,
                verbose: args.verbose > 0,
                quiet: args.quiet,
            },
        )?;
    }
    Ok(code)
}

fn helper_missing(code: Option<i32>, automatic: bool) -> bool {
    automatic && crate::remote_helper::needs_install(code)
}

/// Set for an attached remote coordinator: its standard input carries this
/// many mapping manifest bytes, then `REQUESTER_MARKER`, then nothing more
/// until the syq that started it ends.
pub(crate) const REQUESTER_STDIN: &str = "SYQ_INTERNAL_NATIVE_REQUESTER_STDIN";
const REQUESTER_MARKER: u8 = b'\n';
/// How long a coordinator whose requester ended waits for SIGTERM to end it.
const REQUESTER_LOSS_KILL_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

/// Stop this remote coordinator when the attached syq that started it ends.
///
/// sshd sends no signal to a command without a terminal when its client goes
/// away, so nothing else would stop the copy. The requesting syq holds this
/// process's standard input open without writing to it. Input ends when
/// that syq exits however it ends, including SIGKILL, or when its SSH
/// connection closes. The coordinator then sends itself SIGTERM, exactly as
/// if it had been interrupted: it does not finish the copy, and its
/// receivers see a lost connection rather than a completed copy.
pub(crate) fn follow_requester(args: &mut Args) -> Result<()> {
    use std::os::fd::{AsFd, AsRawFd};
    let Some(manifest_bytes) = args.requester_stdin.filter(|_| args.delegated) else {
        return Ok(());
    };
    let mut input = std::fs::File::from(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .context("take the requesting syq's input")?,
    );
    // Child processes keep the empty input they had before.
    let null = std::fs::File::open("/dev/null").context("open /dev/null")?;
    if unsafe { libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) } < 0 {
        return Err(std::io::Error::last_os_error()).context("replace standard input");
    }
    if args.native_mapping.as_deref() == Some(b"-".as_slice()) {
        let mut contents = Vec::new();
        (&mut input)
            .take(manifest_bytes)
            .read_to_end(&mut contents)
            .context("--mapping -: read stdin")?;
        anyhow::ensure!(
            contents.len() as u64 == manifest_bytes,
            "--mapping -: the requesting syq ended before sending the whole manifest"
        );
        args.parsed_mapping = Some(std::sync::Arc::new(crate::mapping::read_mapping_manifest(
            contents,
        )?));
    } else {
        anyhow::ensure!(
            manifest_bytes == 0,
            "the requesting syq sent a manifest without --mapping -"
        );
    }
    std::thread::Builder::new()
        .name("requester".into())
        .spawn(move || {
            if wait_for_requester_loss(&mut input) {
                unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
                std::thread::sleep(REQUESTER_LOSS_KILL_AFTER);
                unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
            }
        })
        .context("watch the requesting syq")?;
    Ok(())
}

/// Wait for the end of the requester's input. Returns whether it ended after
/// the marker: input that ends first never came from the requester, as with
/// `ssh -n` or `StdinNull`, so it says nothing about the requester.
fn wait_for_requester_loss(input: &mut impl Read) -> bool {
    let mut marked = false;
    let mut buffer = [0u8; 64];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return marked,
            Ok(_) => marked = true,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return marked,
        }
    }
}

#[cfg(test)]
mod tests;
