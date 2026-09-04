//! Remote-to-remote copies: run the coordinator on one of the remote hosts so data
//! flows source→destination without passing through this machine.

use crate::cli::PeerAuth;
use crate::cli::{parse_rsh, Args, Existence, Interface, Location, Placement, SourceSelection};
use crate::delegation::RequestId;
use crate::enrollment::EnrollmentId;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use std::io::{BufRead, IsTerminal, Read, Seek, Write};
use std::process::{Command, Stdio};

/// What the invoking machine expects hostB's receipt to say about itself.
#[derive(Debug)]
struct ReceiptExpectation {
    public_key: String,
    enrollment_id: EnrollmentId,
    request_id: RequestId,
    recipient_secret: Option<crate::receipt::RecipientSecret>,
    policy: crate::receipt::ReceiptPolicy,
    grant_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptSettlementOutcome {
    results_status: &'static str,
    exit_code: i32,
    rejects_receipt: bool,
}

fn receipt_settlement_outcome(
    receipt_status: crate::receipt::ReceiptStatus,
    refusals: u64,
    coordinator_exit_code: i32,
) -> ReceiptSettlementOutcome {
    // The receipt decides whether verification fails the run: a non-clean
    // receipt against a coordinator that claimed success is a contradiction
    // the exit code must surface.
    let rejects_receipt = refusals > 0
        || (receipt_status != crate::receipt::ReceiptStatus::Clean && coordinator_exit_code == 0);
    // Status first, then the exit code the automation contract pairs with
    // it — the two can never disagree.
    let results_status = if receipt_status == crate::receipt::ReceiptStatus::Incomplete {
        // An incomplete receipt stream can omit operations. Never describe it
        // as safe input for a per-entry retry, even when the coordinator also
        // reported a conventional partial-transfer exit.
        "aborted"
    } else if coordinator_exit_code == 1 {
        // A coordinator-fatal run may hold unsettled entries; the attested
        // records still describe what did land.
        "failed"
    } else if refusals > 0 || coordinator_exit_code == 25 {
        "refused"
    } else if receipt_status != crate::receipt::ReceiptStatus::Clean || coordinator_exit_code == 23
    {
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
    ReceiptSettlementOutcome {
        results_status,
        exit_code,
        rejects_receipt,
    }
}

const MAX_RECEIPT_LINE_BYTES: usize = 192 * 1024;
const MAX_RECEIPT_CAPTURE_BYTES: u64 = 640 * 1024 * 1024;

struct CapturedReceipt {
    file: std::fs::File,
    frames: u64,
    bytes: u64,
    ended: bool,
}

impl CapturedReceipt {
    fn new() -> Result<Self> {
        Ok(Self {
            file: tempfile::tempfile().context("create encrypted receipt spool")?,
            frames: 0,
            bytes: 0,
            ended: false,
        })
    }

    fn push(&mut self, encoded: &[u8]) -> Result<()> {
        if self.ended {
            bail!("the relayed receipt contains a frame after its terminal frame");
        }
        let terminal = crate::receipt::receipt_frame_is_end(encoded)?;
        let length = u32::try_from(encoded.len()).context("receipt frame length exceeds u32")?;
        let added = 4u64 + u64::from(length);
        self.bytes = self
            .bytes
            .checked_add(added)
            .context("receipt capture byte count overflow")?;
        if self.bytes > MAX_RECEIPT_CAPTURE_BYTES {
            bail!("the relayed receipt exceeds its local capture limit");
        }
        self.file.write_all(&length.to_be_bytes())?;
        self.file.write_all(encoded)?;
        self.frames += 1;
        self.ended = terminal;
        Ok(())
    }

    fn frames(&mut self) -> Result<CapturedFrames<'_>> {
        self.file.flush()?;
        self.file.seek(std::io::SeekFrom::Start(0))?;
        Ok(CapturedFrames {
            file: &mut self.file,
            remaining: self.frames,
        })
    }
}

struct CapturedFrames<'a> {
    file: &'a mut std::fs::File,
    remaining: u64,
}

impl Iterator for CapturedFrames<'_> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some((|| {
            let mut length = [0u8; 4];
            self.file.read_exact(&mut length)?;
            let mut encoded = vec![0u8; u32::from_be_bytes(length) as usize];
            self.file.read_exact(&mut encoded)?;
            Ok(encoded)
        })())
    }
}

/// Pass the coordinator's stdout through byte for byte, keeping only the
/// receipt marker lines to ourselves. Used only when a receipt is expected;
/// other transfers inherit stdout untouched. Frames are decoded one line
/// at a time and spooled rather than accumulated in memory.
fn relay_stdout(stdout: impl std::io::Read) -> Result<Option<CapturedReceipt>> {
    let mut output_error = None;
    let result = relay_output(stdout, &mut std::io::stdout().lock(), &mut output_error);
    // Report only after releasing stdout, including when receipt parsing fails.
    if let Some(error) = output_error {
        crate::output::warn_stdout(&error);
    }
    result
}

fn relay_output(
    stdout: impl std::io::Read,
    out: &mut impl Write,
    output_error: &mut Option<std::io::Error>,
) -> Result<Option<CapturedReceipt>> {
    let prefix = crate::receipt::RECEIPT_LINE_PREFIX.as_bytes();
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, stdout);
    // A failed human-output sink must not discard the receiver's evidence.
    // Keep draining and validating receipt frames after the first write error.
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
    let mut receipt = None;
    // The first bytes of the current line, held only until the prefix
    // decision; then either the receipt payload being collected or nothing.
    let mut head: Vec<u8> = Vec::with_capacity(prefix.len());
    let mut decided = false;
    let mut capturing: Option<Vec<u8>> = None;
    let finish_capture = |payload: &mut Vec<u8>| {
        while payload
            .last()
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
        {
            payload.pop();
        }
        std::mem::take(payload)
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
                if head.len() >= prefix.len() || ends_line {
                    decided = true;
                    if head.starts_with(prefix) {
                        capturing = Some(head[prefix.len()..].to_vec());
                    } else {
                        forward(&head, false);
                    }
                    head.clear();
                }
            } else if let Some(payload) = capturing.as_mut() {
                payload.extend_from_slice(segment);
            } else {
                forward(segment, false);
            }
            if let Some(payload) = capturing.as_mut() {
                if payload.len() > MAX_RECEIPT_LINE_BYTES {
                    bail!("the relayed receipt line exceeds {MAX_RECEIPT_LINE_BYTES} bytes");
                }
            }
            if ends_line {
                if let Some(mut payload) = capturing.take() {
                    store_receipt_line(&mut receipt, finish_capture(&mut payload))?;
                } else {
                    forward(&[], true);
                }
                decided = false;
            }
        }
        reader.consume(consumed);
    }
    // Output that ended without a newline.
    if !head.is_empty() {
        if head.starts_with(prefix) {
            capturing = Some(head[prefix.len()..].to_vec());
        } else {
            forward(&head, false);
        }
    }
    if let Some(mut payload) = capturing.take() {
        store_receipt_line(&mut receipt, finish_capture(&mut payload))?;
    }
    forward(&[], true);
    Ok(receipt)
}

fn store_receipt_line(captured: &mut Option<CapturedReceipt>, payload: Vec<u8>) -> Result<()> {
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(payload.trim_ascii())
        .context("decode a receipt frame relayed from the source host")?;
    let receipt = match captured {
        Some(receipt) => receipt,
        None => captured.insert(CapturedReceipt::new()?),
    };
    receipt.push(&encoded)
}

/// Verify hostB's receipt against the grant this machine signed. A missing,
/// unverifiable, or mismatching receipt fails the transfer regardless of
/// what the source-side coordinator reported.
/// The context a captured receipt settles against.
struct ReceiptSettlement<'a> {
    src_host: &'a str,
    dst_host: &'a str,
    coordinator_exit_code: i32,
    results: Option<&'a crate::results::ResultsWriter>,
    elapsed_ms: u64,
    verbose: bool,
    quiet: bool,
}

/// Returns the process exit code the settled stream advertises, so the two
/// can never disagree.
fn settle_receipt(
    expectation: &ReceiptExpectation,
    captured: Option<&mut CapturedReceipt>,
    settlement: ReceiptSettlement<'_>,
) -> Result<i32> {
    let Some(captured) = captured else {
        bail!(
            "the command-restricted receiver on {} issued no receipt through {}; what landed cannot be verified",
            settlement.dst_host,
            settlement.src_host
        );
    };
    settle_captured_receipt(expectation, captured, settlement)
}

fn settle_captured_receipt(
    expectation: &ReceiptExpectation,
    captured: &mut CapturedReceipt,
    settlement: ReceiptSettlement<'_>,
) -> Result<i32> {
    let ReceiptSettlement {
        src_host,
        dst_host,
        coordinator_exit_code,
        results,
        elapsed_ms,
        verbose,
        quiet,
    } = settlement;
    if !captured.ended {
        bail!("the receipt relayed through {src_host} has no terminal frame");
    }
    let secret = expectation
        .recipient_secret
        .as_ref()
        .context("the local HPKE receipt key is unavailable")?;
    let policy = &expectation.policy;
    if !matches!(
        policy.delivery,
        crate::receipt::ReceiptDelivery::AttachedEncrypted { .. }
    ) {
        bail!("an attached transfer has a detached receipt policy");
    }
    let grant_digest = expectation
        .grant_digest
        .context("the signed grant digest is unavailable")?;
    let frames = captured.frames()?;
    let mut receipt = crate::receipt::open_attached_frames(
        frames,
        secret,
        &expectation.public_key,
        expectation.enrollment_id,
        expectation.request_id,
        grant_digest,
        policy,
    )
    .with_context(|| format!("decrypt and verify the receipt from {dst_host}"))?;

    let mut first_problem = None;
    receipt.for_each_record(|record| {
        if first_problem.is_none() {
            first_problem = match record {
                crate::receipt::ReceiptRecord::Operation(record)
                    if !matches!(
                        record.disposition,
                        crate::receipt::OperationDisposition::Succeeded
                            | crate::receipt::OperationDisposition::Observed
                    ) =>
                {
                    Some(format!(
                        "{:?} {:?} for scope {} path {:?}{}",
                        record.action,
                        record.disposition,
                        record.scope,
                        String::from_utf8_lossy(&record.path),
                        record
                            .diagnostic
                            .as_deref()
                            .map(|message| format!(": {message}"))
                            .unwrap_or_default()
                    ))
                }
                crate::receipt::ReceiptRecord::Refusal(record) => Some(format!(
                    "receiver refusal{}",
                    record
                        .diagnostic
                        .as_deref()
                        .map(|message| format!(": {message}"))
                        .unwrap_or_default()
                )),
                crate::receipt::ReceiptRecord::FinalState(record)
                    if matches!(
                        record.object,
                        crate::receipt::FinalObject::ObservationFailed { .. }
                            | crate::receipt::FinalObject::Present {
                                observation_error: Some(_),
                                ..
                            }
                    ) =>
                {
                    Some(format!(
                        "final-state observation failed for scope {} path {:?}",
                        record.scope,
                        String::from_utf8_lossy(&record.path)
                    ))
                }
                _ => None,
            };
        }
        Ok(())
    })?;

    let terminal = receipt.terminal.clone();
    let outcome = receipt_settlement_outcome(
        terminal.status,
        terminal.summary.refusals,
        coordinator_exit_code,
    );
    let settlement_error = if terminal.summary.refusals > 0 {
        Some(format!(
            "the receiver on {dst_host} refused {} request(s) from {src_host}; first: {}",
            terminal.summary.refusals,
            first_problem.as_deref().unwrap_or("(no detail recorded)")
        ))
    } else if terminal.status != crate::receipt::ReceiptStatus::Clean && coordinator_exit_code == 0
    {
        Some(format!(
            "the receiver on {dst_host} issued a {:?} receipt{}, yet {src_host} reported success",
            terminal.status,
            first_problem
                .as_deref()
                .map(|problem| format!("; first: {problem}"))
                .unwrap_or_default()
        ))
    } else {
        None
    };
    debug_assert_eq!(outcome.rejects_receipt, settlement_error.is_some());
    if let Some(writer) = results {
        let emitted = crate::receipt::emit_automation_records(
            &mut receipt,
            writer,
            outcome.results_status,
            outcome.exit_code,
            elapsed_ms,
        )
        .context("write receiver-attested --results stream")?;
        // The human summary renders from the same verified terminal the
        // machine just received (the coordinator's own summary was
        // suppressed), so the two can never disagree.
        if !quiet {
            crate::output::human_stdout!(
                "syq: receiver-attested: {} files published ({}), {} deleted, {} error(s); receipt {}; {}",
                terminal.summary.published_files,
                crate::progress::human(terminal.summary.transferred_bytes),
                terminal.summary.deletions,
                emitted.errors,
                crate::receipt::receipt_status_label(terminal.status),
                outcome.results_status,
            );
        }
        // A stream was settled: the process must exit with the code that
        // stream advertises. Verification complaints reach stderr; they do
        // not fork the exit code away from the terminal record.
        if let Some(message) = settlement_error {
            crate::output::diagnostic!("syq: {message}");
        }
        return Ok(outcome.exit_code);
    }
    if let Some(message) = settlement_error {
        bail!(message);
    }
    if terminal.status != crate::receipt::ReceiptStatus::Clean {
        let message = format!(
            "the receiver on {dst_host} issued a {:?} receipt{}",
            terminal.status,
            first_problem
                .as_deref()
                .map(|problem| format!("; first: {problem}"))
                .unwrap_or_default()
        );
        crate::output::diagnostic!("syq: warning: {message}");
    }
    if verbose {
        crate::output::diagnostic!(
            "syq: encrypted receipt from {dst_host} verified: {} operations, {} final states, {} files published ({}), {} deletions",
            terminal.summary.operations,
            terminal.summary.final_states,
            terminal.summary.published_files,
            crate::progress::human(terminal.summary.published_bytes),
            terminal.summary.deletions
        );
    }
    Ok(coordinator_exit_code)
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
        // files, then uses only the forwarded socket with host-bound auth.
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

fn constrained_destination_rsh(port: u16, host_key_algorithms: &str) -> String {
    shell_words::join([
        "ssh".to_owned(),
        "-F".to_owned(),
        "/dev/null".to_owned(),
        "-a".to_owned(),
        "-x".to_owned(),
        "-k".to_owned(),
        "-T".to_owned(),
        "-o".to_owned(),
        "IdentityAgent=SSH_AUTH_SOCK".to_owned(),
        "-o".to_owned(),
        "IdentitiesOnly=no".to_owned(),
        "-o".to_owned(),
        "IdentityFile=none".to_owned(),
        "-o".to_owned(),
        "CertificateFile=none".to_owned(),
        "-o".to_owned(),
        "PKCS11Provider=none".to_owned(),
        "-o".to_owned(),
        "PubkeyAuthentication=host-bound".to_owned(),
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
        "StrictHostKeyChecking=no".to_owned(),
        "-o".to_owned(),
        "LogLevel=ERROR".to_owned(),
        "-o".to_owned(),
        "UserKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "-o".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        "-o".to_owned(),
        format!("HostKeyAlgorithms={host_key_algorithms}"),
        "-p".to_owned(),
        port.to_string(),
    ])
}

fn broker_connection_limit(connections_opt: Option<usize>, connections: usize) -> Result<usize> {
    // A direct transfer keeps one destination control connection open beside
    // its data workers. Automatic tuning may grow beyond the initial worker
    // count, while an explicit -j is a fixed user-selected upper bound.
    let data_connections = if connections_opt.is_some() {
        connections
    } else {
        crate::tune::MAX
    };
    data_connections
        .checked_add(1)
        .context("SSH connection count is too large for the constrained agent broker")
}

fn automatic_enrollment_allowed(dry_run: bool, verify_only: bool) -> bool {
    !(dry_run || verify_only)
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

fn endpoint_arg(
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
    let rsh = parse_rsh(&args.rsh)?;
    let coordinator = if coordinator_at_dst { dst } else { &srcs[0] };
    let peer = if coordinator_at_dst { &srcs[0] } else { dst };
    let coordinator_host = coordinator.host.clone().unwrap();
    let same_host = srcs[0].same_host(dst);
    if args.detach && args.rsh.is_none() && !same_host && args.peer_auth != PeerAuth::OwnCredentials
    {
        bail!(
            "a constrained agent exists only while syq is attached; --detach requires --peer-auth own-credentials and credentials on {coordinator_host}, or an explicit --rsh policy"
        );
    }

    let mut broker_guard = None;
    let mut peer_login_user = None;
    let mut peer_connection_host = None;
    let mut constrained_rsh = None;
    let mut restricted_destination_path = None;
    let mut restricted_grant = None;
    let mut receipt_expectation = None;
    let default_ssh_agent_policy = if args.rsh.is_some() {
        None
    } else if same_host || args.peer_auth == PeerAuth::OwnCredentials {
        Some(AgentForwarding::Disabled)
    } else if args.peer_auth == PeerAuth::FullAgent {
        Some(AgentForwarding::Unrestricted)
    } else {
        crate::conn::require_constrained_openssh(&rsh[0], "on this machine")?;
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
        ));
        // Native new/existing placement forms travel in the signed grant as the
        // root-existence precondition, so they use the receiver like any other
        // form instead of silently keeping only the constrained broker.
        let prepared = (!coordinator_at_dst && args.peer_auth != PeerAuth::Broker)
            .then(|| {
                crate::restricted::prepare_transfer(
                    args,
                    srcs,
                    dst,
                    &coordinator_policy.login_user,
                    &peer_policy.login_user,
                    automatic_enrollment_allowed(args.dry_run, args.verify_only),
                )
            })
            .transpose()
            .context(
                "prepare command-restricted destination enrollment; use --peer-auth broker to explicitly request authentication-only confinement",
            )?;
        let policy = crate::agent_broker::BrokerPolicy::new(coordinator_policy, peer_policy);
        let limit = broker_connection_limit(args.connections_opt, args.connections)?;
        let broker = if let Some(prepared) = prepared {
            restricted_destination_path = Some(prepared.canonical_destination);
            restricted_grant = Some(prepared.grant);
            receipt_expectation = Some(ReceiptExpectation {
                public_key: prepared.receipt_public_key.clone(),
                enrollment_id: prepared.enrollment_id,
                request_id: prepared.request_id,
                recipient_secret: prepared.receipt_recipient_secret,
                policy: prepared.receipt_policy,
                grant_digest: Some(prepared.grant_digest),
            });
            if !args.quiet {
                crate::output::diagnostic!(
                    "syq: using command-restricted destination enrollment {}",
                    prepared.enrollment_id
                );
            }
            crate::agent_broker::ConstrainedAgentBroker::start_with_private_key(
                policy,
                limit,
                prepared.private_key,
            )?
        } else {
            crate::agent_broker::ConstrainedAgentBroker::start(policy, limit)?
        };
        let ambient = broker.ambient_socket().to_string_lossy().into_owned();
        let socket = broker.socket_path().to_string_lossy().into_owned();
        broker_guard = Some(broker);
        Some(AgentForwarding::Constrained {
            ambient,
            broker: socket,
        })
    };
    if (args.receiver_max_entries.is_some()
        || args.receiver_max_bytes.is_some()
        || args.receiver_receipt.is_some())
        && restricted_grant.is_none()
    {
        bail!(
            "--receiver-max-entries, --receiver-max-bytes, and --receiver-receipt address the command-restricted receiver, but this transfer does not use the enrolled receiver"
        );
    }
    let coordinator_target = endpoint_display(coordinator);
    let spec = crate::conn::RemoteSpec {
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
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
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
    if results.is_some() && receipt_expectation.is_some() {
        // The invoking machine renders the summary from the verified
        // attested terminal; the coordinator's own summary would race it
        // and could disagree.
        remote.push("--suppress-summary".into());
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
    if args.checksum {
        remote.push("--hash".into());
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
    if args.delete {
        remote.push("--prune".into());
    }
    if args.inplace {
        remote.push("--inplace".into());
    }
    for line in &args.ignore_lines {
        remote.push(format!("--ignore={line}"));
    }
    if args.perms {
        remote.push("--preserve=permissions".into());
    }
    if args.owner || args.group {
        remote.push("--preserve=ownership".into());
    }
    if args.devices {
        remote.push("--preserve=specials".into());
    }
    if let Some(j) = args.connections_opt {
        remote.push("-j".into());
        remote.push(j.to_string());
    }
    if let Some(maximum) = &args.max_size {
        remote.push(format!("--max-size={maximum}"));
    }
    if let Some(minimum) = &args.min_size {
        remote.push(format!("--min-size={minimum}"));
    }
    if let Some(rate) = &args.bwlimit {
        remote.push(format!("--bwlimit={rate}"));
    }
    if args.stats {
        remote.push("--stats".into());
    }
    if let Some(n) = args.max_delete {
        remote.push(format!("--max-delete={n}"));
    }
    if results.is_some() && receipt_expectation.is_none() {
        // Without a command-restricted receiver there is no verified
        // channel to carry per-operation records home from a remote
        // coordinator; the wrapper turns this into a failed terminal
        // record, so the stream still settles.
        bail!(
            "--results with a direct remote-to-remote copy needs a command-restricted receiver enrollment (its verified receipt is the stream) or --coordinate-at local to route the transfer through this machine"
        );
    }
    // Helper selection applies to ordinary remote syq processes. The local
    // launcher already used it for this coordinator; an enrolled destination
    // is selected by its forced authorized_keys command instead.
    append_delegated_helper_selection(
        &mut remote,
        args.syq_path.as_deref(),
        args.no_bootstrap,
        receipt_expectation.is_some(),
    );
    if args.no_tcp {
        remote.push("--no-tcp".into());
    }
    if args.tcp_plain {
        remote.push("--tcp-plain".into());
    }
    if let Some(algorithm) = &args.tcp_congestion {
        remote.push(format!("--tcp-congestion={algorithm}"));
    }
    remote.push(format!("--tcp-ports={}", args.tcp_ports));
    if let Some(remote_shell) = destination_rsh(
        args.rsh.as_deref(),
        same_host,
        default_ssh_agent_policy.as_ref(),
        constrained_rsh.as_deref(),
    ) {
        remote.push("--rsh".into());
        remote.push(remote_shell);
    }
    if args.progress_json && !args.quiet {
        remote.push("--progress-json".into());
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
    for source in srcs {
        remote.push(
            match source.selection {
                SourceSelection::Contents => "--srcs-in",
                SourceSelection::File => "--src-file",
                SourceSelection::Directory => "--src-dir",
                SourceSelection::Named
                | SourceSelection::NamedNoFollow
                | SourceSelection::Rsync => "--src",
            }
            .into(),
        );
        remote.push(delegated_operand(&source.path));
    }
    if !coordinator_at_dst && !same_host {
        remote.push("--to".into());
        remote.push(endpoint_arg(
            dst,
            peer_login_user.as_deref(),
            peer_connection_host.as_deref(),
        ));
    }
    remote.push(native_placement_arg(args)?.into());
    remote.push(delegated_operand(
        restricted_destination_path.as_deref().unwrap_or(&dst.path),
    ));

    if args.detach {
        // Detached: log JSON progress instead of a live display.
        remote.retain(|a| {
            a != "--progress"
                && a != "--no-progress"
                && a != "--progress-json"
                && !a.starts_with("--width=")
        });
        remote.insert(1, "--no-progress".into());
        remote.insert(1, "--progress-json".into());
        remote.insert(1, "-v".into());
    }
    // A detached launcher returns before the background syq execs, so a
    // missing helper could otherwise look like a successful start.  Validate
    // and, in automatic mode, install it before detaching.
    if args.detach {
        drop(spec.connect_with(false, false)?);
    }
    let dbg = if crate::transfer::debug() {
        "SYQ_DEBUG=1 "
    } else {
        ""
    };
    let mut internal_environment = Vec::new();
    if let Some(grant) = &restricted_grant {
        internal_environment.push(("SYQ_INTERNAL_NATIVE_RESTRICTED_GRANT", grant.clone()));
    }
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
            cmd.output().with_context(|| format!("spawn {:?}", rsh[0]))
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
    let run = || {
        let mut cmd = make_command();
        cmd.stdin(Stdio::null()).stderr(Stdio::inherit());
        if receipt_expectation.is_none() {
            // Nothing to intercept: leave stdout to the terminal or pipe the
            // user gave us, bytes and all.
            let status = cmd
                .status()
                .with_context(|| format!("spawn {:?}", rsh[0]))?;
            return Ok::<_, anyhow::Error>((status, None));
        }
        cmd.stdout(Stdio::piped());
        let mut child = cmd.spawn().with_context(|| format!("spawn {:?}", rsh[0]))?;
        let stdout = child.stdout.take().expect("piped stdout");
        // Always reap the child, even when relaying its output failed.
        let relayed = relay_stdout(stdout);
        let status = child
            .wait()
            .with_context(|| format!("wait for {:?}", rsh[0]))?;
        Ok((status, relayed?))
    };
    let (mut status, mut receipt_payload) = run()?;
    if helper_missing(status.code(), spec.bootstrap_helper) {
        spec.install_helper()?;
        (status, receipt_payload) = run()?;
    }
    // Keep the broker alive until the outer SSH connection and all forwarded
    // channels have closed.
    drop(broker_guard);
    let outcome: Result<i32> = match status.code() {
        Some(0) => Ok(0),
        // 1 (fatal), 23 (some files failed) and 25 (--max-delete refused)
        // pass through: they are defined transfer results, the remote's
        // stderr was inherited so its errors are already printed, and the
        // coordinator requested the receipt before exiting — settlement
        // below still emits the captured attested evidence. Other statuses
        // receive source-host connectivity or constrained-authentication
        // context here.
        Some(c @ (1 | 23 | 25)) => Ok(c),
        // These arms build Err values rather than bailing: every failure
        // must pass through the held-terminal settlement below.
        Some(c) => {
            if args.rsh.is_none()
                && matches!(args.peer_auth, PeerAuth::Restricted | PeerAuth::Broker)
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
    if let Some(expectation) = &receipt_expectation {
        code = settle_receipt(
            expectation,
            receipt_payload.as_mut(),
            ReceiptSettlement {
                src_host: &coordinator_host,
                dst_host: peer.host.as_deref().unwrap_or("the peer endpoint"),
                coordinator_exit_code: code,
                results: results.as_deref(),
                elapsed_ms: started.elapsed().as_millis() as u64,
                verbose: args.verbose > 0,
                quiet: args.quiet,
            },
        )?;
    }
    Ok(code)
}

fn helper_missing(code: Option<i32>, automatic: bool) -> bool {
    automatic
        && matches!(
            code,
            Some(crate::remote_helper::HELPER_MISSING_EXIT)
                | Some(crate::remote_helper::HELPER_NOT_EXECUTABLE_EXIT)
        )
}

#[cfg(test)]
mod tests {
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
    fn broker_capacity_covers_control_and_planned_workers() {
        assert_eq!(broker_connection_limit(None, 8).unwrap(), 65);
        assert_eq!(broker_connection_limit(Some(128), 128).unwrap(), 129);
        assert!(broker_connection_limit(Some(usize::MAX), usize::MAX).is_err());
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
    fn read_only_operations_never_allow_automatic_enrollment() {
        assert!(automatic_enrollment_allowed(false, false));
        assert!(!automatic_enrollment_allowed(true, false));
        assert!(!automatic_enrollment_allowed(false, true));
        assert!(!automatic_enrollment_allowed(true, true));
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
                let writer =
                    crate::results::ResultsWriter::new(Box::new(file.try_clone().unwrap()));
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
}
