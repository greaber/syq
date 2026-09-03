//! Direct remote-to-remote: run the coordinator on the source host so data
//! flows source→destination without passing through this machine.

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
    recipient_secret: Option<crate::receipt_v2::RecipientSecret>,
    policy: Option<crate::receipt_v2::ReceiptPolicyV2>,
    grant_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptSettlementOutcome {
    results_status: &'static str,
    exit_code: i32,
    rejects_receipt: bool,
}

fn receipt_settlement_outcome(
    receipt_status: crate::receipt_v2::ReceiptStatusV2,
    refusals: u64,
    orchestrator_exit_code: i32,
) -> ReceiptSettlementOutcome {
    let rejects_receipt = refusals > 0
        || (receipt_status != crate::receipt_v2::ReceiptStatusV2::Clean
            && orchestrator_exit_code == 0);
    let exit_code = if rejects_receipt {
        1
    } else {
        orchestrator_exit_code
    };
    let results_status = if receipt_status == crate::receipt_v2::ReceiptStatusV2::Incomplete {
        // An incomplete receipt stream can omit operations. Never describe it
        // as safe input for a per-entry retry, even when the coordinator also
        // reported a conventional partial-transfer exit.
        "aborted"
    } else if refusals > 0 || orchestrator_exit_code == 25 {
        "refused"
    } else if exit_code == 0 {
        "success"
    } else {
        "partial"
    };
    ReceiptSettlementOutcome {
        results_status,
        exit_code,
        rejects_receipt,
    }
}

const MAX_RECEIPT_V2_LINE_BYTES: usize = 192 * 1024;
const MAX_RECEIPT_V2_CAPTURE_BYTES: u64 = 640 * 1024 * 1024;

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
        let terminal = crate::receipt_v2::transport_frame_is_end(encoded)?;
        let length = u32::try_from(encoded.len()).context("receipt frame length exceeds u32")?;
        let added = 4u64 + u64::from(length);
        self.bytes = self
            .bytes
            .checked_add(added)
            .context("receipt capture byte count overflow")?;
        if self.bytes > MAX_RECEIPT_V2_CAPTURE_BYTES {
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
    let prefix = crate::receipt_v2::RECEIPT_LINE_PREFIX.as_bytes();
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, stdout);
    let mut out = std::io::stdout().lock();
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
                        out.write_all(&head)
                            .context("relay remote coordinator output")?;
                    }
                    head.clear();
                }
            } else if let Some(payload) = capturing.as_mut() {
                payload.extend_from_slice(segment);
            } else {
                out.write_all(segment)
                    .context("relay remote coordinator output")?;
            }
            if let Some(payload) = capturing.as_mut() {
                if payload.len() > MAX_RECEIPT_V2_LINE_BYTES {
                    bail!("the relayed receipt line exceeds {MAX_RECEIPT_V2_LINE_BYTES} bytes");
                }
            }
            if ends_line {
                if let Some(mut payload) = capturing.take() {
                    store_receipt_line(&mut receipt, finish_capture(&mut payload))?;
                } else {
                    out.flush().context("relay remote coordinator output")?;
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
            out.write_all(&head)
                .context("relay remote coordinator output")?;
        }
    }
    if let Some(mut payload) = capturing.take() {
        store_receipt_line(&mut receipt, finish_capture(&mut payload))?;
    }
    out.flush().context("relay remote coordinator output")?;
    Ok(receipt)
}

fn store_receipt_line(captured: &mut Option<CapturedReceipt>, payload: Vec<u8>) -> Result<()> {
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(payload.trim_ascii())
        .context("decode a receipt frame relayed from the source host")?;
    if captured.is_none() {
        *captured = Some(CapturedReceipt::new()?);
    }
    captured.as_mut().unwrap().push(&encoded)?;
    Ok(())
}

/// Verify hostB's receipt against the grant this machine signed. A missing,
/// unverifiable, or mismatching receipt fails the transfer regardless of
/// what the source-side coordinator reported.
fn settle_receipt(
    expectation: &ReceiptExpectation,
    captured: Option<&mut CapturedReceipt>,
    src_host: &str,
    dst_host: &str,
    orchestrator_exit_code: i32,
    emit_results: bool,
    verbose: bool,
) -> Result<()> {
    let Some(captured) = captured else {
        bail!(
            "the command-restricted receiver on {dst_host} issued no receipt through {src_host}; what landed cannot be verified"
        );
    };
    settle_receipt_v2(
        expectation,
        captured,
        src_host,
        dst_host,
        orchestrator_exit_code,
        emit_results,
        verbose,
    )
}

fn settle_receipt_v2(
    expectation: &ReceiptExpectation,
    captured: &mut CapturedReceipt,
    src_host: &str,
    dst_host: &str,
    orchestrator_exit_code: i32,
    emit_results: bool,
    verbose: bool,
) -> Result<()> {
    if !captured.ended {
        bail!("the receipt relayed through {src_host} has no terminal frame");
    }
    let secret = expectation
        .recipient_secret
        .as_ref()
        .context("the local HPKE receipt key is unavailable")?;
    let policy = expectation
        .policy
        .as_ref()
        .context("the signed receipt policy is unavailable")?;
    if !matches!(
        policy.delivery,
        crate::receipt_v2::ReceiptDeliveryV2::AttachedEncrypted { .. }
    ) {
        bail!("an attached transfer has a detached receipt policy");
    }
    let grant_digest = expectation
        .grant_digest
        .context("the signed grant digest is unavailable")?;
    let frames = captured.frames()?;
    let mut receipt = crate::receipt_v2::open_attached_frames(
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
                crate::receipt_v2::RecordV2::Operation(record)
                    if !matches!(
                        record.disposition,
                        crate::receipt_v2::OperationDispositionV2::Applied
                            | crate::receipt_v2::OperationDispositionV2::Observed
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
                crate::receipt_v2::RecordV2::Refusal(record) => Some(format!(
                    "receiver refusal{}",
                    record
                        .diagnostic
                        .as_deref()
                        .map(|message| format!(": {message}"))
                        .unwrap_or_default()
                )),
                crate::receipt_v2::RecordV2::FinalState(record)
                    if matches!(
                        record.object,
                        crate::receipt_v2::FinalObjectV2::ObservationFailed { .. }
                            | crate::receipt_v2::FinalObjectV2::Present {
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
        orchestrator_exit_code,
    );
    let settlement_error = if terminal.summary.refusals > 0 {
        Some(format!(
            "the receiver on {dst_host} refused {} request(s) from {src_host}; first: {}",
            terminal.summary.refusals,
            first_problem.as_deref().unwrap_or("(no detail recorded)")
        ))
    } else if terminal.status != crate::receipt_v2::ReceiptStatusV2::Clean
        && orchestrator_exit_code == 0
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
    if emit_results {
        crate::receipt_v2::write_automation_results(
            &mut receipt,
            &mut std::io::stdout().lock(),
            outcome.results_status,
            outcome.exit_code,
        )
        .context("write receiver-attested --results stream")?;
    }
    if let Some(message) = settlement_error {
        bail!(message);
    }
    if terminal.status != crate::receipt_v2::ReceiptStatusV2::Clean {
        let message = format!(
            "the receiver on {dst_host} issued a {:?} receipt{}",
            terminal.status,
            first_problem
                .as_deref()
                .map(|problem| format!("; first: {problem}"))
                .unwrap_or_default()
        );
        eprintln!("syq: warning: {message}");
    }
    if verbose {
        eprintln!(
            "syq: encrypted receipt from {dst_host} verified: {} operations, {} final states, {} files published ({}), {} deletions",
            terminal.summary.operations,
            terminal.summary.final_states,
            terminal.summary.published_files,
            crate::progress::human(terminal.summary.published_bytes),
            terminal.summary.deletions
        );
    }
    Ok(())
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

fn utf8_path(path: &[u8], role: &str) -> Result<String> {
    String::from_utf8(path.to_vec())
        .map_err(|_| anyhow::anyhow!("native direct remote-to-remote {role} must be valid UTF-8"))
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
        "mkdir -p \"$HOME/.syq\" && [ -x /bin/kill ] || {{ echo 'syq: detached launch requires /bin/kill for process-group cleanup' >&2; exit 1; }}; log=\"$HOME/.syq/{name}-$(date +%Y%m%d-%H%M%S)-$$.log\" && ready=\"$log.ready\" && rm -f -- \"$ready\" && {{ terminate_group() {{ /bin/kill -TERM -- \"-$pid\" 2>/dev/null || :; j=0; while /bin/kill -0 -- \"-$pid\" 2>/dev/null && [ \"$j\" -lt {termination_attempts} ]; do j=$((j + 1)); sleep 1; done; if /bin/kill -0 -- \"-$pid\" 2>/dev/null; then /bin/kill -KILL -- \"-$pid\" 2>/dev/null || :; fi; wait \"$pid\" 2>/dev/null || :; j=0; while /bin/kill -0 -- \"-$pid\" 2>/dev/null && [ \"$j\" -lt {termination_attempts} ]; do j=$((j + 1)); sleep 1; done; ! /bin/kill -0 -- \"-$pid\" 2>/dev/null; }}; SYQ_INTERNAL_DETACH_READY=\"$ready\" setsid nohup sh -c {} > \"$log\" 2>&1 < /dev/null & pid=$!; i=0; while [ \"$i\" -lt {readiness_attempts} ]; do if [ -f \"$ready\" ]; then rm -f -- \"$ready\"; echo \"$log\"; exit 0; fi; if ! kill -0 \"$pid\" 2>/dev/null; then wait \"$pid\"; status=$?; cat -- \"$log\" >&2; exit \"$status\"; fi; i=$((i + 1)); sleep 1; done; if ! terminate_group; then rm -f -- \"$ready\"; cat -- \"$log\" >&2; echo 'syq: could not terminate timed-out detached coordinator process group' >&2; exit 1; fi; rm -f -- \"$ready\"; cat -- \"$log\" >&2; echo 'syq: detached coordinator did not become ready within {readiness_attempts} seconds' >&2; exit 1; }}",
        shell_words::quote(remote_command)
    )
}

pub fn run(args: &Args, srcs: &[Location], dst: &Location) -> Result<i32> {
    if args.interface == Interface::Rsync {
        bail!("syq rsync does not support remote-to-remote transfers");
    }
    run_remote(args, srcs, dst, false)
}

pub fn coordinate_at_dest(args: &Args, srcs: &[Location], dst: &Location) -> Result<i32> {
    if args.interface == Interface::Rsync {
        bail!("--coordinate-at dest is available only through native copy syntax");
    }
    if !srcs[0].same_host(dst)
        && args.rsh.is_none()
        && !args.no_forward_agent
        && !args.unrestricted_agent_forwarding
        && !args.agent_broker_only
    {
        bail!(
            "--coordinate-at dest requires a read-restricted source enrollment, which is not implemented yet; use --agent-broker-only, --no-forward-agent with destination-host credentials, or an explicit --rsh policy"
        );
    }
    run_remote(args, srcs, dst, true)
}

fn run_remote(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    coordinator_at_destination: bool,
) -> Result<i32> {
    match args.native_results.as_deref() {
        Some(b"-") if args.detach => bail!(
            "--results cannot be used with --detach because the remote result stream would not remain attached"
        ),
        Some(b"-") | None => {}
        Some(_) => bail!(
            "a remote transfer coordinator accepts only --results -; use --coordinate-at local to create a named results file"
        ),
    }
    let rsh = parse_rsh(&args.rsh)?;
    let coordinator = if coordinator_at_destination {
        dst
    } else {
        &srcs[0]
    };
    let peer = if coordinator_at_destination {
        &srcs[0]
    } else {
        dst
    };
    let coordinator_host = coordinator.host.clone().unwrap();
    let same_host = srcs[0].same_host(dst);
    if args.detach && args.rsh.is_none() && !same_host && !args.no_forward_agent {
        bail!(
            "a constrained agent exists only while syq is attached; --detach requires --no-forward-agent and credentials on {coordinator_host}, or an explicit --rsh policy"
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
    } else if same_host || args.no_forward_agent {
        Some(AgentForwarding::Disabled)
    } else if args.unrestricted_agent_forwarding {
        Some(AgentForwarding::Unrestricted)
    } else {
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
        let prepared = (!coordinator_at_destination && !args.agent_broker_only)
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
                "prepare command-restricted destination enrollment; use --agent-broker-only to explicitly request authentication-only confinement",
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
                policy: Some(prepared.receipt_policy),
                grant_digest: Some(prepared.grant_digest),
            });
            if !args.quiet {
                eprintln!(
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
    if (args.max_entries.is_some()
        || args.max_total_bytes.is_some()
        || args.max_runtime_secs.is_some()
        || args.receipt_requested)
        && restricted_grant.is_none()
    {
        bail!(
            "--max-entries, --max-total-bytes, --max-runtime, and --receipt address the command-restricted receiver, but this transfer does not use the enrolled receiver"
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
        auto_helper: args.syq_path.is_none() && !args.no_bootstrap,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: None,
        quiet: args.quiet,
        tcp: Default::default(),
        diagnostics: Default::default(),
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
    if args.native_results.is_some() && receipt_expectation.is_none() {
        // run_remote accepts only stdout above. The outer SSH process inherits
        // stdout, so the NDJSON stream and its terminal record reach the
        // original caller without assigning surprising remote path semantics.
        remote.push("--results".into());
        remote.push("-".into());
    }
    if args.no_bootstrap {
        remote.push("--no-bootstrap".into());
    }
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
    if let Some(path) = &args.syq_path {
        remote.push(format!("--syq-path={path}"));
    }
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

    if coordinator_at_destination && !same_host {
        remote.push("--from".into());
        remote.push(endpoint_arg(
            &srcs[0],
            peer_login_user.as_deref(),
            peer_connection_host.as_deref(),
        ));
    }
    for source in srcs {
        remote.push(
            match source.selection {
                SourceSelection::Contents => "--src-src",
                SourceSelection::File => "--src-file",
                SourceSelection::Directory => "--src-dir",
                SourceSelection::Named
                | SourceSelection::NamedNoFollow
                | SourceSelection::Rsync => "--src",
            }
            .into(),
        );
        remote.push(utf8_path(&source.path, "source path")?);
    }
    if !coordinator_at_destination && !same_host {
        remote.push("--to".into());
        remote.push(endpoint_arg(
            dst,
            peer_login_user.as_deref(),
            peer_connection_host.as_deref(),
        ));
    }
    remote.push(native_placement_arg(args)?.into());
    remote.push(
        restricted_destination_path
            .clone()
            .unwrap_or(utf8_path(&dst.path, "destination path")?),
    );

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
    if args.unrestricted_agent_forwarding {
        eprintln!(
            "syq: warning: --unrestricted-agent-forwarding exposes every capability in your SSH agent to {coordinator_host} for this transfer"
        );
    }
    if args.detach {
        if receipt_expectation.is_some() {
            eprintln!(
                "syq: warning: detached restricted transfer reports only that the job started; its final signed receipt will be plaintext in hostA's log, visible to hostA, and will not be verified on this machine"
            );
        }
        let run = || {
            let mut cmd = make_command();
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            cmd.output().with_context(|| format!("spawn {:?}", rsh[0]))
        };
        let mut out = run()?;
        if helper_missing(out.status.code(), spec.auto_helper) {
            spec.install_helper()?;
            out = run()?;
        }
        let log = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || log.is_empty() {
            bail!("could not start detached transfer on {coordinator_host}");
        }
        // The handoff is the command's result, not chatter: -q trims it to
        // the bare coordinator and log path rather than suppressing it.
        if args.quiet {
            println!("{coordinator_target}:{log}");
        } else {
            println!("syq: started on {coordinator_target}, log {log}");
        }
        return Ok(0);
    }
    if !args.quiet {
        eprintln!("syq: remote-to-remote: running on {coordinator_host}");
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
    if helper_missing(status.code(), spec.auto_helper) {
        spec.install_helper()?;
        (status, receipt_payload) = run()?;
    }
    // Keep the broker alive until the outer SSH connection and all forwarded
    // channels have closed.
    drop(broker_guard);
    let outcome: Result<i32> = match status.code() {
        Some(0) => Ok(0),
        // 23 (some files failed) and 25 (--max-delete refused) pass through:
        // they are transfer results, and the remote's stderr was inherited so
        // its errors are already printed. Other statuses receive source-host
        // connectivity or constrained-authentication context here.
        Some(c @ (23 | 25)) => Ok(c),
        // These arms build Err values rather than bailing: every failure
        // must pass through the held-terminal settlement below.
        Some(c) => {
            if args.rsh.is_none()
                && !args.no_forward_agent
                && !args.unrestricted_agent_forwarding
                && !same_host
            {
                bail!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); constrained authentication permits only {}@{} and requires OpenSSH session-bind/host-bound authentication. Use --no-forward-agent with coordinator-host credentials, or explicitly accept full agent exposure with --unrestricted-agent-forwarding", peer_login_user.as_deref().unwrap_or("the peer user"), peer.host.as_deref().unwrap_or("the peer"))
            }
            bail!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); {coordinator_host} may not be able to reach the peer endpoint")
        }
        None => Err(anyhow::anyhow!(
            "remote syq on {coordinator_host} killed by signal"
        )),
    };
    let code = outcome?;
    if let Some(expectation) = &receipt_expectation {
        settle_receipt(
            expectation,
            receipt_payload.as_mut(),
            &coordinator_host,
            peer.host.as_deref().unwrap_or("the peer endpoint"),
            code,
            args.native_results.is_some(),
            args.verbose > 0,
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

    #[cfg(target_os = "linux")]
    #[test]
    fn detached_timeout_terminates_the_complete_process_group() {
        let directory = tempfile::tempdir().unwrap();
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
        use crate::receipt_v2::ReceiptStatusV2::{Clean, Failed, Incomplete};

        let cases = [
            (Clean, 0, 0, "success", 0, false),
            (Clean, 0, 23, "partial", 23, false),
            (Clean, 0, 25, "refused", 25, false),
            (Failed, 0, 0, "partial", 1, true),
            (Failed, 1, 23, "refused", 1, true),
            (Incomplete, 0, 0, "aborted", 1, true),
            (Incomplete, 0, 23, "aborted", 23, false),
            (Incomplete, 1, 23, "aborted", 1, true),
        ];
        for (receipt_status, refusals, coordinator, status, exit_code, rejects) in cases {
            let outcome = receipt_settlement_outcome(receipt_status, refusals, coordinator);
            assert_eq!(outcome.results_status, status);
            assert_eq!(outcome.exit_code, exit_code);
            assert_eq!(outcome.rejects_receipt, rejects);
        }
    }

    #[test]
    fn receipt_marker_lines_are_decoded_and_spooled() {
        // Marker lines are decoded and spooled as separate bounded frames,
        // not accumulated into one receipt allocation.
        let frames = [
            crate::receipt_v2::TransportFrameV2::Start {
                mode: crate::receipt_v2::TransportModeV2::DetachedSignedPlaintext,
                encapsulated_key: Vec::new(),
            },
            crate::receipt_v2::TransportFrameV2::Chunk {
                sequence: 0,
                payload: b"stream".to_vec(),
            },
            crate::receipt_v2::TransportFrameV2::End {
                sequence: 1,
                payload: b"terminal".to_vec(),
            },
        ]
        .map(|frame| crate::receipt_v2::encode_transport_frame(&frame).unwrap());
        let mut output = Vec::new();
        for frame in &frames {
            output.extend_from_slice(crate::receipt_v2::RECEIPT_LINE_PREFIX.as_bytes());
            output.extend_from_slice(
                base64::engine::general_purpose::STANDARD_NO_PAD
                    .encode(frame)
                    .as_bytes(),
            );
            output.push(b'\n');
        }
        let mut captured = relay_stdout(&output[..]).unwrap().unwrap();
        let captured: Vec<Vec<u8>> = captured.frames().unwrap().map(Result::unwrap).collect();
        assert_eq!(captured, frames);

        assert!(relay_stdout(b"plain\n".as_slice()).unwrap().is_none());
        let mut oversized = crate::receipt_v2::RECEIPT_LINE_PREFIX.as_bytes().to_vec();
        oversized.extend(std::iter::repeat_n(b'A', MAX_RECEIPT_V2_LINE_BYTES));
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
