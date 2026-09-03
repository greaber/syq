//! Direct remote-to-remote: run the orchestrator on the source host so data
//! flows source→destination without passing through this machine.

use crate::cli::{parse_rsh, Args, Existence, Interface, Location, Placement, SourceSelection};
use crate::delegation::RequestId;
use crate::enrollment::EnrollmentId;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use std::io::{BufRead, IsTerminal};
use std::process::{Command, Stdio};

/// What the invoking machine expects hostB's receipt to say about itself.
#[derive(Clone, Debug)]
struct ReceiptExpectation {
    public_key: String,
    enrollment_id: EnrollmentId,
    request_id: RequestId,
}

/// The receipt envelope is bounded at 64 MiB; allow for base64 and slack.
const MAX_RECEIPT_LINE_BYTES: usize = 96 * 1024 * 1024;

/// A relayed line that may be the stream's terminal `result` record is
/// held back until the receipt settles (serde orders keys, so the type
/// marker sits mid-line and a line must be complete before it can be
/// judged). Terminal records are small; a line that outgrows this bound is
/// spilled straight through, keeping the no-large-buffering property.
const TERMINAL_HOLD_LIMIT: usize = 64 * 1024;
const TERMINAL_MARKER: &[u8] = b"\"type\":\"result\"";

/// What the relay hands back: the receipt payload it captured, and the
/// terminal-shaped line it withheld for receipt settlement.
struct RelayedStream {
    receipt: Option<Vec<u8>>,
    held_terminal: Option<Vec<u8>>,
}

fn looks_like_terminal(line: &[u8]) -> bool {
    line.windows(TERMINAL_MARKER.len())
        .any(|window| window == TERMINAL_MARKER)
}

/// Pass the orchestrator's stdout through byte for byte, keeping only the
/// receipt line to ourselves and holding back the most recent line that
/// looks like a terminal `result` record, so the caller can verify the
/// receipt before releasing it (a terminal claiming success must not reach
/// consumers ahead of a failed verification). Used only when a receipt is
/// expected; other transfers inherit stdout untouched. Returns the last
/// receipt payload and the held line.
fn relay_stdout(stdout: impl std::io::Read) -> Result<RelayedStream> {
    let mut out = std::io::stdout().lock();
    relay_stdout_bounded(stdout, &mut out, MAX_RECEIPT_LINE_BYTES)
}

/// Streams every ordinary line straight through without holding more than
/// one bounded buffer of it, so a hostile orchestrator cannot make this
/// machine buffer an arbitrarily long line; only a receipt line (up to
/// `limit` bytes) and one terminal-shaped line (up to
/// `TERMINAL_HOLD_LIMIT`) are collected.
fn relay_stdout_bounded(
    stdout: impl std::io::Read,
    out: &mut dyn std::io::Write,
    limit: usize,
) -> Result<RelayedStream> {
    let prefix = crate::receipt::RECEIPT_LINE_PREFIX.as_bytes();
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, stdout);
    let mut receipt = None;
    let mut held: Option<Vec<u8>> = None;
    // The first bytes of the current line, held only until the prefix
    // decision; then either the receipt payload being collected or the
    // buffered ordinary line.
    let mut head: Vec<u8> = Vec::with_capacity(prefix.len());
    let mut decided = false;
    let mut capturing: Option<Vec<u8>> = None;
    // The current ordinary line, buffered until its newline so a terminal
    // record can be withheld; once spilled it streams through unbuffered.
    let mut line: Vec<u8> = Vec::new();
    let mut spilled = false;
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
            .context("read remote orchestrator output")?;
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
                        head.clear();
                    } else {
                        line.append(&mut head);
                    }
                }
            } else if let Some(payload) = capturing.as_mut() {
                payload.extend_from_slice(segment);
            } else if spilled {
                out.write_all(segment)
                    .context("relay remote orchestrator output")?;
            } else {
                line.extend_from_slice(segment);
            }
            if !spilled && capturing.is_none() && line.len() > TERMINAL_HOLD_LIMIT {
                // Too big to be a terminal record: release everything in
                // order and stream the rest of this line through.
                if let Some(previous) = held.take() {
                    out.write_all(&previous)
                        .context("relay remote orchestrator output")?;
                }
                out.write_all(&line)
                    .context("relay remote orchestrator output")?;
                line.clear();
                spilled = true;
            }
            if let Some(payload) = capturing.as_mut() {
                if payload.len() > limit {
                    bail!("the relayed receipt line exceeds {limit} bytes");
                }
            }
            if ends_line {
                if let Some(payload) = capturing.as_mut() {
                    receipt = Some(finish_capture(payload));
                    capturing = None;
                } else if spilled {
                    spilled = false;
                    out.flush().context("relay remote orchestrator output")?;
                } else {
                    let complete = std::mem::take(&mut line);
                    if looks_like_terminal(&complete) {
                        if let Some(previous) = held.replace(complete) {
                            out.write_all(&previous)
                                .context("relay remote orchestrator output")?;
                        }
                    } else {
                        if let Some(previous) = held.take() {
                            out.write_all(&previous)
                                .context("relay remote orchestrator output")?;
                        }
                        out.write_all(&complete)
                            .context("relay remote orchestrator output")?;
                        out.flush().context("relay remote orchestrator output")?;
                    }
                }
                decided = false;
            }
        }
        reader.consume(consumed);
    }
    // Output that ended without a newline. An incomplete trailing line
    // cannot be a complete terminal record; release it in order.
    if !head.is_empty() {
        if head.starts_with(prefix) {
            capturing = Some(head[prefix.len()..].to_vec());
        } else {
            line.append(&mut head);
        }
    }
    if let Some(payload) = capturing.as_mut() {
        receipt = Some(finish_capture(payload));
    }
    if !line.is_empty() {
        if let Some(previous) = held.take() {
            out.write_all(&previous)
                .context("relay remote orchestrator output")?;
        }
        out.write_all(&line)
            .context("relay remote orchestrator output")?;
    }
    out.flush().context("relay remote orchestrator output")?;
    Ok(RelayedStream {
        receipt,
        held_terminal: held,
    })
}

/// Forward a line the relay held back for receipt settlement.
fn release_held_line(held: Option<Vec<u8>>) -> Result<()> {
    use std::io::Write;
    if let Some(line) = held {
        let mut out = std::io::stdout().lock();
        out.write_all(&line)
            .context("relay remote orchestrator output")?;
        out.flush().context("relay remote orchestrator output")?;
    }
    Ok(())
}

/// Verify hostB's receipt against the grant this machine signed. A missing,
/// unverifiable, or mismatching receipt fails the transfer regardless of
/// what the source-side orchestrator reported.
fn settle_receipt(
    expectation: &ReceiptExpectation,
    payload: Option<&[u8]>,
    src_host: &str,
    dst_host: &str,
    orchestrator_succeeded: bool,
    verbose: bool,
) -> Result<()> {
    let Some(payload) = payload else {
        bail!(
            "the command-restricted receiver on {dst_host} issued no receipt through {src_host}; what landed cannot be verified"
        );
    };
    let envelope = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(payload.trim_ascii())
        .context("decode the receipt relayed from the source host")?;
    let receipt = crate::receipt::verify(&envelope, &expectation.public_key)
        .with_context(|| format!("verify the receipt from {dst_host}"))?;
    if receipt.enrollment_id != expectation.enrollment_id
        || receipt.request_id != expectation.request_id
    {
        bail!(
            "the receipt from {dst_host} names a different grant than the one this transfer signed"
        );
    }
    if receipt.refused > 0 {
        bail!(
            "the receiver on {dst_host} refused {} request(s) from {src_host}; first: {}",
            receipt.refused,
            receipt
                .refusal_samples
                .first()
                .map(String::as_str)
                .unwrap_or("(no message recorded)")
        );
    }
    if receipt.incomplete_count > 0 {
        let message = format!(
            "{} in-place file(s) on {dst_host} were written but never completed",
            receipt.incomplete_count
        );
        if orchestrator_succeeded {
            bail!("{message}, yet {src_host} reported success");
        }
        eprintln!("syq: warning: {message}");
    }
    if verbose {
        eprintln!(
            "syq: receipt from {dst_host} verified: {} files published ({}), {} deleted, {} hashed, {} entries touched",
            receipt.published_count,
            crate::progress::human(receipt.published_bytes),
            receipt.deleted_count,
            receipt.observed_count,
            receipt.entries
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
                // off or an older master could substitute its forwarded agent.
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
        // The compatibility escape hatch still selects the forwarded ambient
        // agent, but does not require host-bound authentication from OpenSSH
        // versions that predate the constrained broker's 8.9 floor.
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

fn utf8_path(path: &[u8], role: &str, interface: Interface) -> Result<String> {
    String::from_utf8(path.to_vec()).map_err(|_| {
        if interface == Interface::Rsync {
            anyhow::anyhow!(
                "direct remote-to-remote {role} is not valid UTF-8; use --relay so raw path bytes travel in the protocol"
            )
        } else {
            anyhow::anyhow!("native direct remote-to-remote {role} must be valid UTF-8")
        }
    })
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

pub fn run(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    source_operand_count: usize,
) -> Result<i32> {
    run_remote(args, srcs, dst, source_operand_count, false)
}

pub fn run_at_target(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    source_operand_count: usize,
) -> Result<i32> {
    if args.interface == Interface::Rsync {
        bail!("--run-at target is available only through native copy syntax");
    }
    if !srcs[0].same_host(dst)
        && args.rsh.is_none()
        && !args.no_forward_agent
        && !args.unrestricted_agent_forwarding
        && !args.agent_broker_only
    {
        bail!(
            "--run-at target requires a read-restricted source enrollment, which is not implemented yet; use --agent-broker-only, --no-forward-agent with target-host credentials, or an explicit --rsh policy"
        );
    }
    run_remote(args, srcs, dst, source_operand_count, true)
}

fn run_remote(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    source_operand_count: usize,
    coordinator_at_target: bool,
) -> Result<i32> {
    match args.native_results.as_deref() {
        Some(b"-") if args.detach => bail!(
            "--results cannot be used with --detach because the remote result stream would not remain attached"
        ),
        Some(b"-") | None => {}
        Some(_) => bail!(
            "a remote transfer coordinator accepts only --results -; use --run-at local to create a named results file"
        ),
    }
    let rsh = parse_rsh(&args.rsh)?;
    let coordinator = if coordinator_at_target { dst } else { &srcs[0] };
    let peer = if coordinator_at_target { &srcs[0] } else { dst };
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
            false,
        )?;
        let peer_policy = crate::agent_broker::resolve_host_policy_at(
            &rsh[0],
            peer.user.as_deref(),
            peer.host.as_deref().unwrap(),
            peer.port,
            args.agent_broker_only,
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
        let prepared = (!coordinator_at_target && !args.agent_broker_only)
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
    // The follow target must reconnect the way we did: keep an explicit user.
    let coordinator_target = endpoint_display(coordinator);
    let source_target = endpoint_display(&srcs[0]);
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

    // Rebuild the public command for the remote orchestrator. Compatibility
    // runs remain compatibility runs; native placement must not be translated
    // back into destination-existence or trailing-slash heuristics.
    let mut remote: Vec<String> = vec![match args.interface {
        Interface::Rsync => "rsync",
        Interface::NativeCp => "cp",
        Interface::NativeRm => bail!("native rm cannot be a remote-to-remote transfer"),
        Interface::NativeMap => bail!("syq map runs locally and is never remoted"),
    }
    .into()];
    let mut short = String::new();
    let short_flags: Vec<(char, bool)> = if args.interface == Interface::Rsync {
        vec![
            ('a', args.archive),
            ('r', args.recursive && !args.archive),
            ('l', args.links && !args.archive),
            ('p', args.perms && !args.archive),
            ('t', args.times && !args.archive),
            ('g', args.group && !args.archive),
            ('o', args.owner && !args.archive),
            ('D', args.devices && !args.archive),
            ('n', args.dry_run),
            ('q', args.quiet),
            ('c', args.checksum),
        ]
    } else {
        vec![('n', args.dry_run), ('q', args.quiet)]
    };
    for (flag, on) in short_flags {
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
    if args.interface != Interface::Rsync && args.checksum {
        remote.push("--hash".into());
    }
    if args.interface != Interface::Rsync && args.native_follow {
        remote.push("--follow".into());
    }
    if args.interface == Interface::NativeCp && args.delete {
        remote.push("--prune".into());
    }
    if args.inplace {
        remote.push("--inplace".into());
    }
    for line in &args.ignore_lines {
        remote.push(format!("--ignore={line}"));
    }
    if args.interface != Interface::Rsync {
        if args.perms {
            remote.push("--preserve=permissions".into());
        }
        if args.owner || args.group {
            remote.push("--preserve=ownership".into());
        }
        if args.devices {
            remote.push("--preserve=specials".into());
        }
    }
    if let Some(j) = args.connections_opt {
        remote.push("-j".into());
        remote.push(j.to_string());
    }
    if args.interface == Interface::Rsync {
        remote.push(format!("--block-size={}", args.block_size));
        remote.push(format!("--min-split={}", args.min_split));
        if args.verify_only {
            remote.push("--verify-only".into());
        }
        if args.insecure_links {
            remote.push("--insecure-links".into());
        }
        if args.delete {
            remote.push("--delete".into());
        }
        if args.delete_excluded {
            remote.push("--delete-excluded".into());
        }
        if args.update {
            remote.push("--update".into());
        }
        if args.ignore_existing {
            remote.push("--ignore-existing".into());
        }
        if args.existing {
            remote.push("--existing".into());
        }
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
    if args.native_results.is_some() {
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
        remote.push(if args.interface == Interface::Rsync {
            "-e".into()
        } else {
            "--rsh".into()
        });
        remote.push(remote_shell);
    }
    if args.interface == Interface::Rsync {
        if let Some(grant) = &restricted_grant {
            remote.push(format!("--restricted-grant={grant}"));
        }
        if args.dry_run {
            remote.push(format!("--plan-source-host={source_target}"));
        }
        remote.push(format!(
            "--direct-source-operand-count={source_operand_count}"
        ));
        remote.push("--direct-sources-prededuplicated".into());
    }
    if args.progress_json && !args.quiet {
        remote.push("--progress-json".into());
    }
    if args.no_progress || args.quiet {
        remote.push("--no-progress".into());
    } else if args.progress {
        remote.push("--progress".into());
    } else if args.interface == Interface::Rsync && std::io::stderr().is_terminal() {
        remote.push("--progress".into());
        remote.push(format!("--width={}", crate::progress::term_width()));
    }

    if args.interface == Interface::Rsync {
        remote.push("--".into());
        for source in srcs {
            remote.push(utf8_path(&source.path, "source path", args.interface)?);
        }
        let dst_path = restricted_destination_path.clone().unwrap_or(utf8_path(
            &dst.path,
            "target path",
            args.interface,
        )?);
        let dst_arg = if srcs[0].same_host(dst) {
            if dst.path.starts_with(b"/")
                || dst.path == b"~"
                || dst.path.starts_with(b"~/")
                || dst.path.starts_with(b"./")
                || dst.path.starts_with(b"../")
            {
                dst_path
            } else {
                format!("./{dst_path}")
            }
        } else {
            let host = peer_connection_host
                .as_deref()
                .unwrap_or_else(|| dst.host.as_deref().unwrap());
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            match peer_login_user.as_deref().or(dst.user.as_deref()) {
                Some(user) => format!("{user}@{host}:{dst_path}"),
                None => format!("{host}:{dst_path}"),
            }
        };
        remote.push(dst_arg);
    } else {
        if coordinator_at_target && !same_host {
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
            remote.push(utf8_path(&source.path, "source path", args.interface)?);
        }
        if !coordinator_at_target && !srcs[0].same_host(dst) {
            remote.push("--to".into());
            remote.push(endpoint_arg(
                dst,
                peer_login_user.as_deref(),
                peer_connection_host.as_deref(),
            ));
        }
        remote.push(native_placement_arg(args)?.into());
        remote.push(restricted_destination_path.clone().unwrap_or(utf8_path(
            &dst.path,
            "target path",
            args.interface,
        )?));
    }

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
        drop(spec.connect(false)?);
    }
    let dbg = if crate::transfer::debug() {
        "SYQ_DEBUG=1 "
    } else {
        ""
    };
    let mut internal_environment = Vec::new();
    if args.interface != Interface::Rsync {
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
        // the bare follow target rather than suppressing it.
        if args.quiet {
            println!("{coordinator_target}:{log}");
        } else {
            println!("syq: started on {coordinator_target}, log {log}");
            let remote_shell = args
                .rsh
                .as_deref()
                .map(|rsh| format!(" -e {}", shell_words::quote(rsh)))
                .unwrap_or_default();
            println!(
                "syq: follow with:  syq rsync{remote_shell} --follow {coordinator_target}:{log}"
            );
        }
        return Ok(0);
    }
    if !args.quiet {
        if args.interface == Interface::Rsync {
            eprintln!("syq: remote-to-remote: running on {coordinator_host} (use --relay to route data through this machine)");
        } else {
            eprintln!("syq: remote-to-remote: running on {coordinator_host}");
        }
    }
    let run = || {
        let mut cmd = make_command();
        cmd.stdin(Stdio::null()).stderr(Stdio::inherit());
        if receipt_expectation.is_none() && args.native_results.is_none() {
            // Nothing to intercept: leave stdout to the terminal or pipe the
            // user gave us, bytes and all. A results stream is relayed even
            // without a receipt, so its terminal record can be withheld
            // when the coordinator's exit status fails to confirm it.
            let status = cmd
                .status()
                .with_context(|| format!("spawn {:?}", rsh[0]))?;
            return Ok::<_, anyhow::Error>((status, None, None));
        }
        cmd.stdout(Stdio::piped());
        let mut child = cmd.spawn().with_context(|| format!("spawn {:?}", rsh[0]))?;
        let stdout = child.stdout.take().expect("piped stdout");
        // Always reap the child, even when relaying its output failed.
        let relayed = relay_stdout(stdout);
        let status = child
            .wait()
            .with_context(|| format!("wait for {:?}", rsh[0]))?;
        let relayed = relayed?;
        Ok((status, relayed.receipt, relayed.held_terminal))
    };
    let (mut status, mut receipt_payload, mut held_terminal) = run()?;
    if helper_missing(status.code(), spec.auto_helper) {
        release_held_line(held_terminal.take())?;
        spec.install_helper()?;
        (status, receipt_payload, held_terminal) = run()?;
    }
    // Keep the broker alive until the outer SSH connection and all forwarded
    // channels have closed.
    drop(broker_guard);
    let outcome: Result<i32> = match status.code() {
        Some(0) => Ok(0),
        // 23 (some files failed) and 25 (--max-delete refused) pass through:
        // they are transfer results, and the remote's stderr was inherited so
        // its errors are already printed. Exit 1 is also a defined remote
        // result (fatal), but it is indistinguishable from "hostA cannot
        // reach the destination", where the --relay hint below is the useful
        // answer — so 1 keeps the hint. All of this assumes the -e shell
        // relays the remote exit status (ssh does, using 255 for its own
        // transport failures); a custom shell that exits 23/25 itself would
        // be mistaken for the orchestrator.
        Some(c @ (23 | 25)) => Ok(c),
        // These arms build Err values rather than bailing: every failure
        // must pass through the held-terminal settlement below.
        Some(c) => {
            if args.rsh.is_none()
                && !args.no_forward_agent
                && !args.unrestricted_agent_forwarding
                && !same_host
            {
                if args.interface == Interface::Rsync {
                    Err(anyhow::anyhow!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); constrained authentication permits only {}@{} and requires OpenSSH session-bind/host-bound authentication. Retry with --relay, use --no-forward-agent with coordinator-host credentials, or explicitly accept full agent exposure with --unrestricted-agent-forwarding", peer_login_user.as_deref().unwrap_or("the peer user"), peer.host.as_deref().unwrap_or("the peer")))
                } else {
                    Err(anyhow::anyhow!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); constrained authentication permits only {}@{} and requires OpenSSH session-bind/host-bound authentication. Use --no-forward-agent with coordinator-host credentials, or explicitly accept full agent exposure with --unrestricted-agent-forwarding", peer_login_user.as_deref().unwrap_or("the peer user"), peer.host.as_deref().unwrap_or("the peer")))
                }
            } else if args.interface == Interface::Rsync {
                Err(anyhow::anyhow!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); if {coordinator_host} cannot reach the destination, retry with --relay"))
            } else {
                Err(anyhow::anyhow!("remote-to-remote transfer on {coordinator_host} failed (exit {c}); {coordinator_host} may not be able to reach the peer endpoint"))
            }
        }
        None => Err(anyhow::anyhow!(
            "remote syq on {coordinator_host} killed by signal"
        )),
    };
    // A held line that is not actually a terminal record is ordinary
    // output and is always released. A genuine terminal is released only
    // when the coordinator's exit status, the record's own exit_code, and
    // (when expected) the receipt all confirm it — otherwise the stream
    // ends without a terminal record, the documented unknown-outcome
    // signal, rather than with a result the transport or receipt could
    // not vouch for.
    let terminal_exit_code = held_terminal.as_deref().and_then(|line| {
        serde_json::from_slice::<serde_json::Value>(line)
            .ok()
            .filter(|record| record["type"] == "result")
            .map(|record| record["exit_code"].as_i64())
    });
    let code = match outcome {
        Ok(code) => code,
        Err(error) => {
            if terminal_exit_code.is_some() {
                eprintln!(
                    "syq: withholding the relayed terminal record: the coordinator's exit status did not confirm it"
                );
            } else {
                release_held_line(held_terminal)?;
            }
            return Err(error);
        }
    };
    if let Some(expectation) = &receipt_expectation {
        if let Err(error) = settle_receipt(
            expectation,
            receipt_payload.as_deref(),
            &coordinator_host,
            peer.host.as_deref().unwrap_or("the peer endpoint"),
            code == 0,
            args.verbose > 0,
        ) {
            if terminal_exit_code.is_some() {
                eprintln!(
                    "syq: withholding the relayed terminal record: the receipt did not verify"
                );
            } else {
                release_held_line(held_terminal)?;
            }
            return Err(error);
        }
    }
    if let Some(advertised) = terminal_exit_code {
        if advertised != Some(i64::from(code)) {
            // Same struct drives both on the coordinator, so any mismatch
            // means corruption or mangling in between.
            eprintln!(
                "syq: withholding the relayed terminal record: it advertises exit code {} but the coordinator exited {code}",
                advertised.map_or_else(|| "none".to_string(), |c| c.to_string())
            );
            bail!("the relayed terminal record disagrees with the coordinator exit status");
        }
    }
    release_held_line(held_terminal)?;
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

/// `syq rsync --follow HOST:LOG`: tail a detached transfer's log, rendering the JSON
/// progress lines as a status line and passing everything else through.
pub fn follow(args: &Args) -> Result<i32> {
    let target = args
        .paths
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: syq rsync --follow HOST:LOGFILE"))?;
    let loc = parse_follow_location(target)?;
    let (Some(host), log) = (&loc.host, &loc.path) else {
        bail!("usage: syq rsync --follow HOST:LOGFILE")
    };
    let log = utf8_path(log, "log path", Interface::Rsync)?;
    let rsh = parse_rsh(&args.rsh)?;
    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if let Some(u) = &loc.user {
        cmd.args(["-l", u]);
    }
    if let Some(port) = loc.port {
        if !rsh[0].ends_with("ssh") {
            bail!("a follow target with an explicit port requires an ssh remote-shell command");
        }
        cmd.args(["-p", &port.to_string()]);
    }
    cmd.arg(host)
        .arg(format!("tail -n +1 -f {}", shell_words::quote(&log)));
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn()?;
    let out = child.stdout.take().unwrap();
    use std::io::BufRead;
    let tty = std::io::stderr().is_terminal();
    let mut last_status = String::new();
    for line in std::io::BufReader::new(out).lines() {
        let line = line?;
        if line.starts_with('{') {
            let get = |k: &str| -> f64 {
                line.split(&format!("\"{k}\":"))
                    .nth(1)
                    .and_then(|r| r.split([',', '}']).next())
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0.0)
            };
            let (done, total, fd, ft, rate, el) = (
                get("bytes_done"),
                get("bytes_total"),
                get("files_done"),
                get("files_total"),
                get("rate"),
                get("elapsed"),
            );
            let pct = if total > 0.0 {
                done / total * 100.0
            } else {
                0.0
            };
            last_status = format!(
                "{} / {}  {pct:>3.0}%  {}/s  files {}/{}  elapsed {}",
                crate::progress::human(done as u64),
                crate::progress::human(total as u64),
                crate::progress::human(rate as u64),
                fd as u64,
                ft as u64,
                crate::progress::hms(el)
            );
            if tty {
                eprint!("\r\x1b[K{last_status}");
            }
        } else {
            if tty && !last_status.is_empty() {
                eprint!("\r\x1b[K");
            }
            println!("{line}");
            if line.starts_with("syq: transferred")
                || line.starts_with("syq: would transfer")
                || line.starts_with("  route:")
            {
                let _ = child.kill();
                return Ok(0);
            }
        }
    }
    if tty {
        eprintln!();
    }
    Ok(0)
}

fn parse_follow_location(target: &str) -> Result<Location> {
    if let Some(separator) = target.find(":/") {
        let endpoint = &target[..separator];
        if let Some(endpoint) = crate::cli::parse_native_endpoint(Some(endpoint))? {
            return Ok(Location {
                user: endpoint.user,
                host: Some(endpoint.host),
                port: endpoint.port,
                path: target.as_bytes()[separator + 1..].to_vec(),
                selection: crate::cli::SourceSelection::Rsync,
            });
        }
    }
    Location::parse(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn args(command: &Command) -> Vec<&OsStr> {
        command.get_args().collect()
    }

    #[test]
    fn follow_target_accepts_native_ports_and_ipv6() {
        let location = parse_follow_location("alice@host:2222:/home/alice/run.log").unwrap();
        assert_eq!(location.user.as_deref(), Some("alice"));
        assert_eq!(location.host.as_deref(), Some("host"));
        assert_eq!(location.port, Some(2222));
        assert_eq!(location.path, b"/home/alice/run.log");

        let location = parse_follow_location("[2001:db8::1]:2200:/tmp/run.log").unwrap();
        assert_eq!(location.host.as_deref(), Some("2001:db8::1"));
        assert_eq!(location.port, Some(2200));
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
    fn receipts_are_verified_against_the_signed_grant() {
        let keypair = ssh_key::private::Ed25519Keypair::from_seed(&[5; 32]);
        let key = ssh_key::PrivateKey::new(keypair.into(), "syq-receipt-test").unwrap();
        let enrollment_id = EnrollmentId::random();
        let request_id = RequestId::fresh(1_900_000_000).unwrap();
        let expectation = ReceiptExpectation {
            public_key: key.public_key().to_openssh().unwrap(),
            enrollment_id,
            request_id,
        };
        let mut ledger = crate::receipt::Ledger::default();
        ledger.published.insert(
            b"/dst/a".to_vec(),
            crate::receipt::Published {
                size: 3,
                digest: None,
                complete: true,
            },
        );
        let encode = |ledger: &crate::receipt::Ledger, request_id| {
            let receipt = ledger
                .receipt(enrollment_id, request_id, 1_900_000_000, 1, 3)
                .unwrap();
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(crate::receipt::sign(&receipt, &key).unwrap())
        };
        let settle = |expectation: &ReceiptExpectation, payload: Option<&str>| {
            settle_receipt(
                expectation,
                payload.map(str::as_bytes),
                "host-a",
                "host-b",
                true,
                false,
            )
        };

        let good = encode(&ledger, request_id);
        settle(&expectation, Some(&good)).unwrap();
        assert!(settle(&expectation, None).is_err());
        assert!(settle(&expectation, Some("not a receipt")).is_err());

        // The receipt must name the grant this machine signed.
        let other = encode(&ledger, RequestId::fresh(1_900_000_001).unwrap());
        assert!(settle(&expectation, Some(&other)).is_err());

        // A refused request fails the transfer whatever hostA reported.
        let mut refused = crate::receipt::Ledger::default();
        refused.record_refusal("receiver mutation is outside the signed destination scopes");
        let refused = encode(&refused, request_id);
        assert!(settle(&expectation, Some(&refused)).is_err());

        // An incomplete in-place file contradicts a successful orchestrator
        // but is only a warning beside a failure it already reported.
        let mut partial = crate::receipt::Ledger::default();
        partial.published.insert(
            b"/dst/image".to_vec(),
            crate::receipt::Published {
                size: 9,
                digest: None,
                complete: false,
            },
        );
        let partial = encode(&partial, request_id);
        assert!(settle(&expectation, Some(&partial)).is_err());
        settle_receipt(
            &expectation,
            Some(partial.as_bytes()),
            "host-a",
            "host-b",
            false,
            false,
        )
        .unwrap();

        // And it must verify against the enrollment's key.
        let stranger = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[6; 32]).into(),
            "stranger",
        )
        .unwrap();
        let mismatched = ReceiptExpectation {
            public_key: stranger.public_key().to_openssh().unwrap(),
            ..expectation.clone()
        };
        assert!(settle(&mismatched, Some(&good)).is_err());

        // The relay keeps the receipt line, byte for byte, and passes
        // everything else on, including bytes that are not UTF-8.
        let mut output = b"syq: transferred 1 files\xff\r\n".to_vec();
        output.extend_from_slice(crate::receipt::RECEIPT_LINE_PREFIX.as_bytes());
        output.extend_from_slice(good.as_bytes());
        output.extend_from_slice(b"\r\n");
        let mut relayed = Vec::new();
        let stream =
            relay_stdout_bounded(output.as_slice(), &mut relayed, MAX_RECEIPT_LINE_BYTES).unwrap();
        assert_eq!(stream.receipt.as_deref(), Some(good.as_bytes()));
        assert_eq!(stream.held_terminal, None);
        assert_eq!(relayed, b"syq: transferred 1 files\xff\r\n");
        let mut relayed = Vec::new();
        let stream =
            relay_stdout_bounded(b"plain\n".as_slice(), &mut relayed, MAX_RECEIPT_LINE_BYTES)
                .unwrap();
        assert_eq!(stream.receipt, None);
        assert_eq!(stream.held_terminal, None);
        assert_eq!(relayed, b"plain\n");

        // Ordinary lines stream through however long they are, a receipt
        // line without a trailing newline still counts, and an oversized
        // receipt line is refused instead of buffered.
        let mut long = vec![b'x'; 300 * 1024];
        long.push(b'\n');
        long.extend_from_slice(crate::receipt::RECEIPT_LINE_PREFIX.as_bytes());
        long.extend_from_slice(good.as_bytes());
        let mut relayed = Vec::new();
        let stream = relay_stdout_bounded(long.as_slice(), &mut relayed, 4096).unwrap();
        assert_eq!(stream.receipt.as_deref(), Some(good.as_bytes()));
        assert_eq!(stream.held_terminal, None);
        assert_eq!(relayed.len(), 300 * 1024 + 1);
        let mut oversized = crate::receipt::RECEIPT_LINE_PREFIX.as_bytes().to_vec();
        oversized.extend(std::iter::repeat_n(b'A', 5000));
        oversized.push(b'\n');
        let mut relayed = Vec::new();
        assert!(relay_stdout_bounded(oversized.as_slice(), &mut relayed, 4096).is_err());
    }

    #[test]
    fn relay_holds_back_the_terminal_record() {
        let run = b"{\"schema\":\"syq.automation\",\"seq\":0,\"type\":\"run\"}\n";
        let progress = b"{\"bytes_done\":1,\"seq\":1,\"type\":\"progress\"}\n";
        let result = b"{\"exit_code\":0,\"seq\":2,\"status\":\"success\",\"type\":\"result\"}\n";
        let mut stream = Vec::new();
        stream.extend_from_slice(run);
        stream.extend_from_slice(progress);
        stream.extend_from_slice(result);
        let mut relayed = Vec::new();
        let relayed_stream =
            relay_stdout_bounded(stream.as_slice(), &mut relayed, MAX_RECEIPT_LINE_BYTES).unwrap();
        assert_eq!(relayed_stream.receipt, None);
        // Everything before the terminal streams through; the terminal is
        // withheld for receipt settlement.
        assert_eq!(relayed, [run.as_slice(), progress.as_slice()].concat());
        assert_eq!(
            relayed_stream.held_terminal.as_deref(),
            Some(result.as_slice())
        );

        // A non-terminal line containing the raw marker (impossible in
        // valid JSON, where inner quotes are escaped) is briefly held, then
        // released in order as soon as a later line completes; the real
        // terminal stays held.
        let error = b"noise \"type\":\"result\" noise\n";
        let mut stream = Vec::new();
        stream.extend_from_slice(error);
        stream.extend_from_slice(progress);
        stream.extend_from_slice(result);
        let mut relayed = Vec::new();
        let relayed_stream =
            relay_stdout_bounded(stream.as_slice(), &mut relayed, MAX_RECEIPT_LINE_BYTES).unwrap();
        assert_eq!(relayed, [error.as_slice(), progress.as_slice()].concat());
        assert_eq!(
            relayed_stream.held_terminal.as_deref(),
            Some(result.as_slice())
        );

        // A trailing partial line cannot be the terminal record: the held
        // line and the partial are both released, in order.
        let mut stream = Vec::new();
        stream.extend_from_slice(result);
        stream.extend_from_slice(b"partial");
        let mut relayed = Vec::new();
        let relayed_stream =
            relay_stdout_bounded(stream.as_slice(), &mut relayed, MAX_RECEIPT_LINE_BYTES).unwrap();
        assert_eq!(relayed_stream.held_terminal, None);
        assert_eq!(relayed, [result.as_slice(), b"partial".as_slice()].concat());
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
