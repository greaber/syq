//! Direct remote-to-remote: run the orchestrator on the source host so data
//! flows source→destination without passing through this machine.

use crate::cli::{parse_rsh, Args, Existence, Interface, Location, Placement, SourceSelection};
use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::process::{Command, Stdio};

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
            Some("ssh -a -o IdentityAgent=SSH_AUTH_SOCK -o IdentitiesOnly=no".into())
        }
        // With no forwarded agent, preserve hostA's own IdentityAgent and
        // authentication configuration while preventing another forwarding hop.
        Some(AgentForwarding::Disabled) | None => Some("ssh -a".into()),
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
    String::from_utf8(path.to_vec()).map_err(|_| {
        anyhow::anyhow!(
            "direct remote-to-remote {role} is not valid UTF-8; use --relay so raw path bytes travel in the protocol"
        )
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
    match login_user.or(location.user.as_deref()) {
        Some(user) => format!("{user}@{host}"),
        None => host,
    }
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

pub fn run(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    source_operand_count: usize,
) -> Result<i32> {
    let rsh = parse_rsh(&args.rsh)?;
    let src_host = srcs[0].host.clone().unwrap();
    let same_host = srcs[0].same_host(dst);
    if args.detach && args.rsh.is_none() && !same_host && !args.no_forward_agent {
        bail!(
            "a constrained agent exists only while syq is attached; --detach requires --no-forward-agent and credentials on {src_host}, or an explicit --rsh policy"
        );
    }

    let mut broker_guard = None;
    let mut destination_login_user = None;
    let mut destination_connection_host = None;
    let mut constrained_rsh = None;
    let mut restricted_destination_path = None;
    let mut restricted_grant = None;
    let default_ssh_agent_policy = if args.rsh.is_some() {
        None
    } else if same_host || args.no_forward_agent {
        Some(AgentForwarding::Disabled)
    } else if args.unrestricted_agent_forwarding {
        Some(AgentForwarding::Unrestricted)
    } else {
        let source_policy = crate::agent_broker::resolve_host_policy(
            &rsh[0],
            srcs[0].user.as_deref(),
            &src_host,
            false,
        )?;
        let destination_policy = crate::agent_broker::resolve_host_policy(
            &rsh[0],
            dst.user.as_deref(),
            dst.host.as_deref().unwrap(),
            args.agent_broker_only,
        )?;
        destination_login_user = Some(destination_policy.login_user.clone());
        destination_connection_host = Some(destination_policy.connection_host().to_owned());
        constrained_rsh = Some(constrained_destination_rsh(
            destination_policy.port(),
            &destination_policy.host_key_algorithms(),
        ));
        // Native new/existing forms are deliberately only ordinary initial
        // pathname checks. The command-restricted receiver cannot currently
        // represent that lightweight policy, so retain the live constrained
        // broker without preparing a receiver grant for those forms.
        let receiver_grant_allowed =
            args.interface == Interface::Rsync || args.target_existence == Existence::Any;
        let prepared = (!args.agent_broker_only && receiver_grant_allowed)
            .then(|| {
                crate::restricted::prepare_transfer(
                    args,
                    srcs,
                    dst,
                    &source_policy.login_user,
                    &destination_policy.login_user,
                    automatic_enrollment_allowed(args.dry_run, args.verify_only),
                )
            })
            .transpose()
            .context(
                "prepare command-restricted destination enrollment; use --agent-broker-only to explicitly request authentication-only confinement",
            )?;
        let policy = crate::agent_broker::BrokerPolicy::new(source_policy, destination_policy);
        let limit = broker_connection_limit(args.connections_opt, args.connections)?;
        let broker = if let Some(prepared) = prepared {
            restricted_destination_path = Some(prepared.canonical_destination);
            restricted_grant = Some(prepared.grant);
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
    // The follow target must reconnect the way we did: keep an explicit user.
    let src_target = match &srcs[0].user {
        Some(user) => format!("{user}@{src_host}"),
        None => src_host.clone(),
    };
    let spec = crate::conn::RemoteSpec {
        local_process: false,
        user: srcs[0].user.clone(),
        host: src_host.clone(),
        rsh: source_setup_rsh(&rsh, args.rsh.is_some()),
        syq_path: args.syq_path.clone(),
        auto_helper: args.syq_path.is_none() && !args.no_bootstrap,
        restricted_grant: None,
        helper_install: Default::default(),
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
        Interface::NativeCpPrune => "cp-prune",
        Interface::NativeRm => bail!("native rm cannot be a remote-to-remote transfer"),
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
    if args.interface == Interface::Rsync && !args.compress {
        remote.push("--no-compress".into());
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
        if args.inplace {
            remote.push("--inplace".into());
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
        if let Some(m) = &args.max_size {
            remote.push(format!("--max-size={m}"));
        }
        if let Some(m) = &args.min_size {
            remote.push(format!("--min-size={m}"));
        }
        if let Some(path) = &args.checkpoint {
            remote.push(format!("--checkpoint={path}"));
        }
        for line in &args.ignore_lines {
            remote.push(format!("--ignore={line}"));
        }
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
    if args.interface == Interface::Rsync {
        if args.no_bootstrap {
            remote.push("--no-bootstrap".into());
        }
        if args.no_tcp {
            remote.push("--no-tcp".into());
        }
        if args.tcp_plain {
            remote.push("--tcp-plain".into());
        }
        if let Some(grant) = &restricted_grant {
            remote.push(format!("--restricted-grant={grant}"));
        }
        if let Some(algorithm) = &args.tcp_congestion {
            remote.push(format!("--tcp-congestion={algorithm}"));
        }
        remote.push(format!("--tcp-ports={}", args.tcp_ports));
        if args.dry_run {
            remote.push(format!("--plan-source-host={src_target}"));
        }
        remote.push(format!(
            "--direct-source-operand-count={source_operand_count}"
        ));
        remote.push("--direct-sources-prededuplicated".into());
        if let Some(p) = &args.syq_path {
            remote.push(format!("--syq-path={p}"));
        }
        if let Some(e) = destination_rsh(
            args.rsh.as_deref(),
            same_host,
            default_ssh_agent_policy.as_ref(),
            constrained_rsh.as_deref(),
        ) {
            remote.push("-e".into());
            remote.push(e);
        }
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
            remote.push(utf8_path(&source.path, "source path")?);
        }
        let dst_path = restricted_destination_path
            .clone()
            .unwrap_or(utf8_path(&dst.path, "target path")?);
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
            let host = destination_connection_host
                .as_deref()
                .unwrap_or_else(|| dst.host.as_deref().unwrap());
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            match destination_login_user.as_deref().or(dst.user.as_deref()) {
                Some(user) => format!("{user}@{host}:{dst_path}"),
                None => format!("{host}:{dst_path}"),
            }
        };
        remote.push(dst_arg);
    } else {
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
        if !srcs[0].same_host(dst) {
            remote.push("--to".into());
            remote.push(endpoint_arg(
                dst,
                destination_login_user.as_deref(),
                destination_connection_host.as_deref(),
            ));
        }
        remote.push(native_placement_arg(args)?.into());
        remote.push(
            restricted_destination_path
                .clone()
                .unwrap_or(utf8_path(&dst.path, "target path")?),
        );
    }

    if args.detach {
        // Detached: log JSON progress instead of a live display.
        remote.retain(|a| a != "--progress" && !a.starts_with("--width="));
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
            internal_environment.push(("SYQ_INTERNAL_NATIVE_PLAN_SOURCE_HOST", src_target.clone()));
        }
        if let Some(rsh) = destination_rsh(
            args.rsh.as_deref(),
            same_host,
            default_ssh_agent_policy.as_ref(),
            constrained_rsh.as_deref(),
        ) {
            internal_environment.push(("SYQ_INTERNAL_NATIVE_RSH", rsh));
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
        format!(
            "mkdir -p \"$HOME/.syq\" && log=\"$HOME/.syq/{name}-$(date +%Y%m%d-%H%M%S).log\" && (setsid nohup sh -c {} > \"$log\" 2>&1 < /dev/null &) && echo \"$log\"",
            shell_words::quote(&remote_cmd)
        )
    } else {
        remote_cmd
    };

    let make_command = || {
        direct_command(
            &rsh,
            srcs[0].user.as_deref(),
            &src_host,
            &remote_cmd,
            default_ssh_agent_policy.as_ref(),
        )
    };
    if args.unrestricted_agent_forwarding {
        eprintln!(
            "syq: warning: --unrestricted-agent-forwarding exposes every capability in your SSH agent to {src_host} for this transfer"
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
            bail!("could not start detached transfer on {src_host}");
        }
        // The handoff is the command's result, not chatter: -q trims it to
        // the bare follow target rather than suppressing it.
        if args.quiet {
            println!("{src_target}:{log}");
        } else {
            println!("syq: started on {src_target}, log {log}");
            println!("syq: follow with:  syq rsync --follow {src_target}:{log}");
        }
        return Ok(0);
    }
    if !args.quiet {
        eprintln!("syq: remote-to-remote: running on {src_host} (use --relay to route data through this machine)");
    }
    let run = || {
        let mut cmd = make_command();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        cmd.status().with_context(|| format!("spawn {:?}", rsh[0]))
    };
    let mut status = run()?;
    if helper_missing(status.code(), spec.auto_helper) {
        spec.install_helper()?;
        status = run()?;
    }
    // Keep the broker alive until the outer SSH connection and all forwarded
    // channels have closed.
    drop(broker_guard);
    match status.code() {
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
        Some(c) => {
            if args.rsh.is_none()
                && !args.no_forward_agent
                && !args.unrestricted_agent_forwarding
                && !same_host
            {
                bail!("remote-to-remote transfer on {src_host} failed (exit {c}); constrained authentication permits only {}@{} and requires OpenSSH session-bind/host-bound authentication. Retry with --relay, use --no-forward-agent with source-host credentials, or explicitly accept full agent exposure with --unrestricted-agent-forwarding", destination_login_user.as_deref().unwrap_or("the destination user"), dst.host.as_deref().unwrap_or("the destination"))
            }
            bail!("remote-to-remote transfer on {src_host} failed (exit {c}); if {src_host} cannot reach the destination, retry with --relay")
        }
        None => bail!("remote syq on {src_host} killed by signal"),
    }
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
    let loc = Location::parse(target)?;
    let (Some(host), log) = (&loc.host, &loc.path) else {
        bail!("usage: syq rsync --follow HOST:LOGFILE")
    };
    let log = utf8_path(log, "log path")?;
    let rsh = parse_rsh(&args.rsh)?;
    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if let Some(u) = &loc.user {
        cmd.args(["-l", u]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn args(command: &Command) -> Vec<&OsStr> {
        command.get_args().collect()
    }

    #[test]
    fn default_ssh_controls_agent_forwarding_explicitly() {
        let rsh = vec!["ssh".to_string(), "-p".to_string(), "2222".to_string()];
        let forwarded = direct_command(
            &rsh,
            Some("alice"),
            "source",
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
        let command = direct_command(&rsh, None, "source", "syq ...", Some(&policy));
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
    }

    #[test]
    fn explicit_ssh_does_not_get_agent_flags() {
        let rsh = vec!["ssh".to_string(), "-a".to_string()];
        let command = direct_command(&rsh, None, "source", "syq ...", None);
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
        let command = direct_command(&rsh, None, "source", "syq ...", None);
        let args = args(&command);
        assert!(!args.contains(&OsStr::new("-a")));
        assert!(!args.contains(&OsStr::new("-A")));
    }
}
