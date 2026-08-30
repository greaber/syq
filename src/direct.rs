//! Direct remote-to-remote: run the orchestrator on the source host so data
//! flows source→destination without passing through this machine.

use crate::cli::{parse_rsh, Args, Existence, Interface, Location, Placement, SourceSelection};
use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::process::{Command, Stdio};

fn direct_command(
    rsh: &[String],
    user: Option<&str>,
    host: &str,
    remote_cmd: &str,
    default_ssh_forward_agent: Option<bool>,
) -> Command {
    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if rsh[0].ends_with("ssh") {
        // Manage agent forwarding only for syq's implicit `ssh`. An explicit
        // -e/--rsh command is a complete user policy and is left unchanged.
        if let Some(forward_agent) = default_ssh_forward_agent {
            cmd.arg(if forward_agent { "-A" } else { "-a" });
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

fn utf8_path(path: &[u8]) -> Result<String> {
    String::from_utf8(path.to_vec())
        .map_err(|_| anyhow::anyhow!("direct remote-to-remote paths must be valid UTF-8"))
}

fn endpoint_arg(location: &Location) -> String {
    let host = location.host.as_deref().expect("remote endpoint");
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match &location.user {
        Some(user) => format!("{user}@{host}"),
        None => host,
    }
}

fn native_remote_args(args: &Args, srcs: &[Location], dst: &Location) -> Result<Vec<String>> {
    let command = match args.interface {
        Interface::NativeCp => "cp",
        Interface::NativeCpPrune => "cp-prune",
        Interface::NativeRm | Interface::Rsync => unreachable!(),
    };
    let mut remote = vec![command.to_string()];
    let mut short = String::new();
    if args.dry_run {
        short.push('n');
    }
    if args.quiet {
        short.push('q');
    }
    for _ in 0..args.verbose {
        short.push('v');
    }
    if !short.is_empty() {
        remote.push(format!("-{short}"));
    }
    if let Some(connections) = args.connections_opt {
        remote.push("-j".into());
        remote.push(connections.to_string());
    }
    if let Some(max_delete) = args.max_delete {
        remote.push(format!("--max-delete={max_delete}"));
    }
    for source in srcs {
        remote.push(
            match source.selection {
                SourceSelection::Named => "--src",
                SourceSelection::Contents => "--src-src",
                SourceSelection::Rsync => unreachable!(),
            }
            .into(),
        );
        remote.push(utf8_path(&source.path)?);
    }
    if !srcs[0].same_host(dst) {
        remote.push("--to".into());
        remote.push(endpoint_arg(dst));
    }
    let placement = match (args.placement, args.target_existence) {
        (Placement::Into, Existence::Any) => "--into",
        (Placement::Into, Existence::New) => "--into-new",
        (Placement::Into, Existence::Existing) => "--into-existing",
        (Placement::As, Existence::Any) => "--as",
        (Placement::As, Existence::New) => "--as-new",
        (Placement::As, Existence::Existing) => "--as-existing",
        (Placement::Rsync, _) => unreachable!(),
    };
    remote.push(placement.into());
    remote.push(utf8_path(&dst.path)?);
    Ok(remote)
}

fn rsync_remote_args(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    source_operand_count: usize,
    src_target: &str,
) -> Result<Vec<String>> {
    let mut remote: Vec<String> = vec!["rsync".into()];
    let mut short = String::new();
    for (flag, on) in [
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
    ] {
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
    if let Some(j) = args.connections_opt {
        remote.push("-j".into());
        remote.push(j.to_string());
    }
    remote.push(format!("--block-size={}", args.block_size));
    remote.push(format!("--min-split={}", args.min_split));
    if let Some(rate) = &args.bwlimit {
        remote.push(format!("--bwlimit={rate}"));
    }
    if args.stats {
        remote.push("--stats".into());
    }
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
    if let Some(n) = args.max_delete {
        remote.push(format!("--max-delete={n}"));
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
    if args.progress_json && !args.quiet {
        remote.push("--progress-json".into());
    }
    if args.dry_run {
        remote.push(format!("--plan-source-host={src_target}"));
    }
    remote.push(format!(
        "--direct-source-operand-count={source_operand_count}"
    ));
    remote.push("--direct-sources-prededuplicated".into());
    for line in &args.ignore_lines {
        remote.push(format!("--ignore={line}"));
    }
    if args.no_progress || args.quiet {
        remote.push("--no-progress".into());
    } else if std::io::stderr().is_terminal() {
        remote.push("--progress".into());
        remote.push(format!("--width={}", crate::progress::term_width()));
    }
    if let Some(path) = &args.syq_path {
        remote.push(format!("--syq-path={path}"));
    }
    if let Some(rsh) = &args.rsh {
        remote.push("-e".into());
        remote.push(rsh.clone());
    }
    remote.push("--".into());
    for source in srcs {
        remote.push(utf8_path(&source.path)?);
    }
    let dst_path = utf8_path(&dst.path)?;
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
        format!("{}:{dst_path}", endpoint_arg(dst))
    };
    remote.push(dst_arg);
    Ok(remote)
}

pub fn run(
    args: &Args,
    srcs: &[Location],
    dst: &Location,
    source_operand_count: usize,
) -> Result<i32> {
    let rsh = parse_rsh(&args.rsh)?;
    let src_host = srcs[0].host.clone().unwrap();
    // The follow target must reconnect the way we did: keep an explicit user.
    let src_target = match &srcs[0].user {
        Some(user) => format!("{user}@{src_host}"),
        None => src_host.clone(),
    };
    let spec = crate::conn::RemoteSpec {
        local_process: false,
        user: srcs[0].user.clone(),
        host: src_host.clone(),
        rsh: rsh.clone(),
        syq_path: args.syq_path.clone(),
        auto_helper: args.syq_path.is_none() && !args.no_bootstrap,
        helper_install: Default::default(),
        quiet: args.quiet,
        tcp: Default::default(),
        diagnostics: Default::default(),
    };

    // Rebuild only the public surface that produced this operation. Native
    // commands remain a strict allowlist even though they share the engine.
    let mut remote = match args.interface {
        Interface::Rsync => rsync_remote_args(args, srcs, dst, source_operand_count, &src_target)?,
        Interface::NativeCp | Interface::NativeCpPrune => native_remote_args(args, srcs, dst)?,
        Interface::NativeRm => unreachable!(),
    };

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
    let remote_cmd = format!("{dbg}{}", spec.program_command(&remote));

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
        let name: String = raw
            .iter()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
                    *byte as char
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

    let default_ssh_forward_agent = args
        .rsh
        .is_none()
        .then(|| !args.no_forward_agent && !srcs[0].same_host(dst));
    let make_command = || {
        direct_command(
            &rsh,
            srcs[0].user.as_deref(),
            &src_host,
            &remote_cmd,
            default_ssh_forward_agent,
        )
    };
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
        if args.interface == Interface::Rsync {
            eprintln!("syq: remote-to-remote: running on {src_host} (use --relay to route data through this machine)");
        } else {
            eprintln!("syq: remote-to-remote: running on {src_host}");
        }
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
        Some(c) if args.interface != Interface::Rsync => {
            bail!("remote-to-remote transfer on {src_host} failed (exit {c}); the source host must be able to reach the target host")
        }
        Some(c) => {
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
    let rsh = parse_rsh(&args.rsh)?;
    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if let Some(u) = &loc.user {
        cmd.args(["-l", u]);
    }
    let log = std::str::from_utf8(log).context("log path is not valid UTF-8")?;
    cmd.arg(host)
        .arg(format!("tail -n +1 -f {}", shell_words::quote(log)));
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
    use clap::Parser;
    use std::ffi::OsStr;

    fn args(command: &Command) -> Vec<&OsStr> {
        command.get_args().collect()
    }

    #[test]
    fn default_ssh_controls_agent_forwarding_explicitly() {
        let rsh = vec!["ssh".to_string(), "-p".to_string(), "2222".to_string()];
        let forwarded = direct_command(&rsh, Some("alice"), "source", "syq ...", Some(true));
        let forwarded = args(&forwarded);
        assert!(forwarded.contains(&OsStr::new("-A")));
        assert!(!forwarded.contains(&OsStr::new("-a")));

        let disabled = direct_command(&rsh, Some("alice"), "source", "syq ...", Some(false));
        let disabled = args(&disabled);
        assert!(disabled.contains(&OsStr::new("-a")));
        assert!(!disabled.contains(&OsStr::new("-A")));
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

    #[test]
    fn native_direct_invocation_stays_on_the_strict_surface() {
        let mut parsed = Args::try_parse_from(["syq rsync", "source", "destination"]).unwrap();
        parsed.interface = Interface::NativeCpPrune;
        parsed.placement = Placement::Into;
        parsed.target_existence = Existence::New;
        parsed.dry_run = true;
        parsed.verbose = 2;
        parsed.connections_opt = Some(3);
        parsed.max_delete = Some(4);
        let sources = [
            Location {
                user: Some("alice".into()),
                host: Some("source.test".into()),
                path: b"one".to_vec(),
                selection: SourceSelection::Named,
            },
            Location {
                user: Some("alice".into()),
                host: Some("source.test".into()),
                path: b"tree".to_vec(),
                selection: SourceSelection::Contents,
            },
        ];
        let destination = Location {
            user: Some("bob".into()),
            host: Some("target.test".into()),
            path: b"dest".to_vec(),
            selection: SourceSelection::Named,
        };

        let remote = native_remote_args(&parsed, &sources, &destination).unwrap();
        assert_eq!(
            remote,
            [
                "cp-prune",
                "-nvv",
                "-j",
                "3",
                "--max-delete=4",
                "--src",
                "one",
                "--src-src",
                "tree",
                "--to",
                "bob@target.test",
                "--into-new",
                "dest",
            ]
        );
    }
}
