//! Direct remote-to-remote: run the orchestrator on the source host so data
//! flows source→destination without passing through this machine.

use crate::cli::{parse_rsh, Args, Location};
use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::process::{Command, Stdio};

pub fn run(args: &Args, srcs: &[Location], dst: &Location) -> Result<i32> {
    let rsh = parse_rsh(&args.rsh)?;
    let src_host = srcs[0].host.clone().unwrap();

    if args.bootstrap {
        let spec = crate::conn::RemoteSpec {
            user: srcs[0].user.clone(),
            host: src_host.clone(),
            rsh: rsh.clone(),
            pcp_path: args.pcp_path.clone(),
            quiet_tcp: !(args.tcp || args.tcp_plain || args.no_tcp),
            tcp: Default::default(),
        };
        if spec.connect(false).is_err() {
            spec.bootstrap()?;
        }
    }

    // Rebuild the option list for the remote orchestrator.
    let mut remote: Vec<String> = Vec::new();
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
        ('z', args.compress),
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
    if let Some(j) = args.connections_opt {
        remote.push("-j".into());
        remote.push(j.to_string());
    }
    remote.push(format!("--block-size={}", args.block_size));
    remote.push(format!("--min-split={}", args.min_split));
    if args.stats {
        remote.push("--stats".into());
    }
    if args.verify_only {
        remote.push("--verify-only".into());
    }
    if args.inplace {
        remote.push("--inplace".into());
    }
    if args.atomic {
        remote.push("--atomic".into());
    }
    if args.fsync {
        remote.push("--fsync".into());
    }
    if args.bootstrap {
        remote.push("--bootstrap".into());
    }
    if args.tcp {
        remote.push("--tcp".into());
    }
    if args.no_tcp {
        remote.push("--no-tcp".into());
    }
    if args.tcp_plain {
        remote.push("--tcp-plain".into());
    }
    remote.push(format!("--tcp-ports={}", args.tcp_ports));
    if args.progress_json {
        remote.push("--progress-json".into());
    }
    if args.no_progress || args.quiet {
        remote.push("--no-progress".into());
    } else if std::io::stderr().is_terminal() {
        // The remote has no tty; force the display and tell it our width.
        remote.push("--progress".into());
        remote.push(format!("--width={}", crate::progress::term_width()));
    }
    if let Some(p) = &args.pcp_path {
        remote.push(format!("--pcp-path={p}"));
    }
    if let Some(e) = &args.rsh {
        remote.push("-e".into());
        remote.push(e.clone());
    }
    remote.push("--".into());
    for s in srcs {
        remote.push(s.path.clone());
    }
    let dst_str = match &dst.user {
        Some(u) => format!("{u}@{}:{}", dst.host.as_ref().unwrap(), dst.path),
        None => format!("{}:{}", dst.host.as_ref().unwrap(), dst.path),
    };
    remote.push(dst_str);

    if args.detach {
        // Detached: log JSON progress instead of a live display.
        remote.retain(|a| a != "--progress" && !a.starts_with("--width="));
        remote.insert(0, "--no-progress".into());
        remote.insert(0, "--progress-json".into());
        remote.insert(0, "-v".into());
    }
    let dbg = if crate::transfer::debug() { "PCP_DEBUG=1 " } else { "" };
    let remote_cmd = match &args.pcp_path {
        Some(p) => format!("{dbg}{} {}", shell_words::quote(p), shell_words::join(&remote)),
        None => format!(
            "{dbg}sh -c 'command -v pcp >/dev/null 2>&1 && exec pcp \"$@\"; exec \"$HOME/.local/bin/pcp\" \"$@\"' pcp {}",
            shell_words::join(&remote)
        ),
    };

    let remote_cmd = if args.detach {
        // Survive the loss of this ssh session: new session, no controlling
        // terminal, everything to a log file. The transfer itself still needs
        // the forwarded agent only for its initial connections, so hostA must
        // be able to reach hostB with its own credentials for a long run.
        // The basename is interpolated into a remote shell command; allow only
        // safe characters so a crafted filename can't inject commands.
        let raw = srcs[0].path.trim_end_matches('/').rsplit('/').next().unwrap_or("pcp");
        let name: String = raw.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' }).collect();
        let name = if name.trim_matches('.').is_empty() { "pcp".to_string() } else { name };
        format!(
            "mkdir -p \"$HOME/.pcp\" && log=\"$HOME/.pcp/{name}-$(date +%Y%m%d-%H%M%S).log\" && (setsid nohup sh -c {} > \"$log\" 2>&1 < /dev/null &) && echo \"$log\"",
            shell_words::quote(&remote_cmd)
        )
    } else {
        remote_cmd
    };

    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if rsh[0].ends_with("ssh") {
        // Agent forwarding so the source host can authenticate to the destination.
        cmd.arg("-A");
        if let Some(u) = &srcs[0].user {
            cmd.args(["-l", u]);
        }
        cmd.arg("--");
    } else if let Some(u) = &srcs[0].user {
        cmd.args(["-l", u]);
    }
    cmd.arg(&src_host).arg(&remote_cmd);
    if args.detach {
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let out = cmd.output().with_context(|| format!("spawn {:?}", rsh[0]))?;
        let log = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() || log.is_empty() {
            bail!("could not start detached transfer on {src_host}");
        }
        println!("pcp: started on {src_host}, log {log}");
        println!("pcp: follow with:  pcp --follow {src_host}:{log}");
        return Ok(0);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    if !args.quiet {
        eprintln!("pcp: remote-to-remote: running on {src_host} (use --relay to route data through this machine)");
    }
    let status = cmd.status().with_context(|| format!("spawn {:?}", rsh[0]))?;
    match status.code() {
        Some(0) => Ok(0),
        Some(c) => {
            bail!("remote-to-remote transfer on {src_host} failed (exit {c}); if {src_host} cannot reach the destination, retry with --relay")
        }
        None => bail!("remote pcp on {src_host} killed by signal"),
    }
}

/// `pcp --follow HOST:LOG`: tail a detached transfer's log, rendering the JSON
/// progress lines as a status line and passing everything else through.
pub fn follow(args: &Args) -> Result<i32> {
    let target = args.paths.first().ok_or_else(|| anyhow::anyhow!("usage: pcp --follow HOST:LOGFILE"))?;
    let loc = Location::parse(target)?;
    let (Some(host), log) = (&loc.host, &loc.path) else { bail!("usage: pcp --follow HOST:LOGFILE") };
    let rsh = parse_rsh(&args.rsh)?;
    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if let Some(u) = &loc.user {
        cmd.args(["-l", u]);
    }
    cmd.arg(host).arg(format!("tail -n +1 -f {}", shell_words::quote(log)));
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = cmd.spawn()?;
    let out = child.stdout.take().unwrap();
    use std::io::BufRead;
    let tty = std::io::stderr().is_terminal();
    let mut last_status = String::new();
    for line in std::io::BufReader::new(out).lines() {
        let line = line?;
        if line.starts_with('{') {
            let get = |k: &str| -> f64 {
                line.split(&format!("\"{k}\":")).nth(1).and_then(|r| r.split([',', '}']).next()).and_then(|v| v.trim().parse().ok()).unwrap_or(0.0)
            };
            let (done, total, fd, ft, rate, el) = (get("bytes_done"), get("bytes_total"), get("files_done"), get("files_total"), get("rate"), get("elapsed"));
            let pct = if total > 0.0 { done / total * 100.0 } else { 0.0 };
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
            if line.starts_with("pcp: transferred") || line.starts_with("pcp: would transfer") {
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
