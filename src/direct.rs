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
    remote.push("-j".into());
    remote.push(args.connections.to_string());
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
    if args.bootstrap {
        remote.push("--bootstrap".into());
    }
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

    let remote_cmd = match &args.pcp_path {
        Some(p) => format!("{} {}", shell_words::quote(p), shell_words::join(&remote)),
        None => format!(
            "sh -c 'command -v pcp >/dev/null 2>&1 && exec pcp \"$@\"; exec \"$HOME/.local/bin/pcp\" \"$@\"' pcp {}",
            shell_words::join(&remote)
        ),
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
