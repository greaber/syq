//! Direct remote-to-remote: run the orchestrator on the source host so data
//! flows source→destination without passing through this machine.

use crate::cli::{parse_rsh, Args, Location};
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

pub fn run(args: &Args, srcs: &[Location], dst: &Location) -> Result<i32> {
    let rsh = parse_rsh(&args.rsh)?;
    let src_host = srcs[0].host.clone().unwrap();
    let spec = crate::conn::RemoteSpec {
        user: srcs[0].user.clone(),
        host: src_host.clone(),
        rsh: rsh.clone(),
        syq_path: args.syq_path.clone(),
        auto_helper: args.syq_path.is_none() && !args.no_bootstrap,
        helper_install: Default::default(),
        quiet: args.quiet,
        tcp: Default::default(),
    };

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
    remote.push(format!("--tcp-ports={}", args.tcp_ports));
    if args.progress_json && !args.quiet {
        remote.push("--progress-json".into());
    }
    // --ignore-from files were read locally; forward the merged lines.
    for l in &args.ignore_lines {
        // One argument, so a pattern starting with '-' can't be taken for a flag.
        remote.push(format!("--ignore={l}"));
    }
    if args.no_progress || args.quiet {
        remote.push("--no-progress".into());
    } else if std::io::stderr().is_terminal() {
        // The remote has no tty; force the display and tell it our width.
        remote.push("--progress".into());
        remote.push(format!("--width={}", crate::progress::term_width()));
    }
    if let Some(p) = &args.syq_path {
        remote.push(format!("--syq-path={p}"));
    }
    if let Some(e) = &args.rsh {
        remote.push("-e".into());
        remote.push(e.clone());
    }
    remote.push("--".into());
    for s in srcs {
        remote.push(s.path.clone());
    }
    // Same host (and user) on both ends: on that host this is a plain local
    // copy — no ssh back to itself, copy_file_range applies, and the
    // copy-into-itself check sees both paths on one machine.
    let dst_str = if srcs[0].same_host(dst) {
        // A relative remote path is relative to the home; anchor it so the
        // orchestrator's local parse can't take it for something else.
        if dst.path.starts_with('/')
            || dst.path == "~"
            || dst.path.starts_with("~/")
            || dst.path.starts_with("./")
            || dst.path.starts_with("../")
        {
            dst.path.clone()
        } else {
            format!("./{}", dst.path)
        }
    } else {
        match &dst.user {
            Some(u) => format!("{u}@{}:{}", dst.host.as_ref().unwrap(), dst.path),
            None => format!("{}:{}", dst.host.as_ref().unwrap(), dst.path),
        }
    };
    remote.push(dst_str);

    if args.detach {
        // Detached: log JSON progress instead of a live display.
        remote.retain(|a| a != "--progress" && !a.starts_with("--width="));
        remote.insert(0, "--no-progress".into());
        remote.insert(0, "--progress-json".into());
        remote.insert(0, "-v".into());
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
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or("syq");
        let name: String = raw
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
            println!("{src_host}:{log}");
        } else {
            println!("syq: started on {src_host}, log {log}");
            println!("syq: follow with:  syq --follow {src_host}:{log}");
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
    match status.code() {
        Some(0) => Ok(0),
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

/// `syq --follow HOST:LOG`: tail a detached transfer's log, rendering the JSON
/// progress lines as a status line and passing everything else through.
pub fn follow(args: &Args) -> Result<i32> {
    let target = args
        .paths
        .first()
        .ok_or_else(|| anyhow::anyhow!("usage: syq --follow HOST:LOGFILE"))?;
    let loc = Location::parse(target)?;
    let (Some(host), log) = (&loc.host, &loc.path) else {
        bail!("usage: syq --follow HOST:LOGFILE")
    };
    let rsh = parse_rsh(&args.rsh)?;
    let mut cmd = Command::new(&rsh[0]);
    cmd.args(&rsh[1..]);
    if let Some(u) = &loc.user {
        cmd.args(["-l", u]);
    }
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
            if line.starts_with("syq: transferred") || line.starts_with("syq: would transfer") {
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
}
