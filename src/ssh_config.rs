//! This machine's effective OpenSSH configuration for a host, as `ssh -G`
//! prints it: one `name value` line per setting, names in lower case.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::process::{Command, Stdio};
use std::time::Instant;

/// `ssh -G` prints a few kilobytes; with `-vvv` its trace of the files it
/// read can be longer.
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Which process group a lookup runs in.
#[derive(Clone, Copy)]
pub(crate) enum Group {
    /// Its own: a timeout or cancellation ends everything the lookup
    /// started, such as `Match exec` commands.
    Own,
    /// This process's: whatever ends this process with its group ends the
    /// lookup too, and an interactive `Match exec` can read the terminal.
    /// A timeout ends only ssh; what it started ends with this group.
    Callers,
}

/// What `ssh -G` printed for one host.
pub(crate) struct SshConfig {
    text: String,
    trace: Vec<u8>,
}

impl SshConfig {
    /// Run `program -G options [-l user] [-p port] -- host` within
    /// `deadline`. `ssh -G` contacts no server, but it runs the
    /// configuration's `Match exec` commands, which can take any time.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn query(
        program: impl AsRef<OsStr>,
        options: &[impl AsRef<OsStr>],
        user: Option<&str>,
        port: Option<u16>,
        host: &str,
        group: Group,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self> {
        let mut command = Command::new(program);
        command.arg("-G").args(options);
        if let Some(user) = user {
            command.args(["-l", user]);
        }
        if let Some(port) = port {
            command.args(["-p", &port.to_string()]);
        }
        command
            .args(["--", host])
            .env("LC_ALL", "C")
            .stdin(Stdio::null());
        // A timeout or cancellation names the lookup itself, and keeps its
        // kind for callers that tell a timeout apart.
        let capture = match group {
            Group::Own => crate::process::capture_output_bounded,
            Group::Callers => crate::process::capture_output_bounded_in_this_group,
        };
        let output = match capture(
            &format!("the SSH configuration lookup for {host}"),
            &mut command,
            deadline,
            cancelled,
            MAX_OUTPUT_BYTES,
        ) {
            Ok(output) => output,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Err(error.into())
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect SSH configuration for {host}"))
            }
        };
        if !output.status.success() {
            // Keep ssh's error, not a `-vvv` trace of the files it read.
            let detail = String::from_utf8_lossy(&output.stderr)
                .lines()
                .filter(|line| {
                    let version_banner = line.starts_with("OpenSSH_")
                        && crate::conn::parse_openssh_version(line.as_bytes()).is_some();
                    let debug_trace = ["debug1:", "debug2:", "debug3:"]
                        .iter()
                        .any(|prefix| line.starts_with(prefix));
                    !(version_banner || debug_trace)
                })
                .collect::<Vec<_>>()
                .join("\n");
            let detail = detail.trim();
            bail!(
                "could not inspect SSH configuration for {host}{}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            );
        }
        let text = String::from_utf8(output.stdout).context("SSH configuration is not UTF-8")?;
        Ok(Self {
            text,
            trace: output.stderr,
        })
    }

    /// Everything `ssh -G` printed on its standard output.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) fn into_text(self) -> String {
        self.text
    }

    /// What ssh wrote to its standard error, such as a `-vvv` trace.
    pub(crate) fn trace(&self) -> &[u8] {
        &self.trace
    }

    /// The first value of setting `name`.
    pub(crate) fn value(&self, name: &str) -> Option<&str> {
        value(&self.text, name)
    }
}

/// Each setting `ssh -G` printed, as written: its name, and its value
/// without the separating space. Values are not trimmed: a quoted value in
/// the configuration can end with a space.
pub(crate) fn entries(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines().filter_map(|line| line.split_once(' '))
}

/// Every value of setting `name`, such as each `identityfile`.
pub(crate) fn values<'a>(text: &'a str, name: &'a str) -> impl Iterator<Item = &'a str> {
    entries(text).filter_map(move |(entry, value)| (entry == name).then_some(value))
}

/// The first value of setting `name`.
pub(crate) fn value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    entries(text).find_map(|(entry, value)| (entry == name).then_some(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn values_are_read_as_written() {
        let text = "user alice\nidentityfile ~/.ssh/a\nidentityfile ~/.ssh/b\ncontrolpath /tmp/with space \nproxycommand none\n";
        assert_eq!(value(text, "user"), Some("alice"));
        assert_eq!(value(text, "controlpath"), Some("/tmp/with space "));
        assert_eq!(value(text, "proxy"), None);
        assert_eq!(
            values(text, "identityfile").collect::<Vec<_>>(),
            ["~/.ssh/a", "~/.ssh/b"]
        );
    }

    fn fake_ssh(script: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let root = crate::test_support::tempdir().unwrap();
        let ssh = root.path().join("ssh");
        crate::test_support::write_executable(&ssh, script, 0o700);
        (root, ssh)
    }

    #[test]
    fn query_passes_the_endpoint_and_pins_the_locale() {
        let (_root, ssh) =
            fake_ssh("#!/bin/sh\nprintf 'args %s\\nlocale %s\\n' \"$*\" \"$LC_ALL\"\n");
        let config = SshConfig::query(
            &ssh,
            &["-o", "BatchMode=yes"],
            Some("alice"),
            Some(2200),
            "backup",
            Group::Own,
            Instant::now() + Duration::from_secs(10),
            &|| false,
        )
        .unwrap();
        assert_eq!(
            config.value("args"),
            Some("-G -o BatchMode=yes -l alice -p 2200 -- backup")
        );
        assert_eq!(config.value("locale"), Some("C"));
    }

    /// A `Match exec` command that never finishes cannot hold syq.
    #[test]
    fn a_hanging_lookup_times_out_naming_the_host() {
        let (_root, ssh) = fake_ssh("#!/bin/sh\nexec sleep 30\n");
        for group in [Group::Own, Group::Callers] {
            let started = Instant::now();
            let error = SshConfig::query(
                &ssh,
                &[] as &[&str],
                None,
                None,
                "backup",
                group,
                Instant::now() + Duration::from_millis(100),
                &|| false,
            )
            .err()
            .unwrap();
            assert!(started.elapsed() < Duration::from_secs(10));
            assert_eq!(
                error.to_string(),
                "the SSH configuration lookup for backup timed out"
            );
            assert!(error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut));
        }
    }

    /// A lookup in the caller's group ends with it, as when the receiving
    /// service ends a setup child's group; one in its own group does not.
    #[test]
    fn a_lookup_runs_in_the_group_asked_for() {
        let (_root, ssh) = fake_ssh("#!/bin/sh\nprintf 'group %s\\n' $(ps -o pgid= -p $$)\n");
        let ours = unsafe { libc::getpgrp() }.to_string();
        let group = |group| {
            SshConfig::query(
                &ssh,
                &[] as &[&str],
                None,
                None,
                "backup",
                group,
                Instant::now() + Duration::from_secs(10),
                &|| false,
            )
            .unwrap()
            .value("group")
            .unwrap()
            .to_owned()
        };
        assert_eq!(group(Group::Callers), ours);
        assert_ne!(group(Group::Own), ours);
    }
}
