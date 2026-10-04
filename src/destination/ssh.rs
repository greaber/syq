//! SSH session arguments. Authorization and process lifetime belong to the caller.
use crate::cli::{AuthFrom, NativeEndpoint};
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub(super) mod foreground;
mod master_lifetime;
pub(crate) mod persistent;

#[derive(Parser)]
#[command(
    name = "syq ssh",
    about = "Open an SSH shell or run a command",
    long_about = "Open an SSH shell or run a command. With no command, open a shell. Like ssh, the remote shell interprets command arguments joined with spaces; quote shell syntax for the remote shell. This differs from syq exec --on @NAME, which passes literal arguments."
)]
struct SshCommand {
    /// Authorization source; omitted uses the saved preference, then an approved account connection or native SSH
    #[arg(long, value_name = "auto|ssh|@NAME", value_parser = crate::cli::parse_auth_from)]
    auth_from: Option<AuthFrom>,
    /// Use connections and authorization preferences from this persistence scope
    #[arg(long, value_name = "PATH")]
    pscope: Option<PathBuf>,
    /// Request a terminal, including when running a command
    #[arg(short = 't', conflicts_with = "no_tty")]
    tty: bool,
    /// Disable terminal allocation
    #[arg(short = 'T')]
    no_tty: bool,
    /// SSH endpoint: [USER@]HOST[:PORT]; enclose IPv6 addresses in brackets
    #[arg(value_name = "HOST")]
    destination: String,
    /// Remote shell command and arguments, interpreted as with ssh
    #[arg(last = true, num_args = 0.., value_name = "COMMAND")]
    command: Vec<OsString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tty {
    /// Leave OpenSSH's normal shell/command terminal selection in effect.
    Default,
    Request,
    Disabled,
}

#[derive(Clone, Debug)]
pub(crate) struct SessionRequest {
    pub(crate) authorizer: String,
    pub(crate) destination: NativeEndpoint,
    pub(crate) tty: Tty,
    pub(crate) command: Vec<OsString>,
}

pub(crate) fn command_for_help() -> clap::Command {
    crate::help::configure(SshCommand::command().bin_name("syq ssh"))
        .mut_arg("auth_from", |arg| arg.hide_short_help(false))
        .mut_arg("tty", |arg| arg.hide_short_help(false))
        .mut_arg("no_tty", |arg| arg.hide_short_help(false))
}

fn parse_command(argv: &[OsString]) -> Result<(SessionRequest, Option<AuthFrom>, Option<PathBuf>)> {
    let matches = command_for_help().try_get_matches_from(argv)?;
    let parsed = SshCommand::from_arg_matches(&matches)?;
    if parsed.destination.len() > 512 {
        bail!("destination SSH endpoint is too long");
    }
    let destination = crate::cli::parse_native_endpoint(Some(&parsed.destination))?
        .context("SSH destination is missing")?;
    validate_endpoint(&destination)?;
    if parsed.command.iter().any(|arg| arg.as_bytes().contains(&0)) {
        bail!("SSH command arguments must not contain NUL");
    }
    Ok((
        SessionRequest {
            authorizer: String::new(),
            destination,
            tty: if parsed.tty {
                Tty::Request
            } else if parsed.no_tty {
                Tty::Disabled
            } else {
                Tty::Default
            },
            command: parsed.command,
        },
        parsed.auth_from,
        parsed.pscope,
    ))
}

/// An explicit receiving name, used for persistent account requests.
pub(crate) fn parse(argv: &[OsString]) -> Result<SessionRequest> {
    let (mut request, mode, _) = parse_command(argv)?;
    let Some(AuthFrom::Return(name)) = mode else {
        bail!("SSH authorization requires a receiving machine named @NAME");
    };
    request.authorizer = name;
    Ok(request)
}

/// Validate the displayed command without reading the laptop's preferences.
pub(crate) fn parse_for_approval(argv: &[OsString], expected: &str) -> Result<SessionRequest> {
    let (mut request, mode, _) = parse_command(argv)?;
    match mode {
        None => {}
        Some(AuthFrom::Return(name)) if name == expected => {}
        _ => bail!("SSH authorizer does not match the shown command"),
    }
    request.authorizer = expected.to_owned();
    Ok(request)
}

pub(crate) fn run(argv: &[OsString]) -> Result<i32> {
    let (request, explicit, scope) = parse_command(argv)?;
    let domain = crate::persistence::Domain::select(scope.as_deref())?;
    let mode = crate::auth_from::resolve(&domain, &request.destination.host, explicit)?;
    crate::fsops::reserve_startup_descriptors();
    if let Some(mut command) = persistent::command(&domain, &request, &mode)? {
        return foreground::run_cached(&mut command, || false);
    }
    anyhow::ensure!(
        !matches!(mode, AuthFrom::Return(_)),
        "laptop account authorization did not produce an SSH connection"
    );
    let mut command = std::process::Command::new("ssh");
    if let Some(scope) = crate::persistence::scope_for_implicit_ssh(domain.explicit_path())? {
        let control = crate::persistence::prepare_endpoint(
            &scope,
            request.destination.user.as_deref(),
            &request.destination.host,
            request.destination.port,
            None,
        )?;
        let persist = if domain.is_default() {
            "ControlPersist=yes"
        } else {
            "ControlPersist=300"
        };
        command
            .args(["-o", "ControlMaster=auto", "-o", persist, "-S"])
            .arg(crate::persistence::openssh_control_path(&control));
    }
    command.args(request.ssh_arguments(&request.destination)?);
    // Native auth executes once: a failing command must never run again through a laptop.
    foreground::run(&mut command, || false)
}

pub(crate) fn validate_endpoint(endpoint: &NativeEndpoint) -> Result<()> {
    if endpoint.host.is_empty()
        || endpoint.host.starts_with('-')
        || !endpoint
            .host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))
        || endpoint.user.as_ref().is_some_and(|user| {
            user.is_empty()
                || user.starts_with('-')
                || !user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        || endpoint.host.len() + endpoint.user.as_ref().map_or(0, String::len) > 512
        || endpoint.port == Some(0)
    {
        bail!("SSH sessions require an ordinary SSH destination with a plain host and login name");
    }
    Ok(())
}

impl SessionRequest {
    /// Append these arguments after the caller's authorization options. The
    /// authorizer resolves its SSH aliases; do not resolve `destination` again
    /// on the requesting server. No quoting is added: OpenSSH intentionally
    /// joins the remote command's arguments for the destination's shell.
    pub(crate) fn ssh_arguments(
        &self,
        authorized_endpoint: &NativeEndpoint,
    ) -> Result<Vec<OsString>> {
        validate_endpoint(authorized_endpoint)?;
        let mut args = Vec::new();
        match self.tty {
            Tty::Default => {}
            Tty::Request => args.push("-t".into()),
            Tty::Disabled => args.push("-T".into()),
        }
        if let Some(user) = &authorized_endpoint.user {
            args.extend(["-l".into(), user.into()]);
        }
        if let Some(port) = authorized_endpoint.port {
            args.extend(["-p".into(), port.to_string().into()]);
        }
        args.extend(["--".into(), authorized_endpoint.host.clone().into()]);
        args.extend(self.command.iter().cloned());
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    fn request(args: &[&str]) -> Result<SessionRequest> {
        parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn a_shell_uses_only_the_explicit_authorizer_and_normal_ssh_terminal_selection() {
        let parsed = request(&["ssh", "hostB", "--auth-from", "@laptop"]).unwrap();
        assert_eq!(parsed.authorizer, "laptop");
        assert_eq!(parsed.destination.host, "hostB");
        assert_eq!(parsed.tty, Tty::Default);
        assert!(parsed.command.is_empty());
        assert_eq!(
            parsed.ssh_arguments(&parsed.destination).unwrap(),
            [OsString::from("--"), OsString::from("hostB")]
        );
        for args in [
            vec!["ssh", "hostB"],
            vec!["ssh", "--auth-from", "auto", "hostB"],
            vec!["ssh", "--auth-from", "ssh", "hostB"],
            vec!["ssh", "--auth-from", "laptop", "hostB"],
            vec!["ssh", "--auth-from", "@", "hostB"],
            vec!["ssh", "--auth-from", "@bad/name", "hostB"],
        ] {
            assert!(request(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn native_choices_and_approval_validation_do_not_read_preferences() {
        for selector in ["auto", "ssh"] {
            let argv: Vec<OsString> = ["ssh", "--auth-from", selector, "hostB", "--", "exit 17"]
                .into_iter()
                .map(Into::into)
                .collect();
            assert!(parse_command(&argv).is_ok());
            assert!(parse_for_approval(&argv, "laptop").is_err());
        }
        let argv: Vec<OsString> = ["ssh", "hostB", "--", "exit 17"]
            .into_iter()
            .map(Into::into)
            .collect();
        let approved = parse_for_approval(&argv, "laptop").unwrap();
        assert_eq!(approved.authorizer, "laptop");
        assert_eq!(approved.command, [OsString::from("exit 17")]);
        let mismatch: Vec<OsString> = ["ssh", "--auth-from", "@other", "hostB"]
            .into_iter()
            .map(Into::into)
            .collect();
        assert!(parse_for_approval(&mismatch, "laptop").is_err());
    }

    #[test]
    fn source_scope_is_local_metadata_and_not_a_remote_approval_dependency() {
        let argv: Vec<OsString> = [
            "ssh",
            "--pscope",
            "/does/not/exist/on/provider",
            "--auth-from",
            "@laptop",
            "hostB",
            "--",
            "exit 17",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        let (request, _, scope) = parse_command(&argv).unwrap();
        assert_eq!(
            scope.as_deref(),
            Some(std::path::Path::new("/does/not/exist/on/provider"))
        );
        let approved = parse_for_approval(&argv, "laptop").unwrap();
        assert_eq!(approved.destination, request.destination);
        assert_eq!(
            approved.ssh_arguments(&approved.destination).unwrap(),
            [
                OsString::from("--"),
                OsString::from("hostB"),
                OsString::from("exit 17")
            ]
        );
    }

    #[test]
    fn terminal_options_are_explicit_and_mutually_exclusive() {
        for (flag, expected) in [("-t", Tty::Request), ("-T", Tty::Disabled)] {
            let parsed = request(&["ssh", "--auth-from", "@laptop", flag, "hostB"]).unwrap();
            assert_eq!(parsed.tty, expected);
            assert_eq!(parsed.ssh_arguments(&parsed.destination).unwrap()[0], flag);
        }
        assert!(request(&["ssh", "--auth-from", "@laptop", "-t", "-T", "hostB"]).is_err());
    }

    #[test]
    fn ipv6_and_authorizer_resolved_endpoint_are_passed_as_ssh_operands() {
        let parsed = request(&[
            "ssh",
            "--auth-from",
            "@laptop",
            "alice@[2001:db8::1]:2222",
            "--",
            "uptime",
        ])
        .unwrap();
        assert_eq!(parsed.destination.user.as_deref(), Some("alice"));
        assert_eq!(parsed.destination.host, "2001:db8::1");
        assert_eq!(parsed.destination.port, Some(2222));
        let resolved = NativeEndpoint {
            user: Some("bob".into()),
            host: "2001:db8::2".into(),
            port: Some(2200),
        };
        assert_eq!(
            parsed.ssh_arguments(&resolved).unwrap(),
            ["-l", "bob", "-p", "2200", "--", "2001:db8::2", "uptime"].map(OsString::from)
        );
    }

    #[test]
    fn commands_keep_ssh_shell_semantics_after_the_option_boundary() {
        let mut args = [
            "ssh",
            "--auth-from",
            "@laptop",
            "hostB",
            "--",
            "printf",
            "'%s'",
            "'two words'",
            "&&",
            "echo",
            "--auth-from",
            "-oProxyCommand=touch marker",
        ]
        .map(OsString::from)
        .to_vec();
        args.push(OsString::from_vec(vec![0xff]));
        let parsed = parse(&args).unwrap();
        assert_eq!(parsed.command, args[5..]);
        let outgoing = parsed.ssh_arguments(&parsed.destination).unwrap();
        assert_eq!(outgoing[0], "--");
        assert_eq!(outgoing[1], "hostB");
        assert_eq!(outgoing[2..], args[5..]);
        assert!(request(&["ssh", "--auth-from", "@laptop", "hostB", "uptime"]).is_err());
        args.push(OsString::from_vec(b"bad\0argument".to_vec()));
        assert!(parse(&args).is_err());
    }

    #[test]
    fn endpoints_cannot_supply_ssh_options_or_shell_substitutions() {
        for endpoint in [
            "@other",
            "-oProxyCommand=bad",
            "user;bad@host",
            "-user@host",
            "$(id)",
            "host%h",
            "host/path",
            "host:0",
            "host:65536",
            "2001:db8::1",
            "[::1",
            "a@b@c",
        ] {
            assert!(
                request(&["ssh", "--auth-from", "@laptop", endpoint]).is_err(),
                "{endpoint}"
            );
        }
        let too_long = "h".repeat(513);
        assert!(request(&["ssh", "--auth-from", "@laptop", &too_long]).is_err());
        let parsed = request(&["ssh", "--auth-from", "@laptop", "hostB"]).unwrap();
        for resolved in [
            NativeEndpoint {
                user: None,
                host: "-bad".into(),
                port: None,
            },
            NativeEndpoint {
                user: Some("x;bad".into()),
                host: "hostB".into(),
                port: None,
            },
            NativeEndpoint {
                user: None,
                host: "hostB".into(),
                port: Some(0),
            },
        ] {
            assert!(parsed.ssh_arguments(&resolved).is_err());
        }
    }

    #[test]
    fn help_explains_shell_interpretation_and_shows_terminal_options() {
        let brief = command_for_help().render_help().to_string();
        assert!(brief.contains("--auth-from"));
        assert!(brief.contains("-t"));
        assert!(brief.contains("-T"));
        assert!(brief.contains("[COMMAND]"));
        let full = command_for_help()
            .render_long_help()
            .to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(full.contains("joined with spaces"));
        assert!(full.contains("literal arguments"));
        assert!(full.contains("enclose IPv6 addresses in brackets"));
    }
}
