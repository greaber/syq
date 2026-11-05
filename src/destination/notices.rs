//! What a command says when it waits for a receiving machine's approval,
//! why `auto` asks one after this machine's own SSH login failed, and what
//! to do when a receiving name cannot be used.
//!
//! The person reading a receiving-name error is usually on the server, often
//! an agent working for someone whose laptop is the receiving machine. The
//! fix runs on that laptop and names this server, so each message says which
//! machine runs what, and names this server account as a hint for HOST.
use super::*;
use crate::agent_socket::Agent;
use crate::conn::SshLoginFailure;

/// Say at once, on stderr, that the command now waits for `who` to approve
/// `what`, so that a log, or a caller without a terminal, shows why it waits.
pub(super) fn waiting(who: &str, what: &str) {
    crate::output::diagnostic!(
        "syq: waiting up to {} minutes for {who} to approve {what}; approve it there in the desktop prompt or with `syq persist receive pending`",
        REQUEST_TIMEOUT.as_secs() / 60
    );
}

/// As `waiting`, when another command is still setting up the same `what`:
/// its request may wait for approval, or it may be starting the connection.
pub(super) fn waiting_for_earlier(who: &str, what: &str) {
    crate::output::diagnostic!(
        "syq: waiting up to {} minutes for another command to finish setting up {what}; if it still needs approval, approve it on {who} in the desktop prompt or with `syq persist receive pending`",
        REQUEST_TIMEOUT.as_secs() / 60
    );
}

/// This machine's hostname and login name. Someone at a receiving machine
/// can use them to work out which HOST reaches this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Here {
    pub(crate) host: String,
    pub(crate) user: Option<String>,
}

/// This machine's hostname and login name, looked up once and only for
/// error messages. `None` when the hostname is unavailable or unprintable;
/// the login name alone would not help find the machine.
pub(crate) fn here() -> Option<&'static Here> {
    static HERE: std::sync::OnceLock<Option<Here>> = std::sync::OnceLock::new();
    HERE.get_or_init(|| {
        let mut buffer = [0u8; 256];
        let host = (unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } == 0)
            .then(|| buffer.iter().position(|byte| *byte == 0))
            .flatten()
            .and_then(|end| std::str::from_utf8(&buffer[..end]).ok())
            .filter(|host| !host.is_empty() && host.bytes().all(|byte| byte.is_ascii_graphic()))?;
        Some(Here {
            host: host.to_owned(),
            user: crate::restricted::current_account_name(),
        })
    })
    .as_ref()
}

/// ` (this server's hostname is j5 and its account is alice; your laptop
/// may use another name for it)`, or nothing when the hostname is unknown.
/// A laptop often reaches a server through an SSH alias, so this is a hint
/// for HOST, not a value to use.
fn hint(machine: &str, here: Option<&Here>) -> String {
    let Some(here) = here else {
        return String::new();
    };
    let account = here
        .user
        .as_deref()
        .map(|user| format!(" and its account is {user}"))
        .unwrap_or_default();
    format!(
        " ({machine}'s hostname is {}{account}; your laptop may use another name for it)",
        here.host
    )
}

/// What the person at `machine` runs to connect it to this server account.
fn connect_instruction(machine: &str, here: Option<&Here>) -> String {
    format!(
        "run `syq persist connect HOST` on {machine} (for example your laptop), where HOST is how it reaches this server{}",
        hint("this server", here)
    )
}

/// No receiving machine is registered as `@name`; `registered` lists the
/// names that are. A mistyped or guessed name is the usual cause, so a
/// registered name comes first, before how to connect another machine.
pub(super) fn not_connected(name: &str, registered: &[String], here: Option<&Here>) -> String {
    let mut message =
        format!("no receiving machine named @{name} is connected to this server account");
    match registered {
        [] => message.push('.'),
        [only] => message.push_str(&format!("; did you mean @{only}?")),
        _ => {
            let shown = registered
                .iter()
                .take(8)
                .map(|name| format!("@{name}"))
                .collect::<Vec<_>>()
                .join(", ");
            let more = match registered.len() {
                0..=8 => String::new(),
                count => format!(", and {} more", count - 8),
            };
            message.push_str(&format!(". Names registered here: {shown}{more}."));
        }
    }
    message.push_str(&format!(
        "\nTo connect a receiving machine, {}. If receiving was never set up there, run `syq persist receive on --connection HOST` there instead.",
        connect_instruction("it", here)
    ));
    message
}

/// `@name` is registered here, but its connection is gone.
pub(super) fn offline(name: &str, here: Option<&Here>) -> String {
    format!(
        "receiving machine @{name} is registered on this server account but not connected; it may have restarted or lost its connection.\nTo reconnect it, {}. Then retry, or release the name on this server with `syq persist destinations forget {name}`.",
        connect_instruction("that machine", here)
    )
}

/// The registered connection did not answer.
pub(super) fn unreachable(here: Option<&Here>) -> String {
    format!(
        "could not reach the receiving machine; it may be busy, or its connection may have ended, for example because it restarted. Try again, or {}",
        connect_instruction("that machine", here)
    )
}

/// The registration cannot be used as it is; a new connection replaces it.
pub(super) fn reconnect(problem: &str, here: Option<&Here>) -> String {
    format!(
        "{problem}; to reconnect, {}",
        connect_instruction("the receiving machine", here)
    )
}

/// The syq on `@name` is too old for `what`.
pub(super) fn outdated(name: &str, what: &str, here: Option<&Here>) -> String {
    format!(
        "the syq connected as @{name} does not support {what}; update syq on that machine, then {}",
        connect_instruction("it", here)
    )
}

/// `syq persist connect @name`: the command runs on the receiving machine
/// and names the SSH server it connects to.
pub(crate) fn connect_takes_server(name: &str, here: Option<&Here>) -> String {
    format!(
        "@{name} is a receiving name, not an SSH server: run `syq persist connect HOST` on the receiving machine itself (for example your laptop), where HOST is the SSH server it should connect to{}",
        hint("this machine", here)
    )
}

/// A copy from `@name`, which receiving machines do not serve.
pub(crate) fn copy_from(name: &str, here: Option<&Here>) -> String {
    format!(
        "cannot copy from receiving machine @{name}: receiving machines accept copies sent to them (`syq cp PATH --to @{name}`) and commands (`syq exec --on @{name} -- COMMAND`).\nTo copy files from that machine to this server, run `syq cp PATH --to HOST` on it, where HOST is how it reaches this server{}.",
        hint("this server", here)
    )
}

/// `command` given `@name`, which only copies and commands can use.
pub(crate) fn unsupported(command: &str, name: &str) -> String {
    format!(
        "receiving machine @{name} cannot be used with {command}; receiving machines accept copies sent with `syq cp PATH --to @{name}` and commands run with `syq exec --on @{name} -- COMMAND`"
    )
}

/// After this machine's own SSH login to `spec` failed with `error`, say in
/// one line why syq asks `@name` to approve `what` instead, and how to avoid
/// it. Nothing is said when this machine simply has no SSH credentials to
/// offer: asking the receiving machine is then the ordinary way to get
/// authorization, as with agent forwarding.
pub(super) fn asking(
    error: &anyhow::Error,
    spec: &crate::conn::RemoteSpec,
    name: &str,
    what: &str,
) {
    let host = &spec.host;
    let asking = format!("asking @{name} to approve {what}");
    let line = match crate::conn::ssh_authorization_failure(error) {
        Some(SshLoginFailure::Credentials) => match credentials(spec) {
            Credentials::None => return,
            Credentials::DeadAgent {
                socket,
                environment: true,
            } => format!(
                "SSH_AUTH_SOCK names {}, where no SSH agent answers, so this machine could not log in to {host}; {asking}. To fix this, point SSH_AUTH_SOCK at a running agent, or unset it",
                socket.display()
            ),
            Credentials::DeadAgent {
                socket,
                environment: false,
            } => format!(
                "no SSH agent answers at {}, the IdentityAgent for {host}, so this machine could not log in; {asking}. To fix this, start that agent or change IdentityAgent in your SSH configuration",
                socket.display()
            ),
            Credentials::AgentFailed { socket, reason } => format!(
                "this machine could not log in to {host}, and the SSH agent at {} {reason}; {asking}. To fix this, restart that agent",
                socket.display()
            ),
            Credentials::Present => format!(
                "this machine could not log in to {host} with its SSH keys; {asking}. To avoid this, make sure this machine's key is authorized on {host} and available to its SSH agent"
            ),
        },
        _ => format!("{}; {asking}", error.root_cause()),
    };
    crate::output::diagnostic!("syq: {line}");
}

/// What this machine had to offer when ssh reported rejected credentials.
#[derive(Debug, PartialEq, Eq)]
enum Credentials {
    /// No agent keys, key files or PKCS#11 provider: nothing to offer.
    None,
    /// Nothing answers at the agent socket ssh used. `environment` says
    /// whether that socket came from `SSH_AUTH_SOCK` rather than an
    /// `IdentityAgent` setting.
    DeadAgent { socket: PathBuf, environment: bool },
    /// The agent is there but did not list its keys, for `reason`.
    AgentFailed {
        socket: PathBuf,
        reason: &'static str,
    },
    /// Keys that did not get this machine in, or credentials syq could not
    /// rule out.
    Present,
}

fn credentials(spec: &crate::conn::RemoteSpec) -> Credentials {
    // ssh's own view of the destination: its agent and identity files.
    let Ok(output) = crate::process::capture_output_bounded(
        &mut spec.ssh_hostname_command(),
        Instant::now() + Duration::from_secs(5),
        &|| false,
        MAX_MESSAGE,
    ) else {
        return Credentials::Present;
    };
    if !output.status.success() {
        return Credentials::Present;
    }
    let Ok(agent) = crate::agent_broker::configured_agent_socket(&output.stdout) else {
        return Credentials::Present;
    };
    let config = String::from_utf8_lossy(&output.stdout);
    classify(
        &config,
        agent.map(|socket| {
            let answer =
                crate::agent_socket::inspect(&socket, Instant::now() + Duration::from_secs(2));
            (socket, answer)
        }),
        |path| path.exists(),
    )
}

fn classify(
    config: &str,
    agent: Option<(PathBuf, Agent)>,
    exists: impl Fn(&Path) -> bool,
) -> Credentials {
    match agent {
        Some((socket, Agent::Dead)) => {
            let environment = matches!(
                config
                    .lines()
                    .find_map(|line| line.strip_prefix("identityagent ")),
                None | Some("SSH_AUTH_SOCK")
            );
            return Credentials::DeadAgent {
                socket,
                environment,
            };
        }
        Some((socket, Agent::Failed(reason))) => {
            return Credentials::AgentFailed { socket, reason };
        }
        Some((_, Agent::Identities(0))) | None => {}
        Some((_, Agent::Identities(_))) => return Credentials::Present,
    }
    // A PKCS#11 provider holds keys that neither the agent nor files show.
    if config
        .lines()
        .any(|line| line.starts_with("pkcs11provider ") && line != "pkcs11provider none")
    {
        return Credentials::Present;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let key_files = config
        .lines()
        .filter_map(|line| line.strip_prefix("identityfile "))
        .any(|file| {
            // `ssh -G` leaves `~` and tokens in identity files unexpanded.
            // A file whose name syq cannot work out may exist.
            if file.contains('%') || file.contains("${") {
                return true;
            }
            let path = match (file.strip_prefix("~/"), &home) {
                (Some(rest), Some(home)) => home.join(rest),
                (None, _) if !file.starts_with('~') => PathBuf::from(file),
                _ => return true,
            };
            exists(&path)
        });
    if key_files {
        Credentials::Present
    } else {
        Credentials::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each message says which machine runs the fix and what it names, so
    /// an agent on the server knows to ask the person at the laptop.
    #[test]
    fn receiving_name_errors_say_where_to_run_what() {
        let j5 = Here {
            host: "j5".into(),
            user: Some("alice".into()),
        };
        let here = Some(&j5);
        let server = "(this server's hostname is j5 and its account is alice; your laptop may use another name for it)";
        let connect = format!("run `syq persist connect HOST` on it (for example your laptop), where HOST is how it reaches this server {server}");
        let none = not_connected("master", &[], here);
        assert!(
            none.starts_with(
                "no receiving machine named @master is connected to this server account.\n"
            ),
            "{none}"
        );
        assert!(none.contains(&connect), "{none}");
        assert!(
            none.ends_with(
                ". If receiving was never set up there, run `syq persist receive on --connection HOST` there instead."
            ),
            "{none}"
        );
        let one = not_connected("master", &["laptop".into()], here);
        assert!(
            one.starts_with("no receiving machine named @master is connected to this server account; did you mean @laptop?\n"),
            "{one}"
        );
        let names: Vec<String> = (0..10).map(|n| format!("m{n}")).collect();
        let many = not_connected("master", &names, here);
        assert!(
            many.contains(
                ". Names registered here: @m0, @m1, @m2, @m3, @m4, @m5, @m6, @m7, and 2 more.\n"
            ),
            "{many}"
        );
        assert!(!many.contains("did you mean"), "{many}");
        for message in [&none, &one, &many] {
            assert!(!message.contains("restarted"), "{message}");
        }
        assert_eq!(
            offline("laptop", here),
            format!("receiving machine @laptop is registered on this server account but not connected; it may have restarted or lost its connection.\nTo reconnect it, run `syq persist connect HOST` on that machine (for example your laptop), where HOST is how it reaches this server {server}. Then retry, or release the name on this server with `syq persist destinations forget laptop`.")
        );
        assert!(unreachable(here).ends_with(&format!("run `syq persist connect HOST` on that machine (for example your laptop), where HOST is how it reaches this server {server}")));
        assert_eq!(
            connect_takes_server("master", here),
            "@master is a receiving name, not an SSH server: run `syq persist connect HOST` on the receiving machine itself (for example your laptop), where HOST is the SSH server it should connect to (this machine's hostname is j5 and its account is alice; your laptop may use another name for it)"
        );
        assert!(copy_from("master", here).ends_with(&format!(
            "run `syq cp PATH --to HOST` on it, where HOST is how it reaches this server {server}."
        )));
        assert!(outdated("laptop", "syq ssh", here)
            .ends_with(&format!("update syq on that machine, then {connect}")));
        assert!(reconnect("the registration for @laptop is invalid", here).ends_with(
            &format!("is invalid; to reconnect, run `syq persist connect HOST` on the receiving machine (for example your laptop), where HOST is how it reaches this server {server}")
        ));
        // Without a login name the hostname still helps; without a
        // hostname the hint is left out.
        let nameless = Here {
            host: "j5".into(),
            user: None,
        };
        assert!(not_connected("master", &[], Some(&nameless)).contains(
            "reaches this server (this server's hostname is j5; your laptop may use another name for it). If"
        ));
        assert!(not_connected("master", &[], None).contains(
            "where HOST is how it reaches this server. If receiving was never set up there"
        ));
        let local = super::here().expect("this test host has a hostname");
        assert!(
            !local.host.is_empty() && local.host.bytes().all(|byte| byte.is_ascii_graphic()),
            "{local:?}"
        );
    }

    #[test]
    fn credentials_are_absent_only_without_agent_keys_and_key_files() {
        let defaults = "user alice\nidentityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ed25519\n";
        let none = |_: &Path| false;
        let socket = PathBuf::from("/tmp/ssh-old/agent.1");
        assert_eq!(classify(defaults, None, none), Credentials::None);
        assert_eq!(
            classify(defaults, Some((socket.clone(), Agent::Identities(0))), none),
            Credentials::None
        );
        assert_eq!(
            classify(defaults, Some((socket.clone(), Agent::Identities(1))), none),
            Credentials::Present
        );
        // An agent that fails to list its keys is not an empty one.
        assert_eq!(
            classify(
                defaults,
                Some((socket.clone(), Agent::Failed("refused to list its keys"))),
                none
            ),
            Credentials::AgentFailed {
                socket: socket.clone(),
                reason: "refused to list its keys"
            }
        );
        assert_eq!(
            classify(
                &format!("{defaults}pkcs11provider /usr/lib/token.so\n"),
                None,
                none
            ),
            Credentials::Present
        );
        assert_eq!(
            classify(&format!("{defaults}pkcs11provider none\n"), None, none),
            Credentials::None
        );
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let ed25519 = home.join(".ssh/id_ed25519");
        assert_eq!(
            classify(defaults, None, |path| path == ed25519),
            Credentials::Present
        );
        for file in ["~/.ssh/%h_key", "${KEYS}/key", "~other/.ssh/id_rsa"] {
            assert_eq!(
                classify(&format!("identityfile {file}\n"), None, none),
                Credentials::Present,
                "{file}"
            );
        }
        assert_eq!(
            classify("identityfile /keys/id\n", None, |path| path
                == Path::new("/keys/id")),
            Credentials::Present
        );
    }

    #[test]
    fn a_dead_agent_names_where_its_socket_came_from() {
        let socket = PathBuf::from("/tmp/ssh-old/agent.1");
        for (config, environment) in [
            ("identityfile ~/.ssh/id_rsa\n", true),
            ("identityagent SSH_AUTH_SOCK\n", true),
            ("identityagent /run/agent.sock\n", false),
        ] {
            // A dead agent explains the failure even beside key files.
            assert_eq!(
                classify(config, Some((socket.clone(), Agent::Dead)), |_| true),
                Credentials::DeadAgent {
                    socket: socket.clone(),
                    environment
                },
                "{config}"
            );
        }
    }
}
