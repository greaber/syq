//! What a command says when it waits for a receiving machine's approval,
//! and why `auto` asks one after this machine's own SSH login failed.
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
            Credentials::Present => format!(
                "{host} did not accept this machine's SSH keys; {asking}. To avoid this, authorize one of them on {host}"
            ),
        },
        _ => format!("{}; {asking}", error.root_cause()),
    };
    crate::output::diagnostic!("syq: {line}");
}

/// What this machine had to offer when ssh reported rejected credentials.
#[derive(Debug, PartialEq, Eq)]
enum Credentials {
    /// No agent keys and no key files: nothing was there to reject.
    None,
    /// Nothing answers at the agent socket ssh used. `environment` says
    /// whether that socket came from `SSH_AUTH_SOCK` rather than an
    /// `IdentityAgent` setting.
    DeadAgent { socket: PathBuf, environment: bool },
    /// Keys the destination did not accept, or credentials syq could not
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
            let answer = crate::agent_socket::inspect(&socket, Duration::from_secs(2));
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
        Some((_, Agent::Identities(0))) | None => {}
        Some((_, Agent::Identities(_) | Agent::Unreadable)) => return Credentials::Present,
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
        for answer in [Agent::Identities(1), Agent::Unreadable] {
            assert_eq!(
                classify(defaults, Some((socket.clone(), answer)), none),
                Credentials::Present
            );
        }
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
