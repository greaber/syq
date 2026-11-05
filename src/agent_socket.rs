//! The SSH agent socket that syq's own ssh commands use.
//!
//! A shell inside tmux keeps the `SSH_AUTH_SOCK` it started with. After the
//! user reattaches from a new SSH login, that names the old login's agent
//! socket, which is gone, while tmux has recorded the new login's socket in
//! the session's environment, where a new shell in the session finds it.
use std::ffi::OsString;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(crate) const VARIABLE: &str = "SSH_AUTH_SOCK";

/// Connect to the agent at `socket` without waiting: a Unix stream connect
/// completes at once or fails, and a full listen queue (EAGAIN on Linux)
/// still means an agent is there.
fn connect(socket: &Path) -> io::Result<Option<UnixStream>> {
    use socket2::{Domain, SockAddr, Socket, Type};
    let stream = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    stream.set_nonblocking(true)?;
    match stream.connect(&SockAddr::unix(socket)?) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
        Err(error) => return Err(error),
    }
    stream.set_nonblocking(false)?;
    let descriptor: std::os::fd::OwnedFd = stream.into();
    Ok(Some(descriptor.into()))
}

/// Whether anything accepts connections at `socket`.
pub(crate) fn answers(socket: &Path) -> bool {
    connect(socket).is_ok()
}

/// What the agent at a socket holds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Agent {
    /// Nothing accepts connections there.
    Dead,
    /// The agent listed this many identities.
    Identities(u32),
    /// The agent accepted the connection, but its list could not be read.
    Unreadable,
}

/// Ask the agent at `socket` how many identities it holds, waiting at most
/// `timeout` for each step.
pub(crate) fn inspect(socket: &Path, timeout: Duration) -> Agent {
    let mut stream = match connect(socket) {
        Ok(Some(stream)) => stream,
        Ok(None) => return Agent::Unreadable,
        Err(_) => return Agent::Dead,
    };
    let count = (|| {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        // SSH2_AGENTC_REQUEST_IDENTITIES
        crate::agent_broker::write_frame(&mut stream, &[11])?;
        let frame = crate::agent_broker::read_frame(&mut stream)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        match frame.as_slice() {
            // SSH_AGENT_FAILURE: an agent that lists nothing.
            [5] => Ok(0),
            // SSH2_AGENT_IDENTITIES_ANSWER, then the count.
            [12, a, b, c, d, ..] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    })();
    count.map_or(Agent::Unreadable, Agent::Identities)
}

/// Inside tmux, replace an `SSH_AUTH_SOCK` where nothing answers with the
/// tmux session's value when an agent answers there, for this process and
/// the programs it starts, as a new shell in that session would have it.
/// Nothing changes outside tmux, or when the shell's socket answers.
///
/// This changes the process environment, so call it before any thread
/// starts.
pub(crate) fn repair_from_tmux() {
    if std::env::var_os("TMUX").is_none() {
        return;
    }
    let Some(current) = std::env::var_os(VARIABLE).filter(|value| !value.is_empty()) else {
        return;
    };
    if answers(Path::new(&current)) {
        return;
    }
    let Some(session) = tmux_session_socket() else {
        return;
    };
    if session.as_os_str() == current || !answers(&session) {
        return;
    }
    if crate::output::debug() {
        crate::output::diagnostic!(
            "syq: no SSH agent answers at {}; using tmux's {}",
            Path::new(&current).display(),
            session.display()
        );
    }
    // SAFETY: main calls this before starting any threads.
    unsafe { std::env::set_var(VARIABLE, session) };
}

/// The tmux session's `SSH_AUTH_SOCK`. `tmux show-environment` prints
/// `SSH_AUTH_SOCK=VALUE`, `-SSH_AUTH_SOCK` when the session removed it, and
/// fails when the session never had it.
fn tmux_session_socket() -> Option<PathBuf> {
    let output = crate::process::capture_output_bounded(
        std::process::Command::new("tmux").args(["show-environment", VARIABLE]),
        Instant::now() + Duration::from_secs(2),
        &|| false,
        64 * 1024,
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    session_socket(&output.stdout)
}

fn session_socket(output: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let line = output.strip_suffix(b"\n").unwrap_or(output);
    let value = line.strip_prefix(format!("{VARIABLE}=").as_bytes())?;
    if value.is_empty() || value.contains(&b'\n') {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(value.to_vec())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;

    #[test]
    fn tmux_session_values_name_one_socket() {
        assert_eq!(
            session_socket(b"SSH_AUTH_SOCK=/tmp/ssh-abc/agent.1\n"),
            Some(PathBuf::from("/tmp/ssh-abc/agent.1"))
        );
        for output in [
            &b"-SSH_AUTH_SOCK\n"[..],
            b"SSH_AUTH_SOCK=\n",
            b"OTHER=/tmp/agent\n",
            b"SSH_AUTH_SOCK=/a\nSSH_AUTH_SOCK=/b\n",
            b"",
        ] {
            assert_eq!(session_socket(output), None, "{output:?}");
        }
    }

    #[test]
    fn inspection_tells_dead_sockets_from_agents_and_counts_identities() {
        let directory = crate::test_support::short_tempdir().unwrap();
        let socket = directory.path().join("agent");
        assert_eq!(inspect(&socket, Duration::from_secs(1)), Agent::Dead);
        assert!(!answers(&socket));
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(answers(&socket));
        let agent = std::thread::spawn(move || {
            let replies = [&[12u8, 0, 0, 0, 2][..], &[5], &[12, 0, 0, 0, 0], &[99]];
            let mut next = 0;
            while next < replies.len() {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 5];
                // `answers` connects and closes without a request.
                if stream.read_exact(&mut request).is_err() {
                    continue;
                }
                assert_eq!(request, [0, 0, 0, 1, 11]);
                let reply = replies[next];
                next += 1;
                stream
                    .write_all(&(reply.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(reply).unwrap();
            }
            listener
        });
        for expected in [
            Agent::Identities(2),
            Agent::Identities(0),
            Agent::Identities(0),
            Agent::Unreadable,
        ] {
            assert_eq!(inspect(&socket, Duration::from_secs(5)), expected);
        }
        let listener = agent.join().unwrap();
        // An agent that accepts but never answers is not dead.
        assert_eq!(
            inspect(&socket, Duration::from_millis(100)),
            Agent::Unreadable
        );
        drop(listener);
        // The file stays, but nothing accepts connections there.
        assert_eq!(inspect(&socket, Duration::from_secs(1)), Agent::Dead);
    }
}
