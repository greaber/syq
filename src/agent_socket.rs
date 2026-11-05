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
    /// The agent is there, but did not list its identities; the reason
    /// completes "the SSH agent at SOCKET ...".
    Failed(&'static str),
}

/// Ask the agent at `socket` how many identities it holds, giving the whole
/// exchange until `deadline`. Only the answer's type and count are read;
/// the connection then closes, as a client that goes away early does.
pub(crate) fn inspect(socket: &Path, deadline: Instant) -> Agent {
    let mut stream = match connect(socket) {
        Ok(Some(stream)) => stream,
        Ok(None) => return Agent::Failed("is not accepting connections"),
        Err(_) => return Agent::Dead,
    };
    // SSH2_AGENTC_REQUEST_IDENTITIES, after its four-byte length.
    let mut answer = [0; 9];
    let result = write_by(&mut stream, &[0, 0, 0, 1, 11], deadline)
        .and_then(|()| read_by(&mut stream, &mut answer[..5], deadline))
        .and_then(|()| match answer[4] {
            // SSH2_AGENT_IDENTITIES_ANSWER: the count follows.
            12 if u32::from_be_bytes(answer[..4].try_into().unwrap()) >= 5 => {
                read_by(&mut stream, &mut answer[5..], deadline).map(|()| {
                    Agent::Identities(u32::from_be_bytes(answer[5..].try_into().unwrap()))
                })
            }
            // SSH_AGENT_FAILURE: the request failed, which says nothing
            // about which keys the agent holds.
            5 => Ok(Agent::Failed("refused to list its keys")),
            _ => Ok(Agent::Failed("gave an answer syq could not read")),
        });
    match result {
        Ok(agent) => agent,
        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
            Agent::Failed("did not list its keys in time")
        }
        Err(_) => Agent::Failed("gave an answer syq could not read"),
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(left)
}

fn timed_out(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Write all of `bytes` before `deadline`, however the peer paces reads.
fn write_by(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    use std::io::Write;
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if timed_out(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Fill `buffer` before `deadline`, however the peer fragments its answer.
fn read_by(stream: &mut UnixStream, mut buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    use std::io::Read;
    while !buffer.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error) if timed_out(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Inside tmux, replace an `SSH_AUTH_SOCK` that no longer exists with the
/// tmux session's value when an agent you own answers there, for this
/// process and the programs it starts, as a new shell in that session would
/// have it. Nothing changes outside tmux, or while the shell's path exists:
/// `SSH_AUTH_SOCK=/dev/null` keeps turning the agent off.
///
/// sshd removes a forwarded agent's socket when its login ends, so a stale
/// socket is one that no longer exists. Checking only that keeps every
/// command in tmux from connecting to the agent, which for a forwarded agent
/// opens a channel back to the laptop. A socket that exists where nothing
/// answers, as after an agent was killed, is reported when a login fails.
///
/// This changes the process environment, so call it before any thread
/// starts, and only for commands that can start ssh.
pub(crate) fn repair_from_tmux() {
    if std::env::var_os("TMUX").is_none() {
        return;
    }
    let Some(current) = std::env::var_os(VARIABLE).filter(|value| !value.is_empty()) else {
        return;
    };
    if Path::new(&current).exists() {
        return;
    }
    let Some(session) = tmux_session_socket() else {
        return;
    };
    if session.as_os_str() == current || !owned(&session) || !answers(&session) {
        return;
    }
    if crate::output::debug() {
        crate::output::diagnostic!(
            "syq: the SSH agent socket {} is gone; using tmux's {}",
            Path::new(&current).display(),
            session.display()
        );
    }
    // SAFETY: main calls this before starting any threads.
    unsafe { std::env::set_var(VARIABLE, session) };
}

/// Whether this user owns `socket`, so that adopting it cannot pick up
/// another user's agent.
fn owned(socket: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(socket).is_ok_and(|metadata| metadata.uid() == unsafe { libc::geteuid() })
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

    /// Serve one agent connection that sends a request: answer with
    /// `reply` in `pieces`, pausing `pause` before each. Connections that
    /// close without a request, as `answers` makes, are skipped.
    fn serve(listener: &UnixListener, reply: &[u8], pieces: usize, pause: Duration) {
        loop {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 5];
            if stream.read_exact(&mut request).is_err() {
                continue;
            }
            assert_eq!(request, [0, 0, 0, 1, 11]);
            let mut frame = (reply.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(reply);
            for piece in frame.chunks(frame.len().div_ceil(pieces)) {
                std::thread::sleep(pause);
                // The client may close once it has what it needs.
                if stream.write_all(piece).is_err() {
                    break;
                }
            }
            return;
        }
    }

    #[test]
    fn inspection_tells_dead_sockets_from_agents_and_counts_identities() {
        let directory = crate::test_support::short_tempdir().unwrap();
        let socket = directory.path().join("agent");
        let soon = || Instant::now() + Duration::from_secs(5);
        assert_eq!(inspect(&socket, soon()), Agent::Dead);
        assert!(!answers(&socket));
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(answers(&socket));
        // Two identities, each a key blob and a comment after the count.
        let mut two = vec![12, 0, 0, 0, 2];
        for _ in 0..2 {
            two.extend_from_slice(&[0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 1, b'c']);
        }
        let cases = [
            (two.clone(), 1, Agent::Identities(2)),
            // The same answer one byte at a time.
            (two, usize::MAX, Agent::Identities(2)),
            (vec![12, 0, 0, 0, 0], 1, Agent::Identities(0)),
            // SSH_AGENT_FAILURE says nothing about the agent's keys.
            (vec![5], 1, Agent::Failed("refused to list its keys")),
            (
                vec![99],
                1,
                Agent::Failed("gave an answer syq could not read"),
            ),
            (
                vec![12, 0],
                1,
                Agent::Failed("gave an answer syq could not read"),
            ),
        ];
        for (reply, pieces, expected) in cases {
            let agent = std::thread::scope(|scope| {
                scope.spawn(|| {
                    serve(
                        &listener,
                        &reply,
                        pieces.min(reply.len() + 4),
                        Duration::ZERO,
                    )
                });
                inspect(&socket, soon())
            });
            assert_eq!(agent, expected, "{reply:?}");
        }

        // An agent that trickles its answer, each piece well within any
        // per-read limit, still gets only until the deadline in all.
        let (agent, took) = std::thread::scope(|scope| {
            scope.spawn(|| serve(&listener, &[12, 0, 0, 0, 0], 9, Duration::from_millis(150)));
            let started = Instant::now();
            let agent = inspect(&socket, started + Duration::from_millis(500));
            (agent, started.elapsed())
        });
        assert_eq!(agent, Agent::Failed("did not list its keys in time"));
        assert!(took < Duration::from_millis(900), "{took:?}");

        // An agent that accepts but never answers is not dead.
        assert_eq!(
            inspect(&socket, Instant::now() + Duration::from_millis(100)),
            Agent::Failed("did not list its keys in time")
        );
        drop(listener);
        // The file stays, but nothing accepts connections there.
        assert_eq!(inspect(&socket, soon()), Agent::Dead);
    }
}
