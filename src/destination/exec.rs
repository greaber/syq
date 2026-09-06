//! Individually approved foreground commands over an existing return connection.
use super::*;
use clap::FromArgMatches;
use std::fs::File;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::ExitStatusExt;

const OUTPUT_CHUNK: usize = 16 * 1024;
const MAX_ARG_BYTES: usize = 16 * 1024;

#[derive(Parser)]
#[command(
    name = "syq exec",
    about = "Run a command on a named receiving machine after local approval"
)]
struct ExecCommand {
    /// Receiving name; requires a live return connection (never falls back to SSH)
    #[arg(long, value_name = "@NAME")]
    on: String,
    /// Working directory on that machine, relative to its receiving directory
    #[arg(long, short = 'C', default_value = ".", value_name = "DIR")]
    cwd: OsString,
    /// Program and literal arguments; use sh -c explicitly for shell syntax
    #[arg(last = true, required = true, num_args = 1.., value_name = "PROGRAM")]
    argv: Vec<OsString>,
}

pub(crate) fn command_for_help() -> clap::Command {
    crate::help::configure(ExecCommand::command().bin_name("syq exec"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecRequest {
    pub argv: Vec<Vec<u8>>,
    pub cwd: Vec<u8>,
}
impl ExecRequest {
    fn validate(&self) -> Result<()> {
        if self.argv.is_empty() || self.argv.len() > 256 || self.argv[0].is_empty() {
            bail!("exec requires a program and at most 256 arguments");
        }
        if self.argv.iter().any(|arg| arg.contains(&0))
            || self.argv.iter().map(Vec::len).sum::<usize>() > MAX_ARG_BYTES
        {
            bail!("exec arguments contain NUL or exceed 16 KiB");
        }
        if self.cwd.is_empty() || self.cwd.len() > 4096 || self.cwd.contains(&0) {
            bail!("exec working directory must be nonempty, without NUL, and at most 4096 bytes");
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Event {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited {
        code: Option<i32>,
        signal: Option<i32>,
    },
    // Also accepts errors from the return broker before streaming starts.
    Error(String),
}

pub(crate) fn run(argv: &[OsString]) -> Result<i32> {
    let matches = command_for_help().try_get_matches_from(argv)?;
    let command = ExecCommand::from_arg_matches(&matches)?;
    let name = command.on.strip_prefix('@').unwrap_or(&command.on);
    validate_name(name)?;
    let request = ExecRequest {
        argv: command.argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        cwd: command.cwd.as_bytes().to_vec(),
    };
    request.validate()?;
    let registration = load_registration(name)?;
    crate::output::diagnostic!("syq: requesting command permission from @{name}; approve on that machine with its desktop prompt or syq recv pending");
    let (mut stream, reply) = exchange(
        &registration,
        Message::Exec(request),
        REQUEST_TIMEOUT + Duration::from_secs(10),
    )?;
    if !matches!(reply, Reply::Ready) {
        bail!("unexpected command approval response");
    }
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    receive_output(&mut stream, &mut std::io::stdout(), &mut std::io::stderr())
}

fn receive_output(
    stream: &mut impl Read,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<i32> {
    loop {
        let event: Event = read_message(stream).context(
            "command connection ended without an exit status; the command may have run; it will not be retried",
        )?;
        match event {
            Event::Stdout(bytes) | Event::Stderr(bytes) if bytes.len() > OUTPUT_CHUNK => {
                bail!("oversized command output frame");
            }
            Event::Stdout(bytes) => {
                stdout.write_all(&bytes)?;
                stdout.flush()?;
            }
            Event::Stderr(bytes) => {
                stderr.write_all(&bytes)?;
                stderr.flush()?;
            }
            Event::Exited { code, signal } => match (code, signal) {
                (Some(code @ 0..=255), None) => return Ok(code),
                (None, Some(signal @ 1..=127)) => {
                    crate::output::diagnostic!("syq: command terminated by signal {signal}");
                    return Ok(128 + signal);
                }
                _ => bail!("invalid command exit status"),
            },
            Event::Error(error) => bail!("receiving machine: {error}"),
        }
    }
}

struct Slot<'a>(&'a AtomicU64);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Receiver {
    pub(super) fn execute(&self, request: ExecRequest, mut stream: TrackedStream) -> Result<()> {
        request.validate()?;
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another request is awaiting approval; retry after it is decided")
        })?;
        let count = self.exec_count.fetch_add(1, Ordering::AcqRel);
        let _slot = Slot(&self.exec_count);
        if count >= 8 {
            bail!("too many active commands; wait for one to finish");
        }
        let (generation, _channel) = {
            let _sessions = self.sessions.lock().unwrap();
            (
                self.generation.load(Ordering::Acquire),
                self.active_streams.track(stream.try_clone()?)?,
            )
        };
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
                || requester_closed(&socket)
        };
        let cwd = self.cwd.join(OsString::from_vec(request.cwd.clone()));
        // This is command authority, not the restricted copy executor. Root
        // and copy --approve always do not change a command's permission.
        self.approvals.request_command(
            &self.requester,
            &request.argv,
            &cwd,
            self.notifications,
            cancelled,
        )?;
        if cancelled() {
            bail!("command disconnected before execution");
        }
        drop(request_lock);
        write_message(&mut stream, &Reply::Ready)?;
        let result = execute_command(&request, &cwd, socket.try_clone()?, cancelled);
        if let Err(error) = &result {
            crate::output::diagnostic!("syq: command from {:?}: {error:#}", self.requester);
        }
        result
    }
}

fn nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn execute_command(
    request: &ExecRequest,
    cwd: &Path,
    mut socket: UnixStream,
    cancelled: impl Fn() -> bool,
) -> Result<()> {
    let mut command = Command::new(OsString::from_vec(request.argv[0].clone()));
    command
        .args(
            request.argv[1..]
                .iter()
                .map(|a| OsString::from_vec(a.clone())),
        )
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cancelled() {
        bail!("command disconnected before execution");
    }
    let mut child = crate::process_group::ProcessGroup::spawn(&mut command)
        .context("start approved command")?;
    let mut pipes = [
        Some(unsafe { File::from_raw_fd(child.child.stdout.take().unwrap().into_raw_fd()) }),
        Some(unsafe { File::from_raw_fd(child.child.stderr.take().unwrap().into_raw_fd()) }),
    ];
    for pipe in pipes.iter().flatten() {
        nonblocking(pipe.as_raw_fd())?;
    }
    socket.set_nonblocking(true)?;
    let mut pending = Vec::new();
    let mut offset = 0;
    let mut next_pipe = 0;
    let mut terminal = false;
    loop {
        if cancelled() {
            bail!("command cancelled: requester disconnected or receiving stopped");
        }
        let status = child.poll()?;
        if offset == pending.len() {
            if terminal {
                return Ok(());
            }
            pending.clear();
            offset = 0;
            for index in [next_pipe, 1 - next_pipe] {
                let Some(pipe) = &mut pipes[index] else {
                    continue;
                };
                let mut bytes = vec![0; OUTPUT_CHUNK];
                match pipe.read(&mut bytes) {
                    Ok(0) => pipes[index] = None,
                    Ok(n) => {
                        bytes.truncate(n);
                        write_message(
                            &mut pending,
                            &if index == 0 {
                                Event::Stdout(bytes)
                            } else {
                                Event::Stderr(bytes)
                            },
                        )?;
                        next_pipe = 1 - index;
                        break;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error).context("read command output"),
                }
            }
            if pending.is_empty() && pipes.iter().all(Option::is_none) {
                if let Some(status) = status {
                    write_message(
                        &mut pending,
                        &Event::Exited {
                            code: status.code(),
                            signal: status.signal(),
                        },
                    )?;
                    terminal = true;
                }
            }
        }
        if offset < pending.len() {
            match socket.write(&pending[offset..]) {
                Ok(0) => bail!("command output connection closed"),
                Ok(n) => {
                    offset += n;
                    continue;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error).context("send command output"),
            }
        }
        let mut fds = vec![libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN
                | if offset < pending.len() {
                    libc::POLLOUT
                } else {
                    0
                },
            revents: 0,
        }];
        if offset == pending.len() {
            for pipe in pipes.iter().flatten() {
                fds.push(libc::pollfd {
                    fd: pipe.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
        }
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 100) };
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error()).context("wait for command output");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive_approval::Kind;

    fn request(script: &str) -> ExecRequest {
        ExecRequest {
            argv: vec![b"sh".to_vec(), b"-c".to_vec(), script.as_bytes().to_vec()],
            cwd: b".".to_vec(),
        }
    }
    fn pending(receiver: &Receiver) -> crate::receive_approval::Summary {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(summary) = receiver.approvals.snapshots().first() {
                return summary.clone();
            }
            assert!(Instant::now() < deadline, "command did not become pending");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn wait_finished(receiver: &Receiver) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while receiver.exec_count.load(Ordering::Acquire) != 0 {
            assert!(
                Instant::now() < deadline,
                "command did not release its slot after cancellation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn wait_file(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "command did not create {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn command_permission_is_distinct_from_copy_autoapproval_and_one_use() {
        let root = tempfile::tempdir().unwrap();
        let (_broker, receiver, registration, _) =
            super::super::tests::broker(root.path(), Approval::Always);
        for allow in [false, true] {
            let registration = registration.clone();
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    Message::Exec(request("printf done > marker; printf output; exit 17")),
                    Duration::from_secs(5),
                )
            });
            let summary = pending(&receiver);
            assert_eq!(summary.kind(), Kind::Command);
            let json = serde_json::to_value(&summary).unwrap();
            assert_eq!(json["kind"], "command");
            assert!(json.get("destination").is_none());
            assert!(summary.description().contains("Runs as your local user"));
            assert!(!root.path().join("marker").exists());
            assert!(receiver
                .approvals
                .decide(&summary.id, true, Kind::Copy)
                .is_err());
            receiver
                .approvals
                .decide(&summary.id, allow, Kind::Command)
                .unwrap();
            assert!(receiver
                .approvals
                .decide(&summary.id, allow, Kind::Command)
                .is_err());
            let result = task.join().unwrap();
            if allow {
                let (mut stream, reply) = result.unwrap();
                assert!(matches!(reply, Reply::Ready));
                let mut output = Vec::new();
                assert_eq!(
                    receive_output(&mut stream, &mut output, &mut Vec::new()).unwrap(),
                    17
                );
                assert_eq!(output, b"output");
                assert_eq!(fs::read(root.path().join("marker")).unwrap(), b"done");
            } else {
                assert!(result.is_err());
                assert!(!root.path().join("marker").exists());
            }
        }
    }

    #[test]
    fn pending_command_disconnect_and_revocation_never_spawn() {
        for revoke in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let (_broker, receiver, registration, _) =
                super::super::tests::broker(root.path(), Approval::Always);
            let mut stream = UnixStream::connect(&registration.socket).unwrap();
            write_message(
                &mut stream,
                &Envelope {
                    version: VERSION,
                    identity: crate::identity::build().into(),
                    secret: registration.secret,
                    message: Message::Exec(request("touch marker")),
                },
            )
            .unwrap();
            let summary = pending(&receiver);
            if revoke {
                receiver.revoke_all();
            } else {
                stream.shutdown(std::net::Shutdown::Both).unwrap();
            }
            wait_finished(&receiver);
            assert!(receiver
                .approvals
                .decide(&summary.id, true, Kind::Command)
                .is_err());
            assert!(!root.path().join("marker").exists());
        }
    }

    #[test]
    fn command_cleanup_handles_disconnect_revocation_and_output_backpressure() {
        for mode in 0..3 {
            let root = tempfile::tempdir().unwrap();
            let (_broker, receiver, registration, _) =
                super::super::tests::broker(root.path(), Approval::Always);
            let script = if mode == 2 {
                "echo $$ > leader; (sleep 1; touch survived) & touch ready; exec yes"
            } else {
                "echo $$ > leader; (sleep 1; touch survived) & touch ready; wait"
            };
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    Message::Exec(request(script)),
                    Duration::from_secs(5),
                )
            });
            let summary = pending(&receiver);
            receiver
                .approvals
                .decide(&summary.id, true, Kind::Command)
                .unwrap();
            let (stream, _) = task.join().unwrap().unwrap();
            wait_file(&root.path().join("ready"));
            let leader: i32 = fs::read_to_string(root.path().join("leader"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            if mode == 0 {
                drop(stream);
            } else if mode == 1 {
                receiver.revoke_all();
            } else {
                // Let the socket fill while nobody reads its output.
                std::thread::sleep(Duration::from_millis(150));
                receiver.stop.store(true, Ordering::Release);
            }
            wait_finished(&receiver);
            assert_eq!(
                unsafe { libc::kill(leader, 0) },
                -1,
                "command leader was not reaped"
            );
            std::thread::sleep(Duration::from_millis(1100));
            assert!(
                !root.path().join("survived").exists(),
                "command descendant survived cancellation"
            );
        }
    }

    fn run_direct(request: ExecRequest, cwd: &Path) -> (i32, Vec<u8>, Vec<u8>) {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let cwd = cwd.to_owned();
        let monitor = server.try_clone().unwrap();
        let task = std::thread::spawn(move || {
            execute_command(&request, &cwd, server, || requester_closed(&monitor))
        });
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let status = receive_output(&mut client, &mut stdout, &mut stderr).unwrap();
        task.join().unwrap().unwrap();
        (status, stdout, stderr)
    }

    #[test]
    fn command_preserves_cwd_literal_byte_arguments_and_binary_output() {
        let root = tempfile::tempdir().unwrap();
        let cwd = root.path().join("with spaces");
        fs::create_dir(&cwd).unwrap();
        let mut req = request("pwd -P; printf '%s' \"$1\"; printf '\\000\\377' >&2; exit 17");
        req.argv
            .extend([b"arg0".to_vec(), b"$(touch injected)\n\xff".to_vec()]);
        let (code, output, errors) = run_direct(req, &cwd);
        assert_eq!(code, 17);
        let mut expected = fs::canonicalize(&cwd)
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        expected.extend_from_slice(b"\n$(touch injected)\n\xff");
        assert_eq!(output, expected);
        assert_eq!(errors, [0, 255]);
        assert!(!cwd.join("injected").exists());
    }

    #[test]
    fn relative_program_runs_in_selected_directory_with_closed_stdin() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let program = root.path().join("probe");
        fs::write(
            &program,
            b"#!/bin/sh\nif read -r input; then exit 99; fi\nprintf '%s' \"$1\"\n",
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let request = ExecRequest {
            argv: vec![b"./probe".to_vec(), b"literal value".to_vec()],
            cwd: b".".to_vec(),
        };
        let (status, stdout, stderr) = run_direct(request, root.path());
        assert_eq!(status, 0);
        assert_eq!(stdout, b"literal value");
        assert!(stderr.is_empty());
    }

    #[test]
    fn both_output_streams_are_drained_past_pipe_capacity() {
        let root = tempfile::tempdir().unwrap();
        let (code, stdout, stderr) = run_direct(
            request("head -c 262144 /dev/zero; head -c 262145 /dev/zero >&2"),
            root.path(),
        );
        assert_eq!(code, 0);
        assert_eq!(stdout, vec![0; 262144]);
        assert_eq!(stderr, vec![0; 262145]);
    }

    #[test]
    fn command_status_reports_signal_and_rejects_truncated_output() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(run_direct(request("kill -TERM $$"), root.path()).0, 143);
        let mut bytes = Vec::new();
        write_message(&mut bytes, &Event::Stdout(b"partial".to_vec())).unwrap();
        let mut output = Vec::new();
        let error =
            receive_output(&mut bytes.as_slice(), &mut output, &mut Vec::new()).unwrap_err();
        assert_eq!(output, b"partial");
        assert!(error.to_string().contains("will not be retried"));
    }

    #[test]
    fn malformed_command_is_refused_before_prompting() {
        let root = tempfile::tempdir().unwrap();
        let (_broker, receiver, registration, _) =
            super::super::tests::broker(root.path(), Approval::Always);
        let mut req = request("touch marker");
        req.argv[0].push(0);
        assert!(exchange(&registration, Message::Exec(req), Duration::from_secs(2)).is_err());
        assert!(receiver.approvals.snapshots().is_empty());
        assert!(!root.path().join("marker").exists());
    }
}
