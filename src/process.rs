//! Coordinate process creation and bounded policy-inspection subprocesses.
use std::process::{Child, Command, ExitStatus, Output, Stdio};

/// Serialize non-atomic close-on-exec setup with child launches on Darwin.
/// The operation must only create/protect descriptors or launch a process;
/// do not hold this guard while waiting for peer I/O or child completion.
pub(crate) fn with_inheritance_guard<T>(operation: impl FnOnce() -> T) -> T {
    #[cfg(target_os = "macos")]
    let _guard = {
        static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        SPAWN.lock().unwrap_or_else(|error| error.into_inner())
    };
    operation()
}

pub(crate) trait CommandExt {
    fn spawn_guarded(&mut self) -> std::io::Result<Child>;
    fn status_guarded(&mut self) -> std::io::Result<ExitStatus>;
    /// Capture both outputs with null stdin. For custom stdio, configure it
    /// explicitly and use spawn_guarded followed by wait_with_output instead.
    fn capture_output(&mut self) -> std::io::Result<Output>;
}

impl CommandExt for Command {
    fn spawn_guarded(&mut self) -> std::io::Result<Child> {
        with_inheritance_guard(|| self.spawn())
    }

    fn status_guarded(&mut self) -> std::io::Result<ExitStatus> {
        self.spawn_guarded()?.wait()
    }

    fn capture_output(&mut self) -> std::io::Result<Output> {
        self.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_guarded()?
            .wait_with_output()
    }
}

/// Run an inspection command under one deadline, including descendants that
/// retain its output pipes. Neither output nor cancellation needs a reader
/// thread whose lifetime can outlast the command's process group.
pub(crate) fn capture_output_bounded(
    command: &mut Command,
    deadline: std::time::Instant,
    cancelled: &dyn Fn() -> bool,
    max_output_bytes: usize,
) -> std::io::Result<Output> {
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, RawFd};
    use std::time::{Duration, Instant};

    fn check(deadline: Instant, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
        if cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "SSH policy inspection cancelled",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "SSH policy inspection timed out",
            ));
        }
        Ok(())
    }
    fn nonblocking(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn drain(
        reader: &mut impl Read,
        output: &mut Vec<u8>,
        total: &mut usize,
        limit: usize,
    ) -> io::Result<bool> {
        let mut buffer = [0; 16 * 1024];
        match reader.read(&mut buffer) {
            Ok(0) => Ok(true),
            Ok(count) => {
                if count > limit.saturating_sub(*total) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSH policy inspection output exceeds its byte limit",
                    ));
                }
                *total += count;
                output.extend_from_slice(&buffer[..count]);
                Ok(false)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    check(deadline, cancelled)?;
    let mut group = crate::process_group::ProcessGroup::spawn(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )?;
    let mut stdout = group.child.stdout.take().unwrap();
    let mut stderr = group.child.stderr.take().unwrap();
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (mut out_done, mut err_done) = (false, false);
    let mut total = 0;
    loop {
        check(deadline, cancelled)?;
        if !out_done {
            out_done = drain(&mut stdout, &mut out, &mut total, max_output_bytes)?;
        }
        if !err_done {
            err_done = drain(&mut stderr, &mut err, &mut total, max_output_bytes)?;
        }
        // Keep the leader unreaped until its descendants have closed the
        // pipes, then let ProcessGroup stop remaining descendants before
        // reaping. The process-group identifier stays reserved until cleanup.
        if out_done && err_done {
            match group.poll() {
                Ok(Some(status)) => {
                    return Ok(Output {
                        status,
                        stdout: out,
                        stderr: err,
                    });
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        let mut descriptors = [
            libc::pollfd {
                fd: if out_done { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if err_done { -1 } else { stderr.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20))
            .as_millis() as i32;
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                timeout,
            )
        };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt as _;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn descriptor_creation_excludes_child_launch() {
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let (child, _pipes) = with_inheritance_guard(|| {
            // Model the interval between pipe() and fcntl(FD_CLOEXEC).
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let pipes = fds.map(|fd| unsafe { std::fs::File::from_raw_fd(fd) });
            let child = std::thread::spawn(move || {
                let mut command = Command::new("/usr/bin/true");
                unsafe {
                    command.pre_exec(move || {
                        for fd in fds {
                            if libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC == 0 {
                                return Err(std::io::Error::from_raw_os_error(libc::EBADF));
                            }
                        }
                        Ok(())
                    });
                }
                started_tx.send(()).unwrap();
                let result = command.spawn_guarded();
                finished_tx.send(result.is_ok()).unwrap();
                result.unwrap().wait().unwrap()
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let blocked = finished_rx.recv_timeout(Duration::from_millis(100));
            for fd in fds {
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                    0
                );
            }
            assert_eq!(blocked, Err(mpsc::RecvTimeoutError::Timeout));
            (child, pipes)
        });
        assert!(finished_rx.recv_timeout(Duration::from_secs(5)).unwrap());
        assert!(child.join().unwrap().success());
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn capture(
        script: &str,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
        limit: usize,
    ) -> std::io::Result<Output> {
        capture_output_bounded(
            Command::new("sh").args(["-c", script]),
            Instant::now() + timeout,
            cancelled,
            limit,
        )
    }

    #[test]
    fn captures_both_outputs_and_exit_status() {
        let output = capture(
            "printf output; printf error >&2; exit 17",
            Duration::from_secs(5),
            &|| false,
            64,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(17));
        assert_eq!(output.stdout, b"output");
        assert_eq!(output.stderr, b"error");
    }

    #[test]
    fn deadline_kills_descendant_holding_output_after_parent_exits() {
        let directory = crate::test_support::tempdir().unwrap();
        let pidfile = directory.path().join("descendant");
        let script = format!(
            "sleep 30 & echo $! > {}; exit 0",
            shell_words::quote(pidfile.to_str().unwrap())
        );
        let error = capture(&script, Duration::from_millis(150), &|| false, 1024).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let pid: libc::pid_t = std::fs::read_to_string(pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_descendant_stopped(pid);
    }

    #[test]
    fn normal_completion_stops_descendant_without_output_pipes() {
        let output = capture(
            "sleep 30 </dev/null >/dev/null 2>&1 & echo $!; exit 17",
            Duration::from_secs(5),
            &|| false,
            1024,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(17));
        let pid = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_descendant_stopped(pid);
    }

    fn assert_descendant_stopped(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if unsafe { libc::kill(pid, 0) } != 0 {
                break;
            }
            // A container's PID 1 may defer reaping an adopted zombie. It has
            // already exited and cannot retain pipes or execute Match exec.
            #[cfg(target_os = "linux")]
            if std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, fields)| fields.starts_with("Z "))
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "inspection descendant survived process-group cleanup"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn cancellation_interrupts_a_stalled_process() {
        let started = Instant::now();
        let error = capture(
            "exec sleep 30",
            Duration::from_secs(10),
            &|| started.elapsed() >= Duration::from_millis(100),
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn output_limit_stops_a_continuously_writing_process() {
        let error = capture(
            "while :; do printf 0123456789abcdef; done",
            Duration::from_secs(5),
            &|| false,
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("byte limit"));
    }
}
