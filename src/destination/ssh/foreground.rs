//! Keep a foreground OpenSSH child and its authorization alive together.
use crate::process::CommandExt as _;
use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ChildStderr, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

pub(in crate::destination) struct Signals {
    pub(in crate::destination) received: Arc<AtomicUsize>,
    _registrations: crate::process::signals::Owned<crate::process::signals::Registrations>,
    wake: UnixStream,
}
impl Signals {
    pub(in crate::destination) fn new() -> std::io::Result<Self> {
        let (wake, sender) = crate::process::with_inheritance_guard(UnixStream::pair)?;
        wake.set_nonblocking(true)?;
        let received = Arc::new(AtomicUsize::new(0));
        let mut termination = vec![libc::SIGINT, libc::SIGTERM];
        if !crate::process::signals::inherited_hangup_is_ignored()? {
            termination.push(libc::SIGHUP);
        }
        let registrations = crate::process::signals::owned(&termination, || {
            let mut registrations = crate::process::signals::Registrations::default();
            for signal in termination.iter().copied() {
                registrations.push(signal_hook::flag::register_usize(
                    signal,
                    received.clone(),
                    signal as usize,
                )?);
            }
            for signal in std::iter::once(libc::SIGCHLD).chain(termination.iter().copied()) {
                registrations.push(signal_hook::low_level::pipe::register(
                    signal,
                    sender.try_clone()?,
                )?);
            }
            Ok(registrations)
        })?;
        let guard = Self {
            received,
            _registrations: registrations,
            wake,
        };
        Ok(guard)
    }

    pub(in crate::destination) fn wait(&self, timeout: Duration) -> std::io::Result<()> {
        self.wait_readable(timeout, None)
    }

    fn wait_readable(&self, timeout: Duration, stderr: Option<RawFd>) -> std::io::Result<()> {
        let mut descriptors = [
            libc::pollfd {
                fd: self.wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, timeout.as_millis() as i32) };
        if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error());
        }
        let mut wake = &self.wake;
        loop {
            match wake.read(&mut [0; 128]) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) struct ForegroundChild<'a> {
    child: Child,
    status: Option<ExitStatus>,
    signals: &'a Signals,
}
impl<'a> ForegroundChild<'a> {
    pub(super) fn spawn(command: &mut Command, signals: &'a Signals) -> std::io::Result<Self> {
        Ok(Self {
            child: command.spawn_guarded()?,
            status: None,
            signals,
        })
    }

    pub(super) fn poll(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }

    fn follow_terminal_stop(&self) -> std::io::Result<()> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // Consume only a stop notification; Child remains the sole owner of
        // exit/reaping. OpenSSH's ~^Z stops its own PID, not the whole job.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id() as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WNOHANG,
            )
        } < 0
        {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(error)
            };
        }
        if info.si_signo != 0 {
            // Once both wrapper and SSH are stopped, the invoking shell can
            // reclaim its terminal. On fg/bg it normally resumes the group;
            // also resume SSH if only this wrapper received SIGCONT.
            if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if unsafe { libc::kill(self.child.id() as i32, libc::SIGCONT) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub(super) fn stop(&mut self, signal: i32) -> std::io::Result<()> {
        if self.poll()?.is_some() {
            return Ok(());
        }
        // Unlike ProcessGroup, retain the foreground terminal's process
        // group. This SSH command disables proxy/local commands, forwarding,
        // and background masters, so the owned child is the SSH client itself.
        // Its PID remains reserved until this guard reaps it.
        unsafe { libc::kill(self.child.id() as i32, signal) };
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            if self.poll()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.child.kill()?;
                self.status = Some(self.child.wait()?);
                return Ok(());
            }
            self.signals.wait(POLL)?;
        }
    }
}
impl Drop for ForegroundChild<'_> {
    fn drop(&mut self) {
        let _ = self.stop(libc::SIGTERM);
    }
}

pub(super) fn run(command: &mut Command, cancelled: impl Fn() -> bool) -> Result<i32> {
    run_inner(command, cancelled, None)
}

pub(super) fn run_cached(command: &mut Command, cancelled: impl Fn() -> bool) -> Result<i32> {
    let mut stderr = std::io::stderr();
    if stderr.is_terminal() {
        return run(command, cancelled);
    }
    run_inner(command, cancelled, Some(&mut stderr))
}

struct StderrRelay(ChildStderr);
impl StderrRelay {
    fn new(stderr: ChildStderr) -> std::io::Result<Self> {
        let flags = unsafe { libc::fcntl(stderr.as_raw_fd(), libc::F_GETFL) };
        if flags == -1
            || unsafe { libc::fcntl(stderr.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                == -1
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(stderr))
    }

    fn drain(&mut self, output: &mut dyn Write, mut limit: usize) -> std::io::Result<bool> {
        let mut buffer = [0; 16 * 1024];
        while limit != 0 {
            let count = limit.min(buffer.len());
            match self.0.read(&mut buffer[..count]) {
                Ok(0) => return Ok(true),
                Ok(count) => {
                    output.write_all(&buffer[..count])?;
                    limit -= count;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(false)
    }

    fn finish(&mut self, output: &mut dyn Write) -> std::io::Result<()> {
        // A mux master can retain stderr after its client exits, including
        // after interruption. Flush bytes already queued without waiting for
        // that independent process to close its descriptor or finish writing.
        let mut queued: libc::c_int = 0;
        if unsafe { libc::ioctl(self.0.as_raw_fd(), libc::FIONREAD, &mut queued) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        self.drain(output, queued.max(0) as usize)?;
        Ok(())
    }
}

fn run_inner(
    command: &mut Command,
    cancelled: impl Fn() -> bool,
    mut stderr: Option<&mut dyn Write>,
) -> Result<i32> {
    let signals = Signals::new().context("watch SSH session interruption")?;
    if cancelled() {
        bail!("SSH authorization ended before the session started");
    }
    let signal = signals.received.load(Ordering::Acquire) as i32;
    if signal != 0 {
        return Ok(128 + signal);
    }
    // OpenSSH passes these descriptors to its persistent master. Keep a
    // redirected caller's stderr private so an interrupted mux session cannot
    // hold an outer SSH command or pipeline open. Terminal descriptors remain
    // inherited, preserving OpenSSH's terminal behavior.
    if stderr.is_some() {
        command.stderr(Stdio::piped());
    }
    let mut child = ForegroundChild::spawn(command, &signals).context("start SSH session")?;
    let mut relay = if stderr.is_some() {
        child
            .child
            .stderr
            .take()
            .map(StderrRelay::new)
            .transpose()?
    } else {
        None
    };
    let result = (|| loop {
        if let (Some(pipe), Some(output)) = (&mut relay, &mut stderr) {
            if pipe
                .drain(*output, 16 * 1024)
                .context("forward SSH stderr")?
            {
                relay = None;
            }
        }
        if let Some(status) = child.poll().context("wait for SSH session")? {
            return Ok(status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)));
        }
        let signal = signals.received.load(Ordering::Acquire) as i32;
        if signal != 0 {
            child.stop(signal).context("stop interrupted SSH session")?;
            return Ok(128 + signal);
        }
        if cancelled() {
            child
                .stop(libc::SIGTERM)
                .context("stop revoked SSH session")?;
            bail!("SSH authorization was revoked or its receiving connection ended");
        }
        child
            .follow_terminal_stop()
            .context("follow SSH terminal suspension")?;
        // SIGCHLD wakes completed commands immediately; only return-channel
        // revocation relies on the bounded timeout.
        signals
            .wait_readable(POLL, relay.as_ref().map(|relay| relay.0.as_raw_fd()))
            .context("wait for SSH session state")?;
    })();
    if let (Some(relay), Some(output)) = (&mut relay, &mut stderr) {
        relay.finish(*output).context("finish SSH stderr")?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::process::Stdio;

    const SUBPROCESS: &str = "SYQ_TEST_FOREGROUND_SIGNAL";
    const SUBPROCESS_TEST: &str = "destination::ssh::foreground::tests::signal_subprocess";

    fn subprocess(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", SUBPROCESS_TEST, "--nocapture"])
            .env(SUBPROCESS, mode);
        command
    }

    #[test]
    fn signal_subprocess() {
        let Ok(mode) = std::env::var(SUBPROCESS) else {
            return;
        };
        match mode.as_str() {
            "nohup" => {
                let mut command = Command::new("sh");
                command.args(["-c", "kill -HUP $PPID; kill -HUP $$; exit 17"]);
                assert_eq!(run(&mut command, || false).unwrap(), 17);
                assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
            }
            "terminal-child" => {
                assert_eq!(unsafe { libc::isatty(libc::STDIN_FILENO) }, 1);
                assert_eq!(unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) }, unsafe {
                    libc::getpgrp()
                });
                // This is the same self-directed stop as OpenSSH's ~^Z.
                assert_eq!(unsafe { libc::raise(libc::SIGTSTP) }, 0);
            }
            "terminal-wrapper" => {
                let deadline = Instant::now() + Duration::from_secs(3);
                while unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) != libc::getpgrp() } {
                    assert!(
                        Instant::now() < deadline,
                        "driver never selected the wrapper foreground group"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(run(&mut subprocess("terminal-child"), || false).unwrap(), 0);
            }
            "terminal-driver" => {
                use std::os::unix::process::CommandExt as _;
                let mut command = subprocess("terminal-wrapper");
                command.stdout(Stdio::null()).stderr(Stdio::inherit());
                unsafe {
                    command.pre_exec(|| {
                        if libc::signal(libc::SIGTSTP, libc::SIG_DFL) == libc::SIG_ERR {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let mut wrapper = crate::process::group::ProcessGroup::spawn(&mut command).unwrap();
                let pid = wrapper.child.id() as i32;
                fs::write(
                    std::env::var("SYQ_TEST_FOREGROUND_PID").unwrap(),
                    pid.to_string(),
                )
                .unwrap();
                assert_eq!(unsafe { libc::tcsetpgrp(libc::STDIN_FILENO, pid) }, 0);
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                    assert_eq!(
                        unsafe {
                            libc::waitid(
                                libc::P_PID,
                                pid as libc::id_t,
                                &mut info,
                                libc::WSTOPPED | libc::WNOHANG,
                            )
                        },
                        0
                    );
                    if info.si_signo != 0 {
                        break;
                    }
                    assert!(
                        wrapper.poll().unwrap().is_none(),
                        "foreground wrapper exited without suspending"
                    );
                    assert!(
                        Instant::now() < deadline,
                        "wrapper did not suspend after its SSH child stopped"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(unsafe { libc::kill(-pid, libc::SIGCONT) }, 0);
                loop {
                    if let Some(status) = wrapper.poll().unwrap() {
                        assert!(status.success(), "resumed wrapper failed: {status}");
                        break;
                    }
                    assert!(Instant::now() < deadline, "resumed wrapper did not finish");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            _ => panic!("unknown foreground signal fixture"),
        }
    }

    #[test]
    fn nohup_preserves_ignored_hangup_during_foreground_ownership_and_exec() {
        let mut command = Command::new("nohup");
        command
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", SUBPROCESS_TEST, "--nocapture"])
            .env(SUBPROCESS, "nohup");
        let output = crate::process::capture_output_bounded(
            &mut command,
            Instant::now() + Duration::from_secs(5),
            &|| false,
            64 * 1024,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "status={}, stdout={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn terminal_child_suspension_stops_and_resumes_the_foreground_wrapper() {
        let root = crate::test_support::tempdir().unwrap();
        let pid_path = root.path().join("wrapper-pid");
        let mut command = subprocess("terminal-driver");
        command
            .env("SYQ_TEST_FOREGROUND_PID", &pid_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let lifetime = super::super::master_lifetime::attach(&mut command).unwrap();
        let mut driver = command.spawn_guarded().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = driver.try_wait().unwrap() {
                assert!(status.success(), "terminal driver failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                // Dispose of the separately owned foreground group before its
                // session leader on a fixture failure, including stopped jobs.
                if let Ok(pid) = fs::read_to_string(&pid_path)
                    .and_then(|s| s.parse::<i32>().map_err(std::io::Error::other))
                {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
                driver.kill().unwrap();
                driver.wait().unwrap();
                panic!("terminal suspension driver timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(lifetime);
    }

    #[test]
    fn binary_input_eof_outputs_and_exit_status_reach_the_native_child() {
        let root = crate::test_support::tempdir().unwrap();
        let input = root.path().join("input");
        let stdout = root.path().join("stdout");
        let stderr = root.path().join("stderr");
        let bytes = [0, 255, b'\n', b'x'];
        fs::write(&input, bytes).unwrap();
        let mut command = Command::new("sh");
        command
            .args(["-c", "cat; printf error >&2; exit 23"])
            .stdin(Stdio::from(File::open(input).unwrap()))
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()));
        assert_eq!(run(&mut command, || false).unwrap(), 23);
        assert_eq!(fs::read(stdout).unwrap(), bytes);
        assert_eq!(fs::read(stderr).unwrap(), b"error");
    }

    #[test]
    fn cached_stderr_preserves_large_binary_output_and_exit_status() {
        let root = crate::test_support::tempdir().unwrap();
        let bytes: Vec<u8> = (0..1024 * 1024).map(|index| index as u8).collect();
        fs::write(root.path().join("input"), &bytes).unwrap();
        let mut command = Command::new("sh");
        command
            .args(["-c", "cat input >&2; exit 17"])
            .current_dir(root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        let mut output = Vec::new();
        assert_eq!(
            run_inner(&mut command, || false, Some(&mut output)).unwrap(),
            17
        );
        assert_eq!(output, bytes);
    }

    #[test]
    fn cached_stderr_does_not_wait_for_an_independent_writer_after_child_exit() {
        let root = crate::test_support::tempdir().unwrap();
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                "sleep 30 >&2 & echo $! > writer; printf error >&2; exit 17",
            ])
            .current_dir(root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        let mut output = Vec::new();
        let started = Instant::now();
        let result = run_inner(&mut command, || false, Some(&mut output));
        let elapsed = started.elapsed();
        let writer: i32 = fs::read_to_string(root.path().join("writer"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // The independent writer models the mux master retaining stderr.
        // Dispose of it even when one of the assertions below fails.
        unsafe { libc::kill(writer, libc::SIGKILL) };
        assert_eq!(result.unwrap(), 17);
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert_eq!(output, b"error");
    }

    #[test]
    fn revocation_terminates_and_reaps_the_child() {
        let root = crate::test_support::tempdir().unwrap();
        let marker = root.path().join("pid");
        let mut command = Command::new("sh");
        command
            .args(["-c", "echo $$ > pid; exec sleep 30"])
            .current_dir(root.path());
        let started = Instant::now();
        let error = run(&mut command, || marker.exists()).unwrap_err();
        assert!(error.to_string().contains("revoked"));
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid: i32 = fs::read_to_string(marker).unwrap().trim().parse().unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn already_revoked_authorization_never_starts_a_command() {
        let root = crate::test_support::tempdir().unwrap();
        let mut command = Command::new("sh");
        command
            .args(["-c", "touch started"])
            .current_dir(root.path());
        assert!(run(&mut command, || true).is_err());
        assert!(!root.path().join("started").exists());
    }

    #[test]
    fn foreground_group_and_signal_status_are_preserved() {
        let expected = unsafe { libc::getpgrp() };
        let mut command = Command::new("sh");
        use std::os::unix::process::CommandExt as _;
        unsafe {
            command.pre_exec(move || {
                if libc::getpgrp() != expected {
                    return Err(std::io::Error::other(
                        "child lost the foreground process group",
                    ));
                }
                Ok(())
            });
        }
        command.args(["-c", "kill -TERM $$"]);
        assert_eq!(run(&mut command, || false).unwrap(), 128 + libc::SIGTERM);
    }
}
