//! Keep a foreground OpenSSH child and its authorization alive together.
use crate::process::CommandExt as _;
use anyhow::{bail, Context, Result};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct Signals {
    pub(super) received: Arc<AtomicUsize>,
    registrations: Vec<signal_hook::SigId>,
    wake: UnixStream,
}
impl Signals {
    pub(super) fn new() -> std::io::Result<Self> {
        let (wake, sender) = crate::process::with_inheritance_guard(UnixStream::pair)?;
        wake.set_nonblocking(true)?;
        let mut guard = Self {
            received: Arc::new(AtomicUsize::new(0)),
            registrations: Vec::new(),
            wake,
        };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            guard.registrations.push(signal_hook::flag::register_usize(
                signal,
                guard.received.clone(),
                signal as usize,
            )?);
        }
        for signal in [libc::SIGCHLD, libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            guard
                .registrations
                .push(signal_hook::low_level::pipe::register(
                    signal,
                    sender.try_clone()?,
                )?);
        }
        Ok(guard)
    }

    pub(super) fn wait(&self, timeout: Duration) -> std::io::Result<()> {
        let mut descriptor = libc::pollfd {
            fd: self.wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout.as_millis() as i32) };
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
impl Drop for Signals {
    fn drop(&mut self) {
        for registration in &self.registrations {
            signal_hook::low_level::unregister(*registration);
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
    let signals = Signals::new().context("watch SSH session interruption")?;
    if cancelled() {
        bail!("SSH authorization ended before the session started");
    }
    let signal = signals.received.load(Ordering::Acquire) as i32;
    if signal != 0 {
        return Ok(128 + signal);
    }
    let mut child = ForegroundChild::spawn(command, &signals).context("start SSH session")?;
    loop {
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
        // SIGCHLD wakes completed commands immediately; only return-channel
        // revocation relies on the bounded timeout.
        signals.wait(POLL).context("wait for SSH session state")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::process::Stdio;

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
