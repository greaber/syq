//! Own a foreground child and kill its process group before reaping its leader.
use crate::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus};

pub(crate) struct ProcessGroup {
    pub child: Child,
    status: Option<ExitStatus>,
}
impl ProcessGroup {
    pub fn spawn(command: &mut Command) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt;
        Ok(Self {
            child: command.process_group(0).spawn_guarded()?,
            status: None,
        })
    }
    /// Let an interactive SSH child read the controlling terminal until its
    /// authentication finishes. The parent regains it before asking for a PIN.
    pub fn foreground(&self) -> std::io::Result<Option<ForegroundTerminal>> {
        use std::os::fd::AsRawFd;
        let terminal = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        {
            Ok(terminal) => terminal,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
                ) =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let previous = unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) };
        if previous != unsafe { libc::getpgrp() } {
            return Ok(None);
        }
        set_terminal_group(terminal.as_raw_fd(), self.child.id() as libc::pid_t)?;
        // A prompt may have attempted a read just before tcsetpgrp and stopped.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGCONT) };
        Ok(Some(ForegroundTerminal { terminal, previous }))
    }
    pub fn close(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        // Nobody else may reap this child. Keeping its PID reserved prevents
        // cleanup from killing an unrelated group after PID reuse.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        let status = self.child.wait()?;
        self.status = Some(status);
        Ok(status)
    }
    /// Give a cancelled command a bounded chance to clean up. Keep the leader
    /// unreaped until close() kills any remaining descendants, as on normal exit.
    pub fn terminate(&mut self, grace: std::time::Duration) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGTERM);
            libc::kill(-(self.child.id() as i32), libc::SIGCONT);
        }
        let deadline = std::time::Instant::now() + grace;
        loop {
            match self.poll() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return self.close();
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
        }
    }
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return self.close();
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    pub fn poll(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if info.si_signo == 0 {
            return Ok(None);
        }
        self.close().map(Some)
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(crate) struct ForegroundTerminal {
    terminal: std::fs::File,
    previous: libc::pid_t,
}

fn set_terminal_group(fd: libc::c_int, group: libc::pid_t) -> std::io::Result<()> {
    // Only this calling thread must suppress SIGTTOU while changing the
    // foreground group; do not replace process-wide signal handlers.
    unsafe {
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        let result = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        let result = libc::tcsetpgrp(fd, group);
        let error = std::io::Error::last_os_error();
        libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        if result < 0 {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl Drop for ForegroundTerminal {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let _ = set_terminal_group(self.terminal.as_raw_fd(), self.previous);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn child(script: &str) -> ProcessGroup {
        let mut command = Command::new("sh");
        command
            .args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = ProcessGroup::spawn(&mut command).unwrap();
        let mut ready = [0; 6];
        let output = child.child.stdout.as_mut().unwrap();
        let mut poll = libc::pollfd {
            fd: output.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut poll, 1, 3000) },
            1,
            "child did not become ready"
        );
        // The fixture emits these six bytes in one pipe write after its trap
        // and child are installed, before blocking in the shell's builtin wait.
        output.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready\n");
        child
    }

    #[test]
    fn graceful_termination_runs_child_cleanup() {
        let mut child =
            child("trap 'printf cleaned; exit 23' TERM; sleep 30 & printf 'ready\n'; wait");
        assert_eq!(
            child.terminate(Duration::from_secs(1)).unwrap().code(),
            Some(23)
        );
        let mut output = String::new();
        child
            .child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        assert_eq!(output, "cleaned");
    }

    #[test]
    fn termination_forces_exit_after_bounded_grace() {
        let mut child = child("trap '' TERM; printf 'ready\n'; while :; do sleep 30; done");
        let started = Instant::now();
        assert_eq!(
            child
                .terminate(Duration::from_millis(100))
                .unwrap()
                .signal(),
            Some(libc::SIGKILL)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
