//! Own a foreground child and kill its process group before reaping its leader.
use crate::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus};

pub(crate) struct ProcessGroup {
    pub child: Child,
    status: Option<ExitStatus>,
    /// Whether the child leads its own group, which ending it kills.
    leader: bool,
}
impl ProcessGroup {
    pub fn spawn(command: &mut Command) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt;
        Ok(Self {
            child: command.process_group(0).spawn_guarded()?,
            status: None,
            leader: true,
        })
    }
    /// A child that stays in this process's group, for a process whose own
    /// owner ends that group with everything in it, such as the receiving
    /// service's setup child. It cannot take the terminal.
    pub fn spawn_in_this_group(command: &mut Command) -> std::io::Result<Self> {
        Ok(Self {
            child: command.spawn_guarded()?,
            status: None,
            leader: false,
        })
    }
    /// The target of a signal to the child: its group when it leads one.
    fn target(&self) -> libc::pid_t {
        let pid = self.child.id() as libc::pid_t;
        if self.leader {
            -pid
        } else {
            pid
        }
    }
    /// Let an interactive SSH child read the controlling terminal until its
    /// authentication finishes. The parent regains it before asking for a PIN.
    pub fn foreground(&self) -> std::io::Result<Option<ForegroundTerminal>> {
        use std::os::fd::AsRawFd;
        if !self.leader {
            return Ok(None);
        }
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
        unsafe { libc::kill(self.target(), libc::SIGKILL) };
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
            libc::kill(self.target(), libc::SIGTERM);
            libc::kill(self.target(), libc::SIGCONT);
        }
        // The shell may exit before its children finish their TERM handlers.
        // poll() closes the entire group when that leader exits, so do not call
        // it during the grace period. Keep the PID reserved for the final kill.
        // Cancellation pays this bounded delay; successful exits still use poll.
        std::thread::sleep(grace);
        self.close()
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
    fn a_child_in_this_group_stays_in_it_and_is_killed_alone() {
        let mut command = Command::new("sleep");
        command.arg("30");
        let mut child = ProcessGroup::spawn_in_this_group(&mut command).unwrap();
        let pid = child.child.id() as libc::pid_t;
        assert_eq!(unsafe { libc::getpgid(pid) }, unsafe { libc::getpgrp() });
        assert!(child.foreground().unwrap().is_none());
        let started = Instant::now();
        let status = child.close().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(started.elapsed() < Duration::from_secs(5));
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
    fn descendants_keep_the_grace_period_after_the_shell_exits() {
        // The outer shell dies immediately on TERM. Its child must still get
        // time to run a cleanup handler before the group is forcibly closed.
        let mut child = child(
            r#"sh -c 'trap "sleep 0.1; printf cleaned; exit 0" TERM; sleep 30 & printf "ready\n"; wait' & wait"#,
        );
        child.terminate(Duration::from_secs(1)).unwrap();
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
