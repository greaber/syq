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
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};

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
}
