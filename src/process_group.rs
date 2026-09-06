//! Own a foreground child and kill its process group before reaping its leader.
use std::process::{Child, Command, ExitStatus};

pub(crate) struct ProcessGroup {
    pub child: Child,
    status: Option<ExitStatus>,
}
impl ProcessGroup {
    pub fn spawn(command: &mut Command) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt;
        Ok(Self {
            child: command.process_group(0).spawn()?,
            status: None,
        })
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
