//! Coordinate process creation, not process lifetime.
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
