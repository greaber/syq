//! Interrupt the transports owned by one coordinated copy.
//!
//! Registration and cancellation share a lock, so a connection opened during
//! cancellation is interrupted too. Child registrations stay live until the
//! child is reaped under the registration lock: a concurrent cancel can never
//! signal a PID which has been recycled. Only commands we start in their own
//! process group are registered. Persistent SSH masters belong to their
//! persistence scope, not to this cancellation group.

use std::io::{self, Read};
use std::net::{Shutdown, TcpStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

#[derive(Debug, Default)]
pub(crate) struct Cancellation {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct State {
    cancelled: bool,
    resources: Vec<Weak<Mutex<Option<Resource>>>>,
}

#[derive(Debug)]
enum Resource {
    ProcessGroup(u32),
    Socket(TcpStream),
}

impl Resource {
    fn interrupt(&self) {
        match self {
            Self::ProcessGroup(pid) => {
                // The registration lock excludes reaping this child, so its
                // PID still reserves the group identity even if it has exited.
                // spawn() made it the leader of a new process group.
                unsafe { libc::kill(-(*pid as libc::pid_t), libc::SIGKILL) };
            }
            Self::Socket(socket) => {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct Registration(Arc<Mutex<Option<Resource>>>);

impl Drop for Registration {
    fn drop(&mut self) {
        self.0.lock().unwrap().take();
    }
}

impl Cancellation {
    pub(crate) fn check(&self) -> io::Result<()> {
        if self.state.lock().unwrap().cancelled {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "copy cancelled because another destination failed",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn cancel(&self) {
        let resources = {
            let mut state = self.state.lock().unwrap();
            state.cancelled = true;
            self.changed.notify_all();
            std::mem::take(&mut state.resources)
        };
        for resource in resources.into_iter().filter_map(|entry| entry.upgrade()) {
            if let Some(resource) = resource.lock().unwrap().as_ref() {
                resource.interrupt();
            }
        }
    }

    pub(crate) fn sleep(&self, duration: Duration) -> io::Result<()> {
        let state = self.state.lock().unwrap();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, duration, |state| !state.cancelled)
            .unwrap();
        let cancelled = state.cancelled;
        drop(state);
        if cancelled {
            self.check()
        } else {
            Ok(())
        }
    }

    fn register(&self, resource: Resource) -> Registration {
        Self::register_locked(&mut self.state.lock().unwrap(), resource)
    }

    fn register_locked(state: &mut State, resource: Resource) -> Registration {
        let resource = Arc::new(Mutex::new(Some(resource)));
        if state.cancelled {
            resource.lock().unwrap().as_ref().unwrap().interrupt();
        } else {
            state.resources.retain(|entry| entry.strong_count() != 0);
            state.resources.push(Arc::downgrade(&resource));
        }
        Registration(resource)
    }

    pub(crate) fn socket(&self, socket: &TcpStream) -> io::Result<Registration> {
        Ok(self.register(Resource::Socket(socket.try_clone()?)))
    }
}

pub(crate) struct TrackedChild {
    child: Child,
    registration: Option<Registration>,
}

impl std::ops::Deref for TrackedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for TrackedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl From<Child> for TrackedChild {
    fn from(child: Child) -> Self {
        Self {
            child,
            registration: None,
        }
    }
}

pub(crate) fn spawn(
    command: &mut Command,
    cancellation: Option<&Arc<Cancellation>>,
) -> io::Result<TrackedChild> {
    // Hold the state lock across spawn and registration. In particular, the
    // signal cleanup thread must not finish cancelling and exit our process
    // while an unregistered child is being created in its own process group.
    let mut state = cancellation.map(|token| token.state.lock().unwrap());
    if let Some(state) = &state {
        if state.cancelled {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "copy cancelled"));
        }
        command.process_group(0);
    }
    let child = command.spawn()?;
    let registration = state
        .as_mut()
        .map(|state| Cancellation::register_locked(state, Resource::ProcessGroup(child.id())));
    Ok(TrackedChild {
        child,
        registration,
    })
}

pub(crate) fn output(
    command: &mut Command,
    cancellation: Option<&Arc<Cancellation>>,
) -> io::Result<Output> {
    if cancellation.is_none() {
        return command.output();
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn(command, cancellation)?.wait_with_output()
}

impl TrackedChild {
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let mut resource = self
            .registration
            .as_ref()
            .map(|entry| entry.0.lock().unwrap());
        if let Some(Some(owned)) = resource.as_ref().map(|entry| entry.as_ref()) {
            // Observe exit without reaping. Descendants may still hold our
            // pipes; stop them while the leader's PID still owns the group.
            // SAFETY: waitid initializes this valid siginfo_t and WNOWAIT
            // leaves our Child's wait status available to std::process.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: waitid returned successfully with the WEXITED selector.
            if unsafe { info.si_pid() } == 0 {
                return Ok(None);
            }
            owned.interrupt();
        }
        let status = self.child.try_wait()?;
        if status.is_some() {
            if let Some(resource) = &mut resource {
                resource.take();
            }
        }
        Ok(status)
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        if self.registration.is_none() {
            return self.child.wait();
        }
        // Do not hold the registration lock in waitpid: cancellation needs
        // that lock to kill the still-owned process group and wake this wait.
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn terminate(&mut self) {
        if let Some(registration) = &self.registration {
            if let Some(resource) = registration.0.lock().unwrap().as_ref() {
                resource.interrupt();
            }
        }
    }

    pub(crate) fn finish(&mut self) {
        // The protocol has already settled; close the owned SSH session and
        // any children before reaping its leader. Waiting for an unresponsive
        // helper here would delay publishing a member's failure to the group.
        self.terminate();
        let _ = self.wait();
    }

    pub(crate) fn wait_with_output(mut self) -> io::Result<Output> {
        drop(self.child.stdin.take());
        let stdout = self.child.stdout.take();
        let stderr = self.child.stderr.take();
        std::thread::scope(|scope| {
            let read = |pipe: Option<Box<dyn Read + Send>>| -> io::Result<Vec<u8>> {
                let mut bytes = Vec::new();
                if let Some(mut pipe) = pipe {
                    pipe.read_to_end(&mut bytes)?;
                }
                Ok(bytes)
            };
            let out = scope.spawn(move || read(stdout.map(|pipe| Box::new(pipe) as _)));
            let err = scope.spawn(move || read(stderr.map(|pipe| Box::new(pipe) as _)));
            // Keep the process registration (and its unreaped PID) alive
            // until descendants have closed the pipes too.
            let stdout = out.join().expect("stdout reader panicked")?;
            let stderr = err.join().expect("stderr reader panicked")?;
            Ok(Output {
                status: self.wait()?,
                stdout,
                stderr,
            })
        })
    }
}

impl Drop for TrackedChild {
    fn drop(&mut self) {
        if self.registration.is_some() {
            self.terminate();
            let _ = self.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    #[test]
    fn cancellation_interrupts_a_blocked_tcp_read_and_late_registration() {
        let token = Cancellation::default();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let _registration = token.socket(&client).unwrap();
        std::thread::scope(|scope| {
            let read = scope.spawn(|| client.read(&mut [0]));
            token.cancel();
            assert_eq!(read.join().unwrap().unwrap(), 0);
        });
        let mut late = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_late_server, _) = listener.accept().unwrap();
        let _registration = token.socket(&late).unwrap();
        assert!(late.write_all(b"cancelled").is_err());
    }

    #[test]
    fn cancellation_keeps_ownership_until_descendants_close_output() {
        let token = Arc::new(Cancellation::default());
        let mut command = Command::new("sh");
        // The leader exits while its child holds stdout. The token must still
        // be able to kill that child and release wait_with_output.
        command
            .args(["-c", "printf 'ready\\n'; sleep 30 &"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = spawn(&mut command, Some(&token)).unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        token.cancel();
        let mut rest = Vec::new();
        stdout.read_to_end(&mut rest).unwrap();
        child.wait().unwrap();
        assert!(token.check().is_err());
    }

    #[test]
    fn reaping_an_exited_leader_closes_its_descendants_first() {
        let token = Arc::new(Cancellation::default());
        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30 & exit 42"])
            .stdout(Stdio::piped());
        let mut child = spawn(&mut command, Some(&token)).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(42));
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn cancelled_group_refuses_new_commands_and_wakes_backoff() {
        let token = Arc::new(Cancellation::default());
        let waiter = {
            let token = token.clone();
            std::thread::spawn(move || token.sleep(Duration::from_secs(30)))
        };
        token.cancel();
        assert!(waiter.join().unwrap().is_err());
        assert!(spawn(&mut Command::new("sh"), Some(&token)).is_err());
    }
}
