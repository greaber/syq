use crate::restricted::RestrictedAuthority;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

/// Revoke even if the protocol reader is blocked behind queued metadata work.
/// The authenticated control owns this guard; no worker may prolong its life.
pub(crate) struct ControlLifetime {
    wake: UnixStream,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ControlLifetime {
    pub(crate) fn watch(
        input: &impl AsFd,
        authority: Arc<RestrictedAuthority>,
    ) -> io::Result<Self> {
        let input = input.as_fd().try_clone_to_owned()?;
        let (wake, stopped) = crate::process::with_inheritance_guard(UnixStream::pair)?;
        let watcher = Hangup::new(&input, &stopped)?;
        let thread = std::thread::Builder::new()
            .name("copy-control-lifetime".into())
            .spawn(move || {
                if watcher.wait(&input, &stopped).unwrap_or(true) {
                    authority.close_control();
                }
            })?;
        Ok(Self {
            wake,
            thread: Some(thread),
        })
    }
}

impl Drop for ControlLifetime {
    fn drop(&mut self) {
        let _ = self.wake.shutdown(std::net::Shutdown::Both);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(not(target_os = "macos"))]
struct Hangup;

#[cfg(not(target_os = "macos"))]
impl Hangup {
    fn new(_input: &OwnedFd, _stopped: &UnixStream) -> io::Result<Self> {
        Ok(Self)
    }

    fn wait(&self, input: &OwnedFd, stopped: &UnixStream) -> io::Result<bool> {
        loop {
            let mut descriptors = [
                libc::pollfd {
                    fd: input.as_raw_fd(),
                    events: 0,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stopped.as_raw_fd(),
                    events: 0,
                    revents: 0,
                },
            ];
            let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if descriptors[1].revents != 0 {
                return Ok(false);
            }
            if descriptors[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Ok(true);
            }
        }
    }
}

#[cfg(target_os = "macos")]
struct Hangup(OwnedFd);

#[cfg(target_os = "macos")]
impl Hangup {
    fn new(input: &OwnedFd, stopped: &UnixStream) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        let queue = crate::process::with_inheritance_guard(|| {
            let fd = unsafe { libc::kqueue() };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let queue = unsafe { OwnedFd::from_raw_fd(fd) };
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(queue)
        })?;
        // Darwin poll with events=0 registers no events. Even POLLHUP loses
        // the subscription if unread data arrives first. Persistent EV_CLEAR
        // filters report EOF later without consuming bytes or spinning on them.
        let changes = [input.as_raw_fd(), stopped.as_raw_fd()].map(|fd| libc::kevent {
            ident: fd as _,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        });
        if unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                changes.as_ptr(),
                2,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(queue))
    }

    fn wait(&self, input: &OwnedFd, stopped: &UnixStream) -> io::Result<bool> {
        loop {
            let mut events: [libc::kevent; 2] = unsafe { std::mem::zeroed() };
            let count = unsafe {
                libc::kevent(
                    self.0.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    2,
                    std::ptr::null(),
                )
            };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            let events = &events[..count as usize];
            if events
                .iter()
                .any(|event| event.ident == stopped.as_raw_fd() as libc::uintptr_t)
            {
                return Ok(false);
            }
            if events.iter().any(|event| {
                event.ident == input.as_raw_fd() as libc::uintptr_t
                    && event.flags & (libc::EV_EOF | libc::EV_ERROR) != 0
            }) {
                return Ok(true);
            }
        }
    }
}
