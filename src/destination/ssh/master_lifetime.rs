//! Kernel-owned lifetime for a background native SSH master.
//!
//! Only the keeper owns the PTY master descriptor. Closing it, including on
//! SIGKILL, sends SIGHUP to SSH's private session. The PTY carries no SSH data:
//! native SSH still owns the TCP connection and the multiplexed client streams.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

pub(super) struct Lifetime {
    _master: OwnedFd,
}

#[cfg(target_os = "linux")]
fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    // Linux's spawn guard deliberately has no lock, so both descriptors need
    // CLOEXEC at creation rather than a later fcntl after openpty.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master < 0 {
        return Err(io::Error::last_os_error());
    }
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    if unsafe { libc::grantpt(master.as_raw_fd()) } < 0
        || unsafe { libc::unlockpt(master.as_raw_fd()) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut path = [0 as libc::c_char; libc::PATH_MAX as usize];
    let result = unsafe { libc::ptsname_r(master.as_raw_fd(), path.as_mut_ptr(), path.len()) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result));
    }
    let slave = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if slave < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((master, unsafe { OwnedFd::from_raw_fd(slave) }))
}

#[cfg(not(target_os = "linux"))]
fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (mut master, mut slave) = (-1, -1);
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty returned two distinct owned descriptors. On Darwin the
    // caller holds the process inheritance guard until CLOEXEC is installed.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    for descriptor in [&master, &slave] {
        if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((master, slave))
}

pub(super) fn attach(command: &mut Command) -> io::Result<Lifetime> {
    let (master, slave) = crate::process::with_inheritance_guard(|| -> io::Result<_> {
        let (master, slave) = pair()?;
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(slave.as_raw_fd(), termios.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut termios = unsafe { termios.assume_init() };
        // Darwin's line discipline sends HUP on carrier loss unless CLOCAL or
        // modem-buffer flow control requests different behavior.
        termios.c_cflag &= !libc::CLOCAL;
        #[cfg(target_os = "macos")]
        {
            termios.c_cflag &= !libc::MDMBUF;
        }
        if unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &termios) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((master, slave))
    })?;
    command.stdin(Stdio::from(slave));
    // SAFETY: only async-signal-safe libc operations run between fork and exec.
    // The child receives the PTY slave as fd 0 before this hook runs.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0
                || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0
                || libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgrp()) < 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGHUP, &action, std::ptr::null_mut()) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut signals = std::mem::zeroed();
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGHUP);
            if libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(Lifetime { _master: master })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::CommandExt as _;
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};

    #[test]
    fn closing_the_only_master_descriptor_hangs_up_the_owned_session() {
        let mut command = Command::new("sleep");
        command
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let lifetime = attach(&mut command).unwrap();
        let mut child = command.spawn_guarded().unwrap();
        assert_eq!(
            unsafe { libc::getsid(child.id() as i32) },
            child.id() as i32
        );
        assert_eq!(
            unsafe { libc::getpgid(child.id() as i32) },
            child.id() as i32
        );
        drop(lifetime);
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("closing the owner descriptor did not stop its session");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGHUP));
    }
}
