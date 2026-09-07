//! Active receiver shutdown. The grant holder cannot modify enrollment state.
//!
//! Receivers hold shared leases and terminate themselves on revocation. The
//! revoker waits for an exclusive lease, so successful revocation confirms that
//! their processes have stopped without identifying or signalling a numeric PID.

use super::{atomic_write, lock_directory, open_directory};
use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

const CHECK_INTERVAL: Duration = Duration::from_millis(100);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn require_not_revoked(state: &Path) -> Result<()> {
    match fs::symlink_metadata(state.join("revoked")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect receiver revocation state"),
        Ok(_) => {
            bail!("receiver enrollment is revoked; finish receiver revoke before enrolling again")
        }
    }
}

pub(super) fn open_leases(state: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(state.join("active-receivers"))
        .context("open active receiver leases")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
    {
        bail!("active receiver leases must be a private, singly linked regular file");
    }
    Ok(file)
}

fn try_lock(file: &File, operation: libc::c_int) -> Result<bool> {
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(false),
            _ => return Err(error).context("lock active receiver leases"),
        }
    }
}

/// Start the standalone receiver's watcher. Its lease lives in the watcher
/// thread until process exit, including while the main thread reports a server
/// error or any admitted worker finishes. Dropping it when `serve` returns
/// would let revocation report success while worker threads could still write.
pub(super) fn watch(
    home: &Path,
    state: &Path,
    expected: (u64, u64),
    deadline: Instant,
) -> Result<()> {
    let lifecycle = open_directory(&home.join(".ssh"))?;
    lock_directory(&lifecycle)?;
    crate::delegation::validate_private_directory_path(state)?;
    let directory = open_directory(state)?;
    let metadata = directory.metadata()?;
    if (metadata.dev(), metadata.ino()) != expected {
        bail!("receiver enrollment changed during grant verification");
    }
    require_not_revoked(state)?;
    let lease = open_leases(state)?;
    if !try_lock(&lease, libc::LOCK_SH)? {
        bail!("receiver enrollment is being revoked");
    }
    // Include any helper child (such as interface discovery) in shutdown,
    // without sharing a process group with sshd or another receiver.
    if unsafe { libc::getpgrp() } != unsafe { libc::getpid() }
        && unsafe { libc::setpgid(0, 0) } != 0
    {
        return Err(io::Error::last_os_error()).context("isolate receiver process group");
    }
    let state = state.to_path_buf();
    std::thread::Builder::new()
        .name("receiver-revocation".into())
        .spawn(move || {
            let _lease = lease;
            // Pin the enrollment inode even if an older revoke removes it.
            let _directory = directory;
            loop {
                // Also notice an older revoke command removing the enrollment.
                let unchanged = fs::symlink_metadata(&state)
                    .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == expected);
                if !unchanged || require_not_revoked(&state).is_err() || Instant::now() >= deadline
                {
                    // Do not write to peer-controlled output before stopping: a
                    // full SSH pipe must not prevent revocation. This process
                    // only runs the restricted receiver and its worker threads.
                    unsafe {
                        libc::kill(0, libc::SIGKILL);
                        libc::_exit(1);
                    }
                }
                std::thread::sleep(
                    CHECK_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        })
        .context("start receiver revocation watcher")?;
    Ok(())
}

/// Caller holds the SSH directory lifecycle lock until state removal finishes.
/// Leave the marker and credentials' local bookkeeping intact on failure so a
/// retry can finish revocation; never reopen admission after a partial failure.
pub(super) fn revoke(state: &Path, leases: &File) -> Result<()> {
    atomic_write(state, "revoked", b"revoked\n", 0o600)?;
    wait_for_receivers(leases, SHUTDOWN_TIMEOUT)
}

fn wait_for_receivers(leases: &File, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut next_progress = Instant::now() + Duration::from_secs(1);
    loop {
        if try_lock(leases, libc::LOCK_EX)? {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            bail!("receiver enrollment is revoked but active receivers have not stopped; retry receiver revoke (last state: active receiver leases are still held)");
        }
        if now >= next_progress {
            crate::output::diagnostic!("syq: waiting for revoked receivers to stop");
            next_progress = now + Duration::from_secs(1);
        }
        std::thread::sleep(CHECK_INTERVAL.min(deadline - now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, ExitStatus, Stdio};

    struct Worker(Child);
    impl Drop for Worker {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                unsafe {
                    libc::kill(-(self.0.id() as i32), libc::SIGKILL);
                }
                let _ = self.0.wait();
            }
        }
    }

    fn private_dir(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn identity(path: &Path) -> (u64, u64) {
        let metadata = fs::metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    }

    fn wait_until(label: &str, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut progress = Instant::now();
        while !ready() {
            assert!(
                Instant::now() < deadline,
                "{label}: deadline expired; condition still false"
            );
            if Instant::now() >= progress {
                eprintln!("waiting for {label}");
                progress = Instant::now() + Duration::from_secs(1);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn worker(home: &Path, state: &Path, name: &str, mode: &str) -> Worker {
        let ready = home.join(format!("ready-{name}"));
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restricted::active::tests::receiver_process",
                "--nocapture",
            ])
            .env("SYQ_TEST_ACTIVE_HOME", home)
            .env("SYQ_TEST_ACTIVE_STATE", state)
            .env("SYQ_TEST_ACTIVE_READY", &ready)
            .env("SYQ_TEST_ACTIVE_MODE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut child = Worker(child);
        wait_until("receiver readiness", || {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "receiver exited before readiness"
            );
            ready.exists()
        });
        child
    }

    fn exited(child: &mut Worker) -> ExitStatus {
        let mut status = None;
        wait_until("receiver exit", || {
            status = child.0.try_wait().unwrap();
            status.is_some()
        });
        status.unwrap()
    }

    #[test]
    fn receiver_process() {
        let Some(home) = std::env::var_os("SYQ_TEST_ACTIVE_HOME") else {
            return;
        };
        let home = Path::new(&home);
        let state = std::env::var_os("SYQ_TEST_ACTIVE_STATE").unwrap();
        let state = Path::new(&state);
        let ready = std::env::var_os("SYQ_TEST_ACTIVE_READY").unwrap();
        let mode = std::env::var("SYQ_TEST_ACTIVE_MODE").unwrap();
        let expected = identity(state);
        if mode == "verification" {
            fs::write(&ready, b"verifying").unwrap();
            std::io::stdin().read_exact(&mut [0]).unwrap();
        }
        let result = watch(
            home,
            state,
            expected,
            Instant::now() + Duration::from_secs(30),
        );
        if mode == "verification" {
            assert!(result.is_err(), "revoked verification admitted a receiver");
            return;
        }
        result.unwrap();
        fs::write(&ready, b"ready").unwrap();
        if mode == "normal" {
            return;
        }
        // The revocation watcher must stop the entire process even when its
        // main thread is blocked on a source that will not read its output.
        std::io::stdout()
            .write_all(&vec![b'x'; 2 * 1024 * 1024])
            .unwrap();
        panic!("test output pipe unexpectedly accepted all bytes");
    }

    #[test]
    fn revoke_stops_all_receivers_of_only_that_enrollment() {
        let temporary = crate::test_support::tempdir().unwrap();
        let home = temporary.path();
        private_dir(&home.join(".ssh"));
        let state = home.join("enrollment");
        let other = home.join("other-enrollment");
        private_dir(&state);
        private_dir(&other);
        let mut first = worker(home, &state, "first", "blocked");
        let mut second = worker(home, &state, "second", "blocked");
        let mut unrelated = worker(home, &other, "unrelated", "blocked");
        let leases = open_leases(&state).unwrap();
        assert!(!try_lock(&leases, libc::LOCK_EX).unwrap());
        revoke(&state, &leases).unwrap();
        assert!(!exited(&mut first).success());
        assert!(!exited(&mut second).success());
        assert!(unrelated.0.try_wait().unwrap().is_none());
        assert!(watch(
            home,
            &state,
            identity(&state),
            Instant::now() + Duration::from_secs(30)
        )
        .is_err());
        let other_leases = open_leases(&other).unwrap();
        revoke(&other, &other_leases).unwrap();
        assert!(!exited(&mut unrelated).success());
    }

    #[test]
    fn revocation_during_verification_prevents_admission() {
        let temporary = crate::test_support::tempdir().unwrap();
        let home = temporary.path();
        private_dir(&home.join(".ssh"));
        let state = home.join("enrollment");
        private_dir(&state);
        let mut child = worker(home, &state, "verifying", "verification");
        let leases = open_leases(&state).unwrap();
        revoke(&state, &leases).unwrap();
        child.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        assert!(exited(&mut child).success());
    }

    #[test]
    fn enrollment_replacement_prevents_admission() {
        let temporary = crate::test_support::tempdir().unwrap();
        let home = temporary.path();
        private_dir(&home.join(".ssh"));
        let state = home.join("enrollment");
        private_dir(&state);
        let mut child = worker(home, &state, "verifying", "verification");
        fs::rename(&state, home.join("old-enrollment")).unwrap();
        private_dir(&state);
        child.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        assert!(exited(&mut child).success());
    }

    #[test]
    fn older_revoke_removing_state_also_stops_new_receivers() {
        let temporary = crate::test_support::tempdir().unwrap();
        let home = temporary.path();
        private_dir(&home.join(".ssh"));
        let state = home.join("enrollment");
        private_dir(&state);
        let mut child = worker(home, &state, "old-revoke", "blocked");
        fs::remove_dir_all(&state).unwrap();
        private_dir(&state);
        assert!(!exited(&mut child).success());
    }

    #[test]
    fn normal_receiver_exit_releases_its_lease() {
        let temporary = crate::test_support::tempdir().unwrap();
        let home = temporary.path();
        private_dir(&home.join(".ssh"));
        let state = home.join("enrollment");
        private_dir(&state);
        // No readiness poll: this receiver can finish before the parent runs.
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restricted::active::tests::receiver_process",
                "--nocapture",
            ])
            .env("SYQ_TEST_ACTIVE_HOME", home)
            .env("SYQ_TEST_ACTIVE_STATE", &state)
            .env("SYQ_TEST_ACTIVE_READY", home.join("ready-normal"))
            .env("SYQ_TEST_ACTIVE_MODE", "normal")
            .process_group(0)
            .spawn()
            .map(Worker)
            .unwrap();
        assert!(exited(&mut child).success());
        revoke(&state, &open_leases(&state).unwrap()).unwrap();
    }

    #[test]
    fn shutdown_timeout_keeps_admission_closed_and_allows_retry() {
        let temporary = crate::test_support::tempdir().unwrap();
        let state_path = temporary.path().join("enrollment");
        private_dir(&state_path);
        let state = state_path.as_path();
        let held = open_leases(state).unwrap();
        assert!(try_lock(&held, libc::LOCK_SH).unwrap());
        let leases = open_leases(state).unwrap();
        atomic_write(state, "revoked", b"revoked\n", 0o600).unwrap();
        let error = wait_for_receivers(&leases, Duration::from_millis(20)).unwrap_err();
        assert!(error
            .to_string()
            .contains("active receiver leases are still held"));
        assert!(require_not_revoked(state).is_err());
        drop(held);
        revoke(state, &leases).unwrap();
    }

    #[test]
    fn lease_file_rejects_symlinks_and_hardlinks() {
        let temporary = crate::test_support::tempdir().unwrap();
        let state = temporary.path();
        let outside = state.join("outside");
        fs::write(&outside, b"sentinel").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        let leases = state.join("active-receivers");
        std::os::unix::fs::symlink(&outside, &leases).unwrap();
        assert!(open_leases(state).is_err());
        fs::remove_file(&leases).unwrap();
        fs::hard_link(&outside, &leases).unwrap();
        assert!(open_leases(state).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"sentinel");
    }
}
