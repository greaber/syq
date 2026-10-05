//! Shared helpers for unit tests.

use crate::process::CommandExt as _;
#[path = "../tests/support/temp.rs"]
mod temporary;
pub(crate) use temporary::{short_tempdir, temp_dir, tempdir};
#[path = "../tests/support/executable.rs"]
mod executable;
pub(crate) use executable::{copy_executable, write_executable};

/// Run a unit test in a separate process whose stderr reader has gone away.
/// Keep stdout available for the test harness and assertion diagnostics.
pub(crate) fn with_broken_stderr(name: &str) -> bool {
    if std::env::var("SYQ_TEST_BROKEN_STDERR").as_deref() == Ok(name) {
        return true;
    }
    let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(reader);
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("SYQ_TEST_BROKEN_STDERR", name)
        .stderr(std::process::Stdio::from(std::os::fd::OwnedFd::from(
            writer,
        )))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn_guarded()
        .and_then(|child| child.wait_with_output())
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    false
}

/// Whether the temporary filesystem accepts file names that are not valid
/// UTF-8. APFS on macOS rejects them with `EILSEQ`, so tests that exercise raw
/// byte names have nothing to test there.
pub(crate) fn filesystem_accepts_non_utf8_names() -> bool {
    use std::os::unix::ffi::OsStringExt;
    let name =
        std::ffi::OsString::from_vec(format!("syq-probe-{}-", std::process::id()).into_bytes());
    let mut name = name;
    name.push(std::ffi::OsString::from_vec(vec![0xff]));
    let path = temp_dir().join(name);
    match std::fs::File::create(&path) {
        Ok(_) => {
            let _ = std::fs::remove_file(&path);
            true
        }
        Err(_) => false,
    }
}

/// The ordinary confined source registration: each path is its own root, no
/// root symlink is followed, and only `independent_handoff_workers` varies.
pub(crate) fn register_source_roots<P: AsRef<std::path::Path>>(
    paths: &[P],
    independent_handoff_workers: usize,
) -> crate::proto::Request {
    use std::os::unix::ffi::OsStrExt;
    crate::proto::Request::RegisterSourceRoots {
        base: crate::proto::SourceRootBase::default(),
        selections: paths
            .iter()
            .map(|path| crate::proto::SourceRootSelection {
                path: path.as_ref().as_os_str().as_bytes().to_vec(),
                follow_root: false,
            })
            .collect(),
        symlink_policy: crate::proto::OperatorSymlinkPolicy::Refuse,
        allow_unconfined_paths: false,
        shared_workers: 0,
        independent_handoff_workers,
    }
}

/// Drain a Unix stream to EOF within a fixed deadline, without changing socket
/// options or shared descriptor flags. The peer may already have closed it.
pub(crate) fn read_until_closed(
    stream: &std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    use std::os::fd::AsRawFd;
    use std::time::Instant;
    let deadline = Instant::now() + timeout;
    let mut output = Vec::new();
    let mut bytes = [0u8; 4096];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::TimedOut,
                    "peer did not close before the deadline",
                )
            })?;
        // Per-call nonblocking reads preserve the flags of any socket clones.
        let count = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if count == 0 {
            return Ok(output);
        }
        if count > 0 {
            output.extend_from_slice(&bytes[..count as usize]);
            continue;
        }
        let error = Error::last_os_error();
        match error.kind() {
            ErrorKind::Interrupted => continue,
            ErrorKind::WouldBlock => {}
            _ => return Err(error),
        }
        let mut ready = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining.as_millis().max(1).min(libc::c_int::MAX as u128) as libc::c_int;
        if unsafe { libc::poll(&mut ready, 1, millis) } < 0 {
            let error = Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[test]
fn closed_socket_wait_preserves_buffered_bytes_and_socket_settings() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    let (client, mut peer) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let flags = unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFL) };
    peer.write_all(b"buffered reply").unwrap();
    drop(peer);
    assert_eq!(
        read_until_closed(&client, Duration::from_secs(1)).unwrap(),
        b"buffered reply"
    );
    assert_eq!(client.read_timeout().unwrap(), Some(Duration::from_secs(3)));
    assert_eq!(
        unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFL) },
        flags
    );
}

/// Executable fixtures must never be open for writing in this process: a
/// child that another test forks meanwhile keeps that descriptor until it
/// execs, and running the fixture then fails with "Text file busy". Writing
/// to a FIFO keeps the writer open mid-write, so any writer this process
/// holds shows up among its descriptors.
#[cfg(target_os = "linux")]
#[test]
fn executable_fixtures_are_never_open_for_writing_in_this_process() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let root = tempdir().unwrap();
    // More than a FIFO buffers, so the writer stays blocked until drained.
    let contents = vec![b'#'; 1 << 20];
    let source = root.path().join("source");
    std::fs::write(&source, &contents).unwrap();
    let inode = |metadata: std::fs::Metadata| (metadata.dev(), metadata.ino());
    for copy in [false, true] {
        let fifo = root.path().join(if copy { "copied" } else { "written" });
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let fifo_inode = inode(std::fs::metadata(&fifo).unwrap());
        // Open the reader first so the writer's open does not wait for it.
        let mut reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                if copy {
                    copy_executable(&source, &fifo, 0o700);
                } else {
                    write_executable(&fifo, &contents, 0o700);
                }
            });
            let mut ready = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let started = unsafe { libc::poll(&mut ready, 1, 10_000) } == 1;
            let held: Vec<i32> = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
                .filter(|&fd| {
                    fd != reader.as_raw_fd()
                        && std::fs::metadata(format!("/proc/self/fd/{fd}"))
                            .is_ok_and(|metadata| inode(metadata) == fifo_inode)
                })
                .collect();
            // Drain in blocking mode until the writer closes, so it finishes
            // even when this test fails. Without a writer, this reads EOF.
            assert_eq!(
                unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, 0) },
                0
            );
            let mut received = Vec::new();
            reader.read_to_end(&mut received).unwrap();
            writer.join().unwrap();
            assert!(started, "the fixture writer did not start");
            assert!(held.is_empty(), "this process held the fixture as {held:?}");
            assert_eq!(received.len(), contents.len());
        });
    }
}

#[test]
fn closed_socket_wait_times_out_while_peer_stays_open() {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;
    let (client, _peer) = UnixStream::pair().unwrap();
    assert_eq!(
        read_until_closed(&client, Duration::from_millis(20))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(client.read_timeout().unwrap(), None);
}
