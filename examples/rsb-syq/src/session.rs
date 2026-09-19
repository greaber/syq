//! A small client for the version-1 syq stream-mapping subprocess protocol.
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::{
    ffi::OsString,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

type Work = dyn Fn(&mut File) -> Result<()> + Send + Sync;
pub struct Entry {
    pub path: String,
    pub upload: bool,
    pub work: Box<Work>,
}
pub struct Client {
    pub executable: OsString,
    pub options: Vec<OsString>,
    pub jobs: usize,
}
#[derive(Default, Debug)]
pub struct Stats {
    pub bytes: u64,
    pub skipped: u64,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Control {
    Hello { version: u64 },
    Start { entry: usize, direction: String },
    Transferred { entry: usize, error: Option<String> },
    End,
}
#[derive(Deserialize)]
struct Record {
    schema: String,
    schema_version: u64,
    seq: u64,
    #[serde(flatten)]
    event: Event,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Event {
    StreamResult {
        entry: usize,
        disposition: String,
        message: Option<String>,
    },
    Result {
        status: String,
        exit_code: i32,
        bytes_transferred: u64,
        files_excluded: u64,
    },
    #[serde(other)]
    Other,
}

fn results(input: impl Read, count: usize) -> Result<Stats> {
    let mut input = BufReader::new(input);
    let mut line = String::new();
    let mut sequence = 0;
    let mut seen = vec![false; count];
    let mut terminal = None;
    let mut failure = None;
    while input.read_line(&mut line)? != 0 {
        ensure!(terminal.is_none(), "result after terminal record");
        let record: Record =
            serde_json::from_str(&line).with_context(|| format!("invalid result: {line}"))?;
        ensure!(
            record.schema == "syq.automation"
                && record.schema_version == 3
                && record.seq == sequence,
            "unsupported or incomplete syq results"
        );
        sequence += 1;
        match record.event {
            Event::StreamResult {
                entry,
                disposition,
                message,
            } => {
                if disposition == "failed" && failure.is_none() {
                    failure = Some(format!(
                        "entry {entry}: {}",
                        message.as_deref().unwrap_or("transfer failed")
                    ));
                }
                ensure!(entry < count && !seen[entry], "unexpected stream result");
                ensure!(
                    ["succeeded", "failed", "skipped", "planned"].contains(&disposition.as_str()),
                    "unexpected stream disposition"
                );
                seen[entry] = true;
            }
            Event::Result {
                status,
                exit_code,
                bytes_transferred,
                files_excluded,
            } => {
                terminal = Some((
                    status,
                    exit_code,
                    Stats {
                        bytes: bytes_transferred,
                        skipped: files_excluded,
                    },
                ));
            }
            Event::Other => {}
        }
        line.clear();
    }
    let (status, code, stats) = terminal.context("syq omitted its terminal result")?;
    ensure!(
        status == "success" && code == 0,
        "syq reported {status} (exit {code}): {}",
        failure.as_deref().unwrap_or("see syq diagnostics")
    );
    ensure!(seen.iter().all(|v| *v), "syq omitted an entry result");
    Ok(stats)
}

#[allow(clippy::disallowed_methods)] // This standalone caller intentionally launches syq.
impl Client {
    pub fn run(&self, entries: &[Entry], options: &[OsString]) -> Result<Stats> {
        ensure!(
            self.jobs > 0 && self.jobs <= 256,
            "jobs must be between 1 and 256"
        );
        if entries.is_empty() {
            return Ok(Stats::default());
        }
        let mut manifest = tempfile::NamedTempFile::new()?;
        for (index, entry) in entries.iter().enumerate() {
            let path = json!({"encoding":"utf-8", "value":entry.path});
            let stream = json!({"stream":index});
            let (src, dst) = if entry.upload {
                (stream, path)
            } else {
                (path, stream)
            };
            serde_json::to_writer(&mut manifest, &json!({"src":src,"dst":dst}))?;
            manifest.write_all(b"\n")?;
        }
        manifest.flush()?;
        let (mut channel, child_channel) = UnixStream::pair()?;
        let control_fd = child_channel.as_raw_fd();
        let (results_input, results_output) = UnixStream::pair()?;
        let results_fd = results_output.as_raw_fd();
        let mut command = Command::new(&self.executable);
        command
            .args(["cp", "--mapping"])
            .arg(manifest.path())
            .arg(format!("--stream-mapping-fd={control_fd}"))
            .arg(format!("--stream-concurrency={}", self.jobs))
            .arg(format!("--results-fd={results_fd}"))
            .args(&self.options)
            .args(options)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .process_group(0);
        // Only the control and results sockets survive exec. This closure does no allocation or locking.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(control_fd, libc::F_SETFD, 0) < 0
                    || libc::fcntl(results_fd, libc::F_SETFD, 0) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let _signals = Signals::new(cancelled.clone())?;
        let mut child = command.spawn().context("start syq")?;
        drop(child_channel);
        drop(results_output);
        let pid = child.id() as i32;
        let finished = Arc::new(AtomicBool::new(false));
        let error = Mutex::new(None::<String>);

        let outcome = thread::scope(|scope| -> Result<Stats> {
            let reader = scope.spawn(|| {
                let result = results(results_input, entries.len());
                if result.is_err() {
                    cancelled.store(true, Relaxed);
                }
                result
            });
            scope.spawn(|| {
                let mut deadline = None;
                while !finished.load(Relaxed) {
                    if cancelled.load(Relaxed) {
                        if deadline.is_none() {
                            unsafe {
                                libc::kill(pid, libc::SIGTERM);
                            }
                            deadline = Some(Instant::now() + Duration::from_secs(6));
                        }
                        if deadline.is_some_and(|at| Instant::now() >= at) {
                            unsafe {
                                libc::kill(-pid, libc::SIGKILL);
                            }
                            break;
                        }
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            });
            let control = (|| -> Result<()> {
                let (hello, fds) = receive(&mut channel)?;
                ensure!(
                    matches!(hello, Control::Hello { version: 1 }) && fds.is_empty(),
                    "unsupported syq stream protocol"
                );
                let hello = b"{\"version\":1}";
                channel.write_all(b"S")?;
                channel.write_all(&(hello.len() as u32).to_be_bytes())?;
                channel.write_all(hello)?;
                let mut started = vec![false; entries.len()];
                let mut transferred = vec![false; entries.len()];
                let mut workers = Vec::<thread::ScopedJoinHandle<'_, ()>>::new();
                loop {
                    let (message, mut fds) = receive(&mut channel)?;
                    match message {
                        Control::Start { entry, direction } => {
                            ensure!(
                                entry < entries.len() && !started[entry] && fds.len() == 2,
                                "invalid stream admission"
                            );
                            let job = &entries[entry];
                            ensure!(
                                direction == if job.upload { "produce" } else { "consume" },
                                "wrong stream direction"
                            );
                            let mut index = 0;
                            while index < workers.len() {
                                if workers[index].is_finished() {
                                    let _ = workers.swap_remove(index).join();
                                } else {
                                    index += 1;
                                }
                            }
                            started[entry] = true;
                            let mut commit = fds.pop().unwrap();
                            let mut payload = fds.pop().unwrap();
                            let cancelled = &cancelled;
                            let error = &error;
                            workers.push(scope.spawn(move || {
                                let result = std::panic::catch_unwind(
                                    std::panic::AssertUnwindSafe(|| -> Result<()> {
                                        (job.work)(&mut payload)?;
                                        if !job.upload {
                                            std::io::copy(&mut payload, &mut std::io::sink())?;
                                        }
                                        drop(payload);
                                        commit.write_all(b"C")?;
                                        Ok(())
                                    }),
                                )
                                .unwrap_or_else(|_| {
                                    Err(anyhow::anyhow!("archive worker panicked"))
                                });
                                if let Err(cause) = result {
                                    let mut error = error.lock().unwrap();
                                    if error.is_none() {
                                        *error = Some(format!("entry {entry}: {cause:#}"));
                                    }
                                    cancelled.store(true, Relaxed);
                                }
                            }));
                        }
                        Control::Transferred {
                            entry,
                            error: failure,
                        } => {
                            ensure!(
                                fds.is_empty()
                                    && entry < entries.len()
                                    && started[entry]
                                    && !transferred[entry],
                                "invalid transfer completion"
                            );
                            transferred[entry] = true;
                            if let Some(failure) = failure {
                                let mut error = error.lock().unwrap();
                                if error.is_none() {
                                    *error = Some(failure);
                                }
                                cancelled.store(true, Relaxed);
                            }
                        }
                        Control::End => {
                            ensure!(fds.is_empty(), "descriptors attached to end");
                            break;
                        }
                        Control::Hello { .. } => bail!("duplicate stream handshake"),
                    }
                }
                for worker in workers {
                    let _ = worker.join();
                }
                Ok(())
            })();
            if control.is_err() {
                cancelled.store(true, Relaxed);
            }
            let status = child.wait();
            finished.store(true, Relaxed);
            let records = reader
                .join()
                .map_err(|_| anyhow::anyhow!("result reader panicked"))?;
            if let Some(error) = error.lock().unwrap().take() {
                bail!("{error}");
            }
            control?;
            let stats = records?;
            ensure!(!cancelled.load(Relaxed), "copy cancelled");
            ensure!(status?.success(), "syq failed");
            Ok(stats)
        });

        if outcome.is_err() {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        outcome
    }
}

fn receive(channel: &mut UnixStream) -> Result<(Control, Vec<File>)> {
    // An aligned ancillary buffer, large enough to detect unexpected extra FDs.
    let mut ancillary = [0usize; 32];
    let mut marker = [0u8; 1];
    let mut iovec = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&ancillary) as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    loop {
        let count = unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, flags) };
        if count > 0 {
            break;
        }
        if count == 0 {
            bail!("syq closed its control connection");
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    let mut fds = Vec::new();
    let mut malformed = message.msg_flags & libc::MSG_CTRUNC != 0;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level != libc::SOL_SOCKET || (*header).cmsg_type != libc::SCM_RIGHTS {
                malformed = true;
            } else {
                let bytes =
                    ((*header).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                malformed |= !bytes.is_multiple_of(std::mem::size_of::<i32>());
                for index in 0..bytes / std::mem::size_of::<i32>() {
                    let fd =
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(index));
                    let file = File::from_raw_fd(fd);
                    if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                        malformed = true;
                    }
                    fds.push(file);
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    ensure!(
        !malformed && marker == *b"S",
        "invalid stream control frame"
    );
    let mut length = [0; 4];
    channel.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        length > 0 && length <= 65536,
        "invalid control frame length"
    );
    let mut body = vec![0; length];
    channel.read_exact(&mut body)?;
    Ok((serde_json::from_slice(&body)?, fds))
}

// Register before spawning, and undo even a partially successful registration.
struct Signals(Vec<signal_hook::SigId>);
impl Signals {
    fn new(cancelled: Arc<AtomicBool>) -> Result<Self> {
        let mut signals = Self(Vec::new());
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            signals
                .0
                .push(signal_hook::flag::register(signal, cancelled.clone())?);
        }
        Ok(signals)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}
