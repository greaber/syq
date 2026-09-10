//! One approved control stream through the receiving machine; data goes to the
//! destination's restricted TCP workers. There is no remote signing interface.
use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::AtomicUsize;

const HELPER_VERSION: u16 = 1;
const SETUP_TIMEOUT: Duration = Duration::from_secs(60);
const FINISH_TIMEOUT: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperRequest {
    version: u16,
    identity: String,
    request: CopyRequest,
}

fn target_endpoint(target: &str) -> Result<crate::cli::NativeEndpoint> {
    if target.len() > 512 {
        bail!("destination SSH endpoint is too long");
    }
    let endpoint = crate::cli::parse_native_endpoint(Some(target))?.unwrap();
    // These values also enter the user's OpenSSH configuration substitutions.
    // Only endpoint text is accepted, never shell or SSH option syntax.
    if endpoint.host.starts_with('-')
        || !endpoint
            .host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))
        || endpoint.user.as_ref().is_some_and(|user| {
            user.starts_with('-')
                || !user
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        bail!("--auth-from requires an ordinary SSH destination with a plain host and login name");
    }
    Ok(endpoint)
}

fn eligible_target(args: &crate::cli::Args) -> Result<String> {
    use crate::cli::{CoordinateAt, Interface, PeerAuth};
    let (destination, sources) = args
        .locations
        .split_last()
        .context("copy endpoints missing")?;
    if args.interface != Interface::NativeCp
        || sources.iter().any(|s| s.is_remote())
        || !destination.is_remote()
    {
        bail!("--auth-from requires syq cp with local sources and an SSH --to destination");
    }
    if args.rsh.is_some()
        || args.syq_path.is_some()
        || args.no_bootstrap
        || args.pscope_explicit
        || args.detach
        || args.restricted_grant.is_some()
        || args.no_tcp
        || args.tcp_plain
        || args.peer_auth != PeerAuth::Restricted
        || args.coordinate_at != CoordinateAt::Auto
    {
        bail!("return authorization owns its SSH connection and requires encrypted direct TCP; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --pscope, --detach, --no-tcp, --tcp-plain, --peer-auth, or --coordinate-at");
    }
    if args.connections_opt.is_some() && args.connections > 32 {
        bail!("return authorization supports at most 32 workers per copy");
    }
    if args.owner || args.group || args.devices || args.inplace {
        bail!("return authorization does not accept ownership, special-file preservation, or --inplace");
    }
    crate::restricted::validate_restricted_args(args)?;
    let target = crate::remote_to_remote::endpoint_arg(destination, None, None);
    target_endpoint(&target)?;
    Ok(target)
}

pub(super) fn select(args: &crate::cli::Args) -> Result<Option<handoff::Selection>> {
    let explicit = match &args.auth_from {
        crate::cli::AuthFrom::Return(name) => Some(name.clone()),
        _ => handoff::selected_name(handoff::Kind::Forward).map(str::to_owned),
    };
    let target = match eligible_target(args) {
        Ok(target) => target,
        Err(_) if explicit.is_none() => return Ok(None),
        Err(error) => return Err(error),
    };
    if explicit.is_none() && args.locations.last().unwrap().path.starts_with(b"~//") {
        // Ordinary SSH interprets ~// as absolute. Do not change the copy's
        // destination just because a return authorizer became available.
        return Ok(None);
    }
    let (name, registration) = if let Some(name) = explicit {
        let registration = load_registration(&name)?;
        (name, registration)
    } else {
        let Some(found) = registered_names().into_iter().find_map(|name| {
            let registration = available(&name, Duration::from_secs(2)).ok()?;
            Some((name, registration))
        }) else {
            return Ok(None);
        };
        found
    };
    Ok(Some(handoff::Selection::new(
        name,
        registration,
        handoff::Kind::Forward,
        Some(target),
    )))
}

pub(super) fn prepare(args: &mut crate::cli::Args, selection: handoff::Selection) -> Result<()> {
    let handoff::Selection {
        name,
        registration,
        target,
        ..
    } = selection;
    let target = target.context("remote authorization target missing")?;
    let (secret, public) = crate::receipt::generate_recipient()?;
    let policy = crate::receipt::ReceiptPolicy {
        required: true,
        hashed: args.receiver_receipt == Some(crate::cli::ReceiptDetail::Digests),
        max_records: crate::receipt::DEFAULT_MAX_RECORDS,
        max_plaintext_bytes: crate::receipt::DEFAULT_MAX_PLAINTEXT_BYTES,
        delivery: crate::receipt::ReceiptDelivery::AttachedEncrypted {
            suite: crate::receipt::HpkeSuite::X25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            recipient_public_key: public,
        },
    };
    let request = crate::restricted::named_request(args, policy.clone())?;
    crate::output::diagnostic!("syq: requesting permission from @{name} to copy to {target:?}; approve on that machine with its desktop prompt or syq persist receive pending");
    let (stream, reply) = exchange(
        &registration,
        Message::Forward {
            target,
            request: Box::new(request),
        },
        REQUEST_TIMEOUT + SETUP_TIMEOUT + Duration::from_secs(10),
    )?;
    if args.verbose > 0 {
        crate::output::diagnostic!("syq: remote copy approved; opening its control connection");
    }
    let Reply::Approved(approved) = reply else {
        bail!("unexpected remote copy approval response");
    };
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.auth_from = crate::cli::AuthFrom::Return(name);
    // The actual authority never leaves the destination helper. This internal
    // marker makes the engine require TCP and suppress ordinary SSH fallback.
    args.restricted_grant = Some("return-control-v1".into());
    args.named_receipt = Some(Arc::new(NamedReceipt {
        control: Mutex::new(Some(stream)),
        secret,
        approved,
        policy,
    }));
    Ok(())
}

struct Slot<'a>(&'a AtomicUsize);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Receiver {
    pub(super) fn forward(
        &self,
        target: String,
        request: CopyRequest,
        mut stream: TrackedStream,
    ) -> Result<()> {
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        target_endpoint(&target)?;
        if request.copy.destination != REQUEST_ROOT
            || request.destination.len() > 4096
            || request.destination.contains(&0)
        {
            bail!("invalid remote copy destination");
        }
        let request = constrain(
            request,
            Path::new(std::ffi::OsStr::from_bytes(REQUEST_ROOT)),
            self.max_bytes,
            self.max_entries,
            self.max_delete,
        )?;
        crate::delegation::validate_return_request(&request)?;
        if !request.constraints.receipt_policy.required
            || !matches!(
                request.constraints.receipt_policy.delivery,
                crate::receipt::ReceiptDelivery::AttachedEncrypted { .. }
            )
        {
            bail!("remote copies require an attached encrypted receipt");
        }
        let count = self.forward_count.fetch_add(1, Ordering::AcqRel);
        let _slot = Slot(&self.forward_count);
        if count >= 8 {
            bail!("too many active remote copies; wait for one to finish");
        }
        let (generation, _channel) = {
            // Serialize registration with revocation, including reconnects.
            let _sessions = self.sessions.lock().unwrap();
            (
                self.generation.load(Ordering::Acquire),
                self.active_streams.track(stream.try_clone()?)?,
            )
        };
        let socket = stream.try_clone()?;
        let cancelled = || {
            self.stop.load(Ordering::Acquire)
                || self.generation.load(Ordering::Acquire) != generation
        };
        let setup_cancelled = || cancelled() || requester_closed(&socket);
        // Automatic approval of writes to this machine does not authorize use
        // of its SSH credentials on another host.
        self.approvals.request_remote(
            &self.requester,
            &target,
            &request,
            self.notifications,
            setup_cancelled,
        )?;
        if setup_cancelled() {
            bail!("remote copy disconnected before setup");
        }
        // This lock only serializes decisions, not SSH setup or active copies.
        drop(request_lock);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(target.as_bytes());
        let (mut child, approved) = ForwardChild::connect(
            &encoded,
            &HelperRequest {
                version: HELPER_VERSION,
                identity: crate::identity::build().into(),
                request,
            },
            Instant::now() + SETUP_TIMEOUT,
            &setup_cancelled,
        )?;
        let result = (|| {
            let input = child.child.stdin.take().unwrap();
            let output = child.child.stdout.take().unwrap();
            write_message(&mut stream, &Reply::Approved(approved))?;
            socket.set_read_timeout(None)?;
            socket.set_write_timeout(None)?;
            relay(socket.try_clone()?, input, output, cancelled, &mut child)
        })();
        result.with_context(|| format!("copy via this machine to {target:?}: {}", child.errors()))
    }
}

/// Kill before reaping, including bootstrap/ProxyCommand descendants. Capture
/// is bounded while the complete pipe is drained; diagnostics never block SSH.
struct ForwardChild {
    child: Child,
    errors: Arc<Mutex<Vec<u8>>>,
    capture: Option<std::thread::JoinHandle<()>>,
    closed: bool,
}
impl ForwardChild {
    fn connect(
        target: &str,
        request: &HelperRequest,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> Result<(Self, Approved)> {
        for install in [false, true] {
            let mut command = Command::new(std::env::current_exe()?);
            command.args([
                if install {
                    "--return-connect-install"
                } else {
                    "--return-connect"
                },
                target,
            ]);
            let mut child = Self::spawn_command(command)?;
            let reply = (|| {
                write_message(
                    &mut DeadlineIo {
                        inner: child.child.stdin.as_mut().unwrap(),
                        deadline,
                        cancelled,
                    },
                    request,
                )?;
                read_message::<Reply>(&mut DeadlineIo {
                    inner: child.child.stdout.as_mut().unwrap(),
                    deadline,
                    cancelled,
                })
            })();
            match reply {
                Ok(Reply::Approved(approved)) => return Ok((child, approved)),
                Ok(Reply::Error(error)) => bail!("destination refused the copy: {error}"),
                Ok(Reply::Ready | Reply::Identity(_)) => {
                    bail!("invalid destination setup response")
                }
                Err(error) => {
                    // Match ordinary bootstrap: a missing helper or an exec
                    // failure may retry setup once, before a copy is approved.
                    let closed = error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                        matches!(
                            e.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::ConnectionReset
                        )
                    });
                    let status = if closed {
                        child.wait_for_exit(deadline, cancelled)
                    } else {
                        child.close().map_err(Into::into)
                    };
                    if !install
                        && status
                            .as_ref()
                            .is_ok_and(|s| crate::remote_helper::needs_install(s.code()))
                    {
                        continue;
                    }
                    return Err(error).with_context(|| {
                        format!(
                            "return helper setup failed ({status:?}): {}",
                            child.errors()
                        )
                    });
                }
            }
        }
        unreachable!("the second helper attempt returns its result")
    }
    fn wait_for_exit(
        &mut self,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> Result<std::process::ExitStatus> {
        loop {
            // Observe without reaping, so cleanup can still kill descendants
            // without allowing the leader's PID to be reused for another group.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.into());
            }
            if info.si_signo != 0 {
                return Ok(self.close()?);
            }
            if cancelled() || Instant::now() >= deadline {
                let _ = self.close();
                bail!("return helper stopped while waiting for its exit status");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn spawn_command(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?;
        let mut stderr = child.stderr.take().unwrap();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let captured = errors.clone();
        let capture = std::thread::spawn(move || {
            let mut bytes = [0; 1024];
            while let Ok(count) = stderr.read(&mut bytes) {
                if count == 0 {
                    break;
                }
                let mut output = captured.lock().unwrap();
                output.extend_from_slice(&bytes[..count]);
                if output.len() > 4096 {
                    let excess = output.len() - 4096;
                    output.drain(..excess);
                }
            }
        });
        Ok(Self {
            child,
            errors,
            capture: Some(capture),
            closed: false,
        })
    }
    fn close(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if !self.closed {
            self.closed = true;
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
        }
        let status = self.child.wait();
        if let Some(capture) = self.capture.take() {
            let _ = capture.join();
        }
        status
    }
    fn errors(&self) -> String {
        format!(
            "{:?}",
            String::from_utf8_lossy(&self.errors.lock().unwrap())
        )
    }
}
impl Drop for ForwardChild {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// Control frames must reach the other side immediately. Avoid kernel copy
// offload, which can wait for more pipe data across this request/reply boundary.
fn pump(reader: &mut impl Read, writer: &mut impl Write) -> std::io::Result<u64> {
    let mut buffer = [0; 16 * 1024];
    let mut total = 0;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => return Ok(total),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        writer.write_all(&buffer[..count])?;
        writer.flush()?;
        total += count as u64;
    }
}

fn relay(
    mut socket: UnixStream,
    mut input: std::process::ChildStdin,
    mut output: std::process::ChildStdout,
    cancelled: impl Fn() -> bool,
    child: &mut ForwardChild,
) -> Result<()> {
    let mut writer = socket.try_clone()?;
    let shutdown = socket.try_clone()?;
    let (done, completions) = mpsc::channel();
    let sent = done.clone();
    let upload = std::thread::spawn(move || {
        let _ = sent.send(pump(&mut socket, &mut input));
    });
    let download = std::thread::spawn(move || {
        let _ = done.send(pump(&mut output, &mut writer));
    });
    let deadline = Instant::now() + FINISH_TIMEOUT;
    let result = loop {
        if cancelled() {
            break Err(anyhow::anyhow!("return connection stopped during copy"));
        }
        if Instant::now() >= deadline {
            break Err(anyhow::anyhow!(
                "remote copy exceeded its seven-day lifetime"
            ));
        }
        match completions.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => break result.map(|_| ()).map_err(Into::into),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(error) => break Err(error.into()),
        }
    };
    let _ = shutdown.shutdown(std::net::Shutdown::Both);
    let _ = child.close();
    let _ = upload.join();
    let _ = download.join();
    result
}

struct DeadlineIo<'a, T, F> {
    inner: &'a mut T,
    deadline: Instant,
    cancelled: &'a F,
}
impl<T: Read + AsRawFd, F: Fn() -> bool> Read for DeadlineIo<'_, T, F> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        wait_fd(
            self.inner.as_raw_fd(),
            libc::POLLIN,
            self.deadline,
            self.cancelled,
        )?;
        self.inner.read(bytes)
    }
}
impl<T: Write + AsRawFd, F: Fn() -> bool> Write for DeadlineIo<'_, T, F> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        wait_fd(
            self.inner.as_raw_fd(),
            libc::POLLOUT,
            self.deadline,
            self.cancelled,
        )?;
        self.inner.write(&bytes[..bytes.len().min(512)])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct HandshakeInput<R> {
    inner: R,
    pending: Arc<AtomicBool>,
    deadline: Instant,
    hello_timeout: Duration,
    started: bool,
}
impl<R> HandshakeInput<R> {
    fn new(
        inner: R,
        pending: Arc<AtomicBool>,
        start_timeout: Duration,
        hello_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            pending,
            deadline: Instant::now() + start_timeout,
            hello_timeout,
            started: false,
        }
    }
}
impl<R: Read + AsRawFd> Read for HandshakeInput<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.pending.load(Ordering::Acquire) {
            wait_fd(self.inner.as_raw_fd(), libc::POLLIN, self.deadline, &|| {
                false
            })?;
        }
        let count = self.inner.read(bytes)?;
        if count > 0 && !self.started {
            // Preparing the source and reaching us through the return relay is
            // separate from completing Hello. Neither phase can wait forever,
            // and subsequent partial bytes never extend the Hello deadline.
            self.started = true;
            self.deadline = Instant::now() + self.hello_timeout;
        }
        Ok(count)
    }
}

fn resolve_ssh_destination(home: &Path, path: &[u8]) -> Result<(PathBuf, PathBuf)> {
    let relative;
    let path = if path == b"~" {
        b"."
    } else if let Some(rest) = path.strip_prefix(b"~/") {
        // Keep even ~//path relative to the destination home. ./~/path still
        // names a literal directory, and named receivers keep their cwd/root.
        relative = [b"./".as_slice(), rest].concat();
        &relative
    } else {
        path
    };
    resolve_destination(home, None, path)
}

fn receive() -> Result<i32> {
    let fd = unsafe { libc::dup(libc::STDIN_FILENO) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut input = unsafe { File::from_raw_fd(fd) };
    let setup = (|| {
        let request: HelperRequest = read_message(&mut DeadlineIo {
            inner: &mut input,
            deadline: Instant::now() + Duration::from_secs(10),
            cancelled: &|| false,
        })?;
        if request.version != HELPER_VERSION || request.identity != crate::identity::build() {
            bail!("return helper build mismatch");
        }
        let cwd = fs::canonicalize(std::env::var_os("HOME").context("HOME is unset")?)?;
        let (destination, container) = resolve_ssh_destination(&cwd, &request.request.destination)?;
        let request = constrain(
            request.request,
            &destination,
            crate::delegation::MAX_COPY_BYTES,
            crate::delegation::MAX_ENTRIES,
            u64::MAX,
        )?;
        crate::restricted::named_authority(&container, request)
    })();
    let (authority, approved) = match setup {
        Ok(value) => value,
        Err(error) => {
            write_message(&mut std::io::stdout(), &Reply::Error(format!("{error:#}")))?;
            return Err(error);
        }
    };
    write_message(&mut std::io::stdout(), &Reply::Approved(approved))?;
    let pending = Arc::new(AtomicBool::new(true));
    crate::server::run_forwarded(
        authority,
        HandshakeInput::new(
            input,
            pending.clone(),
            START_TIMEOUT,
            Duration::from_secs(10),
        ),
        pending,
    )?;
    Ok(0)
}
fn connect(target: &str, install: bool) -> Result<i32> {
    let target =
        String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(target)?)?;
    let endpoint = target_endpoint(&target)?;
    let spec = crate::conn::RemoteSpec {
        local_process: false,
        user: endpoint.user,
        host: endpoint.host,
        port: endpoint.port,
        // A return connection needs its explicit remote forwarding. This
        // outbound copy needs no forwarding and must not ask about host keys
        // from the background service. RemoteSpec disables multiplexing.
        rsh: std::iter::once("ssh")
            .chain(RETURN_SSH_OPTIONS.iter().copied())
            .chain([
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "StrictHostKeyChecking=yes",
            ])
            .map(str::to_owned)
            .collect(),
        syq_path: None,
        bootstrap_helper: true,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: None,
        quiet: true,
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };
    if install {
        spec.install_helper()?;
    }
    Err(spec
        .helper_command(&["--return-receiver".into()])
        .exec()
        .into())
}
pub(super) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    match argv.get(1).and_then(|v| v.to_str())? {
        "--return-receiver" if argv.len() == 2 => Some(receive()),
        "--return-connect" | "--return-connect-install" if argv.len() == 3 => Some(
            argv[2]
                .to_str()
                .context("invalid return target")
                .and_then(|target| connect(target, argv[1] == "--return-connect-install")),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::tests::{args, broker, request};

    #[test]
    fn hello_has_a_separate_start_budget_and_partial_bytes_do_not_extend_it() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let pending = Arc::new(AtomicBool::new(true));
        let mut input = HandshakeInput::new(
            reader,
            pending,
            Duration::from_secs(2),
            Duration::from_millis(150),
        );
        // Source preparation may exceed the entire Hello budget.
        std::thread::sleep(Duration::from_millis(200));
        writer.write_all(b"a").unwrap();
        let mut byte = [0];
        input.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"a");
        let sender = std::thread::spawn(move || {
            for _ in 0..8 {
                std::thread::sleep(Duration::from_millis(40));
                if writer.write_all(b"b").is_err() {
                    break;
                }
            }
        });
        let error = input.read_exact(&mut [0; 8]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        drop(input);
        sender.join().unwrap();
    }

    #[test]
    fn an_idle_hello_expires_but_completed_transfers_have_no_hello_deadline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let pending = Arc::new(AtomicBool::new(true));
        let mut input = HandshakeInput::new(
            reader,
            pending.clone(),
            Duration::from_millis(20),
            Duration::from_millis(20),
        );
        assert_eq!(input.read(&mut []).unwrap(), 0);
        let error = input.read(&mut [0]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        // Once the server has accepted Hello, the reader belongs to the copy.
        pending.store(false, Ordering::Release);
        writer.write_all(b"data").unwrap();
        let mut bytes = [0; 4];
        input.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"data");
    }

    #[test]
    fn ssh_destinations_expand_only_a_leading_home_tilde() {
        let root = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(root.path()).unwrap();
        for path in [b"~/archive".as_slice(), b"~//archive", b"archive"] {
            assert_eq!(
                resolve_ssh_destination(&home, path).unwrap().0,
                home.join("archive")
            );
        }
        assert_eq!(resolve_ssh_destination(&home, b"~").unwrap().0, home);
        assert_eq!(
            resolve_ssh_destination(&home, b"./~/archive").unwrap().0,
            home.join("~/archive")
        );
        assert_eq!(
            resolve_ssh_destination(&home, b"~someone/archive")
                .unwrap()
                .0,
            home.join("~someone/archive")
        );
        // The shared named resolver still interprets paths relative to cwd.
        assert_eq!(
            resolve_destination(&home, None, b"~/archive").unwrap().0,
            home.join("~/archive")
        );
    }

    #[test]
    fn helper_exit_status_and_stderr_survive_group_cleanup() {
        let mut command = Command::new("sh");
        // A descendant keeps stderr open after the launcher has exited.
        command.args(["-c", "sleep 30 & printf missing >&2; exit 125"]);
        let mut child = ForwardChild::spawn_command(command).unwrap();
        let status = child
            .wait_for_exit(Instant::now() + Duration::from_secs(2), &|| false)
            .unwrap();
        assert_eq!(
            status.code(),
            Some(crate::remote_helper::HELPER_MISSING_EXIT)
        );
        assert_eq!(child.errors(), "\"missing\"");
        assert_eq!(child.close().unwrap(), status);
    }

    #[test]
    fn helper_exit_wait_remains_bounded_and_cancellable() {
        for cancel in [false, true] {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 30"]);
            let mut child = ForwardChild::spawn_command(command).unwrap();
            let started = Instant::now();
            assert!(child
                .wait_for_exit(started + Duration::from_millis(20), &|| cancel)
                .is_err());
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(child.child.try_wait().unwrap().is_some());
        }
    }

    #[test]
    fn duplex_control_relay_delivers_small_messages_without_waiting_for_eof() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut command = Command::new("cat");
        command.arg("-");
        let mut child = ForwardChild::spawn_command(command).unwrap();
        let input = child.child.stdin.take().unwrap();
        let output = child.child.stdout.take().unwrap();
        let thread = std::thread::spawn(move || relay(server, input, output, || false, &mut child));
        client.write_all(b"hello").unwrap();
        let mut response = [0; 5];
        let result = client.read_exact(&mut response);
        client.shutdown(std::net::Shutdown::Both).unwrap();
        let _ = thread.join().unwrap();
        result.unwrap();
        assert_eq!(&response, b"hello");
    }
    #[test]
    fn remote_targets_are_endpoints_not_shell_or_ssh_options() {
        for target in ["backup", "alice@backup:2222", "alice@[2001:db8::1]:22"] {
            assert!(target_endpoint(target).is_ok(), "{target}");
        }
        for target in [
            "@laptop",
            "-oProxyCommand=evil",
            "a$(id)",
            "user`id`@host",
            "user;id@host",
            "a\nHost *",
            "a/b",
            "x@host:0",
        ] {
            assert!(target_endpoint(target).is_err(), "{target}");
        }
    }

    #[test]
    fn forward_validation_precedes_approval_and_outbound_ssh() {
        let root = tempfile::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let (valid, _) = request(&args(root.path(), "output"));
        for case in 0..5 {
            let mut copy = valid.clone();
            let mut target = "backup".to_owned();
            match case {
                0 => target = "bad$(command)".into(),
                1 => copy.copy.mutation_scopes[0].path = b"/outside".to_vec(),
                2 => copy.copy.limits.max_entries = 0,
                3 => copy.destination = b"bad\0path".to_vec(),
                _ => copy.constraints.receipt_policy.required = false,
            }
            assert!(exchange(
                &registration,
                Message::Forward {
                    target,
                    request: Box::new(copy)
                },
                Duration::from_secs(2)
            )
            .is_err());
            assert!(receiver.approvals.snapshots().is_empty());
        }
        assert_eq!(receiver.forward_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn forward_always_requires_a_local_decision_and_revocation_cancels_it() {
        for revoke in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
            let (copy, _) = request(&args(root.path(), "output"));
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    Message::Forward {
                        target: "backup".into(),
                        request: Box::new(copy),
                    },
                    Duration::from_secs(3),
                )
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            let pending = loop {
                if let Some(summary) = receiver.approvals.snapshots().first() {
                    break summary.clone();
                }
                assert!(
                    Instant::now() < deadline,
                    "forward request did not become pending"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            let description = pending.description();
            assert!(description.contains("backup"));
            assert!(description.contains("output"));
            assert!(description.contains("SSH access"));
            if revoke {
                receiver.revoke_all();
            } else {
                receiver
                    .approvals
                    .decide(&pending.id, false, crate::receive_approval::Kind::Copy)
                    .unwrap();
            }
            assert!(task.join().unwrap().is_err());
            let deadline = Instant::now() + Duration::from_secs(2);
            while receiver.forward_count.load(Ordering::Acquire) != 0 {
                assert!(
                    Instant::now() < deadline,
                    "forward request did not release its slot"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(receiver.approvals.snapshots().is_empty());
        }
    }

    #[test]
    fn setup_deadlines_cover_partial_frames_and_cancellation_is_not_retried() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&[0, 0]).unwrap();
        let error = read_message::<Reply>(&mut DeadlineIo {
            inner: &mut reader,
            deadline: Instant::now() + Duration::from_millis(20),
            cancelled: &|| false,
        })
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
        let error = read_message::<Reply>(&mut DeadlineIo {
            inner: &mut reader,
            deadline: Instant::now() + Duration::from_secs(60),
            cancelled: &|| true,
        })
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }
}
