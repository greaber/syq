//! One approved control stream through the receiving machine; data goes to the
//! destination's restricted TCP or SSH workers. There is no remote signing interface.
pub(super) mod ssh;
use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::AtomicUsize;

const HELPER_VERSION: u16 = 1;
pub(super) const SETUP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HelperRequest {
    version: u16,
    identity: String,
    request: CopyRequest,
}

pub(super) fn peer_receiver(
    spec: &crate::conn::RemoteSpec,
    request: CopyRequest,
    deadline: Instant,
) -> Result<(ForwardChild, Approved)> {
    let (child, reply) = ForwardChild::over_spec(
        spec,
        "--peer-receiver",
        &HelperRequest {
            version: HELPER_VERSION,
            identity: crate::identity::build().into(),
            request,
        },
        deadline,
        &|| false,
    )?;
    let Reply::Approved(approved) = reply else {
        bail!("invalid peer receiver setup response")
    };
    Ok((child, approved))
}

pub(super) fn target_endpoint(target: &str) -> Result<crate::cli::NativeEndpoint> {
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

pub(super) fn eligible_target(args: &crate::cli::Args) -> Result<String> {
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
        || args.detach
        || args.restricted_grant.is_some()
        || args.no_tcp_encryption
        || args.peer_auth != PeerAuth::Restricted
        || args.coordinate_at != CoordinateAt::Auto
    {
        bail!("return authorization owns its SSH connection and requires encrypted direct data transport; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --detach, --no-tcp-encryption, --peer-auth, or --coordinate-at");
    }
    if args.inplace {
        bail!("return authorization does not accept --inplace");
    }
    crate::restricted::validate_restricted_args(args)?;
    let target = crate::remote_to_remote::endpoint_arg(destination, None, None);
    target_endpoint(&target)?;
    Ok(target)
}

pub(super) fn select(
    args: &mut crate::cli::Args,
    progress: Option<&crate::progress::Progress>,
) -> Result<Option<handoff::Selection>> {
    let explicit = match &args.auth_from {
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name)) => {
            Some(name.clone())
        }
        crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Ssh { .. }) => {
            bail!("this copy cannot use account authorization from an SSH provider; use a supported direct SSH copy or --auth-from @NAME for per-copy authorization");
        }
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
        let names = registered_names();
        if names.is_empty() {
            return Ok(None);
        }
        // Open the actual control connection before considering another
        // machine's access. Keep a successful connection for the transfer;
        // probing with a separate SSH command would add a login/round trip.
        // This must precede reading stdin and opening result files, because
        // selecting a receiving machine can exec its build-pinned helper.
        let crate::conn::Endpoint::Remote(spec) =
            crate::transfer::endpoint(args.locations.last().unwrap(), args)?
        else {
            unreachable!("eligible forwarding destination is remote");
        };
        let error = match crate::transfer::connect_for_authorization(args, &spec, progress) {
            Ok(connection) => {
                *spec.primed_control.lock().unwrap() =
                    crate::conn::PrimedControl::Checked(Some(Box::new(connection)));
                args.direct_destination = Some(Box::new(spec));
                return Ok(None);
            }
            Err(error) if crate::conn::is_ssh_authorization_fallback_error(&error) => error,
            Err(error) => return Err(error),
        };
        let Some(found) = names.into_iter().find_map(|name| {
            let registration = available(&name, Duration::from_secs(2)).ok()?;
            Some((name, registration))
        }) else {
            // Do not repeat the failed SSH attempt when no receiver responds.
            return Err(error);
        };
        crate::output::diagnostic!(
            "syq: {}; trying authorization through @{}",
            error.root_cause(),
            found.0
        );
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
        hashed: args.receiver_receipt == Some(crate::cli::ReceiptDetail::Hashes),
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
            command: crate::approval_command::current()?,
            cwd: crate::approval_command::current_directory(),
            request: Box::new(request),
        },
        REQUEST_TIMEOUT + SETUP_TIMEOUT + Duration::from_secs(10),
        None,
    )?;
    if args.verbose > 0 {
        crate::output::diagnostic!("syq: remote copy approved; opening its control connection");
    }
    let Reply::Approved(approved) = reply else {
        bail!("unexpected remote copy approval response");
    };
    super::apply_deletion_limit(args, &approved);
    args.locations.last_mut().unwrap().path = approved.destination.clone();
    args.auth_from = crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name));
    // The actual authority never leaves the destination helper. This internal
    // marker selects its restricted executor and per-copy worker admission.
    args.restricted_grant = Some(super::RETURN_GRANT.into());
    let ssh = ssh::Client::new(registration, approved.token.clone());
    args.named_receipt = Some(Arc::new(NamedReceipt {
        connection: Some(ReturnConnection::new(stream, Some(ssh))),
        secret,
        approved,
        policy,
    }));
    Ok(())
}

pub(super) struct Slot<'a>(pub(super) &'a AtomicUsize);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Receiver {
    pub(super) fn forward(
        &self,
        target: String,
        command: Vec<Vec<u8>>,
        cwd: String,
        request: CopyRequest,
        mut stream: TrackedStream,
    ) -> Result<()> {
        let request_lock = self.request_lock.try_lock().map_err(|_| {
            anyhow::anyhow!("another transfer is awaiting approval; retry after it is decided")
        })?;
        target_endpoint(&target)?;
        crate::approval_command::check_authorizer(&command, &self.name)?;
        crate::approval_command::check_copy(&command, &request, None, Some(&target))?;
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
            &command,
            &cwd,
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
        let (mut child, reply) = ForwardChild::connect(
            &encoded,
            &HelperRequest {
                version: HELPER_VERSION,
                identity: crate::identity::build().into(),
                request,
            },
            "--return-receiver",
            Instant::now() + SETUP_TIMEOUT,
            &setup_cancelled,
        )?;
        let Reply::Approved(mut approved) = reply else {
            bail!("invalid destination setup response");
        };
        let session =
            ssh::SessionGuard::insert(self, target.clone(), approved.token.clone(), generation)?;
        approved.token = session.token();
        approved.max_delete = Some(self.max_delete.min(self.max_entries));
        let result = (|| {
            let input = child.child.stdin.take().unwrap();
            let output = child.child.stdout.take().unwrap();
            socket.set_read_timeout(None)?;
            socket.set_write_timeout(None)?;
            write_message(&mut stream, &Reply::Approved(approved))?;
            relay(socket.try_clone()?, input, output, cancelled, &mut child)
        })();
        result.with_context(|| format!("copy via this machine to {target:?}: {}", child.errors()))
    }
}

/// Kill before reaping, including bootstrap/ProxyCommand descendants. Capture
/// is bounded while the complete pipe is drained; diagnostics never block SSH.
pub(super) struct ForwardChild {
    pub(super) child: Child,
    errors: Arc<Mutex<Vec<u8>>>,
    capture: Option<std::thread::JoinHandle<()>>,
    closed: bool,
}
impl ForwardChild {
    pub(super) fn connect<T: Serialize>(
        target: &str,
        request: &T,
        operation: &str,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> Result<(Self, Reply)> {
        for install in [false, true] {
            let mut command = Command::new(std::env::current_exe()?);
            command.args([
                if install {
                    "--return-connect-install"
                } else {
                    "--return-connect"
                },
                target,
                operation,
            ]);
            let mut child = Self::spawn_command(command)?;
            let reply = (|| {
                write_message(
                    &mut DeadlineIo {
                        inner: child.child.stdin.as_mut().unwrap(),
                        deadline,
                        cancelled: Some(cancelled),
                    },
                    request,
                )?;
                read_message::<Reply>(&mut DeadlineIo {
                    inner: child.child.stdout.as_mut().unwrap(),
                    deadline,
                    cancelled: Some(cancelled),
                })
            })();
            match reply {
                Ok(reply @ (Reply::Approved(_) | Reply::SourceApproved { .. })) => {
                    return Ok((child, reply))
                }
                Ok(Reply::Error(error)) => bail!("destination refused the copy: {error}"),
                Ok(Reply::RetryableError(error)) => {
                    return Err(super::ssh_auth::RetryableSetupError(error).into());
                }
                Ok(
                    Reply::Ready
                    | Reply::Identity(_)
                    | Reply::TcpProbed(_)
                    | Reply::TcpCongestionRejected(_)
                    | Reply::ForwardSsh(_),
                ) => {
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
    /// Reuse an already authorized account transport without another login.
    pub(super) fn over_spec<T: Serialize>(
        spec: &crate::conn::RemoteSpec,
        operation: &str,
        request: &T,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> Result<(Self, Reply)> {
        let mut installed = false;
        let mut reclaimed = false;
        loop {
            anyhow::ensure!(!cancelled(), "copy setup cancelled");
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "copy setup deadline expired",
                )
                .into());
            }
            let mut child = Self::spawn_command(spec.helper_command(&[operation.into()]))?;
            let reply = (|| {
                write_message(
                    &mut DeadlineIo {
                        inner: child.child.stdin.as_mut().unwrap(),
                        deadline,
                        cancelled: Some(cancelled),
                    },
                    request,
                )?;
                read_message(&mut DeadlineIo {
                    inner: child.child.stdout.as_mut().unwrap(),
                    deadline,
                    cancelled: Some(cancelled),
                })
            })();
            match reply {
                Ok(Reply::Error(error)) => {
                    return Err(ssh::SetupRefusal(format!(
                        "remote copy helper refused setup: {error}"
                    ))
                    .into());
                }
                Ok(Reply::RetryableError(error)) => {
                    return Err(super::ssh_auth::RetryableSetupError(error).into());
                }
                Ok(reply) => return Ok((child, reply)),
                Err(error) => {
                    let status = child.wait_for_exit(deadline, cancelled);
                    if !reclaimed
                        && status
                            .as_ref()
                            .is_ok_and(|status| status.code() == Some(255))
                        && spec.release_idle_helpers_after_startup_failure(status.as_ref().unwrap())
                    {
                        // The failed child has been closed. No copy data has
                        // been admitted before this setup reply and Hello.
                        reclaimed = true;
                        continue;
                    }
                    if !installed
                        && spec.bootstrap_helper
                        && status
                            .as_ref()
                            .is_ok_and(|s| crate::remote_helper::needs_install(s.code()))
                    {
                        spec.install_helper()?;
                        installed = true;
                        continue;
                    }
                    let errors = child.errors();
                    let error = if status.as_ref().is_ok_and(|s| s.code() == Some(255))
                        && errors.contains("mux_client_request_session: session request failed:")
                    {
                        let error =
                            super::ssh_auth::RetryableSetupError(format!("{error:#}")).into();
                        if operation == "--return-ssh-setup" {
                            anyhow::Error::context(error, "SSH session refused; destination sshd MaxSessions >= 2 is required beside the copy control session")
                        } else {
                            error
                        }
                    } else {
                        error
                    };
                    return Err(error)
                        .with_context(|| format!("approved account helper failed: {errors}"));
                }
            }
        }
    }

    pub(super) fn spawn_streaming_command(mut command: Command) -> Result<Self> {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn_guarded()?;
        Ok(Self {
            child,
            errors: Arc::new(Mutex::new(Vec::new())),
            capture: None,
            closed: false,
        })
    }

    pub(super) fn wait_for_exit(
        &mut self,
        deadline: Instant,
        cancelled: &impl Fn() -> bool,
    ) -> Result<std::process::ExitStatus> {
        self.wait_until_exit(Some(deadline), cancelled)
    }
    pub(super) fn wait_until_exit(
        &mut self,
        deadline: Option<Instant>,
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
            if cancelled() {
                let _ = self.close();
                bail!("return helper cancelled while waiting for its exit status");
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                let _ = self.close();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "return helper deadline expired while waiting for its exit status",
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub(super) fn spawn_command(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn_guarded()?;
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
    pub(super) fn errors(&self) -> String {
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

pub(super) fn relay(
    socket: UnixStream,
    input: std::process::ChildStdin,
    output: std::process::ChildStdout,
    cancelled: impl Fn() -> bool,
    child: &mut ForwardChild,
) -> Result<()> {
    relay_inner(socket, input, output, cancelled, child, false).map(|_| ())
}

/// Wait for the coordinator to release its control after peer EOF. Its final
/// stdout may be slow without leaving any live destination authority behind.
pub(super) fn relay_peer(
    socket: UnixStream,
    input: std::process::ChildStdin,
    output: std::process::ChildStdout,
    cancelled: impl Fn() -> bool,
    child: &mut ForwardChild,
) -> Result<bool> {
    relay_inner(socket, input, output, cancelled, child, true)
}

fn relay_inner(
    mut socket: UnixStream,
    mut input: std::process::ChildStdin,
    mut output: std::process::ChildStdout,
    cancelled: impl Fn() -> bool,
    child: &mut ForwardChild,
    wait_for_release: bool,
) -> Result<bool> {
    let mut writer = socket.try_clone()?;
    let shutdown = socket.try_clone()?;
    let (done, completions) = mpsc::channel();
    let sent = done.clone();
    let upload = std::thread::spawn(move || {
        let _ = sent.send((true, pump(&mut socket, &mut input)));
    });
    let download = std::thread::spawn(move || {
        let _ = done.send((false, pump(&mut output, &mut writer)));
    });
    let mut release_deadline = None;
    let result = loop {
        if cancelled() {
            break Err(anyhow::anyhow!("return connection stopped during copy"));
        }
        if release_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break Ok(false);
        }
        match completions.recv_timeout(Duration::from_millis(if wait_for_release {
            10
        } else {
            100
        })) {
            Ok((true, result)) => break result.map(|_| true).map_err(Into::into),
            Ok((false, result)) if !wait_for_release => {
                break result.map(|_| false).map_err(Into::into)
            }
            Ok((false, _)) => {
                // Do not shut the read side: only a natural upload EOF proves
                // that B has released control, including on normal completion.
                let _ = shutdown.shutdown(std::net::Shutdown::Write);
                let _ = child.close();
                release_deadline = Some(Instant::now() + Duration::from_secs(2));
            }
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

pub(crate) struct DeadlineIo<'a, T> {
    pub(crate) inner: &'a mut T,
    pub(crate) deadline: Instant,
    pub(crate) cancelled: Option<&'a dyn Fn() -> bool>,
}
impl<T: Read + AsRawFd> Read for DeadlineIo<'_, T> {
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
impl<T: Write + AsRawFd> Write for DeadlineIo<'_, T> {
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

pub(super) struct HandshakeInput<R> {
    inner: R,
    pending: Arc<AtomicBool>,
    deadline: Instant,
    hello_timeout: Duration,
    started: bool,
}
impl<R> HandshakeInput<R> {
    pub(super) fn new(
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
            wait_fd(self.inner.as_raw_fd(), libc::POLLIN, self.deadline, None)?;
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
    crate::fsops::reserve_startup_descriptors();
    let fd = unsafe { libc::dup(libc::STDIN_FILENO) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut input = unsafe { File::from_raw_fd(fd) };
    let setup = (|| {
        crate::restricted::refuse_privileged_approved_receiver()?;
        let request: HelperRequest = read_message(&mut DeadlineIo {
            inner: &mut input,
            deadline: Instant::now() + Duration::from_secs(10),
            cancelled: None,
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
    let _lifetime = crate::server::ControlLifetime::watch(&input, authority.clone())?;
    let workers = ssh::Server::start(authority.clone())?;
    let mut approved = approved;
    approved.token = workers.ticket()?;
    write_message(&mut std::io::stdout(), &Reply::Approved(approved))?;
    let pending = Arc::new(AtomicBool::new(true));
    let result = crate::server::run_forwarded(
        authority.clone(),
        HandshakeInput::new(
            input,
            pending.clone(),
            START_TIMEOUT,
            Duration::from_secs(10),
        ),
        std::io::stdout().lock(),
        pending,
        true,
    );
    authority.close_control();
    drop(workers);
    result?;
    Ok(0)
}
fn connect(target: &str, install: bool, operation: &str) -> Result<i32> {
    crate::fsops::reserve_startup_descriptors();
    let target =
        String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(target)?)?;
    let spec = target_spec(&target)?;
    if install {
        spec.install_helper()?;
    }
    Err(spec.helper_command(&[operation.into()]).exec().into())
}
/// Build the same SSH route for helper setup and laptop-side address lookup.
pub(super) fn target_spec(target: &str) -> Result<crate::conn::RemoteSpec> {
    let endpoint = target_endpoint(target)?;
    Ok(crate::conn::RemoteSpec {
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
        pacing: Default::default(),
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    })
}

pub(super) fn source_data_hostname(
    spec: &crate::conn::RemoteSpec,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<String> {
    read_source_hostname(spec.ssh_hostname_command(), deadline, cancelled)
}

fn read_source_hostname(
    command: Command,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<String> {
    // Reuse helper process-group ownership, bounded stderr capture, and the
    // setup's absolute deadline. A local Match exec must not outlive revocation.
    let mut child = ForwardChild::spawn_command(command)?;
    drop(child.child.stdin.take());
    let mut output = Vec::new();
    DeadlineIo {
        inner: child.child.stdout.as_mut().unwrap(),
        deadline,
        cancelled: Some(cancelled),
    }
    .take(MAX_MESSAGE as u64 + 1)
    .read_to_end(&mut output)?;
    anyhow::ensure!(
        output.len() <= MAX_MESSAGE,
        "source SSH configuration output is too large"
    );
    let status = child.wait_for_exit(deadline, cancelled)?;
    anyhow::ensure!(
        status.success(),
        "resolve source SSH hostname: {}",
        child.errors()
    );
    let text = std::str::from_utf8(&output).context("source SSH configuration is not UTF-8")?;
    let hostname = text
        .lines()
        .find_map(|line| line.strip_prefix("hostname "))
        .context("source SSH configuration did not report its hostname")?
        .trim()
        .to_owned();
    validate_data_hostname(&hostname)?;
    Ok(hostname)
}

pub(super) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    match argv.get(1).and_then(|v| v.to_str())? {
        "--return-receiver" | "--peer-receiver" if argv.len() == 2 => Some(receive()),
        "--return-ssh-setup" if argv.len() == 2 => Some(ssh::setup()),
        "--return-ssh-worker" if argv.len() == 3 => Some(
            argv[2]
                .to_str()
                .context("invalid copy worker admission")
                .and_then(ssh::worker),
        ),
        "--return-ssh-connect" if argv.len() == 3 => Some(
            argv[2]
                .to_str()
                .context("invalid return target")
                .and_then(|target| connect(target, false, "--return-ssh-setup")),
        ),
        "--return-source-probe" if argv.len() == 2 => Some(Ok(0)),
        "--return-source" if argv.len() == 2 => Some(super::pull::receive()),
        "--return-connect" | "--return-connect-install" if argv.len() == 3 || argv.len() == 4 => {
            Some(
                argv[2]
                    .to_str()
                    .context("invalid return target")
                    .and_then(|target| {
                        connect(
                            target,
                            argv[1] == "--return-connect-install",
                            match argv.get(3).and_then(|arg| arg.to_str()) {
                                None | Some("--return-receiver") => "--return-receiver",
                                Some("--return-source") => "--return-source",
                                _ => bail!("invalid return helper operation"),
                            },
                        )
                    }),
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::tests::{args, broker, request};

    #[test]
    fn source_hostname_lookup_obeys_setup_deadline_and_cancellation() {
        for cancelled in [false, true] {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 30; printf 'hostname example.test\n'"]);
            let start = Instant::now();
            let result =
                read_source_hostname(command, start + Duration::from_millis(20), &|| cancelled);
            assert!(result.is_err());
            assert!(start.elapsed() < Duration::from_secs(2));
        }
        let mut command = Command::new("sh");
        command.args(["-c", "printf 'hostname example.test\n'; exit 1"]);
        assert!(
            read_source_hostname(command, Instant::now() + Duration::from_secs(2), &|| false)
                .is_err()
        );
    }

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
        let root = crate::test_support::tempdir().unwrap();
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
    fn approved_setup_session_hint_only_follows_an_actual_session_refusal() {
        for (message, operation, hint) in [
            (
                "mux_client_request_session: session request failed: Session open refused by peer",
                "--return-ssh-setup",
                true,
            ),
            (
                "Permission denied (publickey).",
                "--return-ssh-setup",
                false,
            ),
            (
                "mux_client_request_session: session request failed: Session open refused by peer",
                "--peer-receiver",
                false,
            ),
        ] {
            let mut spec = crate::conn::RemoteSpec::local_receiver(false);
            spec.local_process = false;
            spec.rsh = vec![
                "sh".into(),
                "-c".into(),
                format!("printf '%s' '{}' >&2; exit 255", message),
            ];
            let error = ForwardChild::over_spec(
                &spec,
                operation,
                &"setup",
                Instant::now() + Duration::from_secs(3),
                &|| false,
            )
            .err()
            .unwrap();
            let detail = format!("{error:#}");
            assert!(detail.contains(message), "{detail}");
            assert_eq!(detail.contains("MaxSessions >= 2"), hint, "{detail}");
        }
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
    fn peer_relay_release_allows_slow_final_coordinator_output() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "printf done"]);
        let mut peer = ForwardChild::spawn_command(command).unwrap();
        let input = peer.child.stdin.take().unwrap();
        let output = peer.child.stdout.take().unwrap();
        let thread =
            std::thread::spawn(move || relay_peer(server, input, output, || false, &mut peer));
        let mut result = Vec::new();
        client.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"done");
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let released = thread.join().unwrap().unwrap();
        assert!(released);
        // The independently owned coordinator may still flush its final stdout.
        // No fixed deadline applies after it released its peer control.
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 2.2; printf final"]);
        let mut coordinator = ForwardChild::spawn_command(command).unwrap();
        let mut output = coordinator.child.stdout.take().unwrap();
        assert!(coordinator
            .wait_until_exit(None, &|| !released)
            .unwrap()
            .success());
        result.clear();
        output.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"final");
    }

    #[test]
    fn peer_relay_loss_without_control_release_stops_the_coordinator() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        let mut peer = ForwardChild::spawn_command(command).unwrap();
        let input = peer.child.stdin.take().unwrap();
        let output = peer.child.stdout.take().unwrap();
        let started = Instant::now();
        let thread =
            std::thread::spawn(move || relay_peer(server, input, output, || false, &mut peer));
        // read_exact retries EINTR from signal tests sharing this process.
        assert_eq!(
            client.read_exact(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        // Keep B's read/upload side alive even though C disappeared.
        assert!(!thread.join().unwrap().unwrap());
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(client.write_all(b"late").is_err());
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30"]);
        let mut coordinator = ForwardChild::spawn_command(command).unwrap();
        assert!(coordinator.wait_until_exit(None, &|| true).is_err());
        assert!(coordinator.child.try_wait().unwrap().is_some());
    }

    #[test]
    fn peer_relay_cancellation_wakes_both_blocked_pumps() {
        let (_client, server) = UnixStream::pair().unwrap();
        let mut command = Command::new("cat");
        command.arg("-");
        let mut peer = ForwardChild::spawn_command(command).unwrap();
        let input = peer.child.stdin.take().unwrap();
        let output = peer.child.stdout.take().unwrap();
        let started = Instant::now();
        assert!(relay_peer(
            server,
            input,
            output,
            || started.elapsed() >= Duration::from_millis(20),
            &mut peer
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(peer.child.try_wait().unwrap().is_some());
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
    fn return_authorization_uses_the_restricted_worker_limit() {
        let root = crate::test_support::tempdir().unwrap();
        let mut args = args(root.path(), "output");
        for workers in [1, 32, 64, 128] {
            args.connections_opt = Some(workers);
            args.connections = workers;
            assert_eq!(eligible_target(&args).unwrap(), "server");
        }
        args.connections_opt = Some(129);
        args.connections = 129;
        assert!(eligible_target(&args).is_err());
    }

    /// As on other routes to an ordinary account, ownership and special
    /// files are accepted; only in-place writes are not.
    #[test]
    fn return_authorization_accepts_ownership_and_special_files() {
        let root = crate::test_support::tempdir().unwrap();
        let mut args = args(root.path(), "output");
        args.owner = true;
        args.group = true;
        args.devices = true;
        assert_eq!(eligible_target(&args).unwrap(), "server");
        // Pruning states no limit of its own; the approving machine's applies.
        args.delete = true;
        assert_eq!(eligible_target(&args).unwrap(), "server");
        args.inplace = true;
        let error = eligible_target(&args).unwrap_err();
        assert!(error.to_string().contains("--inplace"), "{error:#}");
    }

    fn forward_command(source: &Path) -> Vec<Vec<u8>> {
        let source = source.as_os_str().as_bytes().to_vec();
        [b"cp".to_vec(), b"--src".to_vec(), source]
            .into_iter()
            .chain(
                ["--to", "backup", "--into", "output"]
                    .iter()
                    .map(|arg| arg.as_bytes().to_vec()),
            )
            .collect()
    }

    #[test]
    fn forward_validation_precedes_approval_and_outbound_ssh() {
        let root = crate::test_support::tempdir().unwrap();
        let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
        let command = forward_command(root.path());
        let (valid, _) = request(&crate::approval_command::parse(&command).unwrap());
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
                    command: command.clone(),
                    cwd: String::new(),
                    request: Box::new(copy)
                },
                Duration::from_secs(2),
                Some(Duration::from_secs(2))
            )
            .is_err());
            assert!(receiver.approvals.snapshots().is_empty());
        }
        assert_eq!(receiver.forward_count.load(Ordering::Acquire), 0);
    }

    #[test]
    fn forward_always_requires_a_local_decision_and_revocation_cancels_it() {
        for revoke in [false, true] {
            let root = crate::test_support::tempdir().unwrap();
            let (_broker, receiver, registration, _) = broker(root.path(), Approval::Always);
            let command = forward_command(root.path());
            let (copy, _) = request(&crate::approval_command::parse(&command).unwrap());
            let task = std::thread::spawn(move || {
                exchange(
                    &registration,
                    Message::Forward {
                        target: "backup".into(),
                        command,
                        cwd: "~/rt-bench".into(),
                        request: Box::new(copy),
                    },
                    Duration::from_secs(3),
                    Some(Duration::from_secs(3)),
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
            let description =
                pending.description(&crate::persistence::Domain::default(), str::to_owned);
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
            cancelled: None,
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
            cancelled: Some(&|| true),
        })
        .err()
        .unwrap();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::ConnectionAborted
        );
    }
}
