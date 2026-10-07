//! `syq --server`: serve requests over stdin/stdout, and optionally over
//! TCP data connections (see `crypto.rs`) when the client asks for them.

use crate::descriptor_broker::DescriptorSessionSlot;
use crate::fsops::{self, FsOps};
use crate::proto::*;
use crate::tcp_records::{Cipher, RecordReader, RecordWriter};
use anyhow::{bail, Context, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;
use subtle::ConstantTimeEq;

mod control_lifetime;
pub(crate) use control_lifetime::ControlLifetime;

mod interfaces;
use interfaces::{local_addrs, BoundFamilies};

struct RequestReader {
    rx: Option<std::sync::mpsc::Receiver<io::Result<crate::wire_budget::Budgeted<Request>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    tcp_socket: Option<TcpStream>,
    named_socket: Option<std::os::unix::net::UnixStream>,
}

impl RequestReader {
    fn spawn<R: Read + Send + 'static>(
        mut reader: FrameReader<R>,
        tcp_socket: Option<TcpStream>,
        named_socket: Option<std::os::unix::net::UnixStream>,
        disconnected: Arc<std::sync::atomic::AtomicBool>,
        source_control: Option<Arc<crate::restricted::source::SourceAuthority>>,
        sweep: Option<SweepOnLoss>,
    ) -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let thread = std::thread::Builder::new().spawn(move || loop {
            let msg = reader.read_budgeted::<Request>();
            if let (Ok(request), Some(sweep)) = (&msg, &sweep) {
                if matches!(request.value, Request::Shutdown) {
                    sweep.ended();
                }
            }
            let failed = msg.is_err();
            if failed {
                // The control operation may still be busy, including blocked
                // on its response. Revoke shared TCP read authority before
                // waiting for that operation to consume the disconnect.
                if let Some(source) = &source_control {
                    source.close();
                }
                disconnected.store(true, std::sync::atomic::Ordering::Release);
                // Unless the coordinator asked this process to shut down, the
                // copy has lost it. Remove what it staged now, rather than
                // once the operation under way finishes.
                if let Some(sweep) = &sweep {
                    sweep.run();
                }
            }
            if tx.send(msg).is_err() || failed {
                break;
            }
        })?;
        Ok(Self {
            rx: Some(rx),
            thread: Some(thread),
            tcp_socket,
            named_socket,
        })
    }

    fn recv(
        &self,
    ) -> std::result::Result<
        io::Result<crate::wire_budget::Budgeted<Request>>,
        std::sync::mpsc::RecvError,
    > {
        self.rx.as_ref().expect("request receiver present").recv()
    }

    fn tcp_stats(&self) -> Option<TcpSocketStats> {
        self.tcp_socket
            .as_ref()
            .and_then(crate::conn::tcp_socket_stats)
    }

    /// Process one-way limit updates before the next read. Return to the
    /// writer when a shrink exhausts the range so it can send Done before
    /// waiting for Stop. Once Done is sent, consume late controls through Stop
    /// before accepting another operation on this connection.
    fn stream_stopped(&self, off: u64, limit: &mut u64, done_sent: bool) -> Result<bool> {
        use std::sync::mpsc::TryRecvError;
        loop {
            if off >= *limit && !done_sent {
                return Ok(false);
            }
            let request = if off >= *limit {
                self.recv()
                    .context("read stream control channel closed")??
            } else {
                match self.rx.as_ref().unwrap().try_recv() {
                    Ok(request) => request?,
                    Err(TryRecvError::Empty) => return Ok(false),
                    Err(TryRecvError::Disconnected) => bail!("read stream control channel closed"),
                }
            };
            match request.value {
                Request::StopReadStream => return Ok(true),
                Request::ShrinkReadStream { end } => {
                    crate::streaming::shrink_limit(limit, end)?;
                }
                _ => bail!("only stop and shrink requests are valid during a read stream"),
            }
        }
    }
}

impl Drop for RequestReader {
    fn drop(&mut self) {
        let joinable = self.tcp_socket.is_some() || self.named_socket.is_some();
        if let Some(socket) = &self.named_socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        if let Some(socket) = &self.tcp_socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        self.rx.take();
        // An ssh server process exits immediately after `serve`; joining its
        // stdin reader here would deadlock while the client waits for process
        // exit before closing stdin. A TCP socket can be woken explicitly, so
        // its reader is joined deterministically on every return path.
        if joinable {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

/// Removes the sidecars of the one copy this process serves when the copy's
/// connection is lost: closed or broken before the coordinator asked this
/// process to shut down, as when the coordinator was interrupted or killed.
/// A copy that ends normally keeps them as before, a failed file's included.
/// Partials too short to resume are removed only when the connection was
/// the copy's control: a data worker's own process leaves them, since other
/// workers may still be writing them.
#[derive(Clone)]
struct SweepOnLoss {
    partials: bool,
    ended: Arc<std::sync::atomic::AtomicBool>,
}

impl SweepOnLoss {
    fn new(partials: bool) -> Self {
        Self {
            partials,
            ended: Default::default(),
        }
    }

    /// The coordinator asked this process to shut down.
    fn ended(&self) {
        self.ended.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Within the cap: a removal that stalls, as on a filesystem that stops
    /// answering, ends the process rather than leaving it running.
    fn run(&self) {
        if self.ended.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        crate::process::termination::bounded(|deadline| {
            let swept = crate::fsops::sweep_sidecars(self.partials, deadline);
            if crate::output::debug() && swept != crate::fsops::Swept::default() {
                crate::output::diagnostic!("syq server: copy lost: temporary files {swept:?}");
            }
        });
    }
}

impl Drop for SweepOnLoss {
    fn drop(&mut self) {
        self.run();
    }
}

/// Remove this process's unpublished sidecars, partials too short to resume
/// included, before SIGINT or SIGTERM ends it. A local receiver shares the
/// terminal's process group, so Ctrl-C reaches it directly; a remote one
/// learns of an interrupted copy when its connection closes. This is best
/// effort: a receiver that cannot listen for signals still copies.
fn clean_up_on_termination() -> Option<crate::process::termination::Cleanup> {
    crate::process::termination::add(|deadline| {
        let started = std::time::Instant::now();
        let swept = crate::fsops::sweep_sidecars(true, deadline);
        if crate::output::debug() {
            crate::output::diagnostic!(
                "syq server: interrupted: temporary files {swept:?} in {:?}",
                started.elapsed()
            );
        }
    })
    .ok()
}

struct ServeSession {
    /// This process serves only this session's copy and ends with it, so
    /// the copy's sidecars are removed if the connection is lost.
    owns_process: bool,
    handshake_pending: Option<Arc<std::sync::atomic::AtomicBool>>,
    ssh_worker_ticket: Option<std::result::Result<String, String>>,
    allow_tcp: bool,
    /// A bridged control may carry metadata and receipts, never file payloads.
    metadata_control: bool,
    /// A local copy's receiver: listen for data on loopback only and
    /// advertise no interface addresses.
    loopback_only: bool,
    named_socket: Option<std::os::unix::net::UnixStream>,
    authority: Option<Arc<crate::restricted::RestrictedAuthority>>,
    source_authority: Option<Arc<crate::restricted::source::SourceAuthority>>,
    descriptor_session: DescriptorSessionSlot,
}

/// Ceiling on accepted TCP sockets being served at once, authenticated or
/// not. It bounds thread use against scanners and stray connections; the
/// signed grant's `max_connections` is charged separately, after a worker
/// authenticates.
const MAX_LIVE_TCP_CONNECTIONS: u32 = 256;

/// One authenticated worker's share of a signed grant's connection allowance,
/// returned when the connection ends.
pub(crate) struct ConnectionPermit(Arc<crate::restricted::RestrictedAuthority>);

impl ConnectionPermit {
    pub(crate) fn acquire(authority: Arc<crate::restricted::RestrictedAuthority>) -> Result<Self> {
        authority.acquire_connection()?;
        Ok(Self(authority))
    }
}

/// Absolute Hello deadline. Socket clones share the timeout; serve clears it
/// only after validating Hello and sending HelloOk.
struct NamedHandshakeReader {
    inner: crate::private_broker::TrackedStream,
    socket: std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
}
impl Read for NamedHandshakeReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.socket.read_timeout()?.is_some() {
            let remaining = self
                .deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|time| !time.is_zero())
                .ok_or_else(|| {
                    io::Error::new(ErrorKind::TimedOut, "named channel Hello timed out")
                })?;
            self.socket.set_read_timeout(Some(remaining))?;
        }
        self.inner.read(bytes)
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.release_connection();
    }
}

/// `local_receiver` marks the child process that receives a local copy.
pub fn run(local_receiver: bool) -> Result<()> {
    let _termination = clean_up_on_termination();
    let descriptor_session = DescriptorSessionSlot::default();
    let result = serve(
        io::stdin(),
        io::stdout().lock(),
        true,
        None,
        None,
        None,
        ServeSession {
            owns_process: true,
            handshake_pending: None,
            ssh_worker_ticket: None,
            allow_tcp: true,
            metadata_control: false,
            loopback_only: local_receiver,
            named_socket: None,
            authority: None,
            source_authority: None,
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    crate::process::termination::wait_if_terminating();
    result
}

pub(crate) fn run_restricted(authority: Arc<crate::restricted::RestrictedAuthority>) -> Result<()> {
    let _termination = clean_up_on_termination();
    let (_workers, ticket) = match crate::restricted::start_ssh_workers(authority.clone()) {
        Ok((workers, ticket)) => (Some(workers), Ok(ticket)),
        Err(error) => (
            None,
            Err(format!("start restricted SSH workers: {error:#}")),
        ),
    };
    let descriptor_session = DescriptorSessionSlot::default();
    let result = serve(
        io::stdin(),
        io::stdout().lock(),
        true,
        None,
        None,
        None,
        ServeSession {
            owns_process: true,
            handshake_pending: None,
            ssh_worker_ticket: Some(ticket),
            allow_tcp: true,
            metadata_control: false,
            loopback_only: false,
            named_socket: None,
            authority: Some(Arc::clone(&authority)),
            source_authority: None,
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    authority.close_control();
    crate::process::termination::wait_if_terminating();
    result
}

/// A relayed one-copy control. File payload uses direct TCP or SSH workers.
/// `owns_process` marks a process that serves only this copy: it removes the
/// copy's sidecars when interrupted or when the control is lost.
pub(crate) fn run_forwarded<R: Read + Send + 'static, W: Write>(
    authority: Arc<crate::restricted::RestrictedAuthority>,
    input: R,
    output: W,
    pending: Arc<std::sync::atomic::AtomicBool>,
    owns_process: bool,
) -> Result<()> {
    let _termination = owns_process.then(clean_up_on_termination).flatten();
    let descriptor_session = DescriptorSessionSlot::default();
    let result = serve(
        input,
        output,
        true,
        None,
        None,
        None,
        ServeSession {
            owns_process,
            handshake_pending: Some(pending),
            ssh_worker_ticket: None,
            allow_tcp: true,
            metadata_control: true,
            loopback_only: false,
            named_socket: None,
            authority: Some(authority.clone()),
            source_authority: None,
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    authority.close_control();
    if owns_process {
        crate::process::termination::wait_if_terminating();
    }
    result
}

fn file_payload_request(request: &Request) -> bool {
    // Keep this exhaustive: every new protocol operation must explicitly
    // choose whether it can carry file data over the relayed control channel.
    match request {
        Request::ReadRange { .. }
        | Request::ReadSmallBatch(_)
        | Request::WriteRange { .. }
        | Request::PutSmallBatch(_)
        | Request::CopySmallFiles(_)
        | Request::ReadStream(_)
        | Request::DescriptorCopy(_)
        | Request::ReadComparedRange { .. }
        | Request::ReadDifferingBatch { .. }
        | Request::PatchSmallBatch(_)
        | Request::PatchBegin { .. }
        | Request::PatchData { .. }
        | Request::PatchEnd { .. } => true,
        Request::Hello { .. }
        | Request::TcpListen { .. }
        | Request::Scan { .. }
        | Request::ListDir { .. }
        | Request::NativeRemove { .. }
        | Request::StatMany { .. }
        | Request::CheckOperatorDirectory { .. }
        | Request::CheckOperatorDirectoryAncestry { .. }
        | Request::RegisterSourceRoots { .. }
        | Request::CreateOperatorDirectory { .. }
        | Request::AnchorDestination { .. }
        | Request::DestinationFilesystemInfo { .. }
        | Request::PartialPaths { .. }
        | Request::WidenDirectories { .. }
        | Request::Apply { .. }
        | Request::PlanBatch { .. }
        | Request::ProbePartial { .. }
        | Request::Prepare { .. }
        | Request::HashAndHold { .. }
        | Request::HashExistingBatch { .. }
        | Request::FinishBasis { .. }
        | Request::SeedBasis { .. }
        | Request::CopyLocal { .. }
        | Request::HashBlocks { .. }
        | Request::Finalize { .. }
        | Request::FileHash { .. }
        | Request::Canonicalize { .. }
        | Request::TransportStats
        | Request::Receipt
        | Request::Shutdown
        | Request::ListDirDetails { .. }
        | Request::StopReadStream
        | Request::WriteStreamFence
        | Request::ShrinkReadStream { .. }
        | Request::ListDirNoFollowFinal { .. }
        | Request::MappingChunk { .. }
        | Request::PruneLookup { .. }
        | Request::ConfigureHashing(_)
        | Request::ValidateDigest { .. }
        | Request::BindStream(_)
        | Request::ConfigurePreservation { .. }
        | Request::NativeMap(_)
        | Request::PrepareSmallFiles(_)
        | Request::StageBasis { .. }
        | Request::HashWindow { .. }
        | Request::ReuseComparedRange { .. }
        | Request::CreateSendBudget { .. } => false,
    }
}

/// An authenticated named-destination channel. Worker admission and path
/// checks are identical to restricted TCP workers; SSH encrypts these streams.
pub(crate) fn run_named(
    r: crate::private_broker::TrackedStream,
    w: std::os::unix::net::UnixStream,
    authority: Arc<crate::restricted::RestrictedAuthority>,
    control: bool,
) -> Result<()> {
    let descriptor_session = DescriptorSessionSlot::default();
    let socket = w.try_clone()?;
    let timeout = socket
        .read_timeout()?
        .context("named handshake requires a timeout")?;
    let reader = NamedHandshakeReader {
        inner: r,
        socket: socket.try_clone()?,
        deadline: std::time::Instant::now() + timeout,
    };
    let result = serve(
        reader,
        w,
        control,
        None,
        None,
        None,
        ServeSession {
            owns_process: false,
            handshake_pending: None,
            ssh_worker_ticket: None,
            allow_tcp: false,
            metadata_control: false,
            loopback_only: false,
            named_socket: Some(socket),
            authority: Some(Arc::clone(&authority)),
            source_authority: None,
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    if control {
        authority.close_control();
    }
    result
}

/// One approved source control stream. The caller creates a fresh descriptor
/// session and shares it with its private worker broker; this control owns the
/// session lifetime. Dropping that broker after this returns wakes idle workers.
pub(crate) fn run_authorized_source<R: Read + Send + 'static, W: Write>(
    input: R,
    output: W,
    authority: Arc<crate::restricted::source::SourceAuthority>,
    descriptor_session: DescriptorSessionSlot,
    pending: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> Result<()> {
    let result = serve(
        input,
        output,
        true,
        None,
        None,
        None,
        ServeSession {
            owns_process: false,
            handshake_pending: pending,
            ssh_worker_ticket: None,
            allow_tcp: true,
            metadata_control: false,
            loopback_only: false,
            named_socket: None,
            authority: None,
            source_authority: Some(authority.clone()),
            descriptor_session: descriptor_session.clone(),
        },
    );
    authority.close();
    descriptor_session.close();
    result
}

/// A private-broker source worker. Its outer SSH/Unix-channel authentication
/// must be complete before entry. Only source worker Hello roles are allowed;
/// the live authority validates the exact descriptors installed by control.
#[cfg(test)]
pub(crate) fn run_authorized_source_worker(
    input: crate::private_broker::TrackedStream,
    output: std::os::unix::net::UnixStream,
    authority: Arc<crate::restricted::source::SourceAuthority>,
    descriptor_session: DescriptorSessionSlot,
) -> Result<()> {
    let socket = output.try_clone()?;
    let timeout = socket
        .read_timeout()?
        .context("source worker handshake requires a timeout")?;
    let reader = NamedHandshakeReader {
        inner: input,
        socket: socket.try_clone()?,
        deadline: Instant::now() + timeout,
    };
    serve(
        reader,
        output,
        false,
        None,
        None,
        None,
        ServeSession {
            owns_process: false,
            handshake_pending: None,
            ssh_worker_ticket: None,
            allow_tcp: false,
            metadata_control: false,
            loopback_only: false,
            named_socket: Some(socket),
            authority: None,
            source_authority: Some(authority),
            descriptor_session,
        },
    )
}

/// A laptop-initiated TCP worker, admitted through its approved SSH channel.
pub(crate) fn run_named_tcp(
    stream: TcpStream,
    channel: std::os::unix::net::UnixStream,
    key: &[u8],
    authority: Arc<crate::restricted::RestrictedAuthority>,
) -> Result<()> {
    let descriptor_session = DescriptorSessionSlot::default();
    let pending = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let reader = TcpHandshakeReader {
        stream: stream.try_clone()?,
        pending: pending.clone(),
        deadline: std::time::Instant::now() + Duration::from_secs(10),
    };
    let result = serve(
        RecordReader::new(reader, Some(Cipher::new(key, 0, 1))),
        RecordWriter::new(stream.try_clone()?, Some(Cipher::new(key, 0, 2))),
        false,
        Some(Vec::new()),
        None,
        Some(stream),
        ServeSession {
            owns_process: false,
            handshake_pending: Some(pending),
            ssh_worker_ticket: None,
            allow_tcp: false,
            metadata_control: false,
            loopback_only: false,
            named_socket: Some(channel),
            authority: Some(authority),
            source_authority: None,
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    result
}

pub(crate) fn return_tcp_addresses(listeners: &[TcpListener]) -> Vec<(String, u32)> {
    local_addrs(BoundFamilies {
        v4: listeners
            .iter()
            .any(|l| l.local_addr().is_ok_and(|a| a.is_ipv4())),
        v6: listeners
            .iter()
            .any(|l| l.local_addr().is_ok_and(|a| a.is_ipv6())),
    })
}

/// Serve one connection. `over_ssh` connections may set up a TCP listener;
/// TCP connections must present `expect_token` in their Hello.
fn serve<R: Read + Send + 'static, W: Write>(
    r: R,
    w: W,
    over_ssh: bool,
    expect_token: Option<Vec<u8>>,
    authed: Option<&std::sync::atomic::AtomicBool>,
    tcp_socket: Option<TcpStream>,
    session: ServeSession,
) -> Result<()> {
    let ServeSession {
        owns_process,
        handshake_pending,
        ssh_worker_ticket,
        allow_tcp,
        metadata_control,
        loopback_only,
        named_socket,
        authority,
        source_authority,
        descriptor_session,
    } = session;
    anyhow::ensure!(
        authority.is_none() || source_authority.is_none(),
        "a server session cannot combine source and destination authority"
    );
    let mut r = FrameReader::new(r);
    r.set_limit(MAX_HANDSHAKE_FRAME);
    let sending_budget = Arc::new(std::sync::OnceLock::new());
    let disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = disconnected.clone();
    let source_stopped = source_authority.clone();
    let mut w = FrameWriter::new(
        crate::bwlimit::transport::SessionWriter {
            inner: w,
            budget: sending_budget.clone(),
            stopped: move || {
                stopped.load(std::sync::atomic::Ordering::Acquire)
                    || source_stopped
                        .as_ref()
                        .is_some_and(|source| !source.is_open())
            },
        },
        false,
    );
    // Send our build identity before waiting for the client's first postcard
    // frame. Both peers can therefore diagnose version skew even when their
    // Request or Response enum layouts no longer agree.
    w.write_preamble().context("write wire preamble")?;

    let debug;
    let role;
    // Held for the life of the connection; dropping it releases the worker
    // permit even when a later request fails.
    let _permit: Option<ConnectionPermit>;
    let source_permit;
    let (hello, _hello_hold) = r.read_budgeted::<Request>()?.into_parts();
    match hello {
        Request::Hello {
            identity,
            compress,
            debug: d,
            token,
            role: requested_role,
        } => {
            debug = d;
            if let Some(t) = &expect_token {
                if !bool::from(token.ct_eq(t)) {
                    bail!("bad token on data connection");
                }
            }
            // The token is the credential: once it matches, the peer is
            // authenticated. Mark it now so a later failure (identity mismatch
            // or a failed HelloOk write) can't free the connection id for replay.
            if let Some(a) = authed {
                a.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            // Only an authenticated data connection counts against the signed
            // grant's worker allowance. The control connection arrives over
            // ssh and is not a worker.
            _permit = match (&authority, over_ssh) {
                (Some(authority), false) if named_socket.is_none() => {
                    Some(ConnectionPermit::acquire(authority.clone())?)
                }
                _ => None,
            };
            let expected_identity = crate::identity::build();
            if identity != expected_identity {
                w.write_msg(&Response::Err(format!(
                    "build identity mismatch (remote {expected_identity}, client {identity})"
                )))?;
                bail!("build identity mismatch");
            }
            if metadata_control && !matches!(requested_role, ConnectionRole::Control) {
                w.write_msg(&Response::Err(
                    "bridged connection requires the control role".into(),
                ))?;
                bail!("bridged connection requires the control role");
            }
            if let Some(authority) = &authority {
                authority.validate_hello(compress)?;
            }
            source_permit = match &source_authority {
                Some(source) => match source.acquire(&requested_role, compress) {
                    Ok(permit) => Some(permit),
                    Err(error) => {
                        w.write_msg(&Response::Err(format!("{error:#}")))?;
                        return Err(error);
                    }
                },
                None => None,
            };
            role = requested_role;
            w.compress = compress;
        }
        _ => bail!("expected Hello"),
    }

    if matches!(&role, ConnectionRole::Control) && !over_ssh {
        w.write_msg(&Response::Err(
            "control role is not allowed on a TCP data connection".into(),
        ))?;
        bail!("control role is not allowed on a TCP data connection");
    }
    let is_control = matches!(&role, ConnectionRole::Control);
    let is_source_worker = matches!(&role, ConnectionRole::SourceWorker { .. });
    // The copy's sidecars are registered from here so that they can be
    // removed; the guard is dropped on every return, after the reader.
    if owns_process {
        crate::fsops::track_sidecars();
    }
    let sweep_on_loss = owns_process.then(|| SweepOnLoss::new(is_control));
    let _sweep = sweep_on_loss.clone();
    let mut ops = FsOps::with_descriptor_session(descriptor_session.clone());
    if let Some(authority) = &authority {
        ops.set_hash_policy(authority.hash_policy());
    }
    if let Some(source) = &source_permit {
        source.initialize(&mut ops)?;
    }
    let mut initial_sending_budget = match source_authority
        .as_ref()
        .filter(|_| is_source_worker && tcp_socket.is_none())
    {
        Some(source) => source
            .sending_budget(&descriptor_session)?
            .map(|(budget, _)| budget),
        None => None,
    };
    match &role {
        ConnectionRole::SourceWorker { .. } if authority.is_some() => {
            w.write_msg(&Response::Err(
                "a command-restricted receiver does not accept caller-supplied source roots".into(),
            ))?;
            bail!("command-restricted receiver rejected supplied source roots");
        }
        ConnectionRole::SourceWorker { roots, send_budget } => {
            if let Some(ticket) = send_budget.as_ref().filter(|_| source_authority.is_none()) {
                anyhow::ensure!(over_ssh, "SSH sender budget supplied over TCP");
                anyhow::ensure!(ticket.is_bandwidth(), "not a bandwidth budget ticket");
                let file = descriptor_session.acquire(ticket)?;
                initial_sending_budget = Some(Arc::new(
                    crate::bwlimit::transport::Budget::from_shared(&file)?,
                ));
            }
            if let Err(error) = ops.initialize_sources(roots) {
                w.write_msg(&Response::Err(format!(
                    "initialize source worker: {error:#}"
                )))?;
                return Err(error).context("initialize source worker");
            }
        }
        ConnectionRole::DestinationWorker { copy_sources, .. }
            if authority.is_some() && !copy_sources.is_empty() =>
        {
            w.write_msg(&Response::Err(
                "a command-restricted receiver does not accept caller-supplied copy sources".into(),
            ))?;
            bail!("command-restricted receiver rejected supplied copy sources");
        }
        ConnectionRole::DestinationWorker {
            destination: Some(_),
            ..
        } if authority.is_some() => {
            w.write_msg(&Response::Err(
                "a command-restricted destination derives its root from the signed grant".into(),
            ))?;
            bail!("command-restricted receiver rejected a supplied destination root");
        }
        ConnectionRole::DestinationWorker {
            destination: None, ..
        } if authority.is_none() => {
            w.write_msg(&Response::Err(
                "unrestricted destination worker requires a registered root".into(),
            ))?;
            bail!("unrestricted destination worker has no registered root");
        }
        ConnectionRole::DestinationWorker {
            destination: Some(destination),
            copy_sources,
        } => {
            if let Err(error) = ops.initialize_destination(destination) {
                w.write_msg(&Response::Err(format!(
                    "initialize destination worker: {error:#}"
                )))?;
                return Err(error).context("initialize destination worker");
            }
            if !copy_sources.is_empty() {
                if let Err(error) = ops.initialize_copy_sources(copy_sources) {
                    w.write_msg(&Response::Err(format!(
                        "initialize local copy sources: {error:#}"
                    )))?;
                    return Err(error).context("initialize local copy sources");
                }
            }
        }
        ConnectionRole::StreamWorker { ticket, settings } => {
            let initialized = if authority.is_some() {
                Err(anyhow::anyhow!(
                    "restricted receivers do not accept stream file capabilities"
                ))
            } else {
                ops.initialize_stream(ticket, *settings)
            };
            if let Err(error) = initialized {
                w.write_msg(&Response::Err(format!(
                    "initialize stream worker: {error:#}"
                )))?;
                return Err(error);
            }
        }
        ConnectionRole::Control
        | ConnectionRole::DestinationWorker {
            destination: None, ..
        } => {}
    }
    // Configure the data phase before acknowledging Hello. The peer may
    // send its final requests and close as soon as it sees HelloOk.
    if let Some(socket) = &tcp_socket {
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
    }
    if let Some(socket) = &named_socket {
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
    }

    // All foreign descriptor claims and their close-on-exec setup are complete
    // before readiness is acknowledged or this connection starts its reader.
    w.write_msg(&Response::HelloOk {
        descriptors: is_control
            .then(crate::resources::Descriptors::current)
            .flatten(),
        identity: crate::identity::build().to_string(),
        platform: crate::identity::platform(),
        supports_confined_socket_nodes: crate::identity::supports_confined_socket_nodes(),
        ssh_worker_ticket: if is_control { ssh_worker_ticket } else { None },
    })?;

    if let Some(pending) = handshake_pending {
        pending.store(false, std::sync::atomic::Ordering::Release);
    }

    if let Some(budget) = initial_sending_budget {
        sending_budget
            .set(budget)
            .map_err(|_| anyhow::anyhow!("sender budget already attached"))?;
    }

    // Requests are parsed on a reader thread so incoming data keeps flowing
    // while a block is being hashed and written. TCP readers are shut down and
    // joined by the guard on every exit path.
    r.set_limit(MAX_FRAME);
    let telemetry_socket = tcp_socket.as_ref().and_then(|s| s.try_clone().ok());
    let source_control = source_authority
        .as_ref()
        .filter(|_| matches!(role, ConnectionRole::Control))
        .cloned();
    let reader = RequestReader::spawn(
        r,
        tcp_socket,
        named_socket,
        disconnected,
        source_control,
        sweep_on_loss,
    )
    .context("start request reader")?;
    let server_actor = ops.observations.actor("server");
    let mut w = ObservedWriter {
        compress: w.compress,
        inner: w,
        registry: ops.observations.clone(),
        actor: server_actor.clone(),
        last: std::time::Instant::now(),
        enabled: false,
        socket: telemetry_socket,
        source_authority: source_authority.clone(),
    };

    // A restricted receiver holds each streamed patch to its grant across
    // its pieces. Declared after `ops`, so that a connection that closes with
    // one open settles it before its stage is removed.
    let mut stream_gate = authority
        .as_ref()
        .map(|authority| crate::restricted::PatchStreamGate::new(authority.clone()));
    let (mut blocks, mut bytes) = (0u64, 0u64);
    loop {
        let waiting = server_actor.span(crate::transfer_observations::Stage::RequestWait);
        let queued = match reader.recv() {
            Ok(Ok(req)) => req,
            Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        };
        drop(waiting);
        let (mut req, _request_hold) = queued.into_parts();
        // A connection with a streamed patch open carries nothing else
        // until the patch ends; closing the connection abandons it.
        if (ops.patch_stream_open()
            || stream_gate
                .as_ref()
                .is_some_and(crate::restricted::PatchStreamGate::is_open))
            && !matches!(
                req,
                Request::PatchData { .. } | Request::PatchEnd { .. } | Request::Shutdown
            )
        {
            w.write_msg(&Response::Err(crate::fsops::OPEN_PATCH_STREAM.into()))?;
            continue;
        }
        if metadata_control && file_payload_request(&req) {
            w.write_msg(&Response::Err(
                "file payload requires a direct data worker".into(),
            ))?;
            continue;
        }

        if !is_control
            && matches!(
                &req,
                Request::TcpListen { .. }
                    | Request::CreateSendBudget { .. }
                    | Request::DescriptorCopy(_)
                    | Request::ListDir { .. }
                    | Request::ListDirDetails { .. }
                    | Request::ListDirNoFollowFinal { .. }
                    | Request::NativeMap(_)
                    | Request::NativeRemove { .. }
                    | Request::CheckOperatorDirectory { .. }
                    | Request::CheckOperatorDirectoryAncestry { .. }
                    | Request::RegisterSourceRoots { .. }
                    | Request::CreateOperatorDirectory { .. }
                    | Request::AnchorDestination { .. }
                    | Request::PrepareSmallFiles(_)
                    | Request::CopySmallFiles(_)
                    | Request::PruneLookup { .. }
                    | Request::Receipt
                    | Request::MappingChunk { .. }
            )
        {
            w.write_msg(&Response::Err(
                "request is allowed only on the control connection".into(),
            ))?;
            continue;
        }
        if is_source_worker && !req.allowed_on_source_worker() {
            w.write_msg(&Response::Err(
                "request is not valid on a source worker".into(),
            ))?;
            continue;
        }
        if let Some(source) = &source_permit {
            if matches!(req, Request::RegisterSourceRoots { .. }) {
                let response = match source.register(&mut ops, &req) {
                    Ok(response) => response,
                    Err(error) => Response::Err(format!("{error:#}")),
                };
                w.write_msg(&response)?;
                continue;
            }
            // Whole-file hashing authorizes and checks each chunk in its
            // dedicated executor below, including standalone callers.
            if !matches!(req, Request::FileHash { .. }) {
                if let Err(error) = source.authorize(&req) {
                    w.write_msg(&Response::Err(format!("{error:#}")))?;
                    continue;
                }
            }
        }
        // A fence performs no filesystem operation and grants no authority.
        // It must work after expiration/revocation too: preceding writes have
        // already received their individual authorization/error responses.
        if matches!(req, Request::WriteStreamFence) {
            w.write_msg(&Response::WriteStreamDone)?;
            continue;
        }
        let settlement = match &mut stream_gate {
            Some(gate) => match gate.authorize(&mut req, over_ssh) {
                Ok(settlement) => Some(settlement),
                Err(error) => {
                    let error = format!("{error:#}");
                    // A refused piece fails its patch, whose end reports it;
                    // a refused end abandons the patch.
                    match req {
                        Request::PatchData { .. } => ops.fail_patch_stream(&error),
                        Request::PatchEnd { .. } => {
                            ops.abandon_patch_stream();
                            gate.abandon(&error);
                        }
                        _ => {}
                    }
                    w.write_msg(&Response::Err(error))?;
                    continue;
                }
            },
            None => None,
        };
        if let Err(error) = ops.validate_source_session_request(&req) {
            w.write_msg(&Response::Err(format!("{error:#}")))?;
            continue;
        }
        match &req {
            Request::WriteRange { data, .. } => {
                blocks += 1;
                bytes += data.len() as u64;
            }
            Request::ReadRange { len, .. } | Request::ReadComparedRange { len, .. } => {
                blocks += 1;
                bytes += *len as u64;
            }
            Request::ReadSmallBatch(reads) => {
                blocks += reads.len() as u64;
                bytes += reads.iter().map(|read| u64::from(read.len)).sum::<u64>();
            }
            Request::ReadDifferingBatch { reads, .. } => {
                blocks += reads.len() as u64;
                bytes += reads.iter().map(|read| u64::from(read.len)).sum::<u64>();
            }
            Request::PatchSmallBatch(patches) => {
                blocks += patches.len() as u64;
                bytes += patches
                    .iter()
                    .map(|patch| patch.data.len() as u64)
                    .sum::<u64>();
            }
            Request::PatchData { data, .. } => {
                blocks += 1;
                bytes += data.len() as u64;
            }
            Request::PutSmallBatch(puts) => {
                blocks += puts.len() as u64;
                bytes += puts.iter().map(|put| put.data.len() as u64).sum::<u64>();
            }
            _ => {}
        }
        match req {
            Request::Shutdown => break,
            Request::CreateSendBudget { rate } => {
                let response = if let Some(source) = &source_authority {
                    match source.sending_budget(&descriptor_session) {
                        Ok(Some((_, ticket))) => Response::SendBudget(ticket),
                        Ok(None) => Response::Err("source sender budget was not approved".into()),
                        Err(error) => Response::Err(format!("{error:#}")),
                    }
                } else if authority.is_none() && over_ssh {
                    match descriptor_session.send_budget(rate) {
                        Ok((_, ticket)) => Response::SendBudget(ticket),
                        Err(error) => Response::Err(format!("{error:#}")),
                    }
                } else {
                    Response::Err("sender budget requires an ordinary control session".into())
                };
                w.write_msg(&response)?;
            }
            Request::ReadStream(mut stream) => {
                if !is_source_worker {
                    w.write_msg(&Response::Err(
                        "read stream requires a source worker".into(),
                    ))?;
                    continue;
                }
                if let Err(error) = stream.validate() {
                    w.write_msg(&Response::Err(error.to_string()))?;
                    continue;
                }
                w.write_msg(&Response::Ok)?;
                ops.begin_source_range(stream.off..stream.end);
                let mut limit = stream.end;
                let mut done_sent = false;
                loop {
                    // Once all payload (or a read error) is sent, advertise
                    // the data boundary without waiting another network RTT
                    // for Stop. Still consume Stop before leaving this mode:
                    // the client's later commands follow it on the same
                    // ordered connection, including late shrink notifications.
                    if stream.off >= limit && !done_sent {
                        ops.end_source_range();
                        w.write_msg(&Response::ReadStreamDone)?;
                        done_sent = true;
                    }
                    if reader.stream_stopped(stream.off, &mut limit, done_sent)? {
                        break;
                    }
                    ops.shrink_source_range(limit);
                    if stream.off >= limit {
                        // A late shrink crossed the current offset: send Done
                        // on the next iteration, without another read or RTT.
                        continue;
                    }
                    let mut request = stream.next_request();
                    let response = match source_permit
                        .as_ref()
                        .map(|source| source.authorize(&request))
                        .transpose()
                    {
                        Ok(_) => ops.handle_in_place(&mut request),
                        Err(error) => Response::Err(format!("{error:#}")),
                    };
                    if let Response::Block { data, .. } = &response {
                        stream.off += data.len() as u64;
                        blocks += 1;
                        bytes += data.len() as u64;
                    } else {
                        stream.off = stream.end;
                        ops.end_source_range();
                    }
                    w.write_msg(&response)?;
                }
                ops.end_source_range();
                if !done_sent {
                    w.write_msg(&Response::ReadStreamDone)?;
                }
            }
            Request::StopReadStream | Request::ShrinkReadStream { .. } => {
                w.write_msg(&Response::Err("no read stream is active".into()))?;
            }
            Request::TcpListen {
                key,
                token,
                port_lo,
                port_hi,
                congestion_control,
                send_rate,
            } => {
                if !allow_tcp {
                    w.write_msg(&Response::Err(
                        "named destinations carry data through SSH; TCP listeners are disabled"
                            .into(),
                    ))?;
                    continue;
                }
                if !is_control {
                    w.write_msg(&Response::Err(
                        "TcpListen only allowed on the control connection".into(),
                    ))?;
                    continue;
                }
                if send_rate == Some(0) || (send_rate.is_some() && authority.is_some()) {
                    w.write_msg(&Response::Err(
                        "invalid transport bandwidth configuration".into(),
                    ))?;
                    continue;
                }
                match tcp_listen(
                    key,
                    token,
                    port_lo,
                    port_hi,
                    loopback_only,
                    debug,
                    w.compress,
                    congestion_control.as_deref(),
                    send_rate,
                    authority.clone(),
                    source_authority.clone(),
                    descriptor_session.clone(),
                ) {
                    Ok((port, families, congestion_control)) => {
                        w.write_msg(&Response::TcpListening {
                            port,
                            // The local client connects to loopback directly.
                            addrs: if loopback_only {
                                Vec::new()
                            } else {
                                local_addrs(families)
                            },
                            congestion_control,
                        })?
                    }
                    Err(e) if crate::conn::is_tcp_congestion_error(&e) => {
                        w.write_msg(&Response::TcpCongestionRejected(format!("{e:#}")))?
                    }
                    Err(e) => w.write_msg(&Response::Err(format!("{e:#}")))?,
                }
            }
            Request::NativeMap(options) => {
                struct Output<'a, W: std::io::Write>(&'a mut ObservedWriter<W>);
                impl<W: std::io::Write> std::io::Write for Output<'_, W> {
                    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                        for chunk in data.chunks(64 * 1024) {
                            self.0.write_msg(&Response::NativeMapData(chunk.to_vec()))?;
                        }
                        Ok(data.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                let mut out = std::io::BufWriter::with_capacity(64 * 1024, Output(&mut w));
                let result = crate::native_map::write_local(&options, &mut out).and_then(|()| {
                    std::io::Write::flush(&mut out)?;
                    Ok(())
                });
                drop(out);
                match result {
                    Ok(()) => w.write_msg(&Response::NativeMapDone)?,
                    Err(error) => w.write_msg(&Response::Err(format!("{error:#}")))?,
                }
            }
            Request::NativeRemove {
                cwd,
                root,
                selections,
                follow_symlinks,
                dry_run,
                workers,
            } => {
                let wref = std::cell::RefCell::new(&mut w);
                let result = crate::native_rm::remove(
                    cwd.as_deref(),
                    root.as_deref(),
                    &selections,
                    follow_symlinks,
                    dry_run,
                    workers,
                    &mut |messages| {
                        Ok(wref
                            .borrow_mut()
                            .write_msg(&Response::NativeRemoveTrace(messages))?)
                    },
                    &mut |outcomes| {
                        Ok(wref
                            .borrow_mut()
                            .write_msg(&Response::NativeRemoveBatch(outcomes))?)
                    },
                );
                match result {
                    Ok(()) => wref.borrow_mut().write_msg(&Response::NativeRemoveDone)?,
                    Err(error) => wref
                        .borrow_mut()
                        .write_msg(&Response::EndpointError(crate::fsops::wire_error(&error)))?,
                }
            }
            Request::Scan {
                root,
                source,
                follow_root,
                ignore,
                report_ignored,
                guard,
            } => {
                let requested_root = root.clone();
                let source_scan = if guard.is_none() {
                    match ops.source_scan_root(source.as_ref()) {
                        Ok(scan) => scan,
                        Err(error) => {
                            w.write_msg(&Response::Err(format!("{error:#}")))?;
                            continue;
                        }
                    }
                } else {
                    None
                };
                let destination_scan = if guard.is_none() {
                    match ops.destination_scan_root(&root) {
                        Ok(scan) => scan,
                        Err(error) => {
                            w.write_msg(&Response::Err(format!("{error:#}")))?;
                            continue;
                        }
                    }
                } else {
                    None
                };
                let root = match ops.scan_root(&root) {
                    Ok(root) => root,
                    Err(error) => {
                        w.write_msg(&Response::Err(format!("{error:#}")))?;
                        continue;
                    }
                };
                // Warnings are collected and sent between batches so a single
                // writer borrow suffices.
                let warns = std::cell::RefCell::new(Vec::new());
                let wref = std::cell::RefCell::new(&mut w);
                let mut sink = |mut batch: Vec<crate::proto::Entry>| {
                    if let Some(permit) = &source_permit {
                        permit.record_scan(
                            source
                                .as_ref()
                                .context("approved source scan omitted its reference")?,
                            batch.iter().map(|entry| entry.path.as_slice()),
                        )?;
                    }
                    ops.capture_scan_metadata(
                        &requested_root,
                        source.as_ref(),
                        follow_root,
                        guard.as_ref(),
                        &mut batch,
                    )?;
                    if let Some(authority) = &authority {
                        authority.record_scanned(
                            &requested_root,
                            batch.iter().map(|entry| entry.path.as_slice()),
                        )?;
                    }
                    let mut w = wref.borrow_mut();
                    for m in warns.borrow_mut().drain(..) {
                        w.write_msg(&Response::ScanWarn(m))?;
                    }
                    if ops.preserving_inode_metadata() {
                        write_metadata_batches(
                            &mut w,
                            batch,
                            crate::proto::Entry::size_hint,
                            Response::ScanBatch,
                            Response::ScanBatch,
                        )?;
                        Ok(())
                    } else {
                        Ok(w.write_msg(&Response::ScanBatch(batch))?)
                    }
                };
                let mut ignored = |paths: Vec<crate::proto::PathBytes>| {
                    if let Some(permit) = &source_permit {
                        permit.record_scan(
                            source
                                .as_ref()
                                .context("approved source scan omitted its reference")?,
                            paths.iter().map(Vec::as_slice),
                        )?;
                    }
                    if let Some(authority) = &authority {
                        authority
                            .record_scanned(&requested_root, paths.iter().map(Vec::as_slice))?;
                    }
                    Ok(wref.borrow_mut().write_msg(&Response::ScanIgnored(paths))?)
                };
                let res = if let Some(guard) = &guard {
                    crate::scan::scan_rooted(
                        &root,
                        follow_root,
                        &ignore,
                        report_ignored,
                        guard,
                        &mut sink,
                        &mut ignored,
                        &mut |msg| warns.borrow_mut().push(msg),
                    )
                } else if let Some(source) = source_scan {
                    crate::scan::scan_descriptor(
                        source.root,
                        &source.relative,
                        source.expected_leaf,
                        false,
                        false,
                        &ignore,
                        report_ignored,
                        &mut sink,
                        &mut ignored,
                        &mut |msg| warns.borrow_mut().push(msg),
                    )
                } else if let Some((destination_root, relative)) = destination_scan {
                    crate::scan::scan_descriptor(
                        destination_root,
                        &relative,
                        None,
                        follow_root,
                        true,
                        &ignore,
                        report_ignored,
                        &mut sink,
                        &mut ignored,
                        &mut |msg| warns.borrow_mut().push(msg),
                    )
                } else {
                    crate::scan::scan(
                        &fsops::resolve(&root),
                        follow_root,
                        &ignore,
                        report_ignored,
                        &mut sink,
                        &mut ignored,
                        &mut |msg| warns.borrow_mut().push(msg),
                    )
                };
                for m in warns.borrow_mut().drain(..) {
                    w.write_msg(&Response::ScanWarn(m))?;
                }
                match res {
                    Ok(count) => {
                        if count > 0 {
                            w.write_msg(&Response::ScanIgnoredCount(count))?;
                        }
                        w.write_msg(&Response::ScanDone)?;
                    }
                    Err(e) => w.write_msg(&Response::Err(format!("{e:#}")))?,
                }
            }
            Request::TransportStats => {
                #[cfg(debug_assertions)]
                if let Some(mode) = std::env::var_os("SYQ_TEST_REJECT_TELEMETRY") {
                    if mode == "disconnect" {
                        break;
                    }
                    w.write_msg(&Response::Err("telemetry unavailable (test)".into()))?;
                    continue;
                }
                ops.observations.enable();
                w.enabled = true;
                w.write_msg(&Response::TransportStats(Box::new(TransportStatsReply {
                    tcp: reader.tcp_stats(),
                    observation: Some(ops.observations.snapshot()),
                    solicited: true,
                })))?;
            }
            Request::MappingChunk { .. } => {
                let response = if authority.is_some() {
                    Response::Ok
                } else {
                    Response::Err("mapping admission requires a restricted receiver".into())
                };
                if let (Some(gate), Some(settlement)) = (&mut stream_gate, settlement) {
                    gate.settle(settlement, &response, ops.patch_stream_open());
                }
                w.write_msg(&response)?;
            }
            Request::Receipt => match &authority {
                Some(authority) => match authority.issue_receipt() {
                    Ok(receipt) => {
                        crate::receipt::emit_receipt_frames(receipt, |frame| {
                            w.write_msg(&Response::Receipt(frame))?;
                            Ok(())
                        })?;
                    }
                    Err(error) => w.write_msg(&Response::Err(format!("{error:#}")))?,
                },
                None => w.write_msg(&Response::Err(
                    "receipts are issued only by a command-restricted receiver".into(),
                ))?,
            },
            mut other => {
                let resp = if let Some(source) = source_permit
                    .as_ref()
                    .filter(|_| matches!(other, Request::FileHash { .. }))
                {
                    match source.file_hash(&mut ops, &other) {
                        Ok(response) => response,
                        Err(error) => Response::Err(format!("{error:#}")),
                    }
                } else {
                    ops.handle_with_copy_progress(&mut other, &mut |bytes| {
                        w.write_msg(&Response::CopyLocalProgress(bytes))?;
                        Ok(())
                    })
                };
                if let (Some(gate), Some(settlement)) = (&mut stream_gate, settlement) {
                    gate.settle(settlement, &resp, ops.patch_stream_open());
                }
                if drop_after_handling_for_test(&other) {
                    return Ok(());
                }
                if ops.preserving_inode_metadata() {
                    if let Response::Stats(entries) = resp {
                        write_metadata_batches(
                            &mut w,
                            entries,
                            |e| e.as_ref().map_or(1, crate::proto::Entry::size_hint),
                            Response::StatsMore,
                            Response::Stats,
                        )?;
                    } else {
                        w.write_owned(resp)?;
                    }
                } else {
                    w.write_owned(resp)?;
                }
            }
        }
    }
    if debug {
        crate::output::diagnostic!(
            "syq server{}: {blocks} blocks, {} MiB",
            if over_ssh { "" } else { " (tcp)" },
            bytes >> 20,
        );
    }
    Ok(())
}

/// Bind the data listener on the first free port in `lo..=hi`, on both
/// address families when the host supports both. IPv6 is bound `V6ONLY` so the
/// two sockets never contend for the same wildcard address, whatever the
/// platform default. A port where either family is already taken is skipped
/// so the two listeners always share one port number; a family the host cannot
/// bind at all (no IPv6, say) is simply left out.
pub(crate) fn bind_data_listeners(
    lo: u16,
    hi: u16,
    loopback_only: bool,
) -> Result<(u16, Vec<TcpListener>)> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let mut last_error = None;
    // Port 0 asks the kernel for an ephemeral port: the first family's bind
    // chooses it and the second must follow. Retry a few times if the second
    // family finds that port taken.
    let attempts: Vec<u16> = if lo == 0 && hi == 0 {
        vec![0; 8]
    } else {
        (lo..=hi.max(lo)).collect()
    };
    for requested in attempts {
        let mut port = requested;
        let mut listeners: Vec<TcpListener> = Vec::new();
        let mut in_use = false;
        // A local copy's client connects to 127.0.0.1 only.
        let domains: &[Domain] = if loopback_only {
            &[Domain::IPV4]
        } else {
            &[Domain::IPV4, Domain::IPV6]
        };
        for &domain in domains {
            let bound = (|| -> std::io::Result<TcpListener> {
                let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                // As std's TcpListener::bind does: a port with lingering
                // TIME_WAIT sockets from an earlier transfer stays usable.
                #[cfg(unix)]
                socket.set_reuse_address(true)?;
                let address: SocketAddr = if domain == Domain::IPV4 {
                    let ip = if loopback_only {
                        Ipv4Addr::LOCALHOST
                    } else {
                        Ipv4Addr::UNSPECIFIED
                    };
                    (ip, port).into()
                } else {
                    socket.set_only_v6(true)?;
                    (Ipv6Addr::UNSPECIFIED, port).into()
                };
                socket.bind(&SockAddr::from(address))?;
                socket.listen(128)?;
                Ok(socket.into())
            })();
            match bound {
                Ok(listener) => {
                    if port == 0 {
                        port = listener.local_addr()?.port();
                    }
                    listeners.push(listener);
                }
                Err(error) if error.kind() == ErrorKind::AddrInUse => {
                    in_use = true;
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        if in_use || listeners.is_empty() {
            continue;
        }
        return Ok((port, listeners));
    }
    match last_error {
        Some(error) => bail!("no free port in {lo}-{hi} ({error})"),
        None => bail!("no free port in {lo}-{hi}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn tcp_listen(
    key: Option<Vec<u8>>,
    token: Vec<u8>,
    lo: u16,
    hi: u16,
    loopback_only: bool,
    debug: bool,
    compress: bool,
    congestion_control: Option<&str>,
    send_rate: Option<u64>,
    authority: Option<Arc<crate::restricted::RestrictedAuthority>>,
    source_authority: Option<Arc<crate::restricted::source::SourceAuthority>>,
    descriptor_session: DescriptorSessionSlot,
) -> Result<(u16, BoundFamilies, Option<String>)> {
    let pacing = if let Some(source) = &source_authority {
        source
            .sending_budget(&descriptor_session)?
            .map(|(budget, _)| budget)
    } else {
        send_rate
            .map(|rate| {
                descriptor_session
                    .send_budget(rate)
                    .map(|(budget, _)| budget)
            })
            .transpose()?
    };
    #[cfg(debug_assertions)]
    let loopback_only = loopback_only || std::env::var_os("SYQ_TEST_TCP_LOOPBACK_ONLY").is_some();
    let (port, listeners) = bind_data_listeners(lo, hi, loopback_only)?;
    // Passive connections inherit the listener's congestion controller. Set
    // and verify it on every listener before advertising the port so even
    // handshake-time behavior uses the requested algorithm.
    let mut effective_congestion_control = None;
    for listener in &listeners {
        let effective = crate::conn::configure_tcp_congestion(listener, congestion_control)?;
        effective_congestion_control = effective_congestion_control.or(effective);
    }
    let families = BoundFamilies {
        v4: listeners
            .iter()
            .any(|l| l.local_addr().is_ok_and(|a| a.is_ipv4())),
        v6: listeners
            .iter()
            .any(|l| l.local_addr().is_ok_and(|a| a.is_ipv6())),
    };
    let next_id = Arc::new(AtomicU32::new(1));
    // Bound in-flight data connections (a peer shouldn't be able to spawn
    // unbounded threads), and remember which client connection ids we've seen
    // so a captured record stream can't be replayed while the listener is up.
    // This bound covers every accepted socket, including reachability probes
    // and other peers that never authenticate. A signed grant's connection
    // limit is a separate allowance for authenticated workers only; `serve`
    // charges it once the Hello token has matched, so a probe or scanner
    // cannot consume a worker's permit and force a reset on a real worker.
    let live = Arc::new(AtomicU32::new(0));
    let seen: Arc<std::sync::Mutex<std::collections::HashSet<u32>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let max_live = MAX_LIVE_TCP_CONNECTIONS;
    // One accept thread per bound family; every listener feeds the same
    // token, connection limit, replay set, and id sequence.
    for listener in listeners {
        listener.set_nonblocking(true)?;
        let (key, token, next_id, live, seen, authority, source_authority, descriptor_session) = (
            key.clone(),
            token.clone(),
            next_id.clone(),
            live.clone(),
            seen.clone(),
            authority.clone(),
            source_authority.clone(),
            descriptor_session.clone(),
        );
        let pacing = pacing.clone();
        std::thread::Builder::new()
            .spawn(move || {
                accept_data_connections(
                    listener,
                    key,
                    token,
                    debug,
                    compress,
                    next_id,
                    live,
                    max_live,
                    seen,
                    authority,
                    source_authority,
                    descriptor_session,
                    pacing,
                )
            })
            .context("start TCP accept thread")?;
    }
    Ok((port, families, effective_congestion_control))
}

#[allow(clippy::too_many_arguments)]
fn accept_data_connections(
    listener: TcpListener,
    key: Option<Vec<u8>>,
    token: Vec<u8>,
    debug: bool,
    compress: bool,
    next_id: Arc<AtomicU32>,
    live: Arc<AtomicU32>,
    max_live: u32,
    seen: Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    authority: Option<Arc<crate::restricted::RestrictedAuthority>>,
    source_authority: Option<Arc<crate::restricted::source::SourceAuthority>>,
    descriptor_session: DescriptorSessionSlot,
    pacing: Option<Arc<crate::bwlimit::transport::Budget>>,
) {
    loop {
        if descriptor_session.is_closed()
            || authority
                .as_ref()
                .is_some_and(|authority| !authority.control_is_open())
            || source_authority
                .as_ref()
                .is_some_and(|source| !source.is_open())
        {
            break;
        }
        let stream = match listener.accept() {
            // BSD-derived kernels (macOS) hand accepted sockets the
            // listener's non-blocking flag; Linux does not. Every
            // connection handler expects a blocking socket.
            Ok((stream, _)) if stream.set_nonblocking(false).is_ok() => stream,
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // Wake as soon as a peer connects; a sleep here delayed every
                // data connection. The timeout keeps the closure checks above.
                crate::sys::wait_readable(
                    std::os::fd::AsRawFd::as_raw_fd(&listener),
                    Duration::from_millis(25),
                );
                continue;
            }
            // Back off rather than spin on persistent errors such as EMFILE.
            Err(_) => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
        };
        let handshake_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let id = next_id.fetch_add(1, Relaxed);
        // Reserve a slot atomically: both family listeners charge one bound.
        if live.fetch_add(1, Relaxed) >= max_live {
            live.fetch_sub(1, Relaxed);
            if debug {
                crate::output::diagnostic!(
                    "syq server (tcp): refusing connection, {max_live} already live"
                );
            }
            continue; // drop; stream closes
        }
        let (key, token, live, seen, authority, source_authority, descriptor_session) = (
            key.clone(),
            token.clone(),
            live.clone(),
            seen.clone(),
            authority.clone(),
            source_authority.clone(),
            descriptor_session.clone(),
        );
        let pacing = pacing.clone();
        let failed_live = live.clone();
        if std::thread::Builder::new()
            .spawn(move || {
                if let Err(e) = serve_tcp(
                    stream,
                    id,
                    key,
                    token,
                    debug,
                    compress,
                    &seen,
                    authority.clone(),
                    source_authority.clone(),
                    descriptor_session,
                    pacing,
                    handshake_deadline,
                ) {
                    if debug {
                        crate::output::diagnostic!("syq server (tcp {id}): {e:#}");
                    }
                }
                live.fetch_sub(1, Relaxed);
            })
            .is_err()
        {
            failed_live.fetch_sub(1, Relaxed);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_tcp(
    stream: TcpStream,
    id: u32,
    key: Option<Vec<u8>>,
    token: Vec<u8>,
    _debug: bool,
    _compress: bool,
    seen: &std::sync::Mutex<std::collections::HashSet<u32>>,
    authority: Option<Arc<crate::restricted::RestrictedAuthority>>,
    source_authority: Option<Arc<crate::restricted::source::SourceAuthority>>,
    descriptor_session: DescriptorSessionSlot,
    pacing: Option<Arc<crate::bwlimit::transport::Budget>>,
    handshake_deadline: std::time::Instant,
) -> Result<()> {
    // The listening socket is nonblocking so its owner can notice session
    // shutdown. Darwin propagates that status flag to accepted sockets, while
    // Linux does not. Framed connections use blocking I/O on every platform.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    // Scanners and stray connections must not hold a thread forever.
    let handshake_timeout = handshake_deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("TCP Hello deadline expired before the handler started")?;
    stream.set_read_timeout(Some(handshake_timeout))?;
    stream.set_write_timeout(Some(handshake_timeout))?;
    let handshake_pending = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut handshake_reader = TcpHandshakeReader {
        stream: stream.try_clone()?,
        pending: handshake_pending.clone(),
        deadline: handshake_deadline,
    };
    // The client tells us its connection id first (plaintext), so both sides
    // derive the same nonces.
    let mut idbuf = [0u8; 4];
    handshake_reader.read_exact(&mut idbuf)?;
    let conn_id = u32::from_be_bytes(idbuf);
    let _ = id;
    // Reject aliases before reserving the ID or emitting encrypted records.
    if conn_id > crate::tcp_records::CONNECTION_ID_MAX {
        bail!("TCP connection id {conn_id} exceeds nonce space");
    }
    // Each client connection id is single-use: a replayed record stream carries
    // the original id (it must, to decrypt) and is rejected here.
    if !seen.lock().unwrap().insert(conn_id) {
        bail!("duplicate connection id {conn_id} (possible replay)");
    }
    let (rc, wc) = match &key {
        Some(k) => (
            Some(Cipher::new(k, conn_id, 1)),
            Some(Cipher::new(k, conn_id, 2)),
        ),
        None => (None, None),
    };
    let reader = RecordReader::new(handshake_reader, rc);
    let authed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let output: Box<dyn Write + Send> = if let Some(budget) = pacing {
        let session = descriptor_session.clone();
        let socket = stream.try_clone()?;
        let source = source_authority.clone();
        Box::new(crate::bwlimit::transport::PacedWriter {
            inner: stream.try_clone()?,
            budget,
            handshake_pending: Some(handshake_pending.clone()),
            stopped: move || {
                session.is_closed()
                    || source.as_ref().is_some_and(|source| !source.is_open())
                    || crate::bwlimit::transport::socket_closed(&socket)
            },
        })
    } else {
        Box::new(stream.try_clone()?)
    };
    let writer = RecordWriter::new(output, wc);
    // Free the id only if the connection NEVER authenticated, so an
    // unauthenticated peer can't reserve ids. Once the token authenticated, the
    // id is retained permanently even if a later request fails — otherwise an
    // on-path attacker could corrupt an authenticated stream to free the id and
    // then replay captured records under it.
    let res = serve(
        reader,
        writer,
        false,
        Some(token),
        Some(&authed),
        Some(stream.try_clone()?),
        ServeSession {
            owns_process: false,
            handshake_pending: Some(handshake_pending),
            ssh_worker_ticket: None,
            allow_tcp: true,
            metadata_control: false,
            loopback_only: false,
            named_socket: None,
            authority,
            source_authority,
            descriptor_session,
        },
    );
    if res.is_err() && !authed.load(std::sync::atomic::Ordering::SeqCst) {
        seen.lock().unwrap().remove(&conn_id);
    }
    res
}

#[cfg(debug_assertions)]
static TEST_DROP_MATCHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(debug_assertions)]
fn drop_after_handling_for_test(request: &Request) -> bool {
    let Some(kind) = std::env::var_os("SYQ_TEST_DROP_AFTER_REQUEST") else {
        return false;
    };
    let matches = match kind.to_string_lossy().as_ref() {
        "read" => matches!(
            request,
            Request::ReadRange { .. } | Request::ReadComparedRange { .. }
        ),
        "write" => matches!(request, Request::WriteRange { .. }),
        "finalize" => matches!(request, Request::Finalize { .. }),
        "patch-data" => matches!(request, Request::PatchData { .. }),
        _ => false,
    };
    if !matches {
        return false;
    }
    let target = std::env::var_os("SYQ_TEST_DROP_AFTER_N_REQUESTS")
        .and_then(|value| value.to_string_lossy().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);
    if TEST_DROP_MATCHES.fetch_add(1, Relaxed) + 1 < target {
        return false;
    }
    let Some(marker) = std::env::var_os("SYQ_TEST_DROP_MARKER") else {
        return false;
    };
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .is_ok()
}

#[cfg(not(debug_assertions))]
fn drop_after_handling_for_test(_request: &Request) -> bool {
    false
}

/// Bound every socket read, including partial IDs and records, by the same
/// Hello deadline. `serve` clears the shared socket timeout before HelloOk.
struct TcpHandshakeReader {
    stream: TcpStream,
    pending: Arc<std::sync::atomic::AtomicBool>,
    deadline: std::time::Instant,
}

impl Read for TcpHandshakeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending.load(std::sync::atomic::Ordering::Acquire) {
            let remaining = self
                .deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|time| !time.is_zero())
                .ok_or_else(|| io::Error::new(ErrorKind::TimedOut, "TCP Hello timed out"))?;
            self.stream.set_read_timeout(Some(remaining))?;
        }
        self.stream.read(buf)
    }
}

/// Stats follow the same exact-build response protocol. They are consumed by
/// the existing reader before entering the bounded data-reply queue.
struct ObservedWriter<W: Write> {
    inner: FrameWriter<W>,
    compress: bool,
    registry: Arc<crate::transfer_observations::Registry>,
    actor: Arc<crate::transfer_observations::Actor>,
    last: std::time::Instant,
    enabled: bool,
    socket: Option<std::net::TcpStream>,
    source_authority: Option<Arc<crate::restricted::source::SourceAuthority>>,
}
impl<W: Write> ObservedWriter<W> {
    fn write_msg(&mut self, response: &Response) -> std::io::Result<()> {
        self.prepare_write(response)?;
        let _send = self
            .actor
            .span(crate::transfer_observations::Stage::ResponseSend);
        self.inner.write_msg(response)
    }

    /// As `write_msg`, but free the response once it is encoded, so that its
    /// data is not held beside the compressed frame.
    fn write_owned(&mut self, response: Response) -> std::io::Result<()> {
        self.prepare_write(&response)?;
        let _send = self
            .actor
            .span(crate::transfer_observations::Stage::ResponseSend);
        self.inner.write_owned(response)
    }

    /// Check a response the source authority must allow, and send the
    /// periodic transport statistics before it.
    fn prepare_write(&mut self, response: &Response) -> std::io::Result<()> {
        if let Some(authority) = &self.source_authority {
            if let Err(error) = authority.check_response(response) {
                self.inner.write_msg(&Response::Err(format!("{error:#}")))?;
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    error.to_string(),
                ));
            }
        }
        if self.enabled
            && self.last.elapsed() >= std::time::Duration::from_secs(1)
            && !matches!(response, Response::TransportStats(_))
        {
            self.last = std::time::Instant::now();
            self.inner
                .write_msg(&Response::TransportStats(Box::new(TransportStatsReply {
                    tcp: self.socket.as_ref().and_then(crate::conn::tcp_socket_stats),
                    observation: Some(self.registry.snapshot()),
                    solicited: false,
                })))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod source_tests;
#[cfg(test)]
mod tests;

fn write_metadata_batches<W: std::io::Write, T>(
    writer: &mut ObservedWriter<W>,
    items: Vec<T>,
    size: impl Fn(&T) -> usize,
    more: fn(Vec<T>) -> Response,
    last: fn(Vec<T>) -> Response,
) -> std::io::Result<()> {
    let mut batch = Vec::new();
    let mut bytes = 0usize;
    for item in items {
        let item_size = size(&item);
        if !batch.is_empty() && bytes.saturating_add(item_size) > crate::proto::METADATA_BATCH_BYTES
        {
            writer.write_msg(&more(std::mem::take(&mut batch)))?;
            bytes = 0;
        }
        bytes = bytes.saturating_add(item_size);
        batch.push(item);
    }
    writer.write_msg(&last(batch))
}

#[cfg(test)]
mod peer_control_tests;
