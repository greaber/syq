//! `syq --server`: serve requests over stdin/stdout, and optionally over
//! TCP data connections (see `crypto.rs`) when the client asks for them.

use crate::descriptor_broker::DescriptorSessionSlot;
use crate::fsops::FsOps;
use crate::proto::*;
use crate::restricted::Checker;
use crate::tcp_records::{Cipher, RecordReader, RecordWriter};
use anyhow::{bail, Context, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{
    AtomicU32,
    Ordering::{Acquire, Relaxed, Release},
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

mod interfaces;
use interfaces::{local_addrs, BoundFamilies};

struct RequestReader {
    rx: Option<std::sync::mpsc::Receiver<io::Result<crate::wire_budget::Budgeted<Request>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    tcp_socket: Option<TcpStream>,
    named_socket: Option<std::os::unix::net::UnixStream>,
    /// Ends the reader's wait for decompression memory once the server is
    /// closing the connection.
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl RequestReader {
    fn spawn<R: Read + Send + 'static>(
        reader: FrameReader<R>,
        tcp_socket: Option<TcpStream>,
        named_socket: Option<std::os::unix::net::UnixStream>,
        disconnected: Arc<std::sync::atomic::AtomicBool>,
        source_control: Option<Arc<crate::restricted::source::SourceAuthority>>,
        sweep: Option<SweepOnLoss>,
    ) -> std::io::Result<Self> {
        Self::spawn_charged(
            reader,
            tcp_socket,
            named_socket,
            disconnected,
            source_control,
            sweep,
            crate::wire_budget::ExpansionBudget::shared(),
        )
    }

    fn spawn_charged<R: Read + Send + 'static>(
        mut reader: FrameReader<R>,
        tcp_socket: Option<TcpStream>,
        named_socket: Option<std::os::unix::net::UnixStream>,
        disconnected: Arc<std::sync::atomic::AtomicBool>,
        source_control: Option<Arc<crate::restricted::source::SourceAuthority>>,
        sweep: Option<SweepOnLoss>,
        budget: Arc<crate::wire_budget::ExpansionBudget>,
    ) -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        // Queued requests hold what decompression added to them, so a peer
        // cannot make them hold far more than it sent. A frame waiting for
        // room stops waiting when the server closes the connection, or when
        // the peer of a TCP or socket connection hangs up.
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let peer: Option<std::os::fd::OwnedFd> = match (&tcp_socket, &named_socket) {
            (Some(socket), _) => Some(socket.try_clone()?.into()),
            (None, Some(socket)) => Some(socket.try_clone()?.into()),
            (None, None) => None,
        };
        let closing = closed.clone();
        reader.charge_expansion(crate::wire_budget::ExpansionCharge {
            budget,
            closed: Box::new(move || {
                closing.load(std::sync::atomic::Ordering::Acquire)
                    || peer
                        .as_ref()
                        .is_some_and(crate::bwlimit::transport::socket_closed)
            }),
        });
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
            closed,
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
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
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
/// included, before SIGINT, SIGTERM or SIGHUP ends it. A local receiver shares the
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

struct ServeSession<'a> {
    /// This process serves only this session's copy and ends with it, so
    /// the copy's sidecars are removed if the connection is lost.
    owns_process: bool,
    handshake_pending: Option<Arc<std::sync::atomic::AtomicBool>>,
    ssh_worker_ticket: Option<std::result::Result<String, String>>,
    allow_tcp: bool,
    /// A local copy's receiver: listen for data on loopback only and
    /// advertise no interface addresses.
    loopback_only: bool,
    named_socket: Option<std::os::unix::net::UnixStream>,
    /// The restricted rules the connection is served under, if any.
    checker: Option<Checker>,
    descriptor_session: DescriptorSessionSlot,
    /// The connection arrived over SSH: it may be a copy's control and set
    /// up a TCP listener.
    over_ssh: bool,
    /// What a TCP connection must present in its Hello.
    expect_token: Option<Vec<u8>>,
    /// A TCP connection's id in its listener's replay set.
    connection_id: Option<&'a TcpConnectionId<'a>>,
    tcp_socket: Option<TcpStream>,
}

impl ServeSession<'_> {
    /// A connection served in `descriptor_session` with every option off:
    /// not over SSH, unrestricted, and without TCP.
    fn new(descriptor_session: DescriptorSessionSlot) -> Self {
        Self {
            owns_process: false,
            handshake_pending: None,
            ssh_worker_ticket: None,
            allow_tcp: false,
            loopback_only: false,
            named_socket: None,
            checker: None,
            descriptor_session,
            over_ssh: false,
            expect_token: None,
            connection_id: None,
            tcp_socket: None,
        }
    }
}

/// Lets go of the files a copy is writing when its control connection ends.
struct ReleaseStages(u64);

impl Drop for ReleaseStages {
    fn drop(&mut self) {
        crate::fsops::release_stages(self.0);
    }
}

/// Most worker connections one receiving process serves at once, over TCP
/// or handed over from SSH sessions, each counted separately.
pub(crate) const MAX_WORKER_CONNECTIONS: usize = 256;

/// Ceiling on accepted TCP sockets being served at once, authenticated or
/// not. It bounds thread use against scanners and stray connections; the
/// signed grant's `max_connections` is charged separately, after a worker
/// authenticates.
const MAX_LIVE_TCP_CONNECTIONS: u32 = MAX_WORKER_CONNECTIONS as u32;

/// One authenticated worker's share of a signed grant's connection allowance,
/// returned when the connection ends.
pub(crate) struct ConnectionPermit(Arc<crate::restricted::RestrictedAuthority>);

impl ConnectionPermit {
    pub(crate) fn acquire(authority: Arc<crate::restricted::RestrictedAuthority>) -> Result<Self> {
        authority.acquire_connection()?;
        Ok(Self(authority))
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
    let (prefix, hello) = peek_hello();
    if let Some(ticket) = hello.as_ref().and_then(handed_worker_ticket) {
        return hand_off_worker(&ticket, &prefix);
    }
    let descriptor_session = DescriptorSessionSlot::default();
    let handed = HandedWorkers::default();
    descriptor_session.serve_handed_connections(handed_connection_handler(
        descriptor_session.clone(),
        handed.clone(),
    ));
    let client_gone = std::sync::atomic::AtomicBool::new(false);
    let result = serve(
        io::Cursor::new(prefix).chain(io::stdin()),
        ClientOutput {
            inner: io::stdout().lock(),
            gone: &client_gone,
        },
        ServeSession {
            owns_process: true,
            over_ssh: true,
            allow_tcp: true,
            loopback_only: local_receiver,
            ..ServeSession::new(descriptor_session.clone())
        },
    );
    close_after_handed(&descriptor_session, &handed, HANDED_END_WAIT);
    crate::process::termination::wait_if_terminating();
    client_gone_result(result, client_gone.load(Relaxed))
}

/// Mark a failure as [`ClientGone`] when the client stopped reading replies
/// (`gone`) and the failure is that closed pipe. Every other failure, and a
/// broken pipe on a connection the client still reads, is reported as is.
fn client_gone_result(result: Result<()>, gone: bool) -> Result<()> {
    match result {
        Err(error)
            if gone
                && error.chain().any(|cause| {
                    cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == ErrorKind::BrokenPipe)
                }) =>
        {
            Err(error.context(ClientGone))
        }
        result => result,
    }
}

/// The client closed the control connection before reading every reply,
/// as a copy does once one endpoint refuses it. The client reports its own
/// outcome, so the server exits without a message.
#[derive(Debug)]
pub(crate) struct ClientGone;

impl std::fmt::Display for ClientGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the client stopped reading replies")
    }
}

/// The control connection's output, noting when the client stops reading it.
struct ClientOutput<'a, W> {
    inner: W,
    gone: &'a std::sync::atomic::AtomicBool,
}

impl<W: Write> ClientOutput<'_, W> {
    fn note<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::BrokenPipe)
        {
            self.gone.store(true, Relaxed);
        }
        result
    }
}

impl<W: Write> Write for ClientOutput<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = self.inner.write(bytes);
        self.note(result)
    }
    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let result = self.inner.write_vectored(buffers);
        self.note(result)
    }
    fn flush(&mut self) -> io::Result<()> {
        let result = self.inner.flush();
        self.note(result)
    }
}

/// Records every byte read through it.
struct Recording<'a, R> {
    inner: R,
    recorded: &'a mut Vec<u8>,
}

impl<R: Read> Read for Recording<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(bytes)?;
        self.recorded.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
}

/// Read the client's Hello from standard input, unbuffered by `io::stdin`,
/// with every byte read for it. A Hello that cannot be read is left to
/// `serve`, which reads the same bytes again and reports what is wrong.
fn peek_hello() -> (Vec<u8>, Option<Request>) {
    // SAFETY: borrows descriptor 0 without closing it.
    let input = std::mem::ManuallyDrop::new(unsafe {
        <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(0)
    });
    let mut recorded = Vec::new();
    let hello = {
        let mut reader = FrameReader::new(Recording {
            inner: &*input,
            recorded: &mut recorded,
        });
        reader.set_limit(MAX_HANDSHAKE_FRAME);
        reader
            .read_budgeted::<Request>()
            .ok()
            .map(|hello| hello.into_parts().0)
    };
    (recorded, hello)
}

/// The descriptor session whose process serves this destination worker:
/// the copy's receiver, which registered the destination root.
fn handed_worker_ticket(hello: &Request) -> Option<crate::descriptor_broker::DescriptorTicket> {
    match hello {
        Request::Hello {
            role:
                ConnectionRole::DestinationWorker {
                    destination: Some(destination),
                    ..
                },
            ..
        } => Some(destination.ticket.clone()),
        _ => None,
    }
}

/// Give an SSH session's worker connection to the copy's receiver, which
/// serves it on a thread as it serves a TCP worker, and wait until it has.
/// The bytes already read (`prefix`) go with it.
fn hand_off_worker(
    ticket: &crate::descriptor_broker::DescriptorTicket,
    prefix: &[u8],
) -> Result<()> {
    let handed = match crate::descriptor_broker::hand_off_pipes(ticket, prefix, 0, 1) {
        Ok(handed) => handed,
        Err(error) => {
            // The coordinator learns of it as of any worker that cannot start.
            let mut writer = FrameWriter::new(io::stdout().lock(), false);
            let _ = writer.write_msg(&Response::Err(format!(
                "hand the worker connection to the receiver: {error:#}"
            )));
            return Err(error);
        }
    };
    crate::descriptor_broker::release_standard_streams()?;
    handed.wait()
}

/// Serve a restricted copy's SSH worker under `checker`, whose input and
/// output its process handed over `control` after the receiver admitted it,
/// and tell that process how it ended. Hello must arrive within the
/// handshake time.
pub(crate) fn serve_handed_restricted(
    input: std::fs::File,
    output: std::fs::File,
    control: crate::private_broker::TrackedStream,
    checker: Checker,
    handshake: Duration,
) -> Result<()> {
    serve_accepted(control, || {
        #[cfg(debug_assertions)]
        if checker.destination().is_some() {
            record_handed_connection_for_test();
        }
        let pending = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let reader = HandshakeReader::new(
            input,
            pending.clone(),
            Instant::now() + handshake,
            "SSH worker Hello timed out",
        );
        let descriptor_session = checker.connection_session();
        let result = serve(
            reader,
            output,
            ServeSession {
                handshake_pending: Some(pending),
                checker: Some(checker.clone()),
                ..ServeSession::new(descriptor_session.clone())
            },
        );
        checker.end_connection(&descriptor_session, false);
        result
    })
}

/// Serve a connection another process handed over `control` once that
/// process has learned it was accepted, and tell it how the connection
/// ended.
fn serve_accepted(
    mut control: crate::private_broker::TrackedStream,
    serve: impl FnOnce() -> Result<()>,
) -> Result<()> {
    use crate::descriptor_broker::HandedConnection;
    HandedConnection::accept(&mut control)?;
    let result = serve();
    HandedConnection::report_end(control, &result);
    result
}

/// Bound every read by the Hello deadline until `serve` clears `pending`
/// after acknowledging Hello: each read first waits, at most until the
/// deadline, for the descriptor to become readable. Unbuffered input only,
/// since the wait cannot see bytes another buffer already read. A socket's
/// read is also bounded by what remains (`on_socket`), since a socket
/// reported readable can still block.
struct HandshakeReader<R> {
    inner: R,
    pending: Arc<std::sync::atomic::AtomicBool>,
    deadline: Instant,
    /// Once the first byte arrives, the deadline becomes this much later.
    hello_timeout: Option<Duration>,
    timed_out: &'static str,
    /// Set the socket's receive timeout to what remains before each read.
    socket: bool,
}

impl<R> HandshakeReader<R> {
    fn new(
        inner: R,
        pending: Arc<std::sync::atomic::AtomicBool>,
        deadline: Instant,
        timed_out: &'static str,
    ) -> Self {
        Self {
            inner,
            pending,
            deadline,
            hello_timeout: None,
            timed_out,
            socket: false,
        }
    }

    /// `inner` is a socket: bound each read itself by what remains too.
    fn on_socket(self) -> Self {
        Self {
            socket: true,
            ..self
        }
    }

    /// A Hello that must start within `start_timeout` and then finish
    /// within `hello_timeout` of its first byte.
    fn starting(
        inner: R,
        pending: Arc<std::sync::atomic::AtomicBool>,
        (start_timeout, hello_timeout): (Duration, Duration),
        timed_out: &'static str,
    ) -> Self {
        Self {
            hello_timeout: Some(hello_timeout),
            ..Self::new(inner, pending, Instant::now() + start_timeout, timed_out)
        }
    }
}

impl<R: Read + std::os::fd::AsRawFd> Read for HandshakeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pending.load(Acquire) {
            // A signal can end a wait early; the next one waits for what
            // remains of the deadline. Any other failure ends the read.
            let mut ready = libc::pollfd {
                fd: self.inner.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                let remaining = self
                    .deadline
                    .checked_duration_since(Instant::now())
                    .filter(|time| !time.is_zero())
                    .ok_or_else(|| io::Error::new(ErrorKind::TimedOut, self.timed_out))?;
                let millis = libc::c_int::try_from(remaining.as_micros().div_ceil(1000))
                    .unwrap_or(libc::c_int::MAX);
                // SAFETY: `ready` is one initialized pollfd for a descriptor
                // `inner` keeps open.
                match unsafe { libc::poll(&mut ready, 1, millis) } {
                    0 => {}
                    count if count > 0 => break,
                    _ => {
                        let error = io::Error::last_os_error();
                        if error.kind() != ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
            }
            if self.socket {
                let remaining = self
                    .deadline
                    .checked_duration_since(Instant::now())
                    .filter(|time| !time.is_zero())
                    .ok_or_else(|| io::Error::new(ErrorKind::TimedOut, self.timed_out))?;
                set_receive_timeout(self.inner.as_raw_fd(), remaining)?;
            }
        }
        let count = self.inner.read(buf)?;
        if count > 0 {
            // Preparing the copy and reaching this receiver is separate from
            // completing Hello. Neither phase can wait forever, and later
            // partial bytes never extend the Hello deadline.
            if let Some(hello_timeout) = self.hello_timeout.take() {
                self.deadline = Instant::now() + hello_timeout;
            }
        }
        Ok(count)
    }
}

/// Set socket `fd`'s receive timeout to `timeout`, which is not zero.
fn set_receive_timeout(fd: std::os::fd::RawFd, timeout: Duration) -> io::Result<()> {
    let seconds = libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX);
    // Below a million, so it fits every platform's `suseconds_t`.
    let mut micros = timeout.subsec_micros() as libc::suseconds_t;
    if seconds == 0 && micros == 0 {
        // Zero would mean no timeout at all.
        micros = 1;
    }
    let value = libc::timeval {
        tv_sec: seconds,
        tv_usec: micros,
    };
    // SAFETY: `value` is a live timeval of the size passed, for a socket the
    // caller keeps open.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Most connections handed to one receiver that it serves at once, as for
/// TCP connections.
const MAX_LIVE_HANDED_CONNECTIONS: u32 = MAX_LIVE_TCP_CONNECTIONS;

/// How long a receiver whose control connection ended waits for the worker
/// connections handed to it to end. The coordinator ends a copy's workers
/// together with its control, so they normally end at once.
pub(crate) const HANDED_END_WAIT: Duration = Duration::from_secs(1);

/// Counts the worker connections handed to this receiver until each has
/// been told how it ended.
#[derive(Clone, Default)]
pub(crate) struct HandedWorkers(Arc<AtomicU32>);

/// One counted handed worker; dropping it ends its count.
pub(crate) struct HandedWorker(Arc<AtomicU32>);

impl Drop for HandedWorker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Release);
    }
}

impl HandedWorkers {
    /// Count one more worker.
    pub(crate) fn count(&self) -> HandedWorker {
        self.0.fetch_add(1, Relaxed);
        HandedWorker(self.0.clone())
    }

    /// Count one more worker, unless `limit` are counted already.
    fn admit(&self, limit: u32) -> Option<HandedWorker> {
        if self.0.fetch_add(1, Relaxed) >= limit {
            self.0.fetch_sub(1, Relaxed);
            return None;
        }
        Some(HandedWorker(self.0.clone()))
    }

    /// Wait until every counted worker has ended, at most `limit`, so that
    /// each has told its own process how it ended.
    pub(crate) fn wait(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        while self.0.load(Acquire) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// Serve the worker connections other processes hand to this receiver,
/// each on a thread of its own, counting in `live` those not yet ended.
fn handed_connection_handler(
    descriptor_session: DescriptorSessionSlot,
    live: HandedWorkers,
) -> crate::descriptor_broker::ConnectionHandler {
    handed_connection_handler_within(descriptor_session, live, MAX_LIVE_HANDED_CONNECTIONS)
}

/// Close `descriptor_session` once the handed connections `live` counts
/// have ended, waiting at most `limit`. Closing it ends the channel by
/// which each connection's own process learns how it ended: one closed
/// before reporting makes that process fail, as if this receiver had
/// crashed while serving it.
fn close_after_handed(
    descriptor_session: &DescriptorSessionSlot,
    live: &HandedWorkers,
    limit: Duration,
) {
    live.wait(limit);
    descriptor_session.close();
}

/// `handed_connection_handler`, refusing connections beyond `limit` live.
fn handed_connection_handler_within(
    descriptor_session: DescriptorSessionSlot,
    live: HandedWorkers,
    limit: u32,
) -> crate::descriptor_broker::ConnectionHandler {
    Arc::new(move |connection| {
        let Some(served) = live.admit(limit) else {
            connection.refuse();
            return Ok(());
        };
        let session = descriptor_session.clone();
        // A connection whose thread cannot start goes with the closure,
        // uncounted: its process sees no answer.
        let _ = std::thread::Builder::new()
            .name("syq-handed-worker".into())
            .spawn(move || {
                let crate::descriptor_broker::HandedConnection {
                    prefix,
                    transport,
                    control,
                } = connection;
                let _ = serve_accepted(control, || serve_handed(prefix, transport, session));
                drop(served);
            });
        Ok(())
    })
}

/// Serve one handed-over worker connection. It is a data connection: it may
/// not become a control.
fn serve_handed(
    prefix: Vec<u8>,
    transport: crate::descriptor_broker::HandedTransport,
    descriptor_session: DescriptorSessionSlot,
) -> Result<()> {
    #[cfg(debug_assertions)]
    record_handed_connection_for_test();
    match transport {
        crate::descriptor_broker::HandedTransport::Pipes { input, output } => serve(
            io::Cursor::new(prefix).chain(input),
            output,
            ServeSession::new(descriptor_session),
        ),
        crate::descriptor_broker::HandedTransport::Socket(socket) => serve(
            socket.try_clone()?,
            socket.try_clone()?,
            ServeSession {
                named_socket: Some(socket),
                ..ServeSession::new(descriptor_session)
            },
        ),
    }
}

/// Record, for tests, that this process served a handed-over worker.
#[cfg(debug_assertions)]
fn record_handed_connection_for_test() {
    let _ = crate::fsops::record_test_event(
        "SYQ_TEST_HANDED_WORKER_EVENTS",
        format_args!("served {}", std::process::id()),
    );
}

/// The forced command of an enrollment's `authorized_keys` line, which runs
/// for every session an entry key starts: admit the session, then serve the
/// copy its verified directive allows. A worker's session is handed to the
/// running copy it joins, which serves it.
///
/// Returns the exit status: a coordinating source's is its copy's.
pub(crate) fn run_checker(enrollment: &str, generation: &str) -> Result<i32> {
    let session = crate::restricted::admit_session(enrollment, generation).map_err(|error| {
        if crate::restricted::is_sessions_full(&error) || crate::restricted::is_other_build(&error)
        {
            error
        } else {
            crate::restricted::Refused(error).into()
        }
    })?;
    match session {
        crate::restricted::Session::Worker => Ok(0),
        crate::restricted::Session::Serve(checker) => run_restricted(checker).map(|()| 0),
        crate::restricted::Session::Coordinate(coordinating) => {
            crate::remote_to_remote::coordinate(*coordinating)
        }
    }
}

/// How long a verified copy's control has to start its Hello, and then to
/// finish it.
const RESTRICTED_START_TIMEOUT: Duration = Duration::from_secs(60);
const RESTRICTED_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve the copy a verified directive allows to the server that started
/// it: over this session, over the TCP workers it sets up, and over SSH
/// workers that join with this session's ticket. Closing this session ends
/// them all.
fn run_restricted(checker: Checker) -> Result<()> {
    // An enrolled destination's process serves only its copy, whose
    // temporary files it removes when interrupted.
    let owns_process = checker.destination().is_some();
    let _termination = owns_process.then(clean_up_on_termination).flatten();
    let (workers, ticket) = match crate::restricted::start_ssh_workers(checker.clone()) {
        Ok((workers, ticket)) => (Some(workers), Ok(ticket)),
        Err(error) => (
            None,
            Err(format!("start restricted SSH workers: {error:#}")),
        ),
    };
    let descriptor_session = checker.connection_session();
    let pending = Arc::new(std::sync::atomic::AtomicBool::new(true));
    // Unbuffered: the deadline waits on the descriptor, which must not hide
    // bytes another buffer already read.
    let input = std::fs::File::from(
        std::os::fd::AsFd::as_fd(&io::stdin())
            .try_clone_to_owned()
            .context("take the copy's input")?,
    );
    let client_gone = std::sync::atomic::AtomicBool::new(false);
    let result = serve(
        HandshakeReader::starting(
            input,
            pending.clone(),
            (RESTRICTED_START_TIMEOUT, RESTRICTED_HELLO_TIMEOUT),
            "return channel exchange timed out",
        ),
        ClientOutput {
            inner: io::stdout().lock(),
            gone: &client_gone,
        },
        ServeSession {
            owns_process,
            handshake_pending: Some(pending),
            ssh_worker_ticket: Some(ticket),
            allow_tcp: true,
            over_ssh: true,
            checker: Some(checker.clone()),
            ..ServeSession::new(descriptor_session.clone())
        },
    );
    // The closed copy grants the SSH workers nothing more.
    checker.end_connection(&descriptor_session, true);
    if let Some(workers) = workers {
        workers.end(result.is_ok(), HANDED_END_WAIT);
    }
    // The workers' broker listens for termination signals to remove its
    // directory; one arriving now ends the process by that signal.
    crate::process::termination::wait_if_terminating();
    client_gone_result(result, client_gone.load(Relaxed))
}

/// An authenticated channel of a copy approved here, served under
/// `checker`. Worker admission and path checks are identical to restricted
/// TCP workers; SSH encrypts these streams. A source's control and workers
/// share its descriptor session, so workers can use only the roots control
/// registered; closing control ends both.
pub(crate) fn run_named(
    r: crate::private_broker::TrackedStream,
    w: std::os::unix::net::UnixStream,
    checker: Checker,
    control: bool,
) -> Result<()> {
    let descriptor_session = checker.connection_session();
    let socket = w.try_clone()?;
    let timeout = socket
        .read_timeout()?
        .context("named handshake requires a timeout")?;
    let pending = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let reader = HandshakeReader::new(
        r,
        pending.clone(),
        Instant::now() + timeout,
        "named channel Hello timed out",
    )
    .on_socket();
    let result = serve(
        reader,
        w,
        ServeSession {
            over_ssh: control,
            handshake_pending: Some(pending),
            named_socket: Some(socket),
            checker: Some(checker.clone()),
            ..ServeSession::new(descriptor_session.clone())
        },
    );
    checker.end_connection(&descriptor_session, control);
    result
}

/// A TCP worker that the receiving or sending machine dialed, admitted
/// through its approved SSH channel.
pub(crate) fn run_named_tcp(
    stream: TcpStream,
    channel: std::os::unix::net::UnixStream,
    key: &[u8],
    checker: Checker,
) -> Result<()> {
    let descriptor_session = checker.connection_session();
    let pending = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let reader = HandshakeReader::new(
        stream.try_clone()?,
        pending.clone(),
        Instant::now() + Duration::from_secs(10),
        "TCP Hello timed out",
    )
    .on_socket();
    let result = serve(
        RecordReader::new(reader, Some(Cipher::new(key, 0, 1))),
        RecordWriter::new(stream.try_clone()?, Some(Cipher::new(key, 0, 2))),
        ServeSession {
            expect_token: Some(Vec::new()),
            tcp_socket: Some(stream),
            handshake_pending: Some(pending),
            named_socket: Some(channel),
            checker: Some(checker.clone()),
            ..ServeSession::new(descriptor_session.clone())
        },
    );
    checker.end_connection(&descriptor_session, false);
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
fn serve<R: Read + Send + 'static, W: Write>(r: R, w: W, session: ServeSession) -> Result<()> {
    let ServeSession {
        owns_process,
        handshake_pending,
        ssh_worker_ticket,
        allow_tcp,
        loopback_only,
        named_socket,
        checker,
        descriptor_session,
        over_ssh,
        expect_token,
        connection_id,
        tcp_socket,
    } = session;
    let authority = checker.as_ref().and_then(Checker::destination).cloned();
    let source_authority = checker
        .as_ref()
        .and_then(Checker::source_authority)
        .cloned();
    // Worker connections handed over from SSH sessions are served as data
    // connections too, but do not arrive over TCP.
    let over_tcp = tcp_socket.is_some();
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
            // authenticated. Claim its connection id now, and never free it,
            // so a later failure (such as a failed HelloOk write)
            // can't make the id available to a replay.
            if let Some(id) = connection_id {
                id.claim()?;
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
    // Tests check that every destination worker is served in the copy's
    // receiver, handed over to it (`record_handed_connection_for_test`).
    #[cfg(debug_assertions)]
    if matches!(&role, ConnectionRole::DestinationWorker { .. }) {
        let _ = crate::fsops::record_test_event(
            "SYQ_TEST_HANDED_WORKER_EVENTS",
            format_args!("worker {}", std::process::id()),
        );
    }
    // The copy's sidecars are registered from here so that they can be
    // removed; the guard is dropped on every return, after the reader.
    if owns_process {
        crate::fsops::track_sidecars();
    }
    let sweep_on_loss = owns_process.then(|| SweepOnLoss::new(is_control));
    let _sweep = sweep_on_loss.clone();
    let mut ops = FsOps::with_descriptor_session(descriptor_session.clone());
    if let Some(authority) = &authority {
        authority.configure_session(&mut ops);
    }
    // The files a copy is writing are let go when its control ends; a
    // receiver that serves many copies would otherwise keep those that never
    // reached Finalize.
    let _release_stages =
        (is_control && source_authority.is_none()).then(|| ReleaseStages(ops.stage_scope()));
    if let Some(source) = &source_permit {
        source.initialize(&mut ops)?;
    }
    let mut initial_sending_budget = match source_authority
        .as_ref()
        // A worker the coordinator's TCP listener paces itself; one a
        // receiving machine dialed (`named_socket`) has no such listener.
        .filter(|_| is_source_worker && (tcp_socket.is_none() || named_socket.is_some()))
    {
        Some(source) => source
            .sending_budget(&descriptor_session)?
            .map(|(budget, _)| budget),
        None => None,
    };
    match &role {
        ConnectionRole::SourceWorker { .. } if authority.is_some() => {
            w.write_msg(&Response::Err(
                "a restricted receiver does not accept caller-supplied source roots".into(),
            ))?;
            bail!("restricted receiver rejected supplied source roots");
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
                "a restricted receiver does not accept caller-supplied copy sources".into(),
            ))?;
            bail!("restricted receiver rejected supplied copy sources");
        }
        ConnectionRole::DestinationWorker {
            destination: Some(_),
            ..
        } if authority.is_some() => {
            w.write_msg(&Response::Err(
                "a restricted destination derives its root from the signed grant".into(),
            ))?;
            bail!("restricted receiver rejected a supplied destination root");
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
        inner: w,
        registry: ops.observations.clone(),
        actor: server_actor.clone(),
        last: std::time::Instant::now(),
        enabled: false,
        socket: telemetry_socket,
        source_authority: source_authority.clone(),
        destination_results: authority.clone(),
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
        let (mut req, mut request_hold) = queued.into_parts();
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
        if !is_control && req.control_only() {
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
        let mut settlement = match &mut stream_gate {
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
                // The stream lasts until the client's Stop, which arrives on
                // this connection: holding this request's decompression room
                // until then could leave that Stop waiting for it.
                request_hold.release_expansion();
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
                    congestion_control.as_deref(),
                    send_rate,
                    checker.clone(),
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
                        for part in crate::proto::native_remove_messages(messages, |m| m.len() + 8)
                        {
                            wref.borrow_mut()
                                .write_msg(&Response::NativeRemoveTrace(part))?;
                        }
                        Ok(())
                    },
                    &mut |outcomes| {
                        for part in crate::proto::native_remove_messages(
                            outcomes,
                            crate::proto::NativeRemoveOutcome::size_hint,
                        ) {
                            wref.borrow_mut()
                                .write_msg(&Response::NativeRemoveBatch(part))?;
                        }
                        Ok(())
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
            } => {
                // Inode metadata is read beneath the destination root an
                // ordinary or restricted session installed, by its own name.
                let requested_root = match ops.scan_metadata_root(&root, source.as_ref()) {
                    Ok(root) => root,
                    Err(error) => {
                        w.write_msg(&Response::Err(format!("{error:#}")))?;
                        continue;
                    }
                };
                let source_scan = match ops.source_scan_root(source.as_ref()) {
                    Ok(scan) => scan,
                    Err(error) => {
                        w.write_msg(&Response::Err(format!("{error:#}")))?;
                        continue;
                    }
                };
                let destination_scan = match ops.destination_scan_root(&root) {
                    Ok(scan) => scan,
                    Err(error) => {
                        w.write_msg(&Response::Err(format!("{error:#}")))?;
                        continue;
                    }
                };
                if source_scan.is_none() && destination_scan.is_none() {
                    w.write_msg(&Response::Err(
                        "scan names neither a registered source nor a destination root".into(),
                    ))?;
                    continue;
                }
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
                        &mut batch,
                    )?;
                    let mut w = wref.borrow_mut();
                    for m in warns.borrow_mut().drain(..) {
                        w.write_msg(&Response::ScanWarnAt(m))?;
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
                    Ok(wref.borrow_mut().write_msg(&Response::ScanIgnored(paths))?)
                };
                let res = if let Some(source) = source_scan {
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
                } else {
                    let (destination_root, relative) =
                        destination_scan.expect("checked before the scan");
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
                };
                for m in warns.borrow_mut().drain(..) {
                    w.write_msg(&Response::ScanWarnAt(m))?;
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
            Request::DestinationResults { records } => {
                let response = match &authority {
                    Some(authority) => match authority.start_results(records) {
                        Ok(()) => Response::Ok,
                        Err(error) => Response::Err(format!("{error:#}")),
                    },
                    None => Response::Err(
                        "destination results come only from a restricted receiver".into(),
                    ),
                };
                w.write_msg(&response)?;
            }
            Request::FinishDestinationResults => {
                let response = match &authority {
                    Some(authority) => match authority.finish_results() {
                        Ok(()) => Response::Ok,
                        Err(error) => Response::Err(format!("{error:#}")),
                    },
                    None => Response::Err(
                        "destination results come only from a restricted receiver".into(),
                    ),
                };
                w.write_msg(&response)?;
            }
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
                    let mut execute = |ops: &mut FsOps| {
                        ops.handle_with_copy_progress(&mut other, &mut |bytes| {
                            w.write_msg(&Response::CopyLocalProgress(bytes))?;
                            Ok(())
                        })
                    };
                    match &mut settlement {
                        Some(settlement) => settlement.execute(&mut ops, execute),
                        None => execute(&mut ops),
                    }
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
            if over_tcp { " (tcp)" } else { "" },
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
    congestion_control: Option<&str>,
    send_rate: Option<u64>,
    checker: Option<Checker>,
    descriptor_session: DescriptorSessionSlot,
) -> Result<(u16, BoundFamilies, Option<String>)> {
    let pacing = if let Some(source) = checker.as_ref().and_then(Checker::source_authority) {
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
        let (key, token, next_id, live, seen, checker, descriptor_session) = (
            key.clone(),
            token.clone(),
            next_id.clone(),
            live.clone(),
            seen.clone(),
            checker.clone(),
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
                    next_id,
                    live,
                    max_live,
                    seen,
                    checker,
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
    next_id: Arc<AtomicU32>,
    live: Arc<AtomicU32>,
    max_live: u32,
    seen: Arc<std::sync::Mutex<std::collections::HashSet<u32>>>,
    checker: Option<Checker>,
    descriptor_session: DescriptorSessionSlot,
    pacing: Option<Arc<crate::bwlimit::transport::Budget>>,
) {
    loop {
        if descriptor_session.is_closed()
            || checker.as_ref().is_some_and(|checker| !checker.is_open())
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
        let (key, token, live, seen, checker, descriptor_session) = (
            key.clone(),
            token.clone(),
            live.clone(),
            seen.clone(),
            checker.clone(),
            descriptor_session.clone(),
        );
        let pacing = pacing.clone();
        let failed_live = live.clone();
        if std::thread::Builder::new()
            .spawn(move || {
                if let Err(e) = serve_tcp(
                    stream,
                    key,
                    token,
                    &seen,
                    checker,
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
    key: Option<Vec<u8>>,
    token: Vec<u8>,
    seen: &std::sync::Mutex<std::collections::HashSet<u32>>,
    checker: Option<Checker>,
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
    let mut handshake_reader = HandshakeReader::new(
        stream.try_clone()?,
        handshake_pending.clone(),
        handshake_deadline,
        "TCP Hello timed out",
    )
    .on_socket();
    // The client tells us its connection id first (plaintext), so both sides
    // derive the same nonces.
    let mut idbuf = [0u8; 4];
    handshake_reader.read_exact(&mut idbuf)?;
    let conn_id = u32::from_be_bytes(idbuf);
    // Reject aliases before emitting encrypted records.
    if conn_id > crate::tcp_records::CONNECTION_ID_MAX {
        bail!("TCP connection id {conn_id} exceeds nonce space");
    }
    // Each client connection id is single-use: a replayed record stream carries
    // the original id (it must, to decrypt) and is rejected here, before the
    // server encrypts anything under it. The id is claimed only once the
    // Hello authenticates (`TcpConnectionId::claim`), so a peer without the
    // key and token cannot take ids that the client's workers will use.
    // Until then, connections sharing an id each send only the server's
    // preamble, whose plaintext is the same for every connection.
    let connection_id = TcpConnectionId { seen, id: conn_id };
    connection_id.ensure_unclaimed()?;
    let (rc, wc) = match &key {
        Some(k) => (
            Some(Cipher::new(k, conn_id, 1)),
            Some(Cipher::new(k, conn_id, 2)),
        ),
        None => (None, None),
    };
    let reader = RecordReader::new(handshake_reader, rc);
    let output: Box<dyn Write + Send> = if let Some(budget) = pacing {
        let session = descriptor_session.clone();
        let socket = stream.try_clone()?;
        let source = checker
            .as_ref()
            .and_then(Checker::source_authority)
            .cloned();
        Box::new(crate::bwlimit::transport::PacedWriter {
            inner: stream.try_clone()?,
            budget,
            unpaced: Some(handshake_pending.clone()),
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
    serve(
        reader,
        writer,
        ServeSession {
            expect_token: Some(token),
            connection_id: Some(&connection_id),
            tcp_socket: Some(stream.try_clone()?),
            handshake_pending: Some(handshake_pending),
            allow_tcp: true,
            checker,
            ..ServeSession::new(descriptor_session)
        },
    )
}

/// A TCP data connection's id in its listener's replay set. An id is claimed
/// once its connection authenticates and stays claimed while the listener is
/// up, even if the connection later fails: otherwise an on-path attacker
/// could corrupt an authenticated stream to free the id and then replay
/// captured records under it.
struct TcpConnectionId<'a> {
    seen: &'a std::sync::Mutex<std::collections::HashSet<u32>>,
    id: u32,
}

impl TcpConnectionId<'_> {
    fn ensure_unclaimed(&self) -> Result<()> {
        if self.seen.lock().unwrap().contains(&self.id) {
            bail!("duplicate connection id {} (possible replay)", self.id);
        }
        Ok(())
    }

    fn claim(&self) -> Result<()> {
        if !self.seen.lock().unwrap().insert(self.id) {
            bail!("duplicate connection id {} (possible replay)", self.id);
        }
        Ok(())
    }
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
        "prepare" => matches!(request, Request::Prepare { .. }),
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

/// Stats follow the same exact-build response protocol. They are consumed by
/// the existing reader before entering the bounded data-reply queue.
struct ObservedWriter<W: Write> {
    inner: FrameWriter<W>,
    registry: Arc<crate::transfer_observations::Registry>,
    actor: Arc<crate::transfer_observations::Actor>,
    last: std::time::Instant,
    enabled: bool,
    socket: Option<std::net::TcpStream>,
    source_authority: Option<Arc<crate::restricted::source::SourceAuthority>>,
    /// A restricted receiver's results go out ahead of any response.
    destination_results: Option<Arc<crate::restricted::RestrictedAuthority>>,
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
        if let Some(authority) = &self.destination_results {
            for frame in authority.take_results_frames() {
                self.inner
                    .write_owned(Response::DestinationResults(frame))?;
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
