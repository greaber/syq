//! `syq --server`: serve requests over stdin/stdout, and optionally over
//! TCP data connections (see `crypto.rs`) when the client asks for them.

use crate::descriptor_broker::DescriptorSessionSlot;
use crate::fsops::{self, FsOps};
use crate::proto::*;
use crate::tcp_records::{Cipher, RecordReader, RecordWriter};
use anyhow::{bail, Context, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

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
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let thread = std::thread::spawn(move || loop {
            let msg = reader.read_budgeted::<Request>();
            let failed = msg.is_err();
            if tx.send(msg).is_err() || failed {
                break;
            }
        });
        Self {
            rx: Some(rx),
            thread: Some(thread),
            tcp_socket,
            named_socket,
        }
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

struct ServeSession {
    handshake_pending: Option<Arc<std::sync::atomic::AtomicBool>>,
    ssh_worker_ticket: Option<std::result::Result<String, String>>,
    allow_tcp: bool,
    named_socket: Option<std::os::unix::net::UnixStream>,
    authority: Option<Arc<crate::restricted::RestrictedAuthority>>,
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

pub fn run() -> Result<()> {
    let descriptor_session = DescriptorSessionSlot::default();
    let result = serve(
        io::stdin(),
        io::stdout().lock(),
        true,
        None,
        None,
        None,
        ServeSession {
            handshake_pending: None,
            ssh_worker_ticket: None,
            allow_tcp: true,
            named_socket: None,
            authority: None,
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    result
}

pub(crate) fn run_restricted(authority: Arc<crate::restricted::RestrictedAuthority>) -> Result<()> {
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
            handshake_pending: None,
            ssh_worker_ticket: Some(ticket),
            allow_tcp: true,
            named_socket: None,
            authority: Some(Arc::clone(&authority)),
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    authority.close_control();
    result
}

/// A laptop-authenticated, one-copy helper with direct encrypted TCP workers.
pub(crate) fn run_forwarded<R: Read + Send + 'static>(
    authority: Arc<crate::restricted::RestrictedAuthority>,
    input: R,
    pending: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let descriptor_session = DescriptorSessionSlot::default();
    let result = serve(
        input,
        io::stdout().lock(),
        true,
        None,
        None,
        None,
        ServeSession {
            handshake_pending: Some(pending),
            ssh_worker_ticket: None,
            allow_tcp: true,
            named_socket: None,
            authority: Some(authority.clone()),
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    authority.close_control();
    result
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
            handshake_pending: None,
            ssh_worker_ticket: None,
            allow_tcp: false,
            named_socket: Some(socket),
            authority: Some(Arc::clone(&authority)),
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    if control {
        authority.close_control();
    }
    result
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
        handshake_pending,
        ssh_worker_ticket,
        allow_tcp,
        named_socket,
        authority,
        descriptor_session,
    } = session;
    let mut r = FrameReader::new(r);
    r.set_limit(MAX_HANDSHAKE_FRAME);
    let mut w = FrameWriter::new(w, false);
    // Send our build identity before waiting for the client's first postcard
    // frame. Both peers can therefore diagnose version skew even when their
    // Request or Response enum layouts no longer agree.
    w.write_preamble().context("write wire preamble")?;

    let debug;
    let role;
    // Held for the life of the connection; dropping it releases the worker
    // permit even when a later request fails.
    let _permit: Option<ConnectionPermit>;
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
            if let Some(authority) = &authority {
                authority.validate_hello(compress)?;
            }
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
    let mut ops = FsOps::with_descriptor_session(descriptor_session.clone());
    match &role {
        ConnectionRole::SourceWorker { .. } if authority.is_some() => {
            w.write_msg(&Response::Err(
                "a command-restricted receiver does not accept caller-supplied source roots".into(),
            ))?;
            bail!("command-restricted receiver rejected supplied source roots");
        }
        ConnectionRole::SourceWorker { roots } => {
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
        ConnectionRole::Control
        | ConnectionRole::DestinationWorker {
            destination: None, ..
        } => {}
    }
    w.write_msg(&Response::HelloOk {
        identity: crate::identity::build().to_string(),
        platform: crate::identity::platform(),
        supports_confined_socket_nodes: crate::identity::supports_confined_socket_nodes(),
        ssh_worker_ticket: if is_control { ssh_worker_ticket } else { None },
    })?;

    if let Some(socket) = &tcp_socket {
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
    }
    if let Some(socket) = &named_socket {
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
    }

    if let Some(pending) = handshake_pending {
        pending.store(false, std::sync::atomic::Ordering::Release);
    }

    // Requests are parsed on a reader thread so incoming data keeps flowing
    // while a block is being hashed and written. TCP readers are shut down and
    // joined by the guard on every exit path.
    r.set_limit(MAX_FRAME);
    let reader = RequestReader::spawn(r, tcp_socket, named_socket);

    let mut t = [0f64; 3];
    let (mut blocks, mut bytes) = (0u64, 0u64);
    loop {
        let t0 = std::time::Instant::now();
        let queued = match reader.recv() {
            Ok(Ok(req)) => req,
            Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        };
        let (mut req, _request_hold) = queued.into_parts();
        t[0] += t0.elapsed().as_secs_f64();
        if !is_control
            && matches!(
                &req,
                Request::TcpListen { .. }
                    | Request::ListDir { .. }
                    | Request::ListDirDetails { .. }
                    | Request::ListDirNoFollowFinal { .. }
                    | Request::NativeRemove { .. }
                    | Request::CheckOperatorDirectory { .. }
                    | Request::CheckOperatorDirectoryAncestry { .. }
                    | Request::RegisterSourceRoots { .. }
                    | Request::CreateOperatorDirectory { .. }
                    | Request::AnchorDestination { .. }
                    | Request::CopySmallFiles(_)
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
        // A fence performs no filesystem operation and grants no authority.
        // It must work after expiration/revocation too: preceding writes have
        // already received their individual authorization/error responses.
        if matches!(req, Request::WriteStreamFence) {
            w.write_msg(&Response::WriteStreamDone)?;
            continue;
        }
        let settlement = match &authority {
            Some(authority) => match authority.authorize(&mut req, over_ssh) {
                Ok(settlement) => Some(settlement),
                Err(error) => {
                    w.write_msg(&Response::Err(format!("{error:#}")))?;
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
            Request::ReadRange { len, .. } => {
                blocks += 1;
                bytes += *len as u64;
            }
            Request::ReadSmallBatch(reads) => {
                blocks += reads.len() as u64;
                bytes += reads.iter().map(|read| u64::from(read.len)).sum::<u64>();
            }
            Request::PutSmallBatch(puts) => {
                blocks += puts.len() as u64;
                bytes += puts.iter().map(|put| put.data.len() as u64).sum::<u64>();
            }
            _ => {}
        }
        match req {
            Request::Shutdown => break,
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
                let mut limit = stream.end;
                let mut done_sent = false;
                loop {
                    // Once all payload (or a read error) is sent, advertise
                    // the data boundary without waiting another network RTT
                    // for Stop. Still consume Stop before leaving this mode:
                    // the client's later commands follow it on the same
                    // ordered connection, including late shrink notifications.
                    if stream.off >= limit && !done_sent {
                        w.write_msg(&Response::ReadStreamDone)?;
                        done_sent = true;
                    }
                    if reader.stream_stopped(stream.off, &mut limit, done_sent)? {
                        break;
                    }
                    if stream.off >= limit {
                        // A late shrink crossed the current offset: send Done
                        // on the next iteration, without another read or RTT.
                        continue;
                    }
                    let t0 = std::time::Instant::now();
                    let response = ops.handle(&stream.next_request());
                    t[1] += t0.elapsed().as_secs_f64();
                    if let Response::Block { data, .. } = &response {
                        stream.off += data.len() as u64;
                        blocks += 1;
                        bytes += data.len() as u64;
                    } else {
                        stream.off = stream.end;
                    }
                    let t0 = std::time::Instant::now();
                    w.write_msg(&response)?;
                    t[2] += t0.elapsed().as_secs_f64();
                }
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
                match tcp_listen(
                    key,
                    token,
                    port_lo,
                    port_hi,
                    debug,
                    w.compress,
                    congestion_control.as_deref(),
                    authority.clone(),
                    descriptor_session.clone(),
                ) {
                    Ok((port, families, congestion_control)) => {
                        w.write_msg(&Response::TcpListening {
                            port,
                            addrs: local_addrs(families),
                            congestion_control,
                        })?
                    }
                    Err(e) if crate::conn::is_tcp_congestion_error(&e) => {
                        w.write_msg(&Response::TcpCongestionRejected(format!("{e:#}")))?
                    }
                    Err(e) => w.write_msg(&Response::Err(format!("{e:#}")))?,
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
                let mut sink = |batch: Vec<crate::proto::Entry>| {
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
                    Ok(w.write_msg(&Response::ScanBatch(batch))?)
                };
                let mut ignored = |paths: Vec<crate::proto::PathBytes>| {
                    if let Some(authority) = &authority {
                        authority
                            .record_scanned(&requested_root, paths.iter().map(Vec::as_slice))?;
                    }
                    Ok(wref.borrow_mut().write_msg(&Response::ScanIgnored(paths))?)
                };
                let res = if let Some(guard) = guard {
                    crate::scan::scan_rooted(
                        &root,
                        follow_root,
                        &ignore,
                        report_ignored,
                        &guard,
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
                    Ok(()) => w.write_msg(&Response::ScanDone)?,
                    Err(e) => w.write_msg(&Response::Err(format!("{e:#}")))?,
                }
            }
            Request::TransportStats => {
                w.write_msg(&Response::TransportStats(reader.tcp_stats()))?;
            }
            Request::MappingChunk { .. } => {
                let response = if authority.is_some() {
                    Response::Ok
                } else {
                    Response::Err("mapping admission requires a restricted receiver".into())
                };
                if let (Some(authority), Some(settlement)) = (&authority, settlement) {
                    authority.settle(settlement, &response);
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
            other => {
                let t0 = std::time::Instant::now();
                let resp = ops.handle(&other);
                if let (Some(authority), Some(settlement)) = (&authority, settlement) {
                    authority.settle(settlement, &resp);
                }
                t[1] += t0.elapsed().as_secs_f64();
                if drop_after_handling_for_test(&other) {
                    return Ok(());
                }
                let t0 = std::time::Instant::now();
                w.write_msg(&resp)?;
                t[2] += t0.elapsed().as_secs_f64();
            }
        }
    }
    if debug {
        crate::output::diagnostic!(
            "syq server{}: {blocks} blocks, {} MiB; waiting for input {:.2}s, handling {:.2}s, writing responses {:.2}s",
            if over_ssh { "" } else { " (tcp)" },
            bytes >> 20,
            t[0],
            t[1],
            t[2]
        );
    }
    Ok(())
}

fn is_virtual_iface(name: &str) -> bool {
    name == "lo"
        || [
            "docker", "veth", "br-", "virbr", "vmnet", "cni", "flannel", "cali", "kube", "ib",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        || std::path::Path::new(&format!("/sys/class/net/{name}/bridge")).exists()
}

fn iface_speed(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/speed"))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v as u32)
        .unwrap_or(0)
}

/// Which address families the data listener bound, and so which advertised
/// addresses a client could possibly connect to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BoundFamilies {
    v4: bool,
    v6: bool,
}

impl BoundFamilies {
    fn accepts(self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }
}

/// (ip, speed_mbps) for each real NIC the client might reach us on, over
/// both IPv4 and IPv6. The ssh session's own server address is first (and is
/// included even when the interface listing is unavailable); virtual
/// interfaces (docker/bridges/etc.) are skipped so multipath never fans out
/// onto a dead bridge.
fn local_addrs(families: BoundFamilies) -> Vec<(String, u32)> {
    let ssh_ip = std::env::var("SSH_CONNECTION").ok().and_then(|c| {
        c.split_whitespace()
            .nth(2)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
    });
    let out = std::process::Command::new("ip")
        .args(["-o", "addr", "show"])
        .output();
    let text = out
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    advertised_addrs(&text, ssh_ip, families, iface_speed)
}

/// Priority bucket for an advertised address: lower sorts first. The address
/// ssh arrived on is bucket 0 (handled by the caller); this classifies the
/// rest so that LAN addresses are tried before public ones and overlay
/// (CGNAT / Tailscale) addresses last.
fn addr_bucket(ip: IpAddr) -> u8 {
    if crate::conn::is_overlay_address(&ip.to_string()) {
        return 3; // CGNAT / Tailscale
    }
    match ip {
        IpAddr::V4(v4) if v4.is_private() => 1,
        // Unique local (fc00::/7), e.g. a private cloud network.
        IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00 => 1,
        _ => 2, // public
    }
}

/// Parse `ip -o addr show` output into the addresses worth advertising, in
/// priority order: the ssh arrival address, then by bucket, then by NIC speed
/// (fastest first). Only `scope global` addresses of a bound family count,
/// which drops loopback and link-local addresses (a client cannot use an
/// `fe80::` address without the interface scope, which syq does not carry).
fn advertised_addrs(
    text: &str,
    ssh_ip: Option<IpAddr>,
    families: BoundFamilies,
    iface_speed: impl Fn(&str) -> u32,
) -> Vec<(String, u32)> {
    let mut addrs: Vec<(IpAddr, u32, u8)> = Vec::new(); // (ip, speed, priority-bucket)
    for line in text.lines() {
        // "3: bond0    inet 10.2.201.45/24 brd ... scope global bond0\ ..."
        // "3: bond0    inet6 fdaa:0:1::2/112 scope global \ ..."
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(iface) = f.get(1) else {
            continue;
        };
        let Some(family_at) = f.iter().position(|w| *w == "inet" || *w == "inet6") else {
            continue;
        };
        let Some(ipcidr) = f.get(family_at + 1) else {
            continue;
        };
        let scope = f
            .iter()
            .position(|w| *w == "scope")
            .and_then(|at| f.get(at + 1))
            .copied();
        if scope != Some("global") {
            continue;
        }
        // An address the kernel is still checking, or is retiring, is not a
        // reliable route to advertise.
        if f.iter().any(|w| *w == "tentative" || *w == "deprecated") {
            continue;
        }
        if is_virtual_iface(iface) {
            continue;
        }
        let Some(ip) = ipcidr
            .split('/')
            .next()
            .and_then(|ip| ip.parse::<IpAddr>().ok())
        else {
            continue;
        };
        if !families.accepts(ip) || ip.is_loopback() {
            continue;
        }
        let bucket = if ssh_ip == Some(ip) {
            0
        } else {
            addr_bucket(ip)
        };
        addrs.push((ip, iface_speed(iface), bucket));
    }
    // The address ssh arrived on is reachable by construction (loopback
    // included: the client is then on this host). Advertise it even when the
    // listing did not name it (no `ip` tool, or an address on an interface
    // the listing filtered out).
    if let Some(ip) = ssh_ip {
        if families.accepts(ip) && !addrs.iter().any(|a| a.0 == ip) {
            addrs.push((ip, 0, 0));
        }
    }
    // ssh-arrival ip first, then by bucket, then by speed (fastest first).
    addrs.sort_by(|a, b| a.2.cmp(&b.2).then(b.1.cmp(&a.1)));
    addrs.dedup_by(|a, b| a.0 == b.0);
    addrs
        .into_iter()
        .map(|(ip, sp, _)| (ip.to_string(), sp))
        .collect()
}

/// Bind the data listener on the first free port in `lo..=hi`, on both
/// address families when the host supports both. IPv6 is bound `V6ONLY` so the
/// two sockets never contend for the same wildcard address, whatever the
/// platform default. A port where either family is already taken is skipped
/// so the two listeners always share one port number; a family the host cannot
/// bind at all (no IPv6, say) is simply left out.
fn bind_data_listeners(lo: u16, hi: u16) -> Result<(u16, Vec<TcpListener>)> {
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
        for domain in [Domain::IPV4, Domain::IPV6] {
            let bound = (|| -> std::io::Result<TcpListener> {
                let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
                // As std's TcpListener::bind does: a port with lingering
                // TIME_WAIT sockets from an earlier transfer stays usable.
                #[cfg(unix)]
                socket.set_reuse_address(true)?;
                let address: SocketAddr = if domain == Domain::IPV4 {
                    (Ipv4Addr::UNSPECIFIED, port).into()
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
    debug: bool,
    compress: bool,
    congestion_control: Option<&str>,
    authority: Option<Arc<crate::restricted::RestrictedAuthority>>,
    descriptor_session: DescriptorSessionSlot,
) -> Result<(u16, BoundFamilies, Option<String>)> {
    let (port, listeners) = bind_data_listeners(lo, hi)?;
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
        let (key, token, next_id, live, seen, authority, descriptor_session) = (
            key.clone(),
            token.clone(),
            next_id.clone(),
            live.clone(),
            seen.clone(),
            authority.clone(),
            descriptor_session.clone(),
        );
        std::thread::spawn(move || {
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
                descriptor_session,
            )
        });
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
    descriptor_session: DescriptorSessionSlot,
) {
    loop {
        if descriptor_session.is_closed()
            || authority
                .as_ref()
                .is_some_and(|authority| !authority.control_is_open())
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
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(_) => continue,
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
        let (key, token, live, seen, authority, descriptor_session) = (
            key.clone(),
            token.clone(),
            live.clone(),
            seen.clone(),
            authority.clone(),
            descriptor_session.clone(),
        );
        std::thread::spawn(move || {
            if let Err(e) = serve_tcp(
                stream,
                id,
                key,
                token,
                debug,
                compress,
                &seen,
                authority.clone(),
                descriptor_session,
                handshake_deadline,
            ) {
                if debug {
                    crate::output::diagnostic!("syq server (tcp {id}): {e:#}");
                }
            }
            live.fetch_sub(1, Relaxed);
        });
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
    descriptor_session: DescriptorSessionSlot,
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
    let writer = RecordWriter::new(stream.try_clone()?, wc);
    // Free the id only if the connection NEVER authenticated, so an
    // unauthenticated peer can't reserve ids. Once the token authenticated, the
    // id is retained permanently even if a later request fails — otherwise an
    // on-path attacker could corrupt an authenticated stream to free the id and
    // then replay captured records under it.
    let authed = std::sync::atomic::AtomicBool::new(false);
    let res = serve(
        reader,
        writer,
        false,
        Some(token),
        Some(&authed),
        Some(stream.try_clone()?),
        ServeSession {
            handshake_pending: Some(handshake_pending),
            ssh_worker_ticket: None,
            allow_tcp: true,
            named_socket: None,
            authority,
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
        "write" => matches!(request, Request::WriteRange { .. }),
        "finalize" => matches!(request, Request::Finalize { .. }),
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
/// Hello deadline. `serve` clears the shared socket timeout after HelloOk.
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

#[cfg(test)]
mod tests {
    #[test]
    fn read_stream_shrinks_before_the_next_read_and_fences_late_updates() {
        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        let reader = super::RequestReader {
            rx: Some(rx),
            thread: None,
            tcp_socket: None,
            named_socket: None,
        };
        let send = |value| {
            tx.send(Ok(crate::wire_budget::Budgeted {
                value,
                hold: crate::wire_budget::Hold::new(),
            }))
            .unwrap();
        };
        let mut limit = 4096;
        send(super::Request::ShrinkReadStream { end: 2048 });
        send(super::Request::ShrinkReadStream { end: 1024 });
        assert!(!reader.stream_stopped(0, &mut limit, false).unwrap());
        assert_eq!(limit, 1024);

        // Even if a block straddled the new end, consume subsequent shrink
        // commands and wait for Stop; never issue another read or consume
        // the next stream's command. A zero limit cancels all future reads.
        send(super::Request::ShrinkReadStream { end: 0 });
        send(super::Request::StopReadStream);
        send(super::Request::Shutdown);
        assert!(reader.stream_stopped(2048, &mut limit, true).unwrap());
        assert_eq!(limit, 0);
        assert!(matches!(
            reader.recv().unwrap().unwrap().value,
            super::Request::Shutdown
        ));

        // Increasing a limit is a protocol error, not new read authority.
        send(super::Request::ShrinkReadStream { end: u64::MAX });
        assert!(reader.stream_stopped(2048, &mut limit, true).is_err());
        assert_eq!(limit, 0);
        drop(tx);
        assert!(reader.stream_stopped(2048, &mut limit, true).is_err());
    }

    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn streaming_fence_survives_revocation_without_authorizing_more_writes() {
        let root = crate::test_support::tempdir().unwrap();
        let authority = Arc::new(crate::restricted::tests::tcp_test_authority(root.path()));
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server_authority = authority.clone();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            serve(
                socket.try_clone().unwrap(),
                socket.try_clone().unwrap(),
                false,
                None,
                None,
                Some(socket),
                ServeSession {
                    handshake_pending: None,
                    ssh_worker_ticket: None,
                    allow_tcp: true,
                    named_socket: None,
                    authority: Some(server_authority),
                    descriptor_session: DescriptorSessionSlot::default(),
                },
            )
            .unwrap();
        });
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = FrameReader::new(socket.try_clone().unwrap());
        let mut writer = FrameWriter::new(socket.try_clone().unwrap(), true);
        writer
            .write_msg(&Request::Hello {
                identity: crate::identity::build().to_string(),
                compress: true,
                debug: false,
                token: Vec::new(),
                role: ConnectionRole::DestinationWorker {
                    destination: None,
                    copy_sources: Vec::new(),
                },
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::HelloOk { .. }
        ));
        authority.close_control();
        for _ in 0..2 {
            writer
                .write_msg(&Request::WriteRange {
                    path: b"file".to_vec(),
                    inplace: false,
                    copy_id: CopyId::default(),
                    attempt: 0,
                    off: 0,
                    hash: fsops::content_digest(b"data"),
                    data: b"data".to_vec(),
                    guard: None,
                })
                .unwrap();
            assert!(
                matches!(reader.read_msg::<Response>().unwrap(), Response::Err(error) if error.contains("closed"))
            );
            writer.write_msg(&Request::WriteStreamFence).unwrap();
            assert!(matches!(
                reader.read_msg::<Response>().unwrap(),
                Response::WriteStreamDone
            ));
        }
        socket.shutdown(std::net::Shutdown::Both).unwrap();
        server.join().unwrap();
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    const IP_ADDR_SHOW: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever
2: eth0    inet 172.19.3.10/29 brd 172.19.3.15 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet6 fdaa:0:1:a7b::2/112 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::2/64 scope global \\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::3/64 scope global tentative \\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::9e6b:ff:fe4e:89ad/64 scope link \\       valid_lft forever preferred_lft forever
3: bond0    inet 10.2.201.45/24 brd 10.2.201.255 scope global bond0\\       valid_lft forever preferred_lft forever
4: tailscale0    inet 100.101.102.103/32 scope global tailscale0\\       valid_lft forever preferred_lft forever
4: tailscale0    inet6 fd7a:115c:a1e0::1234/128 scope global \\       valid_lft forever preferred_lft forever
5: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
";

    fn speeds(name: &str) -> u32 {
        match name {
            "bond0" => 25000,
            "eth0" => 1000,
            _ => 0,
        }
    }

    #[test]
    fn advertised_addrs_lists_both_families_with_ssh_arrival_first() {
        let ssh = "fdaa:0:1:a7b::2".parse().ok();
        let both = BoundFamilies { v4: true, v6: true };
        let got = advertised_addrs(IP_ADDR_SHOW, ssh, both, speeds);
        assert_eq!(
            got,
            vec![
                ("fdaa:0:1:a7b::2".to_string(), 1000),
                ("10.2.201.45".to_string(), 25000),
                ("172.19.3.10".to_string(), 1000),
                ("2001:db8::2".to_string(), 1000),
                ("100.101.102.103".to_string(), 0),
                ("fd7a:115c:a1e0::1234".to_string(), 0),
            ]
        );
    }

    #[test]
    fn advertised_addrs_only_names_families_the_listener_bound() {
        let v4 = BoundFamilies {
            v4: true,
            v6: false,
        };
        let got = advertised_addrs(IP_ADDR_SHOW, None, v4, speeds);
        assert!(got
            .iter()
            .all(|(ip, _)| ip.parse::<IpAddr>().unwrap().is_ipv4()));
        assert_eq!(got[0].0, "10.2.201.45");
        // The ssh arrival address is still advertised first, but only when a
        // listener of its family exists.
        let ssh = "fdaa:0:1:a7b::2".parse().ok();
        let got = advertised_addrs(IP_ADDR_SHOW, ssh, v4, speeds);
        assert!(!got.iter().any(|(ip, _)| ip.starts_with("fdaa")));
    }

    #[test]
    fn advertised_addrs_includes_ssh_arrival_address_without_a_listing() {
        let ssh = "203.0.113.7".parse().ok();
        let both = BoundFamilies { v4: true, v6: true };
        assert_eq!(
            advertised_addrs("", ssh, both, speeds),
            vec![("203.0.113.7".to_string(), 0)]
        );
    }

    #[test]
    fn data_listeners_share_one_port_across_families() {
        let (port, listeners) = bind_data_listeners(0, 0).unwrap();
        assert_ne!(port, 0);
        let ports: Vec<u16> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();
        assert!(ports.iter().all(|p| *p == port), "{ports:?} != {port}");
        for listener in &listeners {
            let local = listener.local_addr().unwrap();
            let target: SocketAddr = if local.is_ipv4() {
                (Ipv4Addr::LOCALHOST, port).into()
            } else {
                (Ipv6Addr::LOCALHOST, port).into()
            };
            TcpStream::connect_timeout(&target, Duration::from_secs(2))
                .unwrap_or_else(|e| panic!("connect {target}: {e}"));
        }
    }

    struct ExitObserved<R> {
        inner: R,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl<R: Read> Read for ExitObserved<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl<R> Drop for ExitObserved<R> {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn tcp_server_joins_request_reader_on_shutdown() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let selected = crate::test_support::tempdir().unwrap();
        let marker = selected.path().join("marker");
        std::fs::write(&marker, b"marker").unwrap();
        std::fs::File::create(selected.path().join("stream-large"))
            .unwrap()
            .set_len(8 << 20)
            .unwrap();
        let descriptor_session = DescriptorSessionSlot::default();
        let ticket = descriptor_session
            .register(std::fs::File::open(selected.path()).unwrap())
            .unwrap();
        let selection = RegisteredPath::new(ticket.root_id(), Vec::new()).unwrap();
        let source = RegisteredSourceRoot {
            selection: selection.clone(),
            ticket,
            leaf_ticket: None,
            expected_leaf: None,
            allow_unconfined_paths: false,
        };
        let server_session = descriptor_session.clone();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = dropped.clone();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            serve(
                ExitObserved {
                    inner: socket.try_clone().unwrap(),
                    dropped: observed,
                },
                socket.try_clone().unwrap(),
                false,
                None,
                None,
                Some(socket),
                ServeSession {
                    handshake_pending: None,
                    ssh_worker_ticket: None,
                    allow_tcp: true,
                    named_socket: None,
                    authority: None,
                    descriptor_session: server_session,
                },
            )
            .unwrap();
        });

        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut writer = FrameWriter::new(socket.try_clone().unwrap(), false);
        let mut reader = FrameReader::new(socket);
        writer
            .write_msg(&Request::Hello {
                identity: crate::identity::build().to_string(),
                compress: false,
                debug: false,
                token: Vec::new(),
                role: ConnectionRole::SourceWorker {
                    roots: vec![source],
                },
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::HelloOk { .. }
        ));
        let selected_metadata = std::fs::metadata(selected.path()).unwrap();
        let guard = ContainerGuard {
            root: selected.path().as_os_str().as_bytes().to_vec(),
            dev: selected_metadata.dev(),
            ino: selected_metadata.ino(),
        };
        writer
            .write_msg(&Request::Scan {
                root: selected.path().as_os_str().as_bytes().to_vec(),
                source: None,
                follow_root: false,
                ignore: Vec::new(),
                report_ignored: false,
                guard: Some(guard.clone()),
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(error) if error.contains("source session rejects caller-supplied guards")
        ));
        writer
            .write_msg(&Request::Apply {
                ops: vec![Op::Unlink {
                    path: marker.as_os_str().as_bytes().to_vec(),
                }],
                guard: None,
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(error) if error.contains("not valid on a source worker")
        ));
        assert_eq!(std::fs::read(&marker).unwrap(), b"marker");
        writer
            .write_msg(&Request::StatMany {
                paths: vec![selected.path().as_os_str().as_bytes().to_vec()],
                sources: None,
                follow: false,
                guard: Some(guard),
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(error) if error.contains("source session rejects caller-supplied guards")
        ));
        writer
            .write_msg(&Request::ReadRange {
                // This contradictory spelling is diagnostic only; the
                // registered source reference is the read authority.
                path: b"/not/the/source/marker".to_vec(),
                source: Some(selection.join(b"marker").unwrap()),
                attempt: 0,
                off: 0,
                len: 6,
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Block { data, .. } if data == b"marker"
        ));
        writer
            .write_msg(&Request::ReadRange {
                path: selected
                    .path()
                    .join("marker")
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
                source: None,
                attempt: 0,
                off: 0,
                len: 6,
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::EndpointError(error) if error.message.contains("omitted")
        ));
        // Streaming must retain the same source capability checks, including
        // after an error and after stopping an interval early.
        for (source, end, expected_error) in [
            (Some(selection.join(b"marker").unwrap()), 6, false),
            (None, 6, true),
            (Some(selection.join(b"marker").unwrap()), 4096, true),
        ] {
            writer
                .write_msg(&Request::ReadStream(ReadStreamRequest {
                    path: marker.as_os_str().as_bytes().to_vec(),
                    source,
                    attempt: 0,
                    off: 0,
                    end,
                    block: 512,
                }))
                .unwrap();
            assert!(matches!(
                reader.read_msg::<Response>().unwrap(),
                Response::Ok
            ));
            let response = reader.read_msg::<Response>().unwrap();
            if expected_error {
                assert!(
                    matches!(response, Response::EndpointError(_)),
                    "{response:?}"
                );
            } else {
                assert!(matches!(response, Response::Block { data, .. } if data == b"marker"));
            }
            // Completion arrives before Stop, including after a read error.
            // The socket's read deadline makes waiting for Stop fail this test.
            assert!(matches!(
                reader.read_msg::<Response>().unwrap(),
                Response::ReadStreamDone
            ));
            // A shrink can arrive after the final block or an error. It has
            // no reply, does not restart reading, and cannot cross the fence.
            writer
                .write_msg(&Request::ShrinkReadStream { end: 0 })
                .unwrap();
            writer.write_msg(&Request::StopReadStream).unwrap();
            // The next iteration's request must not consume a second Done
            // or a response to the late shrink/stop.
            writer
                .write_msg(&Request::ShrinkReadStream { end: 0 })
                .unwrap();
            assert!(matches!(
                reader.read_msg::<Response>().unwrap(),
                Response::Err(error) if error == "no read stream is active"
            ));
        }
        // A late shrink can exhaust a still-active stream after read-ahead
        // crossed its new boundary. It must produce Done before Stop, just
        // like natural EOF. Small frames keep the stream in flight until the
        // client sends the shrink; the read deadline catches a stop-RTT stall.
        writer
            .write_msg(&Request::ReadStream(ReadStreamRequest {
                path: Vec::new(),
                source: Some(selection.join(b"stream-large").unwrap()),
                attempt: 0,
                off: 0,
                end: 8 << 20,
                block: 512,
            }))
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Ok
        ));
        let mut received = match reader.read_msg::<Response>().unwrap() {
            Response::Block { data, .. } => data.len(),
            other => panic!("expected first streamed block, got {other:?}"),
        };
        writer
            .write_msg(&Request::ShrinkReadStream { end: 0 })
            .unwrap();
        loop {
            match reader.read_msg::<Response>().unwrap() {
                Response::Block { data, .. } => received += data.len(),
                Response::ReadStreamDone => break,
                other => panic!("unexpected late-shrink response: {other:?}"),
            }
        }
        assert!(
            received < 8 << 20,
            "stream ended naturally before the shrink"
        );
        writer
            .write_msg(&Request::ShrinkReadStream { end: 0 })
            .unwrap();
        writer.write_msg(&Request::StopReadStream).unwrap();
        writer
            .write_msg(&Request::ReadStream(ReadStreamRequest {
                path: Vec::new(),
                source: Some(selection.join(b"marker").unwrap()),
                attempt: 0,
                off: 0,
                end: 6,
                block: 0,
            }))
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(_)
        ));
        writer
            .write_msg(&Request::RegisterSourceRoots {
                base: SourceRootBase::default(),
                selections: vec![SourceRootSelection {
                    path: b".".to_vec(),
                    follow_root: false,
                }],
                symlink_policy: OperatorSymlinkPolicy::Refuse,
                allow_unconfined_paths: false,
                shared_workers: 0,
                independent_handoff_workers: 0,
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(error) if error.contains("only on the control connection")
        ));
        writer.write_msg(&Request::Shutdown).unwrap();
        server.join().unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(Arc::strong_count(&dropped), 1);
    }

    #[test]
    fn rejected_destination_ticket_is_not_acknowledged_as_ready() {
        let selected = crate::test_support::tempdir().unwrap();
        let owner = DescriptorSessionSlot::default();
        let ticket = owner
            .register(std::fs::File::open(selected.path()).unwrap())
            .unwrap();
        owner.close();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            serve(
                socket.try_clone().unwrap(),
                socket,
                false,
                None,
                None,
                None,
                ServeSession {
                    handshake_pending: None,
                    ssh_worker_ticket: None,
                    allow_tcp: true,
                    named_socket: None,
                    authority: None,
                    descriptor_session: DescriptorSessionSlot::default(),
                },
            )
            .unwrap_err()
        });

        let socket = TcpStream::connect(address).unwrap();
        let mut writer = FrameWriter::new(socket.try_clone().unwrap(), false);
        let mut reader = FrameReader::new(socket);
        writer
            .write_msg(&Request::Hello {
                identity: crate::identity::build().to_string(),
                compress: false,
                debug: false,
                token: Vec::new(),
                role: ConnectionRole::DestinationWorker {
                    destination: Some(DestinationRoot {
                        ticket,
                        request_prefix: b"destination".to_vec(),
                    }),
                    copy_sources: Vec::new(),
                },
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(error) if error.contains("initialize destination worker")
        ));
        server.join().unwrap();
    }

    #[test]
    fn rejected_source_ticket_is_not_acknowledged_as_ready() {
        let selected = crate::test_support::tempdir().unwrap();
        let owner = DescriptorSessionSlot::default();
        let ticket = owner
            .register(std::fs::File::open(selected.path()).unwrap())
            .unwrap();
        let source = RegisteredSourceRoot {
            selection: RegisteredPath::new(ticket.root_id(), Vec::new()).unwrap(),
            ticket,
            leaf_ticket: None,
            expected_leaf: None,
            allow_unconfined_paths: false,
        };
        owner.close();

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            serve(
                socket.try_clone().unwrap(),
                socket,
                false,
                None,
                None,
                None,
                ServeSession {
                    handshake_pending: None,
                    ssh_worker_ticket: None,
                    allow_tcp: true,
                    named_socket: None,
                    authority: None,
                    descriptor_session: DescriptorSessionSlot::default(),
                },
            )
            .unwrap_err()
        });

        let socket = TcpStream::connect(address).unwrap();
        let mut writer = FrameWriter::new(socket.try_clone().unwrap(), false);
        let mut reader = FrameReader::new(socket);
        writer
            .write_msg(&Request::Hello {
                identity: crate::identity::build().to_string(),
                compress: false,
                debug: false,
                token: Vec::new(),
                role: ConnectionRole::SourceWorker {
                    roots: vec![source],
                },
            })
            .unwrap();
        assert!(matches!(
            reader.read_msg::<Response>().unwrap(),
            Response::Err(error) if error.contains("initialize source worker")
        ));
        server.join().unwrap();
    }

    fn tcp_test_hello(token: &[u8]) -> Request {
        Request::Hello {
            identity: crate::identity::build().to_string(),
            compress: true,
            debug: false,
            token: token.to_vec(),
            role: ConnectionRole::DestinationWorker {
                destination: None,
                copy_sources: Vec::new(),
            },
        }
    }

    fn tcp_test_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        (client, listener.accept().unwrap().0)
    }

    #[test]
    fn tcp_rejects_replayed_hello_with_high_connection_id_bits() {
        let temporary = crate::test_support::tempdir().unwrap();
        let authority = Arc::new(crate::restricted::tests::tcp_test_authority(
            temporary.path(),
        ));
        let key = vec![7; crate::tcp_records::KEY_LEN];
        let token = b"replay-test";
        let conn_id = 42u32;
        let mut capture = Vec::new();
        FrameWriter::new(
            RecordWriter::new(&mut capture, Some(Cipher::new(&key, conn_id, 1))),
            false,
        )
        .write_msg(&tcp_test_hello(token))
        .unwrap();
        let seen = std::sync::Mutex::new(std::collections::HashSet::new());
        // The original authenticates; changing only the high byte used to
        // bypass the replay set while decrypting exactly the same records.
        for (attempt, high) in [0u32, 1, 2, 128, 255, 0].into_iter().enumerate() {
            let (mut client, server) = tcp_test_pair();
            client
                .write_all(&(conn_id | (high << 24)).to_be_bytes())
                .unwrap();
            client.write_all(&capture).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let result = serve_tcp(
                server,
                0,
                Some(key.clone()),
                token.to_vec(),
                false,
                false,
                &seen,
                Some(authority.clone()),
                DescriptorSessionSlot::default(),
                std::time::Instant::now() + Duration::from_secs(1),
            );
            if high != 0 {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("exceeds nonce space"));
                // Rejection must precede the server's encrypted preamble.
                let mut response = Vec::new();
                let _ = client.read_to_end(&mut response);
                assert!(response.is_empty());
            } else if attempt != 0 {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("duplicate connection id"));
            } else {
                result.unwrap();
                assert!(seen.lock().unwrap().contains(&conn_id));
            }
            assert_eq!(
                *seen.lock().unwrap(),
                std::collections::HashSet::from([conn_id])
            );
        }
    }

    #[test]
    fn tcp_partial_handshakes_time_out_without_reserving_ids() {
        for encrypted in [false, true] {
            // Stop inside the ID, after a complete preamble record, and
            // inside the Hello record. None of these authenticates a peer.
            for part in 0..3 {
                let key = encrypted.then(|| vec![9; crate::tcp_records::KEY_LEN]);
                let id = 43u32;
                let mut preamble = Vec::new();
                FrameWriter::new(
                    RecordWriter::new(
                        &mut preamble,
                        key.as_ref().map(|key| Cipher::new(key, id, 1)),
                    ),
                    false,
                )
                .write_preamble()
                .unwrap();
                let mut hello = Vec::new();
                FrameWriter::new(
                    RecordWriter::new(&mut hello, key.as_ref().map(|key| Cipher::new(key, id, 1))),
                    false,
                )
                .write_msg(&tcp_test_hello(b"timeout-test"))
                .unwrap();
                let mut bytes = id.to_be_bytes().to_vec();
                match part {
                    0 => bytes.truncate(1),
                    1 => bytes.extend_from_slice(&preamble),
                    _ => bytes.extend_from_slice(&hello[..hello.len() - 1]),
                }
                let (mut client, server) = tcp_test_pair();
                client.write_all(&bytes).unwrap();
                let (tx, rx) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let seen = std::sync::Mutex::new(std::collections::HashSet::new());
                    let result = serve_tcp(
                        server,
                        0,
                        key,
                        b"timeout-test".to_vec(),
                        false,
                        false,
                        &seen,
                        None,
                        DescriptorSessionSlot::default(),
                        std::time::Instant::now() + Duration::from_millis(100),
                    );
                    tx.send((result, seen.into_inner().unwrap())).unwrap();
                });
                let result = rx.recv_timeout(Duration::from_secs(3));
                // Ensure a regression never leaves a blocked server thread.
                client.shutdown(std::net::Shutdown::Both).ok();
                worker.join().unwrap();
                let (result, seen) =
                    result.expect("partial TCP Hello held a worker past its deadline");
                assert!(result.is_err());
                assert!(seen.is_empty());
            }
        }
    }

    #[test]
    fn tcp_hello_clears_timeouts_only_after_authentication() {
        let temporary = crate::test_support::tempdir().unwrap();
        let authority = Arc::new(crate::restricted::tests::tcp_test_authority(
            temporary.path(),
        ));
        for encrypted in [false, true] {
            let key = encrypted.then(|| vec![8; crate::tcp_records::KEY_LEN]);
            let server_key = key.clone();
            let authority = authority.clone();
            let (client, server) = tcp_test_pair();
            let observer = server.try_clone().unwrap();
            let worker = std::thread::spawn(move || {
                let seen = std::sync::Mutex::new(std::collections::HashSet::new());
                serve_tcp(
                    server,
                    0,
                    server_key,
                    b"valid-token".to_vec(),
                    false,
                    false,
                    &seen,
                    Some(authority),
                    DescriptorSessionSlot::default(),
                    std::time::Instant::now() + Duration::from_millis(100),
                )
            });
            (&client).write_all(&44u32.to_be_bytes()).unwrap();
            let mut writer = FrameWriter::new(
                RecordWriter::new(
                    client.try_clone().unwrap(),
                    key.as_ref().map(|key| Cipher::new(key, 44, 1)),
                ),
                false,
            );
            let mut reader = FrameReader::new(RecordReader::new(
                client.try_clone().unwrap(),
                key.as_ref().map(|key| Cipher::new(key, 44, 2)),
            ));
            writer.write_msg(&tcp_test_hello(b"valid-token")).unwrap();
            assert!(matches!(
                reader.read_msg::<Response>().unwrap(),
                Response::HelloOk { .. }
            ));
            // Wait beyond the handshake deadline, then prove the worker is
            // still alive and both shared socket timeouts have been cleared.
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(observer.read_timeout().unwrap(), None);
            assert_eq!(observer.write_timeout().unwrap(), None);
            assert!(!worker.is_finished());
            client.shutdown(std::net::Shutdown::Both).unwrap();
            worker.join().unwrap().unwrap();
        }
    }

    #[test]
    fn tcp_handshake_deadline_does_not_reset_after_partial_reads() {
        let (mut client, server) = tcp_test_pair();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut reader = TcpHandshakeReader {
            stream: server,
            pending: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            deadline: std::time::Instant::now() + Duration::from_millis(100),
        };
        client.write_all(b"a").unwrap();
        reader.read_exact(&mut [0]).unwrap();
        assert!(reader.stream.read_timeout().unwrap().is_some());
        std::thread::sleep(Duration::from_millis(150));
        client.write_all(b"b").unwrap();
        assert_eq!(
            reader.read(&mut [0]).unwrap_err().kind(),
            ErrorKind::TimedOut
        );
    }

    /// Connect to the data listener and complete a token-authenticated Hello
    /// as a destination worker. Returns the still-open socket on success so
    /// the caller controls when the worker's permit is released.
    fn authenticated_worker(
        port: u16,
        token: &[u8],
    ) -> std::result::Result<TcpStream, anyhow::Error> {
        let socket = TcpStream::connect(("127.0.0.1", port))?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        let conn_id = TEST_TCP_CONN_ID.fetch_add(1, Relaxed);
        (&socket).write_all(&conn_id.to_be_bytes())?;
        let mut writer = FrameWriter::new(RecordWriter::new(socket.try_clone()?, None), false);
        let mut reader = FrameReader::new(RecordReader::new(socket.try_clone()?, None));
        writer.write_msg(&Request::Hello {
            identity: crate::identity::build().to_string(),
            compress: true,
            debug: false,
            token: token.to_vec(),
            role: ConnectionRole::DestinationWorker {
                destination: None,
                copy_sources: Vec::new(),
            },
        })?;
        match reader.read_msg::<Response>()? {
            Response::HelloOk { .. } => Ok(socket),
            other => bail!("unexpected Hello response {other:?}"),
        }
    }

    static TEST_TCP_CONN_ID: AtomicU32 = AtomicU32::new(1000);

    #[test]
    fn unauthenticated_sockets_do_not_consume_signed_worker_permits() {
        let temporary = crate::test_support::tempdir().unwrap();
        let root = temporary.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let authority = Arc::new(crate::restricted::tests::tcp_test_authority(&root));
        let max_workers = usize::from(crate::restricted::tests::TEST_AUTHORITY_MAX_CONNECTIONS);
        let token = b"data-token".to_vec();
        let descriptor_session = DescriptorSessionSlot::default();
        let (port, _, _) = tcp_listen(
            None,
            token.clone(),
            0,
            0,
            false,
            true,
            None,
            Some(authority.clone()),
            descriptor_session.clone(),
        )
        .unwrap();

        // Pending handshakes that never authenticate, held open for the whole
        // test. One of them presents a connection id but never a Hello.
        let mut pending: Vec<TcpStream> = (0..max_workers + 1)
            .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
            .collect();
        pending[0].write_all(&0u32.to_be_bytes()).unwrap();
        // Reachability probes: connect and hang up without sending anything.
        for _ in 0..max_workers + 1 {
            drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
        }
        // Give the accept loop (which polls every 25ms) time to take every
        // pending socket, then confirm each is being served rather than
        // dropped. A socket with no connection id stays silent; the one that
        // supplied an id receives the server's proactive wire preamble.
        std::thread::sleep(Duration::from_millis(200));
        for socket in &pending {
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut byte = [0u8; 1];
            match (&*socket).read(&mut byte) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Ok(1) => {}
                other => panic!("pending socket was not held open: {other:?}"),
            }
        }

        // Every granted worker must still authenticate despite the probes and
        // pending sockets above.
        let mut workers: Vec<TcpStream> = (0..max_workers)
            .map(|_| authenticated_worker(port, &token).unwrap())
            .collect();

        // The grant's allowance is exhausted by authenticated workers alone.
        let refused = authenticated_worker(port, &token);
        assert!(
            refused.is_err(),
            "worker beyond the grant limit was accepted"
        );

        // Releasing one worker returns its permit.
        drop(workers.pop());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let replacement = loop {
            match authenticated_worker(port, &token) {
                Ok(socket) => break socket,
                Err(error) if std::time::Instant::now() < deadline => {
                    let _ = error;
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => panic!("released permit was not reusable: {error:#}"),
            }
        };
        workers.push(replacement);

        drop(pending);
        drop(workers);
        authority.close_control();
        descriptor_session.close();
    }
}
