//! Connections to endpoints: local (in-process) or remote (over an ssh child).

use crate::crypto::{Cipher, RecordReader, RecordWriter};
use crate::fsops::{self, FsOps};
#[allow(unused_imports)]
use crate::proto::SizeHint;
use crate::proto::*;
use crate::remote_helper::{self, Target};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

pub trait Conn: Send {
    fn send(&mut self, req: Request) -> Result<()>;
    fn recv(&mut self) -> Result<Response>;
    fn call(&mut self, req: Request) -> Result<Response> {
        self.send(req)?;
        self.recv()
    }
    /// True once the transport has failed (remote process gone).
    fn is_dead(&self) -> bool {
        false
    }
    /// Current kernel RTT estimate for a direct TCP connection. This is a
    /// local socket query and never sends a protocol request.
    fn tcp_rtt_us(&self) -> Option<u64> {
        None
    }
    /// Best-effort counters for a direct TCP data connection. Collection is
    /// deliberately observational: unavailable kernels and SSH return None.
    fn transport_stats(&mut self) -> Option<TcpPairStats> {
        None
    }
    /// Streamed scan; `sink` gets batches, `warn` gets non-fatal messages,
    /// `ignored` gets the paths the patterns pruned (only if `report_ignored`).
    #[allow(clippy::too_many_arguments)]
    fn scan(
        &mut self,
        root: &[u8],
        _source: Option<&RegisteredPath>,
        follow_root: bool,
        ignore: &[String],
        report_ignored: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()>;
    #[allow(clippy::too_many_arguments)]
    fn native_remove(
        &mut self,
        cwd: Option<&[u8]>,
        root: Option<&[u8]>,
        selections: &[NativeRemoveSelection],
        follow_symlinks: bool,
        dry_run: bool,
        workers: usize,
        trace: &mut dyn FnMut(Vec<String>) -> Result<()>,
        sink: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
    ) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub identity: String,
    pub platform: String,
}

#[derive(Clone, Debug)]
pub struct TcpPairStats {
    pub label: String,
    pub local: Option<TcpSocketStats>,
    pub peer: Option<TcpSocketStats>,
}

/// Marker for an explicit per-socket congestion-control request that could
/// not be honored. Callers use this to distinguish a bad experiment setup
/// from ordinary TCP reachability failures, which may fall back to SSH.
#[derive(Debug)]
pub(crate) struct TcpCongestionError(String);

impl std::fmt::Display for TcpCongestionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TcpCongestionError {}

pub(crate) fn is_tcp_congestion_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<TcpCongestionError>())
}

pub(crate) fn tcp_congestion_fallback_note(requested: Option<&str>) -> String {
    requested
        .map(|algorithm| {
            format!("; requested congestion control {algorithm} is not used by the SSH fallback")
        })
        .unwrap_or_default()
}

/// A worker reached the receiver, but its destination anchor was rejected.
/// Retrying or changing transports cannot repair a failed identity check.
#[derive(Debug)]
struct WorkerInitializationError(String);

impl std::fmt::Display for WorkerInitializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WorkerInitializationError {}

pub(crate) fn is_worker_initialization_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<WorkerInitializationError>())
}

/// OpenSSH accepted the control connection but rejected a multiplexed worker
/// session. Independent SSH connections may still be permitted (for example,
/// with `MaxSessions 1`), so callers can safely disable reuse and retry.
#[derive(Debug)]
struct MultiplexedSshSessionError(String);

impl std::fmt::Display for MultiplexedSshSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MultiplexedSshSessionError {}

fn is_multiplexed_ssh_session_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<MultiplexedSshSessionError>())
}

#[cfg(target_os = "linux")]
fn tcp_congestion_control<S: AsRawFd>(socket: &S) -> std::io::Result<String> {
    // Linux currently caps names at TCP_CA_NAME_MAX (16 including NUL). Leave
    // extra room so this remains safe if the kernel raises that limit.
    let mut name = [0u8; 64];
    let mut len = name.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            name.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let len = (len as usize).min(name.len());
    let end = name[..len]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(len);
    std::str::from_utf8(&name[..end])
        .map(str::to_owned)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// Apply an explicit Linux TCP_CONGESTION override and read it back. With no
/// override this is observational only: an unavailable getter returns None
/// and never changes normal socket behavior.
pub(crate) fn configure_tcp_congestion<S: AsRawFd>(
    socket: &S,
    requested: Option<&str>,
) -> Result<Option<String>> {
    let Some(requested) = requested else {
        #[cfg(target_os = "linux")]
        return Ok(tcp_congestion_control(socket).ok());
        #[cfg(not(target_os = "linux"))]
        return Ok(None);
    };

    #[cfg(not(target_os = "linux"))]
    return Err(TcpCongestionError(format!(
        "TCP congestion control {requested:?} was requested, but per-socket selection is supported only on Linux"
    ))
    .into());

    #[cfg(target_os = "linux")]
    {
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                requested.as_ptr().cast(),
                requested.len() as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            return Err(TcpCongestionError(format!(
                "kernel rejected TCP congestion control {requested:?}: {error}; check net.ipv4.tcp_available_congestion_control and net.ipv4.tcp_allowed_congestion_control on this host"
            ))
            .into());
        }
        let actual = tcp_congestion_control(socket).map_err(|error| {
            TcpCongestionError(format!(
                "could not verify TCP congestion control {requested:?}: {error}"
            ))
        })?;
        if actual != requested {
            return Err(TcpCongestionError(format!(
                "requested TCP congestion control {requested:?}, but the socket reports {actual:?}"
            ))
            .into());
        }
        Ok(Some(actual))
    }
}

fn connect_tcp_stream(
    address: &SocketAddr,
    timeout: std::time::Duration,
    congestion_control: Option<&str>,
) -> Result<TcpStream> {
    let Some(congestion_control) = congestion_control else {
        return TcpStream::connect_timeout(address, timeout).map_err(Into::into);
    };

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (address, timeout);
        return Err(TcpCongestionError(format!(
            "TCP congestion control {congestion_control:?} was requested, but per-socket selection is supported only on Linux"
        ))
        .into());
    }

    #[cfg(target_os = "linux")]
    {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        configure_tcp_congestion(&socket, Some(congestion_control))?;
        socket.connect_timeout(&SockAddr::from(*address), timeout)?;
        Ok(socket.into())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn tcp_socket_stats(stream: &TcpStream) -> Option<TcpSocketStats> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 {
        return None;
    }
    macro_rules! field {
        ($name:ident, $value:expr) => {
            ((len as usize)
                >= std::mem::offset_of!(libc::tcp_info, $name) + std::mem::size_of_val(&info.$name))
            .then(|| $value)
        };
    }
    Some(TcpSocketStats {
        congestion_control: tcp_congestion_control(stream).ok(),
        bytes_sent: field!(tcpi_bytes_sent, info.tcpi_bytes_sent),
        bytes_retransmitted: field!(tcpi_bytes_retrans, info.tcpi_bytes_retrans),
        segments_sent: field!(tcpi_segs_out, info.tcpi_segs_out.into()),
        segments_received: field!(tcpi_segs_in, info.tcpi_segs_in.into()),
        retransmissions: field!(tcpi_total_retrans, info.tcpi_total_retrans.into()),
        rtt_us: field!(tcpi_rtt, info.tcpi_rtt.into()),
        rtt_variance_us: field!(tcpi_rttvar, info.tcpi_rttvar.into()),
        min_rtt_us: field!(tcpi_min_rtt, info.tcpi_min_rtt.into()),
        send_cwnd_bytes: field!(
            tcpi_snd_cwnd,
            u64::from(info.tcpi_snd_cwnd) * u64::from(info.tcpi_snd_mss)
        ),
        delivery_rate: field!(tcpi_delivery_rate, info.tcpi_delivery_rate),
        busy_time_us: field!(tcpi_busy_time, info.tcpi_busy_time),
        receive_window_limited_us: field!(tcpi_rwnd_limited, info.tcpi_rwnd_limited),
        send_buffer_limited_us: field!(tcpi_sndbuf_limited, info.tcpi_sndbuf_limited),
        ecn_ce_delivered: field!(tcpi_delivered_ce, info.tcpi_delivered_ce.into()),
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn tcp_socket_stats(stream: &TcpStream) -> Option<TcpSocketStats> {
    let mut info: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_connection_info>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 {
        return None;
    }
    macro_rules! field {
        ($name:ident, $value:expr) => {
            ((len as usize)
                >= std::mem::offset_of!(libc::tcp_connection_info, $name)
                    + std::mem::size_of_val(&info.$name))
            .then(|| $value)
        };
    }
    Some(TcpSocketStats {
        congestion_control: None,
        bytes_sent: field!(tcpi_txbytes, info.tcpi_txbytes),
        bytes_retransmitted: field!(tcpi_txretransmitbytes, info.tcpi_txretransmitbytes),
        segments_sent: field!(tcpi_txpackets, info.tcpi_txpackets),
        segments_received: field!(tcpi_rxpackets, info.tcpi_rxpackets),
        retransmissions: None,
        // Darwin reports these fields in milliseconds.
        rtt_us: field!(tcpi_srtt, u64::from(info.tcpi_srtt) * 1000),
        rtt_variance_us: field!(tcpi_rttvar, u64::from(info.tcpi_rttvar) * 1000),
        min_rtt_us: None,
        send_cwnd_bytes: field!(tcpi_snd_cwnd, info.tcpi_snd_cwnd.into()),
        delivery_rate: None,
        busy_time_us: None,
        receive_window_limited_us: None,
        send_buffer_limited_us: None,
        ecn_ce_delivered: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn tcp_socket_stats(_stream: &TcpStream) -> Option<TcpSocketStats> {
    None
}

/// Turn an `Err` response into an error, otherwise pass through.
pub fn ok(resp: Response, what: &str) -> Result<Response> {
    match resp {
        Response::Err(e) => Err(anyhow!("{what}: {e}")),
        r => Ok(r),
    }
}

pub struct LocalConn {
    ops: FsOps,
    pending: VecDeque<Response>,
    is_control: bool,
}

impl LocalConn {
    fn new(
        is_control: bool,
        descriptor_session: crate::descriptor_broker::DescriptorSessionSlot,
    ) -> Self {
        LocalConn {
            ops: FsOps::with_descriptor_session(descriptor_session),
            pending: VecDeque::new(),
            is_control,
        }
    }
}

impl Conn for LocalConn {
    fn send(&mut self, req: Request) -> Result<()> {
        if !self.is_control
            && matches!(
                &req,
                Request::TcpListen { .. }
                    | Request::NativeRemove { .. }
                    | Request::CheckOperatorDirectory { .. }
                    | Request::RegisterSourceRoots { .. }
                    | Request::CreateOperatorDirectory { .. }
                    | Request::AnchorDestination { .. }
                    | Request::Receipt
            )
        {
            self.pending.push_back(Response::Err(
                "request is allowed only on the control connection".into(),
            ));
            return Ok(());
        }
        let resp = self.ops.handle(&req);
        self.pending.push_back(resp);
        Ok(())
    }
    fn recv(&mut self) -> Result<Response> {
        self.pending
            .pop_front()
            .ok_or_else(|| anyhow!("no pending response"))
    }
    fn scan(
        &mut self,
        root: &[u8],
        _source: Option<&RegisteredPath>,
        follow_root: bool,
        ignore: &[String],
        report_ignored: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        if let Some((destination_root, relative)) = self.ops.destination_scan_root(root)? {
            return crate::scan::scan_descriptor(
                destination_root,
                &relative,
                follow_root,
                ignore,
                report_ignored,
                sink,
                ignored,
                warn,
            );
        }
        let root = self.ops.scan_root(root)?;
        crate::scan::scan(
            &fsops::resolve(&root),
            follow_root,
            ignore,
            report_ignored,
            sink,
            ignored,
            warn,
        )
    }

    fn native_remove(
        &mut self,
        cwd: Option<&[u8]>,
        root: Option<&[u8]>,
        selections: &[NativeRemoveSelection],
        follow_symlinks: bool,
        dry_run: bool,
        workers: usize,
        trace: &mut dyn FnMut(Vec<String>) -> Result<()>,
        sink: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
    ) -> Result<()> {
        crate::native_rm::remove(
            cwd,
            root,
            selections,
            follow_symlinks,
            dry_run,
            workers,
            trace,
            sink,
        )
    }
}

pub struct RemoteConn {
    child: Option<Child>,
    w: FrameWriter<Box<dyn Write + Send>>,
    /// Responses are parsed on a reader thread so the network keeps flowing
    /// while the caller processes the previous one.
    rx: Option<std::sync::mpsc::Receiver<std::io::Result<Response>>>,
    reader: Option<std::thread::JoinHandle<()>>,
    label: String,
    dead: bool,
    peer: Option<PeerInfo>,
    tcp_socket: Option<TcpStream>,
    multiplexed_ssh: bool,
}

const READ_AHEAD: usize = 4;
const TRANSPORT_STATS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

fn spawn_reader(
    input: Box<dyn Read + Send>,
) -> (
    std::sync::mpsc::Receiver<std::io::Result<Response>>,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = std::sync::mpsc::sync_channel(READ_AHEAD);
    let reader = std::thread::spawn(move || {
        let mut r = FrameReader::new(input);
        loop {
            let msg = r.read_msg::<Response>();
            let failed = msg.is_err();
            if tx.send(msg).is_err() || failed {
                break;
            }
        }
    });
    (rx, reader)
}

fn receive_transport_stats(
    rx: &std::sync::mpsc::Receiver<std::io::Result<Response>>,
    timeout: std::time::Duration,
) -> Option<TcpSocketStats> {
    match rx.recv_timeout(timeout) {
        Ok(Ok(Response::TransportStats(stats))) => stats,
        _ => None,
    }
}

fn validate_remote_scan_batch(batch: &[Entry], saw_root: &mut bool) -> Result<()> {
    for entry in batch {
        if !*saw_root {
            if !entry.path.is_empty() {
                bail!("scan response did not begin with the root entry");
            }
            *saw_root = true;
            continue;
        }
        if entry.path.is_empty() {
            bail!("scan response contained the root entry more than once");
        }
        if entry.path.starts_with(b"/")
            || entry.path.contains(&0)
            || entry
                .path
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            bail!(
                "scan response contained unsafe relative path {:?}",
                String::from_utf8_lossy(&entry.path)
            );
        }
    }
    Ok(())
}

impl RemoteConn {
    fn transport_stats_with_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> Option<TcpPairStats> {
        let socket = self.tcp_socket.as_ref()?.try_clone().ok()?;
        let local = tcp_socket_stats(&socket);
        // Changing SO_RCVTIMEO cannot wake a reader already blocked on another
        // clone. Bound the actual response wait instead. This connection is
        // retired immediately after collection, so a late reply cannot become
        // a response to a later request.
        let peer = if self.dead || self.send(Request::TransportStats).is_err() {
            None
        } else {
            receive_transport_stats(self.rx.as_ref().expect("reader receiver present"), timeout)
        };
        (local.is_some() || peer.is_some()).then(|| TcpPairStats {
            label: self.label.clone(),
            local,
            peer,
        })
    }

    fn io_err(&mut self, e: anyhow::Error) -> anyhow::Error {
        self.dead = true;
        // If the child has exited (or does so shortly), that's the more useful error.
        if let Some(child) = &mut self.child {
            for _ in 0..20 {
                if let Ok(Some(status)) = child.try_wait() {
                    if self.multiplexed_ssh && status.code() == Some(255) {
                        return MultiplexedSshSessionError(format!(
                            "{}: multiplexed SSH session was rejected ({status})",
                            self.label
                        ))
                        .into();
                    }
                    return anyhow!("{}: remote syq exited ({status})", self.label);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        let msg = if e
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
        {
            "connection closed by remote".to_string()
        } else {
            format!("{e:#}")
        };
        anyhow!("{}: {msg}", self.label)
    }
}

impl Conn for RemoteConn {
    fn send(&mut self, req: Request) -> Result<()> {
        self.w.write_msg(&req).map_err(|e| self.io_err(e.into()))
    }
    fn recv(&mut self) -> Result<Response> {
        match self.rx.as_ref().expect("reader receiver present").recv() {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(self.io_err(e.into())),
            Err(_) => Err(self.io_err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "reader stopped").into(),
            )),
        }
    }
    fn is_dead(&self) -> bool {
        self.dead
    }
    fn tcp_rtt_us(&self) -> Option<u64> {
        self.tcp_socket
            .as_ref()
            .and_then(tcp_socket_stats)
            .and_then(|stats| stats.rtt_us)
    }
    fn transport_stats(&mut self) -> Option<TcpPairStats> {
        self.transport_stats_with_timeout(TRANSPORT_STATS_TIMEOUT)
    }
    fn scan(
        &mut self,
        root: &[u8],
        source: Option<&RegisteredPath>,
        follow_root: bool,
        ignore: &[String],
        report_ignored: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        self.send(Request::Scan {
            root: root.to_vec(),
            source: source.cloned(),
            follow_root,
            ignore: ignore.to_vec(),
            report_ignored,
            guard: None,
        })?;
        let mut saw_root = false;
        loop {
            match self.recv()? {
                Response::ScanBatch(b) => {
                    validate_remote_scan_batch(&b, &mut saw_root)
                        .with_context(|| format!("{}: unsafe remote scan", self.label))?;
                    sink(b)?;
                }
                Response::ScanIgnored(v) => ignored(v)?,
                Response::ScanWarn(w) => warn(w),
                Response::ScanDone if saw_root => return Ok(()),
                Response::ScanDone => bail!("{}: remote scan returned no root entry", self.label),
                Response::Err(e) => bail!("{}: scan: {e}", self.label),
                other => bail!("{}: unexpected response during scan: {other:?}", self.label),
            }
        }
    }

    fn native_remove(
        &mut self,
        cwd: Option<&[u8]>,
        root: Option<&[u8]>,
        selections: &[NativeRemoveSelection],
        follow_symlinks: bool,
        dry_run: bool,
        workers: usize,
        trace: &mut dyn FnMut(Vec<String>) -> Result<()>,
        sink: &mut dyn FnMut(Vec<NativeRemoveOutcome>) -> Result<()>,
    ) -> Result<()> {
        self.send(Request::NativeRemove {
            cwd: cwd.map(<[u8]>::to_vec),
            root: root.map(<[u8]>::to_vec),
            selections: selections.to_vec(),
            follow_symlinks,
            dry_run,
            workers,
        })?;
        loop {
            match self.recv()? {
                Response::NativeRemoveTrace(messages) => trace(messages)?,
                Response::NativeRemoveBatch(outcomes) => sink(outcomes)?,
                Response::NativeRemoveDone => return Ok(()),
                Response::Err(error) => bail!("{}: remove: {error}", self.label),
                other => bail!(
                    "{}: unexpected response during native removal: {other:?}",
                    self.label
                ),
            }
        }
    }
}

impl Drop for RemoteConn {
    fn drop(&mut self) {
        if !self.dead {
            let _ = self.w.write_msg(&Request::Shutdown);
        }
        // Sending Shutdown asks for an orderly peer exit; shutting down the
        // retained TCP descriptor also wakes our reader clone and the peer's
        // request reader if either side is wedged or the diagnostic reply
        // timed out. Drop the receiver before joining so a reader blocked on a
        // full response channel can exit as well.
        if let Some(socket) = &self.tcp_socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        self.rx.take();
        if let Some(child) = &mut self.child {
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// How many *data* ssh sessions may be establishing at once. Starts high:
/// on a server tuned for syq (`MaxStartups 100`) a burst of 32 handshakes
/// takes 14 s where four rounds of 8 would take 26. sshd's default
/// `MaxStartups 10:30:100` randomly drops new connections beyond 10
/// unauthenticated ones, so each failed connect halves the limit (down to
/// MIN_CONCURRENT_CONNECTS) for the rest of the run, and the retry then
/// succeeds. The control connection bypasses this entirely.
const START_CONCURRENT_CONNECTS: usize = 32;
const MIN_CONCURRENT_CONNECTS: usize = 4;
static CONNECT_LIMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(START_CONCURRENT_CONNECTS);
static CONNECTS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static CONNECTS_CV: std::sync::Condvar = std::sync::Condvar::new();

struct ConnectSlot;
fn connect_slot() -> ConnectSlot {
    let mut n = CONNECTS.lock().unwrap();
    while *n >= CONNECT_LIMIT.load(std::sync::atomic::Ordering::Relaxed) {
        n = CONNECTS_CV.wait(n).unwrap();
    }
    *n += 1;
    ConnectSlot
}

/// A data connect failed in a way that looks like the server shedding load:
/// halve how many we attempt at once. Returns the new limit.
fn tighten_connect_limit() -> usize {
    let _g = CONNECTS.lock().unwrap();
    let cur = CONNECT_LIMIT.load(std::sync::atomic::Ordering::Relaxed);
    let new = (cur / 2).max(MIN_CONCURRENT_CONNECTS);
    CONNECT_LIMIT.store(new, std::sync::atomic::Ordering::Relaxed);
    new
}
impl Drop for ConnectSlot {
    fn drop(&mut self) {
        *CONNECTS.lock().unwrap() -= 1;
        CONNECTS_CV.notify_one();
    }
}

pub const CIPHERS: &str = "Ciphers=aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataAddressSource {
    RemoteInterface,
    SshTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpCandidate {
    pub address: String,
    pub speed_mbps: u32,
    pub source: DataAddressSource,
    pub reachable: bool,
    pub selected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpProbe {
    pub port: u16,
    pub encrypted: bool,
    /// Effective algorithm read back from the remote listener, when exposed.
    pub congestion_control: Option<String>,
    pub candidates: Vec<TcpCandidate>,
}

/// TCP listener state whose route probes are running in the background.
///
/// The listener must be requested over the authenticated control connection,
/// but probing its advertised addresses does not use that connection. Keeping
/// the probe join handle here lets destination preflight cover the bounded
/// reachability window without weakening route selection.
pub(crate) struct PendingTcpSetup {
    port: u16,
    key: Option<Vec<u8>>,
    token: Vec<u8>,
    congestion_control: Option<String>,
    remote_congestion_control: Option<String>,
    probe: std::thread::JoinHandle<Vec<TcpCandidate>>,
}

#[derive(Clone, Debug, Default)]
pub struct RemoteDiagnostics {
    pub peer: Option<PeerInfo>,
    pub tcp_probe: Option<TcpProbe>,
    pub tcp_setup_error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataTransport {
    Ssh,
    EncryptedTcp,
    PlaintextTcp,
}

#[derive(Debug)]
pub(crate) struct SshMultiplexer {
    /// Owns the per-run private socket directory; None in persistent mode,
    /// where the socket lives in the shared per-user runtime directory and
    /// deliberately outlives this process.
    _directory: Option<tempfile::TempDir>,
    path: PathBuf,
    /// A managed persistence scope uses ControlMaster=auto with a
    /// ControlPersist window, so later syq runs in that scope skip the SSH
    /// handshake.
    persistent: bool,
    reuse_for_workers: AtomicBool,
}

/// How long a persistent control master lingers after its last client, in
/// seconds. Long enough for scripted bursts of runs; short enough that the
/// no-reauthentication window stays comparable to sudo's credential cache.
const REUSE_PERSIST_SECONDS: &str = "300";

impl SshMultiplexer {
    pub(crate) fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("syq-ssh-")
            .tempdir()
            .context("create private SSH control directory")?;
        let path = directory.path().join("socket");
        crate::persistence::validate_openssh_control_path(&path)?;
        Ok(Self {
            _directory: Some(directory),
            path,
            persistent: false,
            reuse_for_workers: AtomicBool::new(false),
        })
    }

    pub(crate) fn persistent(
        scope: &std::path::Path,
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> Result<Self> {
        let path = crate::persistence::prepare_endpoint(scope, user, host, port)?;
        Ok(Self {
            _directory: None,
            path,
            persistent: true,
            reuse_for_workers: AtomicBool::new(false),
        })
    }

    fn set_reuse_for_workers(&self, reuse: bool) {
        // A persistent master is shared across runs; worker data channels
        // must never ride it (MaxSessions contention, shared cipher stream).
        if self.persistent {
            return;
        }
        self.reuse_for_workers.store(reuse, Ordering::Relaxed);
    }

    fn reuse_for_workers(&self) -> bool {
        self.reuse_for_workers.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SshConnection {
    Independent,
    Control,
    Worker,
}

#[derive(Clone, Debug)]
pub struct RemoteSpec {
    /// Run the receiver helper as a local child. This gives local copies the
    /// same process-local cwd anchoring as an SSH receiver while its workers
    /// share one TCP listener instead of spawning one process each.
    pub local_process: bool,
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub rsh: Vec<String>,
    pub syq_path: Option<String>,
    /// Install and use the versioned helper rather than resolving `syq` on PATH.
    pub auto_helper: bool,
    /// One-time signed authorization for a command-restricted receiver. It is
    /// sent only on the SSH control connection; authenticated TCP workers are
    /// children of that already-authorized receiver.
    pub restricted_grant: Option<String>,
    /// Serializes a first-use install across control and worker clones.
    pub helper_install: std::sync::Arc<std::sync::Mutex<bool>>,
    /// A private OpenSSH control socket. The control session is always capable
    /// of multiplexing, but workers use it only after the completed plan shows
    /// that every payload is a fresh small file.
    pub(crate) ssh_multiplexer: Option<std::sync::Arc<SshMultiplexer>>,
    /// `-q`: suppress the "falling back to ssh" notice.
    pub quiet: bool,
    /// Shared across clones so workers see the TCP setup done on the control connection.
    pub tcp: std::sync::Arc<std::sync::Mutex<Option<TcpInfo>>>,
    /// User-facing facts gathered by the same connection path the transfer uses.
    pub diagnostics: std::sync::Arc<std::sync::Mutex<RemoteDiagnostics>>,
}

impl RemoteSpec {
    pub fn local_receiver(quiet: bool) -> Self {
        Self {
            local_process: true,
            user: None,
            host: "127.0.0.1".into(),
            port: None,
            rsh: vec!["local".into()],
            syq_path: None,
            auto_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet,
            tcp: Default::default(),
            diagnostics: Default::default(),
        }
    }

    pub fn label(&self) -> String {
        if self.local_process {
            return "local receiver".into();
        }
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let endpoint = match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        };
        match self.port {
            Some(port) => format!("{endpoint}:{port}"),
            None => endpoint,
        }
    }

    pub fn diagnostics(&self) -> RemoteDiagnostics {
        self.diagnostics.lock().unwrap().clone()
    }

    pub fn data_transport(&self) -> DataTransport {
        match self.tcp.lock().unwrap().as_ref() {
            Some(info) if !info.failed && info.key.is_some() => DataTransport::EncryptedTcp,
            Some(info) if !info.failed => DataTransport::PlaintextTcp,
            _ => DataTransport::Ssh,
        }
    }

    pub fn set_ssh_multiplexing(&self, reuse: bool) {
        if let Some(multiplexer) = &self.ssh_multiplexer {
            multiplexer.set_reuse_for_workers(reuse);
        }
    }

    pub fn remote_shell_name(&self) -> String {
        std::path::Path::new(&self.rsh[0])
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new(&self.rsh[0]))
            .to_string_lossy()
            .into_owned()
    }

    fn record_peer(&self, conn: &RemoteConn) {
        if let Some(peer) = &conn.peer {
            self.diagnostics.lock().unwrap().peer = Some(peer.clone());
        }
    }

    fn ssh_command(&self, connection: SshConnection) -> Command {
        let mut cmd = Command::new(&self.rsh[0]);
        cmd.args(&self.rsh[1..]);
        if self.rsh[0].ends_with("ssh") {
            let multiplex = match (connection, &self.ssh_multiplexer) {
                (SshConnection::Control, Some(multiplexer)) => Some((multiplexer, true)),
                (SshConnection::Worker, Some(multiplexer)) => Some((multiplexer, false)),
                _ => None,
            };
            if let Some((multiplexer, master)) = multiplex {
                if master && multiplexer.persistent {
                    // Reuse across runs: become the master only if no live
                    // one exists, and linger after this run so the next one
                    // skips the handshake.
                    cmd.arg("-o")
                        .arg("ControlMaster=auto")
                        .arg("-S")
                        .arg(crate::persistence::openssh_control_path(&multiplexer.path))
                        .arg("-o")
                        .arg(format!("ControlPersist={REUSE_PERSIST_SECONDS}"));
                } else {
                    if master {
                        // A failed control command can leave its socket briefly
                        // behind while OpenSSH exits. This path is private to this
                        // transfer, so clearing that stale inode before a retry is
                        // safe and prevents the next master from refusing it.
                        let _ = std::fs::remove_file(&multiplexer.path);
                    }
                    cmd.arg("-o")
                        .arg(format!(
                            "ControlMaster={}",
                            if master { "yes" } else { "no" }
                        ))
                        .arg("-S")
                        .arg(crate::persistence::openssh_control_path(&multiplexer.path))
                        .arg("-o")
                        .arg("ControlPersist=no");
                }
            } else {
                // Large-file data connections need independent TCP streams and
                // cipher processes. Custom remote-shell commands also keep
                // their existing policy.
                cmd.args(["-o", "ControlMaster=no", "-o", "ControlPath=none"]);
            }
            // AES-GCM is much faster than OpenSSH's default chacha20 on CPUs
            // with AES-NI. The list still includes the defaults so negotiation
            // never fails.
            cmd.args(["-o", CIPHERS]);
            if let Some(u) = &self.user {
                cmd.args(["-l", u]);
            }
            if let Some(port) = self.port {
                cmd.args(["-p", &port.to_string()]);
            }
            cmd.arg("--");
        } else if let Some(u) = &self.user {
            cmd.args(["-l", u]);
        }
        cmd.arg(&self.host);
        cmd
    }

    fn ssh_connection(&self, limited: bool) -> SshConnection {
        if !limited {
            SshConnection::Control
        } else if self
            .ssh_multiplexer
            .as_ref()
            .is_some_and(|multiplexer| multiplexer.reuse_for_workers())
        {
            SshConnection::Worker
        } else {
            SshConnection::Independent
        }
    }

    /// A shell command that runs syq with `args` on this host.  Automatic mode
    /// addresses the exact release/build-identified helper; explicit mode preserves the
    /// administrator-provided path; disabling bootstrap uses normal PATH lookup.
    pub fn program_command(&self, args: &[String]) -> String {
        if let Some(p) = &self.syq_path {
            return format!("{} {}", shell_words::quote(p), shell_words::join(args));
        }
        if self.auto_helper {
            return remote_helper::launcher(args);
        }
        format!("syq {}", shell_words::join(args))
    }

    /// `limited`: take a connect slot (data connections). The control
    /// connection passes false: everything waits on it, so it must never
    /// queue behind workers. In managed mode the release helper is installed
    /// on first use if the remote lacks it.
    pub fn connect_with(&self, compress: bool, limited: bool) -> Result<RemoteConn> {
        let role = if limited {
            ConnectionRole::SourceWorker { roots: Vec::new() }
        } else {
            ConnectionRole::Control
        };
        self.connect_with_role(compress, limited, role)
    }

    fn connect_with_role(
        &self,
        compress: bool,
        limited: bool,
        role: ConnectionRole,
    ) -> Result<RemoteConn> {
        let first = self.connect_retried(compress, limited, role.clone());
        let Err(first_error) = first else {
            return first;
        };
        if !self.auto_helper || !helper_needs_install(&first_error) {
            return Err(first_error);
        }

        self.install_helper()?;
        self.connect_retried(compress, limited, role)
            .with_context(|| {
                format!(
                    "could not start the {} helper installed on {}",
                    remote_helper::helper_identity(),
                    self.label()
                )
            })
    }

    fn connect_retried(
        &self,
        compress: bool,
        limited: bool,
        role: ConnectionRole,
    ) -> Result<RemoteConn> {
        let mut delay = std::time::Duration::from_millis(200);
        let mut last = None;
        for attempt in 0..6 {
            let _slot = limited.then(connect_slot);
            let ssh_connection = self.ssh_connection(limited);
            match self.connect_once(compress, ssh_connection, role.clone()) {
                Ok(c) => return Ok(c),
                Err(e)
                    if ssh_connection == SshConnection::Worker
                        && is_multiplexed_ssh_session_error(&e) =>
                {
                    // MaxSessions can reject a new channel on an otherwise
                    // healthy control connection while still allowing a new
                    // independently authenticated SSH connection. Disable
                    // reuse for every later worker and retry immediately.
                    self.set_ssh_multiplexing(false);
                    if crate::transfer::debug() {
                        eprintln!(
                            "syq: {}: multiplexed SSH worker rejected; using independent SSH connections",
                            self.label()
                        );
                    }
                    last = Some(e);
                    continue;
                }
                // Don't retry what won't change: a missing binary (127) or a
                // build identity mismatch.
                Err(e)
                    if attempt == 5
                        || format!("{e:#}").contains("build identity mismatch")
                        || is_worker_initialization_error(&e)
                        || format!("{e:#}").contains("exit status: 127")
                        || format!("{e:#}").contains(&format!(
                            "exit status: {}",
                            remote_helper::HELPER_MISSING_EXIT
                        ))
                        || format!("{e:#}").contains(&format!(
                            "exit status: {}",
                            remote_helper::HELPER_NOT_EXECUTABLE_EXIT
                        )) =>
                {
                    return Err(e)
                }
                Err(e) => {
                    let limit = if limited {
                        Some(tighten_connect_limit())
                    } else {
                        None
                    };
                    if crate::transfer::debug() {
                        eprintln!(
                            "syq: connect to {} failed (attempt {}): {e:#}{}",
                            self.label(),
                            attempt + 1,
                            limit
                                .map(|l| format!("; now at most {l} connects at once"))
                                .unwrap_or_default()
                        );
                    }
                    last = Some(e);
                    std::thread::sleep(delay);
                    delay *= 2;
                }
            }
        }
        Err(last.unwrap())
    }

    fn connect_once(
        &self,
        compress: bool,
        ssh_connection: SshConnection,
        role: ConnectionRole,
    ) -> Result<RemoteConn> {
        let mut server_args = vec!["--server".into()];
        if let Some(grant) = &self.restricted_grant {
            server_args.push(format!("--restricted-grant={grant}"));
        }
        let mut cmd = if self.local_process {
            let mut command = Command::new(std::env::current_exe()?);
            command.args(&server_args);
            command
        } else {
            let mut command = self.ssh_command(ssh_connection);
            let remote_command = if self.restricted_grant.is_some() {
                // This text is inspected by the forced receiver through
                // SSH_ORIGINAL_COMMAND; sshd replaces the requested executable.
                format!("syq {}", shell_words::join(&server_args))
            } else {
                self.program_command(&server_args)
            };
            command.arg(remote_command);
            command
        };
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().with_context(|| {
            if self.local_process {
                "spawn local receiver".to_string()
            } else {
                format!("spawn {:?}", self.rsh[0])
            }
        })?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (rx, reader) = spawn_reader(Box::new(stdout));
        let conn = RemoteConn {
            child: Some(child),
            w: FrameWriter::new(Box::new(stdin), compress),
            rx: Some(rx),
            reader: Some(reader),
            label: self.label(),
            dead: false,
            peer: None,
            tcp_socket: None,
            multiplexed_ssh: ssh_connection == SshConnection::Worker,
        };
        let conn = hello(conn, compress, Vec::new(), role)?;
        self.record_peer(&conn);
        Ok(conn)
    }

    /// Ask the remote (over the control connection) to accept TCP data
    /// connections, then begin probing the advertised routes in the
    /// background. The caller must finish the setup before opening workers.
    pub(crate) fn begin_tcp_setup(
        &self,
        ctl: &mut dyn Conn,
        plain: bool,
        ports: (u16, u16),
        congestion_control: Option<&str>,
    ) -> Result<PendingTcpSetup> {
        *self.tcp.lock().unwrap() = None;
        {
            let mut diagnostics = self.diagnostics.lock().unwrap();
            diagnostics.tcp_probe = None;
            diagnostics.tcp_setup_error = None;
        }
        let result = self.begin_tcp_setup_inner(ctl, plain, ports, congestion_control);
        if let Err(error) = &result {
            self.diagnostics.lock().unwrap().tcp_setup_error = Some(format!("{error:#}"));
        }
        result
    }

    /// Join background route probes and record the selected TCP data paths.
    pub(crate) fn finish_tcp_setup(&self, pending: PendingTcpSetup) -> Result<()> {
        let result = self.finish_tcp_setup_inner(pending);
        if let Err(error) = &result {
            self.diagnostics.lock().unwrap().tcp_setup_error = Some(format!("{error:#}"));
        }
        result
    }

    fn begin_tcp_setup_inner(
        &self,
        ctl: &mut dyn Conn,
        plain: bool,
        ports: (u16, u16),
        congestion_control: Option<&str>,
    ) -> Result<PendingTcpSetup> {
        let key = if plain {
            None
        } else {
            Some(crate::crypto::random_bytes(crate::crypto::KEY_LEN))
        };
        let token = crate::crypto::random_bytes(16);
        let resp = ctl.call(Request::TcpListen {
            key: key.clone(),
            token: token.clone(),
            port_lo: ports.0,
            port_hi: ports.1,
            congestion_control: congestion_control.map(str::to_owned),
        })?;
        let (port, advertised, remote_congestion_control) = match resp {
            Response::TcpCongestionRejected(error) => return Err(TcpCongestionError(error).into()),
            response => match ok(response, "tcp listen")? {
                Response::TcpListening {
                    port,
                    addrs,
                    congestion_control,
                } => (port, addrs, congestion_control),
                other => bail!("unexpected response {other:?}"),
            },
        };
        let mut candidates: Vec<TcpCandidate> = advertised
            .into_iter()
            .map(|(address, speed_mbps)| TcpCandidate {
                address,
                speed_mbps,
                source: DataAddressSource::RemoteInterface,
                reachable: false,
                selected: false,
            })
            .collect();
        // Always also try the name we reached ssh through: a server behind
        // NAT / port forwarding advertises only its private addresses, which
        // are unreachable from outside, while its public address is exactly
        // what we connected to. It goes after the LAN / fast-NIC addresses
        // (better when reachable) but before CGNAT / Tailscale ones, which
        // are overlay paths and must not win over the direct public address.
        if let Some(h) = self.resolved_hostname() {
            if !candidates.iter().any(|candidate| candidate.address == h) {
                let at = candidates
                    .iter()
                    .position(|candidate| candidate.address.starts_with("100."))
                    .unwrap_or(candidates.len());
                candidates.insert(
                    at,
                    TcpCandidate {
                        address: h,
                        speed_mbps: 0,
                        source: DataAddressSource::SshTarget,
                        reachable: false,
                        selected: false,
                    },
                );
            }
        }
        // Probing is independent of the authenticated control stream. Let the
        // orchestrator do destination preflight and plan payloads while every
        // candidate receives its complete bounded probe window.
        let probe = std::thread::spawn(move || {
            probe_reachable(&mut candidates, port);
            candidates
        });
        Ok(PendingTcpSetup {
            port,
            key,
            token,
            congestion_control: congestion_control.map(str::to_owned),
            remote_congestion_control,
            probe,
        })
    }

    fn finish_tcp_setup_inner(&self, pending: PendingTcpSetup) -> Result<()> {
        let PendingTcpSetup {
            port,
            key,
            token,
            congestion_control,
            remote_congestion_control,
            probe,
        } = pending;
        let mut candidates = probe
            .join()
            .map_err(|_| anyhow!("TCP route probe thread panicked"))?;
        // Multipath only across comparable-speed NICs: keep those within 2x of
        // the fastest reachable one. Mixing a fast and a slow path (a rail and
        // Tailscale, say) would drag the transfer down, so we don't.
        let fastest = candidates
            .iter()
            .filter(|candidate| candidate.reachable)
            .map(|candidate| candidate.speed_mbps)
            .max()
            .unwrap_or(0);
        let mut selected_unknown = false;
        for candidate in &mut candidates {
            candidate.selected = candidate.reachable
                && if fastest > 0 {
                    candidate.speed_mbps.saturating_mul(2) >= fastest
                } else if selected_unknown {
                    false
                } else {
                    selected_unknown = true;
                    true
                };
        }
        self.diagnostics.lock().unwrap().tcp_probe = Some(TcpProbe {
            port,
            encrypted: key.is_some(),
            congestion_control: remote_congestion_control,
            candidates: candidates.clone(),
        });
        let addrs: Vec<String> = candidates
            .iter()
            .filter(|candidate| candidate.selected)
            .map(|candidate| candidate.address.clone())
            .collect();
        if addrs.is_empty() {
            bail!("no advertised data address is reachable");
        }
        if crate::transfer::debug() {
            eprintln!(
                "syq: {}: data paths {:?} (advertised {:?})",
                self.label(),
                addrs,
                candidates
            );
        }
        *self.tcp.lock().unwrap() = Some(TcpInfo {
            addrs,
            port,
            key,
            token,
            congestion_control,
            failed: false,
            failure: None,
            next: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
        Ok(())
    }

    /// The real host name behind an ssh config alias.
    fn resolved_hostname(&self) -> Option<String> {
        if !self.rsh[0].ends_with("ssh") {
            return Some(self.host.clone());
        }
        let out = Command::new(&self.rsh[0])
            .args(&self.rsh[1..])
            .arg("-G")
            .args(
                self.port
                    .map(|port| vec!["-p".to_owned(), port.to_string()])
                    .unwrap_or_default(),
            )
            .arg("--")
            .arg(&self.host)
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .find_map(|l| l.strip_prefix("hostname "))
            .map(|h| h.trim().to_string())
            .or_else(|| Some(self.host.clone()))
    }

    /// Open one data connection, spreading successive connections across the
    /// reachable data addresses (multipath). Addresses were already probed and
    /// speed-filtered in setup_tcp, so we just round-robin and fall through on
    /// the rare transient failure.
    fn connect_tcp(
        &self,
        info: &TcpInfo,
        compress: bool,
        role: ConnectionRole,
    ) -> Result<RemoteConn> {
        let n = info.addrs.len();
        let start = info.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % n;
        let mut last = anyhow!("no data address");
        for k in 0..n {
            let addr = &info.addrs[(start + k) % n];
            let resolved: Vec<_> = match (addr.as_str(), info.port).to_socket_addrs() {
                Ok(it) => it.collect(),
                Err(_) => {
                    last = anyhow!("cannot resolve {addr}");
                    continue;
                }
            };
            // Try each resolved address in turn (dual-stack names may list an
            // unreachable family first).
            let mut got = None;
            for sa in &resolved {
                match connect_tcp_stream(
                    sa,
                    std::time::Duration::from_secs(4),
                    info.congestion_control.as_deref(),
                ) {
                    Ok(s) => {
                        got = Some(s);
                        break;
                    }
                    Err(error) if is_tcp_congestion_error(&error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "local/orchestrating host could not configure the connecting data socket to {}",
                                self.label()
                            )
                        })
                    }
                    Err(e) => last = anyhow!("{addr}:{}: {e}", info.port),
                }
            }
            let stream = match got {
                Some(s) => s,
                None => continue,
            };
            let addr_s = stream
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_default();
            if crate::transfer::debug() {
                eprintln!("syq: {}: data connection via tcp {addr_s}", self.label());
            }
            stream.set_nodelay(true)?;
            let conn_id = TCP_CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            (&stream).write_all(&conn_id.to_be_bytes())?;
            let (wc, rc) = match &info.key {
                Some(k) => (
                    Some(Cipher::new(k, conn_id, 1)),
                    Some(Cipher::new(k, conn_id, 2)),
                ),
                None => (None, None),
            };
            let writer = RecordWriter::new(stream.try_clone()?, wc);
            let tcp_socket = stream.try_clone()?;
            let reader = RecordReader::new(stream, rc);
            let (rx, reader) = spawn_reader(Box::new(reader));
            let conn = RemoteConn {
                child: None,
                w: FrameWriter::new(Box::new(writer), compress),
                rx: Some(rx),
                reader: Some(reader),
                label: format!("{} (tcp {addr_s})", self.label()),
                dead: false,
                peer: None,
                tcp_socket: Some(tcp_socket),
                multiplexed_ssh: false,
            };
            let conn = hello(conn, compress, info.token.clone(), role.clone())?;
            self.record_peer(&conn);
            return Ok(conn);
        }
        Err(last)
    }
}

fn helper_needs_install(e: &anyhow::Error) -> bool {
    let message = format!("{e:#}");
    message.contains(&format!(
        "exit status: {}",
        remote_helper::HELPER_MISSING_EXIT
    )) || message.contains(&format!(
        "exit status: {}",
        remote_helper::HELPER_NOT_EXECUTABLE_EXIT
    )) || message.contains("build identity mismatch")
}

/// Concurrently probe which (addr, speed) entries accept a TCP connection on
/// `port`, preserving the server's priority order. Used once per endpoint.
fn probe_reachable(candidates: &mut [TcpCandidate], port: u16) {
    // Resolve candidate names in parallel. More importantly, probe every
    // resolved socket address in parallel too: a dual-stack name must not
    // spend the whole candidate budget timing out on IPv6 before trying IPv4.
    let (resolved_tx, resolved_rx) = std::sync::mpsc::channel();
    for (i, candidate) in candidates.iter().enumerate() {
        let tx = resolved_tx.clone();
        let address = candidate.address.clone();
        std::thread::spawn(move || {
            let addrs = (address.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect())
                .unwrap_or_default();
            let _ = tx.send((i, addrs));
        });
    }
    drop(resolved_tx);
    let mut resolved = vec![Vec::new(); candidates.len()];
    for _ in 0..candidates.len() {
        let Ok((i, addrs)) = resolved_rx.recv() else {
            break;
        };
        resolved[i] = addrs;
    }

    let timeout = std::time::Duration::from_millis(1000);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut remaining: Vec<usize> = resolved.iter().map(Vec::len).collect();
    let mut undetermined = remaining.iter().filter(|&&count| count > 0).count();
    let mut determined = vec![false; candidates.len()];
    for (i, addrs) in resolved.into_iter().enumerate() {
        for addr in addrs {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = tx.send((i, TcpStream::connect_timeout(&addr, timeout).is_ok()));
            });
        }
    }
    drop(tx);

    // Every path gets its complete bounded probe window. Do not cut off a
    // higher-bandwidth path merely because the public SSH fallback connected
    // first; a higher-latency rail may still be the better transfer path.
    let deadline = std::time::Instant::now() + timeout + std::time::Duration::from_millis(100);
    while undetermined > 0 {
        let Some(wait) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        let Ok((i, reachable)) = rx.recv_timeout(wait) else {
            break;
        };
        if determined[i] {
            continue;
        }
        remaining[i] -= 1;
        if reachable || remaining[i] == 0 {
            candidates[i].reachable = reachable;
            determined[i] = true;
            undetermined -= 1;
        }
    }
}

static TCP_CONN_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

#[derive(Clone)]
pub struct TcpInfo {
    /// Reachable, speed-filtered data addresses to spread connections across.
    pub addrs: Vec<String>,
    pub port: u16,
    pub key: Option<Vec<u8>>,
    pub token: Vec<u8>,
    /// Explicit algorithm requested for each outgoing data socket. None keeps
    /// the host default.
    pub congestion_control: Option<String>,
    /// Set once a connect attempt failed; later connections use ssh.
    pub failed: bool,
    pub failure: Option<String>,
    /// Round-robin cursor so successive data connections use different addresses.
    pub next: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl std::fmt::Debug for TcpInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpInfo")
            .field("addrs", &self.addrs)
            .field("port", &self.port)
            .field("failed", &self.failed)
            .finish()
    }
}

fn hello(
    mut conn: RemoteConn,
    compress: bool,
    token: Vec<u8>,
    role: ConnectionRole,
) -> Result<RemoteConn> {
    let worker = !matches!(role, ConnectionRole::Control);
    conn.send(Request::Hello {
        identity: crate::identity::build().to_string(),
        compress,
        debug: crate::transfer::debug(),
        token,
        role,
    })?;
    match conn.recv() {
        Ok(Response::HelloOk { identity, platform }) if identity == crate::identity::build() => {
            conn.peer = Some(PeerInfo { identity, platform });
        }
        Ok(Response::HelloOk { identity, .. }) => {
            bail!(
                "{}: build identity mismatch (remote {identity}, local {})",
                conn.label,
                crate::identity::build()
            )
        }
        Ok(Response::Err(error)) if worker => {
            return Err(WorkerInitializationError(format!("{}: {error}", conn.label)).into())
        }
        Ok(Response::Err(error)) => bail!("{}: {error}", conn.label),
        Ok(other) if worker => {
            return Err(WorkerInitializationError(format!(
                "{}: unexpected handshake response {other:?}",
                conn.label
            ))
            .into())
        }
        Ok(other) => bail!("{}: unexpected handshake response {other:?}", conn.label),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("could not start the remote syq on {}", conn.label))
        }
    }
    Ok(conn)
}

impl RemoteSpec {
    /// Ensure the exact release helper exists in the remote cache.
    /// Only authorized release assets may populate the managed helper cache.
    pub fn install_helper(&self) -> Result<()> {
        crate::identity::require_release_build()?;
        let mut installed = self.helper_install.lock().unwrap();
        if *installed {
            return Ok(());
        }

        let bootstrap = self.remote_bootstrap()?;
        let target = bootstrap.target;
        if !self.quiet {
            eprintln!(
                "syq: {}: installing {} helper for {}",
                self.label(),
                remote_helper::helper_identity(),
                target.key
            );
        }
        self.bootstrap_helper(bootstrap).with_context(|| {
            format!(
                "could not install the authorized {} helper on {} ({})",
                remote_helper::helper_identity(),
                self.label(),
                target.key
            )
        })?;
        *installed = true;
        Ok(())
    }

    fn remote_bootstrap(&self) -> Result<RemoteBootstrap> {
        let mut cmd = self.ssh_command(SshConnection::Independent);
        cmd.arg(remote_helper::probe_command())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = cmd
            .output()
            .with_context(|| format!("probe platform on {}", self.label()))?;
        if !out.status.success() {
            bail!(
                "could not detect the platform on {} ({}){}",
                self.label(),
                out.status,
                output_suffix(&out.stderr)
            );
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix("syq-helper-target:"))
            .ok_or_else(|| anyhow!("{}: platform probe returned no target", self.label()))?;
        let (os, arch) = value
            .split_once(':')
            .ok_or_else(|| anyhow!("{}: malformed platform response {value:?}", self.label()))?;
        let target = Target::from_uname(os, arch).ok_or_else(|| {
            anyhow!(
                "{}: automatic remote helpers do not support {os} {arch}",
                self.label()
            )
        })?;
        let direct_download = text
            .lines()
            .find_map(|line| line.strip_prefix("syq-helper-tools:"))
            .is_some_and(|tools| {
                let mut tools = tools.split(':');
                tools.next().is_some_and(|tool| !tool.is_empty())
                    && tools.next().is_some_and(|tool| !tool.is_empty())
                    && tools.next().is_some_and(|tool| !tool.is_empty())
                    && tools.next().is_none()
            });
        Ok(RemoteBootstrap {
            target,
            direct_download,
        })
    }

    fn bootstrap_helper(&self, bootstrap: RemoteBootstrap) -> Result<()> {
        let mut trusted = None;
        if bootstrap.direct_download {
            match self.try_direct_helper(bootstrap.target)? {
                DirectHelper::Installed => return Ok(()),
                DirectHelper::Fallback { detail, helper } => {
                    trusted = helper;
                    if !self.quiet {
                        eprintln!(
                            "syq: {}: remote download unavailable{}; uploading the verified helper over SSH",
                            self.label(),
                            parenthesized_detail(&detail)
                        );
                    }
                }
                DirectHelper::Integrity { warning, helper } => {
                    trusted = helper;
                    eprintln!(
                        "syq: warning: {}: {}; the remote download was discarded; uploading the verified helper over SSH",
                        self.label(),
                        warning
                    );
                }
            }
        } else if !self.quiet {
            eprintln!(
                "syq: {}: remote download prerequisites unavailable; uploading the verified helper over SSH",
                self.label()
            );
        }

        let helper = match trusted {
            Some(helper) => helper,
            None => crate::update::trusted_current_helper(bootstrap.target)
                .context("download and verify the signed release manifest")?,
        };
        let binary = crate::update::verified_current_helper(&helper)
            .context("download and verify the helper for SSH upload")?;
        self.upload_helper(bootstrap.target, &binary)
    }

    fn try_direct_helper(&self, target: Target) -> Result<DirectHelper> {
        let script = remote_helper::download_script(target);
        let mut cmd = self.ssh_command(SshConnection::Independent);
        cmd.arg(format!("sh -c {}", shell_words::quote(&script)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("start helper download on {}", self.label()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("remote helper download stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("remote helper download stdout was not piped"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("remote helper download stderr was not piped"))?;
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        });

        let report = read_direct_report(&mut BufReader::new(stdout));
        let mut helper = None;
        let mut integrity_warning = None;
        let mut protocol_detail = None;
        let mut authorized = false;
        match report {
            Ok(Some(report)) if valid_sha256(&report.sha256) => {
                match crate::update::trusted_current_helper_from_manifest(target, &report.manifest)
                {
                    Ok(trusted) => {
                        if report.sha256 == trusted.archive_sha256() {
                            authorized = true;
                        } else {
                            integrity_warning = Some(format!(
                                "remote helper download failed integrity verification (expected SHA-256 {}, got {})",
                                trusted.archive_sha256(),
                                report.sha256
                            ));
                        }
                        helper = Some(trusted);
                    }
                    Err(error) => {
                        integrity_warning = Some(format!(
                            "remote release manifest failed integrity verification or validation ({error})"
                        ));
                    }
                }
            }
            Ok(Some(_)) => {
                protocol_detail = Some("the remote hasher returned no valid digest".into());
            }
            Ok(None) => {
                protocol_detail =
                    Some("the remote returned no download verification report".into());
            }
            Err(error) => {
                protocol_detail = Some(format!(
                    "could not read the remote verification report: {error}"
                ));
            }
        }
        let decision = if authorized {
            b"install\n"
        } else {
            b"discard\n"
        };
        let write_result = stdin.write_all(decision);
        drop(stdin);

        let status = child
            .wait()
            .with_context(|| format!("wait for helper download on {}", self.label()))?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow!("remote helper stderr reader panicked"))?;
        let detail = output_message(&stderr);
        if status.success() {
            write_result.context("authorize the verified remote helper")?;
            return if authorized {
                Ok(DirectHelper::Installed)
            } else {
                Ok(DirectHelper::Fallback {
                    detail: protocol_detail
                        .unwrap_or_else(|| "the remote ignored a discard decision".into()),
                    helper,
                })
            };
        }
        match status.code() {
            Some(remote_helper::DIRECT_FALLBACK_EXIT) => Ok(DirectHelper::Fallback {
                detail: if detail.is_empty() {
                    protocol_detail.unwrap_or_default()
                } else {
                    detail
                },
                helper,
            }),
            Some(remote_helper::DIRECT_INTEGRITY_EXIT) => match integrity_warning {
                Some(warning) => Ok(DirectHelper::Integrity { warning, helper }),
                None => Ok(DirectHelper::Fallback {
                    detail: protocol_detail.unwrap_or(detail),
                    helper,
                }),
            },
            _ => {
                bail!(
                    "remote download exited {}{}",
                    status,
                    output_suffix(&stderr)
                );
            }
        }
    }

    fn upload_helper(&self, target: Target, binary: &[u8]) -> Result<()> {
        let script = remote_helper::upload_script(target);
        let mut cmd = self.ssh_command(SshConnection::Independent);
        cmd.arg(format!("sh -c {}", shell_words::quote(&script)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("start helper upload to {}", self.label()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("helper upload stdin was not piped"))?;
        let write_result = stdin.write_all(binary);
        drop(stdin);
        let out = child
            .wait_with_output()
            .with_context(|| format!("wait for helper upload to {}", self.label()))?;
        if !out.status.success() {
            bail!(
                "remote helper upload exited {}{}",
                out.status,
                output_suffix(&out.stderr)
            );
        }
        write_result.with_context(|| format!("upload helper to {}", self.label()))
    }
}

#[derive(Clone, Copy)]
struct RemoteBootstrap {
    target: Target,
    direct_download: bool,
}

enum DirectHelper {
    Installed,
    Fallback {
        detail: String,
        helper: Option<crate::update::TrustedCurrentHelper>,
    },
    Integrity {
        warning: String,
        helper: Option<crate::update::TrustedCurrentHelper>,
    },
}

#[derive(Debug)]
struct DirectReport {
    manifest: Vec<u8>,
    sha256: String,
}

fn read_direct_report(reader: &mut impl BufRead) -> std::io::Result<Option<DirectReport>> {
    const MAX_MANIFEST_SIZE: usize = 1024 * 1024;
    let mut line = Vec::new();
    if reader.read_until(b'\n', &mut line)? == 0 {
        return Ok(None);
    }
    if protocol_line(&line) != b"syq-helper-manifest-begin" {
        return Ok(None);
    }

    let mut manifest = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "remote manifest was not terminated",
            ));
        }
        let framed = protocol_line(&line);
        if framed == b"syq-helper-manifest-end" {
            break;
        }
        let data = framed
            .strip_prefix(b"syq-helper-manifest-data:")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "remote manifest contained unframed protocol data",
                )
            })?;
        if manifest.len().saturating_add(data.len() + 1) > MAX_MANIFEST_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "remote manifest exceeded 1 MiB",
            ));
        }
        manifest.extend_from_slice(data);
        manifest.push(b'\n');
    }

    line.clear();
    if reader.read_until(b'\n', &mut line)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "remote helper digest was missing",
        ));
    }
    let digest = protocol_line(&line)
        .strip_prefix(b"syq-helper-sha256:")
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "remote helper digest marker was missing",
            )
        })?;
    let sha256 = String::from_utf8_lossy(digest).into_owned();
    line.clear();
    if reader.read_until(b'\n', &mut line)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "remote helper report was not terminated",
        ));
    }
    if protocol_line(&line) != b"syq-helper-report-end" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "remote helper report contained trailing or malformed protocol data",
        ));
    }
    Ok(Some(DirectReport { manifest, sha256 }))
}

fn protocol_line(mut line: &[u8]) -> &[u8] {
    if let Some(value) = line.strip_suffix(b"\n") {
        line = value;
    }
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn output_suffix(stderr: &[u8]) -> String {
    let message = output_message(stderr);
    if message.is_empty() {
        String::new()
    } else {
        format!(": {message}")
    }
}

fn output_message(stderr: &[u8]) -> String {
    let message = String::from_utf8_lossy(stderr);
    message
        .trim()
        .strip_prefix("syq: ")
        .unwrap_or_else(|| message.trim())
        .to_owned()
}

fn parenthesized_detail(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(" ({detail})")
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone)]
pub(crate) enum Endpoint {
    Local {
        descriptor_session: crate::descriptor_broker::DescriptorSessionSlot,
    },
    Remote(RemoteSpec),
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Local { .. } => formatter.write_str("Local"),
            Endpoint::Remote(spec) => formatter.debug_tuple("Remote").field(spec).finish(),
        }
    }
}

impl Endpoint {
    pub(crate) fn local() -> Self {
        Self::Local {
            descriptor_session: Default::default(),
        }
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, Endpoint::Remote(spec) if !spec.local_process)
    }

    pub fn has_data_server(&self) -> bool {
        matches!(self, Endpoint::Remote(_))
    }

    pub(crate) fn connect_control(&self, compress: bool) -> Result<Box<dyn Conn>> {
        self.connect_with_role(compress, ConnectionRole::Control)
    }

    pub(crate) fn connect_with_sources(
        &self,
        compress: bool,
        roots: Vec<RegisteredSourceRoot>,
    ) -> Result<Box<dyn Conn>> {
        self.connect_with_role(compress, ConnectionRole::SourceWorker { roots })
    }

    pub(crate) fn connect_with_destination(
        &self,
        compress: bool,
        destination: Option<DestinationRoot>,
    ) -> Result<Box<dyn Conn>> {
        self.connect_with_role(compress, ConnectionRole::DestinationWorker { destination })
    }

    fn connect_with_role(&self, compress: bool, role: ConnectionRole) -> Result<Box<dyn Conn>> {
        match self {
            Endpoint::Local { descriptor_session } => {
                // Every connection clone for this logical local endpoint uses
                // the control connection's process-local session slot. Once
                // the control registers roots, workers clone those retained
                // descriptors in process instead of claiming SCM_RIGHTS from
                // the broker after worker threads exist (unsupported on
                // Darwin).
                let mut conn = LocalConn::new(
                    matches!(&role, ConnectionRole::Control),
                    descriptor_session.clone(),
                );
                match role {
                    ConnectionRole::DestinationWorker {
                        destination: Some(destination),
                    } => conn
                        .ops
                        .initialize_destination(&destination)
                        .map_err(|error| {
                            WorkerInitializationError(format!(
                                "initialize local destination worker: {error:#}"
                            ))
                        })?,
                    ConnectionRole::DestinationWorker { destination: None } => {
                        return Err(WorkerInitializationError(
                            "local destination worker requires a registered root".into(),
                        )
                        .into())
                    }
                    ConnectionRole::SourceWorker { roots } => {
                        conn.ops.initialize_sources(&roots).map_err(|error| {
                            WorkerInitializationError(format!(
                                "initialize local source worker: {error:#}"
                            ))
                        })?
                    }
                    ConnectionRole::Control => {}
                }
                Ok(Box::new(conn))
            }
            Endpoint::Remote(spec) => {
                let info = spec.tcp.lock().unwrap().clone();
                if let Some(info) = info.filter(|i| !i.failed) {
                    match spec.connect_tcp(&info, compress, role.clone()) {
                        Ok(c) => return Ok(Box::new(c)),
                        Err(e)
                            if is_tcp_congestion_error(&e)
                                || is_worker_initialization_error(&e) =>
                        {
                            return Err(e)
                        }
                        Err(e) => {
                            if spec.restricted_grant.is_some() {
                                return Err(e).with_context(|| {
                                    format!(
                                        "{}: signed receiver TCP data connection failed; its one-time SSH grant cannot be replayed as a fallback",
                                        spec.label()
                                    )
                                });
                            }
                            let mut g = spec.tcp.lock().unwrap();
                            if let Some(i) = g.as_mut() {
                                if !i.failed {
                                    i.failed = true;
                                    i.failure = Some(format!("{e:#}"));
                                    if !spec.quiet || crate::transfer::debug() {
                                        let congestion_note = tcp_congestion_fallback_note(
                                            info.congestion_control.as_deref(),
                                        );
                                        eprintln!("syq: {}: data over ssh (TCP port {} stopped answering: {e:#}{congestion_note})", spec.label(), info.port);
                                    }
                                }
                            }
                        }
                    }
                }
                if spec.restricted_grant.is_some() {
                    bail!(
                        "{}: signed receiver has no authorized TCP data connection",
                        spec.label()
                    );
                }
                Ok(Box::new(spec.connect_with_role(compress, true, role)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    struct ExitObserved<R> {
        inner: R,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[test]
    fn local_workers_clone_the_control_descriptor_session_in_process() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        let endpoint = Endpoint::local();
        let mut control = endpoint.connect_control(false).unwrap();
        let response = control
            .call(Request::RegisterSourceRoots {
                selections: vec![SourceRootSelection {
                    path: selected.as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                }],
                symlink_policy: OperatorSymlinkPolicy::Refuse,
                shared_workers: 1,
            })
            .unwrap();
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };

        // Once the socket name is gone, an empty session slot cannot claim the
        // ticket with SCM_RIGHTS. The endpoint clone still succeeds because it
        // reaches the control connection's process-local registry instead.
        std::fs::remove_file(roots[0].ticket.broker_path()).unwrap();
        endpoint.connect_with_sources(false, roots.clone()).unwrap();
        let error = Endpoint::local()
            .connect_with_sources(false, roots)
            .err()
            .expect("a fresh local endpoint must not share another session");
        assert!(format!("{error:#}").contains("connect to descriptor broker"));
    }

    impl<R: Read> Read for ExitObserved<R> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buffer)
        }
    }

    impl<R> Drop for ExitObserved<R> {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn kernel_tcp_stats_are_available_for_a_live_socket() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            socket.read_exact(&mut byte).unwrap();
            socket.write_all(&byte).unwrap();
            tcp_socket_stats(&socket).unwrap()
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(&[7]).unwrap();
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).unwrap();
        let client_stats = tcp_socket_stats(&client).unwrap();
        let server_stats = server.join().unwrap();
        assert_eq!(byte, [7]);
        assert!(
            client_stats.segments_sent.is_some_and(|value| value > 0)
                || client_stats.bytes_sent.is_some_and(|value| value > 0)
        );
        assert!(
            server_stats.segments_sent.is_some_and(|value| value > 0)
                || server_stats.bytes_sent.is_some_and(|value| value > 0)
        );
        #[cfg(target_os = "linux")]
        {
            assert!(client_stats.congestion_control.is_some());
            assert!(server_stats.congestion_control.is_some());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_tcp_congestion_is_set_before_connect_and_inherited_on_accept() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        assert_eq!(
            configure_tcp_congestion(&listener, Some("reno")).unwrap(),
            Some("reno".into())
        );
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            tcp_congestion_control(&socket).unwrap()
        });
        let client =
            connect_tcp_stream(&address, std::time::Duration::from_secs(1), Some("reno")).unwrap();
        assert_eq!(tcp_congestion_control(&client).unwrap(), "reno");
        assert_eq!(server.join().unwrap(), "reno");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejected_tcp_congestion_is_classified_separately() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let error = configure_tcp_congestion(&listener, Some("syq_missing_cc")).unwrap_err();
        assert!(is_tcp_congestion_error(&error));
        assert!(error.to_string().contains("kernel rejected"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn connecting_socket_congestion_rejection_is_attributed_locally() {
        let spec = RemoteSpec {
            local_process: false,
            user: None,
            host: "remote.example".into(),
            port: None,
            rsh: vec!["ssh".into()],
            syq_path: None,
            auto_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
        };
        let info = TcpInfo {
            addrs: vec!["127.0.0.1".into()],
            port: 9,
            key: None,
            token: Vec::new(),
            congestion_control: Some("syq_missing_cc".into()),
            failed: false,
            failure: None,
            next: Default::default(),
        };

        let error = spec
            .connect_tcp(
                &info,
                false,
                ConnectionRole::SourceWorker { roots: Vec::new() },
            )
            .err()
            .expect("unregistered congestion control should fail locally");
        let message = format!("{error:#}");
        assert!(is_tcp_congestion_error(&error));
        assert!(message.contains(
            "local/orchestrating host could not configure the connecting data socket to remote.example"
        ));
    }

    #[test]
    fn tcp_fallback_note_scopes_the_unused_override_to_ssh() {
        assert_eq!(tcp_congestion_fallback_note(None), "");
        assert_eq!(
            tcp_congestion_fallback_note(Some("reno")),
            "; requested congestion control reno is not used by the SSH fallback"
        );
    }

    #[test]
    fn rejected_worker_initialization_is_not_a_retryable_transport_error() {
        let error: anyhow::Error = WorkerInitializationError("destination changed".into()).into();
        assert!(is_worker_initialization_error(&error));
        assert!(!is_tcp_congestion_error(&error));
    }

    #[test]
    fn hello_carries_destination_initialization_before_readiness() {
        let temp = tempfile::tempdir().unwrap();
        let descriptor_session = crate::descriptor_broker::DescriptorSessionSlot::default();
        let ticket = descriptor_session
            .register(std::fs::File::open(temp.path()).unwrap())
            .unwrap();
        let destination = DestinationRoot {
            ticket,
            request_prefix: b"destination".to_vec(),
        };
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            let mut reader = FrameReader::new(socket.try_clone().unwrap());
            let hello = reader.read_msg::<Request>().unwrap();
            let Request::Hello {
                role:
                    ConnectionRole::DestinationWorker {
                        destination: Some(destination),
                    },
                ..
            } = hello
            else {
                panic!("destination initialization was not carried in Hello");
            };
            assert_eq!(destination.request_prefix, b"destination");

            let mut writer = FrameWriter::new(socket, false);
            writer
                .write_msg(&Response::HelloOk {
                    identity: crate::identity::build().to_string(),
                    platform: crate::identity::platform(),
                })
                .unwrap();
        });

        let socket = TcpStream::connect(address).unwrap();
        let (rx, reader) = spawn_reader(Box::new(socket.try_clone().unwrap()));
        let conn = RemoteConn {
            child: None,
            w: FrameWriter::new(Box::new(socket), false),
            rx: Some(rx),
            reader: Some(reader),
            label: "pipelined hello test".into(),
            dead: false,
            peer: None,
            tcp_socket: None,
            multiplexed_ssh: false,
        };
        let conn = hello(
            conn,
            false,
            Vec::new(),
            ConnectionRole::DestinationWorker {
                destination: Some(destination),
            },
        )
        .unwrap();
        assert!(conn.peer.is_some());
        drop(conn);
        server.join().unwrap();
        descriptor_session.close();
    }

    #[test]
    fn transport_stats_response_wait_has_a_deadline() {
        let (_sender, receiver) = std::sync::mpsc::sync_channel(1);
        let timeout = std::time::Duration::from_millis(20);
        let start = std::time::Instant::now();
        assert!(receive_transport_stats(&receiver, timeout).is_none());
        assert!(start.elapsed() >= timeout);
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn repeatedly_retiring_timed_out_tcp_connections_joins_their_readers() {
        const CONNECTIONS: usize = 32;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..CONNECTIONS {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request_bytes = Vec::new();
                socket.read_to_end(&mut request_bytes).unwrap();
                assert!(!request_bytes.is_empty());
            }
        });

        for _ in 0..CONNECTIONS {
            let socket = TcpStream::connect(address).unwrap();
            let writer = socket.try_clone().unwrap();
            let tcp_socket = socket.try_clone().unwrap();
            let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let input = ExitObserved {
                inner: socket,
                dropped: dropped.clone(),
            };
            let (rx, reader) = spawn_reader(Box::new(input));
            let mut connection = RemoteConn {
                child: None,
                w: FrameWriter::new(Box::new(writer), false),
                rx: Some(rx),
                reader: Some(reader),
                label: "test tcp".into(),
                dead: false,
                peer: None,
                tcp_socket: Some(tcp_socket),
                multiplexed_ssh: false,
            };
            let timeout = std::time::Duration::from_millis(5);
            let start = std::time::Instant::now();
            let _ = connection.transport_stats_with_timeout(timeout);
            assert!(start.elapsed() >= timeout);
            drop(connection);
            assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(std::sync::Arc::strong_count(&dropped), 1);
        }
        server.join().unwrap();
    }

    fn entry(path: &[u8]) -> Entry {
        Entry {
            path: path.to_vec(),
            kind: Kind::File,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            rdev: 0,
            dev: 0,
            ino: 0,
            ctime: 0,
            ctime_nsec: 0,
            link: None,
        }
    }

    #[test]
    fn remote_scan_paths_are_rooted_and_normalized() {
        let mut saw_root = false;
        validate_remote_scan_batch(&[entry(b""), entry(b"dir/file")], &mut saw_root).unwrap();
        assert!(saw_root);

        for bad in [
            &b"/absolute"[..],
            &b"../escape"[..],
            &b"dir/../escape"[..],
            &b"dir/./file"[..],
            &b"dir//file"[..],
            &b"dir/"[..],
            &b"nul\0byte"[..],
        ] {
            let mut saw_root = true;
            assert!(validate_remote_scan_batch(&[entry(bad)], &mut saw_root).is_err());
        }
    }

    #[test]
    fn remote_scan_requires_exactly_one_leading_root() {
        let mut saw_root = false;
        assert!(validate_remote_scan_batch(&[entry(b"file")], &mut saw_root).is_err());

        let mut saw_root = true;
        assert!(validate_remote_scan_batch(&[entry(b"")], &mut saw_root).is_err());
    }

    #[test]
    fn direct_download_report_frames_manifest_and_digest() {
        let digest = "a".repeat(64);
        let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{\nsyq-helper-manifest-data:  \"schema\": 1\nsyq-helper-manifest-data:}}\nsyq-helper-manifest-end\nsyq-helper-sha256:{digest}\nsyq-helper-report-end\n"
        );
        let report = read_direct_report(&mut bytes.as_bytes()).unwrap().unwrap();
        assert_eq!(report.manifest, b"{\n  \"schema\": 1\n}\n");
        assert_eq!(report.sha256, digest);
    }

    #[test]
    fn direct_download_report_rejects_unterminated_manifest() {
        let error = read_direct_report(
            &mut b"syq-helper-manifest-begin\nsyq-helper-manifest-data:{\"schema\":1}\n".as_slice(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn direct_download_report_keeps_injected_markers_inside_the_manifest() {
        let spoofed = "a".repeat(64);
        let actual = "b".repeat(64);
        let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{\"schema\":1}}\nsyq-helper-manifest-data:syq-helper-manifest-end\nsyq-helper-manifest-data:syq-helper-sha256:{spoofed}\nsyq-helper-manifest-end\nsyq-helper-sha256:{actual}\nsyq-helper-report-end\n"
        );
        let report = read_direct_report(&mut bytes.as_bytes()).unwrap().unwrap();
        assert_eq!(report.sha256, actual);
        assert!(report
            .manifest
            .windows(b"syq-helper-manifest-end".len())
            .any(|window| window == b"syq-helper-manifest-end"));
        assert!(report
            .manifest
            .windows(spoofed.len())
            .any(|window| { window == spoofed.as_bytes() }));
    }

    #[test]
    fn direct_download_report_rejects_data_after_the_digest() {
        let digest = "a".repeat(64);
        let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{}}\nsyq-helper-manifest-end\nsyq-helper-sha256:{digest}\nunexpected\nsyq-helper-report-end\n"
        );
        let error = read_direct_report(&mut bytes.as_bytes()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn ssh_inherits_host_key_policy() {
        let spec = RemoteSpec {
            local_process: false,
            user: None,
            host: "example".to_string(),
            port: None,
            rsh: vec!["ssh".to_string()],
            syq_path: None,
            auto_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
        };
        let command = spec.ssh_command(SshConnection::Independent);
        assert!(!command
            .get_args()
            .any(|arg| arg.to_string_lossy().starts_with("StrictHostKeyChecking=")));

        let mut configured = spec;
        configured.rsh = vec![
            "ssh".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
        ];
        assert!(configured
            .ssh_command(SshConnection::Independent)
            .get_args()
            .any(|arg| arg == OsStr::new("StrictHostKeyChecking=yes")));
    }

    #[test]
    fn ssh_workers_reuse_the_private_control_socket_only_when_enabled() {
        let multiplexer = std::sync::Arc::new(SshMultiplexer::new().unwrap());
        let control_path = multiplexer.path.to_string_lossy().into_owned();
        let spec = RemoteSpec {
            local_process: false,
            user: None,
            host: "example".into(),
            port: None,
            rsh: vec!["ssh".into()],
            syq_path: None,
            auto_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: Some(multiplexer),
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
        };
        let args = |connection| {
            spec.ssh_command(connection)
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };

        let control = args(SshConnection::Control);
        assert!(control.iter().any(|arg| arg == "ControlMaster=yes"));
        assert!(control
            .windows(2)
            .any(|pair| pair[0] == "-S" && pair[1] == control_path));
        assert!(control.iter().any(|arg| arg == "ControlPersist=no"));

        let worker = args(spec.ssh_connection(true));
        assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
        assert!(worker.iter().any(|arg| arg == "ControlPath=none"));

        spec.set_ssh_multiplexing(true);
        let worker = args(spec.ssh_connection(true));
        assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
        assert!(worker
            .windows(2)
            .any(|pair| pair[0] == "-S" && pair[1] == control_path));
        assert!(!worker.iter().any(|arg| arg == "ControlPath=none"));

        let independent = args(SshConnection::Independent);
        assert!(independent.iter().any(|arg| arg == "ControlPath=none"));
    }

    #[test]
    fn persistent_reuse_uses_auto_master_and_never_shares_with_workers() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().join("scope");
        crate::persistence::initialize_scope(&base).unwrap();
        // The socket name is stable per endpoint, and a dead leftover at the
        // path is cleared so a fresh master can bind.
        let probe = SshMultiplexer::persistent(&base, Some("u"), "example", None).unwrap();
        std::fs::write(&probe.path, b"stale").unwrap();
        let multiplexer = SshMultiplexer::persistent(&base, Some("u"), "example", None).unwrap();
        assert_eq!(probe.path, multiplexer.path);
        let alternate_port =
            SshMultiplexer::persistent(&base, Some("u"), "example", Some(2222)).unwrap();
        assert_ne!(multiplexer.path, alternate_port.path);
        assert!(!multiplexer.path.exists());
        assert_eq!(
            std::fs::metadata(&base).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let control_path = multiplexer.path.to_string_lossy().into_owned();
        let spec = RemoteSpec {
            local_process: false,
            user: Some("u".into()),
            host: "example".into(),
            port: None,
            rsh: vec!["ssh".into()],
            syq_path: None,
            auto_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: Some(std::sync::Arc::new(multiplexer)),
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
        };
        let args = |connection| {
            spec.ssh_command(connection)
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let control = args(SshConnection::Control);
        assert!(control.iter().any(|arg| arg == "ControlMaster=auto"));
        assert!(control
            .windows(2)
            .any(|pair| pair[0] == "-S" && pair[1] == control_path));
        assert!(control
            .iter()
            .any(|arg| arg == &format!("ControlPersist={REUSE_PERSIST_SECONDS}")));
        // Worker data channels never ride a cross-run master, even when the
        // small-file path asks for in-run multiplexing.
        spec.set_ssh_multiplexing(true);
        let worker = args(spec.ssh_connection(true));
        assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
        assert!(worker.iter().any(|arg| arg == "ControlPath=none"));
    }

    #[test]
    fn persistent_control_path_is_one_byte_exact_openssh_argument() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/tmp/scope with space/%h/non-utf8-\xff/socket".to_vec(),
        ));
        let multiplexer = SshMultiplexer {
            _directory: None,
            path,
            persistent: true,
            reuse_for_workers: AtomicBool::new(false),
        };
        let spec = RemoteSpec {
            local_process: false,
            user: None,
            host: "example".into(),
            port: None,
            rsh: vec!["ssh".into()],
            syq_path: None,
            auto_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: Some(std::sync::Arc::new(multiplexer)),
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
        };

        let command = spec.ssh_command(SshConnection::Control);
        let args: Vec<_> = command.get_args().collect();
        let control_index = args
            .iter()
            .position(|arg| *arg == OsStr::new("-S"))
            .unwrap();
        assert_eq!(
            args[control_index + 1].as_bytes(),
            b"/tmp/scope with space/%%h/non-utf8-\xff/socket"
        );
    }
}
