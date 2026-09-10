//! Connections to endpoints: local (in-process) or remote (over an ssh child).

use crate::fsops::{self, FsOps};
#[allow(unused_imports)]
use crate::proto::SizeHint;
use crate::proto::*;
use crate::remote_helper::{self, Target};
use crate::tcp_records::{Cipher, RecordReader, RecordWriter};
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
    /// The experimental writer must not retain one reply per sent block.
    fn begin_streaming_writes(&mut self) -> Result<()> {
        bail!("this connection does not support experimental streaming writes")
    }
    fn check_streaming_writes(&mut self) -> Result<()> {
        bail!("no streaming writes are active")
    }
    /// Start the non-writing fence without waiting for its reply. Pass its
    /// result to finish even after failure, so the collector is always joined.
    fn fence_streaming_writes(&mut self) -> Result<()> {
        bail!("no streaming writes are active")
    }
    fn finish_streaming_writes(&mut self, _sent: u64, _fence: Result<()>) -> Result<()> {
        bail!("no streaming writes are active")
    }
    fn stop_read_stream(&mut self) -> Result<u64> {
        self.send(Request::StopReadStream)?;
        crate::streaming::drain_reads(|| self.recv())
    }
    fn call(&mut self, req: Request) -> Result<Response> {
        let expected = match &req {
            Request::StatMany { paths, .. } => Some(("stat", paths.len())),
            Request::Apply { ops, .. } => Some(("apply", ops.len())),
            Request::PartialPaths { paths, .. } => Some(("partial paths", paths.len())),
            _ => None,
        };
        self.send(req)?;
        let response = self.recv()?;
        if let Some((operation, expected)) = expected {
            let actual = match &response {
                Response::Stats(values) => Some(values.len()),
                Response::Applied(values) => Some(values.len()),
                Response::PathResults(values) => Some(values.len()),
                _ => None,
            };
            if actual.is_some_and(|actual| actual != expected) {
                bail!(
                    "{operation} reply count {} does not match request count {expected}",
                    actual.unwrap()
                );
            }
        }
        Ok(response)
    }
    /// True once the transport has failed (remote process gone).
    fn is_dead(&self) -> bool {
        false
    }
    /// Whether sending several requests before receiving their responses can
    /// overlap useful work. LocalConn executes requests synchronously, so
    /// queueing several block responses there only retains their buffers.
    fn supports_request_pipelining(&self) -> bool {
        true
    }
    /// Current kernel RTT estimate for a TCP data connection. This is a
    /// local socket query and never sends a protocol request.
    fn tcp_rtt_us(&self) -> Option<u64> {
        None
    }
    /// Best-effort counters for a TCP data connection. Collection is
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
        source: Option<&RegisteredPath>,
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

/// Restore an ordinary range's request/reply boundary after an operation
/// error. Endpoint errors still consume a response; a broken transport cannot
/// be drained and must be recovered by the caller. Never send a new request.
pub(crate) fn drain_range_replies(conn: &mut dyn Conn, count: usize, what: &str) -> Result<()> {
    let mut error = None;
    for _ in 0..count {
        anyhow::ensure!(!conn.is_dead(), "cannot drain a failed range transport");
        let response = conn.recv()?;
        if let Err(failure) = ok(response, what) {
            error.get_or_insert(failure);
        }
    }
    error.map_or(Ok(()), Err)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub identity: String,
    pub platform: String,
    pub supports_confined_socket_nodes: bool,
    pub(crate) ssh_worker_ticket: Option<std::result::Result<String, String>>,
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

fn is_non_retryable_connect_error(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}");
    is_worker_initialization_error(error)
        || error.chain().any(|cause| cause.is::<OpenSshVersionError>())
        || message.contains("build identity mismatch")
        || message.contains(WIRE_PREAMBLE_PROTOCOL_ERROR)
        || message.contains("unexpected handshake response")
        || message.contains("exit status: 127")
        || message.contains(&format!(
            "exit status: {}",
            remote_helper::HELPER_MISSING_EXIT
        ))
        || message.contains(&format!(
            "exit status: {}",
            remote_helper::HELPER_NOT_EXECUTABLE_EXIT
        ))
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
#[cfg(not(target_os = "linux"))]
pub(crate) fn configure_tcp_congestion<S: AsRawFd>(
    _socket: &S,
    requested: Option<&str>,
) -> Result<Option<String>> {
    match requested {
        None => Ok(None),
        Some(requested) => Err(TcpCongestionError(format!(
            "TCP congestion control {requested:?} was requested, but per-socket selection is supported only on Linux"
        ))
        .into()),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn configure_tcp_congestion<S: AsRawFd>(
    socket: &S,
    requested: Option<&str>,
) -> Result<Option<String>> {
    let Some(requested) = requested else {
        return Ok(tcp_congestion_control(socket).ok());
    };

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

#[cfg(not(target_os = "linux"))]
fn connect_tcp_stream(
    address: &SocketAddr,
    timeout: std::time::Duration,
    congestion_control: Option<&str>,
) -> Result<TcpStream> {
    match congestion_control {
        None => TcpStream::connect_timeout(address, timeout).map_err(Into::into),
        Some(congestion_control) => Err(TcpCongestionError(format!(
            "TCP congestion control {congestion_control:?} was requested, but per-socket selection is supported only on Linux"
        ))
        .into()),
    }
}

#[cfg(target_os = "linux")]
fn connect_tcp_stream(
    address: &SocketAddr,
    timeout: std::time::Duration,
    congestion_control: Option<&str>,
) -> Result<TcpStream> {
    let Some(congestion_control) = congestion_control else {
        return TcpStream::connect_timeout(address, timeout).map_err(Into::into);
    };

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

/// `struct tcp_connection_info` as the XNU kernel lays it out. The `libc`
/// crate expands the kernel's single 32-bit TFO bit-field word into
/// eighteen separate fields, which shifts every 64-bit counter and makes the
/// kernel's returned length fall short of them.
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct DarwinTcpConnectionInfo {
    tcpi_state: u8,
    tcpi_snd_wscale: u8,
    tcpi_rcv_wscale: u8,
    __pad1: u8,
    tcpi_options: u32,
    tcpi_flags: u32,
    tcpi_rto: u32,
    tcpi_maxseg: u32,
    tcpi_snd_ssthresh: u32,
    tcpi_snd_cwnd: u32,
    tcpi_snd_wnd: u32,
    tcpi_snd_sbbytes: u32,
    tcpi_rcv_wnd: u32,
    tcpi_rttcur: u32,
    tcpi_srtt: u32,
    tcpi_rttvar: u32,
    tcpi_tfo: u32,
    tcpi_txpackets: u64,
    tcpi_txbytes: u64,
    tcpi_txretransmitbytes: u64,
    tcpi_rxpackets: u64,
    tcpi_rxbytes: u64,
    tcpi_rxoutoforderbytes: u64,
    tcpi_txretransmitpackets: u64,
}

#[cfg(target_os = "macos")]
pub(crate) fn tcp_socket_stats(stream: &TcpStream) -> Option<TcpSocketStats> {
    let mut info: DarwinTcpConnectionInfo = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<DarwinTcpConnectionInfo>() as libc::socklen_t;
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
                >= std::mem::offset_of!(DarwinTcpConnectionInfo, $name)
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
        Response::EndpointError(error) => Err(endpoint_error(error)).context(what.to_owned()),
        r => Ok(r),
    }
}

pub fn endpoint_error(error: WireError) -> anyhow::Error {
    anyhow::Error::new(error)
}

pub struct LocalConn {
    ops: FsOps,
    pending: VecDeque<Response>,
    role: LocalConnectionRole,
    read_stream: Option<ReadStreamRequest>,
    read_stream_limit: u64,
    read_stream_done_sent: bool,
    write_stream: Option<crate::streaming::Completions>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalConnectionRole {
    Control,
    SourceWorker,
    DestinationWorker,
}

impl From<&ConnectionRole> for LocalConnectionRole {
    fn from(role: &ConnectionRole) -> Self {
        match role {
            ConnectionRole::Control => Self::Control,
            ConnectionRole::SourceWorker { .. } => Self::SourceWorker,
            ConnectionRole::DestinationWorker { .. } => Self::DestinationWorker,
        }
    }
}

impl LocalConn {
    fn new(
        role: &ConnectionRole,
        descriptor_session: crate::descriptor_broker::DescriptorSessionSlot,
    ) -> Self {
        LocalConn {
            ops: FsOps::with_descriptor_session(descriptor_session),
            pending: VecDeque::new(),
            role: role.into(),
            read_stream: None,
            read_stream_limit: 0,
            read_stream_done_sent: false,
            write_stream: None,
        }
    }
}

impl Conn for LocalConn {
    fn send(&mut self, mut req: Request) -> Result<()> {
        anyhow::ensure!(
            self.write_stream.is_none() || matches!(req, Request::WriteRange { .. }),
            "only range writes are valid during streaming writes"
        );
        anyhow::ensure!(
            self.read_stream.is_none()
                || matches!(
                    req,
                    Request::StopReadStream | Request::ShrinkReadStream { .. }
                ),
            "only stop and shrink requests are valid during a read stream"
        );
        if self.role != LocalConnectionRole::Control
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
            )
        {
            self.pending.push_back(Response::Err(
                "request is allowed only on the control connection".into(),
            ));
            return Ok(());
        }
        if self.role == LocalConnectionRole::SourceWorker && !req.allowed_on_source_worker() {
            self.pending.push_back(Response::Err(
                "request is not valid on a source worker".into(),
            ));
            return Ok(());
        }
        match req {
            Request::ReadStream(stream) => {
                if self.role != LocalConnectionRole::SourceWorker || self.read_stream.is_some() {
                    self.pending.push_back(Response::Err(
                        "read stream requires an idle source worker".into(),
                    ));
                } else if let Err(error) = stream.validate() {
                    self.pending.push_back(Response::Err(error.to_string()));
                } else {
                    self.read_stream_limit = stream.end;
                    self.read_stream_done_sent = false;
                    self.read_stream = Some(stream);
                    self.pending.push_back(Response::Ok);
                }
                return Ok(());
            }
            Request::ShrinkReadStream { end } => {
                if self.read_stream.is_none() {
                    self.pending
                        .push_back(Response::Err("no read stream is active".into()));
                    return Ok(());
                }
                return crate::streaming::shrink_limit(&mut self.read_stream_limit, end);
            }
            Request::StopReadStream => {
                if self.read_stream.take().is_none() {
                    self.pending
                        .push_back(Response::Err("no read stream is active".into()));
                } else if !self.read_stream_done_sent {
                    self.pending.push_back(Response::ReadStreamDone);
                }
                return Ok(());
            }
            _ => {}
        }
        let resp = self.ops.handle_in_place(&mut req);
        if let Some(state) = &mut self.write_stream {
            state.record(resp);
            return Ok(());
        }
        self.pending.push_back(resp);
        Ok(())
    }
    fn recv(&mut self) -> Result<Response> {
        if self.pending.is_empty() {
            if let Some(stream) = &mut self.read_stream {
                if stream.off < self.read_stream_limit {
                    let response = self.ops.handle_in_place(&mut stream.next_request());
                    if let Response::Block { data, .. } = &response {
                        stream.off += data.len() as u64;
                    } else {
                        stream.off = stream.end;
                    }
                    return Ok(response);
                }
                // Match the server's early completion without pre-reading data
                // or adding a local producer thread. Stop still clears the
                // active mode, and never queues a second completion marker.
                if !self.read_stream_done_sent {
                    self.read_stream_done_sent = true;
                    return Ok(Response::ReadStreamDone);
                }
            }
        }
        self.pending
            .pop_front()
            .ok_or_else(|| anyhow!("no pending response"))
    }
    fn supports_request_pipelining(&self) -> bool {
        false
    }
    fn begin_streaming_writes(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.pending.is_empty() && self.write_stream.is_none(),
            "streaming writes require an idle connection"
        );
        self.write_stream = Some(crate::streaming::Completions::default());
        Ok(())
    }
    fn check_streaming_writes(&mut self) -> Result<()> {
        streaming_result(
            self.write_stream
                .as_ref()
                .context("no streaming writes are active")?
                .error
                .clone(),
        )
    }
    fn fence_streaming_writes(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.write_stream.is_some(),
            "no streaming writes are active"
        );
        Ok(())
    }
    fn finish_streaming_writes(&mut self, sent: u64, fence: Result<()>) -> Result<()> {
        let state = self
            .write_stream
            .take()
            .context("no streaming writes are active")?;
        fence?;
        anyhow::ensure!(
            state.count == sent,
            "streaming write completion count mismatch"
        );
        streaming_result(state.error)
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
        if let Some(source) = self.ops.source_scan_root(source)? {
            return crate::scan::scan_descriptor(
                source.root,
                &source.relative,
                source.expected_leaf,
                false,
                false,
                ignore,
                report_ignored,
                sink,
                ignored,
                warn,
            );
        }
        if let Some((destination_root, relative)) = self.ops.destination_scan_root(root)? {
            return crate::scan::scan_descriptor(
                destination_root,
                &relative,
                None,
                follow_root,
                true,
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
        if self.role != LocalConnectionRole::Control {
            bail!("native removal is allowed only on the control connection");
        }
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
    rx: Option<std::sync::mpsc::Receiver<std::io::Result<crate::wire_budget::Budgeted<Response>>>>,
    reader: Option<std::thread::JoinHandle<()>>,
    label: String,
    dead: bool,
    peer: Option<PeerInfo>,
    tcp_socket: Option<TcpStream>,
    named_socket: Option<std::os::unix::net::UnixStream>,
    multiplexed_ssh: bool,
    /// A session taken from the session pool: no child of ours to wait for,
    /// and a reader that ends when the remote closes the pipe.
    detached: bool,
    write_stream: Option<crate::streaming::WriteReplies>,
}

fn streaming_result(error: Option<crate::streaming::Failure>) -> Result<()> {
    match error {
        None => Ok(()),
        Some(crate::streaming::Failure::Endpoint(error)) => Err(endpoint_error(error)),
        Some(
            crate::streaming::Failure::Rejected(error)
            | crate::streaming::Failure::Transport(error),
        ) => Err(anyhow!(error)),
    }
}

const TRANSPORT_STATS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

fn spawn_reader(
    input: Box<dyn Read + Send>,
    read_ahead: usize,
) -> (
    std::sync::mpsc::Receiver<std::io::Result<crate::wire_budget::Budgeted<Response>>>,
    std::thread::JoinHandle<()>,
) {
    let (tx, rx) = std::sync::mpsc::sync_channel(read_ahead);
    let reader = std::thread::spawn(move || {
        let mut r = FrameReader::new(input);
        r.set_limit(MAX_HANDSHAKE_FRAME);
        let hello = r.read_budgeted::<Response>();
        // Make the same acceptance check as receive_hello before allowing the
        // background reader to allocate any ordinary data frame. This also
        // covers pooled sessions, whose Hello was sent by another process.
        let accepted = matches!(&hello, Ok(message)
            if matches!(&message.value, Response::HelloOk { identity, .. }
                if identity == crate::identity::build()));
        if tx.send(hello).is_err() || !accepted {
            return;
        }
        r.set_limit(MAX_FRAME);
        loop {
            let msg = r.read_budgeted::<Response>();
            let failed = msg.is_err();
            if tx.send(msg).is_err() || failed {
                break;
            }
        }
    });
    (rx, reader)
}

fn receive_transport_stats(
    rx: &std::sync::mpsc::Receiver<std::io::Result<crate::wire_budget::Budgeted<Response>>>,
    timeout: std::time::Duration,
) -> Option<TcpSocketStats> {
    match rx
        .recv_timeout(timeout)
        .map(|result| result.map(crate::wire_budget::Budgeted::into_inner))
    {
        Ok(Ok(Response::TransportStats(stats))) => stats,
        _ => None,
    }
}

fn validate_remote_scan_batch(
    batch: &[Entry],
    saw_root: &mut bool,
    matcher: Option<&ignore::gitignore::Gitignore>,
) -> Result<()> {
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
        if matcher.is_some_and(|matcher| {
            crate::scan::path_is_ignored(matcher, &entry.path, entry.kind == Kind::Dir)
        }) {
            bail!(
                "scan response contained excluded path {:?}",
                String::from_utf8_lossy(&entry.path)
            );
        }
    }
    Ok(())
}

impl std::fmt::Debug for RemoteConn {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteConn")
            .field("label", &self.label)
            .field("detached", &self.detached)
            .finish()
    }
}

impl RemoteConn {
    /// A control session taken from the session pool: the ssh client's
    /// pipes, with the preamble and hello already sent by the pool and their
    /// replies unread. The pool reaps the ssh client once this process has
    /// closed the pipes.
    pub(crate) fn from_pooled(
        session: crate::session_pool::PooledSession,
        compress: bool,
        label: String,
    ) -> Self {
        let (rx, reader) = spawn_reader(
            Box::new(session.stdout),
            crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        );
        let mut stderr = session.stderr;
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stderr, &mut std::io::stderr());
        });
        RemoteConn {
            child: None,
            w: FrameWriter::with_preamble_written(Box::new(session.stdin), compress),
            rx: Some(rx),
            reader: Some(reader),
            label,
            dead: false,
            write_stream: None,
            peer: None,
            tcp_socket: None,
            named_socket: None,
            multiplexed_ssh: false,
            detached: true,
        }
    }

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
        let detail = format!("{e:#}");
        // If the child has exited (or does so shortly), that's usually the
        // more useful error. A multiplexed SSH refusal in particular must win
        // over the missing-preamble EOF so the caller can retry independently.
        if let Some(child) = &mut self.child {
            for _ in 0..20 {
                if let Ok(Some(status)) = child.try_wait() {
                    if status.code() == Some(255) {
                        if self.multiplexed_ssh {
                            return MultiplexedSshSessionError(format!(
                                "{}: multiplexed SSH session was rejected ({status})",
                                self.label
                            ))
                            .into();
                        }
                        return anyhow!("{}: remote syq exited ({status})", self.label);
                    }
                    // For other early exits, a preamble failure is the
                    // actionable version-skew diagnosis; the exit status is
                    // commonly just the old helper rejecting unknown bytes.
                    if detail.contains(WIRE_PREAMBLE_PROTOCOL_ERROR)
                        || detail.contains("build identity mismatch")
                    {
                        return anyhow!("{}: {detail}", self.label);
                    }
                    return anyhow!("{}: remote syq exited ({status})", self.label);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        if detail.contains(WIRE_PREAMBLE_PROTOCOL_ERROR)
            || detail.contains("build identity mismatch")
        {
            return anyhow!("{}: {detail}", self.label);
        }
        let msg = if e
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
        {
            "connection closed by remote".to_string()
        } else {
            detail
        };
        anyhow!("{}: {msg}", self.label)
    }
}

impl Conn for RemoteConn {
    fn send(&mut self, req: Request) -> Result<()> {
        anyhow::ensure!(
            self.write_stream.is_none()
                || matches!(req, Request::WriteRange { .. } | Request::WriteStreamFence),
            "only writes and their fence are valid during streaming writes"
        );
        self.w.write_msg(&req).map_err(|e| self.io_err(e.into()))
    }
    fn recv(&mut self) -> Result<Response> {
        match self
            .rx
            .as_ref()
            .context("response reader is collecting streaming writes")?
            .recv()
            .map(|result| result.map(crate::wire_budget::Budgeted::into_inner))
        {
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
    fn begin_streaming_writes(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.write_stream.is_none(),
            "streaming writes already active"
        );
        self.write_stream = Some(crate::streaming::WriteReplies::spawn(
            self.rx.take().context("response reader missing")?,
        ));
        Ok(())
    }
    fn check_streaming_writes(&mut self) -> Result<()> {
        let state = self
            .write_stream
            .as_ref()
            .context("no streaming writes are active")?
            .status();
        if matches!(state.error, Some(crate::streaming::Failure::Transport(_))) {
            self.dead = true;
        }
        streaming_result(state.error)
    }
    fn fence_streaming_writes(&mut self) -> Result<()> {
        // The non-writing marker fences every reply, even when a signed grant
        // has expired and the destination is rejecting all further writes.
        anyhow::ensure!(
            self.write_stream.is_some(),
            "no streaming writes are active"
        );
        if self.dead {
            Err(anyhow!("streaming transport failed"))
        } else {
            self.send(Request::WriteStreamFence)
        }
    }
    fn finish_streaming_writes(&mut self, sent: u64, fence: Result<()>) -> Result<()> {
        let stream = self
            .write_stream
            .take()
            .context("no streaming writes are active")?;
        let (rx, state) = stream.finish(fence.is_err());
        self.rx = Some(rx);
        fence?;
        if matches!(state.error, Some(crate::streaming::Failure::Transport(_)))
            || !state.fenced
            || state.count != sent
        {
            self.dead = true;
            streaming_result(state.error)?;
            bail!("streaming write completion fence/count mismatch");
        }
        streaming_result(state.error)
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
        let matcher = crate::scan::build_ignore(ignore)?;
        let mut saw_root = false;
        loop {
            match self.recv()? {
                Response::ScanBatch(b) => {
                    validate_remote_scan_batch(&b, &mut saw_root, matcher.as_ref())
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
                Response::EndpointError(error) => {
                    return Err(endpoint_error(error)).context(format!("{}: remove", self.label));
                }
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
        // Cancel the reply collector before joining the underlying response
        // reader: otherwise it still owns the channel receiver on an unwind.
        if let Some(stream) = self.write_stream.take() {
            let (rx, _) = stream.finish(true);
            self.rx = Some(rx);
        }
        if !self.dead {
            let _ = self.w.write_msg(&Request::Shutdown);
        }
        if self.detached {
            // Closing the pipes is the whole teardown: the remote exits on
            // Shutdown or EOF, and waiting for its exit status would cost
            // the round trip the pool exists to save.
            self.rx.take();
            return;
        }
        // Sending Shutdown asks for an orderly peer exit; shutting down the
        // retained TCP descriptor also wakes our reader clone and the peer's
        // request reader if either side is wedged or the diagnostic reply
        // timed out. Drop the receiver before joining so a reader blocked on a
        // full response channel can exit as well.
        if let Some(socket) = &self.tcp_socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        if let Some(socket) = &self.named_socket {
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
/// Hard upper bound on simultaneously establishing data connections. A source
/// endpoint's descriptor broker therefore sees no more concurrent independent
/// SSH worker claims than this, even when tuning warms a larger candidate set.
pub(crate) const MAX_CONCURRENT_CONNECTS: usize = 32;
const MIN_CONCURRENT_CONNECTS: usize = 4;
static CONNECT_LIMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(MAX_CONCURRENT_CONNECTS);
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

/// Whether an advertised address belongs to an overlay network (CGNAT /
/// Tailscale). Such routes are last in priority on both ends: the server
/// buckets them last, and the client inserts the direct ssh target before
/// them, so an overlay never wins over the public address ssh reached.
/// Tailscale uses `100.64.0.0/10` and `fd7a:115c:a1e0::/48`; any other IPv6
/// unique-local address is an ordinary private network.
pub(crate) fn is_overlay_address(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let [a, b, _, _] = v4.octets();
            a == 100 && (b & 0xc0) == 64
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
        Err(_) => false,
    }
}

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
    probe: std::thread::JoinHandle<Result<Vec<TcpCandidate>>>,
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
    /// A managed persistence scope keeps its control master alive, so later
    /// syq runs in that scope skip the SSH handshake.
    persistent: bool,
    idle_timeout: &'static str,
    automatic_receiving: bool,
    reuse_for_workers: AtomicBool,
    workers_rejected: AtomicBool,
}

// Keepalives detect dead transports so a later command can reconnect. Durable
// logins have no idle expiry; abandoned script scopes retain a bounded lifetime.
const PERSISTENT_SSH_OPTIONS: &[&str] = &[
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=3",
];

/// The oldest OpenSSH release whose client speaks the agent session-bind
/// extension and host-bound public-key authentication. Constrained agent
/// forwarding relies on both, on the local machine and on the coordinator
/// host, and the peer's `sshd` must be at least this new as well.
pub(crate) const CONSTRAINED_OPENSSH_MINIMUM: OpenSshVersion =
    OpenSshVersion { major: 8, minor: 9 };

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct OpenSshVersion {
    pub major: u32,
    pub minor: u32,
}

impl std::fmt::Display for OpenSshVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenSSH {}.{}", self.major, self.minor)
    }
}

/// Read the release number out of an `ssh -V` banner such as
/// `OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 30 Jan 2024`. Other
/// clients report nothing recognizable and yield `None`.
pub(crate) fn parse_openssh_version(banner: &[u8]) -> Option<OpenSshVersion> {
    let text = String::from_utf8_lossy(banner);
    let rest = text.split("OpenSSH_").nth(1)?;
    let mut numbers = rest
        .split(|c: char| !c.is_ascii_digit())
        .take(2)
        .map(|digits| digits.parse::<u32>().ok());
    let major = numbers.next()??;
    let minor = numbers.next()??;
    Some(OpenSshVersion { major, minor })
}

/// Ask `program -V` for its version once per program name. Only programs
/// whose name ends in `ssh` are probed: an arbitrary `--rsh` command is a
/// complete user policy and might do anything with a `-V` argument.
pub(crate) fn openssh_version(program: &str) -> Option<OpenSshVersion> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static CACHE: Mutex<Option<HashMap<String, Option<OpenSshVersion>>>> = Mutex::new(None);
    if !program.ends_with("ssh") {
        return None;
    }
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = cache.get_or_insert_with(HashMap::new);
    if let Some(version) = cache.get(program) {
        return *version;
    }
    let version = Command::new(program)
        .arg("-V")
        .stdin(Stdio::null())
        .output()
        .ok()
        .and_then(|output| {
            parse_openssh_version(&output.stderr).or_else(|| parse_openssh_version(&output.stdout))
        });
    cache.insert(program.to_owned(), version);
    version
}

/// An installed OpenSSH client is too old for constrained agent forwarding.
/// Nothing about a retry changes that, so the connection loop gives up on it
/// immediately.
#[derive(Debug)]
pub(crate) struct OpenSshVersionError(String);

impl std::fmt::Display for OpenSshVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpenSshVersionError {}

/// Refuse constrained agent forwarding through an OpenSSH client that
/// predates session binding. A client whose version cannot be read is left to
/// fail on its own, so this only turns a confusing authentication failure
/// into a direct explanation.
pub(crate) fn require_constrained_openssh(program: &str, location: &str) -> Result<()> {
    match openssh_version(program) {
        Some(version) if version < CONSTRAINED_OPENSSH_MINIMUM => {
            Err(OpenSshVersionError(format!(
                "constrained agent forwarding needs {CONSTRAINED_OPENSSH_MINIMUM} or newer {location}, but {program} is {version}; use --peer-auth own-credentials with credentials on the coordinator host, --peer-auth full-agent, or an explicit --rsh policy"
            ))
            .into())
        }
        _ => Ok(()),
    }
}

impl SshMultiplexer {
    pub(crate) fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("syq-ssh-")
            .tempdir()
            .context("create private SSH control directory")?;
        let path = directory.path().join("socket");
        crate::persistence::validate_openssh_socket_path(&path)?;
        Ok(Self {
            _directory: Some(directory),
            path,
            persistent: false,
            idle_timeout: "no",
            automatic_receiving: false,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
        })
    }

    pub(crate) fn persistent(
        scope: &std::path::Path,
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
    ) -> Result<Self> {
        let path = crate::persistence::prepare_endpoint(scope, user, host, port)?;
        let global = crate::persistence::is_global_scope(scope)?;
        Ok(Self {
            _directory: None,
            path,
            persistent: true,
            idle_timeout: if global { "yes" } else { "300" },
            automatic_receiving: global,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
        })
    }

    /// The explicit connect command starts receiving once and propagates setup errors.
    pub(crate) fn defer_receiving(&mut self) {
        self.automatic_receiving = false;
    }

    pub(crate) fn control_path(&self) -> &std::path::Path {
        &self.path
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub bootstrap_helper: bool,
    /// One-time signed authorization for a command-restricted receiver. It is
    /// sent only on the SSH control connection; TCP and SSH workers join
    /// that already-authorized receiver without redeeming the grant again.
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
    /// A pooled control session taken ahead of time on the main thread, for
    /// the control connection to consume. An empty result also prevents
    /// descriptor receipt during the later parallel connect.
    pub(crate) primed_control: std::sync::Arc<std::sync::Mutex<PrimedControl>>,
    /// Must cover the worker request pipeline: otherwise a helper blocked
    /// writing responses can stop reading requests while the coordinator is
    /// still filling its pipeline. Control sessions do not need this depth.
    pub(crate) read_ahead: usize,
    pub(crate) forwarded: Option<std::sync::Arc<crate::destination::NamedReceipt>>,
}

#[derive(Debug, Default)]
pub(crate) enum PrimedControl {
    #[default]
    Unchecked,
    Checked(Option<Box<RemoteConn>>),
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
            bootstrap_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet,
            tcp: Default::default(),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
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
            let mut diagnostics = self.diagnostics.lock().unwrap();
            let mut peer = peer.clone();
            // Worker Hello has no admission ticket. Keep the control's ticket
            // for subsequent workers and retries within this same live copy.
            if peer.ssh_worker_ticket.is_none() {
                peer.ssh_worker_ticket = diagnostics
                    .peer
                    .as_ref()
                    .and_then(|p| p.ssh_worker_ticket.clone());
            }
            diagnostics.peer = Some(peer);
        }
    }

    fn ssh_command(&self, connection: SshConnection, verbose: bool) -> Command {
        let mut cmd = Command::new(&self.rsh[0]);
        cmd.args(&self.rsh[1..]);
        if self.rsh[0].ends_with("ssh") {
            // Only foreground helper sessions get verbose SSH diagnostics.
            // A persistent master keeps verbose stderr open after detaching;
            // bootstrap captures stderr as error text. Restricted receiver
            // commands also carry authorization material that must not be logged.
            if verbose
                && self.restricted_grant.is_none()
                && !self
                    .ssh_multiplexer
                    .as_ref()
                    .is_some_and(|mux| mux.persistent)
            {
                cmd.arg("-v");
            }
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
                        .arg(format!("ControlPersist={}", multiplexer.idle_timeout))
                        .args(PERSISTENT_SSH_OPTIONS);
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

    fn ssh_connection(&self, limited: bool, first_worker: bool) -> SshConnection {
        // Startup workers can begin on this copy's authenticated transport.
        // The others retain independent cipher processes and TCP streams.
        // Do not share a persistent master: workers must keep the current
        // invocation's environment and not compete with unrelated copies.
        if !limited {
            SshConnection::Control
        } else if self.ssh_multiplexer.as_ref().is_some_and(|multiplexer| {
            !multiplexer.workers_rejected.load(Ordering::Relaxed)
                && ((first_worker && !multiplexer.persistent) || multiplexer.reuse_for_workers())
        }) {
            SshConnection::Worker
        } else {
            SshConnection::Independent
        }
    }

    fn pool_endpoint(&self) -> crate::session_pool::PoolEndpoint {
        crate::session_pool::PoolEndpoint {
            user: self.user.clone(),
            host: self.host.clone(),
            port: self.port,
            program: self.program_command(&["--server".into()]),
        }
    }

    /// A ready control session from the persistence scope's pool, if the
    /// pool has one for exactly the remote command this connection would
    /// run. The pool sent the hello with a default command's flags; this
    /// process reads the reply. Anything short of a usable session is a
    /// reason to connect directly, never an error.
    fn take_pooled_control(&self, compress: bool) -> Option<RemoteConn> {
        if let PrimedControl::Checked(conn) = &mut *self.primed_control.lock().unwrap() {
            return conn.take().map(|conn| *conn);
        }
        let multiplexer = self.ssh_multiplexer.as_ref()?;
        if !multiplexer.persistent
            || self.local_process
            || self.restricted_grant.is_some()
            || !self
                .rsh
                .first()
                .is_some_and(|program| program.ends_with("ssh"))
        {
            return None;
        }
        let program = self.program_command(&["--server".into()]);
        let session = crate::session_pool::take(&multiplexer.path, &program)?;
        let conn = RemoteConn::from_pooled(session, compress, self.label());
        match receive_hello(conn, false) {
            Ok(conn) => {
                if crate::transfer::debug() {
                    crate::output::diagnostic!(
                        "syq: {}: control connection from the session pool",
                        self.label()
                    );
                }
                self.record_peer(&conn);
                if multiplexer.automatic_receiving {
                    crate::receive_service::ensure(&multiplexer.path, self);
                }
                Some(conn)
            }
            Err(error) => {
                if crate::transfer::debug() {
                    crate::output::diagnostic!(
                        "syq: {}: pooled session unusable ({error:#}); connecting directly",
                        self.label()
                    );
                }
                None
            }
        }
    }

    /// Take a pooled control session now, on the calling thread, for the
    /// control connection to use later. Pooled sessions arrive as
    /// descriptors, and Darwin cannot receive those close-on-exec
    /// atomically, so this runs before any child is spawned alongside.
    pub(crate) fn prime_pooled_control(&self, compress: bool) {
        // The same gate as the control connection's: a --no-compress command
        // connects directly and must not hold a session it will not use.
        if !compress {
            return;
        }
        let conn = self.take_pooled_control(compress);
        *self.primed_control.lock().unwrap() = PrimedControl::Checked(conn.map(Box::new));
    }

    pub(crate) fn helper_command(&self, args: &[String]) -> Command {
        let mut command = self.ssh_command(SshConnection::Independent, false);
        command.arg(self.program_command(args));
        command
    }

    /// A shell command that runs syq with `args` on this host.  Automatic mode
    /// addresses the exact release/build-identified helper; explicit mode preserves the
    /// administrator-provided path; disabling bootstrap uses normal PATH lookup.
    pub fn program_command(&self, args: &[String]) -> String {
        if let Some(p) = &self.syq_path {
            return format!("{} {}", shell_words::quote(p), shell_words::join(args));
        }
        if self.bootstrap_helper {
            return remote_helper::launcher(args);
        }
        format!("syq {}", shell_words::join(args))
    }

    /// `limited`: take a connect slot (data connections). The control
    /// connection passes false: everything waits on it, so it must never
    /// queue behind workers. In managed mode the matching helper is installed
    /// on first use if the remote lacks it.
    pub fn connect_with(&self, compress: bool, limited: bool) -> Result<RemoteConn> {
        let role = if limited {
            ConnectionRole::SourceWorker { roots: Vec::new() }
        } else {
            ConnectionRole::Control
        };
        self.connect_with_role(compress, limited, role, false)
    }

    /// One non-retrying control connection for speculative shell completion.
    /// The caller supplies BatchMode and SSH timeouts in `rsh`; this avoids the
    /// transfer engine's exponential retries while retaining the exact same
    /// managed-helper bootstrap and persistent control socket behavior.
    pub(crate) fn connect_completion(&self) -> Result<RemoteConn> {
        if let Some(conn) = self.take_pooled_control(false) {
            return Ok(conn);
        }
        let role = ConnectionRole::Control;
        let first = self.connect_once(false, SshConnection::Control, role.clone());
        let Err(first_error) = first else {
            return first;
        };
        if !self.bootstrap_helper || !helper_needs_install(&first_error) {
            return Err(first_error);
        }
        self.install_helper()?;
        self.connect_once(false, SshConnection::Control, role)
            .with_context(|| {
                format!(
                    "could not start the {} helper installed on {}",
                    remote_helper::helper_identity(),
                    self.label()
                )
            })
    }

    fn connect_with_role(
        &self,
        compress: bool,
        limited: bool,
        role: ConnectionRole,
        first_worker: bool,
    ) -> Result<RemoteConn> {
        if matches!(role, ConnectionRole::Control) && compress {
            if let Some(conn) = self.take_pooled_control(compress) {
                return Ok(conn);
            }
        }
        let first = self.connect_retried(compress, limited, role.clone(), first_worker);
        let Err(first_error) = first else {
            return first;
        };
        if !self.bootstrap_helper || !helper_needs_install(&first_error) {
            return Err(first_error);
        }

        self.install_helper()?;
        self.connect_retried(compress, limited, role, first_worker)
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
        mut first_worker: bool,
    ) -> Result<RemoteConn> {
        let mut delay = std::time::Duration::from_millis(200);
        let mut last = None;
        // Initial control failures should surface after one SSH invocation.
        // Backoff serves concurrent worker admission (sshd MaxStartups), not
        // repeated authentication or deterministic local configuration errors.
        let attempts = if limited { 6 } else { 1 };
        for attempt in 0..attempts {
            let _slot = limited.then(connect_slot);
            let ssh_connection = self.ssh_connection(limited, first_worker);
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
                    if let Some(multiplexer) = &self.ssh_multiplexer {
                        multiplexer.workers_rejected.store(true, Ordering::Relaxed);
                    }
                    first_worker = false;
                    if crate::transfer::debug() {
                        crate::output::diagnostic!(
                            "syq: {}: multiplexed SSH worker rejected; using independent SSH connections",
                            self.label()
                        );
                    }
                    last = Some(e);
                    continue;
                }
                // Don't retry what won't change: a missing binary or an
                // incompatible protocol/build identity.
                Err(e) if attempt + 1 == attempts || is_non_retryable_connect_error(&e) => {
                    return Err(e)
                }
                Err(e) => {
                    let limit = if limited {
                        Some(tighten_connect_limit())
                    } else {
                        None
                    };
                    if crate::transfer::debug() {
                        crate::output::diagnostic!(
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
        // The receiver child is on this machine, not across the network.
        // Recompressing forwarded blocks here adds CPU work to downloads.
        let compress = compress && !self.local_process;
        let return_stream = if let Some(approved) = &self.forwarded {
            if !matches!(role, ConnectionRole::Control) {
                bail!("copies via a return connection require encrypted TCP workers");
            }
            Some(approved.take_control()?)
        } else if crate::destination::is_named(&self.restricted_grant) {
            Some(crate::destination::connect(
                self.restricted_grant.as_deref().unwrap(),
                matches!(role, ConnectionRole::Control),
            )?)
        } else {
            None
        };
        if let Some(stream) = return_stream {
            let (rx, reader) = spawn_reader(Box::new(stream.try_clone()?), self.read_ahead);
            let conn = RemoteConn {
                child: None,
                w: FrameWriter::new(Box::new(stream.try_clone()?), compress),
                rx: Some(rx),
                reader: Some(reader),
                label: self.label(),
                dead: false,
                write_stream: None,
                peer: None,
                tcp_socket: None,
                named_socket: Some(stream),
                multiplexed_ssh: false,
                detached: false,
            };
            let conn = hello(conn, compress, Vec::new(), role)?;
            self.record_peer(&conn);
            return Ok(conn);
        }
        let mut server_args = vec!["--server".into()];
        if let Some(grant) = &self.restricted_grant {
            if matches!(role, ConnectionRole::Control) {
                server_args.push(format!("--restricted-grant={grant}"));
            } else {
                let ticket = self
                    .diagnostics
                    .lock()
                    .unwrap()
                    .peer
                    .as_ref()
                    .and_then(|peer| peer.ssh_worker_ticket.clone())
                    .context(
                        "restricted receiver did not authorize SSH workers; refresh its enrollment",
                    )?
                    .map_err(anyhow::Error::msg)
                    .context("restricted SSH data transport is unavailable")?;
                server_args.push(format!("--restricted-worker={ticket}"));
            }
        }
        let mut cmd = if self.local_process {
            let mut command = Command::new(std::env::current_exe()?);
            command.args(&server_args);
            command
        } else {
            if self
                .rsh
                .iter()
                .any(|argument| argument == "PubkeyAuthentication=host-bound")
            {
                require_constrained_openssh(&self.rsh[0], "on the coordinator host")?;
            }
            let mut command = self.ssh_command(ssh_connection, crate::transfer::debug());
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
        let (rx, reader) = spawn_reader(Box::new(stdout), self.read_ahead);
        let conn = RemoteConn {
            child: Some(child),
            w: FrameWriter::new(Box::new(stdin), compress),
            rx: Some(rx),
            reader: Some(reader),
            label: self.label(),
            dead: false,
            write_stream: None,
            peer: None,
            tcp_socket: None,
            named_socket: None,
            multiplexed_ssh: ssh_connection == SshConnection::Worker,
            detached: false,
        };
        let conn = hello(conn, compress, Vec::new(), role)?;
        self.record_peer(&conn);
        if ssh_connection == SshConnection::Control
            && !self.local_process
            && self.restricted_grant.is_none()
            && self
                .rsh
                .first()
                .is_some_and(|program| program.ends_with("ssh"))
        {
            crate::completion::remember_endpoint_best_effort(
                self.user.as_deref(),
                &self.host,
                self.port,
            );
            // With persistence on, the next command should find a session
            // ready. The pool is started here, after this connection is up,
            // so it never sits on the critical path.
            if let Some(multiplexer) = &self.ssh_multiplexer {
                if multiplexer.persistent {
                    crate::session_pool::ensure(&multiplexer.path, &self.pool_endpoint());
                    if multiplexer.automatic_receiving {
                        crate::receive_service::ensure(&multiplexer.path, self);
                    }
                }
            }
        }
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
            Some(crate::tcp_records::random_bytes(
                crate::tcp_records::KEY_LEN,
            ))
        };
        let token = crate::tcp_records::random_bytes(16);
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
        validate_advertised_tcp_port(port, ports)?;
        if advertised.len() > MAX_ADVERTISED_TCP_ADDRESSES {
            bail!(
                "TCP listener advertised too many addresses (limit {MAX_ADVERTISED_TCP_ADDRESSES})"
            );
        }
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
                    .position(|candidate| is_overlay_address(&candidate.address))
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
        // coordinator do destination preflight and plan payloads while every
        // candidate receives its complete bounded probe window.
        let probe = std::thread::spawn(move || {
            probe_reachable(&mut candidates, port)?;
            Ok(candidates)
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
            .map_err(|_| anyhow!("TCP route probe thread panicked"))??;
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
            crate::output::diagnostic!(
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
        // Keep network compression, but not on the local receiver's data hop.
        let compress = compress && !self.local_process;
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
                                "coordinator could not configure the connecting data socket to {}",
                                self.label()
                            )
                        })
                    }
                    Err(e) => {
                        last = anyhow!("{}: {e}", crate::transfer::data_address(addr, info.port))
                    }
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
                crate::output::diagnostic!(
                    "syq: {}: data connection via tcp {addr_s}",
                    self.label()
                );
            }
            stream.set_nodelay(true)?;
            let conn_id = next_tcp_connection_id(&TCP_CONN_ID)?;
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
            let (rx, reader) = spawn_reader(Box::new(reader), self.read_ahead);
            let conn = RemoteConn {
                child: None,
                w: FrameWriter::new(Box::new(writer), compress),
                rx: Some(rx),
                reader: Some(reader),
                label: format!("{} (tcp {addr_s})", self.label()),
                dead: false,
                write_stream: None,
                peer: None,
                tcp_socket: Some(tcp_socket),
                named_socket: None,
                multiplexed_ssh: false,
                detached: false,
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
        || message.contains(WIRE_PREAMBLE_PROTOCOL_ERROR)
}

/// Concurrently probe which (addr, speed) entries accept a TCP connection on
/// `port`, preserving the server's priority order. Used once per endpoint.
const MAX_ADVERTISED_TCP_ADDRESSES: usize = 64;
const MAX_RESOLVED_TCP_ADDRESSES: usize = 128;

fn probe_reachable(candidates: &mut [TcpCandidate], port: u16) -> Result<()> {
    // One extra candidate is the coordinator's SSH target.
    if candidates.len() > MAX_ADVERTISED_TCP_ADDRESSES + 1 {
        bail!("too many TCP probe candidates");
    }
    // Resolve candidate names in parallel. More importantly, probe every
    // resolved socket address in parallel too: a dual-stack name must not
    // spend the whole candidate budget timing out on IPv6 before trying IPv4.
    let (resolved_tx, resolved_rx) = std::sync::mpsc::channel();
    for (i, candidate) in candidates.iter().enumerate() {
        let tx = resolved_tx.clone();
        let address = candidate.address.clone();
        std::thread::Builder::new()
            .spawn(move || {
                let addrs = (address.as_str(), port)
                    .to_socket_addrs()
                    .map(|addresses| addresses.take(MAX_RESOLVED_TCP_ADDRESSES + 1).collect())
                    .unwrap_or_default();
                let _ = tx.send((i, addrs));
            })
            .context("start TCP address resolver")?;
    }
    drop(resolved_tx);
    let mut resolved: Vec<Vec<SocketAddr>> = vec![Vec::new(); candidates.len()];
    for _ in 0..candidates.len() {
        let Ok((i, addrs)) = resolved_rx.recv() else {
            break;
        };
        resolved[i] = addrs;
        if resolved.iter().map(Vec::len).sum::<usize>() > MAX_RESOLVED_TCP_ADDRESSES {
            bail!("TCP candidates resolved to too many addresses (limit {MAX_RESOLVED_TCP_ADDRESSES})");
        }
    }

    // Probe each distinct socket address once. An advertised literal and the
    // ssh target name commonly resolve to the same address; one probe answers
    // for every candidate that led there.
    let mut targets: Vec<(SocketAddr, Vec<usize>)> = Vec::new();
    let mut remaining: Vec<usize> = vec![0; candidates.len()];
    for (i, addrs) in resolved.iter().enumerate() {
        for &addr in addrs {
            let owners = match targets.iter_mut().find(|(target, _)| *target == addr) {
                Some((_, owners)) => owners,
                None => {
                    targets.push((addr, Vec::new()));
                    &mut targets.last_mut().unwrap().1
                }
            };
            if !owners.contains(&i) {
                owners.push(i);
                remaining[i] += 1;
            }
        }
    }

    let timeout = std::time::Duration::from_millis(1000);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut undetermined = remaining.iter().filter(|&&count| count > 0).count();
    let mut determined = vec![false; candidates.len()];
    for (t, (addr, _)) in targets.iter().enumerate() {
        let tx = tx.clone();
        let addr = *addr;
        std::thread::Builder::new()
            .spawn(move || {
                let _ = tx.send((t, TcpStream::connect_timeout(&addr, timeout).is_ok()));
            })
            .context("start TCP address probe")?;
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
        let Ok((t, reachable)) = rx.recv_timeout(wait) else {
            break;
        };
        for &i in &targets[t].1 {
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
    Ok(())
}

fn validate_advertised_tcp_port(port: u16, requested: (u16, u16)) -> Result<()> {
    // (0, 0) asks the operating system to allocate an ephemeral port.
    if port == 0 || (requested != (0, 0) && !(requested.0..=requested.1).contains(&port)) {
        bail!(
            "TCP listener advertised port {port} outside requested range {}-{}",
            requested.0,
            requested.1
        );
    }
    Ok(())
}

static TCP_CONN_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

fn next_tcp_connection_id(next: &std::sync::atomic::AtomicU32) -> Result<u32> {
    next.fetch_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |id| (id <= crate::tcp_records::CONNECTION_ID_MAX).then(|| id + 1),
    )
    .map_err(|_| anyhow!("TCP connection IDs exhausted; restart the copy"))
}

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

/// The first request on every connection. The session pool sends it on a
/// command's behalf with a default command's flags.
pub(crate) fn hello_request(
    compress: bool,
    debug: bool,
    token: Vec<u8>,
    role: ConnectionRole,
) -> Request {
    Request::Hello {
        identity: crate::identity::build().to_string(),
        compress,
        debug,
        token,
        role,
    }
}

fn hello(
    mut conn: RemoteConn,
    compress: bool,
    token: Vec<u8>,
    role: ConnectionRole,
) -> Result<RemoteConn> {
    let worker = !matches!(role, ConnectionRole::Control);
    conn.send(hello_request(
        compress,
        crate::transfer::debug(),
        token,
        role,
    ))?;
    receive_hello(conn, worker)
}

fn receive_hello(mut conn: RemoteConn, worker: bool) -> Result<RemoteConn> {
    match conn.recv() {
        Ok(Response::HelloOk {
            identity,
            platform,
            supports_confined_socket_nodes,
            ssh_worker_ticket,
        }) if identity == crate::identity::build() => {
            conn.peer = Some(PeerInfo {
                identity,
                platform,
                supports_confined_socket_nodes,
                ssh_worker_ticket,
            });
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
            "{}: unexpected handshake response {other:?}; remote syq may be a different version",
            conn.label
        ))
            .into())
        }
        Ok(other) => bail!(
            "{}: unexpected handshake response {other:?}; remote syq may be a different version",
            conn.label
        ),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("could not start the remote syq on {}", conn.label))
        }
    }
    Ok(conn)
}

impl RemoteSpec {
    /// Install a matching release asset or upload this source-built executable.
    pub fn install_helper(&self) -> Result<()> {
        let mut installed = self.helper_install.lock().unwrap();
        if *installed {
            return Ok(());
        }

        let bootstrap = self.remote_bootstrap()?;
        let target = bootstrap.target;
        if !self.quiet {
            crate::output::diagnostic!(
                "syq: {}: installing {} helper for {}",
                self.label(),
                remote_helper::helper_identity(),
                target.key
            );
        }
        self.bootstrap_helper(bootstrap).with_context(|| {
            format!(
                "could not install the matching {} helper on {} ({})",
                remote_helper::helper_identity(),
                self.label(),
                target.key
            )
        })?;
        *installed = true;
        Ok(())
    }

    fn remote_bootstrap(&self) -> Result<RemoteBootstrap> {
        let mut cmd = self.ssh_command(SshConnection::Independent, false);
        cmd.arg(remote_helper::probe_command())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_captured(&mut cmd, None)
            .with_context(|| format!("probe platform on {}", self.label()))?;
        if !out.status.success() {
            bail!(
                "could not detect the platform on {} ({}){}",
                self.label(),
                out.status,
                output_suffix(&out.stderr.bytes)
            );
        }
        if out.stdout.truncated {
            bail!(
                "{}: platform probe printed more than {MAX_BOOTSTRAP_OUTPUT_BYTES} bytes",
                self.label()
            );
        }
        let text = String::from_utf8_lossy(&out.stdout.bytes);
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
        let remote_download = text
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
            remote_download,
        })
    }

    fn bootstrap_helper(&self, bootstrap: RemoteBootstrap) -> Result<()> {
        if !crate::identity::is_release_build() {
            if Some(bootstrap.target) != Target::local() {
                bail!(
                    "cannot automatically install a source-built helper for {} from {}; \
                     run syq from a compatible host, use an official release, or install a matching \
                     build on the remote and select it with --syq-path (--rsync-path for syq rsync)",
                    bootstrap.target.key,
                    crate::identity::platform()
                );
            }
            // On Linux this refers to the running image even if a rebuild has
            // replaced or removed its original path.
            #[cfg(target_os = "linux")]
            let executable = std::path::PathBuf::from("/proc/self/exe");
            #[cfg(not(target_os = "linux"))]
            let executable =
                std::env::current_exe().context("locate the running syq executable")?;
            let binary =
                std::fs::read(&executable).context("read the running syq for helper upload")?;
            if !self.quiet {
                crate::output::diagnostic!(
                    "syq: {}: uploading this source build over SSH",
                    self.label()
                );
            }
            // The upload script runs the temporary helper and checks its build
            // identity before renaming it into the cache. OS/CPU agreement alone
            // does not guarantee compatible dynamic libraries or CPU features.
            return self.upload_helper(bootstrap.target, &binary);
        }
        let mut trusted = None;
        if bootstrap.remote_download {
            match self.try_remote_download(bootstrap.target)? {
                RemoteDownloadOutcome::Installed => return Ok(()),
                RemoteDownloadOutcome::Fallback { detail, helper } => {
                    trusted = helper;
                    if !self.quiet {
                        crate::output::diagnostic!(
                            "syq: {}: remote download unavailable{}; uploading the verified helper over SSH",
                            self.label(),
                            parenthesized_detail(&detail)
                        );
                    }
                }
                RemoteDownloadOutcome::Integrity { warning, helper } => {
                    trusted = helper;
                    crate::output::diagnostic!(
                        "syq: warning: {}: {}; the remote download was discarded; uploading the verified helper over SSH",
                        self.label(),
                        warning
                    );
                }
            }
        } else if !self.quiet {
            crate::output::diagnostic!(
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

    fn try_remote_download(&self, target: Target) -> Result<RemoteDownloadOutcome> {
        let script = remote_helper::download_script(target);
        let mut cmd = self.ssh_command(SshConnection::Independent, false);
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
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("remote helper download stderr was not piped"))?;
        let stderr_reader = capture_stream(stderr);

        let report = read_remote_download_report(&mut BufReader::new(stdout));
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
            .map_err(|_| anyhow!("remote helper stderr reader panicked"))?
            .map(|captured| captured.bytes)
            .unwrap_or_default();
        let detail = output_message(&stderr);
        if status.success() {
            write_result.context("authorize the verified remote helper")?;
            return if authorized {
                Ok(RemoteDownloadOutcome::Installed)
            } else {
                Ok(RemoteDownloadOutcome::Fallback {
                    detail: protocol_detail
                        .unwrap_or_else(|| "the remote ignored a discard decision".into()),
                    helper,
                })
            };
        }
        match status.code() {
            Some(remote_helper::REMOTE_DOWNLOAD_FALLBACK_EXIT) => {
                Ok(RemoteDownloadOutcome::Fallback {
                    detail: if detail.is_empty() {
                        protocol_detail.unwrap_or_default()
                    } else {
                        detail
                    },
                    helper,
                })
            }
            Some(remote_helper::REMOTE_DOWNLOAD_INTEGRITY_EXIT) => match integrity_warning {
                Some(warning) => Ok(RemoteDownloadOutcome::Integrity { warning, helper }),
                None => Ok(RemoteDownloadOutcome::Fallback {
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
        let mut cmd = self.ssh_command(SshConnection::Independent, false);
        cmd.arg(format!("sh -c {}", shell_words::quote(&script)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_captured(&mut cmd, Some(binary))
            .with_context(|| format!("run helper upload to {}", self.label()))?;
        if !out.status.success() {
            bail!(
                "remote helper upload exited {}{}",
                out.status,
                output_suffix(&out.stderr.bytes)
            );
        }
        match out.input_error {
            Some(error) => Err(error).with_context(|| format!("upload helper to {}", self.label())),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Copy)]
struct RemoteBootstrap {
    target: Target,
    remote_download: bool,
}

enum RemoteDownloadOutcome {
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
struct RemoteDownloadReport {
    manifest: Vec<u8>,
    sha256: String,
}

/// Bound on each captured stream of a bootstrap command: the platform probe,
/// the remote download report's stderr, and the helper upload. Legitimate
/// output is a few lines; the bound keeps a faulty or hostile remote from
/// growing local memory without limit. Streams are drained past the bound so
/// the child never blocks on a full pipe.
const MAX_BOOTSTRAP_OUTPUT_BYTES: usize = 1024 * 1024;
/// Largest remote release manifest accepted from the download report.
const MAX_MANIFEST_SIZE: usize = 1024 * 1024;
/// Longest report line buffered before it is checked. A manifest data line may
/// carry the whole manifest after its framing prefix.
const MAX_REPORT_LINE_BYTES: usize = MAX_MANIFEST_SIZE + 1024;

struct CapturedStream {
    bytes: Vec<u8>,
    /// The stream produced more than the retained bytes; the rest was discarded.
    truncated: bool,
}

/// Read a stream keeping at most `limit` bytes, then drain and discard the
/// remainder so a child process writing to it never blocks.
fn read_capped(mut reader: impl Read, limit: usize) -> std::io::Result<CapturedStream> {
    let mut bytes = Vec::new();
    reader.by_ref().take(limit as u64).read_to_end(&mut bytes)?;
    let discarded = std::io::copy(&mut reader, &mut std::io::sink())?;
    Ok(CapturedStream {
        bytes,
        truncated: discarded > 0,
    })
}

fn capture_stream(
    reader: impl Read + Send + 'static,
) -> std::thread::JoinHandle<std::io::Result<CapturedStream>> {
    std::thread::spawn(move || read_capped(reader, MAX_BOOTSTRAP_OUTPUT_BYTES))
}

struct CapturedOutput {
    status: std::process::ExitStatus,
    stdout: CapturedStream,
    stderr: CapturedStream,
    /// Writing `input` to the child's stdin failed. Reported after the exit
    /// status, which usually explains why the child stopped reading.
    input_error: Option<std::io::Error>,
}

/// Run a bootstrap command, feeding it `input` when given, with both output
/// streams captured under `MAX_BOOTSTRAP_OUTPUT_BYTES`. The command must have
/// piped stdout and stderr; stdin is piped when there is input.
fn run_captured(cmd: &mut Command, input: Option<&[u8]>) -> Result<CapturedOutput> {
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().context("start command")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("command stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("command stderr was not piped"))?;
    let stdout_reader = capture_stream(stdout);
    let stderr_reader = capture_stream(stderr);
    let input_error = match input {
        Some(bytes) => {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("command stdin was not piped"))?;
            stdin.write_all(bytes).err()
        }
        None => None,
    };
    let status = child.wait().context("wait for command")?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("stdout reader panicked"))?
        .context("read command stdout")?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("stderr reader panicked"))?
        .context("read command stderr")?;
    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
        input_error,
    })
}

/// Read one report line into `line`, refusing lines longer than
/// `MAX_REPORT_LINE_BYTES` before they are buffered in full.
fn read_report_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> std::io::Result<usize> {
    line.clear();
    let read = reader
        .by_ref()
        .take(MAX_REPORT_LINE_BYTES as u64 + 1)
        .read_until(b'\n', line)?;
    if read > MAX_REPORT_LINE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "remote helper report line exceeded the size limit",
        ));
    }
    Ok(read)
}

fn read_remote_download_report(
    reader: &mut impl BufRead,
) -> std::io::Result<Option<RemoteDownloadReport>> {
    let mut line = Vec::new();
    if read_report_line(reader, &mut line)? == 0 {
        return Ok(None);
    }
    if protocol_line(&line) != b"syq-helper-manifest-begin" {
        return Ok(None);
    }

    let mut manifest = Vec::new();
    loop {
        if read_report_line(reader, &mut line)? == 0 {
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

    if read_report_line(reader, &mut line)? == 0 {
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
    if read_report_line(reader, &mut line)? == 0 {
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
    Ok(Some(RemoteDownloadReport { manifest, sha256 }))
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
        self.connect_with_role(compress, ConnectionRole::Control, false)
    }

    pub(crate) fn connect_with_sources(
        &self,
        compress: bool,
        roots: Vec<RegisteredSourceRoot>,
        first_worker: bool,
    ) -> Result<Box<dyn Conn>> {
        self.connect_with_role(
            compress,
            ConnectionRole::SourceWorker { roots },
            first_worker,
        )
    }

    pub(crate) fn connect_with_copy_capabilities(
        &self,
        compress: bool,
        destination: Option<DestinationRoot>,
        copy_sources: Vec<RegisteredSourceRoot>,
        first_worker: bool,
    ) -> Result<Box<dyn Conn>> {
        self.connect_with_role(
            compress,
            ConnectionRole::DestinationWorker {
                destination,
                copy_sources,
            },
            first_worker,
        )
    }

    fn connect_with_role(
        &self,
        compress: bool,
        role: ConnectionRole,
        first_worker: bool,
    ) -> Result<Box<dyn Conn>> {
        match self {
            Endpoint::Local { descriptor_session } => {
                // Coordinator workers use their process-local session. Actual
                // local destinations run in an isolated receiver process, whose
                // spawn path serializes Darwin SCM_RIGHTS claims with exec.
                #[cfg(target_os = "macos")]
                if matches!(&role, ConnectionRole::DestinationWorker { copy_sources, .. } if !copy_sources.is_empty())
                {
                    return Err(WorkerInitializationError(
                        "macOS copy-source claims require an isolated receiver process".into(),
                    )
                    .into());
                }
                let mut conn = LocalConn::new(&role, descriptor_session.clone());
                match role {
                    ConnectionRole::DestinationWorker {
                        destination: Some(destination),
                        copy_sources,
                    } => {
                        conn.ops
                            .initialize_destination(&destination)
                            .map_err(|error| {
                                WorkerInitializationError(format!(
                                    "initialize local destination worker: {error:#}"
                                ))
                            })?;
                        if !copy_sources.is_empty() {
                            conn.ops
                                .initialize_copy_sources(&copy_sources)
                                .map_err(|error| {
                                    WorkerInitializationError(format!(
                                        "initialize local copy sources: {error:#}"
                                    ))
                                })?;
                        }
                    }
                    ConnectionRole::DestinationWorker {
                        destination: None, ..
                    } => {
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
                            if spec.forwarded.is_some() {
                                return Err(e).with_context(|| {
                                    let reason = "TCP data connection failed; return authorization requires direct encrypted TCP and cannot fall back to SSH data";
                                    format!("{}: {reason}", spec.label())
                                });
                            }
                            #[cfg(debug_assertions)]
                            if std::env::var_os("SYQ_TEST_REQUIRE_TCP").is_some() {
                                return Err(e).context("TCP data transport required by test");
                            }
                            let mut g = spec.tcp.lock().unwrap();
                            let mut warning = None;
                            if let Some(i) = g.as_mut() {
                                if !i.failed {
                                    i.failed = true;
                                    i.failure = Some(format!("{e:#}"));
                                    if !spec.quiet || crate::transfer::debug() {
                                        let congestion_note = tcp_congestion_fallback_note(
                                            info.congestion_control.as_deref(),
                                        );
                                        warning = Some(format!("syq: {}: data over ssh (TCP port {} stopped answering: {e:#}{congestion_note})", spec.label(), info.port));
                                    }
                                }
                            }
                            drop(g);
                            if let Some(warning) = warning {
                                crate::output::diagnostic!("{warning}");
                            }
                        }
                    }
                }
                if spec.forwarded.is_some() {
                    let reason =
                        "return authorization has no authorized encrypted TCP data connection";
                    bail!("{}: {reason}", spec.label());
                }
                Ok(Box::new(spec.connect_with_role(
                    compress,
                    true,
                    role,
                    first_worker,
                )?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn advertised_tcp_port_must_match_requested_range() {
        for port in [47_600, 47_650, 47_699] {
            super::validate_advertised_tcp_port(port, (47_600, 47_699)).unwrap();
        }
        for port in [0, 22, 47_599, 47_700, u16::MAX] {
            assert!(super::validate_advertised_tcp_port(port, (47_600, 47_699)).is_err());
        }
        super::validate_advertised_tcp_port(12345, (12345, 12345)).unwrap();
        assert!(super::validate_advertised_tcp_port(12346, (12345, 12345)).is_err());
        // Existing test and local listener callers use (0, 0) for OS allocation.
        for port in [1, 47_650, u16::MAX] {
            super::validate_advertised_tcp_port(port, (0, 0)).unwrap();
        }
        assert!(super::validate_advertised_tcp_port(0, (0, 0)).is_err());
    }

    #[test]
    fn tcp_connection_ids_fail_at_nonce_space_exhaustion() {
        let next = std::sync::atomic::AtomicU32::new(crate::tcp_records::CONNECTION_ID_MAX);
        assert_eq!(super::next_tcp_connection_id(&next).unwrap(), 0x00ff_ffff);
        for _ in 0..3 {
            assert!(super::next_tcp_connection_id(&next)
                .unwrap_err()
                .to_string()
                .contains("restart the copy"));
        }
        assert_eq!(next.load(std::sync::atomic::Ordering::Relaxed), 0x0100_0000);
    }

    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    fn hello_ok() -> Response {
        Response::HelloOk {
            identity: crate::identity::build().into(),
            platform: crate::identity::platform(),
            supports_confined_socket_nodes: crate::identity::supports_confined_socket_nodes(),
            ssh_worker_ticket: None,
        }
    }

    #[test]
    fn client_handshake_limit_applies_before_reading_the_body() {
        let mut wire = Vec::new();
        FrameWriter::new(&mut wire, false).write_preamble().unwrap();
        wire.extend_from_slice(&((MAX_HANDSHAKE_FRAME + 1) as u32).to_le_bytes());
        let (rx, thread) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
        let error = rx.recv().unwrap().unwrap_err();
        assert!(error.to_string().contains("bad frame length"));
        assert!(rx.recv().is_err());
        thread.join().unwrap();
    }

    #[test]
    fn client_handshake_limit_also_bounds_compressed_output() {
        let mut hello = hello_ok();
        if let Response::HelloOk { platform, .. } = &mut hello {
            *platform = "x".repeat(MAX_HANDSHAKE_FRAME + 1);
        }
        let payload = postcard::to_stdvec(&hello).unwrap();
        let body = zstd::bulk::compress(&payload, 1).unwrap();
        let mut wire = Vec::new();
        FrameWriter::new(&mut wire, false).write_preamble().unwrap();
        wire.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
        wire.push(1);
        wire.extend_from_slice(&body);
        let (rx, thread) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
        assert!(rx
            .recv()
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("decompressed frame exceeds limit"));
        thread.join().unwrap();
    }

    #[test]
    fn client_reader_requires_accepted_hello_before_large_data() {
        for accepted in [false, true] {
            let mut wire = Vec::new();
            let mut writer = FrameWriter::new(&mut wire, false);
            let mut hello = hello_ok();
            if let Response::HelloOk { identity, .. } = &mut hello {
                if !accepted {
                    *identity = "wrong-build".into();
                }
            }
            writer.write_msg(&hello).unwrap();
            writer
                .write_msg(&Response::Block {
                    off: 0,
                    hash: [0; 32],
                    data: vec![7; 2 << 20],
                })
                .unwrap();
            drop(writer);
            let (rx, thread) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
            assert!(matches!(
                rx.recv().unwrap().unwrap().value,
                Response::HelloOk { .. }
            ));
            if accepted {
                assert!(
                    matches!(rx.recv().unwrap().unwrap().value, Response::Block { data, .. } if data.len() == 2 << 20)
                );
            } else {
                assert!(rx.recv().is_err());
            }
            drop(rx);
            thread.join().unwrap();
        }
    }

    #[test]
    fn remote_vector_replies_must_match_request_counts() {
        for count in [0, 1, 2] {
            let cases = [
                (
                    Request::StatMany {
                        paths: vec![b"file".to_vec()],
                        sources: None,
                        follow: false,
                        guard: None,
                    },
                    Response::Stats(vec![None; count]),
                ),
                (
                    Request::Apply {
                        ops: vec![Op::Unlink {
                            path: b"file".to_vec(),
                        }],
                        guard: None,
                    },
                    Response::Applied(vec![None; count]),
                ),
                (
                    Request::PartialPaths {
                        paths: vec![b"file".to_vec()],
                        copy_id: [0; 16],
                        guard: None,
                    },
                    Response::PathResults(vec![Ok(b"partial".to_vec()); count]),
                ),
            ];
            for (request, response) in cases {
                let mut bytes = Vec::new();
                let mut writer = FrameWriter::new(&mut bytes, false);
                writer.write_msg(&hello_ok()).unwrap();
                writer.write_msg(&response).unwrap();
                drop(writer);
                let (rx, reader) = spawn_reader(Box::new(std::io::Cursor::new(bytes)), 4);
                let mut conn = RemoteConn {
                    child: None,
                    w: FrameWriter::new(Box::new(std::io::sink()), false),
                    rx: Some(rx),
                    reader: Some(reader),
                    label: "hostile vector reply".into(),
                    dead: false,
                    write_stream: None,
                    peer: None,
                    tcp_socket: None,
                    named_socket: None,
                    multiplexed_ssh: false,
                    detached: false,
                };
                conn = receive_hello(conn, false).unwrap();
                let result = conn.call(request);
                if count == 1 {
                    assert!(result.is_ok());
                } else {
                    assert!(result.unwrap_err().to_string().contains("reply count"));
                }
            }
        }
    }

    #[test]
    fn excessive_probe_candidates_fail_before_resolution() {
        let mut candidates: Vec<_> = (0..MAX_ADVERTISED_TCP_ADDRESSES + 2)
            .map(|_| TcpCandidate {
                address: "must-not-resolve.invalid".into(),
                speed_mbps: 0,
                source: DataAddressSource::RemoteInterface,
                reachable: false,
                selected: false,
            })
            .collect();
        assert!(probe_reachable(&mut candidates, 1)
            .unwrap_err()
            .to_string()
            .contains("too many"));
    }

    struct ExitObserved<R> {
        inner: R,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn coordinator_rejects_darwin_copy_source_claims() {
        let temporary = crate::test_support::tempdir().unwrap();
        let endpoint = Endpoint::local();
        let mut control = endpoint.connect_control(false).unwrap();
        let response = control
            .call(Request::RegisterSourceRoots {
                base: SourceRootBase::default(),
                selections: vec![SourceRootSelection {
                    path: temporary.path().as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                }],
                symlink_policy: OperatorSymlinkPolicy::Refuse,
                allow_unconfined_paths: false,
                shared_workers: 1,
                independent_handoff_workers: 0,
            })
            .unwrap();
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("{response:?}")
        };
        // Removing the broker proves rejection occurs before any foreign claim.
        std::fs::remove_file(roots[0].ticket.broker_path()).unwrap();
        let error = Endpoint::local()
            .connect_with_copy_capabilities(false, None, roots, false)
            .err()
            .expect("in-process Darwin copy sources must be rejected");
        assert!(format!("{error:#}").contains("isolated receiver process"));
    }

    #[test]
    fn local_workers_clone_the_control_descriptor_session_in_process() {
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        let endpoint = Endpoint::local();
        let mut control = endpoint.connect_control(false).unwrap();
        let response = control
            .call(Request::RegisterSourceRoots {
                base: SourceRootBase::default(),
                selections: vec![SourceRootSelection {
                    path: selected.as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                }],
                symlink_policy: OperatorSymlinkPolicy::Refuse,
                allow_unconfined_paths: false,
                shared_workers: 1,
                independent_handoff_workers: 0,
            })
            .unwrap();
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };

        // Once the socket name is gone, an empty session slot cannot claim the
        // ticket with SCM_RIGHTS. The endpoint clone still succeeds because it
        // reaches the control connection's process-local registry instead.
        std::fs::remove_file(roots[0].ticket.broker_path()).unwrap();
        endpoint
            .connect_with_sources(false, roots.clone(), false)
            .unwrap();
        let error = Endpoint::local()
            .connect_with_sources(false, roots, false)
            .err()
            .expect("a fresh local endpoint must not share another session");
        assert!(format!("{error:#}").contains("connect to descriptor broker"));
    }

    #[test]
    fn local_source_worker_rejects_destination_mutation_requests() {
        let temporary = crate::test_support::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        let marker = selected.join("marker");
        std::fs::write(&marker, b"marker").unwrap();
        let endpoint = Endpoint::local();
        let mut control = endpoint.connect_control(false).unwrap();
        let response = control
            .call(Request::RegisterSourceRoots {
                base: SourceRootBase::default(),
                selections: vec![SourceRootSelection {
                    path: selected.as_os_str().as_bytes().to_vec(),
                    follow_root: false,
                }],
                symlink_policy: OperatorSymlinkPolicy::Refuse,
                allow_unconfined_paths: false,
                shared_workers: 1,
                independent_handoff_workers: 0,
            })
            .unwrap();
        let Response::SourceRootsRegistered(roots) = response else {
            panic!("unexpected source registration response: {response:?}")
        };
        let source_marker = roots[0].selection.join(b"marker").unwrap();
        let mut source = endpoint.connect_with_sources(false, roots, false).unwrap();

        let response = source
            .call(Request::ReadRange {
                path: b"contradictory-path".to_vec(),
                source: Some(source_marker.clone()),
                attempt: 0,
                off: 0,
                len: 6,
            })
            .unwrap();
        assert!(matches!(response, Response::Block { data, .. } if data == b"marker"));

        for reference in [Some(source_marker.clone()), None] {
            source
                .send(Request::ReadStream(ReadStreamRequest {
                    path: marker.as_os_str().as_bytes().to_vec(),
                    source: reference.clone(),
                    attempt: 0,
                    off: 0,
                    end: 6,
                    block: 512,
                }))
                .unwrap();
            assert!(matches!(source.recv().unwrap(), Response::Ok));
            let response = source.recv().unwrap();
            if reference.is_some() {
                assert!(matches!(response, Response::Block { data, .. } if data == b"marker"));
            } else {
                assert!(matches!(response, Response::EndpointError(_)));
            }
            assert!(matches!(source.recv().unwrap(), Response::ReadStreamDone));
            source.send(Request::ShrinkReadStream { end: 0 }).unwrap();
            source.send(Request::StopReadStream).unwrap();
            assert!(source.recv().is_err(), "Stop queued a second Done");
        }

        // One-way shrinking does not insert a response before the next block.
        // Preserve the original frame boundary even if the new limit cuts it.
        for end in [3, 0] {
            assert!(matches!(
                source
                    .call(Request::ReadStream(ReadStreamRequest {
                        path: marker.as_os_str().as_bytes().to_vec(),
                        source: Some(source_marker.clone()),
                        attempt: 0,
                        off: 0,
                        end: 6,
                        block: 512,
                    }))
                    .unwrap(),
                Response::Ok
            ));
            let range = std::sync::Arc::new(std::sync::Mutex::new(crate::sched::RangeState {
                idx: 0,
                pos: 0,
                end,
            }));
            let mut announced = 6;
            assert!(
                crate::streaming::notify_shrunk_range(&range, &mut announced, &mut *source)
                    .unwrap()
            );
            assert_eq!(announced, end);
            assert!(
                !crate::streaming::notify_shrunk_range(&range, &mut announced, &mut *source)
                    .unwrap()
            );
            if end > 0 {
                assert!(
                    matches!(source.recv().unwrap(), Response::Block { data, .. } if data == b"marker")
                );
            }
            assert!(matches!(source.recv().unwrap(), Response::ReadStreamDone));
            source.send(Request::StopReadStream).unwrap();
            // Invalid controls are ordinary replies outside stream mode on
            // both local and server connections, not local-only send errors.
            assert!(matches!(
                source.call(Request::ShrinkReadStream { end: 0 }).unwrap(),
                Response::Err(error) if error == "no read stream is active"
            ));
        }

        let response = source
            .call(Request::Apply {
                ops: vec![Op::Unlink {
                    path: marker.as_os_str().as_bytes().to_vec(),
                }],
                guard: None,
            })
            .unwrap();
        assert!(
            matches!(response, Response::Err(error) if error.contains("not valid on a source worker"))
        );
        assert_eq!(std::fs::read(&marker).unwrap(), b"marker");

        let response = source
            .call(Request::ListDir {
                directory: selected.as_os_str().as_bytes().to_vec(),
                confined_root: None,
                prefix: b"mar".to_vec(),
                limit: 10,
                symlink_policy: crate::proto::OperatorSymlinkPolicy::Refuse,
            })
            .unwrap();
        assert!(
            matches!(response, Response::Err(error) if error.contains("only on the control connection"))
        );

        let selection = [NativeRemoveSelection {
            path: b"marker".to_vec(),
            kind: NativeRemoveKind::File,
        }];
        let mut trace = |_| Ok(());
        let mut sink = |_| Ok(());
        let error = source
            .native_remove(
                Some(selected.as_os_str().as_bytes()),
                None,
                &selection,
                false,
                false,
                1,
                &mut trace,
                &mut sink,
            )
            .unwrap_err();
        assert!(error.to_string().contains("only on the control connection"));
        assert_eq!(std::fs::read(&marker).unwrap(), b"marker");

        // Match the remote server's non-control gate for destination workers
        // too; this direct trait method must not be a role bypass.
        let role = ConnectionRole::DestinationWorker {
            destination: None,
            copy_sources: Vec::new(),
        };
        let mut destination = LocalConn::new(&role, Default::default());
        let error = destination
            .native_remove(
                Some(selected.as_os_str().as_bytes()),
                None,
                &selection,
                false,
                false,
                1,
                &mut trace,
                &mut sink,
            )
            .unwrap_err();
        assert!(error.to_string().contains("only on the control connection"));
        assert_eq!(std::fs::read(&marker).unwrap(), b"marker");
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

    #[test]
    fn openssh_version_banners_parse_and_compare() {
        let parse = |banner: &str| parse_openssh_version(banner.as_bytes());
        assert_eq!(
            parse("OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13 30 Jan 2024\n"),
            Some(OpenSshVersion { major: 9, minor: 6 })
        );
        assert_eq!(
            parse("OpenSSH_8.9p1, LibreSSL 3.3.6"),
            Some(CONSTRAINED_OPENSSH_MINIMUM)
        );
        assert_eq!(
            parse("OpenSSH_10.0p2"),
            Some(OpenSshVersion {
                major: 10,
                minor: 0
            })
        );
        assert_eq!(parse("Dropbear v2024.85"), None);
        assert_eq!(parse("OpenSSH_"), None);
        assert!(OpenSshVersion { major: 8, minor: 2 } < CONSTRAINED_OPENSSH_MINIMUM);
        assert!(
            OpenSshVersion {
                major: 8,
                minor: 10
            } > CONSTRAINED_OPENSSH_MINIMUM
        );
        assert!(OpenSshVersion { major: 9, minor: 0 } > CONSTRAINED_OPENSSH_MINIMUM);
        assert_eq!(CONSTRAINED_OPENSSH_MINIMUM.to_string(), "OpenSSH 8.9");
    }

    #[test]
    fn ordinary_range_drain_consumes_errors_but_not_the_next_operation() {
        let mut conn = LocalConn::new(&ConnectionRole::Control, Default::default());
        conn.pending.extend([
            Response::Err("first failed write".into()),
            Response::Err("later failed write".into()),
            Response::Path(b"next operation".to_vec()),
        ]);
        let error = drain_range_replies(&mut conn, 2, "write").unwrap_err();
        assert!(error.to_string().contains("first failed write"));
        assert!(matches!(conn.recv().unwrap(), Response::Path(path) if path == b"next operation"));
        assert!(conn.pending.is_empty());
        conn.begin_streaming_writes().unwrap();
        let fence = conn.fence_streaming_writes();
        conn.finish_streaming_writes(0, fence).unwrap();
    }

    #[test]
    fn inactive_remote_stream_fence_does_not_write_or_take_the_reader() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        struct CountWrites(Arc<AtomicUsize>);
        impl Write for CountWrites {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
        let (_tx, rx) = std::sync::mpsc::channel();
        let writes = Arc::new(AtomicUsize::new(0));
        let mut conn = RemoteConn {
            child: None,
            w: FrameWriter::new(Box::new(CountWrites(writes.clone())), false),
            rx: Some(rx),
            reader: None,
            label: "inactive stream test".into(),
            dead: false,
            write_stream: None,
            peer: None,
            tcp_socket: None,
            named_socket: None,
            multiplexed_ssh: false,
            detached: true,
        };
        let fence = conn.fence_streaming_writes();
        assert!(fence.is_err());
        assert!(conn.finish_streaming_writes(0, fence).is_err());
        assert!(conn.rx.is_some());
        assert!(!conn.dead);
        // Drop normally sends Shutdown; that is outside the operation under test.
        assert_eq!(writes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_old_client_is_not_retried() {
        let error: anyhow::Error = OpenSshVersionError("too old".to_owned()).into();
        assert!(is_non_retryable_connect_error(&error));
        assert!(is_non_retryable_connect_error(
            &error.context("connect to the coordinator")
        ));
        assert!(!is_non_retryable_connect_error(&anyhow!(
            "connection reset"
        )));
    }

    #[test]
    fn only_ssh_named_programs_are_probed_for_a_version() {
        assert_eq!(openssh_version("fake-rsh"), None);
        assert_eq!(openssh_version("/definitely/missing/ssh"), None);
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
                || client_stats.bytes_sent.is_some_and(|value| value > 0),
            "{client_stats:?}"
        );
        assert!(
            server_stats.segments_sent.is_some_and(|value| value > 0)
                || server_stats.bytes_sent.is_some_and(|value| value > 0),
            "{server_stats:?}"
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
    fn connecting_socket_congestion_rejection_is_attributed_to_coordinator() {
        let spec = RemoteSpec {
            local_process: false,
            user: None,
            host: "remote.example".into(),
            port: None,
            rsh: vec!["ssh".into()],
            syq_path: None,
            bootstrap_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
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
            .expect_err("unregistered congestion control should fail locally");
        let message = format!("{error:#}");
        assert!(is_tcp_congestion_error(&error));
        assert!(message.contains(
            "coordinator could not configure the connecting data socket to remote.example"
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
    fn only_the_local_receiver_disables_requested_tcp_compression() {
        for local_process in [false, true] {
            for requested in [false, true] {
                let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
                let port = listener.local_addr().unwrap().port();
                let server = std::thread::spawn(move || {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut id = [0; 4];
                    socket.read_exact(&mut id).unwrap();
                    let mut reader =
                        FrameReader::new(RecordReader::new(socket.try_clone().unwrap(), None));
                    let Request::Hello { compress, .. } = reader.read_msg().unwrap() else {
                        panic!("expected Hello");
                    };
                    let mut writer = FrameWriter::new(RecordWriter::new(socket, None), false);
                    writer.write_msg(&hello_ok()).unwrap();
                    compress
                });
                let mut spec = RemoteSpec::local_receiver(false);
                // Even an explicit SSH endpoint on loopback is not the
                // in-process receiver and keeps the requested compression.
                spec.local_process = local_process;
                let info = TcpInfo {
                    addrs: vec!["127.0.0.1".into()],
                    port,
                    key: None,
                    token: Vec::new(),
                    congestion_control: None,
                    failed: false,
                    failure: None,
                    next: Default::default(),
                };
                let conn = spec
                    .connect_tcp(&info, requested, ConnectionRole::Control)
                    .unwrap();
                let expected = requested && !local_process;
                assert_eq!(conn.w.compress, expected);
                assert_eq!(server.join().unwrap(), expected);
            }
        }
    }

    #[test]
    fn rejected_worker_initialization_is_not_a_retryable_transport_error() {
        let error: anyhow::Error = WorkerInitializationError("destination changed".into()).into();
        assert!(is_worker_initialization_error(&error));
        assert!(!is_tcp_congestion_error(&error));
    }

    #[test]
    fn hello_carries_destination_initialization_before_readiness() {
        let temp = crate::test_support::tempdir().unwrap();
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
                        copy_sources,
                    },
                ..
            } = hello
            else {
                panic!("destination initialization was not carried in Hello");
            };
            assert!(copy_sources.is_empty());
            assert_eq!(destination.request_prefix, b"destination");

            let mut writer = FrameWriter::new(socket, false);
            writer
                .write_msg(&Response::HelloOk {
                    identity: crate::identity::build().to_string(),
                    platform: crate::identity::platform(),
                    supports_confined_socket_nodes: crate::identity::supports_confined_socket_nodes(
                    ),
                    ssh_worker_ticket: None,
                })
                .unwrap();
        });

        let socket = TcpStream::connect(address).unwrap();
        let (rx, reader) = spawn_reader(
            Box::new(socket.try_clone().unwrap()),
            crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        );
        let conn = RemoteConn {
            child: None,
            w: FrameWriter::new(Box::new(socket), false),
            rx: Some(rx),
            reader: Some(reader),
            label: "pipelined hello test".into(),
            dead: false,
            write_stream: None,
            peer: None,
            tcp_socket: None,
            named_socket: None,
            multiplexed_ssh: false,
            detached: false,
        };
        let conn = hello(
            conn,
            false,
            Vec::new(),
            ConnectionRole::DestinationWorker {
                destination: Some(destination),
                copy_sources: Vec::new(),
            },
        )
        .unwrap();
        assert!(conn.peer.is_some());
        drop(conn);
        server.join().unwrap();
        descriptor_session.close();
    }

    #[test]
    fn unexpected_hello_response_reports_version_skew_without_retry() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut reader = FrameReader::new(socket.try_clone().unwrap());
            assert!(matches!(
                reader.read_msg::<Request>().unwrap(),
                Request::Hello { .. }
            ));
            FrameWriter::new(socket, false)
                .write_msg(&Response::Ok)
                .unwrap();
        });

        let socket = TcpStream::connect(address).unwrap();
        let (rx, reader) = spawn_reader(
            Box::new(socket.try_clone().unwrap()),
            crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        );
        let conn = RemoteConn {
            child: None,
            w: FrameWriter::new(Box::new(socket), false),
            rx: Some(rx),
            reader: Some(reader),
            label: "version-skew test".into(),
            dead: false,
            write_stream: None,
            peer: None,
            tcp_socket: None,
            named_socket: None,
            multiplexed_ssh: false,
            detached: false,
        };
        let error = hello(conn, false, Vec::new(), ConnectionRole::Control)
            .expect_err("an operation response is not a valid handshake");
        let message = format!("{error:#}");
        assert!(
            message.contains("unexpected handshake response"),
            "{message}"
        );
        assert!(
            message.contains("remote syq may be a different version"),
            "{message}"
        );
        assert!(is_non_retryable_connect_error(&error));
        server.join().unwrap();
    }

    #[test]
    fn malformed_wire_preamble_is_non_retryable_and_refreshes_a_managed_helper() {
        let error =
            anyhow!("{WIRE_PREAMBLE_PROTOCOL_ERROR}: remote syq sent an invalid build identity");
        assert!(is_non_retryable_connect_error(&error));
        assert!(helper_needs_install(&error));
    }

    #[test]
    fn ssh_exit_255_wins_over_a_missing_wire_preamble() {
        let child = Command::new("/bin/sh")
            .args(["-c", "exit 255"])
            .spawn()
            .unwrap();
        let mut conn = RemoteConn {
            child: Some(child),
            w: FrameWriter::new(Box::new(std::io::sink()), false),
            rx: None,
            reader: None,
            label: "retryable SSH test".into(),
            dead: false,
            write_stream: None,
            peer: None,
            tcp_socket: None,
            named_socket: None,
            multiplexed_ssh: false,
            detached: false,
        };
        let error = conn.io_err(
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("{WIRE_PREAMBLE_PROTOCOL_ERROR}: read header from remote syq"),
            )
            .into(),
        );
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("exit status: 255"), "{diagnostic}");
        assert!(!diagnostic.contains(WIRE_PREAMBLE_PROTOCOL_ERROR));
        assert!(!is_non_retryable_connect_error(&error));
        assert!(!helper_needs_install(&error));
    }

    #[test]
    fn tuning_pipeline_drains_responses_while_sending_large_requests() {
        use std::os::unix::net::UnixStream;
        let (coordinator, helper) = UnixStream::pair().unwrap();
        let timeout = std::time::Duration::from_secs(5);
        for socket in [&coordinator, &helper] {
            socket.set_read_timeout(Some(timeout)).unwrap();
            socket.set_write_timeout(Some(timeout)).unwrap();
        }
        let depth = 64;
        let server = std::thread::spawn(move || {
            let mut requests = FrameReader::new(helper.try_clone().unwrap());
            let mut responses = FrameWriter::new(helper, false);
            responses.write_msg(&hello_ok()).unwrap();
            for _ in 0..depth {
                let Request::ReadRange { off, len, .. } = requests.read_msg().unwrap() else {
                    panic!("expected a range request");
                };
                responses
                    .write_msg(&Response::Block {
                        off,
                        hash: [0; 32],
                        data: vec![7; len as usize],
                    })
                    .unwrap();
            }
        });
        let (responses, reader) = spawn_reader(Box::new(coordinator.try_clone().unwrap()), depth);
        assert!(matches!(
            responses.recv_timeout(timeout).unwrap().unwrap().value,
            Response::HelloOk { .. }
        ));
        let mut requests = FrameWriter::new(coordinator, false);
        // Both directions exceed socket buffering. A reader queue stuck at
        // four responses deadlocks against a sequential helper while the
        // coordinator is still sending its 64 requests.
        for i in 0..depth {
            requests
                .write_msg(&Request::ReadRange {
                    path: vec![b'x'; 16 << 10],
                    source: None,
                    attempt: 0,
                    off: i as u64 * (64 << 10),
                    len: 64 << 10,
                })
                .unwrap();
        }
        for i in 0..depth {
            let response = responses
                .recv_timeout(timeout)
                .unwrap()
                .unwrap()
                .into_inner();
            assert!(matches!(response, Response::Block { off, data, .. }
                if off == i as u64 * (64 << 10) && data == vec![7; 64 << 10]));
        }
        drop(responses);
        drop(requests);
        server.join().unwrap();
        reader.join().unwrap();
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
            let (rx, reader) = spawn_reader(
                Box::new(input),
                crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
            );
            let mut connection = RemoteConn {
                child: None,
                w: FrameWriter::new(Box::new(writer), false),
                rx: Some(rx),
                reader: Some(reader),
                label: "test tcp".into(),
                dead: false,
                write_stream: None,
                peer: None,
                tcp_socket: Some(tcp_socket),
                named_socket: None,
                multiplexed_ssh: false,
                detached: false,
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
    fn hostile_scan_cannot_deliver_excluded_entries_to_the_planner() {
        for (path, patterns, allowed) in [
            (b".env".as_slice(), vec![".env"], false),
            (
                b"ignored/keep/file",
                vec!["ignored/", "!ignored/keep/file"],
                false,
            ),
            (b"logs/keep/file", vec!["logs/*", "!logs/keep/"], true),
            (b"nested/.env", vec!["/.env"], true),
        ] {
            let mut wire = Vec::new();
            let mut writer = FrameWriter::new(&mut wire, false);
            writer.write_msg(&hello_ok()).unwrap();
            let mut root = entry(b"");
            root.kind = Kind::Dir;
            writer.write_msg(&Response::ScanBatch(vec![root])).unwrap();
            // No excluded ancestor is sent. Filtering must not depend on the
            // source's claimed tree order or on previous batches.
            writer
                .write_msg(&Response::ScanBatch(vec![entry(path)]))
                .unwrap();
            writer.write_msg(&Response::ScanDone).unwrap();
            drop(writer);
            let (rx, reader) = spawn_reader(Box::new(std::io::Cursor::new(wire)), 4);
            let mut remote = RemoteConn {
                child: None,
                w: FrameWriter::new(Box::new(Vec::new()), false),
                rx: Some(rx),
                reader: Some(reader),
                label: "hostile source".into(),
                dead: false,
                write_stream: None,
                peer: None,
                tcp_socket: None,
                named_socket: None,
                multiplexed_ssh: false,
                detached: false,
            };
            remote = receive_hello(remote, false).unwrap();
            let mut planned = Vec::new();
            let result = remote.scan(
                b"source",
                None,
                false,
                &patterns.into_iter().map(String::from).collect::<Vec<_>>(),
                false,
                &mut |entries| {
                    planned.extend(entries.into_iter().map(|e| e.path));
                    Ok(())
                },
                &mut |_| Ok(()),
                &mut |_| {},
            );
            assert_eq!(result.is_ok(), allowed, "{path:?}: {result:?}");
            assert_eq!(planned.contains(&path.to_vec()), allowed);
            if !allowed {
                assert!(format!("{:#}", result.unwrap_err()).contains("excluded path"));
            }
        }
    }

    #[test]
    fn remote_scan_paths_are_rooted_and_normalized() {
        let mut saw_root = false;
        validate_remote_scan_batch(&[entry(b""), entry(b"dir/file")], &mut saw_root, None).unwrap();
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
            assert!(validate_remote_scan_batch(&[entry(bad)], &mut saw_root, None).is_err());
        }
    }

    #[test]
    fn remote_scan_requires_exactly_one_leading_root() {
        let mut saw_root = false;
        assert!(validate_remote_scan_batch(&[entry(b"file")], &mut saw_root, None).is_err());

        let mut saw_root = true;
        assert!(validate_remote_scan_batch(&[entry(b"")], &mut saw_root, None).is_err());
    }

    #[test]
    fn remote_download_report_rejects_an_oversized_line() {
        let mut input = b"syq-helper-manifest-begin\nsyq-helper-manifest-data:".to_vec();
        input.resize(input.len() + MAX_REPORT_LINE_BYTES + 16, b'x');
        let error = read_remote_download_report(&mut input.as_slice()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("line exceeded"), "{error}");
    }

    #[test]
    fn capped_reads_keep_the_prefix_and_drain_the_rest() {
        let captured = read_capped(std::io::repeat(b'x').take(5000), 100).unwrap();
        assert_eq!(captured.bytes.len(), 100);
        assert!(captured.truncated);
        let captured = read_capped(&b"short"[..], 100).unwrap();
        assert_eq!(captured.bytes, b"short");
        assert!(!captured.truncated);
    }

    #[test]
    fn captured_commands_bound_both_streams_and_feed_input() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("cat >/dev/null; head -c 3000000 /dev/zero; echo boom >&2; exit 3")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_captured(&mut cmd, Some(b"input")).unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout.bytes.len(), MAX_BOOTSTRAP_OUTPUT_BYTES);
        assert!(out.stdout.truncated);
        assert_eq!(out.stderr.bytes, b"boom\n");
        assert!(!out.stderr.truncated);
        assert!(out.input_error.is_none());
    }

    #[test]
    fn remote_download_report_frames_manifest_and_digest() {
        let digest = "a".repeat(64);
        let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{\nsyq-helper-manifest-data:  \"schema\": 1\nsyq-helper-manifest-data:}}\nsyq-helper-manifest-end\nsyq-helper-sha256:{digest}\nsyq-helper-report-end\n"
        );
        let report = read_remote_download_report(&mut bytes.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(report.manifest, b"{\n  \"schema\": 1\n}\n");
        assert_eq!(report.sha256, digest);
    }

    #[test]
    fn remote_download_report_rejects_unterminated_manifest() {
        let error = read_remote_download_report(
            &mut b"syq-helper-manifest-begin\nsyq-helper-manifest-data:{\"schema\":1}\n".as_slice(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn remote_download_report_keeps_injected_markers_inside_the_manifest() {
        let spoofed = "a".repeat(64);
        let actual = "b".repeat(64);
        let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{\"schema\":1}}\nsyq-helper-manifest-data:syq-helper-manifest-end\nsyq-helper-manifest-data:syq-helper-sha256:{spoofed}\nsyq-helper-manifest-end\nsyq-helper-sha256:{actual}\nsyq-helper-report-end\n"
        );
        let report = read_remote_download_report(&mut bytes.as_bytes())
            .unwrap()
            .unwrap();
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
    fn remote_download_report_rejects_data_after_the_digest() {
        let digest = "a".repeat(64);
        let bytes = format!(
            "syq-helper-manifest-begin\nsyq-helper-manifest-data:{{}}\nsyq-helper-manifest-end\nsyq-helper-sha256:{digest}\nunexpected\nsyq-helper-report-end\n"
        );
        let error = read_remote_download_report(&mut bytes.as_bytes()).unwrap_err();
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
            bootstrap_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        };
        let command = spec.ssh_command(SshConnection::Independent, false);
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
            .ssh_command(SshConnection::Independent, false)
            .get_args()
            .any(|arg| arg == OsStr::new("StrictHostKeyChecking=yes")));
    }

    #[test]
    fn worker_tcp_fallback_survives_broken_stderr() {
        if !crate::test_support::with_broken_stderr(
            "conn::tests::worker_tcp_fallback_survives_broken_stderr",
        ) {
            return;
        }
        let temporary = crate::test_support::tempdir().unwrap();
        let marker = temporary.path().join("ssh-attempted");
        let spec = RemoteSpec {
            local_process: false,
            user: None,
            host: "unused".into(),
            port: None,
            // The shell records that fallback was reached, then reports a
            // missing helper so no retry or real SSH connection is needed.
            rsh: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!(
                    "touch {}; exit 127",
                    shell_words::quote(marker.to_str().unwrap())
                ),
            ],
            syq_path: None,
            bootstrap_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: None,
            quiet: false,
            tcp: std::sync::Arc::new(std::sync::Mutex::new(Some(TcpInfo {
                addrs: vec!["invalid address".into()], // Fail resolution without DNS or a socket.
                port: 0,
                key: None,
                token: Vec::new(),
                congestion_control: None,
                failed: false,
                failure: None,
                next: Default::default(),
            }))),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        };
        let endpoint = Endpoint::Remote(spec.clone());
        assert!(endpoint
            .connect_with_role(
                false,
                ConnectionRole::SourceWorker { roots: Vec::new() },
                false
            )
            .is_err());
        assert!(marker.exists(), "worker never attempted SSH fallback");
        assert!(spec.tcp.lock().unwrap().as_ref().unwrap().failed);
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
            bootstrap_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: Some(multiplexer),
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        };
        let args = |connection| {
            spec.ssh_command(connection, false)
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

        let worker = args(spec.ssh_connection(true, false));
        assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
        assert!(worker.iter().any(|arg| arg == "ControlPath=none"));

        let first = args(spec.ssh_connection(true, true));
        assert!(first
            .windows(2)
            .any(|pair| pair[0] == "-S" && pair[1] == control_path));
        assert!(!first.iter().any(|arg| arg == "ControlPath=none"));
        assert_eq!(spec.ssh_connection(false, true), SshConnection::Control);
        // The first worker's preference is per call, not an opt-in for peers.
        assert_eq!(spec.ssh_connection(true, false), SshConnection::Independent);
        let mut custom = spec.clone();
        custom.ssh_multiplexer = None;
        assert_eq!(
            custom.ssh_connection(true, true),
            SshConnection::Independent
        );

        spec.set_ssh_multiplexing(true);
        let worker = args(spec.ssh_connection(true, false));
        assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
        assert!(worker
            .windows(2)
            .any(|pair| pair[0] == "-S" && pair[1] == control_path));
        assert!(!worker.iter().any(|arg| arg == "ControlPath=none"));

        let independent = args(SshConnection::Independent);
        assert!(independent.iter().any(|arg| arg == "ControlPath=none"));
    }

    #[test]
    fn first_ssh_worker_retries_independently_after_mux_rejection() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = crate::test_support::tempdir().unwrap();
        let script = temporary.path().join("ssh");
        let log = temporary.path().join("attempts");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nfor arg do\n  if [ \"$arg\" = -S ]; then\n    echo shared >> {log}\n    exit 255\n  fi\ndone\necho independent >> {log}\nexit 127\n",
                log = shell_words::quote(log.to_str().unwrap()),
            ),
        ).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut spec = RemoteSpec::local_receiver(true);
        spec.local_process = false;
        spec.rsh = vec![script.to_string_lossy().into_owned()];
        spec.ssh_multiplexer = Some(std::sync::Arc::new(SshMultiplexer::new().unwrap()));
        let result = spec.connect_retried(
            false,
            true,
            ConnectionRole::SourceWorker { roots: Vec::new() },
            true,
        );
        assert!(result.is_err()); // The independent attempt reports a missing helper.
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "shared\nindependent\n"
        );
        // Another startup worker's per-call preference must not override a
        // rejection already observed by a peer sharing this control session.
        let peer = spec.clone();
        peer.set_ssh_multiplexing(true);
        assert_eq!(peer.ssh_connection(true, true), SshConnection::Independent);
        assert_eq!(peer.ssh_connection(true, false), SshConnection::Independent);
        assert_eq!(peer.ssh_connection(false, true), SshConnection::Control);
    }

    #[test]
    fn a_pool_appearing_after_priming_is_not_queried_during_connect() {
        use std::os::unix::net::UnixListener;
        let directory = tempfile::tempdir_in("/tmp").unwrap();
        let scope = directory.path().join("scope");
        crate::persistence::initialize_scope(&scope).unwrap();
        let multiplexer = SshMultiplexer::persistent(&scope, None, "example", None).unwrap();
        let socket = crate::session_pool::socket_path(&multiplexer.path);
        let mut spec = RemoteSpec::local_receiver(true);
        spec.local_process = false;
        spec.rsh = vec!["ssh".into()];
        spec.ssh_multiplexer = Some(std::sync::Arc::new(multiplexer));

        // The pool is absent during the main-thread prime, then starts
        // before the parallel connect. The cloned spec must keep that miss.
        spec.prime_pooled_control(true);
        let listener = UnixListener::bind(socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(spec.clone().take_pooled_control(true).is_none());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn persistent_reuse_uses_auto_master_and_never_shares_with_workers() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir_in("/tmp").unwrap();
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
            bootstrap_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: Some(std::sync::Arc::new(multiplexer)),
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        };
        let args = |connection| {
            spec.ssh_command(connection, false)
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        let control = args(SshConnection::Control);
        assert!(control.iter().any(|arg| arg == "ControlMaster=auto"));
        assert!(control
            .windows(2)
            .any(|pair| pair[0] == "-S" && pair[1] == control_path));
        assert!(control.iter().any(|arg| arg == "ControlPersist=300"));
        // Worker data channels never ride a cross-run master, even when the
        // small-file path asks for in-run multiplexing.
        spec.set_ssh_multiplexing(true);
        let worker = args(spec.ssh_connection(true, false));
        assert!(worker.iter().any(|arg| arg == "ControlMaster=no"));
        assert!(worker.iter().any(|arg| arg == "ControlPath=none"));
        assert_eq!(spec.ssh_connection(true, true), SshConnection::Independent);
    }

    #[test]
    fn verbose_ssh_is_limited_to_nonpersistent_unrestricted_helpers() {
        let mut spec = RemoteSpec::local_receiver(false);
        spec.rsh = vec!["ssh".into()];
        let verbose = |spec: &RemoteSpec, diagnostics| {
            spec.ssh_command(SshConnection::Control, diagnostics)
                .get_args()
                .any(|arg| arg == "-v")
        };
        assert!(verbose(&spec, true));
        assert!(!verbose(&spec, false)); // Bootstrap does not request verbosity.
        spec.restricted_grant = Some("test-authorization".into());
        assert!(!verbose(&spec, true));
        spec.restricted_grant = None;
        spec.ssh_multiplexer = Some(std::sync::Arc::new(SshMultiplexer {
            _directory: None,
            path: PathBuf::from("/tmp/syq-test-socket"),
            persistent: true,
            idle_timeout: "300",
            automatic_receiving: false,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
        }));
        assert!(!verbose(&spec, true));
        assert!(!spec
            .ssh_command(SshConnection::Independent, true)
            .get_args()
            .any(|arg| arg == "-v"));
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
            idle_timeout: "300",
            automatic_receiving: false,
            reuse_for_workers: AtomicBool::new(false),
            workers_rejected: AtomicBool::new(false),
        };
        let spec = RemoteSpec {
            local_process: false,
            user: None,
            host: "example".into(),
            port: None,
            rsh: vec!["ssh".into()],
            syq_path: None,
            bootstrap_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            ssh_multiplexer: Some(std::sync::Arc::new(multiplexer)),
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
            primed_control: Default::default(),
            forwarded: None,
            read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
        };

        let command = spec.ssh_command(SshConnection::Control, false);
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

    #[test]
    fn probe_reachable_probes_each_socket_address_once() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let via_localhost = ("localhost", port)
            .to_socket_addrs()
            .map(|mut it| it.any(|a| a.ip() == std::net::Ipv4Addr::LOCALHOST))
            .unwrap_or(false);
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        std::thread::spawn(move || {
            while let Ok((_stream, _)) = listener.accept() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        let candidate = |address: &str| TcpCandidate {
            address: address.to_string(),
            speed_mbps: 0,
            source: DataAddressSource::RemoteInterface,
            reachable: false,
            selected: false,
        };
        let mut candidates = vec![
            candidate("127.0.0.1"),
            candidate("localhost"),
            candidate("127.0.0.1"),
        ];
        probe_reachable(&mut candidates, port).unwrap();
        assert!(candidates[0].reachable);
        assert!(candidates[2].reachable);
        assert_eq!(candidates[1].reachable, via_localhost);
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn overlay_addresses_are_recognized_in_both_families() {
        assert!(is_overlay_address("100.101.102.103"));
        assert!(is_overlay_address("fd7a:115c:a1e0::1234"));
        assert!(!is_overlay_address("100.1.2.3"));
        assert!(!is_overlay_address("fdaa:0:1:a7b::2"));
        assert!(!is_overlay_address("192.168.1.2"));
        assert!(!is_overlay_address("gpu01.example.net"));
    }
}
