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

mod bootstrap;
mod local;
mod ssh_multiplexer;
mod tcp_socket;

#[cfg(test)]
use bootstrap::*;
pub(crate) use local::*;
pub(crate) use ssh_multiplexer::*;
pub(crate) use tcp_socket::*;

pub trait Conn: Send {
    fn observe(
        &mut self,
        _observations: &crate::transfer_observations::Observations,
        _actor: &std::sync::Arc<crate::transfer_observations::Actor>,
        _source: bool,
        _worker_id: usize,
    ) -> Result<()> {
        Ok(())
    }
    fn send(&mut self, req: Request) -> Result<()>;
    fn recv(&mut self) -> Result<Response>;
    /// Wait before the reply starts, excluding its remaining payload transfer
    /// when the connection can observe arrival separately from decoding.
    fn recv_with_wait(&mut self) -> Result<(Response, std::time::Duration)> {
        let start = std::time::Instant::now();
        let response = self.recv()?;
        Ok((response, start.elapsed()))
    }
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
            Request::StatMany { paths, .. } | Request::PruneLookup { paths, .. } => {
                Some(("stat", paths.len()))
            }
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
    drain_range_replies_with(conn, 0..count, what, |_| {})
}

pub(crate) fn drain_range_replies_with<T>(
    conn: &mut dyn Conn,
    pending: impl IntoIterator<Item = T>,
    what: &str,
    mut acknowledged: impl FnMut(T),
) -> Result<()> {
    let mut error = None;
    for item in pending {
        anyhow::ensure!(!conn.is_dead(), "cannot drain a failed range transport");
        let response = conn.recv()?;
        if let Err(failure) = ok(response, what) {
            error.get_or_insert(failure);
        } else {
            acknowledged(item);
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

#[derive(Clone)]
struct RpcObservation {
    actor: std::sync::Arc<crate::transfer_observations::Actor>,
    source: bool,
}
impl RpcObservation {
    fn span(&self, sending: bool) -> crate::transfer_observations::Span {
        use crate::transfer_observations::Stage;
        self.actor.span(match (self.source, sending) {
            (true, true) => Stage::SourceRequest,
            (true, false) => Stage::SourceResponse,
            (false, true) => Stage::DestinationSend,
            (false, false) => Stage::DestinationAck,
        })
    }
}
/// A decoded reply keeps its memory reservation and local arrival timestamp
/// together while queued, including through the streaming reply collector.
#[derive(Debug)]
pub(crate) struct ReceivedResponse {
    pub(crate) value: Response,
    hold: crate::wire_budget::Hold,
    started_at: std::time::Instant,
}

impl ReceivedResponse {
    pub(crate) fn from_frame(
        (message, started_at): (crate::wire_budget::Budgeted<Response>, std::time::Instant),
    ) -> Self {
        let (value, hold) = message.into_parts();
        Self {
            value,
            hold,
            started_at,
        }
    }

    fn into_inner(self) -> Response {
        self.value
    }

    pub(crate) fn into_parts(self) -> (Response, crate::wire_budget::Hold) {
        (self.value, self.hold)
    }
}

pub struct RemoteConn {
    rpc_observation: Option<RpcObservation>,
    observation: std::sync::Arc<crate::transfer_observations::RemoteSample>,
    child: Option<Child>,
    w: FrameWriter<Box<dyn Write + Send>>,
    /// Responses are parsed on a reader thread so the network keeps flowing
    /// while the caller processes the previous one.
    rx: Option<std::sync::mpsc::Receiver<std::io::Result<ReceivedResponse>>>,
    reader: Option<std::thread::JoinHandle<()>>,
    label: String,
    dead: bool,
    peer: Option<PeerInfo>,
    tcp_socket: Option<std::sync::Arc<TcpStream>>,
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

#[cfg(test)]
fn spawn_reader(
    input: Box<dyn Read + Send>,
    read_ahead: usize,
) -> (
    std::sync::mpsc::Receiver<std::io::Result<ReceivedResponse>>,
    std::thread::JoinHandle<()>,
) {
    spawn_observed_reader(input, read_ahead, Default::default())
}
fn spawn_observed_reader(
    input: Box<dyn Read + Send>,
    read_ahead: usize,
    observation: std::sync::Arc<crate::transfer_observations::RemoteSample>,
) -> (
    std::sync::mpsc::Receiver<std::io::Result<ReceivedResponse>>,
    std::thread::JoinHandle<()>,
) {
    // Control requests also pipeline up to the default depth. Keeping that
    // capacity prevents a sequential helper blocking on replies while its
    // coordinator is still sending requests (including large path batches).
    let (tx, rx) = std::sync::mpsc::sync_channel(
        read_ahead.max(crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH),
    );
    let reader = std::thread::spawn(move || {
        let mut r = FrameReader::new(input);
        r.set_limit(MAX_HANDSHAKE_FRAME);
        let hello = r
            .read_budgeted_with_start::<Response>()
            .map(ReceivedResponse::from_frame);
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
            let msg = r
                .read_budgeted_with_start::<Response>()
                .map(ReceivedResponse::from_frame);
            if let Ok(message) = &msg {
                if let Response::TransportStats(stats) = &message.value {
                    if let Some(value) = &stats.observation {
                        let mut value = value.clone();
                        value.tcp = stats.tcp.clone();
                        observation.update(value);
                    }
                    if !stats.solicited {
                        continue;
                    }
                }
            }
            let failed = msg.is_err();
            if tx.send(msg).is_err() || failed {
                break;
            }
        }
    });
    (rx, reader)
}

fn receive_transport_stats(
    rx: &std::sync::mpsc::Receiver<std::io::Result<ReceivedResponse>>,
    timeout: std::time::Duration,
) -> Option<TcpSocketStats> {
    match rx
        .recv_timeout(timeout)
        .map(|result| result.map(ReceivedResponse::into_inner))
    {
        Ok(Ok(Response::TransportStats(stats))) => stats.tcp,
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
        let observation =
            std::sync::Arc::new(crate::transfer_observations::RemoteSample::default());
        let (rx, reader) = spawn_observed_reader(
            Box::new(session.stdout),
            crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
            observation.clone(),
        );
        let mut stderr = session.stderr;
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut stderr, &mut std::io::stderr());
        });
        RemoteConn {
            observation,
            child: None,
            w: FrameWriter::with_preamble_written(Box::new(session.stdin), compress),
            rx: Some(rx),
            reader: Some(reader),
            label,
            dead: false,
            rpc_observation: None,
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
        let local = self.tcp_socket.as_deref().and_then(tcp_socket_stats);
        *self.observation.final_tcp.lock().unwrap() = local.clone();
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

    fn receive_response(&mut self) -> Result<ReceivedResponse> {
        let _wait = self.rpc_observation.as_ref().map(|o| o.span(false));
        match self
            .rx
            .as_ref()
            .context("response reader is collecting streaming writes")?
            .recv()
        {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(e)) => Err(self.io_err(e.into())),
            Err(_) => Err(self.io_err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "reader stopped").into(),
            )),
        }
    }
}

impl Conn for RemoteConn {
    fn observe(
        &mut self,
        observations: &crate::transfer_observations::Observations,
        actor: &std::sync::Arc<crate::transfer_observations::Actor>,
        source: bool,
        worker_id: usize,
    ) -> Result<()> {
        let subscribe = self.rpc_observation.is_none();
        if subscribe {
            observations.remote(
                format!(
                    "{} worker {worker_id}:{}",
                    if source { "source" } else { "destination" },
                    self.label
                ),
                self.observation.clone(),
                self.tcp_socket.as_ref().map(std::sync::Arc::downgrade),
            );
        }
        self.rpc_observation = Some(RpcObservation {
            actor: actor.clone(),
            source,
        });
        // Pool entries are handed out once; Drop shuts down this helper rather
        // than returning a subscribed session for another command.
        // Subscribe only while this newly attached connection has no pending
        // data replies. The reader consumes later unsolicited stats separately.
        if subscribe
            && !observations
                .remote_subscription_failed
                .load(Ordering::Relaxed)
        {
            match self
                .send(Request::TransportStats)
                .and_then(|()| self.recv())
            {
                Ok(Response::TransportStats(_)) => {}
                Ok(_) => crate::output::diagnostic!(
                    "syq: {}: telemetry unavailable; continuing copy",
                    self.label
                ),
                Err(error) => {
                    // Lost framing cannot be ignored. Let the normal connection
                    // recovery reopen it, without repeating the subscription.
                    observations
                        .remote_subscription_failed
                        .store(true, Ordering::Relaxed);
                    crate::output::diagnostic!(
                        "syq: {}: telemetry connection failed; recovering without remote telemetry",
                        self.label
                    );
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn send(&mut self, req: Request) -> Result<()> {
        let _wait = self.rpc_observation.as_ref().map(|o| o.span(true));
        anyhow::ensure!(
            self.write_stream.is_none()
                || matches!(req, Request::WriteRange { .. } | Request::WriteStreamFence),
            "only writes and their fence are valid during streaming writes"
        );
        self.w.write_msg(&req).map_err(|e| self.io_err(e.into()))
    }
    fn recv(&mut self) -> Result<Response> {
        self.receive_response().map(ReceivedResponse::into_inner)
    }
    fn recv_with_wait(&mut self) -> Result<(Response, std::time::Duration)> {
        let start = std::time::Instant::now();
        let response = self.receive_response()?;
        let waited = response.started_at.saturating_duration_since(start);
        Ok((response.into_inner(), waited))
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
        let _wait = self.rpc_observation.as_ref().map(|o| o.span(false));
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
            .as_deref()
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
    /// still filling its pipeline. Readers also reserve the default depth
    /// for pipelined control lookups.
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
                if crate::output::debug() {
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
                if crate::output::debug() {
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
                    if crate::output::debug() {
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
                    if crate::output::debug() {
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
            let observation =
                std::sync::Arc::new(crate::transfer_observations::RemoteSample::default());
            let (rx, reader) = spawn_observed_reader(
                Box::new(stream.try_clone()?),
                self.read_ahead,
                observation.clone(),
            );
            let conn = RemoteConn {
                observation,
                child: None,
                w: FrameWriter::new(Box::new(stream.try_clone()?), compress),
                rx: Some(rx),
                reader: Some(reader),
                label: self.label(),
                dead: false,
                rpc_observation: None,
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
            let mut command = self.ssh_command(ssh_connection, crate::output::debug());
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
        let observation =
            std::sync::Arc::new(crate::transfer_observations::RemoteSample::default());
        let (rx, reader) =
            spawn_observed_reader(Box::new(stdout), self.read_ahead, observation.clone());
        let conn = RemoteConn {
            observation,
            child: Some(child),
            w: FrameWriter::new(Box::new(stdin), compress),
            rx: Some(rx),
            reader: Some(reader),
            label: self.label(),
            dead: false,
            rpc_observation: None,
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
        if crate::output::debug() {
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
                    Err(e) => last = anyhow!("{}: {e}", data_address(addr, info.port)),
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
            if crate::output::debug() {
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
            let observation =
                std::sync::Arc::new(crate::transfer_observations::RemoteSample::default());
            let (rx, reader) =
                spawn_observed_reader(Box::new(reader), self.read_ahead, observation.clone());
            let conn = RemoteConn {
                observation,
                child: None,
                w: FrameWriter::new(Box::new(writer), compress),
                rx: Some(rx),
                reader: Some(reader),
                label: format!("{} (tcp {addr_s})", self.label()),
                dead: false,
                rpc_observation: None,
                write_stream: None,
                peer: None,
                tcp_socket: Some(std::sync::Arc::new(tcp_socket)),
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
    conn.send(hello_request(compress, crate::output::debug(), token, role))?;
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
                // run_transfer substitutes an isolated receiver for every
                // destination before opening workers, on every platform.
                let mut conn = LocalConn::new(&role, descriptor_session.clone());
                match role {
                    ConnectionRole::DestinationWorker { .. } => {
                        unreachable!("destination workers require an isolated receiver")
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
                                    if !spec.quiet || crate::output::debug() {
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

pub(crate) fn parse_ports(s: &str) -> Result<(u16, u16)> {
    let (a, b) = s.split_once('-').unwrap_or((s, s));
    let lo: u16 = a
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bad port range {s:?}"))?;
    let hi: u16 = b
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("bad port range {s:?}"))?;
    if hi < lo {
        bail!("bad port range {s:?}");
    }
    Ok((lo, hi))
}

pub(crate) fn data_address(address: &str, port: u16) -> String {
    if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

#[cfg(test)]
mod tests;
