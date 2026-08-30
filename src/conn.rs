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
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};

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
        follow_root: bool,
        ignore: &[String],
        report_ignored: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        warn: &mut dyn FnMut(String),
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
}

impl LocalConn {
    pub fn new() -> Self {
        LocalConn {
            ops: FsOps::new(),
            pending: VecDeque::new(),
        }
    }
}

impl Conn for LocalConn {
    fn send(&mut self, req: Request) -> Result<()> {
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
        follow_root: bool,
        ignore: &[String],
        report_ignored: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        crate::scan::scan(
            &fsops::resolve(root),
            follow_root,
            ignore,
            report_ignored,
            sink,
            ignored,
            warn,
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
    fn transport_stats(&mut self) -> Option<TcpPairStats> {
        self.transport_stats_with_timeout(TRANSPORT_STATS_TIMEOUT)
    }
    fn scan(
        &mut self,
        root: &[u8],
        follow_root: bool,
        ignore: &[String],
        report_ignored: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        ignored: &mut dyn FnMut(Vec<PathBytes>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        self.send(Request::Scan {
            root: root.to_vec(),
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
    pub candidates: Vec<TcpCandidate>,
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

#[derive(Clone, Debug)]
pub struct RemoteSpec {
    pub user: Option<String>,
    pub host: String,
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
    /// `-q`: suppress the "falling back to ssh" notice.
    pub quiet: bool,
    /// Shared across clones so workers see the TCP setup done on the control connection.
    pub tcp: std::sync::Arc<std::sync::Mutex<Option<TcpInfo>>>,
    /// User-facing facts gathered by the same connection path the transfer uses.
    pub diagnostics: std::sync::Arc<std::sync::Mutex<RemoteDiagnostics>>,
}

impl RemoteSpec {
    pub fn label(&self) -> String {
        match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
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

    fn ssh_command(&self) -> Command {
        let mut cmd = Command::new(&self.rsh[0]);
        cmd.args(&self.rsh[1..]);
        if self.rsh[0].ends_with("ssh") {
            // Data connections must not share one TCP stream / cipher process,
            // and AES-GCM is much faster than OpenSSH's default chacha20 on
            // CPUs with AES-NI. The list still includes the defaults so
            // negotiation never fails.
            cmd.args([
                "-o",
                "ControlMaster=no",
                "-o",
                "ControlPath=none",
                "-o",
                CIPHERS,
            ]);
            if let Some(u) = &self.user {
                cmd.args(["-l", u]);
            }
            cmd.arg("--");
        } else if let Some(u) = &self.user {
            cmd.args(["-l", u]);
        }
        cmd.arg(&self.host);
        cmd
    }

    /// A shell command that runs syq with `args` on this host.  Automatic mode
    /// addresses the exact release/build-identified helper; explicit mode preserves the
    /// administrator-provided path; --no-bootstrap uses normal PATH lookup.
    pub fn program_command(&self, args: &[String]) -> String {
        if let Some(p) = &self.syq_path {
            return format!("{} {}", shell_words::quote(p), shell_words::join(args));
        }
        if self.auto_helper {
            return remote_helper::launcher(args);
        }
        format!("syq {}", shell_words::join(args))
    }

    /// Connect, retrying a few times: sshd's MaxStartups (default 10) drops
    /// connections at random when many are being set up at once, so we also
    /// limit how many connects are in flight.
    pub fn connect(&self, compress: bool) -> Result<RemoteConn> {
        self.connect_with(compress, true)
    }

    /// `limited`: take a connect slot (data connections). The control
    /// connection passes false: everything waits on it, so it must never
    /// queue behind workers. In managed mode the release helper is installed
    /// on first use if the remote lacks it.
    pub fn connect_with(&self, compress: bool, limited: bool) -> Result<RemoteConn> {
        let first = self.connect_retried(compress, limited);
        let Err(first_error) = first else {
            return first;
        };
        if !self.auto_helper || !helper_needs_install(&first_error) {
            return Err(first_error);
        }

        self.install_helper()?;
        self.connect_retried(compress, limited).with_context(|| {
            format!(
                "could not start the {} helper installed on {}",
                remote_helper::helper_identity(),
                self.label()
            )
        })
    }

    fn connect_retried(&self, compress: bool, limited: bool) -> Result<RemoteConn> {
        let mut delay = std::time::Duration::from_millis(200);
        let mut last = None;
        for attempt in 0..6 {
            let _slot = limited.then(connect_slot);
            match self.connect_once(compress) {
                Ok(c) => return Ok(c),
                // Don't retry what won't change: a missing binary (127) or a
                // build identity mismatch.
                Err(e)
                    if attempt == 5
                        || e.to_string().contains("build identity mismatch")
                        || e.to_string().contains("exit status: 127")
                        || e.to_string().contains(&format!(
                            "exit status: {}",
                            remote_helper::HELPER_MISSING_EXIT
                        ))
                        || e.to_string().contains(&format!(
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

    fn connect_once(&self, compress: bool) -> Result<RemoteConn> {
        let mut cmd = self.ssh_command();
        let mut server_args = vec!["--server".into()];
        if let Some(grant) = &self.restricted_grant {
            server_args.push(format!("--restricted-grant={grant}"));
        }
        let remote_command = if self.restricted_grant.is_some() {
            // This text is inspected by the forced receiver through
            // SSH_ORIGINAL_COMMAND; sshd replaces the requested executable.
            format!("syq {}", shell_words::join(&server_args))
        } else {
            self.program_command(&server_args)
        };
        cmd.arg(remote_command);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {:?}", self.rsh[0]))?;
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
        };
        let conn = hello(conn, compress, Vec::new())?;
        self.record_peer(&conn);
        Ok(conn)
    }

    /// Ask the remote (over the control connection) to accept TCP data
    /// connections; records how to reach it for later `connect` calls.
    pub fn setup_tcp(&self, ctl: &mut dyn Conn, plain: bool, ports: (u16, u16)) -> Result<()> {
        *self.tcp.lock().unwrap() = None;
        {
            let mut diagnostics = self.diagnostics.lock().unwrap();
            diagnostics.tcp_probe = None;
            diagnostics.tcp_setup_error = None;
        }
        let result = self.setup_tcp_inner(ctl, plain, ports);
        if let Err(error) = &result {
            self.diagnostics.lock().unwrap().tcp_setup_error = Some(format!("{error:#}"));
        }
        result
    }

    fn setup_tcp_inner(&self, ctl: &mut dyn Conn, plain: bool, ports: (u16, u16)) -> Result<()> {
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
        })?;
        let (port, advertised) = match ok(resp, "tcp listen")? {
            Response::TcpListening { port, addrs } => (port, addrs),
            other => bail!("unexpected response {other:?}"),
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
        // Probe which advertised addresses this client can actually reach.
        probe_reachable(&mut candidates, port);
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
    fn connect_tcp(&self, info: &TcpInfo, compress: bool) -> Result<RemoteConn> {
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
                match TcpStream::connect_timeout(sa, std::time::Duration::from_secs(4)) {
                    Ok(s) => {
                        got = Some(s);
                        break;
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
            };
            let conn = hello(conn, compress, info.token.clone())?;
            self.record_peer(&conn);
            return Ok(conn);
        }
        Err(last)
    }
}

fn helper_needs_install(e: &anyhow::Error) -> bool {
    let message = e.to_string();
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
    let (tx, rx) = std::sync::mpsc::channel();
    for (i, candidate) in candidates.iter().enumerate() {
        let tx = tx.clone();
        let addr = candidate.address.clone();
        std::thread::spawn(move || {
            // Try every resolved address (a dual-stack name may return IPv6
            // first while the listener is IPv4-only): reachable if any connects.
            let ok = (addr.as_str(), port)
                .to_socket_addrs()
                .map(|it| {
                    it.into_iter().any(|sa| {
                        TcpStream::connect_timeout(&sa, std::time::Duration::from_millis(1000))
                            .is_ok()
                    })
                })
                .unwrap_or(false);
            let _ = tx.send((i, ok));
        });
    }
    drop(tx);
    for (i, reachable) in rx {
        candidates[i].reachable = reachable;
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

fn hello(mut conn: RemoteConn, compress: bool, token: Vec<u8>) -> Result<RemoteConn> {
    {
        conn.send(Request::Hello {
            identity: crate::identity::build().to_string(),
            compress,
            debug: crate::transfer::debug(),
            token,
        })?;
        match conn.recv() {
            Ok(Response::HelloOk { identity, platform })
                if identity == crate::identity::build() =>
            {
                conn.peer = Some(PeerInfo { identity, platform });
                Ok(conn)
            }
            Ok(Response::HelloOk { identity, .. }) => {
                bail!(
                    "{}: build identity mismatch (remote {identity}, local {})",
                    conn.label,
                    crate::identity::build()
                )
            }
            Ok(Response::Err(e)) => bail!("{}: {e}", conn.label),
            Ok(other) => bail!("{}: unexpected handshake response {other:?}", conn.label),
            Err(e) => bail!("{e}\ncould not start the remote syq on {}", conn.label),
        }
    }
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
                "could not install the authorized {} helper on {} ({}); install a compatible syq and pass --syq-path",
                remote_helper::helper_identity(),
                self.label(),
                target.key
            )
        })?;
        *installed = true;
        Ok(())
    }

    fn remote_bootstrap(&self) -> Result<RemoteBootstrap> {
        let mut cmd = self.ssh_command();
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
                "{}: automatic remote helpers do not support {os} {arch}; install syq there and pass --syq-path",
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
        let mut cmd = self.ssh_command();
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
        let mut cmd = self.ssh_command();
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

#[derive(Clone, Debug)]
pub enum Endpoint {
    Local,
    Remote(RemoteSpec),
}

impl Endpoint {
    pub fn is_remote(&self) -> bool {
        matches!(self, Endpoint::Remote(_))
    }

    pub fn connect(&self, compress: bool) -> Result<Box<dyn Conn>> {
        match self {
            Endpoint::Local => Ok(Box::new(LocalConn::new())),
            Endpoint::Remote(spec) => {
                let info = spec.tcp.lock().unwrap().clone();
                if let Some(info) = info.filter(|i| !i.failed) {
                    match spec.connect_tcp(&info, compress) {
                        Ok(c) => return Ok(Box::new(c)),
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
                                        eprintln!("syq: {}: data over ssh (TCP port {} stopped answering: {e:#})", spec.label(), info.port);
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
                Ok(Box::new(spec.connect(compress)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    struct ExitObserved<R> {
        inner: R,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
            user: None,
            host: "example".to_string(),
            rsh: vec!["ssh".to_string()],
            syq_path: None,
            auto_helper: false,
            restricted_grant: None,
            helper_install: Default::default(),
            quiet: false,
            tcp: Default::default(),
            diagnostics: Default::default(),
        };
        let command = spec.ssh_command();
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
            .ssh_command()
            .get_args()
            .any(|arg| arg == OsStr::new("StrictHostKeyChecking=yes")));
    }
}
