//! Connections to endpoints: local (in-process) or remote (over an ssh child).

use crate::crypto::{Cipher, RecordReader, RecordWriter};
use crate::fsops::{self, FsOps};
#[allow(unused_imports)]
use crate::proto::SizeHint;
use crate::proto::*;
use crate::remote_helper::{self, Target};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
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
    rx: std::sync::mpsc::Receiver<std::io::Result<Response>>,
    label: String,
    dead: bool,
    peer: Option<PeerInfo>,
}

const READ_AHEAD: usize = 4;

fn spawn_reader(
    input: Box<dyn Read + Send>,
) -> std::sync::mpsc::Receiver<std::io::Result<Response>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(READ_AHEAD);
    std::thread::spawn(move || {
        let mut r = FrameReader::new(input);
        loop {
            let msg = r.read_msg::<Response>();
            let failed = msg.is_err();
            if tx.send(msg).is_err() || failed {
                break;
            }
        }
    });
    rx
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
        match self.rx.recv() {
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
        if let Some(child) = &mut self.child {
            let _ = child.wait();
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
    pub data_connection_verified: bool,
    pub data_connection_error: Option<String>,
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

    pub fn record_data_connection_check(&self, result: &Result<()>) {
        let mut diagnostics = self.diagnostics.lock().unwrap();
        match result {
            Ok(()) => diagnostics.data_connection_verified = true,
            Err(error) => diagnostics.data_connection_error = Some(format!("{error:#}")),
        }
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
        cmd.arg(self.program_command(&["--server".into()]));
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {:?}", self.rsh[0]))?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let conn = RemoteConn {
            child: Some(child),
            w: FrameWriter::new(Box::new(stdin), compress),
            rx: spawn_reader(Box::new(stdout)),
            label: self.label(),
            dead: false,
            peer: None,
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
            verified: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
            let reader = RecordReader::new(stream, rc);
            let conn = RemoteConn {
                child: None,
                w: FrameWriter::new(Box::new(writer), compress),
                rx: spawn_reader(Box::new(reader)),
                label: format!("{} (tcp {addr_s})", self.label()),
                dead: false,
                peer: None,
            };
            let conn = hello(conn, compress, info.token.clone())?;
            info.verified
                .store(true, std::sync::atomic::Ordering::Relaxed);
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
    /// Shared across snapshots so diagnostics can distinguish a socket probe
    /// from a complete authenticated syq handshake.
    pub verified: std::sync::Arc<std::sync::atomic::AtomicBool>,
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

        let target = self.remote_target()?;
        if !self.quiet {
            eprintln!(
                "syq: {}: installing {} helper for {}",
                self.label(),
                remote_helper::helper_identity(),
                target.key
            );
        }
        self.download_helper(target).with_context(|| {
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

    fn remote_target(&self) -> Result<Target> {
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
        Target::from_uname(os, arch).ok_or_else(|| {
            anyhow!(
                "{}: automatic remote helpers do not support {os} {arch}; install syq there and pass --syq-path",
                self.label()
            )
        })
    }

    fn download_helper(&self, target: Target) -> Result<()> {
        let expected_sha256 = crate::update::trusted_current_archive_hash(target)
            .context("verify the signed release manifest")?;
        let script = remote_helper::download_script(target, &expected_sha256);
        let mut cmd = self.ssh_command();
        cmd.arg(format!("sh -c {}", shell_words::quote(&script)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = cmd
            .output()
            .with_context(|| format!("download helper on {}", self.label()))?;
        if !out.status.success() {
            bail!(
                "remote download exited {}{}",
                out.status,
                output_suffix(&out.stderr)
            );
        }
        Ok(())
    }
}

fn output_suffix(stderr: &[u8]) -> String {
    let message = String::from_utf8_lossy(stderr);
    let message = message.trim();
    if message.is_empty() {
        String::new()
    } else {
        format!(": {message}")
    }
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
                Ok(Box::new(spec.connect(compress)?))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

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
    fn ssh_inherits_host_key_policy() {
        let spec = RemoteSpec {
            user: None,
            host: "example".to_string(),
            rsh: vec!["ssh".to_string()],
            syq_path: None,
            auto_helper: false,
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
