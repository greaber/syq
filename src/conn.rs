//! Connections to endpoints: local (in-process) or remote (over an ssh child).

use crate::fsops::{self, FsOps};
use crate::proto::*;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::VecDeque;
use crate::crypto::{Cipher, RecordReader, RecordWriter};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
#[allow(unused_imports)]
use crate::proto::SizeHint;

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
    /// Streamed scan; `sink` gets batches, `warn` gets non-fatal messages.
    fn scan(
        &mut self,
        root: &[u8],
        follow_root: bool,
        all: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()>;
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
        LocalConn { ops: FsOps::new(), pending: VecDeque::new() }
    }
}

impl Conn for LocalConn {
    fn send(&mut self, req: Request) -> Result<()> {
        let resp = self.ops.handle(&req);
        self.pending.push_back(resp);
        Ok(())
    }
    fn recv(&mut self) -> Result<Response> {
        self.pending.pop_front().ok_or_else(|| anyhow!("no pending response"))
    }
    fn scan(
        &mut self,
        root: &[u8],
        follow_root: bool,
        all: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        crate::scan::scan(&fsops::resolve(root), follow_root, all, sink, warn)
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
}

const READ_AHEAD: usize = 4;

fn spawn_reader(input: Box<dyn Read + Send>) -> std::sync::mpsc::Receiver<std::io::Result<Response>> {
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

impl RemoteConn {
    fn io_err(&mut self, e: anyhow::Error) -> anyhow::Error {
        self.dead = true;
        // If the child has exited (or does so shortly), that's the more useful error.
        if let Some(child) = &mut self.child {
            for _ in 0..20 {
                if let Ok(Some(status)) = child.try_wait() {
                    return anyhow!("{}: remote pcp exited ({status})", self.label);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        let msg = if e.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof) {
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
            Err(_) => Err(self.io_err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "reader stopped").into())),
        }
    }
    fn is_dead(&self) -> bool {
        self.dead
    }
    fn scan(
        &mut self,
        root: &[u8],
        follow_root: bool,
        all: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        self.send(Request::Scan { root: root.to_vec(), follow_root, all })?;
        loop {
            match self.recv()? {
                Response::ScanBatch(b) => sink(b)?,
                Response::ScanWarn(w) => warn(w),
                Response::ScanDone => return Ok(()),
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

/// At most this many ssh sessions are being established at any moment.
const MAX_CONCURRENT_CONNECTS: usize = 6;
static CONNECTS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static CONNECTS_CV: std::sync::Condvar = std::sync::Condvar::new();

struct ConnectSlot;
fn connect_slot() -> ConnectSlot {
    let mut n = CONNECTS.lock().unwrap();
    while *n >= MAX_CONCURRENT_CONNECTS {
        n = CONNECTS_CV.wait(n).unwrap();
    }
    *n += 1;
    ConnectSlot
}
impl Drop for ConnectSlot {
    fn drop(&mut self) {
        *CONNECTS.lock().unwrap() -= 1;
        CONNECTS_CV.notify_one();
    }
}

pub const CIPHERS: &str = "Ciphers=aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com";

#[derive(Clone, Debug)]
pub struct RemoteSpec {
    pub user: Option<String>,
    pub host: String,
    pub rsh: Vec<String>,
    pub pcp_path: Option<String>,
    /// Shared across clones so workers see the TCP setup done on the control connection.
    pub tcp: std::sync::Arc<std::sync::Mutex<Option<TcpInfo>>>,
}

impl RemoteSpec {
    pub fn label(&self) -> String {
        match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
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
            cmd.args(["-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", CIPHERS]);
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

    fn server_command(&self) -> String {
        match &self.pcp_path {
            Some(p) => format!("{} --server", shell_words::quote(p)),
            None => "sh -c 'command -v pcp >/dev/null 2>&1 && exec pcp --server; exec \"$HOME/.local/bin/pcp\" --server'"
                .to_string(),
        }
    }

    /// Connect, retrying a few times: sshd's MaxStartups (default 10) drops
    /// connections at random when many are being set up at once, so we also
    /// limit how many connects are in flight.
    pub fn connect(&self, compress: bool) -> Result<RemoteConn> {
        let mut delay = std::time::Duration::from_millis(200);
        let mut last = None;
        for attempt in 0..6 {
            let _slot = connect_slot();
            match self.connect_once(compress) {
                Ok(c) => return Ok(c),
                // Don't retry what won't change: missing binary (127) or a version mismatch.
                Err(e) if attempt == 5 || e.to_string().contains("version mismatch") || e.to_string().contains("exit status: 127") => return Err(e),
                Err(e) => {
                    if crate::transfer::debug() {
                        eprintln!("pcp: connect to {} failed (attempt {}): {e:#}", self.label(), attempt + 1);
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
        cmd.arg(self.server_command());
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut child = cmd.spawn().with_context(|| format!("spawn {:?}", self.rsh[0]))?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let conn = RemoteConn {
            child: Some(child),
            w: FrameWriter::new(Box::new(stdin), compress),
            rx: spawn_reader(Box::new(stdout)),
            label: self.label(),
            dead: false,
        };
        hello(conn, compress, Vec::new())
    }

    /// Ask the remote (over the control connection) to accept TCP data
    /// connections; records how to reach it for later `connect` calls.
    pub fn setup_tcp(&self, ctl: &mut dyn Conn, plain: bool, ports: (u16, u16)) -> Result<()> {
        let key = if plain { None } else { Some(crate::crypto::random_bytes(crate::crypto::KEY_LEN)) };
        let token = crate::crypto::random_bytes(16);
        let resp = ctl.call(Request::TcpListen { key: key.clone(), token: token.clone(), port_lo: ports.0, port_hi: ports.1 })?;
        let (port, mut addrs) = match ok(resp, "tcp listen")? {
            Response::TcpListening { port, addrs } => (port, addrs),
            other => bail!("unexpected response {other:?}"),
        };
        if let Some(h) = self.resolved_hostname() {
            if !addrs.contains(&h) {
                addrs.push(h);
            }
        }
        *self.tcp.lock().unwrap() = Some(TcpInfo { addrs, port, key, token, failed: false });
        Ok(())
    }

    /// The real host name behind an ssh config alias.
    fn resolved_hostname(&self) -> Option<String> {
        if !self.rsh[0].ends_with("ssh") {
            return Some(self.host.clone());
        }
        let out = Command::new(&self.rsh[0]).args(&self.rsh[1..]).arg("-G").arg(&self.host).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .find_map(|l| l.strip_prefix("hostname "))
            .map(|h| h.trim().to_string())
            .or_else(|| Some(self.host.clone()))
    }

    /// Try every advertised address at once (firewalls that drop packets make
    /// sequential attempts slow), then use the best one that connected:
    /// addresses are listed in priority order, and once one succeeds we give
    /// higher-priority ones a short grace period to succeed too.
    fn connect_tcp(&self, info: &TcpInfo, compress: bool) -> Result<RemoteConn> {
        let (tx, rx) = std::sync::mpsc::channel();
        let n = info.addrs.len();
        for (prio, addr) in info.addrs.clone().into_iter().enumerate() {
            let (tx, port) = (tx.clone(), info.port);
            std::thread::spawn(move || {
                let r = (addr.as_str(), port)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut i| i.next())
                    .ok_or_else(|| anyhow!("cannot resolve {addr}"))
                    .and_then(|sa| TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(4)).map_err(|e| anyhow!("{addr}:{port}: {e}")));
                let _ = tx.send((prio, r));
            });
        }
        drop(tx);
        let mut last = anyhow!("no address advertised");
        let mut best: Option<(usize, TcpStream)> = None;
        let mut got = 0;
        let mut deadline: Option<std::time::Instant> = None;
        while got < n {
            let msg = match deadline {
                Some(d) => match rx.recv_timeout(d.saturating_duration_since(std::time::Instant::now())) {
                    Ok(m) => m,
                    Err(_) => break,
                },
                None => match rx.recv() {
                    Ok(m) => m,
                    Err(_) => break,
                },
            };
            got += 1;
            match msg {
                (prio, Ok(stream)) => {
                    if best.as_ref().map_or(true, |(p, _)| prio < *p) {
                        best = Some((prio, stream));
                    }
                    if prio == 0 {
                        break;
                    }
                    deadline.get_or_insert(std::time::Instant::now() + std::time::Duration::from_millis(400));
                }
                (_, Err(e)) => last = e,
            }
        }
        match best {
            Some((_, stream)) => {
                {
                    let addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                    if crate::transfer::debug() {
                        eprintln!("pcp: {}: data connection via tcp {addr}", self.label());
                    }
                    stream.set_nodelay(true)?;
                    let conn_id = TCP_CONN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (&stream).write_all(&conn_id.to_be_bytes())?;
                    let (wc, rc) = match &info.key {
                        Some(k) => (Some(Cipher::new(k, conn_id, 1)), Some(Cipher::new(k, conn_id, 2))),
                        None => (None, None),
                    };
                    let writer = RecordWriter::new(stream.try_clone()?, wc);
                    let reader = RecordReader::new(stream, rc);
                    let conn = RemoteConn {
                        child: None,
                        w: FrameWriter::new(Box::new(writer), compress),
                        rx: spawn_reader(Box::new(reader)),
                        label: format!("{} (tcp {addr})", self.label()),
                        dead: false,
                    };
                    hello(conn, compress, info.token.clone())
                }
            }
            None => Err(last),
        }
    }
}

static TCP_CONN_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

#[derive(Clone, Debug)]
pub struct TcpInfo {
    pub addrs: Vec<String>,
    pub port: u16,
    pub key: Option<Vec<u8>>,
    pub token: Vec<u8>,
    /// Set once a connect attempt failed; later connections use ssh.
    pub failed: bool,
}

fn hello(mut conn: RemoteConn, compress: bool, token: Vec<u8>) -> Result<RemoteConn> {
    {
        conn.send(Request::Hello { version: VERSION, compress, debug: crate::transfer::debug(), token })?;
        match conn.recv() {
            Ok(Response::HelloOk { version }) if version == VERSION => Ok(conn),
            Ok(Response::HelloOk { version }) => {
                bail!("{}: protocol version mismatch (remote {version}, local {VERSION})", conn.label)
            }
            Ok(Response::Err(e)) => bail!("{}: {e}", conn.label),
            Ok(other) => bail!("{}: unexpected handshake response {other:?}", conn.label),
            Err(e) => bail!(
                "{e}\ncould not start pcp on {} — is it installed there? (try --bootstrap, or --pcp-path)",
                conn.label
            ),
        }
    }
}

impl RemoteSpec {
    /// Copy this binary to `~/.local/bin/pcp` on the remote host.
    pub fn bootstrap(&self) -> Result<()> {
        let exe = std::env::current_exe().context("locate own executable")?;
        let bin = std::fs::read(&exe).with_context(|| format!("read {}", exe.display()))?;
        eprintln!("pcp: installing pcp on {} (~/.local/bin/pcp, {} bytes)", self.label(), bin.len());
        let mut cmd = self.ssh_command();
        cmd.arg(
            "sh -c 'd=\"$HOME/.local/bin\"; mkdir -p \"$d\" && cat > \"$d/pcp.tmp\" && chmod 755 \"$d/pcp.tmp\" && mv \"$d/pcp.tmp\" \"$d/pcp\" && \"$d/pcp\" --version'",
        );
        cmd.stdin(Stdio::piped()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
        let mut child = cmd.spawn()?;
        {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(&bin)?;
        }
        let status = child.wait()?;
        if !status.success() {
            bail!("bootstrap on {} failed ({status}); the remote may need a different architecture build", self.label());
        }
        Ok(())
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
                                    eprintln!("pcp: {}: TCP data connection failed ({e:#}); falling back to ssh (is port {} open?)", spec.label(), info.port);
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
