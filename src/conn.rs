//! Connections to endpoints: local (in-process) or remote (over an ssh child).

use crate::fsops::{self, FsOps};
use crate::proto::*;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::VecDeque;
use std::io::Write;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        crate::scan::scan(&fsops::resolve(root), follow_root, sink, warn)
    }
}

pub struct RemoteConn {
    child: Child,
    w: FrameWriter<ChildStdin>,
    r: FrameReader<ChildStdout>,
    label: String,
    dead: bool,
}

impl RemoteConn {
    fn io_err(&mut self, e: anyhow::Error) -> anyhow::Error {
        self.dead = true;
        // If the child has exited (or does so shortly), that's the more useful error.
        for _ in 0..20 {
            if let Ok(Some(status)) = self.child.try_wait() {
                return anyhow!("{}: remote pcp exited ({status})", self.label);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
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
        self.r.read_msg().map_err(|e| self.io_err(e.into()))
    }
    fn is_dead(&self) -> bool {
        self.dead
    }
    fn scan(
        &mut self,
        root: &[u8],
        follow_root: bool,
        sink: &mut dyn FnMut(Vec<Entry>) -> Result<()>,
        warn: &mut dyn FnMut(String),
    ) -> Result<()> {
        self.send(Request::Scan { root: root.to_vec(), follow_root })?;
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
        let _ = self.child.wait();
    }
}

#[derive(Clone, Debug)]
pub struct RemoteSpec {
    pub user: Option<String>,
    pub host: String,
    pub rsh: Vec<String>,
    pub pcp_path: Option<String>,
}

impl RemoteSpec {
    fn label(&self) -> String {
        match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        }
    }

    fn ssh_command(&self) -> Command {
        let mut cmd = Command::new(&self.rsh[0]);
        cmd.args(&self.rsh[1..]);
        if self.rsh[0].ends_with("ssh") {
            // Data connections must not share one TCP stream / cipher process.
            cmd.args(["-o", "ControlMaster=no", "-o", "ControlPath=none"]);
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

    pub fn connect(&self, compress: bool) -> Result<RemoteConn> {
        let mut cmd = self.ssh_command();
        cmd.arg(self.server_command());
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut child = cmd.spawn().with_context(|| format!("spawn {:?}", self.rsh[0]))?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut conn = RemoteConn {
            child,
            w: FrameWriter::new(stdin, compress),
            r: FrameReader::new(stdout),
            label: self.label(),
            dead: false,
        };
        conn.send(Request::Hello { version: VERSION, compress })?;
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
            Endpoint::Remote(spec) => Ok(Box::new(spec.connect(compress)?)),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Endpoint::Local => "local".into(),
            Endpoint::Remote(s) => s.label(),
        }
    }
}
