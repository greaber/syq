//! `pcp --server`: serve requests over stdin/stdout, and optionally over
//! TCP data connections (see `crypto.rs`) when the client asks for them.

use crate::crypto::{Cipher, RecordReader, RecordWriter};
use crate::fsops::{self, FsOps};
use crate::proto::*;
use anyhow::{bail, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

pub fn run() -> Result<()> {
    serve(io::stdin(), io::stdout().lock(), true, None)
}

/// Serve one connection. `over_ssh` connections may set up a TCP listener;
/// TCP connections must present `expect_token` in their Hello.
fn serve<R: Read + Send + 'static, W: Write>(r: R, w: W, over_ssh: bool, expect_token: Option<Vec<u8>>) -> Result<()> {
    let mut r = FrameReader::new(r);
    let mut w = FrameWriter::new(w, false);

    let debug;
    match r.read_msg::<Request>()? {
        Request::Hello { version, compress, debug: d, token } => {
            debug = d;
            if let Some(t) = &expect_token {
                if &token != t {
                    bail!("bad token on data connection");
                }
            }
            if version != VERSION {
                w.write_msg(&Response::Err(format!(
                    "protocol version mismatch (remote {VERSION}, client {version})"
                )))?;
                bail!("protocol version mismatch");
            }
            w.compress = compress;
            w.write_msg(&Response::HelloOk { version: VERSION })?;
        }
        _ => bail!("expected Hello"),
    }

    // Requests are parsed on a reader thread so incoming data keeps flowing
    // while a block is being hashed and written.
    let (tx, rx) = std::sync::mpsc::sync_channel::<io::Result<Request>>(4);
    std::thread::spawn(move || loop {
        let msg = r.read_msg::<Request>();
        let failed = msg.is_err();
        if tx.send(msg).is_err() || failed {
            break;
        }
    });

    let mut ops = FsOps::new();
    let mut t = [0f64; 3];
    let (mut blocks, mut bytes) = (0u64, 0u64);
    loop {
        let t0 = std::time::Instant::now();
        let req: Request = match rx.recv() {
            Ok(Ok(req)) => req,
            Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        };
        t[0] += t0.elapsed().as_secs_f64();
        match &req {
            Request::WriteRange { data, .. } => {
                blocks += 1;
                bytes += data.len() as u64;
            }
            Request::ReadRange { len, .. } => {
                blocks += 1;
                bytes += *len as u64;
            }
            _ => {}
        }
        match req {
            Request::Shutdown => break,
            Request::TcpListen { key, token, port_lo, port_hi } => {
                if !over_ssh {
                    w.write_msg(&Response::Err("TcpListen only allowed on the control connection".into()))?;
                    continue;
                }
                match tcp_listen(key, token, port_lo, port_hi, debug, w.compress) {
                    Ok(port) => w.write_msg(&Response::TcpListening { port, addrs: local_addrs() })?,
                    Err(e) => w.write_msg(&Response::Err(format!("{e:#}")))?,
                }
            }
            Request::Scan { root, follow_root, all } => {
                let root = fsops::resolve(&root);
                // Warnings are collected and sent between batches so a single
                // writer borrow suffices.
                let warns = std::cell::RefCell::new(Vec::new());
                let wref = std::cell::RefCell::new(&mut w);
                let res = crate::scan::scan(
                    &root,
                    follow_root,
                    all,
                    &mut |batch| {
                        let mut w = wref.borrow_mut();
                        for m in warns.borrow_mut().drain(..) {
                            w.write_msg(&Response::ScanWarn(m))?;
                        }
                        Ok(w.write_msg(&Response::ScanBatch(batch))?)
                    },
                    &mut |msg| warns.borrow_mut().push(msg),
                );
                for m in warns.borrow_mut().drain(..) {
                    w.write_msg(&Response::ScanWarn(m))?;
                }
                match res {
                    Ok(()) => w.write_msg(&Response::ScanDone)?,
                    Err(e) => w.write_msg(&Response::Err(format!("{e:#}")))?,
                }
            }
            other => {
                let t0 = std::time::Instant::now();
                let resp = ops.handle(&other);
                t[1] += t0.elapsed().as_secs_f64();
                let t0 = std::time::Instant::now();
                w.write_msg(&resp)?;
                t[2] += t0.elapsed().as_secs_f64();
            }
        }
    }
    if debug {
        eprintln!(
            "pcp server{}: {blocks} blocks, {} MiB; waiting for input {:.2}s, handling {:.2}s, writing responses {:.2}s",
            if over_ssh { "" } else { " (tcp)" },
            bytes >> 20,
            t[0],
            t[1],
            t[2]
        );
    }
    Ok(())
}

/// Addresses a client might reach us on: the one this ssh session came in
/// on first, then every other local IPv4 address (private ones before public).
fn local_addrs() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(c) = std::env::var("SSH_CONNECTION") {
        if let Some(a) = c.split_whitespace().nth(2) {
            out.push(a.to_string());
        }
    }
    let mut rest: Vec<String> = std::process::Command::new("hostname")
        .arg("-I")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    rest.retain(|a| a.contains('.') && !a.starts_with("127.") && !out.contains(a));
    // Private LANs first, then CGNAT (Tailscale and the like), then public.
    rest.sort_by_key(|a| {
        if a.starts_with("100.") && a.split('.').nth(1).and_then(|o| o.parse::<u8>().ok()).is_some_and(|o| (64..128).contains(&o)) {
            1
        } else if a.starts_with("10.") || a.starts_with("192.168.") || a.starts_with("172.") {
            0
        } else {
            2
        }
    });
    out.extend(rest);
    out
}

fn tcp_listen(key: Option<Vec<u8>>, token: Vec<u8>, lo: u16, hi: u16, debug: bool, compress: bool) -> Result<u16> {
    let mut listener = None;
    for port in lo..=hi.max(lo) {
        if let Ok(l) = TcpListener::bind(("0.0.0.0", port)) {
            listener = Some(l);
            break;
        }
    }
    let Some(listener) = listener else {
        bail!("no free port in {lo}-{hi}");
    };
    let port = listener.local_addr()?.port();
    let next_id = Arc::new(AtomicU32::new(1));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let id = next_id.fetch_add(1, Relaxed);
            let (key, token) = (key.clone(), token.clone());
            std::thread::spawn(move || {
                if let Err(e) = serve_tcp(stream, id, key, token, debug, compress) {
                    if debug {
                        eprintln!("pcp server (tcp {id}): {e:#}");
                    }
                }
            });
        }
    });
    Ok(port)
}

fn serve_tcp(stream: TcpStream, id: u32, key: Option<Vec<u8>>, token: Vec<u8>, _debug: bool, _compress: bool) -> Result<()> {
    stream.set_nodelay(true)?;
    // Scanners and stray connections must not hold a thread forever.
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    // The client tells us its connection id first (plaintext), so both sides
    // derive the same nonces.
    let mut idbuf = [0u8; 4];
    (&stream).read_exact(&mut idbuf)?;
    let conn_id = u32::from_be_bytes(idbuf);
    let _ = id;
    let (rc, wc) = match &key {
        Some(k) => (Some(Cipher::new(k, conn_id, 1)), Some(Cipher::new(k, conn_id, 2))),
        None => (None, None),
    };
    let reader = RecordReader::new(stream.try_clone()?, rc);
    let writer = RecordWriter::new(stream.try_clone()?, wc);
    // Only the Hello is subject to the timeout; the serve loop reads on a thread
    // so it can't be told apart, hence clear it once we have the stream set up.
    let res = serve(TimeoutOnce { inner: reader, stream: stream.try_clone()?, cleared: false }, writer, false, Some(token));
    res
}

/// Clears the socket read timeout after the first successful read.
struct TimeoutOnce<R: Read> {
    inner: R,
    stream: TcpStream,
    cleared: bool,
}

impl<R: Read> Read for TimeoutOnce<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if !self.cleared {
            self.cleared = true;
            let _ = self.stream.set_read_timeout(None);
        }
        Ok(n)
    }
}
