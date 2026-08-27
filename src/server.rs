//! `syq --server`: serve requests over stdin/stdout, and optionally over
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
    serve(io::stdin(), io::stdout().lock(), true, None, None)
}

/// Serve one connection. `over_ssh` connections may set up a TCP listener;
/// TCP connections must present `expect_token` in their Hello.
fn serve<R: Read + Send + 'static, W: Write>(
    r: R,
    w: W,
    over_ssh: bool,
    expect_token: Option<Vec<u8>>,
    authed: Option<&std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let mut r = FrameReader::new(r);
    let mut w = FrameWriter::new(w, false);

    let debug;
    match r.read_msg::<Request>()? {
        Request::Hello {
            version,
            release,
            compress,
            debug: d,
            token,
        } => {
            debug = d;
            if let Some(t) = &expect_token {
                if &token != t {
                    bail!("bad token on data connection");
                }
            }
            // The token is the credential: once it matches, the peer is
            // authenticated. Mark it now so a later failure (version mismatch,
            // a failed HelloOk write) can't free the connection id for replay.
            if let Some(a) = authed {
                a.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if version != VERSION {
                w.write_msg(&Response::Err(format!(
                    "protocol version mismatch (remote {VERSION}, client {version})"
                )))?;
                bail!("protocol version mismatch");
            }
            let expected_release = env!("CARGO_PKG_VERSION");
            if release != expected_release {
                w.write_msg(&Response::Err(format!(
                    "release mismatch (remote {expected_release}, client {release})"
                )))?;
                bail!("release mismatch");
            }
            w.compress = compress;
            w.write_msg(&Response::HelloOk {
                version: VERSION,
                release: expected_release.to_string(),
            })?;
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
            Request::TcpListen {
                key,
                token,
                port_lo,
                port_hi,
            } => {
                if !over_ssh {
                    w.write_msg(&Response::Err(
                        "TcpListen only allowed on the control connection".into(),
                    ))?;
                    continue;
                }
                match tcp_listen(key, token, port_lo, port_hi, debug, w.compress) {
                    Ok(port) => w.write_msg(&Response::TcpListening {
                        port,
                        addrs: local_addrs(),
                    })?,
                    Err(e) => w.write_msg(&Response::Err(format!("{e:#}")))?,
                }
            }
            Request::Scan {
                root,
                follow_root,
                all,
                ignore,
            } => {
                let root = fsops::resolve(&root);
                // Warnings are collected and sent between batches so a single
                // writer borrow suffices.
                let warns = std::cell::RefCell::new(Vec::new());
                let wref = std::cell::RefCell::new(&mut w);
                let res = crate::scan::scan(
                    &root,
                    follow_root,
                    all,
                    &ignore,
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

/// (ip, speed_mbps) for each real NIC the client might reach us on. The ssh
/// session's own server-IP is first; virtual interfaces (docker/bridges/etc.)
/// are skipped so multipath never fans out onto a dead bridge.
fn local_addrs() -> Vec<(String, u32)> {
    let ssh_ip = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|c| c.split_whitespace().nth(2).map(str::to_string));
    let out = std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output();
    let text = out
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut addrs: Vec<(String, u32, u8)> = Vec::new(); // (ip, speed, priority-bucket)
    for line in text.lines() {
        // "3: bond0    inet 10.2.201.45/24 brd ... scope global bond0"
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(iface), Some(ipcidr)) = (f.get(1), f.iter().skip_while(|w| **w != "inet").nth(1))
        else {
            continue;
        };
        if is_virtual_iface(iface) {
            continue;
        }
        let ip = ipcidr.split('/').next().unwrap_or("").to_string();
        if ip.is_empty() || ip.starts_with("127.") {
            continue;
        }
        let bucket = if ssh_ip.as_deref() == Some(&ip) {
            0
        } else if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") {
            1
        } else if ip.starts_with("100.") {
            3 // CGNAT / Tailscale
        } else {
            2 // public
        };
        addrs.push((ip, iface_speed(iface), bucket));
    }
    // ssh-arrival ip first, then by bucket, then by speed (fastest first).
    addrs.sort_by(|a, b| a.2.cmp(&b.2).then(b.1.cmp(&a.1)));
    addrs.dedup_by(|a, b| a.0 == b.0);
    addrs.into_iter().map(|(ip, sp, _)| (ip, sp)).collect()
}

fn tcp_listen(
    key: Option<Vec<u8>>,
    token: Vec<u8>,
    lo: u16,
    hi: u16,
    debug: bool,
    compress: bool,
) -> Result<u16> {
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
    // Bound in-flight data connections (a peer shouldn't be able to spawn
    // unbounded threads), and remember which client connection ids we've seen
    // so a captured record stream can't be replayed while the listener is up.
    let live = Arc::new(AtomicU32::new(0));
    let seen: Arc<std::sync::Mutex<std::collections::HashSet<u32>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    const MAX_LIVE: u32 = 256;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let id = next_id.fetch_add(1, Relaxed);
            if live.load(Relaxed) >= MAX_LIVE {
                if debug {
                    eprintln!("syq server (tcp): refusing connection, {MAX_LIVE} already live");
                }
                continue; // drop; stream closes
            }
            live.fetch_add(1, Relaxed);
            let (key, token, live, seen) = (key.clone(), token.clone(), live.clone(), seen.clone());
            std::thread::spawn(move || {
                if let Err(e) = serve_tcp(stream, id, key, token, debug, compress, &seen) {
                    if debug {
                        eprintln!("syq server (tcp {id}): {e:#}");
                    }
                }
                live.fetch_sub(1, Relaxed);
            });
        }
    });
    Ok(port)
}

fn serve_tcp(
    stream: TcpStream,
    id: u32,
    key: Option<Vec<u8>>,
    token: Vec<u8>,
    _debug: bool,
    _compress: bool,
    seen: &std::sync::Mutex<std::collections::HashSet<u32>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    // Scanners and stray connections must not hold a thread forever.
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    // The client tells us its connection id first (plaintext), so both sides
    // derive the same nonces.
    let mut idbuf = [0u8; 4];
    (&stream).read_exact(&mut idbuf)?;
    let conn_id = u32::from_be_bytes(idbuf);
    let _ = id;
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
    let reader = RecordReader::new(stream.try_clone()?, rc);
    let writer = RecordWriter::new(stream.try_clone()?, wc);
    // Free the id only if the connection NEVER authenticated, so an
    // unauthenticated peer can't reserve ids. Once the token authenticated, the
    // id is retained permanently even if a later request fails — otherwise an
    // on-path attacker could corrupt an authenticated stream to free the id and
    // then replay captured records under it.
    let authed = std::sync::atomic::AtomicBool::new(false);
    let res = serve(
        TimeoutOnce {
            inner: reader,
            stream: stream.try_clone()?,
            cleared: false,
        },
        writer,
        false,
        Some(token),
        Some(&authed),
    );
    if res.is_err() && !authed.load(std::sync::atomic::Ordering::SeqCst) {
        seen.lock().unwrap().remove(&conn_id);
    }
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
