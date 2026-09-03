//! `syq --server`: serve requests over stdin/stdout, and optionally over
//! TCP data connections (see `crypto.rs`) when the client asks for them.

use crate::crypto::{Cipher, RecordReader, RecordWriter};
use crate::descriptor_broker::DescriptorSessionSlot;
use crate::fsops::{self, FsOps};
use crate::proto::*;
use anyhow::{bail, Context, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

struct RequestReader {
    rx: Option<std::sync::mpsc::Receiver<io::Result<Request>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    tcp_socket: Option<TcpStream>,
}

impl RequestReader {
    fn spawn<R: Read + Send + 'static>(
        mut reader: FrameReader<R>,
        tcp_socket: Option<TcpStream>,
    ) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(4);
        let thread = std::thread::spawn(move || loop {
            let msg = reader.read_msg::<Request>();
            let failed = msg.is_err();
            if tx.send(msg).is_err() || failed {
                break;
            }
        });
        Self {
            rx: Some(rx),
            thread: Some(thread),
            tcp_socket,
        }
    }

    fn recv(&self) -> std::result::Result<io::Result<Request>, std::sync::mpsc::RecvError> {
        self.rx.as_ref().expect("request receiver present").recv()
    }

    fn tcp_stats(&self) -> Option<TcpSocketStats> {
        self.tcp_socket
            .as_ref()
            .and_then(crate::conn::tcp_socket_stats)
    }
}

impl Drop for RequestReader {
    fn drop(&mut self) {
        let tcp = self.tcp_socket.is_some();
        if let Some(socket) = &self.tcp_socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        self.rx.take();
        // An ssh server process exits immediately after `serve`; joining its
        // stdin reader here would deadlock while the client waits for process
        // exit before closing stdin. A TCP socket can be woken explicitly, so
        // its reader is joined deterministically on every return path.
        if tcp {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

struct ServeSession {
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
struct ConnectionPermit(Arc<crate::restricted::RestrictedAuthority>);

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
            authority: None,
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    result
}

pub(crate) fn run_restricted(authority: Arc<crate::restricted::RestrictedAuthority>) -> Result<()> {
    let descriptor_session = DescriptorSessionSlot::default();
    let result = serve(
        io::stdin(),
        io::stdout().lock(),
        true,
        None,
        None,
        None,
        ServeSession {
            authority: Some(Arc::clone(&authority)),
            descriptor_session: descriptor_session.clone(),
        },
    );
    descriptor_session.close();
    authority.close_control();
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
        authority,
        descriptor_session,
    } = session;
    let mut r = FrameReader::new(r);
    let mut w = FrameWriter::new(w, false);

    let debug;
    let role;
    // Held for the life of the connection; dropping it releases the worker
    // permit even when a later request fails.
    let _permit: Option<ConnectionPermit>;
    match r.read_msg::<Request>()? {
        Request::Hello {
            identity,
            compress,
            debug: d,
            token,
            role: requested_role,
        } => {
            debug = d;
            if let Some(t) = &expect_token {
                if &token != t {
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
                (Some(authority), false) => {
                    authority.acquire_connection()?;
                    Some(ConnectionPermit(authority.clone()))
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
    })?;

    // Requests are parsed on a reader thread so incoming data keeps flowing
    // while a block is being hashed and written. TCP readers are shut down and
    // joined by the guard on every exit path.
    let reader = RequestReader::spawn(r, tcp_socket);

    let mut t = [0f64; 3];
    let (mut blocks, mut bytes) = (0u64, 0u64);
    loop {
        let t0 = std::time::Instant::now();
        let mut req: Request = match reader.recv() {
            Ok(Ok(req)) => req,
            Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        };
        t[0] += t0.elapsed().as_secs_f64();
        if !is_control
            && matches!(
                &req,
                Request::TcpListen { .. }
                    | Request::NativeRemove { .. }
                    | Request::CheckOperatorDirectory { .. }
                    | Request::CheckOperatorDirectoryAncestry { .. }
                    | Request::RegisterSourceRoots { .. }
                    | Request::CreateOperatorDirectory { .. }
                    | Request::AnchorDestination { .. }
                    | Request::Receipt
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
            Request::TcpListen {
                key,
                token,
                port_lo,
                port_hi,
                congestion_control,
            } => {
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
                    Ok((port, congestion_control)) => w.write_msg(&Response::TcpListening {
                        port,
                        addrs: local_addrs(),
                        congestion_control,
                    })?,
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
                        .write_msg(&Response::Err(format!("{error:#}")))?,
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
            Request::Receipt => match &authority {
                Some(authority) => match authority.issue_receipt() {
                    Ok(receipt) => {
                        crate::receipt_v2::emit_transport_frames(receipt, |frame| {
                            w.write_msg(&Response::ReceiptV2(frame))?;
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
) -> Result<(u16, Option<String>)> {
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
    // Passive connections inherit the listener's congestion controller. Set
    // and verify it before advertising the port so even handshake-time
    // behavior uses the requested algorithm.
    let congestion_control = crate::conn::configure_tcp_congestion(&listener, congestion_control)?;
    let port = listener.local_addr()?.port();
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
    listener.set_nonblocking(true)?;
    std::thread::spawn(move || {
        loop {
            if descriptor_session.is_closed()
                || authority
                    .as_ref()
                    .is_some_and(|authority| !authority.control_is_open())
            {
                break;
            }
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(_) => continue,
            };
            let id = next_id.fetch_add(1, Relaxed);
            if live.load(Relaxed) >= max_live {
                if debug {
                    eprintln!("syq server (tcp): refusing connection, {max_live} already live");
                }
                continue; // drop; stream closes
            }
            live.fetch_add(1, Relaxed);
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
                ) {
                    if debug {
                        eprintln!("syq server (tcp {id}): {e:#}");
                    }
                }
                live.fetch_sub(1, Relaxed);
            });
        }
    });
    Ok((port, congestion_control))
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
        Some(stream.try_clone()?),
        ServeSession {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

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
        let selected = tempfile::tempdir().unwrap();
        let marker = selected.path().join("marker");
        std::fs::write(&marker, b"marker").unwrap();
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
                    authority: None,
                    descriptor_session: server_session,
                },
            )
            .unwrap();
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
        writer
            .write_msg(&Request::RegisterSourceRoots {
                selections: vec![SourceRootSelection {
                    path: b".".to_vec(),
                    follow_root: false,
                }],
                symlink_policy: OperatorSymlinkPolicy::Refuse,
                allow_unconfined_paths: false,
                shared_workers: 0,
                independent_claim_workers: 0,
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
        let selected = tempfile::tempdir().unwrap();
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
        let selected = tempfile::tempdir().unwrap();
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
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let authority = Arc::new(crate::restricted::tests::tcp_test_authority(&root));
        let max_workers = usize::from(crate::restricted::tests::TEST_AUTHORITY_MAX_CONNECTIONS);
        let token = b"data-token".to_vec();
        let descriptor_session = DescriptorSessionSlot::default();
        let (port, _) = tcp_listen(
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
        // dropped: a served socket stays silent, a dropped one reads EOF.
        std::thread::sleep(Duration::from_millis(200));
        for socket in &pending {
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut byte = [0u8; 1];
            match (&*socket).read(&mut byte) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
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
