//! `pcp --server`: serve requests over stdin/stdout.

use crate::fsops::{self, FsOps};
use crate::proto::*;
use anyhow::{bail, Result};
use std::io::{self, ErrorKind};

pub fn run() -> Result<()> {
    let stdout = io::stdout().lock();
    let mut r = FrameReader::new(io::stdin());
    let mut w = FrameWriter::new(stdout, false);

    let debug;
    match r.read_msg::<Request>()? {
        Request::Hello { version, compress, debug: d } => {
            debug = d;
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
            Request::Scan { root, follow_root } => {
                let root = fsops::resolve(&root);
                // Warnings are collected and sent between batches so a single
                // writer borrow suffices.
                let warns = std::cell::RefCell::new(Vec::new());
                let wref = std::cell::RefCell::new(&mut w);
                let res = crate::scan::scan(
                    &root,
                    follow_root,
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
            "pcp server: {blocks} blocks, {} MiB; waiting for input {:.2}s, handling {:.2}s, writing responses {:.2}s",
            bytes >> 20, t[0], t[1], t[2]
        );
    }
    Ok(())
}
