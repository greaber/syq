//! `pcp --server`: serve requests over stdin/stdout.

use crate::fsops::{self, FsOps};
use crate::proto::*;
use anyhow::{bail, Result};
use std::io::{self, ErrorKind};

pub fn run() -> Result<()> {
    let stdin = io::stdin().lock();
    let stdout = io::stdout().lock();
    let mut r = FrameReader::new(stdin);
    let mut w = FrameWriter::new(stdout, false);

    match r.read_msg::<Request>()? {
        Request::Hello { version, compress } => {
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

    let mut ops = FsOps::new();
    loop {
        let req: Request = match r.read_msg() {
            Ok(req) => req,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
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
                let resp = ops.handle(&other);
                w.write_msg(&resp)?;
            }
        }
    }
    Ok(())
}
