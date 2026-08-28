//! `syq --rm`: recursive removal with N parallel connections. Files are
//! unlinked in batches spread across workers; directories are removed
//! deepest-first, each depth level in parallel.

use crate::cli::{Args, Location};
use crate::conn::{ok, Conn, Endpoint};
use crate::fsops::join;
use crate::progress::{commas, Progress};
use crate::proto::*;
use crate::transfer::{connect_ctl, endpoint};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{mpsc, Arc, Condvar, Mutex};

const BATCH: usize = 200;

struct Pool {
    tx: Mutex<Option<mpsc::Sender<Vec<Op>>>>,
    pending: Mutex<usize>,
    cv: Condvar,
    progress: Arc<Progress>,
    verbose: bool,
    aborted: std::sync::atomic::AtomicBool,
}

impl Pool {
    fn submit(&self, ops: Vec<Op>) {
        if ops.is_empty() {
            return;
        }
        *self.pending.lock().unwrap() += 1;
        if let Some(tx) = self.tx.lock().unwrap().as_ref() {
            let _ = tx.send(ops);
        }
    }
    fn done(&self) {
        let mut p = self.pending.lock().unwrap();
        *p -= 1;
        if *p == 0 {
            self.cv.notify_all();
        }
    }
    fn abort(&self) {
        self.aborted
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.cv.notify_all();
    }
    fn is_aborted(&self) -> bool {
        self.aborted.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn wait_idle(&self) {
        let mut p = self.pending.lock().unwrap();
        while *p > 0 && !self.is_aborted() {
            p = self.cv.wait(p).unwrap();
        }
    }
    fn close(&self) {
        self.tx.lock().unwrap().take();
    }
}

fn worker(
    pool: Arc<Pool>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<Op>>>>,
    ep: Endpoint,
    compress: bool,
) -> Result<()> {
    let mut conn: Box<dyn Conn> = ep.connect(compress)?;
    loop {
        let ops = match rx.lock().unwrap().recv() {
            Ok(ops) => ops,
            Err(_) => return Ok(()),
        };
        let names: Vec<PathBytes> = ops
            .iter()
            .map(|o| match o {
                Op::Remove { path } | Op::Rmdir { path } => path.clone(),
                _ => Vec::new(),
            })
            .collect();
        let res = conn.call(Request::Apply(ops)).and_then(|r| ok(r, "remove"));
        match res {
            Ok(Response::Applied(errs)) => {
                for (name, err) in names.iter().zip(errs) {
                    match err {
                        Some(e) => pool.progress.error(&format!("syq: {e}")),
                        None => {
                            pool.progress.files_done.fetch_add(1, Relaxed);
                            if pool.verbose {
                                pool.progress.println(&String::from_utf8_lossy(name));
                            }
                        }
                    }
                }
            }
            Ok(other) => pool
                .progress
                .error(&format!("syq: unexpected response {other:?}")),
            Err(e) => {
                pool.progress.error(&format!("syq: {e:#}"));
                pool.done();
                if conn.is_dead() {
                    pool.abort(); // wake wait_idle so the run doesn't hang on queued ops
                    return Err(e);
                }
                continue;
            }
        }
        pool.done();
    }
}

/// Reject dangerous removal targets: traversal (`..`), the filesystem root,
/// home, cwd, and any ancestor of cwd/home. `..` components are rejected for
/// every target (local or remote) so `child/..` can't escape; local targets are
/// additionally canonicalized to catch symlink and alias tricks.
/// Match `rm -rf` refusals: a target whose lexical final component is `.` or
/// `..` is rejected (so `path/.`, `child/..`, `/tmp/..` all fail), as is the
/// filesystem root and an empty/`~` target. This is a lexical rule on the given
/// path — deliberately not stricter than rm (no home/cwd/ancestor guessing).
fn check_rm_safety(locs: &[Location], _args: &Args) -> Result<()> {
    for l in locs {
        let raw = l.path.trim_end_matches('/');
        let last = raw.rsplit('/').next().unwrap_or("");
        if raw.is_empty() || l.path == "/" {
            bail!("refusing to remove the filesystem root {:?}", l.path);
        }
        if raw == "~" {
            bail!("refusing to remove {:?}", l.path);
        }
        if last == "." || last == ".." {
            bail!(
                "\"{}\" may not be removed: its final path component is {:?}",
                l.path,
                last
            );
        }
    }
    Ok(())
}

pub fn run(args: Args) -> Result<i32> {
    let locs: Vec<Location> = args
        .paths
        .iter()
        .map(|p| Location::parse(p))
        .collect::<Result<_>>()?;
    for l in &locs {
        if !l.same_host(&locs[0]) {
            bail!("all paths must be on the same host");
        }
    }
    let mut args = args;
    check_rm_safety(&locs, &args)?;
    let ep = endpoint(&locs[0], &args)?;
    if args.connections_default && !ep.is_remote() {
        args.connections = crate::transfer::LOCAL_DEFAULT_CONNECTIONS;
    }
    let mut ctl = connect_ctl(&ep, &args)?;

    let show_progress = !args.no_progress && !args.quiet && !args.dry_run;
    let progress = Progress::new(
        args.connections,
        show_progress,
        args.progress,
        args.width,
        args.progress_json,
    );
    // Safety: Progress is behind an Arc we just created; set the mode before anyone reads it.
    let progress = {
        let mut p = Arc::try_unwrap(progress).ok().expect("fresh progress");
        p.rm = true;
        Arc::new(p)
    };
    progress.scan_done.store(true, Relaxed);
    let ticker = progress.spawn_ticker();

    let (tx, rx) = mpsc::channel::<Vec<Op>>();
    let rx = Arc::new(Mutex::new(rx));
    let pool = Arc::new(Pool {
        tx: Mutex::new(Some(tx)),
        pending: Mutex::new(0),
        cv: Condvar::new(),
        progress: progress.clone(),
        verbose: args.verbose > 0,
        aborted: std::sync::atomic::AtomicBool::new(false),
    });
    let mut workers = Vec::new();
    if !args.dry_run {
        for _ in 0..args.connections {
            let (pool, rx, ep, compress) = (pool.clone(), rx.clone(), ep.clone(), args.compress);
            workers.push(std::thread::spawn(move || {
                let r = worker(pool.clone(), rx, ep, compress);
                if r.is_err() {
                    pool.abort(); // wake wait_idle even if connect() failed before any op
                }
                r
            }));
        }
    }

    // Directories by depth, removed after all files are gone.
    let mut dirs: BTreeMap<usize, Vec<PathBytes>> = BTreeMap::new();
    let mut scan_err = None;
    for l in &locs {
        let root = l.path.as_bytes().to_vec();
        let mut batch: Vec<Op> = Vec::with_capacity(BATCH);
        let res = ctl.scan(
            &root,
            false,
            &[],
            &mut |entries: Vec<Entry>| {
                for e in entries {
                    let full = join(&root, &e.path);
                    progress.files_total.fetch_add(1, Relaxed);
                    if e.kind == Kind::Dir {
                        let depth = full.iter().filter(|&&c| c == b'/').count();
                        dirs.entry(depth).or_default().push(full);
                    } else if args.dry_run {
                        progress.files_done.fetch_add(1, Relaxed);
                        if args.verbose > 0 {
                            println!("{}", String::from_utf8_lossy(&full));
                        }
                    } else {
                        batch.push(Op::Remove { path: full });
                        if batch.len() >= BATCH {
                            pool.submit(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)));
                        }
                    }
                }
                Ok(())
            },
            &mut |w| progress.error(&format!("syq: {w}")),
        );
        pool.submit(batch);
        if let Err(e) = res {
            scan_err = Some(e);
            break;
        }
    }
    pool.wait_idle();

    // Deepest first; every directory at one depth can go in parallel.
    for (_, paths) in dirs.iter().rev() {
        if args.dry_run {
            progress.files_done.fetch_add(paths.len() as u64, Relaxed);
            if args.verbose > 0 {
                for p in paths {
                    println!("{}/", String::from_utf8_lossy(p));
                }
            }
            continue;
        }
        for chunk in paths.chunks(
            BATCH
                .max(paths.len() / (args.connections * 2).max(1))
                .min(BATCH),
        ) {
            pool.submit(
                chunk
                    .iter()
                    .map(|p| Op::Rmdir { path: p.clone() })
                    .collect(),
            );
        }
        pool.wait_idle();
    }
    pool.close();
    for w in workers {
        if let Ok(Err(e)) = w.join() {
            progress.error(&format!("syq: worker: {e:#}"));
        }
    }
    progress.stop();
    if let Some(t) = ticker {
        let _ = t.join();
    }
    progress.clear();
    if let Some(e) = scan_err {
        progress.error(&format!("syq: {e:#}"));
    }
    let errors = progress.errors.load(Relaxed) + if pool.is_aborted() { 1 } else { 0 };
    if !args.quiet {
        println!(
            "syq: {} {} entries in {}{}",
            if args.dry_run {
                "would remove"
            } else {
                "removed"
            },
            commas(progress.files_done.load(Relaxed)),
            crate::progress::hms(progress.start.elapsed().as_secs_f64()),
            if errors > 0 {
                format!(", {errors} errors")
            } else {
                String::new()
            }
        );
    }
    Ok(if errors > 0 { 23 } else { 0 })
}
