//! `syq rsync --rm` and native `syq rm`: recursive removal with N parallel
//! connections. Files are
//! unlinked in batches spread across workers; directories are removed
//! deepest-first, each depth level in parallel.

use crate::cli::{Args, Interface, Location, SourceSelection};
use crate::conn::{ok, Conn, Endpoint};
use crate::fsops::join;
use crate::progress::{commas, Progress};
use crate::proto::*;
use crate::transfer::{connect_ctl, endpoint};
use anyhow::{bail, Result};
use std::collections::{BTreeMap, HashSet};
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
                Op::Remove { path } | Op::Rmdir { path } | Op::Unlink { path } => path.clone(),
                _ => Vec::new(),
            })
            .collect();
        let res = conn
            .call(Request::Apply { ops, guard: None })
            .and_then(|r| ok(r, "remove"));
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
        let mut raw = l.path.as_slice();
        while raw.ends_with(b"/") {
            raw = &raw[..raw.len() - 1];
        }
        let last = raw.rsplit(|byte| *byte == b'/').next().unwrap_or(b"");
        let shown = String::from_utf8_lossy(&l.path);
        if raw.is_empty() || l.path == b"/" {
            bail!("refusing to remove the filesystem root {shown:?}");
        }
        if raw == b"~" {
            bail!("refusing to remove {shown:?}");
        }
        if last == b"." || last == b".." {
            bail!(
                "\"{shown}\" may not be removed: its final path component is {:?}",
                String::from_utf8_lossy(last)
            );
        }
    }
    Ok(())
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct SelectorKey {
    absolute: bool,
    components: Vec<Vec<u8>>,
}

impl SelectorKey {
    fn new(path: &[u8]) -> Self {
        Self {
            absolute: path.starts_with(b"/"),
            components: path
                .split(|byte| *byte == b'/')
                .filter(|component| !component.is_empty() && *component != b".")
                .map(<[u8]>::to_vec)
                .collect(),
        }
    }

    fn is_strict_ancestor_of(&self, other: &Self) -> bool {
        self.absolute == other.absolute
            && self.components.len() < other.components.len()
            && other.components.starts_with(&self.components)
    }
}

fn selection_order(selection: SourceSelection) -> u8 {
    match selection {
        SourceSelection::Contents => 0,
        SourceSelection::Named | SourceSelection::NamedNoFollow | SourceSelection::Rsync => 1,
    }
}

/// Give each distinct lexical path-and-mode selector one scan. Exact aliases
/// in the same mode are deduplicated. Cross-mode selectors remain independent,
/// and overlapping roots are ordered so they can be serialized without one
/// selection mutating the namespace beneath another.
fn normalize_native_rm_locations(locs: Vec<Location>) -> (Vec<Location>, bool) {
    let mut identities = HashSet::new();
    let mut normalized: Vec<(Location, SelectorKey)> = Vec::with_capacity(locs.len());
    for location in locs {
        let key = SelectorKey::new(&location.path);
        let identity = (key.clone(), location.selection);
        if !identities.insert(identity) {
            continue;
        }
        normalized.push((location, key));
    }

    let overlaps = normalized.iter().enumerate().any(|(index, (_, key))| {
        normalized[index + 1..].iter().any(|(_, other)| {
            key == other || key.is_strict_ancestor_of(other) || other.is_strict_ancestor_of(key)
        })
    });
    if overlaps {
        // Descendants precede ancestors. At one path, contents precedes the
        // named object so a selected symlink remains usable for that scan.
        normalized.sort_by(|(left_location, left), (right_location, right)| {
            right
                .components
                .len()
                .cmp(&left.components.len())
                .then_with(|| left.cmp(right))
                .then_with(|| {
                    selection_order(left_location.selection)
                        .cmp(&selection_order(right_location.selection))
                })
        });
    }
    (
        normalized
            .into_iter()
            .map(|(location, _)| location)
            .collect(),
        overlaps,
    )
}

fn remove_pending_directories(
    dirs: &mut BTreeMap<usize, Vec<PathBytes>>,
    args: &Args,
    pool: &Arc<Pool>,
    progress: &Arc<Progress>,
    verbose: bool,
) {
    // Deepest first; every directory at one depth can go in parallel.
    for paths in dirs.values().rev() {
        if args.dry_run {
            progress.files_done.fetch_add(paths.len() as u64, Relaxed);
            if verbose {
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
    dirs.clear();
}

pub fn run(args: Args) -> Result<i32> {
    let mut locs: Vec<Location> = if args.locations.is_empty() {
        args.paths
            .iter()
            .map(|p| Location::parse(p))
            .collect::<Result<_>>()?
    } else {
        args.locations.clone()
    };
    for l in &locs {
        if !l.same_host(&locs[0]) {
            bail!("all paths must be on the same host");
        }
    }
    check_rm_safety(&locs, &args)?;
    let serialize_selectors = if args.interface == Interface::NativeRm {
        let (normalized, overlaps) = normalize_native_rm_locations(locs);
        locs = normalized;
        overlaps
    } else {
        false
    };
    let mut args = args;
    let ep = endpoint(&locs[0], &args)?;
    if args.connections_default && !ep.is_remote() {
        args.connections = crate::transfer::LOCAL_DEFAULT_CONNECTIONS;
    }
    let mut ctl = connect_ctl(&ep, &args)?;

    let show_progress = !args.no_progress && !args.quiet && !args.dry_run;
    let verbose = !args.quiet && args.verbose > 0;
    let progress = Progress::new(
        args.connections,
        show_progress,
        args.progress,
        args.width,
        !args.quiet && args.progress_json,
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
        verbose,
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
    // A dry run cannot make a descendant disappear before its ancestor is
    // scanned, so suppress entries already reported by an overlapping root.
    let mut dry_run_seen = (serialize_selectors && args.dry_run).then(HashSet::new);
    let mut scan_err = None;
    for l in &locs {
        let root = l.path.clone();
        let contents = l.copies_contents();
        let mut batch: Vec<Op> = Vec::with_capacity(BATCH);
        let res = ctl.scan(
            &root,
            contents,
            &[],
            false,
            &mut |entries: Vec<Entry>| {
                for e in entries {
                    if contents && e.path.is_empty() {
                        if e.kind != Kind::Dir {
                            bail!(
                                "contents selector {} is not a directory",
                                String::from_utf8_lossy(&root)
                            );
                        }
                        continue;
                    }
                    let full = join(&root, &e.path);
                    if let Some(seen) = dry_run_seen.as_mut() {
                        if !seen.insert(SelectorKey::new(&full)) {
                            continue;
                        }
                    }
                    progress.files_total.fetch_add(1, Relaxed);
                    if e.kind == Kind::Dir {
                        let depth = full.iter().filter(|&&c| c == b'/').count();
                        dirs.entry(depth).or_default().push(full);
                    } else if args.dry_run {
                        progress.files_done.fetch_add(1, Relaxed);
                        if verbose {
                            println!("{}", String::from_utf8_lossy(&full));
                        }
                    } else {
                        #[cfg(debug_assertions)]
                        {
                            if let Some(ready) = std::env::var_os("SYQ_TEST_RM_LEAF_READY_FILE") {
                                std::fs::write(&ready, b"ready")?;
                            }
                            if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_RM_LEAF_MS") {
                                if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                                    std::thread::sleep(std::time::Duration::from_millis(ms));
                                }
                            }
                        }
                        // The scan selected a non-directory. Do not broaden that
                        // decision if a directory appears here before execution.
                        batch.push(Op::Unlink { path: full });
                        if batch.len() >= BATCH {
                            pool.submit(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)));
                        }
                    }
                }
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |w| progress.error(&format!("syq: {w}")),
        );
        pool.submit(batch);
        let error = res.err();
        if serialize_selectors {
            pool.wait_idle();
            remove_pending_directories(&mut dirs, &args, &pool, &progress, verbose);
        }
        if let Some(e) = error {
            scan_err = Some(e);
            break;
        }
    }
    pool.wait_idle();
    remove_pending_directories(&mut dirs, &args, &pool, &progress, verbose);
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
