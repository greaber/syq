//! `syq rsync --rm` and native `syq rm`: recursive removal with N parallel
//! connections.
//!
//! Compatibility removal preserves the streaming scan/execution path. Native
//! removal completes selection, readiness assessment, and approval before it
//! mutates anything, then unlinks leaves and removes directories deepest-first.

use crate::cli::{Args, Interface, Location};
use crate::conn::{ok, Conn, Endpoint};
use crate::fsops::join;
use crate::progress::{commas, Progress};
use crate::proto::*;
use crate::transfer::{connect_ctl, endpoint};
use anyhow::{bail, Context, Result};
use std::collections::{btree_map::Entry as BtreeEntry, BTreeMap};
use std::io::{BufRead, Write};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{mpsc, Arc, Condvar, Mutex};

const BATCH: usize = 200;
type WorkReceiver = Arc<Mutex<mpsc::Receiver<Vec<Op>>>>;

struct Pool {
    tx: Mutex<Option<mpsc::Sender<Vec<Op>>>>,
    pending: Mutex<usize>,
    cv: Condvar,
    progress: Arc<Progress>,
    verbose: bool,
    aborted: std::sync::atomic::AtomicBool,
    failed_paths: Mutex<Vec<PathBytes>>,
}

impl Pool {
    fn submit(&self, ops: Vec<Op>) {
        if ops.is_empty() || self.is_aborted() {
            return;
        }
        *self.pending.lock().unwrap() += 1;
        let sent = self
            .tx
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|tx| tx.send(ops).is_ok());
        if !sent {
            self.done();
            self.abort();
        }
    }

    fn done(&self) {
        let mut pending = self.pending.lock().unwrap();
        *pending -= 1;
        if *pending == 0 {
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

    fn fail(&self, path: PathBytes) {
        self.failed_paths.lock().unwrap().push(path);
    }

    fn failures(&self) -> Vec<PathBytes> {
        self.failed_paths.lock().unwrap().clone()
    }

    fn wait_idle(&self) {
        let mut pending = self.pending.lock().unwrap();
        while *pending > 0 && !self.is_aborted() {
            pending = self.cv.wait(pending).unwrap();
        }
    }

    fn close(&self) {
        self.tx.lock().unwrap().take();
    }
}

fn op_path(op: &Op) -> Option<&PathBytes> {
    match op {
        Op::Remove { path }
        | Op::Rmdir { path }
        | Op::Unlink { path }
        | Op::UnlinkIfSame { path, .. }
        | Op::RmdirIfSame { path, .. } => Some(path),
        _ => None,
    }
}

fn worker(pool: Arc<Pool>, rx: WorkReceiver, ep: Endpoint, compress: bool) -> Result<()> {
    let mut conn: Box<dyn Conn> = ep.connect(compress)?;
    loop {
        let ops = match rx.lock().unwrap().recv() {
            Ok(ops) => ops,
            Err(_) => return Ok(()),
        };
        if pool.is_aborted() {
            // Drain work counted as pending after an operation-invalidating
            // failure without performing more mutations.
            pool.done();
            continue;
        }
        let names: Vec<PathBytes> = ops.iter().filter_map(op_path).cloned().collect();
        let result = conn
            .call(Request::Apply { ops, guard: None })
            .and_then(|response| ok(response, "remove"));
        match result {
            Ok(Response::Applied(errors)) if errors.len() == names.len() => {
                for (name, error) in names.iter().zip(errors) {
                    match error {
                        Some(error) => {
                            pool.fail(name.clone());
                            pool.progress.error(&format!("syq: {error}"));
                        }
                        None => {
                            pool.progress.files_done.fetch_add(1, Relaxed);
                            if pool.verbose {
                                pool.progress.println(&String::from_utf8_lossy(name));
                            }
                        }
                    }
                }
            }
            Ok(Response::Applied(errors)) => {
                for name in names {
                    pool.fail(name);
                }
                pool.progress.error(&format!(
                    "syq: remove returned {} results for a different-sized request",
                    errors.len()
                ));
                pool.abort();
            }
            Ok(other) => {
                for name in names {
                    pool.fail(name);
                }
                pool.progress
                    .error(&format!("syq: unexpected response {other:?}"));
                pool.abort();
            }
            Err(error) => {
                for name in names {
                    pool.fail(name);
                }
                pool.progress.error(&format!("syq: {error:#}"));
                pool.done();
                if conn.is_dead() {
                    pool.abort();
                    return Err(error);
                }
                continue;
            }
        }
        pool.done();
    }
}

/// Match `rm -rf` refusals: a target whose lexical final component is `.` or
/// `..` is rejected (so `path/.`, `child/..`, `/tmp/..` all fail), as is the
/// filesystem root and an empty/`~` target. This is a lexical rule on the given
/// path -- deliberately not stricter than rm (no home/cwd/ancestor guessing).
fn check_rm_safety(locs: &[Location], _args: &Args) -> Result<()> {
    for location in locs {
        let mut raw = location.path.as_slice();
        while raw.ends_with(b"/") {
            raw = &raw[..raw.len() - 1];
        }
        let last = raw.rsplit(|byte| *byte == b'/').next().unwrap_or(b"");
        let shown = String::from_utf8_lossy(&location.path);
        if raw.is_empty() || location.path == b"/" {
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

#[derive(Default)]
struct DeletePlan {
    leaves: Vec<DeleteCandidate>,
    dirs: BTreeMap<usize, Vec<DeleteCandidate>>,
}

impl DeletePlan {
    fn len(&self) -> usize {
        self.leaves.len() + self.dirs.values().map(Vec::len).sum::<usize>()
    }

    fn directories(&self) -> usize {
        self.dirs.values().map(Vec::len).sum()
    }

    fn candidates(&self) -> impl Iterator<Item = &DeleteCandidate> {
        self.leaves.iter().chain(self.dirs.values().rev().flatten())
    }
}

fn delete_condition(entry: &Entry) -> TargetCondition {
    if entry.kind == Kind::Dir {
        // Removing children intentionally changes a directory's ctime. Its
        // stable device/inode identity still distinguishes a replacement.
        TargetCondition::Matches {
            dev: entry.dev,
            ino: entry.ino,
        }
    } else {
        TargetCondition::MatchesFingerprint {
            dev: entry.dev,
            ino: entry.ino,
            ctime: entry.ctime,
            ctime_nsec: entry.ctime_nsec,
        }
    }
}

fn build_delete_plan(ctl: &mut dyn Conn, locs: &[Location]) -> Result<DeletePlan> {
    let mut selected: BTreeMap<PathBytes, DeleteCandidate> = BTreeMap::new();
    let mut issues = Vec::new();
    for location in locs {
        let root = location.path.clone();
        let scan_result = ctl.scan(
            &root,
            false,
            &[],
            false,
            &mut |entries: Vec<Entry>| {
                for entry in entries {
                    let path = join(&root, &entry.path);
                    let candidate = DeleteCandidate {
                        path: path.clone(),
                        kind: entry.kind,
                        condition: delete_condition(&entry),
                    };
                    match selected.entry(path) {
                        BtreeEntry::Vacant(slot) => {
                            slot.insert(candidate);
                        }
                        BtreeEntry::Occupied(slot)
                            if slot.get().kind == candidate.kind
                                && slot.get().condition == candidate.condition => {}
                        BtreeEntry::Occupied(slot) => {
                            bail!(
                                "{} changed while overlapping selectors were being evaluated",
                                String::from_utf8_lossy(&slot.get().path)
                            );
                        }
                    }
                }
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |warning| issues.push(warning),
        );
        if let Err(error) = scan_result {
            issues.push(format!("{}: {error:#}", String::from_utf8_lossy(&root)));
        }
    }
    if !issues.is_empty() {
        let details = issues
            .into_iter()
            .map(|issue| format!("  - {issue}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!("cannot construct a complete deletion plan; deleting nothing:\n{details}");
    }

    let mut plan = DeletePlan::default();
    for (_, candidate) in selected {
        if candidate.kind == Kind::Dir {
            let depth = candidate.path.iter().filter(|byte| **byte == b'/').count();
            plan.dirs.entry(depth).or_default().push(candidate);
        } else {
            plan.leaves.push(candidate);
        }
    }
    Ok(plan)
}

fn assess_delete_plan(
    ctl: &mut dyn Conn,
    plan: &DeletePlan,
) -> Result<Vec<(PathBytes, DeleteReadiness)>> {
    let candidates: Vec<DeleteCandidate> = plan.candidates().cloned().collect();
    let mut assessed = Vec::with_capacity(candidates.len());
    for chunk in candidates.chunks(BATCH) {
        let response = ok(
            ctl.call(Request::AssessDeletes {
                candidates: chunk.to_vec(),
            })?,
            "assess deletion readiness",
        )?;
        let Response::DeleteReadiness(readiness) = response else {
            bail!("unexpected response {response:?}");
        };
        if readiness.len() != chunk.len() {
            bail!(
                "deletion readiness returned {} results for {} candidates",
                readiness.len(),
                chunk.len()
            );
        }
        assessed.extend(
            chunk
                .iter()
                .zip(readiness)
                .map(|(candidate, readiness)| (candidate.path.clone(), readiness)),
        );
    }
    Ok(assessed)
}

fn endpoint_label(location: &Location) -> String {
    match (&location.user, &location.host) {
        (Some(user), Some(host)) => format!("{user}@{host}"),
        (None, Some(host)) => host.clone(),
        (_, None) => "local".into(),
    }
}

fn print_native_plan(args: &Args, locs: &[Location], plan: &DeletePlan) {
    if args.quiet {
        return;
    }
    let directories = plan.directories();
    println!(
        "syq rm plan: {} entries ({} non-directories, {} directories) on {}",
        commas(plan.len() as u64),
        commas(plan.leaves.len() as u64),
        commas(directories as u64),
        endpoint_label(&locs[0])
    );
    println!("selected roots:");
    for location in locs {
        println!("  {}", String::from_utf8_lossy(&location.path));
    }
    if args.verbose > 0 {
        println!("planned actions:");
        for candidate in &plan.leaves {
            println!("  unlink {}", String::from_utf8_lossy(&candidate.path));
        }
        for candidate in plan.dirs.values().rev().flatten() {
            println!("  rmdir {}", String::from_utf8_lossy(&candidate.path));
        }
    }
}

fn confirm_delete(count: usize) -> Result<bool> {
    eprint!(
        "Approve removal of {} planned entries? [y/N] ",
        commas(count as u64)
    );
    std::io::stderr().flush().context("flush approval prompt")?;
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .context("read deletion approval")?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(debug_assertions)]
fn hold_after_native_rm_plan_for_test() -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_RM_PLAN_READY_FILE") {
        std::fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write rm-plan-ready signal {}",
                std::path::Path::new(&ready).display()
            )
        })?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_RM_PLAN_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_native_rm_plan_for_test() -> Result<()> {
    Ok(())
}

fn path_is_at_or_beneath(path: &[u8], ancestor: &[u8]) -> bool {
    path == ancestor
        || (path.starts_with(ancestor)
            && (ancestor.ends_with(b"/") || path.get(ancestor.len()) == Some(&b'/')))
}

fn new_pool(progress: Arc<Progress>, verbose: bool) -> (Arc<Pool>, WorkReceiver) {
    let (tx, rx) = mpsc::channel::<Vec<Op>>();
    (
        Arc::new(Pool {
            tx: Mutex::new(Some(tx)),
            pending: Mutex::new(0),
            cv: Condvar::new(),
            progress,
            verbose,
            aborted: std::sync::atomic::AtomicBool::new(false),
            failed_paths: Mutex::new(Vec::new()),
        }),
        Arc::new(Mutex::new(rx)),
    )
}

fn spawn_workers(
    count: usize,
    pool: &Arc<Pool>,
    rx: &WorkReceiver,
    ep: &Endpoint,
    compress: bool,
) -> Vec<std::thread::JoinHandle<Result<()>>> {
    (0..count)
        .map(|_| {
            let (pool, rx, ep) = (pool.clone(), rx.clone(), ep.clone());
            std::thread::spawn(move || {
                let result = worker(pool.clone(), rx, ep, compress);
                if result.is_err() {
                    pool.abort();
                }
                result
            })
        })
        .collect()
}

fn finish_workers(pool: &Arc<Pool>, workers: Vec<std::thread::JoinHandle<Result<()>>>) {
    pool.close();
    for worker in workers {
        match worker.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => pool.progress.error(&format!("syq: worker: {error:#}")),
            Err(_) => {
                pool.abort();
                pool.progress.error("syq: removal worker panicked");
            }
        }
    }
}

fn run_native(mut args: Args, locs: Vec<Location>) -> Result<i32> {
    let ep = endpoint(&locs[0], &args)?;
    if args.connections_default && !ep.is_remote() {
        args.connections = crate::transfer::LOCAL_DEFAULT_CONNECTIONS;
    }
    let mut ctl = connect_ctl(&ep, &args)?;
    let plan = build_delete_plan(ctl.as_mut(), &locs)?;
    let readiness = assess_delete_plan(ctl.as_mut(), &plan)?;
    print_native_plan(&args, &locs, &plan);

    let mut force_required = 0usize;
    let mut changed = 0usize;
    for (path, status) in &readiness {
        match status {
            DeleteReadiness::Ready => {}
            DeleteReadiness::NeedsForce(reason) => {
                force_required += 1;
                let path = String::from_utf8_lossy(path);
                if args.rm_force {
                    eprintln!("syq: warning: forcing removal of {path}: {reason}");
                } else if args.dry_run {
                    eprintln!("syq: plan would require --force for {path}: {reason}");
                } else {
                    eprintln!("syq: plan requires --force for {path}: {reason}");
                }
            }
            DeleteReadiness::Unknown(reason) => eprintln!(
                "syq: warning: deletion readiness is unknown for {}: {reason}",
                String::from_utf8_lossy(path)
            ),
            DeleteReadiness::Changed(reason) => {
                changed += 1;
                eprintln!(
                    "syq: plan is stale for {}: {reason}",
                    String::from_utf8_lossy(path)
                );
            }
        }
    }
    if changed > 0 {
        bail!("{changed} planned entries changed during preflight; deleting nothing");
    }
    if args.dry_run {
        if !args.quiet {
            println!("syq: would remove {} entries", commas(plan.len() as u64));
        }
        return Ok(0);
    }
    if force_required > 0 && !args.rm_force {
        bail!("{force_required} planned entries require --force; deleting nothing");
    }
    if !args.rm_yes && !confirm_delete(plan.len())? {
        if !args.quiet {
            println!("syq: removal cancelled; removed 0 entries");
        }
        return Ok(0);
    }
    hold_after_native_rm_plan_for_test()?;

    let show_progress = !args.no_progress && !args.quiet;
    let progress = Progress::new(
        args.connections,
        show_progress,
        args.progress,
        args.width,
        !args.quiet && args.progress_json,
    );
    let progress = {
        let mut progress = Arc::try_unwrap(progress).ok().expect("fresh progress");
        progress.rm = true;
        Arc::new(progress)
    };
    progress
        .files_total
        .store(plan.len().try_into().unwrap_or(u64::MAX), Relaxed);
    progress.scan_done.store(true, Relaxed);
    let ticker = progress.spawn_ticker();
    let (pool, rx) = new_pool(progress.clone(), false);
    let workers = spawn_workers(args.connections, &pool, &rx, &ep, args.compress);

    for chunk in plan.leaves.chunks(BATCH) {
        pool.submit(
            chunk
                .iter()
                .map(|candidate| Op::UnlinkIfSame {
                    path: candidate.path.clone(),
                    condition: candidate.condition,
                })
                .collect(),
        );
    }
    pool.wait_idle();

    if !pool.is_aborted() {
        for (_, candidates) in plan.dirs.iter().rev() {
            let failures = pool.failures();
            let mut eligible = Vec::with_capacity(candidates.len());
            for candidate in candidates {
                if failures
                    .iter()
                    .any(|failed| path_is_at_or_beneath(failed, &candidate.path))
                {
                    pool.fail(candidate.path.clone());
                    pool.progress.error(&format!(
                        "syq: skipping {} because a descendant deletion failed",
                        String::from_utf8_lossy(&candidate.path)
                    ));
                } else {
                    eligible.push(candidate);
                }
            }
            for chunk in eligible.chunks(BATCH) {
                pool.submit(
                    chunk
                        .iter()
                        .map(|candidate| Op::RmdirIfSame {
                            path: candidate.path.clone(),
                            condition: candidate.condition,
                        })
                        .collect(),
                );
            }
            pool.wait_idle();
            if pool.is_aborted() {
                break;
            }
        }
    }

    finish_workers(&pool, workers);
    progress.stop();
    if let Some(ticker) = ticker {
        let _ = ticker.join();
    }
    progress.clear();
    let errors = progress.errors.load(Relaxed);
    if !args.quiet {
        println!(
            "syq: removed {} of {} planned entries in {}{}",
            commas(progress.files_done.load(Relaxed)),
            commas(progress.files_total.load(Relaxed)),
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

fn run_streaming(mut args: Args, locs: Vec<Location>) -> Result<i32> {
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
    let progress = {
        let mut progress = Arc::try_unwrap(progress).ok().expect("fresh progress");
        progress.rm = true;
        Arc::new(progress)
    };
    progress.scan_done.store(true, Relaxed);
    let ticker = progress.spawn_ticker();
    let (pool, rx) = new_pool(progress.clone(), verbose);
    let workers = if args.dry_run {
        Vec::new()
    } else {
        spawn_workers(args.connections, &pool, &rx, &ep, args.compress)
    };

    // Directories by depth, removed after all files are gone. Compatibility
    // mode deliberately retains scan/execution overlap for non-directories.
    let mut dirs: BTreeMap<usize, Vec<PathBytes>> = BTreeMap::new();
    let mut scan_err = None;
    for location in &locs {
        let root = location.path.clone();
        let mut batch: Vec<Op> = Vec::with_capacity(BATCH);
        let result = ctl.scan(
            &root,
            false,
            &[],
            false,
            &mut |entries: Vec<Entry>| {
                for entry in entries {
                    let full = join(&root, &entry.path);
                    progress.files_total.fetch_add(1, Relaxed);
                    if entry.kind == Kind::Dir {
                        let depth = full.iter().filter(|&&byte| byte == b'/').count();
                        dirs.entry(depth).or_default().push(full);
                    } else if args.dry_run {
                        progress.files_done.fetch_add(1, Relaxed);
                        if verbose {
                            println!("{}", String::from_utf8_lossy(&full));
                        }
                    } else {
                        // A leaf that becomes a directory is refused rather
                        // than recursively deleting an unscanned population.
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
                        batch.push(Op::Unlink { path: full });
                        if batch.len() >= BATCH {
                            pool.submit(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)));
                        }
                    }
                }
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |warning| progress.error(&format!("syq: {warning}")),
        );
        pool.submit(batch);
        if let Err(error) = result {
            scan_err = Some(error);
            break;
        }
    }
    pool.wait_idle();

    for (_, paths) in dirs.iter().rev() {
        if args.dry_run {
            progress.files_done.fetch_add(paths.len() as u64, Relaxed);
            if verbose {
                for path in paths {
                    println!("{}/", String::from_utf8_lossy(path));
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
                    .map(|path| Op::Rmdir { path: path.clone() })
                    .collect(),
            );
        }
        pool.wait_idle();
    }
    finish_workers(&pool, workers);
    progress.stop();
    if let Some(ticker) = ticker {
        let _ = ticker.join();
    }
    progress.clear();
    if let Some(error) = scan_err {
        progress.error(&format!("syq: {error:#}"));
    }
    let errors = progress.errors.load(Relaxed);
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

pub fn run(args: Args) -> Result<i32> {
    let mut locs: Vec<Location> = if args.locations.is_empty() {
        args.paths
            .iter()
            .map(|path| Location::parse(path))
            .collect::<Result<_>>()?
    } else {
        args.locations.clone()
    };
    for location in &locs {
        if !location.same_host(&locs[0]) {
            bail!("all paths must be on the same host");
        }
    }
    check_rm_safety(&locs, &args)?;
    if args.interface == Interface::NativeRm {
        // Exact duplicates do not need a second scan. Nested selectors remain
        // and are collapsed by population membership after scanning.
        locs.sort_by(|left, right| left.path.cmp(&right.path));
        locs.dedup_by(|left, right| left.path == right.path);
        run_native(args, locs)
    } else {
        run_streaming(args, locs)
    }
}
