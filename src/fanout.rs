//! Coordinated execution of one native copy against several destinations.
//!
//! Each member uses the single-target transfer engine. The group shares the
//! descriptor-backed source scan, holds every destination mutation behind one
//! barrier, and cancels all peer schedulers after a fatal member failure.

use crate::bwlimit::BandwidthLimit;
use crate::cli::{Args, Location};
use crate::progress::Progress;
use crate::proto::Entry;
use crate::sched::Sched;
use anyhow::{bail, Result};
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Condvar, Mutex, Weak};

#[derive(Clone, Debug)]
pub struct RunContext {
    pub group: Arc<Group>,
    pub label: String,
    pub destination_index: usize,
}

#[derive(Debug)]
pub struct ScannedSource {
    pub batches: Vec<Vec<Entry>>,
    pub ignored: u64,
    pub warnings: Vec<String>,
}

impl ScannedSource {
    pub fn root(&self) -> Option<&Entry> {
        self.batches.first().and_then(|batch| batch.first())
    }
}

pub enum ScanClaim {
    Populate,
    Cached(Arc<ScannedSource>),
}

#[derive(Debug)]
enum SourceState {
    Available,
    Scanning,
    Ready(Arc<ScannedSource>),
    Failed(String),
}

#[derive(Debug)]
struct SourceCache {
    state: Mutex<SourceState>,
    ready: Condvar,
}

#[derive(Debug)]
struct Preflight {
    arrived: usize,
    released: bool,
    failure: Option<String>,
}

pub struct Group {
    total: usize,
    quiet: bool,
    preflight: Mutex<Preflight>,
    ready: Condvar,
    sources: Vec<SourceCache>,
    cancelled: AtomicBool,
    schedulers: Mutex<Vec<Weak<Sched>>>,
    progresses: Mutex<Vec<Option<Arc<Progress>>>>,
    terminals: Mutex<Vec<Option<crate::results::ResultRecord>>>,
    results: Option<Arc<crate::results::ResultsWriter>>,
    bandwidth: Option<Arc<BandwidthLimit>>,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Group")
            .field("total", &self.total)
            .field("cancelled", &self.cancelled.load(Relaxed))
            .finish_non_exhaustive()
    }
}

impl Group {
    fn new(
        total: usize,
        source_count: usize,
        quiet: bool,
        bytes_per_second: u64,
        results: Option<Arc<crate::results::ResultsWriter>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            total,
            quiet,
            preflight: Mutex::new(Preflight {
                arrived: 0,
                released: false,
                failure: None,
            }),
            ready: Condvar::new(),
            sources: (0..source_count)
                .map(|_| SourceCache {
                    state: Mutex::new(SourceState::Available),
                    ready: Condvar::new(),
                })
                .collect(),
            cancelled: AtomicBool::new(false),
            schedulers: Mutex::new(Vec::with_capacity(total)),
            progresses: Mutex::new(vec![None; total]),
            terminals: Mutex::new(vec![None; total]),
            results,
            bandwidth: (bytes_per_second > 0)
                .then(|| Arc::new(BandwidthLimit::new(bytes_per_second))),
        })
    }

    pub fn bandwidth(&self) -> Option<Arc<BandwidthLimit>> {
        self.bandwidth.clone()
    }

    pub fn register_scheduler(self: &Arc<Self>, scheduler: &Arc<Sched>) {
        scheduler.attach_fanout(Arc::downgrade(self));
        self.schedulers
            .lock()
            .unwrap()
            .push(Arc::downgrade(scheduler));
        if self.cancelled.load(Relaxed) {
            scheduler.abort_from_fanout();
        }
    }

    pub fn results(&self) -> Option<Arc<crate::results::ResultsWriter>> {
        self.results.clone()
    }

    pub fn register_progress(&self, index: usize, progress: &Arc<Progress>) {
        self.progresses.lock().unwrap()[index] = Some(progress.clone());
    }

    pub fn complete_member(&self, index: usize, terminal: crate::results::ResultRecord) {
        self.terminals.lock().unwrap()[index] = Some(terminal);
    }

    fn aggregate_terminal(
        &self,
        args: &Args,
        exit_code: i32,
        elapsed_ms: u64,
    ) -> crate::results::ResultRecord {
        let terminals = self.terminals.lock().unwrap();
        let progresses = self.progresses.lock().unwrap();
        let mut aggregate = crate::results::ResultRecord {
            status: match exit_code {
                0 => "success",
                23 => "partial",
                25 => "refused",
                _ => "failed",
            },
            exit_code,
            dry_run: args.dry_run,
            files_transferred: 0,
            files_unchanged: 0,
            files_excluded: 0,
            directories_created: 0,
            symlinks_created: 0,
            specials_created: 0,
            errors: 0,
            bytes_transferred: 0,
            bytes_unchanged: 0,
            elapsed_ms,
            deletions_planned: args.delete.then_some(0),
            deletions_completed: args.delete.then_some(0),
            deletions_blocked: args.delete.then_some(0),
        };
        for (index, terminal) in terminals.iter().enumerate() {
            if let Some(terminal) = terminal {
                aggregate.files_transferred = aggregate
                    .files_transferred
                    .saturating_add(terminal.files_transferred);
                aggregate.files_unchanged = aggregate
                    .files_unchanged
                    .saturating_add(terminal.files_unchanged);
                aggregate.files_excluded = aggregate
                    .files_excluded
                    .saturating_add(terminal.files_excluded);
                aggregate.directories_created = aggregate
                    .directories_created
                    .saturating_add(terminal.directories_created);
                aggregate.symlinks_created = aggregate
                    .symlinks_created
                    .saturating_add(terminal.symlinks_created);
                aggregate.specials_created = aggregate
                    .specials_created
                    .saturating_add(terminal.specials_created);
                aggregate.errors = aggregate.errors.saturating_add(terminal.errors);
                aggregate.bytes_transferred = aggregate
                    .bytes_transferred
                    .saturating_add(terminal.bytes_transferred);
                aggregate.bytes_unchanged = aggregate
                    .bytes_unchanged
                    .saturating_add(terminal.bytes_unchanged);
                aggregate.deletions_planned =
                    sum_optional(aggregate.deletions_planned, terminal.deletions_planned);
                aggregate.deletions_completed =
                    sum_optional(aggregate.deletions_completed, terminal.deletions_completed);
                aggregate.deletions_blocked =
                    sum_optional(aggregate.deletions_blocked, terminal.deletions_blocked);
            } else {
                // A target without a terminal failed before its ordinary
                // engine could settle. Count that group-level failure in
                // addition to any target-local errors already observed.
                aggregate.errors = aggregate.errors.saturating_add(1);
                if let Some(progress) = progresses[index].as_ref() {
                    aggregate.files_transferred = aggregate
                        .files_transferred
                        .saturating_add(progress.files_done.load(Relaxed));
                    aggregate.files_unchanged = aggregate
                        .files_unchanged
                        .saturating_add(progress.files_skipped.load(Relaxed));
                    aggregate.files_excluded = aggregate
                        .files_excluded
                        .saturating_add(progress.files_excluded.load(Relaxed));
                    aggregate.directories_created = aggregate
                        .directories_created
                        .saturating_add(progress.dirs_created.load(Relaxed));
                    aggregate.symlinks_created = aggregate
                        .symlinks_created
                        .saturating_add(progress.links_created.load(Relaxed));
                    aggregate.specials_created = aggregate
                        .specials_created
                        .saturating_add(progress.specials_created.load(Relaxed));
                    aggregate.errors = aggregate
                        .errors
                        .saturating_add(progress.errors.load(Relaxed));
                    aggregate.bytes_transferred = aggregate
                        .bytes_transferred
                        .saturating_add(progress.bytes_done.load(Relaxed));
                    aggregate.bytes_unchanged = aggregate
                        .bytes_unchanged
                        .saturating_add(progress.bytes_skipped.load(Relaxed));
                    aggregate.deletions_planned = sum_optional(
                        aggregate.deletions_planned,
                        args.delete
                            .then(|| progress.deletions_planned.load(Relaxed)),
                    );
                    aggregate.deletions_completed = sum_optional(
                        aggregate.deletions_completed,
                        args.delete
                            .then(|| progress.deletions_completed.load(Relaxed)),
                    );
                    aggregate.deletions_blocked = sum_optional(
                        aggregate.deletions_blocked,
                        args.delete
                            .then(|| progress.deletions_blocked.load(Relaxed)),
                    );
                }
            }
        }
        aggregate
    }

    fn progress_snapshot(&self, elapsed_ms: u64) -> crate::results::ProgressRecord {
        let progresses = self.progresses.lock().unwrap();
        let active: Vec<_> = progresses.iter().flatten().collect();
        crate::results::ProgressRecord {
            bytes_done: active
                .iter()
                .map(|progress| progress.bytes_done.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            bytes_total: active
                .iter()
                .map(|progress| progress.bytes_total.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            bytes_unchanged: active
                .iter()
                .map(|progress| progress.bytes_skipped.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            files_done: active
                .iter()
                .map(|progress| progress.files_done.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            files_total: active
                .iter()
                .map(|progress| progress.files_total.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            files_unchanged: active
                .iter()
                .map(|progress| progress.files_skipped.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            files_excluded: active
                .iter()
                .map(|progress| progress.files_excluded.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            scanned: active
                .iter()
                .map(|progress| progress.scanned.load(Relaxed))
                .fold(0u64, u64::saturating_add),
            scan_done: active.len() == self.total
                && active
                    .iter()
                    .all(|progress| progress.scan_done.load(Relaxed)),
            elapsed_ms,
        }
    }

    pub fn claim_source(&self, index: usize) -> Result<ScanClaim> {
        let cache = self
            .sources
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("fan-out source cache index {index} is out of range"))?;
        let mut state = cache.state.lock().unwrap();
        loop {
            if self.cancelled.load(Relaxed) {
                bail!("fan-out source scan cancelled because another target failed");
            }
            match &*state {
                SourceState::Available => {
                    *state = SourceState::Scanning;
                    return Ok(ScanClaim::Populate);
                }
                SourceState::Scanning => state = cache.ready.wait(state).unwrap(),
                SourceState::Ready(source) => return Ok(ScanClaim::Cached(source.clone())),
                SourceState::Failed(error) => bail!("fan-out source scan failed: {error}"),
            }
        }
    }

    pub fn complete_source(&self, index: usize, source: ScannedSource) {
        let cache = &self.sources[index];
        *cache.state.lock().unwrap() = SourceState::Ready(Arc::new(source));
        cache.ready.notify_all();
    }

    pub fn fail_source(&self, index: usize, error: &anyhow::Error) {
        let cache = &self.sources[index];
        *cache.state.lock().unwrap() = SourceState::Failed(format!("{error:#}"));
        cache.ready.notify_all();
        self.cancel();
    }

    /// Join the final read-only destination planning boundary. The last
    /// member releases every target to replay its buffered mutations.
    pub fn arrive(&self, label: &str) -> Result<()> {
        let mut state = self.preflight.lock().unwrap();
        if let Some(failure) = &state.failure {
            bail!("fan-out preflight cancelled: {failure}");
        }
        if self.cancelled.load(Relaxed) {
            bail!("fan-out preflight cancelled because another target failed");
        }
        state.arrived += 1;
        if !self.quiet {
            eprintln!(
                "syq: fan-out: target {label} ready ({}/{})",
                state.arrived, self.total
            );
        }
        if state.arrived == self.total {
            state.released = true;
            if !self.quiet {
                eprintln!(
                    "syq: fan-out: all {} targets ready; starting copies",
                    self.total
                );
            }
            self.ready.notify_all();
            return Ok(());
        }
        while !state.released && state.failure.is_none() {
            state = self.ready.wait(state).unwrap();
        }
        if let Some(failure) = &state.failure {
            bail!("fan-out preflight cancelled: {failure}");
        }
        Ok(())
    }

    pub fn failed(&self, label: &str, error: &anyhow::Error) {
        let mut state = self.preflight.lock().unwrap();
        if !state.released && state.failure.is_none() {
            state.failure = Some(format!("target {label}: {error:#}"));
            self.ready.notify_all();
        }
        drop(state);
        self.cancel();
    }

    pub fn cancel(&self) {
        {
            let mut state = self.preflight.lock().unwrap();
            // Publish cancellation while holding the same lock that protects
            // the barrier release. A last arrival can therefore only release
            // before this failure (post-barrier), or observe it and refuse.
            self.cancelled.store(true, Relaxed);
            if !state.released && state.failure.is_none() {
                state.failure = Some("another target failed".into());
                self.ready.notify_all();
            }
        }
        for source in &self.sources {
            // Pair the notification with the cache predicate lock so a source
            // waiter cannot miss cancellation between its check and wait.
            let _state = source.state.lock().unwrap();
            source.ready.notify_all();
        }
        let mut schedulers = self.schedulers.lock().unwrap();
        schedulers.retain(|weak| {
            if let Some(scheduler) = weak.upgrade() {
                scheduler.abort_from_fanout();
                true
            } else {
                false
            }
        });
    }
}

fn target_label(target: &Location) -> String {
    let host = match (&target.host, target.port) {
        (Some(host), Some(port)) if host.contains(':') => format!("[{host}]:{port}"),
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.clone(),
        (None, _) => return "local".into(),
    };
    match &target.user {
        Some(user) => format!("{user}@{host}"),
        None => host,
    }
}

pub fn run(mut args: Args) -> Result<i32> {
    let started = std::time::Instant::now();
    let target_count = args.fanout_targets.len() + 1;
    if args.connections_opt.is_some() && args.connections < target_count {
        bail!(
            "--connections {} is smaller than the {target_count} fan-out targets; allow at least one worker per target",
            args.connections
        );
    }
    let results = crate::results::start(
        &args,
        crate::results::RunMode::Cp {
            prune: args.delete,
            mapping: args.native_mapping.is_some(),
        },
    )?;
    let mut destinations = Vec::with_capacity(args.fanout_targets.len() + 1);
    destinations.push(crate::cli::FanoutTarget {
        location: args
            .locations
            .pop()
            .expect("a parsed native copy has a destination"),
        placement: args.placement,
        target_existence: args.target_existence,
    });
    destinations.append(&mut args.fanout_targets);
    debug_assert_eq!(destinations.len(), target_count);
    let sources = args.locations.clone();
    let source_count = crate::transfer::deduplicate_native_sources(&sources).len();
    if args.native_mapping.is_some() {
        match crate::transfer::read_native_mapping(&args) {
            Ok(mapping) => args.fanout_mapping = mapping.map(Arc::new),
            Err(error) => {
                if let Some(writer) = &results {
                    writer.emit_error_classified(&format!("syq: {error:#}"), None, None);
                    writer.emit_result(&crate::results::ResultRecord {
                        status: "failed",
                        exit_code: 1,
                        dry_run: args.dry_run,
                        files_transferred: 0,
                        files_unchanged: 0,
                        files_excluded: 0,
                        directories_created: 0,
                        symlinks_created: 0,
                        specials_created: 0,
                        errors: 1,
                        bytes_transferred: 0,
                        bytes_unchanged: 0,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                        deletions_planned: args.delete.then_some(0),
                        deletions_completed: args.delete.then_some(0),
                        deletions_blocked: args.delete.then_some(0),
                    });
                }
                return Err(error);
            }
        }
    }
    run_group(
        &args,
        &sources,
        &destinations,
        source_count,
        results,
        started,
    )
}

fn run_group(
    args: &Args,
    sources: &[Location],
    destinations: &[crate::cli::FanoutTarget],
    source_count: usize,
    results: Option<Arc<crate::results::ResultsWriter>>,
    started: std::time::Instant,
) -> Result<i32> {
    let target_count = destinations.len();
    let total_connections = args.connections.max(target_count);
    let group = Group::new(
        target_count,
        source_count,
        args.quiet,
        args.bwlimit_bytes,
        results,
    );
    let ticker = spawn_progress_ticker(group.clone(), args);
    let mut threads = Vec::with_capacity(target_count);
    for (index, destination) in destinations.iter().cloned().enumerate() {
        let label = target_label(&destination.location);
        let mut member = args.clone();
        member.locations = sources.to_vec();
        member.locations.push(destination.location);
        member.placement = destination.placement;
        member.target_existence = destination.target_existence;
        member.fanout_targets.clear();
        member.fanout_run = Some(RunContext {
            group: group.clone(),
            label: label.clone(),
            destination_index: index,
        });
        // A fan-out connection count is one aggregate budget. Every member
        // receives at least one worker; no member may independently multiply
        // the user's total through auto-tuning.
        let connections = total_connections / target_count
            + usize::from(index < total_connections % target_count);
        member.connections = connections;
        member.connections_opt = Some(connections);
        member.connections_default = false;
        // A group renderer owns the terminal. Member tickers would overwrite
        // one another; aggregate progress is added at the coordination layer.
        member.no_progress = true;
        member.progress = false;
        let member_group = group.clone();
        let member_label = label.clone();
        threads.push((
            index,
            label,
            std::thread::spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::transfer::run(member)
                }))
                .unwrap_or_else(|_| Err(anyhow::anyhow!("target engine panicked")));
                match &result {
                    Ok(0) => {}
                    Ok(_) => member_group.cancel(),
                    Err(error) => member_group.failed(&member_label, error),
                }
                result
            }),
        ));
    }

    let mut exit_code = 0;
    let mut failures = Vec::new();
    for (index, label, thread) in threads {
        match thread.join() {
            Ok(Ok(0)) => {
                if !args.quiet {
                    eprintln!("syq: fan-out: target {label} complete");
                }
            }
            Ok(Ok(code)) => {
                group.cancel();
                exit_code = combine_exit_codes(exit_code, code);
                failures.push(format!("target {label} exited {code}"));
            }
            Ok(Err(error)) => {
                group.failed(&label, &error);
                exit_code = 1;
                let failure = format!("target {label}: {error:#}");
                if let Some(results) = group.results() {
                    results.emit_error_classified_for(
                        &format!("syq: fan-out: {failure}"),
                        None,
                        None,
                        Some(index),
                    );
                }
                failures.push(failure);
            }
            Err(_) => {
                group.cancel();
                exit_code = 1;
                let failure = format!("target {label}: worker thread panicked");
                if let Some(results) = group.results() {
                    results.emit_error_classified_for(
                        &format!("syq: fan-out: {failure}"),
                        None,
                        None,
                        Some(index),
                    );
                }
                failures.push(failure);
            }
        }
    }
    for failure in failures {
        eprintln!("syq: fan-out: {failure}");
    }
    if let Some((stop, ticker)) = ticker {
        stop.store(true, Relaxed);
        let _ = ticker.join();
    }
    if let Some(results) = group.results() {
        results.emit_result(&group.aggregate_terminal(
            args,
            exit_code,
            started.elapsed().as_millis() as u64,
        ));
    }
    Ok(exit_code)
}

fn spawn_progress_ticker(
    group: Arc<Group>,
    args: &Args,
) -> Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    let human = !args.no_progress
        && !args.quiet
        && !args.dry_run
        && (args.progress || std::io::stderr().is_terminal());
    let json = !args.quiet && args.progress_json;
    if !human && !json && group.results().is_none() {
        return None;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let started = std::time::Instant::now();
    let width = args.width.unwrap_or_else(crate::progress::term_width);
    let ticker = std::thread::spawn(move || {
        let mut last_sample = None;
        while !thread_stop.load(Relaxed) {
            let elapsed = started.elapsed();
            let snapshot = group.progress_snapshot(elapsed.as_millis() as u64);
            if last_sample.is_none_or(|last| elapsed - last >= std::time::Duration::from_secs(1)) {
                last_sample = Some(elapsed);
                if let Some(results) = group.results() {
                    results.emit_progress(&snapshot);
                }
                if json {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "bytes_done": snapshot.bytes_done,
                            "bytes_total": snapshot.bytes_total,
                            "bytes_skipped": snapshot.bytes_unchanged,
                            "files_done": snapshot.files_done,
                            "files_total": snapshot.files_total,
                            "files_skipped": snapshot.files_unchanged,
                            "files_excluded": snapshot.files_excluded,
                            "scanned": snapshot.scanned,
                            "scan_done": snapshot.scan_done,
                            "elapsed": elapsed.as_secs_f64(),
                            "fanout_targets": group.total,
                        })
                    );
                }
            }
            if human {
                let percent = if snapshot.bytes_total > 0 {
                    snapshot.bytes_done.saturating_mul(100) / snapshot.bytes_total
                } else {
                    0
                };
                let line = format!(
                    "fan-out {} / {}  {percent:>3}%  files {}/{}  {} targets",
                    crate::progress::human(snapshot.bytes_done),
                    crate::progress::human(snapshot.bytes_total),
                    snapshot.files_done,
                    snapshot.files_total,
                    group.total,
                );
                let line = if line.chars().count() >= width {
                    line.chars().take(width.saturating_sub(1)).collect()
                } else {
                    line
                };
                eprint!("\r\x1b[K{line}");
                let _ = std::io::stderr().flush();
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if human {
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        }
    });
    Some((stop, ticker))
}

fn combine_exit_codes(current: i32, next: i32) -> i32 {
    match (current, next) {
        (1, _) | (_, 1) => 1,
        (23, _) | (_, 23) => 23,
        (25, _) | (_, 25) => 25,
        (code, 0) if code != 0 => code,
        (_, code) => code,
    }
}

fn sum_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.saturating_add(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_member_releases_preflight_waiters() {
        let group = Group::new(2, 0, true, 0, None);
        let waiter = {
            let group = group.clone();
            std::thread::spawn(move || group.arrive("ready"))
        };
        group.failed("broken", &anyhow::anyhow!("unreachable"));
        let error = waiter.join().unwrap().unwrap_err().to_string();
        assert!(error.contains("target broken: unreachable"), "{error}");
    }

    #[test]
    fn file_failure_aborts_every_registered_target_scheduler() {
        let group = Group::new(2, 0, true, 0, None);
        let first = Arc::new(Sched::new(64, 128));
        let second = Arc::new(Sched::new(64, 128));
        group.register_scheduler(&first);
        group.register_scheduler(&second);

        first.fail_file(7);

        assert!(first.is_aborted());
        assert!(second.is_aborted());
    }

    #[test]
    fn cancellation_releases_source_cache_waiters() {
        let group = Group::new(2, 1, true, 0, None);
        assert!(matches!(
            group.claim_source(0).unwrap(),
            ScanClaim::Populate
        ));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiter = {
            let group = group.clone();
            std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                group.claim_source(0)
            })
        };
        started_rx.recv().unwrap();
        group.cancel();
        let error = match waiter.join().unwrap() {
            Ok(_) => panic!("cancelled source waiter unexpectedly acquired the cache"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("cancelled"), "{error:#}");
    }

    #[test]
    fn aggregate_exit_code_does_not_lose_an_earlier_failure() {
        assert_eq!(combine_exit_codes(25, 0), 25);
        assert_eq!(combine_exit_codes(0, 25), 25);
        assert_eq!(combine_exit_codes(25, 23), 23);
        assert_eq!(combine_exit_codes(23, 1), 1);
    }

    #[test]
    fn one_member_populates_each_source_cache() {
        let group = Group::new(2, 1, true, 0, None);
        assert!(matches!(
            group.claim_source(0).unwrap(),
            ScanClaim::Populate
        ));
        group.complete_source(
            0,
            ScannedSource {
                batches: Vec::new(),
                ignored: 0,
                warnings: Vec::new(),
            },
        );
        assert!(matches!(
            group.claim_source(0).unwrap(),
            ScanClaim::Cached(_)
        ));
    }
}
