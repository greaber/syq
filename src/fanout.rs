//! Coordinated execution of one native copy against several destinations.
//!
//! Each member uses the single-target transfer engine. The group shares the
//! descriptor-backed source scan, holds every destination mutation behind one
//! barrier, and cancels peer schedulers and owned transports after a fatal failure.

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
    pub(crate) cancellation: Arc<crate::cancellation::Cancellation>,
    schedulers: Mutex<Vec<Weak<Sched>>>,
    progresses: Mutex<Vec<Option<Arc<Progress>>>>,
    terminals: Mutex<Vec<Option<crate::results::ResultRecord>>>,
    human_output: Mutex<()>,
    progress_lines: Mutex<usize>,
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
        cancellation: Arc<crate::cancellation::Cancellation>,
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
            cancellation,
            schedulers: Mutex::new(Vec::with_capacity(total)),
            progresses: Mutex::new(vec![None; total]),
            terminals: Mutex::new(vec![None; total]),
            human_output: Mutex::new(()),
            progress_lines: Mutex::new(0),
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
        let previous = self.terminals.lock().unwrap()[index].replace(terminal);
        debug_assert!(previous.is_none(), "a fan-out member settled twice");
    }

    pub fn lock_human_output(&self) -> std::sync::MutexGuard<'_, ()> {
        // This mutex protects only output serialization, not program state, so
        // its invariant remains valid if an earlier writer unwound while it
        // held the guard.
        let output = self
            .human_output
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut lines = self
            .progress_lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *lines > 0 {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[{}A\x1b[J", *lines);
            let _ = err.flush();
            *lines = 0;
        }
        output
    }

    fn set_progress_lines(&self, lines: usize) {
        *self
            .progress_lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = lines;
    }

    fn write_stderr_block(&self, block: &str) {
        let _output = self.lock_human_output();
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "{block}");
        let _ = err.flush();
    }

    fn ensure_failed_member(&self, index: usize, args: &Args) -> bool {
        let progress = self.progresses.lock().unwrap()[index].clone();
        let mut terminals = self.terminals.lock().unwrap();
        if terminals[index].is_some() {
            return false;
        }
        terminals[index] = Some(progress.map_or_else(
            || failed_result(args, 0, 1),
            |progress| progress.failed_result(args.dry_run, args.delete, 1),
        ));
        true
    }

    fn terminal_records(&self) -> Vec<crate::results::ResultRecord> {
        self.terminals
            .lock()
            .unwrap()
            .iter()
            .map(|terminal| {
                terminal
                    .clone()
                    .expect("every joined fan-out member has a terminal result")
            })
            .collect()
    }

    fn member_progresses(&self) -> Vec<(usize, Arc<Progress>)> {
        self.progresses
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .filter_map(|(index, progress)| progress.clone().map(|progress| (index, progress)))
            .collect()
    }

    fn aggregate_terminal(
        &self,
        args: &Args,
        terminals: &[crate::results::ResultRecord],
        exit_code: i32,
        elapsed_ms: u64,
    ) -> crate::results::ResultRecord {
        let mut aggregate = crate::results::ResultRecord {
            status: exit_code_info(exit_code).0,
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
        for terminal in terminals {
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
        }
        aggregate
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
            self.write_stderr_block(&format!(
                "syq: fan-out: target {label} ready ({}/{})",
                state.arrived, self.total
            ));
        }
        if state.arrived == self.total {
            state.released = true;
            if !self.quiet {
                self.write_stderr_block(&format!(
                    "syq: fan-out: all {} targets ready; starting copies",
                    self.total
                ));
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
        self.cancellation.cancel();
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

pub fn run(mut args: Args) -> Result<i32> {
    let cancellation = Arc::default();
    crate::private_broker::register_transfer_cancellation(&cancellation)?;
    let started = std::time::Instant::now();
    let target_count = args.fanout_targets.len() + 1;
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
    let sources = args.locations.clone();
    if args.native_mapping.is_some() {
        match crate::transfer::read_native_mapping(&args) {
            Ok(mapping) => args.fanout_mapping = mapping.map(Arc::new),
            Err(error) => {
                if let Some(writer) = &results {
                    writer.emit_error_classified(&format!("syq: {error:#}"), None, None);
                    let elapsed_ms = started.elapsed().as_millis() as u64;
                    let member = failed_result(&args, elapsed_ms, 0);
                    for index in 0..target_count {
                        writer.emit_destination_result(index, &member);
                    }
                    writer.emit_result(&failed_result(&args, elapsed_ms, 1));
                }
                return Err(error);
            }
        }
    }
    run_group(
        &args,
        &sources,
        &destinations,
        cancellation,
        results,
        started,
    )
}

fn run_group(
    args: &Args,
    sources: &[Location],
    destinations: &[crate::cli::FanoutTarget],
    cancellation: Arc<crate::cancellation::Cancellation>,
    results: Option<Arc<crate::results::ResultsWriter>>,
    started: std::time::Instant,
) -> Result<i32> {
    let target_count = destinations.len();
    let labels: Vec<_> = destinations
        .iter()
        .map(|destination| crate::transfer::endpoint_identity(&destination.location))
        .collect();
    let group = Group::new(
        target_count,
        crate::transfer::deduplicate_native_sources(sources).len(),
        cancellation,
        args.quiet,
        args.bwlimit_bytes,
        results,
    );
    let ticker = spawn_progress_ticker(group.clone(), labels.clone(), args);
    let mut threads = Vec::with_capacity(target_count);
    for (index, (destination, label)) in destinations.iter().cloned().zip(labels).enumerate() {
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
        // An explicit count is one aggregate budget. With no explicit count,
        // leave the defaults intact so each destination tunes its own path.
        if let Some(total_connections) = args.connections_opt {
            let connections = total_connections / target_count
                + usize::from(index < total_connections % target_count);
            member.connections = connections;
            member.connections_opt = Some(connections);
            member.connections_default = false;
        }
        // A group renderer owns stderr. Member tickers would overwrite one
        // another; the coordinator renders one labelled row per destination.
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
                if let Err(error) = &result {
                    member_group.failed(&member_label, error);
                }
                announce_member_settled_for_test(index);
                result
            }),
        ));
    }

    let mut exit_code = 0;
    let mut notices = Vec::new();
    let mut failures = Vec::new();
    for (index, label, thread) in threads {
        match thread.join() {
            Ok(Ok(0)) => {
                if !args.quiet {
                    notices.push(format!("target {label} complete"));
                }
            }
            Ok(Ok(code)) => {
                exit_code = combine_exit_codes(exit_code, code);
                failures.push(format!("target {label} exited {code}"));
            }
            Ok(Err(error)) => {
                exit_code = 1;
                let failure = format!("target {label}: {error:#}");
                if group.ensure_failed_member(index, args) {
                    let results = group.results();
                    if let Some(results) = results {
                        results.emit_error_classified_for(
                            &format!("syq: fan-out: {failure}"),
                            None,
                            None,
                            Some(index),
                        );
                    }
                }
                failures.push(failure);
            }
            Err(_) => {
                group.cancel();
                exit_code = 1;
                let failure = format!("target {label}: worker thread panicked");
                if group.ensure_failed_member(index, args) {
                    if let Some(results) = group.results() {
                        results.emit_error_classified_for(
                            &format!("syq: fan-out: {failure}"),
                            None,
                            None,
                            Some(index),
                        );
                    }
                }
                failures.push(failure);
            }
        }
    }
    if let Some((stop, ticker)) = ticker {
        stop.store(true, Relaxed);
        let _ = ticker.join();
    }
    for notice in notices {
        crate::output::diagnostic!("syq: fan-out: {notice}");
    }
    for failure in failures {
        crate::output::diagnostic!("syq: fan-out: {failure}");
    }
    let terminals = group.terminal_records();
    if let Some(results) = group.results() {
        for (index, terminal) in terminals.iter().enumerate() {
            results.emit_destination_result(index, terminal);
        }
        results.emit_result(&group.aggregate_terminal(
            args,
            &terminals,
            exit_code,
            started.elapsed().as_millis() as u64,
        ));
    }
    Ok(exit_code)
}

fn failed_result(args: &Args, elapsed_ms: u64, errors: u64) -> crate::results::ResultRecord {
    crate::results::ResultRecord {
        status: "failed",
        exit_code: 1,
        dry_run: args.dry_run,
        files_transferred: 0,
        files_unchanged: 0,
        files_excluded: 0,
        directories_created: 0,
        symlinks_created: 0,
        specials_created: 0,
        errors,
        bytes_transferred: 0,
        bytes_unchanged: 0,
        elapsed_ms,
        deletions_planned: args.delete.then_some(0),
        deletions_completed: args.delete.then_some(0),
        deletions_blocked: args.delete.then_some(0),
    }
}

fn spawn_progress_ticker(
    group: Arc<Group>,
    labels: Vec<String>,
    args: &Args,
) -> Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    let human = human_progress_enabled(args);
    let json = !args.quiet && args.progress_json;
    if !human && !json && group.results().is_none() {
        return None;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let configured_width = args.width;
    let ticker = std::thread::spawn(move || {
        let mut last_sample = None;
        while !thread_stop.load(Relaxed) {
            let now = std::time::Instant::now();
            let progresses = group.member_progresses();
            let all_members_registered = progresses.len() == labels.len();
            let sample_due =
                last_sample.is_none_or(|last| now - last >= std::time::Duration::from_secs(1));
            if all_members_registered && (human || sample_due) {
                let snapshots: Vec<_> = progresses
                    .into_iter()
                    .map(|(index, progress)| (index, progress.snapshot()))
                    .collect();
                if sample_due {
                    last_sample = Some(now);
                    let mut json_lines = Vec::new();
                    for (index, snapshot) in &snapshots {
                        if let Some(results) = group.results() {
                            results.emit_progress(&snapshot.result_record(Some(*index)));
                        }
                        if json {
                            json_lines.push(crate::progress::progress_json(
                                snapshot,
                                Some(*index),
                                Some(&labels[*index]),
                            ));
                        }
                    }
                    if !json_lines.is_empty() {
                        group.write_stderr_block(&json_lines.join("\n"));
                    }
                }
                if human {
                    let _output = group.lock_human_output();
                    let width = configured_width.unwrap_or_else(crate::progress::term_width);
                    let mut err = std::io::stderr().lock();
                    for (index, snapshot) in &snapshots {
                        let line = format!(
                            "target {}: {}",
                            labels[*index],
                            crate::progress::progress_line(snapshot)
                        );
                        let _ = writeln!(
                            err,
                            "{}",
                            crate::progress::truncate(&line, width.saturating_sub(1))
                        );
                    }
                    let _ = err.flush();
                    group.set_progress_lines(snapshots.len());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if human {
            let _output = group.lock_human_output();
        }
    });
    Some((stop, ticker))
}

fn human_progress_enabled(args: &Args) -> bool {
    !args.no_progress
        && !args.quiet
        && !args.dry_run
        && (args.progress || std::io::stderr().is_terminal())
}

fn combine_exit_codes(current: i32, next: i32) -> i32 {
    if exit_code_info(next).1 > exit_code_info(current).1 {
        next
    } else {
        current
    }
}

fn exit_code_info(code: i32) -> (&'static str, u8) {
    match code {
        0 => ("success", 0),
        25 => ("refused", 1),
        23 => ("partial", 2),
        _ => ("failed", 3),
    }
}

#[cfg(debug_assertions)]
fn announce_member_settled_for_test(index: usize) {
    let selected = std::env::var("SYQ_TEST_FANOUT_SETTLED_INDEX")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    if selected != Some(index) {
        return;
    }
    let marker = std::env::var_os("SYQ_TEST_FANOUT_SETTLED_FILE")
        .expect("SYQ_TEST_FANOUT_SETTLED_INDEX requires SYQ_TEST_FANOUT_SETTLED_FILE");
    std::fs::write(marker, b"settled").expect("write fan-out member-settled marker");
}

#[cfg(not(debug_assertions))]
fn announce_member_settled_for_test(_index: usize) {}

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
        let group = Group::new(2, 0, Arc::default(), true, 0, None);
        let waiter = {
            let group = group.clone();
            std::thread::spawn(move || group.arrive("ready"))
        };
        group.failed("broken", &anyhow::anyhow!("unreachable"));
        let error = waiter.join().unwrap().unwrap_err().to_string();
        assert!(error.contains("target broken: unreachable"), "{error}");
    }

    #[test]
    fn file_failure_does_not_abort_any_target_scheduler() {
        let group = Group::new(2, 0, Arc::default(), true, 0, None);
        let first = Arc::new(Sched::new(64, 128));
        let second = Arc::new(Sched::new(64, 128));
        group.register_scheduler(&first);
        group.register_scheduler(&second);

        first.fail_file(7);

        assert!(first.is_failed(7));
        assert!(!first.is_aborted());
        assert!(!second.is_aborted());
    }

    #[test]
    fn fatal_scheduler_abort_still_aborts_every_target_scheduler() {
        let group = Group::new(2, 0, Arc::default(), true, 0, None);
        let first = Arc::new(Sched::new(64, 128));
        let second = Arc::new(Sched::new(64, 128));
        group.register_scheduler(&first);
        group.register_scheduler(&second);

        first.abort();

        assert!(first.is_aborted());
        assert!(second.is_aborted());
    }

    #[test]
    fn cancellation_releases_source_cache_waiters() {
        let group = Group::new(2, 1, Arc::default(), true, 0, None);
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
        let group = Group::new(2, 1, Arc::default(), true, 0, None);
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
