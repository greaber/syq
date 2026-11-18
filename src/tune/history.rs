//! Local, disposable performance evidence. Never a receipt or an audit log.
//! Versioned separately from tuning.json so released binaries cannot erase it.

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod command;
mod inference;
#[cfg(test)]
pub(super) mod tests;
pub(crate) use command::{command_for_help, run};
const SCHEMA: i64 = 2;
const DEFAULT_BUDGET: u64 = 10 << 20;
const MAX_PENDING: usize = 4096;
/// A copy writes nothing to the history for this long after opening it, so
/// that a short copy writes once, when it ends. One killed sooner leaves no
/// record.
/// Many copies starting and finishing together then contend for the writer
/// lock once each, for a single short transaction, instead of several times.
const FIRST_WRITE: Duration = Duration::from_secs(1);
/// How often a longer copy then saves what it has recorded, so that it can
/// be inspected while it runs and leaves its timeline if it is killed.
const WRITE_INTERVAL: Duration = Duration::from_secs(5);
/// This many unsaved events are saved at once, whatever the copy's age,
/// well before `MAX_PENDING` would drop any.
const WRITE_EVENTS: usize = 1024;
/// How long a save that found the history locked leaves it alone.
const WRITE_RETRY: Duration = Duration::from_millis(250);
/// A finishing copy waits for other copies' writes no longer than it ran
/// itself, and at most this long. Then it records nothing. The wait is part
/// of the copy's wall time: a short copy's record is not worth holding the
/// copy up for, and a long copy, whose measurements later copies start from,
/// waits the full time unnoticed.
const FINISH_LOCK_WAIT: Duration = Duration::from_millis(100);
/// How long opening history waits for another run's lock before this run
/// goes without history. Reading an existing history takes no lock that a
/// writer holds; this covers a history being created or recovered.
const OPEN_LOCK_WAIT: Duration = Duration::from_millis(100);
/// About how long one copy spends deleting old runs from a history over its
/// budget and returning its free space.
const PRUNE_TIME: Duration = Duration::from_millis(5);
/// The fraction of its budget a history over it is pruned below.
const PRUNE_SLACK: i64 = 32;
/// The most runs one step deletes, and how many of the oldest runs it reads
/// to choose them. Both bound a step whatever the history holds.
const PRUNE_BATCH: usize = 256;
const PRUNE_WINDOW: i64 = 512;
/// An incomplete run this close behind the finishing one may belong to a copy
/// still in progress, and is never deleted.
const ACTIVE_RUNS: i64 = 256;

#[derive(Clone)]
pub(crate) struct Recorder(Arc<Mutex<Writer>>);

struct Writer {
    db: Connection,
    /// The run's row, which the first save creates.
    id: Option<i64>,
    day: i64,
    start: Instant,
    /// When the next periodic save is due.
    next_write: Instant,
    /// No save is attempted before this, after one found the history locked.
    retry: Instant,
    sequence: u64,
    pending: Vec<Value>,
    pending_context: Option<ContextKey>,
    lost: i64,
    budget: u64,
    finished: bool,
    measurements: inference::Eligibility,
    measurement_segment: i64,
    salt: [u8; 32],
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct ContextKey {
    pub source_endpoint: String,
    pub destination_endpoint: String,
    pub source_transport: String,
    pub destination_transport: String,
    pub route: String,
    pub source_filesystem: Option<String>,
    pub destination_filesystem: Option<String>,
    pub mode: String,
    #[serde(default)]
    pub network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Hint {
    pub run: i64,
    pub workers: usize,
    pub matched: String,
    pub refine: bool,
}

fn day() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
        / 86400
}

pub(crate) fn path() -> Option<PathBuf> {
    // The existing explicit disable remains effective for all tuning persistence.
    if std::env::var_os("SYQ_TUNING_CACHE").is_some_and(|p| p.is_empty()) {
        return None;
    }
    if let Some(path) = std::env::var_os("SYQ_TUNING_HISTORY") {
        return (!path.is_empty()).then(|| path.into());
    }
    super::cache_path().map(|p| p.with_extension("history-v1.sqlite"))
}

fn budget() -> Result<u64> {
    let Some(value) = std::env::var_os("SYQ_TUNING_HISTORY_SIZE") else {
        return Ok(DEFAULT_BUDGET);
    };
    let size = crate::cli::parse_size(&value.to_string_lossy())?;
    anyhow::ensure!(
        size >= 10 << 20,
        "SYQ_TUNING_HISTORY_SIZE must be at least 10M"
    );
    Ok(size)
}

fn open(path: &Path) -> Result<Connection> {
    open_waiting(path, OPEN_LOCK_WAIT)
}

/// `open`, waiting up to `lock_wait` for another connection's lock.
fn open_waiting(path: &Path, lock_wait: Duration) -> Result<Connection> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    anyhow::ensure!(file.metadata()?.is_file(), "history is not a regular file");
    let mut db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    db.busy_timeout(lock_wait)?;
    // This history is disposable: avoid durability barriers on the copy path.
    // Set this before schema creation or journal changes, which can also sync.
    // A system crash can lose or corrupt history; it never authorizes file work.
    db.pragma_update(None, "synchronous", "OFF")?;
    let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    anyhow::ensure!(
        (0..=SCHEMA).contains(&version),
        "unsupported tuning history version {version}"
    );
    if version < SCHEMA {
        if version == 0 {
            db.pragma_update(None, "auto_vacuum", "INCREMENTAL")
                .context("configure history page reclamation")?;
        }
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("lock history for initialization")?;
        // Another process may have initialized the database while we waited.
        let version: i64 = transaction.pragma_query_value(None, "user_version", |r| r.get(0))?;
        anyhow::ensure!(
            (0..=SCHEMA).contains(&version),
            "unsupported tuning history version {version}"
        );
        if version == 0 {
            let tables: i64 = transaction.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [], |r| r.get(0))?;
            anyhow::ensure!(tables == 0, "unrecognized database at tuning history path");
            transaction.execute_batch("CREATE TABLE metadata (key TEXT PRIMARY KEY, value BLOB NOT NULL);
                CREATE TABLE runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, day INTEGER NOT NULL,
                    updated_day INTEGER NOT NULL, build TEXT NOT NULL, context TEXT NOT NULL DEFAULT '{}',
                    route TEXT, source_fs TEXT, destination_fs TEXT, mode TEXT,
                    status TEXT NOT NULL DEFAULT 'incomplete', eligible INTEGER NOT NULL DEFAULT 0,
                    workers INTEGER, summary TEXT, lost INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX by_filesystems ON runs(route,mode,source_fs,destination_fs,eligible,id DESC);
                CREATE INDEX by_route ON runs(route,mode,eligible,id DESC);
                CREATE TABLE events (
                    run INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL, elapsed_us INTEGER NOT NULL, data TEXT NOT NULL,
                    PRIMARY KEY(run,sequence));")?;
        }
        if version < 2 {
            // An empty indexed table is cheap to add even to a large history.
            // Do not scan or backfill old JSON events while holding this lock.
            transaction.execute_batch(
                "CREATE TABLE measurements (
                run INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL, elapsed_us INTEGER NOT NULL,
                segment INTEGER NOT NULL, workers INTEGER NOT NULL,
                seconds REAL NOT NULL, rate REAL NOT NULL, usable INTEGER NOT NULL,
                PRIMARY KEY(run,sequence)) WITHOUT ROWID;
                PRAGMA user_version=2;",
            )?;
        }
        transaction.commit()?;
    }
    // Concurrent first opens can race while changing journal mode. SQLite
    // returns BUSY immediately for this lock upgrade, without the busy handler.
    // Retry only this operation, within the same small startup wait budget.
    db.busy_timeout(Duration::ZERO)?;
    let deadline = Instant::now() + lock_wait;
    loop {
        match db.pragma_update(None, "journal_mode", "WAL") {
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy && Instant::now() < deadline =>
            {
                std::thread::sleep(
                    Duration::from_millis(2)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            result => {
                result.context("enable history WAL")?;
                break;
            }
        }
    }
    db.busy_timeout(lock_wait)?;
    db.pragma_update(None, "foreign_keys", true)?;
    Ok(db)
}

impl Recorder {
    pub(crate) fn start(start: Instant, details: Value) -> Option<Self> {
        let path = path()?;
        match budget().and_then(|budget| Self::at(&path, start, details, budget)) {
            Ok(recorder) => Some(recorder),
            Err(error) => {
                diagnostic(&error);
                None
            }
        }
    }

    fn at(path: &Path, start: Instant, details: Value, budget: u64) -> Result<Self> {
        Self::at_waiting(path, start, details, budget, OPEN_LOCK_WAIT)
    }

    /// `at`, waiting up to `lock_wait` for another run's lock.
    fn at_waiting(
        path: &Path,
        start: Instant,
        details: Value,
        budget: u64,
        lock_wait: Duration,
    ) -> Result<Self> {
        // Starting a copy only reads an existing history: its identity key
        // here and, later, earlier runs for a starting count. Other copies'
        // writes do not hold these reads up, and this copy's own run is
        // written later, off the path to its first byte.
        let db = open_waiting(path, lock_wait)?;
        let salt = identity_key(&db)?;
        db.busy_timeout(Duration::ZERO)?;
        // The first save is counted from here, not from `start`. A copy's
        // clock can start well before its history opens, as when choosing
        // its authorization first connects to a server, and that copy is
        // still starting.
        let opened = Instant::now();
        let recorder = Self(Arc::new(Mutex::new(Writer {
            db,
            id: None,
            day: day(),
            start,
            next_write: opened + FIRST_WRITE,
            retry: opened,
            sequence: 0,
            pending: Vec::new(),
            pending_context: None,
            lost: 0,
            budget,
            finished: false,
            measurements: Default::default(),
            measurement_segment: 0,
            salt,
        })));
        recorder.event("start", details);
        Ok(recorder)
    }

    pub(crate) fn token(&self, domain: &str, value: &str) -> String {
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let mut h = blake3::Hasher::new_keyed(&state.salt);
        h.update(domain.as_bytes());
        h.update(&[0]);
        h.update(value.as_bytes());
        h.finalize().to_hex().to_string()
    }

    /// Record preflight evidence, not a measurement of path throughput or a
    /// claim that every selected candidate carried data. Keep address identity
    /// stable within this store without persisting hostnames or IP addresses.
    pub(crate) fn tcp_probe(&self, role: &str, endpoint: &str, probe: &crate::conn::TcpProbe) {
        let candidates: Vec<_> = probe
            .candidates
            .iter()
            .map(|candidate| {
                let source = match candidate.source {
                    crate::conn::DataAddressSource::RemoteInterface => "remote_interface",
                    crate::conn::DataAddressSource::SshTarget => "ssh_target",
                };
                json!({
                    "address": self.token("tcp_address", &format!("{endpoint}\0{}", candidate.address)),
                    "source": source,
                    "reported_speed_mbps": (candidate.speed_mbps > 0).then_some(candidate.speed_mbps),
                    "reachable": candidate.reachable,
                    "selected": candidate.selected,
                })
            })
            .collect();
        self.event(
            "tcp_preflight",
            json!({
                "role": role,
                "endpoint": self.token("endpoint", endpoint),
                "encrypted": probe.encrypted,
                "congestion_control": probe.congestion_control,
                "candidates": candidates,
            }),
        );
    }

    pub(crate) fn event(&self, kind: &str, data: Value) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.finished {
            return;
        }
        state.record(kind, data);
        let now = Instant::now();
        if now >= state.retry && (now >= state.next_write || state.pending.len() >= WRITE_EVENTS) {
            if let Err(error) = state.save() {
                // Usually another copy holds the writer lock. Keep the
                // events for a later save instead of waiting for it.
                state.retry = now + WRITE_RETRY;
                diagnostic(&error);
            }
        }
    }

    /// Set the run's context, which the next save writes with its events.
    pub(crate) fn context(&self, key: &ContextKey) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if !state.finished {
            state.pending_context = Some(key.clone());
        }
    }

    pub(crate) fn starting_count(&self, key: &ContextKey, allow_route: bool) -> Option<Hint> {
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        inference::starting_count(&state.db, key, allow_route)
            .ok()
            .flatten()
    }

    /// Record the outcome and the final summary. Later events are ignored.
    pub(crate) fn complete(&self, success: bool, summary: Value) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.finished {
            return;
        }
        state.record("finish", summary.clone());
        if let Err(error) = state.finish(success, summary) {
            diagnostic(&error);
        }
        state.finished = true;
    }
}

impl Writer {
    /// Keep an event for the next save.
    fn record(&mut self, kind: &str, mut data: Value) {
        let elapsed_us = self.start.elapsed().as_micros().min(i64::MAX as u128) as u64;
        let sequence = self.sequence;
        self.sequence += 1;
        if matches!(kind, "transition" | "sequential_evidence") {
            self.measurement_segment = sequence as i64;
        }
        if kind == "observation" {
            data["segment"] = json!(self.measurement_segment);
        }
        if self.pending.len() < MAX_PENDING {
            let event =
                json!({"sequence":sequence,"elapsed_us":elapsed_us,"kind":kind,"data":data});
            self.measurements.push(&event);
            self.pending.push(event);
        } else {
            self.lost += 1;
        }
    }

    /// Write what this copy has recorded since its last save, without
    /// waiting for another copy's write to end.
    fn save(&mut self) -> Result<()> {
        if self.pending.is_empty() && self.pending_context.is_none() {
            return Ok(());
        }
        self.commit(Duration::ZERO, None)
    }

    /// Write the pending context and events, and `outcome` if the copy has
    /// ended, in one transaction, waiting at most `wait` for the writer lock.
    /// The first save creates the run's row.
    fn commit(&mut self, wait: Duration, outcome: Option<&Outcome>) -> Result<()> {
        // Other copies wait for as long as this one holds the writer lock, so
        // everything that needs no lock is done before it is taken.
        //
        // Context revisions (for example, discovering a mixed-filesystem tree)
        // must survive contention just like samples, and the outcome is
        // recorded under the context that the same save writes.
        let context = self
            .pending_context
            .as_ref()
            .map(|key| Ok::<_, serde_json::Error>((serde_json::to_string(key)?, key)))
            .transpose()?;
        let events = self
            .pending
            .iter()
            .map(|event| {
                Ok((
                    event["sequence"].as_i64(),
                    event["elapsed_us"].as_i64(),
                    serde_json::to_string(event)?,
                    inference::Observation::from_event(event),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let today = day();
        let id = {
            let mut create = self.db.prepare_cached(
                "INSERT INTO runs(day,updated_day,build,lost,context,route,source_fs,
                    destination_fs,mode,status,eligible,summary)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            )?;
            let mut insert = self
                .db
                .prepare_cached("INSERT INTO events VALUES (?1,?2,?3,?4)")?;
            let mut measurement = self
                .db
                .prepare_cached("INSERT INTO measurements VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")?;
            let transaction = begin_within(&self.db, wait)?;
            let id = if let Some(id) = self.id {
                let found = transaction.execute(
                    "UPDATE runs SET lost=?1,updated_day=?3 WHERE id=?2",
                    params![self.lost, id, today],
                )?;
                if found == 0 {
                    None
                } else {
                    if let Some((json, key)) = &context {
                        transaction.execute("UPDATE runs SET context=?1,route=?2,source_fs=?3,destination_fs=?4,mode=?5 WHERE id=?6",
                            params![json, key.route, key.source_filesystem, key.destination_filesystem, key.mode, id])?;
                    }
                    if let Some(outcome) = outcome {
                        transaction.execute(
                            "UPDATE runs SET status=?1,eligible=?2,summary=?3 WHERE id=?4",
                            params![outcome.status, outcome.eligible, outcome.summary, id],
                        )?;
                    }
                    Some(id)
                }
            } else {
                // A copy that ends before its first periodic save, as most
                // do, writes its whole row at once.
                let key = context.as_ref().map(|(_, key)| *key);
                create.execute(params![
                    self.day,
                    today,
                    crate::identity::build(),
                    self.lost,
                    context.as_ref().map_or("{}", |(json, _)| json),
                    key.map(|key| &key.route),
                    key.and_then(|key| key.source_filesystem.as_ref()),
                    key.and_then(|key| key.destination_filesystem.as_ref()),
                    key.map(|key| &key.mode),
                    outcome.map_or("incomplete", |outcome| outcome.status),
                    outcome.map_or(0, |outcome| outcome.eligible),
                    outcome.map(|outcome| &outcome.summary),
                ])?;
                Some(transaction.last_insert_rowid())
            };
            if let Some(id) = id {
                for (sequence, elapsed_us, data, observation) in &events {
                    if let Some(o) = observation {
                        measurement.execute(params![
                            id,
                            sequence,
                            elapsed_us,
                            o.segment,
                            o.workers as i64,
                            o.seconds,
                            o.rate,
                            o.usable
                        ])?;
                    }
                    insert.execute(params![id, sequence, elapsed_us, data])?;
                }
                transaction.commit()?;
            }
            id
        };
        let Some(id) = id else {
            // An earlier save's row is gone, and nothing was written.
            self.abandon();
            return Ok(());
        };
        self.id = Some(id);
        self.pending.clear();
        self.pending_context = None;
        self.next_write = Instant::now() + WRITE_INTERVAL;
        Ok(())
    }

    /// Stop recording a run that is no longer in the history: another copy
    /// pruned it to keep the history within its budget, or the user cleared
    /// the history. Its remaining events could only fail, each taking the
    /// writer lock that other copies wait for.
    fn abandon(&mut self) {
        self.pending.clear();
        self.pending_context = None;
        self.finished = true;
    }

    fn finish(&mut self, success: bool, summary: Value) -> Result<()> {
        // The `workers` column and the older `eligible` values belong to
        // runs from earlier releases; this build leaves `workers` unset.
        let outcome = Outcome {
            status: if success { "success" } else { "failed" },
            eligible: if success && self.lost == 0 && self.measurements.reusable() {
                inference::MEASUREMENTS
            } else {
                0
            },
            summary: serde_json::to_string(&summary)?,
        };
        // Pay at most one lock wait for the entire final save, no longer
        // than the copy itself took. Once the transaction owns the writer
        // lock, samples, context and the outcome commit together.
        self.commit(finish_wait(self.start.elapsed()), Some(&outcome))?;
        // Maintenance is best effort and must not renew the lock-wait budget.
        if let Some(id) = self.id.filter(|_| !self.finished) {
            prune(&self.db, self.budget, id)?;
        }
        Ok(())
    }
}

struct Outcome {
    status: &'static str,
    eligible: i64,
    summary: String,
}

/// How long a copy that ran for `elapsed` waits to save its run.
fn finish_wait(elapsed: Duration) -> Duration {
    elapsed.min(FINISH_LOCK_WAIT)
}

/// Take the writer lock, trying for at most `wait` while other connections
/// hold it. The connection itself waits for no lock, so this owns the wait
/// and can bound it more finely than a busy timeout does.
fn begin_within(db: &Connection, wait: Duration) -> Result<rusqlite::Transaction<'_>> {
    let deadline = Instant::now() + wait;
    let mut pause = Duration::from_micros(100);
    loop {
        match rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate) {
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DatabaseBusy && Instant::now() < deadline =>
            {
                std::thread::sleep(pause.min(deadline.saturating_duration_since(Instant::now())));
                pause = (pause * 2).min(Duration::from_millis(2));
            }
            result => return Ok(result?),
        }
    }
}

/// The key that makes this history's tokens, created with the history.
fn identity_key(db: &Connection) -> Result<[u8; 32]> {
    let read = || {
        db.query_row(
            "SELECT value FROM metadata WHERE key='identity_key'",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
    };
    let key = match read()? {
        Some(key) => key,
        None => {
            let mut generated = [0u8; 32];
            getrandom::fill(&mut generated).context("create tuning history identity key")?;
            // Another copy may be creating it too; all of them use the one
            // that was stored first.
            db.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('identity_key',?1)",
                [generated.as_slice()],
            )?;
            read()?.context("history identity key missing")?
        }
    };
    key.try_into()
        .map_err(|_| anyhow::anyhow!("invalid history identity key"))
}

impl Drop for Writer {
    fn drop(&mut self) {
        // A copy that ended has saved its run or given up on it.
        if !self.finished {
            let _ = self.save();
        }
    }
}

fn prune(db: &Connection, budget: u64, current: i64) -> Result<()> {
    prune_within(db, budget, current, PRUNE_TIME)
}

/// `prune`, spending at most about `time` deleting old runs.
fn prune_within(db: &Connection, budget: u64, current: i64, time: Duration) -> Result<()> {
    let deadline = Instant::now() + time;
    let page_size: i64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    let budget = budget.min(i64::MAX as u64) as i64;
    let used = || -> Result<(i64, i64)> {
        let pages: i64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let free: i64 = db.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        Ok((
            pages.saturating_sub(free).saturating_mul(page_size),
            free.saturating_mul(page_size),
        ))
    };
    let (mut size, mut free) = used()?;
    if size > budget {
        // Delete a little more than the excess, so that the copies which
        // follow find the history within its budget and only read its size.
        // A history far over its budget, as after the budget shrank, shrinks
        // over several copies, each spending about `time`.
        let target = budget - budget / PRUNE_SLACK;
        // Nothing here counts or scans the runs: each step sizes the next
        // from the space it freed, growing at most fourfold in case the
        // oldest runs are smaller than the ones behind them.
        let mut batch = 1;
        loop {
            let runs = prunable(db, current, batch)?;
            if runs.is_empty() {
                break;
            }
            let before = size;
            let deleted = delete_runs(db, &runs, deadline)? as i128;
            (size, free) = used()?;
            if size <= target || Instant::now() >= deadline {
                break;
            }
            let freed = i128::from(before - size);
            let needed = if freed > 0 {
                (deleted * i128::from(size - target) + freed - 1) / freed
            } else {
                deleted * 2
            };
            batch = needed.clamp(1, (batch * 4).min(PRUNE_BATCH) as i128) as usize;
        }
    }
    if size <= budget && free > budget {
        // Rebuilding costs time in proportion to the kept history, not to
        // the free space, which a gradual reclaim would have to move
        // around. This happens once after a large shrink.
        db.execute_batch("VACUUM;")?;
    } else if size <= budget && size + free > budget {
        // Later runs reuse free pages, so return only the ones that keep the
        // file over the budget. Each step of this pragma moves one page and
        // commits when the statement is dropped, so the same deadline bounds
        // it and the copies which follow finish the rest.
        let pages = (size + free - budget + page_size - 1) / page_size;
        let mut vacuum = db.prepare(&format!("PRAGMA incremental_vacuum({pages})"))?;
        let mut rows = vacuum.raw_query();
        while Instant::now() < deadline && rows.next()?.is_some() {}
    }
    Ok(())
}

/// Up to `batch` of the oldest runs to delete, never `current`.
///
/// A run that finished, or one left incomplete more than two days ago, can
/// go. Among the `PRUNE_WINDOW` oldest runs these go first, so an incomplete
/// run that a long copy may still be recording outlives them. Copies whose
/// final save found the history locked, and copies that were killed, leave
/// incomplete runs that never finish. Once such runs are all that the window
/// holds, the oldest of them go too, except the `ACTIVE_RUNS` started last.
/// Without that a history filled by them would stay over its budget, and
/// would cost every copy this search.
fn prunable(db: &Connection, current: i64, batch: usize) -> Result<Vec<i64>> {
    let mut oldest = db.prepare_cached(
        "SELECT id, status='incomplete' AND updated_day>=?2 FROM runs
         WHERE id!=?1 ORDER BY id LIMIT ?3",
    )?;
    let mut rows = oldest.query(params![current, day().saturating_sub(2), PRUNE_WINDOW])?;
    let settled = current.saturating_sub(ACTIVE_RUNS);
    let (mut runs, mut recent) = (Vec::new(), Vec::new());
    while let Some(row) = rows.next()? {
        let (id, may_be_active): (i64, bool) = (row.get(0)?, row.get(1)?);
        if !may_be_active {
            runs.push(id);
            if runs.len() == batch {
                break;
            }
        } else if id < settled && recent.len() < batch {
            recent.push(id);
        }
    }
    Ok(if runs.is_empty() { recent } else { runs })
}

/// Delete `runs` with their events in one transaction, stopping early at
/// `deadline`. Returns how many were deleted.
fn delete_runs(db: &Connection, runs: &[i64], deadline: Instant) -> Result<usize> {
    // Another run holding the writer lock fails this at once, and a later
    // copy prunes instead.
    let transaction =
        rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
    let mut deleted = 0;
    {
        let mut delete = transaction.prepare_cached("DELETE FROM runs WHERE id=?1")?;
        for run in runs {
            deleted += delete.execute([run])?;
            if Instant::now() >= deadline {
                break;
            }
        }
    }
    transaction.commit()?;
    Ok(deleted)
}

fn diagnostic(error: &anyhow::Error) {
    if crate::output::debug() {
        crate::output::diagnostic!("syq: tuning history: {error:#}");
    }
}

/// Keep transport-byte caps/scores separate from logical-byte measurements.
/// The existing mode already includes the numeric cap and compression setting.
/// Old readers query the old mode, so neither direction reinterprets history.
pub(crate) fn activity_mode(mut mode: String, transport: bool) -> String {
    if transport {
        mode.push_str(";bandwidth-accounting=transport-v1;activity=wire-bytes-v1");
    }
    mode
}

pub(crate) fn context_key(
    recorder: &Recorder,
    src: &crate::conn::Endpoint,
    dst: &crate::conn::Endpoint,
    source: Option<&str>,
    destination: Option<&str>,
    mode: String,
) -> ContextKey {
    let transport = |endpoint: &crate::conn::Endpoint| match endpoint {
        crate::conn::Endpoint::Remote(spec) if !spec.local_process => {
            format!("{:?}", spec.data_transport())
        }
        _ => "Local".into(),
    };
    let source_transport = transport(src);
    let destination_transport = transport(dst);
    let route = format!(
        "{}>{}|{}>{}",
        super::endpoint_key(src),
        super::endpoint_key(dst),
        source_transport,
        destination_transport
    );
    let remote = source_transport != "Local" || destination_transport != "Local";
    let network = remote.then(super::network::fingerprint).flatten();
    let route = if remote {
        super::network_key(&route, network.as_deref())
    } else {
        route
    };
    ContextKey {
        network: network.as_deref().map(|n| recorder.token("network", n)),
        source_endpoint: recorder.token("endpoint", &super::endpoint_key(src)),
        destination_endpoint: recorder.token("endpoint", &super::endpoint_key(dst)),
        source_transport,
        destination_transport,
        route: recorder.token("route", &route),
        source_filesystem: source
            .map(|v| recorder.token("filesystem", &format!("{}:{v}", super::endpoint_key(src)))),
        destination_filesystem: destination
            .map(|v| recorder.token("filesystem", &format!("{}:{v}", super::endpoint_key(dst)))),
        mode,
    }
}
