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
#[cfg(test)]
mod tests;
pub(crate) use command::{command_for_help, run};
const SCHEMA: i64 = 1;
const DEFAULT_BUDGET: u64 = 128 << 20;
const MAX_PENDING: usize = 4096;
const FINISH_LOCK_WAIT: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub(crate) struct Recorder(Arc<Mutex<Writer>>);

struct Writer {
    db: Connection,
    id: i64,
    start: Instant,
    last_flush: Instant,
    sequence: u64,
    pending: Vec<Value>,
    pending_context: Option<ContextKey>,
    lost: i64,
    budget: u64,
    finished: bool,
    recommendation: Option<(usize, bool)>,
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
        size >= 16 << 20,
        "SYQ_TUNING_HISTORY_SIZE must be at least 16M"
    );
    Ok(size)
}

fn open(path: &Path) -> Result<Connection> {
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
    db.busy_timeout(Duration::from_millis(100))?;
    // This history is disposable: avoid durability barriers on the copy path.
    // Set this before schema creation or journal changes, which can also sync.
    // A system crash can lose or corrupt history; it never authorizes file work.
    db.pragma_update(None, "synchronous", "OFF")?;
    let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    anyhow::ensure!(
        matches!(version, 0 | SCHEMA),
        "unsupported tuning history version {version}"
    );
    if version == 0 {
        db.pragma_update(None, "auto_vacuum", "INCREMENTAL")
            .context("configure history page reclamation")?;
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("lock history for initialization")?;
        // Another process may have initialized the database while we waited.
        let version: i64 = transaction.pragma_query_value(None, "user_version", |r| r.get(0))?;
        anyhow::ensure!(
            matches!(version, 0 | SCHEMA),
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
                    PRIMARY KEY(run,sequence));
                PRAGMA user_version=1;")?;
        }
        transaction.commit()?;
    }
    // Concurrent first opens can race while changing journal mode. SQLite
    // returns BUSY immediately for this lock upgrade, without the busy handler.
    // Retry only this operation, within the same small startup wait budget.
    db.busy_timeout(Duration::ZERO)?;
    let deadline = Instant::now() + Duration::from_millis(100);
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
    db.busy_timeout(Duration::from_millis(100))?;
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
        let db = open(path)?;
        let mut generated = [0u8; 32];
        getrandom::fill(&mut generated).context("create tuning history identity key")?;
        db.execute(
            "INSERT OR IGNORE INTO metadata VALUES ('identity_key',?1)",
            [generated.as_slice()],
        )?;
        let salt: Vec<u8> = db.query_row(
            "SELECT value FROM metadata WHERE key='identity_key'",
            [],
            |r| r.get(0),
        )?;
        let salt = salt
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid history identity key"))?;
        db.execute(
            "INSERT INTO runs(day,updated_day,build) VALUES (?1,?1,?2)",
            params![day(), crate::identity::build()],
        )?;
        let id = db.last_insert_rowid();
        db.busy_timeout(Duration::ZERO)?;
        let recorder = Self(Arc::new(Mutex::new(Writer {
            db,
            id,
            start,
            last_flush: Instant::now(),
            sequence: 0,
            pending: Vec::new(),
            pending_context: None,
            lost: 0,
            budget,
            finished: false,
            recommendation: None,
            salt,
        })));
        recorder.event("start", details);
        recorder.flush();
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
        let elapsed_us = state.start.elapsed().as_micros().min(i64::MAX as u128) as u64;
        let sequence = state.sequence;
        state.sequence += 1;
        if state.pending.len() < MAX_PENDING {
            state
                .pending
                .push(json!({"sequence":sequence,"elapsed_us":elapsed_us,"kind":kind,"data":data}));
        } else {
            state.lost += 1;
        }
        if state.last_flush.elapsed() >= Duration::from_secs(1) || state.pending.len() >= 64 {
            if let Err(error) = state.flush() {
                diagnostic(&error);
            }
        }
    }

    pub(crate) fn flush(&self) {
        if let Err(error) = self.0.lock().unwrap_or_else(|p| p.into_inner()).flush() {
            diagnostic(&error);
        }
    }

    pub(crate) fn context(&self, key: &ContextKey) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.pending_context = Some(key.clone());
        if let Err(error) = state.flush() {
            diagnostic(&error);
        }
    }

    pub(crate) fn hint(&self, key: &ContextKey, allow_route: bool) -> Option<Hint> {
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        select_hint(&state.db, key, allow_route).ok().flatten()
    }

    pub(crate) fn recommend(&self, workers: usize, discovery_complete: bool) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .recommendation = Some((workers, discovery_complete));
    }

    pub(crate) fn complete(&self, success: bool, mut summary: Value) {
        let recommendation = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .recommendation;
        if let Some((_, discovery_complete)) = recommendation {
            summary["discovery_complete"] = json!(discovery_complete);
        }
        self.finish(
            success,
            recommendation.is_some(),
            recommendation.map(|(workers, _)| workers),
            summary,
        );
    }

    pub(crate) fn finish(
        &self,
        success: bool,
        eligible: bool,
        workers: Option<usize>,
        summary: Value,
    ) {
        self.event("finish", summary.clone());
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.finished {
            return;
        }
        if let Err(error) = state.finish(success, eligible, workers, summary) {
            diagnostic(&error);
        }
        state.finished = true;
    }
}

fn select_hint(db: &Connection, key: &ContextKey, allow_route: bool) -> Result<Option<Hint>> {
    if let (Some(src), Some(dst)) = (&key.source_filesystem, &key.destination_filesystem) {
        let hint = db.query_row("SELECT id,workers,summary FROM runs WHERE route=?1 AND mode=?2 AND source_fs=?3 AND destination_fs=?4 AND status='success' AND eligible=1 AND workers>0 ORDER BY id DESC LIMIT 1",
            params![key.route,key.mode,src,dst], |r| {
                // The additive summary field leaves old histories usable as
                // starting guesses, without mistaking them for completed search.
                let summary: Option<String> = r.get(2)?;
                let refine = summary.as_deref()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                    .is_some_and(|s| s["discovery_complete"] == true);
                Ok(Hint {run:r.get(0)?,workers:r.get::<_,u32>(1)? as usize,matched:"filesystems".into(),refine})
            }).optional()?;
        if hint.is_some() {
            return Ok(hint);
        }
    }
    if !allow_route {
        return Ok(None);
    }
    Ok(db.query_row("SELECT id,workers FROM runs WHERE route=?1 AND mode=?2 AND status='success' AND eligible=1 AND workers>0 ORDER BY id DESC LIMIT 1",
        params![key.route,key.mode], |r| Ok(Hint {run:r.get(0)?,workers:r.get::<_,u32>(1)? as usize,matched:"route".into(),refine:false})).optional()?)
}

impl Writer {
    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() && self.pending_context.is_none() {
            return Ok(());
        }
        let transaction = self.db.unchecked_transaction()?;
        self.write_pending(&transaction)?;
        transaction.commit()?;
        self.mark_flushed();
        Ok(())
    }

    fn write_pending(&self, transaction: &rusqlite::Transaction<'_>) -> Result<()> {
        // Context revisions (for example, discovering a mixed-filesystem tree)
        // must survive contention just like samples. Finish flushes this before
        // publishing any recommendation under the context.
        if let Some(key) = &self.pending_context {
            transaction.execute("UPDATE runs SET context=?1,route=?2,source_fs=?3,destination_fs=?4,mode=?5 WHERE id=?6",
                params![serde_json::to_string(key)?, key.route, key.source_filesystem, key.destination_filesystem, key.mode, self.id])?;
        }
        {
            let mut insert = transaction.prepare("INSERT INTO events VALUES (?1,?2,?3,?4)")?;
            for event in &self.pending {
                insert.execute(params![
                    self.id,
                    event["sequence"].as_i64(),
                    event["elapsed_us"].as_i64(),
                    serde_json::to_string(event)?
                ])?;
            }
        }
        transaction.execute(
            "UPDATE runs SET lost=?1,updated_day=?3 WHERE id=?2",
            params![self.lost, self.id, day()],
        )?;
        Ok(())
    }

    fn mark_flushed(&mut self) {
        self.pending.clear();
        self.pending_context = None;
        self.last_flush = Instant::now();
    }

    fn finish(
        &mut self,
        success: bool,
        eligible: bool,
        workers: Option<usize>,
        summary: Value,
    ) -> Result<()> {
        // Pay at most one small lock wait for the entire final save. Once the
        // immediate transaction owns the writer lock, samples, context and the
        // recommendation commit together without per-statement busy waits.
        self.db.busy_timeout(FINISH_LOCK_WAIT)?;
        let transaction = rusqlite::Transaction::new_unchecked(
            &self.db,
            rusqlite::TransactionBehavior::Immediate,
        );
        self.db.busy_timeout(Duration::ZERO)?;
        let transaction = transaction?;
        self.write_pending(&transaction)?;
        transaction.execute(
            "UPDATE runs SET status=?1,eligible=?2,workers=?3,summary=?4,lost=?5 WHERE id=?6",
            params![
                if success { "success" } else { "failed" },
                success && eligible && self.lost == 0 && workers.is_some(),
                workers.map(|n| n as u32),
                serde_json::to_string(&summary)?,
                self.lost,
                self.id
            ],
        )?;
        transaction.commit()?;
        self.mark_flushed();
        // Maintenance is best effort and must not renew the lock-wait budget.
        prune(&self.db, self.budget, self.id)?;
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn prune(db: &Connection, budget: u64, current: i64) -> Result<()> {
    let page_size: i64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    // Stop as soon as enough space has been reclaimed, with bounded work per
    // completion. The current run and recent incomplete runs are preserved.
    for _ in 0..100 {
        let pages: i64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let free: i64 = db.pragma_query_value(None, "freelist_count", |r| r.get(0))?;
        if pages.saturating_sub(free) * page_size <= budget.min(i64::MAX as u64) as i64 {
            break;
        }
        let deleted = db.execute("DELETE FROM runs WHERE id IN (SELECT id FROM runs WHERE id!=?1 AND (status!='incomplete' OR updated_day<?2) ORDER BY id LIMIT 1)",params![current,day().saturating_sub(2)])?;
        if deleted == 0 {
            break;
        }
    }
    db.execute_batch("PRAGMA incremental_vacuum(256);")?;
    Ok(())
}

fn diagnostic(error: &anyhow::Error) {
    if crate::output::debug() {
        crate::output::diagnostic!("syq: tuning history: {error:#}");
    }
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
    ContextKey {
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
