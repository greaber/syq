//! `--results`: an NDJSON stream of machine-readable operation outcomes for
//! native cp and rm. Every record carries `schema` (`syq.automation`),
//! `schema_version`, and a monotonic `seq`. The stream
//! target is a freshly created file (`--results FILE`) or a descriptor the
//! caller opened (`--results-fd N`); human output is untouched.
//!
//! Version-1 coverage: one `run` record first (run id, mode, dry-run flags,
//! sanitized endpoints, and copy-only prune/mapping flags); sampled `progress`
//! records; command-specific per-path records; an `error` record for every
//! counted error; and exactly one terminal `result` whose numbers also feed the
//! human summary, so the two cannot disagree. Copy emits `operation_result` or
//! dry-run `trace` records. Removal emits one `selection_result` per explicit
//! selector followed by `removal_result` or dry-run `removal_trace` records for
//! entries in the selected trees. Unchanged and excluded copy entries are
//! aggregated in the terminal record only, and metadata-only copy updates are
//! not reported per operation (dry runs do trace them as `metadata_differs`).
//!
//! Attached direct copies through a command-restricted receiver are the one
//! exception: receipt_policy emits their stream locally after verification, marks
//! its provenance, omits source-side claims hostB cannot authenticate, and
//! includes closure-time final-state records.

use crate::cli::{Args, Interface, Location};
use crate::proto::OperatorSymlinkPolicy;
use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

pub const SCHEMA: &str = "syq.automation";
pub const SCHEMA_VERSION: u64 = 1;

pub struct ResultsWriter {
    out: Mutex<Box<dyn Write + Send>>,
    seq: AtomicU64,
    /// A record failed to write: reported once on stderr, then nothing
    /// further is written. The consumer sees the missing terminal record.
    dead: AtomicBool,
    /// The terminal record has been written: the stream is complete and
    /// nothing may follow it, even from a straggling ticker render racing
    /// an error unwind. Sealing also makes a second terminal impossible.
    sealed: AtomicBool,
}

/// One settled operation. `dst`/`src` are container/base-relative raw path
/// bytes; together with `kind` a failed record round-trips as a mapping
/// entry for retry.
pub struct OperationRecord<'a> {
    pub action: &'static str,
    pub dst: &'a [u8],
    pub src: Option<&'a [u8]>,
    pub kind: &'static str,
    pub disposition: &'static str,
    pub bytes: Option<u64>,
    pub attempts: Option<u64>,
    pub retryable: Option<&'static str>,
    pub class: Option<&'static str>,
    pub os_kind: Option<&'static str>,
    pub message: Option<&'a str>,
}

pub struct RunRecord<'a> {
    pub run_id: &'a str,
    pub started_at: i64,
    pub mode: &'static str,
    /// Copy-only fields. Omitting them gives rm a distinct shape instead of
    /// assigning copy semantics to false values.
    pub prune: Option<bool>,
    pub mapping: Option<bool>,
    pub dry_run: bool,
    pub endpoints: Vec<EndpointRecord>,
}

pub struct EndpointRecord {
    pub role: &'static str,
    pub host: Option<String>,
    pub user: Option<String>,
}

pub struct ProgressRecord {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bytes_unchanged: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub files_unchanged: u64,
    pub files_excluded: u64,
    pub scanned: u64,
    pub scan_done: bool,
    pub elapsed_ms: u64,
}

pub struct TraceRecord<'a> {
    pub action: &'static str,
    pub dst: &'a [u8],
    pub src: Option<&'a [u8]>,
    pub kind: &'static str,
    pub bytes: Option<u64>,
    pub reason: &'static str,
}

pub struct RemovalSelectionRecord<'a> {
    pub selector: u64,
    pub path: &'a [u8],
    pub status: &'static str,
    pub kind: Option<&'static str>,
}

pub struct RemovalRecord<'a> {
    pub selector: u64,
    pub path: &'a [u8],
    pub kind: Option<&'static str>,
    pub disposition: &'static str,
    pub attempts: Option<u64>,
    pub retryable: Option<&'static str>,
    pub class: Option<&'static str>,
    pub os_kind: Option<&'static str>,
    pub message: Option<&'a str>,
}

pub struct ResultRecord {
    pub status: &'static str,
    pub exit_code: i32,
    pub dry_run: bool,
    pub files_transferred: u64,
    pub files_unchanged: u64,
    pub files_excluded: u64,
    pub directories_created: u64,
    pub symlinks_created: u64,
    pub specials_created: u64,
    pub errors: u64,
    pub bytes_transferred: u64,
    pub bytes_unchanged: u64,
    pub elapsed_ms: u64,
    /// `--prune` runs only; None keeps the fields out of the record.
    pub deletions_planned: Option<u64>,
    pub deletions_completed: Option<u64>,
    pub deletions_blocked: Option<u64>,
}

pub struct RemovalResultRecord {
    pub status: &'static str,
    pub exit_code: i32,
    pub dry_run: bool,
    pub selectors_total: u64,
    pub selectors_resolved: u64,
    pub selectors_missing: u64,
    pub entries_planned: u64,
    pub entries_removed: u64,
    pub entries_already_absent: u64,
    pub entries_failed: u64,
    pub errors: u64,
    pub elapsed_ms: u64,
}

#[derive(Clone, Copy)]
pub enum RunMode {
    Cp { prune: bool, mapping: bool },
    Rm,
}

/// Create the caller-side result target and emit its first record. Both
/// native commands use this path so descriptor ownership, symlink policy,
/// fresh-file semantics, and run identity cannot drift.
pub fn start(args: &Args, mode: RunMode) -> Result<Option<Arc<ResultsWriter>>> {
    let requested = args.native_results.is_some() || args.native_results_fd.is_some();
    if !requested {
        return Ok(None);
    }
    let out: Box<dyn std::io::Write + Send> = if let Some(fd) = args.native_results_fd {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 {
            bail!(
                "--results-fd {fd}: descriptor is not open; connect it in the caller, e.g. --results-fd {fd} {fd}>run.ndjson"
            );
        }
        if flags & libc::O_ACCMODE == libc::O_RDONLY {
            bail!(
                "--results-fd {fd}: descriptor is open read-only; connect it for writing, e.g. --results-fd {fd} {fd}>run.ndjson"
            );
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            bail!("--results-fd {fd}: {}", std::io::Error::last_os_error());
        }
        // Safety: the descriptor is inherited, open, and explicitly handed
        // to syq. The operation owns it until the writer is dropped.
        Box::new(unsafe { <std::fs::File as FromRawFd>::from_raw_fd(fd) })
    } else {
        let results = args.native_results.as_deref().expect("results requested");
        let path = std::path::PathBuf::from(OsStr::from_bytes(results).to_os_string());
        let policy = if args.interface == Interface::Rsync {
            OperatorSymlinkPolicy::TrustedOwner
        } else if args.native_follow {
            OperatorSymlinkPolicy::FollowAll
        } else {
            OperatorSymlinkPolicy::Refuse
        };
        let file = crate::fsops::create_operator_file(results, policy).map_err(|error| {
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists)
            }) {
                anyhow::anyhow!(
                    "--results {}: the file already exists; a results file holds exactly one run — remove it or choose a new name (recurring jobs can timestamp: run-$(date +%s).ndjson)",
                    path.display()
                )
            } else {
                anyhow::anyhow!("--results {}: {error}", path.display())
            }
        })?;
        Box::new(file)
    };
    let writer = Arc::new(ResultsWriter::new(out));
    let run_id = {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).context("generate run ID")?;
        let mut hex = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        hex
    };
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    let include_destination = !matches!(mode, RunMode::Rm);
    let (name, prune, mapping) = match mode {
        RunMode::Cp { prune, mapping } => ("cp", Some(prune), Some(mapping)),
        RunMode::Rm => ("rm", None, None),
    };
    writer.emit_run(&RunRecord {
        run_id: &run_id,
        started_at,
        mode: name,
        prune,
        mapping,
        dry_run: args.dry_run,
        endpoints: run_endpoints(&args.locations, include_destination),
    });
    if writer.is_dead() {
        bail!("--results stream failed before the run record was written");
    }
    Ok(Some(writer))
}

fn run_endpoints(locations: &[Location], include_destination: bool) -> Vec<EndpointRecord> {
    let mut endpoints = Vec::new();
    if let Some(source) = locations.first() {
        endpoints.push(EndpointRecord {
            role: "source",
            host: source.host.clone(),
            user: source.user.clone(),
        });
    }
    if include_destination && locations.len() >= 2 {
        if let Some(destination) = locations.last() {
            endpoints.push(EndpointRecord {
                role: "destination",
                host: destination.host.clone(),
                user: destination.user.clone(),
            });
        }
    }
    endpoints
}

impl ResultsWriter {
    pub fn new(out: Box<dyn Write + Send>) -> Self {
        ResultsWriter {
            out: Mutex::new(out),
            seq: AtomicU64::new(0),
            dead: AtomicBool::new(false),
            sealed: AtomicBool::new(false),
        }
    }

    pub fn emit_run(&self, run: &RunRecord) {
        let endpoints: Vec<serde_json::Value> = run
            .endpoints
            .iter()
            .map(|endpoint| {
                let mut value = serde_json::json!({
                    "role": endpoint.role,
                    "kind": if endpoint.host.is_some() { "ssh" } else { "local" },
                });
                let object = value.as_object_mut().expect("endpoint is an object");
                if let Some(host) = &endpoint.host {
                    object.insert("host".into(), host.as_str().into());
                }
                if let Some(user) = &endpoint.user {
                    object.insert("user".into(), user.as_str().into());
                }
                value
            })
            .collect();
        let mut record = serde_json::json!({
            "type": "run",
            "run_id": run.run_id,
            "started_at": run.started_at,
            "syq_version": env!("CARGO_PKG_VERSION"),
            "mode": run.mode,
            "dry_run": run.dry_run,
            "endpoints": endpoints,
        });
        let object = record.as_object_mut().expect("record is an object");
        if let Some(prune) = run.prune {
            object.insert("prune".into(), prune.into());
        }
        if let Some(mapping) = run.mapping {
            object.insert("mapping".into(), mapping.into());
        }
        self.write(record);
    }

    pub fn emit_progress(&self, progress: &ProgressRecord) {
        self.write(serde_json::json!({
            "type": "progress",
            "bytes_done": progress.bytes_done,
            "bytes_total": progress.bytes_total,
            "bytes_unchanged": progress.bytes_unchanged,
            "files_done": progress.files_done,
            "files_total": progress.files_total,
            "files_unchanged": progress.files_unchanged,
            "files_excluded": progress.files_excluded,
            "scanned": progress.scanned,
            "scan_done": progress.scan_done,
            "elapsed_ms": progress.elapsed_ms,
        }));
    }

    /// Dry run only: one intended mutation, sharing `operation_result`'s
    /// identity fields, with the reason the mutation is needed.
    pub fn emit_trace(&self, trace: &TraceRecord) {
        let mut record = serde_json::json!({
            "type": "trace",
            "action": trace.action,
            "dst": tagged(trace.dst),
            "kind": trace.kind,
            "reason": trace.reason,
        });
        let object = record.as_object_mut().expect("record is an object");
        if let Some(src) = trace.src {
            object.insert("src".into(), tagged(src));
        }
        if let Some(bytes) = trace.bytes {
            object.insert("bytes".into(), bytes.into());
        }
        self.write(record);
    }

    pub fn emit_removal_selection(&self, selection: &RemovalSelectionRecord) {
        let mut record = serde_json::json!({
            "type": "selection_result",
            "selector": selection.selector,
            "path": tagged(selection.path),
            "status": selection.status,
        });
        if let Some(kind) = selection.kind {
            record
                .as_object_mut()
                .expect("record is an object")
                .insert("kind".into(), kind.into());
        }
        self.write(record);
    }

    pub fn emit_removal_trace(&self, removal: &RemovalRecord) {
        let kind = removal
            .kind
            .expect("a planned removal always has a resolved object kind");
        self.write(serde_json::json!({
            "type": "removal_trace",
            "selector": removal.selector,
            "path": tagged(removal.path),
            "kind": kind,
            "disposition": "would_remove",
        }));
    }

    pub fn emit_removal(&self, removal: &RemovalRecord) {
        let mut record = serde_json::json!({
            "type": "removal_result",
            "selector": removal.selector,
            "path": tagged(removal.path),
            "disposition": removal.disposition,
        });
        let object = record.as_object_mut().expect("record is an object");
        if let Some(kind) = removal.kind {
            object.insert("kind".into(), kind.into());
        }
        if let Some(attempts) = removal.attempts {
            object.insert("attempts".into(), attempts.into());
        }
        if let Some(retryable) = removal.retryable {
            object.insert("retryable".into(), retryable.into());
        }
        if let Some(class) = removal.class {
            object.insert("class".into(), class.into());
        }
        if let Some(os_kind) = removal.os_kind {
            object.insert("os_kind".into(), os_kind.into());
        }
        if let Some(message) = removal.message {
            object.insert("message".into(), message.into());
        }
        self.write(record);
    }

    pub fn emit_error_classified(
        &self,
        message: &str,
        class: Option<&'static str>,
        os_kind: Option<&'static str>,
    ) {
        let mut record = serde_json::json!({
            "type": "error",
            "message": message,
        });
        let object = record.as_object_mut().expect("record is an object");
        if let Some(class) = class {
            object.insert("class".into(), class.into());
        }
        if let Some(os_kind) = os_kind {
            object.insert("os_kind".into(), os_kind.into());
        }
        self.write(record);
        // Error records must be immediately observable, not buffered until
        // the terminal record.
        self.flush_now();
    }

    fn flush_now(&self) {
        if !self.dead.load(Relaxed) {
            if let Err(error) = self.out.lock().unwrap().flush() {
                self.mark_dead(&error);
            }
        }
    }

    pub fn emit_operation(&self, op: &OperationRecord) {
        let mut record = serde_json::json!({
            "type": "operation_result",
            "action": op.action,
            "dst": tagged(op.dst),
            "kind": op.kind,
            "disposition": op.disposition,
        });
        let object = record.as_object_mut().expect("record is an object");
        if let Some(src) = op.src {
            object.insert("src".into(), tagged(src));
        }
        if let Some(bytes) = op.bytes {
            object.insert("bytes".into(), bytes.into());
        }
        if let Some(attempts) = op.attempts {
            object.insert("attempts".into(), attempts.into());
        }
        if let Some(retryable) = op.retryable {
            object.insert("retryable".into(), retryable.into());
        }
        if let Some(class) = op.class {
            object.insert("class".into(), class.into());
        }
        if let Some(os_kind) = op.os_kind {
            object.insert("os_kind".into(), os_kind.into());
        }
        if let Some(message) = op.message {
            object.insert("message".into(), message.into());
        }
        self.write(record);
    }

    /// The terminal record; flushes the stream. Nothing may be written after.
    pub fn emit_result(&self, result: &ResultRecord) {
        let mut record = serde_json::json!({
            "type": "result",
            "status": result.status,
            "exit_code": result.exit_code,
            "dry_run": result.dry_run,
            "files_transferred": result.files_transferred,
            "files_unchanged": result.files_unchanged,
            "files_excluded": result.files_excluded,
            "directories_created": result.directories_created,
            "symlinks_created": result.symlinks_created,
            "specials_created": result.specials_created,
            "errors": result.errors,
            "bytes_transferred": result.bytes_transferred,
            "bytes_unchanged": result.bytes_unchanged,
            "elapsed_ms": result.elapsed_ms,
        });
        let object = record.as_object_mut().expect("record is an object");
        if let Some(planned) = result.deletions_planned {
            object.insert("deletions_planned".into(), planned.into());
        }
        if let Some(completed) = result.deletions_completed {
            object.insert("deletions_completed".into(), completed.into());
        }
        if let Some(blocked) = result.deletions_blocked {
            object.insert("deletions_blocked".into(), blocked.into());
        }
        self.write_and_seal(record, true);
    }

    pub fn emit_removal_result(&self, result: &RemovalResultRecord) {
        self.write_and_seal(
            serde_json::json!({
                "type": "result",
                "mode": "rm",
                "status": result.status,
                "exit_code": result.exit_code,
                "dry_run": result.dry_run,
                "selectors_total": result.selectors_total,
                "selectors_resolved": result.selectors_resolved,
                "selectors_missing": result.selectors_missing,
                "entries_planned": result.entries_planned,
                "entries_removed": result.entries_removed,
                "entries_already_absent": result.entries_already_absent,
                "entries_failed": result.entries_failed,
                "errors": result.errors,
                "elapsed_ms": result.elapsed_ms,
            }),
            true,
        );
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Relaxed)
    }

    fn write(&self, record: serde_json::Value) {
        self.write_and_seal(record, false);
    }

    /// Emit a caller-built record (receipt-attested emission); the envelope
    /// and sequencing are applied like any other record.
    pub(crate) fn emit_value(&self, record: serde_json::Value) {
        self.write_and_seal(record, false);
    }

    /// Emit a caller-built terminal record and seal the stream, flushing
    /// inside the same critical section like `emit_result`.
    pub(crate) fn emit_terminal_value(&self, record: serde_json::Value) {
        self.write_and_seal(record, true);
    }

    fn write_and_seal(&self, mut record: serde_json::Value, seal: bool) {
        if self.dead.load(Relaxed) {
            return;
        }
        // Take the output lock before allocating the sequence number, so
        // records land in the stream in seq order. The seal is checked and
        // set under the same lock: a ticker that raced past an unsealed
        // check would otherwise block on the mutex and append its progress
        // record after the terminal one.
        let mut out = self.out.lock().unwrap();
        if self.sealed.load(Relaxed) {
            return;
        }
        if seal {
            self.sealed.store(true, Relaxed);
        }
        let seq = self.seq.fetch_add(1, Relaxed);
        let object = record.as_object_mut().expect("record is an object");
        object.insert("schema".into(), SCHEMA.into());
        object.insert("schema_version".into(), SCHEMA_VERSION.into());
        object.insert("seq".into(), seq.into());
        // One buffer, one write: the record lands whole and immediately, so
        // a consumer tailing the file or reading a pipe sees events live.
        let written = serde_json::to_vec(&record)
            .map_err(std::io::Error::from)
            .and_then(|mut line| {
                line.push(b'\n');
                out.write_all(&line)
            })
            // The terminal record leaves the process with the stream, so it
            // flushes inside the same critical section that seals it.
            .and_then(|()| if seal { out.flush() } else { Ok(()) });
        if let Err(error) = written {
            drop(out);
            self.mark_dead(&error);
        }
    }

    fn mark_dead(&self, error: &std::io::Error) {
        if !self.dead.swap(true, Relaxed) {
            eprintln!("syq: warning: --results stream failed ({error}); further records are lost");
        }
    }
}

fn tagged(path: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    match std::str::from_utf8(path) {
        Ok(value) => serde_json::json!({"encoding": "utf-8", "value": value}),
        Err(_) => serde_json::json!({
            "encoding": "base64",
            "value": base64::engine::general_purpose::STANDARD.encode(path),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn nothing_follows_the_terminal_record() {
        let sink = Sink::default();
        let writer = ResultsWriter::new(Box::new(sink.clone()));
        writer.emit_result(&ResultRecord {
            status: "failed",
            exit_code: 1,
            dry_run: false,
            files_transferred: 0,
            files_unchanged: 0,
            files_excluded: 0,
            directories_created: 0,
            symlinks_created: 0,
            specials_created: 0,
            errors: 1,
            bytes_transferred: 0,
            bytes_unchanged: 0,
            elapsed_ms: 0,
            deletions_planned: None,
            deletions_completed: None,
            deletions_blocked: None,
        });
        let after = sink.0.lock().unwrap().len();
        // A straggling ticker render (or a second terminal) must be inert.
        writer.emit_progress(&ProgressRecord {
            bytes_done: 1,
            bytes_total: 1,
            bytes_unchanged: 0,
            files_done: 1,
            files_total: 1,
            files_unchanged: 0,
            files_excluded: 0,
            scanned: 1,
            scan_done: true,
            elapsed_ms: 1,
        });
        writer.emit_result(&ResultRecord {
            status: "success",
            exit_code: 0,
            dry_run: false,
            files_transferred: 0,
            files_unchanged: 0,
            files_excluded: 0,
            directories_created: 0,
            symlinks_created: 0,
            specials_created: 0,
            errors: 0,
            bytes_transferred: 0,
            bytes_unchanged: 0,
            elapsed_ms: 0,
            deletions_planned: None,
            deletions_completed: None,
            deletions_blocked: None,
        });
        assert_eq!(sink.0.lock().unwrap().len(), after);
    }
}
