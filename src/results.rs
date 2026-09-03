//! `--results`: an NDJSON stream of machine-readable operation outcomes for
//! native cp. Automation schema version 1: every record carries `schema`
//! (`syq.automation`), `schema_version`, and a monotonic `seq`. The stream
//! target is a freshly created file (`--results FILE`) or a descriptor the
//! caller opened (`--results-fd N`); human output is untouched.
//!
//! Version-1 coverage: one `run` record first (run id, mode, prune/mapping/
//! dry-run flags, sanitized endpoints); sampled `progress` records; one
//! `operation_result` per settled mutation (file transfers, directory/
//! symlink/special creation inside the target container, `--prune`
//! deletions) and per failed mapping entry, with `retryable` and
//! `class`/`os_kind` where known; an `error` record for every counted
//! error; `trace` records instead of operation results on dry runs; exactly
//! one terminal `result` whose numbers also feed the human summary, so the
//! two cannot disagree. Unchanged and excluded entries are aggregated in
//! the terminal record only, and metadata-only updates are not reported
//! per operation (dry runs do trace them as `metadata_differs`).
//!
//! Attached direct copies through a command-restricted receiver are the one
//! exception: receipt_v2 emits their stream locally after verification, marks
//! its provenance, omits source-side claims hostB cannot authenticate, and
//! includes closure-time final-state records. (Not yet reachable while
//! remote-to-remote copies refuse the file/descriptor targets.)

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

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
    pub prune: bool,
    pub mapping: bool,
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
        self.write(serde_json::json!({
            "type": "run",
            "run_id": run.run_id,
            "started_at": run.started_at,
            "syq_version": env!("CARGO_PKG_VERSION"),
            "mode": run.mode,
            "prune": run.prune,
            "mapping": run.mapping,
            "dry_run": run.dry_run,
            "endpoints": endpoints,
        }));
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
