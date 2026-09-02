//! `--results`: an NDJSON stream of machine-readable operation outcomes for
//! native cp. Automation schema version 0 — an explicitly unstable preview
//! of the planned automation interface (`--output=ndjson` stays reserved for
//! the stable contract). Human output is unchanged; records go to the named
//! file, or to stdout with `-` (combine that with `-q`).
//!
//! Version-0 coverage: one `run` record first; one `operation_result` per
//! settled mutation (file transfers, directory/symlink/special creation
//! inside the target container) and per failed mapping entry; an `error`
//! record for every counted error; exactly one terminal `result`. Unchanged
//! and excluded entries are aggregated in the terminal record only, and
//! metadata-only updates are not yet reported per operation.
//!
//! Attached direct copies through a command-restricted receiver are the one
//! exception: receipt_v2 emits their stream locally after verification, marks
//! its provenance, omits source-side claims hostB cannot authenticate, and
//! includes closure-time final-state records.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

pub const SCHEMA: &str = "syq.automation";
pub const SCHEMA_VERSION: u64 = 0;

pub struct ResultsWriter {
    out: Mutex<Box<dyn Write + Send>>,
    seq: AtomicU64,
    /// A record failed to write: reported once on stderr, then nothing
    /// further is written. The consumer sees the missing terminal record.
    dead: AtomicBool,
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
    pub message: Option<&'a str>,
}

pub struct ResultRecord {
    pub status: &'static str,
    pub exit_code: i32,
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
}

impl ResultsWriter {
    pub fn new(out: Box<dyn Write + Send>) -> Self {
        ResultsWriter {
            out: Mutex::new(out),
            seq: AtomicU64::new(0),
            dead: AtomicBool::new(false),
        }
    }

    pub fn emit_run(&self, mapping: bool) {
        self.write(serde_json::json!({
            "type": "run",
            "syq_version": env!("CARGO_PKG_VERSION"),
            "mode": "cp",
            "mapping": mapping,
        }));
    }

    pub fn emit_error(&self, message: &str) {
        self.write(serde_json::json!({
            "type": "error",
            "message": message,
        }));
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
        if let Some(message) = op.message {
            object.insert("message".into(), message.into());
        }
        self.write(record);
    }

    /// The terminal record; flushes the stream. Nothing may be written after.
    pub fn emit_result(&self, result: &ResultRecord) {
        self.write(serde_json::json!({
            "type": "result",
            "status": result.status,
            "exit_code": result.exit_code,
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
        }));
        if !self.dead.load(Relaxed) {
            if let Err(error) = self.out.lock().unwrap().flush() {
                self.mark_dead(&error);
            }
        }
    }

    fn write(&self, mut record: serde_json::Value) {
        if self.dead.load(Relaxed) {
            return;
        }
        // Take the output lock before allocating the sequence number, so
        // records land in the stream in seq order.
        let mut out = self.out.lock().unwrap();
        let seq = self.seq.fetch_add(1, Relaxed);
        let object = record.as_object_mut().expect("record is an object");
        object.insert("schema".into(), SCHEMA.into());
        object.insert("schema_version".into(), SCHEMA_VERSION.into());
        object.insert("seq".into(), seq.into());
        let written = serde_json::to_writer(&mut *out, &record)
            .map_err(std::io::Error::from)
            .and_then(|()| out.write_all(b"\n"));
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
