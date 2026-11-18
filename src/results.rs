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
//! A copy between two servers writes the remote coordinator's records on
//! the invoking machine (`remote_to_remote`). Through a command-restricted
//! receiver, the records of its changes, and of the changes it refused or
//! that failed there, come from the receiver itself (`destination_results`).

use crate::cli::{Args, Interface};
use crate::proto::OperatorSymlinkPolicy;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

pub const SCHEMA: &str = "syq.automation";
pub const SCHEMA_VERSION: u64 = 4;
/// On an `error` record: the destination path whose failure the record
/// explains. The failure itself is counted by another record, so this one
/// is not.
pub(crate) const DIAGNOSTIC_FOR: &str = "diagnostic_for";

/// Whether a command-restricted receiver lists a failure at a destination
/// path in its own results, which then count it instead of the coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiverListing {
    /// It does not: the coordinator's records count the failure.
    Unlisted,
    /// It does, with the reason it gave: the coordinator's own records of
    /// the failure are left out.
    Listed,
    /// It lists the path as failed without knowing why, as a file it was
    /// writing that was never finished: the coordinator's error explains
    /// it, without counting it again.
    Explained,
}

pub struct ResultsWriter {
    schema_version: u64,
    /// A restricted destination reports the changes it settled itself, and
    /// the failures it saw, so this coordinator leaves those records to it.
    destination_reports: bool,
    parent: Option<Arc<ResultsWriter>>,
    phase_result: Mutex<Option<serde_json::Value>>,
    mapping_metadata: std::sync::OnceLock<
        std::collections::HashMap<crate::proto::PathBytes, crate::mapping::Metadata>,
    >,
    out: Mutex<Box<dyn Write + Send>>,
    seq: AtomicU64,
    /// A record failed to write: reported once on stderr, then nothing
    /// further is written. The consumer sees the missing terminal record.
    dead: AtomicBool,
    /// The terminal record has been written: the stream is complete and
    /// nothing may follow it, even from a straggling ticker render racing
    /// an error unwind. Sealing also makes a second terminal impossible.
    sealed: AtomicBool,
    /// Counted error records written for a caller (`emit_value`), as a
    /// remote coordinator's are relayed: the final record counts them.
    relayed_errors: AtomicU64,
}

impl std::fmt::Debug for ResultsWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResultsWriter").finish_non_exhaustive()
    }
}

/// One settled operation. `dst`/`src` are container/base-relative raw path
/// bytes; together with `kind` a failed record round-trips as a mapping
/// entry for retry.
#[derive(Serialize)]
pub struct OperationRecord<'a> {
    pub action: &'static str,
    #[serde(serialize_with = "tagged_path")]
    pub dst: &'a [u8],
    #[serde(
        serialize_with = "tagged_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub src: Option<&'a [u8]>,
    pub kind: &'static str,
    pub disposition: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'a str>,
}

#[derive(Serialize)]
pub struct RunRecord<'a> {
    pub run_id: &'a str,
    pub started_at: i64,
    pub mode: &'static str,
    /// Copy-only fields. Omitting them gives rm a distinct shape instead of
    /// assigning copy semantics to false values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prune: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<bool>,
    pub dry_run: bool,
    pub endpoints: Vec<EndpointRecord>,
}

pub struct EndpointRecord {
    pub role: &'static str,
    pub host: Option<String>,
    pub user: Option<String>,
}

impl Serialize for EndpointRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Endpoint<'a> {
            role: &'a str,
            kind: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            host: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            user: Option<&'a str>,
        }
        Endpoint {
            role: self.role,
            kind: match self.host.as_deref() {
                Some(host) if host.starts_with("s3://") => "s3",
                Some(_) => "ssh",
                None => "local",
            },
            host: self.host.as_deref(),
            user: self.user.as_deref(),
        }
        .serialize(serializer)
    }
}

#[derive(Serialize)]
pub struct ProgressRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) activity: Option<&'a crate::transfer_observations::Interval>,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bytes_unchanged: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub files_unchanged: u64,
    pub files_excluded: u64,
    pub scanned: u64,
    pub scan_done: bool,
    pub timings: crate::progress::Timings,
    pub rate_bytes_per_second: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_ms: Option<u64>,
}

#[derive(Serialize)]
pub struct TraceRecord<'a> {
    pub action: &'static str,
    #[serde(serialize_with = "tagged_path")]
    pub dst: &'a [u8],
    #[serde(
        serialize_with = "tagged_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub src: Option<&'a [u8]>,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub reason: &'static str,
}

#[derive(Serialize)]
pub struct SelectionResultRecord<'a> {
    pub selector: u64,
    #[serde(serialize_with = "tagged_path")]
    pub path: &'a [u8],
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
}

#[derive(Serialize)]
pub struct RemovalRecord<'a> {
    pub selector: u64,
    #[serde(serialize_with = "tagged_path")]
    pub path: &'a [u8],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
    pub disposition: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'a str>,
}

/// A terminal record's `status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Success,
    Partial,
    Refused,
    Aborted,
    Failed,
}

/// A copy's terminal record. A coordinator on another machine sends one
/// that this machine relays, so it reads back as well.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultRecord {
    pub status: Status,
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
    pub timings: crate::progress::Timings,
    /// Stream copies only: whether the source's size was known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total_known: Option<bool>,
    /// `--prune` runs only; None keeps the fields out of the record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletions_planned: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletions_completed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletions_blocked: Option<u64>,
    /// `--in-place=update` runs only: existing files replaced rather than
    /// updated in place, by reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_not_in_place: Option<ReplacedNotInPlace>,
    /// Fields of a relayed record that this build does not know, kept as
    /// they came.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ResultRecord {
    /// A record with every count zero.
    pub(crate) fn new(status: Status, exit_code: i32, dry_run: bool) -> Self {
        ResultRecord {
            status,
            exit_code,
            dry_run,
            files_transferred: 0,
            files_unchanged: 0,
            files_excluded: 0,
            directories_created: 0,
            symlinks_created: 0,
            specials_created: 0,
            errors: 0,
            bytes_transferred: 0,
            bytes_unchanged: 0,
            timings: Default::default(),
            bytes_total_known: None,
            deletions_planned: None,
            deletions_completed: None,
            deletions_blocked: None,
            replaced_not_in_place: None,
            extra: Default::default(),
        }
    }

    /// Read a terminal record as written, without its envelope.
    pub(crate) fn from_record(mut record: serde_json::Value) -> Result<Self> {
        let object = record
            .as_object_mut()
            .context("a final result is not an object")?;
        anyhow::ensure!(
            object
                .remove("type")
                .as_ref()
                .and_then(serde_json::Value::as_str)
                == Some("result"),
            "a final result has another type"
        );
        serde_json::from_value(record).context("read a final result")
    }
}

/// `replaced_not_in_place`: counts by reason key, each present only when
/// nonzero. A relayed record keeps keys this build does not know.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReplacedNotInPlace(serde_json::Map<String, serde_json::Value>);

impl ReplacedNotInPlace {
    pub(crate) fn from_counts(counts: &[(crate::proto::ReplaceReason, u64)]) -> Self {
        Self(
            counts
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(reason, count)| (reason.key().to_owned(), (*count).into()))
                .collect(),
        )
    }

    /// Every reason this build knows, with its count.
    pub(crate) fn counts(&self) -> Vec<(crate::proto::ReplaceReason, u64)> {
        crate::proto::ReplaceReason::ALL
            .iter()
            .map(|reason| {
                let count = self.0.get(reason.key()).and_then(serde_json::Value::as_u64);
                (*reason, count.unwrap_or(0))
            })
            .collect()
    }
}

#[derive(Serialize)]
pub struct RmResultRecord {
    pub status: Status,
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
    #[serde(rename = "timings", serialize_with = "total_ms")]
    pub elapsed_ms: u64,
}

fn total_ms<S: serde::Serializer>(elapsed_ms: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serde_json::json!({ "total_ms": elapsed_ms }).serialize(serializer)
}

/// A path as `tagged` writes it, serialized without building a value first.
struct Tagged<'a>(&'a [u8]);

impl Serialize for Tagged<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        use serde::ser::SerializeStruct as _;
        let mut tagged = serializer.serialize_struct("Tagged", 2)?;
        match std::str::from_utf8(self.0) {
            Ok(value) => {
                tagged.serialize_field("encoding", "utf-8")?;
                tagged.serialize_field("value", value)?;
            }
            Err(_) => {
                tagged.serialize_field("encoding", "base64")?;
                tagged.serialize_field(
                    "value",
                    &base64::engine::general_purpose::STANDARD.encode(self.0),
                )?;
            }
        }
        tagged.end()
    }
}

fn tagged_path<S: serde::Serializer>(path: &&[u8], serializer: S) -> Result<S::Ok, S::Error> {
    Tagged(path).serialize(serializer)
}

fn tagged_optional<S: serde::Serializer>(
    path: &Option<&[u8]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    path.map(Tagged).serialize(serializer)
}

/// A record of `kind` with `body`'s fields.
fn typed(kind: &str, body: &impl Serialize) -> serde_json::Value {
    let mut record = serde_json::to_value(body).expect("a results record serializes");
    record
        .as_object_mut()
        .expect("record is an object")
        .insert("type".into(), kind.into());
    record
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
    if let Some(writer) = &args.results_override {
        return Ok(Some(writer.clone()));
    }
    let requested =
        args.native_results.is_some() || args.native_results_fd.is_some() || args.relay_results;
    if !requested {
        return Ok(None);
    }
    let out: Box<dyn std::io::Write + Send> = if args.relay_results {
        Box::new(crate::destination_results::relay::CoordinatorLines::new(
            args.results_token
                .as_deref()
                .context("relayed results need their internal token")?,
        ))
    } else if let Some(fd) = args.native_results_fd {
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
    let mut writer = ResultsWriter::new(out);
    if args.stream_mapping_fd.is_some() {
        writer.schema_version = 5;
    }
    writer.destination_reports = args.relay_results && crate::destination::reports_results(args);
    let writer = Arc::new(writer);
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
        endpoints: run_endpoints(args, include_destination),
    });
    if writer.is_dead() {
        bail!("--results stream failed before the run record was written");
    }
    Ok(Some(writer))
}

fn run_endpoints(args: &Args, include_destination: bool) -> Vec<EndpointRecord> {
    if let Some(plan) = &args.descriptor_copy {
        let upload = plan.source.is_some();
        return ["source", "destination"]
            .into_iter()
            .map(|role| {
                let named = if upload {
                    role == "destination" && plan.as_fd.is_none()
                } else {
                    role == "source"
                };
                let host = named
                    .then(|| {
                        args.s3
                            .as_ref()
                            .map(|s3| format!("s3://{}", s3.bucket))
                            .or_else(|| {
                                plan.location
                                    .as_ref()
                                    .and_then(|location| location.host.clone())
                            })
                    })
                    .flatten();
                let user = named
                    .then(|| {
                        plan.location
                            .as_ref()
                            .and_then(|location| location.user.clone())
                    })
                    .flatten();
                EndpointRecord { role, host, user }
            })
            .collect();
    }
    let locations = &args.locations;
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
            schema_version: SCHEMA_VERSION,
            destination_reports: false,
            parent: None,
            phase_result: Mutex::new(None),
            mapping_metadata: Default::default(),
            out: Mutex::new(out),
            seq: AtomicU64::new(0),
            dead: AtomicBool::new(false),
            sealed: AtomicBool::new(false),
            relayed_errors: AtomicU64::new(0),
        }
    }

    pub(crate) fn phase(parent: Arc<Self>) -> Arc<Self> {
        let mut writer = Self::new(Box::new(std::io::sink()));
        writer.schema_version = parent.schema_version;
        writer.parent = Some(parent);
        Arc::new(writer)
    }
    /// The terminal record of the phase this writer collected.
    pub(crate) fn take_phase_result(&self) -> Option<ResultRecord> {
        let record = self.phase_result.lock().unwrap().take()?;
        Some(ResultRecord::from_record(record).expect("a phase settles with a copy's result"))
    }

    pub fn emit_run(&self, run: &RunRecord) {
        let mut record = typed("run", run);
        record["syq_version"] = crate::identity::version().into();
        self.write(record);
    }

    pub fn emit_progress(&self, progress: &ProgressRecord<'_>) {
        self.write(typed("progress", progress));
    }

    /// Dry run only: one intended mutation, sharing `operation_result`'s
    /// identity fields, with the reason the mutation is needed.
    pub fn emit_trace(&self, trace: &TraceRecord) {
        self.write(typed("trace", trace));
    }

    pub fn emit_selection_result(&self, selection: &SelectionResultRecord) {
        self.write(typed("selection_result", selection));
    }

    pub fn emit_removal_trace(&self, removal: &RemovalRecord) {
        self.emit_removal_trace_s3(removal, None);
    }

    pub(crate) fn emit_removal_trace_s3(
        &self,
        removal: &RemovalRecord,
        version: Option<(&str, bool)>,
    ) {
        let kind = removal
            .kind
            .expect("a planned removal always has a resolved object kind");
        let mut record = serde_json::json!({
            "type": "removal_trace",
            "selector": removal.selector,
            "path": tagged(removal.path),
            "kind": kind,
            "disposition": "would_remove",
        });
        if let Some((id, marker)) = version {
            record["s3_version_id"] = id.into();
            record["s3_delete_marker"] = marker.into();
        }
        self.write(record);
    }

    pub fn emit_removal_result(&self, removal: &RemovalRecord) {
        self.emit_removal_result_s3(removal, None);
    }

    pub(crate) fn emit_removal_result_s3(
        &self,
        removal: &RemovalRecord,
        version: Option<(&str, bool)>,
    ) {
        let mut record = typed("removal_result", removal);
        if let Some((id, marker)) = version {
            record["s3_version_id"] = id.into();
            record["s3_delete_marker"] = marker.into();
        }
        self.write(record);
    }

    pub fn emit_error_classified(
        &self,
        message: &str,
        class: Option<&'static str>,
        os_kind: Option<&'static str>,
    ) {
        self.emit_entry_error(message, class, os_kind, None);
    }

    pub(crate) fn destination_reports(&self) -> bool {
        self.destination_reports
    }

    /// As for a coordinator relaying results through a restricted receiver.
    #[cfg(test)]
    pub(crate) fn reporting_destination(mut self) -> Self {
        self.destination_reports = true;
        self
    }

    /// An error about one destination entry, `dst` relative to the
    /// destination as in `operation_result`, which a restricted receiver
    /// may list itself.
    pub(crate) fn emit_entry_error(
        &self,
        message: &str,
        class: Option<&'static str>,
        os_kind: Option<&'static str>,
        entry: Option<(&[u8], ReceiverListing)>,
    ) {
        let listing = entry.map_or(ReceiverListing::Unlisted, |(_, listing)| listing);
        #[cfg(debug_assertions)]
        if self.destination_reports && entry.is_some() && altered_failures().is_some() {
            return;
        }
        if self.destination_reports && listing == ReceiverListing::Listed {
            return;
        }
        let mut record = serde_json::json!({
            "type": "error",
            "message": message,
        });
        let object = record.as_object_mut().expect("record is an object");
        if let (Some((dst, ReceiverListing::Explained)), true) = (entry, self.destination_reports) {
            object.insert(DIAGNOSTIC_FOR.into(), tagged(dst));
        }
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

    pub(crate) fn mapping_metadata(
        &self,
        entries: impl IntoIterator<Item = (crate::proto::PathBytes, crate::mapping::Metadata)>,
    ) {
        // One mapping plan per invocation, installed before starting its jobs.
        let entries: std::collections::HashMap<_, _> = entries.into_iter().collect();
        if !entries.is_empty() {
            assert!(self.mapping_metadata.set(entries).is_ok());
        }
    }

    pub fn emit_operation(&self, op: &OperationRecord) {
        self.emit_operation_listed(op, None, ReceiverListing::Unlisted);
    }

    pub(crate) fn emit_operation_expected(
        &self,
        op: &OperationRecord,
        expected: Option<&crate::hashing::Digest>,
    ) {
        self.emit_operation_listed(op, expected, ReceiverListing::Unlisted);
    }

    /// An operation record; a restricted receiver lists the changes it made,
    /// and the failures `listing` says it lists, itself.
    pub(crate) fn emit_operation_listed(
        &self,
        op: &OperationRecord,
        expected: Option<&crate::hashing::Digest>,
        listing: ReceiverListing,
    ) {
        if self.destination_reports {
            if op.disposition == "succeeded" {
                return;
            }
            if op.disposition == "failed" {
                #[cfg(debug_assertions)]
                if let Some(mode) = altered_failures() {
                    if mode == "alter" {
                        self.write(serde_json::json!({
                            "type": "operation_result",
                            "action": op.action,
                            "dst": tagged(op.dst),
                            "kind": op.kind,
                            "disposition": "succeeded",
                        }));
                    }
                    return;
                }
                if listing != ReceiverListing::Unlisted {
                    return;
                }
            }
        }
        let mut record = typed("operation_result", op);
        let object = record.as_object_mut().expect("record is an object");
        if let Some(expected) = expected {
            object.insert("expected_hash".into(), serde_json::json!(expected));
        }
        if let Some(metadata) = self
            .mapping_metadata
            .get()
            .and_then(|entries| entries.get(op.dst))
        {
            object.insert("metadata".into(), serde_json::json!(metadata));
        }
        self.write(record);
    }

    /// The terminal record; flushes the stream. Nothing may be written after.
    pub fn emit_result(&self, result: &ResultRecord) {
        self.write_and_seal(typed("result", result), true);
    }

    pub fn emit_rm_result(&self, result: &RmResultRecord) {
        let mut record = typed("result", result);
        record["mode"] = "rm".into();
        self.write_and_seal(record, true);
    }

    pub(crate) fn schema_version(&self) -> u64 {
        self.schema_version
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Relaxed)
    }

    fn write(&self, record: serde_json::Value) {
        self.write_and_seal(record, false);
    }

    /// Emit a caller-built record (relayed from a remote coordinator or a
    /// restricted destination); the envelope and sequencing are applied like
    /// any other record.
    pub(crate) fn emit_value(&self, record: serde_json::Value) {
        self.count_relayed(std::slice::from_ref(&record));
        self.write_and_seal(record, false);
    }

    fn count_relayed(&self, records: &[serde_json::Value]) {
        let counted = records
            .iter()
            .filter(|record| counted_error(record))
            .count();
        self.relayed_errors.fetch_add(counted as u64, Relaxed);
    }

    /// The counted error records written for callers, which a final record
    /// built from this machine's own counts adds.
    pub(crate) fn relayed_errors(&self) -> u64 {
        self.relayed_errors.load(Relaxed)
    }

    /// Emit caller-built records in order with one write, as `emit_value`
    /// would one by one.
    pub(crate) fn emit_values(&self, records: Vec<serde_json::Value>) {
        self.count_relayed(&records);
        if records.is_empty() || self.dead.load(Relaxed) {
            return;
        }
        if self.parent.is_some() {
            for record in records {
                self.write(record);
            }
            return;
        }
        let mut out = self.out.lock().unwrap();
        if self.sealed.load(Relaxed) {
            return;
        }
        let mut lines = Vec::new();
        let mut encoded = Ok(());
        for mut record in records {
            let seq = self.seq.fetch_add(1, Relaxed);
            let object = record.as_object_mut().expect("record is an object");
            object.insert("schema".into(), SCHEMA.into());
            object.insert("schema_version".into(), self.schema_version.into());
            object.insert("seq".into(), seq.into());
            encoded = serde_json::to_writer(&mut lines, &record);
            if encoded.is_err() {
                break;
            }
            lines.push(b'\n');
        }
        let written = encoded
            .map_err(std::io::Error::from)
            .and_then(|()| out.write_all(&lines));
        if let Err(error) = written {
            drop(out);
            self.mark_dead(&error);
        }
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
        if let Some(parent) = &self.parent {
            if seal {
                *self.phase_result.lock().unwrap() = Some(record);
            } else if record["type"] != "run" {
                parent.write(record);
            }
            return;
        }
        let seq = self.seq.fetch_add(1, Relaxed);
        let object = record.as_object_mut().expect("record is an object");
        object.insert("schema".into(), SCHEMA.into());
        object.insert("schema_version".into(), self.schema_version.into());
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
            crate::output::diagnostic!(
                "syq: warning: --results stream failed ({error}); further records are lost"
            );
        }
    }
}

/// Test hook: a coordinator that leaves out (`omit`) or misreports as
/// succeeded (`alter`) its own records of the failures a restricted
/// receiver lists.
#[cfg(debug_assertions)]
pub(crate) const ALTER_FAILURES_ENV: &str = "SYQ_TEST_ALTER_RELAYED_FAILURES";

#[cfg(debug_assertions)]
fn altered_failures() -> Option<String> {
    std::env::var(ALTER_FAILURES_ENV).ok()
}

/// An error record a final result counts: not one that only explains a
/// failure another record counts.
pub(crate) fn counted_error(record: &serde_json::Value) -> bool {
    record.get("type").and_then(serde_json::Value::as_str) == Some("error")
        && record.get(DIAGNOSTIC_FOR).is_none()
}

pub(crate) fn tagged(path: &[u8]) -> serde_json::Value {
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

    #[test]
    fn failed_results_and_stderr_do_not_panic() {
        if !crate::test_support::with_broken_stderr(
            "results::tests::failed_results_and_stderr_do_not_panic",
        ) {
            return;
        }
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(reader);
        let writer = ResultsWriter::new(Box::new(writer));
        writer.emit_error_classified("first failure", None, None);
        assert!(writer.is_dead());
        writer.emit_error_classified("later failure", None, None);
        assert!(!writer.out.is_poisoned());
    }

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
            errors: 1,
            ..ResultRecord::new(Status::Failed, 1, false)
        });
        let after = sink.0.lock().unwrap().len();
        // A straggling ticker render (or a second terminal) must be inert.
        writer.emit_progress(&ProgressRecord {
            activity: None,
            bytes_done: 1,
            bytes_total: 1,
            bytes_unchanged: 0,
            files_done: 1,
            files_total: 1,
            files_unchanged: 0,
            files_excluded: 0,
            scanned: 1,
            scan_done: true,
            timings: Default::default(),
            rate_bytes_per_second: 0,
            eta_ms: None,
        });
        writer.emit_result(&ResultRecord::new(Status::Success, 0, false));
        assert_eq!(sink.0.lock().unwrap().len(), after);
    }
}
