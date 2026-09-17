//! Optional bounded request timings for performance investigations. No paths,
//! header values, endpoints or credentials are recorded.
use aws_smithy_types::config_bag::{Storable, StoreReplace};
use serde_json::{json, Value};
use std::{
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
struct Trace {
    start: Instant,
    events: Mutex<Vec<Value>>,
}
fn trace() -> Option<&'static Trace> {
    static TRACE: OnceLock<Option<Trace>> = OnceLock::new();
    TRACE
        .get_or_init(|| {
            (std::env::var("SYQ_S3_DIAGNOSTICS").as_deref() == Ok("1")).then(|| Trace {
                start: Instant::now(),
                events: Mutex::new(Vec::new()),
            })
        })
        .as_ref()
}
#[derive(Debug)]
pub(super) struct Attempt {
    start: Instant,
    at: f64,
    operation: &'static str,
    length: Option<u64>,
}
impl Storable for Attempt {
    type Storer = StoreReplace<Self>;
}
pub(super) fn request(
    request: &aws_smithy_runtime_api::client::orchestrator::HttpRequest,
) -> Option<Attempt> {
    let trace = trace()?;
    let query = request.uri().split_once('?').map_or("", |(_, q)| q);
    let operation = match (
        request.method(),
        query.contains("uploadId="),
        query.contains("uploads"),
        query.contains("list-type="),
    ) {
        ("PUT", true, _, _) => "UploadPart",
        ("POST", true, _, _) => "CompleteMultipartUpload",
        ("POST", _, true, _) => "CreateMultipartUpload",
        ("GET", _, _, true) => "ListObjects",
        ("HEAD", _, _, _) => "HeadObject",
        ("GET", _, _, _) => "GetObject",
        ("PUT", _, _, _) => "PutObject",
        _ => "other",
    };
    Some(Attempt {
        start: Instant::now(),
        at: trace.start.elapsed().as_secs_f64(),
        operation,
        length: request
            .headers()
            .get("content-length")
            .and_then(|s| s.parse().ok()),
    })
}
pub(super) fn response(attempt: &Attempt, status: u16) {
    record(
        json!({"operation":attempt.operation,"start_s":attempt.at,"headers_s":attempt.start.elapsed().as_secs_f64(),"request_bytes":attempt.length,"status":status}),
    );
}
pub(super) fn record(value: Value) {
    if let Some(trace) = trace() {
        let mut events = trace.events.lock().unwrap();
        if events.len() < 16384 {
            events.push(value);
        }
    }
}
pub(super) fn start() -> Option<Instant> {
    trace().map(|_| Instant::now())
}
pub(super) fn elapsed(start: Option<Instant>, phase: &str, bytes: u64) {
    if let Some(start) = start {
        record(json!({"phase":phase,"elapsed_s":start.elapsed().as_secs_f64(),"bytes":bytes}));
    }
}
pub(super) fn planning(control: Option<Duration>, workers: usize, request_limit: usize) {
    if trace().is_some() {
        record(
            json!({"phase":"plan","control_s":control.map(|d| d.as_secs_f64()),"object_workers":workers,"request_limit":request_limit}),
        );
    }
}
pub(super) fn finish() {
    if let Some(trace) = trace() {
        eprintln!(
            "S3_DIAGNOSTICS {}",
            json!({"events":*trace.events.lock().unwrap(),"elapsed_s":trace.start.elapsed().as_secs_f64()})
        );
    }
}

pub(super) fn object_concurrency(before: usize, after: usize, activity_per_second: f64) {
    if let Some(trace) = trace() {
        record(
            json!({"phase":"object_concurrency","at_s":trace.start.elapsed().as_secs_f64(),"before":before,"after":after,"activity_per_second":activity_per_second}),
        );
    }
}

/// Rates actually used by the request ramp, before counters are reset.
pub(super) fn request_window(
    before: usize,
    after: usize,
    bytes_per_second: f64,
    elapsed: Duration,
    completed: usize,
    saturated: bool,
    settled: bool,
) {
    if let Some(trace) = trace() {
        record(json!({
            "phase": "request_window",
            "at_s": trace.start.elapsed().as_secs_f64(),
            "before": before,
            "after": after,
            "bytes_per_second": bytes_per_second,
            "elapsed_s": elapsed.as_secs_f64(),
            "completed": completed,
            "saturated": saturated,
            "settled": settled,
        }));
    }
}

// Track preparation generations only while diagnostics are enabled. This is
// attribution evidence, not an assertion about the concurrency at socket admission.
#[derive(Default)]
pub(super) struct ObjectWindows {
    jobs: std::collections::HashMap<tokio::task::Id, u64>,
    generation: u64,
    fresh_completed: usize,
    fresh_activity: u64,
}

pub(super) struct ObjectWindow {
    pub limit: usize,
    pub active: usize,
    pub queued: usize,
    pub completed: usize,
    pub activity: u64,
    pub elapsed: Duration,
    pub warmup: bool,
    pub previous_rate: Option<f64>,
    pub probe_from: Option<usize>,
    pub probe_baseline: Option<f64>,
}

impl ObjectWindows {
    pub fn new() -> Option<Self> {
        trace()?;
        Some(Self::default())
    }
    pub fn spawned(&mut self, id: tokio::task::Id) {
        self.jobs.insert(id, self.generation);
    }
    pub fn completed(&mut self, id: tokio::task::Id, activity: Option<u64>) {
        let generation = self.jobs.remove(&id);
        if generation == Some(self.generation) {
            if let Some(activity) = activity {
                self.fresh_completed += 1;
                self.fresh_activity = self.fresh_activity.saturating_add(activity);
            }
        }
    }
    pub fn changed(&mut self) {
        self.generation += 1;
        self.reset();
    }
    pub fn reset(&mut self) {
        self.fresh_completed = 0;
        self.fresh_activity = 0;
    }
    pub fn sample(&mut self, window: ObjectWindow) {
        if let Some(trace) = trace() {
            record(json!({
                "phase": "object_window",
                "at_s": trace.start.elapsed().as_secs_f64(),
                "generation": self.generation,
                "limit": window.limit,
                "active": window.active,
                "queued": window.queued,
                "elapsed_s": window.elapsed.as_secs_f64(),
                "completed": window.completed,
                "activity": window.activity,
                "fresh_completed": self.fresh_completed,
                "fresh_activity": self.fresh_activity,
                "warmup": window.warmup,
                "previous_rate": window.previous_rate,
                "probe_from": window.probe_from,
                "probe_baseline": window.probe_baseline,
            }));
        }
        self.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn object_windows_distinguish_old_work_without_retaining_finished_tasks() {
        let mut windows = ObjectWindows::default();
        let old = tokio::spawn(async {});
        let old_id = old.id();
        windows.spawned(old_id);
        windows.changed();
        let current = tokio::spawn(async {});
        let current_id = current.id();
        windows.spawned(current_id);
        old.await.unwrap();
        windows.completed(old_id, Some(100));
        current.await.unwrap();
        windows.completed(current_id, Some(200));
        assert_eq!((windows.fresh_completed, windows.fresh_activity), (1, 200));
        assert!(windows.jobs.is_empty());

        let spanning = tokio::spawn(async {});
        let spanning_id = spanning.id();
        windows.spawned(spanning_id);
        windows.reset(); // A new measurement window, but the same setting.
        spanning.await.unwrap();
        windows.completed(spanning_id, Some(300));
        assert_eq!((windows.fresh_completed, windows.fresh_activity), (1, 300));

        let skipped = tokio::spawn(async {});
        let skipped_id = skipped.id();
        windows.spawned(skipped_id);
        skipped.await.unwrap();
        windows.completed(skipped_id, None);
        assert_eq!((windows.fresh_completed, windows.fresh_activity), (1, 300));
        assert!(windows.jobs.is_empty());
    }
}
