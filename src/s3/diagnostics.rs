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
