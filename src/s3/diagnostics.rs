//! Optional bounded request timings for performance investigations. No paths,
//! header values, endpoints or credentials are recorded.
use aws_smithy_types::config_bag::{Storable, StoreReplace};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
struct Trace {
    start: Instant,
    events: Mutex<Vec<Value>>,
    upload_bytes: AtomicU64,
}
fn trace() -> Option<&'static Trace> {
    static TRACE: OnceLock<Option<Trace>> = OnceLock::new();
    TRACE
        .get_or_init(|| {
            (std::env::var("SYQ_S3_DIAGNOSTICS").as_deref() == Ok("1")).then(|| Trace {
                start: Instant::now(),
                events: Mutex::new(Vec::new()),
                upload_bytes: AtomicU64::new(0),
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
    upload: Option<UploadProgress>,
}
impl Storable for Attempt {
    type Storer = StoreReplace<Self>;
}
pub(super) fn request(
    request: &mut aws_smithy_runtime_api::client::orchestrator::HttpRequest,
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
    let start = Instant::now();
    let length = request
        .headers()
        .get("content-length")
        .and_then(|s| s.parse().ok());
    let upload = if matches!(operation, "PutObject" | "UploadPart") {
        length.map(|length| {
            let progress = UploadProgress::new(length, start);
            let body =
                std::mem::replace(request.body_mut(), aws_smithy_types::body::SdkBody::empty());
            let observed = progress.clone();
            *request.body_mut() = body.map_preserve_contents(move |body| {
                aws_smithy_types::body::SdkBody::from_body_1_x(ObservedBody {
                    body,
                    progress: observed.clone(),
                })
            });
            // The synchronous connector reads its file itself, bypassing SdkBody.
            request.add_extension(progress.clone());
            progress
        })
    } else {
        None
    };
    Some(Attempt {
        start,
        at: trace.start.elapsed().as_secs_f64(),
        operation,
        length,
        upload,
    })
}
pub(super) fn response(attempt: &Attempt, status: u16) {
    let mut event = json!({"operation":attempt.operation,"start_s":attempt.at,"headers_s":attempt.start.elapsed().as_secs_f64(),"request_bytes":attempt.length,"status":status});
    if let Some(progress) = &attempt.upload {
        let body = progress.state.lock().unwrap();
        event["body_handoff_bytes"] = json!(body.bytes);
        event["body_handoff_s"] = json!(body.finished.map(|d| d.as_secs_f64()));
        event["after_body_handoff_s"] =
            json!(body
                .finished
                .map(|d| attempt.start.elapsed().saturating_sub(d).as_secs_f64()));
    }
    record(event);
}

// "Handoff" means the body was read by the HTTP transport, not TCP delivery or
// a provider acknowledgment. Transport/TLS/kernel buffers can still hold bytes.
#[derive(Clone, Debug)]
pub(super) struct UploadProgress {
    length: u64,
    start: Instant,
    state: Arc<Mutex<UploadState>>,
}
#[derive(Debug, Default)]
struct UploadState {
    bytes: u64,
    finished: Option<Duration>,
}
impl UploadProgress {
    fn new(length: u64, start: Instant) -> Self {
        Self {
            length,
            start,
            state: Arc::new(Mutex::new(UploadState::default())),
        }
    }
    pub fn handed(&self, bytes: usize) {
        let mut state = self.state.lock().unwrap();
        state.bytes += bytes as u64;
        if state.bytes == self.length && state.finished.is_none() {
            state.finished = Some(self.start.elapsed());
        }
    }
}
struct ObservedBody {
    body: aws_smithy_types::body::SdkBody,
    progress: UploadProgress,
}
impl http_body::Body for ObservedBody {
    type Data = bytes::Bytes;
    type Error = aws_smithy_runtime_api::box_error::BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let result = std::task::ready!(std::pin::Pin::new(&mut self.body).poll_frame(cx));
        if let Some(Ok(frame)) = &result {
            if let Some(data) = frame.data_ref() {
                self.progress.handed(data.len());
            }
        } else if result.is_none() {
            self.progress.handed(0);
        }
        std::task::Poll::Ready(result)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        http_body::Body::size_hint(&self.body)
    }
}

pub(super) struct UploadBufferTrace(u64);
pub(super) fn upload_buffer(bytes: u64) -> Option<UploadBufferTrace> {
    let trace = trace()?;
    let live = trace.upload_bytes.fetch_add(bytes, Relaxed) + bytes;
    record(
        json!({"phase":"upload_buffers","at_s":trace.start.elapsed().as_secs_f64(),"live_bytes":live}),
    );
    Some(UploadBufferTrace(bytes))
}
impl Drop for UploadBufferTrace {
    fn drop(&mut self) {
        if let Some(trace) = trace() {
            let live = trace.upload_bytes.fetch_sub(self.0, Relaxed) - self.0;
            record(
                json!({"phase":"upload_buffers","at_s":trace.start.elapsed().as_secs_f64(),"live_bytes":live}),
            );
        }
    }
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

// Reuse the scheduler's preparation generations while diagnostics are enabled.
// These do not assert the concurrency at socket admission.
#[derive(Default)]
pub(super) struct ObjectWindows {
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
    pub fn completed(&mut self, prepared: u64, activity: Option<u64>) {
        if prepared == self.generation {
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

    #[test]
    fn object_windows_distinguish_old_and_current_work() {
        let mut windows = ObjectWindows::default();
        windows.changed();
        windows.completed(0, Some(100));
        windows.completed(1, Some(200));
        assert_eq!((windows.fresh_completed, windows.fresh_activity), (1, 200));

        windows.reset(); // A new measurement window, but the same setting.
        windows.completed(1, Some(300));
        assert_eq!((windows.fresh_completed, windows.fresh_activity), (1, 300));

        windows.completed(1, None); // Skipped and failed copies add no activity.
        assert_eq!((windows.fresh_completed, windows.fresh_activity), (1, 300));
        windows.changed();
        windows.completed(1, Some(400));
        assert_eq!((windows.fresh_completed, windows.fresh_activity), (0, 0));
    }
}

#[cfg(test)]
mod upload_tests {
    use super::*;
    use aws_smithy_types::body::SdkBody;
    use http_body::Body;
    use std::pin::Pin;

    #[tokio::test]
    async fn upload_observation_preserves_body_and_marks_only_complete_handoff() {
        let progress = UploadProgress::new(4, Instant::now());
        let mut body = ObservedBody {
            body: SdkBody::from("data"),
            progress: progress.clone(),
        };
        assert_eq!(body.size_hint().exact(), Some(4));
        assert!(progress.state.lock().unwrap().finished.is_none());
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.data_ref().unwrap().as_ref(), b"data");
        assert_eq!(progress.state.lock().unwrap().bytes, 4);
        assert!(progress.state.lock().unwrap().finished.is_some());

        // A truncated source must not be reported as fully handed off.
        let short = UploadProgress::new(5, Instant::now());
        let body = SdkBody::from_body_1_x(ObservedBody {
            body: SdkBody::from("data"),
            progress: short.clone(),
        });
        assert_eq!(
            aws_sdk_s3::primitives::ByteStream::new(body)
                .collect()
                .await
                .unwrap()
                .into_bytes()
                .as_ref(),
            b"data"
        );
        assert_eq!(short.state.lock().unwrap().bytes, 4);
        assert!(short.state.lock().unwrap().finished.is_none());
    }
}
