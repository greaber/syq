//! Exercise recovery with the real SDK response decoder and download/publication
//! code, but scripted bodies and a virtual clock instead of slow TCP fixtures.
use super::*;
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

const SIZE: usize = 65536;
fn data() -> Vec<u8> {
    (0..SIZE).map(|n| (n % 251) as u8).collect()
}

struct Body {
    chunks: VecDeque<bytes::Bytes>,
    delay: Duration,
    ready: Pin<Box<Sleep>>,
    dropped: Option<Arc<Mutex<Option<Instant>>>>,
}
impl Body {
    fn slow(bytes: &[u8], idle: bool) -> Self {
        Self {
            dropped: None,
            chunks: bytes
                .chunks(1024)
                .map(bytes::Bytes::copy_from_slice)
                .collect(),
            delay: Duration::from_millis(40),
            ready: Box::pin(tokio::time::sleep(if idle {
                Duration::from_secs(3)
            } else {
                Duration::from_millis(40)
            })),
        }
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        if let Some(dropped) = &self.dropped {
            *dropped.lock().unwrap() = Some(Instant::now());
        }
    }
}
impl http_body::Body for Body {
    type Data = bytes::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        use std::future::Future;
        if self.chunks.is_empty() {
            return Poll::Ready(None);
        }
        std::task::ready!(self.ready.as_mut().poll(cx));
        let next = Instant::now() + self.delay;
        self.ready.as_mut().reset(next);
        Poll::Ready(
            self.chunks
                .pop_front()
                .map(|b| Ok(http_body::Frame::data(b))),
        )
    }
}

#[derive(Debug, Clone)]
struct Responses {
    fault: &'static str,
    requests: Arc<Mutex<Vec<(usize, Instant)>>>,
}
impl HttpConnector for Responses {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let start = request
            .headers()
            .get("range")
            .unwrap()
            .strip_prefix("bytes=")
            .unwrap()
            .strip_suffix("-65535")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(request.headers().get("if-match"), Some("\"fixture-v1\""));
        let mut requests = self.requests.lock().unwrap();
        requests.push((start, Instant::now()));
        let number = requests.len();
        drop(requests);
        let fault = self.fault;
        HttpConnectorFuture::new(async move {
            let mut response = HttpResponse::new(206.try_into().unwrap(), SdkBody::empty());
            if fault == "changed" {
                *response.status_mut() = 412.try_into().unwrap();
                return Ok(response);
            }
            response.headers_mut().insert("etag", "\"fixture-v1\"");
            response
                .headers_mut()
                .insert("content-length", (SIZE - start).to_string());
            response.headers_mut().insert(
                "content-range",
                format!(
                    "bytes {}-65535/65536",
                    if fault == "range" { 0 } else { start }
                ),
            );
            let bytes = data();
            *response.body_mut() = match fault {
                "retry-slow" => SdkBody::from_body_1_x(Body::slow(&bytes[start..], false)),
                "truncated" if number == 1 => {
                    SdkBody::from(bytes[start..start + (SIZE - start) / 2].to_vec())
                }
                "corrupt" => SdkBody::from(vec![b'y'; SIZE - start]),
                _ => SdkBody::from(bytes[start..].to_vec()),
            };
            Ok(response)
        })
    }
}

async fn copy(fault: &'static str, retries: u32, peers: bool, paced: bool) {
    let dir = crate::test_support::tempdir().unwrap();
    let mut extra = vec!["--integrity-checking=transfer=blake3"];
    if paced {
        extra.extend(["--resource-limits", "bandwidth=16KiB"]);
    }
    let mut engine = super::buffer_tests::planning_engine(&extra);
    engine.options.retries = retries;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connector = Responses {
        fault,
        requests: requests.clone(),
    };
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "test", "test", None, None, "fixture",
        ))
        .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
        .http_client(http_client_fn(move |_, _| {
            SharedHttpConnector::new(connector.clone())
        }))
        .build();
    engine.client = Client::from_conf(config);
    let engine = Arc::new(engine);
    let observe = engine.clone();
    let seed = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if peers {
            for _ in 0..32 {
                observe.tuning.reads.completed(
                    SIZE as u64,
                    if fault == "uniform" {
                        Duration::from_secs(3)
                    } else {
                        Duration::from_millis(100)
                    },
                    Instant::now(),
                );
            }
        }
    });
    let bytes = data();
    let metadata = Metadata {
        kind: crate::s3::client::ObjectKind::File,
        mode: 0o644,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        mtime: 1700000000,
        nsec: 0,
        hash: Some(Digest::hash_bytes(HashAlgorithm::Blake3, &bytes).value),
        hash_algorithm: HashAlgorithm::Blake3,
    };
    let object = Object {
        key: "object".into(),
        size: SIZE as u64,
        etag: "\"fixture-v1\"".into(),
        version: None,
        metadata: None,
        mtime: metadata.mtime,
    };
    let root = Root::open(dir.path()).unwrap();
    let path = RelativePath::new(b"destination").unwrap();
    let dropped = Arc::new(Mutex::new(None));
    let initial = if paced {
        ByteStream::from(bytes.clone())
    } else {
        let mut body = Body::slow(&bytes, fault == "idle");
        if fault == "long-pause" {
            body.delay = Duration::from_secs(120);
            body.ready = Box::pin(tokio::time::sleep(Duration::from_secs(3600)));
        }
        body.dropped = Some(dropped.clone());
        ByteStream::new(SdkBody::from_body_1_x(body))
    };
    let result = engine
        .download_single(
            &object,
            &root,
            &path,
            (&metadata, None),
            None,
            Some(initial),
            None,
        )
        .await;
    seed.await.unwrap();
    let failed = matches!(fault, "changed" | "corrupt" | "range");
    assert_eq!(result.is_err(), failed, "{fault}: {result:?}");
    let expected_requests = if retries == 0 || !peers || paced || fault == "uniform" {
        0
    } else if fault == "truncated" {
        2
    } else {
        1
    };
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), expected_requests, "{fault}: {requests:?}");
    if let Some((offset, sent)) = requests.first() {
        if fault == "idle" {
            assert_eq!(*offset, 0);
        } else {
            assert!(*offset >= 16384, "{fault}: processed prefix fetched again");
        }
        // The first body is dropped by the recovery decision. The replacement
        // must not wait for the ordinary 100 ms transport-error backoff.
        assert!(
            *sent - dropped.lock().unwrap().unwrap() < Duration::from_millis(100),
            "{fault}: delayed speculative restart"
        );
    }
    if requests.len() == 2 {
        assert_eq!(
            requests[1].0, 0,
            "transport error must restart the whole range"
        );
        assert!(
            requests[1].1 - requests[0].1 >= Duration::from_millis(200),
            "transport retry lost its backoff"
        );
    }
    if failed {
        assert!(!dir.path().join("destination").exists());
    } else {
        assert_eq!(
            std::fs::read(dir.path().join("destination")).unwrap(),
            bytes
        );
    }
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        usize::from(!failed),
        "partial file leaked"
    );
}

#[tokio::test(start_paused = true)]
async fn slow_read_recovery_preserves_contents_and_identity() {
    for fault in [
        "ok",
        "changed",
        "retry-slow",
        "idle",
        "corrupt",
        "range",
        "truncated",
    ] {
        copy(fault, if fault == "truncated" { 2 } else { 1 }, true, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn uniformly_slow_or_retry_disabled_reads_are_not_restarted() {
    copy("uniform", 1, true, false).await;
    copy("ok", 0, true, false).await;
    copy("ok", 1, false, false).await;
    copy("ok", 1, true, true).await;
}

#[tokio::test(start_paused = true)]
async fn downloads_without_peers_can_wait_through_long_pauses() {
    copy("long-pause", 1, false, false).await;
    copy("long-pause", 0, false, false).await;
}

#[tokio::test(start_paused = true)]
async fn direct_download_can_resume_after_a_long_pause_within_one_read() {
    use std::os::unix::fs::FileExt;
    let dir = crate::test_support::tempdir().unwrap();
    let path = dir.path().join("large");
    let size = 256 * 1024 * 1024;
    let file = Arc::new(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap(),
    );
    file.set_len(size).unwrap();
    let output = writer::Writer::with_readback(file.clone(), size, false).unwrap();
    // macOS uses the buffered path. Linux exercises the production direct-I/O
    // path when the temporary filesystem supports it.
    let bytes = data();
    let offset = size - bytes.len() as u64;
    let object = Object {
        key: "object".into(),
        size,
        etag: "fixture".into(),
        version: None,
        metadata: None,
        mtime: 0,
    };
    let engine = super::buffer_tests::planning_engine(&["--performance-tuning", "s3-retries=0"]);
    let mut delayed = Body::slow(&bytes, true);
    delayed.delay = Duration::from_secs(120);
    delayed.ready = Box::pin(tokio::time::sleep(Duration::from_secs(3600)));
    let body = ByteStream::new(SdkBody::from_body_1_x(delayed));
    let started = Instant::now();
    let hash = engine
        .download_fast_range(
            &object,
            &output,
            offset,
            bytes.len() as u64,
            Some(body),
            None,
            Some(HashAlgorithm::Blake3),
        )
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(3600));
    output.finish().await.unwrap();
    let mut actual = vec![0; bytes.len()];
    file.read_exact_at(&mut actual, offset).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(
        hash,
        Digest::hash_bytes(HashAlgorithm::Blake3, &bytes).value
    );
}
