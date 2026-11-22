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
fn data_sized(size: usize) -> Vec<u8> {
    (0..size).map(|n| (n % 251) as u8).collect()
}
fn data() -> Vec<u8> {
    data_sized(SIZE)
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
    size: usize,
    fault: &'static str,
    requests: Arc<Mutex<Vec<(usize, Instant)>>>,
}
impl HttpConnector for Responses {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let size = self.size;
        let last = size - 1;
        let suffix = format!("-{last}");
        let start = request
            .headers()
            .get("range")
            .unwrap()
            .strip_prefix("bytes=")
            .unwrap()
            .strip_suffix(&suffix)
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
            if fault == "unreadable-metadata" {
                let mut raw = response.try_into_http1x().unwrap();
                raw.headers_mut().insert(
                    "x-amz-meta-label",
                    http::HeaderValue::from_bytes(b"caf\xe9").unwrap(),
                );
                response = HttpResponse::try_from(raw).unwrap();
            }
            if fault == "changed" {
                *response.status_mut() = 412.try_into().unwrap();
                return Ok(response);
            }
            if fault == "throttled" && number == 1 {
                *response.status_mut() = 503.try_into().unwrap();
                *response.body_mut() = SdkBody::from("<Error><Code>SlowDown</Code></Error>");
                response.headers_mut().insert("x-amz-retry-after", "5000");
                return Ok(response);
            }
            response.headers_mut().insert("etag", "\"fixture-v1\"");
            response
                .headers_mut()
                .insert("content-length", (size - start).to_string());
            response.headers_mut().insert(
                "content-range",
                format!(
                    "bytes {}-{last}/{size}",
                    if fault == "range" { 0 } else { start }
                ),
            );
            let bytes = data_sized(size);
            *response.body_mut() = match fault {
                "retry-slow" => SdkBody::from_body_1_x(Body::slow(&bytes[start..], false)),
                "truncated" if number == 1 => {
                    SdkBody::from(bytes[start..start + (size - start) / 2].to_vec())
                }
                "corrupt" => SdkBody::from(vec![b'y'; size - start]),
                _ => SdkBody::from(bytes[start..].to_vec()),
            };
            Ok(response)
        })
    }
}

async fn copy(fault: &'static str, retries: u32, peers: bool, paced: bool) {
    copy_sized(SIZE, fault, retries, peers, paced).await;
}

async fn copy_sized(size: usize, fault: &'static str, retries: u32, peers: bool, paced: bool) {
    let dir = crate::test_support::tempdir().unwrap();
    let mut extra = vec!["--integrity-checking=transfer=blake3"];
    if paced {
        extra.extend(["--resource-limits", "bandwidth=16KiB"]);
    }
    let mut engine = super::buffer_tests::planning_engine(&extra);
    engine.options.retries = retries;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connector = Responses {
        size,
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
                    size as u64,
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
    let bytes = data_sized(size);
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
        size: size as u64,
        etag: "\"fixture-v1\"".into(),
        version: None,
        metadata: None,
        mtime: metadata.mtime,
    };
    let root = Arc::new(Root::open(dir.path()).unwrap());
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
            (&metadata, None, Default::default()),
            (None, None),
            Some(initial),
            None,
        )
        .await;
    seed.await.unwrap();
    let failed = matches!(
        fault,
        "changed" | "corrupt" | "range" | "unreadable-metadata"
    );
    assert_eq!(result.is_err(), failed, "{fault}: {result:?}");
    if fault == "unreadable-metadata" {
        let message = format!("{:#}", result.as_ref().unwrap_err());
        assert!(message.contains("S3 GET failed"), "{message}");
        assert!(message.contains("Metadata"), "{message}");
    }
    let expected_requests = if retries == 0 || !peers || paced || fault == "uniform" {
        0
    } else if matches!(fault, "truncated" | "throttled") {
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
        if fault == "throttled" {
            assert!(requests[1].1 - requests[0].1 >= Duration::from_secs(5));
        }
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
    for size in [SIZE, 256 * 1024] {
        for fault in [
            "ok",
            "changed",
            "retry-slow",
            "idle",
            "corrupt",
            "range",
            "truncated",
        ] {
            copy_sized(
                size,
                fault,
                if fault == "truncated" { 2 } else { 1 },
                true,
                false,
            )
            .await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn memory_sink_transport_retry_clears_flushed_batches() {
    // 20 fragments of 4 KiB (80 KiB <= 128 KiB inline limit) flush at least one
    // 16-slice batch into DownloadSink::Memory before the transport error hits.
    struct FailingAfterBatch {
        chunks: VecDeque<bytes::Bytes>,
    }
    impl http_body::Body for FailingAfterBatch {
        type Data = bytes::Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            if let Some(chunk) = self.chunks.pop_front() {
                Poll::Ready(Some(Ok(http_body::Frame::data(chunk))))
            } else {
                Poll::Ready(Some(Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "simulated mid-body reset",
                ))))
            }
        }
    }
    let size = 80 * 1024;
    let bytes = data_sized(size);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connector = Responses {
        size,
        fault: "ok",
        requests: requests.clone(),
    };
    let mut engine = super::buffer_tests::planning_engine(&[
        "--s3-retries",
        "2",
        "--integrity-checking=transfer=blake3",
    ]);
    engine.client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(connector.clone())
            }))
            .build(),
    );
    let engine = Arc::new(engine);
    let dir = crate::test_support::tempdir().unwrap();
    let root = Arc::new(Root::open(dir.path()).unwrap());
    let path = RelativePath::new(b"destination").unwrap();
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
        size: size as u64,
        etag: "\"fixture-v1\"".into(),
        version: None,
        metadata: None,
        mtime: metadata.mtime,
    };
    let initial = ByteStream::new(SdkBody::from_body_1_x(FailingAfterBatch {
        chunks: bytes[..72 * 1024]
            .chunks(4096)
            .map(bytes::Bytes::copy_from_slice)
            .collect(),
    }));
    engine
        .download_single(
            &object,
            &root,
            &path,
            (&metadata, None, Default::default()),
            (None, None),
            Some(initial),
            None,
        )
        .await
        .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(
        std::fs::read(dir.path().join("destination")).unwrap(),
        bytes
    );
}

#[test]
fn inline_download_cancelled_while_placement_queued_does_not_publish() {
    // One blocking thread lets us hold the blocking pool while the inline
    // download queues its placement closure, then cancel before it runs.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let dir = crate::test_support::tempdir().unwrap();
        let destination = dir.path().join("destination");
        std::fs::write(&destination, b"keep-original").unwrap();
        let root = Arc::new(Root::open(dir.path()).unwrap());
        let path = RelativePath::new(b"destination").unwrap();
        let engine = Arc::new(super::buffer_tests::planning_engine(&[]));
        let bytes = b"replacement payload".to_vec();
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
            size: bytes.len() as u64,
            etag: "\"fixture-v1\"".into(),
            version: None,
            metadata: None,
            mtime: metadata.mtime,
        };
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        entered_rx.recv().unwrap();
        let download_engine = engine.clone();
        let download = tokio::spawn(async move {
            download_engine
                .download_single(
                    &object,
                    &root,
                    &path,
                    (&metadata, None, Default::default()),
                    (None, None),
                    Some(ByteStream::from(bytes)),
                    None,
                )
                .await
        });
        // Yield until download_single has verified the body and queued its
        // placement closure behind `blocker`.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        engine
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        assert!(download.await.unwrap().is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"keep-original");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    });
}

#[tokio::test(start_paused = true)]
async fn unreadable_metadata_in_replacement_get_reports_header() {
    copy("unreadable-metadata", 3, true, false).await;
}

#[tokio::test(start_paused = true)]
async fn download_throttling_honors_server_delay_before_restarting() {
    copy("throttled", 2, true, false).await;
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
    let engine = super::buffer_tests::planning_engine(&["--s3-retries", "0"]);
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
            None,
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

/// A GET that fails in a way no resend can fix, such as an expired storage
/// authorization, ends at once; a reset connection is still retried.
#[tokio::test(start_paused = true)]
async fn permanent_get_failures_are_not_retried() {
    use aws_smithy_runtime_api::client::result::ConnectorError;
    #[derive(Debug, Clone)]
    struct Failing {
        permanent: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl HttpConnector for Failing {
        fn call(&self, _: HttpRequest) -> HttpConnectorFuture {
            let first = self
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                == 0;
            HttpConnectorFuture::ready(if self.permanent {
                Err(crate::s3::retry::Permanent::connector(anyhow::anyhow!(
                    "storage authorization expired"
                )))
            } else if first {
                Err(ConnectorError::io(Box::new(std::io::Error::from(
                    std::io::ErrorKind::ConnectionReset,
                ))))
            } else {
                let mut response =
                    HttpResponse::new(206.try_into().unwrap(), SdkBody::from(data()));
                let headers = response.headers_mut();
                headers.insert("etag", "fixture");
                headers.insert("content-length", SIZE.to_string());
                headers.insert("content-range", "bytes 0-65535/65536");
                Ok(response)
            })
        }
    }
    let object = Object {
        key: "object".into(),
        size: SIZE as u64,
        etag: "fixture".into(),
        version: None,
        metadata: None,
        mtime: 0,
    };
    for permanent in [true, false] {
        let dir = crate::test_support::tempdir().unwrap();
        let file = Arc::new(std::fs::File::create_new(dir.path().join("object")).unwrap());
        file.set_len(SIZE as u64).unwrap();
        let output = writer::Writer::with_readback(file, SIZE as u64, false).unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let connector = Failing {
            permanent,
            calls: calls.clone(),
        };
        let mut engine = super::buffer_tests::planning_engine(&["--s3-retries", "3"]);
        engine.client = Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "fixture",
                ))
                .http_client(http_client_fn(move |_, _| {
                    SharedHttpConnector::new(connector.clone())
                }))
                .build(),
        );
        let started = Instant::now();
        let result = engine
            .download_fast_range(&object, &output, 0, SIZE as u64, None, None, None, None)
            .await;
        let calls = calls.load(std::sync::atomic::Ordering::Relaxed);
        if permanent {
            let message = format!("{:#}", result.unwrap_err());
            assert!(
                message.contains("storage authorization expired"),
                "{message}"
            );
            assert_eq!((calls, started.elapsed()), (1, Duration::ZERO), "{message}");
        } else {
            result.unwrap();
            assert_eq!(calls, 2);
            assert!(started.elapsed() >= Duration::from_millis(100));
        }
    }
}
