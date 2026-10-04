use super::*;
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;
use std::sync::{
    atomic::{AtomicUsize, Ordering::Relaxed},
    Arc,
};

#[derive(Debug, Default)]
struct Counts {
    active: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
}

#[derive(Clone, Debug)]
struct Delayed(Arc<Counts>, Option<usize>);
impl HttpConnector for Delayed {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        assert_eq!(request.method(), "DELETE");
        let url = url::Url::parse(request.uri()).unwrap();
        let version = url
            .query_pairs()
            .find(|(k, _)| k == "versionId")
            .unwrap()
            .1
            .into_owned();
        let counts = self.0.clone();
        let saturation = self.1;
        HttpConnectorFuture::new(async move {
            let active = counts.active.fetch_add(1, Relaxed) + 1;
            counts.peak.fetch_max(active, Relaxed);
            counts.calls.fetch_add(1, Relaxed);
            let slowdown =
                saturation.map_or(1.0, |cap| (active as f64 / cap as f64).max(1.0).powi(2));
            tokio::time::sleep(std::time::Duration::from_secs_f64(0.020 * slowdown)).await;
            counts.active.fetch_sub(1, Relaxed);
            let mut response = HttpResponse::new(204.try_into().unwrap(), SdkBody::empty());
            response.headers_mut().insert("x-amz-version-id", version);
            response.headers_mut().insert("content-length", "0");
            Ok(response)
        })
    }
}

fn client(counts: Arc<Counts>) -> Client {
    client_with_saturation(counts, None)
}

fn client_with_saturation(counts: Arc<Counts>, saturation: Option<usize>) -> Client {
    let transport = Delayed(counts, saturation);
    Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .endpoint_url("http://localhost")
            .force_path_style(true)
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(transport.clone())
            }))
            .build(),
    )
}

fn identify(n: &usize) -> Target {
    Target {
        key: format!("key{n}"),
        version: Some(format!("v{n}")),
    }
}

#[tokio::test(start_paused = true)]
async fn deletion_adapts_to_latency_without_losing_or_duplicating_outcomes() {
    let mut times = Vec::new();
    for automatic in [false, true] {
        let counts = Arc::new(Counts::default());
        let client = client(counts.clone());
        let deleter = Deleter {
            client: &client,
            bucket: "bucket",
            individual: true,
            concurrency: crate::deletion::Concurrency {
                initial: 10,
                maximum: 64,
                automatic,
                startup_doubling: true,
            },
        };
        let items: Vec<_> = (0..4000).collect();
        let mut seen = vec![false; items.len()];
        let started = tokio::time::Instant::now();
        deleter
            .run(
                &items,
                identify,
                || Ok(()),
                |n, result| {
                    assert!(result.is_ok(), "{result:?}");
                    assert!(!std::mem::replace(&mut seen[*n], true));
                },
            )
            .await
            .unwrap();
        times.push(started.elapsed().as_secs_f64());
        assert!(seen.into_iter().all(|seen| seen));
        assert_eq!(counts.calls.load(Relaxed), items.len());
        assert_eq!(counts.active.load(Relaxed), 0);
        let peak = counts.peak.load(Relaxed);
        if automatic {
            assert!(peak > 10, "peak: {peak}");
        } else {
            assert_eq!(peak, 10);
        }
        assert!(peak <= 64);
        eprintln!(
            "20ms individual deletes: automatic={automatic}, seconds={:.3}, peak={peak}",
            times.last().unwrap()
        );
    }
    assert!(times[1] < times[0] * 0.7, "fixed/automatic: {times:?}");
}

#[tokio::test(start_paused = true)]
async fn cancellation_drains_started_deletions_without_admitting_more() {
    let counts = Arc::new(Counts::default());
    let client = client(counts.clone());
    let deleter = Deleter {
        client: &client,
        bucket: "bucket",
        individual: true,
        concurrency: crate::deletion::Concurrency {
            initial: 8,
            maximum: 8,
            automatic: false,
            startup_doubling: true,
        },
    };
    let checked = AtomicUsize::new(0);
    let mut finished = Vec::new();
    let error = deleter
        .run(
            &(0..100).collect::<Vec<_>>(),
            identify,
            || {
                anyhow::ensure!(checked.fetch_add(1, Relaxed) < 31, "cancelled");
                Ok(())
            },
            |n, result| {
                assert!(result.is_ok());
                finished.push(*n);
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    finished.sort_unstable();
    assert_eq!(finished, (0..31).collect::<Vec<_>>());
    assert_eq!(counts.calls.load(Relaxed), 31);
    assert_eq!(counts.active.load(Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn deletion_backoff_recovers_from_request_contention() {
    let mut times = Vec::new();
    for automatic in [false, true] {
        let counts = Arc::new(Counts::default());
        let client = client_with_saturation(counts.clone(), Some(16));
        let deleter = Deleter {
            client: &client,
            bucket: "bucket",
            individual: true,
            concurrency: crate::deletion::Concurrency {
                initial: 32,
                maximum: 128,
                automatic,
                startup_doubling: true,
            },
        };
        let started = tokio::time::Instant::now();
        let mut finished = 0;
        deleter
            .run(
                &(0..16000).collect::<Vec<_>>(),
                identify,
                || Ok(()),
                |_, result| {
                    assert!(result.is_ok());
                    finished += 1;
                },
            )
            .await
            .unwrap();
        times.push(started.elapsed().as_secs_f64());
        assert_eq!(finished, 16000);
        assert_eq!(counts.active.load(Relaxed), 0);
    }
    eprintln!("contended individual deletes, fixed/automatic seconds: {times:?}");
    assert!(times[1] < times[0] * 0.85, "fixed/automatic: {times:?}");
}

type RequestedVersions = Vec<(String, String)>;

#[derive(Clone, Debug)]
struct BulkResponses {
    calls: Arc<std::sync::Mutex<Vec<RequestedVersions>>>,
    transport_failure: bool,
}

impl HttpConnector for BulkResponses {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        assert_eq!(request.method(), "POST");
        let body = std::str::from_utf8(request.body().bytes().unwrap()).unwrap();
        let value = |object: &str, tag: &str| {
            object
                .split_once(&format!("<{tag}>"))
                .unwrap()
                .1
                .split_once(&format!("</{tag}>"))
                .unwrap()
                .0
                .to_owned()
        };
        let objects: Vec<_> = body
            .split("<Object>")
            .skip(1)
            .map(|object| (value(object, "Key"), value(object, "VersionId")))
            .collect();
        let mut calls = self.calls.lock().unwrap();
        calls.push(objects.clone());
        let attempt = calls.len();
        let mut xml = String::from("<DeleteResult>");
        for (key, version) in objects {
            let code = match key.as_str() {
                "denied" => Some("AccessDenied"),
                "busy" => Some("SlowDown"),
                "unavailable" => Some("ServiceUnavailable"),
                "internal" if attempt == 1 => Some("InternalError"),
                "once" if version == "v1" && attempt == 1 => Some("SlowDown"),
                _ => None,
            };
            if let Some(code) = code {
                xml.push_str(&format!("<Error><Key>{key}</Key><VersionId>{version}</VersionId><Code>{code}</Code></Error>"));
            } else {
                xml.push_str(&format!(
                    "<Deleted><Key>{key}</Key><VersionId>{version}</VersionId></Deleted>"
                ));
            }
        }
        xml.push_str("</DeleteResult>");
        let status = if self.transport_failure { 503 } else { 200 };
        if self.transport_failure {
            xml = "<Error><Code>SlowDown</Code></Error>".into();
        }
        HttpConnectorFuture::new(async move {
            Ok(HttpResponse::new(
                status.try_into().unwrap(),
                SdkBody::from(xml),
            ))
        })
    }
}

fn bulk_client(transport: BulkResponses) -> Client {
    Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .endpoint_url("http://localhost")
            .force_path_style(true)
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(transport.clone())
            }))
            .build(),
    )
}

#[tokio::test(start_paused = true)]
async fn bulk_retries_only_transient_failed_versions_and_bounds_attempts() {
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let client = bulk_client(BulkResponses {
        calls: calls.clone(),
        transport_failure: false,
    });
    let deleter = Deleter {
        client: &client,
        bucket: "bucket",
        individual: false,
        concurrency: crate::deletion::Concurrency::filesystem(1),
    };
    let items: Vec<_> = [
        ("good", "v1"),
        ("once", "v1"),
        ("once", "v2"),
        ("denied", "v1"),
        ("busy", "v1"),
        ("internal", "v1"),
        ("unavailable", "v1"),
    ]
    .into_iter()
    .map(|(key, version)| Target {
        key: key.into(),
        version: Some(version.into()),
    })
    .collect();
    let mut outcomes = Vec::new();
    deleter
        .run(
            &items,
            Clone::clone,
            || Ok(()),
            |target, outcome| {
                outcomes.push((target.clone(), outcome));
            },
        )
        .await
        .unwrap();
    assert_eq!(outcomes.len(), items.len());
    assert_eq!(
        outcomes
            .iter()
            .map(|(target, _)| target)
            .collect::<Vec<_>>(),
        items.iter().collect::<Vec<_>>()
    );
    assert_eq!(outcomes[0].1.as_ref().unwrap(), &1);
    assert_eq!(outcomes[1].1.as_ref().unwrap(), &2);
    assert_eq!(outcomes[2].1.as_ref().unwrap(), &1);
    let denied = outcomes[3].1.as_ref().unwrap_err();
    assert_eq!((denied.attempts, denied.retryable), (1, "no"));
    let busy = outcomes[4].1.as_ref().unwrap_err();
    assert_eq!((busy.attempts, busy.retryable), (3, "yes"));
    assert_eq!(outcomes[5].1.as_ref().unwrap(), &2);
    let unavailable = outcomes[6].1.as_ref().unwrap_err();
    assert_eq!((unavailable.attempts, unavailable.retryable), (3, "yes"));
    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0],
        items
            .iter()
            .map(|target| (target.key.clone(), target.version.clone().unwrap()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        calls[1],
        vec![
            ("once".into(), "v1".into()),
            ("busy".into(), "v1".into()),
            ("internal".into(), "v1".into()),
            ("unavailable".into(), "v1".into()),
        ]
    );
    assert_eq!(
        calls[2],
        vec![
            ("busy".into(), "v1".into()),
            ("unavailable".into(), "v1".into())
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn bulk_retry_backoff_observes_cancellation_and_does_not_repeat_transport_errors() {
    for transport_failure in [false, true] {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let client = bulk_client(BulkResponses {
            calls: calls.clone(),
            transport_failure,
        });
        let deleter = Deleter {
            client: &client,
            bucket: "bucket",
            individual: false,
            concurrency: crate::deletion::Concurrency::filesystem(1),
        };
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = cancelled.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            signal.store(true, Relaxed);
        });
        let mut outcomes = Vec::new();
        let result = deleter
            .run(
                &[Target {
                    key: "busy".into(),
                    version: Some("v1".into()),
                }],
                Clone::clone,
                || {
                    anyhow::ensure!(!cancelled.load(Relaxed), "cancelled");
                    Ok(())
                },
                |_, outcome| outcomes.push(outcome),
            )
            .await;
        assert_eq!(result.is_err(), !transport_failure);
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].as_ref().unwrap_err().attempts, 1);
        task.await.unwrap();
    }
}
