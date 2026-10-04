use super::*;
use aws_sdk_s3::{
    config::{retry::RetryConfig, Credentials, Region},
    Client,
};
use aws_smithy_runtime_api::client::http::{
    http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_types::body::SdkBody;
use futures_util::{stream, StreamExt};
use std::sync::{
    atomic::{AtomicUsize, Ordering::Relaxed},
    Arc,
};

#[derive(Clone, Debug)]
struct Responses {
    attempts: Arc<Vec<AtomicUsize>>,
    fail_before: usize,
    denied: bool,
}
impl HttpConnector for Responses {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let index = request
            .uri()
            .split('?')
            .next()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let attempt = self.attempts[index].fetch_add(1, Relaxed);
        let denied = self.denied;
        let failed = attempt < self.fail_before;
        HttpConnectorFuture::new(async move {
            // Keep a wave in flight together, rather than serializing the test.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let (status, body) = if denied {
                (403, "<Error><Code>AccessDenied</Code></Error>")
            } else if failed {
                (503, "<Error><Code>SlowDown</Code></Error>")
            } else {
                (204, "")
            };
            let mut response = HttpResponse::new(status.try_into().unwrap(), SdkBody::from(body));
            response
                .headers_mut()
                .insert("content-length", body.len().to_string());
            Ok(response)
        })
    }
}
fn client(transport: impl HttpConnector + Clone + 'static, retries: u32) -> Client {
    Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new("test", "test", None, None, "fixture"))
            .endpoint_url("http://localhost")
            .force_path_style(true)
            .retry_config(RetryConfig::standard().with_max_attempts(retries + 1))
            .retry_partition(partition())
            .retry_classifier(crate::s3::client::Throttling)
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(transport.clone())
            }))
            .build(),
    )
}

#[tokio::test(start_paused = true)]
async fn parallel_and_repeated_throttling_keep_each_requests_retry_allowance() {
    for concurrency in [10, 128, 256] {
        let attempts = Arc::new((0..300).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
        let client = client(
            Responses {
                attempts: attempts.clone(),
                fail_before: 2,
                denied: false,
            },
            2,
        );
        let outcomes: Vec<_> = stream::iter(0..300)
            .map(|i| {
                let client = client.clone();
                async move {
                    client
                        .delete_object()
                        .bucket("bucket")
                        .key(i.to_string())
                        .send()
                        .await
                }
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;
        assert!(
            outcomes.iter().all(Result::is_ok),
            "concurrency={concurrency}"
        );
        assert!(attempts.iter().all(|n| n.load(Relaxed) == 3));
    }
}

#[tokio::test(start_paused = true)]
async fn permanent_errors_and_exhausted_requests_remain_bounded() {
    for (denied, retries, expected) in [(false, 2, 3), (true, 2, 1), (false, 0, 1)] {
        let attempts = Arc::new((0..256).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
        let client = client(
            Responses {
                attempts: attempts.clone(),
                fail_before: usize::MAX,
                denied,
            },
            retries,
        );
        let outcomes: Vec<_> = stream::iter(0..256)
            .map(|i| {
                let client = client.clone();
                async move {
                    client
                        .delete_object()
                        .bucket("bucket")
                        .key(i.to_string())
                        .send()
                        .await
                }
            })
            .buffer_unordered(256)
            .collect()
            .await;
        assert!(outcomes.iter().all(Result::is_err));
        assert!(attempts.iter().all(|n| n.load(Relaxed) == expected));
    }
}

#[derive(Clone, Debug)]
struct Bulk(Arc<AtomicUsize>);
impl HttpConnector for Bulk {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let attempt = self.0.fetch_add(1, Relaxed);
        let body = std::str::from_utf8(request.body().bytes().unwrap()).unwrap();
        assert_eq!(
            body.contains("<Key>good</Key>"),
            attempt == 0,
            "successful keys must not be resent"
        );
        let good = if attempt == 0 {
            "<Deleted><Key>good</Key></Deleted>"
        } else {
            ""
        };
        let pending = if attempt < 4 {
            "<Error><Key>busy</Key><Code>SlowDown</Code></Error>"
        } else {
            "<Deleted><Key>busy</Key></Deleted>"
        };
        let body = format!("<DeleteResult>{good}{pending}</DeleteResult>");
        let length = body.len().to_string();
        HttpConnectorFuture::new(async move {
            let mut response = HttpResponse::new(200.try_into().unwrap(), SdkBody::from(body));
            response.headers_mut().insert("content-length", length);
            Ok(response)
        })
    }
}

#[tokio::test(start_paused = true)]
async fn bulk_throttling_recovers_after_more_than_two_retries_and_honors_zero() {
    use crate::s3::delete::{Deleter, Target};
    for retries in [0, 4] {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = client(Bulk(calls.clone()), retries);
        let deleter = Deleter {
            client: &client,
            bucket: "bucket",
            individual: false,
            retries,
            concurrency: crate::deletion::Concurrency::filesystem(1),
        };
        let items: Vec<_> = ["good", "busy"]
            .into_iter()
            .map(|key| Target {
                key: key.into(),
                version: None,
            })
            .collect();
        let mut results = Vec::new();
        deleter
            .run(
                &items,
                Clone::clone,
                || Ok(()),
                |_, result| results.push(result),
            )
            .await
            .unwrap();
        assert_eq!(results[0].as_ref().unwrap(), &1);
        assert_eq!(results[1].is_ok(), retries > 0);
        assert_eq!(calls.load(Relaxed), (retries + 1) as usize);
    }
}

fn error(
    code: &str,
    status: u16,
    headers: &[(&str, &str)],
) -> SdkError<aws_sdk_s3::operation::get_object::GetObjectError, HttpResponse> {
    let mut response = HttpResponse::new(status.try_into().unwrap(), SdkBody::empty());
    for &(name, value) in headers {
        response
            .headers_mut()
            .insert(name.to_owned(), value.to_owned());
    }
    let metadata = aws_smithy_types::error::ErrorMetadata::builder()
        .code(code)
        .build();
    SdkError::service_error(
        aws_sdk_s3::operation::get_object::GetObjectError::generic(metadata),
        response,
    )
}

#[test]
fn payload_backoff_spreads_retries_and_honors_server_hints() {
    let delays: std::collections::HashSet<_> = (0..64).map(|_| delay(0, false)).collect();
    assert!(delays.len() > 1);
    assert!(delays
        .iter()
        .all(|d| (Duration::from_millis(100)..=Duration::from_millis(200)).contains(d)));
    for (code, status) in [("SlowDown", 503), ("provider-specific", 429)] {
        assert!((Duration::from_secs(1)..=Duration::from_secs(2))
            .contains(&error_delay(0, &error(code, status, &[]))));
    }
    assert_eq!(
        error_delay(0, &error("SlowDown", 503, &[("x-amz-retry-after", "5000")])),
        Duration::from_secs(5)
    );
    assert_eq!(
        error_delay(0, &error("custom", 429, &[("retry-after", "7")])),
        Duration::from_secs(7)
    );
    assert_eq!(
        error_delay(0, &error("custom", 429, &[("retry-after", "999999999999")])),
        Duration::from_secs(20)
    );
    assert!(retry_after("invalid").is_none());
    assert!(retry_after("Sun, 06 Nov 2094 08:49:37 GMT").is_some());
    assert!((Duration::from_secs(10)..=Duration::from_secs(20)).contains(&delay(u32::MAX, false)));
}

#[derive(Clone, Debug, Default)]
struct RateLimited(Arc<std::sync::Mutex<Vec<tokio::time::Instant>>>);
impl HttpConnector for RateLimited {
    fn call(&self, _: HttpRequest) -> HttpConnectorFuture {
        let mut sent = self.0.lock().unwrap();
        sent.push(tokio::time::Instant::now());
        let first = sent.len() == 1;
        HttpConnectorFuture::new(async move {
            // This is the response observed from R2 for concurrent writes to one key.
            let mut response = if first {
                HttpResponse::new(
                    429.try_into().unwrap(),
                    SdkBody::from("<Error><Code>ServiceUnavailable</Code></Error>"),
                )
            } else {
                HttpResponse::new(204.try_into().unwrap(), SdkBody::empty())
            };
            response.headers_mut().insert("retry-after", "5");
            Ok(response)
        })
    }
}

#[tokio::test(start_paused = true)]
async fn sdk_requests_honor_rate_limit_retry_after() {
    let transport = RateLimited::default();
    let client = client(transport.clone(), 1);
    client
        .delete_object()
        .bucket("bucket")
        .key("key")
        .send()
        .await
        .unwrap();
    let sent = transport.0.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1] - sent[0], Duration::from_secs(5));
}
