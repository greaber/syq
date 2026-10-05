use super::*;
use aws_sdk_s3::{
    config::retry::RetryConfig,
    types::{Delete, ObjectIdentifier},
    Client,
};
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

#[tokio::test(start_paused = true)]
async fn widespread_rejection_reduces_admission_without_waiting_for_retries() {
    let feedback = Throttle::new();
    tokio::time::advance(Duration::from_millis(100)).await;
    for _ in 0..4 {
        feedback.observe(1000, true, 1000, 0, Duration::from_millis(100));
    }
    for _ in 0..4 {
        feedback.observe(1000, true, 0, 1000, Duration::from_millis(100));
    }
    assert_eq!(feedback.take_limit(10), Some(4));
    assert_eq!(feedback.take_limit(10), None);
}

#[tokio::test(start_paused = true)]
async fn hot_keys_and_partial_bulk_success_do_not_limit_unrelated_work() {
    for partial in [false, true] {
        let feedback = Throttle::new();
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(100)).await;
            // Either one busy batch in four, or busy keys in every batch.
            for n in 0..4 {
                let blocked = if partial {
                    250
                } else if n == 0 {
                    1000
                } else {
                    0
                };
                feedback.observe(
                    1000,
                    true,
                    1000 - blocked,
                    blocked,
                    Duration::from_millis(100),
                );
            }
            for _ in 0..8 {
                feedback.observe(1000, false, 0, 1000, Duration::from_millis(100));
            }
            assert_eq!(feedback.take_limit(10), None);
        }
    }
}

#[derive(Clone, Debug)]
struct Responses {
    calls: Arc<AtomicUsize>,
    bulk: bool,
    status: u16,
}
impl HttpConnector for Responses {
    fn call(&self, _: HttpRequest) -> HttpConnectorFuture {
        let call = self.calls.fetch_add(1, Relaxed);
        let bulk = self.bulk;
        let status = self.status;
        HttpConnectorFuture::new(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let (status, body) = if bulk {
                (200, "<DeleteResult><Deleted><Key>good</Key></Deleted><Error><Key>busy</Key><Code>SlowDown</Code></Error></DeleteResult>")
            } else if call < 2 {
                (status, "<Error><Code>SlowDown</Code></Error>")
            } else {
                (204, "")
            };
            Ok(HttpResponse::new(
                status.try_into().unwrap(),
                SdkBody::from(body),
            ))
        })
    }
}

fn client(transport: Responses) -> Client {
    Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .endpoint_url("http://localhost")
            .force_path_style(true)
            .retry_config(
                RetryConfig::standard()
                    .with_max_attempts(3)
                    .with_initial_backoff(Duration::from_millis(1))
                    .with_use_static_exponential_base(true),
            )
            .retry_partition(crate::s3::retry::partition())
            .retry_classifier(crate::s3::client::Throttling)
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(transport.clone())
            }))
            .build(),
    )
}

#[tokio::test(start_paused = true)]
async fn sdk_attempts_count_new_throttles_once_and_preserve_retries() {
    for status in [429, 503] {
        let feedback = Throttle::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let client = client(Responses {
            calls: calls.clone(),
            bulk: false,
            status,
        });
        client
            .delete_object()
            .bucket("bucket")
            .key("key")
            .customize()
            .config_override(
                aws_sdk_s3::config::Builder::new().interceptor(feedback.observer(1, true)),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(calls.load(Relaxed), 3);
        let state = feedback.state.lock().unwrap();
        assert_eq!(state.fresh_keys, 1);
        assert_eq!(state.fresh_throttled, 1);
        assert_eq!(state.throttled_attempts, 1);
        assert_eq!(state.succeeded, 1.0);
    }
}

#[tokio::test(start_paused = true)]
async fn bulk_http_success_reports_key_outcomes_without_turning_them_into_sdk_retries() {
    let feedback = Throttle::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let client = client(Responses {
        calls: calls.clone(),
        bulk: true,
        status: 200,
    });
    let result = client
        .delete_objects()
        .bucket("bucket")
        .delete(
            Delete::builder()
                .set_objects(Some(
                    ["good", "busy"]
                        .into_iter()
                        .map(|key| ObjectIdentifier::builder().key(key).build().unwrap())
                        .collect(),
                ))
                .build()
                .unwrap(),
        )
        .customize()
        .config_override(aws_sdk_s3::config::Builder::new().interceptor(feedback.observer(2, true)))
        .send()
        .await
        .unwrap();
    assert_eq!(result.deleted().len(), 1);
    assert_eq!(result.errors().len(), 1);
    assert_eq!(calls.load(Relaxed), 1);
    let state = feedback.state.lock().unwrap();
    assert_eq!(state.fresh_keys, 2);
    assert_eq!(state.fresh_throttled, 1);
    assert_eq!(state.throttled_attempts, 0);
    assert_eq!(state.succeeded, 0.5);
}
