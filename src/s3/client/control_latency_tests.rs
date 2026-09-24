use super::*;
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Debug, Clone)]
struct Responses;
impl HttpConnector for Responses {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let uri = request.uri().to_string();
        let head = request.method() == "HEAD";
        HttpConnectorFuture::new(async move {
            let (status, delay, body) = if uri.contains("list-type=") {
                let page = uri
                    .split(['?', '&'])
                    .find_map(|s| s.strip_prefix("continuation-token=page"))
                    .map_or(0, |s| s.parse::<usize>().unwrap());
                let next = if page < 7 {
                    format!("<IsTruncated>true</IsTruncated><NextContinuationToken>page{}</NextContinuationToken>", page+1)
                } else {
                    "<IsTruncated>false</IsTruncated>".into()
                };
                (200, 15, format!("<ListBucketResult>{next}<Contents><Key>data/{page}</Key><Size>4</Size></Contents></ListBucketResult>"))
            } else if uri.ends_with("/slow") {
                (404, 80, String::new())
            } else if head {
                (
                    uri.rsplit('/').next().unwrap().parse::<u16>().unwrap(),
                    1,
                    String::new(),
                )
            } else {
                (200, 1, "data".into())
            };
            tokio::time::advance(Duration::from_millis(delay)).await;
            let length = body.len().to_string();
            let mut response = HttpResponse::new(status.try_into().unwrap(), SdkBody::from(body));
            response.headers_mut().insert("content-length", length);
            Ok(response)
        })
    }
}

#[tokio::test(start_paused = true)]
async fn latency_uses_individual_control_responses_and_ignores_errors_and_data() {
    let control = Arc::new(AtomicU64::new(u64::MAX));
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(RetryConfig::disabled())
            .http_client(http_client_fn(|_, _| SharedHttpConnector::new(Responses)))
            .interceptor(ControlLatency(control.clone()))
            .build(),
    );
    let start = tokio::time::Instant::now();
    assert!(client
        .head_object()
        .bucket("bucket")
        .key("slow")
        .send()
        .await
        .is_err());
    assert_eq!(control.load(Ordering::Relaxed), 80_000_000);
    assert_eq!(
        list(
            &client,
            "bucket",
            "data/",
            None,
            &mut Default::default(),
            32
        )
        .await
        .unwrap()
        .into_objects()
        .len(),
        8
    );
    // Flat pages give no evidence that directory discovery would help.
    assert_eq!(start.elapsed(), Duration::from_millis(200));
    assert_eq!(control.load(Ordering::Relaxed), 15_000_000);
    for status in [301, 429, 503] {
        assert!(client
            .head_object()
            .bucket("bucket")
            .key(status.to_string())
            .send()
            .await
            .is_err());
        assert_eq!(control.load(Ordering::Relaxed), 15_000_000);
    }
    client
        .get_object()
        .bucket("bucket")
        .key("data")
        .send()
        .await
        .unwrap();
    assert_eq!(control.load(Ordering::Relaxed), 15_000_000);
    assert!(client
        .head_object()
        .bucket("bucket")
        .key("404")
        .send()
        .await
        .is_err());
    assert_eq!(control.load(Ordering::Relaxed), 1_000_000);
}
