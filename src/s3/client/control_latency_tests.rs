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
        list(&client, None, "bucket", "data/", 32)
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

/// How long the fake storage service takes to answer, and how long the fake
/// authorizing machine takes to sign. The gap leaves room for a loaded runner.
const STORAGE: Duration = Duration::from_millis(50);
const SIGNING: Duration = Duration::from_millis(2000);

#[derive(Debug, Clone)]
struct Found;
impl HttpConnector for Found {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        assert!(request.uri().contains("X-Amz-Signature="));
        HttpConnectorFuture::new(async {
            tokio::time::sleep(STORAGE).await;
            let mut response = HttpResponse::new(200.try_into().unwrap(), SdkBody::empty());
            response.headers_mut().insert("content-length", "0");
            Ok(response)
        })
    }
}

/// A request signed as it is sent waits for the authorizing machine first.
/// That wait describes the return connection, not the storage service.
#[tokio::test]
async fn latency_leaves_out_the_wait_for_a_signature() {
    use crate::destination::{read_message, write_message};
    use crate::s3::authorization::{http_client, Authorization, Configuration};
    let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let authorizer = std::thread::spawn(move || {
        let message: serde_json::Value = read_message(&mut peer).unwrap();
        let key = message["Sign"][0]["key"].as_str().unwrap().to_owned();
        std::thread::sleep(SIGNING);
        let url = format!("https://storage.example/fixture/{key}?X-Amz-Signature=fake");
        write_message(&mut peer, &serde_json::json!({ "Signed": [url] })).unwrap();
    });
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let authorization = Arc::new(Authorization::new(
        "fixture".into(),
        Configuration {
            endpoint: "https://storage.example".into(),
            region: "auto".into(),
            expires_at,
            requested_lifetime: 60,
        },
        socket,
    ));
    let control = Arc::new(AtomicU64::new(u64::MAX));
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new("auto"))
            .endpoint_url("https://storage.example")
            .force_path_style(true)
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(RetryConfig::disabled())
            .http_client(http_client(
                http_client_fn(|_, _| SharedHttpConnector::new(Found)),
                authorization,
            ))
            .interceptor(ControlLatency(control.clone()))
            .build(),
    );
    let start = tokio::time::Instant::now();
    client
        .head_object()
        .bucket("fixture")
        .key("key")
        .send()
        .await
        .unwrap();
    assert!(start.elapsed() >= SIGNING + STORAGE);
    // The storage service's own time stays in the sample.
    let sample = Duration::from_nanos(control.load(Ordering::Relaxed));
    assert!(sample >= STORAGE && sample < SIGNING / 2, "{sample:?}");
    authorizer.join().unwrap();
}
