use super::*;
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;

#[derive(Debug)]
struct ValidatePayload;
impl HttpConnector for ValidatePayload {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        HttpConnectorFuture::new(async move {
            let payload = request
                .headers()
                .get("x-amz-content-sha256")
                .unwrap()
                .to_owned();
            let checksum = request
                .headers()
                .get("x-amz-checksum-sha256")
                .unwrap()
                .to_owned();
            assert_eq!(
                payload,
                super::super::checksum::single_put_payload("PUT", false, Some(&checksum))
                    .unwrap()
                    .unwrap()
            );
            let mut bytes = Vec::new();
            while let Some(frame) = std::future::poll_fn(|cx| {
                http_body::Body::poll_frame(std::pin::Pin::new(request.body_mut()), cx)
            })
            .await
            {
                if let Ok(data) = frame.unwrap().into_data() {
                    bytes.extend_from_slice(&data);
                }
            }
            let actual = super::super::checksum::Algorithm::Sha256.digest(&bytes);
            // Model a provider that only validates the signed payload digest.
            let valid = super::super::checksum::single_put_payload("PUT", false, Some(&actual))
                .unwrap()
                .unwrap()
                == payload;
            let mut response = if valid {
                HttpResponse::new(200.try_into().unwrap(), SdkBody::empty())
            } else {
                HttpResponse::new(
                    400.try_into().unwrap(),
                    SdkBody::from("<Error><Code>XAmzContentSHA256Mismatch</Code></Error>"),
                )
            };
            response.headers_mut().insert("etag", "\"test\"");
            Ok(response)
        })
    }
}

#[tokio::test]
async fn precomputed_payload_detects_corruption_in_buffered_and_streamed_puts() {
    use aws_sdk_s3::primitives::ByteStream;
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(RetryConfig::disabled())
            .interceptor(Headers(vec![]))
            .http_client(http_client_fn(|_, _| {
                SharedHttpConnector::new(ValidatePayload)
            }))
            .build(),
    );
    let fixture = crate::test_support::tempdir().unwrap();
    let path = fixture.path().join("body");
    std::fs::write(&path, b"original").unwrap();
    for streamed in [false, true] {
        for corrupt in [false, true] {
            let body = if streamed {
                ByteStream::from_path(&path).await.unwrap()
            } else {
                ByteStream::from_static(b"original")
            };
            let checksum = super::super::checksum::Algorithm::Sha256.digest(if corrupt {
                b"different"
            } else {
                b"original"
            });
            let result = client
                .put_object()
                .bucket("bucket")
                .key("key")
                .checksum_sha256(checksum)
                .body(body)
                .customize()
                .disable_payload_signing()
                .send()
                .await;
            if corrupt {
                assert_eq!(
                    result
                        .unwrap_err()
                        .as_service_error()
                        .unwrap()
                        .meta()
                        .code(),
                    Some("XAmzContentSHA256Mismatch")
                );
            } else {
                result.unwrap();
            }
        }
    }
}
