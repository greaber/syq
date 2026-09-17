use super::*;
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;

#[derive(Debug)]
struct SlowTransport {
    read_timeout: Option<Duration>,
}
impl HttpConnector for SlowTransport {
    fn call(&self, mut request: HttpRequest) -> HttpConnectorFuture {
        let timeout = self.read_timeout;
        let upload = request.method() == "PUT";
        HttpConnectorFuture::new(async move {
            let work = async move {
                // Backpressure can leave a buffered body unpolled for much
                // longer than the SDK's stalled-stream grace period.
                tokio::time::sleep(Duration::from_secs(3600)).await;
                if upload {
                    let mut bytes = Vec::new();
                    while let Some(frame) = futures_util::future::poll_fn(|cx| {
                        http_body::Body::poll_frame(std::pin::Pin::new(request.body_mut()), cx)
                    })
                    .await
                    {
                        if let Ok(data) = frame.unwrap().into_data() {
                            bytes.extend_from_slice(&data);
                        }
                    }
                    assert_eq!(&bytes, b"slow upload");
                }
                // Body handoff is not server receipt. The provider may take
                // another hour to receive the bytes and acknowledge the PUT.
                tokio::time::sleep(Duration::from_secs(3600)).await;
                let mut response = HttpResponse::new(200.try_into().unwrap(), SdkBody::empty());
                response.headers_mut().insert("etag", "\"test\"");
                response.headers_mut().insert("content-length", "0");
                Ok(response)
            };
            if let Some(timeout) = timeout {
                tokio::time::timeout(timeout, work).await.map_err(|e| {
                    aws_smithy_runtime_api::client::result::ConnectorError::timeout(e.into())
                })?
            } else {
                work.await
            }
        })
    }
}

#[derive(Debug)]
struct UploadPolicy;
impl Intercept for UploadPolicy {
    fn name(&self) -> &'static str {
        "CheckUploadPolicy"
    }
    fn read_before_transmit(
        &self,
        _: &aws_smithy_runtime_api::client::interceptors::context::BeforeTransmitInterceptorContextRef<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let timeout = cfg.load::<TimeoutConfig>().unwrap();
        assert_eq!(timeout.connect_timeout(), Some(Duration::from_secs(15)));
        assert_eq!(timeout.read_timeout(), None);
        assert_eq!(timeout.operation_timeout(), None);
        assert_eq!(timeout.operation_attempt_timeout(), None);
        let protection = cfg
            .load::<aws_sdk_s3::config::StalledStreamProtectionConfig>()
            .unwrap();
        assert!(!protection.upload_enabled());
        assert!(protection.download_enabled());
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn uploads_can_take_hours_without_changing_control_or_download_deadlines() {
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(RetryConfig::disabled())
            .timeout_config(
                TimeoutConfig::builder()
                    .connect_timeout(Duration::from_secs(15))
                    .read_timeout(Duration::from_secs(60))
                    .build(),
            )
            .http_client(http_client_fn(|settings, _| {
                assert_eq!(settings.connect_timeout(), Some(Duration::from_secs(15)));
                SharedHttpConnector::new(SlowTransport {
                    read_timeout: settings.read_timeout(),
                })
            }))
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .build(),
    );
    let start = tokio::time::Instant::now();
    client
        .put_object()
        .bucket("bucket")
        .key("object")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            b"slow upload",
        ))
        .customize()
        .config_override(upload_config())
        .interceptor(UploadPolicy)
        .send()
        .await
        .unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(7200));
    let start = tokio::time::Instant::now();
    client
        .upload_part()
        .bucket("bucket")
        .key("object")
        .upload_id("upload")
        .part_number(1)
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            b"slow upload",
        ))
        .customize()
        .config_override(upload_config())
        .interceptor(UploadPolicy)
        .send()
        .await
        .unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(7200));
    let start = tokio::time::Instant::now();
    assert!(client
        .head_object()
        .bucket("bucket")
        .key("object")
        .send()
        .await
        .is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(60));
    let start = tokio::time::Instant::now();
    assert!(client
        .get_object()
        .bucket("bucket")
        .key("object")
        .customize()
        .config_override(without_sdk_retries())
        .send()
        .await
        .is_err());
    assert_eq!(start.elapsed(), Duration::from_secs(60));
}
