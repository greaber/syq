//! Retry a misdirected AWS request in the region returned by S3.
use super::*;
use aws_sdk_s3::config::{endpoint::Params, Builder};
use aws_smithy_runtime_api::client::{
    endpoint::EndpointResolverParams,
    http::{http_client_fn, HttpClient, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    interceptors::context::{
        BeforeDeserializationInterceptorContextMut, BeforeTransmitInterceptorContextRef,
    },
    orchestrator::{HttpRequest, HttpResponse},
    result::ConnectorError,
};
use http_body_util::BodyExt;
use std::sync::Arc;
use tokio::sync::OnceCell;

// The probe has the original transport, so it cannot trigger another
// redirect lookup. The ordinary client still lets the SDK resolve and sign
// each retry, using only the region returned by S3.
pub(super) fn allow_redirect(
    builder: Builder,
    bucket: &str,
    corrected: DiscoveredRegion,
) -> Builder {
    let probe = Client::from_conf(
        builder
            .clone()
            .retry_config(RetryConfig::disabled())
            .build(),
    );
    let transport = probe
        .config()
        .http_client()
        .expect("S3 HTTP client configured");
    let lookup = Arc::new(RegionLookup {
        bucket: bucket.to_owned(),
        probe,
        fallback: OnceCell::new(),
        corrected: corrected.clone(),
    });
    builder
        .http_client(http_client_fn(move |settings, components| {
            SharedHttpConnector::new(RedirectConnector {
                inner: transport.http_connector(settings, components),
                lookup: lookup.clone(),
            })
        }))
        .interceptor(BucketRegion {
            bucket: bucket.to_owned(),
            corrected,
        })
        .retry_classifier(RegionRedirect)
}

#[derive(Debug)]
struct BucketRegion {
    bucket: String,
    corrected: DiscoveredRegion,
}

fn params(cfg: &ConfigBag) -> Option<&Params> {
    cfg.load::<EndpointResolverParams>()?.get()
}

fn with_region(
    p: &Params,
    region: String,
) -> Result<Params, aws_sdk_s3::config::endpoint::InvalidParams> {
    Params::builder()
        .region(region)
        .set_bucket(p.bucket().map(str::to_owned))
        .set_endpoint(p.endpoint().map(str::to_owned))
        .set_use_fips(p.use_fips())
        .set_use_dual_stack(p.use_dual_stack())
        .set_force_path_style(p.force_path_style())
        .set_accelerate(p.accelerate())
        .set_use_global_endpoint(p.use_global_endpoint())
        .set_use_object_lambda_endpoint(p.use_object_lambda_endpoint())
        .set_key(p.key().map(str::to_owned))
        .set_prefix(p.prefix().map(str::to_owned))
        .set_copy_source(p.copy_source().map(str::to_owned))
        .set_disable_access_points(p.disable_access_points())
        .set_disable_multi_region_access_points(p.disable_multi_region_access_points())
        .set_use_arn_region(p.use_arn_region())
        .set_use_s3_express_control_endpoint(p.use_s3_express_control_endpoint())
        .set_disable_s3_express_session_auth(p.disable_s3_express_session_auth())
        .build()
}

impl Intercept for BucketRegion {
    fn name(&self) -> &'static str {
        "SyqS3BucketRegion"
    }

    fn read_before_attempt(
        &self,
        _: &BeforeTransmitInterceptorContextRef<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let Some(region) = self.corrected.get() else {
            return Ok(());
        };
        let Some(p) = params(cfg).filter(|p| {
            p.bucket() == Some(self.bucket.as_str()) && p.region() != Some(region.as_str())
        }) else {
            return Ok(());
        };
        let updated = with_region(p, region.clone())?;
        cfg.interceptor_state()
            .store_put(EndpointResolverParams::new(updated));
        Ok(())
    }

    fn modify_before_transmit(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        if let Some(region) = params(cfg)
            .filter(|p| p.bucket() == Some(self.bucket.as_str()))
            .and_then(Params::region)
            .filter(|region| {
                self.corrected
                    .get()
                    .is_none_or(|corrected| corrected != region)
            })
        {
            context
                .request_mut()
                .add_extension(RequestRegion(region.to_owned()));
        }
        Ok(())
    }

    fn modify_before_deserialization(
        &self,
        context: &mut BeforeDeserializationInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        if context
            .response_mut()
            .extension::<RegionRedirect>()
            .is_some()
        {
            // Region correction gets one extra attempt even when transient
            // retries are disabled. The corrected request cannot redirect again.
            if let Some(retry) = cfg.load::<RetryConfig>() {
                let retry = retry.clone().with_max_attempts(retry.max_attempts() + 1);
                cfg.interceptor_state().store_put(retry);
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct RequestRegion(String);

#[derive(Debug)]
struct RegionLookup {
    bucket: String,
    probe: Client,
    fallback: OnceCell<Option<String>>,
    corrected: DiscoveredRegion,
}

impl RegionLookup {
    async fn recover(
        &self,
        request_region: &str,
        response: &mut HttpResponse,
    ) -> Result<(), ConnectorError> {
        let status = response.status().as_u16();
        if !matches!(status, 301 | 302 | 307 | 400) {
            return Ok(());
        }
        let region = if let Some(region) = response
            .headers()
            .get("x-amz-bucket-region")
            .filter(|r| valid_region(r))
        {
            region.to_owned()
        } else {
            // Smithy reads error bodies after the transmit interceptors, which
            // also cannot await a probe. Buffer only possible routing errors.
            if response.body().bytes().is_none() {
                let body = std::pin::pin!(response.take_body());
                let bytes = body
                    .collect()
                    .await
                    .map_err(|e| ConnectorError::other(e, None))?
                    .to_bytes();
                *response.body_mut() = bytes.into();
            }
            let (code, region) = error_fields(response.body().bytes().unwrap_or_default());
            if status == 400
                && !matches!(
                    code.as_deref()
                        .or_else(|| response.headers().get("x-amz-error-code")),
                    Some(
                        "AuthorizationHeaderMalformed"
                            | "AuthorizationQueryParametersError"
                            | "PermanentRedirect"
                            | "TemporaryRedirect"
                            | "EndpointNotFound"
                            | "IncorrectEndpoint"
                            | "IllegalLocationConstraintException"
                    )
                )
            {
                return Ok(());
            }
            if let Some(region) = region.filter(|r| valid_region(r)) {
                region
            } else if let Some(region) = self.corrected.get() {
                region.clone()
            } else {
                let region = self
                    .fallback
                    .get_or_init(|| async {
                        tokio::time::timeout(
                            Duration::from_secs(15),
                            bucket_region(&self.probe, &self.bucket),
                        )
                        .await
                        .ok()?
                        .ok()
                        .filter(|r| valid_region(r))
                    })
                    .await;
                let Some(region) = region else {
                    return Ok(());
                };
                region.clone()
            }
        };
        if region != request_region && self.corrected.get_or_init(|| region.clone()) == &region {
            response.add_extension(RegionRedirect);
        }
        Ok(())
    }
}

fn valid_region(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 63
        && region
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn error_fields(body: &[u8]) -> (Option<String>, Option<String>) {
    use aws_smithy_xml::decode::{try_data, Document};
    let Ok(xml) = std::str::from_utf8(body) else {
        return (None, None);
    };
    let mut document = Document::new(xml);
    let Ok(mut root) = document.root_element() else {
        return (None, None);
    };
    if !root.start_el().matches("Error") {
        return (None, None);
    }
    let (mut code, mut region) = (None, None);
    while let Some(mut field) = root.next_tag() {
        let field_value = match field.start_el().local() {
            "Code" => &mut code,
            "Region" => &mut region,
            _ => continue,
        };
        *field_value = try_data(&mut field)
            .ok()
            .map(|value| value.trim().to_owned());
    }
    (code, region)
}

#[derive(Debug)]
struct RedirectConnector {
    inner: SharedHttpConnector,
    lookup: Arc<RegionLookup>,
}

impl HttpConnector for RedirectConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let request_region = request.extension::<RequestRegion>().cloned();
        let response = self.inner.call(request);
        let Some(RequestRegion(region)) = request_region else {
            return response;
        };
        let lookup = self.lookup.clone();
        HttpConnectorFuture::new(async move {
            let mut response = response.await?;
            lookup.recover(&region, &mut response).await?;
            Ok(response)
        })
    }
}

#[derive(Clone, Debug)]
struct RegionRedirect;

impl ClassifyRetry for RegionRedirect {
    fn classify_retry(&self, context: &InterceptorContext) -> RetryAction {
        if context
            .response()
            .is_some_and(|r| r.extension::<Self>().is_some())
        {
            RetryAction::retryable_error_with_explicit_delay(
                aws_smithy_types::retry::ErrorKind::ClientError,
                Duration::ZERO,
            )
        } else {
            RetryAction::NoActionIndicated
        }
    }

    fn name(&self) -> &'static str {
        "S3 bucket region redirect"
    }

    fn priority(&self) -> RetryClassifierPriority {
        RetryClassifierPriority::run_after(
            RetryClassifierPriority::modeled_as_retryable_classifier(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_types::body::SdkBody;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    #[derive(Debug, Clone)]
    struct Bucket {
        calls: Arc<AtomicUsize>,
        status: u16,
        header: Option<&'static str>,
        body: &'static str,
        probe_region: Option<&'static str>,
    }

    impl HttpConnector for Bucket {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            self.calls.fetch_add(1, Relaxed);
            let uri = request.uri().split('?').next().unwrap();
            let authorization = request.headers().get("authorization").unwrap();
            let probe = request.method() == "HEAD" && uri.ends_with('/');
            let corrected = uri == "https://example-bucket.s3.eu-central-1.amazonaws.com/key";
            assert!(authorization.contains(if corrected {
                "/eu-central-1/s3/aws4_request"
            } else {
                "/us-east-1/s3/aws4_request"
            }));
            let (status, header, body) = if probe {
                assert_eq!(uri, "https://example-bucket.s3.us-east-1.amazonaws.com/");
                (403, self.probe_region, "")
            } else if corrected {
                (200, None, "")
            } else {
                assert_eq!(uri, "https://example-bucket.s3.us-east-1.amazonaws.com/key");
                (self.status, self.header, self.body)
            };
            let body = if body.is_empty() {
                SdkBody::empty()
            } else {
                SdkBody::from_body_1_x(http_body_util::Full::new(bytes::Bytes::from_static(
                    body.as_bytes(),
                )))
            };
            let mut response = HttpResponse::new(status.try_into().unwrap(), body);
            if let Some(region) = header {
                response.headers_mut().insert("x-amz-bucket-region", region);
            }
            response
                .headers_mut()
                .insert("location", "https://unrelated.example/key");
            HttpConnectorFuture::new(async { Ok(response) })
        }
    }

    async fn connect(bucket: Bucket) -> (Client, DiscoveredRegion) {
        let region = Region::new("us-east-1");
        let builder = Builder::new()
            .behavior_version_latest()
            .region(region.clone())
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(RetryConfig::disabled())
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(bucket.clone())
            }));
        let args = crate::cli::Args::parse_args(
            &["cp", "file", "--to", "s3://example-bucket", "--as", "key"]
                .map(std::ffi::OsString::from),
        )
        .unwrap();
        let (client, note, discovered) =
            connect_region(builder, &args.s3.unwrap(), Some(&region), false).await;
        assert!(note.is_none());
        (client, discovered.unwrap())
    }

    #[tokio::test]
    async fn region_redirect_resigns_once_even_with_transient_retries_disabled() {
        for status in [301, 302, 307, 400] {
            let calls = Arc::new(AtomicUsize::new(0));
            let (client, discovered) = connect(Bucket {
                calls: calls.clone(),
                status,
                header: Some("eu-central-1"),
                body: "",
                probe_region: None,
            })
            .await;
            assert_eq!(calls.load(Relaxed), 0);
            for count in [2, 3] {
                client
                    .head_object()
                    .bucket("example-bucket")
                    .key("key")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(calls.load(Relaxed), count);
            }
            assert_eq!(discovered.get().map(String::as_str), Some("eu-central-1"));
        }
    }

    #[tokio::test]
    async fn headerless_region_errors_read_the_body_and_probe_once_if_needed() {
        for (status, body, probe_region, success, requests) in [
            (400, "<Error><Code>AuthorizationHeaderMalformed</Code><Region>eu-central-1</Region></Error>", None, true, 2),
            (400, "<Error><Code>AuthorizationHeaderMalformed</Code></Error>", Some("eu-central-1"), true, 3),
            (307, "<Error><Code>TemporaryRedirect</Code></Error>", Some("eu-central-1"), true, 3),
            (400, "<Error><Code>IncorrectEndpoint</Code></Error>", Some("eu-central-1"), true, 3),
            (302, "", None, false, 2),
            (400, "<Error><Code>BadDigest</Code></Error>", Some("eu-central-1"), false, 1),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let (client, discovered) = connect(Bucket {
                calls: calls.clone(),
                status,
                header: None,
                body,
                probe_region,
            }).await;
            assert_eq!(calls.load(Relaxed), 0);
            for expected in [requests, requests + 1] {
                let response = client.get_object().bucket("example-bucket").key("key").send().await;
                assert_eq!(response.is_ok(), success, "{response:?}");
                assert_eq!(calls.load(Relaxed), expected, "{status} {body}");
            }
            assert_eq!(discovered.get().map(String::as_str), success.then_some("eu-central-1"));
        }
    }

    #[test]
    fn rebuilding_endpoint_params_changes_only_the_region() {
        let builder = Params::builder()
            .bucket("bucket")
            .endpoint("https://endpoint.example")
            .use_fips(true)
            .use_dual_stack(true)
            .force_path_style(true)
            .accelerate(true)
            .use_global_endpoint(true)
            .use_object_lambda_endpoint(true)
            .key("key")
            .prefix("prefix")
            .copy_source("source/key")
            .disable_access_points(true)
            .disable_multi_region_access_points(true)
            .use_arn_region(true)
            .use_s3_express_control_endpoint(true)
            .disable_s3_express_session_auth(true);
        let original = builder.clone().region("us-east-1").build().unwrap();
        assert_eq!(
            with_region(&original, "eu-central-1".to_owned()).unwrap(),
            builder.region("eu-central-1").build().unwrap()
        );
        // Params is non-exhaustive and its fields are private. Detect SDK
        // additions even when an added field defaults to the same value.
        assert_eq!(
            format!("{original:#?}")
                .lines()
                .filter(|line| {
                    line.strip_prefix("    ")
                        .is_some_and(|field| !field.starts_with(' ') && field.contains(": "))
                })
                .count(),
            17,
            "update the endpoint rebuild and fixture for the SDK's current fields"
        );
    }
}
