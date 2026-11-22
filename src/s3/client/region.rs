//! Retry a misdirected AWS request in the region returned by S3.
use super::*;
use aws_sdk_s3::config::{endpoint::Params, Builder};
use aws_smithy_runtime_api::client::{
    endpoint::EndpointResolverParams,
    interceptors::context::{
        BeforeDeserializationInterceptorContextMut, BeforeTransmitInterceptorContextRef,
    },
};

pub(super) fn allow_redirect(
    builder: Builder,
    bucket: &str,
    corrected: DiscoveredRegion,
) -> Builder {
    builder
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
        // Preserve the SDK's endpoint inputs, including FIPS, dual-stack,
        // and S3 Express options. The SDK resolves and signs the new request.
        let updated = Params::builder()
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
            .build()?;
        cfg.interceptor_state()
            .store_put(EndpointResolverParams::new(updated));
        Ok(())
    }

    fn modify_before_deserialization(
        &self,
        context: &mut BeforeDeserializationInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let response = context.response_mut();
        // AWS sends 301 PermanentRedirect or 400 AuthorizationHeaderMalformed
        // depending on the region and the request. Never use Location or an
        // endpoint from the response as a signing or transport destination.
        if !matches!(response.status().as_u16(), 301 | 400) {
            return Ok(());
        }
        let Some(params) = params(cfg).filter(|p| p.bucket() == Some(self.bucket.as_str())) else {
            return Ok(());
        };
        let Some(region) = response
            .headers()
            .get("x-amz-bucket-region")
            .filter(|region| {
                Some(*region) != params.region()
                    && !region.is_empty()
                    && region.len() <= 63
                    && region
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            })
        else {
            return Ok(());
        };
        if self.corrected.get_or_init(|| region.to_owned()) != region {
            return Ok(());
        }
        // Region correction also applies when transient retries are disabled.
        // Each operation can spend at most one extra attempt on it, since
        // later attempts use the cached region and cannot repeat this branch.
        if let Some(retry) = cfg.load::<RetryConfig>() {
            let retry = retry.clone().with_max_attempts(retry.max_attempts() + 1);
            cfg.interceptor_state().store_put(retry);
        }
        response.add_extension(RegionRedirect);
        Ok(())
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
    use aws_smithy_runtime_api::client::{
        http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
        orchestrator::{HttpRequest, HttpResponse},
    };
    use aws_smithy_types::body::SdkBody;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Debug, Clone)]
    struct Bucket(Arc<AtomicUsize>, u16);

    impl HttpConnector for Bucket {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            let position = self.0.fetch_add(1, Ordering::Relaxed);
            let initial = position == 0;
            assert_eq!(request.method(), "HEAD");
            assert!(request.uri().ends_with("/key"));
            let region = if initial { "us-east-1" } else { "eu-central-1" };
            if !initial {
                assert_eq!(
                    request.uri(),
                    "https://example-bucket.s3.eu-central-1.amazonaws.com/key"
                );
            }
            assert!(request
                .headers()
                .get("authorization")
                .unwrap()
                .contains(&format!("/{region}/s3/aws4_request")));
            let mut response = HttpResponse::new(
                (if initial { self.1 } else { 200 }).try_into().unwrap(),
                SdkBody::empty(),
            );
            response
                .headers_mut()
                .insert("x-amz-bucket-region", "eu-central-1");
            response
                .headers_mut()
                .insert("location", "https://unrelated.example/key");
            response.headers_mut().insert("etag", "\"fixture\"");
            HttpConnectorFuture::new(async { Ok(response) })
        }
    }

    #[tokio::test]
    async fn region_redirect_resigns_once_even_with_transient_retries_disabled() {
        for status in [301, 400] {
            let calls = Arc::new(AtomicUsize::new(0));
            let bucket = Bucket(calls.clone(), status);
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
            let options = args.s3.unwrap();
            let (client, note, discovered) =
                connect_region(builder, &options, Some(&region), false).await;
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            assert!(note.is_none());
            let discovered = discovered.unwrap();
            for count in [2, 3] {
                client
                    .head_object()
                    .bucket("example-bucket")
                    .key("key")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(calls.load(Ordering::Relaxed), count);
            }
            assert_eq!(discovered.get().map(String::as_str), Some("eu-central-1"));
        }
    }
}
