use super::{Header, Options};
use anyhow::{bail, Context, Result};
use aws_sdk_s3::{
    config::{retry::RetryConfig, timeout::TimeoutConfig, Region, RequestChecksumCalculation},
    Client,
};
use aws_smithy_runtime_api::{
    box_error::BoxError,
    client::{
        interceptors::{
            context::{
                BeforeDeserializationInterceptorContextRef,
                BeforeSerializationInterceptorContextRef, BeforeTransmitInterceptorContextMut,
                FinalizerInterceptorContextRef, InterceptorContext,
            },
            Intercept,
        },
        retries::classifiers::{ClassifyRetry, RetryAction, RetryClassifierPriority},
        runtime_components::RuntimeComponents,
    },
};
use aws_smithy_types::config_bag::ConfigBag;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

// The SDK retries throttling only by known error codes in an XML body. HEAD
// responses have no body, and some providers send HTTP 429 with other codes,
// so classify the status itself for every operation. A 429 response means the
// request was not processed, so a retry within the bounded budget is safe.
#[derive(Debug)]
pub(super) struct Throttling;
impl ClassifyRetry for Throttling {
    fn classify_retry(&self, context: &InterceptorContext) -> RetryAction {
        if let Some(response) = context.response().filter(|r| r.status().as_u16() == 429) {
            // R2 sends Retry-After seconds; the SDK only reads x-amz-retry-after.
            super::retry::server_delay(response)
                // A zero hint must not disable the SDK's normal backoff.
                .filter(|delay| !delay.is_zero())
                .map_or_else(RetryAction::throttling_error, |delay| {
                    RetryAction::retryable_error_with_explicit_delay(
                        aws_smithy_types::retry::ErrorKind::ThrottlingError,
                        delay,
                    )
                })
        } else {
            RetryAction::NoActionIndicated
        }
    }
    fn name(&self) -> &'static str {
        "S3 HTTP 429 throttling"
    }
    fn priority(&self) -> RetryClassifierPriority {
        // Run after AWS error-code and modeled-error classification so known
        // codes such as SlowDown cannot discard our Retry-After delay.
        RetryClassifierPriority::run_after(
            RetryClassifierPriority::modeled_as_retryable_classifier(),
        )
    }
}

/// Requests wrapped by their own retry loop run without SDK retries, so
/// `s3-retries` is one budget per request. Uploads need the loop because the
/// SDK cannot rewind a file body; downloads need it because a response body
/// can fail after the headers arrive. Every other request keeps SDK retries.
pub(super) fn without_sdk_retries() -> aws_sdk_s3::config::Builder {
    aws_sdk_s3::config::Builder::new()
        .retry_config(RetryConfig::disabled())
        .interceptor(OwnRetries)
}

/// Marks a request retried by syq's own loop, which reports its outcome to
/// the outage stop itself.
#[derive(Debug)]
struct OwnRetries;
impl aws_smithy_types::config_bag::Storable for OwnRetries {
    type Storer = aws_smithy_types::config_bag::StoreReplace<Self>;
}
impl Intercept for OwnRetries {
    fn name(&self) -> &'static str {
        "SyqOwnRetries"
    }
    fn read_before_execution(
        &self,
        _: &BeforeSerializationInterceptorContextRef<'_>,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        cfg.interceptor_state().store_put(OwnRetries);
        Ok(())
    }
}

/// Only establishing a connection has a deadline. Request headers, response
/// bodies, and pauses between bytes can all take arbitrarily long.
pub(super) fn request_timeouts() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(Duration::from_secs(15))
        .disable_read_timeout()
        .disable_operation_timeout()
        .disable_operation_attempt_timeout()
        .build()
}

/// Time HEAD and LIST responses to their headers. Each is one small exchange,
/// unlike data requests, whose duration follows their bodies. Only an answer
/// about the object or listing counts: errors and throttling describe the
/// service, and a redirect comes from a region that does not hold the bucket.
#[derive(Debug)]
struct ControlLatency(std::sync::Arc<std::sync::atomic::AtomicU64>);
#[derive(Debug)]
struct ControlStart(tokio::time::Instant);
impl aws_smithy_types::config_bag::Storable for ControlStart {
    type Storer = aws_smithy_types::config_bag::StoreReplace<Self>;
}
/// Report each SDK-retried request's final outcome. Requests marked by
/// `OwnRetries` are reported by syq's own retry loop instead.
#[derive(Debug)]
struct ObserveOutage(std::sync::Arc<super::outage::Outage>);
impl Intercept for ObserveOutage {
    fn name(&self) -> &'static str {
        "SyqS3Outage"
    }
    fn read_after_execution(
        &self,
        context: &FinalizerInterceptorContextRef<'_>,
        components: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        if cfg.load::<OwnRetries>().is_some() {
            return Ok(());
        }
        if context.output_or_error().is_some_and(|r| r.is_ok()) {
            self.0.responded();
        } else {
            // Classify the final error as the SDK's retry strategy does.
            let action = aws_smithy_runtime::client::retries::classifiers::run_classifiers_on_ctx(
                components.retry_classifiers(),
                context.inner(),
            );
            self.0
                .failed(matches!(action, RetryAction::RetryIndicated(_)));
        }
        Ok(())
    }
}

impl Intercept for ControlLatency {
    fn name(&self) -> &'static str {
        "SyqS3ControlLatency"
    }
    fn modify_before_transmit(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let request = context.request();
        if request.method() == "HEAD"
            || (request.method() == "GET" && request.uri().contains("list-type="))
        {
            cfg.interceptor_state()
                .store_put(ControlStart(tokio::time::Instant::now()));
        }
        Ok(())
    }
    fn read_after_transmit(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let status = context.response().status().as_u16();
        if let Some(ControlStart(start)) = cfg.load::<ControlStart>() {
            if (200..300).contains(&status) || status == 404 {
                super::tuning::observe_control(&self.0, start.elapsed());
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Headers {
    every: Vec<Header>,
    write: Vec<Header>,
}
impl Intercept for Headers {
    fn name(&self) -> &'static str {
        "SyqS3Headers"
    }
    fn modify_before_transmit(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        if let Some(attempt) = super::diagnostics::request(context.request_mut()) {
            cfg.interceptor_state().store_put(attempt);
        }
        Ok(())
    }
    fn read_after_transmit(
        &self,
        context: &BeforeDeserializationInterceptorContextRef<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        if let Some(attempt) = cfg.load::<super::diagnostics::Attempt>() {
            super::diagnostics::response(attempt, context.response().status().as_u16());
        }
        Ok(())
    }
    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let request = context.request_mut();
        let url = url::Url::parse(request.uri())?;
        let query = url.query_pairs().map(|(key, _)| key).collect::<Vec<_>>();
        let method = request.method().to_owned();
        for Header(name, value) in super::applicable_headers(
            &self.every,
            &self.write,
            &method,
            query.iter().map(|key| key.as_ref()),
        ) {
            request
                .headers_mut()
                .try_insert(name.clone(), value.clone())?;
        }
        let request = context.request();
        if request.method() == "PUT" {
            if let Some(checksum) = request.headers().get("x-amz-checksum-sha256") {
                let multipart = query.iter().any(|key| key == "uploadId");
                if let Some(hash) =
                    super::checksum::single_put_payload("PUT", multipart, Some(checksum))?
                {
                    cfg.interceptor_state()
                        .store_put(aws_runtime::auth::PayloadSigningOverride::Precomputed(hash));
                }
            }
        }
        Ok(())
    }
}

/// S3 names a bucket's region on every response, including the redirect or
/// denial that a request sent to the wrong region receives.
fn response_region(
    response: Option<&aws_smithy_runtime_api::client::orchestrator::HttpResponse>,
) -> Option<String> {
    response?
        .headers()
        .get("x-amz-bucket-region")
        .map(str::to_owned)
}

#[derive(Debug)]
pub(super) struct RequestFailure {
    operation: String,
    status: Option<u16>,
    region: Option<String>,
}
impl RequestFailure {
    pub(super) fn region_mismatch(&self) -> bool {
        self.status == Some(301) && self.region.is_some()
    }
}
impl std::fmt::Display for RequestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed", self.operation)?;
        if let Some(status) = self.status {
            write!(f, " (HTTP {status})")?;
        }
        if let (Some(301), Some(region)) = (self.status, &self.region) {
            write!(
                f,
                ": the bucket is in region {region}; pass --s3-region {region} or set AWS_REGION"
            )?;
        }
        Ok(())
    }
}

/// Preserve structured region information for the two-endpoint copy diagnostic.
pub(super) fn failure<E>(
    operation: &str,
    error: &aws_sdk_s3::error::SdkError<
        E,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
) -> RequestFailure {
    RequestFailure {
        operation: operation.into(),
        status: error.raw_response().map(|r| r.status().as_u16()),
        region: response_region(error.raw_response()),
    }
}

/// Every listing reports failures the same way. A named source is looked up
/// with a HEAD and a listing at once, and either one may be the first to fail.
fn listing_failure(
    error: aws_sdk_s3::error::SdkError<
        aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
) -> anyhow::Error {
    let message = failure("S3 listing", &error);
    anyhow::Error::new(error.into_service_error()).context(message)
}

/// Whether to ask S3 for the bucket's region before copying. A custom
/// endpoint already identifies its provider's storage and is never probed.
fn looks_up_region(explicit_region: Option<&str>, custom_endpoint: Option<&str>) -> bool {
    explicit_region.is_none() && custom_endpoint.is_none()
}

/// Ask S3 where a bucket is. Any response carries the answer, so this needs
/// no permission on the bucket. The error says why there was no answer.
async fn bucket_region(client: &Client, bucket: &str) -> std::result::Result<String, String> {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(output) => output
            .bucket_region()
            .map(str::to_owned)
            .ok_or_else(|| "the response did not name a region".to_owned()),
        Err(error) => response_region(error.raw_response()).ok_or_else(|| {
            aws_smithy_types::error::display::DisplayErrorContext(&error).to_string()
        }),
    }
}

/// Also returns a note for verbose output when the region lookup got no answer.
pub(super) async fn connect(
    options: &mut Options,
    control: std::sync::Arc<std::sync::atomic::AtomicU64>,
    uploads: std::sync::Arc<super::upload_http::Cancellation>,
) -> Result<(Client, Option<String>)> {
    connect_authorized(options, control, uploads, None, None).await
}

pub(super) async fn connect_authorized(
    options: &mut Options,
    control: std::sync::Arc<std::sync::atomic::AtomicU64>,
    uploads: std::sync::Arc<super::upload_http::Cancellation>,
    authorization: Option<std::sync::Arc<super::authorization::Authorization>>,
    outage: Option<std::sync::Arc<super::outage::Outage>>,
) -> Result<(Client, Option<String>)> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(profile) = &options.profile {
        loader = loader.profile_name(profile);
    }
    if let Some(region) = &options.region {
        loader = loader.region(Region::new(region.clone()));
    }
    let shared = if let Some(authorization) = &authorization {
        options.endpoint = Some(authorization.configuration.endpoint.clone());
        options.region = Some(authorization.configuration.region.clone());
        aws_types::SdkConfig::builder()
            .region(Region::new(authorization.configuration.region.clone()))
            .credentials_provider(
                aws_credential_types::provider::SharedCredentialsProvider::new(
                    aws_credential_types::Credentials::new(
                        "syq-delegated",
                        "unused",
                        None,
                        None,
                        "delegated-storage",
                    ),
                ),
            )
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build()
    } else {
        loader.load().await
    };
    let transport = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
        ))
        .build_with_resolver(super::dns::CoalescingDns::default());
    let transport = super::upload_http::client(transport, uploads);
    let transport = match authorization {
        Some(authorization) => super::authorization::http_client(transport, authorization),
        None => transport,
    };
    let mut config = aws_sdk_s3::config::Builder::from(&shared)
        .http_client(transport)
        .region(
            shared
                .region()
                .cloned()
                .unwrap_or_else(|| Region::new("us-east-1")),
        )
        .retry_config(RetryConfig::standard().with_max_attempts(options.retries + 1))
        .retry_partition(super::retry::partition())
        .retry_classifier(Throttling)
        .timeout_config(request_timeouts())
        .stalled_stream_protection(aws_sdk_s3::config::StalledStreamProtectionConfig::disabled())
        // Explicit payload checksums avoid aws-chunked trailers, which several
        // S3-compatible services do not implement. Downloads retain SDK checks.
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .interceptor(Headers {
            every: options.headers.clone(),
            write: options.write_headers.clone(),
        })
        .interceptor(ControlLatency(control));
    if let Some(outage) = outage {
        config = config.interceptor(ObserveOutage(outage));
    }

    let endpoint = options
        .endpoint
        .clone()
        .or_else(|| std::env::var("AWS_ENDPOINT_URL_S3").ok())
        .or_else(|| std::env::var("AWS_ENDPOINT_URL").ok());
    // Resolve service-profile endpoints before the profile-wide fallback, just
    // as the SDK does. The recovery identity must name the same provider that
    // receives requests, including when two profiles use the same bucket/key.
    let endpoint = endpoint
        .or_else(|| {
            shared.service_config().and_then(|service| {
                service.load_config(
                    aws_types::service_config::ServiceConfigKey::builder()
                        .service_id("S3")
                        .env("AWS_ENDPOINT_URL")
                        .profile("endpoint_url")
                        .build()
                        .expect("all service configuration key fields are set"),
                )
            })
        })
        .or_else(|| shared.endpoint_url().map(str::to_owned));
    options.endpoint = endpoint.clone();
    let mut note = None;
    let lookup = looks_up_region(options.region.as_deref(), endpoint.as_deref());
    if let Some(endpoint) = endpoint {
        super::validate_endpoint(&endpoint)?;
        config = config.endpoint_url(endpoint).force_path_style(true);
    }
    if lookup {
        // AWS serves each bucket from one region and redirects requests sent
        // elsewhere. A region from the environment or a profile is the
        // account's default, not a fact about this bucket, so it only chooses
        // where to ask. `--s3-region` is a statement about the bucket and is
        // used as given.
        let hint = shared
            .region()
            .map_or("us-east-1", |r| r.as_ref())
            .to_owned();
        let probe = Client::from_conf(config.clone().build());
        match bucket_region(&probe, &options.bucket).await {
            Ok(region) => config = config.region(Region::new(region)),
            Err(reason) => {
                note = Some(format!(
                    "could not look up the bucket's region, signing for {hint}: {reason}"
                ))
            }
        }
    }
    Ok((Client::from_conf(config.build()), note))
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(super) enum ObjectKind {
    File,
    Dir,
    Symlink,
}
impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
        }
    }
}

impl std::str::FromStr for ObjectKind {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "file" => Ok(Self::File),
            "dir" => Ok(Self::Dir),
            "symlink" => Ok(Self::Symlink),
            _ => bail!("unsupported syq object kind"),
        }
    }
}

/// Version 1 is an ordinary object body plus this small metadata record.
/// Other tools can read regular-file contents without understanding syq.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Metadata {
    pub kind: ObjectKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub nsec: u32,
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "is_blake3")]
    pub hash_algorithm: crate::hashing::HashAlgorithm,
}
fn is_blake3(algorithm: &crate::hashing::HashAlgorithm) -> bool {
    *algorithm == crate::hashing::HashAlgorithm::Blake3
}
impl Metadata {
    pub(super) fn override_with(&mut self, metadata: &crate::mapping::Metadata) {
        let mut meta = crate::proto::Meta {
            inode_metadata: None,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
            mtime_nsec: self.nsec,
        };
        metadata.apply(&mut meta);
        self.mode = meta.mode;
        self.uid = meta.uid;
        self.gid = meta.gid;
        self.mtime = meta.mtime;
        self.nsec = meta.mtime_nsec;
    }

    pub fn encode(&self) -> HashMap<String, String> {
        let mut values = HashMap::from([
            (
                "syq-format".into(),
                if self.hash.is_some() && !is_blake3(&self.hash_algorithm) {
                    "2"
                } else {
                    "1"
                }
                .into(),
            ),
            ("syq-kind".into(), self.kind.as_str().into()),
            ("syq-mode".into(), self.mode.to_string()),
            ("syq-uid".into(), self.uid.to_string()),
            ("syq-gid".into(), self.gid.to_string()),
            ("syq-mtime".into(), self.mtime.to_string()),
            ("syq-mtime-nsec".into(), self.nsec.to_string()),
        ]);
        if let Some(hash) = &self.hash {
            if is_blake3(&self.hash_algorithm) {
                values.insert("syq-blake3".into(), hash.clone());
            } else {
                values.insert(
                    "syq-hash-algorithm".into(),
                    self.hash_algorithm.as_str().into(),
                );
                values.insert("syq-hash".into(), hash.clone());
            }
        }
        values
    }
    pub fn decode(values: Option<&HashMap<String, String>>) -> Result<Option<Self>> {
        let Some(values) = values else {
            return Ok(None);
        };
        let Some(version) = values.get("syq-format") else {
            return Ok(None);
        };
        if version != "1" && version != "2" {
            bail!("unsupported syq object metadata version {version}; use a syq version that supports this format");
        }
        let get = |name| {
            values
                .get(name)
                .with_context(|| format!("missing object metadata {name}"))
        };
        let kind = get("syq-kind")?.parse()?;
        let result = Self {
            kind,
            mode: get("syq-mode")?.parse()?,
            uid: get("syq-uid")?.parse()?,
            gid: get("syq-gid")?.parse()?,
            mtime: get("syq-mtime")?.parse()?,
            nsec: get("syq-mtime-nsec")?.parse()?,
            hash: if version == "1" {
                values.get("syq-blake3").cloned()
            } else {
                Some(get("syq-hash")?.clone())
            },
            hash_algorithm: if version == "1" {
                crate::hashing::HashAlgorithm::Blake3
            } else {
                serde_json::from_value(serde_json::Value::String(
                    get("syq-hash-algorithm")?.clone(),
                ))?
            },
        };
        if result.nsec >= 1_000_000_000 || result.mode > 0o7777 {
            bail!("invalid syq object metadata");
        }
        if let Some(hash) = &result.hash {
            let digest = crate::hashing::Digest {
                algorithm: result.hash_algorithm,
                value: hash.clone(),
            };
            digest.validate().context("invalid syq object digest")?;
        }
        Ok(Some(result))
    }
}

#[derive(Clone, Debug)]
pub(super) struct Object {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub version: Option<String>,
    pub metadata: Option<Metadata>,
    pub mtime: i64,
}
pub(super) fn is_directory_marker(key: &str, size: u64) -> bool {
    size == 0 && key.ends_with('/')
}

/// syq stores directories only as markers, and files and symlinks never under
/// marker-shaped keys. Listings rely on this to classify markers without HEAD.
fn check_marker_kind(key: &str, size: u64, metadata: Option<&Metadata>) -> Result<()> {
    match (metadata.map(|m| m.kind), is_directory_marker(key, size)) {
        (Some(ObjectKind::Dir), false) => bail!("invalid syq directory marker"),
        (Some(kind @ (ObjectKind::File | ObjectKind::Symlink)), true) => {
            bail!(
                "invalid syq {} object under directory-marker key {key}",
                kind.as_str()
            )
        }
        _ => Ok(()),
    }
}

impl Object {
    pub(super) fn expression_file(&self) -> crate::expression::File {
        crate::expression::File {
            exists: true,
            kind: Some(match self.kind() {
                ObjectKind::File => crate::proto::Kind::File,
                ObjectKind::Dir => crate::proto::Kind::Dir,
                ObjectKind::Symlink => crate::proto::Kind::Symlink,
            }),
            size: Some(self.size),
            mtime: self.metadata.as_ref().map(|m| (m.mtime, m.nsec)),
            s3_last_modified: Some((self.mtime, 0)),
            mode: self.metadata.as_ref().map(|m| m.mode & 0o7777),
            uid: self.metadata.as_ref().map(|m| m.uid),
            gid: self.metadata.as_ref().map(|m| m.gid),
            ..Default::default()
        }
    }
    pub fn kind(&self) -> ObjectKind {
        self.metadata.as_ref().map_or(
            if is_directory_marker(&self.key, self.size) {
                ObjectKind::Dir
            } else {
                ObjectKind::File
            },
            |m| m.kind,
        )
    }
}

pub(super) async fn head(client: &Client, bucket: &str, key: &str) -> Result<Option<Object>> {
    head_output(client, bucket, key, None)
        .await?
        .map(|output| from_head(key, &output))
        .transpose()
}

/// Read metadata, optionally probing checksum support for server-copy comparisons.
/// Admission is controlled by the caller so ordinary HEAD behavior is unchanged.
pub(super) async fn head_output(
    client: &Client,
    bucket: &str,
    key: &str,
    unsupported: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Option<aws_sdk_s3::operation::head_object::HeadObjectOutput>> {
    use aws_sdk_s3::types::ChecksumMode;
    use std::sync::atomic::Ordering::Relaxed;
    let request = client.head_object().bucket(bucket).key(key);
    let checksums = unsupported.is_some_and(|flag| !flag.load(Relaxed));
    let result = if checksums {
        request
            .clone()
            .checksum_mode(ChecksumMode::Enabled)
            .send()
            .await
    } else {
        request.clone().send().await
    };
    let result = match result {
        Err(e)
            if checksums
                && e.raw_response()
                    .is_some_and(|r| matches!(r.status().as_u16(), 400 | 403 | 501)) =>
        {
            // Only NotImplemented establishes an unsupported capability. Generic
            // bad requests and access denials can depend on the object or request.
            if e.raw_response().is_some_and(|r| r.status().as_u16() == 501) {
                if let Some(flag) = unsupported {
                    flag.store(true, Relaxed);
                }
            }
            request.send().await
        }
        result => result,
    };
    match result {
        Ok(output) => Ok(Some(output)),
        Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404) => Ok(None),
        Err(e) => {
            let operation = if unsupported.is_some() {
                "S3 copy HEAD"
            } else {
                "S3 HEAD"
            };
            let detail = failure(operation, &e);
            Err(anyhow::Error::new(e.into_service_error()).context(detail))
        }
    }
}

pub(super) fn from_head(
    key: &str,
    output: &aws_sdk_s3::operation::head_object::HeadObjectOutput,
) -> Result<Object> {
    let size = u64::try_from(
        output
            .content_length()
            .context("S3 HEAD omitted Content-Length")?,
    )?;
    let etag = output.e_tag().context("S3 HEAD omitted ETag")?.to_owned();
    let metadata = Metadata::decode(output.metadata())?;
    check_marker_kind(key, size, metadata.as_ref())?;
    Ok(Object {
        key: key.to_owned(),
        size,
        etag,
        version: output.version_id().map(str::to_owned),
        metadata,
        mtime: output.last_modified().map_or(0, |t| t.secs()),
    })
}

/// Existence needs only one object, regardless of the size of the prefix.
pub(super) async fn prefix_exists(client: &Client, bucket: &str, prefix: &str) -> Result<bool> {
    let output = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .max_keys(1)
        .send()
        .await
        .map_err(listing_failure)?;
    anyhow::ensure!(
        !output.contents().is_empty() || output.is_truncated() != Some(true),
        "S3 existence listing was truncated without an object"
    );
    Ok(!output.contents().is_empty())
}

/// Bound destination discovery by the size of the upload. An incomplete listing
/// cannot prove that an upload key is absent, so leave those decisions to HEAD.
pub(super) async fn upload_listing(
    client: &Client,
    bucket: &str,
    prefix: &str,
    source_keys: &std::collections::HashSet<&str>,
) -> Result<Option<std::collections::HashMap<String, u64>>> {
    let mut keys = std::collections::HashMap::new();
    let mut token = None;
    // Never spend as many LIST requests as checking each source with HEAD.
    // Retain only relevant keys so a large destination cannot grow the cache.
    for _ in 0..source_keys.len().saturating_sub(1) {
        let output = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix)
            .set_continuation_token(token.clone())
            .send()
            .await
            .map_err(listing_failure)?;
        for object in output.contents() {
            let key = object.key().context("S3 listing omitted key")?;
            anyhow::ensure!(
                key.starts_with(prefix),
                "S3 listing returned a key outside the requested prefix"
            );
            if source_keys.contains(key) {
                let size = u64::try_from(object.size().context("S3 listing omitted size")?)?;
                keys.insert(key.to_owned(), size);
            }
        }
        if output.is_truncated() != Some(true) || keys.len() == source_keys.len() {
            return Ok(Some(keys));
        }
        let next = output
            .next_continuation_token()
            .context("truncated S3 listing omitted continuation token")?
            .to_owned();
        if token.as_ref() == Some(&next) {
            bail!("S3 listing repeated its continuation token");
        }
        token = Some(next);
    }
    Ok(None)
}

/// The first excluded ancestor is the boundary a filesystem walk would prune.
/// Keep that boundary rather than counting every descendant in a flat S3 page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exclusion<'a> {
    File,
    Subtree(&'a str),
}

impl Exclusion<'_> {
    pub(super) fn count(self, subtrees: &mut std::collections::HashSet<String>) -> u64 {
        match self {
            Self::File => 1,
            Self::Subtree(path) if subtrees.contains(path) => 0,
            Self::Subtree(path) => {
                subtrees.insert(path.to_owned());
                1
            }
        }
    }
}

pub(super) fn exclusion<'a>(
    matcher: Option<&ignore::gitignore::Gitignore>,
    prefix: &str,
    key: &'a str,
    directory: bool,
    known_subtrees: &std::collections::HashSet<String>,
) -> Option<Exclusion<'a>> {
    let matcher = matcher?;
    let relative = key.strip_prefix(prefix)?;
    let relative = if directory {
        relative.trim_end_matches('/')
    } else {
        relative
    };
    // A selected prefix and its ancestors are never filtered.
    if relative.is_empty() {
        return None;
    }
    let key = if directory {
        key.trim_end_matches('/')
    } else {
        key
    };
    // These boundaries were already classified under the same rules. Reuse
    // them for adjacent objects rather than rematching a deep parent chain.
    if directory && known_subtrees.contains(key) {
        return Some(Exclusion::Subtree(key));
    }
    if let Some((parent, _)) = key.rsplit_once('/') {
        if known_subtrees.contains(parent) {
            return Some(Exclusion::Subtree(parent));
        }
    }
    for (separator, _) in relative.match_indices('/') {
        let ancestor = &relative[..separator];
        if !ancestor.is_empty() && matcher.matched(ancestor, true).is_ignore() {
            return Some(Exclusion::Subtree(&key[..prefix.len() + separator]));
        }
    }
    if matcher.matched(relative, directory).is_ignore() {
        Some(if directory {
            Exclusion::Subtree(key)
        } else {
            Exclusion::File
        })
    } else {
        None
    }
}

pub(super) struct Listing {
    objects: ListingObjects,
    pub found: bool,
    pub excluded: u64,
}

type TimedListingObject = (String, u64, Option<(i64, u32)>);

// Store timestamps with their keys when requested. Plain listings retain the
// compact pair representation and pay no per-object cost for unused times.
enum ListingObjects {
    Plain(Vec<(String, u64)>),
    Timed(Vec<TimedListingObject>),
}
impl ListingObjects {
    fn new(retain_times: bool) -> Self {
        if retain_times {
            Self::Timed(Vec::new())
        } else {
            Self::Plain(Vec::new())
        }
    }
    fn push(&mut self, key: String, size: u64, time: Option<(i64, u32)>) {
        match self {
            Self::Plain(objects) => objects.push((key, size)),
            Self::Timed(objects) => objects.push((key, size, time)),
        }
    }
    fn clear(&mut self) {
        match self {
            Self::Plain(objects) => objects.clear(),
            Self::Timed(objects) => objects.clear(),
        }
    }
    fn is_empty(&self) -> bool {
        match self {
            Self::Plain(objects) => objects.is_empty(),
            Self::Timed(objects) => objects.is_empty(),
        }
    }
    fn sort(&mut self) {
        match self {
            Self::Plain(objects) => objects.sort_unstable_by(|a, b| a.0.cmp(&b.0)),
            Self::Timed(objects) => objects.sort_unstable_by(|a, b| a.0.cmp(&b.0)),
        }
    }
}
impl Listing {
    pub fn into_objects(self) -> Vec<(String, u64)> {
        match self.objects {
            ListingObjects::Plain(objects) => objects,
            ListingObjects::Timed(objects) => objects
                .into_iter()
                .map(|(key, size, _)| (key, size))
                .collect(),
        }
    }
    pub fn into_entries(self) -> impl Iterator<Item = TimedListingObject> {
        let (plain, timed) = match self.objects {
            ListingObjects::Plain(objects) => (objects, Vec::new()),
            ListingObjects::Timed(objects) => (Vec::new(), objects),
        };
        plain
            .into_iter()
            .map(|(key, size)| (key, size, None))
            .chain(timed)
    }
}

/// Reuse the bounded recursive planner for existing literal-prefix operations.
/// Filtered copies retain the exclusion-directed lookahead below: it can prune
/// an ignored subtree without enumerating or interpreting its descendants.
async fn parallel_listing(
    client: &Client,
    bucket: &str,
    prefix: &str,
    concurrency: usize,
    retain_times: bool,
) -> Result<Listing> {
    use super::listing::engine::{self, Entry, Page, Store};
    struct S3<'a> {
        client: &'a Client,
        bucket: &'a str,
        root: &'a str,
        retain_times: bool,
        discovery_denied: std::sync::atomic::AtomicBool,
    }
    impl Store for S3<'_> {
        fn ordered(&self) -> bool {
            // Directory buckets do not promise lexicographic LIST order.
            !self.bucket.ends_with("--x-s3")
        }

        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            start_after: Option<&str>,
        ) -> Result<Page> {
            let response = self
                .client
                .list_objects_v2()
                .bucket(self.bucket)
                .prefix(prefix)
                .max_keys(1000)
                .set_delimiter(delimiter.then(|| "/".into()))
                .set_continuation_token(token.map(str::to_owned))
                .set_start_after(start_after.map(str::to_owned))
                .send()
                .await
                .map_err(|error| {
                    if (delimiter || prefix != self.root)
                        && error
                            .raw_response()
                            .is_some_and(|response| response.status().as_u16() == 403)
                    {
                        self.discovery_denied
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    listing_failure(error)
                })?;
            // Preserve this path's existing SDK decoding and failure context.
            // Transfer metadata still comes from HEAD/GET, not LIST.
            let entries = response
                .contents()
                .iter()
                .map(|object| {
                    Ok(Entry {
                        key: object.key().context("S3 listing omitted key")?.to_owned(),
                        size: u64::try_from(object.size().context("S3 listing omitted size")?)?,
                        last_modified: if self.retain_times {
                            object
                                .last_modified()
                                .map(|t| t.fmt(aws_smithy_types::date_time::Format::DateTime))
                                .transpose()?
                        } else {
                            None
                        },
                        etag: None,
                    })
                })
                .collect::<Result<_>>()?;
            let prefixes = response
                .common_prefixes()
                .iter()
                .map(|child| {
                    Ok(child
                        .prefix()
                        .context("S3 listing omitted common prefix")?
                        .to_owned())
                })
                .collect::<Result<_>>()?;
            let next = if response.is_truncated() == Some(true) {
                Some(
                    response
                        .next_continuation_token()
                        .context("truncated S3 listing omitted continuation token")?
                        .to_owned(),
                )
            } else {
                None
            };
            Ok(Page {
                entries,
                prefixes,
                next,
            })
        }
    }
    let mut objects = ListingObjects::new(retain_times);
    let store = S3 {
        client,
        bucket,
        root: prefix,
        retain_times,
        discovery_denied: std::sync::atomic::AtomicBool::new(false),
    };
    let collect = |objects: &mut ListingObjects, entry: Entry| -> Result<()> {
        let time = entry
            .last_modified
            .as_deref()
            .map(|value| {
                aws_smithy_types::DateTime::from_str(
                    value,
                    aws_smithy_types::date_time::Format::DateTime,
                )
                .map(|time| (time.secs(), time.subsec_nanos()))
            })
            .transpose()?;
        objects.push(entry.key, entry.size, time);
        Ok(())
    };
    let outcome = engine::enumerate_prefix(&store, prefix, concurrency.min(32), |entry| {
        collect(&mut objects, entry)
    })
    .await;
    if let Err(error) = outcome {
        if !store
            .discovery_denied
            .load(std::sync::atomic::Ordering::Relaxed)
            || error
                .downcast_ref::<RequestFailure>()
                .is_none_or(|failure| failure.status != Some(403))
        {
            return Err(error);
        }
        // Exact-prefix IAM policies can permit the original LIST while denying
        // discovery or child prefixes. No caller has consumed the plan yet.
        objects.clear();
        engine::enumerate_prefix(&store, prefix, 1, |entry| collect(&mut objects, entry)).await?;
    }
    // Previously LIST delivered keys in order. Preserve planning/claim order
    // for callers despite concurrent subtree completion.
    objects.sort();
    Ok(Listing {
        found: !objects.is_empty(),
        objects,
        excluded: 0,
    })
}

/// Keep flat listings for small trees and filename filters. Only switch to
/// directory discovery when the first full page contains only excluded descendants.
/// A complete directory probe can prune children or descend through a single
/// included child toward excluded descendants. Limit probes to four per source
/// selector: deep chains must not turn a flat listing into an unbounded walk.
/// Wide or truncated probes reuse the flat sample instead of fanning out.
pub(super) async fn list(
    client: &Client,
    bucket: &str,
    prefix: &str,
    matcher: Option<&ignore::gitignore::Gitignore>,
    excluded_subtrees: &mut std::collections::HashSet<String>,
    concurrency: usize,
) -> Result<Listing> {
    list_with_times(
        client,
        bucket,
        prefix,
        matcher,
        excluded_subtrees,
        concurrency,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn list_with_times(
    client: &Client,
    bucket: &str,
    prefix: &str,
    matcher: Option<&ignore::gitignore::Gitignore>,
    excluded_subtrees: &mut std::collections::HashSet<String>,
    concurrency: usize,
    retain_times: bool,
) -> Result<Listing> {
    if matcher.is_none() {
        return parallel_listing(client, bucket, prefix, concurrency, retain_times).await;
    }
    let mut result = Listing {
        objects: ListingObjects::new(retain_times),
        found: false,
        excluded: 0,
    };
    let mut probes_remaining = 4;
    let mut pending = vec![prefix.to_owned()];
    while let Some(current) = pending.pop() {
        let mut token = None;
        loop {
            let mut directories = false;
            let mut output = client
                .list_objects_v2()
                .bucket(bucket)
                .prefix(&current)
                .set_continuation_token(token.clone())
                .send()
                .await
                .map_err(listing_failure)?;
            result.found |= !output.contents().is_empty() || !output.common_prefixes().is_empty();
            let mut reachable_exclusion = false;
            if probes_remaining > 0
                && token.is_none()
                && output.is_truncated() == Some(true)
                && !output.contents().is_empty()
                && output.contents().iter().all(|object| {
                    object.key().is_some_and(|key| {
                        if let Some(Exclusion::Subtree(boundary)) = exclusion(
                            matcher,
                            prefix,
                            key,
                            object.size() == Some(0) && key.ends_with('/'),
                            excluded_subtrees,
                        ) {
                            reachable_exclusion |=
                                boundary.strip_prefix(&current).is_some_and(|relative| {
                                    relative.bytes().filter(|byte| *byte == b'/').count()
                                        < probes_remaining
                                });
                            true
                        } else {
                            false
                        }
                    })
                })
                && reachable_exclusion
            {
                let mut probe_prefix = current.clone();
                let mut parent_objects = Vec::new();
                while probes_remaining > 0 {
                    probes_remaining -= 1;
                    let mut directory_page = client
                        .list_objects_v2()
                        .bucket(bucket)
                        .prefix(&probe_prefix)
                        .delimiter("/")
                        .send()
                        .await
                        .map_err(listing_failure)?;
                    let mut included = 0;
                    let mut excluded = 0;
                    for child in directory_page.common_prefixes() {
                        let child = child.prefix().context("S3 listing omitted common prefix")?;
                        anyhow::ensure!(
                            child.starts_with(&probe_prefix)
                                && child.len() > probe_prefix.len()
                                && child.ends_with('/'),
                            "S3 listing returned an invalid common prefix"
                        );
                        if exclusion(matcher, prefix, child, true, excluded_subtrees).is_some() {
                            excluded += 1;
                        } else {
                            included += 1;
                        }
                    }
                    if directory_page.is_truncated() == Some(true) || included > 1 {
                        break;
                    }
                    for object in directory_page.contents() {
                        anyhow::ensure!(
                            object
                                .key()
                                .context("S3 listing omitted key")?
                                .starts_with(&probe_prefix),
                            "S3 listing returned a key outside the requested prefix"
                        );
                    }
                    if excluded > 0 {
                        // Commit the lookahead only once it actually prunes.
                        // Ancestor objects and this page replace the sample;
                        // intermediate prefixes have already been visited.
                        parent_objects.extend(directory_page.contents.take().unwrap_or_default());
                        directory_page.contents = Some(parent_objects);
                        output = directory_page;
                        directories = true;
                        break;
                    }
                    if included == 0 {
                        break;
                    }
                    // Every sampled object was under an excluded ancestor and
                    // this page has just one child. Follow that child without
                    // refetching the same flat sample at each directory level.
                    probe_prefix = directory_page.common_prefixes()[0]
                        .prefix()
                        .context("S3 listing omitted common prefix")?
                        .to_owned();
                    parent_objects.extend(directory_page.contents.take().unwrap_or_default());
                }
                // If the budget or a wide page stopped lookahead, the original
                // flat sample and its continuation token are still usable.
            }
            for object in output.contents() {
                let key = object.key().context("S3 listing omitted key")?;
                anyhow::ensure!(
                    key.starts_with(&current),
                    "S3 listing returned a key outside the requested prefix"
                );
                let size = u64::try_from(object.size().context("S3 listing omitted size")?)?;
                let directory = is_directory_marker(key, size);
                if let Some(excluded) =
                    exclusion(matcher, prefix, key, directory, excluded_subtrees)
                {
                    // A filename-only exclusion still encounters the key and
                    // preserves its path validation. Pruned descendants do not.
                    if excluded == Exclusion::File {
                        super::local::key_path(key.as_bytes())?;
                    }
                    result.excluded += excluded.count(excluded_subtrees);
                } else {
                    let time = if retain_times {
                        object
                            .last_modified()
                            .map(|time| (time.secs(), time.subsec_nanos()))
                    } else {
                        None
                    };
                    result.objects.push(key.to_owned(), size, time);
                }
            }
            for child in output.common_prefixes() {
                let child = child.prefix().context("S3 listing omitted common prefix")?;
                anyhow::ensure!(
                    directories
                        && child.starts_with(&current)
                        && child.len() > current.len()
                        && child.ends_with('/'),
                    "S3 listing returned an invalid common prefix"
                );
                if let Some(excluded) = exclusion(matcher, prefix, child, true, excluded_subtrees) {
                    result.excluded += excluded.count(excluded_subtrees);
                } else {
                    pending.push(child.to_owned());
                }
            }
            if output.is_truncated() != Some(true) {
                break;
            }
            let next = output
                .next_continuation_token()
                .context("truncated S3 listing omitted continuation token")?
                .to_owned();
            if token.as_ref() == Some(&next) {
                bail!("S3 listing repeated its continuation token");
            }
            token = Some(next);
        }
    }
    Ok(result)
}

// GET metadata is authoritative for the body returned by that same request.
pub(super) fn from_get(
    key: &str,
    size: u64,
    part_size: u64,
    output: &aws_sdk_s3::operation::get_object::GetObjectOutput,
) -> Result<Object> {
    let range = (size > part_size).then(|| format!("bytes 0-{}/{}", part_size - 1, size));
    if output.content_length() != Some(size.min(part_size) as i64)
        || output.content_range() != range.as_deref()
    {
        bail!("S3 object size changed after listing or GET returned an unexpected range");
    }
    let object = Object {
        key: key.into(),
        size,
        etag: output.e_tag().context("S3 GET omitted ETag")?.into(),
        version: output.version_id().map(str::to_owned),
        metadata: Metadata::decode(output.metadata())?,
        mtime: output.last_modified().map_or(0, |t| t.secs()),
    };
    check_marker_kind(key, size, object.metadata.as_ref())?;
    Ok(object)
}

/// Update supported file attributes without dropping unrelated object headers.
/// The same request description is used while authorizing and while executing.
pub(super) fn metadata_update_request(
    bucket: &str,
    key: &str,
    head: &aws_sdk_s3::operation::head_object::HeadObjectOutput,
    desired: &aws_sdk_s3::operation::head_object::HeadObjectOutput,
    overrides: &[Header],
) -> Result<super::authorization::Unsigned> {
    anyhow::ensure!(
        head.missing_meta().unwrap_or(0) == 0,
        "cannot update S3 metadata: the service omitted existing metadata (x-amz-missing-meta); replacing it would lose those entries"
    );
    let encode = |text: &str| {
        percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC).to_string()
    };
    let mut request = super::authorization::Unsigned::new("PUT", key)
        .header(
            "x-amz-copy-source",
            &format!("{}/{}", encode(bucket), encode(key)),
        )
        .header(
            "x-amz-copy-source-if-match",
            head.e_tag().context("S3 omitted destination ETag")?,
        )
        .header("x-amz-metadata-directive", "REPLACE")
        .header("x-amz-tagging-directive", "COPY");
    for (name, value) in desired.metadata().into_iter().flat_map(|m| m.iter()) {
        request = request.header(&format!("x-amz-meta-{name}"), value);
    }
    for (name, value) in [
        ("content-type", desired.content_type()),
        ("content-encoding", desired.content_encoding()),
        ("content-language", desired.content_language()),
        ("content-disposition", desired.content_disposition()),
        ("cache-control", desired.cache_control()),
        ("expires", desired.expires_string()),
        (
            "x-amz-storage-class",
            desired.storage_class().map(|v| v.as_str()),
        ),
        (
            "x-amz-server-side-encryption",
            head.server_side_encryption().map(|v| v.as_str()),
        ),
        (
            "x-amz-server-side-encryption-aws-kms-key-id",
            head.ssekms_key_id(),
        ),
        (
            "x-amz-server-side-encryption-bucket-key-enabled",
            head.bucket_key_enabled()
                .map(|v| if v { "true" } else { "false" }),
        ),
        (
            "x-amz-website-redirect-location",
            desired.website_redirect_location(),
        ),
    ] {
        if let Some(value) = value {
            request = request.header(name, value);
        }
    }
    merge_metadata_encryption(&mut request, overrides)?;
    Ok(request)
}

/// Keep compatible destination settings, but do not attach inherited KMS fields
/// to a newly selected encryption method. Resolve this before both authorization
/// and execution; the client interceptor adds the same explicit headers later.
fn merge_metadata_encryption(
    request: &mut super::authorization::Unsigned,
    overrides: &[Header],
) -> Result<()> {
    const MODE: &str = "x-amz-server-side-encryption";
    const KEY: &str = "x-amz-server-side-encryption-aws-kms-key-id";
    const CONTEXT: &str = "x-amz-server-side-encryption-context";
    const BUCKET_KEY: &str = "x-amz-server-side-encryption-bucket-key-enabled";
    let explicit = |name: &str| {
        overrides
            .iter()
            .rev()
            .find(|Header(key, _)| key == name)
            .map(|Header(_, value)| value.as_str())
    };
    let customer_key = overrides
        .iter()
        .any(|Header(name, _)| name.starts_with("x-amz-server-side-encryption-customer-"));
    if customer_key {
        anyhow::ensure!(
            [MODE, KEY, CONTEXT, BUCKET_KEY]
                .iter()
                .all(|name| explicit(name).is_none()),
            "conflicting S3 header encryption settings: customer-key encryption cannot be combined with a server-managed encryption method or KMS settings"
        );
        for name in [MODE, KEY, CONTEXT, BUCKET_KEY] {
            request.headers.remove(name);
        }
    } else {
        let mode = explicit(MODE).or_else(|| request.headers.get(MODE).map(String::as_str));
        let kms = matches!(mode, Some("aws:kms" | "aws:kms:dsse"));
        let bucket_key = mode == Some("aws:kms");
        for name in [KEY, CONTEXT, BUCKET_KEY] {
            if !kms || (name == BUCKET_KEY && !bucket_key) {
                anyhow::ensure!(
                    explicit(name).is_none(),
                    "conflicting S3 header encryption settings: {name} requires {}",
                    if name == BUCKET_KEY {
                        "aws:kms encryption"
                    } else {
                        "aws:kms or aws:kms:dsse encryption"
                    }
                );
                if explicit(MODE).is_some() {
                    request.headers.remove(name);
                }
            }
        }
    }
    for Header(name, value) in overrides {
        if name.starts_with("x-amz-server-side-encryption") {
            request.headers.insert(name.clone(), value.clone());
        }
    }
    Ok(())
}

pub(super) async fn copy_metadata(
    client: &Client,
    bucket: &str,
    update: super::authorization::Unsigned,
) -> Result<()> {
    client
        .copy_object()
        .bucket(bucket)
        .key(&update.key)
        .copy_source(update.headers["x-amz-copy-source"].clone())
        .customize()
        .map_request(move |mut request| {
            for (name, value) in &update.headers {
                request
                    .headers_mut()
                    .try_insert(name.clone(), value.clone())?;
            }
            Ok::<_, aws_smithy_runtime_api::http::HttpError>(request)
        })
        .send()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn metadata_update_keeps_reported_storage_and_encryption_settings() {
        use aws_sdk_s3::{
            operation::head_object::HeadObjectOutput,
            types::{ServerSideEncryption, StorageClass},
        };
        for (encryption, bucket_key) in [
            (None, None),
            (Some(ServerSideEncryption::Aes256), None),
            (Some(ServerSideEncryption::AwsKms), Some(false)),
            (Some(ServerSideEncryption::AwsKms), Some(true)),
            (
                Some(ServerSideEncryption::from("provider-specific")),
                Some(false),
            ),
        ] {
            let head = HeadObjectOutput::builder()
                .e_tag("destination")
                .storage_class(StorageClass::IntelligentTiering)
                .set_server_side_encryption(encryption.clone())
                .set_bucket_key_enabled(bucket_key)
                .build();
            let request =
                super::metadata_update_request("bucket", "key", &head, &head, &[]).unwrap();
            assert_eq!(
                request.headers["x-amz-storage-class"],
                "INTELLIGENT_TIERING"
            );
            assert_eq!(
                request
                    .headers
                    .get("x-amz-server-side-encryption")
                    .map(String::as_str),
                encryption.as_ref().map(|v| v.as_str())
            );
            assert_eq!(
                request
                    .headers
                    .get("x-amz-server-side-encryption-bucket-key-enabled")
                    .map(String::as_str),
                bucket_key.map(|v| if v { "true" } else { "false" })
            );
            assert!(!request
                .headers
                .contains_key("x-amz-server-side-encryption-aws-kms-key-id"));
        }
    }

    #[test]
    fn metadata_encryption_overrides_keep_only_compatible_settings() {
        use aws_sdk_s3::{operation::head_object::HeadObjectOutput, types::ServerSideEncryption};
        let head = HeadObjectOutput::builder()
            .e_tag("destination")
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .ssekms_key_id("destination-key")
            .bucket_key_enabled(false)
            .build();
        for (values, mode, key, bucket_key) in [
            (
                vec!["x-amz-server-side-encryption: AES256"],
                Some("AES256"),
                None,
                None,
            ),
            (
                vec!["x-amz-server-side-encryption-aws-kms-key-id: selected-key"],
                Some("aws:kms"),
                Some("selected-key"),
                Some("false"),
            ),
            (
                vec!["x-amz-server-side-encryption-bucket-key-enabled: true"],
                Some("aws:kms"),
                Some("destination-key"),
                Some("true"),
            ),
            (
                vec!["x-amz-server-side-encryption: aws:kms:dsse"],
                Some("aws:kms:dsse"),
                Some("destination-key"),
                None,
            ),
            (
                vec!["x-amz-server-side-encryption-customer-algorithm: AES256"],
                None,
                None,
                None,
            ),
            (
                vec![
                    "x-amz-server-side-encryption: AES256",
                    "x-amz-server-side-encryption: aws:kms",
                ],
                Some("aws:kms"),
                Some("destination-key"),
                Some("false"),
            ),
        ] {
            let overrides: Vec<super::Header> = values.iter().map(|v| v.parse().unwrap()).collect();
            let request =
                super::metadata_update_request("bucket", "key", &head, &head, &overrides).unwrap();
            for (name, expected) in [
                ("x-amz-server-side-encryption", mode),
                ("x-amz-server-side-encryption-aws-kms-key-id", key),
                (
                    "x-amz-server-side-encryption-bucket-key-enabled",
                    bucket_key,
                ),
            ] {
                assert_eq!(
                    request.headers.get(name).map(String::as_str),
                    expected,
                    "{values:?}: {name}"
                );
            }
            for super::Header(name, value) in &overrides {
                if overrides.iter().rev().find(|h| h.0 == *name).unwrap().1 == *value {
                    assert_eq!(request.headers.get(name), Some(value));
                }
            }
        }
    }

    #[test]
    fn metadata_encryption_rejects_conflicting_overrides() {
        use aws_sdk_s3::{operation::head_object::HeadObjectOutput, types::ServerSideEncryption};
        let head = HeadObjectOutput::builder()
            .e_tag("destination")
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .ssekms_key_id("destination-key")
            .bucket_key_enabled(false)
            .build();
        for values in [
            vec![
                "x-amz-server-side-encryption: AES256",
                "x-amz-server-side-encryption-aws-kms-key-id: secret-key",
            ],
            vec![
                "x-amz-server-side-encryption: AES256",
                "x-amz-server-side-encryption-context: secret-context",
            ],
            vec![
                "x-amz-server-side-encryption: AES256",
                "x-amz-server-side-encryption-bucket-key-enabled: false",
            ],
            vec![
                "x-amz-server-side-encryption: aws:kms:dsse",
                "x-amz-server-side-encryption-bucket-key-enabled: true",
            ],
            vec![
                "x-amz-server-side-encryption: AES256",
                "x-amz-server-side-encryption-customer-key: secret-key",
            ],
        ] {
            let overrides: Vec<super::Header> = values.iter().map(|v| v.parse().unwrap()).collect();
            let error = super::metadata_update_request("bucket", "key", &head, &head, &overrides)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("conflicting S3 header encryption settings"),
                "{error}"
            );
            assert!(
                !error.contains("secret-"),
                "header values must not appear in errors"
            );
        }
    }

    #[test]
    fn exclusion_identifies_first_pruned_ancestor_and_preserves_negations() {
        use super::{exclusion, Exclusion};
        for (rules, key, directory, expected) in [
            (
                vec!["archive/"],
                "root/archive/nested/file",
                false,
                Some(Exclusion::Subtree("root/archive")),
            ),
            (
                vec!["archive/"],
                "root/archive/",
                true,
                Some(Exclusion::Subtree("root/archive")),
            ),
            (vec!["archive/"], "root/archive", false, None),
            (
                vec!["archive/", "!**/archive/keep"],
                "root/archive/keep",
                false,
                Some(Exclusion::Subtree("root/archive")),
            ),
            (vec!["*.tmp"], "root/file.tmp", false, Some(Exclusion::File)),
            (
                vec!["**/archive/*", "!**/archive/keep/"],
                "root/archive/keep/file",
                false,
                None,
            ),
            (
                vec!["root/", "archive/"],
                "root/archive/file",
                false,
                Some(Exclusion::Subtree("root")),
            ),
        ] {
            let matcher =
                crate::scan::build_ignore(&rules.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                    .unwrap()
                    .unwrap();
            let mut known_subtrees = std::collections::HashSet::new();
            let actual = exclusion(Some(&matcher), "", key, directory, &known_subtrees);
            assert_eq!(actual, expected, "{rules:?} {key}");
            if let Some(excluded) = actual {
                excluded.count(&mut known_subtrees);
                assert_eq!(
                    exclusion(Some(&matcher), "", key, directory, &known_subtrees),
                    expected
                );
            }
            assert_eq!(
                actual.is_some(),
                crate::scan::path_is_ignored(
                    &matcher,
                    if directory {
                        key.trim_end_matches('/').as_bytes()
                    } else {
                        key.as_bytes()
                    },
                    directory
                ),
                "{rules:?} {key} directory={directory}"
            );
        }
    }

    #[test]
    fn exclusion_anchors_patterns_inside_the_selected_prefix() {
        use super::{exclusion, Exclusion};
        let matcher = crate::scan::build_ignore(&[
            "/build/".into(),
            "logs/*".into(),
            "!logs/keep/".into(),
            "project/".into(),
        ])
        .unwrap()
        .unwrap();
        let mut known = std::collections::HashSet::new();
        for (key, directory, expected) in [
            ("parent/project/", true, None),
            (
                "parent/project/build/",
                true,
                Some(Exclusion::Subtree("parent/project/build")),
            ),
            (
                "parent/project/build/file",
                false,
                Some(Exclusion::Subtree("parent/project/build")),
            ),
            ("parent/project/nested/build/file", false, None),
            ("parent/project/logs/drop", false, Some(Exclusion::File)),
            ("parent/project/logs/keep/file", false, None),
            ("parent/project/src/file", false, None),
        ] {
            let actual = exclusion(Some(&matcher), "parent/project/", key, directory, &known);
            assert_eq!(actual, expected, "{key}");
            if let Some(excluded) = actual {
                excluded.count(&mut known);
            }
        }
        let all = crate::scan::build_ignore(&["*".into()]).unwrap().unwrap();
        assert_eq!(
            exclusion(
                Some(&all),
                "parent/project/",
                "parent/project/",
                true,
                &known
            ),
            None
        );
        assert_eq!(
            exclusion(
                Some(&all),
                "parent/project/",
                "parent/project/file",
                false,
                &known
            ),
            Some(Exclusion::File)
        );
    }

    #[test]
    fn marker_keys_hold_only_directories() {
        let values = HashMap::from([
            ("syq-format", "1"),
            ("syq-kind", "file"),
            ("syq-mode", "420"),
            ("syq-uid", "0"),
            ("syq-gid", "0"),
            ("syq-mtime", "1700000000"),
            ("syq-mtime-nsec", "0"),
        ])
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let mut metadata = Metadata::decode(Some(&values)).unwrap().unwrap();
        assert!(check_marker_kind("d/", 0, None).is_ok());
        assert!(check_marker_kind("f", 0, None).is_ok());
        for (key, size, kind, valid) in [
            ("d/", 0, ObjectKind::Dir, true),
            ("d", 0, ObjectKind::Dir, false),
            ("d/", 0, ObjectKind::File, false),
            ("d/", 0, ObjectKind::Symlink, false),
            ("f", 0, ObjectKind::File, true),
            ("l", 4, ObjectKind::Symlink, true),
        ] {
            metadata.kind = kind;
            assert_eq!(
                check_marker_kind(key, size, Some(&metadata)).is_ok(),
                valid,
                "{key} {size} {kind:?}"
            );
        }
    }

    use super::*;
    use crate::hashing::{Digest, HashAlgorithm};

    #[test]
    fn legacy_blake3_metadata_remains_readable() {
        // Literal metadata emitted by the original S3 format, not a round trip
        // through the current writer.
        let values = HashMap::from([
            ("syq-format", "1"),
            ("syq-kind", "file"),
            ("syq-mode", "420"),
            ("syq-uid", "0"),
            ("syq-gid", "0"),
            ("syq-mtime", "1700000000"),
            ("syq-mtime-nsec", "0"),
            (
                "syq-blake3",
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
        ])
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let metadata = Metadata::decode(Some(&values)).unwrap().unwrap();
        assert_eq!(metadata.hash_algorithm, HashAlgorithm::Blake3);
        assert_eq!(
            metadata.hash.unwrap(),
            Digest::hash_bytes(HashAlgorithm::Blake3, b"").value
        );
    }

    #[test]
    fn kind_enum_preserves_recovery_json_and_metadata_headers() {
        // JSON emitted by the String-based Metadata representation.
        for json in [
            r#"{"kind":"file","mode":420,"uid":0,"gid":0,"mtime":0,"nsec":0,"hash":null}"#,
            r#"{"kind":"dir","mode":420,"uid":0,"gid":0,"mtime":0,"nsec":0,"hash":null}"#,
            r#"{"kind":"symlink","mode":420,"uid":0,"gid":0,"mtime":0,"nsec":0,"hash":null}"#,
        ] {
            let metadata: Metadata = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&metadata).unwrap(), json);
            let headers = metadata.encode();
            assert_eq!(headers["syq-kind"], metadata.kind.as_str());
            assert_eq!(Metadata::decode(Some(&headers)).unwrap(), Some(metadata));
        }
    }

    #[test]
    fn alternate_digest_metadata_has_explicit_version_and_algorithm() {
        let metadata = Metadata {
            kind: ObjectKind::File,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            nsec: 0,
            hash: Some(Digest::hash_bytes(HashAlgorithm::Md5, b"abc").value),
            hash_algorithm: HashAlgorithm::Md5,
        };
        let values = metadata.encode();
        assert_eq!(values["syq-format"], "2");
        assert_eq!(values["syq-hash-algorithm"], "md5");
        assert!(!values.contains_key("syq-blake3"));
        assert_eq!(Metadata::decode(Some(&values)).unwrap(), Some(metadata));
    }

    #[tokio::test]
    async fn bucket_region_comes_from_redirects_and_denials() {
        use std::io::{Read, Write};
        for status in ["301 Moved Permanently", "403 Forbidden"] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") && socket.read(&mut byte).unwrap() == 1 {
                    request.push(byte[0]);
                }
                assert!(request.starts_with(b"HEAD /bucket"));
                let response = format!(
                    "HTTP/1.1 {status}\r\nx-amz-bucket-region: eu-central-1\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                socket.write_all(response.as_bytes()).unwrap();
            });
            let config = aws_sdk_s3::config::Builder::new()
                .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "key", "secret", None, None, "test",
                ))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .build();
            let region = bucket_region(&Client::from_conf(config), "bucket").await;
            server.join().unwrap();
            assert_eq!(region.as_deref(), Ok("eu-central-1"), "{status}");
        }
    }

    #[test]
    fn only_an_explicit_region_or_a_custom_endpoint_skips_the_lookup() {
        // Regions from the environment or a profile never reach this decision:
        // they are hints for where to ask, not reasons to skip asking.
        assert!(looks_up_region(None, None));
        assert!(!looks_up_region(Some("eu-central-1"), None));
        assert!(!looks_up_region(None, Some("https://storage.example")));
    }

    #[tokio::test]
    async fn bucket_region_reports_why_there_was_no_answer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "key", "secret", None, None, "test",
            ))
            .retry_config(RetryConfig::disabled())
            .endpoint_url(endpoint)
            .force_path_style(true)
            .build();
        let reason = bucket_region(&Client::from_conf(config), "bucket")
            .await
            .unwrap_err();
        assert!(!reason.is_empty());
    }
}

#[cfg(test)]
mod control_latency_tests;

#[cfg(test)]
mod upload_timeout_tests;

#[cfg(test)]
mod payload_signing_tests;
