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
                BeforeDeserializationInterceptorContextRef, BeforeTransmitInterceptorContextMut,
                InterceptorContext,
            },
            Intercept,
        },
        retries::classifiers::{ClassifyRetry, RetryAction},
        runtime_components::RuntimeComponents,
    },
};
use aws_smithy_types::config_bag::ConfigBag;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

// HEAD errors have no XML body, so the SDK cannot recover a provider's
// TooManyRequests error code. Keep throttling inside its bounded retry policy.
#[derive(Debug)]
struct HeadThrottling;
impl ClassifyRetry for HeadThrottling {
    fn classify_retry(&self, context: &InterceptorContext) -> RetryAction {
        if context
            .response()
            .is_some_and(|r| r.status().as_u16() == 429)
        {
            RetryAction::throttling_error()
        } else {
            RetryAction::NoActionIndicated
        }
    }
    fn name(&self) -> &'static str {
        "S3 HEAD throttling"
    }
}

#[derive(Debug)]
struct Headers(Vec<Header>);
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
        if let Some(attempt) = super::diagnostics::request(context.request()) {
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
        _: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        for Header(name, value) in &self.0 {
            context
                .request_mut()
                .headers_mut()
                .try_insert(name.clone(), value.clone())?;
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

/// Describe a failed request. A bodyless redirect otherwise reads as an
/// "unhandled error", although S3 says where the bucket is.
fn failure<E>(
    operation: &str,
    error: &aws_sdk_s3::error::SdkError<
        E,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
) -> String {
    let response = error.raw_response();
    match (
        response.map(|r| r.status().as_u16()),
        response_region(response),
    ) {
        (Some(301), Some(region)) => format!(
            "{operation} failed (HTTP 301): the bucket is in region {region}; \
             pass --s3-region {region} or set AWS_REGION"
        ),
        (Some(status), _) => format!("{operation} failed (HTTP {status})"),
        (None, _) => format!("{operation} failed"),
    }
}

/// Ask S3 where a bucket is. Any response carries the answer, so this needs
/// no permission on the bucket; without a response the caller keeps its region.
async fn bucket_region(client: &Client, bucket: &str) -> Option<String> {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(output) => output.bucket_region().map(str::to_owned),
        Err(error) => response_region(error.raw_response()),
    }
}

pub(super) async fn connect(options: &mut Options) -> Result<Client> {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Some(profile) = &options.profile {
        loader = loader.profile_name(profile);
    }
    if let Some(region) = &options.region {
        loader = loader.region(Region::new(region.clone()));
    }
    let shared = loader.load().await;
    let transport = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
        ))
        .build_with_resolver(super::dns::CoalescingDns::default());
    let transport = super::upload_http::client(transport);
    let mut config = aws_sdk_s3::config::Builder::from(&shared)
        .http_client(transport)
        .region(
            shared
                .region()
                .cloned()
                .unwrap_or_else(|| Region::new("us-east-1")),
        )
        .retry_config(RetryConfig::standard().with_max_attempts(options.retries + 1))
        .timeout_config(
            TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(15))
                .read_timeout(Duration::from_secs(60))
                .build(),
        )
        // Explicit payload checksums avoid aws-chunked trailers, which several
        // S3-compatible services do not implement. Downloads retain SDK checks.
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .interceptor(Headers(options.headers.clone()));

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
    if let Some(endpoint) = endpoint {
        super::validate_endpoint(&endpoint)?;
        config = config.endpoint_url(endpoint).force_path_style(true);
    } else if shared.region().is_none() {
        // AWS serves each bucket from one region and redirects requests sent
        // elsewhere. With no region configured, ask instead of assuming
        // us-east-1. A configured region is used as given, and a custom
        // endpoint already identifies its provider's storage.
        let probe = Client::from_conf(config.clone().build());
        if let Some(region) = bucket_region(&probe, &options.bucket).await {
            config = config.region(Region::new(region));
        }
    }
    Ok(Client::from_conf(config.build()))
}

/// Version 1 is an ordinary object body plus this small metadata record.
/// Other tools can read regular-file contents without understanding syq.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Metadata {
    pub kind: String,
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
            ("syq-kind".into(), self.kind.clone()),
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
        let kind = get("syq-kind")?.clone();
        if !matches!(kind.as_str(), "file" | "dir" | "symlink") {
            bail!("unsupported syq object kind");
        }
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
impl Object {
    pub fn kind(&self) -> &str {
        self.metadata.as_ref().map_or(
            if self.key.ends_with('/') && self.size == 0 {
                "dir"
            } else {
                "file"
            },
            |m| m.kind.as_str(),
        )
    }
}

pub(super) async fn head(client: &Client, bucket: &str, key: &str) -> Result<Option<Object>> {
    let output = match client
        .head_object()
        .bucket(bucket)
        .key(key)
        .customize()
        .config_override(aws_sdk_s3::config::Builder::new().retry_classifier(HeadThrottling))
        .send()
        .await
    {
        Ok(output) => output,
        Err(error)
            if error
                .raw_response()
                .is_some_and(|r| r.status().as_u16() == 404) =>
        {
            return Ok(None)
        }
        Err(error) => {
            let message = failure("S3 HEAD", &error);
            return Err(error.into_service_error()).context(message);
        }
    };
    let size = u64::try_from(
        output
            .content_length()
            .context("S3 HEAD omitted Content-Length")?,
    )?;
    let etag = output.e_tag().context("S3 HEAD omitted ETag")?.to_owned();
    let metadata = Metadata::decode(output.metadata())?;
    if metadata.as_ref().is_some_and(|m| m.kind == "dir") && (!key.ends_with('/') || size != 0) {
        bail!("invalid syq directory marker");
    }
    Ok(Some(Object {
        key: key.to_owned(),
        size,
        etag,
        version: output.version_id().map(str::to_owned),
        metadata,
        mtime: output.last_modified().map_or(0, |t| t.secs()),
    }))
}

pub(super) async fn list(
    client: &Client,
    bucket: &str,
    prefix: &str,
) -> Result<Vec<(String, u64)>> {
    let mut objects = Vec::new();
    let mut token = None;
    loop {
        let output = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix)
            .set_continuation_token(token.clone())
            .send()
            .await
            .map_err(|e| {
                let message = failure("S3 listing", &e);
                anyhow::Error::new(e.into_service_error()).context(message)
            })?;
        for object in output.contents() {
            objects.push((
                object.key().context("S3 listing omitted key")?.to_owned(),
                u64::try_from(object.size().context("S3 listing omitted size")?)?,
            ));
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
    Ok(objects)
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
    if object.kind() == "dir" && (!key.ends_with('/') || size != 0) {
        bail!("invalid syq directory marker");
    }
    Ok(object)
}

#[cfg(test)]
mod tests {
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
    fn alternate_digest_metadata_has_explicit_version_and_algorithm() {
        let metadata = Metadata {
            kind: "file".into(),
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
            assert_eq!(region.as_deref(), Some("eu-central-1"), "{status}");
        }
    }
}
