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
            },
            Intercept,
        },
        runtime_components::RuntimeComponents,
    },
};
use aws_smithy_types::config_bag::ConfigBag;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};

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
    let output = match client.head_object().bucket(bucket).key(key).send().await {
        Ok(output) => output,
        Err(error)
            if error
                .raw_response()
                .is_some_and(|r| r.status().as_u16() == 404) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error.into_service_error()).context("S3 HEAD failed"),
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

/// Existence needs only one object, regardless of the size of the prefix.
pub(super) async fn prefix_exists(client: &Client, bucket: &str, prefix: &str) -> Result<bool> {
    let output = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .max_keys(1)
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("S3 listing failed")?;
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
) -> Result<Option<std::collections::HashSet<String>>> {
    let mut keys = std::collections::HashSet::new();
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
            .map_err(|e| e.into_service_error())
            .context("S3 listing failed")?;
        for object in output.contents() {
            let key = object.key().context("S3 listing omitted key")?;
            if source_keys.contains(key) {
                keys.insert(key.to_owned());
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

pub(super) struct Listing {
    pub objects: Vec<(String, u64)>,
    pub found: bool,
    pub excluded: u64,
}

/// Keep flat listings for small trees and filename filters. Only switch to
/// directory discovery when the first full page contains only excluded descendants.
/// Probe one directory page, but accept it only when it prunes a subtree and
/// leaves at most one child to visit. Otherwise reuse the flat sample. This
/// prevents an exclusion from turning a wide tree into one request per folder.
pub(super) async fn list(
    client: &Client,
    bucket: &str,
    prefix: &str,
    matcher: Option<&ignore::gitignore::Gitignore>,
) -> Result<Listing> {
    let ignored = |key: &str, directory| {
        matcher.is_some_and(|m| crate::scan::path_is_ignored(m, key.as_bytes(), directory))
    };
    let mut result = Listing {
        objects: Vec::new(),
        found: false,
        excluded: 0,
    };
    if ignored(prefix.trim_end_matches('/'), true) {
        result.found = prefix_exists(client, bucket, prefix).await?;
        return Ok(result);
    }
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
                .map_err(|e| e.into_service_error())
                .context("S3 listing failed")?;
            result.found |= !output.contents().is_empty() || !output.common_prefixes().is_empty();
            if token.is_none()
                && output.is_truncated() == Some(true)
                && !output.contents().is_empty()
                && output.contents().iter().all(|object| {
                    object.key().is_some_and(|key| {
                        key.rsplit_once('/')
                            .is_some_and(|(parent, _)| ignored(parent, true))
                    })
                })
            {
                let directory_page = client
                    .list_objects_v2()
                    .bucket(bucket)
                    .prefix(&current)
                    .delimiter("/")
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("S3 listing failed")?;
                let mut included = 0;
                let mut excluded = 0;
                for child in directory_page.common_prefixes() {
                    let child = child.prefix().context("S3 listing omitted common prefix")?;
                    anyhow::ensure!(
                        child.starts_with(&current)
                            && child.len() > current.len()
                            && child.ends_with('/'),
                        "S3 listing returned an invalid common prefix"
                    );
                    if ignored(child.trim_end_matches('/'), true) {
                        excluded += 1;
                    } else {
                        included += 1;
                    }
                }
                if directory_page.is_truncated() != Some(true) && excluded > 0 && included <= 1 {
                    // Replace rather than append the sample, so objects and
                    // exclusion counts cannot be duplicated.
                    output = directory_page;
                    directories = true;
                }
            }
            for object in output.contents() {
                let key = object.key().context("S3 listing omitted key")?;
                anyhow::ensure!(
                    key.starts_with(&current),
                    "S3 listing returned a key outside the requested prefix"
                );
                let size = u64::try_from(object.size().context("S3 listing omitted size")?)?;
                let directory = key.ends_with('/') && size == 0;
                if ignored(key, directory) {
                    // Skipped directories need no descendant validation, as
                    // with filesystem walks. A filename-only exclusion still
                    // encounters the key and preserves its path validation.
                    if !directory
                        && !key
                            .rsplit_once('/')
                            .is_some_and(|(parent, _)| ignored(parent, true))
                    {
                        super::local::key_path(key.as_bytes())?;
                    }
                    result.excluded += 1;
                } else {
                    result.objects.push((key.to_owned(), size));
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
                if !ignored(child.trim_end_matches('/'), true) {
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
}
