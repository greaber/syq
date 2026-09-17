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

// The SDK retries throttling only by known error codes in an XML body. HEAD
// responses have no body, and some providers send HTTP 429 with other codes,
// so classify the status itself for every operation. A 429 response means the
// request was not processed, so a retry within the bounded budget is safe.
#[derive(Debug)]
struct Throttling;
impl ClassifyRetry for Throttling {
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
        "S3 HTTP 429 throttling"
    }
}

/// Requests wrapped by their own retry loop run without SDK retries, so
/// `s3-retries` is one budget per request. Uploads need the loop because the
/// SDK cannot rewind a file body; downloads need it because a response body
/// can fail after the headers arrive. Every other request keeps SDK retries.
pub(super) fn without_sdk_retries() -> aws_sdk_s3::config::Builder {
    aws_sdk_s3::config::Builder::new().retry_config(RetryConfig::disabled())
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
        .retry_classifier(Throttling)
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
    pub website_redirect: Option<String>,
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
        Err(error) => {
            let status = error.raw_response().map(|r| r.status().as_u16());
            return Err(error.into_service_error()).with_context(|| match status {
                Some(status) => format!("S3 HEAD failed (HTTP {status})"),
                None => "S3 HEAD failed".to_owned(),
            });
        }
    };
    Ok(Some(from_head(key, &output)?))
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
    if metadata.as_ref().is_some_and(|m| m.kind == "dir") && (!key.ends_with('/') || size != 0) {
        bail!("invalid syq directory marker");
    }
    Ok(Object {
        key: key.to_owned(),
        size,
        etag,
        version: output.version_id().map(str::to_owned),
        website_redirect: output.website_redirect_location().map(str::to_owned),
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
            .map_err(|e| e.into_service_error())
            .context("S3 listing failed")?;
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
    key: &'a str,
    directory: bool,
    known_subtrees: &std::collections::HashSet<String>,
) -> Option<Exclusion<'a>> {
    let matcher = matcher?;
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
    for (separator, _) in key.match_indices('/') {
        let ancestor = &key[..separator];
        if !ancestor.is_empty() && matcher.matched(ancestor, true).is_ignore() {
            return Some(Exclusion::Subtree(ancestor));
        }
    }
    if !key.is_empty() && matcher.matched(key, directory).is_ignore() {
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
    pub objects: Vec<(String, u64)>,
    pub found: bool,
    pub excluded: u64,
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
) -> Result<Listing> {
    let mut result = Listing {
        objects: Vec::new(),
        found: false,
        excluded: 0,
    };
    if let Some(excluded) = exclusion(matcher, prefix, true, excluded_subtrees) {
        result.found = prefix_exists(client, bucket, prefix).await?;
        if result.found {
            result.excluded += excluded.count(excluded_subtrees);
        }
        return Ok(result);
    }
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
                .map_err(|e| e.into_service_error())
                .context("S3 listing failed")?;
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
                            key,
                            key.ends_with('/') && object.size() == Some(0),
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
                        .map_err(|e| e.into_service_error())
                        .context("S3 listing failed")?;
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
                        if exclusion(matcher, child, true, excluded_subtrees).is_some() {
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
                let directory = key.ends_with('/') && size == 0;
                if let Some(excluded) = exclusion(matcher, key, directory, excluded_subtrees) {
                    // A filename-only exclusion still encounters the key and
                    // preserves its path validation. Pruned descendants do not.
                    if excluded == Exclusion::File {
                        super::local::key_path(key.as_bytes())?;
                    }
                    result.excluded += excluded.count(excluded_subtrees);
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
                if let Some(excluded) = exclusion(matcher, child, true, excluded_subtrees) {
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
        website_redirect: output.website_redirect_location().map(str::to_owned),
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
            let actual = exclusion(Some(&matcher), key, directory, &known_subtrees);
            assert_eq!(actual, expected, "{rules:?} {key}");
            if let Some(excluded) = actual {
                excluded.count(&mut known_subtrees);
                assert_eq!(
                    exclusion(Some(&matcher), key, directory, &known_subtrees),
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
