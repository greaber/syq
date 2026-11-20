//! Transfer-scoped, in-memory S3 request authorization over a return connection.
//! The authorizer signs requests; every storage request and response travels
//! directly between the invoking server and the object-storage endpoint.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) mod started;
mod transport;
pub(super) use transport::{http_client, signed_header, SigningWait};

pub(crate) const DEFAULT_LIFETIME: u64 = 7 * 24 * 60 * 60;

/// The most requests a caller hands to one signing exchange. An exchange
/// pipelines its bounded wire messages, so it costs about one round trip to
/// the authorizing machine however many requests it carries. The limit bounds
/// the descriptions and signed URLs held outside the prepared set at once.
/// Batches from other callers join an exchange only while it stays within
/// this limit; a caller's own batch is never split.
pub(super) const EXCHANGE_REQUESTS: usize = 128 * 128;

/// Groups requests into signing exchanges of at most `limit` requests each,
/// without first collecting every request.
pub(super) fn exchanges(
    requests: impl Iterator<Item = Unsigned>,
    limit: usize,
) -> impl Iterator<Item = Vec<Unsigned>> {
    let mut requests = requests.fuse();
    std::iter::from_fn(move || {
        let exchange: Vec<_> = requests.by_ref().take(limit).collect();
        (!exchange.is_empty()).then_some(exchange)
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub key: String,
    pub descendants: bool,
}
impl Scope {
    fn contains(&self, key: &str) -> bool {
        key == self.key
            || (self.descendants
                && (self.key.is_empty()
                    || key
                        .strip_prefix(&self.key)
                        .is_some_and(|suffix| suffix.starts_with('/'))))
    }
    fn contains_prefix(&self, prefix: &str) -> bool {
        self.descendants && (self.key.is_empty() || prefix.starts_with(&format!("{}/", self.key)))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadAccess {
    pub bucket: String,
    pub scopes: Vec<Scope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum Removal {
    Current,
    Version(String),
    AllVersions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub bucket: String,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub profile: Option<String>,
    pub scopes: Vec<Scope>,
    pub source: Option<ReadAccess>,
    pub removal: Option<Removal>,
    pub acl: BTreeMap<String, String>,
    pub upload: bool,
    pub delete: bool,
    pub create_only: bool,
    pub lifetime: u64,
    /// Headers the command adds with --s3-header or --s3-write-header. Other
    /// signed headers must be ones syq sends itself.
    #[serde(default)]
    pub headers: std::collections::BTreeSet<(String, String)>,
    /// The command's --max-delete: the most object deletions signed.
    #[serde(default)]
    pub max_delete: Option<u64>,
}
impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        fn valid_bucket(bucket: &str) -> bool {
            !bucket.is_empty()
                && bucket
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        }
        fn valid_scope_count(scopes: &[Scope]) -> bool {
            !scopes.is_empty() && scopes.len() <= 1024
        }
        anyhow::ensure!(valid_bucket(&self.bucket), "invalid storage bucket");
        anyhow::ensure!(
            valid_scope_count(&self.scopes),
            "storage authorization requires 1 to 1024 source or destination scopes"
        );
        anyhow::ensure!(
            (1..=DEFAULT_LIFETIME).contains(&self.lifetime),
            "storage authorization lifetime must be between 1 second and 7 days"
        );
        if let Some(source) = &self.source {
            anyhow::ensure!(
                valid_bucket(&source.bucket),
                "invalid storage source bucket"
            );
            anyhow::ensure!(
                valid_scope_count(&source.scopes),
                "storage authorization requires 1 to 1024 source scopes"
            );
        }
        for scope in self
            .scopes
            .iter()
            .chain(self.source.iter().flat_map(|s| &s.scopes))
        {
            anyhow::ensure!(
                scope.key.len() <= 1024 && !scope.key.contains('\0'),
                "invalid storage authorization key"
            );
        }
        if let Some(Removal::Version(version)) = &self.removal {
            anyhow::ensure!(!version.is_empty(), "storage version ID cannot be empty");
        }
        anyhow::ensure!(
            self.headers.len() <= 64,
            "too many approved storage headers"
        );
        for (name, value) in &self.headers {
            anyhow::ensure!(
                name == &name.to_ascii_lowercase()
                    && http::HeaderName::from_bytes(name.as_bytes()).is_ok()
                    && http::HeaderValue::from_str(value).is_ok(),
                "invalid approved storage header"
            );
        }
        for (name, value) in &self.acl {
            anyhow::ensure!(
                (name == "x-amz-acl" || name.starts_with("x-amz-grant-"))
                    && http::HeaderName::from_bytes(name.as_bytes()).is_ok()
                    && http::HeaderValue::from_str(value).is_ok(),
                "invalid approved storage ACL header"
            );
        }
        if let Some(endpoint) = &self.endpoint {
            super::validate_endpoint(endpoint)?;
        }
        anyhow::ensure!(
            !self.delete || self.upload || self.removal.is_some(),
            "download authorization cannot delete storage objects"
        );
        Ok(())
    }

    fn permits(&self, request: &Unsigned) -> Result<()> {
        let bucket = request.bucket.as_deref().unwrap_or(&self.bucket);
        let destination =
            bucket == self.bucket && self.scopes.iter().any(|s| s.contains(&request.key));
        let source = self.source.as_ref().is_some_and(|s| {
            s.bucket == bucket && s.scopes.iter().any(|s| s.contains(&request.key))
        });
        let reading = matches!(request.method.as_str(), "GET" | "HEAD");
        anyhow::ensure!(
            destination
                || (reading && source)
                || request.query.contains_key("list-type")
                || request.query.contains_key("versions"),
            "storage request is outside the approved paths"
        );
        // The empty key addresses the bucket itself, not an object. Bucket-wide
        // object scopes still must not authorize creating or deleting buckets.
        anyhow::ensure!(
            !request.key.is_empty() || reading,
            "storage authorization does not permit bucket mutations"
        );
        for (name, value) in &request.headers {
            // SigV4 takes an explicit Host header in preference to the URL's
            // authority. Only the approved endpoint may supply that authority.
            anyhow::ensure!(
                !name.eq_ignore_ascii_case("host"),
                "storage signing does not permit a caller-supplied Host header"
            );
            anyhow::ensure!(
                name == &name.to_ascii_lowercase()
                    && http::HeaderName::from_bytes(name.as_bytes()).is_ok()
                    && http::HeaderValue::from_str(value).is_ok(),
                "invalid storage signing header"
            );
            // Some services apply headers a signature does not cover, so this
            // limits only what signing adds: syq's own headers and those the
            // approved command shows.
            anyhow::ensure!(
                sent_by_syq(name) || self.headers.contains(&(name.clone(), value.clone())),
                "storage authorization does not permit the {name} header; the command must add it with --s3-header or --s3-write-header"
            );
        }
        let query = &request.query;
        let allowed = if query.get("list-type").is_some_and(|v| v == "2") {
            request.method == "GET"
                && request.key.is_empty()
                && query.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "list-type"
                            | "prefix"
                            | "continuation-token"
                            | "delimiter"
                            | "max-keys"
                            | "encoding-type"
                            | "start-after"
                    )
                })
                && query.get("prefix").is_some_and(|p| {
                    (bucket == self.bucket && self.scopes.iter().any(|s| s.contains_prefix(p)))
                        || self.source.as_ref().is_some_and(|source| {
                            source.bucket == bucket
                                && source.scopes.iter().any(|s| s.contains_prefix(p))
                        })
                })
        } else if query.contains_key("versions") {
            matches!(
                self.removal,
                Some(Removal::Version(_) | Removal::AllVersions)
            ) && request.method == "GET"
                && request.key.is_empty()
                && bucket == self.bucket
                && query.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "versions"
                            | "prefix"
                            | "delimiter"
                            | "key-marker"
                            | "version-id-marker"
                            | "max-keys"
                            | "encoding-type"
                    )
                })
                && query.get("prefix").is_some_and(|prefix| {
                    self.scopes
                        .iter()
                        .any(|scope| prefix == &scope.key || scope.contains_prefix(prefix))
                })
        } else if query.contains_key("tagging") {
            ((request.method == "GET" && source)
                || (destination
                    && self.upload
                    && !self.create_only
                    && (request.method == "GET"
                        || (request.method == "PUT" && !query.contains_key("versionId")))))
                && query
                    .keys()
                    .all(|k| matches!(k.as_str(), "tagging" | "versionId"))
        } else if query.contains_key("uploads") {
            self.upload && request.method == "POST" && query.len() == 1
        } else if query.contains_key("uploadId") {
            self.upload
                && query.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "uploadId" | "partNumber" | "part-number-marker" | "max-parts"
                    )
                })
                && match request.method.as_str() {
                    "GET" | "DELETE" => !query.contains_key("partNumber"),
                    "POST" => query.len() == 1,
                    "PUT" => {
                        query.len() == 2
                            && query.get("partNumber").is_some_and(|p| {
                                p.parse::<u32>().is_ok_and(|p| (1..=10000).contains(&p))
                            })
                    }
                    _ => false,
                }
        } else {
            query.keys().all(|k| k == "versionId")
                && match request.method.as_str() {
                    "GET" | "HEAD" => true,
                    "PUT" => self.upload && query.is_empty(),
                    "DELETE" => {
                        self.delete
                            && match (&self.removal, query.get("versionId")) {
                                (Some(Removal::Version(approved)), Some(version)) => {
                                    approved == version
                                }
                                (Some(Removal::AllVersions), Some(_)) => true,
                                (None | Some(Removal::Current), None) => true,
                                _ => false,
                            }
                    }
                    _ => false,
                }
        };
        anyhow::ensure!(
            allowed,
            "storage operation is outside the approved permissions"
        );
        anyhow::ensure!(
            !request
                .headers
                .keys()
                .any(|h| (h.starts_with("x-amz-grant-") || h == "x-amz-acl")
                    && self.acl.get(h) != request.headers.get(h)),
            "storage ACL or copy headers are outside the approved permissions"
        );
        if let Some(encoded) = request.headers.get("x-amz-copy-source") {
            let (path, query) = encoded.split_once('?').unwrap_or((encoded, ""));
            let path =
                percent_encoding::percent_decode_str(path.trim_start_matches('/')).decode_utf8()?;
            let (bucket, key) = path
                .split_once('/')
                .context("invalid storage copy source")?;
            anyhow::ensure!(
                (bucket == self.bucket && key == request.key && !self.create_only)
                    || self
                        .source
                        .as_ref()
                        .is_some_and(|source| source.bucket == bucket
                            && source.scopes.iter().any(|scope| scope.contains(key))),
                "storage copy source is outside the approved paths"
            );
            anyhow::ensure!(
                url::form_urlencoded::parse(query.as_bytes()).all(|(name, _)| name == "versionId"),
                "invalid storage copy source query"
            );
            anyhow::ensure!(
                request.method == "PUT" && self.upload && destination,
                "storage copy destination is outside the approved permissions"
            );
        }
        let publishes = request.method == "PUT" && !query.contains_key("uploadId")
            || request.method == "POST" && query.contains_key("uploadId");
        if self.create_only && publishes {
            anyhow::ensure!(
                request
                    .headers
                    .get("if-none-match")
                    .is_some_and(|v| v == "*"),
                "storage authorization requires create-only writes"
            );
        }
        Ok(())
    }
}

/// Headers syq's own storage requests sign: payload and condition checks,
/// server-side copies, and object settings copied from an existing object.
fn sent_by_syq(name: &str) -> bool {
    name.starts_with("x-amz-checksum-")
        || name.starts_with("x-amz-meta-")
        || name.starts_with("x-amz-grant-")
        || matches!(
            name,
            "content-md5"
                | "content-length"
                | "content-type"
                | "content-encoding"
                | "content-language"
                | "content-disposition"
                | "cache-control"
                | "expires"
                | "if-match"
                | "if-none-match"
                | "x-amz-acl"
                | "x-amz-copy-source"
                | "x-amz-copy-source-if-match"
                | "x-amz-copy-source-range"
                | "x-amz-metadata-directive"
                | "x-amz-tagging-directive"
                | "x-amz-tagging"
                | "x-amz-website-redirect-location"
                | "x-amz-storage-class"
                | "x-amz-server-side-encryption"
                | "x-amz-server-side-encryption-aws-kms-key-id"
                | "x-amz-server-side-encryption-bucket-key-enabled"
        )
}

/// The headers a command adds to storage requests.
pub(crate) fn command_headers(
    options: &super::Options,
) -> std::collections::BTreeSet<(String, String)> {
    options
        .headers
        .iter()
        .chain(&options.write_headers)
        .map(|super::Header(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// A canonical request description contains no credentials or request body.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct Unsigned {
    pub bucket: Option<String>,
    pub method: String,
    pub key: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}
impl Unsigned {
    fn payload_sha256(&self) -> Result<Option<String>> {
        super::checksum::single_put_payload(
            &self.method,
            self.query.contains_key("uploadId"),
            self.headers
                .get("x-amz-checksum-sha256")
                .map(String::as_str),
        )
    }
    pub(crate) fn new(method: &str, key: &str) -> Self {
        Self {
            bucket: None,
            method: method.into(),
            key: key.into(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
        }
    }
    pub(crate) fn bucket(mut self, bucket: &str, default: &str) -> Self {
        self.bucket = (bucket != default).then(|| bucket.to_owned());
        self
    }
    pub(crate) fn query(mut self, key: &str, value: &str) -> Self {
        self.query.insert(key.into(), value.into());
        self
    }
    pub(crate) fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}
impl std::fmt::Debug for Unsigned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageRequest")
            .field("bucket", &self.bucket)
            .field("method", &self.method)
            .field("key", &self.key)
            .field("query_fields", &self.query.keys().collect::<Vec<_>>())
            .field("header_fields", &self.headers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    pub endpoint: String,
    pub region: String,
    pub expires_at: u64,
    pub requested_lifetime: u64,
}
impl std::fmt::Debug for Configuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageAuthorization")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Signer {
    request: Request,
    pub configuration: Configuration,
    credentials: aws_sdk_s3::config::Credentials,
    /// Object deletions signed so far, counted against --max-delete.
    deletions: std::sync::atomic::AtomicU64,
}
impl Signer {
    pub(crate) async fn new(request: Request) -> Result<Self> {
        use aws_credential_types::provider::ProvideCredentials;
        request.validate()?;
        let mut options = super::Options {
            bucket: request.bucket.clone(),
            route: super::Route::Download,
            endpoint: request.endpoint.clone(),
            region: request.region.clone(),
            profile: request.profile.clone(),
            headers: vec![],
            write_headers: vec![],
            concurrency: 1,
            part_size: 8 << 20,
            retries: 1,
            automatic_concurrency: false,
            automatic_part_size: false,
        };
        let (client, credentials) = super::client::connect_local(
            &mut options,
            Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            Arc::default(),
        )
        .await?;
        let credentials = credentials
            .context("no storage credential provider configured on authorizing machine")?
            .provide_credentials()
            .await
            .context("load storage credentials on authorizing machine")?;
        let now = now()?;
        let requested = now
            .checked_add(request.lifetime)
            .context("storage expiry overflow")?;
        let expires_at = credentials
            .expiry()
            .map(|t| t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()))
            .transpose()?
            .map_or(requested, |expires| expires.min(requested));
        anyhow::ensure!(
            expires_at > now,
            "authorizing storage credentials have expired"
        );
        let region = client
            .config()
            .region()
            .context("storage region missing")?
            .as_ref()
            .to_owned();
        let endpoint = options
            .endpoint
            .unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com"));
        Ok(Self {
            configuration: Configuration {
                endpoint,
                region,
                expires_at,
                requested_lifetime: request.lifetime,
            },
            request,
            credentials,
            deletions: Default::default(),
        })
    }

    /// A signer for an already approved request, with fixture credentials.
    #[cfg(test)]
    pub(crate) fn fixture(request: Request) -> Self {
        Self {
            request,
            configuration: Configuration {
                endpoint: "https://storage.example".into(),
                region: "auto".into(),
                expires_at: now().unwrap() + DEFAULT_LIFETIME,
                requested_lifetime: DEFAULT_LIFETIME,
            },
            credentials: aws_sdk_s3::config::Credentials::new(
                "fixture-key",
                "fixture-secret",
                None,
                None,
                "test",
            ),
            deletions: Default::default(),
        }
    }

    /// Refuses an object deletion beyond the command's --max-delete. The
    /// copy asks for all of its deletions together, and for none when it
    /// plans more than the limit, so only a server that ignores the limit
    /// reaches this. Each signature counts, whatever key it names.
    fn count_deletion(&self, request: &Unsigned) -> Result<()> {
        let Some(limit) = self.request.max_delete else {
            return Ok(());
        };
        if request.method != "DELETE" || request.query.contains_key("uploadId") {
            return Ok(());
        }
        let signed = self
            .deletions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        anyhow::ensure!(
            signed < limit,
            "storage authorization permits no more than {limit} object deletions (--max-delete)"
        );
        Ok(())
    }

    pub(crate) fn sign(&self, request: &Unsigned) -> Result<String> {
        use aws_sigv4::http_request::{
            sign, PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation,
            SigningSettings, UriPathNormalizationMode,
        };
        self.request.permits(request)?;
        self.count_deletion(request)?;
        let remaining = self
            .configuration
            .expires_at
            .checked_sub(now()?)
            .filter(|s| *s > 0)
            .context("storage authorization expired; rerun the copy for fresh approval")?;
        let identity = self.credentials.clone().into();
        let mut settings = SigningSettings::default();
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(Duration::from_secs(remaining));
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.configuration.region)
            .name("s3")
            .time(SystemTime::now())
            .settings(settings)
            .build()?
            .into();
        let url = request_url(&self.configuration.endpoint, &self.request.bucket, request)?;
        let payload = request.payload_sha256()?;
        let payload_header = payload.as_deref().unwrap_or("UNSIGNED-PAYLOAD");
        let signable = SignableRequest::new(
            &request.method,
            &url,
            request
                .headers
                .iter()
                .filter(|(k, _)| k.as_str() != "x-amz-content-sha256")
                .map(|(k, v)| (k.as_str(), v.as_str()))
                // The transport derives the same value from the approved checksum.
                // R2 requires it in SignedHeaders whenever it is present.
                .chain([("x-amz-content-sha256", payload_header)]),
            payload
                .clone()
                .map_or(SignableBody::UnsignedPayload, SignableBody::Precomputed),
        )?;
        let (instructions, _) = sign(signable, &params)?.into_parts();
        let mut http = http::Request::builder()
            .method(request.method.as_str())
            .uri(&url)
            .body(())?;
        instructions.apply_to_request_http1x(&mut http);
        Ok(http.uri().to_string())
    }
}

fn request_url(endpoint: &str, bucket: &str, request: &Unsigned) -> Result<String> {
    let url = url::Url::parse(endpoint)?;
    // SigV4 Single encoding expects an already canonical RFC 3986 path.
    // URL path-segment encoding alone leaves characters such as '+' literal.
    const PATH: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~')
        .remove(b'/');
    let path = format!(
        "{}/{}/{}",
        url.path().trim_end_matches('/'),
        request.bucket.as_deref().unwrap_or(bucket),
        percent_encoding::utf8_percent_encode(&request.key, PATH)
    );
    // Object keys are literal, including repeated slashes and dot segments.
    // Feeding the assembled path back through Url would normalize those keys.
    let mut result = format!("{}{path}", &url[..url::Position::BeforePath]);
    if !request.query.is_empty() {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in &request.query {
            query.append_pair(key, value);
        }
        result.push('?');
        result.push_str(&query.finish());
    }
    Ok(result)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

struct State {
    /// The connection to the authorizing machine. It is out of the state
    /// while an exchange uses it, and gone once preparation finishes or fails.
    connection: Option<std::os::unix::net::UnixStream>,
    requests: BTreeMap<Unsigned, String>,
    /// Why signing failed. A failed exchange ends the signing session, so
    /// every later request it has not prepared fails for the same reason.
    failure: Option<String>,
    /// Callers' batches waiting for the next exchange, in the order they
    /// arrived and in number order. An exchange a caller left to others is
    /// one entry with the number of the last batch it holds.
    queued: VecDeque<(u64, Vec<Unsigned>)>,
    /// The number given to the last batch queued.
    last_queued: u64,
    /// Every batch numbered up to this one is signed. Exchanges take batches
    /// in order, so batches finish in order.
    signed_through: u64,
    /// Later batches whose requests were all signed by an earlier exchange
    /// by the time an exchange took them or the session failed. Their
    /// callers succeed whatever happens to later exchanges.
    satisfied: BTreeSet<u64>,
    /// The number of requests in the exchange under way, if any.
    in_flight: usize,
}
impl State {
    fn ended(&self, started_elsewhere: bool) -> Result<()> {
        match &self.failure {
            Some(failure) if started_elsewhere => anyhow::bail!(
                "storage signing ended after an earlier request failed ({failure}); run the copy again"
            ),
            Some(failure) => anyhow::bail!(
                "storage authorization ended after an earlier request failed ({failure}); rerun the copy for fresh approval"
            ),
            None => Ok(()),
        }
    }
    /// Ends the session. Queued batches that earlier exchanges have signed
    /// in full stay complete; the rest fail.
    fn fail(&mut self, failure: String) {
        self.connection = None;
        self.failure = Some(failure);
        for (number, batch) in std::mem::take(&mut self.queued) {
            if batch
                .iter()
                .all(|request| self.requests.contains_key(request))
            {
                self.satisfied.insert(number);
            }
        }
    }
}
pub(crate) struct Authorization {
    pub configuration: Configuration,
    pub bucket: String,
    state: Mutex<State>,
    /// Signals the end of each exchange.
    exchanged: Condvar,
    /// The machine that started this copy over SSH signs for it, rather
    /// than a receiving machine that approved it.
    started_elsewhere: bool,
    /// Whether the storage service has answered a request, and whether one
    /// sent to it got no answer.
    answered: std::sync::atomic::AtomicBool,
    unanswered: std::sync::atomic::AtomicBool,
}
impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageAuthorization")
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}
impl Authorization {
    pub(super) fn new(
        bucket: String,
        configuration: Configuration,
        connection: std::os::unix::net::UnixStream,
    ) -> Self {
        Self {
            configuration,
            bucket,
            state: Mutex::new(State {
                connection: Some(connection),
                requests: BTreeMap::new(),
                failure: None,
                queued: VecDeque::new(),
                last_queued: 0,
                signed_through: 0,
                satisfied: BTreeSet::new(),
                in_flight: 0,
            }),
            exchanged: Condvar::new(),
            started_elsewhere: false,
            answered: Default::default(),
            unanswered: Default::default(),
        }
    }
    /// Whether the machine that started this copy signs for it.
    pub(crate) fn started_elsewhere(&self) -> bool {
        self.started_elsewhere
    }
    fn signer(&self) -> &'static str {
        if self.started_elsewhere {
            "the machine that started this copy"
        } else {
            "authorizing machine"
        }
    }
    fn expired(&self) -> anyhow::Error {
        if self.started_elsewhere {
            anyhow::anyhow!(
                "the signed storage URLs for this copy expired at {}; they last {}, or until the credentials that signed them expire if that is sooner. Run the copy again to continue it",
                started::time(self.configuration.expires_at),
                started::duration(self.configuration.requested_lifetime)
            )
        } else {
            anyhow::anyhow!("storage authorization expired; rerun the copy for fresh approval")
        }
    }
    pub(super) fn record_answer(&self, answered: bool) {
        let flag = if answered {
            &self.answered
        } else {
            &self.unanswered
        };
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Whether requests were sent to the storage service and none of them
    /// was ever answered.
    pub(crate) fn never_answered(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        self.unanswered.load(Relaxed) && !self.answered.load(Relaxed)
    }
    /// Signs the requests not yet prepared. Batches that arrive while an
    /// exchange is under way go together in the next one, so callers that
    /// sign as they send share round trips to the authorizing machine
    /// instead of waiting for one each.
    pub(crate) fn authorize(&self, requests: Vec<Unsigned>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let missing: Vec<_> = requests
            .into_iter()
            .filter(|request| !state.requests.contains_key(request))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        state.ended(self.started_elsewhere)?;
        if state.connection.is_none() && state.in_flight == 0 {
            let request = &missing[0];
            if self.started_elsewhere {
                anyhow::bail!("request {request:?} was not signed before the copy started moving data; run the copy again");
            }
            anyhow::bail!("request {request:?} was not prepared before storage authorization disconnected; rerun for fresh approval");
        }
        state.last_queued += 1;
        let batch = state.last_queued;
        state.queued.push_back((batch, missing));
        loop {
            if state.signed_through >= batch || state.satisfied.remove(&batch) {
                return Ok(());
            }
            state.ended(self.started_elsewhere)?;
            if state.in_flight > 0 {
                state = self.exchanged.wait(state).unwrap();
                continue;
            }
            // Nothing is in flight and this caller's batch is unsigned, so it
            // is queued and preparation has not finished.
            if state.connection.is_none() || state.queued.is_empty() {
                state.fail("storage authorization lost its connection".into());
                self.exchanged.notify_all();
                return state.ended(self.started_elsewhere);
            }
            // The first queued batch, and the batches after it while the
            // exchange stays within the limit. A batch an earlier exchange
            // has signed since it was queued is complete already.
            let mut exchange = Vec::new();
            let mut through = state.signed_through;
            let mut combined = false;
            while let Some((number, mut requests)) = state.queued.pop_front() {
                requests.retain(|request| !state.requests.contains_key(request));
                if requests.is_empty() {
                    if exchange.is_empty() {
                        state.signed_through = number;
                    } else {
                        state.satisfied.insert(number);
                    }
                    continue;
                }
                if !exchange.is_empty() && exchange.len() + requests.len() > EXCHANGE_REQUESTS {
                    state.queued.push_front((number, requests));
                    break;
                }
                through = number;
                if exchange.is_empty() {
                    exchange = requests;
                } else {
                    exchange.extend(requests);
                    combined = true;
                }
            }
            // Two combined callers may ask for the same request.
            if combined {
                exchange.sort_unstable();
                exchange.dedup();
            }
            // Callers whose batches are complete need not wait for this exchange.
            self.exchanged.notify_all();
            if exchange.is_empty() {
                continue;
            }
            // If this caller's batch turned out complete, it leaves the
            // exchange to a waiting caller, queued again as one entry with
            // the number of the last batch it holds.
            if state.signed_through >= batch || state.satisfied.remove(&batch) {
                state.queued.push_front((through, exchange));
                return Ok(());
            }
            let mut stream = state.connection.take().unwrap();
            state.in_flight = exchange.len();
            drop(state);
            let mut exchanging = Exchanging(Some(self));
            let signed = crate::destination::storage::sign(&mut stream, &exchange, self.signer())
                .and_then(|signed| {
                    anyhow::ensure!(
                        signed.len() == exchange.len(),
                        "incomplete storage authorization response"
                    );
                    Ok(signed)
                });
            exchanging.0 = None;
            state = self.state.lock().unwrap();
            state.in_flight = 0;
            self.exchanged.notify_all();
            match signed {
                Ok(signed) => {
                    state.connection = Some(stream);
                    state.requests.extend(exchange.into_iter().zip(signed));
                    state.signed_through = through;
                    state.satisfied.retain(|&number| number > through);
                }
                Err(error) => {
                    state.fail(format!("{error:#}"));
                    // This caller may have led the exchange for others.
                    if state.signed_through >= batch || state.satisfied.remove(&batch) {
                        return Ok(());
                    }
                    return Err(error);
                }
            }
        }
    }
    pub(crate) fn signed(&self, request: Unsigned) -> Result<String> {
        if now()? >= self.configuration.expires_at {
            return Err(self.expired());
        }
        if request.method == "PUT" {
            let mut streaming = request.clone();
            streaming.headers.remove("content-md5");
            streaming.headers.remove("content-length");
            if let Some(url) = self.state.lock().unwrap().requests.get(&streaming) {
                return Ok(url.clone());
            }
        }
        self.authorize(vec![request.clone()])?;
        Ok(self.state.lock().unwrap().requests[&request].clone())
    }
    pub(crate) async fn finish(self: &Arc<Self>) -> Result<()> {
        let deadline = aws_smithy_types::DateTime::from_secs(self.configuration.expires_at as i64)
            .fmt(aws_smithy_types::date_time::Format::DateTime)?;
        let authorization = self.clone();
        tokio::task::spawn_blocking(move || authorization.finish_preparation()).await??;
        if self.started_elsewhere {
            // That machine stays connected for the whole copy, and losing it
            // stops the copy, so there is nothing to tell anyone.
            return Ok(());
        }
        crate::output::diagnostic!("syq: storage authorization ready; the authorizing machine may disconnect. Authorization expires at {deadline}; provider policies or credential revocation may shorten it.");
        Ok(())
    }
    pub(crate) fn finish_preparation(&self) -> Result<()> {
        // Requests already asked for are signed first, as they would be had
        // their callers taken the connection before this one.
        let mut state = self
            .exchanged
            .wait_while(self.state.lock().unwrap(), |state| {
                state.failure.is_none() && (state.in_flight > 0 || !state.queued.is_empty())
            })
            .unwrap();
        // Preparation that failed must not count as finished.
        state.ended(self.started_elsewhere)?;
        if let Some(mut stream) = state.connection.take() {
            crate::destination::storage::finish(&mut stream)?;
        }
        Ok(())
    }
}

/// Ends an exchange that stopped without a result, so its waiting callers
/// fail instead of waiting for it forever.
struct Exchanging<'a>(Option<&'a Authorization>);
impl Drop for Exchanging<'_> {
    fn drop(&mut self) {
        if let Some(authorization) = self.0 {
            let mut state = authorization
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.in_flight = 0;
            state.fail("storage signing stopped unexpectedly".into());
            authorization.exchanged.notify_all();
        }
    }
}

pub(crate) async fn connect(
    args: &crate::cli::Args,
    options: &super::Options,
) -> Result<Option<Arc<Authorization>>> {
    if let Some(authorization) = &args.storage_authorization {
        return Ok(Some(authorization.clone()));
    }
    let crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name)) = &args.auth_from
    else {
        return Ok(None);
    };
    anyhow::ensure!(
        args.descriptor_copy.is_none(),
        "storage authorization currently requires a file or tree upload/download"
    );
    let request = request_for(args, options)?;
    connect_request(name, request).await.map(Some)
}

/// The authorization a command requests. The authorizing machine derives the
/// same request from the command it shows for approval.
pub(crate) fn request_for(args: &crate::cli::Args, options: &super::Options) -> Result<Request> {
    let upload = options.route == super::Route::Upload || options.route.is_server_copy();
    // Every location but the last, as keys under the source's base.
    let source_scopes = || -> Result<Vec<Scope>> {
        let base = super::local::key_path(
            args.native_source_root
                .as_deref()
                .or(args.native_source_cwd.as_deref())
                .unwrap_or(b"."),
        )?;
        args.locations[..args.locations.len() - 1]
            .iter()
            .map(|source| {
                Ok(Scope {
                    key: super::local::join(&base, &super::local::key_path(&source.path)?),
                    descendants: true,
                })
            })
            .collect()
    };
    let scopes = if args.rm {
        let base = super::local::key_path(
            args.native_rm_root
                .as_deref()
                .or(args.native_rm_cwd.as_deref())
                .unwrap_or(b"."),
        )?;
        args.locations
            .iter()
            .map(|source| {
                Ok(Scope {
                    key: super::remove::selector_key(
                        &base,
                        source,
                        args.s3_remove.s3_version_id.is_some(),
                    )?,
                    descendants: true,
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else if upload {
        upload_roots(args, options)?
            .into_iter()
            .map(|key| Scope {
                key,
                descendants: true,
            })
            .collect()
    } else {
        source_scopes()?
    };
    let source = options
        .route
        .source_bucket()
        .map(|bucket| -> Result<_> {
            Ok(ReadAccess {
                bucket: bucket.into(),
                scopes: source_scopes()?,
            })
        })
        .transpose()?;
    let request = Request {
        bucket: options.bucket.clone(),
        endpoint: options.endpoint.clone(),
        region: options.region.clone(),
        profile: options.profile.clone(),
        scopes,
        source,
        acl: acl_headers(options),
        removal: args.rm.then(|| {
            if args.s3_remove.s3_all_versions {
                Removal::AllVersions
            } else if let Some(id) = &args.s3_remove.s3_version_id {
                Removal::Version(id.clone())
            } else {
                Removal::Current
            }
        }),
        upload: upload && !args.dry_run,
        delete: (args.rm || (upload && args.delete)) && !args.dry_run,
        create_only: args.ignore_existing || args.target_existence == crate::cli::Existence::New,
        lifetime: DEFAULT_LIFETIME,
        headers: command_headers(options),
        max_delete: args
            .max_delete
            .filter(|_| upload && args.delete && !args.dry_run),
    };
    Ok(request)
}

/// The most upload roots a request names one by one.
const NAMED_ROOTS: usize = 1024;

/// The keys under which an upload reads, writes and lists: each is a key and
/// everything below it. Where the command names its sources, each lands at
/// its own name inside the destination directory, and those names are the
/// roots: nothing else in the directory is the copy's business. The whole
/// destination is the root when the command does not say which names the
/// copy produces (`--srcs-in`, a mapping, a copy between buckets), when it
/// tests the destination directory itself (the `-existing` and `-new`
/// placements), and when it names more sources than a request lists. (A
/// copy between a server and a bucket never does: like a copy between two
/// servers, it refuses more named sources than that before it signs
/// anything.)
///
/// The machine that signs derives the signed paths from this, and the copy
/// lists the destination under the same roots, so the two cannot disagree.
pub(crate) fn upload_roots(
    args: &crate::cli::Args,
    options: &super::Options,
) -> Result<Vec<String>> {
    let (target, sources) = args
        .locations
        .split_last()
        .context("storage destination missing")?;
    let target = super::local::key_path(&target.path)?;
    let named = options.route == super::Route::Upload
        && args.native_mapping.is_none()
        && args.target_existence == crate::cli::Existence::Any;
    if !named {
        return Ok(vec![target]);
    }
    let mut roots = std::collections::BTreeSet::new();
    for source in sources {
        let root = super::local::upload_destination(args, &target, source)?;
        if root == target || roots.len() == NAMED_ROOTS {
            return Ok(vec![target]);
        }
        roots.insert(root);
    }
    if roots.is_empty() {
        return Ok(vec![target]);
    }
    Ok(roots.into_iter().collect())
}

pub(super) fn acl_headers(options: &super::Options) -> BTreeMap<String, String> {
    options
        .headers
        .iter()
        .chain(&options.write_headers)
        .filter(|super::Header(name, _)| name == "x-amz-acl" || name.starts_with("x-amz-grant-"))
        .map(|super::Header(name, value)| (name.clone(), value.clone()))
        .collect()
}

pub(super) async fn connect_request(name: &str, request: Request) -> Result<Arc<Authorization>> {
    let bucket = request.bucket.clone();
    let name = name.to_owned();
    let (connection, configuration) =
        tokio::task::spawn_blocking(move || crate::destination::storage::connect(&name, request))
            .await??;
    crate::output::diagnostic!("syq: preparing storage authorization; keep the authorizing machine connected until preparation finishes");
    Ok(Arc::new(Authorization::new(
        bucket,
        configuration,
        connection,
    )))
}

#[cfg(test)]
mod tests;
