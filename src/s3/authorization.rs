//! Transfer-scoped, in-memory S3 request authorization over a return connection.
//! The authorizer signs requests; every storage request and response travels
//! directly between the invoking server and the object-storage endpoint.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod transport;
pub(super) use transport::{http_client, signed_header};

pub(crate) const DEFAULT_LIFETIME: u64 = 7 * 24 * 60 * 60;

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
}
impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.bucket.is_empty()
                && self
                    .bucket
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
            "invalid storage bucket"
        );
        anyhow::ensure!(
            !self.scopes.is_empty() && self.scopes.len() <= 1024,
            "storage authorization requires 1 to 1024 source or destination scopes"
        );
        anyhow::ensure!(
            (1..=DEFAULT_LIFETIME).contains(&self.lifetime),
            "storage authorization lifetime must be between 1 second and 7 days"
        );
        if let Some(source) = &self.source {
            anyhow::ensure!(
                !source.bucket.is_empty()
                    && source
                        .bucket
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
                "invalid storage source bucket"
            );
            anyhow::ensure!(
                !source.scopes.is_empty() && source.scopes.len() <= 1024,
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
            source
                && request.method == "GET"
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
                .any(
                    |h| (h.starts_with("x-amz-copy-source") && self.source.is_none())
                        || ((h.starts_with("x-amz-grant-") || h == "x-amz-acl")
                            && self.acl.get(h) != request.headers.get(h))
                ),
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
                self.source
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
    pub(super) fn new(method: &str, key: &str) -> Self {
        Self {
            bucket: None,
            method: method.into(),
            key: key.into(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
        }
    }
    pub(super) fn bucket(mut self, bucket: &str, default: &str) -> Self {
        self.bucket = (bucket != default).then(|| bucket.to_owned());
        self
    }
    pub(super) fn query(mut self, key: &str, value: &str) -> Self {
        self.query.insert(key.into(), value.into());
        self
    }
    pub(super) fn header(mut self, key: &str, value: &str) -> Self {
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
            concurrency: 1,
            part_size: 8 << 20,
            retries: 1,
            automatic_concurrency: false,
            automatic_part_size: false,
        };
        let (client, _) = super::client::connect(
            &mut options,
            Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            Arc::default(),
        )
        .await?;
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(profile) = &request.profile {
            loader = loader.profile_name(profile);
        }
        if let Some(region) = &request.region {
            loader = loader.region(aws_types::region::Region::new(region.clone()));
        }
        let config = loader.load().await;
        let credentials = config
            .credentials_provider()
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
        })
    }

    pub(crate) fn sign(&self, request: &Unsigned) -> Result<String> {
        use aws_sigv4::http_request::{
            sign, PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation,
            SigningSettings, UriPathNormalizationMode,
        };
        self.request.permits(request)?;
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
        let signable = SignableRequest::new(
            &request.method,
            &url,
            request
                .headers
                .iter()
                .filter(|(k, _)| k.as_str() != "x-amz-content-sha256")
                .map(|(k, v)| (k.as_str(), v.as_str()))
                // The transport sends this marker, including for HEAD/GET.
                // R2 requires it in SignedHeaders whenever it is present.
                .chain([("x-amz-content-sha256", "UNSIGNED-PAYLOAD")]),
            SignableBody::UnsignedPayload,
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
    connection: Option<std::os::unix::net::UnixStream>,
    requests: BTreeMap<Unsigned, String>,
}
pub(crate) struct Authorization {
    pub configuration: Configuration,
    pub bucket: String,
    state: Mutex<State>,
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
            }),
        }
    }
    pub(super) fn authorize(&self, requests: Vec<Unsigned>) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let missing: Vec<_> = requests
            .into_iter()
            .filter(|request| !state.requests.contains_key(request))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let stream = state.connection.as_mut().with_context(|| format!("request {request:?} was not prepared before storage authorization disconnected; rerun for fresh approval", request = missing[0]))?;
        let signed = crate::destination::storage::sign(stream, &missing)?;
        anyhow::ensure!(
            signed.len() == missing.len(),
            "incomplete storage authorization response"
        );
        state.requests.extend(missing.into_iter().zip(signed));
        Ok(())
    }
    pub(super) fn signed(&self, request: Unsigned) -> Result<String> {
        anyhow::ensure!(
            now()? < self.configuration.expires_at,
            "storage authorization expired; rerun the copy for fresh approval"
        );
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
        crate::output::diagnostic!("syq: storage authorization ready; the authorizing machine may disconnect. Authorization expires at {deadline}; provider policies or credential revocation may shorten it.");
        Ok(())
    }
    pub(super) fn finish_preparation(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(mut stream) = state.connection.take() {
            crate::destination::storage::finish(&mut stream)?;
        }
        Ok(())
    }
}

pub(crate) async fn connect(
    args: &crate::cli::Args,
    options: &super::Options,
) -> Result<Option<Arc<Authorization>>> {
    if let Some(authorization) = &args.storage_authorization {
        return Ok(Some(authorization.clone()));
    }
    let crate::cli::AuthFrom::Return(name) = &args.auth_from else {
        return Ok(None);
    };
    anyhow::ensure!(
        args.descriptor_copy.is_none(),
        "storage authorization currently requires a file or tree upload/download"
    );
    let upload = options.route == super::Route::Upload || options.route.is_server_copy();
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
                    key: super::local::join(&base, &super::local::key_path(&source.path)?),
                    descendants: true,
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else if upload {
        vec![Scope {
            key: super::local::key_path(
                &args
                    .locations
                    .last()
                    .context("storage destination missing")?
                    .path,
            )?,
            descendants: true,
        }]
    } else {
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
            .collect::<Result<Vec<_>>>()?
    };
    let source = options
        .route
        .source_bucket()
        .map(|bucket| -> Result<_> {
            let base = super::local::key_path(
                args.native_source_root
                    .as_deref()
                    .or(args.native_source_cwd.as_deref())
                    .unwrap_or(b"."),
            )?;
            let scopes = args.locations[..args.locations.len() - 1]
                .iter()
                .map(|source| {
                    Ok(Scope {
                        key: super::local::join(&base, &super::local::key_path(&source.path)?),
                        descendants: true,
                    })
                })
                .collect::<Result<_>>()?;
            Ok(ReadAccess {
                bucket: bucket.into(),
                scopes,
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
    };
    connect_request(name, request).await.map(Some)
}

pub(super) fn acl_headers(options: &super::Options) -> BTreeMap<String, String> {
    options
        .headers
        .iter()
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
