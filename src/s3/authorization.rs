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
pub(crate) struct Request {
    pub bucket: String,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub profile: Option<String>,
    pub scopes: Vec<Scope>,
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
        for scope in &self.scopes {
            anyhow::ensure!(
                scope.key.len() <= 1024 && !scope.key.contains('\0'),
                "invalid storage authorization key"
            );
        }
        if let Some(endpoint) = &self.endpoint {
            super::validate_endpoint(endpoint)?;
        }
        anyhow::ensure!(
            !self.delete || self.upload,
            "download authorization cannot delete storage objects"
        );
        Ok(())
    }

    fn permits(&self, request: &Unsigned) -> Result<()> {
        anyhow::ensure!(
            self.scopes.iter().any(|s| s.contains(&request.key))
                || request.query.contains_key("list-type"),
            "storage request is outside the approved paths"
        );
        anyhow::ensure!(
            !request
                .key
                .split('/')
                .any(|part| matches!(part, "." | "..")),
            "storage key contains a traversal component"
        );
        for (name, value) in &request.headers {
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
                && query
                    .get("prefix")
                    .is_some_and(|p| self.scopes.iter().any(|s| s.contains_prefix(p)))
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
                    "DELETE" => self.delete && query.is_empty(),
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
                .any(|h| h.starts_with("x-amz-copy-source")
                    || h.starts_with("x-amz-grant-")
                    || h == "x-amz-acl"),
            "storage authorization does not permit ACL changes or server-side copies"
        );
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
    pub method: String,
    pub key: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}
impl Unsigned {
    pub(super) fn new(method: &str, key: &str) -> Self {
        Self {
            method: method.into(),
            key: key.into(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
        }
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
    let mut url = url::Url::parse(endpoint)?;
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
        bucket,
        percent_encoding::utf8_percent_encode(&request.key, PATH)
    );
    url.set_path(&path);
    if !request.query.is_empty() {
        let mut query = url.query_pairs_mut();
        for (key, value) in &request.query {
            query.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

struct State {
    connection: Option<std::os::unix::net::UnixStream>,
    requests: BTreeMap<Unsigned, String>,
}
pub(super) struct Authorization {
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
        for batch in missing.chunks(128) {
            let stream = state.connection.as_mut().with_context(|| format!("request {request:?} was not prepared before storage authorization disconnected; rerun for fresh approval", request = batch[0]))?;
            let signed = crate::destination::storage::sign(stream, batch)?;
            anyhow::ensure!(
                signed.len() == batch.len(),
                "incomplete storage authorization response"
            );
            for (request, signed) in batch.iter().cloned().zip(signed) {
                state.requests.insert(request, signed);
            }
        }
        Ok(())
    }
    pub(super) fn signed(&self, request: Unsigned) -> Result<String> {
        anyhow::ensure!(
            now()? < self.configuration.expires_at,
            "storage authorization expired; rerun the copy for fresh approval"
        );
        self.authorize(vec![request.clone()])?;
        Ok(self.state.lock().unwrap().requests[&request].clone())
    }
    pub(super) fn finish_preparation(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(mut stream) = state.connection.take() {
            crate::destination::storage::finish(&mut stream)?;
        }
        Ok(())
    }
}

pub(super) async fn connect(
    args: &crate::cli::Args,
    options: &super::Options,
) -> Result<Option<Arc<Authorization>>> {
    let crate::cli::AuthFrom::Return(name) = &args.auth_from else {
        return Ok(None);
    };
    anyhow::ensure!(
        !options.route.is_server_copy() && args.descriptor_copy.is_none(),
        "storage authorization currently requires a file or tree upload/download"
    );
    let upload = options.route == super::Route::Upload;
    let scopes = if upload {
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
    let request = Request {
        bucket: options.bucket.clone(),
        endpoint: options.endpoint.clone(),
        region: options.region.clone(),
        profile: options.profile.clone(),
        scopes,
        upload: upload && !args.dry_run,
        delete: upload && args.delete && !args.dry_run,
        create_only: args.ignore_existing || args.target_existence == crate::cli::Existence::New,
        lifetime: DEFAULT_LIFETIME,
    };
    let bucket = request.bucket.clone();
    let name = name.clone();
    let (connection, configuration) =
        tokio::task::spawn_blocking(move || crate::destination::storage::connect(&name, request))
            .await??;
    crate::output::diagnostic!("syq: preparing storage authorization; keep the authorizing machine connected until preparation finishes");
    Ok(Some(Arc::new(Authorization::new(
        bucket,
        configuration,
        connection,
    ))))
}

#[cfg(test)]
mod tests;
