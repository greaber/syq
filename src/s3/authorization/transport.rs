mod redaction;

use super::*;
use aws_smithy_runtime_api::client::{
    http::{
        http_client_fn, HttpClient, HttpConnector, HttpConnectorFuture, SharedHttpClient,
        SharedHttpConnector,
    },
    orchestrator::HttpRequest,
    result::ConnectorError,
};

#[derive(Debug)]
struct Connector {
    inner: SharedHttpConnector,
    authorization: Arc<Authorization>,
}
impl HttpConnector for Connector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let inner = self.inner.clone();
        let authorization = self.authorization.clone();
        HttpConnectorFuture::new(async move {
            let mut request = request
                .try_into_http1x()
                .map_err(|e| ConnectorError::other(e.into(), None))?;
            let unsigned = describe(&mut request, &authorization)
                .map_err(|e| ConnectorError::other(e.into(), None))?;
            let signed = tokio::task::spawn_blocking(move || authorization.signed(unsigned))
                .await
                .map_err(|_| failure("storage authorization task failed"))?
                .map_err(|e| ConnectorError::other(e.into(), None))?;
            *request.uri_mut() = signed
                .parse()
                .map_err(|_| failure("invalid authorized storage URL"))?;
            request.headers_mut().remove("authorization");
            request.headers_mut().remove("x-amz-security-token");
            request.headers_mut().remove("x-amz-date");
            request.headers_mut().remove("host");
            request.headers_mut().insert(
                "x-amz-content-sha256",
                http::HeaderValue::from_static("UNSIGNED-PAYLOAD"),
            );
            inner
                .call(
                    HttpRequest::try_from(request)
                        .map_err(|_| failure("invalid authorized storage request"))?,
                )
                .await
                .map_err(redaction::connector_error)
        })
    }
}
fn failure(message: &'static str) -> ConnectorError {
    ConnectorError::other(anyhow::anyhow!(message).into(), None)
}

pub(in crate::s3) fn http_client(
    client: impl HttpClient + 'static,
    authorization: Arc<Authorization>,
) -> SharedHttpClient {
    http_client_fn(move |settings, components| {
        SharedHttpConnector::new(Connector {
            inner: client.http_connector(settings, components),
            authorization: authorization.clone(),
        })
    })
}

fn describe<B>(request: &mut http::Request<B>, authorization: &Authorization) -> Result<Unsigned> {
    let url = url::Url::parse(&request.uri().to_string()).context("invalid storage request URL")?;
    let endpoint = url::Url::parse(&authorization.configuration.endpoint)?;
    anyhow::ensure!(
        url.scheme() == endpoint.scheme()
            && url.host_str() == endpoint.host_str()
            && url.port_or_known_default() == endpoint.port_or_known_default(),
        "storage request endpoint differs from authorization"
    );
    let prefix = format!(
        "{}/{}/",
        endpoint.path().trim_end_matches('/'),
        authorization.bucket
    );
    let key = url
        .path()
        .strip_prefix(&prefix)
        .or_else(|| (url.path() == prefix.trim_end_matches('/')).then_some(""))
        .context("storage request bucket differs from authorization")?;
    let key = percent_encoding::percent_decode_str(key)
        .decode_utf8()
        .context("storage key is not UTF-8")?;
    let mut result = Unsigned::new(request.method().as_str(), &key);
    for (name, value) in url.query_pairs() {
        if name == "x-id" {
            continue;
        }
        anyhow::ensure!(
            result
                .query
                .insert(name.into_owned(), value.into_owned())
                .is_none(),
            "duplicate storage query field"
        );
    }
    // The engine supplies explicit integrity checks. These optional SDK hints
    // must not cause the signature to depend on an SDK-generated header.
    request.headers_mut().remove("x-amz-sdk-checksum-algorithm");
    request.headers_mut().remove("x-amz-checksum-mode");
    request.headers_mut().remove("x-amz-user-agent");
    for (name, value) in request.headers() {
        if signed_header(name.as_str(), request.method().as_str()) {
            result.headers.insert(
                name.as_str().into(),
                value.to_str().context("invalid storage header")?.into(),
            );
        }
    }
    Ok(result)
}

pub(in crate::s3) fn signed_header(name: &str, method: &str) -> bool {
    (name.starts_with("x-amz-")
        && !matches!(
            name,
            "x-amz-date"
                | "x-amz-security-token"
                | "x-amz-content-sha256"
                | "x-amz-sdk-checksum-algorithm"
                | "x-amz-checksum-mode"
                | "x-amz-user-agent"
        ))
        || matches!(name, "content-md5" | "if-match" | "if-none-match")
        || (method == "PUT" && name == "content-length")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Clone)]
    struct ResetOnce {
        attempts: Arc<std::sync::atomic::AtomicUsize>,
        include_url: bool,
    }
    impl HttpConnector for ResetOnce {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            use std::sync::atomic::Ordering::Relaxed;
            let result = if self.attempts.fetch_add(1, Relaxed) == 0 {
                let details = if self.include_url {
                    format!("connection reset while accessing {}", request.uri())
                } else {
                    "connection reset".to_owned()
                };
                Err(ConnectorError::io(
                    std::io::Error::new(std::io::ErrorKind::ConnectionReset, details).into(),
                ))
            } else {
                let mut response = aws_smithy_runtime_api::client::orchestrator::HttpResponse::new(
                    200.try_into().unwrap(),
                    aws_smithy_types::body::SdkBody::empty(),
                );
                response.headers_mut().insert("content-length", "0");
                Ok(response)
            };
            HttpConnectorFuture::ready(result)
        }
    }

    #[tokio::test]
    async fn delegated_head_retries_connection_resets_like_ordinary_head() {
        use aws_sdk_s3::config::{retry::RetryConfig, Builder, Credentials, Region};
        for delegated in [false, true] {
            for include_url in [false, true] {
                let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let connector = ResetOnce {
                    attempts: attempts.clone(),
                    include_url,
                };
                let client =
                    http_client_fn(move |_, _| SharedHttpConnector::new(connector.clone()));
                let client = if delegated {
                    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
                    let authorization = Arc::new(Authorization::new(
                        "fixture".into(),
                        Configuration {
                            endpoint: "https://storage.example".into(),
                            region: "auto".into(),
                            expires_at: now().unwrap() + 60,
                            requested_lifetime: 60,
                        },
                        socket,
                    ));
                    {
                        let mut state = authorization.state.lock().unwrap();
                        state.connection = None;
                        state.requests.insert(Unsigned::new("HEAD", "key"),
                            "https://storage.example/fixture/key?X-Amz-Signature=secret&X-Amz-Security-Token=token".into());
                    }
                    http_client(client, authorization)
                } else {
                    client.into()
                };
                let client = aws_sdk_s3::Client::from_conf(
                    Builder::new()
                        .behavior_version_latest()
                        .region(Region::new("auto"))
                        .endpoint_url("https://storage.example")
                        .force_path_style(true)
                        .credentials_provider(Credentials::new(
                            "fixture", "fixture", None, None, "test",
                        ))
                        .retry_config(RetryConfig::standard().with_max_attempts(2))
                        .http_client(client)
                        .build(),
                );
                client
                    .head_object()
                    .bucket("fixture")
                    .key("key")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 2);
            }
        }
    }

    #[test]
    fn sdk_telemetry_and_ranges_do_not_change_the_prepared_request() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let authorization = Authorization::new(
            "fixture".into(),
            Configuration {
                endpoint: "https://storage.example".into(),
                region: "auto".into(),
                expires_at: 0,
                requested_lifetime: 0,
            },
            socket,
        );
        let mut request = http::Request::builder().method("PUT")
            .uri("https://storage.example/fixture/a%20%2B%3F%23%E9%9B%AA?uploadId=a%2B%2F%3D&partNumber=1&x-id=UploadPart")
            .header("content-length", "123").header("x-amz-checksum-sha256", "checksum")
            .header("x-amz-user-agent", "sdk/changes-between-attempts")
            .header("x-amz-sdk-checksum-algorithm", "SHA256")
            .header("x-amz-date", "today").body(()).unwrap();
        assert_eq!(
            describe(&mut request, &authorization).unwrap(),
            Unsigned::new("PUT", "a +?#雪")
                .query("uploadId", "a+/=")
                .query("partNumber", "1")
                .header("content-length", "123")
                .header("x-amz-checksum-sha256", "checksum")
        );
        let mut request = http::Request::builder()
            .uri("https://storage.example/fixture/key")
            .header("if-match", "etag")
            .header("range", "bytes=5-10")
            .body(())
            .unwrap();
        assert_eq!(
            describe(&mut request, &authorization).unwrap(),
            Unsigned::new("GET", "key").header("if-match", "etag")
        );
        *request.uri_mut() = "https://another.example/fixture/key".parse().unwrap();
        assert!(describe(&mut request, &authorization).is_err());
    }
}
