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
                .map_err(|_| {
                    failure("direct storage connection failed; signed request details suppressed")
                })
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

pub(super) fn describe<B>(
    request: &mut http::Request<B>,
    authorization: &Authorization,
) -> Result<Unsigned> {
    let url = url::Url::parse(&request.uri().to_string()).context("invalid storage request URL")?;
    let endpoint = url::Url::parse(&authorization.configuration.endpoint)?;
    anyhow::ensure!(
        url.scheme() == endpoint.scheme()
            && url.host_str() == endpoint.host_str()
            && url.port_or_known_default() == endpoint.port_or_known_default(),
        "storage request endpoint differs from authorization"
    );
    let prefix = format!("{}/", endpoint.path().trim_end_matches('/'));
    let resource = request
        .uri()
        .path()
        .strip_prefix(&prefix)
        .context("storage request path differs from authorization")?;
    let (bucket, key) = resource.split_once('/').unwrap_or((resource, ""));
    let key = percent_encoding::percent_decode_str(key)
        .decode_utf8()
        .context("storage key is not UTF-8")?;
    let mut result =
        Unsigned::new(request.method().as_str(), &key).bucket(bucket, &authorization.bucket);
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
        if signed_header(name.as_str(), request.method().as_str())
            && !(name == "content-length" && request.headers().contains_key("x-amz-copy-source"))
        {
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
