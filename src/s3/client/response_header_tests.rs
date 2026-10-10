use super::*;
use aws_smithy_runtime_api::client::{
    http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
    orchestrator::{HttpRequest, HttpResponse},
};
use aws_smithy_types::body::SdkBody;

#[derive(Debug, Clone)]
struct ResponseHeaders {
    name: &'static str,
    value: &'static [u8],
}

impl HttpConnector for ResponseHeaders {
    fn call(&self, _: HttpRequest) -> HttpConnectorFuture {
        let response = http::Response::builder()
            .status(200)
            .header("content-length", "0")
            .header("etag", "\"fixture\"")
            .header("x-amz-meta-keep", "existing")
            .header(
                self.name,
                http::HeaderValue::from_bytes(self.value).unwrap(),
            )
            .body(SdkBody::empty())
            .unwrap();
        // Exercise the raw HTTP-to-Smithy conversion before the SDK parses its
        // modeled headers. String-only fixtures cannot represent this case.
        HttpConnectorFuture::ready(Ok(HttpResponse::try_from(response).unwrap()))
    }
}

fn client(name: &'static str, value: &'static [u8]) -> Client {
    Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "fixture",
            ))
            .retry_config(RetryConfig::disabled())
            .http_client(http_client_fn(move |_, _| {
                SharedHttpConnector::new(ResponseHeaders { name, value })
            }))
            .build(),
    )
}

#[tokio::test]
async fn unreadable_metadata_headers_fail_head_and_get() {
    // 0xe9 is legal in an HTTP header, but is not a complete UTF-8 character.
    // A successful response with a missing value would let metadata replacement
    // erase an attribute that the source actually supplied.
    for (name, member) in [
        ("content-disposition", "ContentDisposition"),
        ("x-amz-meta-label", "Metadata"),
    ] {
        let client = client(name, b"caf\xe9");
        let error = client
            .head_object()
            .bucket("bucket")
            .key("object")
            .send()
            .await
            .expect_err("HEAD must reject unreadable metadata");
        let message = aws_smithy_types::error::display::DisplayErrorContext(&error).to_string();
        assert!(message.contains(member), "{name}: {message}");
        let error = client
            .get_object()
            .bucket("bucket")
            .key("object")
            .send()
            .await
            .expect_err("GET must reject unreadable metadata");
        let message = aws_smithy_types::error::display::DisplayErrorContext(&error).to_string();
        assert!(message.contains(member), "{name}: {message}");
    }
}

#[tokio::test]
async fn readable_headers_survive_metadata_replacement() {
    for name in ["content-disposition", "x-amz-meta-label"] {
        for value in ["plain", "café"] {
            let client = client(name, value.as_bytes());
            let head = client
                .head_object()
                .bucket("bucket")
                .key("object")
                .send()
                .await
                .unwrap();
            let request = metadata_update_request("bucket", "object", &head, &head, &[]).unwrap();
            assert_eq!(request.headers[name], value);
            assert_eq!(request.headers["x-amz-meta-keep"], "existing");
            assert_eq!(request.headers["x-amz-metadata-directive"], "REPLACE");
            let get = client
                .get_object()
                .bucket("bucket")
                .key("object")
                .send()
                .await
                .unwrap();
            assert_eq!(get.metadata(), head.metadata());
            assert_eq!(get.content_disposition(), head.content_disposition());
        }
    }
}
