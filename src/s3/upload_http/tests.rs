use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn file_upload_accepts_precomputed_digest_but_rejects_placeholder_hash() {
    let checksum = crate::s3::checksum::Algorithm::Sha256
        .digest(b"abc")
        .unwrap();
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for (query, native, signed, valid) in [
        ("", Some(checksum.as_str()), digest, true),
        ("", Some(checksum.as_str()), empty, false),
        ("", Some(checksum.as_str()), "UNSIGNED-PAYLOAD", false),
        ("", None, "UNSIGNED-PAYLOAD", true),
        ("", None, empty, false),
        (
            "?uploadId=id&partNumber=1",
            Some(checksum.as_str()),
            "UNSIGNED-PAYLOAD",
            true,
        ),
    ] {
        let mut request = http::Request::builder()
            .method("PUT")
            .uri(format!("https://storage.example/bucket/key{query}"))
            .header("x-amz-content-sha256", signed);
        if let Some(native) = native {
            request = request.header("x-amz-checksum-sha256", native);
        }
        assert_eq!(
            check_payload(&request.body(SdkBody::empty()).unwrap()).is_ok(),
            valid
        );
    }
}

#[tokio::test]
async fn cancellation_retires_buffered_and_file_uploads_and_rejects_new_requests() {
    for synchronous in [false, true] {
        for phase in ["upload", "response-headers", "response-body"] {
            let await_response = phase != "upload";
            let temp = crate::test_support::tempdir().unwrap();
            let path = temp.path().join("source");
            let size = if await_response {
                4096
            } else {
                16 * 1024 * 1024
            };
            std::fs::File::create(&path).unwrap().set_len(size).unwrap();
            let args = crate::cli::Args::parse_args(
                &[
                    "cp",
                    path.to_str().unwrap(),
                    "--to",
                    "s3://bucket",
                    "--as",
                    "object",
                ]
                .map(std::ffi::OsString::from),
            )
            .unwrap();
            let source = crate::s3::local::upload_plan(&args)
                .unwrap()
                .sources
                .pop()
                .unwrap();
            let file = FileBody::new(source, 0, size);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (ready, started) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(socket.read_u8().await.unwrap());
                    assert!(headers.len() < 65536);
                }
                if await_response {
                    let mut data = vec![0; size as usize];
                    socket.read_exact(&mut data).await.unwrap();
                    assert!(data.iter().all(|b| *b == 0));
                }
                if phase == "response-body" {
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\nx")
                        .await
                        .unwrap();
                }
                ready.send(()).unwrap();
                // Do not send a response. Cancellation must retire the client
                // without a provider reply or a request-duration timeout.
                let mut buffer = [0; 65536];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            let cancellation = Arc::new(Cancellation::default());
            let fallback = aws_smithy_http_client::Builder::new()
                .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                    aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
                ))
                .build_https();
            let sdk = aws_sdk_s3::Client::from_conf(
                aws_sdk_s3::config::Builder::new()
                    .behavior_version_latest()
                    .region(aws_sdk_s3::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_s3::config::Credentials::new(
                        "test", "test", None, None, "fixture",
                    ))
                    .timeout_config(crate::s3::client::request_timeouts())
                    .stalled_stream_protection(
                        aws_sdk_s3::config::StalledStreamProtectionConfig::disabled(),
                    )
                    .endpoint_url(endpoint)
                    .force_path_style(true)
                    .http_client(client(fallback, cancellation.clone()))
                    .request_checksum_calculation(
                        aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
                    )
                    .build(),
            );
            let stream = if synchronous {
                body(size)
            } else {
                aws_sdk_s3::primitives::ByteStream::from(vec![0; size as usize])
            };
            let request = sdk
                .put_object()
                .bucket("bucket")
                .key("object")
                .content_length(size as i64)
                .body(stream)
                .customize()
                .config_override(crate::s3::client::without_sdk_retries())
                .disable_payload_signing();
            let request = if synchronous {
                request.interceptor(file.clone())
            } else {
                request
            };
            let worker = tokio::spawn(request.send());
            let observed = tokio::time::timeout(Duration::from_secs(10), started).await;
            // Also release the blocking worker if the fixture failed to start.
            cancellation.cancel();
            let outcome = tokio::time::timeout(Duration::from_secs(10), async {
                let outcome = worker.await.unwrap();
                file.drain().await;
                outcome
            })
            .await;
            assert!(observed.unwrap().is_ok());
            assert!(outcome.unwrap().is_err());
            assert_eq!(file.active.count.load(Ordering::Acquire), 0);
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .unwrap()
                .unwrap();
            assert!(sdk
                .put_object()
                .bucket("bucket")
                .key("later")
                .customize()
                .config_override(crate::s3::client::without_sdk_retries())
                .send()
                .await
                .is_err());
        }
    }
}

#[tokio::test]
async fn cancellation_retires_download_and_control_response_bodies() {
    for control in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (ready, started) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(socket.read_u8().await.unwrap());
                assert!(headers.len() < 65536);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 128\r\n\r\nx")
                .await
                .unwrap();
            ready.send(()).unwrap();
            let mut buffer = [0; 128];
            assert!(matches!(socket.read(&mut buffer).await, Ok(0) | Err(_)));
        });
        let cancellation = Arc::new(Cancellation::default());
        let fallback = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
            ))
            .build_https();
        let sdk = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "fixture",
                ))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
                .timeout_config(crate::s3::client::request_timeouts())
                .stalled_stream_protection(
                    aws_sdk_s3::config::StalledStreamProtectionConfig::disabled(),
                )
                .http_client(client(fallback, cancellation.clone()))
                .build(),
        );
        let worker = tokio::spawn(async move {
            if control {
                sdk.list_objects_v2()
                    .bucket("bucket")
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(anyhow::Error::from)
            } else {
                let response = sdk
                    .get_object()
                    .bucket("bucket")
                    .key("object")
                    .send()
                    .await?;
                response
                    .body
                    .collect()
                    .await
                    .map(|_| ())
                    .map_err(anyhow::Error::from)
            }
        });
        tokio::time::timeout(Duration::from_secs(10), started)
            .await
            .unwrap()
            .unwrap();
        // Give the client time to receive the headers and start consuming the
        // unfinished response; cancellation must cover this later phase too.
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancellation.cancel();
        assert!(tokio::time::timeout(Duration::from_secs(10), worker)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[path = "../../../tests/support/https.rs"]
mod https;

#[test]
fn file_upload_uses_system_certificates() {
    // A child process keeps its root-store cache and environment isolated even
    // when this test is run with the multithreaded cargo test harness.
    let Ok(endpoint) = std::env::var("SYQ_TEST_FILE_UPLOAD_TLS_ENDPOINT") else {
        use crate::process::CommandExt as _;
        let temp = crate::test_support::tempdir().unwrap();
        let server = https::Server::start("127.0.0.1");
        let ca = temp.path().join("ca.pem");
        std::fs::write(&ca, &server.ca).unwrap();
        std::fs::write(temp.path().join("source"), b"file upload through HTTPS").unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "s3::upload_http::tests::file_upload_uses_system_certificates",
                "--nocapture",
            ])
            .current_dir(temp.path())
            .env("SYQ_TEST_FILE_UPLOAD_TLS_ENDPOINT", server.url())
            .env("SSL_CERT_FILE", ca)
            .env_remove("SSL_CERT_DIR")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .capture_output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].1, b"file upload through HTTPS");
        return;
    };
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let args = crate::cli::Args::parse_args(
            &["cp", "source", "--to", "s3://bucket", "--as", "object"]
                .map(std::ffi::OsString::from),
        )
        .unwrap();
        let source = crate::s3::local::upload_plan(&args)
            .unwrap()
            .sources
            .pop()
            .unwrap();
        let size = std::fs::metadata("source").unwrap().len();
        let file = FileBody::new(source, 0, size);
        let fallback = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
            ))
            .build_https();
        let sdk = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "fixture",
                ))
                .timeout_config(crate::s3::client::request_timeouts())
                .endpoint_url(endpoint)
                .force_path_style(true)
                .http_client(client(fallback, Arc::new(Cancellation::default())))
                .request_checksum_calculation(
                    aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
                )
                .build(),
        );
        sdk.put_object()
            .bucket("bucket")
            .key("object")
            .content_length(size as i64)
            .body(body(size))
            .customize()
            .config_override(crate::s3::client::without_sdk_retries())
            .disable_payload_signing()
            .interceptor(file.clone())
            .send()
            .await
            .unwrap();
        file.drain().await;
    });
}
