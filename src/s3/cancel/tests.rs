use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn cancellation_retires_buffered_and_file_uploads_and_rejects_new_requests() {
    for from_file in [false, true] {
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
            let transport = aws_smithy_http_client::Builder::new()
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
                    .http_client(client(transport, cancellation.clone()))
                    .request_checksum_calculation(
                        aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
                    )
                    .build(),
            );
            let stream = if from_file {
                let file = source.open().unwrap();
                let opened = crate::s3::file_body::Opened::new(source, file, None);
                aws_sdk_s3::primitives::ByteStream::new(crate::s3::file_body::body(
                    &opened, 0, size,
                ))
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
            let worker = tokio::spawn(request.send());
            let observed = tokio::time::timeout(Duration::from_secs(10), started).await;
            // Also release the request if the fixture failed to start.
            cancellation.cancel();
            let outcome = tokio::time::timeout(Duration::from_secs(10), worker).await;
            assert!(observed.unwrap().is_ok());
            assert!(outcome.unwrap().unwrap().is_err());
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
        let transport = aws_smithy_http_client::Builder::new()
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
                .http_client(client(transport, cancellation.clone()))
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

/// After cancellation a multipart upload's abort still goes out, so an upload
/// without a recovery record is not left on the server, but only for the
/// grace: a server that does not answer, stalls its reply, or asks for a
/// later retry cannot hold up cancellation.
#[tokio::test]
async fn multipart_aborts_still_go_out_for_a_while_after_cancellation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let server = tokio::spawn({
        let seen = seen.clone();
        async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = socket.read_u8().await else {
                            return;
                        };
                        headers.push(byte);
                    }
                    let line = String::from_utf8_lossy(&headers)
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned();
                    seen.lock().unwrap().push(line.clone());
                    let reply: &[u8] = if line.contains("/bucket/answered?") {
                        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                    } else if line.contains("/bucket/throttled?") {
                        b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 20\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                    } else if line.contains("/bucket/partial?") {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 128\r\n\r\n<"
                    } else {
                        b""
                    };
                    socket.write_all(reply).await.unwrap();
                    let mut buffer = [0; 1024];
                    while matches!(socket.read(&mut buffer).await, Ok(1..)) {}
                });
            }
        }
    });
    let cancellation = Arc::new(Cancellation::default());
    let transport = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
        ))
        .build_https();
    // Retries as copies make them.
    let sdk =
        aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "fixture",
                ))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .retry_config(
                    aws_sdk_s3::config::retry::RetryConfig::standard().with_max_attempts(3),
                )
                .retry_classifier(crate::s3::client::Throttling)
                .sleep_impl(aws_sdk_s3::config::SharedAsyncSleep::new(Sleep(
                    cancellation.clone(),
                )))
                .timeout_config(crate::s3::client::request_timeouts())
                .stalled_stream_protection(
                    aws_sdk_s3::config::StalledStreamProtectionConfig::disabled(),
                )
                .http_client(client(transport, cancellation.clone()))
                .build(),
        );
    let abort = |key: &'static str| {
        sdk.abort_multipart_upload()
            .bucket("bucket")
            .key(key)
            .upload_id("upload")
            .send()
    };
    let cancelled = tokio::time::Instant::now();
    cancellation.cancel();
    abort("answered").await.unwrap();
    let delete = sdk.delete_object().bucket("bucket").key("other").send();
    let (silent, partial, throttled, delete) =
        tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(
                abort("silent"),
                abort("partial"),
                abort("throttled"),
                delete
            )
        })
        .await
        .unwrap();
    assert!(silent.is_err());
    assert!(partial.is_err());
    assert!(throttled.is_err());
    assert!(delete.is_err());
    assert!(cancelled.elapsed() >= ABORT_GRACE);
    // Not the 20 seconds the server asked the throttled abort to wait.
    assert!(cancelled.elapsed() < ABORT_GRACE + Duration::from_secs(3));
    // The grace is counted from cancellation, not from each abort.
    let late = tokio::time::Instant::now();
    assert!(abort("answered").await.is_err());
    assert!(late.elapsed() < Duration::from_secs(1));
    let mut seen = seen.lock().unwrap().clone();
    seen.sort();
    assert_eq!(seen.len(), 4, "{seen:?}");
    for (line, key) in seen
        .iter()
        .zip(["answered", "partial", "silent", "throttled"])
    {
        assert!(
            line.starts_with(&format!("DELETE /bucket/{key}?")) && line.contains("uploadId=upload"),
            "{line}"
        );
    }
    server.abort();
}
