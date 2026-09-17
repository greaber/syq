use super::*;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn cancellation_retires_buffered_and_file_uploads_and_rejects_new_requests() {
    for synchronous in [false, true] {
        for await_response in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().canonicalize().unwrap().join("source");
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
                .0
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
                .config_override(crate::s3::client::upload_config())
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
                .config_override(crate::s3::client::upload_config())
                .send()
                .await
                .is_err());
        }
    }
}
