use super::*;
use http_body::Body as _;
use std::{collections::HashSet, time::Duration};

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// A source for `contents`, selected the way an upload selects it.
fn opened(temp: &std::path::Path, contents: &[u8]) -> Arc<Opened> {
    let path = temp.join("source");
    std::fs::write(&path, contents).unwrap();
    // Changes made within the clock tick of creation could keep the same
    // timestamps; start from an old modification time.
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1 << 30))
        .unwrap();
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
    let file = source.open().unwrap();
    Arc::new(Opened { file, source })
}

fn pool(max_idle: usize) -> &'static Pool {
    Box::leak(Box::new(Pool::new(max_idle)))
}

async fn frame<B: http_body::Body<Data = Bytes> + Unpin>(
    body: &mut B,
) -> Option<Result<Bytes, B::Error>> {
    std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx))
        .await
        .map(|frame| frame.map(|frame| frame.into_data().unwrap()))
}

async fn eventually_idle(pool: &Pool, count: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while pool.idle().len() != count {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} idle buffers, not {count}", pool.idle().len()));
}

#[tokio::test]
async fn chunks_read_the_range_and_reuse_released_buffers() {
    let temp = crate::test_support::tempdir().unwrap();
    let data = patterned(4 * CHUNK + 300);
    let opened = opened(temp.path(), &data);
    let pool = pool(8);
    let (offset, length) = (100, 2 * CHUNK as u64 + 7);
    let mut chunks = Chunks::new(opened.clone(), offset, length, pool);
    assert_eq!(chunks.size_hint().exact(), Some(length));
    let mut read = Vec::new();
    let mut addresses = HashSet::new();
    while let Some(bytes) = frame(&mut chunks).await {
        let bytes = bytes.unwrap();
        assert!(bytes.len() <= CHUNK);
        addresses.insert(bytes.as_ptr());
        read.extend_from_slice(&bytes);
    }
    assert!(chunks.is_end_stream());
    assert_eq!(read, data[offset as usize..][..length as usize]);
    // Each chunk was released before the next read, so one buffer served all.
    assert_eq!(addresses.len(), 1);
    assert_eq!(pool.idle().len(), 1);
}

#[tokio::test]
async fn an_empty_pool_allocates_and_keeps_at_most_its_cap() {
    let temp = crate::test_support::tempdir().unwrap();
    let opened = opened(temp.path(), &patterned(4 * CHUNK));
    let pool = pool(2);
    let mut chunks = Chunks::new(opened, 0, 4 * CHUNK as u64, pool);
    // Holding every chunk takes a new buffer for each one.
    let mut held = Vec::new();
    while let Some(bytes) = frame(&mut chunks).await {
        held.push(bytes.unwrap());
        assert!(pool.idle().is_empty());
    }
    assert_eq!(held.len(), 4);
    drop(held);
    assert_eq!(pool.idle().len(), 2);
}

#[tokio::test]
async fn bodies_shorter_than_a_chunk_do_not_use_the_pool() {
    let temp = crate::test_support::tempdir().unwrap();
    let opened = opened(temp.path(), b"short body");
    let pool = pool(2);
    let mut chunks = Chunks::new(opened, 6, 4, pool);
    assert_eq!(&frame(&mut chunks).await.unwrap().unwrap()[..], b"body");
    assert!(frame(&mut chunks).await.is_none());
    assert!(pool.idle().is_empty());
}

/// Every copy of the body the SDK takes for a new attempt starts again at the
/// range's first byte, however far the previous attempt got.
#[tokio::test]
async fn copies_of_the_body_start_from_the_beginning() {
    let temp = crate::test_support::tempdir().unwrap();
    let data = patterned(3 * CHUNK);
    let opened = opened(temp.path(), &data);
    let mut body = body(
        opened.source.clone(),
        opened.source.open().unwrap(),
        CHUNK as u64,
        2 * CHUNK as u64,
    );
    let first = frame(&mut body).await.unwrap().unwrap();
    assert_eq!(first, data[CHUNK..2 * CHUNK]);
    let mut copy = body.try_clone().expect("the body can be sent again");
    let mut resent = Vec::new();
    while let Some(bytes) = frame(&mut copy).await {
        resent.extend_from_slice(&bytes.unwrap());
    }
    assert_eq!(resent, data[CHUNK..]);
}

#[tokio::test]
async fn a_source_that_shrinks_fails_the_body_and_returns_its_buffer() {
    let temp = crate::test_support::tempdir().unwrap();
    let opened = opened(temp.path(), &patterned(3 * CHUNK));
    let pool = pool(8);
    let mut chunks = Chunks::new(opened.clone(), 0, 3 * CHUNK as u64, pool);
    drop(frame(&mut chunks).await.unwrap().unwrap());
    std::fs::File::options()
        .write(true)
        .open(temp.path().join("source"))
        .unwrap()
        .set_len(CHUNK as u64 + 10)
        .unwrap();
    let error = frame(&mut chunks).await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("source changed during S3 copy"),
        "{error}"
    );
    assert_eq!(pool.idle().len(), 1);
}

/// A change that keeps the size shows in the timestamps, which the read of
/// the last chunk checks before the body can finish.
#[tokio::test]
async fn a_source_changed_in_place_fails_the_last_chunk() {
    use std::os::unix::fs::FileExt as _;
    let temp = crate::test_support::tempdir().unwrap();
    let opened = opened(temp.path(), &patterned(2 * CHUNK));
    let pool = pool(8);
    let mut chunks = Chunks::new(opened.clone(), 0, 2 * CHUNK as u64, pool);
    drop(frame(&mut chunks).await.unwrap().unwrap());
    std::fs::File::options()
        .write(true)
        .open(temp.path().join("source"))
        .unwrap()
        .write_all_at(b"changed", 0)
        .unwrap();
    let error = frame(&mut chunks).await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("source changed during S3 copy"),
        "{error}"
    );
    assert!(!chunks.is_end_stream());
    assert_eq!(pool.idle().len(), 1);
}

/// Dropping a body, as cancellation does, while a read is in flight still
/// returns that read's buffer when the read finishes.
#[tokio::test]
async fn a_body_dropped_mid_read_returns_its_buffer() {
    let temp = crate::test_support::tempdir().unwrap();
    let opened = opened(temp.path(), &patterned(3 * CHUNK));
    let pool = pool(8);
    let mut chunks = Chunks::new(opened.clone(), 0, 3 * CHUNK as u64, pool);
    // The first chunk's buffer is the only one, so the next read takes it.
    drop(frame(&mut chunks).await.unwrap().unwrap());
    assert_eq!(pool.idle().len(), 1);
    // Holding the pool's lock stops that read before it takes the buffer, so
    // it is still pending when the body is dropped.
    let idle = pool.idle();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(Pin::new(&mut chunks).poll_frame(&mut cx).is_pending());
    drop(chunks);
    drop(idle);
    // The abandoned read holds the last other reference until it finishes.
    tokio::time::timeout(Duration::from_secs(10), async {
        while Arc::strong_count(&opened) > 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the abandoned read finishes");
    // A buffer kept by the abandoned read would leave the pool empty.
    eventually_idle(pool, 1).await;
}

/// The SDK sends the body unchanged next to a precomputed request checksum,
/// as storage-authorized uploads do.
#[tokio::test]
async fn the_sdk_sends_the_body_that_matches_its_request_checksum() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temp = crate::test_support::tempdir().unwrap();
    let data = patterned(2 * CHUNK + 11);
    let opened = opened(temp.path(), &data);
    let checksum = crate::s3::checksum::Algorithm::Sha256
        .digest(&data)
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        let header = |name: &str| {
            head.lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim().to_owned())
        };
        let length: usize = header("content-length").unwrap().parse().unwrap();
        let mut body = vec![0; length];
        socket.read_exact(&mut body).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nETag: \"x\"\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        (header("x-amz-checksum-sha256"), body)
    });
    let sdk =
        aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "fixture",
                ))
                .stalled_stream_protection(
                    aws_sdk_s3::config::StalledStreamProtectionConfig::disabled(),
                )
                .endpoint_url(endpoint)
                .force_path_style(true)
                .request_checksum_calculation(
                    aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
                )
                .build(),
        );
    sdk.put_object()
        .bucket("bucket")
        .key("object")
        .body(aws_sdk_s3::primitives::ByteStream::new(body(
            opened.source.clone(),
            opened.source.open().unwrap(),
            0,
            data.len() as u64,
        )))
        .content_length(data.len() as i64)
        .checksum_sha256(&checksum)
        .customize()
        .config_override(crate::s3::client::without_sdk_retries())
        .disable_payload_signing()
        .send()
        .await
        .unwrap();
    let (header, received) = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(header.as_deref(), Some(checksum.as_str()));
    assert!(received == data, "the body differs from the file");
}

/// An SDK client whose uploads go to a local server that reads each request
/// and answers 200.
async fn sdk() -> (aws_sdk_s3::Client, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let Ok(byte) = socket.read_u8().await else {
                        return;
                    };
                    head.push(byte);
                }
                let length: u64 = String::from_utf8(head)
                    .unwrap()
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse().unwrap())
                    .unwrap();
                let mut body = (&mut socket).take(length);
                if tokio::io::copy(&mut body, &mut tokio::io::sink())
                    .await
                    .ok()
                    == Some(length)
                {
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 OK\r\nETag: \"x\"\r\nContent-Length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
        ))
        .build_https();
    let client =
        aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "fixture",
                ))
                .stalled_stream_protection(
                    aws_sdk_s3::config::StalledStreamProtectionConfig::disabled(),
                )
                .endpoint_url(endpoint)
                .force_path_style(true)
                .http_client(http)
                .request_checksum_calculation(
                    aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
                )
                .build(),
        );
    (client, server)
}

/// Upload `length` bytes of `file`, opened for `source`, through the upload
/// retry loop with up to `retries` retries.
async fn sdk_upload(
    source: &Source,
    file: &File,
    length: u64,
    retries: u32,
) -> (usize, Duration, anyhow::Error, bool) {
    let (client, server) = sdk().await;
    let result = crate::s3::upload_send::tests::failed_upload_stopping(retries, || {
        client
            .put_object()
            .bucket("bucket")
            .key("object")
            .body(aws_sdk_s3::primitives::ByteStream::new(body(
                source.clone(),
                file.try_clone().unwrap(),
                0,
                length,
            )))
            .content_length(length as i64)
            .customize()
            .config_override(crate::s3::client::without_sdk_retries())
            .disable_payload_signing()
            .send()
    })
    .await;
    server.abort();
    result
}

/// A source that changes in place, shrinks or is removed during an upload
/// fails it after one attempt, without backoff, and is not taken for an
/// outage.
#[tokio::test]
async fn a_changed_source_fails_the_upload_without_retries() {
    use std::os::unix::fs::FileExt as _;
    for change in ["in place", "shrunk", "removed"] {
        let temp = crate::test_support::tempdir().unwrap();
        let length = 2 * CHUNK + 11;
        let opened = opened(temp.path(), &patterned(length));
        let path = temp.path().join("source");
        match change {
            "in place" => std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .write_all_at(b"changed", 0)
                .unwrap(),
            "shrunk" => std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(CHUNK as u64 + 10)
                .unwrap(),
            _ => std::fs::remove_file(&path).unwrap(),
        }
        let (attempts, _, error, stopped) =
            sdk_upload(&opened.source, &opened.file, length as u64, 8).await;
        assert_eq!((attempts, stopped), (1, false), "{change}: {error:#}");
        assert!(
            format!("{error:#}").contains("source changed during S3 copy"),
            "{change}: {error:#}"
        );
    }
}

/// An error reading an unchanged source may pass, so the upload retries it
/// with backoff, and running out of retries counts toward the outage stop.
#[tokio::test]
async fn a_read_error_is_retried() {
    let temp = crate::test_support::tempdir().unwrap();
    let length = 2 * CHUNK + 11;
    let opened = opened(temp.path(), &patterned(length));
    // Reading a write-only handle fails, while its metadata still matches.
    let write_only = std::fs::File::options()
        .write(true)
        .open(temp.path().join("source"))
        .unwrap();
    let (attempts, waited, error, stopped) =
        sdk_upload(&opened.source, &write_only, length as u64, 2).await;
    assert_eq!((attempts, stopped), (3, true), "{error:#}");
    assert!(waited >= Duration::from_millis(300), "{waited:?}");
    assert!(
        !format!("{error:#}").contains("source changed"),
        "{error:#}"
    );
}
