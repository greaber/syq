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
    // Start that read, then drop the body before it completes.
    let started = std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut chunks).poll_frame(cx)));
    if let Poll::Ready(frame) = started.await {
        drop(frame);
    }
    drop(chunks);
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
