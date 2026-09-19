use super::*;

#[test]
fn resource_ceilings_bound_initial_and_adaptive_s3_concurrency() {
    for route in [
        Route::Upload,
        Route::Download,
        Route::ServerCopy {
            source_bucket: "source".into(),
        },
    ] {
        for size in [1024, 8 << 20, 32u64 << 30] {
            let mut engine = planning_engine(&["--resource-limits", "s3-max-concurrent-objects=3,s3-max-concurrent-requests=2,s3-max-concurrent-parts-per-object=1"]);
            engine.options.route = route.clone();
            engine.tuning.observe_control(Duration::from_millis(100));
            let workers = engine
                .object_workers(std::iter::repeat_n(size, 1024))
                .unwrap();
            assert!((1..=3).contains(&workers.initial));
            assert!(workers.maximum.is_none_or(|n| n <= 3));
            assert_eq!(engine.part_workers(), 1);
            assert!(engine.tuning.request_limit() <= 2);
            if let Some(maximum) = workers.maximum {
                engine.tuning.requests.finish_objects(maximum);
                assert!(engine.tuning.request_limit() <= 2);
            }
        }
    }
    let fixed = planning_engine(&["--performance-tuning", "s3-max-concurrent-objects=7,s3-max-concurrent-requests=6,s3-max-concurrent-parts-per-object=5"]);
    let workers = fixed
        .object_workers(std::iter::repeat_n(1024, 1024))
        .unwrap();
    assert_eq!(workers.initial, 7);
    assert!(workers.maximum.is_none());
    assert_eq!(fixed.tuning.request_limit(), 6);
    assert_eq!(fixed.part_workers(), 5);
}

#[test]
fn server_copy_threshold_tracks_single_request_scheduling() {
    let mut engine = planning_engine(&[]);
    engine.options.route = Route::ServerCopy {
        source_bucket: "source".into(),
    };
    let limit = 5 * 1024 * 1024 * 1024;
    assert_eq!(engine.copy_request_limit(32 << 20), limit);
    assert_eq!(engine.copy_request_limit(limit + 1), limit);
    assert_eq!((6u64 << 30).div_ceil(engine.part_size(6u64 << 30)), 24);
    assert_eq!(engine.part_workers(), engine.tuning.request_capacity());
    assert!(engine
        .object_workers([256 << 20; 100].into_iter())
        .unwrap()
        .maximum
        .is_some());
    assert!(engine
        .object_workers([limit + 1; 100].into_iter())
        .unwrap()
        .maximum
        .is_none());
    let mut explicit = planning_engine(&["--performance-tuning", "s3-part-size=64M"]);
    explicit.options.route = Route::ServerCopy {
        source_bucket: "source".into(),
    };
    assert_eq!(explicit.copy_request_limit(32 << 20), 64 << 20);
    assert!(explicit
        .object_workers([256 << 20; 100].into_iter())
        .unwrap()
        .maximum
        .is_none());
}

#[test]
fn server_copy_tuning_is_provider_neutral_and_respects_explicit_limits() {
    let mut observed = Vec::new();
    for endpoint in ["https://t3.storage.dev", "https://storage.example"] {
        for extra in [
            "",
            "s3-max-concurrent-requests=1",
            "s3-max-concurrent-requests=128",
            "s3-max-concurrent-parts-per-object=7",
        ] {
            let mut flags = vec!["--to", "s3://destination", "--s3-endpoint", endpoint];
            if !extra.is_empty() {
                flags.extend(["--performance-tuning", extra]);
            }
            let engine = planning_engine(&flags);
            assert!(!engine.tuning.tigris());
            engine.tuning.observe_control(Duration::from_millis(100));
            let workers = engine.object_workers([32u64 << 30].into_iter()).unwrap();
            let expected = match extra {
                "s3-max-concurrent-requests=1" => 1,
                "s3-max-concurrent-requests=128" => 128,
                "s3-max-concurrent-parts-per-object=7" => 7,
                _ => 256,
            };
            // A per-object queue follows the global exploration range,
            // not the initial 64 permits; explicit limits remain binding.
            assert_eq!(engine.part_workers(), expected);
            observed.push((
                workers.initial,
                engine.part_size(32u64 << 30),
                engine.part_workers(),
                engine.tuning.request_limit(),
            ));
            engine.object_workers([1024u64; 512].into_iter()).unwrap();
            assert_eq!(
                engine.tuning.request_limit(),
                match extra {
                    "s3-max-concurrent-requests=1" => 1,
                    "s3-max-concurrent-requests=128" => 128,
                    _ => 256,
                }
            );
        }
    }
    assert_eq!(observed[..4], observed[4..]);
}

#[tokio::test]
async fn fragmented_downloads_release_receive_buffers_and_preserve_bytes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct ReceiveBuffer(Vec<u8>, Arc<AtomicUsize>);
    impl AsRef<[u8]> for ReceiveBuffer {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl Drop for ReceiveBuffer {
        fn drop(&mut self) {
            self.1.fetch_sub(1, Ordering::Relaxed);
        }
    }
    struct FragmentBody {
        tiny: u8,
        live: Arc<AtomicUsize>,
        chunks: std::collections::VecDeque<bytes::Bytes>,
    }
    impl http_body::Body for FragmentBody {
        type Data = bytes::Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            if self.live.load(Ordering::Relaxed) != 0 {
                return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "previous tiny fragment still owns its receive buffer",
                ))));
            }
            let bytes = if self.tiny < 32 {
                let value = self.tiny;
                self.tiny += 1;
                let mut allocation = vec![0; 32 * 1024];
                allocation[..3].copy_from_slice(&[value, value + 1, value + 2]);
                self.live.fetch_add(1, Ordering::Relaxed);
                Some(
                    bytes::Bytes::from_owner(ReceiveBuffer(allocation, self.live.clone()))
                        .slice(..3),
                )
            } else {
                self.chunks.pop_front()
            };
            std::task::Poll::Ready(bytes.map(|b| Ok(http_body::Frame::data(b))))
        }
    }
    let mut expected: Vec<u8> = (0..32u8).flat_map(|v| [v, v + 1, v + 2]).collect();
    let mut chunks = std::collections::VecDeque::new();
    // Mix compacted and scatter batches, empty frames, the full-batch
    // boundary, scatter limit, large-chunk bypass, and all-tiny final tail.
    for (i, length) in [0, 4095, 4096, 8192, 3, 130_000, 300_000]
        .into_iter()
        .chain(std::iter::repeat_n(4096, 17))
        .chain([1, 2, 3])
        .enumerate()
    {
        let bytes: Vec<u8> = (0..length)
            .map(|n| (n as u8).wrapping_add(i as u8))
            .collect();
        expected.extend_from_slice(&bytes);
        chunks.push_back(bytes::Bytes::from(bytes));
    }
    let live = Arc::new(AtomicUsize::new(0));
    let body = ByteStream::new(aws_smithy_types::body::SdkBody::from_body_1_x(
        FragmentBody {
            tiny: 0,
            live: live.clone(),
            chunks,
        },
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output");
    std::fs::write(&path, b"prefix!").unwrap();
    let size = 7 + expected.len() as u64;
    let file = Arc::new(std::fs::OpenOptions::new().write(true).open(&path).unwrap());
    let writer = writer::Writer::with_readback(file, size, true).unwrap();
    let object = Object {
        key: "fragmented".into(),
        size,
        etag: "fixture".into(),
        version: None,
        metadata: None,
        mtime: 0,
    };
    let engine = planning_engine(&["--performance-tuning", "s3-retries=0"]);
    let hash = engine
        .download_fast_range(
            &object,
            &writer,
            7,
            expected.len() as u64,
            Some(body),
            None,
            Some(HashAlgorithm::Blake3),
        )
        .await
        .unwrap();
    writer.finish().await.unwrap();
    assert_eq!(
        hash,
        Digest::hash_bytes(HashAlgorithm::Blake3, &expected).value
    );
    let actual = std::fs::read(path).unwrap();
    assert_eq!(&actual[..7], b"prefix!");
    assert_eq!(&actual[7..], expected);
    assert_eq!(live.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn pending_read_exact_keeps_consumed_bytes_across_observations() {
    use tokio::io::AsyncWriteExt;
    let (mut send, mut recv) = tokio::io::duplex(4);
    let writer = tokio::spawn(async move {
        send.write_all(b"ab").await.unwrap();
        tokio::time::sleep(Duration::from_secs(120)).await;
        send.write_all(b"cd").await.unwrap();
    });
    let mut bytes = [0; 4];
    let mut waited = Duration::ZERO;
    let mut observations = 0;
    read_body(recv.read_exact(&mut bytes), &mut waited, |_| {
        observations += 1;
        false
    })
    .await
    .unwrap()
    .unwrap();
    writer.await.unwrap();
    assert!(observations >= 1);
    assert_eq!(&bytes, b"abcd");
}

pub(super) fn planning_engine(extra: &[&str]) -> Engine {
    let argv = [
        "cp",
        "--from",
        "s3://bucket",
        "object",
        "--as",
        "destination",
    ];
    let args = Arc::new(
        Args::parse_args(
            &argv
                .iter()
                .chain(extra)
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    let options = args.s3.clone().unwrap();
    let tuning = crate::s3::tuning::Tuning::new(
        &options,
        &args,
        Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
    );
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .build();
    Engine {
        args,
        options,
        tuning,
        client: Client::from_conf(config),
        progress: Progress::new(false, false, None, false),
        pace: Mutex::new(tokio::time::Instant::now()),
        upload_keys: OnceLock::new(),
        copy_checksum_unsupported: Default::default(),
        copy_tagging_unsupported: Default::default(),
        cancelled: Default::default(),
        cancel_wake: Default::default(),
        uploads: Default::default(),
    }
}

#[test]
fn completed_download_releases_blocking_capacity_for_secondary_hash() {
    for valid in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("destination");
        std::fs::write(&destination, b"original").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let data = b"verified through two distinct algorithms";
        let outcome = runtime.block_on(async {
            let engine = planning_engine(&["--integrity-checking=transfer=blake3"]);
            let root = Root::open(dir.path()).unwrap();
            let path = RelativePath::new(b"destination").unwrap();
            let expected = Digest::hash_bytes(HashAlgorithm::Sha256, data);
            let metadata = Metadata {
                kind: crate::s3::client::ObjectKind::File,
                mode: 0o644,
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                mtime: 1700000000,
                nsec: 0,
                hash: Some(
                    Digest::hash_bytes(
                        HashAlgorithm::Blake3,
                        if valid { data.as_slice() } else { b"wrong" },
                    )
                    .value,
                ),
                hash_algorithm: HashAlgorithm::Blake3,
            };
            let object = Object {
                key: "object".into(),
                size: data.len() as u64,
                etag: "fixture".into(),
                version: None,
                metadata: None,
                mtime: metadata.mtime,
            };
            tokio::time::timeout(
                Duration::from_secs(1),
                engine.download_single(
                    &object,
                    &root,
                    &path,
                    (&metadata, Some(&expected), Default::default()),
                    None,
                    Some(ByteStream::from_static(data)),
                    None,
                ),
            )
            .await
        });
        // Cancelling the copy drops its writer, allowing a failed baseline
        // test to shut down rather than leaving a blocked worker alive.
        runtime.shutdown_timeout(Duration::from_secs(1));
        let outcome = outcome.expect("completed writer starved secondary verification");
        if valid {
            assert_eq!(outcome.unwrap(), Some(data.len() as u64));
            assert_eq!(std::fs::read(&destination).unwrap(), data);
        } else {
            assert!(outcome.is_err());
            assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[tokio::test]
async fn small_download_search_preserves_seeds_mixed_batches_and_overrides() {
    let engine = planning_engine(&[]);
    engine.tuning.observe_control(Duration::from_millis(100));
    let concurrency = engine
        .object_workers(std::iter::repeat_n(64 * 1024, 8192))
        .unwrap();
    let maximum = concurrency.maximum.unwrap();
    assert!((1..=4096).contains(&maximum));
    assert_eq!(concurrency.initial, maximum.min(256));
    assert_eq!(engine.tuning.request_limit(), 256);

    // An average below 1 MiB does not make every object small. Keep the
    // existing target when even one larger object needs streaming buffers.
    let mixed = planning_engine(&[])
        .object_workers(std::iter::repeat_n(64 * 1024, 8192).chain([1024 * 1024]))
        .unwrap();
    assert_eq!(mixed.initial, 256);
    assert_eq!(mixed.maximum, Some(256));

    let fixed = planning_engine(&[
        "--performance-tuning",
        "s3-max-concurrent-objects=1024,s3-max-concurrent-requests=128",
    ]);
    let concurrency = fixed
        .object_workers(std::iter::repeat_n(64 * 1024, 8192))
        .unwrap();
    assert_eq!(concurrency.initial, 1024);
    assert!(concurrency.maximum.is_none());
    assert_eq!(fixed.tuning.request_limit(), 128);
}

#[tokio::test]
async fn whole_object_batches_start_conservatively_and_can_tune_higher() {
    for count in [16, 32, 33, 128, 4096] {
        let engine = planning_engine(&[]);
        let concurrency = engine
            .object_workers(std::iter::repeat_n(1024 * 1024, count))
            .unwrap();
        assert_eq!(engine.tuning.request_limit(), 32);
        assert_eq!(concurrency.maximum, (count > 32).then_some(count.min(256)));
        assert_eq!(concurrency.initial, 32);
        if count > 32 {
            let requests = concurrency.requests.unwrap();
            assert_eq!(requests.preparation_limit(), 33);
            assert_eq!(requests.begin_objects(concurrency.initial), Some(32));
            requests.finish_objects(concurrency.maximum.unwrap());
            assert_eq!(requests.preparation_limit(), count.min(256) + 1);
        }
    }
    for size_mib in [1, 2, 4, 8] {
        let engine = planning_engine(&[]);
        engine.tuning.observe_control(Duration::from_millis(100));
        let concurrency = engine
            .object_workers(std::iter::repeat_n(size_mib * 1024 * 1024, 512))
            .unwrap();
        assert_eq!(concurrency.initial, 32);
        assert_eq!(engine.tuning.request_limit(), 32);
        assert_eq!(concurrency.maximum, Some(256));
        let requests = concurrency.requests.unwrap();
        assert_eq!(requests.preparation_limit(), 33);
        assert_eq!(requests.begin_objects(concurrency.initial), Some(32));
    }
    for mode in ["--verify-only", "--dry-run"] {
        let engine = planning_engine(&[mode]);
        let concurrency = engine
            .object_workers(std::iter::repeat_n(1024 * 1024, 512))
            .unwrap();
        assert_eq!(concurrency.initial, 32);
        assert_eq!(engine.tuning.request_limit(), 32);
        assert!(concurrency.maximum.is_none());
    }
    let engine = planning_engine(&["--performance-tuning", "s3-max-concurrent-requests=64"]);
    let concurrency = engine
        .object_workers(std::iter::repeat_n(1024 * 1024, 512))
        .unwrap();
    assert_eq!(concurrency.initial, 64);
    assert_eq!(engine.tuning.request_limit(), 64);
    let engine = planning_engine(&["--performance-tuning", "s3-max-concurrent-objects=8"]);
    let concurrency = engine
        .object_workers(std::iter::repeat_n(1024 * 1024, 128))
        .unwrap();
    assert_eq!(concurrency.initial, 8);
    assert!(concurrency.maximum.is_none());
}

#[tokio::test]
async fn upload_memory_reservation_follows_the_last_sdk_body_clone() {
    let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let reservation = budget.clone().acquire_many_owned(8).await.unwrap();
    let body = aws_smithy_types::body::SdkBody::from(bytes::Bytes::from_owner(UploadBuffer {
        bytes: vec![42; 8],
        _reservation: reservation,
        _trace: None,
    }));
    let retry = body.try_clone().unwrap();
    drop(body);
    assert_eq!(retry.bytes(), Some(&[42; 8][..]));
    assert!(budget.try_acquire().is_err());
    drop(retry);
    assert_eq!(budget.available_permits(), 8);
}
