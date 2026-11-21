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
            let mut engine = planning_engine(&[
                "--resource-limits",
                "s3-objects=3,s3-requests=2,s3-parts-per-object=1",
            ]);
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
    let fixed = planning_engine(&[
        "--performance-tuning",
        "s3-objects=7,s3-requests=6,s3-parts-per-object=5",
    ]);
    let workers = fixed
        .object_workers(std::iter::repeat_n(1024, 1024))
        .unwrap();
    assert_eq!(workers.initial, 7);
    assert!(workers.maximum.is_none());
    assert_eq!(fixed.tuning.request_limit(), 6);
    assert_eq!(fixed.part_workers(), 5);
}

#[test]
fn objects_checked_beyond_the_transfer_limit_stay_within_set_limits() {
    let copy = || Route::ServerCopy {
        source_bucket: "source".into(),
    };
    let checking = |flags: &[&str], route: Route| {
        let mut engine = planning_engine(flags);
        engine.options.route = route;
        engine
            .object_workers(std::iter::repeat_n(8u64 << 20, 1024))
            .unwrap()
            .checking
            .map(|checking| checking.maximum)
    };
    assert_eq!(checking(&[], Route::Upload), Some(256));
    assert_eq!(checking(&[], Route::Download), Some(256));
    // A copy between buckets asks about the source and the destination.
    assert_eq!(checking(&[], copy()), Some(128));
    for (flag, route, expected) in [
        ("--resource-limits=s3-objects=40", Route::Upload, Some(40)),
        ("--resource-limits=s3-objects=40", copy(), Some(40)),
        (
            "--resource-limits=s3-requests=40",
            Route::Download,
            Some(40),
        ),
        ("--resource-limits=s3-requests=40", copy(), Some(20)),
        (
            "--performance-tuning=s3-requests=16",
            Route::Upload,
            Some(16),
        ),
        ("--performance-tuning=s3-requests=1", copy(), Some(1)),
        // A fixed object count is the number of objects in progress.
        ("--performance-tuning=s3-objects=7", Route::Upload, None),
    ] {
        assert_eq!(checking(&[flag], route), expected, "{flag}");
    }
    // Between buckets a request count the user set also admits each
    // object's own metadata requests, as before.
    for (flags, set) in [
        (&[][..], false),
        (&["--performance-tuning=s3-requests=16"][..], true),
        (&["--resource-limits=s3-requests=16"][..], true),
        (&["--resource-limits=s3-objects=16"][..], false),
    ] {
        assert_eq!(
            planning_engine(flags).tuning.requests_set(),
            set,
            "{flags:?}"
        );
    }
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
    for (endpoint, tigris) in [
        ("https://t3.storage.dev", true),
        ("https://storage.example", false),
    ] {
        for extra in [
            "",
            "s3-requests=1",
            "s3-requests=128",
            "s3-parts-per-object=7",
        ] {
            let mut flags = vec!["--to", "s3://destination", "--s3-endpoint", endpoint];
            if !extra.is_empty() {
                flags.extend(["--performance-tuning", extra]);
            }
            let engine = planning_engine(&flags);
            assert_eq!(engine.options.is_tigris(), tigris);
            assert!(!engine.tuning.tigris());
            engine.tuning.observe_control(Duration::from_millis(100));
            let workers = engine.object_workers([32u64 << 30].into_iter()).unwrap();
            let expected = match extra {
                "s3-requests=1" => 1,
                "s3-requests=128" => 128,
                "s3-parts-per-object=7" => 7,
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
                    "s3-requests=1" => 1,
                    "s3-requests=128" => 128,
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
    let dir = crate::test_support::tempdir().unwrap();
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
    let engine = planning_engine(&["--s3-retries", "0"]);
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

#[test]
fn far_small_copies_start_with_at_most_2048_objects_below_32_ms() {
    // Only a capacity above 2,048 shows the lower start; raise the soft
    // descriptor limit as the binary does at startup.
    crate::raise_nofile();
    room(MemoryRoom::Unlimited);
    for route in [Route::Upload, Route::Download] {
        let plan = |ms| {
            let mut engine = planning_engine(&[]);
            engine.options.route = route.clone();
            engine.tuning.observe_control(Duration::from_millis(ms));
            let workers = engine
                .object_workers(std::iter::repeat_n(1024, 10_000))
                .unwrap();
            (workers.initial, engine.tuning.request_limit())
        };
        // A far start admits as many requests as objects.
        let start = |ms| {
            let (objects, requests) = plan(ms);
            assert_eq!(requests, objects, "{route:?}, {ms} ms");
            objects
        };
        let capacity = start(100);
        assert!(
            capacity > 2048,
            "{route:?}: small-object capacity {capacity}"
        );
        assert_eq!(start(32), capacity, "{route:?}");
        assert_eq!(start(20), capacity.min(2048), "{route:?}");
        assert_eq!(start(31), capacity.min(2048), "{route:?}");
        // A near endpoint starts with 256 objects and ramps requests from 64.
        assert_eq!(plan(19), (256, 64), "{route:?}");
    }
}

fn room(room: MemoryRoom) {
    crate::s3::tuning::memory::TEST_ROOM.with(|test| test.set(Some(room)));
}

#[test]
fn far_small_downloads_widen_only_within_a_readable_memory_limit() {
    crate::raise_nofile();
    let mib = 1024 * 1024;
    // Objects, requests and ceiling a far download of 10,000 objects plans.
    let plan = |flags: &[&str], route: Route, size: u64, memory: MemoryRoom| {
        room(memory);
        let mut engine = planning_engine(flags);
        engine.options.route = route;
        engine.tuning.observe_control(Duration::from_millis(100));
        let workers = engine
            .object_workers(std::iter::repeat_n(size, 10_000))
            .unwrap();
        (
            workers.initial,
            engine.tuning.request_limit(),
            workers.maximum,
        )
    };
    let download = |memory, size| plan(&[], Route::Download, size, memory);
    let (capacity, _, _) = download(MemoryRoom::Unlimited, 64 * 1024);
    assert!(capacity > 2048, "small-object capacity {capacity}");
    assert_eq!(
        download(MemoryRoom::Unlimited, 64 * 1024),
        (capacity, capacity, Some(capacity))
    );
    // Unreadable memory keeps the near start; the ceiling is as before.
    assert_eq!(
        download(MemoryRoom::Unknown, 64 * 1024),
        (256, 256, Some(capacity))
    );
    // A limit bounds the start and the ceiling alike.
    let within = crate::s3::tuning::memory::objects_within(400 * mib, 64 * 1024);
    assert!((256..capacity).contains(&within));
    assert_eq!(
        download(MemoryRoom::Limited(400 * mib), 64 * 1024),
        (within, within, Some(within))
    );
    // Never below the near start, which also bounds growth then.
    assert_eq!(
        download(MemoryRoom::Limited(mib), 64 * 1024),
        (256, 256, Some(256))
    );
    // Set limits and counts still apply.
    let limited = &["--resource-limits", "s3-objects=300"][..];
    assert_eq!(
        plan(limited, Route::Download, 64 * 1024, MemoryRoom::Unlimited),
        (300, 300, Some(300))
    );
    let fixed = &["--performance-tuning", "s3-objects=3000"][..];
    assert_eq!(
        plan(fixed, Route::Download, 64 * 1024, MemoryRoom::Limited(mib)).0,
        3000
    );
    // Uploads do not read memory limits.
    assert_eq!(
        plan(&[], Route::Upload, 64 * 1024, MemoryRoom::Limited(mib)),
        plan(&[], Route::Upload, 64 * 1024, MemoryRoom::Unknown)
    );
}

/// Lowers the soft descriptor limit until dropped.
struct TightDescriptors(libc::rlimit);

impl TightDescriptors {
    /// Leaves too few descriptors for the small-object budget, but enough
    /// for the test itself.
    fn new() -> Self {
        let limits = crate::fsops::nofile_limits().unwrap();
        let open = crate::fsops::current_open_descriptor_count(limits.rlim_cur).unwrap();
        crate::fsops::set_nofile_limits(&libc::rlimit {
            rlim_cur: open as libc::rlim_t + 66,
            rlim_max: limits.rlim_max,
        })
        .unwrap();
        assert!(crate::s3::tuning::small_object_capacity(1024).is_err());
        Self(limits)
    }
}

impl Drop for TightDescriptors {
    fn drop(&mut self) {
        crate::fsops::set_nofile_limits(&self.0).unwrap();
    }
}

#[test]
fn small_downloads_read_the_descriptor_budget_only_where_they_did_before() {
    let plan = |flags: &[&str], far: bool, count: usize, memory: MemoryRoom| {
        room(memory);
        let engine = planning_engine(flags);
        if far {
            engine.tuning.observe_control(Duration::from_millis(100));
        }
        engine
            .object_workers(std::iter::repeat_n(1024, count))
            .map(|workers| (workers.initial, engine.tuning.request_limit()))
            .map_err(|error| error.to_string())
    };
    let _tight = TightDescriptors::new();
    // Paths that never read the budget still plan.
    assert_eq!(plan(&[], false, 100, MemoryRoom::Unlimited), Ok((256, 64)));
    assert_eq!(plan(&[], true, 100, MemoryRoom::Unknown), Ok((256, 256)));
    let dry = &["--dry-run"][..];
    assert_eq!(plan(dry, true, 10_000, MemoryRoom::Unknown), Ok((256, 256)));
    let fixed = &["--performance-tuning", "s3-objects=8"][..];
    assert_eq!(
        plan(fixed, true, 10_000, MemoryRoom::Unlimited),
        Ok((8, 256))
    );
    // A widened start that cannot read the budget keeps the near start.
    assert_eq!(plan(&[], true, 100, MemoryRoom::Unlimited), Ok((256, 256)));
    assert_eq!(
        plan(dry, true, 10_000, MemoryRoom::Limited(1 << 30)),
        Ok((256, 256))
    );
    // A batch large enough for the controller reads it, as before.
    assert!(plan(&[], false, 10_000, MemoryRoom::Unlimited).is_err());
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
    super::super::tests::engine(&[&argv, extra].concat())
}

#[test]
fn completed_download_releases_blocking_capacity_for_secondary_hash() {
    for valid in [true, false] {
        let dir = crate::test_support::tempdir().unwrap();
        let destination = dir.path().join("destination");
        std::fs::write(&destination, b"original").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let data = b"verified through two distinct algorithms";
        let outcome = runtime.block_on(async {
            let engine =
                planning_engine(&["--if-exists=update", "--integrity-checking=transfer=blake3"]);
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
                    (None, None),
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
    room(MemoryRoom::Unlimited);
    let engine = planning_engine(&[]);
    engine.tuning.observe_control(Duration::from_millis(100));
    let concurrency = engine
        .object_workers(std::iter::repeat_n(64 * 1024, 8192))
        .unwrap();
    let maximum = concurrency.maximum.unwrap();
    assert!((1..=4096).contains(&maximum));
    // A far endpoint starts with every object the budget allows in flight.
    assert_eq!(concurrency.initial, maximum);
    assert_eq!(engine.tuning.request_limit(), maximum);

    // An average below 1 MiB does not make every object small. Keep the
    // existing target when even one larger object needs streaming buffers.
    let mixed = planning_engine(&[]);
    mixed.tuning.observe_control(Duration::from_millis(100));
    let mixed = mixed
        .object_workers(std::iter::repeat_n(64 * 1024, 8192).chain([8 * 1024 * 1024]))
        .unwrap();
    assert_eq!(mixed.initial, 256);
    assert_eq!(mixed.maximum, Some(256));

    let fixed = planning_engine(&["--performance-tuning", "s3-objects=1024,s3-requests=128"]);
    fixed.tuning.observe_control(Duration::from_millis(100));
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
    {
        let engine = planning_engine(&["--dry-run"]);
        let concurrency = engine
            .object_workers(std::iter::repeat_n(1024 * 1024, 512))
            .unwrap();
        assert_eq!(concurrency.initial, 32);
        assert_eq!(engine.tuning.request_limit(), 32);
        assert!(concurrency.maximum.is_none());
    }
    let engine = planning_engine(&["--performance-tuning", "s3-requests=64"]);
    let concurrency = engine
        .object_workers(std::iter::repeat_n(1024 * 1024, 512))
        .unwrap();
    assert_eq!(concurrency.initial, 64);
    assert_eq!(engine.tuning.request_limit(), 64);
    let engine = planning_engine(&["--performance-tuning", "s3-objects=8"]);
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
