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
            let workers = engine
                .object_workers(std::iter::repeat_n(size, 1024))
                .unwrap();
            assert!(workers.objects <= 3);
            assert!((1..=3).contains(&workers.limit()));
            assert_eq!(engine.part_workers(), 1);
            assert!(engine.tuning.request_limit() <= 2);
            assert!(engine.tuning.request_capacity() <= 2);
        }
    }
    let fixed = planning_engine(&[
        "--performance-tuning",
        "s3-objects=7,s3-requests=6,s3-parts-per-object=5",
    ]);
    let workers = fixed
        .object_workers(std::iter::repeat_n(1024, 1024))
        .unwrap();
    assert_eq!(workers.objects, 7);
    assert!(workers.requests.is_none());
    assert_eq!(fixed.tuning.request_limit(), 6);
    assert_eq!(fixed.part_workers(), 5);
}

#[test]
fn request_and_object_ceilings_apply_to_checks_and_transfers_alike() {
    // So that uploads' descriptor budget allows 256 objects.
    crate::raise_nofile();
    let copy = || Route::ServerCopy {
        source_bucket: "source".into(),
    };
    // Checks take request permits like transfers, so the same two ceilings
    // bound both: the objects in progress and the requests in flight.
    let ceilings = |flags: &[&str], route: Route| {
        let mut engine = planning_engine(flags);
        engine.options.route = route;
        let workers = engine
            .object_workers(std::iter::repeat_n(8u64 << 20, 1024))
            .unwrap();
        (workers.objects, engine.tuning.request_capacity())
    };
    for (flags, route, expected) in [
        (&[][..], Route::Upload, (256, 256)),
        (&[][..], Route::Download, (256, 256)),
        (&[][..], copy(), (256, 256)),
        (
            &["--resource-limits=s3-objects=40"][..],
            Route::Upload,
            (40, 256),
        ),
        (&["--resource-limits=s3-objects=40"][..], copy(), (40, 256)),
        (
            &["--resource-limits=s3-requests=40"][..],
            Route::Download,
            (256, 40),
        ),
        (&["--resource-limits=s3-requests=40"][..], copy(), (256, 40)),
        (
            &["--performance-tuning=s3-requests=16"][..],
            Route::Upload,
            (256, 16),
        ),
        (
            &["--performance-tuning=s3-objects=7"][..],
            Route::Upload,
            (7, 256),
        ),
    ] {
        assert_eq!(ceilings(flags, route), expected, "{flags:?}");
    }
}

#[test]
fn only_files_the_upload_buffers_hold_wait_for_room_in_them() {
    // So that uploads' descriptor budget allows 256 objects.
    crate::raise_nofile();
    let in_progress = |size: u64| {
        let (engine, _temp) = route_engine("upload", &[]);
        let workers = engine
            .object_workers(std::iter::repeat_n(size, 1024))
            .unwrap();
        engine.tuning.requests.set_limit(64);
        workers.limit()
    };
    // Files of up to 8 MiB are kept from hashing to sending them, so no
    // more get ready ahead of their requests than the buffers hold: 64 of
    // 4 MiB, beside 64 requests.
    assert_eq!(in_progress(4 << 20), 64);
    // Larger files sent in one request are read again to send them anyway,
    // so the objects in progress follow the requests as for downloads,
    // rather than stop at the 21 files of 12 MiB the buffers would hold.
    assert_eq!(in_progress(12 << 20), 128);
}

/// Where the open-file limit leaves no room beyond the descriptors kept for
/// sockets and opens, only small uploads fail; other copies keep the usual
/// ceiling.
#[test]
fn a_low_open_file_limit_fails_only_small_uploads() {
    const CHILD: &str = "SYQ_TEST_LOW_NOFILE_OBJECT_WORKERS";
    if std::env::var_os(CHILD).is_none() {
        // Only the child lowers its limit; other tests are unaffected.
        let name =
            "s3::transfer::fast::buffer_tests::a_low_open_file_limit_fails_only_small_uploads";
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{output:?}"
        );
        return;
    }
    let mut limits = crate::fsops::nofile_limits().unwrap();
    limits.rlim_cur = limits.rlim_cur.min(64);
    crate::fsops::set_nofile_limits(&limits).unwrap();
    assert!(tuning::small_object_capacity(1024).is_err());
    let small = || std::iter::repeat_n(1024u64, 100);
    // Downloads of small objects, few or many, a count the user fixed,
    for count in [2, 100] {
        let workers = planning_engine(&[])
            .object_workers(std::iter::repeat_n(1024u64, count))
            .unwrap();
        assert_eq!(workers.objects, 256);
    }
    let fixed = planning_engine(&["--performance-tuning", "s3-objects=1"]);
    assert_eq!(fixed.object_workers(small()).unwrap().objects, 1);
    let (fixed, _temp) = route_engine("upload", &["--performance-tuning", "s3-objects=2"]);
    let workers = fixed
        .object_workers(std::iter::repeat_n(4u64 << 20, 100))
        .unwrap();
    assert_eq!(workers.objects, 2);
    // a dry run, and a single object.
    planning_engine(&["--dry-run"])
        .object_workers(small())
        .unwrap();
    planning_engine(&[])
        .object_workers(std::iter::once(1024))
        .unwrap();
    // Every small upload needs room for its files.
    let (upload, _temp) = route_engine("upload", &[]);
    assert!(upload.object_workers(small()).is_err());
    let (upload, _temp) = route_engine("upload", &["--performance-tuning", "s3-objects=1"]);
    assert!(upload.object_workers(small()).is_err());
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
    // Objects of one request each may all be in progress; objects in parts
    // keep the request limit busy with fewer.
    let objects = |engine: &Engine, size| {
        engine
            .object_workers([size; 100].into_iter())
            .unwrap()
            .objects
    };
    assert_eq!(objects(&engine, 256 << 20), 256);
    assert_eq!(objects(&engine, limit + 1), MULTIPART_OBJECTS);
    let mut explicit = planning_engine(&["--performance-tuning", "s3-part-size=64M"]);
    explicit.options.route = Route::ServerCopy {
        source_bucket: "source".into(),
    };
    assert_eq!(explicit.copy_request_limit(32 << 20), 64 << 20);
    assert_eq!(objects(&explicit, 256 << 20), MULTIPART_OBJECTS);
}

/// An engine for `route`, whose tuning knows the route from the start.
fn route_engine(route: &str, extra: &[&str]) -> (Engine, Option<tempfile::TempDir>) {
    match route {
        "upload" => {
            let temp = crate::test_support::tempdir().unwrap();
            let path = temp.path().join("source");
            std::fs::write(&path, b"selected").unwrap();
            let argv = [
                "cp",
                path.to_str().unwrap(),
                "--to",
                "s3://bucket",
                "--as",
                "o",
            ];
            let engine = super::super::tests::engine(&[&argv[..], extra].concat());
            (engine, Some(temp))
        }
        "download" => (planning_engine(extra), None),
        _ => (
            planning_engine(&[&["--to", "s3://destination"][..], extra].concat()),
            None,
        ),
    }
}

#[test]
fn transfers_start_by_route_endpoint_and_explicit_limits() {
    const MIB: u64 = 1 << 20;
    const LOCAL: u64 = 1;
    const NEAR: u64 = 10;
    const FAR: u64 = 100;
    let example = "https://storage.example";
    let tigris = "https://t3.storage.dev";
    // Part size and parts per object for a 32 GiB object; requests in flight
    // when a batch of such objects starts, and when 512 small ones start
    // (`None`: as many as the batch's memory and descriptors allow).
    for (route, endpoint, ms, parts, small) in [
        ("upload", example, LOCAL, (16 * MIB, 64), Some(64)),
        ("upload", example, FAR, (16 * MIB, 64), None),
        ("upload", tigris, LOCAL, (8 * MIB, 32), Some(64)),
        // Tigris uploads keep the usual start, which measured faster there.
        ("upload", tigris, FAR, (8 * MIB, 32), Some(64)),
        ("download", example, LOCAL, (64 * MIB, 4), Some(64)),
        ("download", example, NEAR, (8 * MIB, 64), Some(64)),
        ("download", example, FAR, (8 * MIB, 64), Some(256)),
        ("download", tigris, LOCAL, (64 * MIB, 4), Some(64)),
        ("download", tigris, FAR, (16 * MIB, 8), Some(256)),
        ("copy", example, LOCAL, (256 * MIB, 256), Some(64)),
        ("copy", tigris, FAR, (256 * MIB, 256), Some(256)),
    ] {
        for extra in ["", "s3-requests=128", "s3-parts-per-object=7"] {
            let mut flags = vec!["--s3-endpoint", endpoint];
            if !extra.is_empty() {
                flags.extend(["--performance-tuning", extra]);
            }
            let (engine, _temp) = route_engine(route, &flags);
            engine.tuning.observe_control(Duration::from_millis(ms));
            let case = format!("{route} {endpoint} {ms} ms {extra}");
            let fixed = (extra == "s3-requests=128").then_some(128);
            engine.object_workers([32u64 << 30].into_iter()).unwrap();
            let workers = match (extra, route) {
                ("s3-parts-per-object=7", _) => 7,
                (_, "copy") => fixed.unwrap_or(parts.1),
                _ => parts.1,
            };
            assert_eq!(
                (engine.part_size(32u64 << 30), engine.part_workers()),
                (parts.0, workers),
                "{case}"
            );
            assert_eq!(engine.tuning.request_limit(), fixed.unwrap_or(64), "{case}");
            engine.object_workers([1024u64; 512].into_iter()).unwrap();
            let capacity = engine.tuning.request_capacity();
            assert_eq!(
                engine.tuning.request_limit(),
                fixed.unwrap_or(small.unwrap_or(capacity).min(capacity)),
                "{case}"
            );
        }
    }
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
            None,
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
fn far_small_uploads_start_with_at_most_2048_requests_below_32_ms() {
    // Only a capacity above 2,048 shows the lower start; raise the soft
    // descriptor limit as the binary does at startup.
    crate::raise_nofile();
    let start = |ms| {
        let (engine, _temp) = route_engine("upload", &[]);
        engine.tuning.observe_control(Duration::from_millis(ms));
        let workers = engine
            .object_workers(std::iter::repeat_n(1024, 10_000))
            .unwrap();
        // Objects follow the requests, within what memory and descriptors
        // allow.
        assert_eq!(engine.tuning.request_capacity(), workers.objects, "{ms} ms");
        assert_eq!(
            workers.limit(),
            (2 * engine.tuning.request_limit()).min(workers.objects),
            "{ms} ms"
        );
        (engine.tuning.request_limit(), workers.objects)
    };
    let (limit, capacity) = start(100);
    {
        let (engine, _temp) = route_engine("upload", &[]);
        engine.tuning.observe_control(Duration::from_millis(100));
        engine
            .object_workers(std::iter::repeat_n(1024, 10_000))
            .unwrap();
        assert!(!engine.tuning.requests.gradual());
    }
    assert!(capacity > 2048, "small-object capacity {capacity}");
    // Far away, every request memory and descriptors allow from the start;
    assert_eq!(limit, capacity);
    assert_eq!(start(32).0, capacity);
    // a little nearer, no more than 2,048,
    assert_eq!(start(20).0, capacity.min(2048));
    assert_eq!(start(31).0, capacity.min(2048));
    // and near, the usual start, to grow from what the requests show.
    assert_eq!(start(19).0, 64);
    assert_eq!(start(1).0, 64);
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
    let small = b"verified through two distinct algorithms".to_vec();
    let streaming: Vec<u8> = (0..140 * 1024).map(|i| (i % 251) as u8).collect();
    for data in [&small, &streaming] {
        for valid in [true, false] {
            let dir = crate::test_support::tempdir().unwrap();
            let destination = dir.path().join("destination");
            std::fs::write(&destination, b"original").unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()
                .unwrap();
            let outcome = runtime.block_on(async {
                let engine = Arc::new(planning_engine(&[
                    "--if-exists=update",
                    "--integrity-checking=transfer=blake3",
                ]));
                let root = Arc::new(Root::open(dir.path()).unwrap());
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
                        Some(ByteStream::from(data.clone())),
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
                assert_eq!(std::fs::read(&destination).unwrap(), *data);
            } else {
                assert!(outcome.is_err());
                assert_eq!(std::fs::read(&destination).unwrap(), b"original");
            }
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}

#[tokio::test]
async fn far_small_downloads_start_at_256_requests_within_their_ceiling() {
    let engine = planning_engine(&[]);
    engine.tuning.observe_control(Duration::from_millis(100));
    let concurrency = engine
        .object_workers(std::iter::repeat_n(64 * 1024, 8192))
        .unwrap();
    assert!((1..=4096).contains(&concurrency.objects));
    assert_eq!(engine.tuning.request_capacity(), concurrency.objects);
    assert_eq!(engine.tuning.request_limit(), concurrency.objects.min(256));
    // Each response in flight holds its buffers: add them gradually.
    assert!(engine.tuning.requests.gradual());
    assert_eq!(
        concurrency.limit(),
        concurrency.objects.min(2 * engine.tuning.request_limit())
    );

    // An average below 1 MiB does not make every object small. Keep the
    // existing ceiling when even one larger object needs streaming buffers.
    let mixed = planning_engine(&[]);
    mixed.tuning.observe_control(Duration::from_millis(100));
    let concurrency = mixed
        .object_workers(std::iter::repeat_n(64 * 1024, 8192).chain([1024 * 1024]))
        .unwrap();
    assert_eq!(concurrency.objects, 256);
    assert_eq!(mixed.tuning.request_capacity(), 256);
    assert_eq!(mixed.tuning.request_limit(), 256);

    let fixed = planning_engine(&["--performance-tuning", "s3-objects=1024,s3-requests=128"]);
    let concurrency = fixed
        .object_workers(std::iter::repeat_n(64 * 1024, 8192))
        .unwrap();
    assert_eq!(concurrency.limit(), 1024);
    assert!(concurrency.requests.is_none());
    assert_eq!(fixed.tuning.request_limit(), 128);
}

#[test]
fn files_get_ready_ahead_of_their_requests_only_as_far_as_upload_buffers_hold() {
    let (engine, _temp) = route_engine("upload", &[]);
    // Thirty-two 8 MiB files fill the upload buffers: no more get ready
    // beside the 32 requests in flight,
    let concurrency = engine
        .object_workers(std::iter::repeat_n(8 * 1024 * 1024, 64))
        .unwrap();
    assert_eq!(engine.tuning.request_limit(), 32);
    assert_eq!(concurrency.limit(), 32);
    // though objects still follow a higher request limit.
    concurrency.requests.as_ref().unwrap().set_limit(64);
    assert_eq!(concurrency.limit(), 64);
    // Small files fit many times over: twice the requests get ready.
    let (engine, _temp) = route_engine("upload", &[]);
    let concurrency = engine
        .object_workers(std::iter::repeat_n(64 * 1024, 1024))
        .unwrap();
    assert_eq!(concurrency.limit(), 2 * engine.tuning.request_limit());
}

#[tokio::test]
async fn whole_object_batches_start_conservatively_and_can_tune_higher() {
    let initial = crate::s3::tuning::INITIAL_REQUESTS;
    for count in [16, 32, 33, 128, 4096] {
        let engine = planning_engine(&[]);
        let concurrency = engine
            .object_workers(std::iter::repeat_n(1024 * 1024, count))
            .unwrap();
        assert_eq!(engine.tuning.request_limit(), initial);
        assert_eq!(engine.tuning.request_capacity(), 256);
        assert_eq!(concurrency.objects, 256);
        assert_eq!(concurrency.limit(), 2 * initial);
        let requests = concurrency.requests.as_ref().unwrap();
        requests.set_limit(1000);
        assert_eq!(concurrency.limit(), 256);
    }
    for size_mib in [1, 2, 4, 8] {
        for flags in [&[][..], &["--dry-run"][..]] {
            let engine = planning_engine(flags);
            engine.tuning.observe_control(Duration::from_millis(100));
            let concurrency = engine
                .object_workers(std::iter::repeat_n(size_mib * 1024 * 1024, 512))
                .unwrap();
            assert_eq!(concurrency.limit(), 2 * initial);
            assert_eq!(engine.tuning.request_limit(), initial);
            assert_eq!(concurrency.objects, 256);
        }
    }
    let engine = planning_engine(&["--performance-tuning", "s3-requests=64"]);
    let concurrency = engine
        .object_workers(std::iter::repeat_n(1024 * 1024, 512))
        .unwrap();
    assert_eq!(concurrency.limit(), 128);
    assert_eq!(engine.tuning.request_limit(), 64);
    let engine = planning_engine(&["--performance-tuning", "s3-objects=8"]);
    let concurrency = engine
        .object_workers(std::iter::repeat_n(1024 * 1024, 128))
        .unwrap();
    assert_eq!(concurrency.limit(), 8);
    assert!(concurrency.requests.is_none());
}

#[test]
fn a_refusal_lowers_the_copy_request_limit_as_it_arrives() {
    let engine = planning_engine(&[]);
    engine
        .object_workers(std::iter::repeat_n(64 * 1024 * 1024u64, 4_000))
        .unwrap();
    let before = engine.tuning.request_limit();
    // The client reports the refusal while its request may still retry.
    engine.outage.throttled();
    assert_eq!(engine.tuning.request_limit(), before / 2);
    // A count the user fixed stays.
    let fixed = planning_engine(&["--performance-tuning", "s3-requests=6"]);
    fixed.outage.throttled();
    assert_eq!(fixed.tuning.request_limit(), 6);
}
