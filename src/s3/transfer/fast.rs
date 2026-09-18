//! Automatic request scheduling and bounded writers, independent of hash policy.
use super::*;
use crate::s3::{admission::Concurrency, writer};

impl Engine {
    pub(super) fn object_workers(&self, sizes: impl Iterator<Item = u64>) -> Result<Concurrency> {
        let mut count = 0u64;
        let mut bytes = 0u64;
        let mut largest = 0u64;
        for size in sizes {
            count += 1;
            largest = largest.max(size);
            bytes = bytes.saturating_add(size);
        }
        if count == 0 {
            return Ok(Concurrency {
                initial: 1,
                maximum: None,
                initial_probe_up: false,
                requests: None,
            });
        }
        let average = bytes / count;
        let tiny = average < 1024 * 1024;
        let single_request = largest
            <= if self.options.route.is_server_copy() {
                self.copy_request_limit(largest)
            } else {
                self.part_size(largest)
            };
        let fixed_workers = self.args.tuning_options.and_then(|t| t.s3_object_workers);
        let object_limit = self
            .args
            .resource_limits
            .as_ref()
            .and_then(|limits| limits.s3_object_workers)
            .unwrap_or(usize::MAX);
        let ramp_whole_objects = single_request && !tiny && fixed_workers.is_none();
        let small_upload = self.options.route == Route::Upload && largest <= 1024 * 1024;
        let capacity = if small_upload {
            super::super::tuning::small_object_capacity(largest)?
        } else {
            256
        };
        let workers = if let Some(fixed) = fixed_workers {
            fixed
        } else if tiny {
            if small_upload && self.tuning.high_latency() {
                capacity
            } else {
                256
            }
        } else if single_request {
            // Taper the object seed instead of dropping eightfold at 1 MiB.
            ((256 * 1024 * 1024) / average.max(1)).clamp(32, 256) as usize
        } else {
            32
        };
        if small_upload && fixed_workers.is_some_and(|n| n > capacity) {
            bail!("s3-max-concurrent-objects exceeds the available small-upload capacity ({capacity}); lower it or increase the open-file limit");
        }
        // Automatic small-upload admission leaves room for source opens,
        // payload buffers, and descriptors pinned during discovery.
        let workers = if small_upload {
            workers.min(capacity)
        } else {
            workers
        }
        .min(object_limit);
        // Object size and control latency do not establish available bandwidth.
        // Start whole-object batches conservatively and measure before growing;
        // preparation follows the same request budget.
        self.tuning.configure(
            tiny,
            if small_upload { workers } else { 256 },
            if ramp_whole_objects { 32 } else { 64 },
        );
        let starting = if ramp_whole_objects {
            workers.min(self.tuning.request_limit())
        } else {
            workers
        };
        // Batches larger than the starting concurrency can use the object
        // controller, with preparation bounded by its current request limit.
        let maximum = if count > starting as u64
            && fixed_workers.is_none()
            && !self.args.dry_run
            && !self.args.verify_only
            && single_request
        {
            let capacity = if self.options.route.is_server_copy() {
                256
            } else if self.options.route == Route::Upload {
                let buffer_size = if self.tuning.tigris() {
                    8 * 1024 * 1024
                } else {
                    1024 * 1024
                };
                super::super::tuning::small_object_capacity(largest.min(buffer_size))?
            } else if largest < 1024 * 1024 {
                // Keep the starting load unchanged, but allow measured gains
                // beyond 256 when small objects fit the payload/FD budget.
                super::super::tuning::small_object_capacity(largest)?
            } else {
                256
            };
            let maximum = capacity.min(count as usize).min(object_limit);
            Some(maximum)
        } else {
            None
        };
        // Let the object controller measure fresh generations immediately,
        // rather than first running a second, request-level concurrency search.
        let initial = starting.min(maximum.unwrap_or(starting));
        self.tuning.report(initial);
        Ok(Concurrency {
            initial,
            maximum,
            requests: maximum.map(|_| self.tuning.requests.clone()),
            initial_probe_up: self
                .tuning
                .control_latency()
                .is_some_and(|latency| latency >= Duration::from_millis(50)),
        })
    }

    pub(super) fn part_size(&self, size: u64) -> u64 {
        let seed = if !self.options.automatic_part_size {
            self.options.part_size
        } else {
            match self.options.route {
                // No payload buffer: larger parts reduce provider round trips.
                Route::ServerCopy { .. } => 256 * 1024 * 1024,
                Route::Upload if self.tuning.tigris() => 8 * 1024 * 1024,
                Route::Upload => 16 * 1024 * 1024,
                Route::Download if self.tuning.local_latency() => 64 * 1024 * 1024,
                Route::Download if self.tuning.tigris() => 16 * 1024 * 1024,
                Route::Download => 8 * 1024 * 1024,
            }
        };
        seed.max(size.div_ceil(10_000).next_multiple_of(1024 * 1024))
    }
    pub(super) fn part_workers(&self) -> usize {
        let workers = if !self.options.automatic_concurrency {
            self.options.concurrency
        } else {
            match self.options.route {
                // Every part still acquires a permit from the shared budget.
                Route::ServerCopy { .. } => self.tuning.request_capacity(),
                Route::Download if self.tuning.local_latency() => 4,
                Route::Upload if self.tuning.tigris() => 32,
                Route::Download if self.tuning.tigris() => 8,
                Route::Upload | Route::Download => 64,
            }
        };
        workers.min(
            self.args
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.s3_part_workers)
                .unwrap_or(usize::MAX),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn download_fast_range(
        &self,
        object: &Object,
        output: &writer::Writer,
        offset: u64,
        length: u64,
        mut initial: Option<ByteStream>,
        initial_slot: Option<crate::s3::tuning::Permit>,
        algorithm: Option<HashAlgorithm>,
    ) -> Result<String> {
        let slot = match initial_slot {
            Some(slot) => slot,
            None => self.tuning.requests.acquire().await,
        };
        let mut attempt = 0;
        // Hold the process-local recovery slot until the retried range finishes.
        let mut recovery = None;
        let mut done = 0;
        let mut hash = algorithm.map(HashAlgorithm::hasher);
        let mut batch = Vec::new();
        let mut batch_size = 0;
        let mut fragments = bytes::BytesMut::new();
        loop {
            self.check_cancelled()?;
            let started = crate::s3::diagnostics::start();
            let body_started = tokio::time::Instant::now();
            let mut waited = Duration::ZERO;
            let mut next_check = Duration::from_secs(1);
            let attempt_offset = offset + done;
            let attempt_length = length - done;
            let result = async {
                let body = if let Some(body) = initial.take() {
                    body
                } else {
                    let end = offset + length.saturating_sub(1);
                    let response = self
                        .client
                        .get_object()
                        .bucket(&self.options.bucket)
                        .key(&object.key)
                        .set_range((length > 0).then(|| format!("bytes={attempt_offset}-{end}")))
                        .if_match(&object.etag)
                        .set_version_id(object.version.clone())
                        .customize()
                        .config_override(crate::s3::client::without_sdk_retries())
                        .send()
                        .await
                        .map_err(|e| {
                            if retryable(&e) {
                                anyhow::Error::new(e.into_service_error())
                            } else {
                                Permanent(format!("S3 GET failed: {}", e.into_service_error()))
                                    .into()
                            }
                        })?;
                    if response.content_length() != Some(attempt_length as i64)
                        || response.e_tag() != Some(object.etag.as_str())
                        || (length > 0
                            && response.content_range()
                                != Some(
                                    format!("bytes {attempt_offset}-{end}/{}", object.size)
                                        .as_str(),
                                ))
                    {
                        return Err(
                            Permanent("S3 response length, range, or ETag differs".into()).into(),
                        );
                    }
                    response.body
                };
                let mut recover = |done: u64, waited: Duration| {
                    if attempt != 0
                        || self.options.retries == 0
                        || done >= length
                        || waited < next_check
                    {
                        return false;
                    }
                    next_check = waited + Duration::from_millis(250);
                    recovery = self.tuning.reads.retry(length, body_started, waited);
                    if recovery.is_some() {
                        crate::s3::diagnostics::record(serde_json::json!({
                            "phase": "download_slow_retry", "bytes": length,
                            "received": done, "network_wait_s": waited.as_secs_f64(),
                        }));
                    }
                    recovery.is_some()
                };
                if !output.direct() {
                    let mut body = body;
                    loop {
                        let bytes =
                            read_body(body.next(), &mut waited, |elapsed| recover(done, elapsed))
                                .await?;
                        let Some(bytes) = bytes else { break };
                        let mut bytes = bytes?;
                        if bytes.len() as u64 > length - done {
                            return Err(Permanent("S3 body exceeded length".into()).into());
                        }
                        slot.received(bytes.len());
                        if let Some(h) = &mut hash {
                            h.update(&bytes);
                        }
                        while !bytes.is_empty() {
                            if batch_size == 0 && bytes.len() >= 128 * 1024 {
                                self.pace(128 * 1024).await?;
                                output
                                    .write(bytes.split_to(128 * 1024), offset + done)
                                    .await?;
                                done += 128 * 1024;
                                continue;
                            }
                            let n = bytes.len().min(128 * 1024 - batch_size);
                            let chunk = bytes.split_to(n);
                            // Tiny slices can pin much larger SDK buffers and
                            // exhaust the scatter limit with only a few bytes.
                            // Pack consecutive small fragments; keep large ones
                            // in the scatter batch without copying them.
                            if n < 4096 {
                                fragments.extend_from_slice(&chunk);
                            } else {
                                flush_fragments(&mut batch, &mut fragments);
                                batch.push(chunk);
                            }
                            batch_size += n;
                            done += n as u64;
                            if batch_size == 128 * 1024
                                || batch.len() + usize::from(!fragments.is_empty()) >= 16
                            {
                                flush_fragments(&mut batch, &mut fragments);
                                self.pace(batch_size as u64).await?;
                                output
                                    .write_batch(
                                        std::mem::take(&mut batch),
                                        offset + done - batch_size as u64,
                                    )
                                    .await?;
                                batch = Vec::new();
                                batch_size = 0;
                            }
                        }
                        anyhow::ensure!(!recover(done, waited), SlowRead);
                    }
                    anyhow::ensure!(done == length, "S3 body truncated");
                    if batch_size != 0 {
                        flush_fragments(&mut batch, &mut fragments);
                        self.pace(batch_size as u64).await?;
                        output
                            .write_batch(
                                std::mem::take(&mut batch),
                                offset + done - batch_size as u64,
                            )
                            .await?;
                    }
                    return Ok(hash
                        .take()
                        .map(|h| Digest::from_hash(algorithm.unwrap(), &h.finalize()).value)
                        .unwrap_or_default());
                }
                let mut body = body.into_async_read();
                let mut buffer = writer::Aligned::new(1024 * 1024)?;
                while done < length {
                    let want = (length - done).min(1024 * 1024) as usize;
                    read_body(
                        body.read_exact(&mut buffer.bytes_mut()[..want]),
                        &mut waited,
                        |elapsed| recover(done, elapsed),
                    )
                    .await??;
                    anyhow::ensure!(
                        (offset + done).is_multiple_of(4096)
                            && (want.is_multiple_of(4096)
                                || offset + done + want as u64 == object.size),
                        "unaligned S3 direct range"
                    );
                    slot.received(want);
                    if let Some(h) = &mut hash {
                        h.update(&buffer.bytes()[..want]);
                    }
                    let padded = want.next_multiple_of(4096);
                    buffer.bytes_mut()[want..padded].fill(0);
                    self.pace(want as u64).await?;
                    buffer = output.write_direct(buffer, offset + done, padded).await?;
                    done += want as u64;
                    anyhow::ensure!(!recover(done, waited), SlowRead);
                }
                let mut extra = [0];
                if body.read(&mut extra).await? != 0 {
                    return Err(Permanent("S3 body exceeded length".into()).into());
                }
                Ok::<String, anyhow::Error>(
                    hash.take()
                        .map(|h| Digest::from_hash(algorithm.unwrap(), &h.finalize()).value)
                        .unwrap_or_default(),
                )
            }
            .await;
            match result {
                Ok(hash) => {
                    self.tuning.reads.completed(
                        attempt_length,
                        waited,
                        tokio::time::Instant::now(),
                    );
                    crate::s3::diagnostics::elapsed(started, "download_range", attempt_length);
                    self.tuning.requests.completed(length);
                    self.progress.add_bytes(length);
                    return Ok(hash);
                }
                Err(e)
                    if attempt < self.options.retries
                        && e.downcast_ref::<Permanent>().is_none() =>
                {
                    output.finish().await?;
                    self.check_cancelled()?;
                    if e.downcast_ref::<SlowRead>().is_none() {
                        // Only our own slow-read decision trusts the prefix.
                        // Errors from the response/transport restart the range.
                        done = 0;
                        hash = algorithm.map(HashAlgorithm::hasher);
                        batch.clear();
                        fragments.clear();
                        batch_size = 0;
                        crate::s3::backoff(attempt).await;
                    }
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn flush_fragments(batch: &mut Vec<bytes::Bytes>, fragments: &mut bytes::BytesMut) {
    if !fragments.is_empty() {
        batch.push(std::mem::take(fragments).freeze());
    }
}

#[derive(Debug)]
struct SlowRead;
impl std::fmt::Display for SlowRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3 body progressing much more slowly than completed peers")
    }
}
impl std::error::Error for SlowRead {}

// Keep a pending read alive across observations. In particular, cancelling
// read_exact at each tick would lose track of bytes already consumed into its
// buffer. A recovery discards that unfinished read; only previously processed
// bytes, their hash and the pending write batch survive the writer barrier.
async fn read_body<F: std::future::Future>(
    read: F,
    waited: &mut Duration,
    mut recover: impl FnMut(Duration) -> bool,
) -> Result<F::Output> {
    let started = tokio::time::Instant::now();
    tokio::pin!(read);
    loop {
        match tokio::time::timeout(Duration::from_secs(1), &mut read).await {
            Ok(result) => {
                *waited += started.elapsed();
                return Ok(result);
            }
            Err(_) => {
                anyhow::ensure!(!recover(*waited + started.elapsed()), SlowRead);
            }
        }
    }
}

pub(super) struct UploadBuffer {
    pub(super) bytes: Vec<u8>,
    pub(super) _reservation: tokio::sync::OwnedSemaphorePermit,
    pub(super) _trace: Option<crate::s3::diagnostics::UploadBufferTrace>,
}
impl AsRef<[u8]> for UploadBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
#[cfg(test)]
mod buffer_tests {
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
            ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>>
            {
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
                        (&metadata, Some(&expected)),
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
}

#[cfg(test)]
mod recovery_tests;
