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
        let single_request = largest <= self.part_size(largest);
        let fixed_workers = self.args.tuning_options.and_then(|t| t.s3_object_workers);
        let ramp_whole_objects = single_request && !tiny && fixed_workers.is_none();
        let small_upload = self.options.upload && largest <= 1024 * 1024;
        let capacity = if small_upload {
            super::super::tuning::small_upload_capacity(largest)?
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
        };
        // Keep the initial network load conservative; preparation follows the
        // request budget until its measurements justify the larger object seed.
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
        // A short batch may fit the object target while exceeding the initial
        // request budget. It still needs bounded preparation during the ramp.
        let maximum = if count > starting as u64
            && fixed_workers.is_none()
            && !self.args.dry_run
            && !self.args.verify_only
            && single_request
        {
            let capacity = if self.options.upload {
                let buffer_size = if self.tuning.tigris() {
                    8 * 1024 * 1024
                } else {
                    1024 * 1024
                };
                super::super::tuning::small_upload_capacity(largest.min(buffer_size))?
            } else {
                256
            };
            let maximum = capacity.min(count as usize);
            Some(maximum)
        } else {
            None
        };
        let initial = workers.min(maximum.unwrap_or(workers));
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
        } else if self.options.upload {
            if self.tuning.tigris() {
                8 * 1024 * 1024
            } else {
                16 * 1024 * 1024
            }
        } else if self.tuning.local_latency() {
            64 * 1024 * 1024
        } else if self.tuning.tigris() {
            16 * 1024 * 1024
        } else {
            8 * 1024 * 1024
        };
        seed.max(size.div_ceil(10_000).next_multiple_of(1024 * 1024))
    }
    pub(super) fn part_workers(&self) -> usize {
        if !self.options.automatic_concurrency {
            self.options.concurrency
        } else if !self.options.upload && self.tuning.local_latency() {
            4
        } else if self.tuning.tigris() {
            if self.options.upload {
                32
            } else {
                8
            }
        } else {
            64
        }
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
        let _slot = match initial_slot {
            Some(slot) => slot,
            None => self.tuning.requests.acquire().await,
        };
        let mut attempt = 0;
        // Hold the process-local recovery slot until the retried range finishes.
        let mut recovery = None;
        loop {
            self.check_cancelled()?;
            let started = crate::s3::diagnostics::start();
            let body_started = std::time::Instant::now();
            let mut waited = Duration::ZERO;
            let mut next_check = Duration::from_secs(1);
            let result = async {
                let mut hash = algorithm.map(HashAlgorithm::hasher);
                let body = if let Some(body) = initial.take() {
                    body
                } else {
                    let end = offset + length.saturating_sub(1);
                    let response = self
                        .client
                        .get_object()
                        .bucket(&self.options.bucket)
                        .key(&object.key)
                        .set_range((length > 0).then(|| format!("bytes={offset}-{end}")))
                        .if_match(&object.etag)
                        .set_version_id(object.version.clone())
                        .send()
                        .await
                        .map_err(|e| {
                            if retryable_status(e.raw_response().map(|r| r.status().as_u16())) {
                                anyhow::Error::new(e.into_service_error())
                            } else {
                                Permanent(format!("S3 GET failed: {}", e.into_service_error()))
                                    .into()
                            }
                        })?;
                    if response.content_length() != Some(length as i64)
                        || response.e_tag() != Some(object.etag.as_str())
                        || (length > 0
                            && response.content_range()
                                != Some(format!("bytes {offset}-{end}/{}", object.size).as_str()))
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
                    let mut done = 0;
                    let mut batch = Vec::new();
                    let mut batch_size = 0;
                    loop {
                        let bytes =
                            read_body(body.next(), &mut waited, |elapsed| recover(done, elapsed))
                                .await?;
                        let Some(bytes) = bytes else { break };
                        let mut bytes = bytes?;
                        if bytes.len() as u64 > length - done {
                            return Err(Permanent("S3 body exceeded length".into()).into());
                        }
                        anyhow::ensure!(
                            !recover(done + bytes.len() as u64, waited),
                            "S3 body progressing much more slowly than completed peers"
                        );
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
                            batch.push(bytes.split_to(n));
                            batch_size += n;
                            done += n as u64;
                            if batch_size == 128 * 1024 || batch.len() == 16 {
                                self.pace(batch_size as u64).await?;
                                output
                                    .write_batch(batch, offset + done - batch_size as u64)
                                    .await?;
                                batch = Vec::new();
                                batch_size = 0;
                            }
                        }
                    }
                    anyhow::ensure!(done == length, "S3 body truncated");
                    if !batch.is_empty() {
                        self.pace(batch_size as u64).await?;
                        output
                            .write_batch(batch, offset + done - batch_size as u64)
                            .await?;
                    }
                    return Ok(hash
                        .map(|h| Digest::from_hash(algorithm.unwrap(), &h.finalize()).value)
                        .unwrap_or_default());
                }
                let mut body = body.into_async_read();
                let mut done = 0;
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
                        !recover(done + want as u64, waited),
                        "S3 body progressing much more slowly than completed peers"
                    );
                    anyhow::ensure!(
                        (offset + done).is_multiple_of(4096)
                            && (want.is_multiple_of(4096)
                                || offset + done + want as u64 == object.size),
                        "unaligned S3 direct range"
                    );
                    if let Some(h) = &mut hash {
                        h.update(&buffer.bytes()[..want]);
                    }
                    let padded = want.next_multiple_of(4096);
                    buffer.bytes_mut()[want..padded].fill(0);
                    self.pace(want as u64).await?;
                    buffer = output.write_direct(buffer, offset + done, padded).await?;
                    done += want as u64;
                }
                let mut extra = [0];
                if tokio::time::timeout(Duration::from_secs(60), body.read(&mut extra)).await?? != 0
                {
                    return Err(Permanent("S3 body exceeded length".into()).into());
                }
                Ok::<String, anyhow::Error>(
                    hash.map(|h| Digest::from_hash(algorithm.unwrap(), &h.finalize()).value)
                        .unwrap_or_default(),
                )
            }
            .await;
            match result {
                Ok(hash) => {
                    self.tuning
                        .reads
                        .completed(length, waited, std::time::Instant::now());
                    crate::s3::diagnostics::elapsed(started, "download_range", length);
                    self.tuning.requests.completed(length);
                    self.progress.add_bytes(length);
                    return Ok(hash);
                }
                Err(e)
                    if attempt < self.options.retries
                        && e.downcast_ref::<Permanent>().is_none() =>
                {
                    output.finish().await?;
                    crate::s3::backoff(attempt).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

// Keep a pending read alive across observations. In particular, cancelling
// read_exact at each tick would lose track of bytes already consumed into its
// buffer. A recovery abandons the entire attempt and uses its normal barrier.
async fn read_body<F: std::future::Future>(
    read: F,
    waited: &mut Duration,
    mut recover: impl FnMut(Duration) -> bool,
) -> Result<F::Output> {
    let started = std::time::Instant::now();
    tokio::pin!(read);
    loop {
        match tokio::time::timeout(Duration::from_secs(1), &mut read).await {
            Ok(result) => {
                *waited += started.elapsed();
                return Ok(result);
            }
            Err(_) => {
                anyhow::ensure!(
                    started.elapsed() < Duration::from_secs(60),
                    "S3 body read timed out"
                );
                anyhow::ensure!(
                    !recover(*waited + started.elapsed()),
                    "S3 body progressing much more slowly than completed peers"
                );
            }
        }
    }
}

pub(super) struct UploadBuffer {
    pub(super) bytes: Vec<u8>,
    pub(super) _reservation: tokio::sync::OwnedSemaphorePermit,
}
impl AsRef<[u8]> for UploadBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
#[cfg(test)]
mod buffer_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn pending_read_exact_keeps_consumed_bytes_across_observations() {
        use tokio::io::AsyncWriteExt;
        let (mut send, mut recv) = tokio::io::duplex(4);
        let writer = tokio::spawn(async move {
            send.write_all(b"ab").await.unwrap();
            tokio::time::sleep(Duration::from_secs(3)).await;
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

    fn planning_engine(extra: &[&str]) -> Engine {
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
        let tuning = crate::s3::tuning::Tuning::new(&options, &args);
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
            cancelled: Default::default(),
            cancel_wake: Default::default(),
        }
    }

    #[tokio::test]
    async fn short_whole_object_batches_keep_request_preparation_bounded() {
        for count in [32, 33, 128, 4096] {
            let engine = planning_engine(&[]);
            let concurrency = engine
                .object_workers(std::iter::repeat_n(1024 * 1024, count))
                .unwrap();
            assert_eq!(engine.tuning.request_limit(), 32);
            assert_eq!(concurrency.maximum, (count > 32).then_some(count.min(256)));
            if count > 32 {
                assert_eq!(concurrency.initial, count.min(256));
                let requests = concurrency.requests.unwrap();
                assert_eq!(requests.preparation_limit(), 33);
                assert_eq!(requests.begin_objects(concurrency.initial), None);
            }
        }
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
        }));
        let retry = body.try_clone().unwrap();
        drop(body);
        assert_eq!(retry.bytes(), Some(&[42; 8][..]));
        assert!(budget.try_acquire().is_err());
        drop(retry);
        assert_eq!(budget.available_permits(), 8);
    }
}
