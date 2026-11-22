//! Automatic request scheduling and bounded writers, independent of hash policy.
use super::*;
use crate::s3::{
    admission::{Checking, Concurrency},
    writer,
};

/// The most metadata requests in flight for objects checked beyond the
/// transfer limit. Tiny objects over a slow link already start this high.
const CHECKING_REQUESTS: usize = 256;

pub(super) enum DownloadSink<'a> {
    Writer(&'a writer::Writer),
    Memory(&'a mut Vec<bytes::Bytes>),
}

impl DownloadSink<'_> {
    fn direct(&self) -> bool {
        matches!(self, Self::Writer(writer) if writer.direct())
    }
    async fn write(&mut self, bytes: bytes::Bytes, offset: u64) -> Result<()> {
        match self {
            Self::Writer(writer) => writer.write(bytes, offset).await,
            Self::Memory(chunks) => {
                chunks.push(bytes);
                Ok(())
            }
        }
    }
    async fn write_batch(&mut self, batch: Vec<bytes::Bytes>, offset: u64) -> Result<()> {
        match self {
            Self::Writer(writer) => writer.write_batch(batch, offset).await,
            Self::Memory(chunks) => {
                chunks.extend(batch);
                Ok(())
            }
        }
    }
    async fn flush(&self) -> Result<()> {
        match self {
            Self::Writer(writer) => writer.flush().await,
            Self::Memory(_) => Ok(()),
        }
    }
    fn reset(&mut self) {
        if let Self::Memory(chunks) = self {
            chunks.clear();
        }
    }
}

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
                checking: None,
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
                if self
                    .tuning
                    .control_latency()
                    .is_some_and(|latency| latency < super::super::tuning::NEAR_FAR_LATENCY)
                {
                    capacity.min(2048)
                } else {
                    capacity
                }
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
            bail!("s3-objects exceeds the available small-upload capacity ({capacity}); lower it or increase the open-file limit");
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
            && single_request
        {
            let capacity = if self.options.route.is_server_copy() {
                256
            } else if self.options.route == Route::Upload {
                // Keep the measured Tigris worker ceiling. The nonblocking upload
                // buffer budget controls memory independently of object admission.
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
        // Finding an object unchanged takes one metadata request, or two
        // between buckets, so the ceiling counts those requests. A fixed
        // object count leaves nothing to adjust, a request count the user
        // set bounds these requests too, and small uploads keep the room
        // their descriptors leave.
        let checking = fixed_workers.is_none().then(|| {
            let requests = self
                .args
                .tuning_options
                .and_then(|tuning| tuning.s3_requests)
                .into_iter()
                .chain(
                    self.args
                        .resource_limits
                        .as_ref()
                        .and_then(|limits| limits.s3_requests),
                )
                .fold(CHECKING_REQUESTS, usize::min);
            let per_object = if self.options.route.is_server_copy() {
                2
            } else {
                1
            };
            let maximum = (requests / per_object).max(1).min(object_limit);
            Checking {
                maximum: if small_upload {
                    maximum.min(capacity)
                } else {
                    maximum
                },
                outage: self.outage.clone(),
            }
        });
        Ok(Concurrency {
            initial,
            maximum,
            checking,
            requests: maximum.map(|_| self.tuning.requests.clone()),
            initial_probe_up: self
                .tuning
                .control_latency()
                .is_some_and(|latency| latency >= super::super::tuning::HIGH_LATENCY),
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
        initial: Option<ByteStream>,
        initial_slot: Option<crate::s3::tuning::Permit>,
        algorithm: Option<HashAlgorithm>,
        tree: Option<&mut subtrees::Part>,
    ) -> Result<String> {
        self.download_fast_range_into(
            object,
            DownloadSink::Writer(output),
            offset,
            length,
            initial,
            initial_slot,
            algorithm,
            tree,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn download_fast_range_into(
        &self,
        object: &Object,
        mut output: DownloadSink<'_>,
        offset: u64,
        length: u64,
        mut initial: Option<ByteStream>,
        initial_slot: Option<crate::s3::tuning::Permit>,
        algorithm: Option<HashAlgorithm>,
        mut tree: Option<&mut subtrees::Part>,
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
            // Whether this attempt's GET succeeded. A body or local write that
            // fails afterwards is not a sign that the service is down.
            let mut answered = initial.is_some();
            let mut retry_delay = None;
            // Whether the GET failed in a way no resend can fix.
            let mut unanswerable = false;
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
                                retry_delay = Some(crate::s3::retry::error_delay(attempt, &e));
                                anyhow::Error::new(e.into_service_error())
                            } else if crate::s3::retry::permanent(&e) {
                                // Fail with the message a retried failure ends with.
                                unanswerable = true;
                                anyhow::Error::new(e.into_service_error())
                            } else {
                                Permanent(format!(
                                    "S3 GET failed: {}",
                                    aws_smithy_types::error::display::DisplayErrorContext(&e)
                                ))
                                .into()
                            }
                        })?;
                    answered = true;
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
                        if let Some(tree) = &mut tree {
                            tree.update(&bytes);
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
                let writer = match &output {
                    DownloadSink::Writer(writer) => *writer,
                    DownloadSink::Memory(_) => unreachable!("memory sink is never direct"),
                };
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
                    if let Some(tree) = &mut tree {
                        tree.update(&buffer.bytes()[..want]);
                    }
                    let padded = want.next_multiple_of(4096);
                    buffer.bytes_mut()[want..padded].fill(0);
                    self.pace(want as u64).await?;
                    buffer = writer.write_direct(buffer, offset + done, padded).await?;
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
                    self.outage.responded();
                    return Ok(hash);
                }
                Err(e)
                    if attempt < self.options.retries
                        && !unanswerable
                        && e.downcast_ref::<Permanent>().is_none() =>
                {
                    output.flush().await?;
                    self.check_cancelled()?;
                    if e.downcast_ref::<SlowRead>().is_none() {
                        // Only our own slow-read decision trusts the prefix.
                        // Errors from the response/transport restart the range.
                        done = 0;
                        hash = algorithm.map(HashAlgorithm::hasher);
                        if let Some(tree) = &mut tree {
                            **tree = subtrees::Part::new(offset, length);
                        }
                        batch.clear();
                        fragments.clear();
                        batch_size = 0;
                        output.reset();
                        tokio::time::sleep(
                            retry_delay.unwrap_or_else(|| crate::s3::retry::delay(attempt, false)),
                        )
                        .await;
                    }
                    attempt += 1;
                }
                Err(e) => {
                    // A permanent GET error is still an answer from the service;
                    // a GET that never reached it says nothing about it.
                    if !unanswerable {
                        self.outage
                            .failed(!answered && e.downcast_ref::<Permanent>().is_none());
                    }
                    return Err(e);
                }
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

#[cfg(test)]
mod buffer_tests;

#[cfg(test)]
mod recovery_tests;
