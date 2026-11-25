//! Automatic request scheduling and bounded writers, independent of hash policy.
use super::*;
use crate::s3::{admission::Concurrency, tuning, writer};

/// Objects in progress at most when each object takes several requests: its
/// parts already keep the request limit busy.
const MULTIPART_OBJECTS: usize = 32;
/// Requests in flight when a batch starts with objects in parts, or with
/// small objects on a near endpoint.
const MULTIPART_REQUESTS: usize = 64;
/// Requests in flight when a batch of small objects other than files to
/// upload starts on a far endpoint.
const FAR_SMALL_REQUESTS: usize = 256;

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
                objects: 1,
                ready: usize::MAX,
                requests: None,
            });
        }
        let average = bytes / count;
        let tiny = average < 1024 * 1024;
        let route = &self.options.route;
        let single_request = largest
            <= if route.is_server_copy() {
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
        let small_upload = *route == Route::Upload && largest <= 1024 * 1024;
        // What memory and descriptors allow in progress at once when each
        // object takes one request: payloads within 256 MiB and four
        // descriptors per object. Larger objects stream their parts. Every
        // small upload needs room for its files; anything else keeps the
        // usual ceiling where the open-file limit leaves little room.
        let small_capacity = |largest| {
            let capacity = tuning::small_object_capacity(largest);
            if small_upload {
                capacity
            } else {
                Ok(capacity.unwrap_or(256))
            }
        };
        let capacity = if !single_request || route.is_server_copy() {
            256
        } else if *route == Route::Upload {
            // Keep the measured Tigris ceiling for files of 1 to 8 MiB. The
            // nonblocking upload buffer budget bounds memory separately.
            let buffer_size = if self.tuning.tigris() {
                8 << 20
            } else {
                1 << 20
            };
            small_capacity(largest.min(buffer_size))?
        } else if largest < 1024 * 1024 {
            small_capacity(largest)?
        } else {
            256
        };
        if small_upload && fixed_workers.is_some_and(|n| n > capacity) {
            bail!("s3-objects exceeds the available small-upload capacity ({capacity}); lower it or increase the open-file limit");
        }
        let (initial, gradual) =
            self.initial_requests(tiny, small_upload, single_request, capacity);
        self.tuning.configure(initial, capacity, gradual);
        let objects = fixed_workers.unwrap_or(if single_request {
            capacity
        } else if tiny {
            // Mostly small objects, with a few in parts.
            256
        } else {
            MULTIPART_OBJECTS
        });
        // Files to upload get ready ahead of their requests only as far as
        // the upload buffers can hold them; others would be read twice.
        // Larger files, and storage-authorized uploads, keep nothing there
        // and are read again to send anyway.
        let ready = if *route == Route::Upload
            && single_request
            && self.authorization.is_none()
            && average <= HELD_UPLOAD_LIMIT
        {
            (tuning::UPLOAD_BUFFER_BYTES / average.max(1)) as usize
        } else {
            usize::MAX
        };
        let concurrency = Concurrency {
            objects: objects.min(object_limit),
            ready,
            requests: fixed_workers
                .is_none()
                .then(|| self.tuning.requests.clone()),
        };
        self.tuning.report(concurrency.limit());
        Ok(concurrency)
    }

    /// Requests in flight when a batch starts, and whether they grow from
    /// there gradually. The limit then moves with what the batch's own
    /// requests measure, so the start only saves the windows it would take
    /// to get there, which a short copy cannot win back.
    fn initial_requests(
        &self,
        tiny: bool,
        small_upload: bool,
        single_request: bool,
        capacity: usize,
    ) -> (usize, bool) {
        if tiny && self.tuning.far() {
            // Small objects' requests mostly wait for the round trip. Small
            // files to upload start with all their memory and descriptors
            // allow, which is as many as their requests can use.
            if small_upload {
                let near_far = self
                    .tuning
                    .control_latency()
                    .is_some_and(|latency| latency < tuning::NEAR_FAR_LATENCY);
                return (
                    if near_far {
                        capacity.min(2048)
                    } else {
                        capacity
                    },
                    false,
                );
            }
            // Each download in flight holds its response, so more of them
            // are added an eighth at a time: a short copy then ends before
            // it holds thousands it would barely use, and a long one still
            // reaches what its requests show pays.
            return (FAR_SMALL_REQUESTS, true);
        }
        if single_request && !tiny {
            // Objects of a megabyte or more fill a path with fewer requests.
            (tuning::INITIAL_REQUESTS, false)
        } else {
            (MULTIPART_REQUESTS, false)
        }
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
                // A few large ranges fill a nearby endpoint's path, and each
                // range in flight holds several megabytes of buffers.
                Route::Download if self.tuning.local() => 64 * 1024 * 1024,
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
                Route::Download if self.tuning.local() => 4,
                Route::Upload if self.tuning.tigris() => 32,
                Route::Download if self.tuning.tigris() => 8,
                // The request limit, not this, bounds parts across objects.
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
        let mut slot = match initial_slot {
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
                    slot.completed(length);
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
