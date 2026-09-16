//! Copies without payload digests or durable recovery. Object identity, lengths,
//! conditional creation, confined paths and atomic publication remain enforced.
use super::*;
use crate::s3::{writer, Integrity};

impl Engine {
    pub(super) fn object_workers(
        &self,
        fallback: usize,
        sizes: impl Iterator<Item = u64>,
    ) -> Result<usize> {
        if self.options.integrity == Integrity::Full {
            return Ok(fallback);
        }
        let mut count = 0u64;
        let mut bytes = 0u64;
        let mut largest = 0u64;
        for size in sizes {
            count += 1;
            largest = largest.max(size);
            bytes = bytes.saturating_add(size);
        }
        if count == 0 {
            return Ok(1);
        }
        let tiny = bytes / count < 1024 * 1024;
        let small_upload = self.options.upload && largest <= 1024 * 1024;
        let capacity = if small_upload {
            super::super::tuning::small_upload_capacity(largest)?
        } else {
            256
        };
        let workers = if self.args.connections_opt.is_some() {
            fallback
        } else if tiny {
            if small_upload && self.tuning.high_latency() {
                capacity
            } else {
                256
            }
        } else {
            32
        };
        // Small uploads hold a socket and briefly reopen confined source paths.
        // Admission accounts for descriptors already pinned during discovery.
        let workers = if small_upload {
            workers.min(capacity)
        } else {
            workers
        };
        self.tuning
            .configure(tiny, workers, if small_upload { workers } else { 256 });
        Ok(workers)
    }

    pub(super) fn part_size(&self, size: u64) -> u64 {
        if self.options.integrity == Integrity::Full {
            return self.options.part_size;
        }
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
    fn part_workers(&self) -> usize {
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
    pub(super) async fn upload_fast(
        self: &Arc<Self>,
        source: Source,
        existing: Option<Object>,
        size: u64,
    ) -> Result<Option<u64>> {
        let metadata = source.metadata(None);
        // Match the download quick-check: size and native modification time.
        let same = existing.as_ref().is_some_and(|o| {
            o.kind() == source.kind()
                && o.size == size
                && o.metadata.as_ref().is_some_and(|m| {
                    m.mtime == metadata.mtime
                        && m.nsec == metadata.nsec
                        && (!self.args.perms || m.mode == metadata.mode)
                        && (!self.args.owner || m.uid == metadata.uid)
                        && (!self.args.group || m.gid == metadata.gid)
                })
        });
        if same {
            self.progress.bytes_unchanged.fetch_add(size, Relaxed);
            return Ok(None);
        }
        if self.args.dry_run {
            self.progress.add_bytes(size);
            return Ok(Some(size));
        }
        let part_size = self.part_size(size);
        let synchronous =
            source.kind() == "file" && size > 1024 * 1024 && self.tuning.local_latency();
        crate::s3::diagnostics::record(
            serde_json::json!({"phase":"upload_plan","size":size,"part_size":part_size,"part_workers":self.part_workers(),"synchronous":synchronous}),
        );
        anyhow::ensure!(
            part_size <= 5 * 1024 * 1024 * 1024,
            "file exceeds S3 multipart limit"
        );
        let must_be_new = self.args.ignore_existing || self.args.target_existence == Existence::New;
        let _interval = self.progress.copying_interval();
        if size <= part_size || source.kind() != "file" {
            let _slot = self.tuning.requests.acquire().await;
            let small = if source.kind() != "file" {
                Some(aws_smithy_types::body::SdkBody::from(source.bytes()?))
            } else if !synchronous
                && size
                    <= if self.tuning.tigris() {
                        8 * 1024 * 1024
                    } else {
                        1024 * 1024
                    }
            {
                let reservation = self
                    .tuning
                    .upload_buffers
                    .clone()
                    .acquire_many_owned(size.max(1) as u32)
                    .await?;
                self.check_cancelled()?;
                let source = source.clone();
                Some(
                    tokio::task::spawn_blocking(
                        move || -> Result<aws_smithy_types::body::SdkBody> {
                            let mut file = source.open()?;
                            let mut bytes = vec![0; size as usize];
                            file.read_exact(&mut bytes)?;
                            source.check(&file)?;
                            // The reservation follows all SDK body clones, including
                            // a body still owned by the transport after cancellation.
                            Ok(aws_smithy_types::body::SdkBody::from(
                                bytes::Bytes::from_owner(UploadBuffer {
                                    bytes,
                                    _reservation: reservation,
                                }),
                            ))
                        },
                    )
                    .await??,
                )
            } else {
                None
            };
            let file =
                synchronous.then(|| crate::s3::upload_http::FileBody::new(source.clone(), 0, size));
            let mut attempt = 0;
            loop {
                self.check_cancelled()?;
                let body = if let Some(bytes) = &small {
                    ByteStream::new(bytes.try_clone().expect("in-memory body can be retried"))
                } else if synchronous {
                    crate::s3::upload_http::body(size)
                } else {
                    file_body(&source, 0, size).await?
                };
                self.pace(size).await;
                let request = self
                    .client
                    .put_object()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .body(body)
                    .content_length(size as i64)
                    .set_metadata(Some(metadata.encode()))
                    .set_if_none_match(must_be_new.then(|| "*".into()))
                    .customize()
                    .disable_payload_signing();
                let request = if let Some(file) = &file {
                    request.interceptor(file.clone())
                } else {
                    request
                };
                let result = request.send().await;
                if let Some(file) = &file {
                    file.drain().await;
                }
                if result.is_err() && source.kind() == "file" {
                    source.check(&source.open()?)?;
                }
                match result {
                    Ok(_) => break,
                    Err(e)
                        if retryable_status(e.raw_response().map(|r| r.status().as_u16()))
                            && attempt < self.options.retries =>
                    {
                        crate::s3::backoff(attempt).await;
                        attempt += 1;
                    }
                    Err(e) => return Err(e.into_service_error()).context("S3 PUT failed"),
                }
            }
            self.tuning.requests.completed(size);
            self.progress.add_bytes(size);
        } else {
            self.check_cancelled()?;
            let response = self
                .client
                .create_multipart_upload()
                .bucket(&self.options.bucket)
                .key(&source.key)
                .set_metadata(Some(metadata.encode()))
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("create multipart upload")?;
            let upload_id = response
                .upload_id()
                .context("S3 omitted upload ID")?
                .to_owned();
            let result = self
                .upload_fast_parts(&source, size, part_size, &upload_id, must_be_new)
                .await;
            if let Err(error) = result {
                // All part tasks have stopped before aborting the multipart upload.
                let abort = self
                    .client
                    .abort_multipart_upload()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .upload_id(&upload_id)
                    .send()
                    .await;
                return match abort {
                    Ok(_) => Err(error),
                    Err(e) => Err(error.context(format!(
                        "multipart cleanup also failed: {}",
                        e.into_service_error()
                    ))),
                };
            }
        }
        if source.kind() == "file" {
            source.check(&source.open()?)?;
        }
        Ok(Some(size))
    }
    async fn upload_fast_parts(
        self: &Arc<Self>,
        source: &Source,
        size: u64,
        part_size: u64,
        upload_id: &str,
        must_be_new: bool,
    ) -> Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        let mut next = 0;
        let total = size.div_ceil(part_size);
        let mut completed = Vec::with_capacity(total as usize);
        let mut error = None;
        while next < total || !tasks.is_empty() {
            while next < total && tasks.len() < self.part_workers() && error.is_none() {
                let engine = self.clone();
                let source = source.clone();
                let id = upload_id.to_owned();
                let index = next;
                next += 1;
                tasks.spawn(async move {
                    let _slot = engine.tuning.requests.acquire().await;
                    let offset = index * part_size;
                    let length = part_size.min(size - offset);
                    let number = index as i32 + 1;
                    let mut attempt = 0;
                    loop {
                        engine.check_cancelled()?;
                        let synchronous = engine.tuning.local_latency();
                        let body = if synchronous {
                            crate::s3::upload_http::body(length)
                        } else {
                            file_body(&source, offset, length).await?
                        };
                        engine.pace(length).await;
                        let file =
                            crate::s3::upload_http::FileBody::new(source.clone(), offset, length);
                        let request = engine
                            .client
                            .upload_part()
                            .bucket(&engine.options.bucket)
                            .key(&source.key)
                            .upload_id(&id)
                            .part_number(number)
                            .body(body)
                            .content_length(length as i64)
                            .customize()
                            .disable_payload_signing();
                        let request = if synchronous {
                            request.interceptor(file.clone())
                        } else {
                            request
                        };
                        let result = request.send().await;
                        file.drain().await;
                        if result.is_err() {
                            source.check(&source.open()?)?;
                        }
                        match result {
                            Ok(output) => {
                                let etag = output.e_tag().context("S3 part omitted ETag")?;
                                engine.tuning.requests.completed(length);
                                engine.progress.add_bytes(length);
                                return Ok::<_, anyhow::Error>(
                                    CompletedPart::builder()
                                        .part_number(number)
                                        .e_tag(etag)
                                        .build(),
                                );
                            }
                            Err(e)
                                if retryable_status(
                                    e.raw_response().map(|r| r.status().as_u16()),
                                ) && attempt < engine.options.retries =>
                            {
                                crate::s3::backoff(attempt).await;
                                attempt += 1;
                            }
                            Err(e) => return Err(e.into_service_error()).context("upload part"),
                        }
                    }
                });
            }
            if let Some(result) = tasks.join_next().await {
                match result.map_err(anyhow::Error::from).and_then(|r| r) {
                    Ok(part) => completed.push(part),
                    Err(e) => {
                        if error.is_none() {
                            error = Some(e);
                        }
                    }
                }
            }
            if error.is_some() && tasks.is_empty() {
                break;
            }
        }
        if let Some(error) = error {
            return Err(error);
        }
        self.check_cancelled()?;
        source.check(&source.open()?)?;
        completed.sort_by_key(|p| p.part_number());
        self.client
            .complete_multipart_upload()
            .bucket(&self.options.bucket)
            .key(&source.key)
            .upload_id(upload_id)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(completed))
                    .build(),
            )
            .set_if_none_match(must_be_new.then(|| "*".into()))
            .send()
            .await
            .map_err(|e| e.into_service_error())
            .context("complete multipart upload")?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn download_fast(
        self: &Arc<Self>,
        object: &Object,
        root: &Root,
        path: &RelativePath,
        metadata: &Metadata,
        mode: Option<u32>,
        initial: Option<ByteStream>,
        mut initial_slot: Option<crate::s3::tuning::Permit>,
        part_size: u64,
    ) -> Result<Option<u64>> {
        let name = path.to_path_buf();
        let label = name.to_str().context("S3 path requires UTF-8")?;
        let parent = label.rsplit_once('/').map_or("", |(p, _)| p);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let unique: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let partial = RelativePath::new(
            local::join(parent, &format!(".syq-s3-{unique}.partial")).as_bytes(),
        )?;
        let file = Arc::new(root.create_file(&partial, 0o600)?);
        let m = file.metadata()?;
        let _cleanup = PartialCleanup {
            root,
            path: partial.clone(),
            identity: (m.dev(), m.ino()),
        };
        let f = file.clone();
        let size = object.size;
        tokio::task::spawn_blocking(move || writer::allocate(&f, size)).await??;
        let output = writer::Writer::new(file.clone(), size)?;
        crate::s3::diagnostics::record(
            serde_json::json!({"phase":"download_plan","size":size,"part_size":part_size,"part_workers":self.part_workers(),"direct":output.direct()}),
        );
        let mut initial = initial;
        let jobs = (0..size.div_ceil(part_size).max(1)).collect();
        let _interval = self.progress.copying_interval();
        let result = parallel(jobs, self.part_workers(), |index| {
            let engine = self.clone();
            let object = object.clone();
            let output = output.clone();
            let first = if index == 0 { initial.take() } else { None };
            let slot = if index == 0 {
                initial_slot.take()
            } else {
                None
            };
            async move {
                let offset = index * part_size;
                let length = part_size.min(object.size - offset);
                engine
                    .download_fast_range(&object, &output, offset, length, first, slot)
                    .await
            }
        })
        .await;
        // The barrier also waits for queued writes on a failed transfer.
        let flushed = output.finish().await;
        result?;
        flushed?;
        local::apply_file_metadata(&file, metadata, &self.args, mode)?;
        if self.args.ignore_existing || self.args.target_existence == Existence::New {
            root.publish_new_regular(&partial, path, (m.dev(), m.ino()))?;
        } else {
            root.rename_regular_if_same(&partial, path, (m.dev(), m.ino()))?;
        }
        Ok(Some(size))
    }
    async fn download_fast_range(
        &self,
        object: &Object,
        output: &writer::Writer,
        offset: u64,
        length: u64,
        mut initial: Option<ByteStream>,
        initial_slot: Option<crate::s3::tuning::Permit>,
    ) -> Result<()> {
        let _slot = match initial_slot {
            Some(slot) => slot,
            None => self.tuning.requests.acquire().await,
        };
        let mut attempt = 0;
        loop {
            self.check_cancelled()?;
            let started = crate::s3::diagnostics::start();
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
                if !output.direct() {
                    let mut body = body;
                    let mut done = 0;
                    let mut batch = Vec::new();
                    let mut batch_size = 0;
                    while let Some(bytes) =
                        tokio::time::timeout(Duration::from_secs(60), body.next()).await?
                    {
                        let mut bytes = bytes?;
                        if bytes.len() as u64 > length - done {
                            return Err(Permanent("S3 body exceeded length".into()).into());
                        }
                        while !bytes.is_empty() {
                            if batch_size == 0 && bytes.len() >= 128 * 1024 {
                                self.pace(128 * 1024).await;
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
                                self.pace(batch_size as u64).await;
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
                        self.pace(batch_size as u64).await;
                        output
                            .write_batch(batch, offset + done - batch_size as u64)
                            .await?;
                    }
                    return Ok(());
                }
                let mut body = body.into_async_read();
                let mut done = 0;
                let mut buffer = writer::Aligned::new(1024 * 1024)?;
                while done < length {
                    let want = (length - done).min(1024 * 1024) as usize;
                    tokio::time::timeout(
                        Duration::from_secs(60),
                        body.read_exact(&mut buffer.bytes_mut()[..want]),
                    )
                    .await??;
                    anyhow::ensure!(
                        (offset + done).is_multiple_of(4096)
                            && (want.is_multiple_of(4096)
                                || offset + done + want as u64 == object.size),
                        "unaligned S3 direct range"
                    );
                    let padded = want.next_multiple_of(4096);
                    buffer.bytes_mut()[want..padded].fill(0);
                    self.pace(want as u64).await;
                    buffer = output.write_direct(buffer, offset + done, padded).await?;
                    done += want as u64;
                }
                let mut extra = [0];
                if tokio::time::timeout(Duration::from_secs(60), body.read(&mut extra)).await?? != 0
                {
                    return Err(Permanent("S3 body exceeded length".into()).into());
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            match result {
                Ok(()) => {
                    crate::s3::diagnostics::elapsed(started, "download_range", length);
                    self.tuning.requests.completed(length);
                    self.progress.add_bytes(length);
                    return Ok(());
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

struct UploadBuffer {
    bytes: Vec<u8>,
    _reservation: tokio::sync::OwnedSemaphorePermit,
}
impl AsRef<[u8]> for UploadBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
#[cfg(test)]
mod buffer_tests {
    use super::UploadBuffer;
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
