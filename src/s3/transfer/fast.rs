//! Automatic request scheduling and bounded writers, independent of hash policy.
use super::*;
use crate::s3::writer;

impl Engine {
    pub(super) fn object_workers(&self, sizes: impl Iterator<Item = u64>) -> Result<usize> {
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
        let workers =
            if let Some(fixed) = self.args.tuning_options.and_then(|t| t.s3_object_workers) {
                fixed
            } else if tiny {
                if small_upload && self.tuning.high_latency() {
                    capacity
                } else {
                    256
                }
            } else {
                32
            };
        if small_upload
            && self
                .args
                .tuning_options
                .and_then(|t| t.s3_object_workers)
                .is_some_and(|n| n > capacity)
        {
            bail!("s3-max-concurrent-objects exceeds the available small-upload capacity ({capacity}); lower it or increase the open-file limit");
        }
        // Automatic small-upload admission leaves room for source opens,
        // payload buffers, and descriptors pinned during discovery.
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
        loop {
            self.check_cancelled()?;
            let started = crate::s3::diagnostics::start();
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
                            if retryable(&e) {
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
                        if let Some(h) = &mut hash {
                            h.update(&bytes);
                        }
                        if bytes.len() as u64 > length - done {
                            return Err(Permanent("S3 body exceeded length".into()).into());
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
