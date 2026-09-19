//! Raw S3 streams with shared client/admission and entry-scoped completion.
//! Regular-file descriptors use the same object metadata as pathname copies.
use super::{checksum::Algorithm, client, Options};
use crate::descriptor_copy::fd::{Descriptor, Source};
use anyhow::{bail, Context, Result};
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
    Client,
};
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};

/// One client/discovery context and shared part/request admission for the
/// lifetime of a batch. Entry failures do not cancel this client's other jobs.
struct Session {
    client: Client,
    options: Options,
    cancellation: Arc<super::upload_http::Cancellation>,
    parts: Arc<tokio::sync::Semaphore>,
    requests: tokio::sync::Semaphore,
    objects: tokio::sync::Semaphore,
    bandwidth: Option<Arc<crate::bwlimit::BandwidthLimit>>,
}
impl Session {
    async fn connect(
        mut options: Options,
        controls: &crate::descriptor_copy::controls::Controls,
    ) -> Result<Self> {
        let cancellation = Arc::new(super::upload_http::Cancellation::default());
        let (client, _) =
            client::connect(&mut options, Arc::default(), cancellation.clone()).await?;
        Ok(Self {
            client,
            // Keep the existing single-stream window, shared across entries
            // instead of multiplying it by the number of concurrent producers.
            parts: Arc::new(tokio::sync::Semaphore::new(options.concurrency)),
            requests: tokio::sync::Semaphore::new(
                controls.s3_requests.unwrap_or(options.concurrency),
            ),
            objects: tokio::sync::Semaphore::new(controls.s3_objects),
            options,
            cancellation,
            bandwidth: controls.bandwidth(),
        })
    }
    async fn pace(&self, length: u64) {
        if let Some(limit) = &self.bandwidth {
            if length != 0 {
                tokio::time::sleep_until(
                    limit
                        .reserve_prepaid_at(std::time::Instant::now(), length)
                        .into(),
                )
                .await;
            }
        }
    }
    async fn read(&self, input: Descriptor) -> Result<(Descriptor, Part)> {
        // Reserve before reading, so concurrent producers cannot each retain a
        // separate full multipart window. The permit travels with the bytes.
        let credit = self.parts.clone().acquire_owned().await?;
        let (input, bytes) = input
            .read_chunk(usize::try_from(self.options.part_size)?)
            .await?;
        Ok((
            input,
            Part {
                bytes,
                _credit: credit,
            },
        ))
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}
struct Part {
    bytes: Bytes,
    _credit: tokio::sync::OwnedSemaphorePermit,
}

struct Plan<'a> {
    session: &'a Session,
    controls: &'a crate::descriptor_copy::controls::Controls,
    options: Options,
    key: String,
    placement: crate::descriptor_copy::StreamPlacement,
    target: String,
    source_meta: Option<crate::proto::Meta>,
}
pub(crate) fn run(
    options: Options,
    key: String,
    source: Option<Source>,
    as_fd: Option<i32>,
    commit_fd: Option<i32>,
    placement: crate::descriptor_copy::StreamPlacement,
    controls: &crate::descriptor_copy::controls::Controls,
) -> Result<i32> {
    let target = key.clone();
    let key = match &placement.name {
        Some(name) => super::local::join(
            key.trim_end_matches('/'),
            std::str::from_utf8(name).context("S3 keys must be UTF-8")?,
        ),
        None => key,
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let interrupt = async { tokio::select! { result = tokio::signal::ctrl_c() => { result?; }, _ = term.recv() => {} }; Ok::<_, anyhow::Error>(()) };
        tokio::pin!(interrupt);
        let commit = commit_fd.map(|n| Descriptor::open(n, true, cancelled.clone())).transpose()?;
        // Protect caller-owned FDs before connecting. Defer opening a named
        // FIFO until the destination conditions have been checked.
        let descriptor = match &source {
            Some(Source::Descriptor(number)) => Some(Descriptor::open(*number, true, cancelled.clone())?),
            Some(Source::Pipe { .. }) => None,
            None => Some(Descriptor::open(as_fd.unwrap(), false, cancelled.clone())?),
        };
        let source_meta = descriptor.as_ref().and_then(Descriptor::metadata);
        if options.route == crate::s3::Route::Upload {
            controls.metadata.source(source_meta)?;
            if let Some(size) = descriptor.as_ref().map(Descriptor::remaining_len).transpose()?.flatten() {
                controls.set_size(size);
            }
        }
        if options.route == crate::s3::Route::Download {
            controls.metadata.output(descriptor.as_ref().and_then(Descriptor::metadata).is_some())?;
        }
        let session = tokio::select! {
            value = Session::connect(options, controls) => value?,
            value = &mut interrupt => { value?; bail!("stream cancelled"); }
        };
        let plan = Plan { session: &session, controls, options: session.options.clone(), key, placement, target, source_meta };
        let operation = execute(&plan, source, descriptor, commit, cancelled.clone());
        tokio::pin!(operation);
        tokio::select! {
            result = &mut operation => result,
            result = &mut interrupt => {
                result?;
                cancelled.store(true, Relaxed);
                operation.await
            }
        }
    });
    cancelled.store(true, Relaxed);
    // A quiet inherited pipe can keep a blocking worker alive indefinitely.
    // This entry point is CLI-only: main exits immediately after reporting the
    // result. Finish multipart cleanup above, then let process exit stop I/O.
    runtime.shutdown_background();
    result.map(|()| 0)
}

async fn execute(
    plan: &Plan<'_>,
    source: Option<Source>,
    descriptor: Option<Descriptor>,
    commit: Option<Descriptor>,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    let mut retirements: Vec<_> = descriptor
        .iter()
        .chain(commit.iter())
        .filter_map(Descriptor::retirement)
        .collect();
    let _cancel = crate::descriptor_copy::fd::CancelOnDrop(cancelled.clone());
    let client = &plan.session.client;
    let controls = plan.controls;
    let mut upload_id = None;
    let mut _object = None;
    let result = {
        let operation = async {
            _object = Some(plan.session.objects.acquire().await?);
            if plan.options.route == crate::s3::Route::Upload {
                {
                    let _request = plan.session.requests.acquire().await?;
                    check_placement(client, plan).await?;
                }
                if controls.report.skipped() || controls.report.dry_run {
                    return Ok(());
                }
                controls.report.ready();
            }
            let descriptor = match descriptor {
                Some(descriptor) => descriptor,
                None => {
                    let descriptor = source
                        .context("missing stream input")?
                        .open(cancelled.clone())
                        .await?;
                    if let Some(retired) = descriptor.retirement() {
                        retirements.push(retired);
                    }
                    descriptor
                }
            };
            if plan.options.route == crate::s3::Route::Upload {
                upload(client, plan, descriptor, &mut upload_id, commit).await
            } else {
                download(client, plan, descriptor).await
            }
        };
        tokio::select! {
            result = operation => result,
            _ = async { while !cancelled.load(Relaxed) { tokio::time::sleep(Duration::from_millis(50)).await; } } => Err(anyhow::anyhow!("stream cancelled")),
        }
    };
    if result.is_err() {
        cancelled.store(true, Relaxed);
        if let Some(id) = upload_id {
            let abort = async {
                let _request = plan.session.requests.acquire().await?;
                client
                    .abort_multipart_upload()
                    .bucket(&plan.options.bucket)
                    .key(&plan.key)
                    .upload_id(&id)
                    .send()
                    .await?;
                Ok::<_, anyhow::Error>(())
            };
            if !matches!(
                tokio::time::timeout(Duration::from_secs(5), abort).await,
                Ok(Ok(()))
            ) {
                crate::output::diagnostic!("syq cp: could not confirm multipart cleanup; inspect incomplete uploads for this object");
            }
        }
    }
    for retired in retirements {
        retired.wait().await;
    }
    result
}

/// With a source base, keys use ordinary cp's relative path semantics.
/// Without one, preserve literal raw-object key spellings.
pub(crate) fn source_key(path: &[u8], base: Option<&[u8]>) -> Result<String> {
    match base {
        Some(base) => Ok(super::local::join(
            &super::local::key_path(base)?,
            &super::local::key_path(path)?,
        )),
        None => Ok(std::str::from_utf8(path)
            .context("S3 key must be UTF-8")?
            .to_owned()),
    }
}

async fn check_placement(client: &Client, plan: &Plan<'_>) -> Result<()> {
    use crate::cli::Existence;
    let existence = plan.placement.existence;
    let report = &plan.controls.report;
    let policy = report.only_new || report.only_existing;
    let inspect_placement = existence != Existence::Any || policy;
    if !inspect_placement && !plan.controls.metadata.skip_newer {
        return Ok(());
    }
    // Match ordinary S3 cp: a new target must have neither an exact object
    // nor descendants; an existing container needs at least one prefixed key.
    // Existence checks do not need to decode object metadata.
    // Timestamp selection alone needs only the exact destination's HEAD.
    // An S3 key and a prefix with the same spelling can coexist.
    let container = inspect_placement && plan.placement.name.is_some();
    let target = if container {
        plan.target.trim_end_matches('/')
    } else {
        &plan.key
    };
    let exact_head = if target.is_empty() {
        None
    } else {
        client::head_output(client, &plan.options.bucket, target, None).await?
    };
    if inspect_placement {
        let exact = exact_head.is_some();
        let prefix = if target.is_empty() {
            String::new()
        } else {
            format!("{target}/")
        };
        let present = (!(existence == Existence::Existing && container) && exact)
            || super::client::prefix_exists(client, &plan.options.bucket, &prefix).await?;
        if (existence == Existence::New && present)
            || (existence == Existence::Existing && !present)
        {
            bail!("S3 destination existence condition failed");
        }
        if policy {
            let final_present = if container {
                super::client::head_output(client, &plan.options.bucket, &plan.key, None)
                    .await?
                    .is_some()
                    || super::client::prefix_exists(
                        client,
                        &plan.options.bucket,
                        &format!("{}/", plan.key.trim_end_matches('/')),
                    )
                    .await?
            } else {
                present
            };
            if (report.only_new && final_present) || (report.only_existing && !final_present) {
                report.skip();
                return Ok(());
            }
        }
        if !container && present && !exact {
            bail!("S3 destination is a prefix, not an object");
        }
    }
    if plan.controls.metadata.skip_newer {
        let head = if container {
            client::head_output(client, &plan.options.bucket, &plan.key, None).await?
        } else {
            exact_head
        };
        // Match pathname S3 copies, which compare whole seconds.
        if let Some(head) = head {
            let stored = client::Metadata::decode(head.metadata())?;
            let mtime =
                stored.map_or_else(|| head.last_modified().map_or(0, |t| t.secs()), |m| m.mtime);
            if mtime > plan.source_meta.context("missing source timestamp")?.mtime {
                report.skip();
            }
        }
    }
    Ok(())
}

fn digest(algorithm: Algorithm, data: &[u8]) -> String {
    let mut hash = algorithm.hasher();
    hash.update(data);
    hash.finish()
}

async fn upload(
    client: &Client,
    plan: &Plan<'_>,
    input: Descriptor,
    upload_id: &mut Option<String>,
    commit: Option<Descriptor>,
) -> Result<()> {
    let controls = plan.controls;
    let options = &plan.options;
    let metadata = plan.source_meta.map(|m| {
        client::Metadata {
            kind: client::ObjectKind::File,
            mode: m.mode,
            uid: m.uid,
            gid: m.gid,
            mtime: m.mtime,
            nsec: m.mtime_nsec,
            hash: None,
            hash_algorithm: Default::default(),
        }
        .encode()
    });

    let size = usize::try_from(options.part_size)?;
    let algorithm = Algorithm::for_endpoint(options.endpoint.as_deref());
    let (mut input, first) = plan.session.read(input).await?;
    if first.bytes.len() < size {
        let length = first.bytes.len() as u64;
        plan.session.pace(length).await;
        crate::descriptor_copy::fd::await_commit(commit).await?;
        let hash = digest(algorithm, &first.bytes);
        let _request = plan.session.requests.acquire().await?;
        client
            .put_object()
            .set_metadata(metadata)
            .bucket(&options.bucket)
            .key(&plan.key)
            .set_checksum_sha256(algorithm.is_sha256().then_some(hash.clone()))
            .set_content_md5((algorithm == Algorithm::Md5).then_some(hash))
            .set_if_none_match(
                (plan.placement.existence == crate::cli::Existence::New
                    || plan.controls.report.only_new)
                    .then(|| "*".into()),
            )
            .body(ByteStream::from(first.bytes))
            .send()
            .await
            .map_err(|e| e.into_service_error())
            .context("upload object")?;
        controls.progress.add_bytes(length);
        return Ok(());
    }
    let request = plan.session.requests.acquire().await?;
    let created = client
        .create_multipart_upload()
        .set_metadata(metadata)
        .bucket(&options.bucket)
        .key(&plan.key)
        .set_checksum_algorithm(
            algorithm
                .is_sha256()
                .then_some(aws_sdk_s3::types::ChecksumAlgorithm::Sha256),
        )
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("create multipart upload")?;
    drop(request);
    let id = created
        .upload_id()
        .context("S3 omitted upload ID")?
        .to_owned();
    *upload_id = Some(id.clone());
    let mut pending = futures_util::stream::FuturesUnordered::new();
    let mut completed = Vec::new();
    let mut number = 1;
    let mut data = first;
    loop {
        if number > 10_000 {
            bail!("stream exceeds 10,000 multipart parts; rerun with a larger --performance-tuning s3-part-size=SIZE");
        }
        let last = data.bytes.len() < size;
        pending.push(upload_part(client, plan, &id, number, data, algorithm));
        number += 1;
        if pending.len() >= options.concurrency {
            completed.push(pending.try_next().await?.unwrap());
        }
        if last {
            break;
        }
        // Poll network futures while reading a possibly slow producer.
        let read = plan.session.read(input);
        tokio::pin!(read);
        let next = loop {
            tokio::select! {
                next = &mut read => break next?,
                part = pending.try_next(), if !pending.is_empty() => { completed.push(part?.unwrap()); }
            }
        };
        input = next.0;
        data = next.1;
        if data.bytes.is_empty() {
            drop(data);
            break;
        }
    }
    while let Some(part) = pending.try_next().await? {
        completed.push(part);
    }
    completed.sort_by_key(|p| p.part_number());
    crate::descriptor_copy::fd::await_commit(commit).await?;
    let _request = plan.session.requests.acquire().await?;
    client
        .complete_multipart_upload()
        .bucket(&options.bucket)
        .key(&plan.key)
        .upload_id(&id)
        .set_if_none_match(
            (plan.placement.existence == crate::cli::Existence::New
                || plan.controls.report.only_new)
                .then(|| "*".into()),
        )
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(completed))
                .build(),
        )
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context(
            "complete multipart upload (destination may have completed if the response was lost)",
        )?;
    *upload_id = None;
    Ok(())
}

async fn upload_part(
    client: &Client,
    plan: &Plan<'_>,
    id: &str,
    number: i32,
    data: Part,
    algorithm: Algorithm,
) -> Result<CompletedPart> {
    let controls = plan.controls;
    let length = data.bytes.len() as u64;
    plan.session.pace(length).await;
    let hash = digest(algorithm, &data.bytes);
    let _request = plan.session.requests.acquire().await?;
    let output = client
        .upload_part()
        .bucket(&plan.options.bucket)
        .key(&plan.key)
        .upload_id(id)
        .part_number(number)
        .set_checksum_sha256(algorithm.is_sha256().then_some(hash.clone()))
        .set_content_md5((algorithm == Algorithm::Md5).then_some(hash.clone()))
        .body(ByteStream::from(data.bytes))
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("upload stream part")?;
    controls.progress.add_bytes(length);
    Ok(CompletedPart::builder()
        .part_number(number)
        .e_tag(output.e_tag().context("S3 part omitted ETag")?)
        .set_checksum_sha256(algorithm.is_sha256().then_some(hash))
        .build())
}

async fn download(client: &Client, plan: &Plan<'_>, mut output: Descriptor) -> Result<()> {
    let controls = plan.controls;
    // Read raw objects, including objects carrying another tool's metadata.
    let request = plan.session.requests.acquire().await?;
    let head = client
        .head_object()
        .bucket(&plan.options.bucket)
        .key(&plan.key)
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("inspect source object")?;
    drop(request);
    let size = u64::try_from(
        head.content_length()
            .context("S3 HEAD omitted Content-Length")?,
    )?;
    controls.set_size(size);
    if controls.report.only_new {
        controls.report.skip();
        return Ok(());
    }
    // Raw output needs no object attributes, even when the FD is a file.
    let source_meta = if controls.metadata.preserve != 0 {
        let stored = client::Metadata::decode(head.metadata())?;
        let meta = stored
            .filter(|m| m.kind == client::ObjectKind::File)
            .map_or_else(
                || crate::proto::Meta {
                    mode: 0o666,
                    uid: unsafe { libc::geteuid() },
                    gid: unsafe { libc::getegid() },
                    mtime: head.last_modified().map_or(0, |t| t.secs()),
                    mtime_nsec: 0,
                },
                |m| crate::proto::Meta {
                    mode: m.mode,
                    uid: m.uid,
                    gid: m.gid,
                    mtime: m.mtime,
                    mtime_nsec: m.nsec,
                },
            );
        Some(meta)
    } else {
        None
    };
    if controls.report.dry_run {
        return Ok(());
    }
    controls.report.ready();
    let etag = head.e_tag().context("S3 HEAD omitted ETag")?;
    let version = head.version_id();
    let part_size = plan.options.part_size;
    let mut parts = stream::iter(0..size.div_ceil(part_size))
        .map(|index| {
            read_part(
                client,
                plan,
                etag,
                version,
                size,
                index * part_size,
                part_size.min(size - index * part_size),
            )
        })
        .buffered(plan.options.concurrency);
    while let Some(bytes) = parts.try_next().await? {
        let length = bytes.bytes.len() as u64;
        output = output.write_chunk(bytes.bytes).await?;
        controls.progress.add_bytes(length);
    }
    output.apply_metadata(controls.metadata, source_meta)
}

async fn read_part(
    client: &Client,
    plan: &Plan<'_>,
    etag: &str,
    version: Option<&str>,
    size: u64,
    offset: u64,
    length: u64,
) -> Result<Part> {
    let credit = plan.session.parts.clone().acquire_owned().await?;
    plan.session.pace(length).await;
    let _request = plan.session.requests.acquire().await?;
    let range = format!("bytes={offset}-{}", offset + length - 1);
    let expected = format!("bytes {offset}-{}/{size}", offset + length - 1);
    for attempt in 0..=plan.options.retries {
        let result = client
            .get_object()
            .bucket(&plan.options.bucket)
            .key(&plan.key)
            .range(&range)
            .if_match(etag)
            .set_version_id(version.map(str::to_owned))
            .customize()
            .config_override(client::without_sdk_retries())
            .send()
            .await;
        let mut response = match result {
            Ok(response) => response,
            Err(e) if super::transfer::retryable(&e) && attempt < plan.options.retries => {
                super::backoff(attempt).await;
                continue;
            }
            Err(e) => return Err(e.into_service_error()).context("download stream part"),
        };
        if response.content_length() != Some(length as i64)
            || response.content_range() != Some(expected.as_str())
            || response.e_tag() != Some(etag)
            || (version.is_some() && response.version_id() != version)
        {
            bail!("S3 object changed or returned an unexpected range");
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(usize::try_from(length)?)
            .context("allocate download part")?;
        let mut failed = false;
        while let Some(chunk) = response.body.next().await {
            match chunk {
                Ok(chunk) => {
                    if chunk.len() as u64 > length - buffer.len() as u64 {
                        bail!("S3 range returned too many bytes");
                    }
                    buffer.extend_from_slice(&chunk);
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if !failed && buffer.len() as u64 == length {
            return Ok(Part {
                bytes: Bytes::from(buffer),
                _credit: credit,
            });
        }
        if attempt == plan.options.retries {
            bail!("S3 range was interrupted or truncated");
        }
        super::backoff(attempt).await;
    }
    unreachable!()
}

#[cfg(test)]
mod tests;
