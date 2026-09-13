use super::{
    client::{self, Metadata, Object},
    local::{self, Destination, Source},
    state::State,
    Options,
};
use crate::{
    cli::{Args, Existence, Placement, SourceSelection},
    progress::Progress,
    rooted::{RelativePath, Root},
};
use anyhow::{bail, Context, Result};
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart},
    Client,
};
use aws_smithy_types::byte_stream::Length;
use base64::Engine as _;
use futures_util::{stream, StreamExt, TryStreamExt};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::Read,
    os::unix::fs::{FileExt, MetadataExt},
    sync::{atomic::Ordering::Relaxed, Arc},
    time::Duration,
};
use tokio::{io::AsyncReadExt, sync::Mutex};

type DirectoryMetadata = Arc<Mutex<Vec<(String, Metadata, Option<u32>)>>>;

pub(super) struct Engine {
    args: Arc<Args>,
    options: Options,
    client: Client,
    progress: Arc<Progress>,
    pace: Mutex<tokio::time::Instant>,
    upload_keys: OnceLock<HashSet<String>>,
}
#[derive(Clone)]
struct Download {
    key: String,
    path: String,
    size: u64,
}
#[derive(Serialize, Deserialize)]
struct UploadState {
    schema: u32,
    digest: String,
    part_size: u64,
    upload_id: String,
    metadata: Metadata,
}
#[derive(Serialize, Deserialize)]
struct DownloadState {
    schema: u32,
    etag: String,
    version: Option<String>,
    size: u64,
    part_size: u64,
    partial: String,
    dev: u64,
    ino: u64,
    parts: BTreeMap<u64, String>,
}

impl Engine {
    pub async fn new(args: Arc<Args>, progress: Arc<Progress>) -> Result<Arc<Self>> {
        let mut options = args.s3.clone().unwrap();
        options.endpoint = options
            .endpoint
            .or_else(|| std::env::var("AWS_ENDPOINT_URL_S3").ok())
            .or_else(|| std::env::var("AWS_ENDPOINT_URL").ok());
        let client = client::connect(&mut options).await?;
        Ok(Arc::new(Self {
            args,
            options,
            client,
            progress,
            pace: Mutex::new(tokio::time::Instant::now()),
            upload_keys: OnceLock::new(),
        }))
    }
    pub async fn run(self: Arc<Self>, workers: usize) -> Result<()> {
        let work = self.clone().copy(workers);
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result=work=>result,
            _=tokio::signal::ctrl_c()=>bail!("S3 copy interrupted; rerun the command to resume"),
            _=terminate.recv()=>bail!("S3 copy terminated; rerun the command to resume"),
        }
    }
    async fn copy(self: Arc<Self>, workers: usize) -> Result<()> {
        if self.options.upload {
            let args = self.args.clone();
            let plan = tokio::task::spawn_blocking(move || local::upload_plan(&args)).await??;
            self.check_upload_placement(&plan).await?;
            if plan.len() > 1 && !self.args.existing && !self.args.ignore_existing {
                let target = local::key_path(&self.args.locations.last().unwrap().path)?;
                let prefix = if target.is_empty() {
                    String::new()
                } else {
                    format!("{target}/")
                };
                let keys = client::list(&self.client, &self.options.bucket, &prefix)
                    .await?
                    .into_iter()
                    .map(|(key, _)| key)
                    .collect();
                let _ = self.upload_keys.set(keys);
            }

            self.progress.files_total.store(plan.len() as u64, Relaxed);
            self.progress.bytes_total.store(
                plan.iter()
                    .filter(|s| s.kind() == "file")
                    .map(|s| s.meta.len)
                    .sum(),
                Relaxed,
            );
            self.progress.scan_done.store(true, Relaxed);
            parallel(plan, workers, |source| {
                let engine = self.clone();
                async move {
                    let key = source.key.clone();
                    let label = source.label.clone();
                    let kind = source.kind();
                    let result = engine.upload(source).await;
                    engine.settle(&label, &key, kind, &result);
                    Ok(())
                }
            })
            .await?;
        } else {
            let destination = Arc::new(Destination::open(&self.args)?);
            let plan = self.download_plan(&destination).await?;
            self.progress.files_total.store(plan.len() as u64, Relaxed);
            self.progress
                .bytes_total
                .store(plan.iter().map(|s| s.size).sum(), Relaxed);
            self.progress.scan_done.store(true, Relaxed);
            // Directory metadata is applied after descendants, so creating
            // children cannot change the restored times or require final modes.
            let directories = Arc::new(Mutex::new(Vec::new()));
            parallel(plan, workers, |job| {
                let engine = self.clone();
                let dst = destination.clone();
                let dirs = directories.clone();
                async move {
                    let mut kind = "file";
                    let result = engine.download(&job, &dst, dirs, &mut kind).await;
                    engine.settle(job.key.as_bytes(), &job.path, kind, &result);
                    Ok(())
                }
            })
            .await?;
            if !self.args.dry_run && !self.args.verify_only {
                let mut directories = directories.lock().await;
                directories.sort_by_key(|(path, _, _)| std::cmp::Reverse(path.len()));
                for (path, meta, mode) in directories.iter() {
                    local::apply_metadata(
                        &destination.root,
                        &RelativePath::new(path.as_bytes())?,
                        meta,
                        &self.args,
                        *mode,
                    )?;
                }
            }
        }
        Ok(())
    }
    fn settle(&self, src: &[u8], dst: &str, kind: &'static str, result: &Result<Option<u64>>) {
        let action = match kind {
            "dir" => "create_directory",
            "symlink" => "create_symlink",
            _ => "transfer_file",
        };
        match result {
            Ok(Some(bytes)) => {
                if kind == "file" {
                    self.progress.files_done.fetch_add(1, Relaxed);
                } else if self.options.upload {
                    if kind == "dir" {
                        self.progress.directories_created.fetch_add(1, Relaxed);
                    } else {
                        self.progress.symlinks_created.fetch_add(1, Relaxed);
                    }
                }
                if self.args.verbose > 0 {
                    self.progress.println(&format!(
                        "{} {dst}",
                        if self.args.dry_run {
                            "would copy"
                        } else {
                            "copied"
                        }
                    ));
                }
                if let Some(writer) = self.progress.results_writer() {
                    if self.args.dry_run {
                        writer.emit_trace(&crate::results::TraceRecord {
                            action,
                            src: Some(src),
                            dst: dst.as_bytes(),
                            kind,
                            bytes: Some(*bytes),
                            reason: "content_differs",
                        });
                    } else {
                        writer.emit_operation(&crate::results::OperationRecord {
                            action,
                            src: Some(src),
                            dst: dst.as_bytes(),
                            kind,
                            disposition: "succeeded",
                            bytes: Some(*bytes),
                            attempts: None,
                            retryable: None,
                            class: None,
                            os_kind: None,
                            message: None,
                        });
                    }
                }
            }
            Ok(None) => {
                if kind == "file" {
                    self.progress.files_unchanged.fetch_add(1, Relaxed);
                }
            }
            Err(error) => {
                let message = format!("S3 {dst}: {error:#}");
                self.progress.error(&message);
                if let Some(writer) = self.progress.results_writer() {
                    writer.emit_operation(&crate::results::OperationRecord {
                        action,
                        src: Some(src),
                        dst: dst.as_bytes(),
                        kind,
                        disposition: "failed",
                        bytes: None,
                        attempts: None,
                        retryable: None,
                        class: Some("transport"),
                        os_kind: None,
                        message: Some(&message),
                    });
                }
            }
        }
    }
    async fn pace(&self, n: u64) {
        if self.args.bwlimit_bytes == 0 {
            return;
        }
        let mut next = self.pace.lock().await;
        let now = tokio::time::Instant::now();
        let start = (*next).max(now);
        *next = start + Duration::from_secs_f64(n as f64 / self.args.bwlimit_bytes as f64);
        drop(next);
        tokio::time::sleep_until(start).await;
    }
    fn identity(&self, key: &str, extra: &str) -> Vec<u8> {
        let mut hash = blake3::Hasher::new();
        for header in &self.options.headers {
            hash.update(header.0.as_bytes());
            hash.update(&[0]);
            hash.update(header.1.as_bytes());
            hash.update(&[0]);
        }
        format!(
            "syq.s3.v1\n{}\n{}\n{}\n{}\n{}\n{extra}",
            self.options.endpoint.as_deref().unwrap_or("AWS"),
            self.client.config().region().map_or("", |r| r.as_ref()),
            self.options.bucket,
            key,
            hash.finalize()
        )
        .into_bytes()
    }
    async fn check_upload_placement(&self, plan: &[Source]) -> Result<()> {
        if self.args.target_existence == Existence::Any {
            return Ok(());
        }
        let target = local::key_path(&self.args.locations.last().unwrap().path)?;
        let exact = if target.is_empty() {
            false
        } else {
            client::head(&self.client, &self.options.bucket, &target)
                .await?
                .is_some()
        };
        let prefix = if target.is_empty() {
            String::new()
        } else {
            format!("{target}/")
        };
        let present = exact
            || !client::list(&self.client, &self.options.bucket, &prefix)
                .await?
                .is_empty();
        if (self.args.target_existence == Existence::New && present)
            || (self.args.target_existence == Existence::Existing && !present)
        {
            bail!("S3 destination existence condition failed");
        }
        if self.args.placement == Placement::As
            && plan.first().is_some_and(|s| s.kind() == "file")
            && present
            && !exact
        {
            bail!("S3 destination is a prefix, not an object");
        }
        Ok(())
    }
    async fn upload(&self, source: Source) -> Result<Option<u64>> {
        let existing = if self
            .upload_keys
            .get()
            .is_some_and(|keys| !keys.contains(&source.key))
        {
            None
        } else {
            client::head(&self.client, &self.options.bucket, &source.key).await?
        };
        if (self.args.ignore_existing && existing.is_some())
            || (self.args.existing && existing.is_none())
        {
            return Ok(None);
        }
        if self.args.update
            && existing.as_ref().is_some_and(|o| {
                o.metadata.as_ref().map_or(o.mtime, |m| m.mtime) > source.meta.mtime
            })
        {
            return Ok(None);
        }
        let size = if source.kind() == "dir" {
            0
        } else {
            source.meta.len
        };
        let part_size = self.options.part_size.max(size.div_ceil(10_000));
        if part_size > 5 * 1024 * 1024 * 1024 {
            bail!("file exceeds the S3 multipart size limit");
        }
        let source_clone = source.clone();
        let (digest, checksums, small) = tokio::task::spawn_blocking(move || -> Result<_> {
            if source_clone.kind() != "file" {
                let bytes = source_clone.bytes()?;
                return Ok((
                    blake3::hash(&bytes).to_hex().to_string(),
                    vec![sha256(&bytes)],
                    Some(bytes),
                ));
            }
            if size > part_size && size >= 32 * 1024 * 1024 {
                // The object's digest must be available before initiating the
                // upload. Hash independent parts and the whole file in parallel
                // so this pass can use the same cores as the transfer workers.
                let (whole, parts) = rayon::join(
                    || local::hash_file(source_clone.open()?),
                    || {
                        (0..size.div_ceil(part_size))
                            .into_par_iter()
                            .map(|index| {
                                let file = source_clone.open()?;
                                let offset = index * part_size;
                                let length = part_size.min(size - offset);
                                let mut buffer = vec![0; 1024 * 1024];
                                let mut hash = Sha256::new();
                                let mut done = 0;
                                while done < length {
                                    let n = buffer.len().min((length - done) as usize);
                                    file.read_exact_at(&mut buffer[..n], offset + done)?;
                                    hash.update(&buffer[..n]);
                                    done += n as u64;
                                }
                                source_clone.check(&file)?;
                                Ok(base64::engine::general_purpose::STANDARD
                                    .encode(hash.finalize()))
                            })
                            .collect::<Result<Vec<_>>>()
                    },
                );
                source_clone.check(&source_clone.open()?)?;
                return Ok((whole?, parts?, None));
            }
            let mut file = source_clone.open()?;
            let mut whole = blake3::Hasher::new();
            let mut buffer = vec![0; 1024 * 1024];
            let mut parts = Vec::new();
            let mut remaining = size;
            while remaining > 0 {
                let mut part = Sha256::new();
                let mut left = remaining.min(part_size);
                while left > 0 {
                    let want = buffer.len().min(left as usize);
                    file.read_exact(&mut buffer[..want])?;
                    whole.update(&buffer[..want]);
                    part.update(&buffer[..want]);
                    left -= want as u64;
                }
                parts.push(base64::engine::general_purpose::STANDARD.encode(part.finalize()));
                remaining = remaining.saturating_sub(part_size);
            }
            if size == 0 {
                parts.push(sha256(&[]));
            }
            source_clone.check(&file)?;
            Ok((whole.finalize().to_hex().to_string(), parts, None))
        })
        .await??;
        let metadata = source.metadata(Some(digest.clone()));
        let mut unchanged = existing.as_ref().is_some_and(|o| {
            o.kind() == source.kind()
                && o.size == size
                && o.metadata.as_ref().is_some_and(|m| {
                    m.hash.as_ref() == Some(&digest)
                        && m.mtime == metadata.mtime
                        && m.nsec == metadata.nsec
                        && (!self.args.perms || m.mode == metadata.mode)
                        && (!(self.args.owner || self.args.group)
                            || (m.uid == metadata.uid && m.gid == metadata.gid))
                })
        });
        if self.args.checksum {
            if let Some(object) = &existing {
                unchanged = unchanged && self.remote_hash(object).await? == digest;
            }
        }
        if self.args.verify_only {
            let object = existing.context("verification failed: destination object is missing")?;
            self.verify_upload(&source, &object, &digest).await?;
            return Ok(None);
        }
        if unchanged {
            self.progress.bytes_unchanged.fetch_add(size, Relaxed);
            return Ok(None);
        }
        if self.args.dry_run {
            self.progress.add_bytes(size);
            return Ok(Some(size));
        }
        let _interval = self.progress.copying_interval();
        let must_be_new = self.args.ignore_existing || self.args.target_existence == Existence::New;
        if size <= part_size || small.is_some() {
            let mut attempt = 0;
            loop {
                let body = if let Some(bytes) = &small {
                    ByteStream::from(bytes.clone())
                } else {
                    file_body(&source, 0, size).await?
                };
                self.pace(size).await;
                let result = self
                    .client
                    .put_object()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .body(body)
                    .content_length(size as i64)
                    .checksum_sha256(&checksums[0])
                    .set_metadata(Some(metadata.encode()))
                    .set_if_none_match(must_be_new.then(|| "*".into()))
                    .send()
                    .await;
                match result {
                    Ok(_) => break,
                    Err(e)
                        if retryable_status(e.raw_response().map(|r| r.status().as_u16()))
                            && attempt < self.options.retries =>
                    {
                        super::backoff(attempt).await;
                        attempt += 1;
                    }
                    Err(e) => return Err(e.into_service_error()).context("S3 PUT failed"),
                }
            }
            self.progress.add_bytes(size);
        } else {
            let state = State::open(&self.identity(&source.key, "upload"))?;
            let mut previous: Option<UploadState> = state.load()?;
            if let Some(old) = &previous {
                if old.schema != 1 {
                    bail!("unsupported S3 upload recovery schema");
                }
                if old.digest != digest || old.part_size != part_size || old.metadata != metadata {
                    self.client
                        .abort_multipart_upload()
                        .bucket(&self.options.bucket)
                        .key(&source.key)
                        .upload_id(&old.upload_id)
                        .send()
                        .await
                        .map_err(|e| e.into_service_error())
                        .context("abort obsolete multipart upload")?;
                    state.clear()?;
                    previous = None;
                }
            }
            let mut uploaded = HashMap::new();
            if let Some(old) = &previous {
                let mut marker = None;
                loop {
                    let result = self
                        .client
                        .list_parts()
                        .bucket(&self.options.bucket)
                        .key(&source.key)
                        .upload_id(&old.upload_id)
                        .set_part_number_marker(marker.clone())
                        .send()
                        .await;
                    match result {
                        Ok(output) => {
                            for p in output.parts() {
                                if let (Some(number), Some(etag), Some(checksum)) =
                                    (p.part_number(), p.e_tag(), p.checksum_sha256())
                                {
                                    uploaded.insert(number, (etag.to_owned(), checksum.to_owned()));
                                }
                            }
                            if output.is_truncated() != Some(true) {
                                break;
                            }
                            let next = output
                                .next_part_number_marker()
                                .context("S3 parts listing omitted continuation")?
                                .to_owned();
                            if marker.as_ref() == Some(&next) {
                                bail!("S3 parts listing repeated its continuation marker");
                            }
                            marker = Some(next);
                        }
                        Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404) => {
                            previous = None;
                            state.clear()?;
                            break;
                        }
                        Err(e) => {
                            return Err(e.into_service_error()).context("list uploaded parts")
                        }
                    }
                }
            }
            let upload = if let Some(old) = previous {
                old
            } else {
                let output = self
                    .client
                    .create_multipart_upload()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .set_metadata(Some(metadata.encode()))
                    .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Sha256)
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("create multipart upload")?;
                let record = UploadState {
                    schema: 1,
                    digest,
                    part_size,
                    metadata: metadata.clone(),
                    upload_id: output.upload_id().context("S3 omitted upload ID")?.into(),
                };
                if let Err(error) = state.save(&record) {
                    self.client
                        .abort_multipart_upload()
                        .bucket(&self.options.bucket)
                        .key(&source.key)
                        .upload_id(&record.upload_id)
                        .send()
                        .await
                        .map_err(|e| e.into_service_error())
                        .context(
                            "recovery record could not be saved and aborting the upload failed",
                        )?;
                    return Err(error);
                }
                record
            };
            let completed = stream::iter(checksums.into_iter().enumerate())
                .map(|(index, checksum)| {
                    let source = &source;
                    let upload = &upload;
                    let uploaded = &uploaded;
                    async move {
                        let number = index as i32 + 1;
                        let offset = index as u64 * part_size;
                        let length = part_size.min(size - offset);
                        if let Some((etag, old_checksum)) = uploaded.get(&number) {
                            if old_checksum == &checksum {
                                self.progress.bytes_unchanged.fetch_add(length, Relaxed);
                                return Ok(CompletedPart::builder()
                                    .part_number(number)
                                    .e_tag(etag)
                                    .checksum_sha256(&checksum)
                                    .build());
                            }
                        }
                        let mut attempt = 0;
                        loop {
                            let body = file_body(source, offset, length).await?;
                            self.pace(length).await;
                            let result = self
                                .client
                                .upload_part()
                                .bucket(&self.options.bucket)
                                .key(&source.key)
                                .upload_id(&upload.upload_id)
                                .part_number(number)
                                .body(body)
                                .content_length(length as i64)
                                .checksum_sha256(&checksum)
                                .send()
                                .await;
                            match result {
                                Ok(output) => {
                                    self.progress.add_bytes(length);
                                    return Ok(CompletedPart::builder()
                                        .part_number(number)
                                        .e_tag(output.e_tag().context("S3 part omitted ETag")?)
                                        .checksum_sha256(&checksum)
                                        .build());
                                }
                                Err(e)
                                    if retryable_status(
                                        e.raw_response().map(|r| r.status().as_u16()),
                                    ) && attempt < self.options.retries =>
                                {
                                    super::backoff(attempt).await;
                                    attempt += 1;
                                }
                                Err(e) => {
                                    return Err(e.into_service_error())
                                        .context("upload part; rerun the command to resume")
                                }
                            }
                        }
                    }
                })
                .buffer_unordered(self.options.concurrency)
                .try_collect::<Vec<_>>()
                .await?;
            source.check(&source.open()?)?;
            let mut completed = completed;
            completed.sort_by_key(|p| p.part_number());
            self.client
                .complete_multipart_upload()
                .bucket(&self.options.bucket)
                .key(&source.key)
                .upload_id(&upload.upload_id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(completed))
                        .build(),
                )
                .set_if_none_match(must_be_new.then(|| "*".into()))
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("complete multipart upload; rerun the command to recover")?;
            state.clear()?;
        }
        if source.kind() == "file" {
            source.check(&source.open()?)?;
        }
        Ok(Some(size))
    }
    async fn verify_upload(&self, source: &Source, object: &Object, digest: &str) -> Result<()> {
        if object.kind() != source.kind()
            || object.size != source.meta.len && source.kind() != "dir"
        {
            bail!("verification failed: object type or size differs");
        }
        let output = self
            .client
            .get_object()
            .bucket(&self.options.bucket)
            .key(&object.key)
            .if_match(&object.etag)
            .set_version_id(object.version.clone())
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        let mut reader = output.body.into_async_read();
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let n =
                tokio::time::timeout(Duration::from_secs(60), reader.read(&mut buffer)).await??;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        if hasher.finalize().to_hex().as_str() != digest {
            bail!("verification failed: contents differ");
        }
        Ok(())
    }
    async fn download_plan(&self, destination: &Destination) -> Result<Vec<Download>> {
        let count = self.args.locations.len() - 1;
        let base = local::key_path(
            self.args
                .native_source_root
                .as_deref()
                .or(self.args.native_source_cwd.as_deref())
                .unwrap_or(b"."),
        )?;
        let mut selectors = Vec::new();
        if let Some(mapping) = &self.args.native_mapping {
            let mapping = mapping.clone();
            let follow = self.args.native_follow;
            let manifest = tokio::task::spawn_blocking(move || -> Result<_> {
                let mut contents = Vec::new();
                if mapping == b"-" {
                    std::io::stdin().read_to_end(&mut contents)?;
                } else {
                    crate::fsops::open_operator_file_read(
                        &mapping,
                        if follow {
                            crate::proto::OperatorSymlinkPolicy::FollowAll
                        } else {
                            crate::proto::OperatorSymlinkPolicy::Refuse
                        },
                    )?
                    .read_to_end(&mut contents)?;
                }
                crate::mapping::read_mapping_manifest(contents)
            })
            .await??;
            for (_, entry) in manifest.entries {
                selectors.push((
                    local::join(&base, &local::key_path(&entry.src)?),
                    local::join(&destination.prefix, &local::key_path(&entry.dst)?),
                    match entry.kind.map(|k| k.label()) {
                        Some("dir") => SourceSelection::Directory,
                        Some("file" | "symlink") => SourceSelection::File,
                        _ => SourceSelection::Named,
                    },
                    entry.kind.map(|kind| kind.label()),
                ));
            }
        } else {
            for location in &self.args.locations[..count] {
                let key = local::join(&base, &local::key_path(&location.path)?);
                let path = if self.args.placement == Placement::As || location.copies_contents() {
                    destination.prefix.clone()
                } else {
                    local::join(
                        &destination.prefix,
                        &local::key_path(
                            crate::cli::native_basename(&location.path)
                                .context("source has no basename")?,
                        )?,
                    )
                };
                selectors.push((key, path, location.selection, None));
            }
        }
        let matcher = crate::scan::build_ignore(&self.args.ignore_lines)?;
        let min = self
            .args
            .min_size
            .as_deref()
            .map(crate::cli::parse_size)
            .transpose()?
            .unwrap_or(0);
        let max = self
            .args
            .max_size
            .as_deref()
            .map(crate::cli::parse_size)
            .transpose()?
            .unwrap_or(u64::MAX);
        let mut out = Vec::new();
        let mut claims = BTreeMap::new();
        for (key, path, selection, declared_kind) in selectors {
            let exact = if key.is_empty() {
                None
            } else {
                client::head(&self.client, &self.options.bucket, &key).await?
            };
            let contents = selection == SourceSelection::Contents;
            let directory = matches!(
                selection,
                SourceSelection::Contents | SourceSelection::Directory
            );
            if exact.is_some() && directory && self.args.native_mapping.is_none() {
                bail!("S3 selector requires a prefix but an object exists at {key:?}");
            }
            let objects = if self.args.native_mapping.is_some() {
                // Mapping entries name individual objects. A directory entry
                // copies its marker, while explicit child entries copy children.
                let object = match exact {
                    Some(object) => object,
                    None => client::head(&self.client, &self.options.bucket, &format!("{key}/"))
                        .await?
                        .context("S3 mapping source object or directory marker is missing")?,
                };
                if declared_kind.is_some_and(|kind| kind != object.kind()) {
                    bail!("S3 source type does not match mapping");
                }
                vec![(object.key, object.size, path.clone())]
            } else if let Some(exact) = exact {
                vec![(exact.key, exact.size, path.clone())]
            } else {
                if selection == SourceSelection::File {
                    bail!("S3 source object {key:?} is missing");
                }
                let prefix = if key.is_empty() {
                    String::new()
                } else {
                    format!("{key}/")
                };
                let listed = client::list(&self.client, &self.options.bucket, &prefix).await?;
                if listed.is_empty() {
                    bail!("S3 source prefix {key:?} contains no objects");
                }
                let mut objects = Vec::new();
                for (object, size) in listed {
                    let suffix = object
                        .strip_prefix(&prefix)
                        .context("S3 listing returned a key outside the requested prefix")?;
                    if suffix.is_empty() && contents {
                        continue;
                    }
                    let suffix = if object.ends_with('/') && size == 0 {
                        suffix.trim_end_matches('/')
                    } else {
                        suffix
                    };
                    let suffix = local::key_path(suffix.as_bytes())?;
                    objects.push((object, size, local::join(&path, &suffix)));
                }
                objects
            };
            for (key, size, path) in objects {
                let directory = key.ends_with('/') && size == 0;
                if !directory && (size < min || size > max) {
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    continue;
                }
                if matcher
                    .as_ref()
                    .is_some_and(|m| crate::scan::path_is_ignored(m, key.as_bytes(), directory))
                {
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    continue;
                }
                if path.is_empty() && !directory {
                    bail!("cannot replace the destination directory with an object");
                }
                local::claim(&mut claims, &path, directory)?;
                out.push(Download { key, path, size });
            }
        }
        Ok(out)
    }
    async fn download(
        &self,
        job: &Download,
        destination: &Destination,
        directories: DirectoryMetadata,
        kind: &mut &'static str,
    ) -> Result<Option<u64>> {
        let root = &destination.root;
        let path = RelativePath::new(job.path.as_bytes())?;
        let existing = match root.metadata_optional(&path) {
            Ok(m) => m,
            Err(e)
                if e.chain().any(|c| {
                    c.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                }) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        if (self.args.ignore_existing && existing.is_some())
            || (self.args.existing && existing.is_none())
        {
            return Ok(None);
        }
        // A fresh small file can obtain metadata and body in the same GET.
        // Existing files still use HEAD so an unchanged object is not fetched.
        let initial = if existing.is_none()
            && !self.args.dry_run
            && !self.args.verify_only
            && job.size <= self.options.part_size
            && !job.key.ends_with('/')
        {
            Some(
                self.client
                    .get_object()
                    .bucket(&self.options.bucket)
                    .key(&job.key)
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("S3 GET failed")?,
            )
        } else {
            None
        };
        let object = if let Some(output) = &initial {
            client::from_get(&job.key, job.size, output)?
        } else {
            client::head(&self.client, &self.options.bucket, &job.key)
                .await?
                .context("S3 source disappeared after listing")?
        };
        *kind = match object.kind() {
            "dir" => "dir",
            "symlink" => "symlink",
            _ => "file",
        };
        let initial = initial.map(|output| output.body);
        let metadata = object.metadata.clone().unwrap_or(Metadata {
            kind: object.kind().into(),
            mode: if object.kind() == "dir" { 0o777 } else { 0o666 },
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            mtime: object.mtime,
            nsec: 0,
            hash: None,
        });
        if self.args.update && existing.is_some_and(|m| m.is_file() && m.mtime > metadata.mtime) {
            return Ok(None);
        }
        if let Some(m) = existing {
            if m.is_dir() != (object.kind() == "dir") {
                bail!("refusing to replace a directory with a non-directory or the reverse");
            }
        }
        if object.kind() == "dir" {
            if self.args.verify_only {
                if existing.is_none() {
                    bail!("verification failed: directory is missing");
                }
                return Ok(None);
            }
            if !self.args.dry_run {
                if existing.is_none() {
                    root.create_missing_parents(&path, 0o777)?;
                    match root.create_directory(&path, 0o777) {
                        Ok(()) => {
                            self.progress.directories_created.fetch_add(1, Relaxed);
                        }
                        Err(e) if root.metadata(&path).is_ok_and(|m| m.is_dir()) => {
                            let _ = e;
                        }
                        Err(e) => return Err(e),
                    }
                }
                directories.lock().await.push((
                    job.path.clone(),
                    metadata,
                    existing.map(|m| m.mode & 0o7777),
                ));
            }
            return Ok(Some(0));
        }
        if object.kind() == "symlink" {
            if object.size > 1024 * 1024 {
                bail!("S3 symlink target is too large");
            }
            let bytes = self.get_small(&object, initial).await?;
            if let Some(hash) = &metadata.hash {
                if blake3::hash(&bytes).to_hex().as_str() != hash {
                    bail!("symlink checksum mismatch");
                }
            }
            let same = existing.is_some_and(|m| m.is_symlink()) && root.read_link(&path)? == bytes;
            if self.args.verify_only {
                if !same {
                    bail!("verification failed: symlink differs");
                }
                return Ok(None);
            }
            if !self.args.dry_run {
                root.create_missing_parents(&path, 0o777)?;
                if !same {
                    if existing.is_some() {
                        root.replace_symlink(&path, &bytes)?;
                    } else {
                        root.create_symlink(&path, &bytes)?;
                    }
                    self.progress.symlinks_created.fetch_add(1, Relaxed);
                }
                local::apply_metadata(root, &path, &metadata, &self.args, None)?;
            }
            if same {
                return Ok(None);
            }
            self.progress.add_bytes(bytes.len() as u64);
            return Ok(Some(bytes.len() as u64));
        }
        let mut unchanged = false;
        if let Some(m) = existing.filter(|m| m.is_file() && m.len == object.size) {
            if self.args.verify_only || self.args.checksum {
                if self.args.verify_only || metadata.hash.is_none() {
                    unchanged = self.verify_download(root, &path, &object).await?;
                } else {
                    let file = root.open_regular_read(&path)?;
                    let hash =
                        tokio::task::spawn_blocking(move || local::hash_file(file)).await??;
                    unchanged = metadata.hash.as_ref() == Some(&hash);
                }
            } else {
                unchanged = m.mtime == metadata.mtime && m.mtime_nsec == metadata.nsec;
            }
        }
        if self.args.verify_only {
            if !unchanged {
                bail!("verification failed: file missing, type differs, or size differs");
            }
            return Ok(None);
        }
        if unchanged {
            if !self.args.dry_run {
                local::apply_metadata(
                    root,
                    &path,
                    &metadata,
                    &self.args,
                    existing.map(|m| m.mode & 0o7777),
                )?;
            }
            self.progress
                .bytes_unchanged
                .fetch_add(object.size, Relaxed);
            return Ok(None);
        }
        if self.args.dry_run {
            self.progress.add_bytes(object.size);
            return Ok(Some(object.size));
        }
        root.create_missing_parents(&path, 0o777)?;
        if object.size <= self.options.part_size {
            return self
                .download_single(
                    &object,
                    root,
                    &path,
                    &metadata,
                    existing.filter(|m| m.is_file()).map(|m| m.mode & 0o7777),
                    initial,
                )
                .await;
        }
        let extra = format!(
            "download:{}:{}:{}",
            root.identity().dev,
            root.identity().ino,
            job.path
        );
        let state = State::open(&self.identity(&object.key, &extra))?;
        let mut saved: Option<DownloadState> = state.load()?;
        if let Some(old) = &saved {
            if old.schema != 1 {
                bail!("unsupported S3 download recovery schema");
            }
            if old.etag != object.etag
                || old.version != object.version
                || old.size != object.size
                || old.part_size != self.options.part_size
            {
                remove_partial(root, old)?;
                state.clear()?;
                saved = None;
            }
        }
        let (record, file) = if let Some(old) = saved {
            let partial = RelativePath::new(old.partial.as_bytes())?;
            match root.metadata_optional(&partial)? {
                Some(m) if m.dev == old.dev && m.ino == old.ino && m.is_file() && m.nlink == 1 => {
                    (old, root.open_regular_read_write(&partial)?)
                }
                None => {
                    state.clear()?;
                    self.new_download_state(root, &job.path, &object, &state)?
                }
                _ => bail!("partial download changed identity; refusing to overwrite it"),
            }
        } else {
            self.new_download_state(root, &job.path, &object, &state)?
        };
        let record = Arc::new(Mutex::new(record));
        let file = Arc::new(file);
        let part_size = self.options.part_size;
        let parts = object.size.div_ceil(part_size);
        let _interval = self.progress.copying_interval();
        stream::iter(0..parts)
            .map(|index| {
                let file = file.clone();
                let record = record.clone();
                let object = &object;
                let state = &state;
                async move {
                    let offset = index * part_size;
                    let length = part_size.min(object.size - offset);
                    let previous = record.lock().await.parts.get(&index).cloned();
                    if let Some(hash) = previous {
                        let f = file.clone();
                        let actual =
                            tokio::task::spawn_blocking(move || hash_range(&f, offset, length))
                                .await??;
                        if actual == hash {
                            self.progress.bytes_unchanged.fetch_add(length, Relaxed);
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                    let hash = self.download_range(object, file, offset, length).await?;
                    let mut record = record.lock().await;
                    record.parts.insert(index, hash);
                    state.save(&*record)?;
                    Ok(())
                }
            })
            .buffer_unordered(self.options.concurrency)
            .try_collect::<Vec<_>>()
            .await?;
        let partial = record.lock().await.partial.clone();
        let partial_path = RelativePath::new(partial.as_bytes())?;
        if let Some(expected) = &metadata.hash {
            let f = root.open_regular_read(&partial_path)?;
            let actual = tokio::task::spawn_blocking(move || local::hash_file(f)).await??;
            if &actual != expected {
                bail!("download checksum mismatch; partial file preserved");
            }
        }
        // A version ID pins immutable content; otherwise confirm the source
        // still has the identity used on every range request.
        if object.version.is_none() {
            let final_object = client::head(&self.client, &self.options.bucket, &object.key)
                .await?
                .context("source disappeared during download")?;
            if final_object.etag != object.etag || final_object.size != object.size {
                bail!("source object changed during download");
            }
        }
        local::apply_metadata(
            root,
            &partial_path,
            &metadata,
            &self.args,
            existing.filter(|m| m.is_file()).map(|m| m.mode & 0o7777),
        )?;
        let m = file.metadata()?;
        if self.args.ignore_existing || self.args.target_existence == Existence::New {
            root.publish_new_regular(&partial_path, &path, (m.dev(), m.ino()))?;
        } else {
            root.rename_regular_if_same(&partial_path, &path, (m.dev(), m.ino()))?;
        }
        state.clear()?;
        Ok(Some(object.size))
    }
    async fn download_single(
        &self,
        object: &Object,
        root: &Root,
        path: &RelativePath,
        metadata: &Metadata,
        mode: Option<u32>,
        initial: Option<ByteStream>,
    ) -> Result<Option<u64>> {
        let path_buf = path.to_path_buf();
        let label = path_buf
            .to_str()
            .context("S3 download placement requires UTF-8")?;
        let parent = label.rsplit_once('/').map_or("", |(p, _)| p);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let partial = RelativePath::new(
            local::join(
                parent,
                &format!(".syq-s3-{}.partial", blake3::hash(&random).to_hex()),
            )
            .as_bytes(),
        )?;
        let file = Arc::new(root.create_file(&partial, 0o600)?);
        let _cleanup = PartialCleanup {
            root,
            path: partial.clone(),
            identity: (file.metadata()?.dev(), file.metadata()?.ino()),
        };
        let result = async {
            let hash = if let Some(body) = initial {
                match self.read_body(body, file.clone(), 0, object.size).await {
                    Ok(hash) => {
                        self.progress.add_bytes(object.size);
                        hash
                    }
                    Err(_) if self.options.retries > 0 && object.size > 0 => {
                        self.download_range(object, file.clone(), 0, object.size)
                            .await?
                    }
                    Err(error) => return Err(error),
                }
            } else if object.size == 0 {
                blake3::hash(&[]).to_hex().to_string()
            } else {
                self.download_range(object, file.clone(), 0, object.size)
                    .await?
            };
            if metadata
                .hash
                .as_ref()
                .is_some_and(|expected| expected != &hash)
            {
                bail!("download checksum mismatch");
            }
            local::apply_metadata(root, &partial, metadata, &self.args, mode)?;
            let m = file.metadata()?;
            if self.args.ignore_existing || self.args.target_existence == Existence::New {
                root.publish_new_regular(&partial, path, (m.dev(), m.ino()))?;
            } else {
                root.rename_regular_if_same(&partial, path, (m.dev(), m.ino()))?;
            }
            Ok(Some(object.size))
        }
        .await;
        result
    }
    fn new_download_state(
        &self,
        root: &Root,
        path: &str,
        object: &Object,
        state: &State,
    ) -> Result<(DownloadState, File)> {
        let parent = path.rsplit_once('/').map_or("", |(p, _)| p);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let partial = local::join(
            parent,
            &format!(".syq-s3-{}.partial", blake3::hash(&random).to_hex()),
        );
        let file = root.create_file(&RelativePath::new(partial.as_bytes())?, 0o600)?;
        file.set_len(object.size)?;
        let m = file.metadata()?;
        let record = DownloadState {
            schema: 1,
            etag: object.etag.clone(),
            version: object.version.clone(),
            size: object.size,
            part_size: self.options.part_size,
            partial,
            dev: m.dev(),
            ino: m.ino(),
            parts: BTreeMap::new(),
        };
        state.save(&record)?;
        Ok((record, file))
    }
    async fn get_small(&self, object: &Object, initial: Option<ByteStream>) -> Result<Vec<u8>> {
        let body = match initial {
            Some(body) => body,
            None => {
                self.client
                    .get_object()
                    .bucket(&self.options.bucket)
                    .key(&object.key)
                    .if_match(&object.etag)
                    .set_version_id(object.version.clone())
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())?
                    .body
            }
        };
        let mut bytes = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(60),
            body.into_async_read()
                .take(object.size + 1)
                .read_to_end(&mut bytes),
        )
        .await??;
        if bytes.len() as u64 != object.size {
            bail!("S3 response length differs");
        }
        Ok(bytes)
    }
    async fn verify_download(
        &self,
        root: &Root,
        path: &RelativePath,
        object: &Object,
    ) -> Result<bool> {
        let file = root.open_regular_read(path)?;
        let expected = tokio::task::spawn_blocking(move || local::hash_file(file)).await??;
        Ok(self.remote_hash(object).await? == expected)
    }
    async fn remote_hash(&self, object: &Object) -> Result<String> {
        let output = self
            .client
            .get_object()
            .bucket(&self.options.bucket)
            .key(&object.key)
            .if_match(&object.etag)
            .set_version_id(object.version.clone())
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        let mut body = output.body.into_async_read();
        let mut buffer = vec![0; 1024 * 1024];
        let mut hash = blake3::Hasher::new();
        let mut n = 0;
        loop {
            let got =
                tokio::time::timeout(Duration::from_secs(60), body.read(&mut buffer)).await??;
            if got == 0 {
                break;
            }
            hash.update(&buffer[..got]);
            n += got as u64;
        }
        if n != object.size {
            bail!("S3 response was truncated or exceeded its advertised size");
        }
        Ok(hash.finalize().to_hex().to_string())
    }
    async fn download_range(
        &self,
        object: &Object,
        file: Arc<File>,
        offset: u64,
        length: u64,
    ) -> Result<String> {
        let mut attempt = 0;
        loop {
            let result = self.read_range(object, file.clone(), offset, length).await;
            match result {
                Ok(hash) => {
                    self.progress.add_bytes(length);
                    return Ok(hash);
                }
                Err(e)
                    if attempt < self.options.retries
                        && e.downcast_ref::<Permanent>().is_none() =>
                {
                    super::backoff(attempt).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
    async fn read_range(
        &self,
        object: &Object,
        file: Arc<File>,
        offset: u64,
        length: u64,
    ) -> Result<String> {
        let end = offset + length - 1;
        let output = match self
            .client
            .get_object()
            .bucket(&self.options.bucket)
            .key(&object.key)
            .range(format!("bytes={offset}-{end}"))
            .if_match(&object.etag)
            .set_version_id(object.version.clone())
            .send()
            .await
        {
            Ok(output) => output,
            Err(e) => {
                if !retryable_status(e.raw_response().map(|r| r.status().as_u16())) {
                    return Err(Permanent(format!(
                        "S3 range GET failed: {}",
                        e.into_service_error()
                    ))
                    .into());
                }
                return Err(e.into_service_error()).context("S3 range GET failed");
            }
        };
        if output.content_length() != Some(length as i64)
            || output.content_range()
                != Some(format!("bytes {offset}-{end}/{}", object.size).as_str())
            || output.e_tag() != Some(object.etag.as_str())
        {
            return Err(Permanent(
                "S3 range response has a different length, range, or ETag".into(),
            )
            .into());
        }
        self.read_body(output.body, file, offset, length).await
    }
    async fn read_body(
        &self,
        body: ByteStream,
        file: Arc<File>,
        offset: u64,
        length: u64,
    ) -> Result<String> {
        let mut body = body.into_async_read();
        let mut buffer = vec![0; 1024 * 1024];
        let mut written = 0;
        let mut hash = blake3::Hasher::new();
        while written < length {
            let want = buffer.len().min((length - written) as usize);
            tokio::time::timeout(
                Duration::from_secs(60),
                body.read_exact(&mut buffer[..want]),
            )
            .await??;
            let n = want;
            self.pace(n as u64).await;
            let file = file.clone();
            let at = offset + written;
            (buffer, hash) = tokio::task::spawn_blocking(move || -> Result<_> {
                hash.update(&buffer[..n]);
                file.write_all_at(&buffer[..n], at)?;
                Ok((buffer, hash))
            })
            .await??;
            written += n as u64;
        }
        let mut extra = [0];
        if tokio::time::timeout(Duration::from_secs(60), body.read(&mut extra)).await?? != 0 {
            return Err(
                Permanent("S3 range response exceeded its advertised length".into()).into(),
            );
        }
        Ok(hash.finalize().to_hex().to_string())
    }
}
#[derive(Debug)]
struct Permanent(String);
impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Permanent {}
fn retryable_status(status: Option<u16>) -> bool {
    status.is_none_or(|s| matches!(s, 408 | 429 | 500 | 502 | 503 | 504))
}
fn sha256(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(bytes))
}
async fn file_body(source: &Source, offset: u64, length: u64) -> Result<ByteStream> {
    let source = source.clone();
    let file = tokio::task::spawn_blocking(move || source.open()).await??;
    Ok(ByteStream::read_from()
        .file(tokio::fs::File::from_std(file))
        .offset(offset)
        .length(Length::Exact(length))
        .buffer_size(1024 * 1024)
        .build()
        .await?)
}
fn hash_range(file: &File, offset: u64, length: u64) -> Result<String> {
    let mut buffer = vec![0; 1024 * 1024];
    let mut done = 0;
    let mut hash = blake3::Hasher::new();
    while done < length {
        let n = buffer.len().min((length - done) as usize);
        file.read_exact_at(&mut buffer[..n], offset + done)?;
        hash.update(&buffer[..n]);
        done += n as u64;
    }
    Ok(hash.finalize().to_hex().to_string())
}
fn remove_partial(root: &Root, record: &DownloadState) -> Result<()> {
    let path = RelativePath::new(record.partial.as_bytes())?;
    if let Some(m) = root.metadata_optional(&path)? {
        if m.dev != record.dev || m.ino != record.ino || !m.is_file() || m.nlink != 1 {
            bail!("obsolete partial changed identity; refusing to remove it");
        }
        root.unlink(&path)?;
    }
    Ok(())
}

// Each object gets a runtime task so hashing and filesystem work can use more
// than one executor thread. JoinSet bounds live tasks and aborts them together
// when the copy is cancelled; detached uploads must never outlive the command.
async fn parallel<T, F, Fut>(jobs: Vec<T>, workers: usize, mut work: F) -> Result<()>
where
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let mut tasks = tokio::task::JoinSet::new();
    let mut jobs = jobs.into_iter();
    for job in jobs.by_ref().take(workers) {
        tasks.spawn(work(job));
    }
    while let Some(result) = tasks.join_next().await {
        result??;
        if let Some(job) = jobs.next() {
            tasks.spawn(work(job));
        }
    }
    Ok(())
}

// Single-request downloads have no reusable completed ranges. Remove their
// temporary file on failure or cancellation, including a dropped future.
struct PartialCleanup<'a> {
    root: &'a Root,
    path: RelativePath,
    identity: (u64, u64),
}
impl Drop for PartialCleanup<'_> {
    fn drop(&mut self) {
        if self
            .root
            .metadata_optional(&self.path)
            .ok()
            .flatten()
            .is_some_and(|m| (m.dev, m.ino) == self.identity)
        {
            let _ = self.root.unlink(&self.path);
        }
    }
}
