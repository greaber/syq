mod fast;
mod pruning;
mod server_copy;

use super::{
    admission::parallel,
    checksum::Algorithm,
    client::{self, Metadata, Object},
    local::{self, Destination, Source},
    state::State,
    Options,
};
use crate::{
    cli::{Args, Existence, Placement, SourceSelection},
    hashing::{Digest, HashAlgorithm},
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
use futures_util::{stream, StreamExt};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
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
    upload_keys: OnceLock<HashMap<String, u64>>,
    copy_checksum_unsupported: [std::sync::atomic::AtomicBool; 2],
    tuning: super::tuning::Tuning,
    cancelled: std::sync::atomic::AtomicBool,
    cancel_wake: tokio::sync::Notify,
}
#[derive(Clone)]
struct Download {
    key: String,
    path: String,
    size: u64,
    expected_digest: Option<Digest>,
    copy_source: Option<Box<(Object, aws_sdk_s3::operation::head_object::HeadObjectOutput)>>,
}
#[derive(Clone, Serialize, Deserialize)]
struct UploadState {
    schema: u32,
    digest: String,
    part_size: u64,
    upload_id: String,
    metadata: Metadata,
    #[serde(default, skip_serializing_if = "Algorithm::is_sha256")]
    algorithm: Algorithm,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    completed: BTreeMap<i32, UploadedPart>,
}
#[derive(Clone, Serialize, Deserialize)]
struct UploadedPart {
    etag: String,
    checksum: String,
    length: u64,
}
impl UploadState {
    fn acknowledged_part(&self, number: i32, etag: &str, checksum: &str, length: u64) -> bool {
        self.completed
            .get(&number)
            .is_some_and(|p| p.etag == etag && p.checksum == checksum && p.length == length)
    }
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
    #[serde(default)]
    hash_algorithm: HashAlgorithm,
}

impl Engine {
    pub async fn new(args: Arc<Args>, progress: Arc<Progress>) -> Result<Arc<Self>> {
        let setup = super::diagnostics::start();
        let mut options = args.s3.clone().unwrap();
        options.endpoint = options
            .endpoint
            .or_else(|| std::env::var("AWS_ENDPOINT_URL_S3").ok())
            .or_else(|| std::env::var("AWS_ENDPOINT_URL").ok());
        let control = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let (client, note) = client::connect(&mut options, control.clone()).await?;
        if let Some(note) = note.filter(|_| args.verbose > 0) {
            progress.println(&note);
        }
        super::diagnostics::elapsed(setup, "client_setup", 0);
        Ok(Arc::new(Self {
            tuning: super::tuning::Tuning::new(&options, &args, control),
            cancelled: std::sync::atomic::AtomicBool::new(false),
            cancel_wake: tokio::sync::Notify::new(),
            args,
            options,
            client,
            progress,
            pace: Mutex::new(tokio::time::Instant::now()),
            upload_keys: OnceLock::new(),
            copy_checksum_unsupported: Default::default(),
        }))
    }
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let work = self.clone().copy();
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::pin!(work);
        let interrupted = tokio::select! {
            result = &mut work => return result,
            _ = tokio::signal::ctrl_c() => "interrupted",
            _ = terminate.recv() => "terminated",
        };
        self.cancelled.store(true, Relaxed);
        self.cancel_wake.notify_waiters();
        // Drain started requests, including synchronous file bodies, before exit.
        let _ = work.await;
        bail!("S3 copy {interrupted}; rerun the command to continue")
    }
    fn check_cancelled(&self) -> Result<()> {
        anyhow::ensure!(!self.cancelled.load(Relaxed), "S3 copy cancelled");
        Ok(())
    }

    async fn copy(self: Arc<Self>) -> Result<()> {
        if self.options.source_bucket.is_some() {
            return self.server_copy().await;
        }
        if self.options.upload {
            let scanning = super::diagnostics::start();
            let args = self.args.clone();
            let (plan, prune) =
                tokio::task::spawn_blocking(move || local::upload_plan(&args)).await??;
            super::diagnostics::elapsed(scanning, "source_plan", plan.len() as u64);
            if self.args.expected_digest.is_some() && (plan.len() != 1 || plan[0].kind() != "file")
            {
                bail!("an expected digest requires exactly one regular file");
            }
            self.check_upload_placement(plan.first().map(|s| s.kind() != "dir"))
                .await?;
            self.discover_destination(plan.iter().map(|s| s.key.as_str()).collect())
                .await?;
            let workers = self.object_workers(plan.iter().map(|s| s.meta.len))?;
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
                    engine.check_cancelled()?;
                    let expected = source
                        .expected_digest
                        .as_ref()
                        .or(engine.args.expected_digest.as_ref())
                        .cloned();
                    let result = engine.upload(source).await;
                    engine.settle(&label, &key, kind, &result, expected.as_ref());
                    Ok(result.ok().flatten())
                }
            })
            .await?;
            self.prune(prune, None).await?;
        } else {
            let destination = Arc::new(Destination::open(&self.args)?);
            let (plan, prune) = self.download_plan(&destination.prefix).await?;
            let workers = self.object_workers(plan.iter().map(|s| s.size))?;
            if self.args.expected_digest.is_some() && plan.len() != 1 {
                bail!("an expected digest requires exactly one regular file");
            }
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
                    engine.check_cancelled()?;
                    let mut kind = "file";
                    let result = engine.download(&job, &dst, dirs, &mut kind).await;
                    engine.settle(
                        job.key.as_bytes(),
                        &job.path,
                        kind,
                        &result,
                        job.expected_digest
                            .as_ref()
                            .or(engine.args.expected_digest.as_ref()),
                    );
                    Ok(result.ok().flatten())
                }
            })
            .await?;
            // Prune while directories are writable, then restore their modes and times.
            // Apply metadata even when the deletion budget refuses pruning.
            let pruned = self.prune(prune, Some(&destination)).await;
            self.finish_directories(&destination, &directories).await?;
            pruned?;
        }
        Ok(())
    }
    async fn finish_directories(
        &self,
        destination: &Destination,
        directories: &DirectoryMetadata,
    ) -> Result<()> {
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
        Ok(())
    }
    fn settle(
        &self,
        src: &[u8],
        dst: &str,
        kind: &'static str,
        result: &Result<Option<u64>>,
        expected: Option<&Digest>,
    ) {
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
                        writer.emit_operation_expected(
                            &crate::results::OperationRecord {
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
                            },
                            expected,
                        );
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
                    writer.emit_operation_expected(
                        &crate::results::OperationRecord {
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
                        },
                        expected,
                    );
                }
            }
        }
    }
    async fn pace(&self, n: u64) -> Result<()> {
        self.check_cancelled()?;
        if self.args.bwlimit_bytes == 0 {
            return Ok(());
        }
        let mut next = self.pace.lock().await;
        let now = tokio::time::Instant::now();
        let start = (*next).max(now);
        *next = start + Duration::from_secs_f64(n as f64 / self.args.bwlimit_bytes as f64);
        drop(next);
        let cancelled = self.cancel_wake.notified();
        tokio::pin!(cancelled);
        // Register before checking the flag so a concurrent signal cannot be lost.
        cancelled.as_mut().enable();
        self.check_cancelled()?;
        tokio::select! {
            _ = &mut cancelled => {},
            _ = tokio::time::sleep_until(start) => {},
        }
        self.check_cancelled()
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
    async fn discover_destination(&self, keys: HashSet<&str>) -> Result<()> {
        if keys.len() > 1 && !self.args.existing && !self.args.ignore_existing {
            let target = local::key_path(&self.args.locations.last().unwrap().path)?;
            let prefix = if target.is_empty() {
                String::new()
            } else {
                format!("{target}/")
            };
            // A prefix listing can establish absence only for keys inside it.
            // Mappings may name destinations outside the placement prefix.
            if keys.iter().any(|key| !key.starts_with(&prefix)) {
                return Ok(());
            }
            let listing = if self.args.delete {
                // Pruning needs every destination key, including keys absent
                // from the upload plan. Only this complete cache is reusable
                // by the deletion planner.
                client::list(
                    &self.client,
                    &self.options.bucket,
                    &prefix,
                    None,
                    &mut HashSet::new(),
                )
                .await
                .map(|listing| Some(listing.objects.into_iter().collect()))
            } else {
                client::upload_listing(&self.client, &self.options.bucket, &prefix, &keys).await
            };
            match listing {
                Ok(Some(keys)) => {
                    let _ = self.upload_keys.set(keys);
                }
                Ok(None) => {}
                Err(error)
                    if error
                        .downcast_ref::<client::RequestFailure>()
                        .is_some_and(|failure| failure.region_mismatch()) =>
                {
                    return Err(error);
                }
                Err(error) if self.args.delete => {
                    self.progress
                        .error(&format!("list S3 destination: {error:#}"));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
    }
    async fn check_upload_placement(&self, single_object: Option<bool>) -> Result<()> {
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
        let needs_prefix = self.args.target_existence == Existence::Existing
            && (self.args.placement != Placement::As || single_object == Some(false));
        let present = (!needs_prefix && exact)
            || client::prefix_exists(&self.client, &self.options.bucket, &prefix).await?;
        if (self.args.target_existence == Existence::New && present)
            || (self.args.target_existence == Existence::Existing && !present)
        {
            bail!("S3 destination existence condition failed");
        }
        if self.args.placement == Placement::As && single_object == Some(true) && present && !exact
        {
            bail!("S3 destination is a prefix, not an object");
        }
        Ok(())
    }
    fn upload_metadata_matches(&self, source: &Source, size: u64, object: &Object) -> bool {
        object.kind() == source.kind()
            && object.size == size
            && object.metadata.as_ref().is_some_and(|m| {
                m.mtime == source.meta.mtime
                    && m.nsec == source.meta.mtime_nsec
                    && (!self.args.perms || m.mode == source.meta.mode & 0o7777)
                    && (!(self.args.owner || self.args.group)
                        || (m.uid == source.meta.uid && m.gid == source.meta.gid))
            })
    }

    async fn upload(self: &Arc<Self>, source: Source) -> Result<Option<u64>> {
        let expected_digest = source
            .expected_digest
            .as_ref()
            .or(self.args.expected_digest.as_ref())
            .filter(|_| !self.args.dry_run);
        let existing = if self
            .upload_keys
            .get()
            .is_some_and(|keys| !keys.contains_key(&source.key))
        {
            None
        } else {
            let object = client::head(&self.client, &self.options.bucket, &source.key).await?;
            object
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
        let whole_algorithm = expected_digest.map(|d| d.algorithm).or_else(|| {
            if self.args.transfer_integrity {
                Some(self.args.transfer_hash_type.unwrap_or_default())
            } else if self.args.checksum || self.args.verify_only {
                Some(self.args.hash_algorithm)
            } else {
                None
            }
        });
        if whole_algorithm.is_none()
            && existing
                .as_ref()
                .is_some_and(|o| self.upload_metadata_matches(&source, size, o))
        {
            if source.kind() == "file" {
                // Opening validates the pinned scan identity without reading the
                // body. Explicit content checks still take the hashing path.
                source.open()?;
            } else {
                source.bytes()?;
            }
            self.progress.bytes_unchanged.fetch_add(size, Relaxed);
            return Ok(None);
        }
        let part_size = self.part_size(size);
        if part_size > 5 * 1024 * 1024 * 1024 {
            bail!("file exceeds the S3 multipart size limit");
        }
        let buffer_limit = if self.tuning.tigris() {
            8 << 20
        } else {
            1 << 20
        };
        let reservation = if source.kind() == "file" && size <= part_size && size <= buffer_limit {
            Some(
                self.tuning
                    .upload_buffers
                    .clone()
                    .acquire_many_owned(size.max(1) as u32)
                    .await?,
            )
        } else {
            None
        };
        self.check_cancelled()?;
        let source_clone = source.clone();
        let algorithm = Algorithm::for_endpoint(self.options.endpoint.as_deref());
        let (whole_digest, checksums, small) = tokio::task::spawn_blocking(move || -> Result<_> {
            if source_clone.kind() != "file" {
                let bytes = source_clone.bytes()?;
                return Ok((
                    whole_algorithm.map(|a| Digest::hash_bytes(a, &bytes).value),
                    vec![algorithm.digest(&bytes)],
                    Some(bytes::Bytes::from(bytes)),
                ));
            }
            if let Some(reservation) = reservation {
                let mut file = source_clone.open()?;
                let mut bytes = vec![0; size as usize];
                file.read_exact(&mut bytes)?;
                source_clone.check(&file)?;
                let native_algorithm = if algorithm.is_sha256() {
                    HashAlgorithm::Sha256
                } else {
                    HashAlgorithm::Md5
                };
                let hash = native_algorithm.hash(&bytes);
                let checksum = encode_native_parts(native_algorithm, &[hash]).remove(0);
                let whole = whole_algorithm.map(|a| {
                    if a == native_algorithm {
                        Digest::from_hash(a, &hash).value
                    } else {
                        Digest::hash_bytes(a, &bytes).value
                    }
                });
                return Ok((
                    whole,
                    vec![checksum],
                    Some(bytes::Bytes::from_owner(fast::UploadBuffer {
                        bytes,
                        _reservation: reservation,
                    })),
                ));
            }
            // Independent native part checksums provide both upload validation
            // and resume identity. A whole-file hash is optional unless requested.
            let native_algorithm = match algorithm {
                Algorithm::Sha256 => HashAlgorithm::Sha256,
                Algorithm::Md5 => HashAlgorithm::Md5,
            };
            let reuse_native = size <= part_size && whole_algorithm == Some(native_algorithm);
            if size <= part_size || size < 32 * 1024 * 1024 {
                // For small files, feed every required digest from one read.
                // Large multipart files retain independent parallel hash work.
                let mut file = source_clone.open()?;
                let mut whole = whole_algorithm
                    .filter(|_| !reuse_native)
                    .map(HashAlgorithm::hasher);
                let mut buffer = vec![0; 1024 * 1024];
                let mut parts = Vec::new();
                let mut remaining = size;
                for _ in 0..size.div_ceil(part_size).max(1) {
                    let mut part = native_algorithm.hasher();
                    let mut left = remaining.min(part_size);
                    while left > 0 {
                        let n = buffer.len().min(left as usize);
                        file.read_exact(&mut buffer[..n])?;
                        part.update(&buffer[..n]);
                        if let Some(whole) = &mut whole {
                            whole.update(&buffer[..n]);
                        }
                        left -= n as u64;
                    }
                    parts.push(part.finalize());
                    remaining = remaining.saturating_sub(part_size);
                }
                source_clone.check(&file)?;
                let whole = if reuse_native {
                    Some(Digest::from_hash(native_algorithm, &parts[0]).value)
                } else {
                    whole.map(|h| Digest::from_hash(whole_algorithm.unwrap(), &h.finalize()).value)
                };
                return Ok((whole, encode_native_parts(native_algorithm, &parts), None));
            }
            let (whole, parts) = rayon::join(
                || -> Result<Option<String>> {
                    whole_algorithm
                        .filter(|_| !reuse_native)
                        .map(|a| local::hash_file_as(source_clone.open()?, a))
                        .transpose()
                },
                || {
                    (0..size.div_ceil(part_size).max(1))
                        .into_par_iter()
                        .map(|index| {
                            let file = source_clone.open()?;
                            let offset = index * part_size;
                            let length = part_size.min(size.saturating_sub(offset));
                            let mut buffer = vec![0; 1024 * 1024];
                            let mut hash = native_algorithm.hasher();
                            let mut done = 0;
                            while done < length {
                                let n = buffer.len().min((length - done) as usize);
                                file.read_exact_at(&mut buffer[..n], offset + done)?;
                                hash.update(&buffer[..n]);
                                done += n as u64;
                            }
                            source_clone.check(&file)?;
                            Ok(hash.finalize())
                        })
                        .collect::<Result<Vec<_>>>()
                },
            );
            let parts = parts?;
            let whole = if reuse_native {
                Some(Digest::from_hash(native_algorithm, &parts[0]).value)
            } else {
                whole?
            };
            let checksums = encode_native_parts(native_algorithm, &parts);
            source_clone.check(&source_clone.open()?)?;
            Ok((whole, checksums, None))
        })
        .await??;
        if let Some(expected) = expected_digest {
            if !whole_digest
                .as_ref()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected.value))
            {
                bail!("source does not match expected digest");
            }
        }
        let mut metadata = source.metadata(whole_digest.clone());
        metadata.hash_algorithm = whole_algorithm.unwrap_or(HashAlgorithm::Blake3);
        let digest = upload_identity(algorithm, size, part_size, &checksums);
        let mut unchanged = existing.as_ref().is_some_and(|o| {
            self.upload_metadata_matches(&source, size, o)
                && o.metadata.as_ref().is_some_and(|m| {
                    self.args.checksum
                        || whole_digest.is_none()
                        || (m.hash == whole_digest && m.hash_algorithm == metadata.hash_algorithm)
                })
        });
        let comparison_digest = if self.args.checksum || self.args.verify_only {
            if whole_algorithm == Some(self.args.hash_algorithm) {
                whole_digest.clone()
            } else {
                let source = source.clone();
                let algorithm = self.args.hash_algorithm;
                Some(
                    tokio::task::spawn_blocking(move || {
                        local::hash_file_as(source.open()?, algorithm)
                    })
                    .await??,
                )
            }
        } else {
            None
        };
        if self.args.checksum {
            if let Some(object) = &existing {
                unchanged = unchanged
                    && self
                        .remote_hash_as(object, self.args.hash_algorithm)
                        .await?
                        == *comparison_digest.as_ref().unwrap();
            }
        }
        if self.args.verify_only {
            let object = existing.context("verification failed: destination object is missing")?;
            self.verify_upload(
                &source,
                &object,
                comparison_digest.as_deref().unwrap(),
                self.args.hash_algorithm,
            )
            .await?;
            return Ok(None);
        }
        if unchanged && expected_digest.is_some() {
            unchanged = self
                .verify_expected_remote(existing.as_ref().unwrap(), expected_digest)
                .await
                .is_ok();
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
            let _slot = self.tuning.requests.acquire().await;
            let synchronous =
                source.kind() == "file" && small.is_none() && self.tuning.local_latency();
            let sync_file =
                synchronous.then(|| crate::s3::upload_http::FileBody::new(source.clone(), 0, size));
            let mut attempt = 0;
            loop {
                let body = if let Some(bytes) = &small {
                    ByteStream::from(bytes.clone())
                } else if synchronous {
                    crate::s3::upload_http::body(size)
                } else {
                    file_body(&source, 0, size).await?
                };
                self.pace(size).await?;
                let request = self
                    .client
                    .put_object()
                    .bucket(&self.options.bucket)
                    .key(&source.key)
                    .body(body)
                    .content_length(size as i64)
                    .set_checksum_sha256(algorithm.is_sha256().then(|| checksums[0].clone()))
                    .set_content_md5((algorithm == Algorithm::Md5).then(|| checksums[0].clone()))
                    .set_metadata(Some(metadata.encode()))
                    .set_if_none_match(must_be_new.then(|| "*".into()))
                    .customize()
                    .config_override(super::client::without_sdk_retries())
                    .disable_payload_signing();
                let request = if let Some(file) = &sync_file {
                    request.interceptor(file.clone())
                } else {
                    request
                };
                let result = request.send().await;
                if let Some(file) = &sync_file {
                    file.drain().await;
                }
                match result {
                    Ok(_) => break,
                    Err(e) if retryable(&e) && attempt < self.options.retries => {
                        super::backoff(attempt).await;
                        attempt += 1;
                    }
                    Err(e) => return Err(e.into_service_error()).context("S3 PUT failed"),
                }
            }
            self.tuning.requests.completed(size);
            self.progress.add_bytes(size);
        } else {
            let state = State::open(&self.identity(&source.key, "upload"))?;
            let mut previous: Option<UploadState> = state.load()?;
            if let Some(old) = &previous {
                if old.schema != old.algorithm.schema() {
                    bail!("unsupported S3 upload recovery schema");
                }
                if old.digest != digest
                    || old.part_size != part_size
                    || old.metadata != metadata
                    || old.algorithm != algorithm
                {
                    match self
                        .client
                        .abort_multipart_upload()
                        .bucket(&self.options.bucket)
                        .key(&source.key)
                        .upload_id(&old.upload_id)
                        .send()
                        .await
                    {
                        Ok(_) => {}
                        Err(error)
                            if error
                                .raw_response()
                                .is_some_and(|r| r.status().as_u16() == 404) => {}
                        Err(error) => {
                            return Err(error.into_service_error())
                                .context("abort obsolete multipart upload")
                        }
                    }
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
                                if let (Some(number), Some(etag)) = (p.part_number(), p.e_tag()) {
                                    uploaded.insert(
                                        number,
                                        (
                                            etag.to_owned(),
                                            p.checksum_sha256().map(str::to_owned),
                                            p.size().and_then(|n| u64::try_from(n).ok()),
                                        ),
                                    );
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
                    .set_checksum_algorithm(
                        algorithm
                            .is_sha256()
                            .then_some(aws_sdk_s3::types::ChecksumAlgorithm::Sha256),
                    )
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("create multipart upload")?;
                let record = UploadState {
                    schema: algorithm.schema(),
                    digest,
                    part_size,
                    metadata: metadata.clone(),
                    upload_id: output.upload_id().context("S3 omitted upload ID")?.into(),
                    algorithm,
                    completed: BTreeMap::new(),
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
            let saved_parts = Mutex::new(upload.completed.clone());
            // Stop admitting parts on failure, but drain requests already in flight.
            let failed = std::sync::atomic::AtomicBool::new(false);
            let completed = stream::iter(checksums.into_iter().enumerate())
                .take_while(|_| std::future::ready(!failed.load(Relaxed)))
                .map(|(index, checksum)| {
                    let source = &source;
                    let upload = &upload;
                    let uploaded = &uploaded;
                    let saved_parts = &saved_parts;
                    let state = &state;
                    async move {
                        let number = index as i32 + 1;
                        let offset = index as u64 * part_size;
                        let length = part_size.min(size - offset);
                        if let Some((etag, old_checksum, old_length)) = uploaded.get(&number) {
                            let matches = match algorithm {
                                Algorithm::Sha256 => old_checksum.as_ref() == Some(&checksum),
                                // An ETag is opaque. Reuse only an acknowledged
                                // part from this exact source/recovery record.
                                Algorithm::Md5 => {
                                    upload.acknowledged_part(number, etag, &checksum, length)
                                }
                            };
                            if matches && *old_length == Some(length) {
                                self.progress.bytes_unchanged.fetch_add(length, Relaxed);
                                return Ok(CompletedPart::builder()
                                    .part_number(number)
                                    .e_tag(etag)
                                    .set_checksum_sha256(
                                        algorithm.is_sha256().then(|| checksum.clone()),
                                    )
                                    .build());
                            }
                        }
                        let _slot = self.tuning.requests.acquire().await;
                        let sync_file = self.tuning.local_latency().then(|| {
                            crate::s3::upload_http::FileBody::new(source.clone(), offset, length)
                        });
                        let mut attempt = 0;
                        loop {
                            self.check_cancelled()?;
                            let body = if sync_file.is_some() {
                                crate::s3::upload_http::body(length)
                            } else {
                                file_body(source, offset, length).await?
                            };
                            self.pace(length).await?;
                            let request = self
                                .client
                                .upload_part()
                                .bucket(&self.options.bucket)
                                .key(&source.key)
                                .upload_id(&upload.upload_id)
                                .part_number(number)
                                .body(body)
                                .content_length(length as i64)
                                .set_checksum_sha256(
                                    algorithm.is_sha256().then(|| checksum.clone()),
                                )
                                .set_content_md5(
                                    (algorithm == Algorithm::Md5).then(|| checksum.clone()),
                                )
                                .customize()
                                .config_override(super::client::without_sdk_retries())
                                .disable_payload_signing();
                            let request = if let Some(file) = &sync_file {
                                request.interceptor(file.clone())
                            } else {
                                request
                            };
                            let result = request.send().await;
                            if let Some(file) = &sync_file {
                                file.drain().await;
                            }
                            match result {
                                Ok(output) => {
                                    let etag = output.e_tag().context("S3 part omitted ETag")?;
                                    if algorithm == Algorithm::Md5 {
                                        let mut parts = saved_parts.lock().await;
                                        parts.insert(
                                            number,
                                            UploadedPart {
                                                etag: etag.into(),
                                                checksum: checksum.clone(),
                                                length,
                                            },
                                        );
                                        let mut record = upload.clone();
                                        record.completed = parts.clone();
                                        state.save(&record)?;
                                    }
                                    self.tuning.requests.completed(length);
                                    self.progress.add_bytes(length);
                                    return Ok(CompletedPart::builder()
                                        .part_number(number)
                                        .e_tag(etag)
                                        .set_checksum_sha256(
                                            algorithm.is_sha256().then(|| checksum.clone()),
                                        )
                                        .build());
                                }
                                Err(e) if retryable(&e) && attempt < self.options.retries => {
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
                .buffer_unordered(self.part_workers())
                .inspect(|result| {
                    if result.is_err() {
                        failed.store(true, Relaxed);
                    }
                })
                .collect::<Vec<Result<_>>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            self.check_cancelled()?;
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
    async fn verify_upload(
        &self,
        source: &Source,
        object: &Object,
        digest: &str,
        algorithm: HashAlgorithm,
    ) -> Result<()> {
        let _slot = self.tuning.requests.acquire().await;
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
        let mut hasher = algorithm.hasher();
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let n =
                tokio::time::timeout(Duration::from_secs(60), reader.read(&mut buffer)).await??;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        if Digest::from_hash(algorithm, &hasher.finalize()).value != digest {
            bail!("verification failed: contents differ");
        }
        Ok(())
    }
    async fn download_plan(
        &self,
        destination_prefix: &str,
    ) -> Result<(Vec<Download>, super::prune::Plan)> {
        let mut prune = super::prune::Plan::default();
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
                    local::join(destination_prefix, &local::key_path(&entry.dst)?),
                    match entry.kind.map(|k| k.label()) {
                        Some("dir") => SourceSelection::Directory,
                        Some("file" | "symlink") => SourceSelection::File,
                        _ => SourceSelection::Named,
                    },
                    entry.kind.map(|kind| kind.label()),
                    entry.expected_digest,
                ));
            }
        } else {
            for location in &self.args.locations[..count] {
                let key = local::join(&base, &local::key_path(&location.path)?);
                let path = if self.args.placement == Placement::As || location.copies_contents() {
                    destination_prefix.to_owned()
                } else {
                    local::join(
                        destination_prefix,
                        &local::key_path(
                            crate::cli::native_basename(&location.path)
                                .context("source has no basename")?,
                        )?,
                    )
                };
                selectors.push((key, path, location.selection, None, None));
            }
        }
        if self.options.source_bucket.is_some() && selectors.iter().any(|s| s.4.is_some()) {
            bail!("S3-to-S3 copies stay server-side; mapping expected digests require reading object contents and are not supported");
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
        let source_bucket = self
            .options
            .source_bucket
            .as_deref()
            .unwrap_or(&self.options.bucket);
        let mut out = Vec::new();
        let mut claims = BTreeMap::new();
        let mut excluded_subtrees = HashSet::new();
        let same_bucket =
            self.options.source_bucket.as_deref() == Some(self.options.bucket.as_str());
        let mut copy_sources = Vec::new();
        let mut copy_targets = Vec::new();
        // Keep selector order for claims, but overlap bounded source metadata reads.
        let mut selectors = stream::iter(selectors)
            .map(|selector| async move {
                let prefix = self.args.native_mapping.is_none()
                    && matches!(
                        selector.2,
                        SourceSelection::Contents | SourceSelection::Directory
                    );
                let head =
                    if self.options.source_bucket.is_some() && !selector.0.is_empty() && !prefix {
                        self.copy_head(source_bucket, &selector.0, 0).await?
                    } else {
                        None
                    };
                Ok::<_, anyhow::Error>((selector, head))
            })
            .buffered(32);
        while let Some(selector) = selectors.next().await {
            let ((key, path, selection, declared_kind, expected_digest), mut copy_source) =
                selector?;
            let contents = selection == SourceSelection::Contents;
            let directory = matches!(
                selection,
                SourceSelection::Contents | SourceSelection::Directory
            );
            let prefix = if key.is_empty() {
                String::new()
            } else {
                format!("{key}/")
            };
            let exact = async {
                let exact = if key.is_empty() {
                    None
                } else if self.options.source_bucket.is_some()
                    && !(directory && self.args.native_mapping.is_none())
                {
                    copy_source.as_ref().map(|(object, _)| object.clone())
                } else {
                    client::head(&self.client, source_bucket, &key).await?
                };
                if exact.is_some() && directory && self.args.native_mapping.is_none() {
                    bail!("S3 selector requires a prefix but an object exists at {key:?}");
                }
                Ok::<_, anyhow::Error>(exact)
            };
            // Explicit prefix selectors need both reads. Start the listing
            // while checking for a conflicting object, but validate both
            // results before any file transfer or publication can begin.
            let (exact, listed) = if directory && self.args.native_mapping.is_none() {
                let (exact, listed) = tokio::try_join!(
                    exact,
                    client::list(
                        &self.client,
                        source_bucket,
                        &prefix,
                        matcher.as_ref(),
                        &mut excluded_subtrees
                    )
                )?;
                (exact, Some(listed))
            } else {
                (exact.await?, None)
            };
            let already_filtered = self.args.native_mapping.is_none() && exact.is_none();
            let objects = if self.args.native_mapping.is_some() {
                // Mapping entries name individual objects. A directory entry
                // copies its marker, while explicit child entries copy children.
                let object = match exact {
                    Some(object) => object,
                    None => {
                        let marker = format!("{key}/");
                        let object = if self.options.source_bucket.is_some() {
                            copy_source = self.copy_head(source_bucket, &marker, 0).await?;
                            copy_source.as_ref().map(|(object, _)| object.clone())
                        } else {
                            client::head(&self.client, source_bucket, &marker).await?
                        };
                        object.context("S3 mapping source object or directory marker is missing")?
                    }
                };
                if declared_kind.is_some_and(|kind| kind != object.kind()) {
                    bail!("S3 source type does not match mapping");
                }
                if expected_digest.is_some() && object.kind() != "file" {
                    bail!("an expected digest requires a regular file");
                }
                vec![(object.key, object.size, path.clone())]
            } else if let Some(exact) = exact {
                vec![(exact.key, exact.size, path.clone())]
            } else {
                if selection == SourceSelection::File {
                    bail!("S3 source object {key:?} is missing");
                }
                let listed = match listed {
                    Some(listed) => listed,
                    None => {
                        client::list(
                            &self.client,
                            source_bucket,
                            &prefix,
                            matcher.as_ref(),
                            &mut excluded_subtrees,
                        )
                        .await?
                    }
                };
                if !listed.found {
                    bail!("S3 source prefix {key:?} contains no objects");
                }
                self.progress
                    .files_excluded
                    .fetch_add(listed.excluded, Relaxed);
                if same_bucket {
                    copy_sources.push((prefix.clone(), true));
                    copy_targets.push((
                        if path.is_empty() {
                            String::new()
                        } else {
                            format!("{path}/")
                        },
                        true,
                    ));
                }
                if self.args.delete {
                    prune.scope(path.as_bytes(), key.as_bytes());
                }
                let mut objects = Vec::new();
                for (object, size) in listed.objects {
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
                if same_bucket && !already_filtered {
                    copy_sources.push((key.clone(), false));
                    copy_targets.push((
                        if directory {
                            format!("{path}/")
                        } else {
                            path.clone()
                        },
                        false,
                    ));
                }
                if !already_filtered {
                    if let Some(excluded) =
                        client::exclusion(matcher.as_ref(), &key, directory, &excluded_subtrees)
                    {
                        self.progress
                            .files_excluded
                            .fetch_add(excluded.count(&mut excluded_subtrees), Relaxed);
                        continue;
                    }
                }
                if !directory && (size < min || size > max) {
                    self.progress.files_excluded.fetch_add(1, Relaxed);
                    prune.protect(path.as_bytes());
                    continue;
                }
                if path.is_empty() && !directory {
                    bail!("cannot replace the destination directory with an object");
                }
                local::claim(&mut claims, &path, directory)?;
                if self.args.delete {
                    if directory {
                        prune.claim(path.as_bytes());
                    } else if self.options.source_bucket.is_some()
                        && !self.args.ignore_existing
                        && !self.args.existing
                    {
                        prune.claim_file(path.as_bytes());
                    } else {
                        prune.protect(path.as_bytes());
                    }
                }
                out.push(Download {
                    key,
                    path,
                    size,
                    expected_digest: expected_digest.clone(),
                    copy_source: copy_source.take().map(Box::new),
                });
            }
        }
        if same_bucket {
            server_copy::check_overlap(&copy_sources, &copy_targets)?;
        }
        Ok((out, prune))
    }
    async fn download(
        self: &Arc<Self>,
        job: &Download,
        destination: &Destination,
        directories: DirectoryMetadata,
        kind: &mut &'static str,
    ) -> Result<Option<u64>> {
        let part_size = self.part_size(job.size);
        let expected_digest = job
            .expected_digest
            .as_ref()
            .or(self.args.expected_digest.as_ref());
        let requires_regular_file = expected_digest.is_some();
        let expected_digest = expected_digest.filter(|_| !self.args.dry_run);
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
        // A fresh file obtains metadata with its first data request. For a
        // multipart download, receiving these headers is enough to start the
        // other ranges; the first body is consumed alongside them.
        // Existing files still use HEAD so an unchanged object is not fetched.
        let mut initial_slot = None;
        let initial = if existing.is_none()
            && !self.args.dry_run
            && !self.args.verify_only
            && !job.key.ends_with('/')
        {
            initial_slot = Some(self.tuning.requests.acquire().await);
            Some(
                self.client
                    .get_object()
                    .bucket(&self.options.bucket)
                    .key(&job.key)
                    .set_range((job.size > part_size).then(|| format!("bytes=0-{}", part_size - 1)))
                    .send()
                    .await
                    .map_err(|e| e.into_service_error())
                    .context("S3 GET failed")?,
            )
        } else {
            None
        };
        let object = if let Some(output) = &initial {
            client::from_get(&job.key, job.size, part_size, output)?
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
        let mut initial = initial.map(|output| output.body);
        let metadata = object.metadata.clone().unwrap_or(Metadata {
            kind: object.kind().into(),
            mode: if object.kind() == "dir" { 0o777 } else { 0o666 },
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            mtime: object.mtime,
            nsec: 0,
            hash: None,
            hash_algorithm: HashAlgorithm::Blake3,
        });
        if self.args.update && existing.is_some_and(|m| m.is_file() && m.mtime > metadata.mtime) {
            return Ok(None);
        }
        if let Some(m) = existing {
            if m.is_dir() != (object.kind() == "dir") {
                bail!("refusing to replace a directory with a non-directory or the reverse");
            }
        }
        if requires_regular_file && object.kind() != "file" {
            bail!("an expected digest requires a regular file");
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
            let bytes = self.get_small(&object, initial, initial_slot).await?;
            if let Some(hash) = metadata
                .hash
                .as_ref()
                .filter(|_| self.args.transfer_integrity)
            {
                if Digest::hash_bytes(metadata.hash_algorithm, &bytes).value != *hash {
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
                if self.args.verify_only
                    || metadata.hash.is_none()
                    || metadata.hash_algorithm != self.args.hash_algorithm
                {
                    unchanged = self.verify_download(root, &path, &object).await?;
                } else {
                    let file = root.open_regular_read(&path)?;
                    let algorithm = metadata.hash_algorithm;
                    let hash =
                        tokio::task::spawn_blocking(move || local::hash_file_as(file, algorithm))
                            .await??;
                    unchanged = metadata.hash.as_ref() == Some(&hash);
                }
            } else {
                unchanged = m.mtime == metadata.mtime && m.mtime_nsec == metadata.nsec;
            }
        }
        if self.args.verify_only {
            if !unchanged {
                if existing.is_some_and(|m| m.is_file() && m.len == object.size) {
                    bail!("verification failed: contents differ");
                }
                bail!("verification failed: file missing, type differs, or size differs");
            }
            self.verify_expected_local(root, &path, expected_digest)
                .await?;
            return Ok(None);
        }
        if unchanged && expected_digest.is_some() {
            unchanged = self
                .verify_expected_local(root, &path, expected_digest)
                .await
                .is_ok();
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
        if object.size <= part_size {
            return self
                .download_single(
                    &object,
                    root,
                    &path,
                    (&metadata, expected_digest),
                    existing.filter(|m| m.is_file()).map(|m| m.mode & 0o7777),
                    initial,
                    initial_slot,
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
            if old.schema != 1 && old.schema != 2 {
                bail!("unsupported S3 download recovery schema");
            }
            if old.etag != object.etag
                || old.version != object.version
                || old.size != object.size
                || old.part_size != part_size
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
        let range_algorithm = record.hash_algorithm;
        let record = Arc::new(Mutex::new(record));
        let file = Arc::new(file);
        let allocation = file.clone();
        let size = object.size;
        tokio::task::spawn_blocking(move || super::writer::allocate(&allocation, size)).await??;
        let output = super::writer::Writer::with_readback(
            file.clone(),
            object.size,
            !part_size.is_multiple_of(4096)
                || !self.download_digests(&metadata, expected_digest).is_empty(),
        )?;
        let parts = object.size.div_ceil(part_size);
        let _interval = self.progress.copying_interval();
        let failed = std::sync::atomic::AtomicBool::new(false);
        let copied = stream::iter(0..parts)
            .take_while(|_| std::future::ready(!failed.load(Relaxed)))
            .map(|index| {
                let output = output.clone();
                let file = file.clone();
                let record = record.clone();
                let object = &object;
                let state = &state;
                let initial = if index == 0 { initial.take() } else { None };
                let slot = if index == 0 {
                    initial_slot.take()
                } else {
                    None
                };
                async move {
                    let offset = index * part_size;
                    let length = part_size.min(object.size - offset);
                    let previous = record.lock().await.parts.get(&index).cloned();
                    if let Some(hash) = previous {
                        let f = file.clone();
                        let actual = tokio::task::spawn_blocking(move || {
                            hash_range(&f, offset, length, range_algorithm)
                        })
                        .await??;
                        if actual == hash {
                            self.progress.bytes_unchanged.fetch_add(length, Relaxed);
                            return Ok::<_, anyhow::Error>(());
                        }
                    }
                    let hash = self
                        .download_fast_range(
                            object,
                            &output,
                            offset,
                            length,
                            initial,
                            slot,
                            Some(range_algorithm),
                        )
                        .await?;
                    output.finish().await?;
                    let mut record = record.lock().await;
                    record.parts.insert(index, hash);
                    state.save(&*record)?;
                    Ok(())
                }
            })
            .buffer_unordered(self.part_workers())
            .inspect(|result| {
                if result.is_err() {
                    failed.store(true, Relaxed);
                }
            })
            .collect::<Vec<Result<_>>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>();
        let flushed = output.finish().await;
        copied?;
        flushed?;
        let partial = record.lock().await.partial.clone();
        let partial_path = RelativePath::new(partial.as_bytes())?;
        for expected in self.download_digests(&metadata, expected_digest) {
            let f = root.open_regular_read(&partial_path)?;
            tokio::task::spawn_blocking(move || expected.verify_reader(&mut &f)).await??;
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
        self.check_cancelled()?;
        local::apply_file_metadata(
            &file,
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
    fn download_digests(&self, metadata: &Metadata, expected: Option<&Digest>) -> Vec<Digest> {
        let mut digests = expected.cloned().into_iter().collect::<Vec<_>>();
        if self.args.transfer_integrity {
            if let Some(value) = &metadata.hash {
                let digest = Digest {
                    algorithm: metadata.hash_algorithm,
                    value: value.clone(),
                };
                if !digests.contains(&digest) {
                    digests.push(digest);
                }
            }
        }
        digests
    }
    async fn verify_expected_local(
        &self,
        root: &Root,
        path: &RelativePath,
        expected: Option<&Digest>,
    ) -> Result<()> {
        if let Some(expected) = expected.cloned() {
            let mut file = root.open_regular_read(path)?;
            tokio::task::spawn_blocking(move || expected.verify_reader(&mut file)).await??;
        }
        Ok(())
    }
    async fn verify_expected_remote(
        &self,
        object: &Object,
        expected: Option<&Digest>,
    ) -> Result<()> {
        if let Some(expected) = expected {
            if object.kind() != "file" {
                bail!("an expected digest requires a regular file");
            }
            let actual = self.remote_hash_as(object, expected.algorithm).await?;
            if actual != expected.value {
                bail!("remote object does not match expected digest");
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn download_single(
        &self,
        object: &Object,
        root: &Root,
        path: &RelativePath,
        validation: (&Metadata, Option<&Digest>),
        mode: Option<u32>,
        initial: Option<ByteStream>,
        initial_slot: Option<super::tuning::Permit>,
    ) -> Result<Option<u64>> {
        let (metadata, expected_digest) = validation;
        let path_buf = path.to_path_buf();
        let label = path_buf
            .to_str()
            .context("S3 download placement requires UTF-8")?;
        let parent = label.rsplit_once('/').map_or("", |(p, _)| p);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)?;
        let partial = RelativePath::new(
            local::join(parent, &super::prune::partial_name(&random)).as_bytes(),
        )?;
        let file = Arc::new(root.create_file(&partial, 0o600)?);
        let _cleanup = PartialCleanup {
            root,
            path: partial.clone(),
            identity: (file.metadata()?.dev(), file.metadata()?.ino()),
        };
        let result = async {
            let digests = self.download_digests(metadata, expected_digest);
            let algorithm = digests.first().map(|d| d.algorithm);
            let output =
                super::writer::Writer::with_readback(file.clone(), object.size, digests.len() > 1)?;
            let hash = if object.size == 0 && initial.is_none() {
                algorithm
                    .map(|a| Digest::hash_bytes(a, &[]).value)
                    .unwrap_or_default()
            } else {
                let copied = self
                    .download_fast_range(
                        object,
                        &output,
                        0,
                        object.size,
                        initial,
                        initial_slot,
                        algorithm,
                    )
                    .await;
                let flushed = output.finish().await;
                let hash = copied?;
                flushed?;
                hash
            };
            if digests
                .first()
                .is_some_and(|expected| expected.value != hash)
            {
                bail!("download checksum mismatch");
            }
            // If the caller requires a second algorithm, reread only for that
            // distinct requirement, never rehash the same digest twice.
            for expected in digests.into_iter().skip(1) {
                let f = file.clone();
                tokio::task::spawn_blocking(move || expected.verify_reader(&mut &*f)).await??;
            }
            self.check_cancelled()?;
            local::apply_file_metadata(&file, metadata, &self.args, mode)?;
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
        let partial = local::join(parent, &super::prune::partial_name(&random));
        let file = root.create_file(&RelativePath::new(partial.as_bytes())?, 0o600)?;
        file.set_len(object.size)?;
        let m = file.metadata()?;
        let record = DownloadState {
            schema: 2,
            etag: object.etag.clone(),
            version: object.version.clone(),
            size: object.size,
            part_size: self.part_size(object.size),
            partial,
            dev: m.dev(),
            ino: m.ino(),
            parts: BTreeMap::new(),
            hash_algorithm: self.args.hash_algorithm,
        };
        state.save(&record)?;
        Ok((record, file))
    }
    async fn get_small(
        &self,
        object: &Object,
        initial: Option<ByteStream>,
        initial_slot: Option<super::tuning::Permit>,
    ) -> Result<Vec<u8>> {
        let _slot = match initial_slot {
            Some(slot) => slot,
            None => self.tuning.requests.acquire().await,
        };
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
        let algorithm = self.args.hash_algorithm;
        let expected =
            tokio::task::spawn_blocking(move || local::hash_file_as(file, algorithm)).await??;
        Ok(self.remote_hash(object).await? == expected)
    }
    async fn remote_hash(&self, object: &Object) -> Result<String> {
        self.remote_hash_as(object, self.args.hash_algorithm).await
    }
    async fn remote_hash_as(&self, object: &Object, algorithm: HashAlgorithm) -> Result<String> {
        let _slot = self.tuning.requests.acquire().await;
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
        let mut hash = algorithm.hasher();
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
        Ok(Digest::from_hash(algorithm, &hash.finalize()).value)
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
/// The upload loops replace SDK retries, so they must recognize the same
/// throttling and transient conditions: dispatch failures without a response,
/// retryable statuses, and the error codes S3 can send with other statuses,
/// such as `RequestTimeout` with HTTP 400.
fn retryable<E: aws_sdk_s3::error::ProvideErrorMetadata>(
    error: &aws_sdk_s3::error::SdkError<
        E,
        aws_smithy_runtime_api::client::orchestrator::HttpResponse,
    >,
) -> bool {
    use aws_runtime::retries::classifiers::{THROTTLING_ERRORS, TRANSIENT_ERRORS};
    error
        .raw_response()
        .map(|r| r.status().as_u16())
        .is_none_or(|s| matches!(s, 408 | 429 | 500 | 502 | 503 | 504))
        || error
            .as_service_error()
            .and_then(|e| e.code())
            .is_some_and(|code| {
                THROTTLING_ERRORS.contains(&code) || TRANSIENT_ERRORS.contains(&code)
            })
}
async fn file_body(source: &Source, offset: u64, length: u64) -> Result<ByteStream> {
    let source = source.clone();
    let file = tokio::task::spawn_blocking(move || source.open()).await??;
    Ok(ByteStream::read_from()
        .file(tokio::fs::File::from_std(file))
        .offset(offset)
        .length(Length::Exact(length))
        .buffer_size(length.clamp(1, 1024 * 1024) as usize)
        .build()
        .await?)
}
fn encode_native_parts(algorithm: HashAlgorithm, parts: &[[u8; 32]]) -> Vec<String> {
    use base64::Engine as _;
    parts
        .iter()
        .map(|p| base64::engine::general_purpose::STANDARD.encode(&p[..algorithm.output_len()]))
        .collect()
}

fn upload_identity(
    algorithm: Algorithm,
    size: u64,
    part_size: u64,
    checksums: &[String],
) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(b"syq-s3-native-parts-v1\0");
    hash.update(&[match algorithm {
        Algorithm::Sha256 => 1,
        Algorithm::Md5 => 2,
    }]);
    hash.update(&size.to_le_bytes());
    hash.update(&part_size.to_le_bytes());
    for checksum in checksums {
        hash.update(checksum.as_bytes());
        hash.update(&[0]);
    }
    format!("parts:{}", hash.finalize().to_hex())
}

fn hash_range(file: &File, offset: u64, length: u64, algorithm: HashAlgorithm) -> Result<String> {
    let mut buffer = vec![0; 1024 * 1024];
    let mut done = 0;
    let mut hash = algorithm.hasher();
    while done < length {
        let n = buffer.len().min((length - done) as usize);
        file.read_exact_at(&mut buffer[..n], offset + done)?;
        hash.update(&buffer[..n]);
        done += n as u64;
    }
    Ok(Digest::from_hash(algorithm, &hash.finalize()).value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_upload_identity_binds_parts_algorithm_and_boundaries() {
        let checksums = vec!["first".to_string(), "second".to_string()];
        let identity = upload_identity(Algorithm::Sha256, 10, 5, &checksums);
        assert_ne!(identity, upload_identity(Algorithm::Md5, 10, 5, &checksums));
        assert_ne!(
            identity,
            upload_identity(Algorithm::Sha256, 11, 5, &checksums)
        );
        assert_ne!(
            identity,
            upload_identity(Algorithm::Sha256, 10, 6, &checksums)
        );
        assert_ne!(
            identity,
            upload_identity(Algorithm::Sha256, 10, 5, &["second".into(), "first".into()])
        );
    }

    #[test]
    fn reads_unchanged_upload_record_from_4be9e58() {
        let fixture = include_str!("../../tests/fixtures/s3-upload-v1.json");
        let record: UploadState = serde_json::from_str(fixture).unwrap();
        assert_eq!(record.schema, 1);
        assert_eq!(record.algorithm, Algorithm::Sha256);
        assert!(record.completed.is_empty());
        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            serde_json::from_str::<serde_json::Value>(fixture).unwrap()
        );
    }

    #[test]
    fn md5_recovery_requires_acknowledged_opaque_etag_checksum_and_length() {
        let mut record: UploadState =
            serde_json::from_str(include_str!("../../tests/fixtures/s3-upload-v1.json")).unwrap();
        record.algorithm = Algorithm::Md5;
        record.schema = record.algorithm.schema();
        record.completed.insert(
            1,
            UploadedPart {
                etag: "opaque-etag".into(),
                checksum: "checksum".into(),
                length: 42,
            },
        );
        let record: UploadState =
            serde_json::from_value(serde_json::to_value(record).unwrap()).unwrap();
        assert_eq!(record.schema, 2); // The earlier binary rejects this schema.
        assert!(record.acknowledged_part(1, "opaque-etag", "checksum", 42));
        assert!(!record.acknowledged_part(2, "opaque-etag", "checksum", 42));
        assert!(!record.acknowledged_part(1, "replaced-etag", "checksum", 42));
        assert!(!record.acknowledged_part(1, "opaque-etag", "changed", 42));
        assert!(!record.acknowledged_part(1, "opaque-etag", "checksum", 41));
    }
}
