//! Same-service copies never read object bodies through the invoking machine.
use super::*;
use aws_sdk_s3::{
    operation::head_object::HeadObjectOutput,
    types::{ChecksumType, MetadataDirective, StorageClass, Tag, Tagging, TaggingDirective},
};

// Compare only fields whose meaning survives a copy. LastModified, encryption,
// version IDs and ETags are not user metadata.
fn same_metadata(a: &HeadObjectOutput, b: &HeadObjectOutput) -> bool {
    a.metadata()
        .into_iter()
        .flat_map(|m| m.iter())
        .collect::<BTreeMap<_, _>>()
        == b.metadata()
            .into_iter()
            .flat_map(|m| m.iter())
            .collect::<BTreeMap<_, _>>()
        && a.content_type() == b.content_type()
        && a.content_encoding() == b.content_encoding()
        && a.content_language() == b.content_language()
        && a.content_disposition() == b.content_disposition()
        && a.cache_control() == b.cache_control()
        && a.expires_string() == b.expires_string()
        && a.website_redirect_location() == b.website_redirect_location()
        && super::super::metadata_fields::storage_class(a)
            == super::super::metadata_fields::storage_class(b)
}

/// Whether both objects carry a syq hash of the same kind, which then
/// decides whether their contents match.
fn syq_hashes<'a>(source: &'a Object, old: &'a Object) -> Option<(&'a str, &'a str)> {
    let (a, b) = source.metadata.as_ref().zip(old.metadata.as_ref())?;
    (a.hash_algorithm == b.hash_algorithm)
        .then(|| a.hash.as_deref().zip(b.hash.as_deref()))
        .flatten()
}

/// A SHA-256 the provider keeps for the whole object, rather than one
/// combined from parts.
fn full_object_sha256(head: &HeadObjectOutput) -> Option<&str> {
    (head.checksum_type() == Some(&ChecksumType::FullObject))
        .then(|| head.checksum_sha256())
        .flatten()
}

/// Whether provider SHA-256 checksums could decide a comparison, so the HEADs
/// must ask for them.
fn sha256_could_decide(source: &Object, old: &Object) -> bool {
    source.kind() == ObjectKind::File
        && old.kind() == ObjectKind::File
        && source.size == old.size
        && syq_hashes(source, old).is_none()
}

/// Whether an existing destination object holds the source's contents.
/// Syq's own whole-file hashes decide when both objects carry one of the same
/// kind. Otherwise full-object SHA-256 checksums the provider keeps decide
/// when both objects have one. Otherwise equal ETags count, and so does
/// `quick_check`: matching stored size and modification time. CRC and SHA-1
/// checksums never decide.
fn same_contents(
    (source, source_head): (&Object, &HeadObjectOutput),
    (old, old_head): (&Object, &HeadObjectOutput),
    quick_check: bool,
) -> bool {
    if source.kind() != old.kind() || source.size != old.size {
        return false;
    }
    if source.kind() == ObjectKind::Dir {
        return true;
    }
    if let Some((a, b)) = syq_hashes(source, old) {
        return a == b;
    }
    if let (Some(a), Some(b)) = (
        full_object_sha256(source_head),
        full_object_sha256(old_head),
    ) {
        return a == b;
    }
    source.etag == old.etag || quick_check
}

fn copy_destination_key(job: &Download) -> String {
    if client::is_directory_marker(&job.key, job.size) {
        format!("{}/", job.path)
    } else {
        job.path.clone()
    }
}

fn encoded_source(bucket: &str, object: &Object) -> String {
    fn encode(value: &str) -> String {
        let mut out = String::new();
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                out.push(byte as char);
            } else {
                use std::fmt::Write;
                write!(out, "%{byte:02X}").unwrap();
            }
        }
        out
    }
    let mut source = format!("{}/{}", encode(bucket), encode(&object.key));
    if let Some(version) = &object.version {
        source.push_str("?versionId=");
        source.push_str(&encode(version));
    }
    source
}

// Prefix ranges include their trailing slash; exact marker objects are exact
// keys too. Ordered lookups avoid comparing every source with every target.
pub(super) fn check_overlap(sources: &[(String, bool)], targets: &[(String, bool)]) -> Result<()> {
    use std::collections::BTreeSet;
    let exact: BTreeSet<&str> = sources
        .iter()
        .filter(|(_, prefix)| !prefix)
        .map(|(key, _)| key.as_str())
        .collect();
    let prefixes: BTreeSet<&str> = sources
        .iter()
        .filter(|(_, prefix)| *prefix)
        .map(|(key, _)| key.as_str())
        .collect();
    for (key, prefix) in targets {
        let key = key.as_str();
        let inside_source = prefixes.contains("")
            || key
                .match_indices('/')
                .any(|(index, _)| prefixes.contains(&key[..=index]));
        let contains_source = *prefix
            && (exact
                .range(key..)
                .next()
                .is_some_and(|source| source.starts_with(key))
                || prefixes
                    .range(key..)
                    .next()
                    .is_some_and(|source| source.starts_with(key)));
        anyhow::ensure!(
            !(exact.contains(key) || inside_source || contains_source),
            "S3 source and destination paths overlap in the same bucket"
        );
    }
    Ok(())
}

enum CopyPreparation {
    Skipped,
    Preview(u64),
    Ready(Box<PreparedCopy>),
    Metadata(Box<super::super::metadata_copy::Prepared>),
    Tags {
        key: String,
        version: Option<String>,
        tags: Vec<Tag>,
        size: u64,
    },
}
struct PreparedCopy {
    source: Object,
    source_head: HeadObjectOutput,
    desired_head: HeadObjectOutput,
    key: String,
    copy_source: String,
    must_be_new: bool,
    explicit: bool,
    multipart: Option<PreparedCopyMultipart>,
}
struct PreparedCopyMultipart {
    id: String,
    part_size: u64,
}

impl Engine {
    fn copy_error(&self, error: anyhow::Error) -> anyhow::Error {
        if error
            .downcast_ref::<client::RequestFailure>()
            .is_some_and(|e| e.region_mismatch())
        {
            error.context(format!("S3-to-S3 source bucket {:?} and destination bucket {:?} are configured with region {}; --s3-region applies to both endpoints: use the reported region if both buckets are there; buckets in different regions are not supported by this route",
                self.options.route.source_bucket().unwrap(), self.options.bucket,
                self.client.config().region().map_or("unknown", |region| region.as_ref())))
        } else {
            error
        }
    }

    pub(super) fn copy_request_limit(&self, size: u64) -> u64 {
        const MAX_SINGLE_COPY: u64 = 5 * 1024 * 1024 * 1024;
        if self.options.automatic_part_size {
            MAX_SINGLE_COPY
        } else {
            self.part_size(size).min(MAX_SINGLE_COPY)
        }
    }

    /// With `checksums`, also ask for the provider's checksums, unless the
    /// service has shown it does not support that.
    pub(super) async fn copy_head(
        &self,
        bucket: &str,
        key: &str,
        checksums: bool,
    ) -> Result<Option<(Object, HeadObjectOutput)>> {
        let _slot = self.tuning.requests.acquire().await;
        let Some(output) = client::head_output(
            &self.client,
            bucket,
            key,
            checksums.then_some(&self.copy_checksum_unsupported),
        )
        .await?
        else {
            return Ok(None);
        };
        Ok(Some((client::from_head(key, &output)?, output)))
    }

    pub(super) async fn server_copy(self: Arc<Self>) -> Result<()> {
        self.clone()
            .server_copy_inner()
            .await
            .map_err(|error| self.copy_error(error))
    }

    async fn server_copy_inner(self: Arc<Self>) -> Result<()> {
        let target = local::key_path(&self.args.locations.last().unwrap().path)?;
        let DownloadPlan {
            jobs: plan,
            mut prune,
            ..
        } = self.download_plan(&target).await?;
        self.check_upload_placement(
            plan.first()
                .map(|job| job.path == target && !job.key.ends_with('/')),
        )
        .await?;
        let keys: Vec<_> = plan.iter().map(copy_destination_key).collect();
        self.discover_destination(keys.iter().map(String::as_str).collect())
            .await?;
        let workers = self.object_workers(plan.iter().map(|p| p.size))?;
        self.progress.files_total.store(plan.len() as u64, Relaxed);
        self.progress
            .bytes_total
            .store(plan.iter().map(|p| p.size).sum(), Relaxed);
        self.progress.scan_done.store(true, Relaxed);
        if self.authorization.is_some() {
            let prepared = Arc::new(Mutex::new(Vec::with_capacity(plan.len())));
            parallel(plan, workers, |mut job| {
                let engine = self.clone();
                let prepared = prepared.clone();
                async move {
                    match engine.prepare_copy(&mut job).await {
                        Ok(work) => prepared.lock().await.push((job, work)),
                        Err(error) => engine.settle(
                            job.key.as_bytes(),
                            &job.path,
                            job.kind,
                            &Err(engine.copy_error(error)),
                            None,
                        ),
                    }
                    Ok(None)
                }
            })
            .await?;
            let prepared = std::mem::take(&mut *prepared.lock().await);
            let finish = async {
                self.prepare_pruning(&prune).await?;
                self.finish_authorization().await?;
                if self.args.prune_before {
                    self.prune(std::mem::take(&mut prune), None).await?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = finish {
                for (_, work) in &prepared {
                    match work {
                        CopyPreparation::Ready(work) => self.abort_prepared_copy(work).await,
                        CopyPreparation::Metadata(work) => {
                            work.abort(&self.client, &self.options.bucket).await
                        }
                        _ => {}
                    }
                }
                return Err(error);
            }
            let workers = self.object_workers(prepared.iter().map(|(job, _)| job.size))?;
            parallel(prepared, workers, |(job, work)| {
                let engine = self.clone();
                async move {
                    let result = engine
                        .execute_copy(work)
                        .await
                        .map_err(|e| engine.copy_error(e));
                    engine.settle(job.key.as_bytes(), &job.path, job.kind, &result, None);
                    Ok(result.ok().flatten())
                }
            })
            .await?;
        } else {
            if self.args.prune_before {
                self.prune(std::mem::take(&mut prune), None).await?;
            }
            parallel(plan, workers, |mut job| {
                let engine = self.clone();
                async move {
                    engine.check_cancelled()?;
                    let result = engine
                        .copy_object(&mut job)
                        .await
                        .map_err(|error| engine.copy_error(error));
                    engine.settle(job.key.as_bytes(), &job.path, job.kind, &result, None);
                    Ok(result.ok().flatten())
                }
            })
            .await?;
        }
        self.progress.finish_transfer();
        if !self.args.prune_before {
            self.prune(prune, None).await?;
        }
        Ok(())
    }

    async fn prepare_copy(&self, job: &mut Download) -> Result<CopyPreparation> {
        let source_bucket = self.options.route.source_bucket().unwrap();
        let key = copy_destination_key(job);
        local::key_path(key.trim_end_matches('/').as_bytes())?;
        anyhow::ensure!(key.len() <= 1024, "S3 key exceeds 1024 bytes");
        // Provider checksums can matter only against an existing destination
        // of the same size that is not kept regardless.
        let listed = self.upload_keys.get().map(|keys| keys.get(&key).copied());
        let comparable =
            !self.args.ignore_existing && listed.is_none_or(|size| size == Some(job.size));
        let destination = async {
            if listed == Some(None) {
                Ok(None)
            } else {
                self.copy_head(&self.options.bucket, &key, comparable).await
            }
        };
        let planned = job.copy_source.is_some();
        let source = async {
            match job.copy_source.take() {
                Some(source) => Ok(Some(*source)),
                None => self.copy_head(source_bucket, &job.key, comparable).await,
            }
        };
        let (source, existing) = tokio::try_join!(source, destination)?;
        let (source, source_head) = source.context("S3 copy source disappeared")?;
        if self.args.expressions.active() {
            let source_file = source.expression_file();
            if !self
                .args
                .expressions
                .selects(&source_file, job.expression_path.as_bytes())?
                || !self.args.expressions.permits(
                    &source_file,
                    job.expression_path.as_bytes(),
                    &existing
                        .as_ref()
                        .map(|(o, _)| o.expression_file())
                        .unwrap_or_default(),
                    job.expression_destination_path.as_bytes(),
                )?
            {
                return Ok(CopyPreparation::Skipped);
            }
        }

        let mut desired_head = source_head.clone();
        let explicit = job.metadata().unwrap_or_default();
        explicit.validate_kind(match source.kind() {
            ObjectKind::File => crate::proto::Kind::File,
            ObjectKind::Dir => crate::proto::Kind::Dir,
            ObjectKind::Symlink => crate::proto::Kind::Symlink,
        })?;
        if explicit.flags() != 0 {
            let mut metadata = source.metadata.clone().unwrap_or(Metadata {
                kind: source.kind(),
                mode: if source.kind() == ObjectKind::Dir {
                    0o777
                } else {
                    0o666
                },
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                mtime: source.mtime,
                nsec: 0,
                hash: None,
                hash_algorithm: HashAlgorithm::Blake3,
            });
            metadata.override_with(&explicit);
            desired_head
                .metadata
                .get_or_insert_with(Default::default)
                .extend(metadata.encode());
        }
        anyhow::ensure!(
            source.size == job.size,
            "S3 source size changed after planning"
        );
        job.kind = source.kind();
        if (self.args.ignore_existing && existing.is_some())
            || (self.args.existing && existing.is_none())
        {
            return Ok(CopyPreparation::Skipped);
        }
        anyhow::ensure!(
            source.kind() == ObjectKind::Dir
                || existing.is_none()
                || self.args.if_exists != Some(crate::cli::IfExists::Error),
            "destination already exists: {key} (--if-exists=error)"
        );
        let source_time = source
            .metadata
            .as_ref()
            .map_or((source.mtime, 0), |m| (m.mtime, m.nsec));
        let mut matching_contents = false;
        let mut selected_tags = None;
        let mut tags_differ = false;
        if let Some((old, old_head)) = &existing {
            let old_time = old
                .metadata
                .as_ref()
                .map_or((old.mtime, 0), |m| (m.mtime, m.nsec));
            if self.args.update && source.kind() != ObjectKind::Dir && old_time > source_time {
                return Ok(CopyPreparation::Skipped);
            }
            // A source looked up while planning, before its destination was
            // known, has no checksums. Ask for them only when they can change
            // the outcome. A lookup that fails, or finds the source changed,
            // decides nothing: compare without it.
            let rechecked = if planned
                && !self.copy_checksum_unsupported.load(Relaxed)
                && sha256_could_decide(&source, old)
                && full_object_sha256(old_head).is_some()
            {
                match self.copy_head(source_bucket, &job.key, true).await {
                    Ok(Some((now, head))) if now.etag == source.etag && now.size == source.size => {
                        Some(head)
                    }
                    _ => None,
                }
            } else {
                None
            };
            matching_contents = same_contents(
                (&source, rechecked.as_ref().unwrap_or(&source_head)),
                (old, old_head),
                !self.args.checksum
                    && source.metadata.is_some()
                    && old.metadata.is_some()
                    && source_time == old_time
                    && explicit.mtime.is_none(),
            );
            anyhow::ensure!(
                source.kind() == ObjectKind::Dir
                    || matching_contents
                    || !self.args.protects_existing_contents(),
                "cannot establish matching destination contents: {key} (--if-exists=error-if-different)"
            );
            if matching_contents {
                desired_head = old_head.clone();
                let flags = self.args.matching_meta_flags() | explicit.apply_flags();
                if flags != 0 {
                    let mut metadata = old.metadata.clone().unwrap_or(Metadata {
                        kind: old.kind(),
                        mode: if old.kind() == ObjectKind::Dir {
                            0o777
                        } else {
                            0o666
                        },
                        uid: unsafe { libc::geteuid() },
                        gid: unsafe { libc::getegid() },
                        mtime: old_time.0,
                        nsec: old_time.1,
                        hash: None,
                        hash_algorithm: HashAlgorithm::Blake3,
                    });
                    if let Some(src) = &source.metadata {
                        if self.args.perms {
                            metadata.mode = src.mode;
                        }
                        if self.args.owner {
                            metadata.uid = src.uid;
                        }
                        if self.args.group {
                            metadata.gid = src.gid;
                        }
                    }
                    if self.args.copy_mtime_metadata {
                        metadata.mtime = source_time.0;
                        metadata.nsec = source_time.1;
                    }
                    metadata.override_with(&explicit);
                    desired_head
                        .metadata
                        .get_or_insert_with(Default::default)
                        .extend(metadata.encode());
                }
                self.args
                    .s3_metadata
                    .apply(&source_head, &mut desired_head)?;
                if self.args.s3_metadata.tags {
                    let (source_tags, destination_tags) = tokio::try_join!(
                        self.selected_tags(source_bucket, &source.key, &source_head),
                        self.selected_tags(&self.options.bucket, &key, old_head),
                    )?;
                    tags_differ = source_tags != destination_tags;
                    selected_tags = Some(source_tags);
                }
                if same_metadata(&desired_head, old_head) && !tags_differ {
                    self.progress
                        .bytes_unchanged
                        .fetch_add(source.size, Relaxed);
                    return Ok(CopyPreparation::Skipped);
                }
            }
        }
        if self.args.dry_run {
            self.progress.bytes_done.fetch_add(source.size, Relaxed);
            return Ok(CopyPreparation::Preview(source.size));
        }
        self.check_cancelled()?;
        if matching_contents {
            let old_head = &existing.as_ref().unwrap().1;
            if same_metadata(&desired_head, old_head) {
                // Upload approvals allow changing the current object, not
                // metadata on an arbitrary historical version.
                let version = if self.authorization.is_some() {
                    None
                } else {
                    old_head.version_id().map(str::to_owned)
                };
                let mut request =
                    super::super::authorization::Unsigned::new("PUT", &key).query("tagging", "");
                if let Some(version) = &version {
                    request = request.query("versionId", version);
                }
                self.authorize_requests(vec![request]).await?;
                return Ok(CopyPreparation::Tags {
                    key,
                    version,
                    tags: selected_tags.unwrap(),
                    size: source.size,
                });
            }
            let _slot = self.tuning.requests.acquire().await;
            let update = super::super::metadata_copy::Prepared::prepare_selected(
                &self.client,
                &self.options,
                &key,
                old_head,
                super::super::metadata_copy::Desired {
                    head: desired_head,
                    tags: selected_tags,
                },
                self.part_size(source.size),
                self.copy_request_limit(source.size),
            )
            .await?;
            drop(_slot);
            if let Err(error) = self.authorize_requests(update.requests()).await {
                update.abort(&self.client, &self.options.bucket).await;
                return Err(error);
            }
            return Ok(CopyPreparation::Metadata(Box::new(update)));
        }
        // Native COPY preserves even metadata omitted from HEAD. Only reject
        // an incomplete set when this request must reconstruct that metadata.
        if self.args.s3_metadata.user_metadata
            && (explicit.flags() != 0 || source.size > self.copy_request_limit(source.size))
        {
            anyhow::ensure!(source_head.missing_meta().unwrap_or(0) == 0,
                "cannot copy user metadata: the service omitted source metadata (x-amz-missing-meta)");
        }
        let copy_source = encoded_source(source_bucket, &source);
        let must_be_new = self.args.ignore_existing
            || self.args.target_existence == Existence::New
            || (self.args.protects_existing_contents() && existing.is_none());
        let multipart = if source.size > self.copy_request_limit(source.size) {
            let selected_tags = if self.args.s3_metadata.tags {
                Some(
                    self.selected_tags(source_bucket, &source.key, &source_head)
                        .await?,
                )
            } else {
                None
            };
            Some(
                self.prepare_multipart_copy(
                    &source,
                    desired_head.clone(),
                    &key,
                    selected_tags.as_deref(),
                )
                .await?,
            )
        } else {
            None
        };
        let prepared = PreparedCopy {
            source,
            source_head,
            desired_head,
            key,
            copy_source,
            must_be_new,
            explicit: explicit.flags() != 0 || matching_contents,
            multipart,
        };
        if let Err(error) = self.authorize_copy(&prepared).await {
            self.abort_prepared_copy(&prepared).await;
            return Err(error);
        }
        Ok(CopyPreparation::Ready(Box::new(prepared)))
    }

    async fn copy_object(&self, job: &mut Download) -> Result<Option<u64>> {
        self.execute_copy(self.prepare_copy(job).await?).await
    }

    async fn execute_copy(&self, work: CopyPreparation) -> Result<Option<u64>> {
        let work = match work {
            CopyPreparation::Skipped => return Ok(None),
            CopyPreparation::Preview(size) => return Ok(Some(size)),
            CopyPreparation::Ready(work) => work,
            CopyPreparation::Tags {
                key,
                version,
                tags,
                size,
            } => {
                let _slot = self.tuning.requests.acquire().await;
                self.check_cancelled()?;
                self.client
                    .put_object_tagging()
                    .bucket(&self.options.bucket)
                    .key(&key)
                    .set_version_id(version)
                    .tagging(Tagging::builder().set_tag_set(Some(tags)).build()?)
                    .send()
                    .await
                    .context("update destination tags")?;
                self.progress.bytes_unchanged.fetch_add(size, Relaxed);
                return Ok(Some(0));
            }
            CopyPreparation::Metadata(update) => {
                update
                    .execute(
                        &self.client,
                        &self.options.bucket,
                        self.part_workers(),
                        || async {
                            let slot = self.tuning.requests.acquire().await;
                            self.check_cancelled()?;
                            Ok(slot)
                        },
                    )
                    .await?;
                self.progress
                    .bytes_unchanged
                    .fetch_add(update.size, Relaxed);
                return Ok(Some(0));
            }
        };
        if let Err(error) = self.check_cancelled() {
            self.abort_prepared_copy(&work).await;
            return Err(error);
        }
        let _interval = self.progress.copying_interval();
        let PreparedCopy {
            source,
            source_head,
            desired_head,
            key,
            copy_source,
            must_be_new,
            explicit,
            multipart,
        } = *work;
        if let Some(multipart) = multipart {
            self.execute_multipart_copy(&source, &key, &copy_source, must_be_new, multipart)
                .await?;
        } else {
            let _slot = self.tuning.requests.acquire().await;
            let request = self
                .client
                .copy_object()
                .bucket(&self.options.bucket)
                .key(&key)
                .copy_source(&copy_source)
                .copy_source_if_match(&source.etag)
                .set_website_redirect_location(
                    source_head.website_redirect_location().map(str::to_owned),
                )
                .metadata_directive(MetadataDirective::Copy)
                .tagging_directive(TaggingDirective::Copy)
                .set_storage_class(self.args.s3_metadata.storage_class.then(|| {
                    desired_head
                        .storage_class()
                        .cloned()
                        .unwrap_or(StorageClass::Standard)
                }))
                .set_if_none_match(must_be_new.then(|| "*".to_owned()));
            let request = if explicit {
                request
                    .metadata_directive(MetadataDirective::Replace)
                    .set_metadata(desired_head.metadata().cloned())
                    .set_content_type(desired_head.content_type().map(str::to_owned))
                    .set_content_encoding(desired_head.content_encoding().map(str::to_owned))
                    .set_content_language(desired_head.content_language().map(str::to_owned))
                    .set_content_disposition(desired_head.content_disposition().map(str::to_owned))
                    .set_cache_control(desired_head.cache_control().map(str::to_owned))
            } else {
                request
            };
            let expires = desired_head.expires_string().map(str::to_owned);
            request
                .customize()
                .map_request(move |mut request| {
                    if explicit {
                        if let Some(expires) = &expires {
                            request
                                .headers_mut()
                                .try_insert("expires", expires.clone())?;
                        }
                    }
                    Ok::<_, aws_smithy_runtime_api::http::HttpError>(request)
                })
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("S3 server-side copy failed")?;
            self.tuning.requests.completed(source.size);
            self.progress.add_bytes(source.size);
        }
        Ok(Some(source.size))
    }

    async fn abort_prepared_copy(&self, work: &PreparedCopy) {
        if let Some(multipart) = &work.multipart {
            let _slot = self.tuning.requests.acquire().await;
            if let Err(error) = self
                .client
                .abort_multipart_upload()
                .bucket(&self.options.bucket)
                .key(&work.key)
                .upload_id(&multipart.id)
                .send()
                .await
            {
                self.progress.eprintln(&format!(
                    "S3 multipart cleanup failed for {:?}: {}",
                    work.key,
                    error.into_service_error()
                ));
            }
        }
    }

    async fn authorize_copy(&self, work: &PreparedCopy) -> Result<()> {
        use crate::s3::authorization::Unsigned;
        if self.authorization.is_none() {
            return Ok(());
        }
        let mut requests = Vec::new();
        let copy = |request: Unsigned| {
            request
                .header("x-amz-copy-source", &work.copy_source)
                .header("x-amz-copy-source-if-match", &work.source.etag)
        };
        if let Some(multipart) = &work.multipart {
            requests.push(Unsigned::new("DELETE", &work.key).query("uploadId", &multipart.id));
            for index in 0..work.source.size.div_ceil(multipart.part_size) {
                let start = index * multipart.part_size;
                let end = (start + multipart.part_size).min(work.source.size) - 1;
                requests.push(
                    copy(
                        Unsigned::new("PUT", &work.key)
                            .query("uploadId", &multipart.id)
                            .query("partNumber", &(index + 1).to_string()),
                    )
                    .header("x-amz-copy-source-range", &format!("bytes={start}-{end}")),
                );
            }
            let mut complete = Unsigned::new("POST", &work.key).query("uploadId", &multipart.id);
            if work.must_be_new {
                complete = complete.header("if-none-match", "*");
            }
            requests.push(complete);
        } else {
            let mut request = copy(Unsigned::new("PUT", &work.key))
                .header(
                    "x-amz-metadata-directive",
                    if work.explicit { "REPLACE" } else { "COPY" },
                )
                .header("x-amz-tagging-directive", "COPY");
            if let Some(redirect) = work.source_head.website_redirect_location() {
                request = request.header("x-amz-website-redirect-location", redirect);
            }
            if work.explicit {
                if let Some(metadata) = work.desired_head.metadata() {
                    for (name, value) in metadata {
                        request = request.header(&format!("x-amz-meta-{name}"), value);
                    }
                }
            }
            if self.args.s3_metadata.storage_class {
                request = request.header(
                    "x-amz-storage-class",
                    super::super::metadata_fields::storage_class(&work.desired_head),
                );
            }
            if work.must_be_new {
                request = request.header("if-none-match", "*");
            }
            requests.push(request);
        }
        self.authorize_requests(requests).await
    }

    async fn selected_tags(
        &self,
        bucket: &str,
        key: &str,
        head: &HeadObjectOutput,
    ) -> Result<Vec<Tag>> {
        if head.tag_count() == Some(0) {
            return Ok(Vec::new());
        }
        let _slot = self.tuning.requests.acquire().await;
        self.check_cancelled()?;
        let mut tags = self
            .client
            .get_object_tagging()
            .bucket(bucket)
            .key(key)
            .set_version_id(head.version_id().map(str::to_owned))
            .send()
            .await
            .context("read explicitly selected S3 tags")?
            .tag_set;
        tags.sort_by(|a, b| a.key().cmp(b.key()).then_with(|| a.value().cmp(b.value())));
        Ok(tags)
    }

    async fn prepare_multipart_copy(
        &self,
        source: &Object,
        metadata: HeadObjectOutput,
        key: &str,
        selected_tags: Option<&[Tag]>,
    ) -> Result<PreparedCopyMultipart> {
        let bucket = self.options.route.source_bucket().unwrap();
        let part_size = self.part_size(source.size);
        anyhow::ensure!(
            part_size <= 5 * 1024 * 1024 * 1024,
            "object exceeds the S3 multipart size limit"
        );
        let setup_slot = self.tuning.requests.acquire().await;
        self.check_cancelled()?;
        let tagging = if let Some(tags) = selected_tags {
            super::super::metadata_copy::encode_tags(tags)
        } else if metadata.tag_count() == Some(0) {
            String::new()
        } else if self.copy_tagging_unsupported.load(Relaxed) {
            anyhow::ensure!(
                metadata.tag_count().is_none_or(|count| count <= 0),
                "source has tags but S3 GetObjectTagging is unsupported; refusing to drop known tags"
            );
            String::new()
        } else {
            // A missing count is unknown. Only explicit lack of tagging support
            // permits copying without tags; permission failures remain fatal.
            let tags = self
                .client
                .get_object_tagging()
                .bucket(bucket)
                .key(&source.key)
                .set_version_id(source.version.clone())
                .send()
                .await;
            let tags = match tags {
                Ok(tags) => Some(tags),
                Err(e)
                    if e.raw_response().is_some_and(|r| r.status().as_u16() == 501)
                        && metadata.tag_count().is_none_or(|count| count <= 0) =>
                {
                    if !self.copy_tagging_unsupported.swap(true, Relaxed) {
                        self.progress.eprintln(
                            "Warning: S3 GetObjectTagging is unsupported (HTTP 501); continuing without tags for objects with an unknown tag count. Tags may be omitted.",
                        );
                    }
                    None
                }
                Err(e) => {
                    let permission = if source.version.is_some() {
                        "s3:GetObjectVersionTagging"
                    } else {
                        "s3:GetObjectTagging"
                    };
                    let operation = format!(
                        "S3 GetObjectTagging for multipart copy (reading source tags requires {permission} on AWS)"
                    );
                    let detail = client::failure(&operation, &e);
                    return Err(anyhow::Error::new(e.into_service_error()).context(detail));
                }
            };
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            if let Some(tags) = tags {
                for tag in tags.tag_set() {
                    serializer.append_pair(tag.key(), tag.value());
                }
            }
            serializer.finish().replace('+', "%20")
        };
        let created = self
            .client
            .create_multipart_upload()
            .bucket(&self.options.bucket)
            .key(key)
            .set_metadata(metadata.metadata().cloned())
            .set_storage_class(self.args.s3_metadata.storage_class.then(|| {
                metadata
                    .storage_class()
                    .cloned()
                    .unwrap_or(StorageClass::Standard)
            }))
            .set_content_type(metadata.content_type().map(str::to_owned))
            .set_content_encoding(metadata.content_encoding().map(str::to_owned))
            .set_content_language(metadata.content_language().map(str::to_owned))
            .set_content_disposition(metadata.content_disposition().map(str::to_owned))
            .set_cache_control(metadata.cache_control().map(str::to_owned))
            .set_website_redirect_location(metadata.website_redirect_location().map(str::to_owned))
            .set_tagging((!tagging.is_empty()).then_some(tagging))
            .customize()
            .map_request(move |mut request| {
                // Expires is an opaque HTTP hint. Providers can retain values
                // such as "0" which the SDK's typed date setter cannot represent.
                if let Some(expires) = metadata.expires_string() {
                    request
                        .headers_mut()
                        .try_insert("expires", expires.to_owned())?;
                }
                Ok::<_, aws_smithy_runtime_api::http::HttpError>(request)
            })
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        let id = created
            .upload_id()
            .context("S3 omitted multipart upload ID")?
            .to_owned();
        drop(setup_slot);
        Ok(PreparedCopyMultipart { id, part_size })
    }

    async fn execute_multipart_copy(
        &self,
        source: &Object,
        key: &str,
        copy_source: &str,
        new: bool,
        prepared: PreparedCopyMultipart,
    ) -> Result<()> {
        let PreparedCopyMultipart { id, part_size } = prepared;
        let id = id.as_str();
        let failed = std::sync::atomic::AtomicBool::new(false);
        let result: Result<()> = async {
            let mut parts = stream::iter(0..source.size.div_ceil(part_size))
                .take_while(|_| std::future::ready(!failed.load(Relaxed)))
                .map(|index| {
                    let failed = &failed;
                    async move {
                        anyhow::ensure!(!failed.load(Relaxed), "another server-copy part failed");
                        let _slot = self.tuning.requests.acquire().await;
                        self.check_cancelled()?;
                        anyhow::ensure!(!failed.load(Relaxed), "another server-copy part failed");
                        let start = index * part_size;
                        let end = (start + part_size).min(source.size) - 1;
                        let output = self
                            .client
                            .upload_part_copy()
                            .bucket(&self.options.bucket)
                            .key(key)
                            .upload_id(id)
                            .part_number((index + 1) as i32)
                            .copy_source(copy_source)
                            .copy_source_if_match(&source.etag)
                            .copy_source_range(format!("bytes={start}-{end}"))
                            .send()
                            .await
                            .map_err(|e| e.into_service_error())?;
                        let part = output
                            .copy_part_result()
                            .context("S3 omitted copy part result")?;
                        let part = CompletedPart::builder()
                            .part_number((index + 1) as i32)
                            .e_tag(part.e_tag().context("S3 omitted copied part ETag")?)
                            .build();
                        self.tuning.requests.completed(end - start + 1);
                        self.progress.add_bytes(end - start + 1);
                        Ok(part)
                    }
                })
                .buffer_unordered(self.part_workers())
                .inspect(|result: &Result<CompletedPart>| {
                    if result.is_err() {
                        failed.store(true, Relaxed);
                    }
                })
                // Drain started requests before aborting: dropping their futures
                // could leave provider-side parts racing cleanup.
                .collect::<Vec<Result<_>>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            parts.sort_by_key(|part| part.part_number());
            let _slot = self.tuning.requests.acquire().await;
            self.check_cancelled()?;
            self.client
                .complete_multipart_upload()
                .bucket(&self.options.bucket)
                .key(key)
                .upload_id(id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .set_if_none_match(new.then(|| "*".to_owned()))
                .send()
                .await
                .map_err(|e| e.into_service_error())?;
            Ok(())
        }
        .await;
        if result.is_err() {
            let _slot = self.tuning.requests.acquire().await;
            if let Err(error) = self
                .client
                .abort_multipart_upload()
                .bucket(&self.options.bucket)
                .key(key)
                .upload_id(id)
                .send()
                .await
            {
                self.progress.eprintln(&format!(
                    "S3 multipart cleanup failed for {key:?}, upload {id:?}: {}",
                    error.into_service_error()
                ));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_distinguishes_exact_keys_from_prefixes() {
        let keys = |values: &[(&str, bool)]| {
            values
                .iter()
                .map(|(key, prefix)| ((*key).to_owned(), *prefix))
                .collect::<Vec<_>>()
        };
        for (sources, targets, overlap) in [
            (vec![("a/child", false)], vec![("a", false)], false),
            (vec![("a", false)], vec![("a/child", false)], false),
            (vec![("a/", false)], vec![("a/child", false)], false),
            (vec![("a", false)], vec![("a", false)], true),
            (vec![("a/", true)], vec![("a/child", false)], true),
            (vec![("a/child", false)], vec![("a/", true)], true),
            (vec![("a/", true)], vec![("a/sub/", true)], true),
            (vec![("a/", true)], vec![("ab/", true)], false),
            (vec![("a", false)], vec![("", true)], true),
            (vec![("", true)], vec![("a", false)], true),
        ] {
            assert_eq!(
                check_overlap(&keys(&sources), &keys(&targets)).is_err(),
                overlap,
                "{sources:?} {targets:?}"
            );
        }
        // Exercise manifest-sized input; the former nested loop had 400M pairs.
        let sources: Vec<_> = (0..20_000)
            .map(|i| (format!("source/{i}"), false))
            .collect();
        let targets: Vec<_> = (0..20_000)
            .map(|i| (format!("target/{i}"), false))
            .collect();
        check_overlap(&sources, &targets).unwrap();
    }

    #[test]
    fn syq_hashes_then_provider_sha256_decide_matching_contents_and_crcs_never_do() {
        let object = |etag: &str, hash: Option<(&str, HashAlgorithm)>| Object {
            key: "data".into(),
            size: 4,
            etag: etag.into(),
            version: None,
            metadata: hash.map(|(hash, algorithm)| Metadata {
                kind: ObjectKind::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 10,
                nsec: 0,
                hash: Some(hash.into()),
                hash_algorithm: algorithm,
            }),
            mtime: 10,
        };
        let blake3 = |hash| Some((hash, HashAlgorithm::Blake3));
        let none = HeadObjectOutput::builder().build();
        let full = |kind: ChecksumType, sha256: Option<&str>, crc: Option<&str>| {
            HeadObjectOutput::builder()
                .checksum_type(kind)
                .set_checksum_sha256(sha256.map(str::to_owned))
                .set_checksum_crc64_nvme(crc.map(str::to_owned))
                .set_checksum_crc32_c(crc.map(str::to_owned))
                .set_checksum_crc32(crc.map(str::to_owned))
                .set_checksum_sha1(crc.map(str::to_owned))
                .build()
        };
        let sha = |value| full(ChecksumType::FullObject, Some(value), None);
        let crc = |value| full(ChecksumType::FullObject, None, Some(value));
        for (case, source, old, quick, same) in [
            (
                "equal hashes match whatever else differs",
                (object("a", blake3("h")), sha("x")),
                (object("b", blake3("h")), sha("y")),
                false,
                true,
            ),
            (
                "different hashes differ whatever else agrees",
                (object("a", blake3("h")), sha("x")),
                (object("a", blake3("i")), sha("x")),
                true,
                false,
            ),
            (
                "SHA-256 decides when a hash is missing: equal",
                (object("a", blake3("h")), sha("x")),
                (object("b", None), sha("x")),
                false,
                true,
            ),
            (
                "SHA-256 decides when a hash is missing: different",
                (object("a", None), sha("x")),
                (object("a", None), sha("y")),
                true,
                false,
            ),
            (
                "hashes of different kinds leave it to SHA-256",
                (object("a", blake3("h")), sha("x")),
                (object("b", Some(("i", HashAlgorithm::Sha256))), sha("x")),
                false,
                true,
            ),
            (
                "a composite SHA-256 depends on parts and never decides",
                (
                    object("a", None),
                    full(ChecksumType::Composite, Some("x"), None),
                ),
                (
                    object("b", None),
                    full(ChecksumType::Composite, Some("x"), None),
                ),
                false,
                false,
            ),
            (
                "equal CRCs and SHA-1 never decide",
                (object("a", None), crc("c")),
                (object("b", None), crc("c")),
                false,
                false,
            ),
            (
                "different CRCs never decide either",
                (object("a", None), crc("c")),
                (object("a", None), crc("d")),
                false,
                true,
            ),
            (
                "without hashes or SHA-256, equal ETags match",
                (object("a", None), none.clone()),
                (object("a", None), none.clone()),
                false,
                true,
            ),
            (
                "without hashes or SHA-256, different ETags differ",
                (object("a", None), none.clone()),
                (object("b", None), sha("x")),
                false,
                false,
            ),
            (
                "the stored-time quick check applies without hashes or SHA-256",
                (object("a", blake3("h")), none.clone()),
                (object("b", None), none.clone()),
                true,
                true,
            ),
        ] {
            assert_eq!(
                same_contents((&source.0, &source.1), (&old.0, &old.1), quick),
                same,
                "{case}"
            );
        }
        let mut larger = object("a", blake3("h"));
        larger.size += 1;
        assert!(!same_contents(
            (&larger, &none),
            (&object("a", blake3("h")), &none),
            true
        ));
        // Checksums are worth asking for only when SHA-256 could decide.
        assert!(sha256_could_decide(
            &object("a", None),
            &object("b", blake3("h"))
        ));
        assert!(!sha256_could_decide(
            &object("a", blake3("h")),
            &object("b", blake3("i"))
        ));
        assert!(!sha256_could_decide(&larger, &object("b", None)));
    }
}
