//! Same-service copies never read object bodies through the invoking machine.
use super::super::{
    authorization::Unsigned,
    metadata_copy::{encode_tags, Condition, Desired, Prepared},
};
use super::*;
use aws_sdk_s3::{
    operation::head_object::HeadObjectOutput,
    types::{ChecksumType, Tag, Tagging},
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

/// Checksums the provider keeps for the whole object, rather than combined
/// from parts, that can decide whether contents match: SHA-256, then
/// CRC64NVME. A 64-bit CRC is long enough that unrelated contents do not
/// match by chance, and AWS now adds it to new objects by default, including
/// one copied in a single request from a multipart source, whose ETag never
/// matches. The 32-bit CRCs collide too easily, and SHA-1 is rarely
/// present; neither decides.
fn full_object_checksums(head: &HeadObjectOutput) -> [Option<&str>; 2] {
    if head.checksum_type() != Some(&ChecksumType::FullObject) {
        return [None, None];
    }
    [head.checksum_sha256(), head.checksum_crc64_nvme()]
}

/// Whether provider checksums could decide a comparison, so the HEADs must
/// ask for them.
fn checksums_could_decide(source: &Object, old: &Object) -> bool {
    source.kind() == ObjectKind::File
        && old.kind() == ObjectKind::File
        && source.size == old.size
        && syq_hashes(source, old).is_none()
}

/// Whether an existing destination object holds the source's contents.
/// Syq's own whole-file hashes decide when both objects carry one of the same
/// kind. Otherwise the first full-object checksum the provider reports for
/// both, SHA-256 or else CRC64NVME, decides. Otherwise equal ETags count, and
/// so does `quick_check`: matching stored size and modification time.
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
    let pairs = full_object_checksums(source_head)
        .into_iter()
        .zip(full_object_checksums(old_head));
    for pair in pairs {
        if let (Some(a), Some(b)) = pair {
            return a == b;
        }
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
    /// A copy of the source's contents.
    Ready(Box<Prepared>),
    /// A copy of the destination onto itself with the source's metadata.
    Metadata(Box<Prepared>),
    Tags {
        key: String,
        version: Option<String>,
        tags: Vec<Tag>,
        size: u64,
    },
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
                    if let CopyPreparation::Ready(work) | CopyPreparation::Metadata(work) = work {
                        self.abort_prepared_copy(work).await;
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
        let listed = self.upload_keys.get().and_then(|listed| listed.size(&key));
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
                && checksums_could_decide(&source, old)
                && full_object_checksums(old_head).iter().any(Option::is_some)
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
                // The command's storage class replaces the copied one in every
                // request, so expect it, or each run would rewrite the object.
                if self.args.s3_metadata.storage_class {
                    let added = self
                        .options
                        .headers_for("PUT", [])
                        .filter(|header| header.0 == "x-amz-storage-class")
                        .last();
                    if let Some(super::super::Header(_, class)) = added {
                        desired_head.storage_class = Some(class.as_str().into());
                    }
                }
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
                let mut request = Unsigned::new("PUT", &key).query("tagging", "");
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
            let update = Prepared::prepare_selected(
                &self.client,
                &self.options,
                &key,
                old_head,
                Desired {
                    head: desired_head,
                    tags: selected_tags,
                },
                self.part_size(source.size),
                self.copy_request_limit(source.size),
            )
            .await?;
            drop(_slot);
            if let Err(error) = self.authorize_requests(update.requests()).await {
                self.abort_prepared_copy(&update).await;
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
        let must_be_new = self.args.ignore_existing
            || self.args.target_existence == Existence::New
            || (self.args.protects_existing_contents() && existing.is_none());
        let (request, headers) = self.copy_request(
            &key,
            &source,
            &desired_head,
            explicit.flags() != 0 || matching_contents,
            must_be_new,
        );
        let mut copy = Prepared::new(request, source.size, must_be_new.then_some(Condition::New));
        if source.size > self.copy_request_limit(source.size) {
            let selected_tags = if self.args.s3_metadata.tags {
                Some(
                    self.selected_tags(source_bucket, &source.key, &source_head)
                        .await?,
                )
            } else {
                None
            };
            let _slot = self.tuning.requests.acquire().await;
            self.check_cancelled()?;
            copy.start_multipart(
                &self.client,
                &self.options.bucket,
                self.part_size(source.size),
                headers,
                self.source_tagging(&source, &desired_head, selected_tags.as_deref()),
            )
            .await?;
        }
        if self.authorization.is_some() {
            if let Err(error) = self.authorize_requests(copy.requests()).await {
                self.abort_prepared_copy(&copy).await;
                return Err(error);
            }
        }
        Ok(CopyPreparation::Ready(Box::new(copy)))
    }

    /// The single CopyObject request, and the headers CreateMultipartUpload
    /// takes when the copy needs parts. Native COPY keeps the source's
    /// metadata, so the single request names it only when replacing it.
    fn copy_request(
        &self,
        key: &str,
        source: &Object,
        desired: &HeadObjectOutput,
        replace: bool,
        must_be_new: bool,
    ) -> (Unsigned, BTreeMap<String, String>) {
        let mut object = super::super::metadata_copy::object_headers(desired);
        if self.args.s3_metadata.storage_class {
            object.insert(
                "x-amz-storage-class".into(),
                super::super::metadata_fields::storage_class(desired).into(),
            );
        }
        let mut request = Unsigned::new("PUT", key)
            .header(
                "x-amz-copy-source",
                &encoded_source(self.options.route.source_bucket().unwrap(), source),
            )
            .header("x-amz-copy-source-if-match", &source.etag)
            .header(
                "x-amz-metadata-directive",
                if replace { "REPLACE" } else { "COPY" },
            )
            .header("x-amz-tagging-directive", "COPY");
        for (name, value) in &object {
            if replace
                || matches!(
                    name.as_str(),
                    "x-amz-website-redirect-location" | "x-amz-storage-class"
                )
            {
                request = request.header(name, value);
            }
        }
        if must_be_new {
            request = request.header("if-none-match", "*");
        }
        // Headers the command adds replace the copy's own, as the client adds
        // them to the request, so the description is what is sent.
        for super::super::Header(name, value) in self.options.headers_for("PUT", []) {
            request = request.header(name, value);
        }
        for super::super::Header(name, value) in self.options.headers_for("POST", ["uploads"]) {
            object.insert(name.clone(), value.clone());
        }
        (request, object)
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
        work.execute_counted(
            &self.client,
            &self.options.bucket,
            self.part_workers(),
            || async {
                let slot = self.tuning.requests.acquire().await;
                self.check_cancelled()?;
                Ok(slot)
            },
            || self.tuning.requests.acquire(),
            |bytes| {
                self.tuning.requests.completed(bytes);
                self.progress.add_bytes(bytes);
            },
        )
        .await?;
        Ok(Some(work.size))
    }

    async fn abort_prepared_copy(&self, work: &Prepared) {
        if work.is_multipart() {
            let _slot = self.tuning.requests.acquire().await;
            work.abort(&self.client, &self.options.bucket).await;
        }
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

    /// The source's tags for a multipart copy's destination, encoded.
    async fn source_tagging(
        &self,
        source: &Object,
        head: &HeadObjectOutput,
        selected: Option<&[Tag]>,
    ) -> Result<String> {
        if let Some(tags) = selected {
            return Ok(encode_tags(tags));
        }
        if head.tag_count() == Some(0) {
            return Ok(String::new());
        }
        if self.copy_tagging_unsupported.load(Relaxed) {
            anyhow::ensure!(
                head.tag_count().is_none_or(|count| count <= 0),
                "source has tags but S3 GetObjectTagging is unsupported; refusing to drop known tags"
            );
            return Ok(String::new());
        }
        // A missing count is unknown. Only explicit lack of tagging support
        // permits copying without tags; permission failures remain fatal.
        match self
            .client
            .get_object_tagging()
            .bucket(self.options.route.source_bucket().unwrap())
            .key(&source.key)
            .set_version_id(source.version.clone())
            .send()
            .await
        {
            Ok(tags) => Ok(encode_tags(tags.tag_set())),
            Err(e)
                if e.raw_response().is_some_and(|r| r.status().as_u16() == 501)
                    && head.tag_count().is_none_or(|count| count <= 0) =>
            {
                if !self.copy_tagging_unsupported.swap(true, Relaxed) {
                    self.progress.eprintln(
                        "Warning: S3 GetObjectTagging is unsupported (HTTP 501); continuing without tags for objects with an unknown tag count. Tags may be omitted.",
                    );
                }
                Ok(String::new())
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
                Err(anyhow::Error::new(e.into_service_error()).context(detail))
            }
        }
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
    fn syq_hashes_then_sha256_then_crc64nvme_decide_matching_contents() {
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
                .set_checksum_crc32_c(crc.map(str::to_owned))
                .set_checksum_crc32(crc.map(str::to_owned))
                .set_checksum_sha1(crc.map(str::to_owned))
                .build()
        };
        let sha = |value| full(ChecksumType::FullObject, Some(value), None);
        // 32-bit CRCs and SHA-1, without CRC64NVME.
        let crc = |value| full(ChecksumType::FullObject, None, Some(value));
        let crc64 = |sha256: Option<&str>, value: &str| {
            HeadObjectOutput::builder()
                .checksum_type(ChecksumType::FullObject)
                .set_checksum_sha256(sha256.map(str::to_owned))
                .checksum_crc64_nvme(value)
                .checksum_crc32("same")
                .build()
        };
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
                "a multipart source and its single-request copy match by CRC64NVME",
                (object("a-3", None), crc64(None, "c")),
                (object("b", None), crc64(None, "c")),
                false,
                true,
            ),
            (
                "different CRC64NVME differ whatever the ETags and times say",
                (object("a", None), crc64(None, "c")),
                (object("a", None), crc64(None, "d")),
                true,
                false,
            ),
            (
                "SHA-256 decides before CRC64NVME",
                (object("a", None), crc64(Some("x"), "c")),
                (object("a", None), crc64(Some("y"), "c")),
                false,
                false,
            ),
            (
                "a composite CRC64NVME never decides",
                (
                    object("a", None),
                    HeadObjectOutput::builder()
                        .checksum_type(ChecksumType::Composite)
                        .checksum_crc64_nvme("c")
                        .build(),
                ),
                (object("b", None), crc64(None, "c")),
                false,
                false,
            ),
            (
                "equal 32-bit CRCs and SHA-1 never decide",
                (object("a", None), crc("c")),
                (object("b", None), crc("c")),
                false,
                false,
            ),
            (
                "different 32-bit CRCs never decide either",
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
        // Checksums are worth asking for only when they could decide.
        assert!(checksums_could_decide(
            &object("a", None),
            &object("b", blake3("h"))
        ));
        assert!(!checksums_could_decide(
            &object("a", blake3("h")),
            &object("b", blake3("i"))
        ));
        assert!(!checksums_could_decide(&larger, &object("b", None)));
    }
}
