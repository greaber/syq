//! Same-service copies never read object bodies through the invoking machine.
use super::*;
use aws_sdk_s3::{
    operation::head_object::HeadObjectOutput,
    types::{ChecksumType, MetadataDirective, TaggingDirective},
};

// Compare only fields whose meaning survives a copy. LastModified, encryption,
// storage class, version IDs and ETags are not user metadata.
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
}

fn full_checksum_match(a: &HeadObjectOutput, b: &HeadObjectOutput) -> Option<bool> {
    // Composite checksums depend on part boundaries. A different value cannot
    // establish a content difference, so leave those to the ordinary quick check.
    if a.checksum_type() != Some(&ChecksumType::FullObject)
        || b.checksum_type() != Some(&ChecksumType::FullObject)
    {
        return None;
    }
    let mut found = false;
    for (left, right) in [
        (a.checksum_sha256(), b.checksum_sha256()),
        (a.checksum_sha1(), b.checksum_sha1()),
        (a.checksum_crc64_nvme(), b.checksum_crc64_nvme()),
        (a.checksum_crc32_c(), b.checksum_crc32_c()),
        (a.checksum_crc32(), b.checksum_crc32()),
    ] {
        if let (Some(left), Some(right)) = (left, right) {
            found = true;
            if left != right {
                return Some(false);
            }
        }
    }
    found.then_some(true)
}

fn unchanged(source: &Object, old: &Object, a: &HeadObjectOutput, b: &HeadObjectOutput) -> bool {
    source.kind() == old.kind()
        && source.size == old.size
        && same_metadata(a, b)
        && full_checksum_match(a, b)
            .unwrap_or_else(|| source.etag == old.etag || source.metadata.is_some())
}

fn copy_destination_key(job: &Download) -> String {
    if job.key.ends_with('/') && job.size == 0 {
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

impl Engine {
    fn copy_error(&self, error: anyhow::Error) -> anyhow::Error {
        if error
            .downcast_ref::<client::RequestFailure>()
            .is_some_and(|e| e.region_mismatch())
        {
            error.context(format!("S3-to-S3 source bucket {:?} and destination bucket {:?} are configured with region {}; --s3-region applies to both endpoints: use the reported region if both buckets are there; buckets in different regions are not supported by this route",
                self.options.source_bucket.as_deref().unwrap(), self.options.bucket,
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

    pub(super) async fn copy_head(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Object, HeadObjectOutput)>> {
        let _slot = self.tuning.requests.acquire().await;
        let Some(output) = client::head_output(
            &self.client,
            bucket,
            key,
            Some(&self.copy_checksum_unsupported),
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
        let (plan, prune) = self.download_plan(&target).await?;
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
        parallel(plan, workers, |mut job| {
            let engine = self.clone();
            async move {
                engine.check_cancelled()?;
                let mut kind = "file";
                let result = engine
                    .copy_object(&mut job, &mut kind)
                    .await
                    .map_err(|error| engine.copy_error(error));
                engine.settle(job.key.as_bytes(), &job.path, kind, &result, None);
                Ok(result.ok().flatten())
            }
        })
        .await?;
        self.prune(prune, None).await?;
        Ok(())
    }

    async fn copy_object(
        &self,
        job: &mut Download,
        kind: &mut &'static str,
    ) -> Result<Option<u64>> {
        let source_bucket = self.options.source_bucket.as_deref().unwrap();
        let key = copy_destination_key(job);
        if job.path.is_empty() && job.key.ends_with('/') {
            *kind = "dir";
            return Ok(None);
        }
        local::key_path(key.trim_end_matches('/').as_bytes())?;
        anyhow::ensure!(key.len() <= 1024, "S3 key exceeds 1024 bytes");
        let destination = async {
            if self
                .upload_keys
                .get()
                .is_some_and(|keys| !keys.contains_key(&key))
            {
                Ok(None)
            } else {
                self.copy_head(&self.options.bucket, &key).await
            }
        };
        let source = async {
            match job.copy_source.take() {
                Some(source) => Ok(Some(*source)),
                None => self.copy_head(source_bucket, &job.key).await,
            }
        };
        let (source, existing) = tokio::try_join!(source, destination)?;
        let (source, source_head) = source.context("S3 copy source disappeared")?;
        anyhow::ensure!(
            source.size == job.size,
            "S3 source size changed after planning"
        );
        *kind = match source.kind() {
            "dir" => "dir",
            "symlink" => "symlink",
            _ => "file",
        };
        if (self.args.ignore_existing && existing.is_some())
            || (self.args.existing && existing.is_none())
        {
            return Ok(None);
        }
        let source_time = source.metadata.as_ref().map_or(source.mtime, |m| m.mtime);
        if let Some((old, old_head)) = &existing {
            let old_time = old.metadata.as_ref().map_or(old.mtime, |m| m.mtime);
            if self.args.update && old_time > source_time {
                return Ok(None);
            }
            if unchanged(&source, old, &source_head, old_head) {
                self.progress
                    .bytes_unchanged
                    .fetch_add(source.size, Relaxed);
                return Ok(None);
            }
        }
        if self.args.dry_run {
            self.progress.bytes_done.fetch_add(source.size, Relaxed);
            return Ok(Some(source.size));
        }
        self.check_cancelled()?;

        let _interval = self.progress.copying_interval();
        let copy_source = encoded_source(source_bucket, &source);
        let must_be_new = self.args.ignore_existing || self.args.target_existence == Existence::New;
        // Respect explicit part sizing for both performance control and exercising
        // multipart copying with small disposable fixtures.
        if source.size <= self.copy_request_limit(source.size) {
            let _slot = self.tuning.requests.acquire().await;
            self.client
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
                .set_if_none_match(must_be_new.then(|| "*".to_owned()))
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("S3 server-side copy failed")?;
            self.tuning.requests.completed(source.size);
            self.progress.add_bytes(source.size);
        } else {
            self.multipart_copy(&source, source_head, &key, &copy_source, must_be_new)
                .await?;
        }
        Ok(Some(source.size))
    }

    async fn multipart_copy(
        &self,
        source: &Object,
        metadata: HeadObjectOutput,
        key: &str,
        copy_source: &str,
        new: bool,
    ) -> Result<()> {
        let bucket = self.options.source_bucket.as_deref().unwrap();
        let part_size = self.part_size(source.size);
        anyhow::ensure!(
            part_size <= 5 * 1024 * 1024 * 1024,
            "object exceeds the S3 multipart size limit"
        );
        let setup_slot = self.tuning.requests.acquire().await;
        self.check_cancelled()?;
        let tagging = if metadata.tag_count() == Some(0) {
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
            .context("S3 omitted multipart upload ID")?;
        drop(setup_slot);
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
}
