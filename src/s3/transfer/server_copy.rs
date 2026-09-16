//! Same-service copies never read object bodies through the invoking machine.
use super::*;
use aws_sdk_s3::types::{MetadataDirective, TaggingDirective};

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

impl Engine {
    pub(super) async fn server_copy(self: Arc<Self>) -> Result<()> {
        let target = local::key_path(&self.args.locations.last().unwrap().path)?;
        let (plan, prune) = self.download_plan(&target).await?;
        self.check_upload_placement(&[]).await?;
        if self.args.placement == Placement::As
            && plan.len() == 1
            && plan[0].path == target
            && !plan[0].key.ends_with('/')
            && !target.is_empty()
            && !client::list(&self.client, &self.options.bucket, &format!("{target}/"))
                .await?
                .is_empty()
        {
            bail!("S3 destination is a prefix, not an object");
        }
        let workers = self.object_workers(plan.iter().map(|p| p.size))?;
        self.progress.files_total.store(plan.len() as u64, Relaxed);
        self.progress
            .bytes_total
            .store(plan.iter().map(|p| p.size).sum(), Relaxed);
        self.progress.scan_done.store(true, Relaxed);
        parallel(plan, workers, |job| {
            let engine = self.clone();
            async move {
                engine.check_cancelled()?;
                let mut kind = "file";
                let result = engine.copy_object(&job, &mut kind).await;
                engine.settle(job.key.as_bytes(), &job.path, kind, &result, None);
                Ok(())
            }
        })
        .await?;
        if self.args.delete && self.progress.errors.load(Relaxed) == 0 {
            self.prune(prune, None).await?;
        }
        Ok(())
    }

    async fn copy_object(&self, job: &Download, kind: &mut &'static str) -> Result<Option<u64>> {
        let source_bucket = self.options.source_bucket.as_deref().unwrap();
        let _slot = self.tuning.requests.acquire().await;
        let source = client::head(&self.client, source_bucket, &job.key)
            .await?
            .context("S3 copy source disappeared")?;
        anyhow::ensure!(
            source.size == job.size,
            "S3 source size changed after planning"
        );
        *kind = match source.kind() {
            "dir" => "dir",
            "symlink" => "symlink",
            _ => "file",
        };
        let key = if *kind == "dir" {
            if job.path.is_empty() {
                return Ok(None);
            }
            format!("{}/", job.path)
        } else {
            job.path.clone()
        };
        local::key_path(key.trim_end_matches('/').as_bytes())?;
        anyhow::ensure!(key.len() <= 1024, "S3 key exceeds 1024 bytes");
        let existing = client::head(&self.client, &self.options.bucket, &key).await?;
        if (self.args.ignore_existing && existing.is_some())
            || (self.args.existing && existing.is_none())
        {
            return Ok(None);
        }
        let source_time = source.metadata.as_ref().map_or(source.mtime, |m| m.mtime);
        if let Some(old) = &existing {
            let old_time = old.metadata.as_ref().map_or(old.mtime, |m| m.mtime);
            if self.args.update && old_time > source_time {
                return Ok(None);
            }
            if old.kind() == source.kind()
                && old.size == source.size
                && old_time == source_time
                && old.metadata == source.metadata
            {
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
        self.pace(source.size).await?;
        let copy_source = encoded_source(source_bucket, &source);
        // Respect explicit part sizing for both performance control and exercising
        // multipart copying with small disposable fixtures.
        if source.size <= self.part_size(source.size).min(5 * 1024 * 1024 * 1024) {
            self.client
                .copy_object()
                .bucket(&self.options.bucket)
                .key(&key)
                .copy_source(&copy_source)
                .copy_source_if_match(&source.etag)
                .set_website_redirect_location(source.website_redirect.clone())
                .metadata_directive(MetadataDirective::Copy)
                .tagging_directive(TaggingDirective::Copy)
                .set_if_none_match(existing.is_none().then(|| "*".to_owned()))
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("S3 server-side copy failed")?;
        } else {
            self.multipart_copy(&source, &key, &copy_source, existing.is_none())
                .await?;
        }
        self.progress.bytes_done.fetch_add(source.size, Relaxed);
        Ok(Some(source.size))
    }

    async fn multipart_copy(
        &self,
        source: &Object,
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
        let metadata = self
            .client
            .head_object()
            .bucket(bucket)
            .key(&source.key)
            .if_match(&source.etag)
            .set_version_id(source.version.clone())
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        let tags = self
            .client
            .get_object_tagging()
            .bucket(bucket)
            .key(&source.key)
            .set_version_id(source.version.clone())
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        let tagging = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for tag in tags.tag_set() {
                serializer.append_pair(tag.key(), tag.value());
            }
            serializer.finish()
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
            .set_expires(
                metadata
                    .expires_string()
                    .map(|v| {
                        aws_smithy_types::DateTime::from_str(
                            v,
                            aws_smithy_types::date_time::Format::HttpDate,
                        )
                    })
                    .transpose()?,
            )
            .set_tagging((!tagging.is_empty()).then_some(tagging))
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        let id = created
            .upload_id()
            .context("S3 omitted multipart upload ID")?;
        let result: Result<()> = async {
            let mut parts = Vec::new();
            for index in 0..source.size.div_ceil(part_size) {
                self.check_cancelled()?;
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
                parts.push(
                    CompletedPart::builder()
                        .part_number((index + 1) as i32)
                        .e_tag(part.e_tag().context("S3 omitted copied part ETag")?)
                        .build(),
                );
            }
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
