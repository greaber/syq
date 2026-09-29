//! Change selected metadata without taking contents or other attributes from a
//! different object. Preparation also supports receivers whose requests must
//! all be authorized before the source connection closes.
use super::{authorization::Unsigned, client};
use anyhow::{Context, Result};
use aws_sdk_s3::{
    operation::head_object::HeadObjectOutput,
    types::{CompletedMultipartUpload, CompletedPart},
    Client,
};
use futures_util::{stream, StreamExt};
use std::{
    collections::HashMap,
    future::Future,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

pub(super) const SINGLE_LIMIT: u64 = 5 * 1024 * 1024 * 1024;

pub(super) struct Desired {
    pub head: HeadObjectOutput,
    /// None keeps destination tags; Some(empty) removes them all.
    pub tags: Option<Vec<aws_sdk_s3::types::Tag>>,
}

pub(super) fn encode_tags(tags: &[aws_sdk_s3::types::Tag]) -> String {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for tag in tags {
        encoded.append_pair(tag.key(), tag.value());
    }
    encoded.finish().replace('+', "%20")
}

#[derive(Clone)]
pub(crate) struct Prepared {
    request: Unsigned,
    pub(super) size: u64,
    multipart: Option<(String, u64)>,
}

impl Prepared {
    /// The caller holds its request permit during setup.
    pub(super) async fn prepare(
        client: &Client,
        options: &super::Options,
        key: &str,
        head: &HeadObjectOutput,
        metadata: HashMap<String, String>,
        part_size: u64,
        single_limit: u64,
    ) -> Result<Self> {
        let mut desired = head.clone();
        desired.metadata = Some(metadata);
        Self::prepare_selected(
            client,
            options,
            key,
            head,
            Desired {
                head: desired,
                tags: None,
            },
            part_size,
            single_limit,
        )
        .await
    }

    pub(super) async fn prepare_selected(
        client: &Client,
        options: &super::Options,
        key: &str,
        head: &HeadObjectOutput,
        desired: Desired,
        part_size: u64,
        single_limit: u64,
    ) -> Result<Self> {
        let size = u64::try_from(head.content_length().context("S3 omitted object size")?)?;
        let bucket = &options.bucket;
        // A metadata update is a self-copy, so it takes the object-writing headers.
        let overrides = options.headers_for("PUT", []).cloned().collect::<Vec<_>>();
        let mut request =
            client::metadata_update_request(bucket, key, head, &desired.head, &overrides)?;
        if let Some(tags) = &desired.tags {
            request = request
                .header("x-amz-tagging-directive", "REPLACE")
                .header("x-amz-tagging", &encode_tags(tags));
        }

        let mut prepared = Self {
            request,
            size,
            multipart: None,
        };
        if size <= single_limit.min(SINGLE_LIMIT) {
            return Ok(prepared);
        }
        // Enlarge parts for large objects without depending on upload tuning.
        let part_size = part_size.max(size.div_ceil(10_000)).max(5 << 20);
        anyhow::ensure!(
            part_size <= SINGLE_LIMIT,
            "object exceeds the S3 multipart size limit"
        );
        let tagging = if let Some(tags) = &desired.tags {
            encode_tags(tags)
        } else if head.tag_count() == Some(0) {
            String::new()
        } else {
            let tags = client
                .get_object_tagging()
                .bucket(bucket)
                .key(key)
                .set_version_id(head.version_id().map(str::to_owned))
                .send()
                .await
                .context("read destination tags before updating metadata")?;
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            for tag in tags.tag_set() {
                encoded.append_pair(tag.key(), tag.value());
            }
            encoded.finish().replace('+', "%20")
        };
        let headers = prepared.request.headers.clone();
        let created = client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key)
            .set_tagging((!tagging.is_empty()).then_some(tagging))
            .customize()
            .map_request(move |mut request| {
                for (name, value) in &headers {
                    if !matches!(
                        name.as_str(),
                        "x-amz-copy-source"
                            | "x-amz-copy-source-if-match"
                            | "x-amz-metadata-directive"
                            | "x-amz-tagging-directive"
                    ) {
                        request
                            .headers_mut()
                            .try_insert(name.clone(), value.clone())?;
                    }
                }
                Ok::<_, aws_smithy_runtime_api::http::HttpError>(request)
            })
            .send()
            .await
            .context("prepare multipart metadata update")?;
        prepared.multipart = Some((
            created
                .upload_id()
                .context("S3 omitted upload ID")?
                .to_owned(),
            part_size,
        ));
        Ok(prepared)
    }

    pub(super) fn matches(&self, etag: &str) -> bool {
        self.request.headers["x-amz-copy-source-if-match"] == etag
    }

    pub(super) fn key(&self) -> &str {
        &self.request.key
    }

    pub(super) fn requests(&self) -> Vec<Unsigned> {
        let Some((id, part_size)) = &self.multipart else {
            return vec![self.request.clone()];
        };
        let mut requests = vec![Unsigned::new("DELETE", &self.request.key).query("uploadId", id)];
        for index in 0..self.size.div_ceil(*part_size) {
            let start = index * part_size;
            let end = (start + part_size).min(self.size) - 1;
            requests.push(
                Unsigned::new("PUT", &self.request.key)
                    .query("uploadId", id)
                    .query("partNumber", &(index + 1).to_string())
                    .header(
                        "x-amz-copy-source",
                        &self.request.headers["x-amz-copy-source"],
                    )
                    .header(
                        "x-amz-copy-source-if-match",
                        &self.request.headers["x-amz-copy-source-if-match"],
                    )
                    .header("x-amz-copy-source-range", &format!("bytes={start}-{end}")),
            );
        }
        requests.push(
            Unsigned::new("POST", &self.request.key)
                .query("uploadId", id)
                .header(
                    "if-match",
                    &self.request.headers["x-amz-copy-source-if-match"],
                ),
        );
        requests
    }

    pub(crate) async fn abort(&self, client: &Client, bucket: &str) {
        if let Some((id, _)) = &self.multipart {
            if let Err(error) = client
                .abort_multipart_upload()
                .bucket(bucket)
                .key(&self.request.key)
                .upload_id(id)
                .send()
                .await
            {
                crate::output::diagnostic!(
                    "syq cp: could not confirm multipart metadata cleanup: {}",
                    error.into_service_error()
                );
            }
        }
    }

    pub(super) async fn execute<F, A, P>(
        &self,
        client: &Client,
        bucket: &str,
        workers: usize,
        acquire: F,
    ) -> Result<(Option<String>, Option<String>)>
    where
        F: Fn() -> A,
        A: Future<Output = Result<P>>,
    {
        let Some((id, part_size)) = &self.multipart else {
            let _permit = acquire().await?;
            return client::copy_metadata(client, bucket, self.request.clone()).await;
        };
        let failed = AtomicBool::new(false);
        let result = async {
            let mut parts = stream::iter(0..self.size.div_ceil(*part_size))
                .take_while(|_| std::future::ready(!failed.load(Relaxed)))
                .map(|index| {
                    let acquire = &acquire;
                    let failed = &failed;
                    async move {
                        let _permit = acquire().await?;
                        anyhow::ensure!(!failed.load(Relaxed), "another metadata copy part failed");
                        let start = index * part_size;
                        let end = (start + part_size).min(self.size) - 1;
                        let output = client
                            .upload_part_copy()
                            .bucket(bucket)
                            .key(&self.request.key)
                            .upload_id(id)
                            .part_number((index + 1) as i32)
                            .copy_source(&self.request.headers["x-amz-copy-source"])
                            .copy_source_if_match(
                                &self.request.headers["x-amz-copy-source-if-match"],
                            )
                            .copy_source_range(format!("bytes={start}-{end}"))
                            .send()
                            .await
                            .context("copy destination part for metadata update")?;
                        Ok(CompletedPart::builder()
                            .part_number((index + 1) as i32)
                            .e_tag(
                                output
                                    .copy_part_result()
                                    .and_then(|p| p.e_tag())
                                    .context("S3 omitted copied part ETag")?,
                            )
                            .build())
                    }
                })
                .buffer_unordered(workers.max(1))
                .inspect(|result: &Result<CompletedPart>| {
                    if result.is_err() {
                        failed.store(true, Relaxed);
                    }
                })
                // Drain in-flight copies before aborting the multipart upload.
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            parts.sort_by_key(|part| part.part_number());
            let _permit = acquire().await?;
            let output = client
                .complete_multipart_upload()
                .bucket(bucket)
                .key(&self.request.key)
                .upload_id(id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .if_match(&self.request.headers["x-amz-copy-source-if-match"])
                .send()
                .await
                .context("complete metadata update")?;
            Ok((
                output.e_tag().map(str::to_owned),
                output.version_id().map(str::to_owned),
            ))
        }
        .await;
        if result.is_err() {
            self.abort(client, bucket).await;
        }
        result
    }
}
