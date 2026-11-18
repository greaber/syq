//! Server-side object copies: a single CopyObject, or a multipart upload whose
//! parts are UploadPartCopy requests. They change metadata by copying an object
//! onto itself, and copy between keys or buckets. Each copy is described once,
//! and the same description is authorized and executed, so receivers whose
//! requests must all be authorized before the source connection closes sign
//! exactly what is later sent.
use super::{authorization::Unsigned, client};
use anyhow::{Context, Result};
use aws_sdk_s3::{
    operation::head_object::HeadObjectOutput,
    types::{CompletedMultipartUpload, CompletedPart, Tag},
    Client,
};
use futures_util::{stream, StreamExt};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

pub(super) const SINGLE_LIMIT: u64 = 5 * 1024 * 1024 * 1024;

/// The headers of a copy request that only a single CopyObject or
/// UploadPartCopy takes, not CreateMultipartUpload.
const COPY_HEADERS: [&str; 4] = [
    "x-amz-copy-source",
    "x-amz-copy-source-if-match",
    "x-amz-metadata-directive",
    "x-amz-tagging-directive",
];

pub(super) struct Desired {
    pub head: HeadObjectOutput,
    /// None keeps destination tags; Some(empty) removes them all.
    pub tags: Option<Vec<Tag>>,
}

/// Tags as the `x-amz-tagging` header value.
pub(super) fn encode_tags<'a>(tags: impl IntoIterator<Item = &'a Tag>) -> String {
    let mut encoded = url::form_urlencoded::Serializer::new(String::new());
    for tag in tags {
        encoded.append_pair(tag.key(), tag.value());
    }
    encoded.finish().replace('+', "%20")
}

/// The object attributes a copy that replaces metadata repeats: content
/// headers, user metadata and the website redirect. Storage class and
/// encryption depend on the kind of copy.
pub(super) fn object_headers(desired: &HeadObjectOutput) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for (name, value) in desired.metadata().into_iter().flat_map(|m| m.iter()) {
        headers.insert(format!("x-amz-meta-{name}"), value.clone());
    }
    for (name, value) in [
        ("content-type", desired.content_type()),
        ("content-encoding", desired.content_encoding()),
        ("content-language", desired.content_language()),
        ("content-disposition", desired.content_disposition()),
        ("cache-control", desired.cache_control()),
        // Expires is an opaque HTTP hint. Providers can retain values such as
        // "0" which the SDK's typed date setter cannot represent.
        ("expires", desired.expires_string()),
        (
            "x-amz-website-redirect-location",
            desired.website_redirect_location(),
        ),
    ] {
        if let Some(value) = value {
            headers.insert(name.to_owned(), value.to_owned());
        }
    }
    headers
}

/// Part numbers and inclusive byte ranges of a multipart copy.
fn parts(size: u64, part_size: u64) -> impl Iterator<Item = (i32, u64, u64)> {
    (0..size.div_ceil(part_size)).map(move |index| {
        let start = index * part_size;
        let end = (start + part_size).min(size) - 1;
        ((index + 1) as i32, start, end)
    })
}

/// The condition a multipart copy completes under.
#[derive(Clone)]
pub(super) enum Condition {
    /// The destination still has this ETag.
    Unchanged(String),
    /// The destination does not exist.
    New,
}

#[derive(Clone)]
struct Multipart {
    id: String,
    part_size: u64,
}

#[derive(Clone)]
pub(crate) struct Prepared {
    /// The single CopyObject request. A multipart copy takes its copy source
    /// and source condition for every part.
    request: Unsigned,
    pub(super) size: u64,
    /// The condition CompleteMultipartUpload carries in place of the single
    /// request's own destination condition.
    complete: Option<Condition>,
    multipart: Option<Multipart>,
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

    /// A metadata update: a copy of the object onto itself.
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
        let etag = request.headers["x-amz-copy-source-if-match"].clone();
        let mut prepared = Self::new(request, size, Some(Condition::Unchanged(etag)));
        if size <= single_limit.min(SINGLE_LIMIT) {
            return Ok(prepared);
        }
        // Enlarge parts for large objects without depending on upload tuning.
        let part_size = part_size.max(size.div_ceil(10_000)).max(5 << 20);
        let tagging = async {
            Ok(if let Some(tags) = &desired.tags {
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
                encode_tags(tags.tag_set())
            })
        };
        let mut headers = prepared.request.headers.clone();
        headers.retain(|name, _| !COPY_HEADERS.contains(&name.as_str()));
        prepared
            .start_multipart(client, bucket, part_size, headers, tagging)
            .await?;
        Ok(prepared)
    }

    /// A copy whose single form is `request`. `complete` is the condition a
    /// multipart form completes under.
    pub(super) fn new(request: Unsigned, size: u64, complete: Option<Condition>) -> Self {
        Self {
            request,
            size,
            complete,
            multipart: None,
        }
    }

    /// Copy in parts instead, creating the destination with `headers` and
    /// the encoded tags `tagging` yields. The caller holds its request permit.
    pub(super) async fn start_multipart(
        &mut self,
        client: &Client,
        bucket: &str,
        part_size: u64,
        headers: BTreeMap<String, String>,
        tagging: impl Future<Output = Result<String>>,
    ) -> Result<()> {
        anyhow::ensure!(
            part_size <= SINGLE_LIMIT,
            "object exceeds the S3 multipart size limit"
        );
        let tagging = tagging.await?;
        let created = client
            .create_multipart_upload()
            .bucket(bucket)
            .key(&self.request.key)
            .set_tagging((!tagging.is_empty()).then_some(tagging))
            .customize()
            .map_request(move |mut request| {
                for (name, value) in &headers {
                    request
                        .headers_mut()
                        .try_insert(name.clone(), value.clone())?;
                }
                Ok::<_, aws_smithy_runtime_api::http::HttpError>(request)
            })
            .send()
            .await
            .map_err(|e| e.into_service_error())
            .context("prepare multipart server-side copy")?;
        self.multipart = Some(Multipart {
            id: created
                .upload_id()
                .context("S3 omitted multipart upload ID")?
                .to_owned(),
            part_size,
        });
        Ok(())
    }

    pub(super) fn is_multipart(&self) -> bool {
        self.multipart.is_some()
    }

    pub(super) fn matches(&self, etag: &str) -> bool {
        self.request.headers["x-amz-copy-source-if-match"] == etag
    }

    fn header(&self, name: &str) -> &str {
        &self.request.headers[name]
    }

    pub(super) fn requests(&self) -> Vec<Unsigned> {
        let Some(Multipart { id, part_size }) = &self.multipart else {
            return vec![self.request.clone()];
        };
        let key = &self.request.key;
        let mut requests = vec![Unsigned::new("DELETE", key).query("uploadId", id)];
        for (number, start, end) in parts(self.size, *part_size) {
            requests.push(
                Unsigned::new("PUT", key)
                    .query("uploadId", id)
                    .query("partNumber", &number.to_string())
                    .header("x-amz-copy-source", self.header("x-amz-copy-source"))
                    .header(
                        "x-amz-copy-source-if-match",
                        self.header("x-amz-copy-source-if-match"),
                    )
                    .header("x-amz-copy-source-range", &format!("bytes={start}-{end}")),
            );
        }
        let complete = Unsigned::new("POST", key).query("uploadId", id);
        requests.push(match &self.complete {
            Some(Condition::Unchanged(etag)) => complete.header("if-match", etag),
            Some(Condition::New) => complete.header("if-none-match", "*"),
            None => complete,
        });
        requests
    }

    /// Abandon a multipart copy's parts. The caller decides whether this needs
    /// a request permit.
    pub(crate) async fn abort(&self, client: &Client, bucket: &str) {
        if let Some(Multipart { id, .. }) = &self.multipart {
            if let Err(error) = client
                .abort_multipart_upload()
                .bucket(bucket)
                .key(&self.request.key)
                .upload_id(id)
                .send()
                .await
            {
                crate::output::diagnostic!(
                    "S3 multipart cleanup failed for {:?}, upload {id:?}: {}",
                    self.request.key,
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
    ) -> Result<()>
    where
        F: Fn() -> A,
        A: Future<Output = Result<P>>,
    {
        self.execute_counted(client, bucket, workers, acquire, || async {}, |_| {})
            .await
    }

    /// Run the copy, holding a permit from `acquire` for each request and
    /// reporting each copied range's length to `copied`. A failed multipart
    /// copy drains its started parts, then aborts while holding what
    /// `cleanup` yields, even after cancellation.
    pub(super) async fn execute_counted<F, A, P, C, Q>(
        &self,
        client: &Client,
        bucket: &str,
        workers: usize,
        acquire: F,
        cleanup: impl FnOnce() -> C,
        copied: impl Fn(u64),
    ) -> Result<()>
    where
        F: Fn() -> A,
        A: Future<Output = Result<P>>,
        C: Future<Output = Q>,
    {
        let Some(Multipart { id, part_size }) = &self.multipart else {
            let _permit = acquire().await?;
            copy_object(client, bucket, self.request.clone()).await?;
            copied(self.size);
            return Ok(());
        };
        let key = &self.request.key;
        let failed = AtomicBool::new(false);
        let result: Result<()> = async {
            let mut parts = stream::iter(parts(self.size, *part_size))
                .take_while(|_| std::future::ready(!failed.load(Relaxed)))
                .map(|(number, start, end)| {
                    let acquire = &acquire;
                    let failed = &failed;
                    let copied = &copied;
                    async move {
                        anyhow::ensure!(!failed.load(Relaxed), "another server-copy part failed");
                        let _permit = acquire().await?;
                        anyhow::ensure!(!failed.load(Relaxed), "another server-copy part failed");
                        let output = client
                            .upload_part_copy()
                            .bucket(bucket)
                            .key(key)
                            .upload_id(id)
                            .part_number(number)
                            .copy_source(self.header("x-amz-copy-source"))
                            .copy_source_if_match(self.header("x-amz-copy-source-if-match"))
                            .copy_source_range(format!("bytes={start}-{end}"))
                            .send()
                            .await
                            .map_err(|e| e.into_service_error())
                            .context("S3 server-side copy failed")?;
                        let part = CompletedPart::builder()
                            .part_number(number)
                            .e_tag(
                                output
                                    .copy_part_result()
                                    .and_then(|p| p.e_tag())
                                    .context("S3 omitted copied part ETag")?,
                            )
                            .build();
                        copied(end - start + 1);
                        Ok(part)
                    }
                })
                .buffer_unordered(workers.max(1))
                .inspect(|result: &Result<CompletedPart>| {
                    if result.is_err() {
                        failed.store(true, Relaxed);
                    }
                })
                // Drain started requests before aborting: dropping their futures
                // could leave provider-side parts racing cleanup.
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>>>()?;
            parts.sort_by_key(|part| part.part_number());
            let _permit = acquire().await?;
            client
                .complete_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(id)
                .multipart_upload(
                    CompletedMultipartUpload::builder()
                        .set_parts(Some(parts))
                        .build(),
                )
                .set_if_match(match &self.complete {
                    Some(Condition::Unchanged(etag)) => Some(etag.clone()),
                    _ => None,
                })
                .set_if_none_match(
                    matches!(self.complete, Some(Condition::New)).then(|| "*".to_owned()),
                )
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("S3 server-side copy failed")?;
            Ok(())
        }
        .await;
        if result.is_err() {
            let _permit = cleanup().await;
            self.abort(client, bucket).await;
        }
        result
    }
}

/// Send a single CopyObject with exactly the described headers.
async fn copy_object(client: &Client, bucket: &str, request: Unsigned) -> Result<()> {
    client
        .copy_object()
        .bucket(bucket)
        .key(&request.key)
        .copy_source(request.headers["x-amz-copy-source"].clone())
        .customize()
        .map_request(move |mut http| {
            for (name, value) in &request.headers {
                http.headers_mut().try_insert(name.clone(), value.clone())?;
            }
            Ok::<_, aws_smithy_runtime_api::http::HttpError>(http)
        })
        .send()
        .await
        .map_err(|e| e.into_service_error())
        .context("S3 server-side copy failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn parts_cover_the_object_once_in_order() {
        assert_eq!(
            super::parts(11, 5).collect::<Vec<_>>(),
            [(1, 0, 4), (2, 5, 9), (3, 10, 10)]
        );
        assert_eq!(super::parts(10, 5).count(), 2);
    }
}
