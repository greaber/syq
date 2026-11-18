use super::*;
use crate::s3::authorization::Unsigned;

impl Engine {
    pub(super) async fn authorize_requests(&self, mut requests: Vec<Unsigned>) -> Result<()> {
        let Some(authorization) = &self.authorization else {
            return Ok(());
        };
        for request in &mut requests {
            // Use the same canonical fields as the executing HTTP transport.
            // Content headers still travel with metadata updates, but are not
            // part of this authorization lookup key.
            request
                .headers
                .retain(|name, _| crate::s3::authorization::signed_header(name, &request.method));
            let headers = self
                .options
                .headers_for(&request.method, request.query.keys().map(String::as_str));
            for super::super::Header(name, value) in headers {
                if crate::s3::authorization::signed_header(name, &request.method) {
                    request.headers.insert(name.clone(), value.clone());
                }
            }
        }
        let authorization = authorization.clone();
        tokio::task::spawn_blocking(move || authorization.authorize(requests)).await?
    }
    pub(super) async fn finish_authorization(&self) -> Result<()> {
        let Some(authorization) = &self.authorization else {
            return Ok(());
        };
        authorization.finish().await
    }
    /// Signs many requests in a few exchanges with the authorizing machine,
    /// so preparation does not wait for one round trip per file.
    pub(super) async fn authorize_all(
        &self,
        requests: impl Iterator<Item = Unsigned>,
    ) -> Result<()> {
        if self.authorization.is_none() {
            return Ok(());
        }
        let limit = crate::s3::authorization::EXCHANGE_REQUESTS;
        for exchange in crate::s3::authorization::exchanges(requests, limit) {
            self.check_cancelled()?;
            self.authorize_requests(exchange).await?;
        }
        Ok(())
    }
    /// The existence checks `prepare_upload` will send, signed together
    /// before preparation starts.
    pub(super) async fn authorize_upload_checks(&self, plan: &[Source]) -> Result<()> {
        let listed = self.upload_keys.get();
        self.authorize_all(
            plan.iter()
                .filter(|source| listed.is_none_or(|keys| keys.contains_key(&source.key)))
                .map(|source| Unsigned::new("HEAD", &source.key)),
        )
        .await
    }
    /// Every request the prepared uploads will send, signed together after
    /// hashing and before any data moves.
    pub(super) async fn authorize_uploads<'a>(
        &self,
        prepared: impl Iterator<Item = &'a UploadPreparation> + Clone,
    ) -> Result<()> {
        let ready = prepared.filter_map(|work| match work {
            UploadPreparation::Ready(work) => Some(&**work),
            UploadPreparation::Skipped | UploadPreparation::Preview(_) => None,
        });
        // First the requests that abandon uploads no recovery record keeps,
        // so a failure while signing the rest can still clean those up.
        self.authorize_all(ready.clone().flat_map(Self::abandon_requests))
            .await?;
        self.authorize_all(ready.flat_map(Self::upload_requests))
            .await
    }
    /// The requests that abort a prepared upload which nothing would resume.
    fn abandon_requests(prepared: &PreparedUpload) -> Vec<Unsigned> {
        let unrecorded = prepared.metadata_update.is_some()
            || prepared.multipart.as_ref().is_some_and(|m| !m.recorded);
        let mut requests = if unrecorded {
            Self::upload_requests(prepared)
        } else {
            Vec::new()
        };
        requests.retain(|r| r.method == "DELETE" && r.query.contains_key("uploadId"));
        requests
    }
    fn upload_requests(prepared: &PreparedUpload) -> Vec<Unsigned> {
        if let Some(update) = &prepared.metadata_update {
            return update.requests();
        }
        let key = &prepared.source.key;
        let mut requests = vec![Unsigned::new("HEAD", key)];
        let checksum = |request: Unsigned, index: usize, length: u64| {
            request
                .header("content-length", &length.to_string())
                .header(
                    if prepared.algorithm.is_sha256() {
                        "x-amz-checksum-sha256"
                    } else {
                        "content-md5"
                    },
                    &prepared.checksums[index],
                )
        };
        if let Some(multipart) = &prepared.multipart {
            let upload_id = &multipart.upload.upload_id;
            for (index, _) in prepared.checksums.iter().enumerate() {
                let length = prepared
                    .part_size
                    .min(prepared.size - index as u64 * prepared.part_size);
                requests.push(checksum(
                    Unsigned::new("PUT", key)
                        .query("uploadId", upload_id)
                        .query("partNumber", &(index + 1).to_string()),
                    index,
                    length,
                ));
            }
            let mut complete = Unsigned::new("POST", key).query("uploadId", upload_id);
            if prepared.must_be_new {
                complete = complete.header("if-none-match", "*");
            }
            requests.push(complete);
            requests.push(Unsigned::new("DELETE", key).query("uploadId", upload_id));
        } else {
            let mut request = checksum(Unsigned::new("PUT", key), 0, prepared.size);
            for (name, value) in prepared.metadata.encode() {
                request = request.header(&format!("x-amz-meta-{name}"), &value);
            }
            if prepared.must_be_new {
                request = request.header("if-none-match", "*");
            }
            requests.push(request);
        }
        requests
    }
    pub(super) async fn authorize_downloads(&self, jobs: &mut [Download]) -> Result<()> {
        if self.authorization.is_none() {
            return Ok(());
        }
        self.authorize_requests(
            jobs.iter()
                .map(|job| Unsigned::new("HEAD", &job.key))
                .collect(),
        )
        .await?;
        let objects = stream::iter(jobs.iter().enumerate())
            .map(|(index, job)| async move {
                self.check_cancelled()?;
                let object = client::head(&self.client, &self.options.bucket, &job.key)
                    .await?
                    .context("S3 source disappeared during authorization")?;
                Ok::<_, anyhow::Error>((index, object))
            })
            .buffer_unordered(self.options.concurrency.max(1))
            .collect::<Vec<_>>()
            .await;
        let mut requests = Vec::with_capacity(jobs.len());
        for object in objects {
            let (index, object) = object?;
            let mut request = Unsigned::new("GET", &object.key).header("if-match", &object.etag);
            if let Some(version) = &object.version {
                request = request.query("versionId", version);
            }
            requests.push(request);
            jobs[index].source_object = Some(Box::new(object));
        }
        self.authorize_requests(requests).await?;
        Ok(())
    }
}
