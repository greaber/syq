use super::*;
use crate::s3::authorization::Unsigned;

impl Engine {
    pub(super) async fn authorize_requests(&self, mut requests: Vec<Unsigned>) -> Result<()> {
        let Some(authorization) = &self.authorization else {
            return Ok(());
        };
        for request in &mut requests {
            for super::super::Header(name, value) in &self.options.headers {
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
    pub(super) async fn authorize_upload(&self, prepared: &PreparedUpload) -> Result<()> {
        if self.authorization.is_none() {
            return Ok(());
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
        self.authorize_requests(requests).await
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
            jobs[index].source_object = Some(object);
        }
        self.authorize_requests(requests).await?;
        Ok(())
    }
}
