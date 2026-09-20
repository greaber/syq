use super::*;
use crate::s3::authorization::{Authorization, Unsigned};
use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use std::collections::HashMap;

pub(crate) enum Prepared {
    Skipped,
    Preview,
    Download(Box<HeadObjectOutput>),
    Upload {
        key: String,
        metadata: Option<HashMap<String, String>>,
        id: Option<String>,
    },
}

impl Session {
    async fn authorize(&self, mut requests: Vec<Unsigned>) -> Result<()> {
        let Some(authorization) = &self.authorization else {
            return Ok(());
        };
        for request in &mut requests {
            request.bucket =
                (self.options.bucket != authorization.bucket).then(|| self.options.bucket.clone());
            for super::super::Header(name, value) in &self.options.headers {
                if crate::s3::authorization::signed_header(name, &request.method) {
                    request.headers.insert(name.clone(), value.clone());
                }
            }
        }
        let authorization = authorization.clone();
        tokio::task::spawn_blocking(move || authorization.authorize(requests)).await?
    }

    pub(super) async fn prepare(
        &self,
        plan: &Plan<'_>,
        size: Option<u64>,
    ) -> Result<Option<Prepared>> {
        if self.authorization.is_none() {
            return Ok(None);
        }
        if plan.options.route == crate::s3::Route::Download {
            let _request = self.requests.acquire().await?;
            let head = self
                .client
                .head_object()
                .bucket(&self.options.bucket)
                .key(&plan.key)
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("inspect source object")?;
            let mut get = Unsigned::new("GET", &plan.key)
                .header("if-match", head.e_tag().context("S3 HEAD omitted ETag")?);
            if let Some(version) = head.version_id() {
                get = get.query("versionId", version);
            }
            self.authorize(vec![get]).await?;
            return Ok(Some(Prepared::Download(Box::new(head))));
        }
        {
            let _request = self.requests.acquire().await?;
            check_placement(&self.client, plan).await?;
        }
        if plan.controls.report.skipped() {
            return Ok(Some(Prepared::Skipped));
        }
        if plan.controls.report.dry_run {
            return Ok(Some(Prepared::Preview));
        }
        let metadata = upload_metadata(plan);
        let new =
            plan.placement.existence == crate::cli::Existence::New || plan.controls.report.only_new;
        let mut put = Unsigned::new("PUT", &plan.key);
        if let Some(metadata) = &metadata {
            for (name, value) in metadata {
                put = put.header(&format!("x-amz-meta-{name}"), value);
            }
        }
        if new {
            put = put.header("if-none-match", "*");
        }
        let mut requests = vec![put];
        let count = size.map_or(10_000, |size| size.div_ceil(self.options.part_size).max(1));
        anyhow::ensure!(
            count <= 10_000,
            "stream exceeds 10,000 multipart parts; choose a larger s3-part-size"
        );
        let id = if size.is_none_or(|size| size >= self.options.part_size) {
            let _request = self.requests.acquire().await?;
            let created = self
                .client
                .create_multipart_upload()
                .bucket(&self.options.bucket)
                .key(&plan.key)
                .set_metadata(metadata.clone())
                .send()
                .await
                .map_err(|e| e.into_service_error())
                .context("prepare multipart stream upload")?;
            let id = created
                .upload_id()
                .context("S3 omitted upload ID")?
                .to_owned();
            // Authorize cleanup before the potentially large part batch.
            self.authorize(vec![
                Unsigned::new("DELETE", &plan.key).query("uploadId", &id)
            ])
            .await?;
            for number in 1..=count {
                requests.push(
                    Unsigned::new("PUT", &plan.key)
                        .query("uploadId", &id)
                        .query("partNumber", &number.to_string()),
                );
            }
            let mut complete = Unsigned::new("POST", &plan.key).query("uploadId", &id);
            if new {
                complete = complete.header("if-none-match", "*");
            }
            requests.push(complete);
            Some(id)
        } else {
            None
        };
        if let Err(error) = self.authorize(requests).await {
            if let Some(id) = &id {
                let _ = self.abort(&plan.key, id).await;
            }
            return Err(error);
        }
        Ok(Some(Prepared::Upload {
            key: plan.key.clone(),
            metadata,
            id,
        }))
    }

    pub(crate) async fn prepare_callback(
        &self,
        key: String,
        upload: bool,
        controls: &crate::descriptor_copy::controls::Controls,
    ) -> Result<Option<Prepared>> {
        let mut options = self.options.clone();
        options.route = if upload {
            crate::s3::Route::Upload
        } else {
            crate::s3::Route::Download
        };
        let plan = Plan {
            session: self,
            controls,
            options,
            target: key.clone(),
            key,
            placement: Default::default(),
            source_meta: None,
        };
        self.prepare(&plan, controls.expected.size).await
    }

    pub(crate) async fn abort(&self, key: &str, id: &str) -> Result<()> {
        let _request = self.requests.acquire().await?;
        self.client
            .abort_multipart_upload()
            .bucket(&self.options.bucket)
            .key(key)
            .upload_id(id)
            .send()
            .await
            .map_err(|e| e.into_service_error())?;
        Ok(())
    }
}

pub(super) async fn connect(
    args: &crate::cli::Args,
    options: &Options,
    target: &str,
    existence: crate::cli::Existence,
) -> Result<Option<Arc<Authorization>>> {
    use crate::s3::authorization::{Request, Scope, DEFAULT_LIFETIME};
    let crate::cli::AuthFrom::Return(name) = &args.auth_from else {
        return Ok(None);
    };
    let upload = options.route == crate::s3::Route::Upload;
    let request = Request {
        bucket: options.bucket.clone(),
        endpoint: options.endpoint.clone(),
        region: options.region.clone(),
        profile: options.profile.clone(),
        scopes: vec![Scope {
            key: target.trim_end_matches('/').into(),
            descendants: true,
        }],
        source: None,
        removal: None,
        acl: crate::s3::authorization::acl_headers(options),
        upload: upload && !args.dry_run,
        delete: false,
        create_only: args.ignore_existing || existence == crate::cli::Existence::New,
        lifetime: DEFAULT_LIFETIME,
    };
    crate::s3::authorization::connect_request(name, request)
        .await
        .map(Some)
}
