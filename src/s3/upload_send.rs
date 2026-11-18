//! Send one upload body, a PutObject or an UploadPart, with syq's own retries.
use super::checksum::{self, Algorithm};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
};

pub(super) struct Upload<'a> {
    pub key: &'a str,
    /// The UploadPart number, named in the corrupted-data warning.
    pub part: Option<i32>,
    pub algorithm: Algorithm,
    /// The precomputed checksum. Without request checksums it is the body's
    /// MD5, if known, to send when the destination requires one.
    pub checksum: Option<&'a str>,
    pub retries: u32,
    /// Set once Content-MD5 fixed a rejection, so later uploads send it.
    pub content_md5: &'a AtomicBool,
    pub outage: Option<&'a super::outage::Outage>,
}

impl Upload<'_> {
    /// Calls `send` for each attempt with the Content-MD5 header to set; its
    /// request must disable SDK retries, since this loop retries transient
    /// errors itself, resends corrupted uploads, and adds Content-MD5 when the
    /// destination requires a checksum. `md5` computes the body's MD5; it runs
    /// only when that is needed and `checksum` does not hold it. The inner
    /// result is the request's final outcome, already reported to `outage`.
    pub(super) async fn send<O, E, F>(
        &self,
        md5: impl Future<Output = anyhow::Result<String>>,
        mut send: impl FnMut(Option<String>) -> F,
    ) -> anyhow::Result<Result<O, SdkError<E, HttpResponse>>>
    where
        E: ProvideErrorMetadata,
        F: Future<Output = anyhow::Result<Result<O, SdkError<E, HttpResponse>>>>,
    {
        let mut md5 = Some(md5);
        let mut fallback = None;
        let mut retry_with_md5 = false;
        let mut attempt = 0;
        loop {
            if self.algorithm == Algorithm::None
                && fallback.is_none()
                && (retry_with_md5 || self.content_md5.load(Relaxed))
            {
                fallback = Some(match (self.checksum, md5.take()) {
                    (Some(md5), _) => md5.to_owned(),
                    (None, Some(compute)) => compute.await?,
                    (None, None) => unreachable!("the fallback is computed once"),
                });
            }
            let header = self
                .algorithm
                .header(Algorithm::Md5, self.checksum)
                .or_else(|| fallback.clone());
            match send(header).await? {
                Ok(output) => {
                    if let Some(outage) = self.outage {
                        outage.responded();
                    }
                    // Content-MD5 fixed the rejection, so send it from now on.
                    if fallback.is_some() {
                        self.content_md5.store(true, Relaxed);
                    }
                    return Ok(Ok(output));
                }
                Err(e)
                    if self.algorithm == Algorithm::None
                        && fallback.is_none()
                        && checksum::requires_checksum(&e) =>
                {
                    retry_with_md5 = true;
                }
                Err(e) if attempt < self.retries && checksum::corrupted(&e).is_some() => {
                    let part = self
                        .part
                        .map(|number| format!(" in part {number}"))
                        .unwrap_or_default();
                    crate::output::diagnostic!(
                        "syq: warning: {}: the destination received corrupted data{part} ({}); retrying",
                        self.key,
                        checksum::corrupted(&e).unwrap_or_default()
                    );
                    super::backoff(attempt).await;
                    attempt += 1;
                }
                Err(e) if attempt < self.retries && super::transfer::retryable(&e) => {
                    super::retry::after_error(attempt, &e).await;
                    attempt += 1;
                }
                Err(e) => {
                    if let Some(outage) = self.outage {
                        outage.failed(super::transfer::retryable(&e));
                    }
                    return Ok(Err(e));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::{error::ErrorMetadata, operation::put_object::PutObjectError};
    use aws_smithy_runtime_api::http::StatusCode;
    use aws_smithy_types::body::SdkBody;

    type Error = SdkError<PutObjectError, HttpResponse>;

    fn error(status: u16, code: &str) -> Error {
        SdkError::service_error(
            PutObjectError::generic(ErrorMetadata::builder().code(code).build()),
            HttpResponse::new(StatusCode::try_from(status).unwrap(), SdkBody::empty()),
        )
    }

    fn upload<'a>(flag: &'a AtomicBool, outage: &'a super::super::outage::Outage) -> Upload<'a> {
        Upload {
            key: "k",
            part: Some(1),
            algorithm: Algorithm::None,
            checksum: None,
            retries: 2,
            content_md5: flag,
            outage: Some(outage),
        }
    }

    /// Corrupted resends and transient retries share one `--s3-retries` budget.
    #[tokio::test(start_paused = true)]
    async fn corrupted_and_transient_retries_share_the_budget() {
        let (flag, outage) = (AtomicBool::new(false), Default::default());
        let mut responses = vec![
            error(400, "BadDigest"),
            error(503, "SlowDown"),
            error(400, "BadDigest"),
            error(400, "BadDigest"),
        ]
        .into_iter();
        let mut attempts = 0;
        let result = upload(&flag, &outage)
            .send(async { unreachable!() }, |_| {
                attempts += 1;
                let response = responses.next().unwrap();
                async move { Ok(Err::<(), _>(response)) }
            })
            .await
            .unwrap();
        assert_eq!(attempts, 3);
        assert_eq!(result.unwrap_err().code(), Some("BadDigest"));
    }

    /// A rejection for a missing checksum adds Content-MD5, computed once,
    /// and later uploads keep sending it.
    #[tokio::test(start_paused = true)]
    async fn checksum_rejection_adds_content_md5() {
        let (flag, outage) = (AtomicBool::new(false), Default::default());
        let mut headers = Vec::new();
        let result = upload(&flag, &outage)
            .send(async { Ok("md5".to_owned()) }, |header| {
                let response = match header {
                    None => Err(error(400, "InvalidRequest")),
                    Some(_) => Ok(()),
                };
                headers.push(header);
                async move { Ok(response) }
            })
            .await
            .unwrap();
        assert!(result.is_ok());
        assert_eq!(headers, [None, Some("md5".to_owned())]);
        assert!(flag.load(Relaxed));
    }
}
