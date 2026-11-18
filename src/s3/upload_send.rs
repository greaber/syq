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
                    // A failure that never reached the service says nothing
                    // about whether it is down.
                    let local = super::retry::permanent(&e);
                    if let Some(outage) = self.outage.filter(|_| !local) {
                        outage.failed(super::transfer::retryable(&e));
                    }
                    return Ok(Err(e));
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
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

    /// A real client whose requests go to `connector`, with `credentials`.
    pub(in crate::s3) fn client(
        connector: impl aws_smithy_runtime_api::client::http::HttpConnector + Clone + 'static,
        credentials: impl aws_credential_types::provider::ProvideCredentials + 'static,
    ) -> aws_sdk_s3::Client {
        use aws_smithy_runtime_api::client::http::{http_client_fn, SharedHttpConnector};
        client_with(
            http_client_fn(move |_, _| SharedHttpConnector::new(connector.clone())),
            credentials,
        )
    }

    pub(in crate::s3) fn client_with(
        http: impl aws_smithy_runtime_api::client::http::HttpClient + 'static,
        credentials: impl aws_credential_types::provider::ProvideCredentials + 'static,
    ) -> aws_sdk_s3::Client {
        aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("auto"))
                .endpoint_url("https://storage.example")
                .force_path_style(true)
                .credentials_provider(credentials)
                .http_client(http)
                .build(),
        )
    }

    /// Upload through `client` with up to eight retries. Returns the
    /// attempts, the time spent backing off, and the error.
    pub(in crate::s3) async fn failed_put(
        client: &aws_sdk_s3::Client,
    ) -> (usize, std::time::Duration, anyhow::Error) {
        failed_upload(|| async {
            client
                .put_object()
                .bucket("b")
                .key("k")
                .body(bytes::Bytes::from_static(b"x").into())
                .customize()
                .config_override(super::super::client::without_sdk_retries())
                .send()
                .await
        })
        .await
    }

    /// Send `put` through [`Upload::send`] with up to eight retries.
    pub(in crate::s3) async fn failed_upload<F, O>(
        mut put: impl FnMut() -> F,
    ) -> (usize, std::time::Duration, anyhow::Error)
    where
        F: Future<Output = Result<O, Error>>,
    {
        let (flag, outage) = (AtomicBool::new(false), Default::default());
        let upload = Upload {
            retries: 8,
            ..upload(&flag, &outage)
        };
        let mut attempts = 0;
        let started = tokio::time::Instant::now();
        let result = upload
            .send(async { unreachable!() }, |_| {
                attempts += 1;
                let put = put();
                async { Ok(put.await) }
            })
            .await
            .unwrap();
        let Err(error) = result else {
            panic!("the upload succeeded")
        };
        let error = anyhow::Error::new(error.into_service_error());
        (attempts, started.elapsed(), error)
    }

    /// Fails every request: without a response, or with a 503.
    #[derive(Clone, Debug)]
    pub(in crate::s3) struct Failing(pub fn() -> Result<HttpResponse, ConnectorError>);
    impl aws_smithy_runtime_api::client::http::HttpConnector for Failing {
        fn call(
            &self,
            _: aws_smithy_runtime_api::client::orchestrator::HttpRequest,
        ) -> aws_smithy_runtime_api::client::http::HttpConnectorFuture {
            aws_smithy_runtime_api::client::http::HttpConnectorFuture::ready(self.0())
        }
    }
    use aws_smithy_runtime_api::client::result::ConnectorError;

    pub(in crate::s3) fn static_credentials() -> aws_sdk_s3::config::Credentials {
        aws_sdk_s3::config::Credentials::new("a", "b", None, None, "test")
    }

    /// Failures that a resend cannot fix end the upload at once, with the
    /// same error they end with after retries.
    #[tokio::test(start_paused = true)]
    async fn permanent_failures_are_not_retried() {
        use crate::s3::retry::Permanent;
        use aws_credential_types::provider::{error::CredentialsError, future, ProvideCredentials};
        #[derive(Debug)]
        struct Missing(fn() -> CredentialsError);
        impl ProvideCredentials for Missing {
            fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
            where
                Self: 'a,
            {
                future::ProvideCredentials::ready(Err(self.0()))
            }
        }
        let unreachable = Failing(|| unreachable!("no request is sent"));
        for (client, message) in [
            (
                client(
                    unreachable.clone(),
                    Missing(|| CredentialsError::not_loaded("no profile")),
                ),
                "no profile",
            ),
            (
                client(
                    unreachable.clone(),
                    Missing(|| CredentialsError::provider_error("the SSO session has expired")),
                ),
                "the SSO session has expired",
            ),
            (
                client(
                    Failing(|| Err(Permanent::connector(anyhow::anyhow!("source changed")))),
                    static_credentials(),
                ),
                "source changed",
            ),
            // A request body reports errors as io::Error, whose causes skip
            // the error it carries.
            (
                client(
                    Failing(|| {
                        Err(ConnectorError::io(Box::new(std::io::Error::other(
                            Permanent::new(anyhow::anyhow!("source shrank")),
                        ))))
                    }),
                    static_credentials(),
                ),
                "source shrank",
            ),
        ] {
            let (attempts, waited, error) = failed_put(&client).await;
            assert_eq!(
                (attempts, waited),
                (1, std::time::Duration::ZERO),
                "{error:#}"
            );
            assert!(format!("{error:#}").contains(message), "{error:#}");
        }
    }

    /// Failures that may pass are retried with backoff, including a credential
    /// provider that timed out.
    #[tokio::test(start_paused = true)]
    async fn transient_failures_are_retried() {
        use aws_credential_types::provider::{error::CredentialsError, future, ProvideCredentials};
        #[derive(Debug)]
        struct Slow;
        impl ProvideCredentials for Slow {
            fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
            where
                Self: 'a,
            {
                future::ProvideCredentials::ready(Err(CredentialsError::provider_timed_out(
                    std::time::Duration::from_secs(5),
                )))
            }
        }
        let unreachable = Failing(|| unreachable!("no request is sent"));
        let reset = Failing(|| {
            Err(ConnectorError::io(Box::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            ))))
        });
        let other = Failing(|| Err(ConnectorError::other("connection closed".into(), None)));
        let unavailable = Failing(|| {
            Ok(HttpResponse::new(
                StatusCode::try_from(503).unwrap(),
                SdkBody::empty(),
            ))
        });
        for client in [
            client(unreachable, Slow),
            client(reset, static_credentials()),
            client(other, static_credentials()),
            client(unavailable, static_credentials()),
        ] {
            let (attempts, waited, error) = failed_put(&client).await;
            assert_eq!(attempts, 9, "{error:#}");
            assert!(waited >= std::time::Duration::from_secs(20), "{waited:?}");
        }
    }
}
