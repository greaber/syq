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
        failed_upload(|| put(client, bytes::Bytes::from_static(b"x").into())).await
    }

    async fn put(
        client: &aws_sdk_s3::Client,
        body: aws_sdk_s3::primitives::ByteStream,
    ) -> Result<aws_sdk_s3::operation::put_object::PutObjectOutput, Error> {
        client
            .put_object()
            .bucket("b")
            .key("k")
            .body(body)
            .customize()
            .config_override(super::super::client::without_sdk_retries())
            .send()
            .await
    }

    /// Send `put` through [`Upload::send`] with up to eight retries.
    pub(in crate::s3) async fn failed_upload<F, O>(
        put: impl FnMut() -> F,
    ) -> (usize, std::time::Duration, anyhow::Error)
    where
        F: Future<Output = Result<O, Error>>,
    {
        let (attempts, waited, error, _) = failed_upload_stopping(8, put).await;
        (attempts, waited, error)
    }

    /// As [`failed_upload`] with up to `retries` retries, after seven
    /// requests that ran out of retries without an answer. Also returns
    /// whether this failure, as the eighth, stopped the batch for an outage.
    pub(in crate::s3) async fn failed_upload_stopping<F, O>(
        retries: u32,
        mut put: impl FnMut() -> F,
    ) -> (usize, std::time::Duration, anyhow::Error, bool)
    where
        F: Future<Output = Result<O, Error>>,
    {
        let flag = AtomicBool::new(false);
        let outage = super::super::outage::Outage::default();
        for _ in 1..super::super::outage::LIMIT {
            outage.exhausted();
        }
        let upload = Upload {
            retries,
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
        let waited = started.elapsed();
        let Err(error) = result else {
            panic!("the upload succeeded")
        };
        let stopped = tokio::time::timeout(std::time::Duration::ZERO, outage.stopped())
            .await
            .is_ok();
        let error = anyhow::Error::new(error.into_service_error());
        (attempts, waited, error, stopped)
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

    #[derive(Debug)]
    struct NoCredentials(fn() -> aws_credential_types::provider::error::CredentialsError);
    impl aws_credential_types::provider::ProvideCredentials for NoCredentials {
        fn provide_credentials<'a>(
            &'a self,
        ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            aws_credential_types::provider::future::ProvideCredentials::ready(Err(self.0()))
        }
    }

    /// Fails the SDK's request construction, before serialization.
    #[derive(Debug)]
    struct Unbuildable;
    impl aws_smithy_runtime_api::client::interceptors::Intercept for Unbuildable {
        fn name(&self) -> &'static str {
            "Unbuildable"
        }
        fn read_before_serialization(
            &self,
            _: &aws_smithy_runtime_api::client::interceptors::context::BeforeSerializationInterceptorContextRef<'_>,
            _: &aws_smithy_runtime_api::client::runtime_components::RuntimeComponents,
            _: &mut aws_smithy_types::config_bag::ConfigBag,
        ) -> Result<(), aws_smithy_runtime_api::box_error::BoxError> {
            Err("the request cannot be built".into())
        }
    }

    /// Failures that a resend cannot fix end the upload at once, with the
    /// same error they end with after retries, and leave the outage count
    /// alone: the eighth failure in a row does not stop the batch.
    #[tokio::test(start_paused = true)]
    async fn permanent_failures_are_not_retried() {
        use crate::s3::retry::Permanent;
        use aws_credential_types::provider::error::CredentialsError;
        let unreachable = Failing(|| unreachable!("no request is sent"));
        let cases = [
            (
                client(
                    unreachable.clone(),
                    NoCredentials(|| CredentialsError::not_loaded("no profile")),
                ),
                "no profile",
            ),
            (
                client(
                    unreachable.clone(),
                    NoCredentials(|| CredentialsError::invalid_configuration("bad profile")),
                ),
                "bad profile",
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
        ];
        for (client, message) in cases {
            let (attempts, waited, error, stopped) =
                failed_upload_stopping(8, || put(&client, bytes::Bytes::from_static(b"x").into()))
                    .await;
            assert_eq!(
                (attempts, waited, stopped),
                (1, std::time::Duration::ZERO, false),
                "{error:#}"
            );
            assert!(format!("{error:#}").contains(message), "{error:#}");
        }
        let client = client(unreachable, static_credentials());
        let (attempts, waited, error, stopped) = failed_upload_stopping(8, || {
            client
                .put_object()
                .bucket("b")
                .key("k")
                .customize()
                .config_override(super::super::client::without_sdk_retries())
                .interceptor(Unbuildable)
                .send()
        })
        .await;
        assert_eq!(
            (attempts, waited, stopped),
            (1, std::time::Duration::ZERO, false),
            "{error:#}"
        );
        assert!(
            format!("{error:#}").contains("failed to construct request"),
            "{error:#}"
        );
    }

    /// A request body's permanent error reaches the classifier through the
    /// SDK's own HTTP client, as it would from a body that reads a file.
    #[tokio::test]
    async fn a_body_can_mark_its_error_permanent() {
        use tokio::io::AsyncReadExt;
        struct Failing;
        impl http_body::Body for Failing {
            type Data = bytes::Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>>
            {
                std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    crate::s3::retry::Permanent::new(anyhow::anyhow!("source changed")),
                ))))
            }
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::SizeHint::with_exact(1024)
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buffer = [0; 4096];
                    while socket.read(&mut buffer).await.is_ok_and(|n| n > 0) {}
                });
            }
        });
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc,
            ))
            .build_https();
        let client = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("auto"))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .credentials_provider(static_credentials())
                .http_client(http)
                .build(),
        );
        let (attempts, _, error) = failed_upload(|| {
            put(
                &client,
                aws_sdk_s3::primitives::ByteStream::new(SdkBody::from_body_1_x(Failing)),
            )
        })
        .await;
        server.abort();
        assert_eq!(attempts, 1, "{error:#}");
        assert!(format!("{error:#}").contains("source changed"), "{error:#}");
    }

    /// Failures that may pass are retried with backoff, including a credential
    /// provider that timed out or failed, and count toward the outage stop.
    #[tokio::test(start_paused = true)]
    async fn transient_failures_are_retried() {
        use aws_credential_types::provider::error::CredentialsError;
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
            client(
                unreachable.clone(),
                NoCredentials(|| {
                    CredentialsError::provider_timed_out(std::time::Duration::from_secs(5))
                }),
            ),
            client(
                unreachable,
                NoCredentials(|| CredentialsError::provider_error("STS returned 503")),
            ),
            client(reset, static_credentials()),
            client(other, static_credentials()),
            client(unavailable, static_credentials()),
        ] {
            let (attempts, waited, error, stopped) =
                failed_upload_stopping(8, || put(&client, bytes::Bytes::from_static(b"x").into()))
                    .await;
            assert_eq!((attempts, stopped), (9, true), "{error:#}");
            assert!(waited >= std::time::Duration::from_secs(20), "{waited:?}");
        }
    }
}
