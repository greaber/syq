//! Keep each file upload's read and socket write on one blocking worker. The
//! AWS SDK still owns signing, headers, credentials, retries and S3 responses.
use super::local::Source;
use aws_smithy_runtime_api::{
    box_error::BoxError,
    client::{
        http::{
            http_client_fn, HttpClient, HttpConnector, HttpConnectorFuture, SharedHttpClient,
            SharedHttpConnector,
        },
        interceptors::{
            context::{
                BeforeSerializationInterceptorContextMut, BeforeTransmitInterceptorContextMut,
            },
            Intercept,
        },
        orchestrator::{HttpRequest, HttpResponse},
        result::ConnectorError,
        runtime_components::RuntimeComponents,
        stalled_stream_protection::StalledStreamProtectionConfig,
    },
};
use aws_smithy_types::{body::SdkBody, config_bag::ConfigBag};
use std::{
    io::{Read, Seek, SeekFrom},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Notify;

#[derive(Debug, Default)]
struct Active {
    count: AtomicUsize,
    idle: Notify,
}
struct Ticket(Arc<Active>);
impl Drop for Ticket {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}
/// One instance per part, retained across SDK retries and caller cancellation.
#[derive(Clone)]
pub(super) struct FileBody {
    source: Source,
    offset: u64,
    length: u64,
    active: Arc<Active>,
}
impl std::fmt::Debug for FileBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3FileBody").finish_non_exhaustive()
    }
}
impl FileBody {
    pub fn new(source: Source, offset: u64, length: u64) -> Self {
        Self {
            source,
            offset,
            length,
            active: Arc::new(Active::default()),
        }
    }
    pub async fn drain(&self) {
        loop {
            let idle = self.active.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self.active.count.load(Ordering::Acquire) == 0 {
                return;
            }
            idle.await;
        }
    }
}
impl Intercept for FileBody {
    fn name(&self) -> &'static str {
        "S3SynchronousFileBody"
    }
    fn modify_before_serialization(
        &self,
        _: &mut BeforeSerializationInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        // This connector reads the source itself, so the SDK's asynchronous
        // body monitor cannot observe progress. Configure this before its
        // interceptor installs a monitor; keep download protection unchanged.
        // The synchronous connector enforces its own connect/global timeouts.
        if let Some(protection) = cfg.load::<StalledStreamProtectionConfig>().cloned() {
            let builder: aws_smithy_runtime_api::client::stalled_stream_protection::Builder =
                protection.into();
            cfg.interceptor_state()
                .store_put(builder.upload_enabled(false).build());
        }
        Ok(())
    }
    fn modify_before_transmit(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _: &RuntimeComponents,
        _: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        // Reattach on every attempt: SDK request cloning clears extensions.
        context.request_mut().add_extension(self.clone());
        Ok(())
    }
}
#[derive(Clone, Debug)]
struct Connector {
    fallback: SharedHttpConnector,
    agent: ureq::Agent,
}
impl HttpConnector for Connector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let request = match request.try_into_http1x() {
            Ok(r) => r,
            Err(e) => {
                return HttpConnectorFuture::ready(Err(ConnectorError::other(e.into(), None)))
            }
        };
        let Some(file) = request.extensions().get::<FileBody>().cloned() else {
            return self
                .fallback
                .call(HttpRequest::try_from(request).expect("unchanged SDK request"));
        };
        let agent = self.agent.clone();
        file.active.count.fetch_add(1, Ordering::AcqRel);
        let ticket = Ticket(file.active.clone());
        HttpConnectorFuture::new(async move {
            tokio::task::spawn_blocking(move || {
                let _ticket = ticket;
                let result = (|| -> anyhow::Result<HttpResponse> {
                    anyhow::ensure!(request.method() == "PUT", "file body requires PUT");
                    anyhow::ensure!(
                        request
                            .headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            == Some(file.length.to_string().as_str()),
                        "file body length differs from signed request"
                    );
                    anyhow::ensure!(
                        request
                            .headers()
                            .get("x-amz-content-sha256")
                            .and_then(|v| v.to_str().ok())
                            == Some("UNSIGNED-PAYLOAD"),
                        "file body requires unsigned payload"
                    );
                    let mut source = file.source.open()?;
                    source.seek(SeekFrom::Start(file.offset))?;
                    let check = source.try_clone()?;
                    let mut builder = ureq::http::Request::builder()
                        .method(request.method())
                        .uri(request.uri());
                    *builder.headers_mut().expect("valid request") = request.headers().clone();
                    let response = agent.run(
                        builder
                            .body(ureq::SendBody::from_owned_reader(source.take(file.length)))?,
                    )?;
                    file.source.check(&check)?;
                    let (parts, mut body) = response.into_parts();
                    let mut bytes = Vec::new();
                    body.as_reader()
                        .take(4 * 1024 * 1024 + 1)
                        .read_to_end(&mut bytes)?;
                    anyhow::ensure!(bytes.len() <= 4 * 1024 * 1024, "oversize S3 PUT response");
                    Ok(HttpResponse::try_from(http::Response::from_parts(
                        parts,
                        SdkBody::from(bytes),
                    ))?)
                })();
                result.map_err(|e| ConnectorError::other(e.into(), None))
            })
            .await
            .map_err(|e| ConnectorError::other(e.into(), None))?
        })
    }
}
pub(super) fn client(fallback: SharedHttpClient) -> SharedHttpClient {
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .max_idle_connections(256)
        .max_idle_connections_per_host(256)
        .output_buffer_size(64 * 1024)
        .build()
        .new_agent();
    http_client_fn(move |settings, components| {
        SharedHttpConnector::new(Connector {
            fallback: fallback.http_connector(settings, components),
            agent: agent.clone(),
        })
    })
}

// The synchronous connector reads the confined source itself. Giving the SDK
// a length-only body avoids opening and seeking an unused asynchronous reader.
// It fails closed if any other transport tries to consume it.
struct FileBodyMarker(u64);
impl http_body::Body for FileBodyMarker {
    type Data = bytes::Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(Some(Err(std::io::Error::other(
            "S3 file body requires its synchronous connector",
        ))))
    }
    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.0)
    }
}
pub(super) fn body(length: u64) -> aws_sdk_s3::primitives::ByteStream {
    aws_sdk_s3::primitives::ByteStream::new(SdkBody::from_body_1_x(FileBodyMarker(length)))
}
