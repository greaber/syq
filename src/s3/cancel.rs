//! Cancel every S3 request and streaming response.
use aws_smithy_runtime_api::client::{
    http::{
        http_client_fn, HttpClient, HttpConnector, HttpConnectorFuture, SharedHttpClient,
        SharedHttpConnector,
    },
    orchestrator::HttpRequest,
    result::ConnectorError,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::Notify;

#[derive(Debug, Default)]
struct State {
    /// When the copy was cancelled.
    cancelled: Option<tokio::time::Instant>,
}

/// How long a multipart upload's abort may still run after cancellation.
/// Without it, an upload that has no recovery record stays on the server,
/// and nothing would find it again. Requests have no read deadline, so the
/// grace is what keeps cancellation prompt when the server does not answer.
pub(super) const ABORT_GRACE: Duration = Duration::from_secs(5);

/// Whether `request` aborts a multipart upload: S3 has no other `DELETE`
/// that names an upload.
fn aborts_upload(request: &HttpRequest) -> bool {
    request.method() == "DELETE"
        && url::Url::parse(request.uri())
            .is_ok_and(|url| url.query_pairs().any(|(key, _)| key == "uploadId"))
}

#[derive(Debug, Default)]
pub(in crate::s3) struct Cancellation {
    state: Mutex<State>,
    changed: Arc<Notify>,
}

fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "S3 copy cancelled")
}

impl Cancellation {
    pub fn cancel(&self) {
        self.state
            .lock()
            .unwrap()
            .cancelled
            .get_or_insert_with(tokio::time::Instant::now);
        self.changed.notify_waiters();
    }

    /// Resolves when a request must stop: at cancellation, or `grace` after
    /// it.
    async fn stopped(self: Arc<Self>, grace: Option<Duration>) {
        loop {
            let changed = self.changed.clone().notified_owned();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let cancelled = self.state.lock().unwrap().cancelled;
            if let Some(cancelled) = cancelled {
                if let Some(grace) = grace {
                    tokio::time::sleep_until(cancelled + grace).await;
                }
                return;
            }
            changed.await;
        }
    }

    fn wrap(
        self: &Arc<Self>,
        request: HttpRequest,
        send: impl FnOnce(HttpRequest) -> HttpConnectorFuture,
    ) -> HttpConnectorFuture {
        let grace = aborts_upload(&request).then_some(ABORT_GRACE);
        let request = send(request);
        let mut stop: Stop = Box::pin(self.clone().stopped(grace));
        HttpConnectorFuture::new(async move {
            tokio::select! {
                biased;
                _ = &mut stop => Err(ConnectorError::other(interrupted().into(), None)),
                result = request => {
                    let mut response = result?;
                    let body = std::mem::replace(response.body_mut(), aws_smithy_types::body::SdkBody::empty());
                    *response.body_mut() = aws_smithy_types::body::SdkBody::from_body_1_x(ResponseBody {
                        body,
                        stop: Some(stop),
                    });
                    Ok(response)
                },
            }
        })
    }
}

type Stop = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;

/// Wraps `transport` so that `cancellation` stops each of its requests and
/// response bodies.
pub(super) fn client(
    transport: SharedHttpClient,
    cancellation: Arc<Cancellation>,
) -> SharedHttpClient {
    http_client_fn(move |settings, components| {
        SharedHttpConnector::new(Connector {
            inner: transport.http_connector(settings, components),
            cancellation: cancellation.clone(),
        })
    })
}

#[derive(Clone, Debug)]
struct Connector {
    inner: SharedHttpConnector,
    cancellation: Arc<Cancellation>,
}
impl HttpConnector for Connector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        self.cancellation
            .wrap(request, |request| self.inner.call(request))
    }
}

/// The SDK's sleeps, such as its retry backoff, for a client this cancels.
/// After cancellation none lasts past the abort grace, so an abort that the
/// server asks to retry later cannot hold up cancellation; its next attempt
/// is then refused.
#[derive(Debug)]
pub(in crate::s3) struct Sleep(pub Arc<Cancellation>);
impl aws_sdk_s3::config::AsyncSleep for Sleep {
    fn sleep(&self, duration: Duration) -> aws_sdk_s3::config::Sleep {
        let stopped = self.0.clone().stopped(Some(ABORT_GRACE));
        aws_sdk_s3::config::Sleep::new(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {}
                () = stopped => {}
            }
        })
    }
}

// Keep cancellation active after headers arrive, including SDK deserialization
// of control responses and streaming GET bodies. Otherwise a body with no
// deadline could prevent the engine from draining after Ctrl-C.
struct ResponseBody {
    body: aws_smithy_types::body::SdkBody,
    /// `None` once the request had to stop.
    stop: Option<Stop>,
}
impl http_body::Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = aws_smithy_types::body::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if self
            .stop
            .as_mut()
            .is_none_or(|stop| stop.as_mut().poll(cx).is_ready())
        {
            self.stop = None;
            return Poll::Ready(Some(Err(interrupted().into())));
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests;
