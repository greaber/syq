//! Cancel requests, streaming responses, and blocking upload sockets.
use aws_smithy_runtime_api::client::{
    http::HttpConnectorFuture, orchestrator::HttpRequest, result::ConnectorError,
};
use std::{
    future::Future,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout, Transport,
};

#[derive(Debug, Default)]
struct State {
    /// When the copy was cancelled.
    cancelled: Option<tokio::time::Instant>,
    sockets: Vec<Weak<TcpStream>>,
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
        let sockets = {
            let mut state = self.state.lock().unwrap();
            state
                .cancelled
                .get_or_insert_with(tokio::time::Instant::now);
            std::mem::take(&mut state.sockets)
        };
        self.changed.notify_waiters();
        for socket in sockets.into_iter().filter_map(|s| s.upgrade()) {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    fn register(&self, socket: &Arc<TcpStream>) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.cancelled.is_some() {
            socket.shutdown(Shutdown::Both)?;
            return Err(interrupted());
        }
        state.sockets.retain(|s| s.strong_count() > 0);
        state.sockets.push(Arc::downgrade(socket));
        Ok(())
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

    pub(super) fn wrap(
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

/// ureq's default TCP transport owns its socket privately. This equivalent
/// transport shares the socket with a weak cancellation registry, without
/// duplicating its descriptor or replacing ureq's HTTP, proxy, or TLS layers.
#[derive(Debug)]
pub(super) struct TcpConnector(pub Arc<Cancellation>);

impl<In: Transport> Connector<In> for TcpConnector {
    type Out = Either<In, Tcp>;

    fn connect(
        &self,
        details: &ConnectionDetails<'_>,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        if let Some(transport) = chained {
            return Ok(Some(Either::A(transport)));
        }
        let started = Instant::now();
        let budget = details.timeout.not_zero().map(|d| *d);
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no S3 socket addresses");
        for (index, address) in details.addrs.iter().enumerate() {
            if self.0.state.lock().unwrap().cancelled.is_some() {
                return Err(interrupted().into());
            }
            let stream = if let Some(budget) = budget {
                let remaining = budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(ureq::Error::Timeout(details.timeout.reason));
                }
                // Share the connect budget across the remaining addresses.
                let share = remaining / (details.addrs.len() - index) as u32;
                TcpStream::connect_timeout(address, share.max(Duration::from_millis(1)))
            } else {
                TcpStream::connect(address)
            };
            match stream {
                Ok(stream) => {
                    stream.set_nodelay(details.config.no_delay())?;
                    let stream = Arc::new(stream);
                    self.0.register(&stream)?;
                    return Ok(Some(Either::B(Tcp {
                        stream,
                        buffers: LazyBuffers::new(
                            details.config.input_buffer_size(),
                            details.config.output_buffer_size(),
                        ),
                        write_timeout: None,
                        read_timeout: None,
                    })));
                }
                Err(error) => last = error,
            }
        }
        Err(last.into())
    }
}

#[derive(Debug)]
pub(super) struct Tcp {
    stream: Arc<TcpStream>,
    buffers: LazyBuffers,
    write_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
}

fn result<T>(value: io::Result<T>, timeout: NextTimeout) -> Result<T, ureq::Error> {
    value.map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            ureq::Error::Timeout(timeout.reason)
        } else {
            error.into()
        }
    })
}

impl Transport for Tcp {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let duration = timeout.not_zero().map(|d| *d);
        if duration != self.write_timeout {
            self.stream.set_write_timeout(duration)?;
            self.write_timeout = duration;
        }
        result(
            (&*self.stream).write_all(&self.buffers.output()[..amount]),
            timeout,
        )
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let duration = timeout.not_zero().map(|d| *d);
        if duration != self.read_timeout {
            self.stream.set_read_timeout(duration)?;
            self.read_timeout = duration;
        }
        let amount = result(
            (&*self.stream).read(self.buffers.input_append_buf()),
            timeout,
        )?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        if self.stream.set_nonblocking(true).is_err() {
            return false;
        }
        let open = self
            .stream
            .peek(&mut [0])
            .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock);
        self.stream.set_nonblocking(false).is_ok() && open
    }
}
