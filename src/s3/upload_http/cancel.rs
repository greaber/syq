//! Cancel requests, streaming responses, and blocking upload sockets.
use aws_smithy_runtime_api::client::{http::HttpConnectorFuture, result::ConnectorError};
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
    cancelled: bool,
    sockets: Vec<Weak<TcpStream>>,
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
            state.cancelled = true;
            std::mem::take(&mut state.sockets)
        };
        self.changed.notify_waiters();
        for socket in sockets.into_iter().filter_map(|s| s.upgrade()) {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    fn register(&self, socket: &Arc<TcpStream>) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.cancelled {
            socket.shutdown(Shutdown::Both)?;
            return Err(interrupted());
        }
        state.sockets.retain(|s| s.strong_count() > 0);
        state.sockets.push(Arc::downgrade(socket));
        Ok(())
    }

    pub(super) fn wrap(self: &Arc<Self>, request: HttpConnectorFuture) -> HttpConnectorFuture {
        let cancellation = self.clone();
        HttpConnectorFuture::new(async move {
            let cancelled = cancellation.changed.notified();
            tokio::pin!(cancelled);
            cancelled.as_mut().enable();
            if cancellation.state.lock().unwrap().cancelled {
                return Err(ConnectorError::other(interrupted().into(), None));
            }
            tokio::select! {
                biased;
                _ = &mut cancelled => Err(ConnectorError::other(interrupted().into(), None)),
                result = request => {
                    let mut response = result?;
                    let body = std::mem::replace(response.body_mut(), aws_smithy_types::body::SdkBody::empty());
                    *response.body_mut() = cancellation.body(body);
                    Ok(response)
                },
            }
        })
    }

    fn body(
        self: &Arc<Self>,
        body: aws_smithy_types::body::SdkBody,
    ) -> aws_smithy_types::body::SdkBody {
        let mut changed = Box::pin(self.changed.clone().notified_owned());
        changed.as_mut().enable();
        let cancelled = self.state.lock().unwrap().cancelled;
        aws_smithy_types::body::SdkBody::from_body_1_x(ResponseBody {
            body,
            changed,
            cancelled,
        })
    }
}

// Keep cancellation active after headers arrive, including SDK deserialization
// of control responses and streaming GET bodies. Otherwise a body with no
// deadline could prevent the engine from draining after Ctrl-C.
struct ResponseBody {
    body: aws_smithy_types::body::SdkBody,
    changed: Pin<Box<tokio::sync::futures::OwnedNotified>>,
    cancelled: bool,
}
impl http_body::Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = aws_smithy_types::body::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if self.cancelled || self.changed.as_mut().poll(cx).is_ready() {
            self.cancelled = true;
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
            if self.0.state.lock().unwrap().cancelled {
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
