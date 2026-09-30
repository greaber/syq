//! Sender-side byte pacing, independent of file and request boundaries.
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MAX_CHUNK: u64 = 64 * 1024;
const CANCEL_INTERVAL: Duration = Duration::from_millis(25);

/// One budget for all sending connections in a copy. Idle credit is bounded,
/// so a long scan does not buy an unbounded burst when payload starts.
pub(crate) struct Budget {
    rate: u64,
    burst: u64,
    state: Mutex<State>,
}

struct State {
    at: Instant,
    credit: f64,
}

impl Budget {
    pub(crate) fn new(rate: u64) -> Self {
        assert!(rate > 0);
        let burst = (rate / 100).clamp(1, MAX_CHUNK);
        Self {
            rate,
            burst,
            state: Mutex::new(State {
                at: Instant::now(),
                credit: burst as f64,
            }),
        }
    }

    pub(crate) fn rate(&self) -> u64 {
        self.rate
    }

    pub(crate) fn chunk(&self) -> usize {
        self.burst as usize
    }

    /// Debit before writing. Concurrent callers reserve successive time slots;
    /// neither the number of workers nor their request sizes enlarge credit.
    fn reserve(&self, now: Instant, bytes: usize) -> Duration {
        assert!(bytes <= self.chunk());
        let mut state = self.state.lock().unwrap();
        let observed = now.max(state.at);
        let elapsed = observed.duration_since(state.at).as_secs_f64();
        state.credit = (state.credit + elapsed * self.rate as f64).min(self.burst as f64);
        state.at = observed;
        state.credit -= bytes as f64;
        observed.duration_since(now)
            + Duration::from_secs_f64((-state.credit / self.rate as f64).max(0.0))
    }

    pub(crate) fn wait(&self, bytes: usize, stopped: impl Fn() -> bool) -> io::Result<()> {
        if stopped() {
            return Err(cancelled());
        }
        let now = Instant::now();
        let delay = self.reserve(now, bytes);
        while now.elapsed() < delay {
            if stopped() {
                return Err(cancelled());
            }
            std::thread::sleep(delay.saturating_sub(now.elapsed()).min(CANCEL_INTERVAL));
        }
        if stopped() {
            Err(cancelled())
        } else {
            Ok(())
        }
    }
}

fn cancelled() -> io::Error {
    // Interrupted is retried automatically by Write::write_all.
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "bandwidth-limited transfer cancelled",
    )
}

/// Observe peer shutdown without consuming protocol bytes or changing the
/// socket's blocking mode (which is shared by its cloned descriptors).
pub(crate) fn socket_closed(socket: &std::net::TcpStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut fd = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    #[cfg(target_os = "linux")]
    {
        fd.events |= libc::POLLRDHUP;
    }
    let result = unsafe { libc::poll(&mut fd, 1, 0) };
    let mask = libc::POLLHUP | libc::POLLERR | libc::POLLNVAL;
    #[cfg(target_os = "linux")]
    let mask = mask | libc::POLLRDHUP;
    if result > 0 && fd.revents & mask != 0 {
        return true;
    }
    #[cfg(not(target_os = "linux"))]
    {
        // BSD/macOS poll need not report HUP for a peer's FIN. A nonblocking
        // peek observes EOF without changing shared descriptor flags.
        let mut byte = 0u8;
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        received == 0
    }
    #[cfg(target_os = "linux")]
    false
}

/// Place below compression and buffering. TCP record buffering must also be
/// above this writer, otherwise a large record would accumulate before a burst.
pub(crate) struct PacedWriter<W, S> {
    pub(crate) inner: W,
    pub(crate) budget: std::sync::Arc<Budget>,
    pub(crate) stopped: S,
    pub(crate) handshake_pending: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl<W: Write, S: Fn() -> bool> Write for PacedWriter<W, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self
            .handshake_pending
            .as_ref()
            .is_some_and(|active| active.load(std::sync::atomic::Ordering::Acquire))
        {
            return self.inner.write(bytes);
        }
        let n = bytes.len().min(self.budget.chunk());
        self.budget.wait(n, &self.stopped)?;
        self.inner.write_all(&bytes[..n])?;
        Ok(n)
    }

    fn write_vectored(&mut self, buffers: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if self
            .handshake_pending
            .as_ref()
            .is_some_and(|active| active.load(std::sync::atomic::Ordering::Acquire))
        {
            return self.inner.write_vectored(buffers);
        }
        // TCP records supply a header and body. Keep them in the same syscall
        // without allocating or copying, while still bounding the total write.
        let mut slices = [io::IoSlice::new(&[]); 2];
        let mut count = 0;
        let mut bytes = 0;
        for buffer in buffers.iter().filter(|buffer| !buffer.is_empty()) {
            let n = buffer.len().min(self.budget.chunk() - bytes);
            slices[count] = io::IoSlice::new(&buffer[..n]);
            count += 1;
            bytes += n;
            if count == slices.len() || bytes == self.budget.chunk() {
                break;
            }
        }
        if bytes == 0 {
            return Ok(0);
        }
        self.budget.wait(bytes, &self.stopped)?;
        let mut remaining = &mut slices[..count];
        while !remaining.is_empty() {
            match self.inner.write_vectored(remaining) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => io::IoSlice::advance_slices(&mut remaining, n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_share_credit_and_bound_idle_bursts() {
        let budget = Budget::new(1_000_000);
        let now = Instant::now();
        assert_eq!(budget.reserve(now, 10_000), Duration::ZERO);
        assert_eq!(budget.reserve(now, 10_000), Duration::from_millis(10));
        assert_eq!(budget.reserve(now, 10_000), Duration::from_millis(20));
        let later = now + Duration::from_secs(30);
        assert_eq!(budget.reserve(later, 10_000), Duration::ZERO);
        assert_eq!(budget.reserve(later, 10_000), Duration::from_millis(10));
    }

    #[test]
    fn out_of_order_callers_do_not_backdate_reservations() {
        let budget = Budget::new(1_000_000);
        let now = Instant::now();
        let later = now + Duration::from_millis(20);
        assert_eq!(budget.reserve(later, 10_000), Duration::ZERO);
        assert_eq!(budget.reserve(now, 10_000), Duration::from_millis(30));
    }

    #[test]
    fn slower_sender_pays_no_per_write_sleep() {
        let budget = Budget::new(1_000_000);
        let now = Instant::now();
        for i in 0..100 {
            assert_eq!(
                budget.reserve(now + Duration::from_millis(i * 20), 10_000),
                Duration::ZERO
            );
        }
    }

    #[test]
    fn cancellation_writes_nothing_and_is_not_retryable() {
        let mut writer = PacedWriter {
            handshake_pending: None,
            inner: Vec::new(),
            budget: std::sync::Arc::new(Budget::new(1024)),
            stopped: || true,
        };
        let error = writer.write_all(&[1; 100]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(writer.inner.is_empty());
    }

    #[test]
    fn cancellation_during_wait_never_reaches_output() {
        let budget = std::sync::Arc::new(Budget::new(100));
        budget.reserve(Instant::now(), budget.chunk());
        let checks = std::cell::Cell::new(0);
        let mut writer = PacedWriter {
            handshake_pending: None,
            inner: Vec::new(),
            budget,
            stopped: || {
                checks.set(checks.get() + 1);
                checks.get() > 1
            },
        };
        assert_eq!(
            writer.write(&[42]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(writer.inner.is_empty());
    }

    #[test]
    fn writer_preserves_bytes_across_chunk_boundaries() {
        let budget = std::sync::Arc::new(Budget::new(u64::MAX));
        let input = vec![42; 3 * MAX_CHUNK as usize + 17];
        let mut writer = PacedWriter {
            handshake_pending: None,
            inner: Vec::new(),
            budget,
            stopped: || false,
        };
        writer.write_all(&input).unwrap();
        assert_eq!(writer.inner, input);
    }

    #[test]
    fn vectored_records_preserve_headers_and_partial_writes() {
        struct ShortWriter(Vec<u8>);
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let n = bytes.len().min(7);
                self.0.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        // The default vectored writer uses only the first slice. Short writes
        // exercise partial progress and the boundary across header and body.
        let mut writer = PacedWriter {
            handshake_pending: None,
            inner: ShortWriter(Vec::new()),
            budget: std::sync::Arc::new(Budget::new(u64::MAX)),
            stopped: || false,
        };
        let header = [1, 2, 3, 4];
        let body = vec![42; MAX_CHUNK as usize + 17];
        let mut buffers = [io::IoSlice::new(&header), io::IoSlice::new(&body)];
        let mut remaining = &mut buffers[..];
        while !remaining.is_empty() {
            let n = writer.write_vectored(remaining).unwrap();
            assert!(n <= MAX_CHUNK as usize);
            io::IoSlice::advance_slices(&mut remaining, n);
        }
        assert_eq!(writer.inner.0, [header.as_slice(), &body].concat());
    }

    #[test]
    fn peer_shutdown_cancels_a_throttled_record() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let socket = server.try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            let mut writer = PacedWriter {
                handshake_pending: None,
                inner: server,
                budget: std::sync::Arc::new(Budget::new(1)),
                stopped: || socket_closed(&socket),
            };
            writer.write_all(&[42; 1024])
        });
        std::thread::sleep(Duration::from_millis(20));
        client.shutdown(std::net::Shutdown::Both).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !writer.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(writer.is_finished(), "sender ignored peer shutdown");
        assert!(writer.join().unwrap().is_err());
    }

    #[test]
    fn chunks_bound_both_extreme_rates() {
        assert_eq!(Budget::new(1).chunk(), 1);
        assert_eq!(Budget::new(u64::MAX).chunk(), MAX_CHUNK as usize);
    }
}
