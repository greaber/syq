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

/// Place below compression and buffering. TCP record buffering must also be
/// above this writer, otherwise a large record would accumulate before a burst.
pub(crate) struct PacedWriter<W, S> {
    pub(crate) inner: W,
    pub(crate) budget: std::sync::Arc<Budget>,
    pub(crate) stopped: S,
}

impl<W: Write, S: Fn() -> bool> Write for PacedWriter<W, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let n = bytes.len().min(self.budget.chunk());
        self.budget.wait(n, &self.stopped)?;
        self.inner.write_all(&bytes[..n])?;
        Ok(n)
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
            inner: Vec::new(),
            budget,
            stopped: || false,
        };
        writer.write_all(&input).unwrap();
        assert_eq!(writer.inner, input);
    }

    #[test]
    fn chunks_bound_both_extreme_rates() {
        assert_eq!(Budget::new(1).chunk(), 1);
        assert_eq!(Budget::new(u64::MAX).chunk(), MAX_CHUNK as usize);
    }
}
