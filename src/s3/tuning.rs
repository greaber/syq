//! Process-local admission control. Samples are useful copies, not calibration traffic.
use super::{Integrity, Options};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

pub(super) struct Tuning {
    control_ns: AtomicU64,
    tigris: bool,
    pub requests: Arc<Budget>,
    pub upload_buffers: Arc<tokio::sync::Semaphore>,
}
impl Tuning {
    pub fn new(options: &Options) -> Self {
        Self {
            control_ns: AtomicU64::new(u64::MAX),
            upload_buffers: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
            // These measured seeds describe provider request behavior; they do
            // not change the data route, integrity policy, or explicit overrides.
            tigris: options
                .endpoint
                .as_deref()
                .and_then(|s| url::Url::parse(s).ok())
                .and_then(|u| u.host_str().map(str::to_owned))
                .is_some_and(|host| {
                    host == "t3.storage.dev"
                        || host == "fly.storage.tigris.dev"
                        || host.ends_with(".tigris.dev")
                }),
            requests: Arc::new(Budget::new(
                if options.integrity == Integrity::None && options.automatic_concurrency {
                    64
                } else {
                    256
                },
                options.integrity == Integrity::None && options.automatic_concurrency,
            )),
        }
    }
    pub fn observe_control(&self, elapsed: Duration) {
        // An empty placement check is not a network observation.
        if elapsed >= Duration::from_micros(100) {
            self.control_ns
                .fetch_min(elapsed.as_nanos().min(u64::MAX as u128) as u64, Relaxed);
        }
    }
    pub fn high_latency(&self) -> bool {
        let ns = self.control_ns.load(Relaxed);
        !self.tigris && ns != u64::MAX && ns >= 50_000_000
    }
    pub fn configure(&self, tiny: bool, workers: usize, request_cap: usize) {
        let ns = self.control_ns.load(Relaxed);
        let mut s = self.requests.state.lock().unwrap();
        s.max = request_cap;
        s.limit = s.limit.min(request_cap);
        if tiny && self.high_latency() {
            // At high request latency, starting below the measured capacity
            // leaves short queues waiting through an extra response cycle.
            s.limit = request_cap;
        }
        super::diagnostics::planning(
            (ns != u64::MAX).then(|| Duration::from_nanos(ns)),
            workers,
            s.limit,
        );
    }
    pub fn tigris(&self) -> bool {
        self.tigris
    }
    pub fn local_latency(&self) -> bool {
        self.control_ns.load(Relaxed) < 3_000_000
    }
}
struct Window {
    active: usize,
    limit: usize,
    max: usize,
    adaptive: bool,
    since: Instant,
    bytes: u64,
    completed: usize,
    saturated: bool,
    previous: Option<(usize, f64)>,
    settled: bool,
}
pub(super) struct Budget {
    state: Mutex<Window>,
    changed: Notify,
}
pub(super) struct Permit {
    budget: Arc<Budget>,
}
impl Budget {
    fn new(limit: usize, adaptive: bool) -> Self {
        Self {
            state: Mutex::new(Window {
                active: 0,
                limit,
                max: 256,
                adaptive,
                since: Instant::now(),
                bytes: 0,
                completed: 0,
                saturated: false,
                previous: None,
                settled: false,
            }),
            changed: Notify::new(),
        }
    }
    pub async fn acquire(self: &Arc<Self>) -> Permit {
        loop {
            let ready = self.changed.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            {
                let mut s = self.state.lock().unwrap();
                if s.active < s.limit {
                    s.active += 1;
                    return Permit {
                        budget: self.clone(),
                    };
                }
                s.saturated = true;
            }
            ready.await;
        }
    }
    pub fn completed(&self, bytes: u64) {
        let mut s = self.state.lock().unwrap();
        s.bytes += bytes;
        s.completed += 1;
        let elapsed = s.since.elapsed();
        if !s.adaptive || s.settled || elapsed < Duration::from_millis(250) || s.completed < 16 {
            return;
        }
        // A throughput plateau is a reason to stop adding competing requests.
        // The first window includes startup and is deliberately only a baseline.
        let rate = s.bytes as f64 / elapsed.as_secs_f64();
        if s.saturated {
            if let Some((old_limit, old_rate)) = s.previous {
                if rate < old_rate * 1.05 {
                    s.limit = old_limit;
                    s.settled = true;
                }
            }
            if !s.settled && s.limit < s.max {
                s.previous = Some((s.limit, rate));
                s.limit = (s.limit * 2).min(s.max);
            }
        }
        s.since = Instant::now();
        s.bytes = 0;
        s.completed = 0;
        s.saturated = false;
        self.changed.notify_waiters();
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.budget.state.lock().unwrap().active -= 1;
        // One completion frees one slot. Waking the entire queue makes every
        // waiting request compete for that slot; capacity growth wakes all
        // waiters separately in completed().
        self.budget.changed.notify_one();
    }
}

// A bounded payload budget, plus room for the socket and transient source opens.
// TLS/SDK allocations are additional; the measured request ceiling bounds those.
fn small_capacity(soft: u64, open: usize, largest: u64) -> usize {
    let descriptors = soft.saturating_sub(open as u64).saturating_sub(64) / 4;
    let payloads = (256 * 1024 * 1024u64) / largest.max(1);
    descriptors.min(payloads).min(4096) as usize
}
pub(super) fn small_upload_capacity(largest: u64) -> anyhow::Result<usize> {
    use anyhow::Context;
    let limits = crate::fsops::nofile_limits().context("read S3 descriptor limit")?;
    let open = crate::fsops::current_open_descriptor_count(limits.rlim_cur)?;
    let capacity = small_capacity(limits.rlim_cur as u64, open, largest);
    anyhow::ensure!(capacity > 0, "insufficient file descriptors for S3 uploads; raise the open-file limit or reduce source selectors");
    Ok(capacity)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Context};

    #[test]
    fn releasing_one_slot_wakes_only_one_queued_request() {
        struct Wakes(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Relaxed);
            }
        }
        let wakes = Arc::new(Wakes(std::sync::atomic::AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let budget = Arc::new(Budget::new(1, false));
        let std::task::Poll::Ready(held) = Box::pin(budget.acquire()).as_mut().poll(&mut cx) else {
            panic!("initial slot unavailable");
        };
        let mut waiting: Vec<_> = (0..64).map(|_| Box::pin(budget.acquire())).collect();
        for request in &mut waiting {
            assert!(request.as_mut().poll(&mut cx).is_pending());
        }
        drop(held);
        assert_eq!(wakes.0.load(Relaxed), 1);
    }

    #[test]
    fn cancelled_notified_request_passes_the_free_slot_to_another_waiter() {
        let budget = Arc::new(Budget::new(1, false));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let std::task::Poll::Ready(held) = Box::pin(budget.acquire()).as_mut().poll(&mut cx) else {
            panic!("initial slot unavailable");
        };
        let mut cancelled = Box::pin(budget.acquire());
        let mut next = Box::pin(budget.acquire());
        assert!(cancelled.as_mut().poll(&mut cx).is_pending());
        assert!(next.as_mut().poll(&mut cx).is_pending());
        drop(held);
        drop(cancelled);
        let std::task::Poll::Ready(held) = next.as_mut().poll(&mut cx) else {
            panic!("cancelled waiter stranded the free slot");
        };
        assert_eq!(budget.state.lock().unwrap().active, 1);
        drop(held);
        assert_eq!(budget.state.lock().unwrap().active, 0);
    }

    #[test]
    fn capacity_growth_admits_multiple_waiters_without_releasing_existing_slots() {
        let budget = Arc::new(Budget::new(4, true));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut held = Vec::new();
        for _ in 0..4 {
            let std::task::Poll::Ready(permit) = Box::pin(budget.acquire()).as_mut().poll(&mut cx)
            else {
                panic!("initial slot unavailable");
            };
            held.push(permit);
        }
        let mut waiting: Vec<_> = (0..4).map(|_| Box::pin(budget.acquire())).collect();
        for request in &mut waiting {
            assert!(request.as_mut().poll(&mut cx).is_pending());
        }
        budget.state.lock().unwrap().since = Instant::now() - Duration::from_secs(1);
        for _ in 0..16 {
            budget.completed(1024);
        }
        for request in &mut waiting {
            let std::task::Poll::Ready(permit) = request.as_mut().poll(&mut cx) else {
                panic!("capacity growth left an available slot asleep");
            };
            held.push(permit);
        }
        assert_eq!(budget.state.lock().unwrap().active, 8);
        assert!(Box::pin(budget.acquire())
            .as_mut()
            .poll(&mut cx)
            .is_pending());
        drop(held);
        assert_eq!(budget.state.lock().unwrap().active, 0);
    }

    #[test]
    fn tiny_upload_budget_leaves_room_for_existing_descriptors() {
        assert_eq!(small_capacity(1024, 900, 1024), 15);
        assert_eq!(small_capacity(64, 10, 1024), 0);
        assert_eq!(small_capacity(8192, 8, 1024), 2030);
        assert_eq!(small_capacity(524288, 8, 1024), 4096);
    }
    #[test]
    fn tiny_upload_budget_bounds_payload_memory_and_empty_objects() {
        assert_eq!(small_capacity(524288, 8, 1024 * 1024), 256);
        assert_eq!(small_capacity(524288, 8, 0), 4096);
    }
}
