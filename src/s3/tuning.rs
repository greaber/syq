//! Process-local admission control. Samples are useful copies, not calibration traffic.
use super::Options;
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
    fixed_requests: Option<usize>,
    tigris: bool,
    upload: bool,
    pub requests: Arc<Budget>,
    pub upload_buffers: Arc<tokio::sync::Semaphore>,
}
impl Tuning {
    pub fn new(options: &Options, args: &crate::cli::Args) -> Self {
        Self {
            control_ns: AtomicU64::new(u64::MAX),
            upload: options.upload,
            fixed_requests: args.tuning_options.and_then(|t| t.s3_requests),
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
                args.tuning_options
                    .and_then(|t| t.s3_requests)
                    .unwrap_or(64),
                args.tuning_options.and_then(|t| t.s3_requests).is_none(),
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
        // Tigris uploads keep their conservative seed. Downloads still need
        // enough requests in flight to cover a long round trip, regardless of
        // provider; short copies cannot recover time spent ramping from 64.
        (!self.tigris || !self.upload) && ns != u64::MAX && ns >= 50_000_000
    }
    pub fn configure(&self, tiny: bool, request_cap: usize) {
        let request_cap = request_cap.max(self.fixed_requests.unwrap_or(1));
        let mut s = self.requests.state.lock().unwrap();
        s.max = request_cap;
        s.limit = s.limit.min(request_cap);
        if self.fixed_requests.is_none() && tiny && self.high_latency() {
            // At high request latency, starting below the measured capacity
            // leaves short queues waiting through an extra response cycle.
            s.limit = request_cap;
        }
    }
    pub fn tigris(&self) -> bool {
        self.tigris
    }
    pub fn request_limit(&self) -> usize {
        self.requests.state.lock().unwrap().limit
    }
    pub fn control_latency(&self) -> Option<Duration> {
        let ns = self.control_ns.load(Relaxed);
        (ns != u64::MAX).then(|| Duration::from_nanos(ns))
    }
    pub fn report(&self, workers: usize) {
        super::diagnostics::planning(self.control_latency(), workers, self.request_limit());
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
    pub fn begin_objects(&self, workers: usize) -> Option<usize> {
        let mut s = self.state.lock().unwrap();
        if s.adaptive && !s.settled && s.limit < workers {
            return None;
        }
        // Freeze the request ramp while the scheduler drains its existing jobs.
        // Some jobs may still be waiting in acquire(); increasing the request
        // limit here would let them bypass the newly chosen object concurrency.
        s.settled = true;
        Some(workers.min(s.limit))
    }
    pub fn finish_objects(&self, maximum: usize) {
        let mut s = self.state.lock().unwrap();
        if s.adaptive {
            s.limit = maximum;
            s.max = maximum;
        }
        s.adaptive = false;
        drop(s);
        self.changed.notify_waiters();
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
    fn object_controller_waits_for_request_ramp_or_plateau() {
        let budget = Budget::new(64, true);
        assert_eq!(budget.begin_objects(256), None);
        for (bytes, expected) in [(1024, 128), (2048, 256)] {
            {
                let mut s = budget.state.lock().unwrap();
                s.since = Instant::now() - Duration::from_secs(1);
                s.saturated = true;
            }
            for _ in 0..16 {
                budget.completed(bytes);
            }
            assert_eq!(budget.state.lock().unwrap().limit, expected);
            if expected < 256 {
                assert_eq!(budget.begin_objects(256), None);
            }
        }
        assert_eq!(budget.begin_objects(256), Some(256));
        assert_eq!(budget.state.lock().unwrap().limit, 256);
        budget.finish_objects(512);
        assert_eq!(budget.state.lock().unwrap().limit, 512);
        assert!(!budget.state.lock().unwrap().adaptive);

        let budget = Budget::new(64, true);
        budget.state.lock().unwrap().settled = true;
        assert_eq!(budget.begin_objects(256), Some(64));
        assert_eq!(budget.state.lock().unwrap().limit, 64);
        budget.finish_objects(512);
        assert!(!budget.state.lock().unwrap().adaptive);
    }

    #[tokio::test(start_paused = true)]
    async fn object_handoff_drains_waiting_jobs_before_opening_request_capacity() {
        let budget = Arc::new(Budget::new(2, true));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (started, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let copy_budget = budget.clone();
        let copy_gate = gate.clone();
        let copy = tokio::spawn(async move {
            crate::s3::admission::parallel(
                (0..8).collect(),
                crate::s3::admission::Concurrency {
                    initial: 8,
                    maximum: Some(16),
                    initial_probe_up: true,
                    requests: Some(copy_budget.clone()),
                },
                move |job| {
                    let budget = copy_budget.clone();
                    let gate = copy_gate.clone();
                    let started = started.clone();
                    async move {
                        let _request = budget.acquire().await;
                        started.send(job).unwrap();
                        gate.acquire().await.unwrap().forget();
                        Ok(Some(1024))
                    }
                },
            )
            .await
        });
        // Two requests are running; the other six live jobs wait for a permit.
        observed.recv().await.unwrap();
        observed.recv().await.unwrap();
        budget.state.lock().unwrap().settled = true;
        tokio::time::advance(Duration::from_millis(250)).await;
        let unexpected = tokio::time::timeout(Duration::from_millis(100), observed.recv()).await;
        gate.add_permits(8);
        copy.await.unwrap().unwrap();
        assert!(
            unexpected.is_err(),
            "handoff started another request before draining old jobs"
        );
        let mut remaining = 0;
        while observed.recv().await.is_some() {
            remaining += 1;
        }
        assert_eq!(remaining, 6);
        assert_eq!(budget.state.lock().unwrap().active, 0);
    }

    #[test]
    fn object_handoff_wakes_waiters_without_a_permit_drop() {
        struct Wakes(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Relaxed);
            }
        }
        let wakes = Arc::new(Wakes(std::sync::atomic::AtomicUsize::new(0)));
        let waker = std::task::Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let budget = Arc::new(Budget::new(1, true));
        let std::task::Poll::Ready(held) = Box::pin(budget.acquire()).as_mut().poll(&mut cx) else {
            panic!("initial slot unavailable");
        };
        let mut waiting = Box::pin(budget.acquire());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        assert_eq!(budget.begin_objects(1), Some(1));
        assert_eq!(wakes.0.load(Relaxed), 0);
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        budget.finish_objects(2);
        assert_eq!(wakes.0.load(Relaxed), 1);
        assert!(waiting.as_mut().poll(&mut cx).is_ready());
        drop(held);
    }

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
    fn initial_request_budget_accounts_for_direction_latency_and_overrides() {
        // (upload, Tigris, observed latency, small objects, explicit maximum, expected)
        for (upload, tigris, latency_ms, tiny, fixed, expected) in [
            (false, true, Some(100), true, None, 256),
            (true, true, Some(100), true, None, 64),
            (false, false, Some(100), true, None, 256),
            (true, false, Some(100), true, None, 256),
            (false, true, Some(1), true, None, 64),
            (false, true, None, true, None, 64),
            (false, true, Some(100), false, None, 64),
            (false, true, Some(100), true, Some(16), 16),
        ] {
            let tuning = Tuning {
                control_ns: AtomicU64::new(u64::MAX),
                fixed_requests: fixed,
                tigris,
                upload,
                requests: Arc::new(Budget::new(fixed.unwrap_or(64), fixed.is_none())),
                upload_buffers: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
            };
            if let Some(ms) = latency_ms {
                tuning.observe_control(Duration::from_millis(ms));
            }
            tuning.configure(tiny, 256);
            assert_eq!(
                tuning.requests.state.lock().unwrap().limit,
                expected,
                "upload={upload}, tigris={tigris}, latency={latency_ms:?}, tiny={tiny}, fixed={fixed:?}",
            );
            let ready = fixed.is_some() || expected >= 256;
            assert_eq!(
                tuning.requests.begin_objects(256),
                ready.then_some(256.min(expected))
            );
            if ready {
                assert_eq!(tuning.request_limit(), expected);
                tuning.requests.finish_objects(512);
                assert_eq!(tuning.request_limit(), fixed.unwrap_or(512));
                assert!(!tuning.requests.state.lock().unwrap().adaptive);
            }
        }
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
