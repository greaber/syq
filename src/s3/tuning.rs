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
    pub reads: crate::s3::read_recovery::Recovery,
    pub upload_buffers: Arc<tokio::sync::Semaphore>,
}
impl Tuning {
    pub fn new(options: &Options, args: &crate::cli::Args) -> Self {
        Self {
            control_ns: AtomicU64::new(u64::MAX),
            reads: crate::s3::read_recovery::Recovery::default(),
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
    pub fn configure(&self, tiny: bool, request_cap: usize, seed: usize) {
        let request_cap = request_cap.max(self.fixed_requests.unwrap_or(1));
        let mut s = self.requests.state.lock().unwrap();
        s.max = request_cap;
        s.limit = self.fixed_requests.unwrap_or(seed).min(request_cap);
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
    since: Option<Instant>,
    bytes: u64,
    completed: usize,
    recent: std::collections::VecDeque<(Instant, u64)>,
    saturated: bool,
    previous: Option<(usize, f64)>,
    slower_limit: usize,
    probe_preserved_rate: bool,
    object_rate: Option<(usize, f64, Duration)>,
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
                since: None,
                bytes: 0,
                completed: 0,
                recent: std::collections::VecDeque::new(),
                saturated: false,
                previous: None,
                slower_limit: 0,
                probe_preserved_rate: false,
                object_rate: None,
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
                    // Planning and source preparation precede request admission;
                    // they must not depress the ramp's first throughput score.
                    s.since.get_or_insert_with(Instant::now);
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
    pub fn preparation_limit(&self) -> usize {
        self.state.lock().unwrap().limit.saturating_add(1)
    }
    pub fn slower_limit(&self) -> usize {
        self.state.lock().unwrap().slower_limit
    }
    // A rejected doubling can still have a small gain. This only chooses the
    // first object probe; it does not accept the higher request setting.
    pub fn probe_preserved_rate(&self) -> bool {
        self.state.lock().unwrap().probe_preserved_rate
    }
    pub fn object_rate(&self, workers: usize) -> Option<(f64, Duration)> {
        let s = self.state.lock().unwrap();
        s.object_rate
            .filter(|(limit, _, _)| *limit == workers)
            .map(|(_, rate, elapsed)| (rate, elapsed))
    }
    pub fn rejected_limit(&self) -> Option<usize> {
        let s = self.state.lock().unwrap();
        let (previous, _) = s.previous?;
        // Read before finish_objects replaces the request ceiling. Growth is
        // always a doubling clamped to that ceiling, including the last probe.
        (s.settled && s.limit == previous).then(|| previous.saturating_mul(2).min(s.max))
    }
    pub fn begin_objects(&self, workers: usize) -> Option<usize> {
        let mut s = self.state.lock().unwrap();
        // Reaching the object seed is not evidence that the last increase helped.
        // Resolve that probe before allowing the object controller to grow again.
        if s.adaptive && !s.settled && (s.limit < workers || s.previous.is_some()) {
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
        let Some(since) = s.since else { return };
        if !s.adaptive || s.settled {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(since);
        // Seventeen endpoints give sixteen complete inter-arrival intervals.
        s.recent.push_back((now, bytes));
        if s.recent.len() > 17 {
            s.recent.pop_front();
        }
        if elapsed < Duration::from_millis(250)
            || s.completed < 16
            || (s.previous.is_none() && s.completed < s.limit)
        {
            return;
        }
        // A throughput plateau is a reason to stop adding competing requests.
        // The first window includes startup and is only a baseline, but must
        // contain a full count: the first few replies understate its capacity.
        let rate = s.bytes as f64 / elapsed.as_secs_f64();
        let before = s.limit;
        if s.saturated || s.previous.is_some() {
            if let Some((old_limit, old_rate)) = s.previous {
                // At the object seed there may be no request waiter. A partial
                // response wave then understates capacity on long-latency paths;
                // collect a full count before accepting or rejecting this probe.
                if !s.saturated && s.completed < s.limit {
                    return;
                }
                if rate < old_rate * 1.05 {
                    if s.completed < s.limit {
                        // The aggregate rate includes a response-cycle gap. Do
                        // not reject a partial sample while recent replies are
                        // arriving fast; a real stall lowers both rates.
                        if s.recent.len() < 17 {
                            return;
                        }
                        let recent_elapsed = now.duration_since(s.recent[0].0).as_secs_f64();
                        let recent_bytes: u64 = s.recent.iter().skip(1).map(|(_, n)| *n).sum();
                        if recent_bytes as f64 / recent_elapsed >= old_rate * 1.05 {
                            return;
                        }
                    }
                    s.probe_preserved_rate = rate >= old_rate;
                    s.limit = old_limit;
                    s.settled = true;
                } else if s.completed < s.limit {
                    // Early completions can still belong to the old setting.
                    // Require more evidence before accepting a gain, while a
                    // saturated losing probe can stop at the usual sample cadence.
                    return;
                } else {
                    // Keep the inferior setting so object admission does not
                    // discard what this completed request probe just learned.
                    s.slower_limit = old_limit;
                    s.previous = None;
                }
            }
            if !s.settled && s.saturated && s.limit < s.max {
                s.previous = Some((s.limit, rate));
                s.limit = (s.limit * 2).min(s.max);
            }
        }
        // Only single-request object batches reuse this score. Match object
        // activity units, including the fixed credit for each completed file.
        // A changed limit or rejected probe cannot supply its new baseline.
        s.object_rate = None;
        if !s.settled && s.limit == before && s.completed >= before {
            s.object_rate = Some((
                before,
                (s.bytes as f64 + s.completed as f64 * crate::tune::FILE_CREDIT as f64)
                    / elapsed.as_secs_f64(),
                elapsed,
            ));
        }
        super::diagnostics::request_window(
            before,
            s.limit,
            rate,
            elapsed,
            s.completed,
            s.saturated,
            s.settled,
        );
        s.since = Some(Instant::now());
        s.bytes = 0;
        s.completed = 0;
        s.recent.clear();
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

    #[tokio::test]
    async fn planning_time_does_not_advance_the_first_request_window() {
        let budget = Arc::new(Budget::new(64, true));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let held = budget.acquire().await;
        // A full request queue is waiting, but the transfer has only just begun.
        budget.state.lock().unwrap().saturated = true;
        for _ in 0..16 {
            budget.completed(1024);
        }
        let (limit, previous, since) = {
            let state = budget.state.lock().unwrap();
            (state.limit, state.previous, state.since)
        };
        assert_eq!(limit, 64);
        assert!(previous.is_none());
        drop(held);
        let _next = budget.acquire().await;
        let next_since = budget.state.lock().unwrap().since;
        assert_eq!(next_since, since);
    }

    #[test]
    fn request_baseline_waits_for_a_full_count() {
        let budget = Budget::new(64, true);
        {
            let mut s = budget.state.lock().unwrap();
            s.since = Some(Instant::now() - Duration::from_secs(1));
            s.saturated = true;
        }
        for _ in 0..63 {
            budget.completed(1024);
        }
        {
            let s = budget.state.lock().unwrap();
            assert_eq!(s.limit, 64);
            assert!(s.previous.is_none());
            assert_eq!(s.completed, 63);
        }
        budget.completed(1024);
        let s = budget.state.lock().unwrap();
        assert_eq!(s.limit, 128);
        assert_eq!(s.previous.unwrap().0, 64);
        assert!(s.recent.is_empty());
    }

    #[test]
    fn a_fast_response_burst_is_not_an_early_request_loss() {
        let budget = Budget::new(128, true);
        let bytes = 1024 * 1024;
        {
            let mut s = budget.state.lock().unwrap();
            let now = Instant::now();
            s.since = Some(now - Duration::from_millis(250));
            s.previous = Some((64, 256.0 * bytes as f64));
            s.saturated = true;
            s.bytes = 53 * bytes;
            s.completed = 53;
            s.recent = (0..16)
                .map(|i| (now - Duration::from_micros(4000 - i * 250), bytes))
                .collect();
        }
        // 54 replies / 250 ms looks slower than the baseline. The latest
        // replies are arriving rapidly, so this partial wave is inconclusive.
        budget.completed(bytes);
        {
            let mut s = budget.state.lock().unwrap();
            assert_eq!(s.limit, 128);
            assert!(!s.settled);
            assert_eq!(s.completed, 54);
            s.since = Some(Instant::now() - Duration::from_millis(300));
            s.bytes = 127 * bytes;
            s.completed = 127;
        }
        budget.completed(bytes);
        let s = budget.state.lock().unwrap();
        assert_eq!(s.limit, 256);
        assert!(!s.settled);
        assert!(s.recent.is_empty());
    }

    #[test]
    fn request_probe_requires_enough_completions_to_accept_a_gain() {
        let budget = Budget::new(64, true);
        {
            let mut state = budget.state.lock().unwrap();
            state.since = Some(Instant::now() - Duration::from_secs(1));
            state.saturated = true;
        }
        for _ in 0..64 {
            budget.completed(4096);
        }
        // A partial response wave appears faster, but fewer than 128 requests
        // have completed since increasing concurrency from 64 to 128.
        {
            let mut state = budget.state.lock().unwrap();
            state.since = Some(Instant::now() - Duration::from_secs(1));
            state.bytes = 79 * 4096;
            state.completed = 79;
            state.saturated = true;
        }
        budget.completed(4096);
        let observed = {
            let state = budget.state.lock().unwrap();
            (state.limit, state.completed, state.settled)
        };
        assert_eq!(observed, (128, 80, false));
        assert_eq!(budget.slower_limit(), 0);
        // If progress then stalls, reject the probe without waiting for 128
        // completions. The original baseline is still available for comparison.
        {
            let mut state = budget.state.lock().unwrap();
            let now = Instant::now();
            state.since = Some(now - Duration::from_secs(2));
            state.recent = (0..16)
                .map(|i| (now - Duration::from_millis(1015 - i), 4096))
                .collect();
        }
        budget.completed(4096);
        let observed = {
            let state = budget.state.lock().unwrap();
            (state.limit, state.settled)
        };
        assert_eq!(observed, (64, true));
        assert_eq!(budget.slower_limit(), 0);
    }

    #[test]
    fn object_controller_waits_for_request_ramp_or_plateau() {
        let budget = Budget::new(64, true);
        assert_eq!(budget.begin_objects(256), None);
        assert_eq!(budget.slower_limit(), 0);
        for (bytes, completions, expected) in [(1024, 64, 128), (2048, 128, 256)] {
            {
                let mut s = budget.state.lock().unwrap();
                s.since = Some(Instant::now() - Duration::from_secs(1));
                s.saturated = true;
            }
            for _ in 0..completions {
                budget.completed(bytes);
            }
            assert_eq!(budget.state.lock().unwrap().limit, expected);
            assert_eq!(budget.slower_limit(), if expected == 128 { 0 } else { 64 });
            assert_eq!(budget.begin_objects(256), None);
        }
        // The final increase must be evaluated even without a request waiter.
        {
            let mut s = budget.state.lock().unwrap();
            s.since = Some(Instant::now() - Duration::from_secs(1));
            s.completed = 255;
            s.bytes = 255 * 4096;
            assert!(!s.saturated);
        }
        budget.completed(4096);
        assert!(budget.state.lock().unwrap().previous.is_none());
        assert_eq!(budget.begin_objects(256), Some(256));
        assert!(budget.rejected_limit().is_none());
        assert_eq!(budget.slower_limit(), 128);
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

    #[test]
    fn final_request_probe_keeps_partial_samples_before_rejecting_a_loss() {
        let budget = Budget::new(256, true);
        let since = Instant::now() - Duration::from_secs(1);
        {
            let mut s = budget.state.lock().unwrap();
            s.since = Some(since);
            s.previous = Some((128, 1024.0 * 1024.0));
        }
        // Even an apparent loss may just be an incomplete response wave when
        // there is no waiter. Neither hand off nor discard the pending sample.
        for count in 1..256 {
            budget.completed(1024);
            assert_eq!(budget.begin_objects(256), None);
            let s = budget.state.lock().unwrap();
            assert_eq!(s.completed, count);
            assert_eq!(s.bytes, count as u64 * 1024);
            assert_eq!(s.since, Some(since));
            assert!(!s.settled);
        }
        budget.completed(1024);
        assert!(budget.rejected_limit().is_some());
        assert_eq!(budget.begin_objects(256), Some(128));
        assert_eq!(budget.preparation_limit(), 129);
        budget.finish_objects(512);
        assert_eq!(budget.state.lock().unwrap().limit, 512);
    }

    #[tokio::test(start_paused = true)]
    async fn request_ramp_bounds_preparation_and_refills_after_growth() {
        let budget = Arc::new(Budget::new(2, true));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (prepared, mut observed) = tokio::sync::mpsc::unbounded_channel();
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
                    let prepared = prepared.clone();
                    async move {
                        prepared.send(job).unwrap();
                        let _permit = budget.acquire().await;
                        gate.acquire().await.unwrap().forget();
                        Ok(Some(1024))
                    }
                },
            )
            .await
        });
        let mut jobs = Vec::new();
        for _ in 0..3 {
            jobs.push(
                tokio::time::timeout(Duration::from_secs(1), observed.recv())
                    .await
                    .expect("prepared work did not refill")
                    .unwrap(),
            );
        }
        let extra_before = tokio::time::timeout(Duration::from_millis(100), observed.recv()).await;
        let saturated = budget.state.lock().unwrap().saturated;
        budget.state.lock().unwrap().since = Some(Instant::now() - Duration::from_secs(1));
        for _ in 0..16 {
            budget.completed(1024);
        }
        let grown_limit = budget.state.lock().unwrap().limit;
        for _ in 0..2 {
            jobs.push(
                tokio::time::timeout(Duration::from_secs(1), observed.recv())
                    .await
                    .expect("prepared work did not refill")
                    .unwrap(),
            );
        }
        let extra_after = tokio::time::timeout(Duration::from_millis(100), observed.recv()).await;
        gate.add_permits(8);
        copy.await.unwrap().unwrap();
        while let Some(job) = observed.recv().await {
            jobs.push(job);
        }
        assert!(extra_before.is_err(), "prepared more than one waiting job");
        assert!(saturated, "the prepared waiter must signal request demand");
        assert_eq!(grown_limit, 4);
        assert!(
            extra_after.is_err(),
            "growth prepared too many waiting jobs"
        );
        jobs.sort_unstable();
        assert_eq!(jobs, (0..8).collect::<Vec<_>>());
    }

    #[tokio::test(start_paused = true)]
    async fn measured_handoff_can_probe_before_more_completions() {
        for (rate, upward, count, maximum, expected) in [
            (Some((4, 1000.0)), true, 32, 16, 8),
            (Some((4, 1000.0)), true, 15, 16, 4),
            (Some((2, 1000.0)), true, 32, 16, 4),
            (None, true, 32, 16, 4),
            (Some((4, 1000.0)), false, 32, 16, 4),
            (Some((4, 1000.0)), true, 32, 4, 4),
        ] {
            let budget = Arc::new(Budget::new(4, true));
            budget.state.lock().unwrap().object_rate =
                rate.map(|(limit, rate)| (limit, rate, Duration::from_secs(1)));
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let (prepared, mut observed) = tokio::sync::mpsc::unbounded_channel();
            let copy_gate = gate.clone();
            let copy = tokio::spawn(async move {
                crate::s3::admission::parallel(
                    (0..count).collect(),
                    crate::s3::admission::Concurrency {
                        initial: 4,
                        maximum: Some(maximum),
                        initial_probe_up: upward,
                        requests: Some(budget.clone()),
                    },
                    move |job| {
                        let budget = budget.clone();
                        let gate = copy_gate.clone();
                        let prepared = prepared.clone();
                        async move {
                            let _permit = budget.acquire().await;
                            prepared.send(job).unwrap();
                            gate.acquire().await.unwrap().forget();
                            Ok(Some(1024))
                        }
                    },
                )
                .await
            });
            // No object has completed yet. A matching request measurement is
            // the only possible evidence for an immediate increase.
            let mut jobs = Vec::new();
            let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
            while let Ok(Some(job)) = tokio::time::timeout_at(deadline, observed.recv()).await {
                jobs.push(job);
            }
            let initial = jobs.len();
            gate.add_permits(count);
            copy.await.unwrap().unwrap();
            while let Some(job) = observed.recv().await {
                jobs.push(job);
            }
            assert_eq!(
                initial, expected,
                "rate={rate:?}, count={count}, upward={upward}"
            );
            jobs.sort_unstable();
            assert_eq!(jobs, (0..count).collect::<Vec<_>>());
        }
    }

    #[test]
    fn handoff_rate_matches_a_completed_probe_at_the_same_limit() {
        let budget = Budget::new(64, true);
        budget.state.lock().unwrap().max = 128;
        for (completions, saturated) in [(64, true), (128, false)] {
            {
                let mut state = budget.state.lock().unwrap();
                state.since = Some(Instant::now() - Duration::from_secs(1));
                state.saturated = saturated;
            }
            for _ in 0..completions {
                budget.completed(2048);
            }
            assert!(budget.object_rate(64).is_none());
        }
        let (rate, elapsed) = budget.object_rate(128).unwrap();
        assert!(elapsed >= Duration::from_secs(1));
        let expected = 128.0 * (2048 + crate::tune::FILE_CREDIT) as f64;
        assert!((rate / expected - 1.0).abs() < 0.01);
    }

    #[tokio::test(start_paused = true)]
    async fn object_handoff_tries_downward_after_a_rejected_request_increase() {
        check_handoff_direction(256, 64, 32).await;
    }

    #[tokio::test(start_paused = true)]
    async fn object_handoff_refines_upward_after_a_small_request_gain() {
        // A 3.125% gain is too small to accept doubled requests, but suggests
        // looking between 64 and 128 before trying fewer than 64 objects.
        check_handoff_direction(1056, 96, 96).await;
    }

    async fn check_handoff_direction(
        probe_bytes: u64,
        expected_peak: usize,
        expected_active: usize,
    ) {
        use std::sync::atomic::AtomicUsize;

        let budget = Arc::new(Budget::new(64, true));
        // The request ramp rejects 128 and returns to 64 in both cases.
        for (bytes, completions, expected) in [(2048, 64, 128), (probe_bytes, 128, 64)] {
            {
                let mut state = budget.state.lock().unwrap();
                state.since = Some(Instant::now() - Duration::from_secs(1));
                state.saturated = true;
            }
            for _ in 0..completions {
                budget.completed(bytes);
            }
            let limit = budget.state.lock().unwrap().limit;
            assert_eq!(limit, expected);
        }
        assert!(budget.rejected_limit().is_some());
        assert!(budget.object_rate(64).is_none());
        let peak = Arc::new(AtomicUsize::new(0));
        let copy_budget = budget.clone();
        let copy_peak = peak.clone();
        let copy = tokio::spawn(async move {
            crate::s3::admission::parallel(
                (0..8192).collect(),
                crate::s3::admission::Concurrency {
                    initial: 256,
                    maximum: Some(256),
                    initial_probe_up: true,
                    requests: Some(copy_budget.clone()),
                },
                move |_| {
                    let budget = copy_budget.clone();
                    let peak = copy_peak.clone();
                    async move {
                        let _permit = budget.acquire().await;
                        let active = budget.state.lock().unwrap().active;
                        peak.fetch_max(active, Relaxed);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Ok(Some(1024))
                    }
                },
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let first_probe_peak = peak.load(Relaxed);
        let first_probe_active = budget.state.lock().unwrap().active;
        // The starting direction does not prevent later increases.
        copy.await.unwrap().unwrap();
        assert_eq!(first_probe_peak, expected_peak);
        assert_eq!(first_probe_active, expected_active);
        assert!(peak.load(Relaxed) > 64);
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
        // Two requests are running; prepared work waits for a permit.
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
        budget.state.lock().unwrap().since = Some(Instant::now() - Duration::from_secs(1));
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
                reads: crate::s3::read_recovery::Recovery::default(),
                fixed_requests: fixed,
                tigris,
                upload,
                requests: Arc::new(Budget::new(fixed.unwrap_or(64), fixed.is_none())),
                upload_buffers: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
            };
            if let Some(ms) = latency_ms {
                tuning.observe_control(Duration::from_millis(ms));
            }
            tuning.configure(tiny, 256, 64);
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
