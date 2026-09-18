//! Process-local admission control. Samples are useful copies, not calibration traffic.
use super::{Options, Route};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

pub(super) struct Tuning {
    control_ns: Arc<AtomicU64>,
    fixed_requests: Option<usize>,
    tigris: bool,
    upload: bool,
    pub requests: Arc<Budget>,
    pub reads: crate::s3::read_recovery::Recovery,
    pub upload_buffers: Arc<tokio::sync::Semaphore>,
}
impl Tuning {
    /// `control` receives the fastest HEAD or LIST response seen by the client.
    pub fn new(options: &Options, args: &crate::cli::Args, control: Arc<AtomicU64>) -> Self {
        Self {
            control_ns: control,
            reads: crate::s3::read_recovery::Recovery::default(),
            upload: options.route == Route::Upload,
            fixed_requests: args.tuning_options.and_then(|t| t.s3_requests),
            upload_buffers: Arc::new(tokio::sync::Semaphore::new(256 * 1024 * 1024)),
            // These measured seeds describe provider request behavior; they do
            // not change the data route, integrity policy, or explicit overrides.
            tigris: !options.route.is_server_copy()
                && options
                    .endpoint
                    .as_deref()
                    .and_then(|s| url::Url::parse(s).ok())
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .is_some_and(|host| {
                        host == "t3.storage.dev"
                            || host == "fly.storage.tigris.dev"
                            || host.ends_with(".tigris.dev")
                    }),
            requests: Arc::new(Budget::with_ceiling(
                args.tuning_options
                    .and_then(|t| t.s3_requests)
                    .unwrap_or(64),
                args.tuning_options.and_then(|t| t.s3_requests).is_none(),
                args.resource_limits
                    .as_ref()
                    .and_then(|limits| limits.s3_requests),
            )),
        }
    }
    #[cfg(test)]
    pub fn observe_control(&self, elapsed: Duration) {
        observe_control(&self.control_ns, elapsed);
    }
    pub fn high_latency(&self) -> bool {
        let ns = self.control_ns.load(Relaxed);
        // Tigris uploads keep their conservative seed. Downloads still need
        // enough requests in flight to cover a long round trip, regardless of
        // provider; short copies cannot recover time spent ramping from 64.
        (!self.tigris || !self.upload) && ns != u64::MAX && ns >= 50_000_000
    }
    pub fn configure(&self, tiny: bool, request_cap: usize, seed: usize) {
        let request_cap = request_cap
            .max(self.fixed_requests.unwrap_or(1))
            .min(self.requests.ceiling.unwrap_or(usize::MAX));
        let mut s = self.requests.state.lock().unwrap();
        // Configuration separates completed planning from transfer admission.
        // Planning HEADs use permits but supply no transfer-throughput samples.
        s.since = None;
        s.saturated = false;
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
    pub fn request_capacity(&self) -> usize {
        self.fixed_requests
            .unwrap_or_else(|| self.requests.state.lock().unwrap().max)
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
/// Path latency is the fastest single control response. The time to plan a copy
/// grows with the number of listing pages, so it says little about the path.
pub(super) fn observe_control(control_ns: &AtomicU64, elapsed: Duration) {
    control_ns.fetch_min(elapsed.as_nanos().min(u64::MAX as u128) as u64, Relaxed);
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
    progress_start: u64,
    previous_progress_rate: Option<f64>,
    proposed_limit: usize,
    slower_limit: usize,
    probe_preserved_rate: bool,
    object_rate: Option<(usize, f64, Duration)>,
    settled: bool,
}
pub(super) struct Budget {
    ceiling: Option<usize>,
    state: Mutex<Window>,
    changed: Notify,
    received: AtomicU64,
}
pub(super) struct Permit {
    budget: Arc<Budget>,
    track_received: bool,
}
impl Permit {
    // Download traffic can include retries; it is evidence for interpreting a
    // partial sample, not for accepting a gain or declaring a copy successful.
    // Requests admitted after ramp-up skip the shared counter entirely.
    pub fn received(&self, bytes: usize) {
        if self.track_received {
            self.budget.received.fetch_add(bytes as u64, Relaxed);
        }
    }
}
impl Budget {
    #[cfg(test)]
    fn new(limit: usize, adaptive: bool) -> Self {
        Self::with_ceiling(limit, adaptive, None)
    }
    fn with_ceiling(limit: usize, adaptive: bool, ceiling: Option<usize>) -> Self {
        let limit = limit.min(ceiling.unwrap_or(usize::MAX));
        Self {
            ceiling,
            state: Mutex::new(Window {
                active: 0,
                limit,
                max: 256.min(ceiling.unwrap_or(usize::MAX)),
                adaptive,
                since: None,
                bytes: 0,
                completed: 0,
                recent: std::collections::VecDeque::new(),
                saturated: false,
                previous: None,
                progress_start: 0,
                previous_progress_rate: None,
                proposed_limit: limit,
                slower_limit: 0,
                probe_preserved_rate: false,
                object_rate: None,
                settled: false,
            }),
            changed: Notify::new(),
            received: AtomicU64::new(0),
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
                        track_received: s.adaptive && !s.settled,
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
        // Keep the actual attempted limit when smaller probes narrow the gap.
        (s.settled && s.limit == previous).then_some(s.proposed_limit)
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
        let maximum = maximum.min(self.ceiling.unwrap_or(usize::MAX));
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
        let received = self.received.load(Relaxed);
        let progress_rate =
            received.saturating_sub(s.progress_start) as f64 / elapsed.as_secs_f64();
        let before = s.limit;
        let mut next_limit = s.limit.saturating_mul(2);
        if s.saturated || s.previous.is_some() {
            if let Some((old_limit, old_rate)) = s.previous {
                // A quarter-sized probe should not need the gain of a doubling.
                // Keep the same gain per additional request slot.
                let added_fraction = s.limit as f64 / old_limit as f64 - 1.0;
                let required_gain = if s.previous_progress_rate.is_some_and(|rate| rate > 0.0) {
                    1.0 + 0.05 * added_fraction
                } else {
                    1.05
                };
                // At the object seed there may be no request waiter. A partial
                // response wave then understates capacity on long-latency paths;
                // collect a full count before accepting or rejecting this probe.
                if !s.saturated && s.completed < s.limit {
                    return;
                }
                if rate < old_rate * required_gain {
                    if s.completed < s.limit {
                        if let Some(old_progress) =
                            s.previous_progress_rate.filter(|old| *old > 0.0)
                        {
                            // Downloads expose bytes still in flight. Compare
                            // those rates before calling an incomplete wave a
                            // loss. A late completion burst cannot erase a slow
                            // body window, nor can unfinished bytes look idle.
                            if progress_rate >= old_progress * required_gain {
                                return;
                            }
                        } else {
                            // Uploads expose only successful completion here.
                            // Keep their recent-arrival confirmation: the whole
                            // window can contain a response-cycle gap.
                            if s.recent.len() < 17 {
                                return;
                            }
                            let recent_elapsed = now.duration_since(s.recent[0].0).as_secs_f64();
                            let recent_bytes: u64 = s.recent.iter().skip(1).map(|(_, n)| *n).sum();
                            if recent_bytes as f64 / recent_elapsed >= old_rate * required_gain {
                                return;
                            }
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
                    // A modest gain from a larger download window calls for
                    // a smaller next probe, limiting work committed to overload.
                    if s.previous_progress_rate.is_some_and(|rate| rate > 0.0)
                        && rate < old_rate * (1.0 + 0.25 * added_fraction)
                    {
                        next_limit = s.limit.saturating_add((s.limit / 4).max(1));
                    }
                    s.previous = None;
                }
            }
            if !s.settled && s.saturated && s.limit < s.max {
                s.previous = Some((s.limit, rate));
                s.previous_progress_rate = Some(progress_rate);
                s.limit = next_limit.min(s.max);
                s.proposed_limit = s.limit;
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
        s.progress_start = received;
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

// Estimate concurrency from payload size and descriptor headroom, leaving room
// for sockets and transient source opens. TLS/SDK allocations are additional;
// this is not a total process-memory bound. Upload buffers have a separate budget.
fn small_capacity(soft: u64, open: usize, largest: u64) -> usize {
    let descriptors = soft.saturating_sub(open as u64).saturating_sub(64) / 4;
    let payloads = (256 * 1024 * 1024u64) / largest.max(1);
    descriptors.min(payloads).min(4096) as usize
}
pub(super) fn small_object_capacity(largest: u64) -> anyhow::Result<usize> {
    use anyhow::Context;
    let limits = crate::fsops::nofile_limits().context("read S3 descriptor limit")?;
    let open = crate::fsops::current_open_descriptor_count(limits.rlim_cur)?;
    let capacity = small_capacity(limits.rlim_cur as u64, open, largest);
    anyhow::ensure!(capacity > 0, "insufficient file descriptors for S3 objects; raise the open-file limit or reduce source selectors");
    Ok(capacity)
}
#[cfg(test)]
mod tests;
