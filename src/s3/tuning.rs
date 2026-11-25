//! One adaptive limit on the S3 requests a copy keeps in flight.
//!
//! Each batch starts from a number planning chooses for its objects and
//! endpoint (`Tuning::configure`), and adjusts the limit from the copy's own
//! requests; nothing is spent on calibration traffic.
//! Little's law relates the average number of requests in flight, N, the
//! rate at which work finishes, X (bytes plus `REQUEST_CREDIT` per request),
//! and the time a request spends in flight per unit of its work, T: X = N/T.
//! T is measured directly, as the requests' response times over their work.
//! A change of the limit is judged by its elasticity, how much of the change
//! in N showed in X: 1 while nothing queues, falling towards 0 as requests
//! queue on the link, at the service or in this process.
//!
//! - While N fills the limit, the limit doubles, and once a change has been
//!   undone, or from the start of a batch that planning asks to grow
//!   gradually, grows by an eighth.
//! - A step up whose added requests carry less than half their share of the
//!   rate (`PAYING`), in two windows, is undone to what the new rate needs at
//!   the old rate per request. Steps down by an eighth follow, until one
//!   costs its share of the rate and is undone in turn, so that the limit
//!   follows a path that saturates at fewer requests. Below one request
//!   there is nothing to try, so steps up follow.
//! - When the service asks for fewer requests (HTTP 429 or 503), the limit
//!   halves as the response arrives, whether or not a window is open or the
//!   request is then retried. Requests admitted before that halving ran into
//!   what it answered, and their retries keep their permits, so further
//!   refusals while any of them is in flight do not halve it again: a burst
//!   halves the limit once, not once per refusal. Only a halving has this
//!   effect; a refusal after any other change halves at once.
//!
//! A window starts only once nearly all requests admitted before the last
//! change have finished, so a change is never judged by the requests that
//! caused it. It ends once as many requests have finished as were in flight
//! on average, which by Little's law takes a mean response time, and once
//! the finished requests' time within the window accounts for most of the
//! window's request-seconds in flight, so that quick checks finishing beside
//! long transfers do not stand for the transfers. Requests that stay in
//! flight only bound that wait, to at most `UNCOVERED_WAIT`.
use super::{outage::Outage, Options, Route};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::{watch, Notify},
    time::Instant,
};

/// Requests in flight when a batch starts, unless planning chooses another
/// start or the user fixed the count.
pub(super) const INITIAL_REQUESTS: usize = 32;
/// The most requests in flight unless a batch's budget allows another number.
const DEFAULT_CEILING: usize = 256;
/// The shortest measurement window, so that requests answered within a
/// millisecond or two do not make every scheduling delay a decision.
const SAMPLE: Duration = Duration::from_millis(50);
/// Requests a window must see finish before it describes the limit.
const MIN_COMPLETIONS: usize = 16;
/// A window may start while this fraction of the limit is still requests
/// admitted before the last change, or once those have taken this many
/// windows' time, so that a few slow ones cannot hold back every decision.
const STRAGGLERS: usize = 16;
const STRAGGLER_WINDOWS: u32 = 4;
/// The share of the window's request-seconds in flight that the finished
/// requests' time within the window must account for before it describes
/// the limit.
const COVERED: f64 = 0.7;
/// The longest a window that has seen enough requests finish waits for the
/// rest to account for its time. A request may take hours, so one still in
/// flight is never known to have stalled, but a few that hang must not hold
/// every later decision back.
const UNCOVERED_WAIT: Duration = Duration::from_secs(30);
/// Work credited to each request besides its bytes, for the fixed cost of a
/// request, so that checks and small objects count as progress.
const REQUEST_CREDIT: u64 = crate::tune::FILE_CREDIT;

/// The fastest control response at which an endpoint counts as far away, so
/// that copies of many small objects start with every request their memory
/// and descriptors allow, instead of taking several windows to grow there.
/// A response on a reused connection takes one round trip. When a copy has
/// only a client's first response, which also opens the connection, it takes
/// about two round trips over HTTP and three over HTTPS, so the endpoint
/// counts as far from about a 10 or 6 ms round trip.
pub(super) const HIGH_LATENCY: Duration = Duration::from_millis(20);
/// Below this fastest control response, a far endpoint's uploads of small
/// files start with at most 2,048 objects in flight instead of 4,096. The
/// response takes at least one round trip, so the endpoint is closer than
/// this, and at up to 30 ms 2,048 objects finish as soon as 4,096 in about
/// 40% less memory. From 60 ms they finish later.
pub(super) const NEAR_FAR_LATENCY: Duration = Duration::from_millis(32);
/// Below this fastest control response the endpoint is on the same machine
/// or a fast LAN, where a few large ranges download an object as fast as
/// many and hold far less memory in flight.
pub(super) const LOCAL_LATENCY: Duration = Duration::from_millis(3);

/// The upload bytes held in memory across files at once, from the read
/// that hashes each file to the request that sends it.
pub(super) const UPLOAD_BUFFER_BYTES: u64 = 256 << 20;

pub(super) struct Tuning {
    control: Arc<ControlSamples>,
    tigris: bool,
    upload: bool,
    pub requests: Arc<Budget>,
    pub reads: crate::s3::read_recovery::Recovery,
    retained_upload_files: std::sync::OnceLock<Arc<tokio::sync::Semaphore>>,
    pub upload_buffers: Arc<tokio::sync::Semaphore>,
}
impl Tuning {
    /// `control` receives the client's HEAD and LIST response times, and
    /// `outage` reports each response that asks the client to slow down.
    pub fn new(
        options: &Options,
        args: &crate::cli::Args,
        control: Arc<ControlSamples>,
        outage: Arc<Outage>,
    ) -> Self {
        let requests = Arc::new(Budget::new(
            args.tuning_options.and_then(|t| t.s3_requests),
            args.resource_limits
                .as_ref()
                .and_then(|limits| limits.s3_requests),
        ));
        outage.slow_down(&requests);
        Self {
            control,
            reads: crate::s3::read_recovery::Recovery::default(),
            upload: options.route == Route::Upload,
            retained_upload_files: Default::default(),
            upload_buffers: Arc::new(tokio::sync::Semaphore::new(UPLOAD_BUFFER_BYTES as usize)),
            // Provider-specific transfer starts do not change the data route,
            // integrity policy, or explicit overrides. Server copies use the
            // same starts for all providers.
            tigris: !options.route.is_server_copy() && options.is_tigris(),
            requests,
        }
    }
    /// Keep at most one file per request slot across hashing and sending.
    /// Size this after source selection so its pinned roots count against
    /// descriptor headroom. A full budget just means reopening per request.
    pub fn retain_upload_file(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.retained_upload_files
            .get_or_init(|| {
                let slots = small_object_capacity(1)
                    .unwrap_or(0)
                    .min(self.request_limit())
                    .min(32);
                Arc::new(tokio::sync::Semaphore::new(slots))
            })
            .clone()
            .try_acquire_owned()
            .ok()
    }
    #[cfg(test)]
    pub fn observe_control(&self, elapsed: Duration) {
        self.control.observe(elapsed);
    }
    /// Whether the endpoint is far enough away that small objects' requests
    /// spend nearly all their time waiting for it. Tigris uploads keep the
    /// usual start, which measured faster there.
    pub fn far(&self) -> bool {
        (!self.tigris || !self.upload)
            && self
                .control_latency()
                .is_some_and(|latency| latency >= HIGH_LATENCY)
    }
    /// Whether the endpoint answers within `LOCAL_LATENCY`.
    pub fn local(&self) -> bool {
        self.control_latency()
            .is_some_and(|latency| latency < LOCAL_LATENCY)
    }
    pub fn tigris(&self) -> bool {
        self.tigris
    }
    /// Start a batch at `initial` requests, whose memory and descriptors
    /// allow `ceiling` in flight at once, growing by an eighth at a time
    /// rather than doubling when `gradual`.
    pub fn configure(&self, initial: usize, ceiling: usize, gradual: bool) {
        self.requests.configure(initial, ceiling, gradual);
    }
    /// The most requests that may be in flight: the count the user fixed, or
    /// the batch's ceiling.
    pub fn request_capacity(&self) -> usize {
        self.requests.capacity()
    }
    pub fn request_limit(&self) -> usize {
        self.requests.limit()
    }
    pub fn control_latency(&self) -> Option<Duration> {
        let ns = self.control.fastest();
        (ns != u64::MAX).then(|| Duration::from_nanos(ns))
    }
    pub fn report(&self, objects: usize) {
        super::diagnostics::planning(self.control_latency(), objects, self.request_limit());
    }
}
/// Path latency is the fastest single control response. The time to plan a copy
/// grows with the number of listing pages, so it says little about the path.
///
/// A client's first response may also include DNS, TCP, and TLS setup, which
/// would make a 6 to 20 ms endpoint look far away. Later responses take one
/// round trip, so their minimum is used once one exists. A copy that plans
/// with a single request, such as one listing page or an upload into an
/// empty prefix, still has the first response, which keeps a distant
/// endpoint's wide start.
#[derive(Debug)]
pub(super) struct ControlSamples {
    first: AtomicU64,
    warm: AtomicU64,
}
impl Default for ControlSamples {
    fn default() -> Self {
        Self {
            first: AtomicU64::new(u64::MAX),
            warm: AtomicU64::new(u64::MAX),
        }
    }
}
impl ControlSamples {
    /// Records a client's first control response.
    pub fn observe_first(&self, elapsed: Duration) {
        self.first.fetch_min(nanos(elapsed), Relaxed);
    }
    /// Records a control response on an established client.
    pub fn observe(&self, elapsed: Duration) {
        self.warm.fetch_min(nanos(elapsed), Relaxed);
    }
    /// The fastest response in nanoseconds, or `u64::MAX` before any.
    pub fn fastest(&self) -> u64 {
        match self.warm.load(Relaxed) {
            u64::MAX => self.first.load(Relaxed),
            warm => warm,
        }
    }
}
fn nanos(elapsed: Duration) -> u64 {
    elapsed.as_nanos().min(u64::MAX as u128) as u64
}

/// One measurement window, as the policy sees it.
#[derive(Clone, Copy, Debug)]
pub(super) struct Sample {
    /// The average number of requests in flight.
    pub in_flight: f64,
    /// Seconds in flight per unit of work: the finished requests' response
    /// times over their bytes plus `REQUEST_CREDIT` each.
    pub time: f64,
    /// Work finished per second as counted, for diagnostics.
    pub rate: f64,
}

/// Growth pays while each request added carries at least this fraction of
/// what a request already in flight carries on average: doubling the
/// requests must raise the rate by at least 41%.
const PAYING: f64 = 0.5;

/// A window's limit and what it measured.
#[derive(Clone, Copy, Debug)]
struct Point {
    limit: usize,
    in_flight: f64,
    /// By Little's law, the rate work finishes: requests in flight over each
    /// one's time in flight per unit of work.
    rate: f64,
}
impl Point {
    /// How much of the change in requests in flight since `before` showed in
    /// the rate: 1 when each request added carried as much as the others, 0
    /// when the rate did not change. `None` when too few requests changed to
    /// tell.
    fn elasticity(&self, before: &Point) -> Option<f64> {
        let requests = (self.in_flight / before.in_flight).ln();
        (requests.abs() >= 0.05).then(|| (self.rate / before.rate).ln() / requests)
    }
}

/// The decisions, apart from the accounting that measures each window.
#[derive(Debug, Default)]
pub(super) struct Policy {
    /// A change has been undone or the service throttled, so growth no
    /// longer doubles.
    settled: bool,
    /// Steps lower the limit, after a step up did not pay, until one costs
    /// as much rate as the requests it removed.
    down: bool,
    /// The window before the last change, which the change is judged against.
    reference: Option<Point>,
    /// The last change already had a window that did not pay. Connections a
    /// change opens start slowly, so it gets one more before it is undone.
    doubted: bool,
}
impl Policy {
    pub fn observe(&mut self, limit: usize, max: usize, sample: Sample) -> usize {
        if sample.time <= 0.0 || sample.in_flight <= 0.0 {
            return limit;
        }
        let here = Point {
            limit,
            in_flight: sample.in_flight,
            rate: sample.in_flight / sample.time,
        };
        let step = (limit / 8).max(1);
        if let Some(before) = self.reference.filter(|before| before.limit != limit) {
            match here.elasticity(&before) {
                Some(paid) if limit > before.limit && paid < PAYING => {
                    if !self.doubted {
                        self.doubted = true;
                        return limit;
                    }
                    // Little's law: the requests that carry the new rate at
                    // the old rate per request.
                    let needed = (before.in_flight * here.rate / before.rate).round() as usize;
                    self.settled = true;
                    self.down = true;
                    return self.change(here, needed.clamp(before.limit, limit - 1));
                }
                // The requests a step down removed carried their share: back.
                Some(paid) if limit < before.limit && paid > PAYING => {
                    self.down = false;
                    return self.change(here, before.limit.min(max));
                }
                _ => {}
            }
        }
        // Nothing below one request to try: probe upwards again.
        if limit <= 1 {
            self.down = false;
        }
        // The last change stands, or there was none: step on.
        let after = if self.down {
            limit.saturating_sub(step).max(1)
        } else if here.in_flight >= (limit - step) as f64 {
            let grown = if self.settled {
                limit + step
            } else {
                limit * 2
            };
            grown.min(max).max(limit)
        } else {
            // Without demand for the whole limit, more would go unused.
            limit
        };
        self.change(here, after)
    }
    /// Move to `after`, to be judged against `here`; a limit that stays
    /// has been judged.
    fn change(&mut self, here: Point, after: usize) -> usize {
        self.doubted = false;
        self.reference = (after != here.limit).then_some(here);
        after
    }
    /// The service asked for fewer requests.
    pub fn throttled(&mut self, limit: usize) -> usize {
        *self = Self {
            settled: true,
            ..Self::default()
        };
        (limit / 2).max(1)
    }
}

/// Accounting for the current measurement window.
struct Window {
    start: Option<Instant>,
    /// When `area` was last brought up to date.
    last: Instant,
    /// Request-seconds in flight since `start`.
    area: f64,
    work: u64,
    completed: usize,
    /// The finished requests' response times, in seconds.
    responses: f64,
    /// The part of those response times since `start`, in seconds: the
    /// finished requests' share of `area`. A request admitted before the
    /// window counts only its time within it.
    covered: f64,
    /// The mean time a request spent in flight in the last complete window,
    /// which bounds the wait for stragglers.
    response: Duration,
}
impl Window {
    fn new(now: Instant) -> Self {
        Self {
            start: None,
            last: now,
            area: 0.0,
            work: 0,
            completed: 0,
            responses: 0.0,
            covered: 0.0,
            response: Duration::ZERO,
        }
    }
    fn begin(&mut self, now: Instant) {
        self.start = Some(now);
        self.last = now;
        self.area = 0.0;
        self.work = 0;
        self.completed = 0;
        self.responses = 0.0;
        self.covered = 0.0;
    }
    /// Bring the window up to `now`, with `active` requests in flight since
    /// it was last brought up to date, or start it once `settled`. Call
    /// before `active` changes.
    fn advance(&mut self, now: Instant, active: usize, settled: bool) {
        if self.start.is_some() {
            self.area += active as f64 * now.saturating_duration_since(self.last).as_secs_f64();
            self.last = now;
        } else if settled {
            self.begin(now);
        }
    }
    /// The window's sample, once it has run long enough to describe the limit.
    fn sample(&self, now: Instant) -> Option<(Sample, Duration)> {
        let elapsed = now.saturating_duration_since(self.start?);
        if elapsed < SAMPLE {
            return None;
        }
        let seconds = elapsed.as_secs_f64();
        let in_flight = self.area / seconds;
        // The first requests to finish are the fastest; wait for the rest.
        if (self.completed as f64) < in_flight.max(MIN_COMPLETIONS as f64) {
            return None;
        }
        // Little's law holds for the requests that finished only once their
        // time within the window accounts for most of the time requests
        // spent in flight in it: quick checks finishing beside long
        // transfers would otherwise stand for the transfers too, and so
        // would one long transfer from before the window finishing early in
        // it while the others are still in flight.
        let covered = self.covered >= COVERED * self.area;
        // Once the window has waited long enough for its stragglers, those
        // still in flight count as having carried nothing yet, and the rate
        // is the work finished per second.
        if !covered && elapsed < UNCOVERED_WAIT {
            return None;
        }
        let spent = if covered { self.responses } else { self.area };
        let sample = Sample {
            in_flight,
            time: spent / self.work as f64,
            rate: self.work as f64 / seconds,
        };
        Some((
            sample,
            Duration::from_secs_f64(self.responses / self.completed as f64),
        ))
    }
}

struct Control {
    /// The batch's ceiling, within the user's.
    max: usize,
    /// The ceiling the user set, if any.
    ceiling: Option<usize>,
    policy: Policy,
    window: Window,
}
impl Control {
    fn new(max: usize, ceiling: Option<usize>, now: Instant) -> Self {
        Self {
            max,
            ceiling,
            policy: Policy::default(),
            window: Window::new(now),
        }
    }
}

struct State {
    active: usize,
    limit: usize,
    /// Counts changes of the limit.
    generation: u64,
    /// When the limit last changed.
    changed: Instant,
    /// Requests in flight admitted before the last change.
    old: usize,
    /// Requests in flight admitted before the service last asked for fewer
    /// requests, whose refusals that halving answered.
    refused: usize,
    /// The generation that halving started, and when.
    cut: (u64, Instant),
    /// `None` when the user fixed the count.
    control: Option<Control>,
}
impl State {
    fn advance(&mut self, now: Instant) {
        let (active, old, limit, changed) = (self.active, self.old, self.limit, self.changed);
        if let Some(control) = &mut self.control {
            let window = &mut control.window;
            let settled = old <= limit / STRAGGLERS
                || now >= changed + STRAGGLER_WINDOWS * SAMPLE.max(window.response);
            window.advance(now, active, settled);
        }
    }
    /// The limit changed: what is in flight now was admitted before, and
    /// the next window waits for it.
    fn changed(&mut self, after: usize, now: Instant) -> usize {
        self.generation += 1;
        self.changed = now;
        self.old = self.active;
        if let Some(control) = &mut self.control {
            control.window.start = None;
        }
        std::mem::replace(&mut self.limit, after)
    }
    /// Count a request admitted at `started` that finished having moved
    /// `bytes`, and decide once the window allows. Returns the limit before
    /// and after a change.
    fn finished(&mut self, now: Instant, started: Instant, bytes: u64) -> Option<(usize, usize)> {
        let limit = self.limit;
        let control = self.control.as_mut()?;
        let window = &mut control.window;
        let start = window.start?;
        // A request that finished as the window started belongs before it.
        if start == now {
            return None;
        }
        window.completed += 1;
        window.responses += now.saturating_duration_since(started).as_secs_f64();
        window.covered += now
            .saturating_duration_since(started.max(start))
            .as_secs_f64();
        window.work = window
            .work
            .saturating_add(bytes.saturating_add(REQUEST_CREDIT));
        let (sample, response) = window.sample(now)?;
        window.response = response;
        let after = control.policy.observe(limit, control.max, sample);
        super::diagnostics::request_window(
            limit,
            after,
            &sample,
            window.completed,
            now.saturating_duration_since(window.start?),
        );
        if after == limit {
            window.begin(now);
            return None;
        }
        self.changed(after, now);
        Some((limit, after))
    }
    /// The service asked for fewer requests. Returns the limit before and
    /// after a change.
    fn throttled(&mut self, now: Instant) -> Option<(usize, usize)> {
        let limit = self.limit;
        let control = self.control.as_mut()?;
        // Requests admitted before the last halving ran into what it
        // answered, and so do their retries, which keep their permits; but
        // a few that stay in flight long after it, which may have hung, do
        // not hold back the next.
        if self.refused > 0 && now < self.cut.1 + UNCOVERED_WAIT {
            return None;
        }
        let after = control.policy.throttled(limit);
        super::diagnostics::request_throttled(limit, after);
        // What the window measured was the service refusing requests; at one
        // request the limit stays, and the next window starts afresh.
        self.changed(after, now);
        self.refused = self.active;
        self.cut = (self.generation, now);
        (after != limit).then_some((limit, after))
    }
    /// A request admitted in `generation` finished.
    fn released(&mut self, generation: u64) {
        self.active -= 1;
        if generation != self.generation {
            self.old = self.old.saturating_sub(1);
        }
        if generation < self.cut.0 {
            self.refused = self.refused.saturating_sub(1);
        }
    }
}

/// The permits for S3 requests, one per request in flight.
pub(super) struct Budget {
    state: Mutex<State>,
    /// Wakes requests waiting for a permit.
    changed: Notify,
    /// The current limit, for admission that follows it.
    limit: watch::Sender<usize>,
}
/// One request's place in flight. A request that succeeds reports the bytes
/// it moved; the permit accounts for them, with its response time, when it
/// is released.
pub(super) struct Permit {
    budget: Arc<Budget>,
    generation: u64,
    started: Instant,
    bytes: u64,
}
impl Permit {
    /// The request succeeded after moving `bytes`.
    pub fn completed(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
}
impl Budget {
    /// `fixed` is a count the user set, `ceiling` one the user capped.
    pub(super) fn new(fixed: Option<usize>, ceiling: Option<usize>) -> Self {
        let now = Instant::now();
        let (limit, control) = match fixed {
            Some(fixed) => (fixed, None),
            None => {
                let max = DEFAULT_CEILING.min(ceiling.unwrap_or(usize::MAX));
                let control = Control::new(max, ceiling, now);
                (INITIAL_REQUESTS.min(max), Some(control))
            }
        };
        Self {
            state: Mutex::new(State {
                active: 0,
                limit,
                generation: 0,
                changed: now,
                old: 0,
                refused: 0,
                cut: (0, now),
                control,
            }),
            changed: Notify::new(),
            limit: watch::Sender::new(limit),
        }
    }
    /// Start a batch at `initial` requests in flight, with `ceiling` as its
    /// most, growing by an eighth at a time rather than doubling when
    /// `gradual`. Nothing carries over from the last batch, whose requests
    /// say little about this one's, nor do earlier refusals, which the
    /// requests that drew them have answered.
    pub fn configure(&self, initial: usize, ceiling: usize, gradual: bool) {
        let mut state = self.state.lock().unwrap();
        let Some(control) = &mut state.control else {
            return;
        };
        let max = ceiling.min(control.ceiling.unwrap_or(usize::MAX)).max(1);
        let now = Instant::now();
        *control = Control::new(max, control.ceiling, now);
        control.policy.settled = gradual;
        let after = initial.clamp(1, max);
        let before = state.changed(after, now);
        self.publish(&state, Some((before, after)));
    }
    /// Wake requests and admission for a change of the limit. The state
    /// lock is held, so that changes reach admission in the order they
    /// happened: otherwise `4 → 2` could publish after `2 → 1`, leaving 2
    /// to hide a later `1 → 2`.
    fn publish(&self, _state: &std::sync::MutexGuard<'_, State>, change: Option<(usize, usize)>) {
        let Some((before, after)) = change else {
            return;
        };
        if after > before {
            self.changed.notify_waiters();
        }
        self.limit.send_if_modified(|limit| {
            let changed = *limit != after;
            *limit = after;
            changed
        });
    }
    pub fn limit(&self) -> usize {
        self.state.lock().unwrap().limit
    }
    /// Move the limit as a measurement would.
    #[cfg(test)]
    pub fn set_limit(&self, after: usize) {
        let mut state = self.state.lock().unwrap();
        let before = state.changed(after, Instant::now());
        self.publish(&state, Some((before, after)));
    }
    /// Whether growth is by an eighth at a time rather than doubling.
    #[cfg(test)]
    pub fn gradual(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.control.as_ref().is_some_and(|c| c.policy.settled)
    }
    pub fn capacity(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.control.as_ref().map_or(state.limit, |c| c.max)
    }
    /// Follow the limit as it changes.
    pub fn subscribe(&self) -> watch::Receiver<usize> {
        self.limit.subscribe()
    }
    /// A response asked the client to slow down (HTTP 429 or 503). Called as
    /// it arrives, while its request may still be retried.
    pub fn throttled(&self) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        state.advance(now);
        let change = state.throttled(now);
        self.publish(&state, change);
    }
    pub async fn acquire(self: &Arc<Self>) -> Permit {
        loop {
            let ready = self.changed.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                let now = Instant::now();
                state.advance(now);
                if state.active < state.limit {
                    state.active += 1;
                    return Permit {
                        budget: self.clone(),
                        generation: state.generation,
                        started: now,
                        bytes: 0,
                    };
                }
            }
            ready.await;
        }
    }
    fn release(&self, permit: &Permit) {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        state.advance(now);
        state.released(permit.generation);
        let change = state.finished(now, permit.started, permit.bytes);
        // One completion frees one slot. Waking the entire queue makes every
        // waiting request compete for that slot; growth wakes them all.
        self.changed.notify_one();
        self.publish(&state, change);
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.budget.release(self);
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
