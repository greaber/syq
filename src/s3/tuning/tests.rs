use super::*;
use std::{future::Future, task::Context};

fn new_budget(fixed: Option<usize>, ceiling: Option<usize>) -> (Arc<Budget>, Arc<Outage>) {
    let outage = Arc::new(Outage::default());
    let budget = Arc::new(Budget::new(fixed, ceiling));
    outage.slow_down(&budget);
    (budget, outage)
}

/// A window with `in_flight` requests on average, which spent `time` seconds
/// in flight per unit of work.
fn sample(in_flight: f64, time: f64) -> Sample {
    Sample {
        in_flight,
        time,
        rate: in_flight / time,
    }
}

#[test]
fn growth_doubles_while_requests_fill_the_limit_and_keep_paying() {
    let mut policy = Policy::default();
    // Fewer requests than the limit allowed were in flight: more would go
    // unused.
    assert_eq!(policy.observe(32, 4096, sample(20.0, 0.1)), 32);
    assert_eq!(policy.observe(32, 4096, sample(32.0, 0.1)), 64);
    // Each step's requests carried their share of the rate.
    assert_eq!(policy.observe(64, 4096, sample(64.0, 0.1)), 128);
    // Never past the batch's ceiling.
    assert_eq!(policy.observe(128, 200, sample(128.0, 0.1)), 200);
    assert_eq!(policy.observe(200, 200, sample(200.0, 0.1)), 200);
}

#[test]
fn a_step_up_that_does_not_pay_is_undone_to_what_the_rate_needs() {
    let mut policy = Policy::default();
    assert_eq!(policy.observe(32, 4096, sample(32.0, 0.1)), 64);
    // Twice the requests raise the rate only by 28%: about 41 requests
    // fill the path. New connections start slowly, so one window is not
    // enough to undo the step,
    let saturated = |requests: f64| sample(requests, requests / 409.6);
    assert_eq!(policy.observe(64, 4096, saturated(64.0)), 64);
    // but a second is. 32 requests carried 320 units; 409.6 need 41.
    assert_eq!(policy.observe(64, 4096, saturated(64.0)), 41);
    // Steps down follow, until one costs as much rate as it removed
    assert_eq!(policy.observe(41, 4096, saturated(41.0)), 36);
    assert_eq!(policy.observe(36, 4096, sample(36.0, 0.1)), 41);
    // and growth resumes, by an eighth at a time.
    assert_eq!(policy.observe(41, 4096, saturated(41.0)), 46);
}

#[test]
fn steps_down_that_reach_one_request_probe_upwards_again() {
    let mut policy = Policy::default();
    // The path carries the same rate however many requests share it.
    let saturated = |requests: f64| sample(requests, requests / 100.0);
    assert_eq!(policy.observe(2, 4096, saturated(2.0)), 4);
    assert_eq!(policy.observe(4, 4096, saturated(4.0)), 4);
    assert_eq!(policy.observe(4, 4096, saturated(4.0)), 2);
    assert_eq!(policy.observe(2, 4096, saturated(2.0)), 1);
    // There is no step below one request; the limit does not stay there.
    assert_eq!(policy.observe(1, 4096, saturated(1.0)), 2);
    assert_eq!(policy.observe(2, 4096, saturated(2.0)), 2);
    assert_eq!(policy.observe(2, 4096, saturated(2.0)), 1);
    assert_eq!(policy.observe(1, 4096, saturated(1.0)), 2);
}

#[test]
fn a_slow_first_window_does_not_undo_growth() {
    let mut policy = Policy::default();
    assert_eq!(policy.observe(64, 4096, sample(64.0, 0.1)), 128);
    // Requests on new connections take longer at first.
    assert_eq!(policy.observe(128, 4096, sample(128.0, 0.17)), 128);
    assert_eq!(policy.observe(128, 4096, sample(128.0, 0.105)), 256);
}

#[test]
fn a_slower_service_does_not_lower_a_judged_limit() {
    let mut policy = Policy::default();
    assert_eq!(policy.observe(512, 1024, sample(512.0, 0.05)), 1024);
    assert_eq!(policy.observe(1024, 1024, sample(1024.0, 0.05)), 1024);
    // Each request takes four times as long, with no change of the limit:
    // nothing this copy did.
    assert_eq!(policy.observe(1024, 1024, sample(1024.0, 0.2)), 1024);
    assert_eq!(policy.observe(1024, 1024, sample(1024.0, 0.2)), 1024);
}

#[test]
fn throttling_halves_and_ends_doubling() {
    let mut policy = Policy::default();
    assert_eq!(policy.throttled(100), 50);
    assert_eq!(policy.throttled(1), 1);
    assert_eq!(policy.observe(50, 4096, sample(50.0, 0.1)), 56);
}

#[test]
fn each_batch_starts_where_planning_chose_within_its_ceiling() {
    let (budget, _) = new_budget(None, None);
    assert_eq!(budget.limit(), INITIAL_REQUESTS);
    assert_eq!(budget.capacity(), DEFAULT_CEILING);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    assert_eq!(
        (budget.limit(), budget.capacity()),
        (INITIAL_REQUESTS, 4096)
    );
    // A wide start for far small objects, up to the ceiling.
    budget.configure(4096, 4096, false);
    assert_eq!((budget.limit(), budget.capacity()), (4096, 4096));
    budget.configure(INITIAL_REQUESTS, 8, false);
    assert_eq!((budget.limit(), budget.capacity()), (8, 8));
    budget.configure(0, 8, false);
    assert_eq!(budget.limit(), 1);

    // A ceiling the user set bounds every batch.
    let (capped, _) = new_budget(None, Some(16));
    capped.configure(4096, 4096, false);
    assert_eq!((capped.limit(), capped.capacity()), (16, 16));
    capped.configure(INITIAL_REQUESTS, 4, false);
    assert_eq!((capped.limit(), capped.capacity()), (4, 4));

    // A count the user fixed stays.
    let (fixed, _) = new_budget(Some(6), None);
    fixed.configure(4096, 4096, false);
    assert_eq!((fixed.limit(), fixed.capacity()), (6, 6));
}

#[test]
fn refusals_before_a_batch_do_not_cut_it() {
    let (budget, outage) = new_budget(None, None);
    // Listing or discovery refusals arrive before transfers are configured.
    outage.throttled();
    outage.throttled();
    budget.configure(INITIAL_REQUESTS, 64, false);
    assert_eq!(budget.limit(), INITIAL_REQUESTS);
}

fn poll_permit(budget: &Arc<Budget>, cx: &mut Context<'_>) -> Permit {
    let std::task::Poll::Ready(permit) = Box::pin(budget.acquire()).as_mut().poll(cx) else {
        panic!("slot unavailable");
    };
    permit
}

#[tokio::test(start_paused = true)]
async fn idle_time_before_the_first_request_is_not_measured() {
    let (budget, _) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    // Planning, listing or preparation take a while before any request.
    tokio::time::advance(Duration::from_secs(10)).await;
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut held: Vec<_> = (0..32).map(|_| poll_permit(&budget, &mut cx)).collect();
    // Half the requests finish after 100 ms, and others take their places:
    // the fastest half of a window.
    tokio::time::advance(Duration::from_millis(100)).await;
    held.drain(..16);
    held.extend((0..16).map(|_| poll_permit(&budget, &mut cx)));
    assert_eq!(budget.limit(), 32);
    // Once as many have finished as were in flight, the window describes
    // the limit. Had it started at the batch rather than at the first
    // request, it would have ended at the first 16.
    tokio::time::advance(Duration::from_millis(100)).await;
    held.drain(..15);
    assert_eq!(budget.limit(), 32);
    held.drain(..1);
    assert_eq!(budget.limit(), 64);
}

#[tokio::test(start_paused = true)]
async fn a_burst_of_refusals_halves_once_until_requests_drain_to_the_new_limit() {
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let mut limits = budget.subscribe();
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut held: Vec<_> = (0..32).map(|_| poll_permit(&budget, &mut cx)).collect();
    tokio::time::advance(Duration::from_millis(10)).await;
    // The refusal halves the limit as it arrives, while every request,
    // including the refused one being retried, still holds its permit, and
    // admission sees the new limit at once.
    outage.throttled();
    assert_eq!(budget.limit(), 16);
    assert!(limits.has_changed().unwrap());
    assert_eq!(*limits.borrow_and_update(), 16);
    // Responses to requests sent at the old limit still ask the client to
    // slow down; the halving already answered them.
    while held.len() > 16 {
        outage.throttled();
        held.pop();
        assert_eq!(budget.limit(), 16);
    }
    // Once no more are in flight than the new limit allows, the service
    // refusing them asks for fewer still.
    outage.throttled();
    assert_eq!(budget.limit(), 8);
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn a_refusal_as_a_window_opens_still_counts() {
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut held: Vec<_> = (0..32).map(|_| poll_permit(&budget, &mut cx)).collect();
    tokio::time::advance(Duration::from_millis(10)).await;
    outage.throttled();
    assert_eq!(budget.limit(), 16);
    // The requests from before the halving drain, and requests admitted
    // after it are refused just as the next window would open.
    held.truncate(1);
    held.extend((0..15).map(|_| poll_permit(&budget, &mut cx)));
    tokio::time::advance(Duration::from_millis(10)).await;
    outage.throttled();
    held.remove(0);
    assert_eq!(budget.limit(), 8);
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn throttling_after_growth_halves_while_older_requests_drain() {
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut old: Vec<_> = (0..32).map(|_| poll_permit(&budget, &mut cx)).collect();
    tokio::time::advance(Duration::from_millis(100)).await;
    old.drain(..16);
    old.extend((0..16).map(|_| poll_permit(&budget, &mut cx)));
    tokio::time::advance(Duration::from_millis(100)).await;
    old.drain(..16);
    assert_eq!(budget.limit(), 64);
    // Sixteen requests admitted at 32 are still in flight, enough to keep
    // the next window from starting, when requests admitted at 64 are
    // refused: the growth went too far, and halving must not wait for them.
    let mut new: Vec<_> = (0..32).map(|_| poll_permit(&budget, &mut cx)).collect();
    tokio::time::advance(Duration::from_millis(10)).await;
    outage.throttled();
    new.pop();
    assert_eq!(budget.limit(), 32);
    // More complaints from requests sent before the halving are answered.
    outage.throttled();
    new.pop();
    assert_eq!(budget.limit(), 32);
    drop((old, new));
}

#[tokio::test(start_paused = true)]
async fn growth_wakes_every_waiting_request_it_admits() {
    let (budget, _) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut held: Vec<_> = (0..32).map(|_| poll_permit(&budget, &mut cx)).collect();
    let (release, released) = tokio::sync::watch::channel(false);
    let waiters: Vec<_> = (0..64)
        .map(|_| {
            let (budget, admitted) = (budget.clone(), admitted.clone());
            let mut released = released.clone();
            tokio::spawn(async move {
                let _permit = budget.acquire().await;
                admitted.fetch_add(1, Relaxed);
                let _ = released.wait_for(|released| *released).await;
            })
        })
        .collect();
    tokio::task::yield_now().await;
    assert_eq!(admitted.load(Relaxed), 0);
    tokio::time::advance(Duration::from_millis(300)).await;
    // Without yielding, so that only growth can wake the waiters beyond
    // the 32 freed slots.
    held.clear();
    assert_eq!(budget.limit(), 64);
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(admitted.load(Relaxed), 64);
    assert_eq!(budget.state.lock().unwrap().active, 64);
    release.send_replace(true);
    for waiter in waiters {
        waiter.await.unwrap();
    }
    drop(held);
    assert_eq!(budget.state.lock().unwrap().active, 0);
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
    let (budget, _) = new_budget(Some(1), None);
    let held = poll_permit(&budget, &mut cx);
    let mut waiting: Vec<_> = (0..64).map(|_| Box::pin(budget.acquire())).collect();
    for request in &mut waiting {
        assert!(request.as_mut().poll(&mut cx).is_pending());
    }
    drop(held);
    assert_eq!(wakes.0.load(Relaxed), 1);
}

#[test]
fn cancelled_notified_request_passes_the_free_slot_to_another_waiter() {
    let (budget, _) = new_budget(Some(1), None);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let held = poll_permit(&budget, &mut cx);
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

/// A simulated storage service for closed-loop runs under paused time.
#[derive(Clone, Copy)]
struct Service {
    /// The time to a response when nothing queues.
    rtt: Duration,
    bytes: u64,
    /// Bytes per second one request moves, and the path in total, shared
    /// by the requests in flight.
    per_request: Option<f64>,
    bandwidth: Option<f64>,
    /// More requests in flight than this are asked to slow down, and are
    /// answered after a retry.
    throttle_above: Option<usize>,
}
impl Service {
    fn far_small_objects() -> Self {
        Self {
            rtt: Duration::from_millis(100),
            bytes: 4096,
            per_request: None,
            bandwidth: None,
            throttle_above: None,
        }
    }
    /// Answer a request while `active()` requests are in flight, in slices
    /// so that the path's bandwidth is shared as their number changes.
    async fn respond(&self, outage: &Outage, active: impl Fn() -> usize) {
        if self.throttle_above.is_some_and(|above| active() > above) {
            outage.throttled();
            // The retry follows the refusal.
            tokio::time::sleep(2 * self.rtt).await;
        }
        tokio::time::sleep(self.rtt).await;
        const SLICES: u32 = 8;
        for _ in 0..SLICES {
            let rate = match (self.per_request, self.bandwidth) {
                (Some(each), Some(total)) => each.min(total / active() as f64),
                (Some(each), None) => each,
                (None, Some(total)) => total / active() as f64,
                (None, None) => return,
            };
            let slice = self.bytes as f64 / f64::from(SLICES);
            tokio::time::sleep(Duration::from_secs_f64(slice / rate)).await;
        }
    }
}

struct Run {
    /// The limit every 10 ms.
    limits: Vec<usize>,
    /// Bytes completed every 10 ms.
    bytes: Vec<u64>,
    /// The most requests in flight seen.
    peak: usize,
}
impl Run {
    fn at(&self, seconds: f64) -> usize {
        self.limits[(seconds * 100.0) as usize]
    }
    fn between(&self, from: f64, to: f64) -> &[usize] {
        &self.limits[(from * 100.0) as usize..(to * 100.0) as usize]
    }
    fn rate(&self, from: f64, to: f64) -> f64 {
        let bytes: u64 = self.bytes[(from * 100.0) as usize..(to * 100.0) as usize]
            .iter()
            .sum();
        bytes as f64 / (to - from)
    }
}

/// Run `demand` requests at once against `service` for `seconds`, each
/// sending its next request when the last one finishes. `change` replaces
/// the service at the given time.
async fn simulate(
    budget: &Arc<Budget>,
    outage: &Arc<Outage>,
    service: Service,
    demand: usize,
    seconds: u64,
    change: Option<(f64, Service)>,
) -> Run {
    let service = Arc::new(Mutex::new(service));
    let done = Arc::new(AtomicU64::new(0));
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..demand {
        let (budget, outage, service, done) = (
            budget.clone(),
            outage.clone(),
            service.clone(),
            done.clone(),
        );
        tasks.spawn(async move {
            while Instant::now() < end {
                let mut permit = budget.acquire().await;
                let service = *service.lock().unwrap();
                service
                    .respond(&outage, || budget.state.lock().unwrap().active)
                    .await;
                permit.completed(service.bytes);
                done.fetch_add(service.bytes, Relaxed);
                drop(permit);
            }
        });
    }
    let start = Instant::now();
    let mut run = Run {
        limits: Vec::new(),
        bytes: Vec::new(),
        peak: 0,
    };
    let mut last = 0;
    let mut ticks = tokio::time::interval(Duration::from_millis(10));
    while Instant::now() < end {
        ticks.tick().await;
        if let Some((at, next)) = change {
            if start.elapsed().as_secs_f64() >= at {
                *service.lock().unwrap() = next;
            }
        }
        let state = budget.state.lock().unwrap();
        run.peak = run.peak.max(state.active);
        run.limits.push(state.limit);
        drop(state);
        let total = done.load(Relaxed);
        run.bytes.push(total - last);
        last = total;
    }
    while tasks.join_next().await.is_some() {}
    let mut changes = Vec::new();
    for (tick, pair) in run.limits.windows(2).enumerate() {
        if pair[0] != pair[1] {
            changes.push(format!("{:.2}s:{}", (tick + 1) as f64 / 100.0, pair[1]));
        }
    }
    eprintln!("TRACE {}", changes.join(" "));
    run
}

#[tokio::test(start_paused = true)]
async fn far_small_objects_ramp_up_smoothly_from_a_small_start() {
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let run = simulate(
        &budget,
        &outage,
        Service::far_small_objects(),
        8192,
        6,
        None,
    )
    .await;
    // No jump of more than a doubling, and never past the ceiling.
    for pair in run.limits.windows(2) {
        assert!(pair[1] <= pair[0] * 2, "{pair:?}");
    }
    assert!(run.peak <= 4096);
    // It starts small rather than with thousands of requests in flight
    assert_eq!(run.at(0.0), INITIAL_REQUESTS);
    assert!(run.at(0.5) <= 128, "{}", run.at(0.5));
    // and still reaches the ceiling within a few seconds at 100 ms.
    assert_eq!(run.at(4.0), 4096);
}

#[tokio::test(start_paused = true)]
async fn a_gradual_start_grows_by_eighths_and_still_reaches_the_ceiling() {
    let (budget, outage) = new_budget(None, None);
    budget.configure(256, 4096, true);
    let run = simulate(
        &budget,
        &outage,
        Service::far_small_objects(),
        8192,
        12,
        None,
    )
    .await;
    assert_eq!(run.at(0.0), 256);
    for pair in run.limits.windows(2) {
        assert!(pair[1] <= pair[0] + pair[0] / 8, "{pair:?}");
    }
    assert_eq!(run.at(11.9), 4096);
}

#[tokio::test(start_paused = true)]
async fn requests_stop_growing_where_the_path_saturates() {
    // Each request moves 50 MiB/s, the path 2 GiB/s: about 41 requests
    // fill it, and more only queue.
    let mib = 1024.0 * 1024.0;
    let service = Service {
        rtt: Duration::from_millis(2),
        bytes: 8 << 20,
        per_request: Some(50.0 * mib),
        bandwidth: Some(2048.0 * mib),
        throttle_above: None,
    };
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 256, false);
    let run = simulate(&budget, &outage, service, 512, 20, None).await;
    // The limit overshoots by at most one doubling, then keeps within a
    // few steps of what the path needs, as it probes for changes,
    assert!(run.peak <= 64, "{}", run.peak);
    let settled = run.between(5.0, 20.0);
    assert!(
        settled.iter().all(|limit| (32..=56).contains(limit)),
        "{settled:?}"
    );
    // without giving up throughput.
    assert!(
        run.rate(5.0, 20.0) >= 0.95 * 2048.0 * mib,
        "{}",
        run.rate(5.0, 20.0) / mib
    );
}

#[tokio::test(start_paused = true)]
async fn throttling_backs_off_and_growth_resumes_once_it_stops() {
    let unthrottled = Service {
        rtt: Duration::from_millis(50),
        ..Service::far_small_objects()
    };
    let throttled = Service {
        throttle_above: Some(100),
        ..unthrottled
    };
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let run = simulate(
        &budget,
        &outage,
        throttled,
        8192,
        14,
        Some((7.0, unthrottled)),
    )
    .await;
    // The service lets 100 requests through. Each time more are in flight
    // the limit halves as the refusal arrives, then grows by an eighth at a
    // time.
    let throttling = run.between(1.0, 7.0);
    assert!(
        throttling.iter().all(|limit| *limit <= 101 + 101 / 8),
        "{throttling:?}"
    );
    let average = throttling.iter().sum::<usize>() / throttling.len();
    assert!((50..=110).contains(&average), "{average}");
    assert!(outage.throttled_responses() > 0);
    // Without throttling, growth resumes: by an eighth at a time, no
    // longer doubling.
    let after = run.between(7.0, 14.0);
    for pair in after.windows(2) {
        assert!(pair[1] <= pair[0] + pair[0] / 8 + 1, "{pair:?}");
    }
    assert!(run.at(13.9) >= 400, "{}", run.at(13.9));
}

#[tokio::test(start_paused = true)]
async fn a_slower_service_does_not_starve_the_copy() {
    // Responses take four times as long from 5 s: nothing this copy did.
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 1024, false);
    let fast = Service {
        rtt: Duration::from_millis(20),
        ..Service::far_small_objects()
    };
    let slow = Service {
        rtt: Duration::from_millis(80),
        ..fast
    };
    let run = simulate(&budget, &outage, fast, 2048, 10, Some((5.0, slow))).await;
    assert_eq!(run.at(4.9), 1024);
    // At most one halving before the next window shows that fewer requests
    // do not shorten the time,
    assert!(run.between(5.0, 10.0).iter().all(|limit| *limit >= 512));
    // and the limit returns to the ceiling.
    assert_eq!(run.at(9.9), 1024);
}

fn new_tuning(tigris: bool, upload: bool) -> Tuning {
    Tuning {
        control: Arc::default(),
        tigris,
        upload,
        requests: new_budget(None, None).0,
        reads: crate::s3::read_recovery::Recovery::default(),
        retained_upload_files: Default::default(),
        upload_buffers: Arc::new(tokio::sync::Semaphore::new(1)),
    }
}

#[test]
fn a_lone_cold_response_keeps_the_wide_start_until_a_warm_one_arrives() {
    let tuning = new_tuning(false, true);
    assert!(!tuning.far() && !tuning.local());
    // One listing page on a 90 ms endpoint: only the cold response exists.
    tuning.control.observe_first(Duration::from_millis(270));
    assert_eq!(tuning.control_latency(), Some(Duration::from_millis(270)));
    assert!(tuning.far());
    // A 10 ms endpoint whose cold response crossed the threshold starts
    // as a near one once a warm response shows the real distance.
    tuning.control.observe(Duration::from_millis(10));
    assert_eq!(tuning.control_latency(), Some(Duration::from_millis(10)));
    assert!(!tuning.far() && !tuning.local());
    tuning.control.observe(Duration::from_micros(500));
    assert!(tuning.local());
    // Tigris uploads keep the usual start however far the endpoint is.
    let tigris = new_tuning(true, true);
    tigris.control.observe(Duration::from_millis(90));
    assert!(!tigris.far());
    let download = new_tuning(true, false);
    download.control.observe(Duration::from_millis(90));
    assert!(download.far());
}

#[test]
fn a_fixed_request_count_ignores_refusals() {
    let (budget, outage) = new_budget(Some(6), None);
    outage.throttled();
    assert_eq!(budget.limit(), 6);
}

#[test]
fn small_object_budget_leaves_room_for_existing_descriptors() {
    assert_eq!(small_capacity(1024, 900, 1024), 15);
    assert_eq!(small_capacity(64, 10, 1024), 0);
    assert_eq!(small_capacity(8192, 8, 1024), 2030);
    assert_eq!(small_capacity(524288, 8, 1024), 4096);
}
#[test]
fn small_object_budget_bounds_payload_memory_and_empty_objects() {
    assert_eq!(small_capacity(524288, 8, 1024 * 1024), 256);
    assert_eq!(small_capacity(524288, 8, 0), 4096);
    assert_eq!(small_capacity(524288, 8, 64 * 1024), 4096);
    assert_eq!(small_capacity(524288, 8, 512 * 1024), 512);
}

#[tokio::test(start_paused = true)]
async fn a_few_slow_requests_cannot_hold_back_the_next_decision() {
    let (budget, _) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut old: Vec<_> = (0..32).map(|_| poll_permit(&budget, &mut cx)).collect();
    budget.set_limit(64);
    // All but eight of the requests admitted before the change finish, and
    // the new ones keep finishing every 10 ms.
    tokio::time::advance(Duration::from_millis(10)).await;
    old.truncate(8);
    let mut new: Vec<_> = (0..56).map(|_| poll_permit(&budget, &mut cx)).collect();
    let cycle = |new: &mut Vec<Permit>, cx: &mut Context<'_>| {
        new.drain(..);
        new.extend((0..56).map(|_| poll_permit(&budget, cx)));
    };
    // The stragglers might yet finish, so no window starts,
    for _ in 0..15 {
        tokio::time::advance(Duration::from_millis(10)).await;
        cycle(&mut new, &mut cx);
    }
    assert_eq!(budget.limit(), 64);
    assert!(budget
        .state
        .lock()
        .unwrap()
        .control
        .as_ref()
        .unwrap()
        .window
        .start
        .is_none());
    // but after several windows' time they no longer hold it back.
    for _ in 0..20 {
        tokio::time::advance(Duration::from_millis(10)).await;
        cycle(&mut new, &mut cx);
    }
    assert_eq!(budget.limit(), 128);
    drop((old, new));
}

/// Half the request slots hang, while requests in the other half keep
/// finishing. A request may take hours, so the hung ones are never known
/// to have stalled, but they must not hold every later decision back.
#[tokio::test(start_paused = true)]
async fn hung_requests_cannot_freeze_the_limit() {
    let (budget, _) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 4096, false);
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let hung: Vec<_> = (0..16).map(|_| poll_permit(&budget, &mut cx)).collect();
    let mut running: Vec<_> = (0..16).map(|_| poll_permit(&budget, &mut cx)).collect();
    let mut limits = vec![];
    for _ in 0..400 {
        tokio::time::advance(Duration::from_millis(100)).await;
        let n = running.len();
        for permit in &mut running {
            permit.completed(64 << 10);
        }
        running.clear();
        running.extend((0..n).map(|_| poll_permit(&budget, &mut cx)));
        // New requests take what growth frees, and finish as the others do.
        loop {
            let state = budget.state.lock().unwrap();
            let free = state.active < state.limit;
            drop(state);
            if !free {
                break;
            }
            running.push(poll_permit(&budget, &mut cx));
        }
        limits.push(budget.limit());
    }
    // The finished requests' times never account for 70% of the time in
    // flight while the hung half still counts: they might be long transfers.
    assert_eq!(limits[250], INITIAL_REQUESTS);
    // After `UNCOVERED_WAIT` the window ends anyway, at the rate the others
    // carry, and the limit grows.
    assert!(limits[350] > INITIAL_REQUESTS, "{limits:?}");
    drop(hung);
}

/// Quick checks of objects that need no transfer, beside transfers that
/// each take seconds, all within the one limit. Most windows end before
/// any transfer finishes; the checks' short response times must not stand
/// for the transfers still in flight.
#[tokio::test(start_paused = true)]
async fn quick_checks_beside_long_transfers_do_not_drive_growth() {
    let mib = 1024.0 * 1024.0;
    // Each transfer moves 50 MiB/s, the path 2 GiB/s: about 41 transfers
    // fill it.
    let transfer = Service {
        rtt: Duration::from_millis(2),
        bytes: 256 << 20,
        per_request: Some(50.0 * mib),
        bandwidth: Some(2048.0 * mib),
        throttle_above: None,
    };
    let check = Service {
        rtt: Duration::from_millis(2),
        bytes: 0,
        per_request: None,
        bandwidth: None,
        throttle_above: None,
    };
    let (budget, outage) = new_budget(None, None);
    budget.configure(INITIAL_REQUESTS, 256, false);
    let transfers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let done = Arc::new(AtomicU64::new(0));
    let end = Instant::now() + Duration::from_secs(60);
    let mut tasks = tokio::task::JoinSet::new();
    for task in 0..512 {
        let (budget, outage, transfers, done) = (
            budget.clone(),
            outage.clone(),
            transfers.clone(),
            done.clone(),
        );
        // A few tasks check objects one after another.
        let service = if task < 4 { check } else { transfer };
        tasks.spawn(async move {
            while Instant::now() < end {
                let mut permit = budget.acquire().await;
                if service.bytes > 0 {
                    transfers.fetch_add(1, Relaxed);
                }
                service.respond(&outage, || transfers.load(Relaxed)).await;
                if service.bytes > 0 {
                    transfers.fetch_sub(1, Relaxed);
                }
                permit.completed(service.bytes);
                done.fetch_add(service.bytes, Relaxed);
                drop(permit);
            }
        });
    }
    let mut limits = Vec::new();
    let mut peak = 0;
    let mut ticks = tokio::time::interval(Duration::from_millis(10));
    let mut bytes_after_20s = 0;
    while Instant::now() < end {
        ticks.tick().await;
        let state = budget.state.lock().unwrap();
        peak = peak.max(state.limit);
        limits.push(state.limit);
        drop(state);
        if limits.len() == 2000 {
            bytes_after_20s = done.load(Relaxed);
        }
    }
    let rate = (done.load(Relaxed) - bytes_after_20s) as f64 / 40.0;
    while tasks.join_next().await.is_some() {}
    let mut changes = Vec::new();
    for (tick, pair) in limits.windows(2).enumerate() {
        if pair[0] != pair[1] {
            changes.push(format!("{:.2}s:{}", (tick + 1) as f64 / 100.0, pair[1]));
        }
    }
    eprintln!("TRACE {} rate {:.0} MiB/s", changes.join(" "), rate / mib);
    // More transfers than the path needs only queue on it.
    let settled = &limits[2000..];
    assert!(settled.iter().all(|limit| *limit <= 128), "{settled:?}");
    assert!(peak < 256, "{peak}");
    assert!(rate >= 0.8 * 2048.0 * mib, "{}", rate / mib);
}
