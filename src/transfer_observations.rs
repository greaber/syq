//! Observation points, not inferred causes. Worker states partition worker
//! lifetime (including tuning pauses); endpoint operations can overlap them.
//! Snapshots include unfinished operations, so a stalled syscall is visible
//! before it returns. No payload storage or collection thread lives here.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const STATES: usize = 18;
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Stage {
    /// Outside a tracked operation; excluded from time fractions.
    Inactive,
    /// Worker run, excluding its nested waits and explicit operations.
    Work,
    /// From entering sched.next() until it returns.
    AwaitingWork,
    /// From entering the connection tuner gate until released.
    Parked,
    /// Source connection send; may execute local handling synchronously.
    SourceRequest,
    /// Source connection recv through receipt or error.
    SourceResponse,
    /// Destination connection send, including synchronous local handling.
    DestinationSend,
    /// Destination recv or streaming-reply join through receipt/error.
    DestinationAck,
    /// Bandwidth limiter wait call, when a limiter is configured.
    Pacing,
    /// Demand read/read_exact_at call; endpoint identifies source or basis.
    SourceRead,
    /// Content digest computation, excluding the preceding read.
    Hashing,
    /// Write/write_all_at call, with no additional durability fence.
    DestinationWrite,
    /// Whole local filesystem-copy operation, including its fallback.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    // Stable cross-platform wire state IDs.
    FilesystemCopy,
    /// Helper advisory syscall; byte count is requested advice length.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    // Stable cross-platform wire state IDs.
    PrefetchAdvice,
    /// Waiting for an in-flight advisory call before releasing an interval.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    // Stable cross-platform wire state IDs.
    PrefetchFence,
    /// Server request queue recv through receipt or disconnect.
    RequestWait,
    /// Filesystem request dispatch, excluding nested measured operations.
    Handling,
    /// Server response serialization/write call.
    ResponseSend,
}
const NAMES: [&str; STATES] = [
    "inactive",
    "other_work",
    "awaiting_work",
    "parked",
    "source_request",
    "source_response",
    "destination_send",
    "destination_ack",
    "pacing",
    "source_read",
    "hashing",
    "destination_write",
    "filesystem_copy",
    "prefetch_advice",
    "prefetch_fence",
    "request_wait",
    "handling",
    "response_send",
];

/// A single executing thread owns transitions; the progress ticker only reads.
/// The sequence lock makes counters and the unfinished state one snapshot.
pub(crate) struct Actor {
    enabled: AtomicBool,
    #[cfg(target_os = "linux")]
    thread_id: AtomicU64,
    thread_cpu: Mutex<HelperCpu>,
    role: &'static str,
    start: Instant,
    sequence: AtomicU64,
    since: AtomicU64,
    state: AtomicU64,
    times: [AtomicU64; STATES],
    bytes: [AtomicU64; STATES],
}
impl Actor {
    pub(crate) fn new(role: &'static str) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(true),
            #[cfg(target_os = "linux")]
            thread_id: AtomicU64::new(0),
            thread_cpu: Mutex::new(HelperCpu::default()),
            role,
            start: Instant::now(),
            sequence: AtomicU64::new(0),
            since: AtomicU64::new(0),
            state: AtomicU64::new(0),
            times: std::array::from_fn(|_| AtomicU64::new(0)),
            bytes: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }
    fn now(&self) -> u64 {
        self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }
    fn transition(&self, state: u64, now: u64) -> u64 {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        let previous = self.state.load(Ordering::Relaxed);
        let since = self.since.swap(now, Ordering::Relaxed);
        if previous != 0 {
            self.times[previous as usize].fetch_add(now.saturating_sub(since), Ordering::Relaxed);
        }
        self.state.store(state, Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
        previous
    }
    pub(crate) fn span(self: &Arc<Self>, stage: Stage) -> Span {
        if !self.enabled.load(Ordering::Relaxed) {
            return Span {
                actor: None,
                previous: 0,
                stage: stage as usize,
            };
        }
        #[cfg(target_os = "linux")]
        if self.role == "prefetch" && self.thread_id.load(Ordering::Relaxed) == 0 {
            // SAFETY: gettid takes no pointers and identifies this helper.
            self.thread_id.store(
                unsafe { libc::syscall(libc::SYS_gettid) } as u64,
                Ordering::Relaxed,
            );
        }
        let previous = self.transition(stage as u64, self.now());
        Span {
            actor: Some(self.clone()),
            previous,
            stage: stage as usize,
        }
    }
    fn snapshot_with_clock(&self, clock: impl Fn() -> u64) -> ActorSnapshot {
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let state = self.state.load(Ordering::Relaxed) as usize;
            let since = self.since.load(Ordering::Relaxed);
            let mut times = std::array::from_fn(|i| self.times[i].load(Ordering::Relaxed));
            let bytes = std::array::from_fn(|i| self.bytes[i].load(Ordering::Relaxed));
            let now = clock();
            std::sync::atomic::fence(Ordering::Acquire);
            if before != self.sequence.load(Ordering::Acquire) {
                continue;
            }
            if state != 0 {
                times[state] = times[state].saturating_add(now.saturating_sub(since));
            }
            return ActorSnapshot {
                role: self.role.into(),
                thread_cpu: None,
                state,
                times,
                bytes,
            };
        }
    }
    #[cfg(test)]
    fn snapshot_at(&self, now: u64) -> ActorSnapshot {
        self.snapshot_with_clock(|| now)
    }
    fn snapshot(&self) -> ActorSnapshot {
        let mut sample = self.snapshot_with_clock(|| self.now());
        let cpu = self.thread_cpu.lock().unwrap();
        #[cfg(target_os = "linux")]
        let mut cpu = cpu;
        #[cfg(target_os = "linux")]
        if self.role == "prefetch" {
            let tid = self.thread_id.load(Ordering::Relaxed);
            if tid != 0 {
                if let Some(live) = thread_cpu(tid) {
                    cpu.latest = Some(cpu.completed.plus(live));
                }
            }
        }
        sample.thread_cpu = cpu.latest;
        sample
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn finish_thread(&self) {
        if self.thread_id.load(Ordering::Relaxed) == 0 {
            return;
        }
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let mut cpu = self.thread_cpu.lock().unwrap();
        if let Some(finished) = CpuTimes::thread() {
            cpu.completed = cpu.completed.plus(finished);
            cpu.latest = Some(cpu.completed);
        }
        self.thread_id.store(0, Ordering::Relaxed);
    }
}
pub(crate) struct Span {
    actor: Option<Arc<Actor>>,
    previous: u64,
    stage: usize,
}
impl Span {
    pub(crate) fn bytes(&self, bytes: u64) {
        if let Some(actor) = &self.actor {
            actor.bytes[self.stage].fetch_add(bytes, Ordering::Relaxed);
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if let Some(actor) = &self.actor {
            actor.transition(self.previous, actor.now());
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ActorSnapshot {
    thread_cpu: Option<CpuTimes>,
    role: String,
    state: usize,
    times: [u64; STATES],
    bytes: [u64; STATES],
}
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub(crate) struct CpuTimes {
    pub user_ns: u64,
    pub system_ns: u64,
}
#[derive(Default)]
struct HelperCpu {
    #[cfg(target_os = "linux")]
    completed: CpuTimes,
    latest: Option<CpuTimes>,
}
impl CpuTimes {
    #[cfg(target_os = "linux")]
    fn plus(self, other: Self) -> Self {
        Self {
            user_ns: self.user_ns.saturating_add(other.user_ns),
            system_ns: self.system_ns.saturating_add(other.system_ns),
        }
    }
    pub(crate) fn process() -> Option<Self> {
        Self::read(libc::RUSAGE_SELF)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn thread() -> Option<Self> {
        Self::read(libc::RUSAGE_THREAD)
    }
    fn read(who: libc::c_int) -> Option<Self> {
        let mut value = std::mem::MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: getrusage initializes the supplied structure on success.
        if unsafe { libc::getrusage(who, value.as_mut_ptr()) } != 0 {
            return None;
        }
        let value = unsafe { value.assume_init() };
        let ns = |t: libc::timeval| {
            (t.tv_sec.max(0) as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add((t.tv_usec.max(0) as u64).saturating_mul(1_000))
        };
        Some(Self {
            user_ns: ns(value.ru_utime),
            system_ns: ns(value.ru_stime),
        })
    }
}

#[derive(Default)]
pub(crate) struct Registry {
    enabled: AtomicBool,
    actors: Mutex<Vec<Arc<Actor>>>,
}
impl Registry {
    pub(crate) fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        for actor in self.actors.lock().unwrap().iter() {
            actor.enabled.store(true, Ordering::Relaxed);
        }
    }
    pub(crate) fn actor(&self, role: &'static str) -> Arc<Actor> {
        let actor = Actor::new(role);
        actor
            .enabled
            .store(self.enabled.load(Ordering::Relaxed), Ordering::Relaxed);
        self.actors.lock().unwrap().push(actor.clone());
        actor
    }
    pub(crate) fn snapshot(&self) -> ServerSnapshot {
        ServerSnapshot {
            actors: self
                .actors
                .lock()
                .unwrap()
                .iter()
                .map(|a| a.snapshot())
                .collect(),
            tcp: None,
            process: process_identity().to_owned(),
            at_ns: process_clock(),
            cpu: CpuTimes::process(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ServerSnapshot {
    /// Attached by the receiver from the existing TransportStats payload.
    #[serde(skip)]
    pub(crate) tcp: Option<crate::proto::TcpSocketStats>,
    actors: Vec<ActorSnapshot>,
    process: String,
    at_ns: u64,
    cpu: Option<CpuTimes>,
}
impl ServerSnapshot {
    pub(crate) fn valid(&self) -> bool {
        self.process.len() <= 96
            && self.actors.len() <= 64
            && self
                .actors
                .iter()
                .all(|a| a.state < STATES && a.role.len() <= 32)
    }
}

/// Received by the existing response reader; the ticker never waits for wire I/O.
#[derive(Default)]
pub(crate) struct RemoteSample {
    pub latest: Mutex<Option<(Instant, ServerSnapshot)>>,
    first: Mutex<Option<ServerSnapshot>>,
    pub final_tcp: Mutex<Option<crate::proto::TcpSocketStats>>,
}
impl RemoteSample {
    pub(crate) fn update(&self, snapshot: ServerSnapshot) {
        if snapshot.valid() {
            self.first
                .lock()
                .unwrap()
                .get_or_insert_with(|| snapshot.clone());
            *self.latest.lock().unwrap() = Some((Instant::now(), snapshot));
        }
    }
}
// One clock/identity per process, shared by all its connection handlers. CPU
// readings from those handlers describe the same process and must not be added.
fn process_identity() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| {
        let mut random = [0u8; 16];
        if getrandom::fill(&mut random).is_ok() {
            random.iter().map(|b| format!("{b:02x}")).collect()
        } else {
            format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            )
        }
    })
}
fn process_clock() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

enum EndpointSource {
    Local(Arc<Registry>),
    Remote(
        Arc<RemoteSample>,
        Option<std::sync::Weak<std::net::TcpStream>>,
    ),
}
struct Endpoint {
    label: String,
    source: EndpointSource,
    initial: Option<ServerSnapshot>,
    previous: Option<ServerSnapshot>,
    previous_tcp: Option<crate::proto::TcpSocketStats>,
}
#[derive(Default)]
pub(crate) struct Observations {
    pub enabled: AtomicBool,
    pub human_summary: AtomicBool,
    /// Stop retrying optional subscriptions if they break a connection.
    pub remote_subscription_failed: AtomicBool,
    pub workers: Registry,
    endpoints: Mutex<Vec<Endpoint>>,
    previous: Mutex<Option<ServerSnapshot>>,
    processes: Mutex<BTreeMap<String, (u64, CpuTimes)>>,
    initial_cpu: Mutex<BTreeMap<String, CpuTimes>>,
}
#[derive(Serialize)]
pub(crate) struct Interval {
    pub summary: String,
    /// Interval length on the coordinator's monotonic clock.
    pub elapsed_ms: u64,
    pub workers: WorkerInterval,
    /// Each process appears once; helper thread CPU is a subset of these totals.
    pub processes: Vec<ProcessInterval>,
    pub endpoints: Vec<EndpointInterval>,
}
#[derive(Serialize)]
pub(crate) struct WorkerInterval {
    /// Includes retired workers, whose completed activity remains in totals.
    pub observed: usize,
    /// Currently executing or waiting; excludes retired and tuner-parked workers.
    pub active: usize,
    pub awaiting_work: usize,
    pub parked: usize,
    /// Sum of measured worker-state durations, excluding tuner parking.
    pub observed_ns: u64,
    pub fractions: BTreeMap<&'static str, f64>,
    pub parked_ns: u64,
    pub cumulative_parked_ns: u64,
    pub cumulative_fractions: BTreeMap<&'static str, f64>,
}
#[derive(Serialize)]
pub(crate) struct ProcessInterval {
    pub process: String,
    pub local: bool,
    pub sample_age_ms: u64,
    pub elapsed_ms: Option<u64>,
    /// Null on the first remote sample or when no newer sample arrived.
    pub cpu: Option<CpuTimes>,
    pub cumulative_cpu: Option<CpuTimes>,
}
#[derive(Serialize)]
pub(crate) struct EndpointInterval {
    pub label: String,
    pub sample_age_ms: Option<u64>,
    pub process: Option<String>,
    /// Null when remote evidence has not advanced since the preceding record.
    pub elapsed_ms: Option<u64>,
    pub actors: Vec<OperationInterval>,
    pub cumulative_actors: Vec<OperationInterval>,
    /// Current local-side TCP_INFO, or the last reading after socket retirement.
    pub tcp: Option<crate::proto::TcpSocketStats>,
    pub tcp_delta: Option<TcpDelta>,
    pub peer_tcp: Option<crate::proto::TcpSocketStats>,
    pub peer_tcp_delta: Option<TcpDelta>,
}
#[derive(Serialize)]
pub(crate) struct OperationInterval {
    pub role: String,
    /// State at the endpoint sample, not necessarily its current state.
    pub state_at_sample: &'static str,
    pub observed_ns: u64,
    pub fractions: BTreeMap<&'static str, f64>,
    /// Completed syscall bytes; prefetch_advice counts requested bytes only.
    pub bytes: BTreeMap<&'static str, u64>,
    /// Linux helper-thread CPU, already included in process CPU.
    pub helper_cpu: Option<CpuTimes>,
}
#[derive(Serialize)]
pub(crate) struct TcpDelta {
    pub bytes_sent: Option<u64>,
    pub retransmissions: Option<u64>,
    pub busy_time_us: Option<u64>,
    pub receive_window_limited_us: Option<u64>,
    pub send_buffer_limited_us: Option<u64>,
}
fn difference(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    a.zip(b).map(|(a, b)| a.saturating_sub(b))
}
fn cpu_difference(a: Option<CpuTimes>, b: Option<CpuTimes>) -> Option<CpuTimes> {
    a.zip(b).map(|(a, b)| CpuTimes {
        user_ns: a.user_ns.saturating_sub(b.user_ns),
        system_ns: a.system_ns.saturating_sub(b.system_ns),
    })
}
fn time_totals(rows: &[ActorSnapshot], old: &[ActorSnapshot]) -> [u64; STATES] {
    let mut totals = [0u64; STATES];
    for (i, actor) in rows.iter().enumerate() {
        for (stage, total) in totals.iter_mut().enumerate().skip(1) {
            *total = total.saturating_add(
                actor.times[stage].saturating_sub(old.get(i).map_or(0, |row| row.times[stage])),
            );
        }
    }
    totals
}
fn operations(sample: &ServerSnapshot, old: &ServerSnapshot) -> Vec<OperationInterval> {
    sample
        .actors
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let b = old.actors.get(i);
            let times =
                std::array::from_fn(|j| a.times[j].saturating_sub(b.map_or(0, |b| b.times[j])));
            let (observed_ns, fractions) = fractions(&times);
            OperationInterval {
                role: a.role.clone(),
                state_at_sample: NAMES[a.state],
                observed_ns,
                fractions,
                bytes: NAMES
                    .iter()
                    .enumerate()
                    .filter_map(|(j, name)| {
                        let n = a.bytes[j].saturating_sub(b.map_or(0, |b| b.bytes[j]));
                        (n > 0).then_some((*name, n))
                    })
                    .collect(),
                helper_cpu: cpu_difference(
                    a.thread_cpu,
                    b.and_then(|b| b.thread_cpu).or(Some(CpuTimes::default())),
                ),
            }
        })
        .collect()
}
fn fractions(totals: &[u64; STATES]) -> (u64, BTreeMap<&'static str, f64>) {
    let total = totals.iter().fold(0u64, |a, b| a.saturating_add(*b));
    (
        total,
        NAMES
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(i, _)| totals[*i] > 0)
            .map(|(i, name)| (*name, totals[i] as f64 / total.max(1) as f64))
            .collect(),
    )
}
fn worker_fractions(mut totals: [u64; STATES]) -> (u64, BTreeMap<&'static str, f64>) {
    totals[Stage::Parked as usize] = 0;
    fractions(&totals)
}
impl Observations {
    pub(crate) fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
        self.workers.enable();
        let mut previous = self.previous.lock().unwrap();
        if previous.is_none() {
            let sample = self.workers.snapshot();
            if let Some(cpu) = sample.cpu {
                self.initial_cpu
                    .lock()
                    .unwrap()
                    .insert(sample.process.clone(), cpu);
                self.processes
                    .lock()
                    .unwrap()
                    .insert(sample.process.clone(), (sample.at_ns, cpu));
            }
            *previous = Some(sample);
        }
    }
    pub(crate) fn local(&self, label: String, registry: Arc<Registry>) {
        let initial = registry.snapshot();
        self.endpoints.lock().unwrap().push(Endpoint {
            label,
            initial: Some(initial.clone()),
            previous: Some(initial),
            previous_tcp: None,
            source: EndpointSource::Local(registry),
        });
    }
    pub(crate) fn remote(
        &self,
        label: String,
        sample: Arc<RemoteSample>,
        socket: Option<std::sync::Weak<std::net::TcpStream>>,
    ) {
        let previous_tcp = socket
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .as_deref()
            .and_then(crate::conn::tcp_socket_stats);
        self.endpoints.lock().unwrap().push(Endpoint {
            label,
            source: EndpointSource::Remote(sample, socket),
            initial: None,
            previous: None,
            previous_tcp,
        });
    }
    pub(crate) fn sample(&self) -> Interval {
        let current = self.workers.snapshot();
        let mut previous = self.previous.lock().unwrap();
        let old = previous.as_ref().map_or(&[][..], |s| s.actors.as_slice());
        let totals = time_totals(&current.actors, old);
        let cumulative = time_totals(&current.actors, &[]);
        let (observed_ns, worker_fractions) = worker_fractions(totals);
        let count = |state: Stage| {
            current
                .actors
                .iter()
                .filter(|a| a.state == state as usize)
                .count()
        };
        let workers = WorkerInterval {
            observed: current.actors.len(),
            active: current.actors.len() - count(Stage::Inactive) - count(Stage::Parked),
            awaiting_work: count(Stage::AwaitingWork),
            parked: count(Stage::Parked),
            observed_ns,
            fractions: worker_fractions,
            parked_ns: totals[Stage::Parked as usize],
            cumulative_parked_ns: cumulative[Stage::Parked as usize],
            cumulative_fractions: self::worker_fractions(cumulative).1,
        };
        let elapsed_ms = previous
            .as_ref()
            .map_or(0, |p| current.at_ns.saturating_sub(p.at_ns) / 1_000_000);
        let mut process_samples = BTreeMap::new();
        process_samples.insert(current.process.clone(), (0, current.at_ns, current.cpu));
        *previous = Some(current);
        let mut process_baselines = BTreeMap::new();
        let endpoints = self
            .endpoints
            .lock()
            .unwrap()
            .iter_mut()
            .map(|endpoint| {
                let (sample, age, tcp) = match &endpoint.source {
                    EndpointSource::Local(registry) => (Some(registry.snapshot()), Some(0), None),
                    EndpointSource::Remote(sample, socket) => {
                        if let Some(first) = sample.first.lock().unwrap().as_ref() {
                            if let Some(cpu) = first.cpu {
                                let entry = process_baselines
                                    .entry(first.process.clone())
                                    .or_insert((first.at_ns, cpu));
                                if first.at_ns < entry.0 {
                                    *entry = (first.at_ns, cpu);
                                }
                            }
                        }
                        if endpoint.previous.is_none() {
                            endpoint.previous = sample.first.lock().unwrap().clone();
                            endpoint.initial = endpoint.previous.clone();
                        }
                        let latest = sample.latest.lock().unwrap();
                        (
                            latest.as_ref().map(|(_, s)| s.clone()),
                            latest
                                .as_ref()
                                .map(|(at, _)| at.elapsed().as_millis() as u64),
                            socket
                                .as_ref()
                                .and_then(std::sync::Weak::upgrade)
                                .as_deref()
                                .and_then(crate::conn::tcp_socket_stats)
                                .or_else(|| sample.final_tcp.lock().unwrap().clone()),
                        )
                    }
                };
                let tcp_delta = tcp
                    .as_ref()
                    .zip(endpoint.previous_tcp.as_ref())
                    .map(|(a, b)| TcpDelta {
                        bytes_sent: difference(a.bytes_sent, b.bytes_sent),
                        retransmissions: difference(a.retransmissions, b.retransmissions),
                        busy_time_us: difference(a.busy_time_us, b.busy_time_us),
                        receive_window_limited_us: difference(
                            a.receive_window_limited_us,
                            b.receive_window_limited_us,
                        ),
                        send_buffer_limited_us: difference(
                            a.send_buffer_limited_us,
                            b.send_buffer_limited_us,
                        ),
                    });
                if tcp.is_some() {
                    endpoint.previous_tcp = tcp;
                }
                let mut row = EndpointInterval {
                    label: endpoint.label.clone(),
                    sample_age_ms: age,
                    process: sample.as_ref().map(|s| s.process.clone()),
                    elapsed_ms: None,
                    actors: Vec::new(),
                    cumulative_actors: Vec::new(),
                    tcp: endpoint.previous_tcp.clone(),
                    tcp_delta,
                    peer_tcp: sample.as_ref().and_then(|s| s.tcp.clone()),
                    peer_tcp_delta: None,
                };
                if let Some(sample) = sample {
                    if let Some(initial) = endpoint.initial.as_ref() {
                        row.cumulative_actors = operations(&sample, initial);
                    }
                    if sample.process != process_identity() {
                        let entry = process_samples.entry(sample.process.clone()).or_insert((
                            age.unwrap_or(0),
                            sample.at_ns,
                            sample.cpu,
                        ));
                        if sample.at_ns > entry.1 {
                            *entry = (age.unwrap_or(0), sample.at_ns, sample.cpu);
                        }
                    }
                    if endpoint
                        .previous
                        .as_ref()
                        .is_none_or(|p| p.at_ns < sample.at_ns)
                    {
                        // The first remote sample establishes its baseline. It cannot
                        // claim an interval whose start was not observed locally.
                        if let Some(old) = endpoint.previous.as_ref() {
                            row.peer_tcp_delta =
                                sample
                                    .tcp
                                    .as_ref()
                                    .zip(old.tcp.as_ref())
                                    .map(|(a, b)| TcpDelta {
                                        bytes_sent: difference(a.bytes_sent, b.bytes_sent),
                                        retransmissions: difference(
                                            a.retransmissions,
                                            b.retransmissions,
                                        ),
                                        busy_time_us: difference(a.busy_time_us, b.busy_time_us),
                                        receive_window_limited_us: difference(
                                            a.receive_window_limited_us,
                                            b.receive_window_limited_us,
                                        ),
                                        send_buffer_limited_us: difference(
                                            a.send_buffer_limited_us,
                                            b.send_buffer_limited_us,
                                        ),
                                    });
                            row.elapsed_ms =
                                Some(sample.at_ns.saturating_sub(old.at_ns) / 1_000_000);
                            row.actors = operations(&sample, old);
                        }
                        endpoint.previous = Some(sample);
                    }
                }
                row
            })
            .collect();
        let mut previous_cpu = self.processes.lock().unwrap();
        let mut initial_cpu = self.initial_cpu.lock().unwrap();
        for (id, baseline) in process_baselines {
            initial_cpu.entry(id.clone()).or_insert(baseline.1);
            previous_cpu.entry(id).or_insert(baseline);
        }
        let processes = process_samples
            .into_iter()
            .map(|(process, (sample_age_ms, at, cpu))| {
                let old = previous_cpu.get(&process).copied();
                let newer = old.is_none_or(|(then, _)| at > then);
                let row = ProcessInterval {
                    cumulative_cpu: cpu_difference(cpu, initial_cpu.get(&process).copied()),
                    local: process == process_identity(),
                    process: process.clone(),
                    sample_age_ms,
                    elapsed_ms: old
                        .filter(|_| newer)
                        .map(|(then, _)| at.saturating_sub(then) / 1_000_000),
                    cpu: if newer {
                        cpu_difference(cpu, old.map(|(_, cpu)| cpu))
                    } else {
                        None
                    },
                };
                if newer {
                    if let Some(cpu) = cpu {
                        previous_cpu.insert(process, (at, cpu));
                    }
                }
                row
            })
            .collect();
        let mut interval = Interval {
            summary: String::new(),
            elapsed_ms,
            workers,
            processes,
            endpoints,
        };
        interval.summary = interval.format_summary();
        interval
    }
}
fn describe_fractions(fractions: &BTreeMap<&str, f64>) -> String {
    let mut states: Vec<_> = fractions
        .iter()
        .filter(|(_, fraction)| **fraction >= 0.01)
        .collect();
    states.sort_by(|a, b| b.1.total_cmp(a.1).then(a.0.cmp(b.0)));
    states
        .into_iter()
        .map(|(name, fraction)| format!("{} {:.0}%", name.replace('_', " "), fraction * 100.0))
        .collect::<Vec<_>>()
        .join(", ")
}
impl Interval {
    pub(crate) fn summary(&self) -> &str {
        &self.summary
    }
    fn format_summary(&self) -> String {
        let states = describe_fractions(&self.workers.cumulative_fractions);
        let mut lines = vec![format!(
            "Observed worker time: {} ({} {}; parking excluded: {:.3}s; wait states, not proven causes)",
            if states.is_empty() { "no worker activity" } else { &states },
            self.workers.observed,
            if self.workers.observed == 1 { "worker" } else { "workers" },
            self.workers.cumulative_parked_ns as f64 / 1e9,
        )];
        for endpoint in &self.endpoints {
            for actor in &endpoint.cumulative_actors {
                let states = describe_fractions(&actor.fractions);
                let bytes = actor
                    .bytes
                    .iter()
                    .map(|(name, n)| format!("{} {n} bytes", name.replace('_', " ")))
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push(format!(
                    "  {} / {}: {}{}{} (process {}; sample age {}ms)",
                    endpoint.label,
                    actor.role,
                    if states.is_empty() {
                        "no observed operation"
                    } else {
                        &states
                    },
                    if bytes.is_empty() { "" } else { "; " },
                    bytes,
                    endpoint.process.as_deref().unwrap_or("unknown"),
                    endpoint.sample_age_ms.unwrap_or(0)
                ));
            }
        }
        for process in &self.processes {
            if let Some(cpu) = process.cumulative_cpu {
                lines.push(format!(
                    "  Process {}{} CPU: user {:.3}s, system {:.3}s",
                    process.process,
                    if process.local { " (coordinator)" } else { "" },
                    cpu.user_ns as f64 / 1e9,
                    cpu.system_ns as f64 / 1e9
                ));
            }
        }
        lines.join("\n")
    }
}

#[cfg(target_os = "linux")]
fn thread_cpu(tid: u64) -> Option<CpuTimes> {
    static TICKS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let ticks = *TICKS.get_or_init(|| {
        // SAFETY: sysconf takes no pointers; a nonpositive result is unavailable.
        unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(0) as u64
    });
    if ticks == 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    let ns = |index: usize| -> Option<u64> {
        fields
            .get(index)?
            .parse::<u64>()
            .ok()
            .map(|n| n.saturating_mul(1_000_000_000) / ticks)
    };
    Some(CpuTimes {
        user_ns: ns(11)?,
        system_ns: ns(12)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_fractions_exclude_parking_but_include_awaiting_work() {
        let a = Actor::new("worker");
        let b = Actor::new("worker");
        a.transition(Stage::AwaitingWork as u64, 100);
        b.transition(Stage::Parked as u64, 200);
        let totals = time_totals(&[a.snapshot_at(400), b.snapshot_at(400)], &[]);
        let (ns, values) = worker_fractions(totals);
        assert_eq!(ns, 300);
        assert_eq!(values["awaiting_work"], 1.0);
        assert_eq!(totals[Stage::Parked as usize], 200);
        assert!(!values.contains_key("parked"));
        assert!(!values.contains_key("inactive"));
    }
    #[test]
    fn human_fractions_are_sorted_and_hide_negligible_states() {
        let values = BTreeMap::from([
            ("awaiting_work", 0.004),
            ("destination_ack", 0.796),
            ("source_response", 0.2),
        ]);
        assert_eq!(
            describe_fractions(&values),
            "destination ack 80%, source response 20%"
        );
    }
    #[test]
    fn disabled_collection_does_not_record_operations() {
        let registry = Registry::default();
        let actor = registry.actor("worker");
        {
            let reading = actor.span(Stage::SourceRead);
            reading.bytes(42);
        }
        assert_eq!(actor.snapshot().times, [0; STATES]);
        assert_eq!(actor.snapshot().bytes, [0; STATES]);
    }
    #[test]
    fn remote_samples_are_not_repeated_as_new_activity_or_cpu() {
        let observations = Observations::default();
        observations.enable();
        let remote = Arc::new(RemoteSample::default());
        let registry = Registry::default();
        registry.enable();
        let actor = registry.actor("filesystem");
        let mut first = registry.snapshot();
        first.process = "remote-process".into();
        first.at_ns = 100;
        first.cpu = Some(CpuTimes::default());
        remote.update(first.clone());
        observations.remote("source".into(), remote.clone(), None);
        let first_interval = observations.sample();
        assert!(first_interval.endpoints[0].elapsed_ms.is_none());
        actor.transition(Stage::SourceRead as u64, 0);
        let mut next = first;
        next.at_ns = 1_000_100;
        next.cpu = Some(CpuTimes {
            user_ns: 20,
            system_ns: 40,
        });
        next.actors = vec![actor.snapshot_at(1_000_000)];
        remote.update(next);
        let measured = observations.sample();
        assert_eq!(
            measured.endpoints[0].actors[0].fractions["source_read"],
            1.0
        );
        assert_eq!(
            measured
                .processes
                .iter()
                .find(|p| !p.local)
                .unwrap()
                .cpu
                .unwrap()
                .system_ns,
            40
        );
        let stale = observations.sample();
        assert!(stale.endpoints[0].actors.is_empty());
        assert_eq!(
            stale.endpoints[0].cumulative_actors[0].fractions["source_read"],
            1.0
        );
        assert_eq!(
            stale
                .processes
                .iter()
                .find(|p| !p.local)
                .unwrap()
                .cumulative_cpu
                .unwrap()
                .system_ns,
            40
        );
        assert!(stale
            .summary()
            .contains("source / filesystem: source read 100%"));
        assert!(stale.summary().contains("Process remote-process CPU:"));
        assert!(stale.endpoints[0].elapsed_ms.is_none());
        assert!(stale
            .processes
            .iter()
            .find(|p| !p.local)
            .unwrap()
            .cpu
            .is_none());
    }
    #[test]
    fn multiple_connections_do_not_duplicate_process_cpu() {
        let observations = Observations::default();
        observations.enable();
        for label in ["one", "two"] {
            let remote = Arc::new(RemoteSample::default());
            let mut sample = Registry::default().snapshot();
            sample.process = "same-remote-process".into();
            remote.update(sample);
            observations.remote(label.into(), remote, None);
        }
        let sample = observations.sample();
        assert_eq!(sample.endpoints.len(), 2);
        assert_eq!(sample.processes.iter().filter(|p| !p.local).count(), 1);
    }
    #[test]
    fn unfinished_wait_is_visible_and_not_counted_twice() {
        let actor = Actor::new("worker");
        actor.transition(Stage::SourceResponse as u64, 100);
        assert_eq!(
            actor.snapshot_at(400).times[Stage::SourceResponse as usize],
            300
        );
        actor.transition(Stage::Work as u64, 600);
        let sample = actor.snapshot_at(800);
        assert_eq!(sample.times[Stage::SourceResponse as usize], 500);
        assert_eq!(sample.times[Stage::Work as usize], 200);
    }
    #[test]
    fn nested_operation_restores_the_callers_state_on_error() {
        let actor = Actor::new("worker");
        let outer = actor.span(Stage::Work);
        {
            let _inner = actor.span(Stage::SourceRead);
        }
        assert_eq!(actor.snapshot().state, Stage::Work as usize);
        drop(outer);
        assert_eq!(actor.snapshot().state, Stage::Inactive as usize);
    }
}
