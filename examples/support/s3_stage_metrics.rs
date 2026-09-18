//! Opt-in wall-time stage histograms. Thread-local counters avoid hot-path contention.
//! Async durations include suspension, and stages overlap; totals are not CPU time.
use std::{
    cell::RefCell,
    sync::{Mutex, OnceLock},
    time::Instant,
};
const NAMES: [&str; 7] = [
    "read",
    "hash",
    "buffered_write",
    "dispatch",
    "write_completion",
    "queue_send",
    "write_join",
];
#[derive(Clone, Default, serde::Serialize)]
struct Histogram {
    calls: u64,
    bytes: u64,
    nanoseconds: u64,
    max_nanoseconds: u64,
    // Bucket 0: <1us; bucket n>0: [2^(n-1), 2^n) us. Last bucket saturates.
    log2_microseconds: [u64; 32],
}
type Stats = [Histogram; 7];
static TOTAL: OnceLock<Mutex<Stats>> = OnceLock::new();
#[derive(Default)]
struct Local(Stats);
impl Local {
    fn flush(&mut self) {
        let mut total = TOTAL.get_or_init(Default::default).lock().unwrap();
        for (dst, src) in total.iter_mut().zip(std::mem::take(&mut self.0)) {
            dst.calls += src.calls;
            dst.bytes += src.bytes;
            dst.nanoseconds += src.nanoseconds;
            dst.max_nanoseconds = dst.max_nanoseconds.max(src.max_nanoseconds);
            for (a, b) in dst.log2_microseconds.iter_mut().zip(src.log2_microseconds) {
                *a += b;
            }
        }
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        self.flush();
    }
}
thread_local! { static LOCAL: RefCell<Local> = RefCell::default(); }
fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("SYQ_SPIKE_STAGES").as_deref() == Ok("1"))
}
pub fn start() -> Option<Instant> {
    enabled().then(Instant::now)
}
pub fn elapsed(started: Option<Instant>, name: &str, bytes: u64) {
    let Some(started) = started else { return };
    let nanos = started.elapsed().as_nanos() as u64;
    let index = NAMES
        .iter()
        .position(|n| *n == name)
        .expect("unknown diagnostic stage");
    LOCAL.with_borrow_mut(|local| {
        let h = &mut local.0[index];
        h.calls += 1;
        h.bytes += bytes;
        h.nanoseconds += nanos;
        h.max_nanoseconds = h.max_nanoseconds.max(nanos);
        let micros = nanos / 1000;
        let bucket = (64 - micros.leading_zeros() as usize).min(31);
        h.log2_microseconds[bucket] += 1;
    });
}
// Call after every worker is joined/runtime dropped, so thread-local counters flushed.
pub fn snapshot() -> serde_json::Value {
    if !enabled() {
        return serde_json::Value::Null;
    }
    LOCAL.with_borrow_mut(Local::flush);
    let totals = TOTAL.get_or_init(Default::default).lock().unwrap();
    serde_json::to_value(
        NAMES
            .iter()
            .zip(totals.iter())
            .collect::<std::collections::BTreeMap<_, _>>(),
    )
    .unwrap()
}
