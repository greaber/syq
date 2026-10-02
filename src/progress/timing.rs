//! Wall-clock measurements of work, which can overlap without adding latency.
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Timings {
    pub total_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planning_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalization_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helper_install_ms: Option<u64>,
}

/// Only coarse coordinator work uses these guards. File work shares one start
/// timestamp and an atomic last-completion timestamp, without locking on each file.
#[derive(Default)]
pub struct Measurement(Mutex<Vec<(Instant, Option<Instant>)>>);

pub struct Measuring<'a> {
    measurement: &'a Measurement,
    index: usize,
    excluded: Option<(Instant, Instant)>,
}

impl Measurement {
    pub fn begin(&self) -> Measuring<'_> {
        let mut spans = self.0.lock().unwrap();
        let index = spans.len();
        spans.push((Instant::now(), None));
        Measuring {
            measurement: self,
            index,
            excluded: None,
        }
    }

    pub fn record(&self, span: (Instant, Instant)) {
        self.0.lock().unwrap().push((span.0, Some(span.1)));
    }

    fn spans(&self, start: Instant, end: Instant) -> Vec<(Instant, Instant)> {
        let mut spans: Vec<_> = self
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|&(a, b)| (a.max(start), b.unwrap_or(end).min(end)))
            .filter(|(a, b)| a < b)
            .collect();
        spans.sort_unstable();
        let mut merged: Vec<(Instant, Instant)> = Vec::new();
        for (a, b) in spans {
            if let Some(last) = merged.last_mut().filter(|last| a <= last.1) {
                last.1 = last.1.max(b);
            } else {
                merged.push((a, b));
            }
        }
        merged
    }
}

impl Measuring<'_> {
    /// Exclude an install from this endpoint's setup only. Another endpoint's
    /// connection work can still contribute while that install is running.
    pub fn exclude(mut self, span: Option<(Instant, Instant)>) {
        self.excluded = span;
    }
}

impl Drop for Measuring<'_> {
    fn drop(&mut self) {
        let end = Instant::now();
        let mut spans = self.measurement.0.lock().unwrap();
        let start = spans[self.index].0;
        if let Some((a, b)) = self.excluded.filter(|(a, b)| *a < end && *b > start) {
            spans[self.index].1 = Some(a.max(start));
            if b < end {
                spans.push((b.max(start), Some(end)));
            }
        } else {
            spans[self.index].1 = Some(end);
        }
    }
}

#[derive(Default)]
pub struct Clock {
    pub setup: Measurement,
    pub planning: Measurement,
    pub finalization: Measurement,
    pub helper_install: Measurement,
    end: OnceLock<Instant>,
}

fn duration(spans: &[(Instant, Instant)]) -> Duration {
    spans.iter().map(|(a, b)| b.duration_since(*a)).sum()
}

impl Clock {
    pub fn finish(&self) {
        let _ = self.end.set(Instant::now());
    }

    pub fn snapshot(&self, start: Instant, transfer: Option<Duration>) -> Timings {
        let end = self.end.get().copied().unwrap_or_else(Instant::now);
        let mut timings = Timings {
            total_ms: end.duration_since(start).as_millis() as u64,
            ..Timings::default()
        };
        if let Some(transfer) = transfer {
            let setup = self.setup.spans(start, end);
            let installs = self.helper_install.spans(start, end);
            timings.setup_ms = Some(duration(&setup).as_millis() as u64);
            timings.planning_ms =
                Some(duration(&self.planning.spans(start, end)).as_millis() as u64);
            timings.transfer_ms = Some(transfer.as_millis() as u64);
            timings.finalization_ms =
                Some(duration(&self.finalization.spans(start, end)).as_millis() as u64);
            timings.helper_install_ms = Some(duration(&installs).as_millis() as u64);
        }
        timings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excluding_an_install_preserves_other_endpoints_setup() {
        let origin = Instant::now() - Duration::from_secs(60);
        let clock = Clock::default();
        // Endpoint A: setup 0..40, including install 5..30.
        let endpoint_a = clock.setup.begin();
        clock.setup.0.lock().unwrap()[endpoint_a.index].0 = origin;
        endpoint_a.exclude(Some((
            origin + Duration::from_secs(5),
            origin + Duration::from_secs(30),
        )));
        // Endpoint B spends 10..20 connecting while A installs.
        clock.setup.record((
            origin + Duration::from_secs(10),
            origin + Duration::from_secs(20),
        ));
        clock.helper_install.record((
            origin + Duration::from_secs(5),
            origin + Duration::from_secs(30),
        ));
        clock.end.set(origin + Duration::from_secs(40)).unwrap();
        let timings = clock.snapshot(origin, Some(Duration::ZERO));
        assert_eq!(timings.setup_ms, Some(25_000));
        assert_eq!(timings.helper_install_ms, Some(25_000));
        assert_eq!(timings.total_ms, 40_000);
    }

    #[test]
    fn overlapping_work_and_installations_are_measured_once_and_clipped() {
        let origin = Instant::now() - Duration::from_secs(60);
        let at = |n| origin + Duration::from_secs(n);
        let clock = Clock::default();
        for span in [(at(0), at(5)), (at(15), at(20)), (at(30), at(40))] {
            clock.setup.record(span);
        }
        for span in [(at(5), at(15)), (at(10), at(30)), (at(45), at(55))] {
            clock.helper_install.record(span);
        }
        for span in [(at(18), at(35)), (at(30), at(45))] {
            clock.planning.record(span);
        }
        clock.finalization.record((at(48), at(70)));
        clock.end.set(at(50)).unwrap();
        let measured = clock.snapshot(origin, Some(Duration::from_secs(20)));
        assert_eq!(measured.total_ms, 50_000);
        assert_eq!(measured.setup_ms, Some(20_000));
        assert_eq!(measured.helper_install_ms, Some(30_000));
        assert_eq!(measured.planning_ms, Some(27_000));
        assert_eq!(measured.transfer_ms, Some(20_000));
        assert_eq!(measured.finalization_ms, Some(2_000));
        // A live guard contributes through the snapshot boundary too.
        let live = clock.planning.begin();
        let now = Instant::now();
        let spans = clock.planning.spans(origin, now);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans.last().unwrap().1, now);
        drop(live);
        assert_eq!(clock.snapshot(origin, None).total_ms, 50_000);
    }
}
