//! Observation of the driver's actual inputs and decisions; never feeds policy.
use super::*;
use serde_json::{json, Value};

pub(crate) struct Trace {
    recorder: Option<history::Recorder>,
    sample: u64,
    recent_samples: std::collections::VecDeque<u64>,
    waiting: Option<&'static str>,
    last_work_check: Option<(u64, crate::sched::TuningWork)>,
}

impl Trace {
    pub fn new(recorder: Option<history::Recorder>, policy: &Policy, interval: Duration) -> Self {
        let trace = Self {
            recorder,
            sample: 0,
            recent_samples: Default::default(),
            waiting: None,
            last_work_check: None,
        };
        trace.event("policy_start",json!({"policy_version":POLICY_VERSION,"policy":snapshot(policy),
            "sample_ms":interval.as_millis(),"discarded_intervals_after_reset":1,"stable_within":STABLE_WITHIN,
            "maximum_samples":MAX_SAMPLES,"near_best_tolerance":NEAR_BEST_TOLERANCE,
            "step":STEP,"startup_step":STARTUP_STEP,"file_credit":FILE_CREDIT,"probe_every":PROBE_EVERY,
            "probe_backoff_max":PROBE_BACKOFF_MAX,"evidence_max_age":EVIDENCE_MAX_AGE,
            "clock_unit":"elapsed_sample_intervals","upward_max_wait_ms":interval.as_millis()*12,
            "downward_max_wait_ms":interval.as_millis()*24,"observation_ms":interval.as_millis().min(500),
            "collapse_fraction":0.5,"collapse_samples":2}));
        trace
    }

    pub fn event(&self, kind: &str, data: Value) {
        if let Some(recorder) = &self.recorder {
            recorder.event(kind, data);
        }
    }

    // Keep the observed counters, elapsed time, policy and gate at the call site.
    #[allow(clippy::too_many_arguments)]
    pub fn sample(
        &mut self,
        last: (u64, u64),
        now: (u64, u64),
        seconds: f64,
        policy: &Policy,
        gate: &Gate,
        disposition: &str,
        score: Option<f64>,
    ) {
        if self.recorder.is_none() {
            return;
        }
        self.sample += 1;
        if self.recent_samples.len() == 2 {
            self.recent_samples.pop_front();
        }
        self.recent_samples.push_back(self.sample);
        let (ready, warming, failed) = gate.counts();
        self.event("sample",json!({"sample":self.sample,"seconds":seconds,
            "bytes":now.0.checked_sub(last.0),"files":now.1.checked_sub(last.1),
            "cumulative_bytes":now.0,"cumulative_files":now.1,
            "rate":activity_rate(last,now,seconds),"score":score,"disposition":disposition,
            "active":policy.active(),"requested":policy.n,"ready":ready,"warming":warming,"failed":failed,
            "last_work_check":self.last_work_check}));
    }

    pub fn enough_work(
        &mut self,
        sched: &Sched,
        workers: usize,
        rate: Option<f64>,
        sample: Duration,
    ) -> bool {
        let required = required_remaining_activity(rate, workers, sample);
        if self.recorder.is_none() {
            return sched.work_left_for(workers, required, FILE_CREDIT);
        }
        let evidence = sched.tuning_work(workers, required, FILE_CREDIT);
        self.last_work_check = Some((self.sample, evidence));
        evidence.sufficient
    }

    pub fn observe(&mut self, policy: &mut Policy, score: f64, trigger: &str) {
        let before = self.recorder.as_ref().map(|_| snapshot(policy));
        let old_n = policy.n;
        let comparisons = policy.comparisons;
        let fails = policy.fails;
        policy.observe(score);
        let reason = if comparisons != policy.comparisons {
            if policy.fails != fails && policy.fails.iter().sum::<u32>() > fails.iter().sum::<u32>()
            {
                if policy.n == old_n {
                    "probe_inconclusive"
                } else {
                    "probe_rejected"
                }
            } else {
                "probe_accepted"
            }
        } else if old_n != policy.n {
            "probe_proposed"
        } else {
            "hold"
        };
        self.waiting = None;
        self.event(
            "decision",
            json!({"reason":reason,"trigger":trigger,"score":score,
            "sample_ids":if trigger == "sequential_evidence" { Vec::new() } else {self.recent_samples.iter().copied().collect::<Vec<_>>()},"before":before,"after":snapshot(policy),
            "active":policy.active(),"requested":policy.n}),
        );
    }

    pub fn refresh_baseline(&mut self, policy: &mut Policy, score: f64) {
        let before = self.recorder.as_ref().map(|_| snapshot(policy));
        policy.refresh_warming_baseline(score);
        self.event("baseline_refreshed",json!({"score":score,"sample_ids":self.recent_samples,
            "before":before,"after":snapshot(policy),"active":policy.active(),"requested":policy.n}));
    }

    pub fn waiting(&mut self, reason: &'static str, policy: &Policy) {
        if self.waiting == Some(reason) {
            return;
        }
        self.waiting = Some(reason);
        self.event(
            "waiting",
            json!({"reason":reason,"active":policy.active(),"requested":policy.n,"last_work_check":self.last_work_check}),
        );
    }

    pub fn cancel(
        &mut self,
        policy: &mut Policy,
        reason: &str,
        rate: Option<f64>,
        sample: Duration,
    ) {
        let before = self.recorder.as_ref().map(|_| snapshot(policy));
        let required = required_remaining_activity(rate, policy.n, sample);
        policy.cancel_unapplied();
        self.waiting = None;
        self.event(
            "decision",
            json!({"reason":reason,"before":before,"after":snapshot(policy),
            "active":policy.active(),"requested":policy.n,"observed_rate":rate,
            "minimum_remaining_activity":required,"last_work_check":self.last_work_check}),
        );
    }

    pub fn transition(&mut self, policy: &Policy, reason: &str) {
        self.waiting = None;
        self.recent_samples.clear();
        self.last_work_check = None;
        self.event("transition",json!({"reason":reason,"active":policy.active(),"requested":policy.n,"policy":snapshot(policy)}));
    }

    pub fn end(&self, policy: &Policy, aborted: bool) {
        self.event("policy_end",json!({"active":policy.active(),"requested":policy.n,
            "last_accepted":policy.settled(),"recommended":policy.recommended(),"completed_comparison":policy.measured(),"discovery_complete":policy.discovery_complete(),
            "pending_comparison":matches!(policy.state,State::Explore{..}),"aborted":aborted,"policy":snapshot(policy)}));
        if let Some(recorder) = &self.recorder {
            recorder.flush();
        }
    }
}

fn snapshot(policy: &Policy) -> Value {
    json!({"requested":policy.n,"active":policy.active,"min":policy.min,"max":(policy.max != usize::MAX).then_some(policy.max),
        "recommended":policy.recommended(),"startup_doubling":policy.startup_doubling,"state":policy.state,"points":policy.points,"clock":policy.tick,"wall_clock":policy.wall_clock,
        "comparisons":policy.comparisons,"failed_probes":policy.fails,"next_probe":policy.due,
        "recent_best":policy.recent_best(),"historical_near_best_floor":policy.recent_best()*(1.0-NEAR_BEST_TOLERANCE)})
}
