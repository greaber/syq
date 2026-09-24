//! Derive a starting choice at read time; saved recommendations are not inputs.
use super::*;
use std::collections::BTreeMap;

// Per doubling, as a fraction of total comparison weight. This weak starting
// preference lets negligible old support for more workers fade instead of
// turning a collection of one-sided comparisons into a maximum-ever rule.
const STARTUP_CONNECTION_COST: f64 = 0.01;

// Original run indexes already partition by eligibility. Older formats remain
// inspectable, but only runs with ordered measurement rows seed new starts.
pub(super) const MEASUREMENTS: i64 = 4;

struct Comparison {
    workers: usize,
    refine: bool,
    // The best count was the highest one measured. This is evidence against
    // lower counts, not evidence against untested higher counts.
    lower_bound: bool,
}

impl Comparison {
    fn distance(&self, workers: usize) -> f64 {
        let delta = (workers as f64 / self.workers as f64).log2();
        if self.lower_bound {
            (-delta).max(0.0)
        } else {
            delta.abs()
        }
    }
}

pub(super) fn starting_count(
    db: &Connection,
    key: &ContextKey,
    allow_route: bool,
) -> Result<Option<Hint>> {
    let exact = key.source_filesystem.is_some() && key.destination_filesystem.is_some();
    for specific in [true, false] {
        if (specific && !exact) || (!specific && !allow_route) {
            continue;
        }
        let filesystem_match = if specific {
            "AND source_fs=?3 AND destination_fs=?4"
        } else {
            "AND ?3 IS NULL AND ?4 IS NULL"
        };
        let mut statement = db.prepare(&format!("SELECT id,day FROM runs WHERE route=?1 AND mode=?2 AND eligible={MEASUREMENTS} AND status='success' AND lost=0 {filesystem_match} ORDER BY id DESC"))?;
        let runs = statement.query_map(
            params![
                key.route,
                key.mode,
                if specific {
                    key.source_filesystem.as_deref()
                } else {
                    None
                },
                if specific {
                    key.destination_filesystem.as_deref()
                } else {
                    None
                }
            ],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )?;
        let mut choices = Vec::new();
        let mut measurements = db.prepare(
            "SELECT segment,workers,seconds,rate,usable FROM measurements WHERE run=?1 ORDER BY sequence",
        )?;
        for run in runs {
            let (run, when) = run?;
            let mut evidence = RunEvidence::default();
            let mut rows = measurements.query([run])?;
            while let Some(row) = rows.next()? {
                evidence.push(Observation {
                    segment: row.get(0)?,
                    workers: row.get::<_, u32>(1)? as usize,
                    seconds: row.get(2)?,
                    rate: row.get(3)?,
                    usable: row.get(4)?,
                });
            }
            if let Some(comparison) = evidence.finish() {
                let rank = choices.len();
                let age = day().saturating_sub(when).max(0) as f64;
                let weight = 2.0_f64.powf(-age / 7.0) / (rank + 1) as f64;
                if weight > 0.0 {
                    choices.push((comparison, weight, run));
                    if choices.len() == 32 {
                        break;
                    }
                }
            }
        }
        // Combine within-run preferences, never absolute speeds across runs.
        // An unfinished ramp supplies no evidence against higher candidates.
        // A separate small connection cost prevents arbitrarily weak old bounds
        // from keeping a high start forever in the absence of a measured slowdown.
        // Equal final scores favor the higher start; live exploration can revise it.
        choices.sort_by_key(|c| std::cmp::Reverse(c.0.workers));
        let Some(minimum) = choices.iter().map(|c| c.0.workers).min() else {
            continue;
        };
        let total_weight = choices.iter().map(|c| c.1).sum::<f64>();
        let mut best = None;
        let mut best_loss = f64::INFINITY;
        for (comparison, _, run) in &choices {
            let loss = choices
                .iter()
                .map(|(c, w, _)| w * c.distance(comparison.workers))
                .sum::<f64>()
                + total_weight
                    * STARTUP_CONNECTION_COST
                    * (comparison.workers as f64 / minimum as f64).log2();
            if loss < best_loss {
                best_loss = loss;
                best = Some(Hint {
                    run: *run,
                    workers: comparison.workers,
                    matched: if specific { "filesystems" } else { "route" }.into(),
                    refine: specific && comparison.refine,
                });
            }
        }
        if best.is_some() {
            return Ok(best);
        }
    }
    Ok(None)
}

/// Run facts used to exclude fixed-count, mixed-context and unmeasured runs
/// before the lookup limit. No rates, durations or inferred choices are saved.
#[derive(Default)]
pub(super) struct Eligibility {
    consistent: bool,
    incompatible: bool,
    counts: std::collections::BTreeSet<usize>,
    positive: bool,
}

impl Eligibility {
    pub(super) fn push(&mut self, event: &Value) {
        if event["kind"] == "start" {
            self.incompatible |= event["data"]["automatic"] == false
                || event["data"]
                    .get("overrides")
                    .is_some_and(|v| !v.is_null() && v != "None");
        }
        if event["kind"] == "learning_context" {
            self.consistent =
                event["data"]["consistent"] == true && event["data"]["automatic"] == true;
        }
        if let Some(observation) = Observation::from_event(event) {
            if observation.valid() {
                self.counts.insert(observation.workers);
                self.positive |= observation.rate > 0.0;
            }
        }
    }

    pub(super) fn reusable(&self) -> bool {
        self.consistent && !self.incompatible && self.counts.len() >= 2 && self.positive
    }
}

pub(super) struct Observation {
    pub segment: i64,
    pub workers: usize,
    pub seconds: f64,
    pub rate: f64,
    pub usable: bool,
}

impl Observation {
    pub(super) fn from_event(event: &Value) -> Option<Self> {
        if event["kind"] != "observation" {
            return None;
        }
        let data = &event["data"];
        Some(Self {
            segment: data["segment"].as_i64().unwrap_or(0),
            workers: data["active"].as_u64().filter(|n| *n <= 65536).unwrap_or(0) as usize,
            seconds: data["seconds"]
                .as_f64()
                .filter(|s| s.is_finite())
                .unwrap_or(0.0),
            rate: data["rate"]
                .as_f64()
                .filter(|r| r.is_finite())
                .unwrap_or(-1.0),
            usable: data["usable"] == true,
        })
    }

    fn valid(&self) -> bool {
        self.usable
            && (1..=65536).contains(&self.workers)
            && self.seconds.is_finite()
            && self.seconds > 0.0
            && self.rate.is_finite()
            && self.rate >= 0.0
    }
}

#[derive(Default)]
struct RunEvidence {
    points: BTreeMap<usize, f64>,
    current: Option<(i64, usize)>,
    current_rate: Option<f64>,
    reference: f64,
    recent: crate::tune::evidence::Evidence,
}

impl RunEvidence {
    fn push(&mut self, observation: Observation) {
        let current = (observation.segment, observation.workers);
        if self.current != Some(current) {
            // Compare against the preceding setting, not the fastest rate
            // anywhere in the run. Never join separate visits to a count.
            self.reference = self.current_rate.unwrap_or(0.0);
            self.current_rate = None;
            self.current = Some(current);
            self.recent.clear();
        }
        if !observation.valid() {
            self.recent.clear();
            return;
        }
        let score = self
            .recent
            .push(observation.rate, observation.seconds, self.reference)
            .or_else(|| self.recent.window())
            .filter(|score| score.rate.is_finite() && score.rate >= 0.0);
        if let Some(score) = score {
            self.points.insert(observation.workers, score.rate);
            self.current_rate = Some(score.rate);
        }
    }

    fn finish(self) -> Option<Comparison> {
        let points: Vec<_> = self.points.into_iter().collect();
        // One observed count establishes throughput, not a relative preference.
        if points.len() < 2 {
            return None;
        }
        let best = points.iter().map(|p| p.1).fold(0.0, f64::max);
        if best <= 0.0 {
            return None;
        }
        // A small connection cost breaks flat-rate ties without sacrificing a
        // meaningful speed gain: 0.1% of throughput per doubling. Otherwise flat
        // successive runs would ratchet their starting counts upward forever.
        let minimum = points.first()?.0 as f64;
        let utility = |n: usize, rate: f64| rate / best - 0.001 * (n as f64 / minimum).log2();
        let workers = points
            .iter()
            .max_by(|a, b| utility(a.0, a.1).total_cmp(&utility(b.0, b.1)))?
            .0;
        let refine = points
            .iter()
            .any(|(n, rate)| *n != workers && *rate >= best * 0.95);
        Some(Comparison {
            workers,
            refine,
            lower_bound: workers == points.last()?.0,
        })
    }
}

#[cfg(test)]
fn infer_run(events: &[Value]) -> Option<(usize, bool)> {
    let mut evidence = RunEvidence::default();
    let mut eligibility = Eligibility::default();
    for event in events {
        eligibility.push(event);
        if let Some(observation) = Observation::from_event(event) {
            evidence.push(observation);
        }
    }
    if !eligibility.reusable() {
        return None;
    }
    evidence.finish().map(|c| (c.workers, c.refine))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> Value {
        json!({"kind":"learning_context","data":{"consistent":true,"automatic":true}})
    }

    fn observation(n: usize, rate: f64, usable: bool) -> Value {
        json!({"kind":"observation","data":{"active":n,
            "seconds":2.5,"rate":rate,"usable":usable}})
    }

    fn record(
        path: &Path,
        key: &ContextKey,
        cap: Option<usize>,
        automatic: bool,
        points: &[(usize, f64)],
    ) -> Recorder {
        let writer = super::super::tests::recorder(path);
        writer.context(key);
        writer.event("start", json!({"automatic":automatic,"worker_limit":cap}));
        writer.event("learning_context", context()["data"].clone());
        for &(n, rate) in points {
            for _ in 0..2 {
                writer.event("observation", observation(n, rate, true)["data"].clone());
            }
        }
        writer.finish(true, false, None, json!({}));
        writer
    }

    #[test]
    fn fast_rollback_measurements_change_the_next_start() {
        use crate::tune::{evidence::Evidence, Policy};
        for prefix in [vec![], vec![100.0]] {
            let temp = crate::test_support::tempdir().unwrap();
            let path = temp.path().join("history.sqlite");
            let key = super::super::tests::key("a");
            record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
            let writer = super::super::tests::recorder(&path);
            writer.context(&key);
            writer.event("learning_context", context()["data"].clone());
            for _ in 0..2 {
                writer.event("observation", observation(8, 100.0, true)["data"].clone());
            }
            let mut policy = Policy::new(8, 1, 16);
            assert_eq!(policy.observe(100.0), 16);
            policy.activated();
            let mut evidence = Evidence::default();
            let rates = prefix
                .iter()
                .copied()
                .chain([20.0, 20.0])
                .collect::<Vec<_>>();
            for (i, rate) in rates.iter().copied().enumerate() {
                writer.event(
                    "observation",
                    json!({"active":16,"seconds":0.5,"rate":rate,"usable":true}),
                );
                let score = evidence.push(rate, 0.5, 100.0);
                if i + 1 != rates.len() {
                    assert!(score.is_none());
                } else {
                    let score = score.expect("recent loss warrants an early rollback");
                    assert_eq!(score.seconds, 1.0);
                    assert_eq!(policy.observe(score.rate), 8);
                }
            }
            writer.complete(true, json!({}));
            drop(writer);
            let db = Connection::open(&path).unwrap();
            let saved = command::read_run(&db, 2).unwrap();
            assert_eq!(saved["selected_workers"], Value::Null);
            assert_eq!(saved["summary"]["measurement_totals"], Value::Null);
            let stored = db
                .prepare(
                    "SELECT rate FROM measurements WHERE run=2 AND workers=16 ORDER BY sequence",
                )
                .unwrap()
                .query_map([], |r| r.get::<_, f64>(0))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                stored, rates,
                "store every interval, including the transient"
            );
            let next = super::super::tests::recorder(&path);
            assert_eq!(
                next.starting_count(&key, false).unwrap().workers,
                8,
                "the next copy must retain the window that justified rollback"
            );
        }
    }

    #[test]
    fn ordering_interruptions_and_separate_visits_change_the_evidence() {
        let short = |n, rate, usable| {
            json!({"kind":"observation","data":{
            "active":n,"seconds":0.5,"rate":rate,"usable":usable}})
        };
        let base = vec![
            context(),
            observation(8, 100.0, true),
            observation(8, 100.0, true),
        ];
        for (probe, expected) in [
            (
                vec![
                    short(16, 100.0, true),
                    short(16, 20.0, true),
                    short(16, 20.0, true),
                ],
                Some((8, false)),
            ),
            (
                vec![
                    short(16, 20.0, true),
                    short(16, 100.0, true),
                    short(16, 20.0, true),
                ],
                None,
            ),
            (
                vec![
                    short(16, 20.0, true),
                    short(16, 20.0, false),
                    short(16, 20.0, true),
                ],
                None,
            ),
            (
                vec![
                    short(16, 20.0, true),
                    short(32, 20.0, true),
                    short(16, 20.0, true),
                ],
                None,
            ),
        ] {
            let mut events = base.clone();
            events.extend(probe);
            assert_eq!(infer_run(&events), expected);
        }
        // A later visit to 16 must not inherit its earlier high maximum.
        let mut events = vec![
            context(),
            observation(16, 200.0, true),
            observation(16, 200.0, true),
        ];
        events.extend(base.into_iter().skip(1));
        events.extend([short(16, 20.0, true), short(16, 20.0, true)]);
        assert_eq!(infer_run(&events), Some((8, false)));
    }

    #[test]
    fn persisted_boundaries_split_windows_without_an_intervening_observation() {
        for boundary in ["transition", "sequential_evidence"] {
            let temp = crate::test_support::tempdir().unwrap();
            let path = temp.path().join("history.sqlite");
            let key = super::super::tests::key("a");
            let writer = super::super::tests::recorder(&path);
            writer.context(&key);
            writer.event("learning_context", context()["data"].clone());
            for _ in 0..2 {
                writer.event("observation", observation(8, 100.0, true)["data"].clone());
            }
            writer.event(
                "observation",
                json!({"active":16,"seconds":0.5,"rate":20.0,"usable":true}),
            );
            writer.event(boundary, json!({}));
            writer.event(
                "observation",
                json!({"active":16,"seconds":0.5,"rate":20.0,"usable":true}),
            );
            writer.complete(true, json!({}));
            assert!(
                writer.starting_count(&key, false).is_none(),
                "{boundary} must split the window"
            );
        }
    }

    #[test]
    fn brief_observations_require_consistent_severe_loss() {
        for workers in [4, 16] {
            for (seconds, rates, accepted) in [
                (0.5, vec![20.0, 20.0], true),
                (0.5, vec![49.9, 49.9], true),
                (0.5, vec![50.0, 50.0], false),
                (0.5, vec![20.0, 60.0], false),
                (0.5, vec![0.0, 20.0], false),
                (0.5, vec![0.0, 0.0], false),
                (0.5, vec![200.0, 200.0], false),
                (0.49, vec![20.0, 20.0], false),
                (1.0, vec![20.0], false),
            ] {
                let mut events = vec![
                    context(),
                    observation(8, 100.0, true),
                    observation(8, 100.0, true),
                ];
                for rate in &rates {
                    events.push(json!({"kind":"observation","data":{
                        "active":workers,"seconds":seconds,"rate":rate,"usable":true}}));
                }
                assert_eq!(
                    infer_run(&events),
                    accepted.then_some((8, false)),
                    "workers={workers}, seconds={seconds}, rates={rates:?}"
                );
            }
        }
    }

    #[test]
    fn short_reference_and_unusable_intervals_cannot_establish_severe_loss() {
        let short = |n, rate, usable| {
            json!({"kind":"observation","data":{
            "active":n,"seconds":0.5,"rate":rate,"usable":usable}})
        };
        let mut events = vec![
            context(),
            short(8, 100.0, true),
            short(8, 100.0, true),
            short(16, 20.0, true),
            short(16, 20.0, true),
        ];
        assert_eq!(
            infer_run(&events),
            None,
            "the reference also needs enough exposure"
        );
        events[1] = observation(8, 100.0, true);
        events[2] = observation(8, 100.0, true);
        events[3] = short(16, 20.0, false);
        assert_eq!(infer_run(&events), None, "only one usable loss interval");
        events[3] = short(16, 20.0, true);
        assert_eq!(infer_run(&events), Some((8, false)));
    }

    #[test]
    fn old_measurement_format_is_inspectable_but_not_a_starting_input() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        let writer = record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
        // Unchanged summary representation from #548. No conversion or fallback
        // should turn an unordered summary into ordered measurements.
        let old = json!({"measured_worker_counts":2,"measurement_totals":{
            "observations":{"8":[500.0,5.0,2],"16":[1000.0,5.0,2]},
            "consistent":true,"incompatible":false}});
        let db = Connection::open(&path).unwrap();
        db.execute("UPDATE runs SET eligible=2,summary=?1", [old.to_string()])
            .unwrap();
        assert!(writer.starting_count(&key, false).is_none());
        assert_eq!(command::read_run(&db, 1).unwrap()["summary"], old);
        let current = record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
        assert_eq!(current.starting_count(&key, false).unwrap().workers, 16);
        // The historical recommendation query also excludes the new marker.
        assert_eq!(
            db.query_row("SELECT count(*) FROM runs WHERE eligible=1", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn capped_comparisons_support_lower_bounds_and_winners_below_the_cap() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        for cap in [None, Some(1)] {
            let single = record(&path, &key, cap, true, &[(1, 100.0)]);
            assert!(single.starting_count(&key, false).is_none());
        }
        let rising = record(&path, &key, Some(8), true, &[(4, 100.0), (8, 200.0)]);
        assert_eq!(rising.starting_count(&key, false).unwrap().workers, 8);
        record(
            &path,
            &key,
            None,
            true,
            &[(8, 100.0), (16, 200.0), (32, 150.0)],
        );
        // Newer rising evidence at a lower ceiling does not oppose 16.
        for _ in 0..4 {
            let capped = record(&path, &key, Some(8), true, &[(4, 100.0), (8, 200.0)]);
            assert_eq!(capped.starting_count(&key, false).unwrap().workers, 16);
        }
        // A newer comparison actually showing a slowdown above 4 is different:
        // it can revise the start, even though the run had an explicit cap.
        record(&path, &key, Some(32), true, &[(4, 200.0), (8, 100.0)]);
        let below = record(&path, &key, Some(32), true, &[(4, 200.0), (8, 100.0)]);
        assert_eq!(below.starting_count(&key, false).unwrap().workers, 4);
    }

    #[test]
    fn aging_a_high_lower_bound_allows_recent_lower_starts() {
        for old_cap in [None, Some(64)] {
            for new_cap in [None, Some(8)] {
                let temp = crate::test_support::tempdir().unwrap();
                let path = temp.path().join("history.sqlite");
                let key = super::super::tests::key("a");
                record(&path, &key, old_cap, true, &[(32, 100.0), (64, 200.0)]);
                let recent = record(&path, &key, new_cap, true, &[(4, 100.0), (8, 200.0)]);
                // Fresh evidence at 64 is still valuable even if newer work
                // stopped at 8 without trying higher counts.
                assert_eq!(recent.starting_count(&key, false).unwrap().workers, 64);
                let db = Connection::open(&path).unwrap();
                db.execute("UPDATE runs SET day=day-42 WHERE id=1", [])
                    .unwrap();
                // Only the evidence age changed. An old high lower bound must
                // not veto every lower candidate until it leaves the window.
                assert_eq!(
                    recent.starting_count(&key, false).unwrap().workers,
                    8,
                    "old_cap={old_cap:?}, new_cap={new_cap:?}"
                );
                for _ in 0..4 {
                    let more = record(&path, &key, new_cap, true, &[(4, 100.0), (8, 200.0)]);
                    assert_eq!(more.starting_count(&key, false).unwrap().workers, 8);
                }
            }
        }
    }

    #[test]
    fn exclusions_do_not_consume_the_comparison_window() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
        for i in 0..40 {
            // Fixed-count runs and automatic single-count runs are excluded.
            record(&path, &key, None, i % 2 == 0, &[(1, 100.0)]);
        }
        for _ in 0..40 {
            record(&path, &key, None, true, &[(2, 0.0), (4, 0.0)]);
        }
        // Runs can have multiple measured counts but no qualifying window.
        // They must not displace the older usable comparison either.
        for _ in 0..40 {
            let short = super::super::tests::recorder(&path);
            short.context(&key);
            short.event("learning_context", context()["data"].clone());
            for n in [2, 4] {
                short.event(
                    "observation",
                    json!({"active":n,"seconds":0.5,"rate":100.0,"usable":true}),
                );
            }
            short.complete(true, json!({}));
        }
        let fixed = record(&path, &key, None, false, &[(2, 100.0), (4, 200.0)]);
        assert_eq!(fixed.starting_count(&key, false).unwrap().workers, 16);
        let mut route_key = key.clone();
        route_key.destination_filesystem = Some("new filesystem".into());
        assert_eq!(fixed.starting_count(&route_key, true).unwrap().workers, 16);
    }

    #[test]
    fn startup_reads_measurement_rows_without_parsing_diagnostics() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        let writer = super::super::tests::recorder(&path);
        writer.context(&key);
        writer.event("learning_context", context()["data"].clone());
        for (n, rate) in [(8, 100.0), (16, 200.0)] {
            for _ in 0..2 {
                writer.event("observation", observation(n, rate, true)["data"].clone());
            }
        }
        writer.finish(true, false, None, json!({}));
        let db = Connection::open(path).unwrap();
        // Diagnostic JSON and summaries are not part of the inference query.
        db.execute("DROP TABLE events", []).unwrap();
        assert_eq!(
            starting_count(&db, &key, false).unwrap().unwrap().workers,
            16
        );
        db.execute("UPDATE runs SET summary=?1", [" ".repeat(65537)])
            .unwrap();
        assert_eq!(
            starting_count(&db, &key, false).unwrap().unwrap().workers,
            16
        );
    }

    #[test]
    fn old_summaries_remain_inspectable_without_startup_backfill() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        let writer = record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
        let db = Connection::open(&path).unwrap();
        let run = command::read_run(&db, 1).unwrap();
        assert_eq!(run["recommendation_eligible"], false);
        assert_eq!(run["selected_workers"], Value::Null);
        assert_eq!(writer.starting_count(&key, false).unwrap().workers, 16);
        // Earlier writers used 0 (no evidence), 1 (recommendation), or 2
        // (measurement totals, with bounds added in 3). None is backfilled.
        for old_eligibility in [0, 1, 2, 3] {
            db.execute("UPDATE runs SET eligible=?1", [old_eligibility])
                .unwrap();
            assert!(writer.starting_count(&key, false).is_none());
            let run = command::read_run(&db, 1).unwrap();
            assert_eq!(run["summary"], json!({}));
        }
    }

    #[test]
    fn legacy_samples_do_not_seed_starting_counts() {
        let old = json!({"kind":"sample","data":{"active":16,"ready":16,"failed":0,
            "seconds":2.5,"rate":100.0,"disposition":"stable"}});
        assert_eq!(infer_run(&[context(), old.clone(), old]), None);
    }

    #[test]
    fn explicit_copy_overrides_do_not_seed_ordinary_copies() {
        let mut events = vec![
            json!({"kind":"start","data":{
                "automatic":true,"overrides":"Some(TuningOptions { request_size: Some(1024) })"
            }}),
            observation(4, 50.0, true),
            observation(4, 50.0, true),
            observation(8, 100.0, true),
            observation(8, 100.0, true),
            context(),
        ];
        assert_eq!(infer_run(&events), None);
        events[0]["data"]["overrides"] = json!("None");
        assert_eq!(infer_run(&events), Some((8, false)));
        events[0]["data"]["automatic"] = json!(false);
        assert_eq!(infer_run(&events), None);
    }

    #[test]
    fn flat_measurements_do_not_ratchet_starting_counts_upward() {
        let events = vec![
            context(),
            observation(8, 100.0, true),
            observation(8, 100.0, true),
            observation(16, 100.0, true),
            observation(16, 100.0, true),
        ];
        assert_eq!(infer_run(&events), Some((8, true)));
    }

    #[test]
    fn observations_learn_rising_gain_without_a_saved_recommendation() {
        let events = vec![
            context(),
            observation(8, 100.0, true),
            observation(8, 100.0, true),
            observation(16, 125.0, true),
            observation(16, 156.25, true),
            observation(16, 195.3125, true),
        ];
        assert_eq!(infer_run(&events), Some((16, false)));
    }

    #[test]
    fn work_limited_and_setup_intervals_do_not_establish_a_winner() {
        let mut events = vec![
            context(),
            observation(4, 50.0, true),
            observation(4, 50.0, true),
            observation(8, 100.0, true),
            observation(8, 100.0, true),
        ];
        for _ in 0..3 {
            let mut e = observation(16, 200.0, true);
            e["data"]["usable"] = json!(false);
            events.push(e);
            events.push(observation(32, 400.0, false));
        }
        assert_eq!(infer_run(&events), Some((8, false)));
    }

    #[test]
    fn new_observations_require_a_consistent_context_and_enough_duration() {
        let mut events = vec![
            json!({"kind":"observation","data":{
            "active":16,"seconds":0.5,"rate":200.0,"usable":true}});
            6
        ];
        events.extend([observation(8, 100.0, true), observation(8, 100.0, true)]);
        assert_eq!(infer_run(&events), None);
        events.push(json!({"kind":"learning_context","data":{"consistent":true,"automatic":true}}));
        assert_eq!(infer_run(&events), Some((16, false)));
        for e in events.iter_mut().take(4) {
            e["data"]["usable"] = json!(false);
        }
        assert_eq!(infer_run(&events), None);
    }

    #[test]
    fn conflicting_runs_use_relative_evidence_and_more_than_the_newest_run() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        for scale in [1.0, 10.0, 100.0] {
            let writer = super::super::tests::recorder(&path);
            writer.context(&key);
            writer.event("learning_context", context()["data"].clone());
            for (n, rate) in [(8, scale), (32, scale * 2.0)] {
                for _ in 0..2 {
                    writer.event("observation", observation(n, rate, true)["data"].clone());
                }
            }
            writer.finish(true, false, None, json!({}));
        }
        let writer = super::super::tests::recorder(&path);
        writer.context(&key);
        writer.event("learning_context", context()["data"].clone());
        for (n, rate) in [(8, 1000.0), (32, 900.0)] {
            for _ in 0..2 {
                writer.event("observation", observation(n, rate, true)["data"].clone());
            }
        }
        writer.finish(true, false, None, json!({}));
        assert_eq!(writer.starting_count(&key, false).unwrap().workers, 32);
    }

    #[test]
    fn saved_decisions_are_not_used_and_short_runs_can_supply_evidence() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        let writer = super::super::tests::recorder(&path);
        writer.context(&key);
        writer.event("learning_context", context()["data"].clone());
        for n in [8, 16] {
            for _ in 0..2 {
                let e = observation(n, n as f64, true);
                writer.event("observation", e["data"].clone());
            }
        }
        writer.finish(true, false, None, json!({}));
        let misleading = super::super::tests::recorder(&path);
        misleading.context(&key);
        misleading.finish(true, true, Some(64), json!({"discovery_complete":true}));
        assert_eq!(misleading.starting_count(&key, false).unwrap().workers, 16);
    }
}
