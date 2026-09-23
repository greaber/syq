//! Derive a starting choice at read time; saved recommendations are not inputs.
use super::*;
use std::collections::BTreeMap;

// Shared by the partial indexes and lookup: filtering precedes the run limit.
// CASE also keeps malformed/oversized diagnostic summaries out of JSON parsing.
pub(super) const MATCHABLE: &str = "status='success' AND lost=0 AND CASE WHEN length(CAST(summary AS BLOB))<=65536 AND json_valid(summary) THEN json_extract(summary,'$.measurement_totals.consistent')=1 AND json_extract(summary,'$.measurement_totals.incompatible')=0 AND json_extract(summary,'$.measured_worker_counts')>=2 ELSE 0 END";

pub(super) fn index(db: &Connection) -> Result<()> {
    db.execute_batch(&format!("CREATE INDEX IF NOT EXISTS measured_filesystems ON runs(route,mode,source_fs,destination_fs,id DESC) WHERE {MATCHABLE};
        CREATE INDEX IF NOT EXISTS measured_routes ON runs(route,mode,id DESC) WHERE {MATCHABLE};"))?;
    Ok(())
}

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
        let mut statement = db.prepare(&format!("SELECT id,day,summary FROM runs WHERE route=?1 AND mode=?2 AND {MATCHABLE} {filesystem_match} ORDER BY id DESC LIMIT 32"))?;
        let runs = statement
            .query_map(
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
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut choices = Vec::new();
        for (rank, (run, when, summary)) in runs.into_iter().enumerate() {
            let evidence = summary
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|s| {
                    serde_json::from_value::<RunEvidence>(s["measurement_totals"].clone()).ok()
                });
            let Some(evidence) = evidence else {
                continue;
            };
            if let Some(comparison) = evidence.finish() {
                let age = day().saturating_sub(when).max(0) as f64;
                let weight = 2.0_f64.powf(-age / 7.0) / (rank + 1) as f64;
                if weight > 0.0 {
                    choices.push((comparison, weight, run));
                }
            }
        }
        // Combine within-run preferences, never absolute speeds across runs.
        // A rising ceiling imposes no penalty on higher candidates: many capped
        // runs therefore cannot drag a better-supported higher start downward.
        // Equal evidence favors the higher start; live exploration can revise it.
        choices.sort_by_key(|c| std::cmp::Reverse(c.0.workers));
        let mut best = None;
        let mut best_loss = f64::INFINITY;
        for (comparison, _, run) in &choices {
            let loss = choices
                .iter()
                .map(|(c, w, _)| w * c.distance(comparison.workers))
                .sum::<f64>();
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

#[derive(Default, Serialize, Deserialize)]
pub(super) struct RunEvidence {
    // Worker count -> (total activity, observed seconds, interval count).
    // Persist measurements, never a selected starting count or a utility score.
    observations: BTreeMap<usize, (f64, f64, usize)>,
    consistent: bool,
    incompatible: bool,
}

impl RunEvidence {
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
        if event["kind"] != "observation" {
            return;
        }
        let data = &event["data"];
        let Some(n) = data["active"].as_u64().filter(|n| *n > 0 && *n <= 65536) else {
            return;
        };
        if data["usable"] != true {
            return;
        }
        let Some(seconds) = data["seconds"]
            .as_f64()
            .filter(|v| v.is_finite() && *v > 0.0)
        else {
            return;
        };
        let Some(rate) = data["rate"].as_f64().filter(|v| v.is_finite() && *v >= 0.0) else {
            return;
        };
        let point = self.observations.entry(n as usize).or_default();
        point.0 += rate * seconds;
        point.1 += seconds;
        point.2 += 1;
    }

    fn points(&self) -> impl Iterator<Item = (usize, f64)> + '_ {
        self.observations
            .iter()
            .filter(|(n, (_, seconds, count))| {
                (1..=65536).contains(*n) && seconds.is_finite() && *seconds >= 2.5 && *count >= 2
            })
            .map(|(n, (activity, seconds, _))| (*n, activity / seconds))
            .filter(|(_, rate)| rate.is_finite() && *rate >= 0.0)
    }

    pub(super) fn measured_counts(&self) -> usize {
        self.points().count()
    }

    fn finish(self) -> Option<Comparison> {
        if self.incompatible || !self.consistent {
            return None;
        }
        let points: Vec<_> = self.points().collect();
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
    for event in events {
        evidence.push(event);
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
    fn exclusions_do_not_consume_the_comparison_window() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
        for i in 0..40 {
            // Fixed-count runs and automatic single-count runs are excluded.
            record(&path, &key, None, i % 2 == 0, &[(1, 100.0)]);
        }
        let fixed = record(&path, &key, None, false, &[(2, 100.0), (4, 200.0)]);
        assert_eq!(fixed.starting_count(&key, false).unwrap().workers, 16);
        let mut route_key = key.clone();
        route_key.destination_filesystem = Some("new filesystem".into());
        assert_eq!(fixed.starting_count(&route_key, true).unwrap().workers, 16);
    }

    #[test]
    fn startup_reads_bounded_summaries_without_reading_timelines() {
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
        // Lookup must work even with no timeline table: its size cannot affect
        // the amount of event data fetched or parsed at startup.
        db.execute("DROP TABLE events", []).unwrap();
        assert_eq!(
            starting_count(&db, &key, false).unwrap().unwrap().workers,
            16
        );
        db.execute("UPDATE runs SET summary=?1", [" ".repeat(65537)])
            .unwrap();
        assert!(starting_count(&db, &key, false).unwrap().is_none());
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
            observation(8, 100.0, true),
            observation(4, 50.0, true),
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
