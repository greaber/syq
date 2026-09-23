//! Derive a starting choice at read time; saved recommendations are not inputs.
use super::*;
use std::collections::BTreeMap;

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
        let mut statement = db.prepare("SELECT id,day,CASE WHEN length(CAST(summary AS BLOB))<=65536 THEN summary END FROM runs WHERE route=?1 AND mode=?2 AND status='success' AND lost=0 AND (?3=0 OR (source_fs=?4 AND destination_fs=?5)) ORDER BY id DESC LIMIT 32")?;
        let runs = statement
            .query_map(
                params![
                    key.route,
                    key.mode,
                    specific,
                    key.source_filesystem,
                    key.destination_filesystem
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
            if let Some((workers, refine)) = evidence.finish() {
                let age = day().saturating_sub(when).max(0) as f64;
                let weight = 2.0_f64.powf(-age / 7.0) / (rank + 1) as f64;
                if weight > 0.0 {
                    choices.push((workers, weight, run, refine));
                }
            }
        }
        // Each transfer contributes once; a long run's correlated intervals do
        // not outvote multiple independent runs. Compare relative rates within
        // each run, never absolute throughput across different conditions.
        choices.sort_by_key(|c| c.0);
        let half = choices.iter().map(|c| c.1).sum::<f64>() * 0.5;
        let mut cumulative = 0.0;
        for (workers, weight, run, refine) in choices {
            cumulative += weight;
            if cumulative > half {
                return Ok(Some(Hint {
                    run,
                    workers,
                    matched: if specific { "filesystems" } else { "route" }.into(),
                    refine: specific && refine,
                }));
            }
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
                || !event["data"]["worker_limit"].is_null()
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

    fn finish(self) -> Option<(usize, bool)> {
        if self.incompatible || !self.consistent {
            return None;
        }
        let points: Vec<_> = self
            .observations
            .into_iter()
            .filter(|(n, (_, seconds, count))| {
                (1..=65536).contains(n) && seconds.is_finite() && *seconds >= 2.5 && *count >= 2
            })
            .map(|(n, (activity, seconds, _))| (n, activity / seconds))
            .filter(|(_, rate)| rate.is_finite())
            .collect();
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
        Some((workers, refine))
    }
}

#[cfg(test)]
fn infer_run(events: &[Value]) -> Option<(usize, bool)> {
    let mut evidence = RunEvidence::default();
    for event in events {
        evidence.push(event);
    }
    evidence.finish()
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

    #[test]
    fn worker_capped_runs_cannot_displace_unrestricted_comparisons() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        let record = |cap: Option<usize>, points: &[(usize, f64)]| {
            let writer = super::super::tests::recorder(&path);
            writer.context(&key);
            writer.event("start", json!({"automatic":true,"worker_limit":cap}));
            writer.event("learning_context", context()["data"].clone());
            for &(n, rate) in points {
                for _ in 0..2 {
                    writer.event("observation", observation(n, rate, true)["data"].clone());
                }
            }
            writer.finish(true, false, None, json!({}));
            writer
        };
        let capped_only = record(Some(1), &[(1, 100.0)]);
        assert!(capped_only.starting_count(&key, false).is_none());
        record(None, &[(8, 100.0), (16, 200.0)]);
        for (cap, points) in [(1, vec![(1, 100.0)]), (8, vec![(4, 100.0), (8, 200.0)])] {
            let capped = record(Some(cap), &points);
            assert_eq!(capped.starting_count(&key, false).unwrap().workers, 16);
        }
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
