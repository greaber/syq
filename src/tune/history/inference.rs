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
        let mut statement = db.prepare("SELECT id,day FROM runs WHERE route=?1 AND mode=?2 AND status='success' AND lost=0 AND (?3=0 OR (source_fs=?4 AND destination_fs=?5)) ORDER BY id DESC LIMIT 32")?;
        let runs = statement
            .query_map(
                params![
                    key.route,
                    key.mode,
                    specific,
                    key.source_filesystem,
                    key.destination_filesystem
                ],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut choices = Vec::new();
        for (rank, (run, when)) in runs.into_iter().enumerate() {
            let mut events =
                db.prepare("SELECT data FROM events WHERE run=?1 ORDER BY sequence")?;
            let records = events.query_map([run], |r| r.get::<_, String>(0))?;
            let mut evidence = RunEvidence::default();
            for record in records {
                if let Ok(event) = serde_json::from_str::<Value>(&record?) {
                    evidence.push(&event);
                }
            }
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

#[derive(Default)]
struct RunEvidence {
    legacy: BTreeMap<usize, (f64, f64, usize)>,
    observations: BTreeMap<usize, (f64, f64, usize)>,
    modern: bool,
    consistent: bool,
}

impl RunEvidence {
    fn push(&mut self, event: &Value) {
        if event["kind"] == "learning_context" {
            self.consistent = event["data"]["consistent"] == true;
        }
        let modern = event["kind"] == "observation";
        if !modern && event["kind"] != "sample" {
            return;
        }
        self.modern |= modern;
        let points = if modern {
            &mut self.observations
        } else {
            &mut self.legacy
        };
        let data = &event["data"];
        let Some(n) = data["active"].as_u64().filter(|n| *n > 0 && *n <= 65536) else {
            return;
        };
        if modern {
            if data["usable"] != true {
                return;
            }
        } else {
            if data["ready"].as_u64().unwrap_or(0) < n || data["failed"].as_u64().unwrap_or(0) != 0
            {
                return;
            }
            if !matches!(
                data["disposition"].as_str(),
                Some(
                    "stable"
                        | "collecting"
                        | "sample_limit"
                        | "warmup_excluded"
                        | "insufficient_remaining_work"
                        | "collapse_guard"
                )
            ) {
                return;
            }
            // Old tail records can still be useful, but don't credit an
            // interval ending with demonstrated insufficient parallel work.
            if data["last_work_check"][1]["parallel"] == false {
                return;
            }
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
        let point = points.entry(n as usize).or_default();
        point.0 += rate * seconds;
        point.1 += seconds;
        point.2 += 1;
    }

    fn finish(self) -> Option<(usize, bool)> {
        if self.modern && !self.consistent {
            return None;
        }
        let points = if self.modern {
            self.observations
        } else {
            self.legacy
        };

        let points: Vec<_> = points
            .into_iter()
            .filter(|(_, (_, seconds, count))| *seconds >= 2.5 && *count >= 2)
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

    fn sample(n: usize, rate: f64, disposition: &str) -> Value {
        json!({"kind":"sample","data":{"active":n,"ready":n,"failed":0,
            "seconds":2.5,"rate":rate,"disposition":disposition}})
    }

    #[test]
    fn flat_measurements_do_not_ratchet_starting_counts_upward() {
        let events = vec![
            sample(8, 100.0, "stable"),
            sample(8, 100.0, "stable"),
            sample(16, 100.0, "stable"),
            sample(16, 100.0, "stable"),
        ];
        assert_eq!(infer_run(&events), Some((8, true)));
    }

    #[test]
    fn released_samples_learn_rising_gain_without_a_saved_recommendation() {
        let events = vec![
            sample(8, 100.0, "collecting"),
            sample(8, 100.0, "stable"),
            sample(16, 125.0, "insufficient_remaining_work"),
            sample(16, 156.25, "insufficient_remaining_work"),
            sample(16, 195.3125, "insufficient_remaining_work"),
        ];
        assert_eq!(infer_run(&events), Some((16, false)));
    }

    #[test]
    fn work_limited_and_setup_intervals_do_not_establish_a_winner() {
        let mut events = vec![sample(8, 100.0, "collecting"), sample(8, 100.0, "stable")];
        for _ in 0..3 {
            let mut e = sample(16, 200.0, "insufficient_remaining_work");
            e["data"]["last_work_check"] = json!([0,{"parallel":false}]);
            events.push(e);
            events.push(sample(32, 400.0, "active_workers_connecting"));
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
        events.push(json!({"kind":"learning_context","data":{"consistent":true}}));
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
            for (n, rate) in [(8, scale), (32, scale * 2.0)] {
                for _ in 0..2 {
                    writer.event("sample", sample(n, rate, "stable")["data"].clone());
                }
            }
            writer.finish(true, false, None, json!({}));
        }
        let writer = super::super::tests::recorder(&path);
        writer.context(&key);
        for (n, rate) in [(8, 1000.0), (32, 900.0)] {
            for _ in 0..2 {
                writer.event("sample", sample(n, rate, "stable")["data"].clone());
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
        for n in [8, 16] {
            for _ in 0..2 {
                let e = sample(n, n as f64, "insufficient_remaining_work");
                writer.event("sample", e["data"].clone());
            }
        }
        writer.finish(true, false, None, json!({}));
        let misleading = super::super::tests::recorder(&path);
        misleading.context(&key);
        misleading.finish(true, true, Some(64), json!({"discovery_complete":true}));
        assert_eq!(misleading.starting_count(&key, false).unwrap().workers, 16);
    }
}
