//! Derive a starting choice at read time; saved recommendations are not inputs.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

// Original run indexes already partition by eligibility. Older formats remain
// inspectable, but only runs with ordered measurement rows seed new starts.
pub(super) const MEASUREMENTS: i64 = 4;

// Startup looks at up to 64 of the newest matching runs and the last 240
// observations (about two minutes at half-second intervals) of each.
const RUN_LIMIT: usize = 64;
const OBSERVATION_LIMIT: usize = 240;

#[derive(Clone, Copy)]
struct Edge {
    a: usize,
    b: usize,
    diff: f64,
    weight: f64,
}

#[derive(Default)]
struct PooledInference {
    runs: Vec<(i64, f64, Vec<Edge>)>,
    newest_for_count: BTreeMap<usize, i64>,
}

impl PooledInference {
    fn push_run(&mut self, run: i64, decay: f64, evidence: RunEvidence) {
        let edges = evidence.edges();
        if edges.is_empty() {
            return;
        }
        for edge in &edges {
            self.newest_for_count.entry(edge.a).or_insert(run);
            self.newest_for_count.entry(edge.b).or_insert(run);
        }
        self.runs.push((run, decay, edges));
    }

    fn solve(self, specific: bool, default_start: usize) -> Option<Hint> {
        const FLOOR_MARGIN: f64 = 0.03;
        let mut vertices = BTreeSet::new();
        let mut weighted_edges = Vec::new();
        let mut max_weight = 0.0_f64;
        for (rank, (_run, time_decay, edges)) in self.runs.iter().enumerate() {
            let decay = time_decay * 0.85_f64.powi(rank as i32);
            for &edge in edges {
                let w = edge.weight * decay;
                if w <= 0.0 || !w.is_finite() {
                    continue;
                }
                vertices.insert(edge.a);
                vertices.insert(edge.b);
                max_weight = max_weight.max(w);
                weighted_edges.push((edge, w));
            }
        }
        let verts: Vec<usize> = vertices.into_iter().collect();
        let m = verts.len();
        if m < 2 || weighted_edges.is_empty() || max_weight <= 0.0 {
            return None;
        }
        // Weak prior between every adjacent pair of observed worker counts so the
        // linear system stays connected and stale unbridged segments decay naturally.
        let lambda = 0.05 * max_weight;
        let idx = |n: usize| verts.binary_search(&n).unwrap();
        let mut f = vec![0.0f64; m];
        if m <= 128 {
            let d = m - 1;
            let mut a = vec![vec![0.0f64; d]; d];
            let mut b = vec![0.0f64; d];
            let mut add_edge = |i: usize, j: usize, y: f64, w: f64| {
                if i > 0 {
                    a[i - 1][i - 1] += w;
                    b[i - 1] -= w * y;
                }
                if j > 0 {
                    a[j - 1][j - 1] += w;
                    b[j - 1] += w * y;
                }
                if i > 0 && j > 0 {
                    a[i - 1][j - 1] -= w;
                    a[j - 1][i - 1] -= w;
                }
            };
            for &(edge, w) in &weighted_edges {
                add_edge(idx(edge.a), idx(edge.b), edge.diff, w);
            }
            for k in 0..d {
                add_edge(k, k + 1, 0.0, lambda);
            }
            for col in 0..d {
                let mut pivot = col;
                let mut best_val = a[col][col].abs();
                for (r, row) in a.iter().enumerate().skip(col + 1) {
                    if row[col].abs() > best_val {
                        best_val = row[col].abs();
                        pivot = r;
                    }
                }
                if best_val == 0.0 {
                    continue;
                }
                a.swap(col, pivot);
                b.swap(col, pivot);
                let diag = a[col][col];
                for cell in &mut a[col][col..d] {
                    *cell /= diag;
                }
                b[col] /= diag;
                let (before_a, rest_a) = a.split_at_mut(col);
                let (pivot_slice, after_a) = rest_a.split_at_mut(1);
                let pivot_tail = &pivot_slice[0][col..d];
                let (before_b, rest_b) = b.split_at_mut(col);
                let pivot_b = rest_b[0];
                let after_b = &mut rest_b[1..];
                for (row, rhs) in before_a
                    .iter_mut()
                    .zip(before_b.iter_mut())
                    .chain(after_a.iter_mut().zip(after_b.iter_mut()))
                {
                    let factor = row[col];
                    if factor == 0.0 {
                        continue;
                    }
                    for (dst, &src) in row[col..d].iter_mut().zip(pivot_tail) {
                        *dst -= factor * src;
                    }
                    *rhs -= factor * pivot_b;
                }
            }
            f[1..=d].copy_from_slice(&b[..d]);
        } else {
            // Jacobi-preconditioned Conjugate Gradient over a coalesced adjacency list
            // handles >128 distinct counts accurately in O(m + E) per iteration.
            let d = m - 1;
            let mut diag = vec![0.0f64; d];
            let mut b = vec![0.0f64; d];
            let mut adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); d];
            let mut add_edge = |i: usize, j: usize, y: f64, w: f64| {
                if i > 0 {
                    diag[i - 1] += w;
                    b[i - 1] -= w * y;
                }
                if j > 0 {
                    diag[j - 1] += w;
                    b[j - 1] += w * y;
                }
                if i > 0 && j > 0 && i != j {
                    adj[i - 1].push((j - 1, w));
                    adj[j - 1].push((i - 1, w));
                }
            };
            for &(edge, w) in &weighted_edges {
                add_edge(idx(edge.a), idx(edge.b), edge.diff, w);
            }
            for k in 0..d {
                add_edge(k, k + 1, 0.0, lambda);
            }
            for row in &mut adj {
                row.sort_unstable_by_key(|&(nb, _)| nb);
                row.dedup_by(|a, b| {
                    if a.0 == b.0 {
                        b.1 += a.1;
                        true
                    } else {
                        false
                    }
                });
            }
            let mut x = vec![0.0f64; d];
            let b_norm = b.iter().map(|&v| v * v).sum::<f64>().sqrt();
            if b_norm > 0.0 {
                let tol_sq = (1e-10 * b_norm.max(1.0)).powi(2);
                let mut r = b;
                let mut z: Vec<f64> = r
                    .iter()
                    .zip(&diag)
                    .map(|(&ri, &di)| if di > 0.0 { ri / di } else { 0.0 })
                    .collect();
                let mut p = z.clone();
                let mut ap = vec![0.0f64; d];
                let mut rz: f64 = r.iter().zip(&z).map(|(&ri, &zi)| ri * zi).sum();
                let max_iters = d.clamp(200, 4000);
                for _ in 0..max_iters {
                    for (((&d_u, neighbors), &p_u), ap_u) in
                        diag.iter().zip(&adj).zip(&p).zip(&mut ap)
                    {
                        let mut sum = d_u * p_u;
                        for &(nb, w) in neighbors {
                            sum -= w * p[nb];
                        }
                        *ap_u = sum;
                    }
                    let p_ap: f64 = p.iter().zip(&ap).map(|(&pi, &api)| pi * api).sum();
                    if !p_ap.is_finite() || p_ap <= 1e-30 {
                        break;
                    }
                    let alpha = rz / p_ap;
                    let mut r_sq = 0.0;
                    for (((xi, ri), &pi), &api) in x.iter_mut().zip(r.iter_mut()).zip(&p).zip(&ap) {
                        *xi += alpha * pi;
                        *ri -= alpha * api;
                        r_sq += *ri * *ri;
                    }
                    if r_sq <= tol_sq {
                        break;
                    }
                    let mut rz_new = 0.0;
                    for ((zi, &ri), &di) in z.iter_mut().zip(&r).zip(&diag) {
                        *zi = if di > 0.0 { ri / di } else { 0.0 };
                        rz_new += ri * *zi;
                    }
                    if !rz_new.is_finite() || rz == 0.0 {
                        break;
                    }
                    let beta = rz_new / rz;
                    for (pi, &zi) in p.iter_mut().zip(&z) {
                        *pi = zi + beta * *pi;
                    }
                    rz = rz_new;
                }
            }
            f[1..=d].copy_from_slice(&x);
        }
        let floor = default_start.max(verts[0]) as f64;
        let mut best_idx = 0usize;
        let mut best_u = f64::NEG_INFINITY;
        for (k, &n) in verts.iter().enumerate() {
            let nf = n as f64;
            let penalty = if nf >= floor {
                crate::tune::CONCURRENCY_COST * (nf / floor).ln()
            } else {
                FLOOR_MARGIN * (floor / nf).ln()
            };
            let u = f[k] - penalty;
            if u > best_u + 1e-12 {
                best_u = u;
                best_idx = k;
            }
        }
        let workers = verts[best_idx];
        let refine = specific
            && verts.iter().enumerate().any(|(k, &n)| {
                n != workers && (f[k] - f[best_idx]).exp() >= 1.0 - crate::tune::NEAR_BEST_TOLERANCE
            });
        let run = *self
            .newest_for_count
            .get(&workers)
            .or_else(|| self.runs.first().map(|(r, _, _)| r))?;
        Some(Hint {
            run,
            workers,
            matched: if specific { "filesystems" } else { "route" }.into(),
            refine,
        })
    }
}

pub(super) fn starting_count(
    db: &Connection,
    key: &ContextKey,
    allow_route: bool,
    default_start: usize,
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
        let mut statement = db.prepare(&format!(
            "SELECT id,day,(status='success' AND lost=0) FROM runs WHERE route=?1 AND mode=?2
             AND eligible={MEASUREMENTS} {filesystem_match} ORDER BY id DESC LIMIT {RUN_LIMIT}"
        ))?;
        let mut runs = statement.query(params![
            key.route,
            key.mode,
            specific
                .then_some(key.source_filesystem.as_deref())
                .flatten(),
            specific
                .then_some(key.destination_filesystem.as_deref())
                .flatten(),
        ])?;
        // Seek to the beginning of this run's bounded tail, then replay it in
        // sequence order. Older runs remain unread once we have 32 comparisons.
        let mut measurements = db.prepare(&format!(
            "SELECT segment,workers,seconds,rate,usable FROM measurements
             WHERE run=?1 AND sequence>=COALESCE((SELECT sequence FROM measurements
                 WHERE run=?1 ORDER BY sequence DESC LIMIT 1 OFFSET {}),0)
             ORDER BY sequence",
            OBSERVATION_LIMIT - 1
        ))?;
        let mut pooled = PooledInference::default();
        let today = day();
        while let Some(row) = runs.next()? {
            if !row.get::<_, bool>(2)? {
                continue;
            }
            let run: i64 = row.get(0)?;
            let when: i64 = row.get(1)?;
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
            evidence.finish_segment();
            let age = today.saturating_sub(when).max(0) as f64;
            let decay = 2.0_f64.powf(-age / 7.0);
            if decay > 0.0 {
                pooled.push_run(run, decay, evidence);
                if pooled.runs.len() == 32 {
                    break;
                }
            }
        }
        if let Some(hint) = pooled.solve(specific, default_start) {
            return Ok(Some(hint));
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
    counts: BTreeSet<usize>,
    positive: bool,
}

impl Eligibility {
    pub(super) fn push(&mut self, event: &Value) {
        if event["kind"] == "start" {
            self.incompatible |= event["data"]["automatic"] == false
                || event["data"].get("overrides").is_some_and(|v| !v.is_null());
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
        self.consistent && !self.incompatible && self.has_comparison()
    }

    pub(super) fn has_comparison(&self) -> bool {
        self.counts.len() >= 2 && self.positive
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
    segments: Vec<(usize, f64, f64)>,
    current: Option<(i64, usize)>,
    current_rate: Option<f64>,
    reference: f64,
    recent: std::collections::VecDeque<(f64, f64)>,
    total_secs: f64,
    total_activity: f64,
    total_intervals: usize,
}

impl RunEvidence {
    fn finish_segment(&mut self) {
        let Some((_, workers)) = self.current else {
            return;
        };
        if let Some(collapse_rate) = self.severe_loss_rate() {
            // Prioritize a recent severe collapse so a fast prefix does not
            // turn a rolled-back count into a positive historical recommendation.
            self.segments.push((workers, 2.5, collapse_rate));
            self.current_rate = Some(collapse_rate);
        } else if self.total_intervals >= 2
            && self.total_secs >= 2.5 - 1e-6
            && self.total_activity > 0.0
        {
            let mean = self.total_activity / self.total_secs;
            self.segments.push((workers, self.total_secs, mean));
            self.current_rate = Some(mean);
        }
        self.recent.clear();
        self.total_secs = 0.0;
        self.total_activity = 0.0;
        self.total_intervals = 0;
    }

    fn severe_loss_rate(&self) -> Option<f64> {
        let base = self.reference;
        if base <= 0.0 {
            return None;
        }
        let (mut seconds, mut activity, mut low, mut high) = (0.0, 0.0, f64::INFINITY, 0.0_f64);
        for (i, &(rate, elapsed)) in self.recent.iter().rev().enumerate() {
            seconds += elapsed;
            activity += rate * elapsed;
            low = low.min(rate);
            high = high.max(rate);
            if i >= 1 && seconds >= 1.0 - 1e-9 && low > 0.0 && high < base * 0.5 {
                return Some(activity / seconds);
            }
        }
        None
    }

    fn push(&mut self, observation: Observation) {
        let current = (observation.segment, observation.workers);
        if self.current != Some(current) {
            self.finish_segment();
            self.reference = self.current_rate.unwrap_or(0.0);
            self.current_rate = None;
            self.current = Some(current);
        }
        if !observation.valid() {
            // Preserve an already-qualified window before draining/starvation clears it.
            self.finish_segment();
            return;
        }
        self.recent
            .push_back((observation.rate, observation.seconds));
        self.total_secs += observation.seconds;
        self.total_activity += observation.rate * observation.seconds;
        self.total_intervals += 1;
        let mut duration: f64 = self.recent.iter().map(|p| p.1).sum();
        while self.recent.len() > 2 && duration - self.recent[0].1 >= 5.0 {
            duration -= self.recent.pop_front().unwrap().1;
        }
        if self.recent.len() >= 2 && duration >= 2.5 - 1e-6 {
            let rate = self.recent.iter().map(|(r, t)| r * t).sum::<f64>() / duration;
            if rate.is_finite() && rate > 0.0 {
                self.current_rate = Some(rate);
            }
        }
    }

    fn edges(&self) -> Vec<Edge> {
        let mut out = Vec::new();
        for pair in self.segments.windows(2) {
            let (n_a, t_a, r_a) = pair[0];
            let (n_b, t_b, r_b) = pair[1];
            if n_a == n_b || r_a <= 0.0 || r_b <= 0.0 {
                continue;
            }
            let ta = t_a.min(10.0);
            let tb = t_b.min(10.0);
            out.push(Edge {
                a: n_a,
                b: n_b,
                diff: (r_b / r_a).ln(),
                weight: (ta * tb) / (ta + tb),
            });
        }
        out
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
    evidence.finish_segment();
    if !eligibility.reusable() {
        return None;
    }
    let mut pooled = PooledInference::default();
    pooled.push_run(1, 1.0, evidence);
    pooled.solve(true, 1).map(|h| (h.workers, h.refine))
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
        writer.complete(true, json!({}));
        writer
    }

    #[test]
    fn bandwidth_history_never_crosses_caps_or_accounting_modes() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let mut capped = super::super::tests::key("a");
        capped.mode = activity_mode("compress=false;bandwidth=2097152".into(), true);
        let writer = record(&path, &capped, None, true, &[(2, 100.0), (4, 100.0)]);
        assert!(writer.starting_count(&capped, true, 1).is_some());
        for mode in [
            activity_mode("compress=false;bandwidth=0".into(), false),
            activity_mode("compress=false;bandwidth=4194304".into(), true),
            // The same number formerly limited logical file bytes.
            activity_mode("compress=false;bandwidth=2097152".into(), false),
        ] {
            let other = ContextKey {
                mode,
                ..capped.clone()
            };
            assert!(writer.starting_count(&other, true, 1).is_none());
        }
        let uncapped = ContextKey {
            mode: activity_mode("compress=false;bandwidth=0".into(), false),
            ..capped.clone()
        };
        record(&path, &uncapped, None, true, &[(16, 100.0), (32, 200.0)]);
        assert_eq!(
            writer.starting_count(&uncapped, true, 1).unwrap().workers,
            32
        );
        // A newer capped plateau cannot vote down that uncapped starting count.
        record(&path, &capped, None, true, &[(2, 100.0), (4, 100.0)]);
        assert_eq!(
            writer.starting_count(&uncapped, true, 1).unwrap().workers,
            32
        );
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
                    assert_eq!(policy.observe(score.rate), 6);
                    assert_eq!(policy.settled(), 8);
                }
            }
            writer.complete(true, json!({}));
            drop(writer);
            let db = Connection::open(&path).unwrap();
            let saved = command::read_run(&db, 2).unwrap();
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
                next.starting_count(&key, false, 1).unwrap().workers,
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
    fn persisted_transition_splits_windows_without_an_intervening_observation() {
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
        writer.event("transition", json!({}));
        writer.event(
            "observation",
            json!({"active":16,"seconds":0.5,"rate":20.0,"usable":true}),
        );
        writer.complete(true, json!({}));
        assert!(writer.starting_count(&key, false, 1).is_none());
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
        assert!(writer.starting_count(&key, false, 1).is_none());
        assert_eq!(command::read_run(&db, 1).unwrap()["summary"], old);
        let current = record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
        assert_eq!(current.starting_count(&key, false, 1).unwrap().workers, 16);
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
            assert!(single.starting_count(&key, false, 1).is_none());
        }
        let rising = record(&path, &key, Some(8), true, &[(4, 100.0), (8, 200.0)]);
        assert_eq!(rising.starting_count(&key, false, 1).unwrap().workers, 8);
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
            assert_eq!(capped.starting_count(&key, false, 1).unwrap().workers, 16);
        }
        // Newer comparisons showing contention across the previously fast counts
        // step the start down even with an explicit cap of 32: two reversing
        // runs overturn the single 8->16 gain (dropping 16->8), and three
        // overcome the five earlier same-day 4->8 runs under 0.85^rank decay.
        for expected in [8, 4] {
            if expected == 8 {
                record(
                    &path,
                    &key,
                    Some(32),
                    true,
                    &[(4, 200.0), (8, 100.0), (16, 50.0)],
                );
            }
            let below = record(
                &path,
                &key,
                Some(32),
                true,
                &[(4, 200.0), (8, 100.0), (16, 50.0)],
            );
            assert_eq!(
                below.starting_count(&key, false, 1).unwrap().workers,
                expected
            );
        }
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
                assert_eq!(recent.starting_count(&key, false, 1).unwrap().workers, 64);
                let db = Connection::open(&path).unwrap();
                db.execute("UPDATE runs SET day=day-42 WHERE id=1", [])
                    .unwrap();
                // Only the evidence age changed. An old high lower bound must
                // not veto every lower candidate until it leaves the window.
                assert_eq!(
                    recent.starting_count(&key, false, 1).unwrap().workers,
                    8,
                    "old_cap={old_cap:?}, new_cap={new_cap:?}"
                );
                for _ in 0..4 {
                    let more = record(&path, &key, new_cap, true, &[(4, 100.0), (8, 200.0)]);
                    assert_eq!(more.starting_count(&key, false, 1).unwrap().workers, 8);
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
        assert_eq!(fixed.starting_count(&key, false, 1).unwrap().workers, 16);
        let mut route_key = key.clone();
        route_key.destination_filesystem = Some("new filesystem".into());
        assert_eq!(
            fixed.starting_count(&route_key, true, 1).unwrap().workers,
            16
        );
    }

    #[test]
    fn recorded_live_scores_at_one_count_share_the_history_window() {
        use crate::tune::{evidence::Evidence, trace::Trace, Policy, SAMPLE};

        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let writer = super::super::tests::recorder(&path);
        let mut trace = Trace::new(Some(writer.clone()), &Policy::new(8, 1, 16), SAMPLE);
        let mut live = Evidence::default();
        for rate in [100.0; 5].into_iter().chain([110.0; 5]) {
            let score = live.push(rate, 0.5, 0.0);
            trace.observation(
                json!({"active":8,"seconds":0.5,"rate":rate,"usable":true}),
                score.as_ref(),
                None,
            );
            if score.is_some() {
                live.clear();
            }
        }
        writer.complete(true, json!({}));
        let db = Connection::open(path).unwrap();
        let events = command::read_events(&db, 1).unwrap();
        let mut evidence = RunEvidence::default();
        let mut live_scores = Vec::new();
        for event in events {
            if let Some(observation) = Observation::from_event(&event) {
                evidence.push(observation);
            } else if event["kind"] == "sequential_evidence" {
                live_scores.push(event["data"]["score"]["rate"].as_f64().unwrap());
            }
        }
        assert_eq!(live_scores, [100.0, 110.0]);
        assert_eq!(evidence.current_rate, Some(105.0));
    }

    #[test]
    fn long_runs_read_only_the_indexed_tail_of_measurements() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("old.sqlite");
        let key = super::super::tests::key("a");
        let writer = record(&path, &key, None, true, &[(8, 100.0), (16, 200.0)]);
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "DELETE FROM measurements;
            WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i < 50000)
            INSERT INTO measurements SELECT 1,i,i,0,4,0.5,50,1 FROM n;
            INSERT INTO measurements VALUES
                (1,50001,0,1,8,2.5,100,1),(1,50002,0,1,8,2.5,100,1),
                (1,50003,0,2,16,2.5,200,1),(1,50004,0,2,16,2.5,200,1);",
        )
        .unwrap();
        drop(writer);
        let reader = Connection::open(&path).unwrap();
        assert_eq!(
            starting_count(&reader, &key, false, 1)
                .unwrap()
                .unwrap()
                .workers,
            16
        );
        let pages = super::super::tests::pages_read(&reader);
        assert!(pages < 40, "lookup fetched {pages} pages for one run");
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
        writer.complete(true, json!({}));
        let db = Connection::open(path).unwrap();
        // Diagnostic JSON and summaries are not part of the inference query.
        db.execute("DROP TABLE events", []).unwrap();
        assert_eq!(
            starting_count(&db, &key, false, 1)
                .unwrap()
                .unwrap()
                .workers,
            16
        );
        db.execute("UPDATE runs SET summary=?1", [" ".repeat(65537)])
            .unwrap();
        assert_eq!(
            starting_count(&db, &key, false, 1)
                .unwrap()
                .unwrap()
                .workers,
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
        assert_eq!(run["recommendation_eligible"], true);
        assert!(run.get("selected_workers").is_none());
        assert_eq!(writer.starting_count(&key, false, 1).unwrap().workers, 16);
        // Earlier writers used 0 (no evidence), 1 (recommendation), or 2
        // (measurement totals, with bounds added in 3). None is backfilled.
        for old_eligibility in [0, 1, 2, 3] {
            db.execute("UPDATE runs SET eligible=?1", [old_eligibility])
                .unwrap();
            assert!(writer.starting_count(&key, false, 1).is_none());
            let run = command::read_run(&db, 1).unwrap();
            assert_eq!(run["recommendation_eligible"], false);
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
                "automatic":true,"overrides":{"request_size":1024}
            }}),
            observation(4, 50.0, true),
            observation(4, 50.0, true),
            observation(8, 100.0, true),
            observation(8, 100.0, true),
            context(),
        ];
        assert_eq!(infer_run(&events), None);
        events[0]["data"]["overrides"] = Value::Null;
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
            writer.complete(true, json!({}));
        }
        let writer = super::super::tests::recorder(&path);
        writer.context(&key);
        writer.event("learning_context", context()["data"].clone());
        for (n, rate) in [(8, 1000.0), (32, 900.0)] {
            for _ in 0..2 {
                writer.event("observation", observation(n, rate, true)["data"].clone());
            }
        }
        writer.complete(true, json!({}));
        assert_eq!(writer.starting_count(&key, false, 1).unwrap().workers, 32);
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
        writer.complete(true, json!({}));
        let misleading = super::super::tests::recorder(&path);
        misleading.context(&key);
        misleading.complete(true, json!({}));
        // A row as earlier releases saved their recommendation.
        let id = super::super::tests::saved(&misleading);
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE runs SET eligible=1,workers=64,summary='{\"discovery_complete\":true}' WHERE id=?1",
                [id],
            )
            .unwrap();
        assert_eq!(
            misleading.starting_count(&key, false, 1).unwrap().workers,
            16
        );
    }

    #[test]
    fn unusable_tail_observation_preserves_completed_comparison() {
        let mut events = vec![context()];
        for _ in 0..5 {
            events.push(json!({"kind":"observation","data":{"active":8,"seconds":0.5,"rate":100.0,"usable":true}}));
        }
        for _ in 0..5 {
            events.push(json!({"kind":"observation","data":{"active":16,"seconds":0.5,"rate":200.0,"usable":true}}));
        }
        events.push(
            json!({"kind":"observation","data":{"active":16,"seconds":0.5,"rate":0.0,"usable":false}}),
        );
        assert_eq!(infer_run(&events), Some((16, false)));
    }

    #[test]
    fn severe_collapse_suffix_overrides_earlier_fast_samples() {
        let mut events = vec![
            context(),
            observation(8, 100.0, true),
            observation(8, 100.0, true),
        ];
        for rate in [200.0, 200.0, 200.0, 20.0, 20.0] {
            events.push(json!({"kind":"observation","data":{"active":16,"seconds":0.5,"rate":rate,"usable":true}}));
        }
        assert_eq!(infer_run(&events), Some((8, false)));
    }

    #[test]
    fn flat_and_contention_runs_respect_route_default_start_floor() {
        let temp = crate::test_support::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let key = super::super::tests::key("a");
        let flat = record(
            &path,
            &key,
            None,
            true,
            &[(1, 100.0), (2, 100.0), (4, 100.0), (8, 100.0), (16, 100.0)],
        );
        assert_eq!(flat.starting_count(&key, false, 8).unwrap().workers, 8);

        let path2 = temp.path().join("history2.sqlite");
        let contention = record(&path2, &key, None, true, &[(4, 200.0), (8, 100.0)]);
        assert_eq!(
            contention.starting_count(&key, false, 8).unwrap().workers,
            4
        );
    }

    #[test]
    fn sparse_solver_matches_dense_across_128_vertex_boundary() {
        let build_pool = |max_worker: usize| {
            let mut pooled = PooledInference::default();
            for r in 0..32 {
                let lo = 128 + (max_worker - 128) * r / 32;
                let hi = (128 + (max_worker - 128) * (r + 1) / 32 + 1).min(max_worker);
                let mut evidence = RunEvidence::default();
                for n in lo..=hi {
                    for _ in 0..5 {
                        evidence.push(Observation {
                            segment: n as i64,
                            workers: n,
                            seconds: 0.5,
                            rate: n as f64,
                            usable: true,
                        });
                    }
                }
                evidence.finish_segment();
                pooled.push_run(r as i64 + 1, 1.0, evidence);
            }
            pooled
        };
        assert_eq!(build_pool(255).solve(true, 1).unwrap().workers, 255);
        assert_eq!(build_pool(256).solve(true, 1).unwrap().workers, 256);
        assert_eq!(build_pool(383).solve(true, 1).unwrap().workers, 383);
    }
}
