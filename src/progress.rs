//! Progress display: one status line plus one line per active worker.

use std::collections::VecDeque;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct WorkerStatus {
    pub path: String,
    pub done: Arc<AtomicU64>,
    pub total: u64,
}

pub struct Progress {
    pub enabled: bool,
    pub json: bool,
    pub width: Option<usize>,
    /// Removal mode: header counts entries instead of bytes.
    pub rm: bool,
    pub bytes_total: AtomicU64,
    pub bytes_done: AtomicU64,
    /// Monotonic high-water mark of logical completion. Recovery may roll
    /// `bytes_done` back, but retransmitting the same range is not fresh useful
    /// throughput and cannot advance this meter until progress passes the mark.
    tuning_high_water: AtomicU64,
    pub bytes_unchanged: AtomicU64,
    pub files_total: AtomicU64,
    pub files_done: AtomicU64,
    pub files_unchanged: AtomicU64,
    /// Source files deliberately not transferred (-u, size limits, --existing,
    /// symlinks without -l, ...); neither "transferred" nor "unchanged".
    pub files_excluded: AtomicU64,
    /// Source paths matched by ignore rules during a dry run. An ignored
    /// directory is one path here even though its unscanned subtree may
    /// contain many entries.
    pub paths_ignored: AtomicU64,
    pub scanned: AtomicU64,
    pub scan_done: AtomicBool,
    pub errors: AtomicU64,
    /// --prune bookkeeping mirrored here so the fatal-error terminal record
    /// can report what the deletion pass did before the run died.
    pub deletions_planned: AtomicU64,
    pub deletions_completed: AtomicU64,
    pub deletions_blocked: AtomicU64,
    /// Settled creations, mirrored here (like the deletion counters) so a
    /// fatal-error terminal record reports what the run actually did.
    pub directories_created: AtomicU64,
    pub symlinks_created: AtomicU64,
    pub specials_created: AtomicU64,
    /// Workers currently allowed to take work (0 = fixed -j, not shown).
    pub active_workers: AtomicU64,
    pub start: Instant,
    workers: Mutex<Vec<Option<WorkerStatus>>>,
    term: Mutex<TermState>,
    stop: AtomicBool,
    /// `--results`: machine-readable NDJSON outcome stream, set once after
    /// construction so workers and the planner reach it with no plumbing.
    results: std::sync::OnceLock<Arc<crate::results::ResultsWriter>>,
    result_destination: std::sync::OnceLock<usize>,
    fanout_group: std::sync::OnceLock<std::sync::Weak<crate::fanout::Group>>,
}

struct TermState {
    lines_drawn: usize,
    samples: VecDeque<(Instant, u64)>,
    last_json: Option<Instant>,
    last_results: Option<Instant>,
}

pub(crate) struct ProgressSnapshot {
    bytes_done: u64,
    bytes_total: u64,
    bytes_unchanged: u64,
    files_done: u64,
    files_total: u64,
    files_unchanged: u64,
    files_excluded: u64,
    scanned: u64,
    scan_done: bool,
    rate: f64,
    eta: Option<f64>,
    elapsed: Duration,
    active_workers: u64,
    rm: bool,
}

impl ProgressSnapshot {
    pub(crate) fn result_record(
        &self,
        destination_index: Option<usize>,
    ) -> crate::results::ProgressRecord {
        crate::results::ProgressRecord {
            destination_index,
            bytes_done: self.bytes_done,
            bytes_total: self.bytes_total,
            bytes_unchanged: self.bytes_unchanged,
            files_done: self.files_done,
            files_total: self.files_total,
            files_unchanged: self.files_unchanged,
            files_excluded: self.files_excluded,
            scanned: self.scanned,
            scan_done: self.scan_done,
            elapsed_ms: self.elapsed.as_millis() as u64,
        }
    }
}

impl Progress {
    pub fn new(
        n_workers: usize,
        enabled: bool,
        force: bool,
        width: Option<usize>,
        json: bool,
    ) -> Arc<Self> {
        Arc::new(Progress {
            enabled: enabled && (force || std::io::stderr().is_terminal()),
            json,
            width,
            rm: false,
            bytes_total: AtomicU64::new(0),
            bytes_done: AtomicU64::new(0),
            tuning_high_water: AtomicU64::new(0),
            bytes_unchanged: AtomicU64::new(0),
            files_total: AtomicU64::new(0),
            files_done: AtomicU64::new(0),
            files_unchanged: AtomicU64::new(0),
            files_excluded: AtomicU64::new(0),
            paths_ignored: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            scan_done: AtomicBool::new(false),
            errors: AtomicU64::new(0),
            deletions_planned: AtomicU64::new(0),
            deletions_completed: AtomicU64::new(0),
            deletions_blocked: AtomicU64::new(0),
            directories_created: AtomicU64::new(0),
            symlinks_created: AtomicU64::new(0),
            specials_created: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            start: Instant::now(),
            workers: Mutex::new(vec![None; n_workers]),
            term: Mutex::new(TermState {
                lines_drawn: 0,
                samples: VecDeque::new(),
                last_json: None,
                last_results: None,
            }),
            stop: AtomicBool::new(false),
            results: std::sync::OnceLock::new(),
            result_destination: std::sync::OnceLock::new(),
            fanout_group: std::sync::OnceLock::new(),
        })
    }

    pub fn set_results(&self, writer: Arc<crate::results::ResultsWriter>) {
        let _ = self.results.set(writer);
    }

    pub fn results_writer(&self) -> Option<&Arc<crate::results::ResultsWriter>> {
        self.results.get()
    }

    pub fn set_result_destination(&self, index: usize) {
        let _ = self.result_destination.set(index);
    }

    pub fn set_fanout_group(&self, group: &Arc<crate::fanout::Group>) {
        let _ = self.fanout_group.set(Arc::downgrade(group));
    }

    pub fn result_destination(&self) -> Option<usize> {
        self.result_destination.get().copied()
    }

    pub(crate) fn failed_result(
        &self,
        dry_run: bool,
        prune: bool,
        extra_errors: u64,
    ) -> crate::results::ResultRecord {
        crate::results::ResultRecord {
            status: "failed",
            exit_code: 1,
            dry_run,
            files_transferred: self.files_done.load(Relaxed),
            files_unchanged: self.files_unchanged.load(Relaxed),
            files_excluded: self.files_excluded.load(Relaxed),
            directories_created: self.directories_created.load(Relaxed),
            symlinks_created: self.symlinks_created.load(Relaxed),
            specials_created: self.specials_created.load(Relaxed),
            errors: self.errors.load(Relaxed).saturating_add(extra_errors),
            bytes_transferred: self.bytes_done.load(Relaxed),
            bytes_unchanged: self.bytes_unchanged.load(Relaxed),
            elapsed_ms: self.start.elapsed().as_millis() as u64,
            deletions_planned: prune.then(|| self.deletions_planned.load(Relaxed)),
            deletions_completed: prune.then(|| self.deletions_completed.load(Relaxed)),
            deletions_blocked: prune.then(|| self.deletions_blocked.load(Relaxed)),
        }
    }

    pub fn set_worker(&self, id: usize, s: Option<WorkerStatus>) {
        let mut w = self.workers.lock().unwrap();
        if id >= w.len() {
            w.resize(id + 1, None);
        }
        w[id] = s;
    }

    pub fn add_bytes(&self, n: u64) {
        let done = self.bytes_done.fetch_add(n, Relaxed).saturating_add(n);
        self.tuning_high_water.fetch_max(done, Relaxed);
    }

    /// Print a line to stdout, keeping the progress area intact.
    pub fn println(&self, line: &str) {
        let group = self.fanout_group.get().and_then(std::sync::Weak::upgrade);
        let mut group_output = group.as_ref().map(|group| group.lock_human_output());
        let mut term = Some(self.term.lock().unwrap());
        self.erase(term.as_mut().unwrap());
        // A redirected stdout cannot disturb the terminal display. Let the
        // ticker keep running while a slow pipe blocks this printing worker.
        if !std::io::stdout().is_terminal() {
            drop(term.take());
            drop(group_output.take());
        }
        let result = {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{line}").and_then(|()| out.flush())
        };
        drop(term);
        if let Err(error) = result {
            crate::output::warn_stdout(&error);
        }
    }

    /// Print a line to stderr (errors and warnings), keeping the progress area intact.
    pub fn eprintln(&self, line: &str) {
        let group = self.fanout_group.get().and_then(std::sync::Weak::upgrade);
        let _group_output = group.as_ref().map(|group| group.lock_human_output());
        let mut t = self.term.lock().unwrap();
        self.erase(&mut t);
        crate::output::diagnostic!("{line}");
    }

    pub fn error(&self, line: &str) {
        self.error_classified(line, None, None);
    }

    pub fn error_classified(
        &self,
        line: &str,
        class: Option<&'static str>,
        os_kind: Option<&'static str>,
    ) {
        self.errors.fetch_add(1, Relaxed);
        self.eprintln(line);
        if let Some(results) = self.results.get() {
            results.emit_error_classified_for(line, class, os_kind, self.result_destination());
        }
    }

    pub fn warning(&self, code: &str, count: u64, message: &str) {
        let group = self.fanout_group.get().and_then(std::sync::Weak::upgrade);
        let _group_output = group.as_ref().map(|group| group.lock_human_output());
        let mut term = self.term.lock().unwrap();
        self.erase(&mut term);
        if self.json {
            crate::output::diagnostic!(
                "{}",
                serde_json::json!({
                    "type": "warning",
                    "code": code,
                    "count": count,
                    "message": message,
                })
            );
        } else {
            crate::output::diagnostic!("syq: warning: {message}");
        }
    }

    fn erase(&self, t: &mut TermState) {
        if t.lines_drawn > 0 {
            let _ = write!(std::io::stderr().lock(), "\r\x1b[{}A\x1b[J", t.lines_drawn);
            t.lines_drawn = 0;
        }
    }

    fn rate(&self, t: &mut TermState) -> f64 {
        let now = Instant::now();
        let done = self.bytes_done.load(Relaxed);
        if t.samples
            .back()
            .is_some_and(|&(_, previous)| done < previous)
        {
            // Recovery can retract bytes whose acknowledgement is uncertain.
            // A window spanning that rollback is not a meaningful rate.
            t.samples.clear();
        }
        t.samples.push_back((now, done));
        while t.samples.len() > 2 && now - t.samples[0].0 > Duration::from_secs(5) {
            t.samples.pop_front();
        }
        let (t0, b0) = t.samples[0];
        let dt = (now - t0).as_secs_f64();
        if dt < 0.2 {
            return 0.0;
        }
        (done - b0) as f64 / dt
    }

    fn snapshot_locked(&self, t: &mut TermState) -> ProgressSnapshot {
        let rate = self.rate(t);
        let done = self.bytes_done.load(Relaxed);
        let total = self.bytes_total.load(Relaxed);
        let fdone = self.files_done.load(Relaxed);
        let ftotal = self.files_total.load(Relaxed);
        let skipped = self.bytes_unchanged.load(Relaxed);
        let scan_done = self.scan_done.load(Relaxed);
        let remaining = total.saturating_sub(done);
        let eta = if rate > 0.0 && scan_done {
            Some(remaining as f64 / rate)
        } else {
            None
        };
        ProgressSnapshot {
            bytes_done: done,
            bytes_total: total,
            bytes_unchanged: skipped,
            files_done: fdone,
            files_total: ftotal,
            files_unchanged: self.files_unchanged.load(Relaxed),
            files_excluded: self.files_excluded.load(Relaxed),
            scanned: self.scanned.load(Relaxed),
            scan_done,
            rate,
            eta,
            elapsed: self.start.elapsed(),
            active_workers: self.active_workers.load(Relaxed),
            rm: self.rm,
        }
    }

    pub(crate) fn snapshot(&self) -> ProgressSnapshot {
        let mut term = self.term.lock().unwrap();
        self.snapshot_locked(&mut term)
    }

    pub fn render(&self) {
        let mut t = self.term.lock().unwrap();
        let snapshot = self.snapshot_locked(&mut t);

        if let Some(results) = self.results.get() {
            let now = Instant::now();
            if t.last_results
                .is_none_or(|last| now - last >= Duration::from_secs(1))
            {
                t.last_results = Some(now);
                results.emit_progress(&snapshot.result_record(self.result_destination()));
            }
        }
        if self.json {
            let now = Instant::now();
            if t.last_json
                .is_none_or(|l| now - l >= Duration::from_secs(1))
            {
                t.last_json = Some(now);
                // Keep telemetry above the live progress area. Otherwise the
                // next erase counts only the progress rows and leaves stale
                // rows behind whenever both displays are enabled.
                if self.enabled {
                    self.erase(&mut t);
                }
                let mut err = std::io::stderr().lock();
                let _ = writeln!(err, "{}", progress_json(&snapshot, None, None));
                let _ = err.flush();
            }
        }
        if !self.enabled {
            return;
        }
        self.erase(&mut t);
        let width = self.width.unwrap_or_else(term_width);
        let mut lines = Vec::new();
        lines.push(progress_line(&snapshot));
        // One line per file in flight; several workers may share a file.
        let mut seen: Vec<(String, u64, u64, usize)> = Vec::new();
        for w in self.workers.lock().unwrap().iter().flatten() {
            match seen.iter_mut().find(|s| s.0 == w.path) {
                Some(s) => s.3 += 1,
                None => seen.push((w.path.clone(), w.done.load(Relaxed), w.total, 1)),
            }
        }
        for (path, done, total, n) in seen {
            let done = done.min(total);
            let pct = if total > 0 { done * 100 / total } else { 100 };
            let prefix = format!("  {pct:>3}% ");
            let suffix = if n > 1 {
                format!("  ×{n}")
            } else {
                String::new()
            };
            let room = width.saturating_sub(prefix.len() + suffix.len() + 1);
            lines.push(format!("{prefix}{}{suffix}", truncate(&path, room)));
        }
        let mut err = std::io::stderr().lock();
        for line in &lines {
            let _ = writeln!(err, "{}", truncate(line, width.saturating_sub(1)));
        }
        let _ = err.flush();
        t.lines_drawn = lines.len();
    }

    pub fn clear(&self) {
        let mut t = self.term.lock().unwrap();
        self.erase(&mut t);
    }

    pub fn spawn_ticker(self: &Arc<Self>) -> Option<std::thread::JoinHandle<()>> {
        // A results stream needs the ticker too: sampled progress records
        // are emitted from render() even when stderr is not a terminal.
        if !self.enabled && !self.json && self.results.get().is_none() {
            return None;
        }
        let p = self.clone();
        Some(std::thread::spawn(move || {
            while !p.stop.load(Relaxed) {
                p.render();
                std::thread::sleep(Duration::from_millis(100));
            }
            p.clear();
        }))
    }

    pub fn stop(&self) {
        self.stop.store(true, Relaxed);
    }
}

pub(crate) fn progress_json(
    snapshot: &ProgressSnapshot,
    destination_index: Option<usize>,
    destination: Option<&str>,
) -> String {
    #[derive(serde::Serialize)]
    struct Record<'a> {
        bytes_done: u64,
        bytes_total: u64,
        bytes_unchanged: u64,
        files_done: u64,
        files_total: u64,
        files_unchanged: u64,
        files_excluded: u64,
        scanned: u64,
        scan_done: bool,
        rate: u64,
        eta: Option<u64>,
        elapsed: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination: Option<&'a str>,
    }

    serde_json::to_string(&Record {
        bytes_done: snapshot.bytes_done,
        bytes_total: snapshot.bytes_total,
        bytes_unchanged: snapshot.bytes_unchanged,
        files_done: snapshot.files_done,
        files_total: snapshot.files_total,
        files_unchanged: snapshot.files_unchanged,
        files_excluded: snapshot.files_excluded,
        scanned: snapshot.scanned,
        scan_done: snapshot.scan_done,
        // Match the rounding used by the previous fixed-precision formatter.
        rate: snapshot.rate.round_ties_even() as u64,
        eta: snapshot.eta.map(|eta| eta.round_ties_even() as u64),
        elapsed: (snapshot.elapsed.as_secs_f64() * 10.0).round_ties_even() / 10.0,
        destination_index,
        destination,
    })
    .expect("serialize progress JSON")
}

pub(crate) fn progress_line(snapshot: &ProgressSnapshot) -> String {
    let pct = if snapshot.bytes_total > 0 {
        snapshot.bytes_done.saturating_mul(100) / snapshot.bytes_total
    } else {
        0
    };
    let mut line = if snapshot.rm {
        format!(
            "removed {} / {} entries",
            commas(snapshot.files_done),
            commas(snapshot.files_total)
        )
    } else {
        format!(
            "{} / {}  {pct:>3}%  {}/s  files {}/{}",
            human(snapshot.bytes_done),
            human(snapshot.bytes_total),
            human(snapshot.rate as u64),
            snapshot.files_done,
            snapshot.files_total
        )
    };
    if let Some(eta) = snapshot.eta {
        line.push_str(&format!("  ETA {}", hms(eta)));
    }
    if snapshot.active_workers > 0 {
        line.push_str(&format!("  {} conn", snapshot.active_workers));
    }
    if snapshot.bytes_unchanged > 0 {
        line.push_str(&format!(
            "  (unchanged {})",
            human(snapshot.bytes_unchanged)
        ));
    }
    if !snapshot.scan_done {
        line.push_str(&format!("  scanning: {} entries", snapshot.scanned));
    }
    line
}

pub fn term_width() -> usize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::ioctl(2, libc::TIOCGWINSZ, &mut ws) };
    if r == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        80
    }
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max < 4 {
        return s.chars().take(max).collect();
    }
    let keep = max - 1;
    // keep the tail (file names matter more than leading dirs)
    let tail: String = s
        .chars()
        .rev()
        .take(keep)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{tail}")
}

pub fn human(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else if v < 10.0 {
        format!("{v:.2} {}", UNITS[i])
    } else if v < 100.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.0} {}", UNITS[i])
    }
}

pub fn hms(secs: f64) -> String {
    let s = secs.round() as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

pub fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

impl crate::tune::Meter for Progress {
    fn bytes(&self) -> u64 {
        self.tuning_high_water.load(Relaxed)
    }
    fn files(&self) -> u64 {
        self.files_done.load(Relaxed)
    }
    fn set_active(&self, n: usize) {
        self.active_workers.store(n as u64, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tune::Meter;

    #[test]
    fn rollback_resets_display_rate_and_retries_do_not_inflate_tuning_progress() {
        let progress = Progress::new(1, false, false, None, false);
        progress.add_bytes(1_000);
        let mut term = progress.term.lock().unwrap();
        term.samples
            .push_back((Instant::now() - Duration::from_secs(1), 1_000));

        progress.bytes_done.fetch_sub(600, Relaxed);
        assert_eq!(progress.rate(&mut term), 0.0);
        assert_eq!(term.samples.len(), 1);
        assert_eq!(Meter::bytes(&*progress), 1_000);

        progress.add_bytes(600);
        assert_eq!(Meter::bytes(&*progress), 1_000);
        progress.add_bytes(100);
        assert_eq!(Meter::bytes(&*progress), 1_100);
    }

    #[test]
    fn progress_json_keeps_the_existing_single_target_field_order() {
        let snapshot = ProgressSnapshot {
            bytes_done: 1,
            bytes_total: 2,
            bytes_unchanged: 3,
            files_done: 4,
            files_total: 5,
            files_unchanged: 6,
            files_excluded: 7,
            scanned: 8,
            scan_done: true,
            rate: 10.5,
            eta: Some(11.5),
            elapsed: Duration::from_millis(1_250),
            active_workers: 0,
            rm: false,
        };

        assert_eq!(
            progress_json(&snapshot, None, None),
            r#"{"bytes_done":1,"bytes_total":2,"bytes_unchanged":3,"files_done":4,"files_total":5,"files_unchanged":6,"files_excluded":7,"scanned":8,"scan_done":true,"rate":10,"eta":12,"elapsed":1.2}"#
        );
    }
}
