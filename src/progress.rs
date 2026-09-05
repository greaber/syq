//! A fixed-height aggregate progress bar. Byte accounting belongs to the engine.

use std::collections::VecDeque;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    term: Mutex<TermState>,
    stop: AtomicBool,
    /// `--results`: machine-readable NDJSON outcome stream, set once after
    /// construction so workers and the planner reach it with no plumbing.
    results: std::sync::OnceLock<Arc<crate::results::ResultsWriter>>,
}

struct TermState {
    line: Option<String>,
    samples: VecDeque<(Instant, u64)>,
    last_json: Option<Instant>,
    last_results: Option<Instant>,
}

impl TermState {
    fn draw(&mut self, out: &mut impl Write, line: String) -> std::io::Result<()> {
        if self.line.as_ref() != Some(&line) {
            out.write_all(format!("\r{line}\x1b[K").as_bytes())?;
            out.flush()?;
            self.line = Some(line);
        }
        Ok(())
    }
}

impl Progress {
    pub fn new(enabled: bool, force: bool, width: Option<usize>, json: bool) -> Arc<Self> {
        Arc::new(Progress {
            enabled: enabled && !json && (force || std::io::stderr().is_terminal()),
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
            term: Mutex::new(TermState {
                line: None,
                samples: VecDeque::from([(Instant::now(), 0)]),
                last_json: None,
                last_results: None,
            }),
            stop: AtomicBool::new(false),
            results: std::sync::OnceLock::new(),
        })
    }

    pub fn set_results(&self, writer: Arc<crate::results::ResultsWriter>) {
        let _ = self.results.set(writer);
    }

    pub fn results_writer(&self) -> Option<&Arc<crate::results::ResultsWriter>> {
        self.results.get()
    }

    pub fn add_bytes(&self, n: u64) {
        let done = self.bytes_done.fetch_add(n, Relaxed).saturating_add(n);
        self.tuning_high_water.fetch_max(done, Relaxed);
    }

    /// Print a line to stdout, keeping the progress area intact.
    pub fn println(&self, line: &str) {
        let mut term = Some(self.term.lock().unwrap());
        if std::io::stdout().is_terminal() {
            self.erase(term.as_mut().unwrap());
        }
        // A redirected stdout cannot disturb the terminal display. Let the
        // ticker keep running while a slow pipe blocks this printing worker.
        if !std::io::stdout().is_terminal() {
            drop(term.take());
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
            results.emit_error_classified(line, class, os_kind);
        }
    }

    pub fn warning(&self, code: &str, count: u64, message: &str) {
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
        if t.line.take().is_some() {
            let _ = write!(std::io::stderr().lock(), "\r\x1b[2K");
        }
    }

    fn rate(&self, t: &mut TermState, now: Instant, done: u64) -> f64 {
        if t.samples
            .back()
            .is_some_and(|&(_, previous)| done < previous)
        {
            // Recovery can retract bytes whose acknowledgement is uncertain.
            t.samples.clear();
        }
        // Sample byte changes, not redraws. Keep the sample before the window:
        // a block taking 30 seconds must not look like it arrived in 5 seconds.
        if t.samples
            .back()
            .is_none_or(|&(_, previous)| done != previous)
        {
            t.samples.push_back((now, done));
        }
        while t.samples.len() > 2 && now - t.samples[1].0 > Duration::from_secs(5) {
            t.samples.pop_front();
        }
        let (t0, b0) = t.samples[0];
        let dt = (now - t0).as_secs_f64();
        if dt < 0.2 {
            return 0.0;
        }
        (done - b0) as f64 / dt
    }

    pub fn render(&self) {
        self.render_status(None);
    }

    fn render_status(&self, status: Option<&str>) {
        let mut t = self.term.lock().unwrap();
        let now = Instant::now();
        let done = self.bytes_done.load(Relaxed);
        let rate = self.rate(&mut t, now, done);
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

        if let Some(results) = self.results.get().filter(|_| status.is_none()) {
            let now = Instant::now();
            if t.last_results
                .is_none_or(|last| now - last >= Duration::from_secs(1))
            {
                t.last_results = Some(now);
                results.emit_progress(&crate::results::ProgressRecord {
                    bytes_done: done,
                    bytes_total: total,
                    bytes_unchanged: skipped,
                    files_done: fdone,
                    files_total: ftotal,
                    files_unchanged: self.files_unchanged.load(Relaxed),
                    files_excluded: self.files_excluded.load(Relaxed),
                    scanned: self.scanned.load(Relaxed),
                    scan_done,
                    elapsed_ms: self.start.elapsed().as_millis() as u64,
                });
            }
        }
        if self.json && status.is_none() {
            let now = Instant::now();
            if t.last_json
                .is_none_or(|l| now - l >= Duration::from_secs(1))
            {
                t.last_json = Some(now);
                crate::output::diagnostic!(
                    "{{\"bytes_done\":{done},\"bytes_total\":{total},\"bytes_unchanged\":{skipped},\"files_done\":{fdone},\"files_total\":{ftotal},\"files_unchanged\":{},\"files_excluded\":{},\"scanned\":{},\"scan_done\":{scan_done},\"rate\":{:.0},\"eta\":{},\"elapsed\":{:.1}}}",
                    self.files_unchanged.load(Relaxed),
                    self.files_excluded.load(Relaxed),
                    self.scanned.load(Relaxed),
                    rate,
                    eta.map_or("null".to_string(), |e| format!("{e:.0}")),
                    self.start.elapsed().as_secs_f64()
                );
            }
        }
        if !self.enabled {
            return;
        }
        let age = now - t.samples.back().unwrap().0;
        let elapsed = now - self.start;
        let state = if let Some(status) = status {
            status.to_string()
        } else if !scan_done {
            format!("scanning {}", commas(self.scanned.load(Relaxed)))
        } else if self.errors.load(Relaxed) > 0 {
            format!("{} errors", self.errors.load(Relaxed))
        } else if !self.rm && done >= total && fdone < ftotal {
            "finishing".to_string()
        } else if age >= Duration::from_secs(5) && !self.rm {
            format!("no update {}", hms(age.as_secs_f64()))
        } else if self.rm {
            "removing".to_string()
        } else {
            format!("{}/s", human(rate as u64))
        };
        let (count, total, units) = if self.rm {
            (
                fdone,
                ftotal,
                format!("{}/{} entries", commas(fdone), commas(ftotal)),
            )
        } else {
            (done, total, format!("{}/{}", human(done), human(total)))
        };
        let mut details = vec![state, format!("elapsed {}", hms(elapsed.as_secs_f64()))];
        if status.is_none() && age < Duration::from_secs(5) && !self.rm {
            if let Some(eta) = eta {
                details.push(format!("ETA {}", hms(eta)));
            }
        }
        if !self.rm {
            details.push(format!("files {fdone}/{ftotal}"));
        }
        if skipped > 0 {
            details.push(format!("unchanged {}", human(skipped)));
        }
        let active = self.active_workers.load(Relaxed);
        if active > 0 {
            details.push(format!("{active} conn"));
        }
        let line = bar_line(
            self.width.unwrap_or_else(term_width).saturating_sub(1),
            count,
            total,
            scan_done || status.is_some(),
            status == Some("done")
                || (status.is_none()
                    && scan_done
                    && ftotal > 0
                    && fdone == ftotal
                    && self.errors.load(Relaxed) == 0),
            &units,
            &details,
        );
        // Never blank the display between frames or move through worker rows.
        // One buffered write replaces this line and clears only its old tail.
        let _ = t.draw(&mut std::io::stderr().lock(), line);
    }

    /// Leave the final bar visible. Call after joining the ticker, with the
    /// actual operation outcome; a full byte counter alone is not success.
    pub fn finish(&self, success: bool) {
        self.render_status(Some(if success { "done" } else { "incomplete" }));
        let mut t = self.term.lock().unwrap();
        if t.line.take().is_some() {
            let _ = writeln!(std::io::stderr().lock());
        }
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

pub fn term_width() -> usize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::ioctl(2, libc::TIOCGWINSZ, &mut ws) };
    if r == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        80
    }
}

/// All fields are ASCII and the line reserves the terminal's final column,
/// avoiding autowrap. Drop optional fields whole; never truncate away progress.
fn bar_line(
    width: usize,
    done: u64,
    total: u64,
    known: bool,
    success: bool,
    units: &str,
    details: &[String],
) -> String {
    let pct = if total > 0 {
        (u128::from(done.min(total)) * 100 / u128::from(total)) as usize
    } else if success {
        100
    } else {
        0
    };
    let percent = if known {
        format!("{pct:>3}%")
    } else {
        " ---".to_string()
    };
    let cells = (width / 5).clamp(3, 24);
    let filled = if known { pct * cells / 100 } else { 0 };
    let mut line = format!(
        "[{}{}] {percent}",
        "=".repeat(filled),
        " ".repeat(cells - filled)
    );
    if line.len() > width {
        return percent.trim().chars().take(width).collect();
    }
    for field in details
        .iter()
        .take(1)
        .map(String::as_str)
        .chain(std::iter::once(units))
        .chain(details.iter().skip(1).map(String::as_str))
    {
        if line.len() + 2 + field.len() <= width {
            line.push_str("  ");
            line.push_str(field);
        }
    }
    line
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
        let progress = Progress::new(false, false, None, false);
        progress.add_bytes(1_000);
        let mut term = progress.term.lock().unwrap();
        term.samples
            .push_back((Instant::now() - Duration::from_secs(1), 1_000));

        progress.bytes_done.fetch_sub(600, Relaxed);
        assert_eq!(progress.rate(&mut term, Instant::now(), 400), 0.0);
        assert_eq!(term.samples.len(), 1);
        assert_eq!(Meter::bytes(&*progress), 1_000);

        progress.add_bytes(600);
        assert_eq!(Meter::bytes(&*progress), 1_000);
        progress.add_bytes(100);
        assert_eq!(Meter::bytes(&*progress), 1_100);
    }

    #[test]
    fn slow_blocks_keep_their_full_measurement_interval() {
        let progress = Progress::new(false, false, None, false);
        let mut term = progress.term.lock().unwrap();
        let start = Instant::now();
        term.samples = VecDeque::from([(start, 0)]);
        for second in 1..30 {
            assert_eq!(
                progress.rate(&mut term, start + Duration::from_secs(second), 0),
                0.0
            );
        }
        let block = 4 * 1024 * 1024;
        let rate = progress.rate(&mut term, start + Duration::from_secs(30), block);
        assert_eq!(rate, block as f64 / 30.0);
        // No invented bytes, and no jump to zero after the old five-second window.
        assert_eq!(
            progress.rate(&mut term, start + Duration::from_secs(40), block),
            block as f64 / 40.0
        );
        assert_eq!(
            progress.rate(&mut term, start + Duration::from_secs(60), block * 2),
            block as f64 / 30.0
        );
    }

    #[test]
    fn bar_stays_visible_across_sparse_updates_without_scrolling_or_clearing() {
        let progress = Progress::new(false, false, None, false);
        let mut term = progress.term.lock().unwrap();
        let mut output = Vec::new();
        let first = bar_line(
            79,
            25,
            100,
            true,
            false,
            "25 B/100 B",
            &["elapsed 0:01".into()],
        );
        term.draw(&mut output, first.clone()).unwrap();
        let before = output.clone();
        term.draw(&mut output, first.clone()).unwrap();
        assert_eq!(output, before, "identical frames need no terminal writes");
        let waiting = bar_line(
            79,
            25,
            100,
            true,
            false,
            "25 B/100 B",
            &["no update 0:30".into()],
        );
        assert_eq!(first.split(']').next(), waiting.split(']').next());
        term.draw(&mut output, waiting.clone()).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("\r{first}\x1b[K\r{waiting}\x1b[K")
        );
    }

    #[test]
    fn bar_fits_narrow_terminals_and_keeps_counts_and_outcomes() {
        for width in 0..200 {
            let line = bar_line(
                width,
                u64::MAX,
                u64::MAX,
                true,
                false,
                "16.0 EiB/16.0 EiB",
                &["incomplete".into(), "elapsed 0:30".into()],
            );
            assert!(line.len() <= width, "width {width}: {line}");
            assert!(!line.contains('\n'));
            if width >= 30 {
                assert!(line.contains("incomplete"), "{line}");
            }
        }
        let scanning = bar_line(
            79,
            10,
            10,
            false,
            false,
            "10 B/10 B",
            &["scanning 10".into()],
        );
        assert!(scanning.contains("---") && !scanning.contains("100%"));
        let empty = bar_line(79, 0, 0, true, true, "0 B/0 B", &["done".into()]);
        assert!(empty.contains("100%") && empty.contains("done"));
    }
}
