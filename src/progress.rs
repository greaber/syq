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
    pub bytes_skipped: AtomicU64,
    pub files_total: AtomicU64,
    pub files_done: AtomicU64,
    pub files_skipped: AtomicU64,
    /// Source files deliberately not transferred (-u, size limits, --existing,
    /// symlinks without -l, ...); neither "transferred" nor "unchanged".
    pub files_excluded: AtomicU64,
    pub scanned: AtomicU64,
    pub scan_done: AtomicBool,
    pub errors: AtomicU64,
    /// Workers currently allowed to take work (0 = fixed -j, not shown).
    pub active_workers: AtomicU64,
    pub start: Instant,
    workers: Mutex<Vec<Option<WorkerStatus>>>,
    term: Mutex<TermState>,
    stop: AtomicBool,
}

struct TermState {
    lines_drawn: usize,
    samples: VecDeque<(Instant, u64)>,
    last_json: Option<Instant>,
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
            bytes_skipped: AtomicU64::new(0),
            files_total: AtomicU64::new(0),
            files_done: AtomicU64::new(0),
            files_skipped: AtomicU64::new(0),
            files_excluded: AtomicU64::new(0),
            scanned: AtomicU64::new(0),
            scan_done: AtomicBool::new(false),
            errors: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            start: Instant::now(),
            workers: Mutex::new(vec![None; n_workers]),
            term: Mutex::new(TermState {
                lines_drawn: 0,
                samples: VecDeque::new(),
                last_json: None,
            }),
            stop: AtomicBool::new(false),
        })
    }

    pub fn set_worker(&self, id: usize, s: Option<WorkerStatus>) {
        let mut w = self.workers.lock().unwrap();
        if id >= w.len() {
            w.resize(id + 1, None);
        }
        w[id] = s;
    }

    pub fn add_bytes(&self, n: u64) {
        self.bytes_done.fetch_add(n, Relaxed);
    }

    /// Print a line to stdout, keeping the progress area intact.
    pub fn println(&self, line: &str) {
        let mut t = self.term.lock().unwrap();
        self.erase(&mut t);
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }

    /// Print a line to stderr (errors and warnings), keeping the progress area intact.
    pub fn eprintln(&self, line: &str) {
        let mut t = self.term.lock().unwrap();
        self.erase(&mut t);
        eprintln!("{line}");
    }

    pub fn error(&self, line: &str) {
        self.errors.fetch_add(1, Relaxed);
        self.eprintln(line);
    }

    fn erase(&self, t: &mut TermState) {
        if t.lines_drawn > 0 {
            eprint!("\r\x1b[{}A\x1b[J", t.lines_drawn);
            t.lines_drawn = 0;
        }
    }

    fn rate(&self, t: &mut TermState) -> f64 {
        let now = Instant::now();
        let done = self.bytes_done.load(Relaxed);
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

    pub fn render(&self) {
        let mut t = self.term.lock().unwrap();
        let rate = self.rate(&mut t);
        let done = self.bytes_done.load(Relaxed);
        let total = self.bytes_total.load(Relaxed);
        let fdone = self.files_done.load(Relaxed);
        let ftotal = self.files_total.load(Relaxed);
        let skipped = self.bytes_skipped.load(Relaxed);
        let scan_done = self.scan_done.load(Relaxed);
        let remaining = total.saturating_sub(done);
        let eta = if rate > 0.0 && scan_done {
            Some(remaining as f64 / rate)
        } else {
            None
        };

        if self.json {
            let now = Instant::now();
            if t.last_json
                .is_none_or(|l| now - l >= Duration::from_secs(1))
            {
                t.last_json = Some(now);
                eprintln!(
                    "{{\"bytes_done\":{done},\"bytes_total\":{total},\"bytes_skipped\":{skipped},\"files_done\":{fdone},\"files_total\":{ftotal},\"files_skipped\":{},\"scanned\":{},\"scan_done\":{scan_done},\"rate\":{:.0},\"eta\":{},\"elapsed\":{:.1}}}",
                    self.files_skipped.load(Relaxed),
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
        self.erase(&mut t);
        let width = self.width.unwrap_or_else(term_width);
        let mut lines = Vec::new();
        let pct = if total > 0 { done * 100 / total } else { 0 };
        let mut head = if self.rm {
            format!("removed {} / {} entries", commas(fdone), commas(ftotal))
        } else {
            format!(
                "{} / {}  {pct:>3}%  {}/s  files {fdone}/{ftotal}",
                human(done),
                human(total),
                human(rate as u64)
            )
        };
        if let Some(e) = eta {
            head.push_str(&format!("  ETA {}", hms(e)));
        }
        let active = self.active_workers.load(Relaxed);
        if active > 0 {
            head.push_str(&format!("  {active} conn"));
        }
        if skipped > 0 {
            head.push_str(&format!("  (unchanged {})", human(skipped)));
        }
        if !scan_done {
            head.push_str(&format!(
                "  scanning: {} entries",
                self.scanned.load(Relaxed)
            ));
        }
        lines.push(head);
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
        for l in &lines {
            let _ = writeln!(err, "{}", truncate(l, width.saturating_sub(1)));
        }
        let _ = err.flush();
        t.lines_drawn = lines.len();
    }

    pub fn clear(&self) {
        let mut t = self.term.lock().unwrap();
        self.erase(&mut t);
    }

    pub fn spawn_ticker(self: &Arc<Self>) -> Option<std::thread::JoinHandle<()>> {
        if !self.enabled && !self.json {
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

fn truncate(s: &str, max: usize) -> String {
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
        self.bytes_done.load(Relaxed)
    }
    fn files(&self) -> u64 {
        self.files_done.load(Relaxed)
    }
    fn set_active(&self, n: usize) {
        self.active_workers.store(n as u64, Relaxed);
    }
}
