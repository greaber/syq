//! Serialize Linux range writes while keeping reception and hashing parallel.
//! The registry is process-local; independent SSH helpers do not share it.
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

#[cfg(any(target_os = "linux", test))]
use {
    std::collections::HashMap,
    std::os::unix::fs::MetadataExt,
    std::sync::{Arc, Mutex, OnceLock, Weak},
};

#[cfg(any(target_os = "linux", test))]
struct Registry {
    gates: HashMap<(u64, u64), Weak<Mutex<()>>>,
    sweep_at: usize,
}

#[cfg(any(target_os = "linux", test))]
impl Registry {
    fn new() -> Self {
        Self {
            gates: HashMap::new(),
            sweep_at: 1024,
        }
    }

    fn gate(&mut self, key: (u64, u64)) -> Arc<Mutex<()>> {
        if self.gates.len() > self.sweep_at {
            self.gates.retain(|_, gate| gate.strong_count() != 0);
            // Leave room above live entries so a busy registry does not rescan
            // on every registration. A later sweep can lower the threshold.
            self.sweep_at = self.gates.len().saturating_mul(2).max(1024);
        }
        self.gates
            .get(&key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let gate = Arc::new(Mutex::new(()));
                self.gates.insert(key, Arc::downgrade(&gate));
                gate
            })
    }
}

// Diagnostic experiment only. No limit is selected unless explicitly requested.
// The eventual policy depends on measured throughput, CPU and wait behavior.
#[cfg(target_os = "linux")]
struct DiagnosticWriteLimit {
    slots: usize,
    active: Mutex<usize>,
    changed: std::sync::Condvar,
}

#[cfg(target_os = "linux")]
impl DiagnosticWriteLimit {
    fn acquire(&self) -> DiagnosticWritePermit<'_> {
        let mut active = self.active.lock().unwrap();
        while *active >= self.slots {
            active = self.changed.wait(active).unwrap();
        }
        *active += 1;
        DiagnosticWritePermit(self)
    }
}

#[cfg(target_os = "linux")]
struct DiagnosticWritePermit<'a>(&'a DiagnosticWriteLimit);

#[cfg(target_os = "linux")]
impl Drop for DiagnosticWritePermit<'_> {
    fn drop(&mut self) {
        *self.0.active.lock().unwrap() -= 1;
        self.0.changed.notify_one();
    }
}

#[cfg(target_os = "linux")]
fn diagnostic_write_limit() -> Option<&'static DiagnosticWriteLimit> {
    static LIMIT: OnceLock<Option<DiagnosticWriteLimit>> = OnceLock::new();
    LIMIT
        .get_or_init(|| {
            std::env::var("SYQ_DIAG_TMPFS_WRITE_SLOTS")
                .ok()
                .map(|value| {
                    let slots = value.parse::<usize>().expect("diagnostic write slot count");
                    assert!(
                        (1..=256).contains(&slots),
                        "diagnostic write slots: 1..=256"
                    );
                    DiagnosticWriteLimit {
                        slots,
                        active: Mutex::new(0),
                        changed: std::sync::Condvar::new(),
                    }
                })
        })
        .as_ref()
}

pub(crate) struct CachedFile {
    file: File,
    #[cfg(any(target_os = "linux", test))]
    gate: OnceLock<Arc<Mutex<()>>>,
    #[cfg(target_os = "linux")]
    diagnostic_tmpfs: OnceLock<bool>,
}

impl CachedFile {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(any(target_os = "linux", test))]
            gate: OnceLock::new(),
            #[cfg(target_os = "linux")]
            diagnostic_tmpfs: OnceLock::new(),
        }
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn into_file(self) -> File {
        self.file
    }

    #[cfg(any(target_os = "linux", test))]
    fn write_gate(&self) -> io::Result<&Arc<Mutex<()>>> {
        if let Some(gate) = self.gate.get() {
            return Ok(gate);
        }
        static GATES: OnceLock<Mutex<Registry>> = OnceLock::new();
        // The open descriptor pins this inode for the lifetime of the cached gate.
        // Register lazily so reads and native copies do not pay for a write gate.
        let metadata = self.file.metadata()?;
        let key = (metadata.dev(), metadata.ino());
        let gate = GATES
            .get_or_init(|| Mutex::new(Registry::new()))
            .lock()
            .unwrap()
            .gate(key);
        Ok(self.gate.get_or_init(|| gate))
    }

    pub(crate) fn write_range_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        // Tests exercise serialization on every Unix host; production enables it
        // only on Linux, where its performance has been measured.
        #[cfg(any(target_os = "linux", test))]
        let gate = self.write_gate()?;
        #[cfg(any(target_os = "linux", test))]
        let _writer = gate.lock().unwrap();
        #[cfg(target_os = "linux")]
        let _permit = diagnostic_write_limit().and_then(|limit| {
            use std::os::fd::AsRawFd;
            let is_tmpfs = self.diagnostic_tmpfs.get_or_init(|| {
                let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
                // fstatfs initializes the structure only on success.
                unsafe {
                    libc::fstatfs(self.file.as_raw_fd(), fs.as_mut_ptr()) == 0
                        && fs.assume_init().f_type as u32 == libc::TMPFS_MAGIC as u32
                }
            });
            is_tmpfs.then(|| limit.acquire())
        });
        self.file.write_all_at(data, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(target_os = "linux")]
    #[test]
    fn diagnostic_limit_bounds_writers_and_releases_after_errors() {
        let limit = DiagnosticWriteLimit {
            slots: 2,
            active: Mutex::new(0),
            changed: std::sync::Condvar::new(),
        };
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let (limit, active, peak) = (&limit, &active, &peak);
                scope.spawn(move || {
                    for _ in 0..32 {
                        let _permit = limit.acquire();
                        let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(n, Ordering::SeqCst);
                        assert!(n <= 2);
                        std::thread::yield_now();
                        active.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert!(peak.load(Ordering::SeqCst) > 0);
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("read-only");
        std::fs::write(&path, b"original").unwrap();
        let file = File::open(path).unwrap();
        let result = {
            let _permit = limit.acquire();
            file.write_all_at(b"replacement", 0)
        };
        assert!(result.is_err());
        assert_eq!(*limit.active.lock().unwrap(), 0);
        let _first = limit.acquire();
        let _second = limit.acquire();
        assert_eq!(*limit.active.lock().unwrap(), 2);
    }

    #[test]
    fn registry_sweeps_leave_room_for_live_gates_and_reclaim_idle_entries() {
        let mut registry = Registry::new();
        let live: Vec<_> = (0..1025).map(|i| registry.gate((1, i))).collect();
        let last = registry.gate((1, 1025));
        assert_eq!(registry.sweep_at, 2050);
        drop(last);
        registry.gate((1, 1026));
        // This dead entry survives until the next scheduled sweep, proving
        // registrations above 1024 do not each scan the live registry.
        assert!(registry.gates.contains_key(&(1, 1025)));
        assert!(Arc::ptr_eq(&live[0], &registry.gate((1, 0))));
        drop(live);
        for i in 1027..2052 {
            registry.gate((1, i));
        }
        assert_eq!(registry.sweep_at, 1024);
        assert_eq!(registry.gates.len(), 1);
    }

    #[test]
    fn concurrent_opens_and_hardlinks_share_one_writer() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("file");
        File::create(&path).unwrap();
        let alias = dir.path().join("alias");
        std::fs::hard_link(&path, &alias).unwrap();
        let active = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for i in 0..16 {
                let path = if i % 2 == 0 { &path } else { &alias };
                let active = &active;
                scope.spawn(move || {
                    let file = CachedFile::new(File::options().write(true).open(path).unwrap());
                    for _ in 0..32 {
                        let gate = file.write_gate().unwrap();
                        let _writer = gate.lock().unwrap();
                        assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                        std::thread::yield_now();
                        file.file().write_all_at(&[i as u8], i).unwrap();
                        assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                    }
                });
            }
        });
        assert_eq!(std::fs::read(path).unwrap(), (0u8..16).collect::<Vec<_>>());
    }

    #[test]
    fn cached_gate_tracks_open_inode_across_path_replacement_and_reopening() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("file");
        let alias = dir.path().join("alias");
        let original = CachedFile::new(File::create(&path).unwrap());
        original.write_range_at(b"old", 0).unwrap();
        let gate = Arc::downgrade(original.write_gate().unwrap());
        std::fs::hard_link(&path, &alias).unwrap();
        let other = CachedFile::new(File::options().write(true).open(&alias).unwrap());
        assert!(Arc::ptr_eq(
            original.write_gate().unwrap(),
            other.write_gate().unwrap()
        ));

        std::fs::remove_file(&path).unwrap();
        let replacement = CachedFile::new(File::create(&path).unwrap());
        assert!(!Arc::ptr_eq(
            original.write_gate().unwrap(),
            replacement.write_gate().unwrap()
        ));
        original.write_range_at(b"OLD", 0).unwrap();
        replacement.write_range_at(b"new", 0).unwrap();
        assert_eq!(std::fs::read(&alias).unwrap(), b"OLD");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");

        // Evicting one worker's descriptor must not split the remaining gate.
        drop(original);
        let reopened = CachedFile::new(File::options().write(true).open(&alias).unwrap());
        assert!(Arc::ptr_eq(
            other.write_gate().unwrap(),
            reopened.write_gate().unwrap()
        ));
        drop(other);
        drop(reopened);
        assert!(gate.upgrade().is_none());
    }

    #[test]
    fn unrelated_files_progress_and_write_errors_release_the_gate() {
        let dir = crate::test_support::tempdir().unwrap();
        let path = dir.path().join("first");
        let first = CachedFile::new(File::create(&path).unwrap());
        let second = CachedFile::new(File::create(dir.path().join("second")).unwrap());
        let first_gate = first.write_gate().unwrap();
        let second_gate = second.write_gate().unwrap();
        assert!(!Arc::ptr_eq(first_gate, second_gate));
        {
            let _held = first_gate.lock().unwrap();
            second.write_range_at(b"independent", 0).unwrap();
        }
        let read_only = CachedFile::new(File::open(path).unwrap());
        assert!(read_only.write_range_at(b"fail", 0).is_err());
        assert!(first_gate.try_lock().is_ok());
        first.write_range_at(b"ok", 0).unwrap();
    }
}
