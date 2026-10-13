//! Serialize Linux range writes while keeping reception and hashing parallel.
//! Every worker of a copy runs in its receiver process, so the registry
//! covers them all. Writes are serialized only on filesystems where that
//! helps (`Profile::serialized_writes`).
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

/// Whether writes to one file on the device of `file` are serialized, as
/// the filesystem's profile says (`Profile::serialized_writes`), cached per
/// device.
#[cfg(any(target_os = "linux", test))]
fn serializes_range_writes(file: &File, dev: u64) -> bool {
    static DEVICES: OnceLock<Mutex<HashMap<u64, bool>>> = OnceLock::new();
    let devices = DEVICES.get_or_init(Default::default);
    if let Some(&serializes) = devices.lock().unwrap().get(&dev) {
        return serializes;
    }
    let serializes = profile_serializes_writes(file);
    devices.lock().unwrap().insert(dev, serializes);
    serializes
}

#[cfg(all(target_os = "linux", not(test)))]
fn profile_serializes_writes(file: &File) -> bool {
    crate::fsops::profile(file).serialized_writes
}

/// Tests serialize on every filesystem, so the gate itself is exercised
/// wherever they run; the profile's choice is tested with the profiles.
#[cfg(test)]
fn profile_serializes_writes(_file: &File) -> bool {
    true
}

pub(crate) struct CachedFile {
    file: File,
    /// The file's write gate, or `None` where writes are not serialized.
    #[cfg(any(target_os = "linux", test))]
    gate: OnceLock<Option<Arc<Mutex<()>>>>,
    /// For a file the receiver holds for a copy, a share of its use count,
    /// which keeps it held while this descriptor is cached.
    _in_use: Option<std::sync::Arc<()>>,
}

impl CachedFile {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(any(target_os = "linux", test))]
            gate: OnceLock::new(),
            _in_use: None,
        }
    }

    /// A descriptor of a file the receiver holds, with a share of its use
    /// count.
    pub(crate) fn held(file: File, in_use: std::sync::Arc<()>) -> Self {
        Self {
            _in_use: Some(in_use),
            ..Self::new(file)
        }
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn into_file(self) -> File {
        self.file
    }

    #[cfg(any(target_os = "linux", test))]
    fn write_gate(&self) -> io::Result<Option<&Arc<Mutex<()>>>> {
        if let Some(gate) = self.gate.get() {
            return Ok(gate.as_ref());
        }
        static GATES: OnceLock<Mutex<Registry>> = OnceLock::new();
        // The open descriptor pins this inode for the lifetime of the cached gate.
        // Register lazily so reads and native copies do not pay for a write gate.
        let metadata = self.file.metadata()?;
        let gate = serializes_range_writes(&self.file, metadata.dev()).then(|| {
            GATES
                .get_or_init(|| Mutex::new(Registry::new()))
                .lock()
                .unwrap()
                .gate((metadata.dev(), metadata.ino()))
        });
        Ok(self.gate.get_or_init(|| gate).as_ref())
    }

    pub(crate) fn write_range_at(&self, data: &[u8], offset: u64, sparse: bool) -> io::Result<()> {
        // Tests exercise serialization on every Unix host; production enables it
        // only on Linux, where its performance has been measured.
        #[cfg(any(target_os = "linux", test))]
        let gate = self.write_gate()?;
        #[cfg(any(target_os = "linux", test))]
        let _writer = gate.map(|gate| gate.lock().unwrap());
        if sparse {
            crate::sparse::write_at(&self.file, data, offset, true)
        } else {
            self.file.write_all_at(data, offset)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
                        let gate = file.write_gate().unwrap().unwrap();
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
        original.write_range_at(b"old", 0, false).unwrap();
        let gate = Arc::downgrade(original.write_gate().unwrap().unwrap());
        std::fs::hard_link(&path, &alias).unwrap();
        let other = CachedFile::new(File::options().write(true).open(&alias).unwrap());
        assert!(Arc::ptr_eq(
            original.write_gate().unwrap().unwrap(),
            other.write_gate().unwrap().unwrap()
        ));

        std::fs::remove_file(&path).unwrap();
        let replacement = CachedFile::new(File::create(&path).unwrap());
        assert!(!Arc::ptr_eq(
            original.write_gate().unwrap().unwrap(),
            replacement.write_gate().unwrap().unwrap()
        ));
        original.write_range_at(b"OLD", 0, false).unwrap();
        replacement.write_range_at(b"new", 0, false).unwrap();
        assert_eq!(std::fs::read(&alias).unwrap(), b"OLD");
        assert_eq!(std::fs::read(&path).unwrap(), b"new");

        // Evicting one worker's descriptor must not split the remaining gate.
        drop(original);
        let reopened = CachedFile::new(File::options().write(true).open(&alias).unwrap());
        assert!(Arc::ptr_eq(
            other.write_gate().unwrap().unwrap(),
            reopened.write_gate().unwrap().unwrap()
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
        let first_gate = first.write_gate().unwrap().unwrap();
        let second_gate = second.write_gate().unwrap().unwrap();
        assert!(!Arc::ptr_eq(first_gate, second_gate));
        {
            let _held = first_gate.lock().unwrap();
            second.write_range_at(b"independent", 0, false).unwrap();
        }
        let read_only = CachedFile::new(File::open(path).unwrap());
        assert!(read_only.write_range_at(b"fail", 0, false).is_err());
        assert!(first_gate.try_lock().is_ok());
        first.write_range_at(b"ok", 0, false).unwrap();
    }
}
