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

pub(crate) struct CachedFile {
    file: File,
    #[cfg(any(target_os = "linux", test))]
    gate: OnceLock<Arc<Mutex<()>>>,
}

impl CachedFile {
    pub(crate) fn new(file: File) -> Self {
        Self {
            file,
            #[cfg(any(target_os = "linux", test))]
            gate: OnceLock::new(),
        }
    }

    pub(crate) fn into_file(self) -> File {
        self.file
    }

    #[cfg(any(target_os = "linux", test))]
    fn write_gate(&self) -> io::Result<&Arc<Mutex<()>>> {
        if let Some(gate) = self.gate.get() {
            return Ok(gate);
        }
        type Registry = Mutex<HashMap<(u64, u64), Weak<Mutex<()>>>>;
        static GATES: OnceLock<Registry> = OnceLock::new();
        // The open descriptor pins this inode for the lifetime of the cached gate.
        // Register lazily so reads and native copies do not pay for a write gate.
        let metadata = self.file.metadata()?;
        let key = (metadata.dev(), metadata.ino());
        let mut gates = GATES.get_or_init(Mutex::default).lock().unwrap();
        // Amortize sweeps across files. Idle entries hold only Weak references;
        // live gates belong to cached descriptors, including waiting writers.
        if gates.len() > 1024 {
            gates.retain(|_, gate| gate.strong_count() != 0);
        }
        let gate = gates.get(&key).and_then(Weak::upgrade).unwrap_or_else(|| {
            let gate = Arc::new(Mutex::new(()));
            gates.insert(key, Arc::downgrade(&gate));
            gate
        });
        Ok(self.gate.get_or_init(|| gate))
    }

    pub(crate) fn write_range_at(&self, data: &[u8], offset: u64) -> io::Result<()> {
        // Tests exercise serialization on every Unix host; production enables it
        // only on Linux, where its performance has been measured.
        #[cfg(any(target_os = "linux", test))]
        let gate = self.write_gate()?;
        #[cfg(any(target_os = "linux", test))]
        let _writer = gate.lock().unwrap();
        self.file.write_all_at(data, offset)
    }
}

impl std::ops::Deref for CachedFile {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn concurrent_opens_and_hardlinks_share_one_writer() {
        let dir = tempfile::tempdir().unwrap();
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
                        file.write_all_at(&[i as u8], i).unwrap();
                        assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                    }
                });
            }
        });
        assert_eq!(std::fs::read(path).unwrap(), (0u8..16).collect::<Vec<_>>());
    }

    #[test]
    fn cached_gate_tracks_open_inode_across_path_replacement_and_reopening() {
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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
