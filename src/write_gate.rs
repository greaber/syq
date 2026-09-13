//! Serialize concurrent range writes on Linux, keeping reception and hashing parallel.
//! The registry is process-local; independent SSH helpers do not share it.
use std::fs::File;
use std::io;

#[cfg(target_os = "linux")]
pub(crate) fn write_all_at(file: &File, data: &[u8], offset: u64) -> io::Result<()> {
    serialized::write_all_at(file, data, offset)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn write_all_at(file: &File, data: &[u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, data, offset)
}

// Exercise the portable gate on every Unix test host without changing the
// production write path on platforms whose performance has not been measured.
#[cfg(any(target_os = "linux", test))]
mod serialized {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::sync::{Arc, Mutex, OnceLock, Weak};

    type Key = (u64, u64);
    type Gate = Mutex<()>;

    fn gate(file: &File) -> io::Result<Arc<Gate>> {
        static GATES: OnceLock<Mutex<HashMap<Key, Weak<Gate>>>> = OnceLock::new();
        // Use the validated open descriptor, not a pathname which could be replaced.
        let metadata = file.metadata()?;
        let key = (metadata.dev(), metadata.ino());
        let mut gates = GATES.get_or_init(Mutex::default).lock().unwrap();
        // Amortize registry sweeps across many files instead of scanning on every block.
        // Idle entries hold only Weak references; live gates belong to in-flight writes.
        if gates.len() > 1024 {
            gates.retain(|_, gate| gate.strong_count() != 0);
        }
        let gate = gates.get(&key).and_then(Weak::upgrade).unwrap_or_else(|| {
            let gate = Arc::new(Mutex::new(()));
            gates.insert(key, Arc::downgrade(&gate));
            gate
        });
        Ok(gate)
    }

    pub(super) fn write_all_at(file: &File, data: &[u8], offset: u64) -> io::Result<()> {
        let gate = gate(file)?;
        // Sleeping here avoids same-inode contention inside the filesystem. Keep
        // the Arc alive while waiting so another worker cannot create a new gate.
        let _writer = gate.lock().unwrap();
        file.write_all_at(data, offset)
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
                        let file = File::options().write(true).open(path).unwrap();
                        for _ in 0..32 {
                            let gate = gate(&file).unwrap();
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
        fn unrelated_files_progress_and_write_errors_release_the_gate() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("first");
            let first = File::create(&path).unwrap();
            let second = File::create(dir.path().join("second")).unwrap();
            let first_gate = gate(&first).unwrap();
            let second_gate = gate(&second).unwrap();
            assert!(!Arc::ptr_eq(&first_gate, &second_gate));
            {
                let _held = first_gate.lock().unwrap();
                write_all_at(&second, b"independent", 0).unwrap();
            }
            let read_only = File::open(path).unwrap();
            assert!(write_all_at(&read_only, b"fail", 0).is_err());
            assert!(first_gate.try_lock().is_ok());
            write_all_at(&first, b"ok", 0).unwrap();
        }
    }
}
