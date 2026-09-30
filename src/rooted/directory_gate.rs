//! Park excess contenders before entering directory mutation syscalls on Linux.
//!
//! This is process-local admission, not a correctness lock. The key combines
//! the open root's identity with the validated parent spelling: separate roots
//! for the same inode share admission, but different descendant aliases may
//! miss that optimization. Path resolution and publication checks remain with
//! the caller, and a permit must not span data writes or metadata inspection.
//!
//! A single operation takes a permit for its one syscall. A batch takes a
//! turn instead and changes many entries before the next contender wakes, so
//! the directory is handed over once per burst rather than once per file.
use super::RootIdentity;
use std::cell::Cell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

// The kernel changes a directory's entries under one lock, so only one
// mutation proceeds at a time however many threads ask. A second contender
// keeps that lock busy while the first does the unlocked part of its call;
// any further one only spins. Independent directories have independent
// capacity.
const MUTATORS: usize = 2;

// Replacing a file frees its inode. On ext4 the throughput of that falls
// once more than about eight threads replace files at once, whichever
// directories they work in, with or without the orphan_file feature. Roots
// on other filesystems do not take this permit: XFS, tmpfs and ZFS replaced
// files as fast or faster with every worker, and on NFS the bound changed
// nothing.
const REPLACERS: usize = 8;

thread_local! {
    // Turns this thread holds. Its operations inside a turn already own the
    // directory's capacity and must not wait for it again.
    static TURNS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Eq, Hash, PartialEq)]
struct Directory {
    root: RootIdentity,
    parents: Vec<Vec<u8>>,
}

#[derive(Default)]
struct State {
    active: usize,
    waiting: usize,
}

struct Gate {
    state: Mutex<State>,
    available: Condvar,
    limit: usize,
}

impl Gate {
    fn new(limit: usize) -> Self {
        Self {
            state: Mutex::default(),
            available: Condvar::new(),
            limit,
        }
    }

    fn acquire(self: &Arc<Self>) -> Permit {
        let mut state = self.state.lock().unwrap();
        while state.active == self.limit {
            state.waiting += 1;
            state = self.available.wait(state).unwrap();
            state.waiting -= 1;
        }
        state.active += 1;
        drop(state);
        Permit(Some(self.clone()))
    }
}

pub(super) struct Permit(Option<Arc<Gate>>);

impl Drop for Permit {
    fn drop(&mut self) {
        let Some(gate) = &self.0 else {
            return;
        };
        let mut state = gate.state.lock().unwrap();
        state.active -= 1;
        let waiting = state.waiting != 0;
        drop(state);
        // Condvar notification can enter the kernel even without a waiter.
        // Uncontended directories need only the userspace mutex fast path.
        if waiting {
            gate.available.notify_one();
        }
    }
}

/// A permit held across several changes by the thread that took it. The
/// turn stays on that thread: its scope is what exempts nested operations.
pub(super) struct Turn {
    _permit: Permit,
    _thread: PhantomData<*const ()>,
}

impl Drop for Turn {
    fn drop(&mut self) {
        TURNS.with(|turns| turns.set(turns.get() - 1));
    }
}

struct Registry {
    gates: HashMap<Directory, Weak<Gate>>,
    sweep_at: usize,
}

impl Registry {
    fn new() -> Self {
        Self {
            gates: HashMap::new(),
            sweep_at: 1024,
        }
    }

    fn gate(&mut self, key: Directory) -> Arc<Gate> {
        if self.gates.len() > self.sweep_at {
            self.gates.retain(|_, gate| gate.strong_count() != 0);
            self.sweep_at = self.gates.len().saturating_mul(2).max(1024);
        }
        self.gates
            .get(&key)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let gate = Arc::new(Gate::new(MUTATORS));
                self.gates.insert(key, Arc::downgrade(&gate));
                gate
            })
    }
}

/// Admit one more thread to replacing files on this filesystem. Callers take
/// it before any directory turn, so that a thread waiting here keeps no
/// directory from its other contender.
pub(super) fn replacement(device: u64) -> Permit {
    static FILESYSTEMS: OnceLock<Mutex<HashMap<u64, Arc<Gate>>>> = OnceLock::new();
    let gate = FILESYSTEMS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
        .entry(device)
        .or_insert_with(|| Arc::new(Gate::new(REPLACERS)))
        .clone();
    gate.acquire()
}

pub(super) fn turn(root: RootIdentity, parents: &[Vec<u8>]) -> Turn {
    // A nested turn waits for nothing either: waiting for a second directory
    // while holding the first could deadlock two batches.
    let permit = acquire(root, parents);
    TURNS.with(|turns| turns.set(turns.get() + 1));
    Turn {
        _permit: permit,
        _thread: PhantomData,
    }
}

pub(super) fn acquire(root: RootIdentity, parents: &[Vec<u8>]) -> Permit {
    if TURNS.with(Cell::get) != 0 {
        return Permit(None);
    }
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    let key = Directory {
        root,
        parents: parents.to_vec(),
    };
    let gate = REGISTRY
        .get_or_init(|| Mutex::new(Registry::new()))
        .lock()
        .unwrap()
        .gate(key);
    // The caller keeps its root descriptor alive throughout the operation,
    // preventing root inode reuse while a permit or its waiter is live.
    // Never hold the registry lock while waiting or performing filesystem I/O.
    gate.acquire()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;

    fn key(ino: u64, parent: &[u8]) -> Directory {
        Directory {
            root: RootIdentity { dev: 1, ino },
            parents: vec![parent.to_vec()],
        }
    }

    #[test]
    fn all_permits_are_usable_and_concurrent_mutations_stay_bounded() {
        let gate = Arc::new(Gate::new(MUTATORS));
        let entered = Barrier::new(MUTATORS);
        std::thread::scope(|scope| {
            for _ in 0..MUTATORS {
                let gate = &gate;
                let entered = &entered;
                scope.spawn(move || {
                    let _permit = gate.acquire();
                    entered.wait();
                });
            }
        });
        let active = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let gate = &gate;
                let active = &active;
                scope.spawn(move || {
                    for _ in 0..100 {
                        let _permit = gate.acquire();
                        assert!(active.fetch_add(1, Ordering::SeqCst) < MUTATORS);
                        std::thread::yield_now();
                        active.fetch_sub(1, Ordering::SeqCst);
                    }
                });
            }
        });
        let state = gate.state.lock().unwrap();
        assert_eq!(state.active, 0);
        assert_eq!(state.waiting, 0);
    }

    #[test]
    fn independent_roots_and_parents_do_not_wait_on_a_busy_directory() {
        let mut registry = Registry::new();
        let gate = registry.gate(key(1, b"a"));
        assert!(Arc::ptr_eq(&gate, &registry.gate(key(1, b"a"))));
        let busy: Vec<_> = (0..MUTATORS).map(|_| gate.acquire()).collect();
        let other_parent = registry.gate(key(1, b"b"));
        let other_root = registry.gate(key(2, b"a"));
        assert!(!Arc::ptr_eq(&gate, &other_parent));
        assert!(!Arc::ptr_eq(&gate, &other_root));
        let _parent_permit = other_parent.acquire();
        let _root_permit = other_root.acquire();
        drop(busy);
    }

    #[test]
    fn a_turn_covers_its_own_threads_operations_until_it_ends() {
        let root = RootIdentity { dev: 7, ino: 7 };
        let parent = vec![b"burst".to_vec()];
        let other = vec![b"elsewhere".to_vec()];
        let held = turn(root, &parent);
        // Operations inside the turn, a nested turn, and a panic that unwinds
        // through a nested turn all leave the outer turn in place.
        assert!(acquire(root, &parent).0.is_none());
        assert!(acquire(root, &other).0.is_none());
        assert!(std::panic::catch_unwind(|| {
            let _nested = turn(root, &other);
            assert!(acquire(root, &other).0.is_none());
            panic!("mutation failed");
        })
        .is_err());
        assert!(acquire(root, &parent).0.is_none());
        // Another thread competes for the capacity the turn occupies.
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let permits: Vec<_> = (1..MUTATORS).map(|_| acquire(root, &parent)).collect();
                assert!(permits.iter().all(|permit| permit.0.is_some()));
            });
        });
        drop(held);
        let all: Vec<_> = (0..MUTATORS).map(|_| acquire(root, &parent)).collect();
        assert!(all.iter().all(|permit| permit.0.is_some()));
    }

    #[test]
    fn replacements_are_bounded_for_each_filesystem_separately() {
        let held: Vec<_> = (0..REPLACERS).map(|_| replacement(u64::MAX)).collect();
        // Another filesystem has its own capacity while this one is full.
        drop(replacement(u64::MAX - 1));
        let (entered, waited) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let _permit = replacement(u64::MAX);
                entered.send(()).unwrap();
            });
            let pause = std::time::Duration::from_millis(50);
            assert!(waited.recv_timeout(pause).is_err());
            drop(held);
            waited.recv().unwrap();
        });
    }

    #[test]
    fn errors_and_panics_release_permits() {
        let gate = Arc::new(Gate::new(MUTATORS));
        let fail = || -> Result<(), ()> {
            let _permit = gate.acquire();
            Err(())
        };
        assert!(fail().is_err());
        assert!(std::panic::catch_unwind(|| {
            let _permit = gate.acquire();
            panic!("operation failed");
        })
        .is_err());
        let all: Vec<_> = (0..MUTATORS).map(|_| gate.acquire()).collect();
        drop(all);
        assert_eq!(gate.state.lock().unwrap().active, 0);
    }

    #[test]
    fn registry_reclaims_idle_entries_without_repeatedly_scanning_live_gates() {
        let mut registry = Registry::new();
        let live: Vec<_> = (0..1025).map(|i| registry.gate(key(i, b"a"))).collect();
        registry.gate(key(1025, b"a"));
        assert_eq!(registry.sweep_at, 2050);
        registry.gate(key(1026, b"a"));
        assert!(registry.gates.contains_key(&key(1025, b"a")));
        assert!(Arc::ptr_eq(&live[0], &registry.gate(key(0, b"a"))));
        drop(live);
        for i in 1027..2052 {
            registry.gate(key(i, b"a"));
        }
        assert_eq!(registry.sweep_at, 1024);
        assert_eq!(registry.gates.len(), 1);
    }
}
