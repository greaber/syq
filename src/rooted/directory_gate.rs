//! Park excess contenders before entering directory mutation syscalls on Linux.
//!
//! This is process-local admission, not a correctness lock. The key combines
//! the open root's identity with the validated parent spelling: separate roots
//! for the same inode share admission, but different descendant aliases may
//! miss that optimization. Path resolution and publication checks remain with
//! the caller, and a permit must not span data writes or metadata inspection.
use super::RootIdentity;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

// Full serialization delayed local copies. A few contenders preserve the
// create/rename pipeline without letting every transfer worker spin in the
// kernel on one directory. Eight retains the CPU saving while avoiding the
// short-copy latency cost measured with four. Independent directories have
// independent capacity.
const MUTATORS: usize = 8;

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

#[derive(Default)]
struct Gate {
    state: Mutex<State>,
    available: Condvar,
}

impl Gate {
    fn acquire(self: &Arc<Self>) -> Permit {
        let mut state = self.state.lock().unwrap();
        while state.active == MUTATORS {
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
                let gate = Arc::new(Gate::default());
                self.gates.insert(key, Arc::downgrade(&gate));
                gate
            })
    }
}

pub(super) fn acquire(root: RootIdentity, parents: &[Vec<u8>]) -> Permit {
    if super::MutationBurst::active() {
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
        let gate = Arc::new(Gate::default());
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
    fn burst_scope_is_thread_local_and_restores_admission_after_unwind() {
        let root = RootIdentity { dev: 9, ino: 7 };
        let parent = vec![b"burst".to_vec()];
        assert!(acquire(root, &parent).0.is_some());
        let outer = crate::rooted::MutationBurst::enter();
        assert!(acquire(root, &parent).0.is_none());
        std::thread::scope(|scope| {
            scope.spawn(|| assert!(acquire(root, &parent).0.is_some()));
        });
        assert!(std::panic::catch_unwind(|| {
            let _inner = crate::rooted::MutationBurst::enter();
            assert!(acquire(root, &parent).0.is_none());
            panic!("mutation failed");
        })
        .is_err());
        assert!(acquire(root, &parent).0.is_none());
        drop(outer);
        assert!(acquire(root, &parent).0.is_some());
    }

    #[test]
    fn errors_and_panics_release_permits() {
        let gate = Arc::new(Gate::default());
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
