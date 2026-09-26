//! Ready namespace turns keyed by the held directory's device/inode identity.
//! The registry contains no descriptors. A domain and all its tickets stay on
//! their executor, retaining the directory until the last ticket/turn ends.
use super::*;
use std::rc::Rc;
use std::sync::{Condvar, Weak};

#[derive(Default)]
pub(super) struct Wake {
    version: Mutex<u64>,
    ready: Condvar,
}

impl Wake {
    pub(super) fn version(&self) -> u64 {
        *self.version.lock().unwrap()
    }
    pub(super) fn notify(&self) {
        *self.version.lock().unwrap() += 1;
        self.ready.notify_all();
    }
    pub(super) fn wait(&self, version: u64) {
        let state = self.version.lock().unwrap();
        drop(
            self.ready
                .wait_while(state, |current| *current == version)
                .unwrap(),
        );
    }
}

struct Waiting {
    wake: Arc<Wake>,
}

#[derive(Default)]
struct State {
    active: bool,
    pending: VecDeque<Arc<Waiting>>,
}

#[derive(Default)]
struct Gate(Mutex<State>);

#[derive(Default)]
struct Registry {
    gates: HashMap<RootIdentity, Weak<Gate>>,
    sweep_at: usize,
}

impl Registry {
    fn gate(&mut self, identity: RootIdentity) -> Arc<Gate> {
        if self.gates.len() >= self.sweep_at.max(1024) {
            self.gates.retain(|_, gate| gate.strong_count() != 0);
            self.sweep_at = self.gates.len().saturating_mul(2).max(1024);
        }
        self.gates
            .entry(identity)
            .or_default()
            .upgrade()
            .unwrap_or_else(|| {
                let gate = Arc::new(Gate::default());
                self.gates.insert(identity, Arc::downgrade(&gate));
                gate
            })
    }
}

/// A singleton stage joins the same queue as batched work. Its request cannot
/// offer other ready files, so park before the short namespace phase. Callers
/// release this turn before resizing, allocating or writing file data.
pub(super) fn single(root: &Root, relative: &RelativePath) -> Result<Option<Turn>> {
    if crate::rooted::MutationBurst::active() {
        return Ok(None);
    }
    let path = relative.to_path_buf();
    let parent = path
        .parent()
        .context("namespace operation requires a leaf")?;
    let directory = root.open_directory(&RelativePath::new(parent.as_os_str().as_bytes())?)?;
    let domain = Domain::new(directory)?;
    let wake = Arc::new(Wake::default());
    let mut ticket = domain.request(&wake);
    loop {
        let version = wake.version();
        if let Some(turn) = ticket.try_enter() {
            return Ok(Some(turn));
        }
        wake.wait(version);
    }
}

pub(super) struct Domain {
    pub(super) identity: RootIdentity,
    _directory: File,
    gate: Arc<Gate>,
}

impl Domain {
    pub(super) fn new(directory: File) -> Result<Rc<Self>> {
        static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
        let metadata = directory.metadata()?;
        anyhow::ensure!(metadata.is_dir(), "namespace turn requires a directory");
        let identity = RootIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        let gate = REGISTRY
            .get_or_init(|| Mutex::new(Registry::default()))
            .lock()
            .unwrap()
            .gate(identity);
        Ok(Rc::new(Self {
            identity,
            _directory: directory,
            gate,
        }))
    }

    pub(super) fn request(self: &Rc<Self>, wake: &Arc<Wake>) -> Ticket {
        // Each request has a distinct wake record. Two queued turns belonging
        // to one executor must still have distinct FIFO positions.
        let position = Arc::new(Waiting { wake: wake.clone() });
        self.gate
            .0
            .lock()
            .unwrap()
            .pending
            .push_back(position.clone());
        Ticket {
            domain: self.clone(),
            position,
            queued: true,
        }
    }
}

pub(super) struct Ticket {
    domain: Rc<Domain>,
    position: Arc<Waiting>,
    queued: bool,
}

impl Ticket {
    pub(super) fn try_enter(&mut self) -> Option<Turn> {
        let mut state = self.domain.gate.0.lock().unwrap();
        if state.active
            || !state
                .pending
                .front()
                .is_some_and(|front| Arc::ptr_eq(front, &self.position))
        {
            return None;
        }
        state.pending.pop_front();
        state.active = true;
        self.queued = false;
        Some(Turn {
            domain: self.domain.clone(),
            _burst: crate::rooted::MutationBurst::enter(),
        })
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if self.queued {
            let mut state = self.domain.gate.0.lock().unwrap();
            state
                .pending
                .retain(|entry| !Arc::ptr_eq(entry, &self.position));
            let next = state.pending.front().map(|next| next.wake.clone());
            drop(state);
            if let Some(next) = next {
                next.notify();
            }
        }
    }
}

pub(super) struct Turn {
    domain: Rc<Domain>,
    _burst: crate::rooted::MutationBurst,
}
impl Drop for Turn {
    fn drop(&mut self) {
        let mut state = self.domain.gate.0.lock().unwrap();
        state.active = false;
        let next = state.pending.front().map(|next| next.wake.clone());
        drop(state);
        if let Some(next) = next {
            next.notify();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_share_turns_and_independent_directories_stay_ready() {
        let temporary = crate::test_support::tempdir().unwrap();
        let a = temporary.path().join("a");
        let b = temporary.path().join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let first = Domain::new(File::open(&a).unwrap()).unwrap();
        let alias = Domain::new(File::open(&a).unwrap()).unwrap();
        let other = Domain::new(File::open(&b).unwrap()).unwrap();
        let wake = Arc::new(Wake::default());
        let turn = first.request(&wake).try_enter().unwrap();
        let mut waiting = alias.request(&wake);
        assert!(waiting.try_enter().is_none());
        let independent = other.request(&wake).try_enter().unwrap();
        let version = wake.version();
        drop(turn);
        assert_ne!(wake.version(), version);
        assert!(waiting.try_enter().is_some());
        drop(independent);
    }

    #[test]
    fn cancellation_releases_the_fifo_position_and_signals_the_next_owner() {
        let temporary = crate::test_support::tempdir().unwrap();
        let domain = Domain::new(File::open(temporary.path()).unwrap()).unwrap();
        let first = Arc::new(Wake::default());
        let second = Arc::new(Wake::default());
        let cancelled = domain.request(&first);
        let mut next = domain.request(&second);
        assert!(next.try_enter().is_none());
        let version = second.version();
        drop(cancelled);
        assert_ne!(second.version(), version);
        assert!(next.try_enter().is_some());
    }

    #[test]
    fn notification_before_wait_is_not_lost() {
        let wake = Wake::default();
        let version = wake.version();
        wake.notify();
        wake.wait(version);
    }
}
