//! Session-owned metadata workers. Only operations, tickets and results cross
//! threads; each worker acquires and drops its own root descriptor.
use super::apply_queue::{Burst, Queue};
use super::*;
use std::sync::mpsc;

pub(super) struct Batch {
    ops: Vec<Op>,
    guard: Option<ContainerGuard>,
    prefix: Option<PathBytes>,
    queue: Mutex<Queue>,
    ready: Arc<namespace::Wake>,
    cancelled: std::sync::atomic::AtomicBool,
}

impl Batch {
    pub(super) fn new(
        ops: &[Op],
        selected: &[usize],
        guard: Option<&ContainerGuard>,
        prefix: Option<&[u8]>,
    ) -> Self {
        Self {
            queue: Mutex::new(Queue::new(ops, selected)),
            ops: ops.to_vec(),
            guard: guard.cloned(),
            prefix: prefix.map(<[u8]>::to_vec),
            ready: Arc::new(namespace::Wake::default()),
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn execute(&self, burst: Burst, root: Option<&Arc<Root>>) {
        for &(task, operation) in &burst.tasks {
            if self.cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                apply_one(
                    &self.ops[operation],
                    self.guard.as_ref(),
                    root.cloned(),
                    self.prefix.as_deref(),
                )
                .err()
                .as_ref()
                .map(wire_error)
            }));
            let mut queue = self.queue.lock().unwrap();
            let was_ready = queue.ready_lanes() != 0;
            match result {
                Ok(error) => queue.complete(task, error),
                Err(_) => {
                    self.cancelled
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    queue.abort("metadata worker panicked".into());
                }
            }
            if queue.finished() || (!was_ready && queue.ready_lanes() != 0) {
                self.ready.notify();
            }
        }
        let mut queue = self.queue.lock().unwrap();
        let was_ready = queue.ready_lanes() != 0;
        queue.release(burst);
        if queue.finished() || (!was_ready && queue.ready_lanes() != 0) {
            self.ready.notify();
        }
    }

    fn prepare(&self, burst: Burst, root: Option<&Arc<Root>>) -> WaitingBurst {
        let operation = burst.tasks[0].1;
        let op = &self.ops[operation];
        let ticket = (|| -> Result<Option<namespace::Ticket>> {
            if matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. }) {
                return Ok(None);
            }
            let (root, relative) = if let Some(guard) = &self.guard {
                let target = guarded_target(op_path(op), guard)?;
                (target.root, target.relative)
            } else {
                (
                    root.context("unrooted metadata operation")?.clone(),
                    RelativePath::new(op_path(op))?,
                )
            };
            let path = relative.to_path_buf();
            let parent = path
                .parent()
                .context("namespace operation requires a leaf")?;
            let directory =
                root.open_directory(&RelativePath::new(parent.as_os_str().as_bytes())?)?;
            let domain = namespace::Domain::new(directory)?;
            Ok(Some(domain.request(&self.ready)))
        })()
        .ok()
        .flatten();
        // Missing/invalid parents still go through apply_one's authoritative
        // checks and implicit-parent handling. A scheduling lookup grants no
        // permission and must not substitute an ancestor for the selected parent.
        WaitingBurst { burst, ticket }
    }

    fn runnable(
        &self,
        waiting: &mut Vec<WaitingBurst>,
        root: Option<&Arc<Root>>,
    ) -> Option<(Burst, Option<namespace::Turn>)> {
        for index in 0..waiting.len() {
            if let Some(turn) = waiting[index].ticket.as_mut().unwrap().try_enter() {
                return Some((waiting.swap_remove(index).burst, Some(turn)));
            }
        }
        // Retain only a bounded number of prepared directories on each owner.
        // Unopened work remains in the shared ready queue and can be stolen.
        while waiting.len() < 8 {
            let burst = self.queue.lock().unwrap().claim()?;
            let mut prepared = self.prepare(burst, root);
            let Some(ticket) = prepared.ticket.as_mut() else {
                return Some((prepared.burst, None));
            };
            if let Some(turn) = ticket.try_enter() {
                return Some((prepared.burst, Some(turn)));
            }
            waiting.push(prepared);
        }
        None
    }

    fn run_worker(&self, root: Option<&Arc<Root>>) {
        let mut waiting = Vec::new();
        loop {
            let version = self.ready.version();
            if self.queue.lock().unwrap().finished() {
                return;
            }
            if let Some((burst, turn)) = self.runnable(&mut waiting, root) {
                self.execute(burst, root);
                drop(turn);
            } else {
                self.ready.wait(version);
            }
        }
    }

    fn abort(&self, error: &anyhow::Error) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .abort(wire_error(error));
        self.ready.notify();
    }
}

struct WaitingBurst {
    burst: Burst,
    ticket: Option<namespace::Ticket>,
}

struct Worker {
    tx: Option<mpsc::SyncSender<Arc<Batch>>>,
    done: Mutex<mpsc::Receiver<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Default)]
pub(super) struct Pool {
    workers: Vec<Worker>,
    cannot_grow: bool,
}

impl Pool {
    fn grow(&mut self, root: Option<&Arc<Root>>) -> Result<()> {
        let handles: Vec<_> = root
            .into_iter()
            .map(|root| root.directory_descriptor())
            .collect();
        let (tx, rx) = mpsc::sync_channel::<Arc<Batch>>(1);
        let (done_tx, done) = mpsc::channel();
        // SAFETY: setup and run capture only channels. Root descriptors enter
        // through the bootstrap handoff and never leave the owning executor.
        let thread = unsafe {
            crate::fs_executor::spawn(
                format!("syq-fs-{}", self.workers.len()),
                false,
                &handles,
                |mut handles| {
                    handles
                        .pop()
                        .map(|file| Root::from_directory(file).map(Arc::new))
                        .transpose()
                },
                move |root| {
                    while let Ok(batch) = rx.recv() {
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            batch.run_worker(root.as_ref())
                        }))
                        .is_err()
                        {
                            batch.abort(&anyhow!("metadata executor stopped during dispatch"));
                        }
                        if done_tx.send(()).is_err() {
                            return;
                        }
                    }
                },
            )?
        }
        .expect("shared-table metadata executors are supported");
        self.workers.push(Worker {
            tx: Some(tx),
            done: Mutex::new(done),
            thread: Some(thread),
        });
        Ok(())
    }

    pub(super) fn run(
        &mut self,
        batch: Arc<Batch>,
        root: Option<&Arc<Root>>,
    ) -> Vec<Option<WireError>> {
        struct AbortOnUnwind<'a>(&'a Batch);
        impl Drop for AbortOnUnwind<'_> {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    self.0
                        .cancelled
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    self.0
                        .queue
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .abort("metadata dispatcher panicked".into());
                    self.0.ready.notify();
                }
            }
        }
        let _abort = AbortOnUnwind(&batch);
        let mut limit = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(PAR_THREADS);
        if self.cannot_grow {
            limit = self.workers.len() + 1;
        }
        let mut assigned = 0;
        let mut waiting = Vec::new();
        loop {
            let version = batch.ready.version();
            let queue = batch.queue.lock().unwrap();
            if queue.finished() {
                break;
            }
            // The caller executes the first ready turn inline. Start additional
            // executors only when independent ready lanes actually exist.
            let wanted = (queue.active_lanes() + queue.ready_lanes())
                .saturating_sub(1)
                .min(limit.saturating_sub(1));
            drop(queue);
            while assigned < wanted {
                if assigned == self.workers.len() && self.grow(root).is_err() {
                    // Extra executors are optional. Resource pressure must not
                    // invalidate the caller's already-selected root.
                    self.cannot_grow = true;
                    limit = self.workers.len() + 1;
                    break;
                }
                if self.workers[assigned]
                    .tx
                    .as_ref()
                    .unwrap()
                    .send(batch.clone())
                    .is_err()
                {
                    batch.abort(&anyhow!("filesystem executor stopped"));
                    break;
                }
                assigned += 1;
            }
            if batch.queue.lock().unwrap().finished() {
                break;
            }
            if let Some((burst, turn)) = batch.runnable(&mut waiting, root) {
                batch.execute(burst, root);
                drop(turn);
            } else {
                batch.ready.wait(version);
            }
        }
        for worker in &mut self.workers[..assigned] {
            if worker.done.get_mut().unwrap().recv().is_err() {
                batch.abort(&anyhow!("filesystem executor stopped before completion"));
            }
        }
        std::mem::take(&mut batch.queue.lock().unwrap().results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mkdir(path: &str) -> Op {
        Op::Mkdir {
            path: path.as_bytes().to_vec(),
            mode: 0o755,
            condition: TargetCondition::Any,
        }
    }

    #[test]
    fn one_ready_chain_stays_inline_and_final_metadata_waits_for_children() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Arc::new(Root::open(directory.path()).unwrap());
        let mut pool = Pool::default();
        let mut ops = vec![mkdir("a"), mkdir("a/b"), mkdir("a/b/c")];
        ops.push(Op::SetMeta {
            path: b"a".to_vec(),
            meta: Meta {
                mode: 0o500,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            },
            flags: flags::MODE,
            condition: TargetCondition::Any,
        });
        let batch = Arc::new(Batch::new(&ops, &[0, 1, 2, 3], None, None));
        assert_eq!(pool.run(batch, Some(&root)), vec![None; 4]);
        assert!(pool.workers.is_empty());
        assert!(directory.path().join("a/b/c").is_dir());
        assert_eq!(
            std::fs::metadata(directory.path().join("a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o500
        );
        std::fs::set_permissions(
            directory.path().join("a"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn worker_imports_selected_root_and_returns_per_operation_errors() {
        let directory = crate::test_support::tempdir().unwrap();
        let original = directory.path().join("original");
        let moved = directory.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        let root = Arc::new(Root::open(&original).unwrap());
        let mut pool = Pool::default();
        pool.grow(Some(&root)).unwrap();
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        let ops = vec![mkdir("a"), mkdir("a/b"), mkdir("../escape")];
        let batch = Arc::new(Batch::new(&ops, &[0, 1, 2], None, None));
        let worker = &mut pool.workers[0];
        worker.tx.as_ref().unwrap().send(batch.clone()).unwrap();
        worker
            .done
            .get_mut()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let queue = batch.queue.lock().unwrap();
        assert!(queue.finished());
        assert!(queue.results[0].is_none() && queue.results[1].is_none());
        assert!(queue.results[2].is_some());
        assert!(moved.join("a/b").is_dir());
        assert!(!original.join("a").exists());
        assert!(!directory.path().join("escape").exists());
        drop(queue);
        drop(pool);
    }

    #[test]
    fn abort_wakes_workers_and_accounts_for_unstarted_operations() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Arc::new(Root::open(directory.path()).unwrap());
        let mut pool = Pool::default();
        pool.grow(Some(&root)).unwrap();
        let ops = vec![mkdir("a"), mkdir("a/b")];
        let batch = Arc::new(Batch::new(&ops, &[0, 1], None, None));
        // Hold the only ready turn, making the executor wait without a syscall.
        let held = batch.queue.lock().unwrap().claim().unwrap();
        let worker = &mut pool.workers[0];
        worker.tx.as_ref().unwrap().send(batch.clone()).unwrap();
        batch.abort(&anyhow!("test cancellation"));
        worker
            .done
            .get_mut()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let mut queue = batch.queue.lock().unwrap();
        queue.release(held);
        assert!(queue.results.iter().all(Option::is_some));
        assert!(!directory.path().join("a").exists());
    }
}
