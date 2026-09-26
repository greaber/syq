//! Session-owned metadata workers. Only operations, tickets and results cross
//! threads; each worker acquires and drops its own root descriptor.
use super::apply_queue::{Burst, Queue};
use super::*;
use std::sync::{mpsc, Condvar};

pub(super) struct Batch {
    ops: Vec<Op>,
    guard: Option<ContainerGuard>,
    prefix: Option<PathBytes>,
    queue: Mutex<Queue>,
    ready: Condvar,
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
            ready: Condvar::new(),
        }
    }

    fn execute(&self, burst: Burst, root: Option<&Arc<Root>>) {
        for &task in &burst.tasks {
            let operation = {
                let queue = self.queue.lock().unwrap();
                if queue.finished() {
                    break;
                }
                queue.operation(task)
            };
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
            match result {
                Ok(error) => queue.complete(task, error),
                Err(_) => queue.abort("metadata worker panicked".into()),
            }
            if queue.finished() {
                self.ready.notify_all();
            } else if queue.ready_lanes() != 0 {
                self.ready.notify_one();
            }
        }
        let mut queue = self.queue.lock().unwrap();
        queue.release(burst);
        if queue.finished() {
            self.ready.notify_all();
        } else if queue.ready_lanes() != 0 {
            self.ready.notify_one();
        }
    }

    fn run_worker(&self, root: Option<&Arc<Root>>) {
        loop {
            let mut queue = self.queue.lock().unwrap();
            let burst = loop {
                if queue.finished() {
                    return;
                }
                if let Some(burst) = queue.claim() {
                    break burst;
                }
                queue = self.ready.wait(queue).unwrap();
            };
            drop(queue);
            self.execute(burst, root);
        }
    }

    fn abort(&self, error: &anyhow::Error) {
        self.queue.lock().unwrap().abort(wire_error(error));
        self.ready.notify_all();
    }
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

struct RootRegistration {
    ticket: DescriptorTicket,
    session: DescriptorSessionSlot,
}

impl Drop for RootRegistration {
    fn drop(&mut self) {
        self.session.release_directory(&self.ticket);
    }
}

#[derive(Default)]
pub(super) struct Pool {
    workers: Vec<Worker>,
    ticket: Option<DescriptorTicket>,
    registration: Option<RootRegistration>,
}

impl Pool {
    pub(super) fn new(ticket: Option<DescriptorTicket>) -> Self {
        Self {
            ticket,
            ..Self::default()
        }
    }

    fn grow(&mut self, root: Option<&Arc<Root>>, session: &DescriptorSessionSlot) -> Result<()> {
        // Root registration happens in the owning (caller) table. The worker
        // receives just the ticket and imports the exact object with SCM_RIGHTS.
        if self.ticket.is_none() {
            if let Some(root) = root {
                let ticket = session.register(root.duplicate_directory()?)?;
                self.ticket = Some(ticket.clone());
                self.registration = Some(RootRegistration {
                    ticket,
                    session: session.clone(),
                });
            }
        }
        let ticket = self.ticket.clone();
        let (tx, rx) = mpsc::sync_channel::<Arc<Batch>>(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name(format!("syq-fs-{}", self.workers.len()))
            .spawn(move || {
                let initialized = (|| -> Result<Option<Arc<Root>>> {
                    // SAFETY: this fresh thread captures no File, socket, Root,
                    // session registry or other descriptor-owning value. It
                    // imports its root only after table setup. apply_one cannot
                    // dispatch descriptor-borrowing work into a global pool.
                    unsafe {
                        crate::sys::isolate_descriptor_table()?;
                    }
                    ticket
                        .as_ref()
                        .map(|ticket| {
                            Root::from_directory(acquire_descriptor(ticket)?).map(Arc::new)
                        })
                        .transpose()
                })();
                let root = match initialized {
                    Ok(root) => {
                        if ready_tx.send(Ok(())).is_err() {
                            return;
                        }
                        root
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                while let Ok(batch) = rx.recv() {
                    batch.run_worker(root.as_ref());
                    if done_tx.send(()).is_err() {
                        return;
                    }
                }
                // root and every operation-local descriptor drop on this thread.
            })
            .context("start filesystem executor")?;
        match ready_rx
            .recv()
            .context("filesystem executor stopped during initialization")
            .and_then(|result| result)
        {
            Ok(()) => self.workers.push(Worker {
                tx: Some(tx),
                done: Mutex::new(done),
                thread: Some(thread),
            }),
            Err(error) => {
                drop(tx);
                let _ = thread.join();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn run(
        &mut self,
        batch: Arc<Batch>,
        root: Option<&Arc<Root>>,
        session: &DescriptorSessionSlot,
    ) -> Vec<Option<WireError>> {
        struct AbortOnUnwind<'a>(&'a Batch);
        impl Drop for AbortOnUnwind<'_> {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    self.0
                        .queue
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .abort("metadata dispatcher panicked".into());
                    self.0.ready.notify_all();
                }
            }
        }
        let _abort = AbortOnUnwind(&batch);
        let limit = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(PAR_THREADS);
        let mut assigned = 0;
        loop {
            let mut queue = batch.queue.lock().unwrap();
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
                if assigned == self.workers.len() {
                    if let Err(error) = self.grow(root, session) {
                        batch.abort(&error);
                        break;
                    }
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
            queue = batch.queue.lock().unwrap();
            if queue.finished() {
                break;
            }
            if let Some(burst) = queue.claim() {
                drop(queue);
                batch.execute(burst, root);
            } else {
                drop(batch.ready.wait(queue).unwrap());
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
        let session = DescriptorSessionSlot::default();
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
        assert_eq!(pool.run(batch, Some(&root), &session), vec![None; 4]);
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
        let session = DescriptorSessionSlot::default();
        let mut pool = Pool::default();
        pool.grow(Some(&root), &session).unwrap();
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
        let ticket = pool.ticket.as_ref().unwrap().clone();
        drop(pool);
        assert!(
            session.acquire(&ticket).is_err(),
            "retiring the pool releases its temporary root registration"
        );
    }

    #[test]
    fn abort_wakes_workers_and_accounts_for_unstarted_operations() {
        let directory = crate::test_support::tempdir().unwrap();
        let root = Arc::new(Root::open(directory.path()).unwrap());
        let session = DescriptorSessionSlot::default();
        let mut pool = Pool::default();
        pool.grow(Some(&root), &session).unwrap();
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
