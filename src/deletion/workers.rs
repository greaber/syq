//! Bounded execution shared by recursive removal and selected-entry pruning.
//! Producers own discovery and dependencies; workers own admission and retirement.
use super::{Concurrency, Control, SAMPLE};
use anyhow::Result;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub(crate) trait Work: Send + Sized + 'static {
    type Outcome: Send;
    const THREAD_NAME: Option<&'static str> = None;
    fn run(self, pool: &Arc<Pool<Self>>);
    fn completed(outcome: &Self::Outcome) -> u64;
}

pub(crate) struct Pool<T: Work> {
    pub(crate) sender: Mutex<Option<mpsc::SyncSender<T>>>,
    pub(crate) pending: Mutex<usize>,
    pub(crate) events: mpsc::Sender<Result<Option<T::Outcome>, ()>>,
    pub(crate) dry_run: bool,
    pub(crate) cancelled: AtomicBool,
    pub(crate) limit: AtomicUsize,
    pub(crate) active: AtomicUsize,
    pub(crate) parked: Mutex<()>,
    pub(crate) waiting: AtomicUsize,
    pub(crate) wake: Condvar,
}

impl<T: Work> Pool<T> {
    pub(crate) fn submit(self: &Arc<Self>, task: T) {
        *self.pending.lock().unwrap() += 1;
        let queued = self
            .sender
            .lock()
            .unwrap()
            .as_ref()
            .map(|sender| sender.try_send(task));
        match queued {
            Some(Ok(())) => return,
            Some(Err(mpsc::TrySendError::Full(task)))
            | Some(Err(mpsc::TrySendError::Disconnected(task))) => {
                task.run(self);
            }
            None => unreachable!("native removal submitted work after shutdown"),
        }
        self.task_done();
    }

    pub(crate) fn task_done(&self) {
        let finished = {
            let mut pending = self.pending.lock().unwrap();
            *pending -= 1;
            *pending == 0
        };
        if finished {
            // The coordinator can consume the last outcome before this task
            // finishes. Wake it again so completion cannot wait for EVENT_POLL.
            let _ = self.events.send(Ok(None));
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        *self.pending.lock().unwrap() == 0
    }

    pub(crate) fn close(&self) {
        self.sender.lock().unwrap().take();
        let _parked = self.parked.lock().unwrap();
        self.wake.notify_all();
    }

    pub(crate) fn set_limit(&self, limit: usize) {
        let _parked = self.parked.lock().unwrap();
        self.limit.store(limit, Ordering::Relaxed);
        self.wake.notify_all();
    }

    pub(crate) fn enter(&self) -> ActiveWorker<'_, T> {
        if !self.try_enter() {
            let parked = self.parked.lock().unwrap();
            let _parked = self.wait_for_capacity(parked);
        }
        ActiveWorker(self)
    }

    pub(crate) fn try_enter(&self) -> bool {
        let mut active = self.active.load(Ordering::SeqCst);
        loop {
            if active >= self.limit.load(Ordering::Relaxed) && !self.is_cancelled() {
                return false;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(current) => active = current,
            }
        }
    }

    pub(crate) fn wait_for_capacity<'a>(
        &self,
        mut parked: std::sync::MutexGuard<'a, ()>,
    ) -> std::sync::MutexGuard<'a, ()> {
        // Register before checking capacity. Together with the sequentially
        // consistent release/check in ActiveWorker::drop, this prevents a
        // missed wakeup without locking on uncontended admission or release.
        self.waiting.fetch_add(1, Ordering::SeqCst);
        while !self.try_enter() {
            parked = self.wake.wait(parked).unwrap();
        }
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        parked
    }

    /// A scan may keep executing inline work while the queue is full. Let
    /// excess workers pause in that scan, retaining its existing state. Any
    /// worker can resume when another releases capacity; worker IDs cannot
    /// decide admission because a parked scan still needs to finish.
    /// Call only while active and without a directory mutation permit.
    pub(crate) fn retire_excess(&self) {
        if self.active.load(Ordering::Relaxed) <= self.limit.load(Ordering::Relaxed) {
            return;
        }
        let parked = self.parked.lock().unwrap();
        if self.active.load(Ordering::Relaxed) > self.limit.load(Ordering::Relaxed)
            && !self.is_cancelled()
        {
            self.active.fetch_sub(1, Ordering::SeqCst);
            let _parked = self.wait_for_capacity(parked);
        }
    }

    pub(crate) fn backlogged(&self) -> bool {
        let limit = self.limit.load(Ordering::Relaxed);
        *self.pending.lock().unwrap() >= limit + limit.min(16)
            && self.active.load(Ordering::Relaxed) <= limit
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let _parked = self.parked.lock().unwrap();
        self.wake.notify_all();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub(crate) fn outcome(&self, outcome: T::Outcome) {
        if !self.is_cancelled() {
            let _ = self.events.send(Ok(Some(outcome)));
        }
    }
}

/// Capacity belongs to a worker only while it can make progress. In
/// particular, waiting for an empty task queue must release it so a paused
/// scan can resume and produce the remaining work.
pub(crate) struct ActiveWorker<'a, T: Work>(&'a Pool<T>);

impl<T: Work> Drop for ActiveWorker<'_, T> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        if self.0.waiting.load(Ordering::SeqCst) != 0 {
            let _parked = self.0.parked.lock().unwrap();
            self.0.wake.notify_one();
        }
    }
}

pub(crate) fn worker_loop<T: Work>(pool: Arc<Pool<T>>, receiver: Arc<Mutex<mpsc::Receiver<T>>>) {
    loop {
        let mut task = match receiver.lock().unwrap().recv() {
            Ok(task) => task,
            Err(_) => return,
        };
        let _active = pool.enter();
        loop {
            pool.retire_excess();
            task.run(&pool);
            pool.task_done();
            // Keep admission across available work, but never while waiting
            // on the queue: paused scans may be its only remaining producers.
            let next = match receiver.try_lock() {
                Ok(receiver) => receiver.try_recv(),
                Err(std::sync::TryLockError::WouldBlock) => break,
                Err(error) => panic!("removal receiver lock poisoned: {error}"),
            };
            match next {
                Ok(next) => task = next,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
    }
}

pub(crate) fn emit<T: Work>(
    pool: &Pool<T>,
    batch: &mut Vec<T::Outcome>,
    sink: &mut dyn FnMut(Vec<T::Outcome>) -> Result<()>,
) -> Result<()> {
    let ready = std::mem::replace(batch, Vec::with_capacity(200));
    if let Err(error) = sink(ready) {
        pool.cancel();
        return Err(error);
    }
    Ok(())
}

/// Kept alive between bounded Apply requests. The caller keeps selection state;
/// workers never infer that an explicit directory removal means recursive work.
pub(crate) struct Executor<T: Work> {
    pub(crate) pool: Arc<Pool<T>>,
    receiver: Arc<Mutex<mpsc::Receiver<T>>>,
    events: Mutex<mpsc::Receiver<Result<Option<T::Outcome>, ()>>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    control: Control,
    failed: bool,
}

impl<T: Work> Executor<T> {
    pub(crate) fn new(concurrency: Concurrency, dry_run: bool) -> Self {
        let (sender, receiver) = mpsc::sync_channel(concurrency.initial.saturating_mul(4).max(1));
        let (events, outcomes) = mpsc::channel();
        Self {
            pool: Arc::new(Pool {
                sender: Mutex::new(Some(sender)),
                pending: Mutex::new(0),
                events,
                dry_run,
                cancelled: AtomicBool::new(false),
                limit: AtomicUsize::new(concurrency.initial),
                active: AtomicUsize::new(0),
                parked: Mutex::new(()),
                waiting: AtomicUsize::new(0),
                wake: Condvar::new(),
            }),
            receiver: Arc::new(Mutex::new(receiver)),
            events: Mutex::new(outcomes),
            threads: Vec::new(),
            control: Control::new(concurrency),
            failed: false,
        }
    }

    fn spawn_to(&mut self, limit: usize) {
        while self.threads.len() < limit {
            let pool = self.pool.clone();
            let receiver = self.receiver.clone();
            let mut builder = std::thread::Builder::new();
            if let Some(name) = T::THREAD_NAME {
                builder = builder.name(format!("{name}-{}", self.threads.len()));
            }
            self.threads.push(
                builder
                    .spawn(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            worker_loop(pool.clone(), receiver)
                        }));
                        if result.is_err() {
                            // A panicking task cannot decrement its outstanding count.
                            // Tell the coordinator instead of leaving it waiting forever.
                            let _ = pool.events.send(Err(()));
                        }
                    })
                    .expect("start removal worker"),
            );
        }
    }

    pub(crate) fn run(
        &mut self,
        tasks: impl IntoIterator<Item = T>,
        batch_backlogged: bool,
        sink: &mut dyn FnMut(Vec<T::Outcome>) -> Result<()>,
    ) -> Result<()> {
        anyhow::ensure!(!self.failed, "removal worker previously panicked");
        let mut tasks = tasks.into_iter().peekable();
        if tasks.peek().is_none() {
            return Ok(());
        }
        self.pool.set_limit(self.control.limit());
        let mut start_workers = true;
        let mut next = tasks.next();
        let mut batch = Vec::with_capacity(200);
        let mut error = None;
        let mut last_emit = Instant::now();
        let mut sampled = Instant::now();
        let mut completed = 0;
        loop {
            // The coordinator never takes the workers' inline fallback: it
            // must keep draining outcomes and detecting a disconnected client.
            while let Some(task) = next.take() {
                *self.pool.pending.lock().unwrap() += 1;
                let sent = self
                    .pool
                    .sender
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .try_send(task);
                match sent {
                    Ok(()) => next = tasks.next(),
                    Err(mpsc::TrySendError::Full(task)) => {
                        self.pool.task_done();
                        next = Some(task);
                        break;
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => unreachable!(),
                }
            }
            if start_workers {
                // Seed the bounded queue first, as recursive removal did before
                // sharing this executor. New threads need not park before work.
                self.spawn_to(self.control.limit());
                start_workers = false;
            }
            if next.is_none() && self.pool.is_done() {
                break;
            }
            match self
                .events
                .get_mut()
                .unwrap()
                .recv_timeout(Duration::from_millis(100))
            {
                Ok(Ok(Some(event))) => {
                    completed += T::completed(&event);
                    if error.is_none() {
                        batch.push(event);
                    }
                }
                Ok(Ok(None)) | Err(mpsc::RecvTimeoutError::Timeout) => (),
                Ok(Err(())) => {
                    self.failed = true;
                    self.pool.cancel();
                    anyhow::bail!("removal worker panicked");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if !self.pool.dry_run && !self.pool.is_cancelled() && sampled.elapsed() >= SAMPLE {
                let limit = self.control.observe(
                    completed,
                    sampled.elapsed(),
                    batch_backlogged || next.is_some() || self.pool.backlogged(),
                );
                if limit != self.pool.limit.load(Ordering::Relaxed) {
                    self.pool.set_limit(limit);
                    self.spawn_to(limit);
                }
                sampled = Instant::now();
                completed = 0;
            }
            if error.is_none()
                && (batch.len() >= 200
                    || (!batch.is_empty() && last_emit.elapsed() >= Duration::from_millis(100))
                    || last_emit.elapsed() >= Duration::from_secs(1))
            {
                if let Err(failure) = emit(&self.pool, &mut batch, sink) {
                    self.pool.cancel();
                    next = None;
                    error = Some(failure);
                }
                last_emit = Instant::now();
            }
        }
        for event in self.events.get_mut().unwrap().try_iter() {
            let event = match event {
                Ok(event) => event,
                Err(()) => {
                    self.failed = true;
                    self.pool.cancel();
                    anyhow::bail!("removal worker panicked");
                }
            };
            let Some(event) = event else {
                continue;
            };
            completed += T::completed(&event);
            if error.is_none() {
                batch.push(event);
            }
            if error.is_none() && batch.len() >= 200 {
                if let Err(failure) = emit(&self.pool, &mut batch, sink) {
                    self.pool.cancel();
                    error = Some(failure);
                }
            }
        }
        if error.is_none() && !batch.is_empty() {
            if let Err(failure) = emit(&self.pool, &mut batch, sink) {
                self.pool.cancel();
                error = Some(failure);
            }
        }
        // Do not count connection round trips or planner idle time as work.
        self.control
            .observe(completed, sampled.elapsed(), batch_backlogged);
        error.map_or(Ok(()), Err)
    }
}

impl<T: Work> Drop for Executor<T> {
    fn drop(&mut self) {
        self.pool.cancel();
        self.pool.close();
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Panics;
    impl Work for Panics {
        type Outcome = ();
        fn run(self, _: &Arc<Pool<Self>>) {
            panic!("test removal panic");
        }
        fn completed(_: &()) -> u64 {
            0
        }
    }

    #[test]
    fn worker_panic_fails_the_batch_and_later_calls_instead_of_hanging() {
        let (done, result) = mpsc::channel();
        std::thread::spawn(move || {
            let mut executor = Executor::new(Concurrency::filesystem(2), false);
            let first = executor.run([Panics], false, &mut |_| Ok(())).unwrap_err();
            let next = executor.run([Panics], false, &mut |_| Ok(())).unwrap_err();
            drop(executor);
            done.send((first.to_string(), next.to_string())).unwrap();
        });
        let (first, next) = result
            .recv_timeout(Duration::from_secs(5))
            .expect("executor hung after a worker panic");
        assert!(first.contains("worker panicked"));
        assert!(next.contains("previously panicked"));
    }
}
