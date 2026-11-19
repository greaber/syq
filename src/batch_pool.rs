//! A fixed set of threads that share out short batches of blocking work,
//! such as metadata lookups, and sleep between batches.
//!
//! A thread with nothing to do sleeps at once, and a batch wakes only as
//! many threads as it has shares for. Rayon's threads instead look for work
//! to steal, yielding the processor 32 times, before they sleep; on an
//! unchanged rerun that search took more processor time than the lookups
//! the threads were woken for.

use std::any::Any;
use std::collections::VecDeque;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

pub(crate) struct BatchPool {
    shared: Arc<Shared>,
    threads: usize,
}

struct Shared {
    state: Mutex<State>,
    /// Signalled once for each request added to `State::requests`.
    requested: Condvar,
}

#[derive(Default)]
struct State {
    /// One entry for each thread a batch still asks for.
    requests: VecDeque<Arc<Batch>>,
    closed: bool,
}

struct Batch {
    /// The caller's work, which borrows from the caller's stack. Only a
    /// thread that took one of the batch's requests calls it, and `run`
    /// does not return before each of those threads has finished.
    work: *const (dyn Fn() + Sync),
    progress: Mutex<Progress>,
    finished: Condvar,
}

#[derive(Default)]
struct Progress {
    /// Pool threads that have returned from the work.
    finished: usize,
    panic: Option<Box<dyn Any + Send>>,
}

// SAFETY: `work` points at a `Sync` closure, which may be called from any
// thread while it is alive; the other fields are `Send` and `Sync`.
unsafe impl Send for Batch {}
// SAFETY: as above.
unsafe impl Sync for Batch {}

/// Nothing panics while holding these locks, so a poisoned one still holds
/// consistent state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl BatchPool {
    /// Start `threads` threads named `{name}-{index}`. When one of them
    /// cannot start, the ones already started exit.
    pub(crate) fn new(name: &str, threads: usize) -> std::io::Result<Self> {
        let pool = Self {
            shared: Arc::new(Shared {
                state: Mutex::default(),
                requested: Condvar::new(),
            }),
            threads,
        };
        for index in 0..threads {
            let shared = pool.shared.clone();
            std::thread::Builder::new()
                .name(format!("{name}-{index}"))
                .spawn(move || serve(&shared))?;
        }
        Ok(pool)
    }

    /// `f` of each share, in the shares' order. The calling thread and the
    /// pool's threads, at most as many as the pool has between them, take
    /// the shares one at a time until none is left. A panic in `f` is
    /// raised here once every thread has stopped.
    pub(crate) fn map<T: Sync, R: Send>(&self, shares: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
        let next = AtomicUsize::new(0);
        let results: Vec<Mutex<Option<R>>> = shares.iter().map(|_| Mutex::new(None)).collect();
        let helpers = shares.len().min(self.threads).saturating_sub(1);
        self.run(helpers, &|| loop {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let (Some(share), Some(result)) = (shares.get(index), results.get(index)) else {
                break;
            };
            let value = f(share);
            *lock(result) = Some(value);
        });
        results
            .into_iter()
            .map(|result| {
                result
                    .into_inner()
                    .unwrap_or_else(PoisonError::into_inner)
                    .expect("every share ran")
            })
            .collect()
    }

    /// Call `work` on this thread and, at the same time, on up to `helpers`
    /// of the pool's threads. Returns once every call has returned, and
    /// raises a panic from any of them. A thread that is still busy when
    /// this thread's call returns is not waited for: its request is
    /// withdrawn.
    fn run(&self, helpers: usize, work: &(dyn Fn() + Sync)) {
        let helpers = helpers.min(self.threads);
        if helpers == 0 {
            return work();
        }
        // SAFETY: this only erases the borrow's lifetime, so that the pool's
        // threads can hold the pointer. They call it only between taking a
        // request and reporting that they have finished, and `Requested`
        // keeps this function from returning, or unwinding, until every
        // request has been withdrawn or reported finished.
        let work_pointer = unsafe {
            std::mem::transmute::<*const (dyn Fn() + Sync + '_), *const (dyn Fn() + Sync + 'static)>(
                work,
            )
        };
        let batch = Arc::new(Batch {
            work: work_pointer,
            progress: Mutex::default(),
            finished: Condvar::new(),
        });
        lock(&self.shared.state)
            .requests
            .extend(std::iter::repeat_n(&batch, helpers).cloned());
        for _ in 0..helpers {
            self.shared.requested.notify_one();
        }
        let requested = Requested {
            shared: &self.shared,
            batch: &batch,
            helpers,
        };
        work();
        drop(requested);
        let panic = lock(&batch.progress).panic.take();
        if let Some(panic) = panic {
            resume_unwind(panic);
        }
    }

    #[cfg(test)]
    pub(crate) fn threads(&self) -> usize {
        self.threads
    }
}

impl Drop for BatchPool {
    fn drop(&mut self) {
        lock(&self.shared.state).closed = true;
        self.shared.requested.notify_all();
    }
}

/// A batch's requests for threads. Dropping it withdraws the requests no
/// thread has taken and waits for the threads that took one, also when the
/// caller's own work panics.
struct Requested<'a> {
    shared: &'a Shared,
    batch: &'a Arc<Batch>,
    helpers: usize,
}

impl Drop for Requested<'_> {
    fn drop(&mut self) {
        let taken = {
            let mut state = lock(&self.shared.state);
            let before = state.requests.len();
            state
                .requests
                .retain(|request| !Arc::ptr_eq(request, self.batch));
            self.helpers - (before - state.requests.len())
        };
        let mut progress = lock(&self.batch.progress);
        while progress.finished < taken {
            progress = self
                .batch
                .finished
                .wait(progress)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

fn serve(shared: &Shared) {
    let mut state = lock(&shared.state);
    loop {
        if let Some(batch) = state.requests.pop_front() {
            drop(state);
            batch.help();
            drop(batch);
            state = lock(&shared.state);
        } else if state.closed {
            return;
        } else {
            state = shared
                .requested
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl Batch {
    fn help(&self) {
        // SAFETY: this thread took one of the batch's requests, so `run` is
        // still waiting for it and the closure `work` points at is alive.
        let outcome = catch_unwind(AssertUnwindSafe(|| unsafe { (*self.work)() }));
        let mut progress = lock(&self.progress);
        // Keep the first panic. A later one is dropped only after this
        // thread has reported: dropping it runs the payload's own code,
        // which could panic while the lock is held and before `run` learns
        // that this thread is done.
        let later = match outcome {
            Err(panic) if progress.panic.is_none() => {
                progress.panic = Some(panic);
                None
            }
            outcome => outcome.err(),
        };
        // `run` may return as soon as the lock is released; nothing after
        // this touches the caller's work.
        progress.finished += 1;
        self.finished.notify_one();
        drop(progress);
        drop(later);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::AtomicBool;
    use std::thread::ThreadId;
    use std::time::Duration;

    /// Wait until `count` calls have arrived, so that a batch finishes only
    /// if that many of its shares run at once.
    struct Together {
        arrived: Mutex<usize>,
        changed: Condvar,
    }

    impl Together {
        fn new() -> Self {
            Self {
                arrived: Mutex::new(0),
                changed: Condvar::new(),
            }
        }

        fn meet(&self, count: usize) -> bool {
            let mut arrived = self.arrived.lock().unwrap();
            *arrived += 1;
            self.changed.notify_all();
            let (_arrived, waited) = self
                .changed
                .wait_timeout_while(arrived, Duration::from_secs(30), |arrived| *arrived < count)
                .unwrap();
            !waited.timed_out()
        }
    }

    fn queued(pool: &BatchPool) -> usize {
        lock(&pool.shared.state).requests.len()
    }

    #[test]
    fn shares_keep_their_order_and_borrow_from_the_caller() {
        let pool = BatchPool::new("syq-test-pool", 4).unwrap();
        let words: Vec<String> = (0..1000).map(|index| format!("word {index}")).collect();
        let shares: Vec<&[String]> = words.chunks(7).collect();
        let lengths = pool.map(&shares, |share| {
            share.iter().map(String::len).sum::<usize>()
        });
        let expected: Vec<usize> = shares
            .iter()
            .map(|share| share.iter().map(String::len).sum())
            .collect();
        assert_eq!(lengths, expected);
        assert_eq!(queued(&pool), 0);
        assert!(pool.map(&[] as &[u8], |byte| *byte).is_empty());
    }

    #[test]
    fn a_batch_uses_the_caller_and_no_more_threads_than_it_has_shares() {
        let pool = BatchPool::new("syq-test-pool", 8).unwrap();
        let caller = std::thread::current().id();
        // One share stays on the calling thread.
        assert_eq!(pool.map(&[()], |()| std::thread::current().id()), [caller]);
        // Three shares that wait for each other need three threads at once:
        // the caller and two of the pool's.
        let together = Together::new();
        let threads: Vec<(bool, ThreadId, Option<String>)> = pool.map(&[(); 3], |()| {
            let thread = std::thread::current();
            (
                together.meet(3),
                thread.id(),
                thread.name().map(str::to_owned),
            )
        });
        assert!(threads.iter().all(|(met, ..)| *met));
        let distinct: HashSet<ThreadId> = threads.iter().map(|(_, id, _)| *id).collect();
        assert_eq!(distinct.len(), 3);
        assert!(distinct.contains(&caller));
        for (_, id, name) in &threads {
            assert!(
                *id == caller
                    || name
                        .as_deref()
                        .is_some_and(|name| name.starts_with("syq-test-pool-")),
                "unexpected thread {name:?}"
            );
        }
        // More shares than threads: the caller and every pool thread but
        // one work at once, and the rest of the shares follow.
        let together = Together::new();
        assert!(pool
            .map(&[(); 40], |()| together.meet(8))
            .into_iter()
            .all(|met| met));
        assert_eq!(queued(&pool), 0);
    }

    #[test]
    fn threads_are_reused_across_batches() {
        let pool = BatchPool::new("syq-test-pool", 4).unwrap();
        let caller = std::thread::current().id();
        let mut threads = HashSet::new();
        // Thread IDs are never reused, so threads started for each batch
        // would exceed the pool's size within a few batches.
        for _ in 0..20 {
            let together = Together::new();
            threads.extend(pool.map(&[(); 4], |()| {
                assert!(together.meet(4));
                std::thread::current().id()
            }));
        }
        threads.remove(&caller);
        assert!(!threads.is_empty() && threads.len() <= pool.threads());
    }

    #[test]
    fn a_panic_on_a_pool_thread_reaches_the_caller_and_the_pool_stays_usable() {
        let pool = BatchPool::new("syq-test-pool", 4).unwrap();
        let caller = std::thread::current().id();
        let together = Together::new();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            pool.map(&[(); 4], |()| {
                assert!(together.meet(4));
                if std::thread::current().id() != caller {
                    std::panic::panic_any("pool test panic");
                }
            })
        }))
        .expect_err("the panic must reach the caller");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"pool test panic"));
        assert_eq!(queued(&pool), 0);
        let together = Together::new();
        assert!(pool
            .map(&[(); 4], |()| together.meet(4))
            .into_iter()
            .all(|met| met));
    }

    #[test]
    fn a_panic_on_the_caller_waits_for_the_pool_threads() {
        let pool = BatchPool::new("syq-test-pool", 2).unwrap();
        let caller = std::thread::current().id();
        let together = Together::new();
        let finished = AtomicBool::new(false);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            pool.map(&[(); 2], |()| {
                assert!(together.meet(2));
                if std::thread::current().id() == caller {
                    std::panic::panic_any("caller test panic");
                }
                // The borrowed flag must still be alive when this is set.
                std::thread::sleep(Duration::from_millis(50));
                finished.store(true, Ordering::SeqCst);
            })
        }))
        .expect_err("the panic must reach the caller");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"caller test panic"));
        assert!(finished.load(Ordering::SeqCst));
    }

    #[test]
    fn a_share_may_start_a_batch_of_its_own() {
        let pool = BatchPool::new("syq-test-pool", 2).unwrap();
        let sums = pool.map(&[10usize, 20, 30, 40], |&base| {
            pool.map(&[1usize, 2, 3], |&offset| base + offset)
                .into_iter()
                .sum::<usize>()
        });
        assert_eq!(sums, [36, 66, 96, 126]);
    }

    #[test]
    fn a_batch_does_not_wait_for_busy_pool_threads() {
        let pool = BatchPool::new("syq-test-pool", 2).unwrap();
        let together = Together::new();
        let release = (Mutex::new(false), Condvar::new());
        std::thread::scope(|scope| {
            // Two other callers hold both pool threads: each batch of two
            // shares runs on its caller and one pool thread, and all four
            // wait until released.
            let hold = || {
                pool.map(&[(); 2], |()| {
                    assert!(together.meet(4));
                    let (released, changed) = &release;
                    let released = lock(released);
                    let (_released, waited) = changed
                        .wait_timeout_while(released, Duration::from_secs(30), |released| {
                            !*released
                        })
                        .unwrap();
                    assert!(!waited.timed_out());
                })
            };
            let busy = [scope.spawn(hold), scope.spawn(hold)];
            let arrived = lock(&together.arrived);
            let (arrived, waited) = together
                .changed
                .wait_timeout_while(arrived, Duration::from_secs(30), |arrived| *arrived < 4)
                .unwrap();
            assert!(!waited.timed_out(), "only {} of 4 shares started", *arrived);
            drop(arrived);
            // This batch's requests find no thread free: the caller takes
            // every share, withdraws the requests and returns at once.
            let caller = std::thread::current().id();
            let threads = pool.map(&[(); 10], |()| std::thread::current().id());
            assert!(threads.iter().all(|thread| *thread == caller));
            assert_eq!(queued(&pool), 0);
            *lock(&release.0) = true;
            release.1.notify_all();
            for busy in busy {
                busy.join().unwrap();
            }
        });
    }

    #[test]
    fn panics_on_the_caller_and_a_pool_thread_raise_one_of_them() {
        let pool = BatchPool::new("syq-test-pool", 2).unwrap();
        let together = Together::new();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            pool.map(&[(); 2], |()| {
                assert!(together.meet(2));
                std::panic::panic_any("both panic");
            })
        }))
        .expect_err("the panic must reach the caller");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"both panic"));
        assert_eq!(queued(&pool), 0);
        assert_eq!(pool.map(&[1, 2, 3], |n| n * 2), [2, 4, 6]);
    }

    /// A panic payload whose drop finishes only once the batch has returned.
    struct WaitsForTheCaller {
        returned: Arc<(Mutex<bool>, Condvar)>,
        timed_out: Arc<AtomicBool>,
    }

    impl Drop for WaitsForTheCaller {
        fn drop(&mut self) {
            let (returned, changed) = &*self.returned;
            let (_returned, waited) = changed
                .wait_timeout_while(lock(returned), Duration::from_secs(10), |returned| {
                    !*returned
                })
                .unwrap();
            if waited.timed_out() {
                self.timed_out.store(true, Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn a_second_panic_is_dropped_after_its_thread_has_reported() {
        let pool = BatchPool::new("syq-test-pool", 3).unwrap();
        let caller = std::thread::current().id();
        let together = Together::new();
        let returned = Arc::new((Mutex::new(false), Condvar::new()));
        let timed_out = Arc::new(AtomicBool::new(false));
        // Both pool threads panic. The first payload goes to the caller; the
        // second is dropped on its pool thread, and its drop waits for the
        // batch to return. Dropped before the thread reports that it is done,
        // it would wait for a batch that waits for it.
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            pool.map(&[(); 3], |()| {
                assert!(together.meet(3));
                if std::thread::current().id() != caller {
                    std::panic::panic_any(WaitsForTheCaller {
                        returned: returned.clone(),
                        timed_out: timed_out.clone(),
                    });
                }
            })
        }));
        *lock(&returned.0) = true;
        returned.1.notify_all();
        let panic = outcome.expect_err("the panic must reach the caller");
        assert!(panic.is::<WaitsForTheCaller>());
        drop(panic);
        // Wait for the second payload's drop: the pool's threads hold the
        // only other references to the flags.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while Arc::strong_count(&timed_out) > 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "the second payload was not dropped"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!timed_out.load(Ordering::SeqCst));
    }

    /// Many threads ask at once, with batches of every size around the
    /// pool's, and some shares panic on the caller or on a pool thread. No
    /// share may still be running once its batch has returned or unwound.
    #[test]
    fn no_share_outlives_its_batch_with_many_callers_and_panics() {
        const CALLERS: usize = 8;
        const ROUNDS: usize = 200;
        let pool = BatchPool::new("syq-test-pool", 4).unwrap();
        let returned: Vec<AtomicBool> = (0..CALLERS * ROUNDS)
            .map(|_| AtomicBool::new(false))
            .collect();
        let late = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for caller in 0..CALLERS {
                let (pool, returned, late) = (&pool, &returned, &late);
                scope.spawn(move || {
                    for round in 0..ROUNDS {
                        let batch = caller * ROUNDS + round;
                        let shares: Vec<usize> = (0..1 + batch % 9).collect();
                        let panicking = batch.is_multiple_of(5).then_some(batch % shares.len());
                        let outcome = catch_unwind(AssertUnwindSafe(|| {
                            pool.map(&shares, |&share| {
                                if share % 2 == 1 {
                                    std::thread::sleep(Duration::from_micros(200));
                                }
                                if returned[batch].load(Ordering::SeqCst) {
                                    late.fetch_add(1, Ordering::SeqCst);
                                }
                                if panicking == Some(share) {
                                    std::panic::panic_any(batch);
                                }
                                share * 3
                            })
                        }));
                        returned[batch].store(true, Ordering::SeqCst);
                        match (outcome, panicking) {
                            (Ok(tripled), None) => {
                                assert_eq!(
                                    tripled,
                                    shares.iter().map(|share| share * 3).collect::<Vec<_>>()
                                )
                            }
                            (Err(panic), Some(_)) => {
                                assert_eq!(panic.downcast_ref::<usize>(), Some(&batch))
                            }
                            (outcome, _) => {
                                panic!("batch {batch}: unexpected outcome {:?}", outcome.is_ok())
                            }
                        }
                    }
                });
            }
        });
        // Shares still running after their batch returned would arrive here
        // late; wait briefly so that they would be counted.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(late.load(Ordering::SeqCst), 0);
        assert_eq!(queued(&pool), 0);
    }

    #[test]
    fn dropping_the_pool_stops_its_threads() {
        let pool = BatchPool::new("syq-test-pool", 3).unwrap();
        assert_eq!(pool.map(&[1, 2, 3, 4], |n| n + 1), [2, 3, 4, 5]);
        let shared = Arc::downgrade(&pool.shared);
        drop(pool);
        // Each thread holds the shared state until it returns.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while shared.upgrade().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "pool threads did not exit"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn concurrent_callers_share_the_pool() {
        let pool = BatchPool::new("syq-test-pool", 3).unwrap();
        std::thread::scope(|scope| {
            for caller in 0..8usize {
                let pool = &pool;
                scope.spawn(move || {
                    for round in 0..50usize {
                        let items: Vec<usize> = (0..17).map(|item| item + caller + round).collect();
                        let doubled = pool.map(&items, |item| item * 2);
                        let expected: Vec<usize> = items.iter().map(|item| item * 2).collect();
                        assert_eq!(doubled, expected);
                    }
                });
            }
        });
        assert_eq!(queued(&pool), 0);
    }
}
