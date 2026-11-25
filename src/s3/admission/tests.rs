use super::*;
use crate::s3::tuning::Budget;
use std::{
    sync::atomic::{AtomicUsize, Ordering::SeqCst},
    time::Duration,
};

/// Counts the jobs in progress and the most seen at once.
#[derive(Clone, Default)]
struct Progress {
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}
impl Progress {
    fn start(&self) {
        self.peak
            .fetch_max(self.active.fetch_add(1, SeqCst) + 1, SeqCst);
    }
    fn finish(&self) {
        self.active.fetch_sub(1, SeqCst);
    }
    fn peak(&self) -> usize {
        self.peak.load(SeqCst)
    }
}

#[test]
fn objects_in_progress_are_twice_the_request_limit_within_their_ceiling() {
    let requests = Arc::new(Budget::new(None, None));
    let following = |objects| Concurrency {
        objects,
        ready: usize::MAX,
        requests: Some(requests.clone()),
    };
    assert_eq!(following(4096).limit(), 64);
    assert_eq!(following(40).limit(), 40);
    requests.set_limit(1);
    assert_eq!(following(4096).limit(), 2);
    let fixed = Concurrency {
        objects: 7,
        ready: usize::MAX,
        requests: None,
    };
    assert_eq!(fixed.limit(), 7);
}

#[tokio::test(start_paused = true)]
async fn admission_follows_the_request_limit_as_it_grows_and_shrinks() {
    let requests = Arc::new(Budget::new(None, None));
    requests.configure(crate::s3::tuning::INITIAL_REQUESTS, 4096, false);
    let progress = Progress::default();
    let (release, released) = tokio::sync::watch::channel(0usize);
    let run = {
        let (requests, progress) = (requests.clone(), progress.clone());
        tokio::spawn(async move {
            parallel(
                (0..1000).collect(),
                Concurrency {
                    objects: 300,
                    ready: usize::MAX,
                    requests: Some(requests),
                },
                |n: usize| {
                    let progress = progress.clone();
                    let mut released = released.clone();
                    async move {
                        progress.start();
                        let _ = released.wait_for(|released| *released > n).await;
                        progress.finish();
                        Ok(())
                    }
                },
            )
            .await
        })
    };
    let settle = || async {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    };
    settle().await;
    assert_eq!(progress.active.load(SeqCst), 64);
    // Growth admits more at once, without any object finishing.
    requests.set_limit(100);
    settle().await;
    assert_eq!(progress.active.load(SeqCst), 200);
    // Never past the batch's ceiling.
    requests.set_limit(1000);
    settle().await;
    assert_eq!(progress.active.load(SeqCst), 300);
    // A lower limit lets the objects in progress finish, then admits fewer.
    requests.set_limit(10);
    release.send_replace(290);
    settle().await;
    assert_eq!(progress.active.load(SeqCst), 20);
    release.send_replace(usize::MAX);
    run.await.unwrap().unwrap();
    assert_eq!(progress.peak(), 300);
    assert_eq!(progress.active.load(SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn every_job_runs_once_while_the_limit_moves() {
    let requests = Arc::new(Budget::new(None, None));
    requests.configure(crate::s3::tuning::INITIAL_REQUESTS, 4096, false);
    let seen = Arc::new((0..16384).map(|_| AtomicUsize::new(0)).collect::<Vec<_>>());
    let mover = {
        let requests = requests.clone();
        tokio::spawn(async move {
            for limit in [1, 64, 3, 200, 17].into_iter().cycle().take(40) {
                tokio::time::sleep(Duration::from_millis(3)).await;
                requests.set_limit(limit);
            }
        })
    };
    let progress = Progress::default();
    parallel(
        (0..16384).collect(),
        Concurrency {
            objects: 256,
            ready: usize::MAX,
            requests: Some(requests.clone()),
        },
        |n: usize| {
            let (seen, progress) = (seen.clone(), progress.clone());
            async move {
                progress.start();
                tokio::time::sleep(Duration::from_millis(2)).await;
                seen[n].fetch_add(1, SeqCst);
                progress.finish();
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    mover.abort();
    assert!(progress.peak() <= 256);
    assert!(seen.iter().all(|count| count.load(SeqCst) == 1));
}

#[tokio::test(start_paused = true)]
async fn a_fixed_count_keeps_that_many_objects_in_progress() {
    let progress = Progress::default();
    parallel(
        (0..100).collect(),
        Concurrency {
            objects: 7,
            ready: usize::MAX,
            requests: None,
        },
        |_: usize| {
            let progress = progress.clone();
            async move {
                progress.start();
                tokio::time::sleep(Duration::from_millis(5)).await;
                progress.finish();
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(progress.peak(), 7);
}

#[tokio::test]
async fn a_failure_stops_admission_and_drains_started_jobs() {
    let started = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    let error = parallel(
        (0..20).collect(),
        Concurrency {
            objects: 2,
            ready: usize::MAX,
            requests: None,
        },
        |n: usize| {
            let started = started.clone();
            let finished = finished.clone();
            async move {
                started.fetch_add(1, SeqCst);
                if n == 0 {
                    anyhow::bail!("fixture failure");
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                finished.fetch_add(1, SeqCst);
                Ok(())
            }
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("fixture failure"));
    assert_eq!(started.load(SeqCst), 2);
    assert_eq!(finished.load(SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn objects_that_need_no_request_do_not_wait_for_the_request_limit() {
    // Most objects are already up to date and finish without a request;
    // the others each send one, 100 ms away. The few permits go to the
    // objects that need them, and the rest pass through at once.
    let requests = Arc::new(Budget::new(Some(4), None));
    let progress = Progress::default();
    let started = tokio::time::Instant::now();
    parallel(
        (0..10_000).collect(),
        Concurrency {
            objects: 4096,
            ready: usize::MAX,
            requests: Some(requests.clone()),
        },
        |n: usize| {
            let (requests, progress) = (requests.clone(), progress.clone());
            async move {
                if n.is_multiple_of(1000) {
                    let _permit = requests.acquire().await;
                    progress.start();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    progress.finish();
                }
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(progress.peak(), 4);
    // Ten requests, four at a time: three round trips.
    assert!(started.elapsed() <= Duration::from_millis(350));
}
