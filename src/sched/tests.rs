use super::*;

pub(crate) fn test_job(name: &[u8], size: u64) -> FileJob {
    FileJob {
        data: FileJobData {
            src: name.to_vec(),
            source: RegisteredPath::new(serde_json::from_str("0").unwrap(), name.to_vec()).unwrap(),
            dst: [name, b"-dst"].concat(),
            rel: String::from_utf8(name.to_vec()).unwrap(),
            rel_bytes: name.to_vec(),
            src_rel: None,
            entry: Entry {
                path: Vec::new(),
                kind: crate::proto::Kind::File,
                size,
                mtime: 0,
                mtime_nsec: 0,
                mode: 0o644,
                uid: 0,
                gid: 0,
                rdev: 0,
                dev: 1,
                ino: 1,
                ctime: 0,
                ctime_nsec: 0,
                link: None,
            },
            target_condition: crate::proto::TargetCondition::Any,
            container_guard: None,
            attempt: 0,
            done: Arc::new(AtomicU64::new(0)),
            inplace: false,
        },
        dst_entry: None,
    }
}

#[test]
fn equal_size_files_spread_across_directory_groups() {
    let sched = Sched::new(64, 128);
    // Model a scan of sixteen directories, sixteen files in each.
    for _ in 0..256 {
        sched.push_file(test_job(b"source", 4096));
    }
    sched.scan_done();
    let mut directories = HashSet::new();
    for _ in 0..16 {
        let Item::File(idx) = sched.next() else {
            panic!("missing file")
        };
        directories.insert(idx / 16);
        sched.ranges_ready(idx, Vec::new());
    }
    assert_eq!(
        directories.len(),
        16,
        "workers should start in distinct directory groups"
    );
}

#[test]
fn reordered_batches_preserve_size_priority_limits_and_every_index() {
    let sched = Sched::new(64, 128);
    // Include zero-length files, repeated sizes, and a non-power-of-two count.
    let sizes: Vec<_> = (0..257).map(|i| (i % 7) * 1024).collect();
    for &size in &sizes {
        sched.push_file(test_job(b"source", size));
    }
    sched.scan_done();
    assert!(sched.take_small(4096, 10, u64::MAX).is_empty());
    let mut seen = HashSet::new();
    let mut previous = u64::MAX;
    while let Item::File(first) = sched.next() {
        let mut batch = vec![first];
        let extra = sched.take_small(sizes[first], 11, 8192);
        assert!(extra.len() <= 11);
        assert!(extra.iter().map(|&idx| sizes[idx]).sum::<u64>() <= 8192);
        batch.extend(extra);
        for idx in batch {
            assert!(seen.insert(idx), "duplicate job {idx}");
            assert!(
                sizes[idx] <= previous,
                "file size must remain the primary priority"
            );
            previous = sizes[idx];
            sched.ranges_ready(idx, Vec::new());
        }
    }
    assert_eq!(seen.len(), sizes.len());
    assert!(sched.finished());
}

#[test]
fn requeued_files_keep_their_identity_with_concurrent_batch_consumers() {
    let sched = Arc::new(Sched::new(64, 128));
    for idx in 0..257 {
        let mut job = test_job(b"source", 4096);
        job.done.store(idx as u64, Relaxed);
        job.rel = idx.to_string();
        sched.push_file(job);
    }
    sched.scan_done();
    let seen = Mutex::new(Vec::new());
    let retried = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                while let Item::File(first) = sched.next() {
                    let mut batch = vec![first];
                    batch.extend(sched.take_small(4096, 3, 3 * 4096));
                    for idx in batch {
                        let jobs = sched.jobs.lock().unwrap();
                        assert_eq!(jobs[idx].rel, idx.to_string());
                        assert_eq!(jobs[idx].done.load(Relaxed), idx as u64);
                        drop(jobs);
                        seen.lock().unwrap().push(idx);
                        if idx == 17 && !retried.swap(true, Relaxed) {
                            sched.requeue(idx);
                        }
                        sched.ranges_ready(idx, Vec::new());
                    }
                }
            });
        }
    });
    let mut seen = seen.into_inner().unwrap();
    seen.sort_unstable();
    let mut expected: Vec<_> = (0..257).chain(std::iter::once(17)).collect();
    expected.sort_unstable();
    assert_eq!(seen, expected);
    assert!(sched.finished());
}

#[test]
fn destination_snapshots_share_and_preserve_replaced_versions() {
    // Worker batches should carry shared handles, not space for owned metadata.
    assert!(size_of::<WorkerJob>() <= 4 * size_of::<usize>());
    let mut jobs = Jobs::default();
    let mut job = test_job(b"source", 7);
    let mut original = job.entry.clone();
    original.path = b"destination/original".to_vec();
    job.dst_entry = Some(original.clone());
    jobs.push(job);
    let first = jobs.snapshot(0);
    let second = jobs.snapshot(0);
    let (Some(a), Some(b)) = (&first.dst_entry, &second.dst_entry) else {
        panic!("destination was deep-cloned");
    };
    assert!(Arc::ptr_eq(a, b));
    assert!(std::ptr::eq(a.as_ref(), jobs.destination(0).unwrap()));
    let old = Arc::downgrade(a);
    let mut replacement = original;
    replacement.path = b"destination/replacement".to_vec();
    replacement.size = 11;
    jobs.set_destination(0, replacement);
    let latest = jobs.snapshot(0);
    assert_eq!(first.dst_entry.as_ref().unwrap().size, 7);
    assert_eq!(
        first.dst_entry.as_ref().unwrap().path,
        b"destination/original"
    );
    assert_eq!(latest.dst_entry.as_ref().unwrap().size, 11);
    jobs.release();
    assert_eq!(
        latest.dst_entry.as_ref().unwrap().path,
        b"destination/replacement"
    );
    drop(first);
    assert!(old.upgrade().is_some());
    drop(second);
    assert!(old.upgrade().is_none());
}

#[test]
fn chunks_allow_append_retry_and_release_with_live_snapshots() {
    let mut jobs = Jobs::default();
    jobs.push(test_job(b"source", 7));
    let first = jobs.snapshot(0);
    let SnapshotData::Chunk { slots, .. } = &first.data else {
        panic!("expected chunk");
    };
    let owner = Arc::downgrade(slots);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..10_000 {
                assert_eq!(first.entry.size, 7);
            }
        });
        for _ in 0..(2 * JOBS_PER_CHUNK) {
            jobs.push(test_job(b"source", 9));
        }
    });
    let second = jobs.snapshot(1);
    let SnapshotData::Chunk {
        slots: second_slots,
        ..
    } = &second.data
    else {
        panic!("expected chunk");
    };
    assert!(Arc::ptr_eq(slots, second_slots));
    assert!(jobs.retries.is_empty());
    assert_eq!(jobs.chunks.len(), 3);
    jobs[0].entry.size = 11;
    let retry = jobs.snapshot(0);
    jobs[0].entry.size = 13;
    assert_eq!(first.entry.size, 7);
    assert_eq!(second.entry.size, 9);
    assert_eq!(retry.entry.size, 11);
    assert_eq!(jobs[0].entry.size, 13);
    jobs.release();
    assert_eq!(first.entry.size, 7);
    assert_eq!(retry.entry.size, 11);
    drop(first);
    assert!(owner.upgrade().is_some());
    drop(second);
    assert!(owner.upgrade().is_none());
}

#[test]
fn jobs_preserve_indexes_snapshots_retries_and_release_capacity() {
    let dir = crate::test_support::tempdir().unwrap();
    let path = dir.path().join("file");
    std::fs::write(&path, b"payload").unwrap();
    let entry = crate::fsops::lstat_entry(b"file".to_vec(), &path).unwrap();
    let sched = Sched::new(4, 8);
    for i in 0..(2 * JOBS_PER_CHUNK + 1) {
        let idx = sched.push_file(FileJob {
            dst_entry: (i % 2 == 0).then(|| entry.clone()),
            data: FileJobData {
                src: b"src/file".to_vec(),
                source: RegisteredPath::new(serde_json::from_str("0").unwrap(), b"file".to_vec())
                    .unwrap(),
                dst: b"dst/file".to_vec(),
                rel: i.to_string(),
                entry: entry.clone(),
                target_condition: crate::proto::TargetCondition::Any,
                container_guard: None,
                attempt: 0,
                done: Arc::new(AtomicU64::new(0)),
                inplace: false,
                rel_bytes: i.to_string().into_bytes(),
                src_rel: None,
            },
        });
        assert_eq!(idx, i);
    }
    let mut jobs = sched.jobs.lock().unwrap();
    assert_eq!(jobs.len(), 2 * JOBS_PER_CHUNK + 1);
    for i in 0..jobs.len() {
        assert_eq!(jobs[i].rel, i.to_string());
        assert_eq!(jobs.destination(i).is_some(), i % 2 == 0);
    }
    let before = jobs.snapshot(1);
    jobs[1].entry.size = 99;
    jobs[1].attempt = 1;
    jobs[1].inplace = true;
    jobs[1].done.store(3, Relaxed);
    jobs.set_destination(1, entry.clone());
    let retry = jobs.snapshot(1);
    assert_eq!(before.entry.size, 7);
    assert_eq!(before.attempt, 0);
    assert!(!before.inplace);
    assert!(before.dst_entry.is_none());
    assert_eq!(retry.entry.size, 99);
    assert_eq!(retry.attempt, 1);
    assert!(retry.inplace);
    assert_eq!(retry.dst_entry.unwrap().size, 7);
    assert_eq!(before.done.load(Relaxed), 3);
    drop(jobs);
    assert_eq!(
        sched.inner.lock().unwrap().files.bytes,
        7 * (2 * JOBS_PER_CHUNK as u64 + 1)
    );
    sched.clear_finished_work();
    assert_eq!(sched.inner.lock().unwrap().files.bytes, 0);
    let jobs = sched.jobs.lock().unwrap();
    assert!(jobs.is_empty());
    assert_eq!(jobs.chunks.capacity(), 0);
    assert_eq!(jobs.destinations.capacity(), 0);
    assert_eq!(jobs.retries.capacity(), 0);
}

#[test]
fn failed_or_aborted_ranges_never_elect_a_publisher() {
    for abort in [false, true] {
        let sched = Sched::new(4, 8);
        sched.inner.lock().unwrap().probing = 1;
        let first = sched.ranges_ready(0, vec![(0, 4), (4, 8)]).unwrap();
        sched.scan_done();
        let Item::Range(last) = sched.next() else {
            panic!("missing range")
        };
        if abort {
            sched.abort();
        } else {
            assert!(sched.fail_file(0));
            assert!(!sched.fail_file(0), "report each failed file once");
        }
        assert!(!sched.range_done(&first));
        assert!(!sched.range_done(&last));
    }
}

#[test]
fn range_work_checks_cancellation_without_consuming_queued_ranges() {
    for abort in [false, true] {
        let sched = Sched::new(512, 8192);
        sched.inner.lock().unwrap().probing = 1;
        let primary = sched.ranges_ready(0, vec![(0, 512), (1024, 1536)]).unwrap();
        assert!(matches!(sched.range_work(0, None), RangeWork::Ready(None)));
        assert_eq!(sched.inner.lock().unwrap().ranges.len(), 1);
        if abort {
            sched.abort();
        } else {
            sched.fail_file(0);
        }
        for limit in [None, Some(512)] {
            assert!(matches!(sched.range_work(0, limit), RangeWork::Cancelled));
            assert_eq!(sched.inner.lock().unwrap().ranges.len(), 1);
        }
        assert!(!sched.range_done(&primary));
    }
}

#[test]
fn short_range_claim_preserves_other_files_limits_and_shares() {
    let sched = Sched::new(512, 8192);
    sched.inner.lock().unwrap().probing = 2;
    let first = sched
        .ranges_ready(0, vec![(0, 512), (1024, 1536), (2048, 2560), (4096, 8192)])
        .unwrap();
    let other = sched.ranges_ready(1, vec![(0, 512), (1024, 1536)]).unwrap();
    assert!(sched.take_short_range(0, 0).is_none());
    sched.inner.lock().unwrap().waiting_workers = 4;
    assert!(sched.take_short_range(0, 512).is_none());
    sched.inner.lock().unwrap().waiting_workers = 3;
    let extra = sched.take_short_range(0, 512).unwrap();
    assert_eq!(extra.lock().unwrap().pos, 1024);
    assert_eq!(sched.inner.lock().unwrap().outstanding[&0], 4);
    assert!(!sched.range_done(&extra));
    assert!(sched.take_short_range(0, 512).is_none());
    sched.inner.lock().unwrap().waiting_workers = 0;
    let extra = sched.take_short_range(0, 512).unwrap();
    assert!(!sched.range_done(&extra));
    assert!(sched.take_short_range(0, 512).is_none());
    sched.release_rest(&first);
    assert!(!sched.range_done(&first));
    assert!(!sched.range_done(&other));
    let inner = sched.inner.lock().unwrap();
    assert!(inner.ranges.contains(&(1, 1024, 1536)));
    assert!(inner.ranges.contains(&(0, 4096, 8192)));
    assert!(inner.ranges.contains(&(0, 0, 512)));
    drop(inner);
    sched.fail_file(0);
    assert!(sched.take_short_range(0, 512).is_none());
    sched.abort();
    assert!(sched.take_short_range(1, 512).is_none());
}

#[test]
fn short_range_tail_is_available_while_other_workers_are_busy() {
    let sched = Sched::new(512, 8192);
    sched.inner.lock().unwrap().probing = 2;
    let primary = sched.ranges_ready(0, vec![(0, 512), (1024, 1536)]).unwrap();
    let busy_peer = sched.ranges_ready(1, vec![(0, 8192)]).unwrap();
    // Both workers own work; the sole queued range can fill the first
    // worker's pipeline instead of waiting for it to drain and call next.
    let extra = sched.take_short_range(0, 512).unwrap();
    assert_eq!(extra.lock().unwrap().pos, 1024);
    assert!(!sched.range_done(&extra));
    assert!(sched.range_done(&primary));
    assert!(sched.range_done(&busy_peer));
}

#[test]
fn short_range_claim_leaves_a_share_for_a_waiting_worker() {
    let sched = Arc::new(Sched::new(512, 8192));
    sched.inner.lock().unwrap().probing = 1;
    let primary = sched.ranges_ready(0, vec![(0, 512)]).unwrap();
    sched.scan_done();
    let (tx, rx) = std::sync::mpsc::channel();
    let peer = {
        let sched = sched.clone();
        std::thread::spawn(move || tx.send(sched.next()).unwrap())
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let waiting = sched.inner.lock().unwrap().waiting_workers;
        if waiting == 1 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            sched.abort();
            peer.join().unwrap();
            panic!("worker did not wait for work: waiting_workers={waiting}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    {
        let mut inner = sched.inner.lock().unwrap();
        // Publish without notifying yet: the owner can claim an extra,
        // but must leave another share for the sleeping peer.
        inner.ranges.push((0, 1024, 1536));
        inner.ranges.push((0, 2048, 2560));
        *inner.outstanding.get_mut(&0).unwrap() += 2;
    }
    let extra = sched.take_short_range(0, 512).unwrap();
    assert!(sched.take_short_range(0, 512).is_none());
    sched.cv.notify_all();
    let item = rx.recv_timeout(Duration::from_secs(2));
    if item.is_err() {
        sched.abort();
    }
    peer.join().unwrap();
    let Item::Range(other) = item.expect("waiting worker must receive its share") else {
        panic!("waiting worker exited without a range")
    };
    assert_eq!(sched.inner.lock().unwrap().waiting_workers, 0);
    assert_ne!(extra.lock().unwrap().pos, other.lock().unwrap().pos);
    assert!(!sched.range_done(&extra));
    assert!(!sched.range_done(&other));
    assert!(sched.range_done(&primary));
    assert!(sched.finished());
}

#[test]
fn range_queue_updates_file_maxima_and_preserves_equal_length_order() {
    let mut queue = RangeQueue::default();
    queue.extend(0, &[(0, 512), (1024, 3072)]);
    // Extending an existing file replaces its maximum exactly once;
    // empty batches must not create an empty per-file index.
    queue.extend(0, &[(4096, 6144)]);
    queue.extend(3, &[]);
    queue.push((1, 0, 2048));
    queue.push((2, 0, 512));
    assert_eq!(queue.len(), 5);
    assert_eq!(queue.bytes, 7168);
    assert_eq!(queue.largest.len(), 3);
    assert_eq!(queue.iter().count(), 5);
    assert_eq!(queue.pop(), Some((1, 0, 2048)));
    assert_eq!(queue.take_short(0, 512), Some((0, 0, 512)));
    assert_eq!(queue.take_short(2, 512), Some((2, 0, 512)));
    assert_eq!(queue.largest.len(), 1);
    assert_eq!(queue.bytes, 4096);
    assert_eq!(queue.take_short(0, 512), None);
    queue.push((0, 8192, 12288));
    queue.push((1, 8192, 10240));
    assert_eq!(queue.pop(), Some((0, 8192, 12288)));
    assert_eq!(queue.pop(), Some((1, 8192, 10240)));
    assert_eq!(queue.pop(), Some((0, 4096, 6144)));
    assert_eq!(queue.pop(), Some((0, 1024, 3072)));
    assert!(queue.is_empty());
    assert!(queue.by_file.is_empty());
    assert!(queue.largest.is_empty());
    assert_eq!(queue.bytes, 0);
}

#[test]
fn range_queue_indexes_agree_after_interleaved_claims() {
    let mut queue = RangeQueue::default();
    for idx in 0..200 {
        let ranges: Vec<_> = (0..1000)
            .map(|i| (i * 8192, i * 8192 + 512 * (1 + i % 8)))
            .collect();
        queue.extend(idx, &ranges);
    }
    assert_eq!(queue.len(), 200_000);
    assert_eq!(
        queue.bytes,
        queue.iter().map(|(_, o, e)| e - o).sum::<u64>()
    );
    assert_eq!(queue.largest.len(), 200);
    for idx in (0..200).rev() {
        for _ in 0..125 {
            let (_, off, end) = queue.take_short(idx, 512).unwrap();
            assert_eq!(end - off, 512);
        }
        assert!(queue.take_short(idx, 512).is_none());
    }
    let mut remaining: u64 = queue.iter().map(|(_, o, e)| e - o).sum();
    assert_eq!(queue.bytes, remaining);
    let mut previous = u64::MAX;
    while let Some((_, off, end)) = queue.pop() {
        remaining -= end - off;
        assert_eq!(queue.bytes, remaining);
        assert!(end - off <= previous);
        previous = end - off;
    }
    assert!(queue.by_file.is_empty());
}

#[test]
fn initial_ranges_preserve_coverage_alignment_and_split_floor() {
    for size in [
        1,
        31 << 20,
        32 << 20,
        63 << 20,
        64 << 20,
        256 << 20,
        (257 << 20) + 7,
    ] {
        for workers in [0, 1, 2, 8, 16] {
            let sched = Sched::new(4 << 20, 32 << 20);
            sched.inner.lock().unwrap().probing = 1;
            sched.reserve_initial_ranges(workers);
            let first = sched.ranges_ready(0, vec![(0, size)]).unwrap();
            let mut spans = {
                let r = first.lock().unwrap();
                vec![(r.pos, r.end)]
            };
            let inner = sched.inner.lock().unwrap();
            spans.extend(inner.ranges.iter().map(|(_, off, end)| (off, end)));
            spans.sort_unstable();
            let count = workers.min((size / sched.min_split) as usize).max(1);
            assert_eq!(spans.len(), count);
            assert_eq!(inner.outstanding[&0] as usize, count);
            let mut end = 0;
            for (off, limit) in spans {
                assert_eq!(off, end);
                assert_eq!(off % sched.block, 0);
                assert!(count == 1 || limit - off >= sched.min_split);
                end = limit;
            }
            assert_eq!(end, size);
        }
    }
}

#[test]
fn initial_ranges_remain_available_after_the_first_worker_advances() {
    let sched = Sched::new(4 << 20, 32 << 20);
    sched.inner.lock().unwrap().probing = 1;
    sched.reserve_initial_ranges(8);
    let first = sched.ranges_ready(0, vec![(0, 256 << 20)]).unwrap();
    first.lock().unwrap().pos += 4 << 20;
    sched.scan_done();
    for _ in 1..8 {
        let Item::Range(range) = sched.next() else {
            panic!("missing reserved range")
        };
        assert!(!sched.range_done(&range));
    }
    assert!(sched.range_done(&first));
    assert!(matches!(sched.next(), Item::Exit));
}

#[test]
fn initial_ranges_leave_diff_ranges_and_other_files_alone() {
    for queued_file in [false, true] {
        let sched = Sched::new(4 << 20, 32 << 20);
        {
            let mut inner = sched.inner.lock().unwrap();
            inner.probing = 1;
            if queued_file {
                inner
                    .files
                    .push_test((64 << 20, Reverse(FileOrder::new(1))));
            }
        }
        sched.reserve_initial_ranges(8);
        let spans = if queued_file {
            vec![(0, 256 << 20)]
        } else {
            vec![(0, 64 << 20), (128 << 20, 256 << 20)]
        };
        let first = sched.ranges_ready(0, spans.clone()).unwrap();
        let range = first.lock().unwrap();
        assert_eq!((range.pos, range.end), spans[0]);
        let inner = sched.inner.lock().unwrap();
        assert_eq!(inner.outstanding[&0] as usize, spans.len());
        assert_eq!(sched.initial_range_workers.load(Relaxed), 0);
    }
}

#[test]
fn tuning_split_threshold_controls_when_idle_workers_can_help() {
    for (threshold, can_split) in [(8 << 20, true), (32 << 20, false)] {
        let tuning: crate::transfer_tuning::TransferTuning =
            format!("split-min-size={threshold}").parse().unwrap();
        let sched = Sched::new(4 << 20, tuning.split_min_size(4 << 20));
        let mut inner = sched.inner.lock().unwrap();
        inner.inflight.push(Arc::new(Mutex::new(RangeState {
            idx: 0,
            pos: 0,
            end: 48 << 20,
        })));
        let stolen = sched.steal(&mut inner);
        assert_eq!(stolen.is_some(), can_split);
        if let Some(stolen) = stolen {
            let stolen = stolen.lock().unwrap();
            assert_eq!((stolen.pos, stolen.end), (24 << 20, 48 << 20));
        }
    }
}

#[test]
fn worker_exit_wakes_the_tuning_wait() {
    let sched = Arc::new(Sched::new(64, 128));
    {
        let mut inner = sched.inner.lock().unwrap();
        inner.scan_done = true;
        inner.probing = 1;
    }
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let waiter = {
        let sched = sched.clone();
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let started = std::time::Instant::now();
            sched.wait_for_tuning(Duration::from_secs(2));
            started.elapsed()
        })
    };
    started_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert!(sched.ranges_ready(0, Vec::new()).is_none());
    assert!(matches!(sched.next(), Item::Exit));

    let elapsed = waiter.join().unwrap();
    assert!(
        elapsed < Duration::from_millis(500),
        "worker exit left the tuner asleep for {elapsed:?}"
    );
}

#[test]
fn eager_connections_wait_for_a_planned_file_and_skip_empty_scans() {
    let with_file = Arc::new(Sched::new(64, 128));
    let waiter = {
        let sched = with_file.clone();
        std::thread::spawn(move || sched.wait_for_anticipated_file_work())
    };
    with_file.anticipate_file_work();
    assert!(waiter.join().unwrap());

    let empty = Arc::new(Sched::new(64, 128));
    let waiter = {
        let sched = empty.clone();
        std::thread::spawn(move || sched.wait_for_anticipated_file_work())
    };
    empty.scan_done();
    assert!(!waiter.join().unwrap());
}

#[test]
fn queued_files_wait_for_planning_and_wake_on_completion_or_abort() {
    for abort in [false, true] {
        let sched = Arc::new(Sched::new(64, 128));
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = {
            let sched = sched.clone();
            std::thread::spawn(move || tx.send(sched.next()).unwrap())
        };
        sched.anticipate_file_work();
        let idx = sched.push_file(test_job(b"source", 4096));
        sched.anticipate_file_work();
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        if abort {
            sched.abort();
        } else {
            sched.scan_done();
        }
        let item = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        if abort {
            assert!(matches!(item, Item::Exit));
        } else {
            assert!(matches!(item, Item::File(actual) if actual == idx));
        }
        worker.join().unwrap();
    }
}

#[test]
fn queued_file_bytes_follow_claims_retries_and_stolen_groups() {
    let sched = Sched::new(64, 128);
    let big = sched.push_file(test_job(b"big", 1024));
    let small = sched.push_file(test_job(b"small", 256));
    let sibling = sched.push_file(test_job(b"sibling", 256));
    sched.scan_done();
    assert!(sched.work_left_for(2, 1536, 0));
    assert!(!sched.work_left_for(2, 1537, 0));
    assert!(matches!(sched.next(), Item::File(idx) if idx == big));
    assert_eq!(sched.inner.lock().unwrap().files.bytes, 512);
    assert_eq!(sched.take_small(256, 2, 512).len(), 2);
    assert!(!sched.work_left_for(1, 1, 0));
    sched.requeue(big);
    sched.ranges_ready(big, Vec::new());
    assert!(sched.work_left_for(1, 1024, 0));
    assert!(matches!(sched.next(), Item::File(idx) if idx == big));
    sched.begin_fast_batch(1, 128);
    sched.mark_fast(2);
    let (_, handle) = sched.share_fast_groups(
        vec![(1024, big), (256, small), (256, sibling)],
        [0..1, 1..3].into(),
    );
    assert_eq!(
        sched.steal_fast_group(&mut sched.inner.lock().unwrap()),
        Some(small)
    );
    assert!(sched.work_left_for(1, 256, 0));
    assert!(!sched.work_left_for(1, 257, 0));
    assert!(matches!(sched.next(), Item::File(idx) if idx == sibling));
    sched.ranges_ready(small, Vec::new());
    sched.ranges_ready(sibling, Vec::new());
    assert_eq!(sched.finish_fast_groups(&handle), vec![true, false, false]);
    sched.complete_fast_batch(1);
    assert!(sched.finished());
    assert_eq!(sched.inner.lock().unwrap().files.bytes, 0);
}

#[test]
fn tail_gate_combines_bytes_file_credit_and_duration_requirement() {
    let sched = Sched::new(64, 128);
    {
        let mut inner = sched.inner.lock().unwrap();
        inner.scan_done = true;
        inner.files.push_test((100, Reverse(FileOrder::new(0))));
        inner.files.push_test((100, Reverse(FileOrder::new(1))));
    }
    assert!(sched.work_left_for(2, 1_200, 512));
    assert!(!sched.work_left_for(2, 1_300, 512));
    assert!(!sched.work_left_for(3, 1_000, 512));
}

#[test]
fn claimed_small_files_do_not_request_replacement_capacity() {
    let sched = Sched::new(64, 128);
    {
        let mut inner = sched.inner.lock().unwrap();
        inner.scan_done = true;
        inner.probing = 2;
        inner.fast_probing = 2;
        inner.fast_batches = 1;
    }
    assert!(!sched.finished());
    assert!(!sched.needs_worker_capacity());

    // A regular file probe will soon expose transferable ranges, so its
    // spare connection should warm while hashing/preparation is underway.
    sched.inner.lock().unwrap().probing += 1;
    assert!(sched.needs_worker_capacity());
    sched.inner.lock().unwrap().probing -= 1;

    sched
        .inner
        .lock()
        .unwrap()
        .files
        .push_test((100, Reverse(FileOrder::new(0))));
    assert!(sched.needs_worker_capacity());
}

#[test]
fn fast_batches_share_the_queue_across_active_workers() {
    let sched = Sched::new(4096, 8192);
    {
        let mut inner = sched.inner.lock().unwrap();
        inner.scan_done = true;
        for idx in 0..2000 {
            inner.files.push_test((4096, Reverse(FileOrder::new(idx))));
        }
    }

    assert!(matches!(sched.next(), Item::File(_)));
    let first_target = sched.begin_fast_batch(32, 128);
    assert_eq!(first_target, 63);
    let first_extra = sched.take_small(4096, first_target - 1, u64::MAX);
    sched.mark_fast(first_extra.len());
    assert_eq!(first_extra.len() + 1, 63);

    assert!(matches!(sched.next(), Item::File(_)));
    let second_target = sched.begin_fast_batch(32, 128);
    assert_eq!(second_target, 63);
}

#[test]
fn claimed_file_groups_cannot_be_stolen_or_request_spare_workers() {
    let sched = Sched::new(512, 8192);
    {
        let mut g = sched.inner.lock().unwrap();
        g.probing = 6;
        g.fast_probing = 6;
        g.fast_batches = 1;
        g.scan_done = true;
    }
    let (first, groups) = sched.share_fast_groups(
        (0..6).map(|i| (512, i)).collect(),
        [0..2, 2..4, 4..6].into(),
    );
    assert_eq!(first, 0..2);
    assert!(sched.needs_worker_capacity());
    assert_eq!(groups.lock().unwrap().claim(), Some(2..4));
    assert_eq!(groups.lock().unwrap().claim(), Some(4..6));
    assert!(!sched.needs_worker_capacity());
    assert_eq!(
        sched.steal_fast_group(&mut sched.inner.lock().unwrap()),
        None
    );
    assert_eq!(sched.finish_fast_groups(&groups), vec![true; 6]);
    sched.complete_fast_batch(6);
    assert!(sched.finished());
}

#[test]
fn single_file_group_is_not_registered_for_stealing() {
    let sched = Sched::new(512, 8192);
    let mut groups = VecDeque::new();
    groups.push_back(0..3);
    let (first, handle) = sched.share_fast_groups(vec![(512, 0), (512, 1), (512, 2)], groups);
    assert_eq!(first, 0..3);
    assert!(sched.inner.lock().unwrap().fast_groups.is_empty());
    assert!(handle.lock().unwrap().claim().is_none());
    assert_eq!(sched.finish_fast_groups(&handle), vec![true; 3]);
}

#[test]
fn retry_range_replaces_the_failed_inflight_share() {
    let sched = Sched::new(64, 128);
    let range = Arc::new(Mutex::new(RangeState {
        idx: 4,
        pos: 192,
        end: 256,
    }));
    {
        let mut inner = sched.inner.lock().unwrap();
        inner.inflight.push(range.clone());
        inner.outstanding.insert(4, 1);
    }
    sched.retry_range(&range, 128);
    let inner = sched.inner.lock().unwrap();
    assert!(inner.inflight.is_empty());
    assert_eq!(inner.ranges.iter().collect::<Vec<_>>(), vec![(4, 128, 256)]);
    assert_eq!(inner.outstanding.get(&4), Some(&1));
}

#[test]
fn retry_of_an_empty_claim_preserves_finalization() {
    let sched = Sched::new(64, 128);
    let range = Arc::new(Mutex::new(RangeState {
        idx: 5,
        pos: 256,
        end: 256,
    }));
    {
        let mut inner = sched.inner.lock().unwrap();
        inner.inflight.push(range.clone());
        inner.outstanding.insert(5, 1);
    }
    sched.retry_range(&range, 256);
    let inner = sched.inner.lock().unwrap();
    assert!(!inner.outstanding.contains_key(&5));
    assert_eq!(inner.finishes, vec![(5, false)]);
}

#[test]
fn preflight_release_runs_jobs_without_treating_an_empty_queue_as_eof() {
    let sched = Arc::new(Sched::new(64, 128));
    sched.push_file(test_job(b"first", 1));
    let (tx, rx) = std::sync::mpsc::channel();
    let worker_sched = sched.clone();
    let worker = std::thread::spawn(move || {
        while let Item::File(index) = worker_sched.next() {
            worker_sched.ranges_ready(index, Vec::new());
            tx.send(Some(index)).unwrap();
        }
        tx.send(None).unwrap();
    });
    assert!(rx
        .recv_timeout(std::time::Duration::from_millis(30))
        .is_err());
    sched.release_preflighted_work();
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
        Some(0)
    );
    assert!(!sched.finished());
    assert!(rx
        .recv_timeout(std::time::Duration::from_millis(30))
        .is_err());
    sched.push_file(test_job(b"second", 1));
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
        Some(1)
    );
    sched.scan_done();
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
        None
    );
    worker.join().unwrap();
    assert!(sched.finished());
}

#[test]
fn small_batches_keep_siblings_and_requeue_preserves_directory() {
    let sched = Sched::new(64, 128);
    for parent in ["a", "b", "c"] {
        for i in 0..8 {
            sched.push_file(test_job(format!("{parent}/{i}").as_bytes(), 128));
        }
    }
    sched.scan_done();
    let mut seen = HashSet::new();
    while let Item::File(first) = sched.next() {
        let siblings = sched.take_small_near(first, 128, 10, 3 * 128);
        assert!(siblings.len() <= 3);
        for idx in std::iter::once(first).chain(siblings) {
            assert_eq!(idx / 8, first / 8);
            assert!(seen.insert(idx));
            sched.ranges_ready(idx, Vec::new());
        }
    }
    assert_eq!(seen.len(), 24);
    sched.requeue(5);
    sched.requeue(6);
    assert!(matches!(sched.next(), Item::File(6)));
    assert_eq!(sched.take_small_near(6, 128, 10, 1024), vec![5]);
    sched.ranges_ready(5, Vec::new());
    sched.ranges_ready(6, Vec::new());
    assert!(matches!(sched.next(), Item::Exit));
}
