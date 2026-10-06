use super::*;
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::sync::OnceLock;

type UnlinkHook = Arc<dyn Fn(&CStr) + Send + Sync>;

/// Hooks that run between the identity re-check and `unlinkat`, keyed by
/// the identity of the parent directory whose entry is about to be
/// removed. Tests register a hook for their own temporary directory so
/// concurrent tests never observe it, and the returned guard removes the
/// hook again so a later test whose temporary directory reuses the inode
/// does not fire it.
fn unlink_hooks() -> &'static Mutex<Vec<(u64, Identity, UnlinkHook)>> {
    static HOOKS: OnceLock<Mutex<Vec<(u64, Identity, UnlinkHook)>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(Vec::new()))
}

pub(super) fn before_unlink(parent: RawFd, name: &CStr) {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(parent, &mut stat) } != 0 {
        return;
    }
    let identity = identity_from_stat(&stat);
    let matching: Vec<UnlinkHook> = unlink_hooks()
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, target, _)| *target == identity)
        .map(|(_, _, hook)| hook.clone())
        .collect();
    for hook in matching {
        hook(name);
    }
}

struct UnlinkHookGuard(u64);

impl Drop for UnlinkHookGuard {
    fn drop(&mut self) {
        unlink_hooks()
            .lock()
            .unwrap()
            .retain(|(token, _, _)| *token != self.0);
    }
}

fn hook_unlinks_in(
    directory: &std::path::Path,
    hook: impl Fn(&CStr) + Send + Sync + 'static,
) -> UnlinkHookGuard {
    static NEXT_TOKEN: AtomicUsize = AtomicUsize::new(0);
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed) as u64;
    let identity = identity_from_file(&File::open(directory).unwrap()).unwrap();
    unlink_hooks()
        .lock()
        .unwrap()
        .push((token, identity, Arc::new(hook)));
    UnlinkHookGuard(token)
}

fn remove_selectors(
    base: &std::path::Path,
    selections: &[NativeRemoveSelection],
) -> Vec<NativeRemoveOutcome> {
    let mut outcomes = Vec::new();
    remove(
        Some(base.as_os_str().as_bytes()),
        None,
        selections,
        false,
        false,
        2,
        &mut |_| Ok(()),
        &mut |batch| {
            outcomes.extend(batch);
            Ok(())
        },
    )
    .unwrap();
    outcomes
}

fn selector(path: &[u8], kind: NativeRemoveKind) -> NativeRemoveSelection {
    NativeRemoveSelection {
        path: path.to_vec(),
        kind,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn removed_directory_accepts_stale_handles_and_synthetic_fuse_link_counts() {
    assert!(
        check_removed_directory(Err(io::Error::from_raw_os_error(libc::ESTALE)), || {
            panic!("a stale removed handle needs no filesystem query")
        })
        .is_ok()
    );
    assert!(
        check_removed_directory(Err(io::Error::from_raw_os_error(libc::EACCES)), || true).is_err()
    );

    let temp = crate::test_support::tempdir().unwrap();
    let path = temp.path().join("directory");
    fs::create_dir(&path).unwrap();
    let directory = File::open(&path).unwrap();
    assert!(directory.metadata().unwrap().nlink() > 0);
    // A synthetic positive count carries no evidence that the directory
    // survived. A reliable positive count still catches the rename race.
    assert!(check_removed_directory(directory.metadata(), || true).is_ok());
    assert!(check_removed_directory(directory.metadata(), || false).is_err());
    fs::remove_dir(&path).unwrap();
    assert!(check_removed_directory(directory.metadata(), || {
        panic!("a zero link count needs no filesystem query")
    })
    .is_ok());
}

#[test]
fn selector_grammar_distinguishes_unconfined_and_rooted_bases() {
    for path in [&b"."[..], b"..", b"a/../b", b"a/./b", b"a//b/"] {
        assert!(validate_selector(path, false).is_ok());
        assert!(validate_selector(path, true).is_ok());
    }
    for path in [&b"/absolute"[..], b"~", b"~/absolute"] {
        assert!(validate_selector(path, false).is_ok());
        assert!(validate_selector(path, true).is_err());
    }
    assert!(validate_selector(b"", false).is_err());
    assert!(validate_selector(b"nul\0name", false).is_err());
}

#[test]
fn repeated_directory_scans_start_at_the_beginning() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::write(temp.path().join("one"), b"1").unwrap();
    fs::write(temp.path().join("two"), b"2").unwrap();
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(temp.path())
        .unwrap();

    let mut first = read_directory(&directory).unwrap();
    let mut second = read_directory(&directory).unwrap();
    first.sort();
    second.sort();

    assert_eq!(first, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(second, first);
}

#[test]
fn repeated_directory_reads_have_independent_offsets() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::write(temp.path().join("one"), b"1").unwrap();
    fs::write(temp.path().join("two"), b"2").unwrap();
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(temp.path())
        .unwrap();
    let mut first_names = read_directory(&directory).unwrap();
    let mut second_names = read_directory(&directory).unwrap();
    first_names.sort();
    second_names.sort();

    assert_eq!(first_names, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(second_names, first_names);
}

#[test]
fn no_follow_aborts_before_any_mutation() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::create_dir(temp.path().join("real")).unwrap();
    fs::write(temp.path().join("real/file"), b"data").unwrap();
    fs::write(temp.path().join("victim"), b"data").unwrap();
    symlink("real", temp.path().join("link")).unwrap();
    let mut traces = Vec::new();
    let result = remove(
        Some(temp.path().as_os_str().as_bytes()),
        None,
        &[
            selector(b"victim", NativeRemoveKind::Any),
            selector(b"link/file", NativeRemoveKind::Any),
        ],
        false,
        false,
        2,
        &mut |messages| {
            traces.extend(messages);
            Ok(())
        },
        &mut |_| Ok(()),
    );
    assert!(result.is_err());
    assert!(temp.path().join("victim").exists());
    assert!(temp.path().join("real/file").exists());
}

#[test]
fn no_follow_unlinks_selected_symlink_and_preserves_referent() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::create_dir(temp.path().join("real")).unwrap();
    fs::write(temp.path().join("real/file"), b"data").unwrap();
    symlink("real", temp.path().join("link")).unwrap();
    let mut outcomes = Vec::new();
    remove(
        Some(temp.path().as_os_str().as_bytes()),
        None,
        &[selector(b"link", NativeRemoveKind::File)],
        false,
        false,
        2,
        &mut |_| Ok(()),
        &mut |batch| {
            outcomes.extend(batch);
            Ok(())
        },
    )
    .unwrap();

    assert!(!temp.path().join("link").is_symlink());
    assert_eq!(fs::read(temp.path().join("real/file")).unwrap(), b"data");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].disposition, NativeRemoveDisposition::Resolved);
    assert_eq!(outcomes[1].disposition, NativeRemoveDisposition::Removed);
    assert!(outcomes[1].failure.is_none());
}

#[test]
fn failed_attached_emit_cancels_pending_mutation() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::write(temp.path().join("victim"), b"data").unwrap();
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(temp.path())
        .unwrap();
    let identity = metadata_at(directory.as_raw_fd(), b"victim").unwrap();
    let (task_tx, _task_rx) = mpsc::sync_channel(1);
    let (event_tx, _event_rx) = mpsc::channel();
    let pool = Arc::new(Pool {
        sender: Mutex::new(Some(task_tx)),
        pending: Mutex::new(0),
        events: event_tx,
        dry_run: false,
        cancelled: AtomicBool::new(false),
        limit: AtomicUsize::new(1),
        active: AtomicUsize::new(0),
        parked: Mutex::new(()),
        waiting: AtomicUsize::new(0),
        wake: Condvar::new(),
    });

    let mut heartbeat = Vec::new();
    let error = crate::deletion::workers::emit(&pool, &mut heartbeat, &mut |_| {
        bail!("client disconnected")
    })
    .unwrap_err();
    assert!(error.to_string().contains("client disconnected"));
    assert!(pool.is_cancelled());

    process_task(
        &pool,
        Task::Leaf {
            selector: 0,
            name: PinnedName {
                parent: PinnedParent::File(directory),
                name: component_cstring(b"victim").unwrap(),
                identity,
            },
            _object: None,
            label: b"victim".to_vec(),
            parent: None,
        },
    );
    assert_eq!(fs::read(temp.path().join("victim")).unwrap(), b"data");
}

#[test]
fn follow_unlinks_final_symlink_and_preserves_referent() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::create_dir(temp.path().join("real")).unwrap();
    fs::write(temp.path().join("real/file"), b"data").unwrap();
    symlink("real", temp.path().join("link")).unwrap();
    remove(
        Some(temp.path().as_os_str().as_bytes()),
        None,
        &[selector(b"link", NativeRemoveKind::File)],
        true,
        false,
        2,
        &mut |_| Ok(()),
        &mut |_| Ok(()),
    )
    .unwrap();
    assert!(!temp.path().join("link").is_symlink());
    assert_eq!(fs::read(temp.path().join("real/file")).unwrap(), b"data");
}

#[test]
fn root_rejects_symlink_that_leaves_and_reenters() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("root/inside")).unwrap();
    symlink("../root/inside", temp.path().join("root/escape")).unwrap();
    let result = remove(
        None,
        Some(temp.path().join("root").as_os_str().as_bytes()),
        &[selector(b"escape", NativeRemoveKind::Contents)],
        true,
        true,
        1,
        &mut |_| Ok(()),
        &mut |_| Ok(()),
    );
    assert!(result.is_err());
}

#[test]
fn selected_directory_rename_cannot_redirect_removal_to_its_replacement() {
    let temp = crate::test_support::tempdir().unwrap();
    fs::create_dir(temp.path().join("tree")).unwrap();
    fs::write(temp.path().join("tree/old"), b"old").unwrap();
    let mut outcomes = Vec::new();
    remove(
        Some(temp.path().as_os_str().as_bytes()),
        None,
        &[selector(b"tree", NativeRemoveKind::Directory)],
        false,
        false,
        2,
        &mut |_| {
            fs::rename(temp.path().join("tree"), temp.path().join("moved"))?;
            fs::create_dir(temp.path().join("tree"))?;
            fs::write(temp.path().join("tree/replacement"), b"keep")?;
            Ok(())
        },
        &mut |batch| {
            outcomes.extend(batch);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(
        fs::read(temp.path().join("tree/replacement")).unwrap(),
        b"keep"
    );
    assert!(temp.path().join("moved").is_dir());
    assert_eq!(fs::read_dir(temp.path().join("moved")).unwrap().count(), 0);
    assert!(outcomes.iter().any(|outcome| outcome.failure.is_some()));
}

#[cfg(target_os = "linux")]
#[test]
fn directory_swapped_after_its_identity_check_is_reported_as_a_failure() {
    let temp = crate::test_support::tempdir().unwrap();
    let base = temp.path().to_path_buf();
    fs::create_dir(base.join("tree")).unwrap();
    fs::write(base.join("tree/old"), b"old").unwrap();
    let swap = base.clone();
    let _hook = hook_unlinks_in(&base, move |name| {
        if name.to_bytes() == b"tree" {
            fs::rename(swap.join("tree"), swap.join("moved")).unwrap();
            fs::create_dir(swap.join("tree")).unwrap();
        }
    });

    let outcomes = remove_selectors(&base, &[selector(b"tree", NativeRemoveKind::Directory)]);

    // The replacement was an empty directory, so rmdir removed it; POSIX
    // offers no way to refuse that. The selected directory survives, and
    // the outcome must say so instead of reporting a removal.
    assert!(base.join("moved").is_dir());
    assert!(!base.join("tree").exists());
    let failure = outcomes
        .iter()
        .find(|outcome| outcome.disposition == NativeRemoveDisposition::Failed)
        .and_then(|outcome| outcome.failure.as_ref())
        .expect("swapped directory removal is reported as a failure");
    assert!(
        failure.error.message.contains("still linked")
            && failure.class == NativeRemoveErrorClass::Conflict,
        "{failure:?}"
    );
    assert!(!outcomes.iter().any(|outcome| {
        outcome.path == b"tree" && outcome.disposition == NativeRemoveDisposition::Removed
    }));
}

#[test]
fn leaf_swapped_after_its_identity_check_removes_only_the_replacement_entry() {
    let temp = crate::test_support::tempdir().unwrap();
    let base = temp.path().to_path_buf();
    fs::write(base.join("file"), b"old").unwrap();
    fs::write(base.join("dir-file"), b"old").unwrap();
    fs::create_dir(base.join("referent")).unwrap();
    fs::write(base.join("referent/keep"), b"keep").unwrap();
    fs::create_dir(base.join("full")).unwrap();
    fs::write(base.join("full/keep"), b"keep").unwrap();
    let swap = base.clone();
    let _hook = hook_unlinks_in(&base, move |name| match name.to_bytes() {
        b"file" => {
            fs::rename(swap.join("file"), swap.join("file-moved")).unwrap();
            symlink("referent", swap.join("file")).unwrap();
        }
        b"dir-file" => {
            fs::rename(swap.join("dir-file"), swap.join("dir-file-moved")).unwrap();
            fs::rename(swap.join("full"), swap.join("dir-file")).unwrap();
        }
        _ => {}
    });

    let outcomes = remove_selectors(
        &base,
        &[
            selector(b"file", NativeRemoveKind::File),
            selector(b"dir-file", NativeRemoveKind::File),
        ],
    );

    // A symlink swapped in is unlinked as an entry and never followed.
    assert!(!base.join("file").exists());
    assert_eq!(fs::read(base.join("file-moved")).unwrap(), b"old");
    assert_eq!(fs::read(base.join("referent/keep")).unwrap(), b"keep");
    // A directory swapped in is refused by the kernel and left intact.
    assert_eq!(fs::read(base.join("dir-file/keep")).unwrap(), b"keep");
    assert_eq!(fs::read(base.join("dir-file-moved")).unwrap(), b"old");
    assert!(outcomes.iter().any(|outcome| {
        outcome.path == b"dir-file" && outcome.disposition == NativeRemoveDisposition::Failed
    }));
}

#[cfg(target_os = "linux")]
fn assert_still_linked_failure(outcomes: &[NativeRemoveOutcome], path: &[u8]) {
    let failure = outcomes
        .iter()
        .find(|outcome| {
            outcome.path == path && outcome.disposition == NativeRemoveDisposition::Failed
        })
        .and_then(|outcome| outcome.failure.as_ref())
        .expect("renamed-away directory is reported as a failure");
    assert!(
        failure.error.message.contains("still linked")
            && failure.class == NativeRemoveErrorClass::Conflict,
        "{failure:?}"
    );
    assert!(!outcomes.iter().any(|outcome| {
        outcome.path == path
            && matches!(
                outcome.disposition,
                NativeRemoveDisposition::Removed | NativeRemoveDisposition::AlreadyAbsent
            )
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn directory_renamed_away_after_its_identity_check_is_reported_as_a_failure() {
    let temp = crate::test_support::tempdir().unwrap();
    let base = temp.path().to_path_buf();
    fs::create_dir(base.join("tree")).unwrap();
    let swap = base.clone();
    let _hook = hook_unlinks_in(&base, move |name| {
        if name.to_bytes() == b"tree" {
            fs::rename(swap.join("tree"), swap.join("moved")).unwrap();
        }
    });

    let outcomes = remove_selectors(&base, &[selector(b"tree", NativeRemoveKind::Directory)]);

    assert!(base.join("moved").is_dir());
    assert_still_linked_failure(&outcomes, b"tree");
}

#[cfg(target_os = "linux")]
#[test]
fn directory_renamed_away_after_pinning_is_reported_as_a_failure() {
    let temp = crate::test_support::tempdir().unwrap();
    let base = temp.path().to_path_buf();
    fs::create_dir(base.join("tree")).unwrap();
    let mut outcomes = Vec::new();
    remove(
        Some(base.as_os_str().as_bytes()),
        None,
        &[selector(b"tree", NativeRemoveKind::Directory)],
        false,
        false,
        2,
        &mut |_| {
            fs::rename(base.join("tree"), base.join("moved"))?;
            Ok(())
        },
        &mut |batch| {
            outcomes.extend(batch);
            Ok(())
        },
    )
    .unwrap();

    assert!(base.join("moved").is_dir());
    assert_still_linked_failure(&outcomes, b"tree");
}

#[test]
fn last_task_wakes_coordinator_after_its_outcome_was_consumed() {
    for cancelled in [false, true] {
        let (task_tx, _task_rx) = mpsc::sync_channel(1);
        let (event_tx, event_rx) = mpsc::channel();
        let pool = Pool {
            sender: Mutex::new(Some(task_tx)),
            pending: Mutex::new(2),
            events: event_tx,
            dry_run: false,
            cancelled: AtomicBool::new(false),
            limit: AtomicUsize::new(1),
            active: AtomicUsize::new(0),
            parked: Mutex::new(()),
            waiting: AtomicUsize::new(0),
            wake: Condvar::new(),
        };
        pool.task_done();
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        pool.outcome(removal_outcome(
            0,
            b"file".to_vec(),
            Kind::File,
            NativeRemoveDisposition::Removed,
            Some(1),
        ));
        assert!(matches!(event_rx.try_recv(), Ok(Ok(Some(_)))));
        assert!(!pool.is_done());
        // Force the problematic ordering: the coordinator already consumed
        // the last outcome while its worker still counted as pending.
        if cancelled {
            pool.cancel();
        }
        pool.task_done();
        assert!(pool.is_done());
        assert!(matches!(event_rx.try_recv(), Ok(None)));
    }
}

#[test]
fn parked_removal_workers_wake_for_growth_cancellation_and_released_capacity() {
    for reason in ["growth", "cancel", "capacity"] {
        let (sender, _receiver) = mpsc::sync_channel(1);
        let (events, _event_rx) = mpsc::channel();
        let pool = Arc::new(Pool {
            sender: Mutex::new(Some(sender)),
            pending: Mutex::new(1),
            events,
            dry_run: false,
            cancelled: AtomicBool::new(false),
            limit: AtomicUsize::new(1),
            active: AtomicUsize::new(0),
            parked: Mutex::new(()),
            waiting: AtomicUsize::new(0),
            wake: Condvar::new(),
        });
        let mut active = Some(pool.enter());
        let (finished, result) = mpsc::channel();
        let worker_pool = pool.clone();
        let thread = std::thread::spawn(move || {
            let _active = worker_pool.enter();
            finished.send(()).unwrap();
        });
        assert!(matches!(
            result.recv_timeout(Duration::from_millis(10)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        match reason {
            "growth" => pool.set_limit(2),
            "cancel" => pool.cancel(),
            "capacity" => drop(active.take()),
            _ => unreachable!(),
        }
        result.recv_timeout(Duration::from_secs(5)).unwrap();
        thread.join().unwrap();
    }
}

#[test]
fn cancellation_within_a_sibling_batch_leaves_remaining_files_and_drains_accounting() {
    let temp = crate::test_support::tempdir().unwrap();
    let directory = File::open(temp.path()).unwrap();
    let parent = Arc::new(DirectoryJob {
        selector: 0,
        directory,
        removal: None,
        label: Vec::new(),
        parent: None,
        remaining: AtomicUsize::new(17),
        retries: AtomicUsize::new(0),
        descendant_failed: AtomicBool::new(false),
        partials_only: false,
        #[cfg(target_os = "linux")]
        leaves: Arc::new(crate::rooted::directory_gate::Gate::new(4)),
    });
    let leaves = (0..16)
        .map(|i| {
            let label = i.to_string().into_bytes();
            fs::write(temp.path().join(OsStr::from_bytes(&label)), b"data").unwrap();
            PinnedLeaf {
                selector: 0,
                name: PinnedName {
                    parent: PinnedParent::Directory(parent.clone()),
                    name: component_cstring(&label).unwrap(),
                    identity: metadata_at(parent.directory.as_raw_fd(), &label).unwrap(),
                },
                _object: None,
                label,
            }
        })
        .collect();
    let (sender, _receiver) = mpsc::sync_channel(1);
    let (events, _outcomes) = mpsc::channel();
    let pool = Arc::new(Pool {
        sender: Mutex::new(Some(sender)),
        pending: Mutex::new(0),
        events,
        dry_run: false,
        cancelled: AtomicBool::new(false),
        limit: AtomicUsize::new(4),
        active: AtomicUsize::new(0),
        parked: Mutex::new(()),
        waiting: AtomicUsize::new(0),
        wake: Condvar::new(),
    });
    let cancel = Arc::downgrade(&pool);
    let entered = AtomicUsize::new(0);
    let _hook = hook_unlinks_in(temp.path(), move |_| {
        if entered.fetch_add(1, Ordering::SeqCst) == 2 {
            cancel.upgrade().unwrap().cancel();
        }
    });
    process_task(
        &pool,
        Task::Leaves {
            parent: parent.clone(),
            leaves,
        },
    );
    // The syscall already entered may complete. Later entries must stay put,
    // and all batch children must be accounted for so shutdown cannot hang.
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 13);
    assert_eq!(parent.remaining.load(Ordering::SeqCst), 1);
}

fn scan_job(directory: &std::path::Path) -> Arc<DirectoryJob> {
    Arc::new(DirectoryJob {
        selector: 0,
        directory: File::open(directory).unwrap(),
        removal: None,
        label: Vec::new(),
        parent: None,
        remaining: AtomicUsize::new(1),
        retries: AtomicUsize::new(0),
        descendant_failed: AtomicBool::new(false),
        partials_only: false,
        #[cfg(target_os = "linux")]
        leaves: Arc::new(crate::rooted::directory_gate::Gate::new(4)),
    })
}

fn wait_for_removal_state(pool: &Pool, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let ready = ready();
    if !ready {
        eprintln!(
            "removal wait timed out: active={}, limit={}, pending={}, parked={}",
            pool.active.load(Ordering::Relaxed),
            pool.limit.load(Ordering::Relaxed),
            *pool.pending.lock().unwrap(),
            pool.waiting.load(Ordering::SeqCst),
        );
    }
    ready
}

#[test]
fn retirement_pauses_inline_scanning_before_the_directory_finishes() {
    let temp = crate::test_support::tempdir().unwrap();
    for i in 0..512 {
        fs::write(temp.path().join(i.to_string()), b"data").unwrap();
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let (events, outcomes) = mpsc::channel();
    let pool = Arc::new(Pool {
        sender: Mutex::new(Some(sender)),
        pending: Mutex::new(0),
        events,
        dry_run: false,
        cancelled: AtomicBool::new(false),
        limit: AtomicUsize::new(2),
        active: AtomicUsize::new(0),
        parked: Mutex::new(()),
        waiting: AtomicUsize::new(0),
        wake: Condvar::new(),
    });
    // Hold the one slot that will remain admitted after the reduction.
    let retained = pool.enter();
    pool.submit(Task::Scan(scan_job(temp.path())));
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let resumed = Mutex::new(resumed);
    let seen = AtomicBool::new(false);
    let _hook = hook_unlinks_in(temp.path(), move |_| {
        if !seen.swap(true, Ordering::SeqCst) {
            entered.send(()).unwrap();
            resumed.lock().unwrap().recv().unwrap();
        }
    });
    let worker_pool = pool.clone();
    let thread =
        std::thread::spawn(move || worker_loop(worker_pool, Arc::new(Mutex::new(receiver))));
    entering.recv_timeout(Duration::from_secs(5)).unwrap();
    // The only worker is inside a Scan: its first batch filled the queue,
    // so the observed unlink is the next batch's inline fallback.
    pool.set_limit(1);
    assert!(!pool.backlogged());
    resume.send(()).unwrap();
    let parked = wait_for_removal_state(&pool, || pool.waiting.load(Ordering::SeqCst) == 1);
    let remaining = fs::read_dir(temp.path()).unwrap().count();
    let measurable = pool.backlogged();
    drop(retained);
    let finished = wait_for_removal_state(&pool, || pool.is_done());
    if !finished {
        pool.cancel();
        assert!(wait_for_removal_state(&pool, || pool.is_done()));
    }
    pool.close();
    thread.join().unwrap();
    assert!(parked, "the worker did not retire within its scan");
    assert!(remaining > 0 && remaining < 512, "remaining={remaining}");
    assert!(measurable, "settled reduction must allow new measurements");
    assert!(finished);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    assert_eq!(
        outcomes
            .try_iter()
            .filter_map(Result::unwrap)
            .filter(|o| o.disposition == NativeRemoveDisposition::Removed)
            .count(),
        512,
    );
    assert_eq!(pool.active.load(Ordering::Relaxed), 0);
}

#[test]
fn reduced_scans_finish_with_idle_workers_waiting_on_the_queue() {
    let temp = crate::test_support::tempdir().unwrap();
    let (sender, receiver) = mpsc::sync_channel(2);
    let (events, outcomes) = mpsc::channel();
    let pool = Arc::new(Pool {
        sender: Mutex::new(Some(sender)),
        pending: Mutex::new(0),
        events,
        dry_run: false,
        cancelled: AtomicBool::new(false),
        limit: AtomicUsize::new(4),
        active: AtomicUsize::new(0),
        parked: Mutex::new(()),
        waiting: AtomicUsize::new(0),
        wake: Condvar::new(),
    });
    let (entered, entering) = mpsc::channel();
    let mut hooks = Vec::new();
    let mut releases = Vec::new();
    for d in 0..2 {
        let path = temp.path().join(d.to_string());
        fs::create_dir(&path).unwrap();
        for i in 0..512 {
            fs::write(path.join(i.to_string()), b"data").unwrap();
        }
        let (resume, resumed) = mpsc::channel();
        releases.push(resume);
        let resumed = Mutex::new(resumed);
        let entered = entered.clone();
        let seen = AtomicBool::new(false);
        hooks.push(hook_unlinks_in(&path, move |_| {
            if !seen.swap(true, Ordering::SeqCst) {
                entered.send(()).unwrap();
                resumed.lock().unwrap().recv().unwrap();
            }
        }));
        pool.submit(Task::Scan(scan_job(&path)));
    }
    let receiver = Arc::new(Mutex::new(receiver));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let pool = pool.clone();
            let receiver = receiver.clone();
            std::thread::spawn(move || worker_loop(pool, receiver))
        })
        .collect();
    for _ in 0..2 {
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    pool.set_limit(1);
    for release in releases {
        release.send(()).unwrap();
    }
    let finished = wait_for_removal_state(&pool, || pool.is_done());
    if !finished {
        pool.cancel();
        assert!(wait_for_removal_state(&pool, || pool.is_done()));
    }
    pool.close();
    for thread in threads {
        thread.join().unwrap();
    }
    assert!(
        finished,
        "an idle receiver retained capacity needed by a paused scan"
    );
    assert_eq!(pool.active.load(Ordering::Relaxed), 0);
    assert_eq!(
        outcomes
            .try_iter()
            .filter_map(Result::unwrap)
            .filter(|o| o.disposition == NativeRemoveDisposition::Removed)
            .count(),
        1024,
    );
    for d in 0..2 {
        assert_eq!(
            fs::read_dir(temp.path().join(d.to_string()))
                .unwrap()
                .count(),
            0
        );
    }
}
