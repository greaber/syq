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
    });

    let mut heartbeat = Vec::new();
    let error =
        emit_attached(&pool, &mut heartbeat, &mut |_| bail!("client disconnected")).unwrap_err();
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
