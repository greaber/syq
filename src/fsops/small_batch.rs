//! Small files of one directory are staged together, written, and then
//! published together. Creating and renaming entries is serialized by the
//! kernel for each directory, so a batch takes the directory once for each
//! burst of changes instead of competing for it once per file. File data and
//! inode metadata are written between the two bursts, outside any turn.
use super::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) type SmallOutcome = std::result::Result<Option<(u64, u64)>, WireError>;

/// Files one burst stages before it publishes any of them.
const BURST: usize = 64;

/// Threads a run writes and closes its files on, on a network filesystem.
/// Creating and renaming stay one at a time per directory, so a few threads
/// keep the rest shorter than the creates.
const PARALLEL_WRITES: usize = 8;

/// A small file's private sidecar between its creation and publication.
pub(super) struct SmallStage {
    target: RootedTarget,
    partial: RelativePath,
    label: PathBuf,
    file: File,
    reused: bool,
    /// Read right after the sidecar was opened, when an NFS client answers
    /// from the create's reply; it decides the metadata step and gives the
    /// published identity, which a rename does not change.
    created: fs::Metadata,
}

/// Apply `each` to `items` on up to `PARALLEL_WRITES` threads, in order.
/// This thread runs the first part, as it would otherwise only wait, and
/// any part whose thread the system refuses to start.
fn on_threads<T: Send, R: Send>(items: Vec<T>, each: impl Fn(T) -> R + Sync) -> Vec<R> {
    let per_thread = items.len().div_ceil(PARALLEL_WRITES).max(1);
    let mut parts = Vec::new();
    let mut items = items.into_iter().peekable();
    while items.peek().is_some() {
        parts.push(Mutex::new(Some(
            items.by_ref().take(per_thread).collect::<Vec<_>>(),
        )));
    }
    let Some((first, rest)) = parts.split_first() else {
        return Vec::new();
    };
    // Whichever thread runs a part takes it. A thread that could not start
    // never took its part, so this thread finds it still there.
    let run = |part: &Mutex<Option<Vec<T>>>| {
        let part = part.lock().unwrap().take().unwrap_or_default();
        part.into_iter().map(&each).collect::<Vec<_>>()
    };
    let run = &run;
    std::thread::scope(|scope| {
        let threads: Vec<_> = rest
            .iter()
            .map(|part| start_thread(scope, move || run(part)).ok())
            .collect();
        let mut results = run(first);
        for (part, thread) in rest.iter().zip(threads) {
            results.extend(match thread {
                Some(thread) => thread
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                None => run(part),
            });
        }
        results
    })
}

#[cfg(test)]
thread_local! {
    /// Refuses the threads this thread starts, as a process limit would.
    static REFUSE_THREADS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Start `work` on a thread of `scope`, unless the system refuses one.
fn start_thread<'scope, R: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    work: impl FnOnce() -> R + Send + 'scope,
) -> io::Result<std::thread::ScopedJoinHandle<'scope, R>> {
    #[cfg(test)]
    if REFUSE_THREADS.get() {
        return Err(io::Error::from_raw_os_error(libc::EAGAIN));
    }
    std::thread::Builder::new().spawn_scoped(scope, work)
}

/// Descriptors that bursts may hold beyond the one each put needs anyway.
/// Every worker of the process draws on the same allowance, so bursts shrink
/// under a low open-file limit instead of exhausting it.
fn burst_descriptors() -> &'static AtomicUsize {
    static AVAILABLE: OnceLock<AtomicUsize> = OnceLock::new();
    AVAILABLE.get_or_init(|| {
        let limit = nofile_limits().map_or(0, |limits| {
            if limits.rlim_cur == libc::RLIM_INFINITY {
                usize::MAX
            } else {
                usize::try_from(limits.rlim_cur).unwrap_or(usize::MAX)
            }
        });
        AtomicUsize::new(limit / 4)
    })
}

struct ReservedDescriptors(usize);

impl ReservedDescriptors {
    fn up_to(wanted: usize) -> Self {
        let mut granted = 0;
        let _ = burst_descriptors().fetch_update(Ordering::AcqRel, Ordering::Acquire, |free| {
            granted = free.min(wanted);
            Some(free - granted)
        });
        Self(granted)
    }
}

impl Drop for ReservedDescriptors {
    fn drop(&mut self) {
        burst_descriptors().fetch_add(self.0, Ordering::AcqRel);
    }
}

/// The target's name, if it lies in the same directory as `first`.
fn sibling_name<'a>(first: &RootedTarget, other: &'a RootedTarget) -> Option<&'a [u8]> {
    let (directory, _) = first.relative.leaf().ok()?;
    let (other_directory, name) = other.relative.leaf().ok()?;
    (first.root.identity() == other.root.identity() && directory == other_directory).then_some(name)
}

impl FsOps {
    pub(super) fn put_small_batch(&mut self, puts: &[SmallPut]) -> Vec<SmallOutcome> {
        let mut results: Vec<SmallOutcome> = vec![Ok(None); puts.len()];
        let mut carried = None;
        let mut next = 0;
        while next < puts.len() || carried.is_some() {
            if carried.is_none() && puts[next].inplace {
                results[next] = self
                    .put_small(&puts[next])
                    .map_err(|error| wire_error(&error));
                next += 1;
                continue;
            }
            let reserved = ReservedDescriptors::up_to(BURST - 1);
            let mut run: Vec<(usize, RootedTarget)> = Vec::with_capacity(1 + reserved.0);
            // A run stays in one directory and names each target once: a
            // repeated target would share its sidecar with the earlier one.
            // The target carried over from the last run is its first name.
            let mut names = HashSet::new();
            if let Some((index, target)) = carried.take() {
                names.extend(sibling_name(&target, &target).map(<[u8]>::to_vec));
                run.push((index, target));
            }
            while run.len() <= reserved.0 && next < puts.len() && !puts[next].inplace {
                let index = next;
                next += 1;
                let target = match self.small_target(&puts[index]) {
                    Ok(target) => target,
                    Err(error) => {
                        results[index] = Err(wire_error(&error));
                        continue;
                    }
                };
                let joins = match run.first() {
                    Some((_, first)) => {
                        sibling_name(first, &target).is_some_and(|name| names.insert(name.to_vec()))
                    }
                    None => {
                        names.extend(sibling_name(&target, &target).map(<[u8]>::to_vec));
                        true
                    }
                };
                if !joins {
                    carried = Some((index, target));
                    break;
                }
                run.push((index, target));
            }
            self.put_small_run(puts, run, &mut results);
        }
        results
    }

    fn small_target(&mut self, put: &SmallPut) -> Result<RootedTarget> {
        if self.hash_policy.transfer_integrity && self.observed_payload_hash(&put.data) != put.hash
        {
            bail!("block hash mismatch on receive");
        }
        self.destination_mutation_target(&put.path, put.guard.as_ref())
    }

    fn put_small_run(
        &mut self,
        puts: &[SmallPut],
        run: Vec<(usize, RootedTarget)>,
        results: &mut [SmallOutcome],
    ) {
        let Some((_, first)) = run.first() else {
            return;
        };
        let (root, directory) = (first.root.clone(), first.relative.clone());
        let mut stages = Vec::with_capacity(run.len());
        {
            // A turn only schedules. If it cannot be taken, the operations
            // themselves report what is wrong with the path.
            let _turn = root.mutation_turn(&directory).ok();
            for (index, target) in run {
                match self.create_small_stage(&puts[index], target) {
                    Ok(stage) => stages.push((index, stage)),
                    Err(error) => results[index] = Err(wire_error(&error)),
                }
            }
        }
        // Writing data and metadata needs no directory turn. On a network
        // filesystem each step waits a round trip, so the files of a run
        // are written on threads of their own: every worker's runs proceed
        // at once, as when each worker wrote its files in turn. Only this
        // thread records observations, so the writes are one span.
        let network = stages.first().is_some_and(|(_, stage)| {
            stages.len() > 1 && on_network_file_system(&stage.file, stage.created.dev())
        });
        let written: Vec<Result<()>> = if network {
            let writing = self
                .operation
                .span(crate::transfer_observations::Stage::DestinationWrite);
            let this = &*self;
            let written = on_threads(stages.iter().collect(), |(index, stage)| {
                this.write_small_stage(&puts[*index], stage, false)
            });
            writing.bytes(
                stages
                    .iter()
                    .zip(&written)
                    .filter(|(_, result)| result.is_ok())
                    .map(|((index, _), _)| puts[*index].data.len() as u64)
                    .sum(),
            );
            written
        } else {
            stages
                .iter()
                .map(|(index, stage)| self.write_small_stage(&puts[*index], stage, true))
                .collect()
        };
        let mut written = written.into_iter();
        stages.retain(
            |(index, _)| match written.next().expect("one result per stage") {
                Ok(()) => true,
                Err(error) => {
                    results[*index] = Err(wire_error(&error));
                    false
                }
            },
        );
        let mut published = Vec::with_capacity(stages.len());
        {
            // Replacing files contends across the whole filesystem on some
            // filesystems, so a burst that replaces any waits for admission
            // there first. New names need none.
            let _replacement = stages
                .iter()
                .any(|(index, _)| puts[*index].replaces)
                .then(|| root.replacement_turn());
            let _turn = root.mutation_turn(&directory).ok();
            for (index, stage) in stages {
                match self.publish_small_stage(&puts[index], &stage) {
                    Ok(()) => published.push((index, stage)),
                    Err(error) => results[index] = Err(wire_error(&error)),
                }
            }
        }
        // Closing a file is a round trip on NFS too, so on a network
        // filesystem the files are finished and closed on threads as well.
        let finish = |(index, stage): (usize, SmallStage)| {
            let result = self
                .finish_small_stage(&puts[index], stage)
                .map_err(|error| wire_error(&error));
            (index, result)
        };
        let finished = if network {
            on_threads(published, finish)
        } else {
            published.into_iter().map(finish).collect()
        };
        for (index, result) in finished {
            results[index] = result;
        }
    }

    pub(super) fn create_small_stage(
        &mut self,
        put: &SmallPut,
        target: RootedTarget,
    ) -> Result<SmallStage> {
        self.uncache_rooted(&target.root, &target.relative);
        let mode = staged_file_mode(&put.meta, put.flags);
        let (partial, label, opened) =
            with_rooted_partial(&target, &put.copy_id, |relative, label| {
                // Nothing reads a small file's sidecar, so it is opened for
                // writing only, and without exclusive creation, which costs
                // an NFS client a further request. Whatever the name held is
                // opened too: a new empty file of ours is used as created,
                // and anything else, or an open the kernel refused, takes
                // the checked reuse that ranged writes apply.
                self.uncache_rooted(&target.root, relative);
                match self.open_or_create_write_only_partial(&target.root, relative, mode) {
                    Ok((file, created)) if is_fresh_partial(&created, mode) => {
                        Ok(Some((file, created, None)))
                    }
                    Ok(_) => self.checked_small_stage(&target.root, relative, label, mode),
                    Err(error) if existing_leaf_refused(&error) => {
                        self.checked_small_stage(&target.root, relative, label, mode)
                    }
                    Err(error) => Err(error),
                }
            })?;
        let (file, created, basis_size) = opened.context("sidecar creation was requested")?;
        Ok(SmallStage {
            target,
            partial,
            label,
            file,
            reused: basis_size.is_some(),
            created,
        })
    }

    /// The checked reuse of whatever the sidecar name holds, with the
    /// metadata of the file it settles on.
    fn checked_small_stage(
        &mut self,
        root: &Root,
        relative: &RelativePath,
        label: &Path,
        mode: u32,
    ) -> Result<Option<(File, fs::Metadata, Option<u64>)>> {
        let Some((file, basis_size)) =
            self.open_private_partial_rooted(root, relative, label, true, mode)?
        else {
            return Ok(None);
        };
        let metadata = file.metadata()?;
        Ok(Some((file, metadata, basis_size)))
    }

    /// Write a staged file's data and metadata. Unless `observe`, the caller
    /// records the write: observations take one thread at a time.
    pub(super) fn write_small_stage(
        &self,
        put: &SmallPut,
        stage: &SmallStage,
        observe: bool,
    ) -> Result<()> {
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_SMALL_STAGE_READY_FILE",
            "SYQ_TEST_SMALL_STAGE_CONTINUE_FILE",
            "small-file stage before data",
        )?;
        if stage.reused {
            stage.file.set_len(0)?;
        }
        if observe {
            observed_write(&self.operation, &stage.file, &put.data, 0, self.sparse)
        } else {
            write_data(&stage.file, &put.data, 0, self.sparse)
        }
        .with_context(|| format!("write {}", stage.label.display()))?;
        check_destination_writes(&stage.file, &stage.label)?;
        set_meta_written_file_for_publication(&stage.file, &put.meta, put.flags, &stage.created)
            .with_context(|| format!("set metadata {}", stage.label.display()))?;
        #[cfg(debug_assertions)]
        fail_put_small_before_rename_for_test(&stage.target.label)?;
        Ok(())
    }

    /// Publication re-resolves both names from the root and checks the staged
    /// name against the held inode immediately before the rename.
    pub(super) fn publish_small_stage(&self, put: &SmallPut, stage: &SmallStage) -> Result<()> {
        publish_partial_rooted(
            &stage.target.root,
            &stage.partial,
            &stage.target.relative,
            &stage.file,
            put.condition,
        )
    }

    pub(super) fn finish_small_stage(
        &self,
        put: &SmallPut,
        stage: SmallStage,
    ) -> Result<Option<(u64, u64)>> {
        crate::inode_metadata::finish_publication(
            &stage.file,
            put.meta.inode_metadata.as_deref(),
            put.meta.mode,
        )?;
        Ok(known_identity(&stage.created, put.flags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(path: &str, data: &[u8]) -> SmallPut {
        SmallPut {
            path: path.as_bytes().to_vec(),
            copy_id: [2; 16],
            data: data.to_vec(),
            hash: content_digest(data),
            meta: Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                inode_metadata: None,
            },
            flags: 0,
            inplace: false,
            condition: TargetCondition::Any,
            guard: None,
            replaces: false,
        }
    }

    fn receiver(directory: &Path) -> FsOps {
        let mut ops = FsOps::new();
        ops.install_destination(File::open(directory).unwrap(), b"logical")
            .unwrap();
        ops
    }

    fn entries(directory: &Path) -> usize {
        fs::read_dir(directory).unwrap().count()
    }

    #[test]
    fn every_file_is_published_and_reported_in_request_order() {
        // Sorted puts make long runs; interleaved ones change directory at
        // every file, so each run carries the next directory's first target.
        for interleaved in [false, true] {
            let temporary = crate::test_support::tempdir().unwrap();
            for name in ["a", "b", "c"] {
                fs::create_dir(temporary.path().join(name)).unwrap();
            }
            let mut puts: Vec<_> = (0..200)
                .map(|i| {
                    let directory = if interleaved { i % 3 } else { i / 67 };
                    put(
                        &format!("{}/f{i}", ["a", "b", "c"][directory]),
                        format!("data{i}").as_bytes(),
                    )
                })
                .collect();
            puts[61].data[0] ^= 1;
            puts[130].path = b"missing/f130".to_vec();
            let results = receiver(temporary.path()).put_small_batch(&puts);
            assert_eq!(results.len(), puts.len());
            for (i, (put, result)) in puts.iter().zip(results).enumerate() {
                let path = temporary.path().join(OsStr::from_bytes(&put.path));
                if i == 61 || i == 130 {
                    assert!(result.is_err(), "{i}");
                    assert!(!path.exists(), "{i}");
                } else {
                    assert_eq!(result, Ok(None), "{i}");
                    assert_eq!(fs::read(path).unwrap(), put.data, "{i}");
                }
            }
            // Nothing but the published files remains in any directory.
            let published: usize = ["a", "b", "c"]
                .iter()
                .map(|name| entries(&temporary.path().join(name)))
                .sum();
            assert_eq!(published, 198);
        }
    }

    #[test]
    fn a_repeated_target_is_published_before_it_is_staged_again() {
        // The third case repeats a target immediately after a run break, so
        // the carried target is the one that must not be joined.
        for (puts, files) in [
            (
                vec![
                    put("file", b"a long first version"),
                    put("other", b"independent"),
                    put("file", b"last"),
                ],
                2,
            ),
            (
                vec![
                    put("file", b"one"),
                    put("file", b"two"),
                    put("file", b"last"),
                ],
                1,
            ),
            (
                vec![
                    put("a/x", b"a"),
                    put("b/y", b"a long first version"),
                    put("b/y", b"last"),
                ],
                2,
            ),
        ] {
            let temporary = crate::test_support::tempdir().unwrap();
            for name in ["a", "b"] {
                fs::create_dir(temporary.path().join(name)).unwrap();
            }
            let results = receiver(temporary.path()).put_small_batch(&puts);
            assert_eq!(results, vec![Ok(None); puts.len()]);
            let last = puts.last().unwrap();
            assert_eq!(
                fs::read(temporary.path().join(OsStr::from_bytes(&last.path))).unwrap(),
                last.data
            );
            let published: usize = entries(temporary.path())
                + entries(&temporary.path().join("a"))
                + entries(&temporary.path().join("b"))
                - 2;
            assert_eq!(published, files, "{puts:?}");
        }
    }

    #[test]
    fn a_batch_replaces_existing_files_and_mixes_with_unstaged_puts() {
        let temporary = crate::test_support::tempdir().unwrap();
        fs::write(temporary.path().join("existing"), b"old contents").unwrap();
        fs::write(temporary.path().join("inplace"), b"old in-place contents").unwrap();
        let before = fs::metadata(temporary.path().join("inplace"))
            .unwrap()
            .ino();
        let mut inplace = put("inplace", b"written through the old inode");
        inplace.inplace = true;
        let puts = [
            put("new", b"new"),
            put("existing", b"replacement"),
            inplace,
            put("after", b"after"),
        ];
        let results = receiver(temporary.path()).put_small_batch(&puts);
        assert_eq!(results, vec![Ok(None); 4]);
        for (name, contents) in [
            ("new", &b"new"[..]),
            ("existing", b"replacement"),
            ("inplace", b"written through the old inode"),
            ("after", b"after"),
        ] {
            assert_eq!(fs::read(temporary.path().join(name)).unwrap(), contents);
        }
        assert_eq!(
            fs::metadata(temporary.path().join("inplace"))
                .unwrap()
                .ino(),
            before
        );
        assert_eq!(entries(temporary.path()), 4);
    }

    #[test]
    fn identity_conditioned_puts_publish_atomically() {
        for batched in [false, true] {
            for fingerprint in [false, true] {
                for changed in [false, true] {
                    let temporary = crate::test_support::tempdir().unwrap();
                    let target = temporary.path().join("file");
                    let alias = temporary.path().join("alias");
                    fs::write(&target, b"old contents").unwrap();
                    fs::hard_link(&target, &alias).unwrap();
                    let before = fs::metadata(&target).unwrap();
                    let mut put = put("file", b"replacement");
                    put.flags = flags::REPORT_IDENTITY;
                    put.condition = if fingerprint {
                        TargetCondition::MatchesFingerprint {
                            dev: before.dev(),
                            ino: before.ino(),
                            ctime: before.ctime() + i64::from(changed),
                            ctime_nsec: before.ctime_nsec() as u32,
                        }
                    } else {
                        TargetCondition::Matches {
                            dev: before.dev(),
                            ino: before.ino() ^ u64::from(changed),
                        }
                    };
                    let mut ops = receiver(temporary.path());
                    let result = if batched {
                        ops.put_small_batch(&[put]).pop().unwrap()
                    } else {
                        ops.put_small(&put).map_err(|error| wire_error(&error))
                    };
                    let after = fs::metadata(&target).unwrap();
                    if changed {
                        assert!(result.is_err());
                        assert_eq!(after.ino(), before.ino());
                        assert_eq!(fs::read(&target).unwrap(), b"old contents");
                    } else {
                        assert_eq!(result, Ok(Some((after.dev(), after.ino()))));
                        assert_ne!(after.ino(), before.ino());
                        assert_eq!(fs::read(&target).unwrap(), b"replacement");
                        assert_eq!(entries(temporary.path()), 2);
                    }
                    assert_eq!(fs::read(&alias).unwrap(), b"old contents");
                }
            }
        }
    }

    #[test]
    fn a_new_sidecar_is_opened_for_writing_only_and_a_leftover_is_reused() {
        let temporary = crate::test_support::tempdir().unwrap();
        let mut ops = receiver(temporary.path());
        let access = |stage: &SmallStage| {
            (unsafe { libc::fcntl(stage.file.as_raw_fd(), libc::F_GETFL) }) & libc::O_ACCMODE
        };
        let file = put("file", b"contents");
        let target = ops.small_target(&file).unwrap();
        let stage = ops.create_small_stage(&file, target).unwrap();
        assert_eq!(access(&stage), libc::O_WRONLY);
        assert!(!stage.reused);
        // An attempt interrupted before it wrote anything leaves an empty
        // sidecar, which is what a new one would be; the copy uses it as
        // created. One interrupted after writing takes the checked reuse.
        drop(stage);
        let target = ops.small_target(&file).unwrap();
        let stage = ops.create_small_stage(&file, target).unwrap();
        assert!(!stage.reused);
        ops.write_small_stage(&file, &stage, true).unwrap();
        drop(stage);
        let target = ops.small_target(&file).unwrap();
        let stage = ops.create_small_stage(&file, target).unwrap();
        assert!(stage.reused);
        ops.write_small_stage(&file, &stage, true).unwrap();
        ops.publish_small_stage(&file, &stage).unwrap();
        assert_eq!(ops.finish_small_stage(&file, stage).unwrap(), None);
        assert_eq!(
            fs::read(temporary.path().join("file")).unwrap(),
            b"contents"
        );
        assert_eq!(entries(temporary.path()), 1);
    }

    #[test]
    fn whatever_else_the_sidecar_name_holds_takes_the_checked_path() {
        // The sidecar is created without O_EXCL, so the open can land on
        // something already at its name. Only a new empty file of ours is
        // used as opened; a symlink, a FIFO, a second link to a file of ours,
        // and a file holding data are left to the checked path, which
        // replaces what is not a safe sidecar and reuses what is. Nothing
        // planted at the name receives the copy's data.
        let temporary = crate::test_support::tempdir().unwrap();
        let mut ops = receiver(temporary.path());
        let wanted = put("file", b"contents");
        let target = ops.small_target(&wanted).unwrap();
        let (relative, _) = rooted_partial_target(&target, &wanted.copy_id).unwrap();
        let sidecar = temporary.path().join(relative.to_path_buf());
        fs::write(temporary.path().join("victim"), b"victim").unwrap();
        for planted in ["symlink", "fifo", "hardlink", "data", "wide"] {
            match planted {
                "symlink" => {
                    std::os::unix::fs::symlink(temporary.path().join("victim"), &sidecar).unwrap()
                }
                "wide" => {
                    // An empty file of ours with permissions beyond the staging
                    // mode is not used as it is: the checked path narrows it
                    // to 0600 before anything is written.
                    fs::write(&sidecar, b"").unwrap();
                    fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o666)).unwrap();
                    let target = ops.small_target(&wanted).unwrap();
                    let stage = ops.create_small_stage(&wanted, target).unwrap();
                    assert!(stage.reused);
                    assert_eq!(stage.created.mode() & 0o777, 0o600);
                    drop(stage);
                }
                "fifo" => {
                    let path = std::ffi::CString::new(sidecar.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                "hardlink" => fs::hard_link(temporary.path().join("victim"), &sidecar).unwrap(),
                "data" => fs::write(&sidecar, b"an earlier attempt").unwrap(),
                _ => unreachable!(),
            }
            let outcomes = ops.put_small_batch(std::slice::from_ref(&wanted));
            outcomes[0]
                .as_ref()
                .unwrap_or_else(|error| panic!("{planted}: {error}"));
            assert_eq!(
                fs::read(temporary.path().join("file")).unwrap(),
                b"contents",
                "{planted}"
            );
            assert_eq!(
                fs::read(temporary.path().join("victim")).unwrap(),
                b"victim",
                "{planted}"
            );
            assert!(
                fs::symlink_metadata(&sidecar).is_err(),
                "{planted}: the name is free again"
            );
            fs::remove_file(temporary.path().join("file")).unwrap();
        }
        assert_eq!(entries(temporary.path()), 1);
    }

    #[test]
    fn an_inplace_put_opens_its_destination_directly() {
        // With no condition on the destination, the in-place path opens the
        // name at once instead of looking it up first. An existing regular
        // file keeps its inode and loses its contents; a symlink or FIFO at
        // the name is replaced by a file, leaving a symlink's target alone; a
        // directory is refused.
        let temporary = crate::test_support::tempdir().unwrap();
        let mut ops = receiver(temporary.path());
        let mut inplace = put("file", b"contents");
        inplace.inplace = true;
        inplace.flags = flags::REPORT_IDENTITY;
        let destination = temporary.path().join("file");
        fs::write(temporary.path().join("victim"), b"victim").unwrap();
        fs::write(&destination, b"an older and longer version").unwrap();
        let before = fs::metadata(&destination).unwrap();
        let identity = ops.put_small(&inplace).unwrap();
        assert_eq!(identity, Some((before.dev(), before.ino())));
        assert_eq!(fs::read(&destination).unwrap(), b"contents");
        for planted in ["symlink", "fifo"] {
            fs::remove_file(&destination).unwrap();
            match planted {
                "symlink" => {
                    std::os::unix::fs::symlink(temporary.path().join("victim"), &destination)
                        .unwrap()
                }
                _ => {
                    let path = std::ffi::CString::new(destination.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
            }
            ops.put_small(&inplace)
                .unwrap_or_else(|error| panic!("{planted}: {error}"));
            assert!(
                fs::symlink_metadata(&destination).unwrap().is_file(),
                "{planted}"
            );
            assert_eq!(fs::read(&destination).unwrap(), b"contents", "{planted}");
            assert_eq!(
                fs::read(temporary.path().join("victim")).unwrap(),
                b"victim",
                "{planted}"
            );
        }
        fs::remove_file(&destination).unwrap();
        fs::create_dir(&destination).unwrap();
        let error = ops.put_small(&inplace).unwrap_err();
        assert!(error.to_string().contains("is a directory"), "{error}");
        fs::remove_dir(&destination).unwrap();
        let identity = ops.put_small(&inplace).unwrap();
        let published = fs::metadata(&destination).unwrap();
        assert_eq!(identity, Some((published.dev(), published.ino())));
        assert_eq!(fs::read(&destination).unwrap(), b"contents");
        // Writing clears an existing file's set-id bits for an unprivileged
        // writer; the metadata read before the write must not hide that from
        // the chmod that restores them.
        for wanted in [0o4755, 0o2755] {
            let mut setid = inplace.clone();
            setid.meta.mode = wanted;
            setid.flags = flags::MODE;
            fs::set_permissions(&destination, fs::Permissions::from_mode(wanted)).unwrap();
            assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o7777, wanted);
            ops.put_small(&setid).unwrap();
            assert_eq!(
                fs::metadata(&destination).unwrap().mode() & 0o7777,
                wanted,
                "{wanted:o}"
            );
        }
    }

    #[test]
    fn a_refused_creation_is_recognized_with_or_without_an_os_error() {
        // The macOS ACL sidecar refuses an existing name with an error that
        // carries only the kind; the kernel's refusals carry an errno.
        assert!(existing_leaf_refused(&anyhow::Error::from(
            io::Error::from(io::ErrorKind::AlreadyExists)
        )));
        for code in [libc::ELOOP, libc::EISDIR, libc::ENXIO, libc::EACCES] {
            assert!(existing_leaf_refused(&anyhow::Error::from(
                io::Error::from_raw_os_error(code)
            )));
        }
        assert!(!existing_leaf_refused(&anyhow::Error::from(
            io::Error::from_raw_os_error(libc::ENOSPC)
        )));
        assert!(!existing_leaf_refused(&anyhow::anyhow!("not an I/O error")));
    }

    #[test]
    fn metadata_and_identity_come_from_the_stage_read_at_creation() {
        // The sidecar's metadata is read once, right after it is created;
        // the mode and times set before publication, and the identity
        // reported after it, follow from that read. A private staging mode
        // (taken when the group is preserved) must still become the wanted
        // mode, and the times must be set even when that read showed the
        // wanted mtime already, because the write since then changed it: the
        // leftover reused from an earlier attempt is given the wanted mtime
        // before the batch finds it.
        let temporary = crate::test_support::tempdir().unwrap();
        let mut ops = receiver(temporary.path());
        let mut wanted = put("file", b"contents");
        wanted.meta.mode = 0o640;
        wanted.meta.gid = unsafe { libc::getegid() };
        wanted.meta.mtime = 1_000_000_000;
        wanted.meta.mtime_nsec = 123_456_789;
        wanted.flags = flags::MODE | flags::GROUP | flags::TIMES | flags::REPORT_IDENTITY;
        for leftover in [false, true] {
            if leftover {
                let target = ops.small_target(&wanted).unwrap();
                let stage = ops.create_small_stage(&wanted, target).unwrap();
                assert_eq!(stage.created.mode() & 0o777, PRIVATE_PARTIAL_MODE);
                let times = [
                    timespec(0, libc::UTIME_OMIT as u32),
                    timespec(wanted.meta.mtime, wanted.meta.mtime_nsec),
                ];
                assert_eq!(
                    unsafe { libc::futimens(stage.file.as_raw_fd(), times.as_ptr()) },
                    0
                );
                drop(stage);
                fs::remove_file(temporary.path().join("file")).unwrap();
            }
            let outcomes = ops.put_small_batch(std::slice::from_ref(&wanted));
            let published = fs::metadata(temporary.path().join("file")).unwrap();
            assert_eq!(
                outcomes[0].as_ref().unwrap(),
                &Some((published.dev(), published.ino())),
                "leftover={leftover}"
            );
            assert_eq!(published.mode() & 0o7777, 0o640, "leftover={leftover}");
            assert_eq!(
                (published.mtime(), published.mtime_nsec()),
                (1_000_000_000, 123_456_789),
                "leftover={leftover}"
            );
            assert_eq!(
                fs::read(temporary.path().join("file")).unwrap(),
                b"contents"
            );
            assert_eq!(entries(temporary.path()), 1);
        }
        // The in-place path reads its new file the same way.
        let mut inplace = wanted.clone();
        inplace.path = b"inplace".to_vec();
        inplace.inplace = true;
        inplace.condition = TargetCondition::Absent;
        let identity = ops.put_small(&inplace).unwrap();
        let published = fs::metadata(temporary.path().join("inplace")).unwrap();
        assert_eq!(identity, Some((published.dev(), published.ino())));
        assert_eq!(published.mode() & 0o7777, 0o640);
        assert_eq!(
            (published.mtime(), published.mtime_nsec()),
            (1_000_000_000, 123_456_789)
        );
    }

    #[test]
    fn parts_keep_their_order_when_threads_are_refused() {
        // This thread runs the first part itself, and every part when no
        // thread starts; a panic in any part reaches the caller.
        let caller = std::thread::current().id();
        let first_part = 20usize.div_ceil(PARALLEL_WRITES);
        for refused in [false, true] {
            REFUSE_THREADS.set(refused);
            let ran = on_threads((0..20).collect(), |i: usize| {
                (i, std::thread::current().id())
            });
            REFUSE_THREADS.set(false);
            let order: Vec<_> = ran.iter().map(|(i, _)| *i).collect();
            assert_eq!(order, (0..20).collect::<Vec<_>>(), "refused={refused}");
            for (i, thread) in ran {
                assert_eq!(
                    thread == caller,
                    refused || i < first_part,
                    "refused={refused} item {i}"
                );
            }
            for panicking in [0, 19] {
                REFUSE_THREADS.set(refused);
                let outcome = std::panic::catch_unwind(|| {
                    on_threads((0..20).collect(), |i: usize| assert_ne!(i, panicking))
                });
                REFUSE_THREADS.set(false);
                assert!(outcome.is_err(), "refused={refused} item {panicking}");
            }
        }
        assert!(on_threads(Vec::<usize>::new(), |i| i).is_empty());
    }

    #[test]
    fn a_batch_completes_when_bursts_may_hold_no_further_descriptors() {
        let temporary = crate::test_support::tempdir().unwrap();
        let exhausted = ReservedDescriptors::up_to(usize::MAX);
        let puts: Vec<_> = (0..10)
            .map(|i| put(&format!("f{i}"), format!("data{i}").as_bytes()))
            .collect();
        let results = receiver(temporary.path()).put_small_batch(&puts);
        assert_eq!(results, vec![Ok(None); 10]);
        assert_eq!(entries(temporary.path()), 10);
        let held = exhausted.0;
        drop(exhausted);
        let again = ReservedDescriptors::up_to(held);
        assert!(again.0 > 0 || held == 0);
    }
}
