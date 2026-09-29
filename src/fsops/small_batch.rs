//! Small files of one directory are staged together, written, and then
//! published together. Creating and renaming entries is serialized by the
//! kernel for each directory, so a batch takes the directory once for each
//! burst of changes instead of competing for it once per file. File data and
//! inode metadata are written between the two bursts, outside any turn.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) type SmallOutcome = std::result::Result<Option<(u64, u64)>, WireError>;

/// Files one burst stages before it publishes any of them.
const BURST: usize = 64;

/// A small file's private sidecar between its creation and publication.
pub(super) struct SmallStage {
    target: RootedTarget,
    partial: RelativePath,
    label: PathBuf,
    file: File,
    reused: bool,
}

/// Whether a put publishes through a sidecar. In-place writes and ordinary
/// conditional updates of an existing inode keep their one-file path.
fn staged(put: &SmallPut) -> bool {
    !put.inplace
        && (put.guard.is_some()
            || matches!(
                put.condition,
                TargetCondition::Any | TargetCondition::Absent
            ))
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
            if carried.is_none() && !staged(&puts[next]) {
                results[next] = self
                    .put_small(&puts[next])
                    .map_err(|error| wire_error(&error));
                next += 1;
                continue;
            }
            let reserved = ReservedDescriptors::up_to(BURST - 1);
            let mut run: Vec<(usize, RootedTarget)> = Vec::with_capacity(1 + reserved.0);
            let mut names = HashSet::new();
            run.extend(carried.take());
            while run.len() <= reserved.0 && next < puts.len() && staged(&puts[next]) {
                let index = next;
                next += 1;
                let target = match self.small_target(&puts[index]) {
                    Ok(target) => target,
                    Err(error) => {
                        results[index] = Err(wire_error(&error));
                        continue;
                    }
                };
                // A run stays in one directory and names each target once: a
                // repeated target would share its sidecar with the earlier one.
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
        // A turn only schedules. If it cannot be taken, the operations
        // themselves report what is wrong with the path.
        let turn = root.mutation_turn(&directory).ok();
        for (index, target) in run {
            match self.create_small_stage(&puts[index], target) {
                Ok(stage) => stages.push((index, stage)),
                Err(error) => results[index] = Err(wire_error(&error)),
            }
        }
        drop(turn);
        stages.retain(
            |(index, stage)| match self.write_small_stage(&puts[*index], stage) {
                Ok(()) => true,
                Err(error) => {
                    results[*index] = Err(wire_error(&error));
                    false
                }
            },
        );
        let mut published = Vec::with_capacity(stages.len());
        let turn = root.mutation_turn(&directory).ok();
        for (index, stage) in stages {
            match self.publish_small_stage(&puts[index], &stage) {
                Ok(()) => published.push((index, stage)),
                Err(error) => results[index] = Err(wire_error(&error)),
            }
        }
        drop(turn);
        for (index, stage) in published {
            results[index] = self
                .finish_small_stage(&puts[index], stage)
                .map_err(|error| wire_error(&error));
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
                // Nothing reads a small file's sidecar, so a new one is
                // opened for writing only. One left by an earlier attempt
                // takes the checked reuse that ranged writes apply.
                self.uncache_rooted(&target.root, relative);
                match self.create_write_only_partial(&target.root, relative, mode) {
                    Ok(file) => Ok(Some((file, None))),
                    Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                        self.open_private_partial_rooted(&target.root, relative, label, true, mode)
                    }
                    Err(error) => Err(error),
                }
            })?;
        let (file, basis_size) = opened.context("sidecar creation was requested")?;
        Ok(SmallStage {
            target,
            partial,
            label,
            file,
            reused: basis_size.is_some(),
        })
    }

    pub(super) fn write_small_stage(&self, put: &SmallPut, stage: &SmallStage) -> Result<()> {
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_SMALL_STAGE_READY_FILE",
            "SYQ_TEST_SMALL_STAGE_CONTINUE_FILE",
            "small-file stage before data",
        )?;
        if stage.reused {
            stage.file.set_len(0)?;
        }
        observed_write(&self.operation, &stage.file, &put.data, 0, self.sparse)
            .with_context(|| format!("write {}", stage.label.display()))?;
        set_meta_file_for_publication(&stage.file, &put.meta, put.flags)
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
        published_identity(&stage.file, put.flags)
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
        let temporary = crate::test_support::tempdir().unwrap();
        let puts = [
            put("file", b"a long first version"),
            put("other", b"independent"),
            put("file", b"last"),
        ];
        let results = receiver(temporary.path()).put_small_batch(&puts);
        assert_eq!(results, vec![Ok(None); 3]);
        assert_eq!(fs::read(temporary.path().join("file")).unwrap(), b"last");
        assert_eq!(
            fs::read(temporary.path().join("other")).unwrap(),
            b"independent"
        );
        assert_eq!(entries(temporary.path()), 2);
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
        // The same copy finds its sidecar again after an interrupted attempt.
        drop(stage);
        let target = ops.small_target(&file).unwrap();
        let stage = ops.create_small_stage(&file, target).unwrap();
        assert!(stage.reused);
        ops.write_small_stage(&file, &stage).unwrap();
        ops.publish_small_stage(&file, &stage).unwrap();
        assert_eq!(ops.finish_small_stage(&file, stage).unwrap(), None);
        assert_eq!(
            fs::read(temporary.path().join("file")).unwrap(),
            b"contents"
        );
        assert_eq!(entries(temporary.path()), 1);
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
