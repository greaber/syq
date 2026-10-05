//! Small files of one directory are staged together, written, and then
//! published together. Creating and renaming entries is serialized by the
//! kernel for each directory, so a batch takes the directory once for each
//! burst of changes instead of competing for it once per file. File data and
//! inode metadata are written between the two bursts, outside any turn.
use super::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(super) type SmallOutcome = std::result::Result<Option<(u64, u64)>, WireError>;

/// Files one burst stages before it publishes any of them.
const BURST: usize = 64;

// Filesystem servers may have a much lower limit than this process, and FUSE
// may translate their exhaustion to EPERM. Learn only for this process. A
// failed create gets one retry after the staged files have been closed; all
// checks and atomic publication still run on that retry.
const REDUCED: usize = 1 << (usize::BITS - 1);
struct StagingAdmission {
    // The high bit stops new bursts; the other bits count admitted bursts.
    state: AtomicUsize,
    wait: Mutex<()>,
    drained: std::sync::Condvar,
}
impl StagingAdmission {
    const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            wait: Mutex::new(()),
            drained: std::sync::Condvar::new(),
        }
    }
    fn width(&self) -> usize {
        if self.state.load(Ordering::Relaxed) & REDUCED == 0 {
            BURST
        } else {
            1
        }
    }
    fn enter(&self) -> Option<StagingBurst<'_>> {
        // The healthy path does not take a process-wide mutex. Admission and
        // reduction use one atomic so no new burst can slip past a reduction.
        let mut state = self.state.load(Ordering::Relaxed);
        while state & REDUCED == 0 {
            match self.state.compare_exchange_weak(
                state,
                state + 1,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(StagingBurst(self)),
                Err(current) => state = current,
            }
        }
        let mut wait = self.wait.lock().unwrap();
        while self.state.load(Ordering::Acquire) != REDUCED {
            wait = self.drained.wait(wait).unwrap();
        }
        None
    }
    fn reduce(&self) {
        let before = self.state.fetch_or(REDUCED, Ordering::AcqRel);
        if before & REDUCED == 0 && crate::output::debug() {
            crate::output::diagnostic!(
                "syq: reducing small-file staging after descriptor pressure"
            );
        }
    }
}
static STAGING_ADMISSION: StagingAdmission = StagingAdmission::new();
struct StagingBurst<'a>(&'a StagingAdmission);
impl Drop for StagingBurst<'_> {
    fn drop(&mut self) {
        if self.0.state.fetch_sub(1, Ordering::AcqRel) == REDUCED + 1 {
            // Pair with the waiter's condition check to avoid a missed wake.
            let _wait = self.0.wait.lock().unwrap();
            self.0.drained.notify_all();
        }
    }
}

fn retry_stage_open(error: &anyhow::Error, network: impl FnOnce() -> bool) -> bool {
    let errno = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .and_then(io::Error::raw_os_error);
    match errno {
        Some(libc::EMFILE | libc::ENFILE) => true,
        // SSHFS can translate the server's EMFILE to EPERM. Inspect only on
        // failure: local permission errors should not shrink future batches.
        Some(libc::EPERM) => network(),
        _ => false,
    }
}
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
    /// Made as a clone of the file its patch replaces, as macOS clones.
    cloned: bool,
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
    /// Patched files this thread wrote over a clone of the file they replace.
    static CLONED_PATCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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

/// A patch reuses at least this much, and half its file, before its stage
/// clones the file it replaces rather than writing every block.
const CLONE_MIN_REUSED: u64 = 1 << 20;

/// What the receiver does with one patch: keep the file it replaces, or
/// stage it for publication.
enum PatchStep<'a> {
    Kept(Option<(u64, u64)>),
    Staged(Box<SmallPut>, Option<PatchSource<'a>>),
}

/// The file a patch reuses blocks of, opened and fingerprinted when the
/// patch arrived.
pub(super) struct PatchSource<'a> {
    old: File,
    basis: FileFingerprint,
    patch: &'a SmallPatch,
}

/// Clone the file a patch replaces into its created stage. Linux clones into
/// an open file; macOS clones only into a new name, so there the stage is
/// made as the clone instead (`clone_patch_stage`).
fn try_clone_basis(old: &File, stage: &File, len: u64) -> bool {
    #[cfg(target_os = "linux")]
    {
        super::basis_copy::try_clone(old, stage, len)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (old, stage, len);
        false
    }
}

/// The whole contents a patch describes: its new blocks, and the reused
/// blocks of `old`, each of which must still hash as compared.
fn assemble(
    old: Option<&File>,
    algorithm: crate::hashing::HashAlgorithm,
    patch: &SmallPatch,
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(patch.len as usize);
    let mut taken = 0;
    for (index, reuse) in patch.reuse.iter().enumerate() {
        let off = index as u64 * patch.block;
        let len = patch.block.min(patch.len - off) as usize;
        match (reuse, old) {
            (Some(expected), Some(old)) => {
                data.resize(off as usize + len, 0);
                let block = &mut data[off as usize..];
                let complete = read_exact_or_short(old, off, block)?;
                if !complete || algorithm.hash(block) != *expected {
                    bail!("the destination changed after it was compared");
                }
            }
            _ => {
                let new = patch
                    .data
                    .get(taken..taken + len)
                    .context("patch contents end early")?;
                data.extend_from_slice(new);
                taken += len;
            }
        }
    }
    if taken != patch.data.len() {
        bail!("patch contents run past the file");
    }
    Ok(data)
}

fn fingerprint(metadata: &fs::Metadata) -> FileFingerprint {
    FileFingerprint {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec() as u32,
    }
}

/// How many comparison blocks of `block` bytes a file of `len` bytes has.
fn block_count(len: u64, block: u64) -> Result<usize> {
    if !(MIN_HASH_BLOCK_BYTES..=MAX_HASH_BLOCK_BYTES).contains(&block) {
        bail!("invalid comparison block size {block}");
    }
    usize::try_from(len.div_ceil(block)).context("comparison block count overflow")
}

/// Check that a patch describes its file consistently: one reuse entry for
/// each comparison block, and new data exactly as long as the blocks it does
/// not reuse, the last of which may be short. A restricted receiver does not
/// trust its coordinator, so a malformed patch fails its own file before
/// anything is kept, cloned or written.
fn check_patch_layout(patch: &SmallPatch) -> Result<()> {
    if patch.len > MAX_PATCH_FILE_BYTES {
        bail!("invalid patch of {} bytes", patch.len);
    }
    let blocks = block_count(patch.len, patch.block)?;
    if patch.reuse.len() != blocks {
        bail!(
            "patch of {} bytes lists {} blocks, not {blocks}",
            patch.len,
            patch.reuse.len()
        );
    }
    let new: u64 = patch
        .reuse
        .iter()
        .enumerate()
        .filter(|(_, reuse)| reuse.is_none())
        .map(|(index, _)| patch.block.min(patch.len - index as u64 * patch.block))
        .sum();
    if patch.data.len() as u64 != new {
        bail!(
            "patch carries {} new bytes for blocks of {new} bytes",
            patch.data.len()
        );
    }
    Ok(())
}

/// Whether a patch describes the file it was compared with, unchanged: it
/// has that file's length and reuses every block of it, which an empty file
/// does vacuously.
fn reproduces_basis(patch: &SmallPatch) -> bool {
    patch.basis.is_some_and(|basis| basis.len == patch.len)
        && patch.data.is_empty()
        && patch.reuse.iter().all(Option::is_some)
}

/// Whether `file` is exactly as long as a patch's file and every block
/// still hashes as the patch reuses it.
fn holds_reused_blocks(
    file: &File,
    algorithm: crate::hashing::HashAlgorithm,
    patch: &SmallPatch,
) -> Result<bool> {
    if file.metadata()?.len() != patch.len {
        return Ok(false);
    }
    let mut buffer = Vec::new();
    for (index, reuse) in patch.reuse.iter().enumerate() {
        let off = index as u64 * patch.block;
        let len = patch.block.min(patch.len - off) as usize;
        if !read_block(file, off, len, &mut buffer)?
            || Some(algorithm.hash(&buffer[..len])) != *reuse
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Read `len` bytes at `off` into the start of `buffer`. Returns false when
/// the file ends first.
fn read_block(file: &File, off: u64, len: usize, buffer: &mut Vec<u8>) -> Result<bool> {
    if buffer.len() < len {
        buffer.resize(len, 0);
    }
    read_exact_or_short(file, off, &mut buffer[..len])
}

/// Fill `buffer` from `file` at `off`. Returns false when the file ends first.
fn read_exact_or_short(file: &File, off: u64, buffer: &mut [u8]) -> Result<bool> {
    match file.read_exact_at(buffer, off) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

impl FsOps {
    /// Hash the blocks each existing destination holds whole, up to the
    /// length of the source that would replace it. A target that is not an
    /// existing regular file under the root and condition has no hashes.
    pub(super) fn hash_existing_batch(
        &mut self,
        block: u64,
        files: &[ExistingRead],
    ) -> Vec<std::result::Result<ExistingHashes, WireError>> {
        let mut buffer = Vec::new();
        files
            .iter()
            .map(|file| {
                self.hash_existing(block, file, &mut buffer)
                    .map_err(|error| wire_error(&error))
            })
            .collect()
    }

    fn hash_existing(
        &mut self,
        block: u64,
        read: &ExistingRead,
        buffer: &mut Vec<u8>,
    ) -> Result<ExistingHashes> {
        let blocks = block_count(read.len, block)?;
        let target = self.destination_mutation_target(&read.path, read.guard.as_ref())?;
        let partials = !self.candidate_partials(&target).is_empty();
        let Some(file) = target
            .root
            .open_regular_read(&target.relative)
            .ok()
            .filter(|file| require_open_target(file, &target.label, read.condition).is_ok())
        else {
            return Ok(ExistingHashes {
                fingerprint: None,
                hashes: Vec::new(),
                partials,
            });
        };
        let fingerprint = fingerprint(&file.metadata()?);
        let algorithm = self.hash_policy.algorithm;
        let mut hashes = Vec::with_capacity(blocks);
        for index in 0..blocks as u64 {
            let off = index * block;
            let len = block.min(read.len - off) as usize;
            if off + len as u64 > fingerprint.len || !read_block(&file, off, len, buffer)? {
                break;
            }
            hashes.push(algorithm.hash(&buffer[..len]));
        }
        Ok(ExistingHashes {
            fingerprint: Some(fingerprint),
            hashes,
            partials,
        })
    }

    /// Keep an existing file found to hold a small file's contents: set its
    /// metadata through the descriptor its contents were read from, as a
    /// content-identical per-file finish does. A writer that extended or
    /// shrank it while it was compared makes it count as changed. Returns the
    /// kept file's identity, or None when it must be replaced.
    #[allow(clippy::too_many_arguments)]
    fn keep_open_small(
        &mut self,
        target: &RootedTarget,
        file: &File,
        len: u64,
        meta: &Meta,
        flags: u8,
        guarded: bool,
        condition: TargetCondition,
    ) -> Result<Option<Option<(u64, u64)>>> {
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_SMALL_COMPARED_READY_FILE",
            "SYQ_TEST_SMALL_COMPARED_CONTINUE_FILE",
            "small-file comparison",
        )?;
        let current = file.metadata()?;
        if current.len() != len {
            return Ok(None);
        }
        #[cfg(debug_assertions)]
        fail_set_meta_for_test(&target.label)?;
        set_meta_file_known(file, meta, flags, &current)
            .with_context(|| format!("set metadata {}", target.label.display()))?;
        if guarded || condition != TargetCondition::Any {
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                file,
                condition,
            )?;
        }
        Ok(Some(published_identity(file, flags)?))
    }

    /// Publish each patch as `put_small_batch` publishes a whole file, from
    /// its new contents and the blocks it reuses from the file it replaces.
    /// A reused block must still hash as compared; otherwise that file fails
    /// and nothing of it is written. A patch that reuses every block of an
    /// existing file that still holds them keeps that file instead.
    /// Each file is built in memory until the batch is published, so a batch
    /// describing more than the protocol allows is refused whole.
    pub(super) fn patch_small_batch(
        &mut self,
        patches: &[SmallPatch],
    ) -> Result<Vec<std::result::Result<SmallPatched, SmallPatchError>>> {
        if !patch_batch_fits(patches.iter().map(|patch| patch.len)) {
            bail!("small-file patch batch describes more file bytes than the protocol allows");
        }
        let mut results = vec![
            Ok(SmallPatched {
                kept: false,
                identity: None,
            });
            patches.len()
        ];
        let mut puts = Vec::new();
        let mut sources = Vec::new();
        let mut positions = Vec::new();
        for (position, patch) in patches.iter().enumerate() {
            match self.prepare_patch(patch) {
                Ok(PatchStep::Staged(put, source)) => {
                    puts.push(*put);
                    sources.push(source);
                    positions.push(position);
                }
                Ok(PatchStep::Kept(identity)) => {
                    results[position] = Ok(SmallPatched {
                        kept: true,
                        identity,
                    })
                }
                Err(error) => results[position] = Err(error),
            }
        }
        for (position, result) in positions
            .into_iter()
            .zip(self.put_small_sources(&puts, &sources))
        {
            results[position] = result
                .map(|identity| SmallPatched {
                    kept: false,
                    identity,
                })
                .map_err(|error| SmallPatchError {
                    error,
                    matched: false,
                    stale_condition: false,
                });
        }
        Ok(results)
    }

    /// Keep the existing file a patch reproduces whole, or stage the patch.
    /// A file found to match whose keeping fails is reported as matched, so
    /// the copy does not rewrite the same contents. A file whose blocks the
    /// patch reuses but that no longer meets its target condition is
    /// reported as stale, before anything is kept or written: keeping
    /// another name of the same file, say, changes the change time a
    /// restricted receiver's condition holds.
    fn prepare_patch<'a>(
        &mut self,
        patch: &'a SmallPatch,
    ) -> std::result::Result<PatchStep<'a>, SmallPatchError> {
        let failed = |matched, stale_condition| {
            move |error: anyhow::Error| SmallPatchError {
                error: wire_error(&error),
                matched,
                stale_condition,
            }
        };
        check_patch_layout(patch).map_err(failed(false, false))?;
        let old = self.open_reused(patch).map_err(failed(false, false))?;
        if let Some((target, file)) = &old {
            require_open_target(file, &target.label, patch.condition)
                .map_err(failed(false, true))?;
            if self
                .whole_match(patch, file)
                .map_err(failed(false, false))?
            {
                let kept = self
                    .keep_open_small(
                        target,
                        file,
                        patch.len,
                        &patch.meta,
                        patch.unchanged_flags,
                        patch.guard.is_some(),
                        patch.condition,
                    )
                    .map_err(failed(true, false))?;
                if let Some(identity) = kept {
                    return Ok(PatchStep::Kept(identity));
                }
            }
        }
        let (put, source) = self
            .stage_patch(patch, old.map(|(_, file)| file))
            .map_err(failed(false, false))?;
        Ok(PatchStep::Staged(Box::new(put), source))
    }

    /// The existing file whose blocks a patch reuses, or that it may keep,
    /// opened for reading under the destination root; None when the patch
    /// needs nothing of it. An empty file has no blocks to reuse but may
    /// still be kept.
    fn open_reused(&mut self, patch: &SmallPatch) -> Result<Option<(RootedTarget, File)>> {
        if !reproduces_basis(patch) && patch.reuse.iter().all(Option::is_none) {
            return Ok(None);
        }
        let target = self.destination_mutation_target(&patch.path, patch.guard.as_ref())?;
        let file = target
            .root
            .open_regular_read(&target.relative)
            .with_context(|| format!("open {} to reuse its blocks", target.label.display()))?;
        Ok(Some((target, file)))
    }

    /// Whether a patch reproduces `file` whole: every block is reused, and
    /// the file still holds them. Its fingerprint shows that nothing has
    /// changed it since it was hashed; when it has changed, as keeping
    /// another name of the same file changes it, the file is hashed again.
    fn whole_match(&self, patch: &SmallPatch, file: &File) -> Result<bool> {
        if !reproduces_basis(patch) {
            return Ok(false);
        }
        Ok(patch.basis == Some(fingerprint(&file.metadata()?))
            || holds_reused_blocks(file, self.hash_policy.algorithm, patch)?)
    }

    /// The put that publishes a patch, and the file whose blocks it reuses.
    /// With enough of a file reused, the stage clones that file and writes
    /// only the differing blocks over it, when the filesystem can clone.
    /// Otherwise the put carries the whole file, its reused blocks read and
    /// checked here. The patch's layout has been checked, and `old` is the
    /// file it reuses blocks of, if any.
    fn stage_patch<'a>(
        &mut self,
        patch: &'a SmallPatch,
        old: Option<File>,
    ) -> Result<(SmallPut, Option<PatchSource<'a>>)> {
        if self.hash_policy.transfer_integrity
            && self.observed_payload_hash(&patch.data) != patch.hash
        {
            bail!("block hash mismatch on receive");
        }
        let put = |data: Vec<u8>, hash| SmallPut {
            path: patch.path.clone(),
            copy_id: patch.copy_id,
            data,
            hash,
            meta: patch.meta.clone(),
            flags: patch.flags,
            inplace: false,
            condition: patch.condition,
            guard: patch.guard.clone(),
            replaces: true,
        };
        let reused = patch.len - patch.data.len() as u64;
        let clones = reused >= CLONE_MIN_REUSED && reused * 2 >= patch.len;
        if let (Some(old), Some(basis), true) = (&old, patch.basis, clones) {
            // A clone keeps the reused blocks unread, so each must lie
            // within the file it comes from. Otherwise assembling reads them
            // and fails.
            let within = patch
                .reuse
                .iter()
                .enumerate()
                .filter(|(_, reuse)| reuse.is_some())
                .all(|(index, _)| {
                    (index as u64 * patch.block + patch.block).min(patch.len) <= basis.len
                });
            if within && fingerprint(&old.metadata()?) == basis {
                let hash = if self.hash_policy.transfer_integrity {
                    self.observed_payload_hash(&[])
                } else {
                    [0; 32]
                };
                let source = PatchSource {
                    old: old.try_clone()?,
                    basis,
                    patch,
                };
                return Ok((put(Vec::new(), hash), Some(source)));
            }
        }
        let data = assemble(old.as_ref(), self.hash_policy.algorithm, patch)?;
        let hash = if self.hash_policy.transfer_integrity {
            self.observed_payload_hash(&data)
        } else {
            [0; 32]
        };
        Ok((put(data, hash), None))
    }

    /// Write a cloning patch's stage: the file it replaces, cloned, with the
    /// differing blocks written over it. A stage made as the clone holds it
    /// already; any other is cloned into here. When the file cannot be
    /// cloned, or changed after it was hashed, the stage holds the assembled
    /// file instead, its reused blocks read and checked again.
    /// Write a patched file, observed unless `unobserved` collects its bytes
    /// for a caller that records them, as `write_small_stage` does.
    fn write_patch_stage(
        &self,
        source: &PatchSource<'_>,
        stage: &SmallStage,
        unobserved: Option<&AtomicU64>,
    ) -> Result<()> {
        let patch = source.patch;
        let file = &stage.file;
        let cloned = if stage.cloned {
            true
        } else {
            file.set_len(0)?;
            try_clone_basis(&source.old, file, source.basis.len)
        } && fingerprint(&source.old.metadata()?) == source.basis;
        if !cloned {
            file.set_len(0)?;
            let data = assemble(Some(&source.old), self.hash_policy.algorithm, patch)?;
            return match unobserved {
                None => observed_write(&self.operation, file, &data, 0, self.sparse),
                Some(bytes) => write_data(file, &data, 0, self.sparse).inspect(|()| {
                    bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }),
            }
            .with_context(|| format!("write {}", stage.label.display()));
        }
        #[cfg(test)]
        CLONED_PATCHES.set(CLONED_PATCHES.get() + 1);
        let writing = unobserved.is_none().then(|| {
            self.operation
                .span(crate::transfer_observations::Stage::DestinationWrite)
        });
        let mut taken = 0;
        for (index, reuse) in patch.reuse.iter().enumerate() {
            if reuse.is_some() {
                continue;
            }
            let off = index as u64 * patch.block;
            let len = patch.block.min(patch.len - off) as usize;
            let bytes = &patch.data[taken..taken + len];
            // Old bytes lie under these blocks: zeros must replace them.
            if self.sparse {
                crate::sparse::write_at(file, bytes, off, true)
            } else {
                file.write_all_at(bytes, off)
            }
            .with_context(|| format!("write {} @{off}", stage.label.display()))?;
            taken += len;
        }
        match (&writing, unobserved) {
            (Some(writing), _) => writing.bytes(taken as u64),
            (None, Some(bytes)) => {
                bytes.fetch_add(taken as u64, Ordering::Relaxed);
            }
            (None, None) => {}
        }
        if self.sparse {
            crate::sparse::set_len(file, patch.len)?;
        } else {
            file.set_len(patch.len)?;
        }
        Ok(())
    }

    pub(super) fn put_small_batch(&mut self, puts: &[SmallPut]) -> Vec<SmallOutcome> {
        self.put_small_sources(puts, &[])
    }

    /// Publish `puts`, writing those with a patch source from the file it
    /// patches rather than from their data.
    fn put_small_sources(
        &mut self,
        puts: &[SmallPut],
        sources: &[Option<PatchSource<'_>>],
    ) -> Vec<SmallOutcome> {
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
            let reserved = ReservedDescriptors::up_to(STAGING_ADMISSION.width() - 1);
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
            self.put_small_run(puts, sources, run, &mut results);
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
        sources: &[Option<PatchSource<'_>>],
        run: Vec<(usize, RootedTarget)>,
        results: &mut [SmallOutcome],
    ) {
        let Some((_, first)) = run.first() else {
            return;
        };
        let Some(burst) = STAGING_ADMISSION.enter() else {
            for (index, _) in run {
                results[index] = self
                    .put_small_with_source(
                        &puts[index],
                        sources.get(index).and_then(Option::as_ref),
                    )
                    .map_err(|error| wire_error(&error));
            }
            return;
        };
        let (root, directory) = (first.root.clone(), first.relative.clone());
        let source = |index: usize| sources.get(index).and_then(Option::as_ref);
        let mut stages = Vec::with_capacity(run.len());
        let mut retry = Vec::new();
        {
            // A turn only schedules. If it cannot be taken, the operations
            // themselves report what is wrong with the path.
            let _turn = root.mutation_turn(&directory).ok();
            let mut remaining = run.into_iter();
            while let Some((index, target)) = remaining.next() {
                #[cfg(debug_assertions)]
                let refuse = std::env::var("SYQ_TEST_STAGING_LIMIT")
                    .ok()
                    .and_then(|n| n.parse::<usize>().ok())
                    .is_some_and(|limit| stages.len() >= limit);
                #[cfg(not(debug_assertions))]
                let refuse = false;
                let created = if refuse {
                    Err(std::io::Error::from_raw_os_error(libc::EMFILE).into())
                } else {
                    self.create_stage(&puts[index], source(index), target)
                };
                match created {
                    Ok(stage) => stages.push((index, stage)),
                    Err(error)
                        if retry_stage_open(&error, || {
                            if let Some((_, stage)) = stages.first() {
                                on_network_file_system(&stage.file, stage.created.dev())
                            } else {
                                root.resolve_parent(&directory).ok().is_some_and(|parent| {
                                    parent.directory().metadata().ok().is_some_and(|meta| {
                                        on_network_file_system(parent.directory(), meta.dev())
                                    })
                                })
                            }
                        }) =>
                    {
                        STAGING_ADMISSION.reduce();
                        retry.push(index);
                        retry.extend(remaining.map(|(index, _)| index));
                        break;
                    }
                    Err(error) => results[index] = Err(wire_error(&error)),
                }
            }
        }
        // Writing data and metadata needs no directory turn. On a network
        // filesystem each step waits a round trip, so the files of a run
        // are written on threads of their own: every worker's runs proceed
        // at once, as when each worker wrote its files in turn. Only this
        // thread records observations, so the whole phase, metadata
        // included, counts as writing.
        let network = stages.first().is_some_and(|(_, stage)| {
            stages.len() > 1 && on_network_file_system(&stage.file, stage.created.dev())
        });
        let written: Vec<Result<()>> = if network {
            let writing = self
                .operation
                .span(crate::transfer_observations::Stage::DestinationWrite);
            let bytes = AtomicU64::new(0);
            let this = &*self;
            let written = on_threads(stages.iter().collect(), |(index, stage)| {
                this.write_small_stage(&puts[*index], source(*index), stage, Some(&bytes))
            });
            writing.bytes(bytes.into_inner());
            written
        } else {
            stages
                .iter()
                .map(|(index, stage)| {
                    self.write_small_stage(&puts[*index], source(*index), stage, None)
                })
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
        drop(burst);
        if !retry.is_empty() {
            // Other workers must publish and close their existing bursts too.
            // They never wait while holding a burst or directory turn.
            drop(STAGING_ADMISSION.enter());
        }
        for index in retry {
            results[index] = self
                .put_small_with_source(&puts[index], sources.get(index).and_then(Option::as_ref))
                .map_err(|error| wire_error(&error));
        }
    }

    // A patch can carry its contents in an open basis rather than put.data.
    // The one-file fallback must keep that basis and its validation intact.
    fn put_small_with_source(
        &mut self,
        put: &SmallPut,
        source: Option<&PatchSource<'_>>,
    ) -> Result<Option<(u64, u64)>> {
        if source.is_none() {
            return self.put_small(put);
        }
        let target = self.small_target(put)?;
        let stage = self.create_stage(put, source, target)?;
        self.write_small_stage(put, source, &stage, None)?;
        self.publish_small_stage(put, &stage)?;
        self.finish_small_stage(put, stage)
    }

    /// Create the stage of a put, or of a patch with the file it reuses
    /// blocks of. On macOS, where a clone is a new file, a cloning patch's
    /// stage is made as a clone of that file when it can be.
    fn create_stage(
        &mut self,
        put: &SmallPut,
        source: Option<&PatchSource<'_>>,
        target: RootedTarget,
    ) -> Result<SmallStage> {
        #[cfg(target_os = "macos")]
        if let Some(source) = source {
            if let Some((partial, label, file)) = self.clone_patch_stage(put, source, &target)? {
                let created = file.metadata()?;
                return Ok(SmallStage {
                    target,
                    partial,
                    label,
                    file,
                    reused: false,
                    cloned: true,
                    created,
                });
            }
        }
        let _ = source;
        self.create_small_stage(put, target)
    }

    /// Clone the file a patch reuses blocks of to the patch's sidecar name,
    /// as the per-file path clones its basis, and return the clone opened.
    /// None when the file cannot be cloned there, or when the clone is not
    /// fit to stage protected data, as a reused sidecar would not be; the
    /// stage is then created as any other, and replaces the clone.
    #[cfg(target_os = "macos")]
    fn clone_patch_stage(
        &mut self,
        put: &SmallPut,
        source: &PatchSource<'_>,
        target: &RootedTarget,
    ) -> Result<Option<(RelativePath, PathBuf, File)>> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_BASIS_CLONE_UNSUPPORTED").is_some() {
            return Ok(None);
        }
        self.uncache_rooted(&target.root, &target.relative);
        let metadata = source.old.metadata()?;
        let (partial, label, clone) = with_rooted_partial(target, &put.copy_id, |relative, _| {
            self.uncache_rooted(&target.root, relative);
            // A clone of a different length fails here; the stage then
            // assembles the file, which reads its reused blocks again.
            target
                .root
                .clone_file_open(&source.old, &metadata, relative, source.basis.len)
        })?;
        let Some(file) = clone else {
            return Ok(None);
        };
        if !self.reusable_partial_permissions(&file)? {
            return Ok(None);
        }
        Ok(Some((partial, label, file)))
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
                if creates_foreign_owners(target.root.identity().dev) {
                    return self.checked_small_stage(&target.root, relative, label, mode);
                }
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
            cloned: false,
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

    /// Write a staged file's data and metadata, from a patch source when
    /// there is one. The data write is observed, or, on a thread that cannot
    /// record observations, its bytes are added to `unobserved` once written,
    /// whatever the metadata step does.
    pub(super) fn write_small_stage(
        &self,
        put: &SmallPut,
        source: Option<&PatchSource<'_>>,
        stage: &SmallStage,
        unobserved: Option<&AtomicU64>,
    ) -> Result<()> {
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_SMALL_STAGE_READY_FILE",
            "SYQ_TEST_SMALL_STAGE_CONTINUE_FILE",
            "small-file stage before data",
        )?;
        if let Some(source) = source {
            self.write_patch_stage(source, stage, unobserved)?;
        } else {
            if stage.reused {
                stage.file.set_len(0)?;
            }
            match unobserved {
                None => observed_write(&self.operation, &stage.file, &put.data, 0, self.sparse),
                Some(bytes) => write_data(&stage.file, &put.data, 0, self.sparse).inspect(|()| {
                    bytes.fetch_add(put.data.len() as u64, Ordering::Relaxed);
                }),
            }
            .with_context(|| format!("write {}", stage.label.display()))?;
        }
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

    #[test]
    fn staging_reduction_drains_admitted_bursts_before_retry() {
        let admission = StagingAdmission::new();
        let first = admission.enter().unwrap();
        let second = admission.enter().unwrap();
        assert_eq!(admission.width(), BURST);
        admission.reduce();
        assert_eq!(admission.width(), 1);
        std::thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel();
            let admission = &admission;
            let waiter = scope.spawn(move || {
                assert!(admission.enter().is_none());
                tx.send(()).unwrap();
            });
            drop(first);
            assert!(rx
                .recv_timeout(std::time::Duration::from_millis(20))
                .is_err());
            drop(second);
            rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            waiter.join().unwrap();
        });
        assert!(admission.enter().is_none());
    }

    #[test]
    fn staging_permission_recovery_requires_network_filesystem() {
        for errno in [libc::EMFILE, libc::ENFILE] {
            let error = io::Error::from_raw_os_error(errno).into();
            assert!(retry_stage_open(&error, || panic!(
                "no filesystem query needed"
            )));
        }
        let permission = io::Error::from_raw_os_error(libc::EPERM).into();
        assert!(!retry_stage_open(&permission, || false));
        assert!(retry_stage_open(&permission, || true));
        let denied = io::Error::from_raw_os_error(libc::EACCES).into();
        assert!(!retry_stage_open(&denied, || panic!(
            "no filesystem query needed"
        )));
    }

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

    /// Whether the filesystem holding `directory` clones files, probed apart
    /// from the code under test. Linux clones on some filesystems only;
    /// macOS CI runs on APFS, which clones.
    fn clones_files(directory: &Path) -> bool {
        let probe = directory.join("clone-probe");
        fs::write(&probe, [1; 4096]).unwrap();
        let source = File::open(&probe).unwrap();
        #[cfg(target_os = "linux")]
        let cloned = crate::local_copy::try_clone(
            &source,
            &File::create(directory.join("clone-probe-copy")).unwrap(),
            4096,
        );
        #[cfg(target_os = "macos")]
        let cloned = unsafe {
            libc::fclonefileat(
                source.as_raw_fd(),
                File::open(directory).unwrap().as_raw_fd(),
                c"clone-probe-copy".as_ptr(),
                0,
            )
        } == 0;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let cloned = false;
        let _ = fs::remove_file(directory.join("clone-probe-copy"));
        fs::remove_file(&probe).unwrap();
        assert!(
            cloned || !cfg!(target_os = "macos") || std::env::var_os("GITHUB_ACTIONS").is_none(),
            "macOS CI requires a TMPDIR that clones files"
        );
        cloned
    }

    #[test]
    fn existing_files_are_hashed_in_whole_blocks_and_patched_from_them() {
        let temporary = crate::test_support::tempdir().unwrap();
        let directory = temporary.path();
        let block = MIN_HASH_BLOCK_BYTES;
        let blocks = |seed: u8, count: usize| -> Vec<u8> {
            (0..count as u64 * block)
                .map(|i| (i % 251) as u8 ^ seed)
                .collect()
        };
        let old = blocks(0, 3);
        for name in ["same", "edited", "raced"] {
            fs::write(directory.join(name), &old).unwrap();
        }
        let mut ops = receiver(directory);
        let algorithm = ops.hash_policy.algorithm;
        let read = |name: &str, len| ExistingRead {
            path: name.as_bytes().to_vec(),
            len,
            condition: TargetCondition::Any,
            guard: None,
        };
        let longer = 3 * block + 10;
        let hashed = ops.hash_existing_batch(
            block,
            &[
                read("same", 3 * block),
                read("edited", longer),
                read("missing", 1),
            ],
        );
        // A block the file holds only in part has no hash.
        let expected: Vec<_> = old
            .chunks(block as usize)
            .map(|chunk| algorithm.hash(chunk))
            .collect();
        let same = hashed[0].as_ref().unwrap();
        assert_eq!(same.hashes, expected);
        assert_eq!(same.fingerprint.unwrap().len, old.len() as u64);
        assert_eq!(hashed[1].as_ref().unwrap().hashes, expected);
        let missing = hashed[2].as_ref().unwrap();
        assert!(missing.fingerprint.is_none() && missing.hashes.is_empty() && !missing.partials);

        let patch =
            |name: &str, len, reuse: Vec<Option<ContentDigest>>, data: Vec<u8>| SmallPatch {
                path: name.as_bytes().to_vec(),
                copy_id: [3; 16],
                len,
                block,
                reuse,
                hash: content_digest(&data),
                data,
                basis: same.fingerprint,
                meta: Meta {
                    mtime: 1_234_567_890,
                    ..put(name, b"").meta
                },
                flags: 0,
                unchanged_flags: flags::TIMES,
                condition: TargetCondition::Any,
                guard: None,
            };
        let reuse_all: Vec<_> = expected.iter().copied().map(Some).collect();
        let mut new_tail = vec![7u8; block as usize];
        new_tail.extend_from_slice(b"0123456789");
        let mut edited = old[..2 * block as usize].to_vec();
        edited.extend_from_slice(&new_tail);
        let inode = |name: &str| fs::metadata(directory.join(name)).unwrap().ino();
        let before = (inode("same"), inode("edited"));
        // Change a reused block of "raced" after it was hashed.
        let mut raced = old.clone();
        raced[5] ^= 1;
        fs::write(directory.join("raced"), &raced).unwrap();
        let mut same_patch = patch("same", 3 * block, reuse_all.clone(), Vec::new());
        same_patch.basis = same.fingerprint;
        let results = ops
            .patch_small_batch(&[
                same_patch,
                patch(
                    "edited",
                    longer,
                    vec![reuse_all[0], reuse_all[1], None, None],
                    new_tail,
                ),
                patch(
                    "raced",
                    3 * block,
                    vec![reuse_all[0], None, None],
                    old[block as usize..].to_vec(),
                ),
            ])
            .unwrap();
        // The unchanged file is kept with the new times; the edited one is
        // published from two reused blocks and the new tail.
        assert_eq!(
            results[0],
            Ok(SmallPatched {
                kept: true,
                identity: None
            })
        );
        assert_eq!(inode("same"), before.0);
        assert_eq!(
            fs::metadata(directory.join("same")).unwrap().mtime(),
            1_234_567_890
        );
        assert_eq!(
            results[1],
            Ok(SmallPatched {
                kept: false,
                identity: None
            })
        );
        assert_ne!(inode("edited"), before.1);
        assert_eq!(fs::read(directory.join("edited")).unwrap(), edited);
        // A reused block that changed fails that file and writes nothing.
        assert!(results[2].is_err(), "{:?}", results[2]);
        assert_eq!(fs::read(directory.join("raced")).unwrap(), raced);
        assert_eq!(entries(directory), 3);
    }

    #[test]
    fn a_mostly_reused_patch_overwrites_a_clone_of_the_file_it_replaces() {
        let block = MIN_HASH_BLOCK_BYTES;
        for sparse in [false, true] {
            let temporary = crate::test_support::tempdir().unwrap();
            let directory = temporary.path();
            let old: Vec<u8> = (0..32 * block).map(|i| (i % 249) as u8 | 1).collect();
            let mut new = old.clone();
            // Zeros must replace the old bytes even where writes make holes.
            new[5 * block as usize..6 * block as usize].fill(0);
            new[20 * block as usize] ^= 0xff;
            new.extend_from_slice(b"tail");
            for name in ["file", "raced"] {
                fs::write(directory.join(name), &old).unwrap();
            }
            let mut ops = receiver(directory);
            ops.sparse = sparse;
            let algorithm = ops.hash_policy.algorithm;
            let read = |name: &str| ExistingRead {
                path: name.as_bytes().to_vec(),
                len: new.len() as u64,
                condition: TargetCondition::Any,
                guard: None,
            };
            let hashed = ops.hash_existing_batch(block, &[read("file"), read("raced")]);
            let patch = |name: &str, hashed: &ExistingHashes| {
                let mut reuse = Vec::new();
                let mut data = Vec::new();
                for (index, chunk) in new.chunks(block as usize).enumerate() {
                    let hash = algorithm.hash(chunk);
                    if hashed.hashes.get(index) == Some(&hash) {
                        reuse.push(Some(hash));
                    } else {
                        reuse.push(None);
                        data.extend_from_slice(chunk);
                    }
                }
                SmallPatch {
                    path: name.as_bytes().to_vec(),
                    copy_id: [4; 16],
                    len: new.len() as u64,
                    block,
                    reuse,
                    hash: content_digest(&data),
                    data,
                    basis: hashed.fingerprint,
                    meta: put(name, b"").meta,
                    flags: 0,
                    unchanged_flags: 0,
                    condition: TargetCondition::Any,
                    guard: None,
                }
            };
            let patches = [
                patch("file", hashed[0].as_ref().unwrap()),
                patch("raced", hashed[1].as_ref().unwrap()),
            ];
            assert_eq!(patches[0].data.len() as u64, 2 * block + 4);
            // A reused block of "raced" changes after it was hashed. A clone
            // keeps reused blocks unread, so only the change time shows the
            // change: wait until the write gives a new one.
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut raced = old.clone();
            raced[0] ^= 1;
            fs::write(directory.join("raced"), &raced).unwrap();
            let now = fingerprint(&fs::metadata(directory.join("raced")).unwrap());
            assert_ne!(Some(now), patches[1].basis);
            let cloned = clones_files(directory);
            CLONED_PATCHES.set(0);
            let results = ops.patch_small_batch(&patches).unwrap();
            assert!(results[0].is_ok(), "{:?}", results[0]);
            assert_eq!(
                fs::read(directory.join("file")).unwrap(),
                new,
                "sparse {sparse}"
            );
            assert_eq!(CLONED_PATCHES.get(), usize::from(cloned), "sparse {sparse}");
            assert!(results[1].is_err(), "{:?}", results[1]);
            assert_eq!(fs::read(directory.join("raced")).unwrap(), raced);
            assert_eq!(entries(directory), 2);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_cloned_patch_publishes_requested_metadata_without_old_xattrs() {
        let temporary = crate::test_support::tempdir().unwrap();
        let directory = temporary.path();
        if !clones_files(directory) {
            return;
        }
        let block = MIN_HASH_BLOCK_BYTES;
        let old = vec![1; 32 * block as usize];
        let path = directory.join("file");
        fs::write(&path, &old).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let original = File::open(&path).unwrap();
        let attribute = c"syq.test.old-metadata";
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    original.as_raw_fd(),
                    attribute.as_ptr(),
                    b"old".as_ptr().cast(),
                    3,
                    0,
                    0,
                )
            },
            0
        );
        let mut ops = receiver(directory);
        let hashed = ops.hash_existing_batch(
            block,
            &[ExistingRead {
                path: b"file".to_vec(),
                len: old.len() as u64,
                condition: TargetCondition::Any,
                guard: None,
            }],
        );
        let hashed = hashed[0].as_ref().unwrap();
        let mut reuse: Vec<_> = hashed.hashes.iter().copied().map(Some).collect();
        reuse[5] = None;
        let data = vec![2; block as usize];
        let patch = SmallPatch {
            path: b"file".to_vec(),
            copy_id: [5; 16],
            len: old.len() as u64,
            block,
            reuse,
            hash: content_digest(&data),
            data,
            basis: hashed.fingerprint,
            meta: Meta {
                // Match the old mode: using its metadata instead of the
                // private clone's would incorrectly skip restoring this.
                mode: 0o644,
                mtime: 1_234_567_890,
                mtime_nsec: 123_456_789,
                ..put("file", b"").meta
            },
            flags: flags::MODE | flags::TIMES,
            unchanged_flags: 0,
            condition: TargetCondition::Any,
            guard: None,
        };
        CLONED_PATCHES.set(0);
        let results = ops.patch_small_batch(&[patch]).unwrap();
        assert!(results[0].is_ok(), "{:?}", results[0]);
        assert_eq!(CLONED_PATCHES.get(), 1);
        let published = File::open(&path).unwrap();
        let metadata = published.metadata().unwrap();
        assert_ne!(metadata.ino(), original.metadata().unwrap().ino());
        assert_eq!(metadata.mode() & 0o7777, 0o644);
        assert_eq!(metadata.mtime(), 1_234_567_890);
        assert_eq!(metadata.mtime_nsec(), 123_456_789);
        assert_eq!(
            unsafe {
                libc::fgetxattr(
                    published.as_raw_fd(),
                    attribute.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                )
            },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOATTR)
        );
        let mut expected = old;
        expected[5 * block as usize..6 * block as usize].fill(2);
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert_eq!(entries(directory), 1);
    }

    #[test]
    fn a_malformed_patch_fails_its_file_and_leaves_nothing_behind() {
        // A file large and reused enough to clone, and one assembled whole.
        let block = MIN_HASH_BLOCK_BYTES;
        for blocks in [32, 3] {
            let temporary = crate::test_support::tempdir().unwrap();
            let directory = temporary.path();
            let old: Vec<u8> = (0..blocks * block).map(|i| (i % 249) as u8 | 1).collect();
            let mut new = old.clone();
            new[block as usize] ^= 0xff;
            new.extend_from_slice(b"tail");
            fs::write(directory.join("file"), &old).unwrap();
            let mut ops = receiver(directory);
            let algorithm = ops.hash_policy.algorithm;
            let hashed = ops
                .hash_existing_batch(
                    block,
                    &[ExistingRead {
                        path: b"file".to_vec(),
                        len: new.len() as u64,
                        condition: TargetCondition::Any,
                        guard: None,
                    }],
                )
                .remove(0)
                .unwrap();
            let mut reuse = Vec::new();
            let mut data = Vec::new();
            for (index, chunk) in new.chunks(block as usize).enumerate() {
                let hash = algorithm.hash(chunk);
                if hashed.hashes.get(index) == Some(&hash) {
                    reuse.push(Some(hash));
                } else {
                    reuse.push(None);
                    data.extend_from_slice(chunk);
                }
            }
            let valid = SmallPatch {
                path: b"file".to_vec(),
                copy_id: [5; 16],
                len: new.len() as u64,
                block,
                reuse,
                hash: content_digest(&data),
                data,
                basis: hashed.fingerprint,
                meta: put("file", b"").meta,
                flags: 0,
                unchanged_flags: 0,
                condition: TargetCondition::Any,
                guard: None,
            };
            let malformed = |change: &dyn Fn(&mut SmallPatch)| {
                let mut patch = valid.clone();
                change(&mut patch);
                patch.hash = content_digest(&patch.data);
                patch
            };
            let patches = [
                malformed(&|patch| {
                    patch.data.pop();
                }),
                malformed(&|patch| patch.data.push(0)),
                malformed(&|patch| patch.reuse.push(None)),
                malformed(&|patch| {
                    patch.reuse.pop();
                }),
                malformed(&|patch| patch.reuse.insert(0, patch.reuse[0])),
            ];
            for patch in patches {
                let results = ops.patch_small_batch(std::slice::from_ref(&patch)).unwrap();
                assert!(results[0].is_err(), "{blocks} blocks: {:?}", results[0]);
                assert_eq!(fs::read(directory.join("file")).unwrap(), old);
                assert_eq!(entries(directory), 1, "{blocks} blocks");
            }
            let cloned = blocks == 32 && clones_files(directory);
            CLONED_PATCHES.set(0);
            let results = ops.patch_small_batch(&[valid]).unwrap();
            assert!(results[0].is_ok(), "{blocks} blocks: {:?}", results[0]);
            assert_eq!(fs::read(directory.join("file")).unwrap(), new);
            assert_eq!(CLONED_PATCHES.get(), usize::from(cloned), "{blocks} blocks");
            assert_eq!(entries(directory), 1);
        }
    }

    #[test]
    fn a_whole_match_whose_file_changed_after_it_was_hashed_is_hashed_again() {
        let temporary = crate::test_support::tempdir().unwrap();
        let directory = temporary.path();
        let block = MIN_HASH_BLOCK_BYTES;
        let old: Vec<u8> = (0..3 * block).map(|i| (i % 241) as u8).collect();
        for name in ["touched", "edited"] {
            fs::write(directory.join(name), &old).unwrap();
        }
        let mut ops = receiver(directory);
        let read = |name: &str| ExistingRead {
            path: name.as_bytes().to_vec(),
            len: old.len() as u64,
            condition: TargetCondition::Any,
            guard: None,
        };
        let hashed = ops.hash_existing_batch(block, &[read("touched"), read("edited")]);
        let patch = |name: &str, hashed: &ExistingHashes| SmallPatch {
            path: name.as_bytes().to_vec(),
            copy_id: [7; 16],
            len: old.len() as u64,
            block,
            reuse: hashed.hashes.iter().copied().map(Some).collect(),
            hash: content_digest(&[]),
            data: Vec::new(),
            basis: hashed.fingerprint,
            meta: put(name, b"").meta,
            flags: 0,
            unchanged_flags: 0,
            condition: TargetCondition::Any,
            guard: None,
        };
        let patches = [
            patch("touched", hashed[0].as_ref().unwrap()),
            patch("edited", hashed[1].as_ref().unwrap()),
        ];
        // Only metadata changes for one; a block of the other is rewritten
        // in place at the same length. Change times are coarser than a
        // nanosecond, so wait until the changes give new ones.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let inode = |name: &str| fs::metadata(directory.join(name)).unwrap().ino();
        let before = inode("touched");
        fs::set_permissions(directory.join("touched"), fs::Permissions::from_mode(0o640)).unwrap();
        let mut edited = old.clone();
        edited[block as usize + 3] ^= 1;
        File::options()
            .write(true)
            .open(directory.join("edited"))
            .unwrap()
            .write_all_at(&edited[block as usize..][..4], block)
            .unwrap();
        for (patch, name) in patches.iter().zip(["touched", "edited"]) {
            let now = fingerprint(&fs::metadata(directory.join(name)).unwrap());
            assert_ne!(Some(now), patch.basis, "{name}");
        }
        let results = ops.patch_small_batch(&patches).unwrap();
        assert_eq!(
            results[0],
            Ok(SmallPatched {
                kept: true,
                identity: None
            })
        );
        assert_eq!(inode("touched"), before);
        assert!(results[1].is_err(), "{:?}", results[1]);
        assert_eq!(fs::read(directory.join("edited")).unwrap(), edited);
        assert_eq!(entries(directory), 2);
    }

    #[test]
    fn a_patch_batch_describing_too_much_is_refused_before_anything_is_built() {
        let temporary = crate::test_support::tempdir().unwrap();
        let directory = temporary.path();
        let block = MIN_HASH_BLOCK_BYTES;
        let len = 40 << 20;
        // Every block reused: the request is small, but the receiver would
        // build each file it describes in memory.
        let patch = SmallPatch {
            path: b"file".to_vec(),
            copy_id: [6; 16],
            len,
            block,
            reuse: vec![Some([0; 32]); (len / block) as usize],
            hash: content_digest(&[]),
            data: Vec::new(),
            basis: None,
            meta: put("file", b"").meta,
            flags: 0,
            unchanged_flags: 0,
            condition: TargetCondition::Any,
            guard: None,
        };
        let mut ops = receiver(directory);
        let error = ops
            .patch_small_batch(&[patch.clone(), patch.clone()])
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("more file bytes than the protocol"),
            "{error}"
        );
        // A batch of one file may describe a whole group file. This one
        // fails alone: there is no file to reuse blocks from.
        let results = ops.patch_small_batch(&[patch]).unwrap();
        assert!(results[0].is_err());
        assert_eq!(entries(directory), 0);
        let half = MAX_READ_BYTES / 2;
        assert!(patch_batch_fits([half, half]));
        assert!(!patch_batch_fits([half, half + 1]));
        assert!(patch_batch_fits([MAX_PATCH_FILE_BYTES]));
        assert!(!patch_batch_fits([MAX_PATCH_FILE_BYTES + 1]));
    }

    #[test]
    fn a_patch_reuses_no_blocks_past_the_end_of_the_file_it_replaces() {
        let block = MIN_HASH_BLOCK_BYTES;
        let temporary = crate::test_support::tempdir().unwrap();
        let directory = temporary.path();
        let old = vec![7; 32 * block as usize];
        fs::write(directory.join("file"), &old).unwrap();
        let mut ops = receiver(directory);
        let read = ExistingRead {
            path: b"file".to_vec(),
            len: 40 * block,
            condition: TargetCondition::Any,
            guard: None,
        };
        let hashed = ops.hash_existing_batch(block, &[read]).remove(0).unwrap();
        // Blocks past the old end claim to be reused, which a clone would
        // turn into zeros without reading them.
        let mut reuse: Vec<_> = hashed.hashes.iter().copied().map(Some).collect();
        reuse.resize(40, Some([0; 32]));
        let patch = SmallPatch {
            path: b"file".to_vec(),
            copy_id: [4; 16],
            len: 40 * block,
            block,
            reuse,
            hash: content_digest(&[]),
            data: Vec::new(),
            basis: hashed.fingerprint,
            meta: put("file", b"").meta,
            flags: 0,
            unchanged_flags: 0,
            condition: TargetCondition::Any,
            guard: None,
        };
        let results = ops.patch_small_batch(&[patch]).unwrap();
        assert!(results[0].is_err(), "{:?}", results[0]);
        assert_eq!(fs::read(directory.join("file")).unwrap(), old);
        assert_eq!(entries(directory), 1);
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
        ops.write_small_stage(&file, None, &stage, None).unwrap();
        drop(stage);
        let target = ops.small_target(&file).unwrap();
        let stage = ops.create_small_stage(&file, target).unwrap();
        assert!(stage.reused);
        ops.write_small_stage(&file, None, &stage, None).unwrap();
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
