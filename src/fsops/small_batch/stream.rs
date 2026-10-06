//! A patch whose new data is too large to hold for a batch is streamed:
//! `PatchBegin` opens its stage, each `PatchData` piece is written into it as
//! it arrives, and `PatchEnd` publishes it or abandons it. The stage is
//! seeded from the file it replaces under the same fingerprint check as a
//! batch patch's, or takes that file's reused blocks as the pieces around
//! them arrive. Either way it holds that file's bytes for as long as the
//! stream lasts, so it is always a new file, created exclusively, and stays
//! private until publication. A stage that will not be published, whether
//! the patch failed, was abandoned or its connection closed, is removed at
//! once.
use super::*;

/// Bytes of reused blocks read, checked and written at once when a stage is
/// not seeded from the file it replaces.
const REUSED_RUN_BYTES: u64 = 1 << 20;

/// The streamed patch open on a connection.
pub(in crate::fsops) struct PatchStream {
    /// The patch, without data.
    patch: SmallPatch,
    /// How the stage is published.
    put: SmallPut,
    /// The new bytes the patch's pieces carry in all, and those received.
    data_len: u64,
    received: u64,
    stage: Option<SmallStage>,
    /// The file whose blocks are reused.
    old: Option<File>,
    /// The stage already holds the reused blocks, cloned or copied from the
    /// file it replaces.
    seeded: bool,
    /// The next block to place.
    next: usize,
    buffer: Vec<u8>,
    /// The destination no longer met the patch's target condition.
    stale: bool,
    /// Why the patch failed. Its stage is gone; its end reports this.
    failure: Option<SmallPatchError>,
}

impl Drop for PatchStream {
    fn drop(&mut self) {
        // A stream dropped with its stage, as when its connection closes,
        // was never published.
        if let Some(stage) = self.stage.take() {
            discard_stage(&stage);
        }
    }
}

/// Remove a stage that will not be published, if its name still holds it.
fn discard_stage(stage: &SmallStage) {
    let _ = discard_safe_rooted_partial_if_same(
        &stage.target.root,
        &stage.partial,
        stage.created.dev(),
        stage.created.ino(),
        &stage.label,
    );
}

impl PatchStream {
    /// What a begin or a piece replies: `Ok`, or the failure that will end
    /// the patch, so that its sender stops sending pieces.
    fn reply(&self) -> Response {
        match &self.failure {
            None => Response::Ok,
            Some(failure) => Response::PatchedBatch(vec![Err(failure.clone())]),
        }
    }
}

/// Check that a streamed patch describes its file consistently, as
/// `check_patch_layout` checks a batch patch, with its data declared rather
/// than carried.
fn check_stream_layout(patch: &SmallPatch, data_len: u64) -> Result<()> {
    if !patch.data.is_empty() {
        bail!("a streamed patch carries its data in pieces");
    }
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
    let new = patch.new_bytes();
    if data_len != new || new == 0 {
        bail!("streamed patch declares {data_len} new bytes for blocks of {new} bytes");
    }
    Ok(())
}

impl FsOps {
    /// Whether a streamed patch is open, so that the connection carries
    /// nothing else until it ends.
    pub(crate) fn patch_stream_open(&self) -> bool {
        self.patch_stream.is_some()
    }

    /// Fail the open streamed patch, as when a piece of it was refused
    /// before it reached this receiver: its stage is removed, and its end
    /// reports `error`.
    pub(crate) fn fail_patch_stream(&mut self, error: &str) {
        if let Some(mut stream) = self.patch_stream.take() {
            self.fail_stream(&mut stream, anyhow!("{error}"));
            self.patch_stream = Some(stream);
        }
    }

    /// Abandon the open streamed patch without publishing it.
    pub(crate) fn abandon_patch_stream(&mut self) {
        if let Some(mut stream) = self.patch_stream.take() {
            self.fail_stream(&mut stream, anyhow!("the streamed patch was abandoned"));
        }
    }

    fn fail_stream(&mut self, stream: &mut PatchStream, error: anyhow::Error) {
        if stream.failure.is_none() {
            stream.failure = Some(SmallPatchError {
                error: wire_error(&error),
                matched: false,
                stale_condition: stream.stale,
            });
        }
        stream.old = None;
        if let Some(stage) = stream.stage.take() {
            self.uncache_rooted(&stage.target.root, &stage.partial);
            discard_stage(&stage);
        }
    }

    /// Open a patch whose new data follows in pieces. Any failure is kept
    /// for its end to report; the patch stays open until then.
    pub(in crate::fsops) fn begin_patch_stream(
        &mut self,
        patch: &SmallPatch,
        data_len: u64,
    ) -> Response {
        let put = SmallPut {
            path: patch.path.clone(),
            copy_id: patch.copy_id,
            data: Vec::new(),
            hash: [0; 32],
            meta: patch.meta.clone(),
            flags: patch.flags,
            inplace: false,
            condition: patch.condition,
            guard: patch.guard.clone(),
            replaces: true,
        };
        let mut stream = Box::new(PatchStream {
            patch: patch.clone(),
            put,
            data_len,
            received: 0,
            stage: None,
            old: None,
            seeded: false,
            next: 0,
            buffer: Vec::new(),
            stale: false,
            failure: None,
        });
        if let Err(error) = self.open_patch_stream(&mut stream) {
            self.fail_stream(&mut stream, error);
        }
        let reply = stream.reply();
        self.patch_stream = Some(stream);
        reply
    }

    /// Create a streamed patch's stage and, with enough of the file it
    /// replaces reused, seed it from that file as a batch patch's stage is
    /// seeded. The reused blocks of a stage that is not seeded are read,
    /// checked and written as the pieces around them arrive.
    fn open_patch_stream(&mut self, stream: &mut PatchStream) -> Result<()> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_PATCH_STREAM_BEGIN").is_some() {
            bail!("injected streamed patch begin failure");
        }
        let patch = &stream.patch;
        check_stream_layout(patch, stream.data_len)?;
        let target = self.destination_mutation_target(&patch.path, patch.guard.as_ref())?;
        if patch.reuse.iter().any(Option::is_some) {
            let old = target
                .root
                .open_regular_read(&target.relative)
                .with_context(|| format!("open {} to reuse its blocks", target.label.display()))?;
            if let Err(error) = require_open_target(&old, &target.label, patch.condition) {
                stream.stale = true;
                return Err(error);
            }
            stream.old = Some(old);
        }
        let reused = patch.len - stream.data_len;
        let source = match (&stream.old, patch.basis) {
            (Some(old), Some(basis))
                if reused >= CLONE_MIN_REUSED
                    && reused * 2 >= patch.len
                    && reuses_within(patch, basis.len)
                    && fingerprint(&old.metadata()?) == basis =>
            {
                Some(PatchSource {
                    old: old.try_clone()?,
                    basis,
                    patch,
                })
            }
            _ => None,
        };
        let stage = self.create_stream_stage(&stream.put, source.as_ref(), target)?;
        let stage = &*stream.stage.insert(stage);
        // Like a clone, a copy is trusted only if the file it came from
        // still has the fingerprint it had when its blocks were hashed.
        let seeded = match &source {
            Some(source) => {
                (stage.cloned || self.copy_basis(source, stage))
                    && fingerprint(&source.old.metadata()?) == source.basis
            }
            None => false,
        };
        if !seeded {
            stage.file.set_len(0)?;
            self.preallocate_stage(stage, patch.len)?;
        }
        #[cfg(test)]
        if seeded {
            CLONED_PATCHES.set(CLONED_PATCHES.get() + 1);
        }
        stream.seeded = seeded;
        Ok(())
    }

    /// Create a streamed patch's stage: a new file, created exclusively in
    /// place of anything left at its name, private until publication. On
    /// macOS a seeded stage is made as a clone of the file it replaces. A
    /// creation refused for want of descriptors reduces small-file staging,
    /// as a batch's does, and is tried once more when other bursts have
    /// closed their files.
    fn create_stream_stage(
        &mut self,
        put: &SmallPut,
        source: Option<&PatchSource<'_>>,
        target: RootedTarget,
    ) -> Result<SmallStage> {
        let (root, relative) = (target.root.clone(), target.relative.clone());
        let created = {
            let _turn = root.mutation_turn(&relative).ok();
            #[cfg(debug_assertions)]
            let refused = std::env::var("SYQ_TEST_STAGING_LIMIT").as_deref() == Ok("0");
            #[cfg(not(debug_assertions))]
            let refused = false;
            if refused {
                Err(std::io::Error::from_raw_os_error(libc::EMFILE).into())
            } else {
                self.create_stage(put, source, target, PRIVATE_PARTIAL_MODE, true)
            }
        };
        match created {
            Err(error)
                if retry_stage_open(&error, || {
                    root.resolve_parent(&relative).ok().is_some_and(|parent| {
                        parent.directory().metadata().ok().is_some_and(|meta| {
                            on_network_file_system(parent.directory(), meta.dev())
                        })
                    })
                }) =>
            {
                STAGING_ADMISSION.reduce();
                // Other workers must publish and close their bursts first.
                drop(STAGING_ADMISSION.enter());
                let target = self.destination_mutation_target(&put.path, put.guard.as_ref())?;
                let _turn = root.mutation_turn(&relative).ok();
                self.create_stage(put, source, target, PRIVATE_PARTIAL_MODE, true)
            }
            created => created,
        }
    }

    /// Write the next piece of the open streamed patch.
    pub(in crate::fsops) fn patch_stream_data(
        &mut self,
        data: &[u8],
        hash: ContentDigest,
    ) -> Result<Response> {
        let mut stream = self
            .patch_stream
            .take()
            .context("no streamed patch is open")?;
        if stream.failure.is_none() {
            if let Err(error) = self.write_patch_piece(&mut stream, data, hash) {
                self.fail_stream(&mut stream, error);
            }
        }
        let reply = stream.reply();
        self.patch_stream = Some(stream);
        Ok(reply)
    }

    fn write_patch_piece(
        &self,
        stream: &mut PatchStream,
        data: &[u8],
        hash: ContentDigest,
    ) -> Result<()> {
        if self.hash_policy.transfer_integrity && self.observed_payload_hash(data) != hash {
            bail!("block hash mismatch on receive");
        }
        let received = stream
            .received
            .checked_add(data.len() as u64)
            .filter(|received| *received <= stream.data_len)
            .context("streamed patch data runs past its declared length")?;
        let writing = self
            .operation
            .span(crate::transfer_observations::Stage::DestinationWrite);
        let mut written = 0;
        let mut taken = 0;
        while taken < data.len() {
            written += self.place_reused(stream)?;
            // The run of new blocks from here that this piece fills.
            let patch = &stream.patch;
            let start = stream.next;
            let (mut end, mut run) = (start, 0);
            while let Some(None) = patch.reuse.get(end) {
                let len = patch.block.min(patch.len - end as u64 * patch.block) as usize;
                if taken + run + len > data.len() {
                    break;
                }
                run += len;
                end += 1;
            }
            if run == 0 {
                bail!("streamed patch piece ends inside a block or past the file");
            }
            let off = start as u64 * patch.block;
            let bytes = &data[taken..taken + run];
            let stage = stream
                .stage
                .as_ref()
                .context("streamed patch has no stage")?;
            if stream.seeded {
                // Old bytes lie under these blocks: zeros must replace them.
                if self.sparse {
                    crate::sparse::write_at(&stage.file, bytes, off, true)
                } else {
                    stage.file.write_all_at(bytes, off)
                }
            } else {
                write_data(&stage.file, bytes, off, self.sparse)
            }
            .with_context(|| format!("write {} @{off}", stage.label.display()))?;
            taken += run;
            written += run as u64;
            stream.next = end;
        }
        writing.bytes(written);
        stream.received = received;
        Ok(())
    }

    /// Place the reused blocks from the next one on, up to the next new
    /// block. A seeded stage holds them already; otherwise each is read from
    /// the file it replaces, which must still hash as compared. Returns the
    /// bytes written.
    fn place_reused(&self, stream: &mut PatchStream) -> Result<u64> {
        let patch = &stream.patch;
        let mut written = 0;
        while let Some(Some(_)) = patch.reuse.get(stream.next) {
            let first = stream.next;
            let mut end = first + 1;
            if stream.seeded {
                while let Some(Some(_)) = patch.reuse.get(end) {
                    end += 1;
                }
                stream.next = end;
                continue;
            }
            let run = REUSED_RUN_BYTES.max(patch.block) / patch.block;
            while (end - first) as u64 * patch.block < run * patch.block
                && matches!(patch.reuse.get(end), Some(Some(_)))
            {
                end += 1;
            }
            let off = first as u64 * patch.block;
            let len = ((end as u64 * patch.block).min(patch.len) - off) as usize;
            if stream.buffer.len() < len {
                stream.buffer.resize(len, 0);
            }
            let bytes = &mut stream.buffer[..len];
            let old = stream.old.as_ref().context("no file to reuse blocks of")?;
            if !self.holds_blocks(old, off, bytes, patch.block, &patch.reuse[first..end])? {
                bail!("the destination changed after it was compared");
            }
            let stage = stream
                .stage
                .as_ref()
                .context("streamed patch has no stage")?;
            write_data(&stage.file, bytes, off, self.sparse)
                .with_context(|| format!("write {} @{off}", stage.label.display()))?;
            written += len as u64;
            stream.next = end;
        }
        Ok(written)
    }

    /// End the open streamed patch: publish it, once all of its data has
    /// arrived, or abandon it.
    pub(in crate::fsops) fn end_patch_stream(&mut self, commit: bool) -> Result<Response> {
        let mut stream = self
            .patch_stream
            .take()
            .context("no streamed patch is open")?;
        let result = match stream.failure.clone() {
            Some(failure) => Err(failure),
            None => match self.publish_patch_stream(&mut stream, commit) {
                Ok(identity) => Ok(SmallPatched {
                    kept: false,
                    identity,
                }),
                Err(error) => {
                    self.fail_stream(&mut stream, error);
                    Err(stream
                        .failure
                        .clone()
                        .expect("the failure was just recorded"))
                }
            },
        };
        Ok(Response::PatchedBatch(vec![result]))
    }

    fn publish_patch_stream(
        &mut self,
        stream: &mut PatchStream,
        commit: bool,
    ) -> Result<Option<(u64, u64)>> {
        if !commit {
            bail!("the sender abandoned the streamed patch");
        }
        if stream.received != stream.data_len {
            bail!("streamed patch data ended early");
        }
        {
            let writing = self
                .operation
                .span(crate::transfer_observations::Stage::DestinationWrite);
            writing.bytes(self.place_reused(stream)?);
        }
        if stream.next != stream.patch.reuse.len() {
            bail!("streamed patch data ended early");
        }
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_PATCH_STREAM_END_READY_FILE",
            "SYQ_TEST_PATCH_STREAM_END_CONTINUE_FILE",
            "streamed patch before publication",
        )?;
        let stage = stream
            .stage
            .as_ref()
            .context("streamed patch has no stage")?;
        if self.sparse {
            crate::sparse::set_len(&stage.file, stream.patch.len)?;
        } else {
            stage.file.set_len(stream.patch.len)?;
        }
        check_destination_writes(&stage.file, &stage.label)?;
        set_meta_written_file_for_publication(
            &stage.file,
            &stream.put.meta,
            stream.put.flags,
            &stage.created,
        )
        .with_context(|| format!("set metadata {}", stage.label.display()))?;
        #[cfg(debug_assertions)]
        fail_put_small_before_rename_for_test(&stage.target.label)?;
        // The file the patch reused may have changed its condition while
        // the data arrived, as keeping another name of it does: the file is
        // then compared again, as a batch patch's would be.
        if stream.patch.condition != TargetCondition::Any {
            if let Err(error) = observe_rooted_condition(&stage.target, stream.patch.condition) {
                stream.stale = true;
                return Err(error);
            }
        }
        {
            let root = stage.target.root.clone();
            let _replacement = root.replacement_turn();
            let _turn = root.mutation_turn(&stage.target.relative).ok();
            self.publish_small_stage(&stream.put, stage)?;
        }
        stream.old = None;
        let stage = stream.stage.take().expect("the stage was just published");
        self.finish_small_stage(&stream.put, stage)
    }
}

/// Whether every block a patch reuses lies within the first `len` bytes of
/// the file it replaces, as a clone or copy of that file must hold them.
pub(super) fn reuses_within(patch: &SmallPatch, len: u64) -> bool {
    patch
        .reuse
        .iter()
        .enumerate()
        .filter(|(_, reuse)| reuse.is_some())
        .all(|(index, _)| (index as u64 * patch.block + patch.block).min(patch.len) <= len)
}
