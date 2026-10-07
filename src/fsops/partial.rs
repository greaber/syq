use super::*;

/// Bytes of a source a grouped comparison reads at once, rounded down to
/// whole comparison blocks, or one block when blocks are larger.
const DIFFERING_READ_CHUNK: u64 = 1 << 20;

impl FsOps {
    pub fn probe_partial(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        guard: Option<&ContainerGuard>,
    ) -> Result<Response> {
        if let Some(target) = self.rooted_destination_target(path, guard)? {
            let (_, _, metadata) = with_rooted_partial(&target, copy_id, |relative, _| {
                target.root.metadata_optional(relative)
            })?;
            let partial_size = metadata
                .filter(|metadata| is_owned_rooted_partial(*metadata))
                .map(|metadata| metadata.len);
            return Ok(Response::PartialSize(partial_size));
        }
        let p = resolve(path);
        let pp = self.partial_path(&p, copy_id)?;
        let partial_size = match fs::symlink_metadata(&pp) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Ok(metadata) if is_owned_partial(&metadata) => Some(metadata.len()),
            Ok(_) => None,
            Err(error) => return Err(error).with_context(|| format!("stat {}", pp.display())),
        };
        Ok(Response::PartialSize(partial_size))
    }

    fn create_partial_rooted(
        &self,
        root: &Root,
        relative: &RelativePath,
        mode: u32,
    ) -> Result<File> {
        #[cfg(target_os = "macos")]
        if self.inode_preservation.acls {
            return root.create_private_file(relative);
        }
        root.create_file(relative, mode)
    }

    /// Open or create a small file's sidecar for writing only, with the
    /// metadata read when it was opened. The caller checks that metadata:
    /// the name may have held something other than a new file.
    pub(super) fn open_or_create_write_only_partial(
        &self,
        root: &Root,
        relative: &RelativePath,
        mode: u32,
    ) -> Result<(File, fs::Metadata)> {
        #[cfg(target_os = "macos")]
        if self.inode_preservation.acls {
            let file = root.create_private_file(relative)?;
            let metadata = file.metadata()?;
            return Ok((file, metadata));
        }
        root.open_or_create_write_only_file(relative, mode)
    }

    fn create_inplace_file(root: &Root, relative: &RelativePath, mode: u32) -> Result<File> {
        // Other range workers, or Prepare after a CopyLocal fallback, must
        // reopen this new inode for writing. Finalize applies the requested
        // mode after every writer is done. Never chmod an existing destination
        // here: its write permissions still decide whether an update is allowed.
        let file = root.create_file(relative, mode | 0o200)?;
        let permissions = file.metadata()?.permissions();
        if permissions.mode() & 0o200 == 0 {
            // A umask or inherited default ACL can remove even owner write.
            file.set_permissions(fs::Permissions::from_mode(permissions.mode() | 0o200))?;
        }
        Ok(file)
    }

    pub(super) fn reusable_partial_permissions(&self, file: &File) -> Result<bool> {
        #[cfg(target_os = "macos")]
        if self.inode_preservation.acls {
            // A previously public inode may have readers with open descriptors.
            // Do not write further protected data through that inode on resume.
            return Ok(file.metadata()?.mode() & 0o077 == 0
                && crate::inode_metadata::staging_acl_is_empty(file)?);
        }
        let _ = file;
        Ok(true)
    }

    /// Open the sidecar at `relative` to resume from or overwrite, creating
    /// it exclusively in `create_mode` when absent and `create_if_missing`.
    /// A sidecar found there keeps its group and other bits: whoever they
    /// let open it may still hold it open, and a chmod does not stop them
    /// reading. One whose group or other bits exceed `widest`, the mode this
    /// attempt would create it in, is replaced instead. `None` leaves that
    /// check to the Prepare that came first in the attempt.
    pub(super) fn open_private_partial_rooted(
        &mut self,
        root: &Root,
        relative: &RelativePath,
        label: &Path,
        create_if_missing: bool,
        create_mode: u32,
        widest: Option<u32>,
    ) -> Result<Option<(File, OpenedPartial)>> {
        self.uncache_rooted(root, relative);
        let mut repaired_permissions = false;
        if create_if_missing {
            match self.create_partial_rooted(root, relative, create_mode) {
                Ok(file) => {
                    let created = file.metadata()?;
                    note_created_owner(&created);
                    self.note_created_mode(&file, &created, create_mode);
                    return Ok(Some((file, OpenedPartial::Created(created))));
                }
                Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {}
                Err(error) => return Err(error),
            }
        }
        for _ in 0..8 {
            match root.metadata_optional(relative)? {
                Some(metadata) if is_owned_rooted_partial(metadata) => {
                    match root.open_regular_read_write(relative) {
                        Ok(file) => {
                            let opened = file.metadata()?;
                            let named = root.metadata(relative)?;
                            if !is_owned_partial(&opened)
                                || !is_owned_rooted_partial(named)
                                || opened.dev() != named.dev
                                || opened.ino() != named.ino
                            {
                                continue;
                            }
                            if !self.reusable_partial_permissions(&file)?
                                || self.wider_than(opened.mode(), opened.dev(), widest)
                            {
                                drop(file);
                                discard_safe_rooted_partial_if_same(
                                    root,
                                    relative,
                                    opened.dev(),
                                    opened.ino(),
                                    label,
                                )?;
                                continue;
                            }
                            let reported = reported_mode(opened.mode());
                            let repaired = reported & 0o777 | 0o600;
                            if reported & 0o7777 != repaired {
                                let repair = (|| -> Result<()> {
                                    fail_partial_chmod_for_test()?;
                                    file.set_permissions(fs::Permissions::from_mode(repaired))?;
                                    Ok(())
                                })();
                                if let Err(error) = repair {
                                    drop(file);
                                    discard_safe_rooted_partial_if_same(
                                        root,
                                        relative,
                                        opened.dev(),
                                        opened.ino(),
                                        label,
                                    )
                                    .with_context(|| {
                                        format!(
                                            "replace partial {} after chmod failed: {error:#}",
                                            label.display()
                                        )
                                    })?;
                                    continue;
                                }
                            }
                            return Ok(Some((file, OpenedPartial::Reused(opened.len()))));
                        }
                        Err(error)
                            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                error.kind() == io::ErrorKind::PermissionDenied
                            }) =>
                        {
                            if repaired_permissions {
                                discard_safe_rooted_partial_if_same(
                                    root,
                                    relative,
                                    metadata.dev,
                                    metadata.ino,
                                    label,
                                )
                                .with_context(|| {
                                    format!(
                                        "replace partial {} after it remained unreadable",
                                        label.display()
                                    )
                                })?;
                                repaired_permissions = false;
                                continue;
                            }
                            let handle = match root.open_metadata(relative) {
                                Ok(handle) => handle,
                                Err(repair_error) => {
                                    discard_safe_rooted_partial_if_same(
                                        root,
                                        relative,
                                        metadata.dev,
                                        metadata.ino,
                                        label,
                                    )
                                    .with_context(|| {
                                        format!(
                                            "replace partial {} after permission repair failed: {repair_error:#}",
                                            label.display()
                                        )
                                    })?;
                                    continue;
                                }
                            };
                            if !is_owned_partial(&handle.metadata()?) {
                                continue;
                            }
                            require_rooted_metadata(&handle, metadata, label)?;
                            if !self.reusable_partial_permissions(&handle)?
                                || self.wider_than(metadata.mode, metadata.dev, widest)
                            {
                                drop(handle);
                                discard_safe_rooted_partial_if_same(
                                    root,
                                    relative,
                                    metadata.dev,
                                    metadata.ino,
                                    label,
                                )?;
                                continue;
                            }
                            let repair = (|| -> Result<()> {
                                fail_partial_chmod_for_test()?;
                                set_mode_handle(&handle, metadata.mode & 0o777 | 0o600)?;
                                Ok(())
                            })();
                            if let Err(error) = repair {
                                drop(handle);
                                discard_safe_rooted_partial_if_same(
                                    root,
                                    relative,
                                    metadata.dev,
                                    metadata.ino,
                                    label,
                                )
                                .with_context(|| {
                                    format!(
                                        "replace partial {} after chmod failed: {error:#}",
                                        label.display()
                                    )
                                })?;
                                continue;
                            }
                            repaired_permissions = true;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Some(_) if !create_if_missing => return Ok(None),
                Some(_) => root.unlink(relative)?,
                None if !create_if_missing => return Ok(None),
                None => match self.create_partial_rooted(root, relative, create_mode) {
                    Ok(file) => {
                        let created = file.metadata()?;
                        note_created_owner(&created);
                        self.note_created_mode(&file, &created, create_mode);
                        return Ok(Some((file, OpenedPartial::Created(created))));
                    }
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
                    {
                        continue
                    }
                    Err(error) => return Err(error),
                },
            }
        }
        bail!(
            "partial {} changed repeatedly while opening it",
            label.display()
        )
    }

    /// Remove this copy's sidecar when its group or other bits exceed
    /// `widest`, as `open_private_partial_rooted` replaces such a sidecar.
    fn discard_wider_partial(
        &mut self,
        target: &RootedTarget,
        copy_id: &CopyId,
        widest: u32,
    ) -> Result<()> {
        with_rooted_partial(target, copy_id, |relative, label| {
            self.uncache_rooted(&target.root, relative);
            match target.root.metadata_optional(relative)? {
                Some(metadata)
                    if is_owned_rooted_partial(metadata)
                        && self.wider_than(metadata.mode, metadata.dev, Some(widest)) =>
                {
                    discard_safe_rooted_partial_if_same(
                        &target.root,
                        relative,
                        metadata.dev,
                        metadata.ino,
                        label,
                    )
                }
                _ => Ok(()),
            }
        })?;
        Ok(())
    }

    /// Bounded, best-effort discovery using equality on the readable prefix.
    /// A truncated prefix is currently indistinguishable from a full basename.
    pub(super) fn candidate_partials(&mut self, target: &RootedTarget) -> Vec<PathBytes> {
        let label = target.relative.to_path_buf();
        let parent = label.parent().unwrap_or_else(|| Path::new(""));
        let basename = label.file_name().unwrap_or_default().as_bytes();
        let Ok(relative) = RelativePath::new(parent.as_os_str().as_bytes()) else {
            return Vec::new();
        };
        let key = FileLocation::Rooted {
            root: target.root.identity(),
            relative,
        };
        if !self.partial_candidates.contains_key(&key) {
            if self.partial_candidates.len() >= PARTIAL_DIRECTORY_CACHE_MAX {
                if let Some(oldest) = self.partial_directory_order.pop_front() {
                    self.partial_candidates.remove(&oldest);
                }
            }
            self.partial_directory_order.push_back(key.clone());
        }
        let candidates = self.partial_candidates.entry(key).or_insert_with(|| {
            let names = RelativePath::new(parent.as_os_str().as_bytes())
                .ok()
                .and_then(|relative| target.root.read_directory(&relative).ok())
                .unwrap_or_default();
            let mut by_basename: HashMap<PathBytes, Vec<PathBytes>> = HashMap::new();
            for name in names
                .into_iter()
                .filter(|name| is_partial_name(OsStr::from_bytes(name)))
                .take(PARTIAL_CANDIDATES_MAX)
            {
                let at = name.len() - PARTIAL_MARKER.len() - 16;
                if at > 1 {
                    by_basename
                        .entry(name[1..at].to_vec())
                        .or_default()
                        .push(name);
                }
            }
            by_basename
        });
        candidates
            .get(basename)
            .into_iter()
            .flatten()
            .map(|name| path_bytes(&parent.join(OsStr::from_bytes(name))))
            .collect()
    }

    fn set_copy_length(&self, file: &File, size: u64) -> io::Result<()> {
        if self.sparse {
            crate::sparse::set_len(file, size)
        } else {
            file.set_len(size)
        }
    }

    pub(super) fn preallocate_new_partial(&mut self, file: &File, size: u64) -> Result<()> {
        if self.sparse {
            return crate::sparse::set_len(file, size).context("set sparse partial length");
        }
        #[cfg(target_os = "linux")]
        {
            preallocate_new_file_on(file, file.metadata()?.dev(), size)
        }
        #[cfg(not(target_os = "linux"))]
        {
            preallocate_new_file(file, size)
        }
    }

    pub(super) fn prepare(
        &mut self,
        target: PartialTarget<'_>,
        options: PrepareOptions,
    ) -> Result<Preparation> {
        let PartialTarget {
            path,
            id: copy_id,
            guard,
        } = target;
        let PrepareOptions {
            size,
            inplace,
            mode,
            attempt,
            create_if_missing,
        } = options;
        let target = self.destination_mutation_target(path, guard)?;
        // Existing finals get their equality check first. For new files,
        // defer allocation until seeding so a fresh preallocation cannot be
        // mistaken for bytes already written by this invocation on a retry.
        if !inplace && create_if_missing && size > 0 && !self.candidate_partials(&target).is_empty()
        {
            if attempt > 0 {
                // Seeding resumes from a sidecar an earlier attempt left,
                // without this attempt's mode to check it against.
                self.discard_wider_partial(&target, copy_id, mode | 0o600)?;
            }
            return Ok(Preparation {
                partial_size: None,
                has_candidates: true,
            });
        }
        if inplace {
            self.uncache_rooted(&target.root, &target.relative);
            if self
                .held_basis
                .as_ref()
                .is_some_and(|held| held.location == target.location() && held.copy_id == *copy_id)
            {
                // The coordinator reuses hashes from this inode. Never resize
                // or write a replacement name using that earlier comparison.
                let held = self.held_basis.take().unwrap();
                let metadata = held.file.metadata()?;
                let file = target.root.open_regular_read_write(&target.relative)?;
                require_open_target(
                    &file,
                    &target.label,
                    TargetCondition::Matches {
                        dev: metadata.dev(),
                        ino: metadata.ino(),
                    },
                )?;
                self.set_copy_length(&file, size)?;
                self.cache_file(target.location(), attempt, false, file);
                return Ok(Preparation::default());
            }
            // Open the name directly, creating it when absent, as a small
            // in-place put does; finalize checks the target condition as it
            // always did. A regular file there, new or existing, is the
            // destination: the open is read-write because a resume hashes an
            // existing file through this descriptor, and a new file keeps
            // owner access for the other range workers until publication
            // sets its mode. The metadata read at the open serves finalize.
            // Anything else at the name is sorted out by the checks below.
            match target
                .root
                .open_or_create_read_write_file(&target.relative, mode | 0o600)
            {
                Ok((file, mut opened)) if opened.is_file() => {
                    let euid = unsafe { libc::geteuid() };
                    if euid != 0 && opened.uid() == euid && opened.mode() & 0o600 != 0o600 {
                        // A umask or inherited default ACL can remove even
                        // owner access from a new file; a file of ours that
                        // opened read-write with less can only be new, since
                        // the open checks owner bits for everyone but root,
                        // whose workers reopen any file regardless. An
                        // existing file of another account that admitted the
                        // open through other bits is never chmod'ed. Finalize
                        // decides its chmod from the metadata kept here, so
                        // read it again.
                        file.set_permissions(fs::Permissions::from_mode(
                            opened.mode() & 0o7777 | 0o600,
                        ))?;
                        opened = file.metadata()?;
                    }
                    self.set_copy_length(&file, size).with_context(|| {
                        format!("resize confined file {}", target.label.display())
                    })?;
                    self.cache_opened_file(target.location(), attempt, false, file, opened);
                    return Ok(Preparation::default());
                }
                Ok(_) => {}
                Err(error) if existing_leaf_refused(&error) => {}
                Err(error) => return Err(error),
            }
            for _ in 0..8 {
                match target.root.metadata_optional(&target.relative)? {
                    Some(metadata) if metadata.is_file() => {
                        // Retain a descriptor that can service the
                        // immediately following destination hash as well
                        // as range writes. Its metadata, read before the
                        // writes, serves finalize.
                        let file = target.root.open_regular_read_write(&target.relative)?;
                        require_rooted_metadata(&file, metadata, &target.label)?;
                        let opened = file.metadata()?;
                        self.set_copy_length(&file, size).with_context(|| {
                            format!("resize confined file {}", target.label.display())
                        })?;
                        self.cache_opened_file(target.location(), attempt, false, file, opened);
                        return Ok(Preparation::default());
                    }
                    Some(metadata) if metadata.is_dir() => {
                        bail!("destination {} is a directory", target.label.display())
                    }
                    Some(_) => target.root.unlink(&target.relative)?,
                    None => match Self::create_inplace_file(&target.root, &target.relative, mode) {
                        Ok(file) => {
                            let opened = file.metadata()?;
                            self.set_copy_length(&file, size).with_context(|| {
                                format!("resize confined file {}", target.label.display())
                            })?;
                            self.cache_opened_file(target.location(), attempt, false, file, opened);
                            return Ok(Preparation::default());
                        }
                        Err(error)
                            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                error.kind() == io::ErrorKind::AlreadyExists
                            }) =>
                        {
                            continue
                        }
                        Err(error) => return Err(error),
                    },
                }
            }
            bail!(
                "destination {} changed repeatedly while opening it",
                target.label.display()
            );
        }
        // A partial this creates is registered, so that an interrupted
        // receiver removes it when it is too short to be worth resuming.
        let creation = create_if_missing.then(sidecars::begin).transpose()?;
        let (relative, _label, opened) =
            with_rooted_partial(&target, copy_id, |relative, label| {
                if create_if_missing {
                    // A new sidecar is created as the small-file batch
                    // creates its own: for writing only, in its staged mode,
                    // without exclusive creation, and used as created only
                    // when the open landed on a new empty file of ours. Its
                    // metadata, read at once, serves publication. Anything
                    // else at the name takes the checked reuse below. Other
                    // range workers reopen the sidecar by name for writing,
                    // and verification reopens it for reading, so it keeps
                    // owner access until publication sets the final mode, as
                    // an in-place file does; that chmod is paid only by files
                    // whose final mode lacks it.
                    let staged = mode | 0o600;
                    self.uncache_rooted(&target.root, relative);
                    if !creates_foreign_owners(target.root.identity().dev) {
                        match self.open_or_create_write_only_partial(&target.root, relative, staged)
                        {
                            Ok((file, created))
                                if is_fresh_partial(&created, staged)
                                    && created.mode() & 0o600 == 0o600 =>
                            {
                                return Ok(Some((file, None, Some(created), None)));
                            }
                            Ok(_) => {}
                            Err(error) if existing_leaf_refused(&error) => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
                self.open_private_partial_rooted(
                    &target.root,
                    relative,
                    label,
                    create_if_missing,
                    PRIVATE_PARTIAL_MODE,
                    Some(mode | 0o600),
                )
                .map(|opened| {
                    opened
                        .map(|(file, opened)| (file, opened.basis_size(), None, opened.identity()))
                })
            })?;
        let Some((file, basis_size, created, identity)) = opened else {
            return Ok(Preparation {
                partial_size: None,
                has_candidates: !self.candidate_partials(&target).is_empty(),
            });
        };
        if let (Some(creation), Some(identity)) =
            (creation, identity.or(created.as_ref().map(identity_of)))
        {
            creation.register(&target.root, &relative, identity, Sidecar::Partial);
        }
        if let Some(old_size) = basis_size {
            if old_size > size {
                self.set_copy_length(&file, size)?;
            }
        } else {
            self.preallocate_new_partial(&file, size)?;
        }
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_PARTIAL_READY_FILE",
            "SYQ_TEST_PARTIAL_CONTINUE_FILE",
            "partial-ready",
        )?;
        let location = FileLocation::Rooted {
            root: target.root.identity(),
            relative,
        };
        match created {
            Some(created) => self.cache_opened_file(location, attempt, true, file, created),
            None => self.cache_file(location, attempt, true, file),
        }
        Ok(Preparation {
            partial_size: basis_size,
            has_candidates: false,
        })
    }

    #[cfg(test)]
    pub fn hash_and_hold(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        block: u64,
        len: u64,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<(Vec<ContentDigest>, u64)> {
        self.hash_and_hold_window(path, copy_id, 0, block, len, condition, guard)
    }

    #[allow(clippy::too_many_arguments)]
    fn hash_and_hold_window(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        off: u64,
        block: u64,
        len: u64,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<(Vec<ContentDigest>, u64)> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_HASH_BASIS").is_some() {
            bail!("injected retained-basis hash failure");
        }
        anyhow::ensure!(
            block > 0 && off.is_multiple_of(block) && off.checked_add(len).is_some(),
            "invalid hash interval"
        );
        let rooted = self.rooted_destination_target(path, guard)?;
        let location = rooted
            .as_ref()
            .map(|target| target.location())
            .unwrap_or_else(|| FileLocation::Path(resolve(path)));
        let (mut file, location, label) = if off > 0 {
            let held = self
                .held_basis
                .take()
                .context("no retained comparison basis")?;
            anyhow::ensure!(
                held.location == location && held.copy_id == *copy_id,
                "retained comparison basis does not match requested file"
            );
            (held.file, held.location, held.label)
        } else if let Some(target) = &rooted {
            (
                target.root.open_regular_read(&target.relative)?,
                target.location(),
                target.label.clone(),
            )
        } else {
            let p = resolve(path);
            open_existing_regular(&p, false)
                .with_context(|| format!("open {} as repair basis", p.display()))
                .map(|file| (file, FileLocation::Path(p.clone()), p))?
        };
        require_open_target(&file, &label, condition)?;
        #[cfg(debug_assertions)]
        record_test_event(
            "SYQ_TEST_BASIS_HASH_EVENTS",
            format_args!("hash {off} {len}"),
        )?;
        file.seek(SeekFrom::Start(off))?;
        let hashes = hash_reader_observed(
            &mut file,
            block,
            len,
            Some(&self.operation),
            self.hash_policy.algorithm,
        )?;
        self.held_basis = Some(HeldBasis {
            location,
            label,
            copy_id: *copy_id,
            file,
        });
        #[cfg(debug_assertions)]
        if off == 0 {
            test_race_barrier(
                "SYQ_TEST_BASIS_READY_FILE",
                "SYQ_TEST_BASIS_CONTINUE_FILE",
                "basis-ready",
            )?;
        }
        // Hashing is intentionally limited to the source length. Report the
        // retained inode's length afterward so a file that grew since the
        // planner's stat cannot be mistaken for an exact content match.
        let held_len = self
            .held_basis
            .as_ref()
            .expect("basis retained above")
            .file
            .metadata()?
            .len();
        Ok((hashes, held_len))
    }

    pub(super) fn take_held_basis(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        guard: Option<&ContainerGuard>,
    ) -> Result<(HeldBasis, RootedTarget)> {
        let held = self
            .held_basis
            .take()
            .context("no retained destination basis")?;
        let target = self.destination_mutation_target(path, guard)?;
        if held.location != target.location() || held.copy_id != *copy_id {
            bail!("retained destination basis does not match requested file");
        }
        Ok((held, target))
    }

    pub fn finish_basis(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        meta: &Meta,
        flags: u8,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<Option<(u64, u64)>> {
        let (held, target) = self.take_held_basis(path, copy_id, guard)?;
        require_open_target(&held.file, &held.label, condition)?;
        set_meta_file(&held.file, meta, flags)
            .with_context(|| format!("set metadata on basis {}", held.label.display()))?;
        if guard.is_some() {
            // A signed receiver keeps the pre-existing guarded behavior:
            // even an `Any` update must still be attached to its enrolled
            // name. An unrestricted content-identical repair preserves
            // the ordinary retry semantics below, where `Any` may finish
            // through the retained inode after a concurrent publication.
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                &held.file,
                condition,
            )?;
        } else if condition != TargetCondition::Any {
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                &held.file,
                condition,
            )?;
        }
        published_identity(&held.file, flags)
    }

    pub(super) fn seed_basis(
        &mut self,
        target: PartialTarget<'_>,
        len: u64,
        block: u64,
        final_ranges: Option<&[(u64, u64)]>,
        attempt: u32,
    ) -> Result<SeededBasis> {
        self.seed_basis_impl(target, len, block, final_ranges, attempt, false)
            .map(|(basis, _)| basis)
    }

    #[allow(clippy::too_many_arguments)]
    fn seed_basis_impl(
        &mut self,
        target: PartialTarget<'_>,
        len: u64,
        block: u64,
        final_ranges: Option<&[(u64, u64)]>,
        attempt: u32,
        stage_only: bool,
    ) -> Result<(SeededBasis, bool)> {
        let PartialTarget {
            path,
            id: copy_id,
            guard,
        } = target;
        if !hash_response_fits(block, if stage_only { 0 } else { len }) {
            bail!("invalid block reuse request");
        }
        if let Some(ranges) = final_ranges {
            let mut previous_end = 0;
            for &(start, end) in ranges {
                if start < previous_end
                    || start >= end
                    || end > len
                    || !start.is_multiple_of(block)
                    || (end != len && !end.is_multiple_of(block))
                {
                    bail!("invalid final basis ranges");
                }
                previous_end = end;
            }
        }
        let target = self.destination_mutation_target(path, guard)?;
        let expected = target.location();
        // A previous failed job may have left a hold on this connection. It is
        // only an optional donor here, unlike the explicit FinishBasis request.
        let held = self
            .held_basis
            .take()
            .filter(|held| held.location == expected && held.copy_id == *copy_id);
        #[cfg(target_os = "macos")]
        if stage_only {
            self.try_clone_basis(
                &target,
                copy_id,
                final_ranges.is_none_or(|ranges| !ranges.is_empty()),
            )?;
        }
        let creation = sidecars::begin()?;
        let (relative, label, opened) =
            with_rooted_partial(&target, copy_id, |relative, label| {
                // Prepare has replaced an earlier attempt's sidecar that is
                // wider than this attempt's staged mode, which is not sent
                // here. One that is not is resumed as it is.
                self.open_private_partial_rooted(
                    &target.root,
                    relative,
                    label,
                    true,
                    PRIVATE_PARTIAL_MODE,
                    None,
                )
            })?;
        let (output, opened) = opened.context("sidecar creation was requested")?;
        let (basis_size, created) = (opened.basis_size(), opened.identity());
        let location = FileLocation::Rooted {
            root: target.root.identity(),
            relative: relative.clone(),
        };
        // Retry bytes already belong to this invocation. Hash them in place;
        // copying them onto themselves adds writes without improving safety.
        let mut input = None;
        let access = SeedAccess::new(&output);
        if basis_size.unwrap_or(0) == 0 && len > 0 {
            for candidate in self.candidate_partials(&target) {
                let Ok(relative) = RelativePath::new(&candidate) else {
                    continue;
                };
                let candidate_location = FileLocation::Rooted {
                    root: target.root.identity(),
                    relative,
                };
                if candidate_location == location {
                    continue;
                }
                // Donors are read-only hints. Missing or unsuitable files are
                // cache misses; successful reads are hashed from the same buffer
                // that is written, even if the donor changes or is unlinked.
                let opened = RelativePath::new(&candidate)
                    .and_then(|relative| target.root.open_regular_read(&relative));
                if let Ok(file) = opened {
                    if file
                        .metadata()
                        .is_ok_and(|m| is_owned_partial(&m) && m.len() > 0)
                        && access.admits(&file)
                    {
                        input = Some(file);
                        break;
                    }
                }
            }
        }
        // A previous transfer's partial is usually closer to the source than
        // the old final. Use the final only when no readable candidate exists.
        let mut selected_final = None;
        let mut final_donor = false;
        if final_ranges.is_none_or(|ranges| !ranges.is_empty())
            && basis_size.unwrap_or(0) == 0
            && input.is_none()
        {
            input = held
                .map(|held| held.file)
                .or_else(|| target.root.open_regular_read(&target.relative).ok());
            selected_final = input.as_ref().and(final_ranges);
            final_donor = input.is_some();
        }
        // A partial's bytes, and the final file's when no matching ranges
        // were selected, are not just the new contents. A staged basis on
        // macOS copies nothing from the final: it compares it instead, and
        // clones it only where no ACL entries are inherited.
        let seeds_other_bytes = !final_donor || (!stage_only && selected_final.is_none());
        if final_donor
            && seeds_other_bytes
            && !input.as_ref().is_some_and(|donor| access.admits(donor))
        {
            input = None;
            final_donor = false;
        }
        // A donor's bytes go only into a sidecar created for them: an empty
        // one found at the name may have been opened while its mode was
        // wider, as when an earlier attempt created it in the final mode.
        let (output, basis_size) = if input.is_some() && basis_size.is_some() {
            drop(output);
            self.uncache_rooted(&target.root, &relative);
            let (output, created) =
                create_fresh_rooted_partial(&target.root, &relative, &label, || {
                    self.create_partial_rooted(&target.root, &relative, PRIVATE_PARTIAL_MODE)
                })?;
            creation.register(
                &target.root,
                &relative,
                identity_of(&created),
                Sidecar::Partial,
            );
            // The new sidecar takes the directory's entries as they are now.
            let access = SeedAccess::new(&output);
            if seeds_other_bytes && !input.as_ref().is_some_and(|donor| access.admits(donor)) {
                input = None;
                selected_final = None;
                final_donor = false;
            }
            (output, None)
        } else {
            if let Some(identity) = created {
                creation.register(&target.root, &relative, identity, Sidecar::Partial);
            }
            (output, basis_size)
        };
        if stage_only {
            let mut compare_final = false;
            if let Some(input) = input.as_ref() {
                let _copy = self
                    .operation
                    .span(crate::transfer_observations::Stage::FilesystemCopy);
                if final_donor {
                    let donor = input.metadata()?;
                    #[cfg(target_os = "linux")]
                    let cloned = super::basis_copy::try_clone(input, &output, len.min(donor.len()));
                    #[cfg(not(target_os = "linux"))]
                    let cloned = false;
                    // APFS was tried before creating the sidecar. Without a
                    // clone, retain bounded windows instead of copying bytes
                    // that comparison may immediately replace.
                    compare_final = !cloned;
                    if compare_final
                        && donor.len() > 0
                        && donor.blocks().saturating_mul(512) >= donor.len()
                    {
                        // Keep the existing dense-file allocation policy. Do
                        // not materialize sparse donor holes or cloned extents.
                        self.preallocate_new_partial(&output, len)?;
                    }
                } else {
                    let donor = input.metadata()?;
                    super::basis_copy::seed(input, &output, len, || {
                        // Preserve sparse extents and successful clones. Dense
                        // donors still reserve capacity before copying begins.
                        if donor.blocks().saturating_mul(512) >= donor.len() {
                            self.preallocate_new_partial(&output, len)?;
                        }
                        Ok(())
                    })?;
                }
            }
            #[cfg(debug_assertions)]
            test_race_barrier(
                "SYQ_TEST_STAGED_BASIS_READY_FILE",
                "SYQ_TEST_STAGED_BASIS_CONTINUE_FILE",
                "staged comparison basis",
            )?;
            // Never replace an existing partial with an older final-file donor.
            self.set_copy_length(&output, len)?;
            self.cache_file(location, attempt, true, output);
            return Ok((
                SeededBasis {
                    hashes: Vec::new(),
                    selected_final: false,
                },
                compare_final,
            ));
        }
        if basis_size.unwrap_or(0) == 0 {
            self.preallocate_new_partial(&output, len)?;
        }
        // A cached donor can disappear or become unsuitable before opening.
        // Freshly allocated zeros are not old copy data worth scanning.
        let reader = input
            .as_ref()
            .or_else(|| (basis_size.unwrap_or(0) > 0).then_some(&output));
        let mut hashes = Vec::new();
        if let Some(reader) = reader {
            let whole = [(0, len)];
            let ranges = selected_final.unwrap_or(&whole);
            let count: u64 = ranges
                .iter()
                .map(|(start, end)| (end - start).div_ceil(block))
                .sum();
            hashes.reserve(count as usize);
            let mut buffer = vec![0; block.min(len) as usize];
            'ranges: for &(start, end) in ranges {
                for off in (start..end).step_by(block as usize) {
                    let bytes = &mut buffer[..(len - off).min(block) as usize];
                    if reader.read_exact_at(bytes, off).is_err() {
                        // An absent trailing hash means the controller must transfer
                        // that block, even when subsequent selected ranges exist.
                        break 'ranges;
                    }
                    let hash = self.hash_policy.algorithm.hash(bytes);
                    if input.is_some() {
                        #[cfg(debug_assertions)]
                        test_race_barrier(
                            "SYQ_TEST_REUSE_READY_FILE",
                            "SYQ_TEST_REUSE_CONTINUE_FILE",
                            "reuse buffered bytes",
                        )?;
                        if self.sparse {
                            crate::sparse::write_at(&output, bytes, off, false)
                        } else {
                            output.write_all_at(bytes, off)
                        }
                        .context("write reused block")?;
                    }
                    hashes.push(hash);
                }
            }
        }
        if output.metadata()?.len() != len {
            self.set_copy_length(&output, len)?;
        }
        self.cache_file(location, attempt, true, output);
        Ok((
            SeededBasis {
                hashes,
                selected_final: selected_final.is_some(),
            },
            false,
        ))
    }

    #[cfg(target_os = "macos")]
    fn try_clone_basis(
        &mut self,
        target: &RootedTarget,
        copy_id: &CopyId,
        allow_final: bool,
    ) -> Result<()> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_BASIS_CLONE_UNSUPPORTED").is_some() {
            return Ok(());
        }
        // APFS cloning creates a new name. Try it before opening a new sidecar,
        // and never unlink or replace an existing resumable output to clone.
        let creation = sidecars::begin()?;
        let (relative, _, cloned) = with_rooted_partial(target, copy_id, |relative, _| {
            if target.root.metadata_optional(relative)?.is_some() {
                return Ok(None);
            }
            let mut donor = None;
            for candidate in self.candidate_partials(target) {
                let file = RelativePath::new(&candidate)
                    .and_then(|path| target.root.open_regular_read(&path));
                if let Ok(file) = file {
                    if file
                        .metadata()
                        .is_ok_and(|m| is_owned_partial(&m) && m.len() > 0)
                    {
                        donor = Some(file);
                        break;
                    }
                }
            }
            if donor.is_none() && allow_final {
                donor = target.root.open_regular_read(&target.relative).ok();
            }
            let Some(file) = donor else {
                return Ok(None);
            };
            let metadata = file.metadata()?;
            // Clone the donor's actual size; preparation resizes it to the
            // planned output length, including growth and shrinkage.
            target
                .root
                .clone_file_open(&file, &metadata, relative, metadata.len())
        })?;
        if let Some(clone) = cloned {
            creation.register_with(&target.root, &relative, Sidecar::Partial, || {
                clone.metadata().map(|metadata| identity_of(&metadata))
            })?;
        }
        Ok(())
    }

    /// `inspect_parent` sees the directory that will hold the copy, so a
    /// caller can learn about the destination filesystem before it creates
    /// anything there.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn prepare_local_copy<T>(
        &self,
        source: &RegisteredPath,
        dst: &[u8],
        inspect_parent: impl FnOnce(&File) -> T,
    ) -> Result<(File, fs::Metadata, RootedTarget, T)> {
        let source_target = self
            .registered_source_target(source)
            .context("resolve registered local-copy source")?;
        let source_label = PathBuf::from(OsStr::from_bytes(source.relative()));
        let s = open_registered_source(&source_target, self.inode_preservation.open_noatime)
            .with_context(|| format!("open registered source {}", source_label.display()))?;
        let destination_root = self
            .destination_root
            .clone()
            .context("local copy requires a registered destination root")?;
        let dp = PathBuf::from(OsStr::from_bytes(dst));
        let destination_relative = RelativePath::new(dst)?;
        let destination_label = self.logical_destination_path(&dp);
        #[cfg(debug_assertions)]
        hold_copy_local_before_destination_open_for_test()?;
        let source_metadata = s.metadata()?;
        let parent = destination_root.resolve_parent(&destination_relative)?;
        let inspected = inspect_parent(parent.directory());
        drop(parent);
        Ok((
            s,
            source_metadata,
            RootedTarget {
                root: destination_root,
                relative: destination_relative,
                label: destination_label,
                create_missing_parents: false,
                query_partial_name_limit: false,
            },
            inspected,
        ))
    }

    /// A staged copy could safely replace a hard-linked destination, but a
    /// command that names the same file is still a self-copy and should not
    /// silently replace its own selected source. The in-place open repeats
    /// this check against the exact descriptor before truncation. It is made
    /// right before the destination is touched: looking the name up costs an
    /// NFS client a request, which a pair known to need the range path spares.
    pub(super) fn require_not_self_copy(
        target: &RootedTarget,
        source_metadata: &fs::Metadata,
    ) -> Result<()> {
        let parent = target.root.resolve_parent(&target.relative)?;
        match parent.metadata() {
            Ok(metadata)
                if metadata.is_file()
                    && metadata.dev == source_metadata.dev()
                    && metadata.ino == source_metadata.ino() =>
            {
                bail!(
                    "source and destination are the same file: {}",
                    target.label.display()
                )
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("stat {}", target.label.display())),
        }
    }

    /// Copy a whole same-machine file without routing its bytes through the
    /// transport. Prefer copy_file_range; eligible local filesystems and the
    /// measured asynchronous NFS destination case use a sequential userspace
    /// writer when offload is unsupported. File workers still run in parallel;
    /// other filesystem pairs retain the adaptive range path.
    #[cfg(target_os = "linux")]
    pub(super) fn copy_local(
        &mut self,
        source: &RegisteredPath,
        dst: &[u8],
        policy: CopyLocalPolicy<'_>,
        copy_id: &CopyId,
        size: u64,
        mode: u32,
    ) -> Result<CopyLocalOutcome> {
        let _copy = self
            .operation
            .span(crate::transfer_observations::Stage::FilesystemCopy);
        // An equality probe that found a difference may have retained the
        // destination inode; the replacement is staged and published by name.
        self.held_basis.take();
        let CopyLocalPolicy {
            inplace,
            replace_partial,
            allow_sequential_nfs_fallback,
            allow_sequential_local_fallback,
            progress,
        } = policy;
        let mut progress = CopyProgress::new(progress, size);
        // A new entry lives on its directory's filesystem, so the directory
        // answers every filesystem question before a sidecar exists.
        let (s, source_metadata, target, destination) =
            self.prepare_local_copy(source, dst, opened_file_system)?;
        let (destination_key, destination_fs) =
            destination.context("inspect the destination filesystem")?;
        let source_label = PathBuf::from(OsStr::from_bytes(source.relative()));
        let destination_root = target.root.clone();
        let source_key = file_system_key(&s, source_metadata.dev());
        let source_fs = file_system_traits(&s, source_key);
        // Exercise fallback policy independently of the filesystem hosting the
        // integration tests. Apply before the NFS/synchronous overrides so those
        // exclusions can still be tested with otherwise eligible local traits.
        #[cfg(debug_assertions)]
        let (source_fs, destination_fs) = match std::env::var("SYQ_TEST_COPY_LOCAL_FS").as_deref() {
            Ok("local") => {
                let local = FileSystemTraits {
                    measured_local_source: true,
                    local_userspace_copy: true,
                    ..FileSystemTraits::default()
                };
                (local, local)
            }
            Ok("unsupported") => (FileSystemTraits::default(), FileSystemTraits::default()),
            Ok(value) => panic!("unknown SYQ_TEST_COPY_LOCAL_FS value: {value}"),
            Err(_) => (source_fs, destination_fs),
        };
        #[cfg(debug_assertions)]
        let source_fs = FileSystemTraits {
            is_nfs: source_fs.is_nfs
                || std::env::var_os("SYQ_TEST_COPY_LOCAL_SOURCE_NFS").is_some(),
            measured_local_source: source_fs.measured_local_source
                || std::env::var_os("SYQ_TEST_COPY_LOCAL_SOURCE_DISK").is_some(),
            ..source_fs
        };
        #[cfg(debug_assertions)]
        let destination_fs = FileSystemTraits {
            is_nfs: destination_fs.is_nfs || std::env::var_os("SYQ_TEST_COPY_LOCAL_NFS").is_some(),
            synchronous: destination_fs.synchronous
                || std::env::var_os("SYQ_TEST_COPY_LOCAL_NFS_SYNC").is_some(),
            ..destination_fs
        };
        // The measured fast path is a local filesystem feeding an ordinary
        // asynchronous NFS mount. NFS reads can benefit from parallelism, and
        // a synchronous destination makes every write syscall wait for the
        // server, so let the normal adaptive range path handle either case.
        let use_sequential_nfs_fallback = allow_sequential_nfs_fallback
            && !source_fs.is_nfs
            && source_fs.measured_local_source
            && destination_fs.is_nfs
            && !destination_fs.synchronous;
        // Local files keep parallelism across files without paying transport
        // and per-range hashing costs. Explicit sparse mode also needs a buffered
        // writer when cloning cannot preserve its allocation.
        let use_userspace_fallback = self.sparse
            || use_sequential_nfs_fallback
            || (allow_sequential_local_fallback
                && source_fs.local_userspace_copy
                && destination_fs.local_userspace_copy
                && !source_fs.is_nfs
                && !destination_fs.is_nfs
                && !destination_fs.synchronous);
        let copy_pair = (source_key, destination_key);
        let copy_pair_unsupported = unsupported_copy_pairs()
            .lock()
            .unwrap()
            .contains(&copy_pair);
        if copy_pair_unsupported && !use_userspace_fallback {
            // An earlier file already showed that this pair cannot offload.
            // Leave the destination alone: a sidecar created only to be
            // removed costs two directory changes for every file, and an
            // in-place file opened or created only to be closed costs the
            // requests of its open and the one that Prepare repeats.
            return Ok(CopyLocalOutcome::Unsupported);
        }
        Self::require_not_self_copy(&target, &source_metadata)?;
        // Advisory sequential readahead for the kernel copy on Linux.
        unsafe {
            libc::posix_fadvise(s.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
        self.uncache_rooted(&destination_root, &target.relative);
        let (mut target_relative, mut target_label) =
            (target.relative.clone(), target.label.clone());
        // The bytes at the start of the output that hold old contents until
        // the copy writes over them: an in-place file's, within its new length.
        let mut old_len = 0;
        let d = if inplace {
            let mut opened = None;
            for _ in 0..8 {
                match destination_root.metadata_optional(&target_relative)? {
                    Some(metadata) if metadata.is_file() => {
                        let file = destination_root.open_regular_write(&target_relative, false)?;
                        require_rooted_metadata(&file, metadata, &target_label)?;
                        let metadata = file.metadata()?;
                        if metadata.dev() == source_metadata.dev()
                            && metadata.ino() == source_metadata.ino()
                        {
                            bail!(
                                "source and destination are the same file: {}",
                                target_label.display()
                            );
                        }
                        // Never empty the file before its new contents are
                        // written: a copy that fails part way, or a
                        // destination that refuses these writes, then
                        // leaves old data rather than nothing. Only bytes
                        // past the new end go now, which also lets a clone
                        // of a shorter, unaligned source replace the rest.
                        if metadata.len() > size {
                            file.set_len(size).with_context(|| {
                                format!("shorten confined file {}", target_label.display())
                            })?;
                        }
                        old_len = metadata.len().min(size);
                        opened = Some(file);
                        break;
                    }
                    Some(metadata) if metadata.is_dir() => {
                        bail!("destination {} is a directory", target_label.display())
                    }
                    Some(_) => destination_root.unlink(&target_relative)?,
                    None => {
                        match Self::create_inplace_file(&destination_root, &target_relative, mode) {
                            Ok(file) => {
                                opened = Some(file);
                                break;
                            }
                            Err(error)
                                if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                    error.kind() == io::ErrorKind::AlreadyExists
                                }) => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
            }
            opened.with_context(|| {
                format!(
                    "destination {} changed repeatedly while opening it",
                    target_label.display()
                )
            })?
        } else {
            let creation = sidecars::begin()?;
            let (relative, label, opened) =
                with_rooted_partial(&target, copy_id, |relative, label| {
                    self.open_private_partial_rooted(
                        &destination_root,
                        relative,
                        label,
                        true,
                        PRIVATE_PARTIAL_MODE,
                        Some(PRIVATE_PARTIAL_MODE),
                    )
                })?;
            target_relative = relative;
            target_label = label;
            let (d, opened) = opened.context("sidecar creation was requested")?;
            // A later copy on this machine copies the file whole again,
            // into a partial of its own, so this one is never resumed:
            // an interrupted copy removes it whatever its length.
            if let Some(identity) = opened.identity() {
                creation.register(
                    &destination_root,
                    &target_relative,
                    identity,
                    Sidecar::Stage,
                );
            }
            if opened.basis_size().is_some() {
                if !replace_partial {
                    // Preserve resumable data unless the coordinator chose
                    // whole-file copying for a source-change retry.
                    return Ok(CopyLocalOutcome::Unsupported);
                }
                d.set_len(0)
                    .context("truncate partial for local-copy retry")?;
            }
            d
        };
        let mut userspace_fallback = copy_pair_unsupported && use_userspace_fallback;
        if copy_pair_unsupported && !use_userspace_fallback {
            // Only an in-place copy reaches this point; it has no sidecar.
            return Ok(CopyLocalOutcome::Unsupported);
        }
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_COPY_LOCAL_EXDEV").is_some() {
            unsupported_copy_pairs().lock().unwrap().insert(copy_pair);
            if use_userspace_fallback {
                userspace_fallback = true;
            } else {
                let partial_metadata = d.metadata()?;
                drop(d);
                if !inplace {
                    discard_rooted_copy_partial(
                        &destination_root,
                        &target_relative,
                        &target_label,
                        partial_metadata.dev(),
                        partial_metadata.ino(),
                    )?;
                }
                return Ok(CopyLocalOutcome::Unsupported);
            }
        }
        // Preserve physical clones before considering read-ahead. A clone
        // needs no source data in memory; metadata I/O is not a reason to
        // prefetch the contents of a successfully cloned file.
        let local_read_ahead = source_fs.local_userspace_copy
            && destination_fs.local_userspace_copy
            && !source_fs.is_nfs
            && !destination_fs.is_nfs
            && !destination_fs.synchronous
            && !userspace_fallback;
        // copy_file_range can clone on filesystems outside the measured
        // read-ahead set too. Sparse mode cannot use its byte-copy fallback,
        // which can fill holes, so try an explicit clone before scanning zeros.
        let cloned = (local_read_ahead || self.sparse)
            && !userspace_fallback
            && crate::local_copy::try_clone(&s, &d, size);
        #[cfg(debug_assertions)]
        if cloned && size > 0 {
            record_test_event("SYQ_TEST_COPY_LOCAL_CLONES", format_args!("clone {size}"))?;
        }
        userspace_fallback |= self.sparse && !cloned;
        let preparation = &mut self.read_ahead;
        let mut read_ahead = (local_read_ahead && !cloned).then(|| preparation.range(&s, 0..size));
        let mut source_offset: libc::off64_t = 0;
        let mut destination_offset: libc::off64_t = 0;
        let mut remaining = if cloned { 0 } else { size };
        let mut previous_input = crate::read_ahead::Activity::sample();
        while remaining > 0 && !userspace_fallback {
            // SAFETY: each offset is its own local that outlives the call, so
            // the kernel reads and advances the two through distinct pointers.
            let n = unsafe {
                libc::copy_file_range(
                    s.as_raw_fd(),
                    &mut source_offset,
                    d.as_raw_fd(),
                    &mut destination_offset,
                    if read_ahead.is_some() {
                        remaining.min(crate::read_ahead::BLOCK) as usize
                    } else {
                        // Preserve server-side copy offload as one operation.
                        // Progress follows its successful return, like a clone.
                        remaining as usize
                    },
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                let raw = e.raw_os_error().unwrap_or(0);
                // First-block failure with a "can't offload" errno: signal fallback.
                if remaining == size
                    && matches!(
                        raw,
                        libc::EXDEV | libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL
                    )
                {
                    if matches!(raw, libc::EXDEV | libc::ENOSYS | libc::EOPNOTSUPP) {
                        unsupported_copy_pairs().lock().unwrap().insert(copy_pair);
                    }
                    if use_userspace_fallback {
                        userspace_fallback = true;
                        continue;
                    }
                    let partial_metadata = d.metadata()?;
                    drop(d);
                    if !inplace {
                        // The planner probed before this empty sidecar existed.
                        // A content-identical fallback completes through its
                        // retained basis fd and would otherwise orphan it.
                        discard_rooted_copy_partial(
                            &destination_root,
                            &target_relative,
                            &target_label,
                            partial_metadata.dev(),
                            partial_metadata.ino(),
                        )?;
                    }
                    return Ok(CopyLocalOutcome::Unsupported);
                }
                if raw == libc::EINTR {
                    continue;
                }
                return Err(e).with_context(|| {
                    format!(
                        "copy_file_range {} -> {}",
                        source_label.display(),
                        target_label.display()
                    )
                });
            }
            if n == 0 {
                bail!("source shortened while copying {}", source_label.display());
            }
            remaining -= n as u64;
            progress.advance(size - remaining)?;
            if let Some(read_ahead) = &mut read_ahead {
                let prepare = if read_ahead.needs_observation() {
                    let current = crate::read_ahead::Activity::sample();
                    let input = current.input_since(previous_input);
                    previous_input = current;
                    input
                } else {
                    false
                };
                read_ahead.advance(size - remaining, prepare);
                #[cfg(debug_assertions)]
                if size - remaining == n as u64 {
                    test_race_barrier(
                        "SYQ_TEST_OVERLAP_READY",
                        "SYQ_TEST_OVERLAP_CONTINUE",
                        "local copy first block",
                    )?;
                }
            }
        }
        drop(read_ahead);

        if userspace_fallback {
            let mut prepared = preparation.range(&s, 0..size);
            let mut source = &s;
            let mut destination = &d;
            source.seek(SeekFrom::Start(0))?;
            destination.seek(SeekFrom::Start(0))?;
            let mut buffer = vec![0u8; 1 << 20];
            let mut remaining = size;
            while remaining > 0 {
                let want = remaining.min(buffer.len() as u64) as usize;
                let before = prepared
                    .needs_observation()
                    .then(crate::read_ahead::Activity::sample);
                let n = source
                    .read(&mut buffer[..want])
                    .with_context(|| format!("read {}", source_label.display()))?;
                if n == 0 {
                    bail!("source shortened while copying {}", source_label.display());
                }
                let prepare = before.is_some_and(|before| {
                    crate::read_ahead::Activity::sample().read_wait_since(before)
                });
                if self.sparse {
                    // Zeros over an in-place file's old bytes must clear them.
                    let off = size - remaining;
                    crate::sparse::write_at(&d, &buffer[..n], off, off < old_len)
                } else {
                    destination.write_all(&buffer[..n])
                }
                .with_context(|| format!("write {}", target_label.display()))?;
                progress.advance(size - remaining + n as u64)?;
                #[cfg(debug_assertions)]
                if remaining == size {
                    test_race_barrier(
                        "SYQ_TEST_COPY_LOCAL_WRITTEN_FILE",
                        "SYQ_TEST_COPY_LOCAL_CONTINUE_FILE",
                        "local-copy first write",
                    )?;
                    if std::env::var_os("SYQ_TEST_FAIL_COPY_LOCAL_AFTER_WRITE").is_some() {
                        return Err(io::Error::from_raw_os_error(libc::ENOSPC))
                            .context("test local-copy write failure");
                    }
                }
                remaining -= n as u64;
                prepared.advance(size - remaining, prepare);
            }
            drop(prepared);
            self.set_copy_length(&d, size)?;
        }
        if inplace {
            // Creation can return a writable descriptor for a read-only mode.
            // Keep it for the immediately following Finalize: reopening the
            // completed file for writing would fail. Finalize removes every
            // attempt for this path, so CopyLocal needs no wire attempt field.
            self.cache_file(target.location(), 0, false, d);
        } else {
            // Finalize reopens the partial. Collect errors on this original
            // writer now: a later open may not observe an already reported error.
            close_writer(d, &target_label)?;
        }
        _copy.bytes(size);
        #[cfg(debug_assertions)]
        if !inplace {
            test_race_barrier(
                "SYQ_TEST_COPY_LOCAL_COPIED_READY_FILE",
                "SYQ_TEST_COPY_LOCAL_COPIED_CONTINUE_FILE",
                "local copy written to its partial",
            )?;
        }
        Ok(CopyLocalOutcome::Copied)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn copy_local(
        &mut self,
        source: &RegisteredPath,
        dst: &[u8],
        policy: CopyLocalPolicy<'_>,
        copy_id: &CopyId,
        size: u64,
        _mode: u32,
    ) -> Result<CopyLocalOutcome> {
        let _copy = self
            .operation
            .span(crate::transfer_observations::Stage::FilesystemCopy);
        self.held_basis.take();
        #[cfg(debug_assertions)]
        record_test_event("SYQ_TEST_COPY_LOCAL_REQUESTS", format_args!("copy-local"))?;
        // This operation stages a new inode; callers must stream in-place
        // writes even if a future coordinator bypasses copy selection.
        if policy.inplace {
            return Ok(CopyLocalOutcome::Unsupported);
        }
        let (source, source_metadata, target, ()) = self.prepare_local_copy(source, dst, |_| ())?;
        Self::require_not_self_copy(&target, &source_metadata)?;
        let root = target.root.clone();
        let (partial, label) = rooted_partial_target(&target, copy_id)?;
        self.uncache_rooted(&root, &target.relative);
        self.uncache_rooted(&root, &partial);
        if policy.replace_partial {
            if let Some(metadata) = root.metadata_optional(&partial)? {
                if is_owned_rooted_partial(metadata) {
                    discard_rooted_copy_partial(
                        &root,
                        &partial,
                        &label,
                        metadata.dev,
                        metadata.ino,
                    )?;
                }
            }
        }
        let creation = sidecars::begin()?;
        let outcome = match root.clone_file_open(&source, &source_metadata, &partial, size)? {
            Some(clone) => {
                // As on Linux, a later copy on this machine clones the file
                // again rather than resuming this partial.
                creation.register_with(&root, &partial, Sidecar::Stage, || {
                    clone.metadata().map(|metadata| identity_of(&metadata))
                })?;
                _copy.bytes(size);
                CopyLocalOutcome::Copied
            }
            None => CopyLocalOutcome::Unsupported,
        };
        // Like staged Linux offload, leave no writer-cache entry. CopyLocal has no
        // attempt field; finalize opens and checks the named partial normally.
        Ok(outcome)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn copy_local(
        &mut self,
        _source: &RegisteredPath,
        _dst: &[u8],
        _policy: CopyLocalPolicy<'_>,
        _copy_id: &CopyId,
        _size: u64,
        _mode: u32,
    ) -> Result<CopyLocalOutcome> {
        Ok(CopyLocalOutcome::Unsupported)
    }

    fn read_small_batch(&mut self, reads: &[SmallRead]) -> Result<Response> {
        let blocks = self.read_small_sources(reads, |_, _, data, hash| SmallBlock {
            source: None,
            data,
            hash,
        })?;
        Ok(Response::SmallBlocks(blocks))
    }

    /// Return only the blocks of each source whose comparison hashes differ
    /// from what the destination holds. Each source is compared a chunk of
    /// whole blocks at a time, so no more of it is held than one chunk and
    /// its differing blocks.
    fn read_differing_batch(&mut self, block: u64, reads: &[DifferingRead]) -> Result<Response> {
        if !(MIN_HASH_BLOCK_BYTES..=MAX_HASH_BLOCK_BYTES).contains(&block) {
            bail!("invalid comparison block size {block}");
        }
        let total: u64 = reads.iter().map(|read| u64::from(read.len)).sum();
        if total > MAX_READ_BYTES {
            bail!("small-file batch requests {total} bytes, exceeding the {MAX_READ_BYTES}-byte protocol limit");
        }
        let chunk = DIFFERING_READ_CHUNK.max(block) / block * block;
        let mut differing: Vec<_> = reads
            .iter()
            .map(|read| {
                self.read_differing(read, block, chunk)
                    .map_err(|error| errstr(&error))
            })
            .collect();
        self.recheck_small_sources(reads, &mut differing)?;
        Ok(Response::DifferingBlocks(differing))
    }

    /// Compare one source with the destination's block hashes, `chunk` bytes
    /// at a time. A comparison that only decides whether the file is
    /// unchanged stops at its first differing block. A file whose differing
    /// blocks pass `MAX_DIFFERING_FILE_BYTES` is compared to its end but
    /// returns no data: the sender reads its differing blocks itself and
    /// streams its patch. A file read in one chunk sends its differing
    /// blocks as read; a longer one reads them again once compared, into a
    /// buffer of exactly their size, rather than keeping blocks that might
    /// all be discarded.
    fn read_differing(
        &mut self,
        read: &DifferingRead,
        block: u64,
        chunk: u64,
    ) -> Result<DifferingBlocks> {
        let len = u64::from(read.len);
        let algorithm = self.hash_policy.algorithm;
        let mut matching = Vec::with_capacity(len.div_ceil(block) as usize);
        if len == 0 {
            // Metadata is enough for an empty file, even with mode 000.
            self.source_content_target(read.source.as_ref())?;
        }
        let mut buffer = vec![0; chunk.min(len) as usize];
        // Prepare the next chunks while this one is compared.
        let chunks = len > chunk;
        if chunks {
            self.begin_source_range(0..len);
        }
        // The bytes of the blocks that differ.
        let mut differing = 0;
        let compared = (|| -> Result<()> {
            let mut off = 0;
            while off < len {
                let read_len = chunk.min(len - off) as usize;
                let contents = &mut buffer[..read_len];
                self.read_source_into(
                    &read.path,
                    read.source.as_ref(),
                    read.attempt,
                    off,
                    contents,
                )?;
                let _hash = self
                    .operation
                    .span(crate::transfer_observations::Stage::Hashing);
                for piece in contents.chunks(block as usize) {
                    let same = read.expected.get(matching.len()) == Some(&algorithm.hash(piece));
                    matching.push(same);
                    if !same {
                        differing += piece.len() as u64;
                        if read.compare_only {
                            return Ok(());
                        }
                    }
                }
                off += read_len as u64;
            }
            Ok(())
        })();
        if chunks {
            self.end_source_range();
        }
        compared?;
        let streamed = !read.compare_only && differing > MAX_DIFFERING_FILE_BYTES;
        let data = if read.compare_only || differing == 0 || streamed {
            Vec::new()
        } else if !chunks && differing == len {
            // Every block of a file read in one chunk differs: send it as
            // read.
            buffer
        } else {
            let mut data = Vec::with_capacity(differing as usize);
            let block = block as usize;
            let mut index = 0;
            while index < matching.len() {
                if matching[index] {
                    index += 1;
                    continue;
                }
                let start = index;
                while index < matching.len() && !matching[index] {
                    index += 1;
                }
                let range = start * block..(index * block).min(len as usize);
                if chunks {
                    let at = data.len();
                    data.resize(at + range.len(), 0);
                    self.read_source_into(
                        &read.path,
                        read.source.as_ref(),
                        read.attempt,
                        range.start as u64,
                        &mut data[at..],
                    )?;
                } else {
                    data.extend_from_slice(&buffer[range]);
                }
            }
            data
        };
        // Only the differing blocks are sent, so only they take a payload
        // hash, and only when transfers are checked. A streamed patch's
        // pieces carry their own.
        let hash = if self.hash_policy.transfer_integrity && !streamed {
            self.observed_payload_hash(&data)
        } else {
            [0; 32]
        };
        Ok(DifferingBlocks {
            source: None,
            matching,
            data,
            hash,
        })
    }

    /// Read each small source whole, convert its contents and payload hash
    /// with `convert` as soon as it is read, and attach the source's metadata
    /// rechecked after every read.
    fn read_small_sources<R: SmallSourceRead, T: SmallSourceResult>(
        &mut self,
        reads: &[R],
        mut convert: impl FnMut(&Self, &R, Vec<u8>, ContentDigest) -> T,
    ) -> Result<Vec<std::result::Result<T, String>>> {
        let total: u64 = reads.iter().map(|read| u64::from(read.len())).sum();
        if total > MAX_READ_BYTES {
            bail!("small-file batch requests {total} bytes, exceeding the {MAX_READ_BYTES}-byte protocol limit");
        }
        let mut blocks: Vec<_> = reads
            .iter()
            .map(|read| {
                // Metadata is enough for an empty file, even with mode 000.
                let result = if read.len() == 0 {
                    self.source_content_target(read.source())
                        .map(|_| (Vec::new(), self.observed_payload_hash(&[])))
                } else {
                    self.read_range(read.path(), read.source(), read.attempt(), 0, read.len())
                        .and_then(|response| match response {
                            Response::Block { data, hash, .. } => Ok((data, hash)),
                            other => bail!("unexpected response {other:?}"),
                        })
                };
                result
                    .map(|(data, hash)| convert(self, read, data, hash))
                    .map_err(|error| errstr(&error))
            })
            .collect();
        self.recheck_small_sources(reads, &mut blocks)?;
        Ok(blocks)
    }

    /// Attach to each source read without error its metadata, rechecked
    /// after every file of the batch was read.
    fn recheck_small_sources<R: SmallSourceRead, T: SmallSourceResult>(
        &mut self,
        reads: &[R],
        blocks: &mut [std::result::Result<T, String>],
    ) -> Result<()> {
        #[cfg(debug_assertions)]
        test_race_barrier(
            "SYQ_TEST_SOURCE_RECHECK_READY_FILE",
            "SYQ_TEST_SOURCE_RECHECK_CONTINUE_FILE",
            "small-file source recheck before sending",
        )?;
        // Keep the existing parallel metadata lookup and return its results
        // alongside the data, avoiding a separate round trip. Never substitute
        // a diagnostic path for a registered source's capability.
        for registered in [true, false] {
            let indices: Vec<_> = reads
                .iter()
                .enumerate()
                .filter_map(|(i, read)| {
                    (blocks[i].is_ok() && read.source().is_some() == registered).then_some(i)
                })
                .collect();
            if indices.is_empty() {
                continue;
            }
            let paths: Vec<_> = indices.iter().map(|&i| reads[i].path().clone()).collect();
            let sources: Option<Vec<_>> = registered.then(|| {
                indices
                    .iter()
                    .map(|&i| reads[i].source().cloned().unwrap())
                    .collect()
            });
            let entries = self.stat_many_request(&paths, sources.as_deref(), false, None)?;
            for (i, entry) in indices.into_iter().zip(entries) {
                blocks[i].as_mut().unwrap().set_source(entry);
            }
        }
        Ok(())
    }

    /// Write a whole small file through its private partial and atomically
    /// rename it into place. Keeping this as one request preserves pipelining;
    /// unlike an in-place write, no partial final-named file is ever visible.
    pub(super) fn put_small(&mut self, put: &SmallPut) -> Result<Option<(u64, u64)>> {
        let target = PartialTarget {
            path: &put.path,
            id: &put.copy_id,
            guard: put.guard.as_ref(),
        };
        let data = &put.data;
        let hash = put.hash;
        let meta = &put.meta;
        let flags = put.flags;
        let inplace = put.inplace;
        let condition = put.condition;
        if self.hash_policy.transfer_integrity && self.observed_payload_hash(data) != hash {
            bail!("block hash mismatch on receive");
        }
        let rooted = self.destination_mutation_target(target.path, target.guard)?;
        self.uncache_rooted(&rooted.root, &rooted.relative);
        if inplace {
            if target.guard.is_some() {
                bail!("guarded small-file updates require atomic publication");
            }
            // Read a file's metadata as soon as it is open: the open has
            // just primed an NFS client's attribute cache, so it costs
            // nothing, and it serves the metadata step and the identity
            // afterwards.
            let mut created = None;
            // How far the file's old contents may extend. They are written
            // over and only then cut to the new length, so a write that
            // fails leaves old data rather than an emptied file.
            let mut old_len = 0;
            let file = match condition {
                // The whole file is written here and never read back.
                TargetCondition::Absent => {
                    let file = rooted
                        .root
                        .create_write_only_file(&rooted.relative, meta.mode)
                        .with_context(|| format!("create {}", rooted.label.display()))?;
                    created = Some(file.metadata()?);
                    file
                }
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
                    let file = rooted.root.open_regular_write(&rooted.relative, false)?;
                    require_open_target(&file, &rooted.label, condition)?;
                    old_len = u64::MAX;
                    file
                }
                TargetCondition::Any => {
                    // Open the name directly, creating it when absent: a
                    // regular file there, new or existing, is the in-place
                    // destination. Looking the name up first cost an NFS
                    // client a request for every new file. Anything else
                    // at the name, or an open the kernel refused, is sorted
                    // out by the checks below.
                    let mut opened = match rooted
                        .root
                        .open_or_create_write_only_file(&rooted.relative, meta.mode)
                    {
                        Ok((file, metadata)) if metadata.is_file() => {
                            old_len = metadata.len();
                            created = Some(metadata);
                            Some(file)
                        }
                        Ok(_) => None,
                        Err(error) if existing_leaf_refused(&error) => None,
                        Err(error) => return Err(error),
                    };
                    for _ in 0..8 {
                        if opened.is_some() {
                            break;
                        }
                        match rooted.root.metadata_optional(&rooted.relative)? {
                            Some(metadata) if metadata.is_file() => {
                                let file =
                                    rooted.root.open_regular_write(&rooted.relative, false)?;
                                require_rooted_metadata(&file, metadata, &rooted.label)?;
                                old_len = metadata.len;
                                opened = Some(file);
                                break;
                            }
                            Some(metadata) if metadata.is_dir() => {
                                bail!("destination {} is a directory", rooted.label.display())
                            }
                            Some(_) => rooted.root.unlink(&rooted.relative)?,
                            None => match rooted
                                .root
                                .create_write_only_file(&rooted.relative, meta.mode)
                            {
                                Ok(file) => {
                                    created = Some(file.metadata()?);
                                    opened = Some(file);
                                    break;
                                }
                                Err(error)
                                    if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {}
                                Err(error) => return Err(error),
                            },
                        }
                    }
                    opened.with_context(|| {
                        format!(
                            "destination {} changed repeatedly while opening it",
                            rooted.label.display()
                        )
                    })?
                }
            };
            observed_overwrite(&self.operation, &file, data, old_len, self.sparse)
                .with_context(|| format!("write {}", rooted.label.display()))?;
            let len = data.len() as u64;
            // A sparse write may end in a hole that only the length makes.
            if self.sparse || old_len > len {
                file.set_len(len)
                    .with_context(|| format!("set length of {}", rooted.label.display()))?;
            }
            check_destination_writes(&file, &rooted.label)?;
            match &created {
                Some(created) => set_meta_written_file(&file, meta, flags, created),
                None => set_meta_file(&file, meta, flags),
            }
            .with_context(|| format!("set metadata {}", rooted.label.display()))?;
            if matches!(
                condition,
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
            ) {
                require_rooted_named_identity(
                    &rooted.root,
                    &rooted.relative,
                    &rooted.label,
                    &file,
                    condition,
                )?;
            }
            return match &created {
                Some(created) => Ok(known_identity(created, flags)),
                None => published_identity(&file, flags),
            };
        }
        let stage = self.create_small_stage(put, rooted)?;
        self.write_small_stage(put, None, &stage, None)?;
        self.publish_small_stage(put, &stage)?;
        self.finish_small_stage(put, stage)
    }

    pub(super) fn hash_blocks(
        &mut self,
        target: HashTarget<'_>,
        options: HashOptions,
        copy_id: &CopyId,
    ) -> Result<Vec<ContentDigest>> {
        let HashOptions {
            off,
            which,
            block,
            len,
            attempt,
        } = options;
        anyhow::ensure!(
            block > 0 && off.is_multiple_of(block) && off.checked_add(len).is_some(),
            "invalid hash interval"
        );
        if target.source.is_some()
            || (self.destination_root.is_none() && !self.source_roots.is_empty())
        {
            #[cfg(debug_assertions)]
            if std::env::var_os("SYQ_TEST_FAIL_SOURCE_BLOCK_HASH").is_some() {
                bail!("injected whole-source hash failure");
            }
            if target.guard.is_some() {
                bail!("source block hash cannot carry a destination guard");
            }
            if which != Which::Final {
                bail!("source block hash is only valid for the final source file");
            }
            if let Some((_, source_target)) = self.source_content_target(target.source)? {
                let mut file =
                    open_registered_source(&source_target, self.inode_preservation.open_noatime)?;
                // A partial block describes only the source's actual EOF
                // tail, not an arbitrary prefix that could be queried byte
                // by byte. Full-block windows need no extra metadata lookup.
                anyhow::ensure!(
                    len.is_multiple_of(block) || off + len == file.metadata()?.len(),
                    "short source hash block must end at the file's current EOF"
                );
                file.seek(SeekFrom::Start(off))?;
                return hash_reader_observed(
                    &mut file,
                    block,
                    len,
                    Some(&self.operation),
                    self.hash_policy.algorithm,
                );
            }
            // Only an explicitly unconfined rsync source session can reach
            // this legacy branch after source roots have been initialized.
        }
        if let Some(target) = self.rooted_destination_target(target.path, target.guard)? {
            let open = |relative: &RelativePath, _: &Path| {
                let location = FileLocation::Rooted {
                    root: target.root.identity(),
                    relative: relative.clone(),
                };
                self.cached_clone(location, attempt, which == Which::Partial)?
                    .map(Ok)
                    .unwrap_or_else(|| target.root.open_regular_read(relative))
            };
            let (relative, label, mut file) = if which == Which::Partial {
                with_rooted_partial(&target, copy_id, open)?
            } else {
                let file = open(&target.relative, &target.label)?;
                (target.relative.clone(), target.label.clone(), file)
            };
            file.seek(SeekFrom::Start(off))?;
            if which == Which::Partial {
                require_safe_rooted_named_partial(&target.root, &relative, &label, &file)?;
            }
            return hash_reader_observed(
                &mut file,
                block,
                len,
                Some(&self.operation),
                self.hash_policy.algorithm,
            );
        }
        let p = resolve(target.path);
        let p = if which == Which::Partial {
            self.partial_path(&p, copy_id)?
        } else {
            p
        };
        let mut f = self
            .cached_clone(
                FileLocation::Path(p.clone()),
                attempt,
                which == Which::Partial,
            )?
            .map(Ok)
            .unwrap_or_else(|| open_existing_regular(&p, false))?;
        crate::inode_metadata::prepare_read(&f, self.inode_preservation.open_noatime);
        f.seek(SeekFrom::Start(off))?;
        if which == Which::Partial {
            require_safe_partial(&f, &p)?;
        }
        hash_reader_observed(
            &mut f,
            block,
            len,
            Some(&self.operation),
            self.hash_policy.algorithm,
        )
    }

    fn hash_window(
        &mut self,
        partial: PartialTarget<'_>,
        off: u64,
        len: u32,
        block: u64,
        attempt: u32,
        final_basis: bool,
    ) -> Result<Vec<ContentDigest>> {
        anyhow::ensure!(
            crate::proto::hash_window_fits(off, len, block),
            "invalid hash window"
        );
        let target = self.destination_mutation_target(partial.path, partial.guard)?;
        if !final_basis {
            self.comparison_window = None;
        }
        if final_basis {
            let location = target.location();
            // Only the bytes need to survive this request. Keeping a donor
            // descriptor in the window would pin replaced files after an error
            // or cancellation, while the connection continues serving other work.
            let Ok(file) = target.root.open_regular_read(&target.relative) else {
                return Ok(vec![
                    self.hash_policy.algorithm.hash(&[]);
                    u64::from(len).div_ceil(block) as usize
                ]);
            };
            let metadata = file.metadata()?;
            let mut window = self
                .comparison_window
                .take()
                .filter(|window| {
                    window.location == location
                        && window.copy_id == *partial.id
                        && window.attempt == attempt
                })
                .unwrap_or_else(|| ComparisonWindow {
                    location,
                    copy_id: *partial.id,
                    attempt,
                    blocks: Vec::new(),
                    sparse: metadata.blocks().saturating_mul(512) < metadata.len(),
                });
            let retained: u64 = window
                .blocks
                .iter()
                .map(|(_, bytes)| bytes.len() as u64)
                .sum();
            anyhow::ensure!(
                retained + u64::from(len) <= MAX_READ_BYTES,
                "too many unconsumed comparison bytes"
            );
            anyhow::ensure!(
                window
                    .blocks
                    .iter()
                    .all(|(pos, bytes)| *pos >= off + u64::from(len)
                        || pos + bytes.len() as u64 <= off),
                "overlapping comparison windows"
            );
            let mut hashes = Vec::new();
            let end = off + u64::from(len);
            let mut pos = off;
            while pos < end {
                let n = (end - pos).min(block) as usize;
                let mut bytes = vec![0; n];
                let mut got = 0;
                {
                    let reading = self
                        .operation
                        .span(crate::transfer_observations::Stage::SourceRead);
                    while got < n {
                        match file.read_at(&mut bytes[got..], pos + got as u64) {
                            Ok(0) => break,
                            Ok(n) => got += n,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(e.into()),
                        }
                    }
                    reading.bytes(got as u64);
                }
                let _hash = self
                    .operation
                    .span(crate::transfer_observations::Stage::Hashing);
                if got == n {
                    hashes.push(self.hash_policy.algorithm.hash(&bytes));
                    window.blocks.push((pos, bytes));
                } else {
                    // Missing donor bytes can never be confirmed as a match.
                    hashes.push(self.hash_policy.algorithm.hash(&[]));
                }
                pos += n as u64;
            }
            self.comparison_window = (!window.blocks.is_empty()).then_some(window);
            return Ok(hashes);
        }

        let (relative, label, file) =
            with_rooted_partial(&target, partial.id, |relative, label| {
                let location = FileLocation::Rooted {
                    root: target.root.identity(),
                    relative: relative.clone(),
                };
                if let Some(file) = self.cached_clone(location.clone(), attempt, true)? {
                    return Ok(file);
                }
                // A range worker alternates reads and writes on this private inode.
                // Cache a read/write descriptor on its first comparison; caching a
                // read-only descriptor would break writes, and a later write-only
                // cache entry would break the next comparison window.
                let file = target.root.open_regular_read_write(relative)?;
                require_safe_rooted_named_partial(&target.root, relative, label, &file)?;
                self.cache_file(location, attempt, true, file.try_clone()?);
                Ok(file)
            })?;
        require_safe_rooted_named_partial(&target.root, &relative, &label, &file)?;
        let mut buffer = vec![0; block.min(u64::from(len)) as usize];
        let mut hashes = Vec::with_capacity(u64::from(len).div_ceil(block) as usize);
        let end = off + u64::from(len);
        let mut pos = off;
        while pos < end {
            let n = (end - pos).min(block) as usize;
            let bytes = &mut buffer[..n];
            {
                let reading = self
                    .operation
                    .span(crate::transfer_observations::Stage::SourceRead);
                file.read_exact_at(bytes, pos)?;
                reading.bytes(n as u64);
            }
            {
                let _hash = self
                    .operation
                    .span(crate::transfer_observations::Stage::Hashing);
                hashes.push(self.hash_policy.algorithm.hash(bytes));
            }
            pos += n as u64;
        }
        Ok(hashes)
    }

    fn reuse_compared_range(
        &mut self,
        partial: PartialTarget<'_>,
        attempt: u32,
        off: u64,
        len: u32,
    ) -> Result<()> {
        let target = self.destination_mutation_target(partial.path, partial.guard)?;
        let window = self
            .comparison_window
            .as_mut()
            .context("no retained comparison window")?;
        anyhow::ensure!(
            window.location == target.location()
                && window.copy_id == *partial.id
                && window.attempt == attempt,
            "comparison window belongs to another file or attempt"
        );
        let index = window
            .blocks
            .iter()
            .position(|(pos, bytes)| *pos == off && bytes.len() == len as usize)
            .context("no retained comparison block at this offset and length")?;
        let (_, bytes) = window.blocks.remove(index);
        let sparse = self.sparse || window.sparse;
        self.write_range_bytes(partial, false, attempt, off, &bytes, sparse)
    }

    pub(crate) fn begin_source_range(&mut self, _range: std::ops::Range<u64>) {
        #[cfg(target_os = "linux")]
        self.read_ahead.begin_stream(_range);
    }

    pub(crate) fn shrink_source_range(&mut self, _end: u64) {
        #[cfg(target_os = "linux")]
        self.read_ahead.shrink_stream(_end);
    }

    pub(crate) fn end_source_range(&mut self) {
        #[cfg(target_os = "linux")]
        self.read_ahead.end_stream();
    }

    pub fn read_range(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        attempt: u32,
        off: u64,
        len: u32,
    ) -> Result<Response> {
        if u64::from(len) > MAX_READ_BYTES {
            bail!("read length {len} exceeds the {MAX_READ_BYTES}-byte protocol limit");
        }
        let mut data = vec![0u8; len as usize];
        self.read_source_into(path, source, attempt, off, &mut data)?;
        let hash = if self.hash_policy.transfer_integrity {
            let _hash = self
                .operation
                .span(crate::transfer_observations::Stage::Hashing);
            self.hash_policy.payload_algorithm().hash(&data)
        } else {
            [0; 32]
        };
        Ok(Response::Block { off, hash, data })
    }

    /// Fill `data` from a source at `off`.
    fn read_source_into(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        attempt: u32,
        off: u64,
        data: &mut [u8],
    ) -> Result<()> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_READ_RANGE").is_some()
            || std::env::var_os("SYQ_TEST_FAIL_READ_RANGE_NAME")
                .is_some_and(|name| resolve(path).file_name() == Some(name.as_os_str()))
        {
            bail!("test read-range failure");
        }
        let len = data.len();
        #[cfg(not(target_os = "linux"))]
        let operation = self.operation.clone();
        #[cfg(target_os = "linux")]
        let mut preparation = std::mem::take(&mut self.read_ahead);
        let result = (|| {
            let target = self.source_content_target(source)?;
            let p = resolve(path);
            let f = if let Some((root_id, target)) = target {
                let relative_bytes = source
                    .expect("rooted source target requires a registered reference")
                    .relative();
                self.cached_source_read(root_id, relative_bytes, &target, attempt)?
            } else {
                // This is either a pre-registration test/control operation or the
                // explicit rsync --insecure-links compatibility path.
                self.cached(&p, attempt)?.file()
            };
            #[cfg(target_os = "linux")]
            let read = preparation.read_exact_at(f, data, off);
            #[cfg(not(target_os = "linux"))]
            let read = {
                let reading = operation.span(crate::transfer_observations::Stage::SourceRead);
                let result = f.read_exact_at(data, off);
                if result.is_ok() {
                    reading.bytes(len as u64);
                }
                result
            };
            read.with_context(|| format!("read {} @{off}+{len}", p.display()))?;
            #[cfg(debug_assertions)]
            record_test_event(
                "SYQ_TEST_SOURCE_READ_EVENTS",
                format_args!("read {off} {len}"),
            )?;
            Ok(())
        })();
        #[cfg(target_os = "linux")]
        {
            self.read_ahead = preparation;
        }
        result
    }

    pub(super) fn write_range(
        &mut self,
        target: PartialTarget<'_>,
        inplace: bool,
        attempt: u32,
        off: u64,
        hash: ContentDigest,
        data: &[u8],
    ) -> Result<()> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_WRITE_RANGE_NAME")
            .is_some_and(|name| resolve(target.path).file_name() == Some(name.as_os_str()))
        {
            bail!("test range write failure");
        }
        let operation = self.operation.clone();
        let actual_hash = {
            if self.hash_policy.transfer_integrity {
                let _hash = operation.span(crate::transfer_observations::Stage::Hashing);
                self.hash_policy.payload_algorithm().hash(data)
            } else {
                [0; 32]
            }
        };
        if self.hash_policy.transfer_integrity && actual_hash != hash {
            bail!("block hash mismatch on receive @{off}");
        }
        self.write_range_bytes(target, inplace, attempt, off, data, self.sparse)
    }

    fn write_range_bytes(
        &mut self,
        target: PartialTarget<'_>,
        inplace: bool,
        attempt: u32,
        off: u64,
        data: &[u8],
        sparse: bool,
    ) -> Result<()> {
        let operation = self.operation.clone();
        let rooted = self.destination_mutation_target(target.path, target.guard)?;
        if let Some(window) = self.comparison_window.as_mut().filter(|window| {
            window.location == rooted.location()
                && window.copy_id == *target.id
                && window.attempt == attempt
        }) {
            window.blocks.retain(|(pos, _)| *pos != off);
        }
        if self
            .comparison_window
            .as_ref()
            .is_some_and(|window| window.blocks.is_empty())
        {
            self.comparison_window = None;
        }
        let mut write = |relative: &RelativePath, label: &Path| {
            let file = self.cached_rooted(label, &rooted.root, relative, attempt, !inplace)?;
            let writing = operation.span(crate::transfer_observations::Stage::DestinationWrite);
            let result = file.write_range_at(data, off, sparse);
            if result.is_ok() {
                writing.bytes(data.len() as u64);
            }
            // Keep a write error inside the successful access result: only
            // opening the name may trigger the filename-limit retry.
            Ok(result.with_context(|| format!("write {} @{off}", label.display())))
        };
        if inplace {
            write(&rooted.relative, &rooted.label)?
        } else {
            with_rooted_partial(&rooted, target.id, write)?.2
        }
    }

    pub(super) fn verify_expected_inode(
        writer: &File,
        reader: &File,
        expected: &crate::hashing::ExpectedHashes,
    ) -> Result<()> {
        let written = writer.metadata()?;
        let read = reader.metadata()?;
        if written.dev() != read.dev() || written.ino() != read.ino() {
            bail!("destination changed before digest validation");
        }
        Self::verify_expected_file(reader, expected)
    }

    pub(super) fn verify_expected_file(
        file: &File,
        expected: &crate::hashing::ExpectedHashes,
    ) -> Result<()> {
        let mut reader = file;
        reader.seek(SeekFrom::Start(0))?;
        expected
            .verify_reader(&mut reader)
            .context("expected file digest mismatch")
    }

    pub(super) fn validate_expected_path(
        &self,
        path: &[u8],
        expected: &crate::hashing::ExpectedHashes,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let file = if let Some(target) = self.rooted_destination_target(path, guard)? {
            target.root.open_regular_read(&target.relative)?
        } else {
            open_existing_regular(&resolve(path), false)?
        };
        Self::verify_expected_file(&file, expected)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_basis_expected(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        meta: &Meta,
        flags: u8,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
        expected: Option<&crate::hashing::ExpectedHashes>,
    ) -> Result<Option<(u64, u64)>> {
        if let Some(expected) = expected {
            Self::verify_expected_file(
                &self.held_basis.as_ref().context("no retained basis")?.file,
                expected,
            )?;
        }
        self.finish_basis(path, copy_id, meta, flags, condition, guard)
    }

    #[cfg(test)]
    pub(super) fn finalize(
        &mut self,
        path: &[u8],
        inplace: bool,
        copy_id: &CopyId,
        meta: &Meta,
        flags: u8,
        mutation: TargetMutation<'_>,
    ) -> Result<Option<(u64, u64)>> {
        self.finalize_expected(None, path, inplace, copy_id, meta, flags, mutation)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn finalize_expected(
        &mut self,
        expected: Option<&crate::hashing::ExpectedHashes>,
        path: &[u8],
        inplace: bool,
        copy_id: &CopyId,
        meta: &Meta,
        flags: u8,
        mutation: TargetMutation<'_>,
    ) -> Result<Option<(u64, u64)>> {
        let target = self.destination_mutation_target(path, mutation.guard)?;
        self.finalize_rooted(&target, inplace, copy_id, meta, flags, mutation, expected)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn finalize_rooted(
        &mut self,
        target: &RootedTarget,
        inplace: bool,
        copy_id: &CopyId,
        meta: &Meta,
        flags: u8,
        mutation: TargetMutation<'_>,
        expected: Option<&crate::hashing::ExpectedHashes>,
    ) -> Result<Option<(u64, u64)>> {
        let TargetMutation { condition, guard } = mutation;
        let guarded = guard.is_some();
        if inplace {
            // The descriptor Prepare opened carries the metadata read then,
            // before the writes; the condition check, the metadata step and
            // the identity use it instead of a read after the data, which an
            // NFS client answers with a request. A reopened file is read as
            // before.
            let (file, opened) = match self.uncache_rooted_opened(&target.root, &target.relative) {
                Some(opened) => opened,
                None => (
                    target.root.open_regular_write(&target.relative, false)?,
                    None,
                ),
            };
            // The file is read at most once here. A restricted receiver
            // binds its approval of this step to the file's ctime as it is
            // now, after the writes, so that condition needs fresh metadata;
            // every other condition, the final identity check and the
            // reported identity are satisfied by the metadata read at the
            // open, since writes change neither device nor inode. The
            // metadata step uses the open-time read when there is one.
            let fingerprint = matches!(condition, TargetCondition::MatchesFingerprint { .. });
            let current = match &opened {
                Some(opened) if !fingerprint => opened.clone(),
                _ => file.metadata()?,
            };
            require_open_target_known(&current, &target.label, condition)?;
            check_destination_writes(&file, &target.label)?;
            if let Some(expected) = expected {
                let reader = target.root.open_regular_read(&target.relative)?;
                Self::verify_expected_inode(&file, &reader, expected)?;
            }
            match &opened {
                Some(opened) => set_meta_written_file(&file, meta, flags, opened),
                None => set_meta_file_known(&file, meta, flags, &current),
            }
            .with_context(|| format!("set metadata {}", target.label.display()))?;
            if guarded || condition != TargetCondition::Any {
                require_rooted_named_identity_known(
                    &target.root,
                    &target.relative,
                    &target.label,
                    &current,
                    condition,
                )?;
            }
            return Ok(known_identity(&current, flags));
        }
        // The descriptor that created the sidecar carries the metadata read
        // then, which the metadata step and the identity use instead of a
        // read after the data: on NFS that read is a request. A reopened
        // sidecar has no such read and takes the reads it always did.
        let (src_relative, src, (file, created)) =
            with_rooted_partial(target, copy_id, |relative, _| {
                match self.uncache_rooted_opened(&target.root, relative) {
                    Some(opened) => Ok(opened),
                    None => target
                        .root
                        .open_regular_write(relative, false)
                        .map(|file| (file, None)),
                }
            })?;
        // The name is checked against the held inode before anything reads
        // the sidecar or changes its metadata, and again before publication.
        // A reopened descriptor may be whatever the name now holds, so it is
        // checked at once. The descriptor that created the sidecar is that
        // inode by construction, so its check waits for the metadata step,
        // whose SETATTR lets an NFS client answer the check's reads of the
        // written file from its cache, where before the step they are a
        // request.
        let checked_early = created.is_none();
        if checked_early {
            require_safe_rooted_named_partial(&target.root, &src_relative, &src, &file)?;
        }
        check_destination_writes(&file, &src)?;
        if let Some(expected) = expected {
            if !checked_early {
                require_safe_rooted_named_partial(&target.root, &src_relative, &src, &file)?;
            }
            let reader = target.root.open_regular_read(&src_relative)?;
            Self::verify_expected_inode(&file, &reader, expected)?;
        }

        match &created {
            Some(created) => set_meta_written_file_for_publication(&file, meta, flags, created),
            None => set_meta_file_for_publication(&file, meta, flags),
        }
        .with_context(|| format!("set metadata {}", src.display()))?;
        require_safe_rooted_named_partial(&target.root, &src_relative, &src, &file)?;
        // A directory at the target name fails the rename; looking the name
        // up first cost an NFS client a request for every file.
        publish_partial_rooted(
            &target.root,
            &src_relative,
            &target.relative,
            &file,
            condition,
        )
        .map_err(|error| {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(libc::EISDIR))
            {
                anyhow::anyhow!("destination {} is a directory", target.label.display())
            } else {
                error
            }
        })?;
        crate::inode_metadata::finish_publication(
            &file,
            meta.inode_metadata.as_deref(),
            meta.mode,
        )?;
        match &created {
            Some(created) => Ok(known_identity(created, flags)),
            None => published_identity(&file, flags),
        }
    }

    pub fn file_hash(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        guard: Option<&ContainerGuard>,
    ) -> Result<Response> {
        self.file_hash_checked(path, source, guard, &mut |_, _| Ok(()))
    }

    /// Check an approved source hash's size and lifetime before reading and
    /// after each bounded chunk. Ordinary hashing supplies a no-op check.
    pub(crate) fn file_hash_checked(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        guard: Option<&ContainerGuard>,
        check: &mut impl FnMut(&File, u64) -> Result<()>,
    ) -> Result<Response> {
        let mut f = if source.is_some()
            || (self.destination_root.is_none() && !self.source_roots.is_empty())
        {
            if guard.is_some() {
                bail!("source file hash cannot carry a destination guard");
            }
            if let Some((_, target)) = self.source_content_target(source)? {
                open_registered_source(&target, self.inode_preservation.open_noatime)?
            } else {
                // Explicit rsync --insecure-links compatibility path.
                open_existing_regular(&resolve(path), false)?
            }
        } else if let Some(guard) = guard {
            let target = guarded_target(path, guard)?;
            target.root.open_regular_read(&target.relative)?
        } else if let Some(root) = &self.destination_root {
            root.open_regular_read(&RelativePath::new(path)?)?
        } else {
            open_existing_regular(&resolve(path), false)?
        };
        check(&f, 0)?;
        crate::inode_metadata::prepare_read(&f, self.inode_preservation.open_noatime);
        let mut h = self.hash_policy.algorithm.hasher();
        let mut buf = vec![0u8; 1 << 20];
        let mut size = 0u64;
        loop {
            check(&f, size)?;
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            check(&f, size)?;
            h.update(&buf[..n]);
        }
        Ok(Response::FileHash {
            size,
            hash: h.finalize(),
        })
    }

    // Borrowed test fixtures may be reused across calls. Production dispatch
    // always maps its already-owned request without cloning payload buffers.
    #[cfg(test)]
    pub fn handle(&mut self, req: &Request) -> Response {
        self.handle_in_place(&mut req.clone())
    }

    /// Dispatch a single-response request, rewriting its paths in place.
    /// The caller must not dispatch the mapped request again.
    pub fn handle_in_place(&mut self, req: &mut Request) -> Response {
        self.handle_with_copy_progress(req, &mut |_| Ok(()))
    }

    pub(crate) fn handle_with_copy_progress(
        &mut self,
        req: &mut Request,
        progress: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Response {
        let _handling = self
            .operation
            .span(crate::transfer_observations::Stage::Handling);
        if self.stream_ticket.is_some() {
            let result = match req {
                Request::BindStream(Some((ticket, settings))) => self
                    .initialize_stream(ticket, *settings)
                    .map(|()| Response::Ok),
                Request::BindStream(None) => {
                    self.stream_worker = None;
                    Ok(Response::Ok)
                }
                _ => self
                    .stream_worker
                    .as_ref()
                    .context("stream worker has no active entry")
                    .and_then(|worker| worker.handle(req)),
            };
            return result.unwrap_or_else(|e| Response::Err(format!("{e:#}")));
        }
        // A connection with a streamed patch open carries nothing else
        // until that patch ends.
        if self.patch_stream.is_some()
            && !matches!(req, Request::PatchData { .. } | Request::PatchEnd { .. })
        {
            return Response::Err(OPEN_PATCH_STREAM.into());
        }
        if let Err(error) = self
            .validate_source_session_request(req)
            .and_then(|()| self.validate_destination_session_request(req))
        {
            return Response::Err(errstr(&error));
        }
        if let Err(error) = self.map_request(req) {
            return Response::EndpointError(wire_error(&error));
        }
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_BLOCK_COMPARISON").is_some()
            && matches!(
                req,
                Request::HashBlocks { .. }
                    | Request::HashAndHold { .. }
                    | Request::SeedBasis { .. }
                    | Request::StageBasis { .. }
                    | Request::HashWindow { .. }
            )
        {
            return Response::Err("injected block-comparison failure".into());
        }
        // HashAndHold's next request must consume the retained descriptor.
        // Any other request means the controller abandoned that comparison
        // (for example because the source hash failed), so release it here.
        let r: Result<Response> = match &req {
            Request::DescriptorCopy(operation) => {
                if !self.source_roots.is_empty() || self.destination_root.is_some() {
                    Err(anyhow::anyhow!(
                        "descriptor copies require a separate unrestricted control session"
                    ))
                } else {
                    crate::descriptor_copy::Session::handle(
                        &mut self.descriptor_copy,
                        operation,
                        &self.descriptor_session,
                    )
                }
            }
            Request::ConfigurePreservation {
                selection,
                sparse,
                destination,
            } => {
                let validation = if *destination {
                    selection.validate_destination()
                } else {
                    selection.validate()
                };
                validation.map(|()| {
                    self.inode_preservation = *selection;
                    self.sparse = *sparse;
                    Response::Ok
                })
            }
            Request::ConfigureHashing(policy) => {
                self.hash_policy = *policy;
                Ok(Response::Ok)
            }
            Request::ValidateDigest {
                path,
                expected,
                guard,
            } => self
                .validate_expected_path(path, expected, guard.as_ref())
                .map(|_| Response::Ok),
            Request::ListDir {
                directory,
                confined_root,
                prefix,
                limit,
                symlink_policy,
            } => Self::completion_entries(
                directory,
                confined_root.as_deref(),
                prefix,
                *limit,
                *symlink_policy,
                false,
                true,
            ),
            Request::ListDirDetails {
                directory,
                confined_root,
                prefix,
                limit,
                symlink_policy,
            } => Self::completion_entries(
                directory,
                confined_root.as_deref(),
                prefix,
                *limit,
                *symlink_policy,
                true,
                true,
            ),
            Request::ListDirNoFollowFinal {
                directory,
                confined_root,
                prefix,
                limit,
                symlink_policy,
                detailed,
            } => Self::completion_entries(
                directory,
                confined_root.as_deref(),
                prefix,
                *limit,
                *symlink_policy,
                *detailed,
                false,
            ),
            Request::StatMany {
                paths,
                sources,
                follow,
                guard,
            } => self
                .stat_many_request(paths, sources.as_deref(), *follow, guard.as_ref())
                .map(Response::Stats),
            Request::CheckOperatorDirectory {
                path,
                allow_missing,
                symlink_policy,
            } => self
                .check_operator_directory(path, *allow_missing, *symlink_policy)
                .with_context(|| format!("resolve operator directory {}", resolve(path).display()))
                .map(Response::DirectorySelection),
            Request::CheckOperatorDirectoryAncestry { checks } => self
                .check_operator_directory_ancestry(checks)
                .map(Response::DirectoryRelations),
            Request::RegisterSourceRoots {
                base,
                selections,
                symlink_policy,
                allow_unconfined_paths,
                shared_workers,
                independent_handoff_workers,
            } => self
                .register_source_roots(
                    base,
                    selections,
                    *symlink_policy,
                    *allow_unconfined_paths,
                    *shared_workers,
                    *independent_handoff_workers,
                )
                .map(Response::SourceRootsRegistered),
            Request::CreateOperatorDirectory {
                mode,
                require_absent,
            } => self
                .create_operator_directory(*mode, *require_absent)
                .map(|anchor| Response::DirectorySelection(Some(anchor))),
            Request::AnchorDestination {
                expected_dev,
                expected_ino,
                request_prefix,
            } => self
                .anchor_destination(*expected_dev, *expected_ino, request_prefix)
                .map(Response::DestinationRegistered),
            Request::PrepareSmallFiles(request) => self.prepare_small_files(request),
            Request::CopySmallFiles(payloads) => self.copy_small_files(payloads),
            Request::DestinationFilesystemInfo {
                check_empty,
                target,
            } => self
                .destination_filesystem_info(*check_empty, target.as_ref())
                .map(Response::DestinationFilesystemInfo),
            Request::DefaultPermissions { paths, guard } => paths
                .iter()
                .map(|path| {
                    let target = self.destination_mutation_target(path, guard.as_ref())?;
                    let directory = target.root.open_metadata(&target.relative)?;
                    anyhow::ensure!(
                        directory.metadata()?.is_dir(),
                        "creation parent is not a directory"
                    );
                    crate::inode_metadata::default_permissions(&directory)
                })
                .collect::<Result<Vec<_>>>()
                .map(Response::DefaultPermissions),
            Request::PruneLookup { paths, guard } => (|| {
                #[cfg(debug_assertions)]
                record_test_event(
                    "SYQ_TEST_DESTINATION_LOOKUPS",
                    format_args!("lookup {}", paths.len()),
                )?;
                self.prune_lookup(paths, guard.as_ref())
                    .map(Response::Stats)
            })(),
            Request::PartialPaths {
                paths,
                copy_id,
                guard,
            } => Ok(Response::PathResults(self.partial_paths(
                paths,
                copy_id,
                guard.as_ref(),
            ))),
            Request::PlanBatch {
                partial_paths,
                copy_id,
                directories,
                others,
                guard,
                strict_metadata,
            } => (|| {
                #[cfg(debug_assertions)]
                record_test_event(
                    "SYQ_TEST_DESTINATION_LOOKUPS",
                    format_args!(
                        "batch {} {} {strict_metadata}",
                        directories.len(),
                        others.len()
                    ),
                )?;
                let guard = guard.as_ref();
                let partial_paths = self.partial_paths(partial_paths, copy_id, guard);
                let directories = if *strict_metadata {
                    self.prune_lookup(directories, guard)?
                } else {
                    self.stat_many(directories, false, guard)
                };
                let safe_to_stat_others = directories.iter().all(|entry| {
                    entry
                        .as_ref()
                        .is_some_and(|entry| entry.kind == Kind::Dir && entry.mode & 0o700 == 0o700)
                });
                let others = if safe_to_stat_others {
                    Some(if *strict_metadata {
                        self.prune_lookup(others, guard)?
                    } else {
                        self.stat_many(others, false, guard)
                    })
                } else {
                    None
                };
                Ok(Response::BatchPlan {
                    partial_paths,
                    directories,
                    others,
                })
            })(),
            Request::WidenDirectories { directories, guard } => Ok(Response::WidenedDirectories(
                parallel_map(directories, |(path, condition)| {
                    (|| {
                        let target = self.destination_mutation_target(path, guard.as_ref())?;
                        widen_directory(&target.root, &target.relative, *condition, &target.label)
                    })()
                    .map_err(|error| wire_error(&error))
                }),
            )),
            Request::Apply { ops, guard } => Ok(Response::Applied(self.apply(ops, guard.as_ref()))),
            Request::ProbePartial {
                path,
                copy_id,
                guard,
            } => self.probe_partial(path, copy_id, guard.as_ref()),
            Request::Prepare {
                path,
                size,
                inplace,
                copy_id,
                mode,
                attempt,
                create_if_missing,
                guard,
            } => self
                .prepare(
                    PartialTarget {
                        path,
                        id: copy_id,
                        guard: guard.as_ref(),
                    },
                    PrepareOptions {
                        size: *size,
                        inplace: *inplace,
                        mode: *mode,
                        attempt: *attempt,
                        create_if_missing: *create_if_missing,
                    },
                )
                .map(Response::Prepared),
            Request::HashAndHold {
                off,
                path,
                copy_id,
                block,
                len,
                condition,
                guard,
            } => self
                .hash_and_hold_window(
                    path,
                    copy_id,
                    *off,
                    *block,
                    *len,
                    *condition,
                    guard.as_ref(),
                )
                .map(|(hashes, len)| Response::HeldHashes { hashes, len }),
            Request::FinishBasis {
                expected_hash,
                path,
                copy_id,
                meta,
                flags,
                condition,
                guard,
            } => self
                .finish_basis_expected(
                    path,
                    copy_id,
                    meta,
                    *flags,
                    *condition,
                    guard.as_ref(),
                    expected_hash.as_ref(),
                )
                .map(publication_response),
            Request::StageBasis {
                path,
                copy_id,
                len,
                block,
                allow_final,
                attempt,
                guard,
            } => self
                .seed_basis_impl(
                    PartialTarget {
                        path,
                        id: copy_id,
                        guard: guard.as_ref(),
                    },
                    *len,
                    *block,
                    if *allow_final { None } else { Some(&[]) },
                    *attempt,
                    true,
                )
                .map(|(_, compare_final)| Response::BasisStaged { compare_final }),
            Request::HashWindow {
                final_basis,
                path,
                copy_id,
                off,
                len,
                block,
                attempt,
                guard,
            } => self
                .hash_window(
                    PartialTarget {
                        path,
                        id: copy_id,
                        guard: guard.as_ref(),
                    },
                    *off,
                    *len,
                    *block,
                    *attempt,
                    *final_basis,
                )
                .map(Response::Hashes),
            Request::ReuseComparedRange {
                path,
                copy_id,
                attempt,
                off,
                len,
                guard,
            } => self
                .reuse_compared_range(
                    PartialTarget {
                        path,
                        id: copy_id,
                        guard: guard.as_ref(),
                    },
                    *attempt,
                    *off,
                    *len,
                )
                .map(|_| Response::Ok),
            Request::ReadComparedRange {
                path,
                source,
                attempt,
                off,
                len,
                expected,
            } => (|| {
                #[cfg(debug_assertions)]
                record_test_event(
                    "SYQ_TEST_COMPARED_READ_EVENTS",
                    format_args!("compare {off} {len}"),
                )?;
                self.read_range(path, source.as_ref(), *attempt, *off, *len)
                    .map(|reply| match reply {
                        Response::Block { off, hash, data } => {
                            let comparison = if self.hash_policy.transfer_integrity
                                && self.hash_policy.payload_algorithm()
                                    == self.hash_policy.algorithm
                            {
                                hash
                            } else {
                                self.hash_policy.algorithm.hash(&data)
                            };
                            if comparison == *expected {
                                Response::RangeMatched { off, len: *len }
                            } else {
                                Response::Block { off, hash, data }
                            }
                        }
                        other => other,
                    })
            })(),
            Request::SeedBasis {
                path,
                copy_id,
                len,
                block,
                final_ranges,
                attempt,
                guard,
            } => self
                .seed_basis(
                    PartialTarget {
                        path,
                        id: copy_id,
                        guard: guard.as_ref(),
                    },
                    *len,
                    *block,
                    final_ranges.as_deref(),
                    *attempt,
                )
                .map(Response::SeededBasis),
            Request::CopyLocal {
                source,
                dst,
                inplace,
                replace_partial,
                allow_sequential_nfs_fallback,
                allow_sequential_local_fallback,
                copy_id,
                size,
                mode,
            } => self
                .copy_local(
                    source,
                    dst,
                    CopyLocalPolicy {
                        inplace: *inplace,
                        replace_partial: *replace_partial,
                        allow_sequential_nfs_fallback: *allow_sequential_nfs_fallback,
                        allow_sequential_local_fallback: *allow_sequential_local_fallback,
                        progress,
                    },
                    copy_id,
                    *size,
                    *mode,
                )
                .map(|outcome| match outcome {
                    CopyLocalOutcome::Copied => Response::Ok,
                    CopyLocalOutcome::Unsupported => Response::CopyLocalUnsupported,
                }),
            Request::HashExistingBatch { block, files } => Ok(Response::ExistingHashes(
                self.hash_existing_batch(*block, files),
            )),
            Request::PatchSmallBatch(patches) => {
                self.patch_small_batch(patches).map(Response::PatchedBatch)
            }
            Request::PatchBegin { patch, data_len } => {
                Ok(self.begin_patch_stream(patch, *data_len))
            }
            Request::PatchData { data, hash } => self.patch_stream_data(data, *hash),
            Request::PatchEnd { commit } => self.end_patch_stream(*commit),
            Request::PutSmallBatch(puts) => {
                let results = self.put_small_batch(puts);
                if puts.iter().any(|p| p.flags & flags::REPORT_IDENTITY != 0) {
                    Ok(Response::PublishedBatch(results))
                } else {
                    Ok(Response::Applied(
                        results.into_iter().map(Result::err).collect(),
                    ))
                }
            }
            Request::HashBlocks {
                off,
                path,
                source,
                which,
                copy_id,
                block,
                len,
                attempt,
                guard,
                ..
            } => self
                .hash_blocks(
                    HashTarget {
                        path,
                        source: source.as_ref(),
                        guard: guard.as_ref(),
                    },
                    HashOptions {
                        off: *off,
                        which: *which,
                        block: *block,
                        len: *len,
                        attempt: *attempt,
                    },
                    copy_id,
                )
                .map(Response::Hashes),
            Request::ReadRange {
                path,
                source,
                attempt,
                off,
                len,
                ..
            } => self.read_range(path, source.as_ref(), *attempt, *off, *len),
            Request::ReadSmallBatch(reads) => self.read_small_batch(reads),
            Request::ReadDifferingBatch { block, reads } => {
                self.read_differing_batch(*block, reads)
            }
            Request::WriteRange {
                path,
                inplace,
                copy_id,
                attempt,
                off,
                hash,
                data,
                guard,
            } => self
                .write_range(
                    PartialTarget {
                        path,
                        id: copy_id,
                        guard: guard.as_ref(),
                    },
                    *inplace,
                    *attempt,
                    *off,
                    *hash,
                    data,
                )
                .map(|_| Response::Ok),
            Request::Finalize {
                expected_hash,
                path,
                inplace,
                copy_id,
                meta,
                flags,
                condition,
                guard,
            } => self
                .finalize_expected(
                    expected_hash.as_ref(),
                    path,
                    *inplace,
                    copy_id,
                    meta,
                    *flags,
                    TargetMutation {
                        condition: *condition,
                        guard: guard.as_ref(),
                    },
                )
                .map(publication_response),
            Request::FileHash {
                path,
                source,
                guard,
            } => self.file_hash(path, source.as_ref(), guard.as_ref()),
            Request::Canonicalize { path, guard } => {
                if let Some(guard) = guard {
                    guarded_target(path, guard)
                        .map(|target| Response::Path(path_bytes(&target.label)))
                } else if self.destination_root.is_some() {
                    Err(anyhow!(
                        "canonicalize is not valid after destination capability activation"
                    ))
                } else {
                    Ok(Response::Path(path_bytes(&normalize(&resolve(path)))))
                }
            }
            Request::BindStream(_)
            | Request::Hello { .. }
            | Request::Scan { .. }
            | Request::NativeMap(_)
            | Request::NativeRemove { .. }
            | Request::TransportStats
            | Request::Receipt
            | Request::Shutdown
            | Request::TcpListen { .. }
            | Request::ReadStream(_)
            | Request::WriteStreamFence
            | Request::ShrinkReadStream { .. }
            | Request::MappingChunk { .. }
            | Request::CreateSendBudget { .. }
            | Request::StopReadStream => Err(anyhow!("unexpected request")),
        };
        let mut response = r.unwrap_or_else(|error| Response::EndpointError(wire_error(&error)));
        match (&*req, &mut response) {
            (Request::Apply { ops, guard }, Response::Applied(errors)) => {
                for (op, error) in ops.iter().zip(errors) {
                    if let Some(error) = error {
                        let access =
                            if matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. }) {
                                0o100
                            } else {
                                0o300
                            };
                        self.annotate_permission_failure(
                            apply::op_path(op),
                            guard.as_ref(),
                            access,
                            error,
                        );
                    }
                }
            }
            (
                Request::Prepare {
                    path,
                    guard,
                    inplace,
                    ..
                },
                Response::EndpointError(error),
            ) => self.annotate_permission_failure(
                path,
                guard.as_ref(),
                if *inplace { 0o100 } else { 0o300 },
                error,
            ),
            (
                Request::Finalize { path, guard, .. }
                | Request::SeedBasis { path, guard, .. }
                | Request::StageBasis { path, guard, .. },
                Response::EndpointError(error),
            ) => self.annotate_permission_failure(path, guard.as_ref(), 0o300, error),
            (Request::PutSmallBatch(puts), Response::Applied(errors)) => {
                for (put, error) in puts.iter().zip(errors) {
                    if let Some(error) = error {
                        self.annotate_permission_failure(
                            &put.path,
                            put.guard.as_ref(),
                            0o300,
                            error,
                        );
                    }
                }
            }
            (Request::PatchSmallBatch(patches), Response::PatchedBatch(results)) => {
                for (patch, result) in patches.iter().zip(results) {
                    if let Err(error) = result {
                        self.annotate_permission_failure(
                            &patch.path,
                            patch.guard.as_ref(),
                            0o300,
                            &mut error.error,
                        );
                    }
                }
            }
            _ => {}
        }
        self.rebase_response(response)
    }
}

pub(super) fn publish_partial_rooted(
    root: &Root,
    source: &RelativePath,
    target: &RelativePath,
    staged: &File,
    condition: TargetCondition,
) -> Result<()> {
    let metadata = staged.metadata()?;
    if !is_safe_partial(&metadata) {
        bail!("confined partial is not a private regular file");
    }
    let staged_dev = metadata.dev();
    let staged_ino = metadata.ino();
    let staged_identity = (staged_dev, staged_ino);
    match condition {
        TargetCondition::Any => root.rename_regular_if_same(source, target, staged_identity),
        TargetCondition::Absent => root.publish_new_regular(source, target, staged_identity),
        TargetCondition::Matches { dev, ino } => {
            root.replace_regular_if_same(source, target, staged_identity, dev, ino, None)
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => root.replace_regular_if_same(
            source,
            target,
            staged_identity,
            dev,
            ino,
            Some((ctime, ctime_nsec)),
        ),
    }?;
    sidecars::forget(staged_identity);
    Ok(())
}

/// Open an existing leaf without following a last-component symlink. Parent
/// component confinement is a separate, root-fd-based design problem.
pub(super) fn open_existing_regular(target: &Path, write: bool) -> Result<File> {
    open_existing_regular_with_metadata(target, write).map(|(file, _)| file)
}

pub(super) fn open_existing_regular_with_metadata(
    target: &Path,
    write: bool,
) -> Result<(File, fs::Metadata)> {
    let mut options = OpenOptions::new();
    options
        .read(!write)
        .write(write)
        // Validate the opened type below. O_NONBLOCK ensures a concurrent FIFO
        // or device replacement cannot hang us before that validation.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(target)
        .with_context(|| format!("open {}", target.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        bail!("{} is not a regular file", target.display());
    }
    Ok((file, metadata))
}

pub(super) fn require_safe_partial(file: &File, target: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !is_safe_partial(&metadata) {
        bail!(
            "partial {} is not a singly-linked regular file",
            target.display()
        );
    }
    Ok(())
}

/// Devices where a file this process has just created exclusively reports
/// another owner: sshfs without uid mapping, squashed NFS, a CIFS mount with
/// a forced uid. Ownership cannot show there that a sidecar opened without
/// exclusive creation is new, so sidecars are created exclusively from the
/// start instead of after that check has failed.
fn foreign_owner_devices() -> &'static Mutex<std::collections::HashSet<u64>> {
    static DEVICES: OnceLock<Mutex<std::collections::HashSet<u64>>> = OnceLock::new();
    DEVICES.get_or_init(Default::default)
}

pub(super) fn creates_foreign_owners(dev: u64) -> bool {
    foreign_owner_devices().lock().unwrap().contains(&dev)
}

fn note_created_owner(metadata: &fs::Metadata) {
    if metadata.uid() != unsafe { libc::geteuid() } {
        foreign_owner_devices()
            .lock()
            .unwrap()
            .insert(metadata.dev());
    }
}

// Ownership is required when adopting a leftover, before chmod or writes.
// Publication checks deliberately allow metadata's requested final owner.
pub(super) fn is_owned_partial(metadata: &fs::Metadata) -> bool {
    is_safe_partial(metadata) && metadata.uid() == unsafe { libc::geteuid() }
}

pub(super) fn is_owned_rooted_partial(metadata: RootMetadata) -> bool {
    is_safe_rooted_partial(metadata) && metadata.uid == unsafe { libc::geteuid() }
}

/// Creation mode of a staging sidecar whose final mode is not yet known.
pub(super) const PRIVATE_PARTIAL_MODE: u32 = 0o600;

/// Creation mode for a whole-file sidecar: the final permission bits, so that
/// publication needs no separate chmod (on a network filesystem every setattr
/// is a round trip). Special bits are still applied by `set_meta_file` once the
/// content is written.
///
/// The sidecar stays private when no mode is requested, when group
/// preservation is requested, and when an ACL will be applied. The kernel
/// assigns the receiver's or a setgid parent's group at creation, and final
/// group bits would let that group read or write the content until the
/// chown. With an ACL the final group bits are the ACL mask, which can be
/// wider than what the file grants its owning group. Without either, the
/// group at creation is the final group, and the owner bits only widen
/// access for the receiver, which already holds the content.
pub(crate) fn staged_file_mode(meta: &Meta, flags: u8) -> u32 {
    staged_mode(meta.mode, flags, has_acl(meta.inode_metadata.as_deref()))
}

/// The same from the parts a sender has at hand, without cloning the
/// file's metadata.
pub(crate) fn staged_mode(mode: u32, flags: u8, acl: bool) -> u32 {
    if flags & flags::MODE_MASK != 0 && flags & flags::GROUP == 0 && !acl {
        mode & 0o777
    } else {
        PRIVATE_PARTIAL_MODE
    }
}

pub(crate) fn has_acl(metadata: Option<&crate::inode_metadata::InodeMetadata>) -> bool {
    metadata.is_some_and(|metadata| metadata.acls.is_some() || metadata.macos_acl.is_some())
}

pub(super) fn is_safe_partial(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && metadata.nlink() == 1
}

/// Whether a sidecar opened without exclusive creation is what an exclusive
/// create with `mode` would have made: a new empty file of ours with no
/// permission beyond that mode and no set-id bit. Anything else at the name,
/// including an older sidecar with data or a wider mode, takes the checked
/// path, which repairs or replaces it before anything is written.
pub(super) fn is_fresh_partial(metadata: &fs::Metadata, mode: u32) -> bool {
    let reported = reported_mode(metadata.mode());
    is_owned_partial(metadata)
        && metadata.len() == 0
        && reported & 0o7000 == 0
        && reported & 0o777 & !(mode & 0o777) == 0
}

impl FsOps {
    /// Whether a sidecar's mode lets its group or others in beyond `widest`,
    /// so that someone may hold it open who could not open a new one. On
    /// Linux an ACL's mask is the group bits, so the mode also bounds what
    /// the ACL's named entries grant. Never on a device where this connection
    /// found that a new file cannot be narrowed: one there would be no less
    /// readable.
    pub(super) fn wider_than(&self, mode: u32, dev: u64, widest: Option<u32>) -> bool {
        widest.is_some_and(|widest| reported_mode(mode) & 0o077 & !widest != 0)
            && self.fixed_wide_modes(dev) != Some(true)
    }

    /// Whether a device this connection probed cannot narrow a new file:
    /// `Some(true)` for one that ignores a chmod, such as a Linux CIFS mount
    /// without POSIX extensions, which reports one fixed mode for every file.
    /// Mode bits restrict nobody there. Every file, new or reused, admits
    /// whoever that mode admits, so replacing a reused sidecar that looks
    /// wider than its attempt's mode could not make it any less readable; it
    /// would only cost the sidecar's resumable bytes and several requests.
    ///
    /// The answer is kept per connection, never per process: a persistent
    /// receiving service handles copies for days, and the number of an
    /// unmounted device is given to the next network, FUSE or tmpfs mount.
    /// A sidecar on another device keeps the check, and so does one on a
    /// device whose new file could be narrowed, or whose chmod was refused.
    pub(super) fn fixed_wide_modes(&self, dev: u64) -> Option<bool> {
        self.fixed_wide_mode_devices.get(&dev).copied()
    }

    /// Probe the device of a sidecar just created exclusively with
    /// `requested` when it came out wider: narrow it to `requested`, which
    /// only takes an empty file of ours to the mode it was created with. The
    /// device counts as unable to narrow a new file only when that succeeds
    /// and the mode stays wider, as a filesystem that ignores chmod leaves
    /// it. A refusal proves nothing about the device, since whether a file's
    /// mode may change can depend on that file's own ACL (NFSv4
    /// ACE4_WRITE_ACL), so the device keeps the check. Either way the device
    /// is probed once per connection.
    pub(super) fn note_created_mode(
        &mut self,
        file: &File,
        created: &fs::Metadata,
        requested: u32,
    ) {
        let requested = requested & 0o777;
        let wider = |mode: u32| reported_mode(mode) & 0o777 & !requested != 0;
        if !wider(created.mode()) || self.fixed_wide_modes(created.dev()).is_some() {
            return;
        }
        let fixed = probe_mode_change(file, requested).is_ok()
            && file.metadata().is_ok_and(|now| wider(now.mode()));
        self.fixed_wide_mode_devices.insert(created.dev(), fixed);
    }
}

#[cfg(test)]
thread_local! {
    /// A mode this thread's sidecars report, as a device that reports one
    /// fixed mode does, like `SYQ_TEST_FORCED_MODE` for a whole process.
    pub(super) static FORCED_MODE: std::cell::Cell<Option<u32>> =
        const { std::cell::Cell::new(None) };
    /// Refuses the mode change that probes a device, as a file's own ACL can.
    pub(super) static REFUSE_MODE_PROBE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Change the mode of a probed file, or refuse as a test asks.
fn probe_mode_change(file: &File, mode: u32) -> io::Result<()> {
    #[cfg(test)]
    if REFUSE_MODE_PROBE.get() {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    file.set_permissions(fs::Permissions::from_mode(mode))
}

/// A sidecar's mode as reported. Debug builds simulate a device that
/// reports one fixed mode for every file with `SYQ_TEST_FORCED_MODE`, the
/// permission bits in octal.
fn reported_mode(mode: u32) -> u32 {
    #[cfg(any(test, debug_assertions))]
    if let Some(forced) = test_forced_mode() {
        return mode & !0o7777 | forced;
    }
    mode
}

#[cfg(any(test, debug_assertions))]
fn test_forced_mode() -> Option<u32> {
    #[cfg(test)]
    if let Some(mode) = FORCED_MODE.get() {
        return Some(mode & 0o777);
    }
    let value = std::env::var_os("SYQ_TEST_FORCED_MODE")?;
    u32::from_str_radix(value.to_str()?, 8)
        .ok()
        .map(|mode| mode & 0o777)
}

/// Whether the open or create of the sidecar was refused because of what
/// the name already held: a symlink, a directory, a FIFO without a reader,
/// a file this account may not write, or an existing entry that a creation
/// without an OS error code refused (the macOS ACL sidecar). The checked
/// path then examines the name, and repeats the creation for an error that
/// was not about it.
pub(super) fn existing_leaf_refused(error: &anyhow::Error) -> bool {
    error_is_kind(error, io::ErrorKind::AlreadyExists)
        || error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .is_some_and(|code| {
                matches!(
                    code,
                    libc::ELOOP
                        | libc::EISDIR
                        | libc::ENXIO
                        | libc::EACCES
                        | libc::EPERM
                        | libc::ETXTBSY
                )
            })
}

pub(super) fn is_safe_rooted_partial(metadata: RootMetadata) -> bool {
    metadata.is_file() && metadata.nlink == 1
}

pub(super) fn require_safe_rooted_named_partial(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    file: &File,
) -> Result<()> {
    let opened = file.metadata()?;
    let named = root.metadata(relative)?;
    if !is_safe_partial(&opened)
        || !is_safe_rooted_partial(named)
        || opened.dev() != named.dev
        || opened.ino() != named.ino
    {
        bail!(
            "partial {} is not the opened singly-linked regular file",
            label.display()
        );
    }
    Ok(())
}

/// Best-effort cleanup of a private job sidecar that still names the inspected
/// inode. POSIX has no identity-conditioned unlink, so a writer of this same
/// retained parent can replace the random sidecar between the observation and
/// `unlinkat`. The operation remains confined to the retained parent; callers
/// must not use this helper for a final destination name whose later writer
/// needs compare-and-swap semantics.
pub(super) fn discard_safe_rooted_partial_if_same(
    root: &Root,
    relative: &RelativePath,
    expected_dev: u64,
    expected_ino: u64,
    label: &Path,
) -> Result<()> {
    match root.metadata_optional(relative)? {
        Some(current)
            if is_safe_rooted_partial(current)
                && current.dev == expected_dev
                && current.ino == expected_ino =>
        {
            root.unlink(relative)
                .with_context(|| format!("replace {}", label.display()))?;
            sidecars::forget((expected_dev, expected_ino));
        }
        Some(_) | None => {}
    }
    Ok(())
}

/// Create a sidecar with `create`, which must create exclusively, removing
/// whatever the name holds first. A sidecar that will hold anything but the
/// new contents, such as bytes of the file it replaces or of an earlier
/// partial, must be a file no one else can have opened: permissions are
/// checked only at open, so whoever opened a leftover while its mode was
/// wider can read what is later written to it. Only an exclusive create shows
/// that a file is new, whatever mode the filesystem gives it; an empty file
/// of ours with a narrow mode may have been neither. Like the checked reuse,
/// this removes anything but a directory at the sidecar's name, which is
/// this copy's own.
pub(super) fn create_fresh_rooted_partial(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    create: impl Fn() -> Result<File>,
) -> Result<(File, fs::Metadata)> {
    for _ in 0..8 {
        match create() {
            Ok(file) => {
                let metadata = file.metadata()?;
                note_created_owner(&metadata);
                return Ok((file, metadata));
            }
            Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                match root.unlink(relative) {
                    Ok(()) => {}
                    Err(error) if error_is_kind(&error, io::ErrorKind::NotFound) => {}
                    Err(error) => return Err(error.context(format!("replace {}", label.display()))),
                }
            }
            Err(error) => return Err(error),
        }
    }
    bail!(
        "partial {} changed repeatedly while creating it",
        label.display()
    )
}

/// Which donors' bytes may be seeded into the sidecar `output`, which is
/// created owner-only so that they stay as private as each donor kept them.
/// On macOS a new file also takes its directory's inheritable ACL entries
/// whatever its mode, and those can let someone read the sidecar whom a
/// donor never let read it: a partial an earlier copy left with `-A`, or
/// from before the directory gained that policy. There a donor is used only
/// when the sidecar has no entries or exactly the donor's; otherwise the
/// copy does without it, as with any unsuitable donor. The sidecar's ACL is
/// read once, however many donors are weighed; each donor's is read only
/// when the sidecar has entries. Elsewhere the owner-only mode suffices: it
/// masks the named entries of a POSIX default ACL.
pub(super) struct SeedAccess<'a> {
    output: &'a File,
    #[cfg(target_os = "macos")]
    acl: std::cell::OnceCell<Option<crate::inode_metadata::MacAcl>>,
}

impl<'a> SeedAccess<'a> {
    pub(super) fn new(output: &'a File) -> Self {
        Self {
            output,
            #[cfg(target_os = "macos")]
            acl: std::cell::OnceCell::new(),
        }
    }

    pub(super) fn admits(&self, donor: &File) -> bool {
        #[cfg(target_os = "macos")]
        {
            use crate::inode_metadata::read_macos_acl;
            match self.acl.get_or_init(|| read_macos_acl(self.output).ok()) {
                Some(stage) if stage.entries.is_empty() => true,
                Some(stage) => read_macos_acl(donor).is_ok_and(|donor| donor == *stage),
                None => false,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (self.output, donor);
            true
        }
    }
}

#[cfg(debug_assertions)]
pub(super) fn fail_partial_chmod_for_test() -> Result<()> {
    if std::env::var_os("SYQ_TEST_FAIL_PARTIAL_CHMOD").is_some() {
        bail!("injected partial chmod failure");
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
pub(super) fn fail_partial_chmod_for_test() -> Result<()> {
    Ok(())
}

/// Preallocate a new file on device `dev`, as `preallocate_new_file` does
/// on that device's filesystem.
#[cfg(target_os = "linux")]
pub(super) fn preallocate_new_file_on(file: &File, dev: u64, size: u64) -> Result<()> {
    let traits = file_system_traits(file, file_system_key(file, dev));
    #[cfg(debug_assertions)]
    let traits = FileSystemTraits {
        is_nfs: traits.is_nfs || std::env::var_os("SYQ_TEST_DESTINATION_NFS").is_some(),
        ..traits
    };
    preallocate_new_file(file, size, traits)
}

#[cfg(target_os = "linux")]
pub(super) fn preallocate_new_file(f: &File, size: u64, traits: FileSystemTraits) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    // NFS writes grow the sidecar naturally, avoiding separate ALLOCATE and
    // SETATTR operations. Unsupported local filesystems retain the portable
    // sparse-sizing fallback.
    if traits.is_nfs {
        return Ok(());
    }
    // Btrfs fallocate disables compression, even when explicitly requested.
    // Keep the logical sizing without reserving uncompressed physical extents.
    if traits.uses_btrfs_compression(f) {
        return f
            .set_len(size)
            .context("set compressed destination file length");
    }
    let fallocate_error = if let Some(raw) = test_fallocate_errno() {
        Some(io::Error::from_raw_os_error(raw))
    } else {
        let length = libc::off_t::try_from(size).context("file is too large to preallocate")?;
        let result = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, length) };
        (result != 0).then(io::Error::last_os_error)
    };
    match fallocate_error {
        None => return Ok(()),
        Some(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL)
            ) => {}
        Some(error) => return Err(error).context("preallocate destination file"),
    }
    f.set_len(size)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    /// Fails the preallocations this thread makes with this error, as
    /// `SYQ_TEST_FALLOCATE_ERRNO` does for a whole process.
    pub(super) static FALLOCATE_ERRNO: std::cell::Cell<Option<i32>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(target_os = "linux", any(test, debug_assertions)))]
pub(super) fn test_fallocate_errno() -> Option<i32> {
    #[cfg(test)]
    if let Some(errno) = FALLOCATE_ERRNO.get() {
        return Some(errno);
    }
    let value = std::env::var_os("SYQ_TEST_FALLOCATE_ERRNO")?;
    match value.to_string_lossy().as_ref() {
        "unsupported" => Some(libc::EOPNOTSUPP),
        "no_space" => Some(libc::ENOSPC),
        "quota" => Some(libc::EDQUOT),
        value => value.parse().ok(),
    }
}

#[cfg(all(target_os = "linux", not(any(test, debug_assertions))))]
pub(super) fn test_fallocate_errno() -> Option<i32> {
    None
}

#[cfg(not(target_os = "linux"))]
pub(super) fn preallocate_new_file(f: &File, size: u64) -> Result<()> {
    if size > 0 {
        f.set_len(size)?;
    }
    Ok(())
}

pub(super) fn timespec(sec: i64, nsec: u32) -> libc::timespec {
    libc::timespec {
        tv_sec: sec as libc::time_t,
        tv_nsec: nsec as libc::c_long,
    }
}

/// Collect pending write errors before metadata changes and publication, while
/// keeping the original inode pinned. Linux NFS flushes on a duplicate close.
/// macOS closes duplicates without calling the filesystem, so flush NFS/SMB
/// explicitly there. This is not a general crash-durability guarantee and does
/// not collect every error reported on other workers' cached handles.
pub(crate) fn check_destination_writes(file: &File, label: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let check = || -> io::Result<()> {
            let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: fstatfs initializes stats, including a NUL-terminated type
            // name, on success. Inspect this inode, not a root that might have
            // a different filesystem mounted underneath it.
            crate::sys::retry_zero(|| unsafe {
                libc::fstatfs(file.as_raw_fd(), stats.as_mut_ptr())
            })?;
            let stats = unsafe { stats.assume_init() };
            let kind = unsafe { std::ffi::CStr::from_ptr(stats.f_fstypename.as_ptr()) };
            if matches!(kind.to_bytes(), b"nfs" | b"smbfs") {
                // Use ordinary fsync: Rust's sync_all/sync_data request the
                // stronger, expensive F_FULLFSYNC on macOS. Local filesystems
                // need neither this flush nor an ineffective duplicate close.
                // SAFETY: file keeps this descriptor alive through the call.
                crate::sys::retry_zero(|| unsafe { libc::fsync(file.as_raw_fd()) })?;
            }
            #[cfg(debug_assertions)]
            fail_writer_close_for_test(label)?;
            Ok(())
        };
        check().with_context(|| format!("check destination writes {}", label.display()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let writer = file
            .try_clone()
            .with_context(|| format!("duplicate destination writer {}", label.display()))?;
        close_writer(writer, label)
    }
}

#[cfg(not(target_os = "macos"))]
fn close_writer(file: File, label: &Path) -> Result<()> {
    use std::os::fd::IntoRawFd;
    let check = || -> io::Result<()> {
        let fd = file.into_raw_fd();
        // SAFETY: into_raw_fd transfers ownership. Close exactly once: retrying
        // an interrupted close can close a descriptor reused by another thread.
        if unsafe { libc::close(fd) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(debug_assertions)]
        fail_writer_close_for_test(label)?;
        Ok(())
    };
    check().with_context(|| format!("check destination writes {}", label.display()))
}

#[cfg(debug_assertions)]
fn fail_writer_close_for_test(label: &Path) -> io::Result<()> {
    if let Some(pattern) = std::env::var_os("SYQ_TEST_FAIL_WRITER_CLOSE") {
        if !pattern.is_empty()
            && label
                .as_os_str()
                .as_bytes()
                .windows(pattern.as_bytes().len())
                .any(|part| part == pattern.as_bytes())
        {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
    }
    Ok(())
}

pub(crate) fn set_meta_file(f: &File, meta: &Meta, flags: u8) -> Result<()> {
    if flags & (flags::MODE_MASK | flags::OWNER | flags::GROUP | flags::TIMES) == 0
        && meta.inode_metadata.is_none()
    {
        return Ok(());
    }
    let current = f.metadata()?;
    set_meta_file_known(f, meta, flags, &current)
}

pub(super) fn set_meta_file_known(
    f: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    set_meta_file_inner(f, meta, flags, current, false, true)
}

/// Set a written file's metadata from the metadata read when it was created.
/// On NFS that read costs nothing, because the create's reply has just
/// primed the attribute cache, where one taken after the write is a request.
/// The write since then has changed the times, so those are always set.
pub(super) fn set_meta_written_file(
    f: &File,
    meta: &Meta,
    flags: u8,
    created: &fs::Metadata,
) -> Result<()> {
    set_meta_file_inner(f, meta, flags, created, false, false)
}

pub(super) fn set_meta_file_for_publication(f: &File, meta: &Meta, flags: u8) -> Result<()> {
    set_meta_file_inner(f, meta, flags, &f.metadata()?, true, true)
}

/// The same for a staged file about to be published.
pub(super) fn set_meta_written_file_for_publication(
    f: &File,
    meta: &Meta,
    flags: u8,
    created: &fs::Metadata,
) -> Result<()> {
    set_meta_file_inner(f, meta, flags, created, true, false)
}

fn set_meta_file_inner(
    f: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
    before_publication: bool,
    times_current: bool,
) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // macOS mode and ACL must change together. Keep private staging
    // permissions until publication instead of opening a mode-only window.
    let atomic_acl_mode = cfg!(target_os = "macos")
        && meta
            .inode_metadata
            .as_ref()
            .is_some_and(|m| m.macos_acl.is_some());
    if before_publication
        && atomic_acl_mode
        && flags & flags::OWNER != 0
        && current.uid() != meta.uid
    {
        // The final owner may itself be denied read access by the source ACL.
        // Do not hand that account the staging inode's owner read permission.
        f.set_permissions(fs::Permissions::from_mode(0o000))?;
    }
    // Owner first: chown clears setuid/setgid, so final mode follows it.
    let owner_changed =
        apply_owner_if_changed(flags, meta, current.uid(), current.gid(), |uid, gid| {
            std::os::unix::fs::fchown(f, uid, gid)
        })?;
    if owner_changed {
        super::access_changed(f);
    }
    #[cfg(debug_assertions)]
    if before_publication && atomic_acl_mode && owner_changed {
        test_race_barrier(
            "SYQ_TEST_ACL_OWNER_READY_FILE",
            "SYQ_TEST_ACL_OWNER_CONTINUE_FILE",
            "ACL stage after ownership change",
        )?;
    }
    if flags & flags::TIMES != 0
        && (!times_current
            || current.mtime() != meta.mtime
            || current.mtime_nsec() as u32 != meta.mtime_nsec)
    {
        let ts = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        let r = unsafe { libc::futimens(f.as_raw_fd(), ts.as_ptr()) };
        if r != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    // A Linux ACL before the mode (see `apply_acls`).
    let narrowed = crate::inode_metadata::apply_acls(
        f,
        meta.inode_metadata.as_deref(),
        meta.mode,
        flags & flags::MODE_MASK != 0,
    )?;
    if flags & flags::MODE_MASK != 0 && !atomic_acl_mode {
        // On network filesystems every setattr is a round trip; skip it when
        // the mode is already right. Always run it for set-id bits after a
        // chown, which clears them, and when the metadata predates a write,
        // which clears them for an unprivileged writer.
        let cur = narrowed.unwrap_or(current.mode() & 0o7777);
        let want = meta.mode & 0o7777;
        if cur != want || ((owner_changed || !times_current) && want & 0o6000 != 0) {
            f.set_permissions(fs::Permissions::from_mode(want))?;
            super::access_changed(f);
        }
    }
    if before_publication {
        crate::inode_metadata::apply_after_acls_before_publication(
            f,
            meta.inode_metadata.as_deref(),
            meta.mode,
        )
    } else {
        crate::inode_metadata::apply_after_acls(f, meta.inode_metadata.as_deref(), meta.mode)
    }
}

/// Apply only ownership fields whose requested values differ from the
/// metadata already observed. Returns whether a chown ran, since it may clear
/// set-id mode bits that a following chmod must restore.
pub(super) fn apply_owner_if_changed(
    flags: u8,
    meta: &Meta,
    current_uid: u32,
    current_gid: u32,
    chown: impl Fn(Option<u32>, Option<u32>) -> io::Result<()>,
) -> Result<bool> {
    let uid = if flags & flags::OWNER != 0
        && (is_superuser() || flags & flags::REQUIRE_OWNER != 0)
        && current_uid != meta.uid
    {
        Some(meta.uid)
    } else {
        None
    };
    let gid = if flags & flags::GROUP != 0 && current_gid != meta.gid {
        Some(meta.gid)
    } else {
        None
    };
    if uid.is_none() && gid.is_none() {
        return Ok(false);
    }
    match chown(uid, gid) {
        Ok(()) => Ok(true),
        Err(e)
            if e.kind() == io::ErrorKind::PermissionDenied
                && uid.is_none()
                && flags & flags::REQUIRE_GROUP == 0 =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

// Read from the completed descriptor, never from its mutable published name.
pub(super) fn published_identity(file: &File, flags: u8) -> Result<Option<(u64, u64)>> {
    if flags & flags::REPORT_IDENTITY == 0 {
        return Ok(None);
    }
    Ok(Some(identity_of(&file.metadata()?)))
}

/// The identity of a file from metadata read at any time since it was
/// opened: a rename does not change it.
pub(super) fn known_identity(metadata: &fs::Metadata, flags: u8) -> Option<(u64, u64)> {
    (flags & flags::REPORT_IDENTITY != 0).then(|| identity_of(metadata))
}

/// One file of a small source batch: what to read, and from where.
trait SmallSourceRead {
    fn path(&self) -> &PathBytes;
    fn source(&self) -> Option<&RegisteredPath>;
    fn attempt(&self) -> u32;
    /// The whole file's length, read from its start.
    fn len(&self) -> u32;
}

impl SmallSourceRead for SmallRead {
    fn path(&self) -> &PathBytes {
        &self.path
    }
    fn source(&self) -> Option<&RegisteredPath> {
        self.source.as_ref()
    }
    fn attempt(&self) -> u32 {
        self.attempt
    }
    fn len(&self) -> u32 {
        self.len
    }
}

impl SmallSourceRead for DifferingRead {
    fn path(&self) -> &PathBytes {
        &self.path
    }
    fn source(&self) -> Option<&RegisteredPath> {
        self.source.as_ref()
    }
    fn attempt(&self) -> u32 {
        self.attempt
    }
    fn len(&self) -> u32 {
        self.len
    }
}

/// A small source read's result, which carries the source metadata
/// rechecked after every file in its batch was read.
trait SmallSourceResult {
    fn set_source(&mut self, source: Option<Entry>);
}

impl SmallSourceResult for SmallBlock {
    fn set_source(&mut self, source: Option<Entry>) {
        self.source = source;
    }
}

impl SmallSourceResult for DifferingBlocks {
    fn set_source(&mut self, source: Option<Entry>) {
        self.source = source;
    }
}

/// How `open_private_partial_rooted` settled on its partial.
pub(super) enum OpenedPartial {
    /// It created the file, whose metadata was read as it was created.
    Created(fs::Metadata),
    /// It reopened a partial of this length.
    Reused(u64),
}

impl OpenedPartial {
    /// The length of the reopened partial, whose bytes may be resumed.
    pub(super) fn basis_size(&self) -> Option<u64> {
        match self {
            Self::Created(_) => None,
            Self::Reused(len) => Some(*len),
        }
    }

    /// The created file's device and inode.
    pub(super) fn identity(&self) -> Option<(u64, u64)> {
        match self {
            Self::Created(created) => Some(identity_of(created)),
            Self::Reused(_) => None,
        }
    }
}

fn identity_of(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn publication_response(identity: Option<(u64, u64)>) -> Response {
    match identity {
        Some((dev, ino)) => Response::Published { dev, ino },
        None => Response::Ok,
    }
}

/// Report the first partial write promptly, then at most every 100 ms. The
/// terminal response credits the remainder without a redundant progress frame.
#[cfg(target_os = "linux")]
struct CopyProgress<'a> {
    emit: &'a mut dyn FnMut(u64) -> Result<()>,
    reported: u64,
    size: u64,
    last: std::time::Instant,
}

#[cfg(target_os = "linux")]
impl<'a> CopyProgress<'a> {
    fn new(emit: &'a mut dyn FnMut(u64) -> Result<()>, size: u64) -> Self {
        Self {
            emit,
            reported: 0,
            size,
            last: std::time::Instant::now(),
        }
    }

    fn advance(&mut self, total: u64) -> Result<()> {
        if total < self.size
            && (self.reported == 0 || self.last.elapsed() >= std::time::Duration::from_millis(100))
        {
            (self.emit)(total)?;
            self.reported = total;
            self.last = std::time::Instant::now();
        }
        Ok(())
    }
}
