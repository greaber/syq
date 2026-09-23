use super::*;

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

    pub(super) fn open_private_partial_rooted(
        &mut self,
        root: &Root,
        relative: &RelativePath,
        label: &Path,
        create_if_missing: bool,
        create_mode: u32,
    ) -> Result<Option<(File, Option<u64>)>> {
        self.uncache_rooted(root, relative);
        let mut repaired_permissions = false;
        if create_if_missing {
            match root.create_file(relative, create_mode) {
                Ok(file) => return Ok(Some((file, None))),
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
                            if opened.mode() & 0o7777 != 0o600 {
                                let repair = (|| -> Result<()> {
                                    fail_partial_chmod_for_test()?;
                                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
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
                            return Ok(Some((file, Some(opened.len()))));
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
                            let repair = (|| -> Result<()> {
                                fail_partial_chmod_for_test()?;
                                set_mode_handle(&handle, 0o600)?;
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
                None => match root.create_file(relative, create_mode) {
                    Ok(file) => return Ok(Some((file, None))),
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
            let dev = file.metadata()?.dev();
            let key = file_system_key(file, dev);
            let traits = file_system_traits(file, key);
            #[cfg(debug_assertions)]
            let traits = FileSystemTraits {
                is_nfs: traits.is_nfs || std::env::var_os("SYQ_TEST_DESTINATION_NFS").is_some(),
                ..traits
            };
            preallocate_new_file(file, size, traits)
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
            return Ok(Preparation {
                partial_size: None,
                has_candidates: true,
            });
        }
        if inplace {
            self.uncache_rooted(&target.root, &target.relative);
            // An interrupted non-inplace run must not strand this job's
            // adjacent sidecar when the retry switches to --inplace.
            let _ = with_rooted_partial(&target, copy_id, |partial, _| target.root.unlink(partial));
            for _ in 0..8 {
                match target.root.metadata_optional(&target.relative)? {
                    Some(metadata) if metadata.is_file() => {
                        // Retain a descriptor that can service the
                        // immediately following destination hash as well
                        // as range writes.
                        let file = target.root.open_regular_read_write(&target.relative)?;
                        require_rooted_metadata(&file, metadata, &target.label)?;
                        self.set_copy_length(&file, size).with_context(|| {
                            format!("resize confined file {}", target.label.display())
                        })?;
                        self.cache_file(target.location(), attempt, false, file);
                        return Ok(Preparation::default());
                    }
                    Some(metadata) if metadata.is_dir() => {
                        bail!("destination {} is a directory", target.label.display())
                    }
                    Some(_) => target.root.unlink(&target.relative)?,
                    None => match target.root.create_file(&target.relative, mode) {
                        Ok(file) => {
                            self.set_copy_length(&file, size).with_context(|| {
                                format!("resize confined file {}", target.label.display())
                            })?;
                            self.cache_file(target.location(), attempt, false, file);
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
        let (relative, _label, opened) =
            with_rooted_partial(&target, copy_id, |relative, label| {
                self.open_private_partial_rooted(
                    &target.root,
                    relative,
                    label,
                    create_if_missing,
                    PRIVATE_PARTIAL_MODE,
                )
            })?;
        let Some((file, basis_size)) = opened else {
            return Ok(Preparation::default());
        };
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
        self.cache_file(
            FileLocation::Rooted {
                root: target.root.identity(),
                relative,
            },
            attempt,
            true,
            file,
        );
        Ok(Preparation {
            partial_size: basis_size,
            has_candidates: false,
        })
    }

    pub fn hash_and_hold(
        &mut self,
        path: &[u8],
        copy_id: &CopyId,
        block: u64,
        len: u64,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<(Vec<ContentDigest>, u64)> {
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_HASH_BASIS").is_some() {
            bail!("injected retained-basis hash failure");
        }
        let rooted = self.rooted_destination_target(path, guard)?;
        let (mut file, location, label) = if let Some(target) = &rooted {
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
        test_race_barrier(
            "SYQ_TEST_BASIS_READY_FILE",
            "SYQ_TEST_BASIS_CONTINUE_FILE",
            "basis-ready",
        )?;
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
        let PartialTarget {
            path,
            id: copy_id,
            guard,
        } = target;
        if !hash_response_fits(block, len) {
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
        let (relative, _label, opened) =
            with_rooted_partial(&target, copy_id, |relative, label| {
                self.open_private_partial_rooted(
                    &target.root,
                    relative,
                    label,
                    true,
                    PRIVATE_PARTIAL_MODE,
                )
            })?;
        let (output, basis_size) = opened.context("sidecar creation was requested")?;
        let location = FileLocation::Rooted {
            root: target.root.identity(),
            relative,
        };
        // Retry bytes already belong to this invocation. Hash them in place;
        // copying them onto themselves adds writes without improving safety.
        let mut input = None;
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
        if final_ranges.is_none_or(|ranges| !ranges.is_empty())
            && basis_size.unwrap_or(0) == 0
            && input.is_none()
        {
            input = held
                .map(|held| held.file)
                .or_else(|| target.root.open_regular_read(&target.relative).ok());
            selected_final = input.as_ref().and(final_ranges);
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
        Ok(SeededBasis {
            hashes,
            selected_final: selected_final.is_some(),
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn prepare_local_copy(
        &self,
        source: &RegisteredPath,
        dst: &[u8],
    ) -> Result<(File, fs::Metadata, RootedTarget)> {
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
        // A staged copy could safely replace a hard-linked destination, but a
        // command that names the same file is still a self-copy and should not
        // silently replace its own selected source. The in-place open repeats
        // this check against the exact descriptor before truncation.
        if destination_root
            .metadata_optional(&destination_relative)?
            .is_some_and(|metadata| {
                metadata.is_file()
                    && metadata.dev == source_metadata.dev()
                    && metadata.ino == source_metadata.ino()
            })
        {
            bail!(
                "source and destination are the same file: {}",
                destination_label.display()
            );
        }
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
        ))
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
        policy: CopyLocalPolicy,
        copy_id: &CopyId,
        size: u64,
        mode: u32,
    ) -> Result<CopyLocalOutcome> {
        let _copy = self
            .operation
            .span(crate::transfer_observations::Stage::FilesystemCopy);
        let CopyLocalPolicy {
            inplace,
            allow_sequential_nfs_fallback,
            allow_sequential_local_fallback,
        } = policy;
        let (s, source_metadata, target) = self.prepare_local_copy(source, dst)?;
        let source_label = PathBuf::from(OsStr::from_bytes(source.relative()));
        // Advisory sequential readahead for the kernel copy on Linux.
        unsafe {
            libc::posix_fadvise(s.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        }
        let destination_root = target.root.clone();
        let source_key = file_system_key(&s, source_metadata.dev());
        self.uncache_rooted(&destination_root, &target.relative);
        let (mut target_relative, mut target_label) =
            (target.relative.clone(), target.label.clone());
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
                        file.set_len(0).with_context(|| {
                            format!("truncate confined file {}", target_label.display())
                        })?;
                        opened = Some(file);
                        break;
                    }
                    Some(metadata) if metadata.is_dir() => {
                        bail!("destination {} is a directory", target_label.display())
                    }
                    Some(_) => destination_root.unlink(&target_relative)?,
                    None => match destination_root.create_file(&target_relative, mode) {
                        Ok(file) => {
                            opened = Some(file);
                            break;
                        }
                        Err(error)
                            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                error.kind() == io::ErrorKind::AlreadyExists
                            }) => {}
                        Err(error) => return Err(error),
                    },
                }
            }
            opened.with_context(|| {
                format!(
                    "destination {} changed repeatedly while opening it",
                    target_label.display()
                )
            })?
        } else {
            let (relative, label, opened) =
                with_rooted_partial(&target, copy_id, |relative, label| {
                    self.open_private_partial_rooted(
                        &destination_root,
                        relative,
                        label,
                        true,
                        PRIVATE_PARTIAL_MODE,
                    )
                })?;
            target_relative = relative;
            target_label = label;
            let (d, basis_size) = opened.context("sidecar creation was requested")?;
            if basis_size.is_some() {
                // Preserve resumable data. The streaming path will hash and
                // reuse it after CopyLocal reports that it is unavailable.
                return Ok(CopyLocalOutcome::Unsupported);
            }
            d
        };
        let destination_metadata = d.metadata()?;
        let destination_dev = destination_metadata.dev();
        let destination_key = file_system_key(&d, destination_dev);
        let source_fs = file_system_traits(&s, source_key);
        let destination_fs = file_system_traits(&d, destination_key);
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
        let mut userspace_fallback = copy_pair_unsupported && use_userspace_fallback;
        if copy_pair_unsupported && !use_userspace_fallback {
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
                    crate::sparse::write_at(&d, &buffer[..n], size - remaining, false)
                } else {
                    destination.write_all(&buffer[..n])
                }
                .with_context(|| format!("write {}", target_label.display()))?;
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
        _copy.bytes(size);
        Ok(CopyLocalOutcome::Copied)
    }

    #[cfg(target_os = "macos")]
    pub(super) fn copy_local(
        &mut self,
        source: &RegisteredPath,
        dst: &[u8],
        policy: CopyLocalPolicy,
        copy_id: &CopyId,
        size: u64,
        _mode: u32,
    ) -> Result<CopyLocalOutcome> {
        let _copy = self
            .operation
            .span(crate::transfer_observations::Stage::FilesystemCopy);
        #[cfg(debug_assertions)]
        record_test_event("SYQ_TEST_COPY_LOCAL_REQUESTS", format_args!("copy-local"))?;
        // This operation stages a new inode; callers must stream in-place
        // writes even if a future coordinator bypasses copy selection.
        if policy.inplace {
            return Ok(CopyLocalOutcome::Unsupported);
        }
        let (source, source_metadata, target) = self.prepare_local_copy(source, dst)?;
        let root = target.root.clone();
        let (partial, _) = rooted_partial_target(&target, copy_id)?;
        self.uncache_rooted(&root, &target.relative);
        self.uncache_rooted(&root, &partial);
        let outcome = root.clone_file(&source, &source_metadata, &partial, size)?;
        if outcome == CopyLocalOutcome::Copied {
            _copy.bytes(size);
        }
        // Like Linux offload, leave no writer-cache entry. CopyLocal has no
        // attempt field; finalize opens and checks the named partial normally.
        Ok(outcome)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn copy_local(
        &mut self,
        _source: &RegisteredPath,
        _dst: &[u8],
        _policy: CopyLocalPolicy,
        _copy_id: &CopyId,
        _size: u64,
        _mode: u32,
    ) -> Result<CopyLocalOutcome> {
        Ok(CopyLocalOutcome::Unsupported)
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
        let staged_mode = staged_file_mode(meta, flags);
        let rooted = self.destination_mutation_target(target.path, target.guard)?;
        self.uncache_rooted(&rooted.root, &rooted.relative);
        if inplace {
            if target.guard.is_some() {
                bail!("guarded small-file updates require atomic publication");
            }
            let file = match condition {
                TargetCondition::Absent => rooted
                    .root
                    .create_file(&rooted.relative, meta.mode)
                    .with_context(|| format!("create {}", rooted.label.display()))?,
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
                    let file = rooted.root.open_regular_write(&rooted.relative, false)?;
                    require_open_target(&file, &rooted.label, condition)?;
                    file.set_len(0)?;
                    file
                }
                TargetCondition::Any => {
                    let mut opened = None;
                    for _ in 0..8 {
                        match rooted.root.metadata_optional(&rooted.relative)? {
                            Some(metadata) if metadata.is_file() => {
                                let file =
                                    rooted.root.open_regular_write(&rooted.relative, false)?;
                                require_rooted_metadata(&file, metadata, &rooted.label)?;
                                file.set_len(0)?;
                                opened = Some(file);
                                break;
                            }
                            Some(metadata) if metadata.is_dir() => {
                                bail!("destination {} is a directory", rooted.label.display())
                            }
                            Some(_) => rooted.root.unlink(&rooted.relative)?,
                            None => match rooted.root.create_file(&rooted.relative, meta.mode) {
                                Ok(file) => {
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
            observed_write(&self.operation, &file, data, 0, self.sparse)
                .with_context(|| format!("write {}", rooted.label.display()))?;
            set_meta_file(&file, meta, flags)
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
            return published_identity(&file, flags);
        }
        if target.guard.is_none()
            && matches!(
                condition,
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
            )
        {
            // Ordinary existing-file updates preserve the selected inode.
            // Validate before truncation, then prove the rooted name still
            // identifies that descriptor after the update.
            let file = rooted.root.open_regular_write(&rooted.relative, false)?;
            require_open_target(&file, &rooted.label, condition)?;
            file.set_len(0)?;
            observed_write(&self.operation, &file, data, 0, self.sparse)
                .with_context(|| format!("write existing {}", rooted.label.display()))?;
            file.set_len(data.len() as u64)?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", rooted.label.display()))?;
            require_rooted_named_identity(
                &rooted.root,
                &rooted.relative,
                &rooted.label,
                &file,
                condition,
            )?;
            return published_identity(&file, flags);
        }

        // New/replace small files, and the existing guarded-receiver
        // policy, stage through the same private rooted sidecar as ranged
        // writes do.
        let (relative, label, opened) =
            with_rooted_partial(&rooted, target.id, |relative, label| {
                self.open_private_partial_rooted(&rooted.root, relative, label, true, staged_mode)
            })?;
        let (file, basis_size) = opened.context("sidecar creation was requested")?;
        if basis_size.is_some() {
            file.set_len(0)?;
        }
        observed_write(&self.operation, &file, data, 0, self.sparse)
            .with_context(|| format!("write {}", label.display()))?;
        set_meta_file_for_publication(&file, meta, flags)
            .with_context(|| format!("set metadata {}", label.display()))?;
        // `publish_partial_rooted` re-checks the staged name against the
        // open descriptor immediately before the rename, so no separate
        // check is needed here.
        #[cfg(debug_assertions)]
        fail_put_small_before_rename_for_test(&rooted.label)?;
        publish_partial_rooted(&rooted.root, &relative, &rooted.relative, &file, condition)?;
        crate::inode_metadata::finish_publication(
            &file,
            meta.inode_metadata.as_deref(),
            meta.mode,
        )?;
        published_identity(&file, flags)
    }

    pub(super) fn hash_blocks(
        &mut self,
        target: HashTarget<'_>,
        options: HashOptions,
        copy_id: &CopyId,
    ) -> Result<Vec<ContentDigest>> {
        let HashOptions {
            which,
            block,
            len,
            attempt,
        } = options;
        if target.source.is_some()
            || (self.destination_root.is_none() && !self.source_roots.is_empty())
        {
            if target.guard.is_some() {
                bail!("source block hash cannot carry a destination guard");
            }
            if which != Which::Final {
                bail!("source block hash is only valid for the final source file");
            }
            if let Some((_, source_target)) = self.source_content_target(target.source)? {
                let mut file =
                    open_registered_source(&source_target, self.inode_preservation.open_noatime)?;
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
            file.seek(SeekFrom::Start(0))?;
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
        f.seek(SeekFrom::Start(0))?;
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
        let operation = self.operation.clone();
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_READ_RANGE").is_some()
            || std::env::var_os("SYQ_TEST_FAIL_READ_RANGE_NAME")
                .is_some_and(|name| resolve(path).file_name() == Some(name.as_os_str()))
        {
            bail!("test read-range failure");
        }
        if u64::from(len) > MAX_READ_BYTES {
            bail!("read length {len} exceeds the {MAX_READ_BYTES}-byte protocol limit");
        }
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
            let mut data = vec![0u8; len as usize];
            #[cfg(target_os = "linux")]
            let read = preparation.read_exact_at(f, &mut data, off);
            #[cfg(not(target_os = "linux"))]
            let read = {
                let reading = operation.span(crate::transfer_observations::Stage::SourceRead);
                let result = f.read_exact_at(&mut data, off);
                if result.is_ok() {
                    reading.bytes(u64::from(len));
                }
                result
            };
            read.with_context(|| format!("read {} @{off}+{len}", p.display()))?;
            let hash = {
                if self.hash_policy.transfer_integrity {
                    let _hash = operation.span(crate::transfer_observations::Stage::Hashing);
                    self.hash_policy.payload_algorithm().hash(&data)
                } else {
                    [0; 32]
                }
            };
            Ok(Response::Block { off, hash, data })
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
        let rooted = self.destination_mutation_target(target.path, target.guard)?;
        let sparse = self.sparse;
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
        expected: &crate::hashing::Digest,
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
        expected: &crate::hashing::Digest,
    ) -> Result<()> {
        let mut reader = file;
        reader.seek(SeekFrom::Start(0))?;
        let mut hasher = expected.algorithm.hasher();
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        expected
            .verify(&hasher.finalize())
            .context("expected file digest mismatch")
    }

    pub(super) fn validate_expected_path(
        &self,
        path: &[u8],
        expected: &crate::hashing::Digest,
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
        expected: Option<&crate::hashing::Digest>,
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
        expected: Option<&crate::hashing::Digest>,
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
        expected: Option<&crate::hashing::Digest>,
    ) -> Result<Option<(u64, u64)>> {
        let TargetMutation { condition, guard } = mutation;
        let guarded = guard.is_some();
        if inplace {
            let file = self
                .uncache_rooted(&target.root, &target.relative)
                .map(Ok)
                .unwrap_or_else(|| target.root.open_regular_write(&target.relative, false))?;
            require_open_target(&file, &target.label, condition)?;
            if let Some(expected) = expected {
                let reader = target.root.open_regular_read(&target.relative)?;
                Self::verify_expected_inode(&file, &reader, expected)?;
            }
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", target.label.display()))?;
            if guarded || condition != TargetCondition::Any {
                require_rooted_named_identity(
                    &target.root,
                    &target.relative,
                    &target.label,
                    &file,
                    condition,
                )?;
            }
            return published_identity(&file, flags);
        }
        let (src_relative, src, file) = with_rooted_partial(target, copy_id, |relative, _| {
            self.uncache_rooted(&target.root, relative)
                .map(Ok)
                .unwrap_or_else(|| target.root.open_regular_write(relative, false))
        })?;
        require_safe_rooted_named_partial(&target.root, &src_relative, &src, &file)?;
        if let Some(expected) = expected {
            let reader = target.root.open_regular_read(&src_relative)?;
            Self::verify_expected_inode(&file, &reader, expected)?;
        }

        if !guarded
            && matches!(
                condition,
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
            )
        {
            // Ordinary identity-conditioned staged updates preserve the
            // existing destination inode.
            // Keep the cached writer pinned while independently opening the
            // exact same named sidecar for reading.
            let staged_metadata = file.metadata()?;
            let mut staged = target.root.open_regular_read(&src_relative)?;
            require_safe_rooted_named_partial(&target.root, &src_relative, &src, &staged)?;
            let reopened_metadata = staged.metadata()?;
            if staged_metadata.dev() != reopened_metadata.dev()
                || staged_metadata.ino() != reopened_metadata.ino()
            {
                bail!("partial {} changed before publication", src.display());
            }

            self.uncache_rooted(&target.root, &target.relative);
            let mut destination = target.root.open_regular_write(&target.relative, false)?;
            require_open_target(&destination, &target.label, condition)?;
            let size = reopened_metadata.len();
            destination.set_len(0)?;
            staged.seek(SeekFrom::Start(0))?;
            destination.seek(SeekFrom::Start(0))?;
            let copy = if self.sparse {
                let mut buffer = vec![0; 1 << 20];
                let mut offset = 0;
                (|| -> io::Result<u64> {
                    while offset < size {
                        let want = (size - offset).min(buffer.len() as u64) as usize;
                        staged.read_exact(&mut buffer[..want])?;
                        crate::sparse::write_at(&destination, &buffer[..want], offset, false)?;
                        offset += want as u64;
                    }
                    Ok(offset)
                })()
            } else {
                io::copy(&mut staged, &mut destination)
            };
            copy.with_context(|| format!("update existing {}", target.label.display()))?;
            self.set_copy_length(&destination, size)?;
            set_meta_file(&destination, meta, flags)
                .with_context(|| format!("set metadata {}", target.label.display()))?;
            require_rooted_named_identity(
                &target.root,
                &target.relative,
                &target.label,
                &destination,
                condition,
            )?;
            discard_safe_rooted_partial_if_same(
                &target.root,
                &src_relative,
                staged_metadata.dev(),
                staged_metadata.ino(),
                &src,
            )?;
            return published_identity(&destination, flags);
        }

        set_meta_file_for_publication(&file, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        require_safe_rooted_named_partial(&target.root, &src_relative, &src, &file)?;
        if target
            .root
            .metadata_optional(&target.relative)?
            .is_some_and(RootMetadata::is_dir)
        {
            bail!("destination {} is a directory", target.label.display());
        }
        publish_partial_rooted(
            &target.root,
            &src_relative,
            &target.relative,
            &file,
            condition,
        )?;
        crate::inode_metadata::finish_publication(
            &file,
            meta.inode_metadata.as_deref(),
            meta.mode,
        )?;
        published_identity(&file, flags)
    }

    pub fn file_hash(
        &mut self,
        path: &[u8],
        source: Option<&RegisteredPath>,
        guard: Option<&ContainerGuard>,
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
        crate::inode_metadata::prepare_read(&f, self.inode_preservation.open_noatime);
        let mut h = self.hash_policy.algorithm.hasher();
        let mut buf = vec![0u8; 1 << 20];
        let mut size = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            size += n as u64;
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
        if let Err(error) = self
            .validate_source_session_request(req)
            .and_then(|()| self.validate_destination_session_request(req))
        {
            return Response::Err(errstr(&error));
        }
        if let Err(error) = self.map_request(req) {
            return Response::EndpointError(wire_error(&error));
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
            Request::CopySmallFiles(request) => self.copy_small_files(request),
            Request::DestinationFilesystemInfo {
                check_empty,
                target,
            } => self
                .destination_filesystem_info(*check_empty, target.as_ref())
                .map(Response::DestinationFilesystemInfo),
            Request::PruneLookup { paths, guard } => self
                .prune_lookup(paths, guard.as_ref())
                .map(Response::Stats),
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
            } => {
                let guard = guard.as_ref();
                let partial_paths = self.partial_paths(partial_paths, copy_id, guard);
                let directories = self.stat_many(directories, false, guard);
                let safe_to_stat_others = directories.iter().all(|entry| {
                    entry
                        .as_ref()
                        .is_some_and(|entry| entry.kind == Kind::Dir && entry.mode & 0o700 == 0o700)
                });
                let others = safe_to_stat_others.then(|| self.stat_many(others, false, guard));
                Ok(Response::BatchPlan {
                    partial_paths,
                    directories,
                    others,
                })
            }
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
                path,
                copy_id,
                block,
                len,
                condition,
                guard,
            } => self
                .hash_and_hold(path, copy_id, *block, *len, *condition, guard.as_ref())
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
                        allow_sequential_nfs_fallback: *allow_sequential_nfs_fallback,
                        allow_sequential_local_fallback: *allow_sequential_local_fallback,
                    },
                    copy_id,
                    *size,
                    *mode,
                )
                .map(|outcome| match outcome {
                    CopyLocalOutcome::Copied => Response::Ok,
                    CopyLocalOutcome::Unsupported => Response::CopyLocalUnsupported,
                }),
            Request::PutSmallBatch(puts) => {
                if puts.iter().any(|p| p.flags & flags::REPORT_IDENTITY != 0) {
                    Ok(Response::PublishedBatch(
                        puts.iter()
                            .map(|put| self.put_small(put).map_err(|e| wire_error(&e)))
                            .collect(),
                    ))
                } else {
                    Ok(Response::Applied(
                        puts.iter()
                            .map(|put| self.put_small(put).err().as_ref().map(wire_error))
                            .collect(),
                    ))
                }
            }
            Request::HashBlocks {
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
            Request::ReadSmallBatch(reads) => {
                // Every block is collected before the batch is answered, so
                // bound the whole batch, not just each read.
                let total: u64 = reads.iter().map(|read| u64::from(read.len)).sum();
                if total > MAX_READ_BYTES {
                    Err(anyhow!(
                        "small-file batch requests {total} bytes, exceeding the {MAX_READ_BYTES}-byte protocol limit"
                    ))
                } else {
                    Ok(Response::SmallBlocks(
                        reads
                            .iter()
                            .map(|read| {
                                match self.read_range(
                                    &read.path,
                                    read.source.as_ref(),
                                    read.attempt,
                                    0,
                                    read.len,
                                ) {
                                    Ok(Response::Block { data, hash, .. }) => {
                                        Ok(SmallBlock { data, hash })
                                    }
                                    Ok(other) => Err(format!("unexpected response {other:?}")),
                                    Err(error) => Err(errstr(&error)),
                                }
                            })
                            .collect(),
                    ))
                }
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
            | Request::NativeRemove { .. }
            | Request::TransportStats
            | Request::Receipt
            | Request::Shutdown
            | Request::TcpListen { .. }
            | Request::ReadStream(_)
            | Request::WriteStreamFence
            | Request::ShrinkReadStream { .. }
            | Request::MappingChunk { .. }
            | Request::StopReadStream => Err(anyhow!("unexpected request")),
        };
        match r {
            Ok(resp) => self.rebase_response(resp),
            Err(e) => Response::EndpointError(wire_error(&e)),
        }
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
    }
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
/// The sidecar stays private when no mode is requested, and when group
/// preservation is requested: the kernel assigns the receiver's or a setgid
/// parent's group at creation, and final group bits would let that group read
/// or write the content until the chown. Without group preservation the group
/// at creation is the final group, and the owner bits only widen access for
/// the receiver, which already holds the content.
pub(super) fn staged_file_mode(meta: &Meta, flags: u8) -> u32 {
    if flags & flags::MODE_MASK != 0 && flags & flags::GROUP == 0 {
        meta.mode & 0o777
    } else {
        PRIVATE_PARTIAL_MODE
    }
}

pub(super) fn is_safe_partial(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && metadata.nlink() == 1
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
        }
        Some(_) | None => {}
    }
    Ok(())
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

#[cfg(all(target_os = "linux", debug_assertions))]
pub(super) fn test_fallocate_errno() -> Option<i32> {
    let value = std::env::var_os("SYQ_TEST_FALLOCATE_ERRNO")?;
    match value.to_string_lossy().as_ref() {
        "unsupported" => Some(libc::EOPNOTSUPP),
        "no_space" => Some(libc::ENOSPC),
        "quota" => Some(libc::EDQUOT),
        value => value.parse().ok(),
    }
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
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
    set_meta_file_inner(f, meta, flags, current, false)
}

fn set_meta_file_for_publication(f: &File, meta: &Meta, flags: u8) -> Result<()> {
    set_meta_file_inner(f, meta, flags, &f.metadata()?, true)
}

fn set_meta_file_inner(
    f: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
    before_publication: bool,
) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // Owner first: chown clears setuid/setgid, so mode must be set afterwards.
    let owner_changed =
        apply_owner_if_changed(flags, meta, current.uid(), current.gid(), |uid, gid| {
            std::os::unix::fs::fchown(f, uid, gid)
        })?;
    // macOS mode and ACL must change together. Keep the private staging
    // permissions until publication instead of opening a mode-only window.
    let atomic_acl_mode = cfg!(target_os = "macos")
        && meta
            .inode_metadata
            .as_ref()
            .is_some_and(|m| m.macos_acl.is_some());
    if flags & flags::MODE_MASK != 0 && !atomic_acl_mode {
        // On network filesystems every setattr is a round trip; skip it when
        // the mode is already right (but always run it after a chown that could
        // have cleared setuid/setgid bits we need to restore).
        let cur = current.mode() & 0o7777;
        let want = meta.mode & 0o7777;
        if cur != want || (owner_changed && want & 0o6000 != 0) {
            f.set_permissions(fs::Permissions::from_mode(want))?;
        }
    }
    if flags & flags::TIMES != 0
        && (current.mtime() != meta.mtime || current.mtime_nsec() as u32 != meta.mtime_nsec)
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
    if before_publication {
        crate::inode_metadata::apply_before_publication(
            f,
            meta.inode_metadata.as_deref(),
            meta.mode,
        )
    } else {
        crate::inode_metadata::apply(f, meta.inode_metadata.as_deref(), meta.mode)
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
fn published_identity(file: &File, flags: u8) -> Result<Option<(u64, u64)>> {
    if flags & flags::REPORT_IDENTITY == 0 {
        return Ok(None);
    }
    let metadata = file.metadata()?;
    Ok(Some((metadata.dev(), metadata.ino())))
}

fn publication_response(identity: Option<(u64, u64)>) -> Response {
    match identity {
        Some((dev, ino)) => Response::Published { dev, ino },
        None => Response::Ok,
    }
}
