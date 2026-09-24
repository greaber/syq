use super::*;

pub(super) fn op_path(op: &Op) -> &[u8] {
    match op {
        Op::Mkdir { path, .. }
        | Op::Symlink { path, .. }
        | Op::Mknod { path, .. }
        | Op::Hardlink { path, .. }
        | Op::SetMeta { path, .. }
        | Op::SetFileMetaIfSame { path, .. }
        | Op::Remove { path }
        | Op::Rmdir { path }
        | Op::Unlink { path } => path,
    }
}

pub(super) fn apply_one(
    op: &Op,
    guard: Option<&ContainerGuard>,
    destination_root: Option<Arc<Root>>,
    destination_prefix: Option<&[u8]>,
) -> Result<()> {
    let registered_target = if let Some(root) = destination_root {
        let path = op_path(op);
        let relative = RelativePath::new(path)?;
        let label = PathBuf::from(OsStr::from_bytes(
            &destination_prefix.map_or_else(|| path.to_vec(), |prefix| join(prefix, path)),
        ));
        Some(RootedTarget {
            root,
            relative,
            label,
            create_missing_parents: true,
            query_partial_name_limit: false,
        })
    } else {
        None
    };
    #[cfg(debug_assertions)]
    fail_apply_capacity_for_test(
        registered_target
            .as_ref()
            .map_or_else(|| resolve(op_path(op)), |target| target.label.clone())
            .as_path(),
    )?;
    #[cfg(debug_assertions)]
    if matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. }) {
        fail_set_meta_for_test(
            registered_target
                .as_ref()
                .map_or_else(|| resolve(op_path(op)), |target| target.label.clone())
                .as_path(),
        )?;
    }
    if matches!(op, Op::SetFileMetaIfSame { .. }) {
        hold_before_quick_metadata_for_test()?;
    }
    if let Some(guard) = guard {
        let target = guarded_target(op_path(op), guard)?;
        if let Op::Hardlink {
            path,
            source,
            dev,
            ino,
        } = op
        {
            let source = guarded_target(source, guard)?;
            let operation = Op::Hardlink {
                path: path.clone(),
                source: source.relative.to_path_buf().into_os_string().into_vec(),
                dev: *dev,
                ino: *ino,
            };
            return apply_one_rooted(&operation, &target.as_rooted());
        }
        return apply_one_rooted(op, &target.as_rooted());
    }
    let Some(target) = registered_target else {
        bail!("{UNROOTED_MUTATION}");
    };
    apply_one_rooted(op, &target)
}

pub(super) fn error_is_kind(error: &anyhow::Error, kind: io::ErrorKind) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .is_some_and(|error| error.kind() == kind)
}

pub(super) struct GuardedTarget {
    pub(super) root: Arc<Root>,
    pub(super) relative: RelativePath,
    pub(super) label: PathBuf,
}

pub(super) struct RootedTarget {
    pub(super) root: Arc<Root>,
    pub(super) relative: RelativePath,
    pub(super) label: PathBuf,
    pub(super) create_missing_parents: bool,
    // Signed receivers independently derive the partial name for quota checks.
    // Keep their exact limit selection in sync with that authority.
    pub(super) query_partial_name_limit: bool,
}

// One filename-limit observation for adjacent siblings in a read-only batch
// chunk. This avoids repeating parent resolution (including missing-parent
// probes). The cache opens no descriptors and ends with the chunk. Later
// requests query again; file operations keep their own confined resolution.
#[derive(Default)]
pub(super) struct PartialNameLimits {
    pub(super) last: Option<(Arc<Root>, PathBuf, usize)>,
}

impl PartialNameLimits {
    pub(super) fn get_or_query(
        &mut self,
        root: &Arc<Root>,
        parent: &Path,
        query: impl FnOnce() -> Result<usize>,
    ) -> Result<usize> {
        if let Some((previous_root, previous_parent, limit)) = &self.last {
            if Arc::ptr_eq(previous_root, root) && previous_parent == parent {
                return Ok(*limit);
            }
        }
        self.last = None;
        let limit = query()?;
        // Keep the actual root alive: device/inode can coincide across
        // distinct mount views, and a raw pointer could otherwise be reused.
        self.last = Some((root.clone(), parent.to_path_buf(), limit));
        Ok(limit)
    }
}

impl RootedTarget {
    pub(super) fn partial_name_max(&self) -> Result<usize> {
        if self.query_partial_name_limit {
            self.root.name_max_for_parent(&self.relative)
        } else {
            self.root.partial_name_max(&self.relative)
        }
    }

    pub(super) fn location(&self) -> FileLocation {
        FileLocation::Rooted {
            root: self.root.identity(),
            relative: self.relative.clone(),
        }
    }
}

impl GuardedTarget {
    pub(super) fn as_rooted(&self) -> RootedTarget {
        RootedTarget {
            root: self.root.clone(),
            relative: self.relative.clone(),
            label: self.label.clone(),
            create_missing_parents: false,
            query_partial_name_limit: true,
        }
    }
}

pub(super) fn rooted_partial_target(
    target: &RootedTarget,
    copy_id: &CopyId,
) -> Result<(RelativePath, PathBuf)> {
    rooted_partial_target_with_limit(target, copy_id, target.partial_name_max()?)
}

fn rooted_partial_target_with_limit(
    target: &RootedTarget,
    copy_id: &CopyId,
    component_limit: usize,
) -> Result<(RelativePath, PathBuf)> {
    let relative_path = target.relative.to_path_buf();
    // Derive the visible component from the logical command-line spelling so
    // PartialPaths and every state-machine request keep one stable sidecar
    // name, including the PATH_MAX compact form. Only the resulting component
    // is placed beneath the retained root.
    let label = partial_path_with_name_max(&target.label, copy_id, component_limit)?;
    let name = label
        .file_name()
        .context("partial path has no final component")?;
    let relative_partial = relative_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(name);
    Ok((
        RelativePath::new(relative_partial.as_os_str().as_bytes())?,
        label,
    ))
}

/// Retry only the initial access to a partial. Later writes and publication
/// must use the returned name; never replay a completed mutation or a batch.
pub(super) fn with_rooted_partial<T>(
    target: &RootedTarget,
    copy_id: &CopyId,
    mut access: impl FnMut(&RelativePath, &Path) -> Result<T>,
) -> Result<(RelativePath, PathBuf, T)> {
    let (relative, label) = rooted_partial_target(target, copy_id)?;
    match access(&relative, &label) {
        Ok(value) => Ok((relative, label, value)),
        Err(error) => {
            let too_long = error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.raw_os_error() == Some(libc::ENAMETOOLONG));
            if !too_long || target.query_partial_name_limit {
                return Err(error);
            }
            let limit = target.root.rejected_partial_name_max(&target.relative)?;
            let (short, label) = rooted_partial_target_with_limit(target, copy_id, limit)?;
            if short == relative {
                return Err(error);
            }
            let value = access(&short, &label)?;
            Ok((short, label, value))
        }
    }
}

pub(super) fn guarded_target(path: &[u8], guard: &ContainerGuard) -> Result<GuardedTarget> {
    hold_before_guarded_mutation_for_test(path)?;
    let root_path = resolve(&guard.root);
    let target = resolve(path);
    let relative = relative_under(&root_path, &target)?;
    let root = Arc::new(Root::open_verified(
        &root_path,
        RootIdentity {
            dev: guard.dev,
            ino: guard.ino,
        },
    )?);
    Ok(GuardedTarget {
        root,
        relative,
        label: target,
    })
}

pub(super) fn relative_under(root: &Path, target: &Path) -> Result<RelativePath> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "destination {} is outside guarded root {}",
            target.display(),
            root.display()
        )
    })?;
    RelativePath::new(relative.as_os_str().as_bytes())
}

/// Observe the object at a guarded path and hold it to the planner's
/// condition. `Absent` requires nothing there (the following `*at` creation
/// then fails atomically if something appears); the matching conditions
/// require the observed identity. `Any` accepts whatever is found.
pub(super) fn observe_rooted_condition(
    target: &RootedTarget,
    condition: TargetCondition,
) -> Result<Option<crate::rooted::RootMetadata>> {
    let observed = target.root.metadata_optional(&target.relative)?;
    let label = &target.label;
    match (condition, observed) {
        (TargetCondition::Any, observed) => Ok(observed),
        (TargetCondition::Absent, None) => Ok(None),
        (TargetCondition::Absent, Some(_)) => {
            bail!(
                "destination {} appeared before no-replace creation",
                label.display()
            )
        }
        (TargetCondition::Matches { dev, ino }, Some(metadata))
            if metadata.dev == dev && metadata.ino == ino =>
        {
            Ok(Some(metadata))
        }
        (
            TargetCondition::MatchesFingerprint {
                dev,
                ino,
                ctime,
                ctime_nsec,
            },
            Some(metadata),
        ) if metadata.dev == dev
            && metadata.ino == ino
            && metadata.ctime == ctime
            && metadata.ctime_nsec == ctime_nsec =>
        {
            Ok(Some(metadata))
        }
        (TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }, _) => {
            bail!(
                "destination {} changed before it could be replaced",
                label.display()
            )
        }
    }
}

pub(super) fn apply_one_rooted(op: &Op, target: &RootedTarget) -> Result<()> {
    let root = &target.root;
    let path = &target.relative;
    match op {
        Op::Mkdir {
            mode, condition, ..
        } => {
            if path.is_empty() {
                if *condition == TargetCondition::Absent {
                    bail!("destination root {} already exists", target.label.display());
                }
                let metadata = root.metadata(path)?;
                require_rooted_condition(metadata, *condition, &target.label)?;
                if metadata.mode & 0o700 != 0o700 {
                    let directory = root.open_metadata(path)?;
                    require_rooted_metadata(&directory, metadata, &target.label)?;
                    set_mode_handle(&directory, metadata.mode | 0o700)?;
                }
                return Ok(());
            }
            let parent = if target.create_missing_parents {
                root.resolve_parent_creating(path, 0o777)?
            } else {
                root.resolve_parent(path)?
            };
            if matches!(condition, TargetCondition::Any | TargetCondition::Absent) {
                match parent
                    .create_directory((*mode & 0o7777) | 0o700)
                    .with_context(|| {
                        format!("create confined directory {}", target.label.display())
                    }) {
                    Ok(()) => return Ok(()),
                    Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                        if *condition == TargetCondition::Absent {
                            bail!(
                                "destination {} appeared before no-replace creation",
                                target.label.display()
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            drop(parent);
            match observe_rooted_condition(target, *condition)? {
                Some(metadata) if metadata.is_dir() => {
                    if metadata.mode & 0o700 != 0o700 {
                        let directory = root.open_metadata(path)?;
                        require_rooted_metadata(&directory, metadata, &target.label)?;
                        set_mode_handle(&directory, metadata.mode | 0o700)?;
                    }
                    Ok(())
                }
                Some(_) => bail!(
                    "cannot replace non-directory {} with a directory",
                    target.label.display()
                ),
                None => create_rooted_directory_or_existing(target, *mode),
            }
        }
        Op::Symlink {
            target: link,
            condition,
            ..
        } => {
            if matches!(condition, TargetCondition::Any | TargetCondition::Absent) {
                match root.create_symlink(path, link) {
                    Ok(()) => return Ok(()),
                    Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                        if *condition == TargetCondition::Absent {
                            bail!(
                                "destination {} appeared before no-replace creation",
                                target.label.display()
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            match observe_rooted_condition(target, *condition)? {
                // A matched replacement swaps the new leaf in atomically, so a
                // concurrent replacement of the observed object is refused
                // rather than deleted.
                Some(metadata) if *condition != TargetCondition::Any => {
                    if !metadata.is_symlink() {
                        bail!(
                            "destination {} cannot change type under a matched condition",
                            target.label.display()
                        );
                    }
                    root.replace_symlink_if_same(path, link, metadata.dev, metadata.ino)
                }
                Some(_) => root.replace_symlink(path, link),
                None => root.create_symlink(path, link),
            }
        }
        Op::Mknod {
            mode,
            rdev,
            condition,
            ..
        } => {
            if matches!(condition, TargetCondition::Any | TargetCondition::Absent) {
                match root.create_node(path, *mode, *rdev) {
                    Ok(()) => return Ok(()),
                    Err(error) if error_is_kind(&error, io::ErrorKind::AlreadyExists) => {
                        if *condition == TargetCondition::Absent {
                            bail!(
                                "destination {} appeared before no-replace creation",
                                target.label.display()
                            );
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            match observe_rooted_condition(target, *condition)? {
                Some(metadata) if *condition != TargetCondition::Any => {
                    if file_type_bits(metadata.mode) != file_type_bits(*mode) {
                        bail!(
                            "destination {} cannot change type under a matched condition",
                            target.label.display()
                        );
                    }
                    root.replace_node_if_same(path, *mode, *rdev, metadata.dev, metadata.ino)
                }
                Some(_) => root.replace_node(path, *mode, *rdev),
                None => root.create_node(path, *mode, *rdev),
            }
        }
        Op::Hardlink {
            source, dev, ino, ..
        } => root.publish_hardlink(&RelativePath::new(source)?, path, (*dev, *ino)),
        Op::SetMeta {
            meta,
            flags,
            condition,
            ..
        } => set_meta_rooted(target, meta, *flags, *condition),
        Op::SetFileMetaIfSame {
            condition,
            meta,
            flags,
            ..
        } => {
            let file = root.open_metadata(path)?;
            let opened = file.metadata()?;
            if !opened.file_type().is_file() {
                bail!(
                    "destination {} changed before metadata repair",
                    target.label.display()
                );
            }
            require_open_target_known(&opened, &target.label, *condition)?;
            set_meta_handle_known_portable(&file, meta, *flags, &opened)?;
            require_rooted_named_identity_known(
                &target.root,
                &target.relative,
                &target.label,
                &opened,
                *condition,
            )
        }
        Op::Rmdir { .. } => match root.metadata_optional(path)? {
            None => Ok(()),
            Some(_) => root.remove_directory(path),
        },
        Op::Unlink { .. } => match root.metadata_optional(path)? {
            None => Ok(()),
            Some(metadata) if metadata.is_dir() => {
                bail!(
                    "{}: is now a directory; not deleting it",
                    target.label.display()
                )
            }
            Some(_) => root.unlink(path),
        },
        Op::Remove { .. } => bail!("recursive remove cannot use a confined destination root"),
    }
}

pub(super) fn set_meta_rooted(
    target: &RootedTarget,
    meta: &Meta,
    flags: u8,
    condition: TargetCondition,
) -> Result<()> {
    if target.relative.is_empty() {
        let metadata = target.root.metadata(&target.relative)?;
        require_rooted_condition(metadata, condition, &target.label)?;
        let handle = target.root.open_metadata(&target.relative)?;
        require_rooted_metadata(&handle, metadata, &target.label)?;
        let opened = handle.metadata()?;
        require_open_target_known(&opened, &target.label, condition)?;
        if flags & flags::TIMES != 0
            && (metadata.mtime != meta.mtime || metadata.mtime_nsec != meta.mtime_nsec)
        {
            let times = [
                timespec(0, libc::UTIME_OMIT as u32),
                timespec(meta.mtime, meta.mtime_nsec),
            ];
            target.root.set_times(&target.relative, &times)?;
        }
        // Birth time follows mtime: macOS may lower birth time when setting
        // an older modification time.
        set_meta_handle_known_portable(&handle, meta, flags & !flags::TIMES, &opened)?;
        return require_rooted_named_identity_known(
            &target.root,
            &target.relative,
            &target.label,
            &opened,
            condition,
        );
    }
    let parent = target.root.resolve_parent(&target.relative)?;
    let metadata = parent
        .metadata()
        .with_context(|| format!("stat confined path {}", target.label.display()))?;
    require_rooted_condition(metadata, condition, &target.label)?;
    let is_link = metadata.is_symlink();
    let owner_differs = (flags & flags::OWNER != 0
        && (is_superuser() || flags & flags::REQUIRE_OWNER != 0)
        && metadata.uid != meta.uid)
        || (flags & flags::GROUP != 0 && metadata.gid != meta.gid);
    let mode_differs =
        flags & flags::MODE_MASK != 0 && !is_link && metadata.mode & 0o7777 != meta.mode & 0o7777;
    let time_differs = flags & flags::TIMES != 0
        && (metadata.mtime != meta.mtime || metadata.mtime_nsec != meta.mtime_nsec);
    if !owner_differs && !mode_differs && !time_differs && meta.inode_metadata.is_none() {
        return Ok(());
    }
    if is_link {
        let handle = meta
            .inode_metadata
            .as_ref()
            .map(|_| {
                parent.open_metadata().with_context(|| {
                    format!("open confined metadata handle {}", target.label.display())
                })
            })
            .transpose()?;
        if let Some(handle) = &handle {
            require_rooted_metadata(handle, metadata, &target.label)?;
        }
        apply_owner_if_changed(flags, meta, metadata.uid, metadata.gid, |uid, gid| {
            parent.chown(uid, gid)
        })
        .with_context(|| format!("change owner of confined path {}", target.label.display()))?;
        if time_differs {
            let times = [
                timespec(0, libc::UTIME_OMIT as u32),
                timespec(meta.mtime, meta.mtime_nsec),
            ];
            parent.set_times(&times).with_context(|| {
                format!("set times on confined path {}", target.label.display())
            })?;
        }
        if let Some(handle) = &handle {
            crate::inode_metadata::apply(handle, meta.inode_metadata.as_deref(), meta.mode)?;
        }
    } else {
        let handle = parent
            .open_metadata()
            .with_context(|| format!("open confined metadata handle {}", target.label.display()))?;
        let opened = handle.metadata()?;
        if opened.dev() != metadata.dev || opened.ino() != metadata.ino {
            bail!(
                "confined destination {} changed while opening it",
                target.label.display()
            );
        }
        require_open_target_known(&opened, &target.label, condition)?;
        // Timestamp mutation is performed separately with no-follow
        // descriptor-relative semantics. All other metadata is applied to
        // the stable opened inode, so a raced leaf symlink cannot redirect it.
        if time_differs {
            let times = [
                timespec(0, libc::UTIME_OMIT as u32),
                timespec(meta.mtime, meta.mtime_nsec),
            ];
            parent.set_times(&times).with_context(|| {
                format!("set times on confined path {}", target.label.display())
            })?;
        }
        // Birth time follows mtime: macOS may lower birth time when setting
        // an older modification time.
        set_meta_handle_known_portable(&handle, meta, flags & !flags::TIMES, &opened)?;
        // The final lookup resolves from Root again. Release the reused
        // parent first so that check does not raise peak descriptor usage.
        drop(parent);
        return require_rooted_named_identity_known(
            &target.root,
            &target.relative,
            &target.label,
            &opened,
            condition,
        );
    }
    drop(parent);
    let after = target.root.metadata(&target.relative)?;
    require_rooted_identity(after, condition, &target.label)
}

/// `TargetCondition::Any` mkdir operations can race each other because apply
/// batches are parallel and deeper paths create implicit parents. Accept the
/// winner only when the conflicting name is a real directory beneath the
/// retained root; a symlink or any other type remains an error.
pub(super) fn create_rooted_directory_or_existing(target: &RootedTarget, mode: u32) -> Result<()> {
    match target
        .root
        .create_directory(&target.relative, (mode & 0o7777) | 0o700)
    {
        Ok(()) => Ok(()),
        Err(error)
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
            }) =>
        {
            let metadata = target.root.metadata(&target.relative)?;
            if !metadata.is_dir() {
                return Err(error);
            }
            if metadata.mode & 0o700 != 0o700 {
                let directory = target.root.open_metadata(&target.relative)?;
                require_rooted_metadata(&directory, metadata, &target.label)?;
                set_mode_handle(&directory, metadata.mode | 0o700)?;
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn require_rooted_identity(
    metadata: RootMetadata,
    condition: TargetCondition,
    label: &Path,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => {
            bail!(
                "destination {} appeared before metadata update",
                label.display()
            )
        }
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. }
            if (metadata.dev, metadata.ino) == (dev, ino) =>
        {
            Ok(())
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            bail!(
                "destination {} changed during metadata update",
                label.display()
            )
        }
    }
}

pub(super) fn require_rooted_condition(
    metadata: RootMetadata,
    condition: TargetCondition,
    label: &Path,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => {
            bail!(
                "destination {} appeared before metadata update",
                label.display()
            )
        }
        TargetCondition::Matches { dev, ino } if (metadata.dev, metadata.ino) == (dev, ino) => {
            Ok(())
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } if (
            metadata.dev,
            metadata.ino,
            metadata.ctime,
            metadata.ctime_nsec,
        ) == (dev, ino, ctime, ctime_nsec) =>
        {
            Ok(())
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            bail!(
                "destination {} changed before metadata update",
                label.display()
            )
        }
    }
}

pub(super) fn require_rooted_metadata(
    file: &File,
    expected: RootMetadata,
    label: &Path,
) -> Result<()> {
    let opened = file.metadata()?;
    if opened.dev() != expected.dev || opened.ino() != expected.ino {
        bail!(
            "confined destination {} changed while opening it",
            label.display()
        );
    }
    Ok(())
}

pub(super) fn require_rooted_named_identity(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    file: &File,
    condition: TargetCondition,
) -> Result<()> {
    let opened = file.metadata()?;
    require_rooted_named_identity_known(root, relative, label, &opened, condition)
}

pub(super) fn require_rooted_named_identity_known(
    root: &Root,
    relative: &RelativePath,
    label: &Path,
    opened: &fs::Metadata,
    condition: TargetCondition,
) -> Result<()> {
    let (dev, ino) = match condition {
        TargetCondition::Any => (opened.dev(), opened.ino()),
        TargetCondition::Absent => bail!("new destination unexpectedly received metadata repair"),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => (dev, ino),
    };
    let named = root.metadata(relative)?;
    if opened.dev() != dev || opened.ino() != ino || named.dev != dev || named.ino != ino {
        bail!("destination {} changed during update", label.display());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT
}

#[cfg(not(target_os = "linux"))]
pub(super) fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT as u32
}

#[cfg(debug_assertions)]
pub(super) fn hold_before_guarded_mutation_for_test(path: &[u8]) -> Result<()> {
    let Some(suffix) = std::env::var_os("SYQ_TEST_GUARDED_MUTATION_SUFFIX") else {
        return Ok(());
    };
    if !path.ends_with(suffix.as_bytes()) {
        return Ok(());
    }
    test_race_barrier(
        "SYQ_TEST_GUARDED_MUTATION_READY_FILE",
        "SYQ_TEST_GUARDED_MUTATION_CONTINUE_FILE",
        "guarded-mutation-ready",
    )
}

#[cfg(not(debug_assertions))]
pub(super) fn hold_before_guarded_mutation_for_test(_path: &[u8]) -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn hold_before_quick_metadata_for_test() -> Result<()> {
    test_race_barrier(
        "SYQ_TEST_QUICK_META_READY_FILE",
        "SYQ_TEST_QUICK_META_CONTINUE_FILE",
        "quick metadata repair",
    )
}

#[cfg(not(debug_assertions))]
pub(super) fn hold_before_quick_metadata_for_test() -> Result<()> {
    Ok(())
}

pub(super) fn require_open_target(
    file: &File,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "destination {} appeared after the new-path precondition was checked",
            path.display()
        ),
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            require_open_target_known(&file.metadata()?, path, condition)
        }
    }
}

pub(super) fn require_open_target_known(
    metadata: &fs::Metadata,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "destination {} appeared after the new-path precondition was checked",
            path.display()
        ),
        TargetCondition::Matches { dev, ino } => {
            if metadata.dev() != dev || metadata.ino() != ino {
                bail!(
                    "destination {} changed after the existing-path precondition was checked",
                    path.display()
                );
            }
            Ok(())
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => {
            if metadata.dev() != dev
                || metadata.ino() != ino
                || metadata.ctime() != ctime
                || metadata.ctime_nsec() as u32 != ctime_nsec
            {
                bail!(
                    "destination {} changed after the existing-path precondition was checked",
                    path.display()
                );
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn set_meta_handle_known(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    let fd = file.as_raw_fd();
    let empty = c"";
    // Owner first: chown clears setuid/setgid, so mode must follow it.
    let owner_changed =
        apply_owner_if_changed(flags, meta, current.uid(), current.gid(), |uid, gid| {
            let r = unsafe {
                libc::fchownat(
                    fd,
                    empty.as_ptr(),
                    uid.unwrap_or(u32::MAX),
                    gid.unwrap_or(u32::MAX),
                    libc::AT_EMPTY_PATH,
                )
            };
            if r == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        })?;
    if flags & flags::MODE_MASK != 0 {
        let current = current.mode() & 0o7777;
        let wanted = meta.mode & 0o7777;
        if current != wanted || (owner_changed && wanted & 0o6000 != 0) {
            set_mode_handle(file, wanted)?;
        }
    }
    if flags & flags::TIMES != 0 {
        bail!("metadata-only O_PATH repair does not support timestamp changes");
    }
    crate::inode_metadata::apply(file, meta.inode_metadata.as_deref(), meta.mode)
}

#[cfg(target_os = "linux")]
pub(super) fn set_meta_handle_known_portable(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    set_meta_handle_known(file, meta, flags, current)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn set_meta_handle_known_portable(
    file: &File,
    meta: &Meta,
    flags: u8,
    current: &fs::Metadata,
) -> Result<()> {
    set_meta_file_known(file, meta, flags, current)
}

#[cfg(target_os = "linux")]
pub(crate) fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    let fd = file.as_raw_fd();
    let r = unsafe { libc::fchmodat(fd, c"".as_ptr(), mode as libc::mode_t, libc::AT_EMPTY_PATH) };
    if r == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    ) {
        return Err(error.into());
    }
    // Older libc/kernel combinations do not expose fchmodat2's AT_EMPTY_PATH
    // support. procfs still resolves this stable O_PATH descriptor, never the
    // possibly replaced pathname.
    fs::set_permissions(
        PathBuf::from("/proc/self/fd").join(fd.to_string()),
        fs::Permissions::from_mode(mode),
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn fail_set_meta_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_SETMETA") {
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            return Err(anyhow!("set metadata {}: injected failure", p.display()));
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn fail_apply_capacity_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_APPLY_ENOSPC") {
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC))
                .with_context(|| format!("apply {}: injected capacity failure", p.display()));
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) fn fail_put_small_before_rename_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME") {
        // Model interruption after the sidecar is complete but before it
        // becomes the final name.
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            bail!("put small {}: injected failure before rename", p.display());
        }
    }
    Ok(())
}
