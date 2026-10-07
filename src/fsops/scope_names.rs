//! A confined receiver changes no file in place that has names outside the
//! directories it promises to stay within: a file's contents and metadata
//! belong to every name it has. The receiver counts the names it knows a
//! file has inside: those its own destination scans and lookups returned,
//! and the links this copy made, each directory entry once. A file with more
//! names than that may have some elsewhere, or inside where the receiver
//! never looked; either way it is not changed in place.

use super::*;

pub(crate) struct ScopeNames {
    /// The receiver's root, beneath which every name here lies.
    root: Vec<u8>,
    /// The approved directories, each with whether it covers descendants.
    scopes: Vec<(Vec<u8>, bool)>,
    names: Mutex<NamesByFile>,
    /// Held while a check reads a file's link count and counts its names,
    /// and while this receiver links a new name to a file, so that no link
    /// it makes can be counted against a link count read before it.
    counting: Mutex<()>,
}

/// The names known inside, relative to the root, by file identity.
type NamesByFile = HashMap<(u64, u64), Vec<Box<[u8]>>>;

/// A file's device, inode and link count.
pub(crate) type LinkedFile = (u64, u64, u64);

impl ScopeNames {
    pub(crate) fn new(root: Vec<u8>, scopes: impl IntoIterator<Item = (Vec<u8>, bool)>) -> Self {
        Self {
            root,
            scopes: scopes.into_iter().collect(),
            names: Mutex::default(),
            counting: Mutex::default(),
        }
    }

    /// The approved directory holding `path`, if any.
    fn scope_of(&self, path: &[u8]) -> Option<&[u8]> {
        self.scopes
            .iter()
            .filter(|(scope, descendants)| {
                path == scope.as_slice()
                    || (*descendants
                        && path.starts_with(scope)
                        && path.get(scope.len()) == Some(&b'/'))
            })
            .map(|(scope, _)| scope.as_slice())
            .max_by_key(|scope| scope.len())
    }

    /// `path` relative to the root, when it lies beneath it.
    fn relative<'a>(&self, path: &'a [u8]) -> Option<&'a [u8]> {
        let rest = path.strip_prefix(self.root.as_slice())?;
        let rest = if self.root.ends_with(b"/") {
            rest
        } else {
            rest.strip_prefix(b"/")?
        };
        (!rest.is_empty()).then_some(rest)
    }

    /// Remember `path` as a name of the file `(dev, ino)` when it lies in an
    /// approved directory.
    pub(crate) fn record(&self, path: &[u8], dev: u64, ino: u64) {
        self.record_all([(path, dev, ino)]);
    }

    /// Remember each `(path, dev, ino)` as `record` does, under one lock.
    fn record_all<'a>(&self, names: impl IntoIterator<Item = (&'a [u8], u64, u64)>) {
        let mut known = None;
        for (path, dev, ino) in names {
            let Some(relative) = self
                .relative(path)
                .filter(|_| self.scope_of(path).is_some())
            else {
                continue;
            };
            let known = known.get_or_insert_with(|| self.names.lock().unwrap());
            let file = known
                .entry((dev, ino))
                .or_insert_with(|| Vec::with_capacity(2));
            if !file.iter().any(|name| **name == *relative) {
                file.push(relative.into());
            }
        }
    }

    /// Remember the names a destination listing or lookup under `root`
    /// returned, for the files with more than one.
    pub(crate) fn record_entries<'a>(
        &self,
        root: &[u8],
        entries: impl IntoIterator<Item = &'a Entry>,
    ) {
        let joined: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.nlink > 1 && entry.kind != Kind::Dir)
            .map(|entry| (join(root, &entry.path), entry.dev, entry.ino))
            .collect();
        self.record_all(
            joined
                .iter()
                .map(|(path, dev, ino)| (path.as_slice(), *dev, *ino)),
        );
    }

    /// Hold off checks while this receiver links a new name to a file.
    pub(crate) fn linking(&self) -> std::sync::MutexGuard<'_, ()> {
        self.counting.lock().unwrap()
    }

    /// Refuse to change in place the file at `relative` beneath `root`
    /// (`label` names it), which `current` describes, unless that name still
    /// leads to it and every name it has can be confirmed inside the
    /// approved directories: names the receiver saw that still lead to the
    /// file, each directory entry counted once however it was spelled.
    pub(crate) fn require_inside(
        &self,
        root: &Root,
        relative: &RelativePath,
        label: &Path,
        current: &dyn Fn() -> Result<LinkedFile>,
    ) -> Result<()> {
        let refuse = || {
            let label = label.as_os_str().as_bytes();
            let shown = |bytes: &[u8]| Path::new(OsStr::from_bytes(bytes)).display().to_string();
            anyhow!(
                "{} has names this copy can't confirm are inside {}; not changed in place",
                shown(label),
                shown(self.scope_of(label).unwrap_or(label)),
            )
        };
        let leads = |name: &RelativePath, (dev, ino): (u64, u64)| {
            matches!(
                root.metadata_optional(name),
                Ok(Some(metadata)) if (metadata.dev, metadata.ino) == (dev, ino)
            )
        };
        // The change goes through this name, so it must still lead to the
        // file: a held file whose name inside is gone may have only names
        // outside left.
        let (dev, ino, nlink) = current()?;
        if !leads(relative, (dev, ino)) {
            return Err(refuse());
        }
        if nlink <= 1 {
            return Ok(());
        }
        let _counting = self.counting.lock().unwrap();
        let (dev, ino, nlink) = current()?;
        let own = relative.to_path_buf().into_os_string().into_vec();
        let mut candidates = vec![own.clone()];
        if let Some(known) = self.names.lock().unwrap().get(&(dev, ino)) {
            candidates.extend(
                known
                    .iter()
                    .filter(|name| ***name != *own)
                    .map(|name| name.to_vec()),
            );
        }
        // Names that still lead to the file, by the identity of the
        // directory holding them: one directory may be reached by several
        // spellings, or through a bind mount.
        let mut directories: HashMap<Vec<u8>, Option<(u64, u64)>> = HashMap::new();
        let mut groups: HashMap<(u64, u64), (Vec<u8>, u64)> = HashMap::new();
        for name in candidates {
            let Ok(path) = RelativePath::new(&name) else {
                continue;
            };
            if !leads(&path, (dev, ino)) {
                continue;
            }
            let parent = name
                .iter()
                .rposition(|byte| *byte == b'/')
                .map_or(Vec::new(), |slash| name[..slash].to_vec());
            let identity = *directories.entry(parent.clone()).or_insert_with(|| {
                let path = RelativePath::new(&parent).ok()?;
                let metadata = root.metadata_optional(&path).ok()??;
                metadata.is_dir().then_some((metadata.dev, metadata.ino))
            });
            if let Some(identity) = identity {
                groups.entry(identity).or_insert((parent, 0)).1 += 1;
            }
        }
        // A name alone in its directory is one entry. Several names in one
        // directory are as many entries as the directory lists for the file,
        // read once, however many spellings lead to them.
        let mut inside = 0;
        for (parent, names) in groups.into_values() {
            inside += if names == 1 {
                1
            } else {
                RelativePath::new(&parent)
                    .and_then(|path| root.count_entries_naming(&path, ino))
                    .unwrap_or(0)
                    .min(names)
            };
            if inside >= nlink {
                return Ok(());
            }
        }
        Err(refuse())
    }
}

impl FsOps {
    /// Confine in-place changes to files whose names are all inside the
    /// approved directories (`ScopeNames`). Only a confined receiver has
    /// them; every other receiver writes through a file's names as before.
    pub(crate) fn set_scope_names(&mut self, names: Arc<ScopeNames>) {
        self.scope_names = Some(names);
    }

    /// Remember the names a destination scan under `root` returned.
    pub(crate) fn record_scope_names(&self, root: &[u8], entries: &[Entry]) {
        if let Some(names) = &self.scope_names {
            names.record_entries(root, entries);
        }
    }

    /// Remember the names a guarded destination lookup of `paths` found,
    /// whichever request asked: a stat, a planning batch or a pruning lookup.
    pub(crate) fn record_looked_up_names(
        &self,
        paths: &[PathBytes],
        entries: &[Option<Entry>],
        guard: Option<&ContainerGuard>,
    ) {
        let Some(names) = self.scope_names.as_ref().filter(|_| guard.is_some()) else {
            return;
        };
        names.record_all(paths.iter().zip(entries).filter_map(|(path, entry)| {
            entry
                .as_ref()
                .filter(|entry| entry.nlink > 1 && entry.kind != Kind::Dir)
                .map(|entry| (path.as_slice(), entry.dev, entry.ino))
        }));
    }

    /// Refuse to change `target`'s file, open as `file`, in place unless all
    /// its names are confirmed inside the approved directories.
    pub(super) fn require_names_inside(&self, target: &RootedTarget, file: &File) -> Result<()> {
        require_names_inside(self.scope_names.as_deref(), target, file)
    }
}

/// As `FsOps::require_names_inside`, for code without the operations.
pub(super) fn require_names_inside(
    names: Option<&ScopeNames>,
    target: &RootedTarget,
    file: &File,
) -> Result<()> {
    let Some(names) = names else {
        return Ok(());
    };
    let current = || -> Result<LinkedFile> {
        let metadata = file.metadata()?;
        Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
    };
    if file.metadata()?.is_dir() {
        return Ok(());
    }
    names.require_inside(&target.root, &target.relative, &target.label, &current)
}

/// Whether applying `meta` under `flags` would change the file `current`
/// describes, as the metadata step changes only what differs. An owner
/// change by a receiver that is not root is skipped unless required.
pub(super) fn changes_metadata(current: &fs::Metadata, meta: &Meta, flags: u8) -> bool {
    meta.inode_metadata.is_some()
        || (flags & flags::MODE != 0
            && !current.file_type().is_symlink()
            && current.mode() & 0o7777 != meta.mode & 0o7777)
        || (flags & flags::OWNER != 0
            && (is_superuser() || flags & flags::REQUIRE_OWNER != 0)
            && current.uid() != meta.uid)
        || (flags & flags::GROUP != 0 && current.gid() != meta.gid)
        || (flags & flags::TIMES != 0
            && (current.mtime() != meta.mtime || current.mtime_nsec() as u32 != meta.mtime_nsec))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scope names for `base/scope`, and a check of the file at `name`
    /// beneath `base` as the receiver makes it.
    struct Fixture {
        base: PathBuf,
        root: Root,
        names: ScopeNames,
    }

    impl Fixture {
        fn new(base: &Path) -> Self {
            for directory in ["scope", "outside"] {
                fs::create_dir_all(base.join(directory)).unwrap();
            }
            Self {
                base: base.to_path_buf(),
                root: Root::open(base).unwrap(),
                names: ScopeNames::new(bytes(base), [(bytes(&base.join("scope")), true)]),
            }
        }

        fn record(&self, name: &str) {
            let metadata = fs::metadata(self.base.join(name)).unwrap();
            self.names.record(
                &bytes(&self.base.join(name)),
                metadata.dev(),
                metadata.ino(),
            );
        }

        fn check(&self, name: &str) -> Result<()> {
            let file = File::open(self.base.join(name)).unwrap();
            self.names.require_inside(
                &self.root,
                &RelativePath::new(name.as_bytes()).unwrap(),
                &self.base.join(name),
                &|| {
                    let metadata = file.metadata()?;
                    Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
                },
            )
        }
    }

    fn bytes(path: &Path) -> Vec<u8> {
        path.as_os_str().as_bytes().to_vec()
    }

    /// A name counts while it still names the file: a name the receiver saw
    /// that now holds another file proves nothing about the others.
    #[test]
    fn names_count_inside_only_while_they_name_the_file() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();

        // An unseen second name may be outside.
        let error = t.check("scope/a").unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "{} has names this copy can't confirm are inside {}; not changed in place",
                t.base.join("scope/a").display(),
                t.base.join("scope").display()
            )
        );
        // Both names seen inside: the file may change.
        t.record("scope/b");
        t.check("scope/a").unwrap();
        // A name outside the scope is never remembered as inside.
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/a")).unwrap();
        t.record("outside/a");
        assert!(t.check("scope/a").is_err());
        // Replacing a remembered name takes it out of the count.
        fs::remove_file(t.base.join("outside/a")).unwrap();
        fs::remove_file(t.base.join("scope/b")).unwrap();
        fs::write(t.base.join("scope/b"), b"other").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/a")).unwrap();
        assert!(t.check("scope/a").is_err());
        // A file with one name is never refused.
        t.check("scope/b").unwrap();
    }

    /// Several names in one directory count as the entries that directory
    /// lists for the file. Where the filesystem folds case, `scope/A` leads
    /// to the entry `scope/a` and adds nothing; elsewhere a second entry
    /// counts.
    #[test]
    fn names_in_one_directory_count_as_its_entries() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/a")).unwrap();
        let folds_case = t.base.join("scope/A").exists();
        t.record("scope/a");
        if folds_case {
            // Another spelling of the same entry.
            t.record("scope/A");
            assert!(t.check("scope/a").is_err());
            assert_eq!(
                fs::metadata(t.base.join("outside/a")).unwrap().nlink(),
                2,
                "the outside name is still there"
            );
        } else {
            eprintln!("this filesystem does not fold case; checking distinct entries only");
        }
        // A second entry in the directory counts, but not the outside name.
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        t.record("scope/b");
        assert!(t.check("scope/a").is_err());
        fs::remove_file(t.base.join("outside/a")).unwrap();
        t.check("scope/a").unwrap();
    }

    /// An enrollment root of `/` keeps names beneath it.
    #[test]
    fn names_beneath_the_root_directory_are_remembered() {
        let names = ScopeNames::new(b"/".to_vec(), [(b"/data".to_vec(), true)]);
        names.record(b"/data/a", 1, 2);
        names.record(b"/database/a", 1, 2);
        // The approved path itself, as for a file copied --as.
        names.record(b"/data", 1, 2);
        let known = names.names.lock().unwrap();
        let file: Vec<&[u8]> = known[&(1, 2)].iter().map(|name| &**name).collect();
        assert_eq!(file, [&b"data/a"[..], b"data"]);
        let rooted = ScopeNames::new(b"/srv".to_vec(), [(b"/srv/data".to_vec(), true)]);
        assert_eq!(rooted.relative(b"/srv/data/a"), Some(&b"data/a"[..]));
        assert_eq!(rooted.relative(b"/srvdata/a"), None);
        assert_eq!(rooted.relative(b"/srv"), None);
    }

    /// A held file whose name inside was removed keeps only its name
    /// outside: finishing it there must not change that file.
    #[test]
    fn removed_inside_name_must_not_allow_finishing_outside_basis() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        let t = Fixture::new(base);
        fs::write(base.join("scope/a"), b"held").unwrap();
        fs::set_permissions(base.join("scope/a"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(base.join("scope/a"), base.join("outside/a")).unwrap();
        let identity = t.root.identity();
        let guard = ContainerGuard {
            root: bytes(base),
            dev: identity.dev,
            ino: identity.ino,
        };
        let mut operations = FsOps::new();
        operations.set_scope_names(Arc::new(t.names));
        let path = bytes(&base.join("scope/a"));
        let copy_id = [5; 16];
        operations
            .hash_and_hold(
                &path,
                &copy_id,
                MIN_HASH_BLOCK_BYTES,
                4,
                TargetCondition::Any,
                Some(&guard),
            )
            .unwrap();
        fs::remove_file(base.join("scope/a")).unwrap();
        let error = operations
            .finish_basis(
                &path,
                &copy_id,
                &Meta {
                    inode_metadata: None,
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                flags::MODE,
                TargetCondition::Any,
                Some(&guard),
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("can't confirm are inside"),
            "{error:#}"
        );
        assert_eq!(
            fs::metadata(base.join("outside/a")).unwrap().mode() & 0o7777,
            0o600
        );
    }
}

#[cfg(test)]
mod measure {
    use super::*;

    fn rss_kb() -> u64 {
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|value| value.trim().trim_end_matches(" kB").trim().parse().ok())
            .unwrap()
    }

    /// Memory the names of 500,000 scanned linked names take, two names per
    /// file, as a receiver remembers them; run explicitly in a release build.
    #[test]
    #[ignore]
    fn measure_remembered_names() {
        let scope = b"/srv/receiving/destination".to_vec();
        let names = ScopeNames::new(b"/srv/receiving".to_vec(), [(scope.clone(), true)]);
        let entry = |path: Vec<u8>, ino: u64| Entry {
            path,
            kind: Kind::File,
            size: 1,
            mtime: 0,
            mtime_nsec: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            rdev: 0,
            dev: 1,
            ino,
            nlink: 2,
            ctime: 0,
            ctime_nsec: 0,
            link: None,
            atime: Default::default(),
            inode_metadata: None,
        };
        let before = rss_kb();
        let started = std::time::Instant::now();
        for batch in 0..500u64 {
            let entries: Vec<Entry> = (0..1000u64)
                .map(|i| {
                    let file = batch * 1000 + i;
                    entry(
                        format!("tree/d{:03}/name{:07}", batch % 100, file).into_bytes(),
                        file / 2,
                    )
                })
                .collect();
            names.record_entries(&scope, &entries);
        }
        eprintln!(
            "MEASURE remembered names: {} kB in {:.2}s",
            rss_kb() - before,
            started.elapsed().as_secs_f64()
        );
    }
}
