//! A confined receiver changes no file in place that has names outside the
//! directories it promises to stay within: a file's contents and metadata
//! belong to every name it has. The receiver counts the names it knows a
//! file has inside: those its own destination scans and lookups returned,
//! and the links this copy made, each directory entry once. A file with more
//! names than that may have some elsewhere, or inside where the receiver
//! never looked; either way it is not changed in place.

use super::*;
use std::collections::BTreeSet;

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
    /// How many entries of a directory name each inode, by the directory's
    /// identity, as of its change time, which any added, removed or renamed
    /// entry advances. Kept for a few directories at a time.
    entries: Mutex<HashMap<(u64, u64), DirectoryEntries>>,
}

/// A directory's entry count per inode, as of its change time, for the
/// inodes it lists more than once.
struct DirectoryEntries {
    changed: (i64, u32),
    per_inode: HashMap<u64, u64>,
}

/// A directory holding names of a file: its path, change time, and the
/// names in it, folded.
type DirectoryNames = (Vec<u8>, (i64, u32), BTreeSet<Vec<u8>>);

/// Directories whose entry counts a receiver keeps at once.
const ENTRY_COUNT_DIRECTORIES: usize = 16;

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
            entries: Mutex::default(),
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
    /// `opened_links` is the link count when the file was opened, for a file
    /// held since: one with a single name then and now has only that name,
    /// since this receiver never gives a file a name outside.
    pub(crate) fn require_inside(
        &self,
        root: &Root,
        relative: &RelativePath,
        label: &Path,
        current: &dyn Fn() -> Result<LinkedFile>,
        opened_links: u64,
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
        let (dev, ino, nlink) = current()?;
        if nlink.max(opened_links) <= 1 {
            return Ok(());
        }
        // The change goes through this name, so it must still lead to the
        // file: a held file whose name inside is gone may have only names
        // outside left.
        if !leads(relative, (dev, ino)) {
            return Err(refuse());
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
        let mut directories: HashMap<Vec<u8>, Option<RootMetadata>> = HashMap::new();
        let mut groups: HashMap<(u64, u64), DirectoryNames> = HashMap::new();
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
            let directory = *directories.entry(parent.clone()).or_insert_with(|| {
                let path = RelativePath::new(&parent).ok()?;
                let metadata = root.metadata_optional(&path).ok()??;
                metadata.is_dir().then_some(metadata)
            });
            if let Some(directory) = directory {
                let leaf = &name[name.len() - path.leaf()?.1.len()..];
                groups
                    .entry((directory.dev, directory.ino))
                    .or_insert_with(|| {
                        (
                            parent,
                            (directory.ctime, directory.ctime_nsec),
                            BTreeSet::new(),
                        )
                    })
                    .2
                    .insert(folded(leaf));
            }
        }
        // A name alone in its directory is one entry. Several names in one
        // directory are as many entries as the directory lists for the file,
        // read once, but no more than the distinct names left once folded as
        // any filesystem might fold them: two spellings of one entry count
        // once.
        let mut inside = 0;
        for (identity, (parent, changed, names)) in groups {
            // A name with another character might be any other name there.
            let distinct = if names.contains(UNFOLDABLE) {
                1
            } else {
                names.len() as u64
            };
            inside += if distinct == 1 {
                1
            } else {
                self.entries_naming(root, &parent, (identity, changed), ino)
                    .unwrap_or(0)
                    .min(distinct)
            };
            if inside >= nlink {
                return Ok(());
            }
        }
        Err(refuse())
    }
}

impl ScopeNames {
    /// How many entries of the directory `parent`, with this identity and
    /// change time, name the inode `ino`. A directory is read once while it
    /// stays unchanged, however many of its files are checked. Its entries
    /// may change within one tick of a coarse clock; a count read too early
    /// misses an entry added since, which can only refuse a change, or
    /// counts one removed since, which the distinct names that still lead
    /// to the file bound.
    fn entries_naming(
        &self,
        root: &Root,
        parent: &[u8],
        (identity, changed): ((u64, u64), (i64, u32)),
        ino: u64,
    ) -> Result<u64> {
        // A name that leads to the file is an entry for it, so an inode
        // the directory does not list more than once has one.
        let mut entries = self.entries.lock().unwrap();
        if let Some(known) = entries
            .get(&identity)
            .filter(|known| known.changed == changed)
        {
            return Ok(known.per_inode.get(&ino).copied().unwrap_or(1));
        }
        let mut per_inode = root.count_entries_by_inode(&RelativePath::new(parent)?)?;
        per_inode.retain(|_, count| *count > 1);
        let count = per_inode.get(&ino).copied().unwrap_or(1);
        if entries.len() >= ENTRY_COUNT_DIRECTORIES {
            entries.clear();
        }
        entries.insert(identity, DirectoryEntries { changed, per_inode });
        Ok(count)
    }
}

/// What a name with a character other than ASCII folds to: no name has a
/// NUL byte.
const UNFOLDABLE: &[u8] = b"\0";

/// `name` as the most aggressive filesystem might fold it when telling
/// names apart, or something coarser: folding too much can only refuse a
/// change, never allow one. ASCII letters fold their case and trailing dots
/// and spaces go, as some filesystems ignore them; any other character may
/// fold to almost anything under Unicode case folding and normalization (a
/// Kelvin sign to `k`, `ß` to `ss`, a precomposed letter to its parts), so
/// a name with one folds to `UNFOLDABLE`, which may be any of the others.
fn folded(name: &[u8]) -> Vec<u8> {
    if !name.is_ascii() {
        return UNFOLDABLE.to_vec();
    }
    let trimmed = name.len()
        - name
            .iter()
            .rev()
            .take_while(|byte| matches!(byte, b'.' | b' '))
            .count();
    name[..trimmed].to_ascii_lowercase()
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
    /// `opened_links` is its link count when it was opened, for a file held
    /// since then.
    pub(super) fn require_names_inside(
        &self,
        target: &RootedTarget,
        file: &File,
        opened_links: Option<u64>,
    ) -> Result<()> {
        require_names_inside(self.scope_names.as_deref(), target, file, opened_links)
    }
}

/// As `FsOps::require_names_inside`, for code without the operations.
pub(super) fn require_names_inside(
    names: Option<&ScopeNames>,
    target: &RootedTarget,
    file: &File,
    opened_links: Option<u64>,
) -> Result<()> {
    let Some(names) = names else {
        return Ok(());
    };
    // One read of the descriptor decides a file with a single name.
    let metadata = file.metadata()?;
    let opened_links = opened_links.unwrap_or(0);
    if metadata.is_dir() || metadata.nlink().max(opened_links) <= 1 {
        return Ok(());
    }
    let current = || -> Result<LinkedFile> {
        let metadata = file.metadata()?;
        Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
    };
    names.require_inside(
        &target.root,
        &target.relative,
        &target.label,
        &current,
        opened_links,
    )
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
                0,
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

    /// Two approved spellings of one entry, and a name the copy never
    /// approved in the same directory: the two spellings fold to one name,
    /// so only one of the file's two entries is confirmed. On a filesystem
    /// that tells `a` from `A`, the same three names are three entries, and
    /// folding still counts two of them as one: a refusal, never a pass.
    #[test]
    fn spellings_of_one_entry_do_not_confirm_another_name() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/unapproved")).unwrap();
        if !t.base.join("scope/A").exists() {
            fs::hard_link(t.base.join("scope/a"), t.base.join("scope/A")).unwrap();
        }
        t.record("scope/a");
        t.record("scope/A");
        assert!(t.check("scope/a").is_err());
        // Any name that is not ASCII might be any other name there.
        let mut other = vec![b'k'; 1];
        other.extend("\u{212a}".as_bytes());
        let other = String::from_utf8(other).unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope").join(&other)).unwrap();
        t.record(&format!("scope/{other}"));
        assert!(t.check("scope/a").is_err());
        assert_eq!(folded(b"Name. ."), b"name");
        assert_eq!(folded("\u{e9}".as_bytes()), UNFOLDABLE);
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

    fn cpu_seconds() -> f64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        let usage = unsafe { usage.assume_init() };
        let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
        seconds(usage.ru_utime) + seconds(usage.ru_stime)
    }

    /// Checks of every file in one directory of linked pairs, as an
    /// in-place copy changing each of them makes them; `SYQ_MEASURE_PAIRS`
    /// sets the number of pairs (50,000 by default). Run explicitly in a
    /// release build.
    #[test]
    #[ignore]
    fn measure_same_directory_pairs() {
        let pairs: usize = std::env::var("SYQ_MEASURE_PAIRS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(50_000);
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        let scope = base.join("scope");
        fs::create_dir(&scope).unwrap();
        let bytes = |path: &Path| path.as_os_str().as_bytes().to_vec();
        let names = ScopeNames::new(bytes(base), [(bytes(&scope), true)]);
        let mut files = Vec::with_capacity(pairs);
        for pair in 0..pairs {
            let first = scope.join(format!("a{pair:06}"));
            let second = scope.join(format!("b{pair:06}"));
            fs::write(&first, b"x").unwrap();
            fs::hard_link(&first, &second).unwrap();
            let metadata = fs::metadata(&first).unwrap();
            names.record(&bytes(&first), metadata.dev(), metadata.ino());
            names.record(&bytes(&second), metadata.dev(), metadata.ino());
            files.push(format!("scope/a{pair:06}"));
        }
        let root = Root::open(base).unwrap();
        let (started, cpu) = (std::time::Instant::now(), cpu_seconds());
        for name in &files {
            let file = File::open(base.join(name)).unwrap();
            names
                .require_inside(
                    &root,
                    &RelativePath::new(name.as_bytes()).unwrap(),
                    &base.join(name),
                    &|| {
                        let metadata = file.metadata()?;
                        Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
                    },
                    0,
                )
                .unwrap();
        }
        eprintln!(
            "MEASURE {pairs} same-directory pairs: {:.2}s elapsed, {:.2}s CPU",
            started.elapsed().as_secs_f64(),
            cpu_seconds() - cpu
        );
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
