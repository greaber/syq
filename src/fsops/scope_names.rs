//! A confined receiver changes no file in place that has names outside the
//! directories it promises to stay within: a file's contents and metadata
//! belong to every name it has. Before changing in place a file with more
//! than one link, the receiver counts the file's entries inside those
//! directories, from its own listing of them, and refuses the change unless
//! it finds as many as the file has links.
//!
//! The listing is read once per copy, on the first such file, with the
//! parallel scan copies use for destinations: it never follows a symlink.
//! It keeps the names of the files with more than one link, leaving out
//! directories on another device (a file's links cannot cross devices) and
//! any directory reached a second time (a bind mount, nested approved
//! directories). Entries are what directories list: a directory that
//! ignores case lists `a` once however it is spelled, so no name is ever
//! compared with another.
//!
//! Stale data only ever refuses. A check counts the names it kept that still
//! lead to the file, so an entry removed, replaced or moved away since no
//! longer counts; a file the listing does not know has no names inside. The
//! links this receiver makes are added as it makes them. A file with one
//! link needs no listing, but the name a change goes through must still lead
//! to a file held open since an earlier step, which no count can show.

use super::*;
use std::collections::HashSet;

pub(crate) struct ScopeNames {
    /// The receiver's root, beneath which every name here lies.
    root: Vec<u8>,
    /// The approved directories, each with whether it covers descendants.
    scopes: Vec<(Vec<u8>, bool)>,
    /// The listing, once read. Held while a check counts and while this
    /// receiver links a name, so that no link it makes is counted against a
    /// link count read before it, or missed by the listing.
    listing: Mutex<Option<Listing>>,
}

/// The names, relative to the root, of the files the listing found inside
/// more than once, and of files this receiver linked inside since.
type Listing = HashMap<(u64, u64), Vec<Box<[u8]>>>;

/// A file's device, inode and link count.
pub(crate) type LinkedFile = (u64, u64, u64);

impl ScopeNames {
    pub(crate) fn new(root: Vec<u8>, scopes: impl IntoIterator<Item = (Vec<u8>, bool)>) -> Self {
        Self {
            root,
            scopes: scopes.into_iter().collect(),
            listing: Mutex::default(),
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

    /// `path` relative to the root, when it lies at or beneath it.
    fn relative<'a>(&self, path: &'a [u8]) -> Option<&'a [u8]> {
        if path == self.root.as_slice() {
            return Some(&[]);
        }
        let rest = path.strip_prefix(self.root.as_slice())?;
        if self.root.ends_with(b"/") {
            Some(rest)
        } else {
            rest.strip_prefix(b"/")
        }
    }

    /// `relative`, beneath the root, as a path.
    fn absolute(&self, relative: &RelativePath) -> Vec<u8> {
        let relative = relative.to_path_buf().into_os_string().into_vec();
        if relative.is_empty() {
            self.root.clone()
        } else {
            join(&self.root, &relative)
        }
    }

    /// Link a new name `target` to the file `identity` with `link`, which
    /// says whether it made one, from `source`, a name of the file. A name
    /// made inside the approved directories counts for the file from then
    /// on, and no check counts the file's names meanwhile.
    pub(crate) fn link(
        &self,
        root: &Root,
        source: &RelativePath,
        target: &RelativePath,
        identity: (u64, u64),
        link: impl FnOnce() -> Result<bool>,
    ) -> Result<()> {
        let mut listing = self.listing.lock().unwrap();
        // Before the listing is read, it will find the name itself.
        let Some(listing) = listing.as_mut() else {
            return link().map(drop);
        };
        // Kept names that do not lead to the file before the link are
        // dropped first: the new entry could be another spelling of one of
        // them, or have its very name. The names that do lead to it name
        // other entries than the one the link makes.
        if let Some(names) = listing.get_mut(&identity) {
            names.retain(|name| leads(root, name, identity));
        }
        if !link()? {
            return Ok(());
        }
        let inside = |name: &RelativePath| self.scope_of(&self.absolute(name)).is_some();
        if !inside(target) {
            return Ok(());
        }
        let names = listing.entry(identity).or_default();
        if names.is_empty() && inside(source) && leads_to(root, source, identity) {
            // The file had one name inside when it was listed, or none then.
            names.push(path_bytes(source).into());
        }
        let target = path_bytes(target);
        if !names.iter().any(|name| **name == *target) {
            names.push(target.into());
        }
        Ok(())
    }

    /// Refuse to change in place the file at `relative` beneath `root`
    /// (`label` names it), which `current` describes, unless that name still
    /// leads to it and every name it has is confirmed inside the approved
    /// directories. `held_links` is the link count when the file was opened,
    /// for a file held open since then, or None for one just opened by this
    /// name.
    pub(crate) fn require_inside(
        &self,
        root: &Arc<Root>,
        relative: &RelativePath,
        label: &Path,
        current: &dyn Fn() -> Result<LinkedFile>,
        held_links: Option<u64>,
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
        let (dev, ino, nlink) = current()?;
        // A file just opened by this name with no other has only that name.
        if held_links.is_none() && nlink <= 1 {
            return Ok(());
        }
        // The change goes through this name, so it must still lead to the
        // file: a file held open since may have been moved, or its name
        // inside removed, leaving it only names outside.
        if !leads_to(root, relative, (dev, ino)) {
            return Err(refuse());
        }
        if nlink.max(held_links.unwrap_or(0)) <= 1 {
            return Ok(());
        }
        let mut listing = self.listing.lock().unwrap();
        let listing = listing.get_or_insert_with(|| self.list(root));
        let (dev, ino, nlink) = current()?;
        let inside = listing.get(&(dev, ino)).map_or(0, |names| {
            names
                .iter()
                .filter(|name| leads(root, name, (dev, ino)))
                .collect::<HashSet<_>>()
                .len() as u64
        });
        if inside >= nlink {
            Ok(())
        } else {
            Err(refuse())
        }
    }

    /// Read the approved directories with the parallel scan copies use:
    /// the names of the files with more than one link found inside. A
    /// directory that cannot be read is left out, which can only refuse a
    /// change.
    fn list(&self, root: &Arc<Root>) -> Listing {
        let mut listing = Listing::new();
        let mut visited = HashSet::new();
        // Outer directories first, so that one nested in another is not
        // scanned again.
        let mut scopes: Vec<_> = self.scopes.iter().collect();
        scopes.sort_by_key(|(scope, _)| scope.len());
        let mut exact = Vec::new();
        for (scope, descendants) in scopes {
            let Some(relative) = self.relative(scope) else {
                continue;
            };
            let Ok(path) = RelativePath::new(relative) else {
                continue;
            };
            if !(*descendants && list_tree(root, relative, &mut visited, &mut listing)) {
                exact.push(path);
            }
        }
        // An approved path that is not a directory is one entry, counted
        // once per directory and file: two approved spellings of one entry
        // must not count twice, and an entry in a directory scanned above
        // has been counted there.
        let mut counted = HashSet::new();
        for path in exact {
            let Ok(Some(file)) = root.metadata_optional(&path) else {
                continue;
            };
            let Some(directory) = path
                .leaf()
                .ok()
                .and_then(|(parents, _)| RelativePath::new(&parents.join(&b'/')).ok())
                .and_then(|parent| root.metadata_optional(&parent).ok().flatten())
            else {
                continue;
            };
            let directory = (directory.dev, directory.ino);
            if !file.is_dir()
                && file.nlink > 1
                && !visited.contains(&directory)
                && counted.insert((directory, (file.dev, file.ino)))
            {
                listing
                    .entry((file.dev, file.ino))
                    .or_default()
                    .push(path_bytes(&path).into());
            }
        }
        listing
    }
}

/// Add to `listing` the names of the files with more than one link in the
/// directory tree at `relative` beneath `root`, scanned as a copy scans a
/// destination: without following a symlink. A directory on another device
/// is left out, since a file's links cannot cross devices, and so is one
/// already read under another name (`visited`: a bind mount, or an approved
/// directory nested in another). Returns whether `relative` is a directory.
fn list_tree(
    root: &Arc<Root>,
    relative: &[u8],
    visited: &mut HashSet<(u64, u64)>,
    listing: &mut Listing,
) -> bool {
    let top = match RelativePath::new(relative).map(|path| root.metadata_optional(&path)) {
        Ok(Ok(Some(top))) if top.is_dir() => top,
        _ => return false,
    };
    if !visited.insert((top.dev, top.ino)) {
        return true;
    }
    // Whether each directory scanned counts, by its path in the tree. The
    // scan reports a directory before anything in it.
    let mut counted = HashMap::from([(Vec::new(), true)]);
    let _ = crate::scan::scan_descriptor(
        root.clone(),
        relative,
        None,
        false,
        false,
        &[],
        false,
        &mut |batch| {
            for entry in batch {
                if entry.path.is_empty() {
                    continue;
                }
                let parent = entry
                    .path
                    .iter()
                    .rposition(|byte| *byte == b'/')
                    .map_or(&entry.path[..0], |slash| &entry.path[..slash]);
                let inside = counted.get(parent).copied().unwrap_or(false);
                if entry.kind == Kind::Dir {
                    let counts =
                        inside && entry.dev == top.dev && visited.insert((entry.dev, entry.ino));
                    counted.insert(entry.path, counts);
                } else if inside && entry.nlink > 1 {
                    let name = if relative.is_empty() {
                        entry.path
                    } else {
                        join(relative, &entry.path)
                    };
                    listing
                        .entry((entry.dev, entry.ino))
                        .or_default()
                        .push(name.into());
                }
            }
            Ok(())
        },
        &mut |_| Ok(()),
        &mut |_| {},
    );
    true
}

/// The bytes of `path`.
fn path_bytes(path: &RelativePath) -> Vec<u8> {
    path.to_path_buf().into_os_string().into_vec()
}

/// Whether `name` beneath `root` leads to the file `identity`.
fn leads_to(root: &Root, name: &RelativePath, identity: (u64, u64)) -> bool {
    matches!(
        root.metadata_optional(name),
        Ok(Some(metadata)) if (metadata.dev, metadata.ino) == identity
    )
}

/// As `leads_to`, for a kept name.
fn leads(root: &Root, name: &[u8], identity: (u64, u64)) -> bool {
    RelativePath::new(name).is_ok_and(|name| leads_to(root, &name, identity))
}

impl FsOps {
    /// Confine in-place changes to files whose names are all inside the
    /// approved directories (`ScopeNames`). Only a confined receiver has
    /// them; every other receiver writes through a file's names as before.
    pub(crate) fn set_scope_names(&mut self, names: Arc<ScopeNames>) {
        self.scope_names = Some(names);
    }

    /// The link count of `file` as it is first held, which only a receiver
    /// that checks names reads: others skip the extra lookup.
    pub(super) fn links_when_held(&self, file: &File) -> Result<u64> {
        Ok(match self.scope_names {
            Some(_) => file.metadata()?.nlink(),
            None => 0,
        })
    }

    /// Refuse to change `target`'s file, open as `file`, in place unless all
    /// its names are confirmed inside the approved directories.
    /// `held_links` is its link count when it was opened, for a file held
    /// open since then, or None for one just opened by this name.
    pub(super) fn require_names_inside(
        &self,
        target: &RootedTarget,
        file: &File,
        held_links: Option<u64>,
    ) -> Result<()> {
        require_names_inside(self.scope_names.as_deref(), target, file, held_links)
    }
}

/// As `FsOps::require_names_inside`, for code without the operations.
pub(super) fn require_names_inside(
    names: Option<&ScopeNames>,
    target: &RootedTarget,
    file: &File,
    held_links: Option<u64>,
) -> Result<()> {
    let Some(names) = names else {
        return Ok(());
    };
    // One read of the descriptor decides a file just opened by its only name.
    let metadata = file.metadata()?;
    if metadata.is_dir() || (held_links.is_none() && metadata.nlink() <= 1) {
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
        held_links,
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

    /// Scope names for the approved directory `base/scope`, and a check of
    /// the file at `name` beneath `base` as the receiver makes it.
    struct Fixture {
        base: PathBuf,
        root: Arc<Root>,
        names: ScopeNames,
    }

    impl Fixture {
        fn new(base: &Path) -> Self {
            for directory in ["scope", "outside"] {
                fs::create_dir_all(base.join(directory)).unwrap();
            }
            Self::with_scopes(base, &[("scope", true)])
        }

        fn with_scopes(base: &Path, scopes: &[(&str, bool)]) -> Self {
            Self {
                base: base.to_path_buf(),
                root: Arc::new(Root::open(base).unwrap()),
                names: ScopeNames::new(
                    bytes(base),
                    scopes
                        .iter()
                        .map(|(scope, descendants)| (bytes(&base.join(scope)), *descendants)),
                ),
            }
        }

        /// A new copy's names, which lists the scope afresh.
        fn next_copy(&mut self) {
            let scopes = std::mem::take(&mut self.names.scopes);
            self.names = ScopeNames::new(bytes(&self.base), scopes);
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
                None,
            )
        }

        /// Link `target` to the file at `source` as this receiver does.
        fn link(&self, source: &str, target: &str) {
            let metadata = fs::metadata(self.base.join(source)).unwrap();
            let identity = (metadata.dev(), metadata.ino());
            let (source, target) = (
                RelativePath::new(source.as_bytes()).unwrap(),
                RelativePath::new(target.as_bytes()).unwrap(),
            );
            self.names
                .link(&self.root, &source, &target, identity, || {
                    self.root
                        .publish_hardlink(&source, &target, identity, TargetCondition::Any)
                })
                .unwrap();
        }
    }

    fn bytes(path: &Path) -> Vec<u8> {
        path.as_os_str().as_bytes().to_vec()
    }

    /// Every entry of the file in the approved directory counts, however
    /// deep; one outside refuses the change, with the reason.
    #[test]
    fn every_entry_inside_counts_and_one_outside_refuses() {
        let temporary = crate::test_support::tempdir().unwrap();
        let mut t = Fixture::new(temporary.path());
        fs::create_dir(t.base.join("scope/sub")).unwrap();
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/sub/c")).unwrap();
        t.check("scope/a").unwrap();
        t.check("scope/sub/c").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/a")).unwrap();
        t.next_copy();
        let error = t.check("scope/a").unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "{} has names this copy can't confirm are inside {}; not changed in place",
                t.base.join("scope/a").display(),
                t.base.join("scope").display()
            )
        );
        // A file with one name is never refused, and needs no listing.
        fs::write(t.base.join("scope/single"), b"one").unwrap();
        t.next_copy();
        t.check("scope/single").unwrap();
        assert!(t.names.listing.lock().unwrap().is_none());
    }

    /// The listing is read once per copy: a file linked again since, by
    /// someone else, is refused rather than listed afresh, as is a file it
    /// never saw with more than one name.
    #[test]
    fn what_the_listing_does_not_know_counts_nothing_inside() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        fs::write(t.base.join("scope/x"), b"other").unwrap();
        t.check("scope/a").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/c")).unwrap();
        assert!(t.check("scope/a").is_err());
        fs::hard_link(t.base.join("scope/x"), t.base.join("scope/y")).unwrap();
        assert!(t.check("scope/x").is_err());
    }

    /// An entry removed, replaced or moved away since the listing no longer
    /// counts: stale data only refuses.
    #[test]
    fn entries_gone_since_the_listing_no_longer_count() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        for name in ["b", "c", "d"] {
            fs::hard_link(t.base.join("scope/a"), t.base.join("scope").join(name)).unwrap();
        }
        t.check("scope/a").unwrap();
        // Moved outside: the file keeps its link count.
        fs::rename(t.base.join("scope/b"), t.base.join("outside/b")).unwrap();
        assert!(t.check("scope/a").is_err());
        // Removed, and replaced by another file: the count falls with it.
        fs::remove_file(t.base.join("scope/c")).unwrap();
        fs::remove_file(t.base.join("scope/d")).unwrap();
        fs::write(t.base.join("scope/d"), b"other").unwrap();
        assert!(t.check("scope/a").is_err());
        fs::remove_file(t.base.join("outside/b")).unwrap();
        t.check("scope/a").unwrap();
    }

    /// Links this receiver makes count from then on: a group it links
    /// inside, from a file the listing saw with one name or with several.
    #[test]
    fn links_this_receiver_makes_count_from_then_on() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        fs::write(t.base.join("scope/single"), b"one").unwrap();
        t.check("scope/a").unwrap();
        t.link("scope/a", "scope/c");
        t.check("scope/a").unwrap();
        t.link("scope/single", "scope/second");
        t.check("scope/single").unwrap();
        t.check("scope/second").unwrap();
        // Linking a name that already leads to the file adds nothing.
        t.link("scope/a", "scope/b");
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/a")).unwrap();
        assert!(t.check("scope/a").is_err());
    }

    /// A name removed and linked again under another spelling of the same
    /// entry is not counted twice: a name kept that no longer leads to the
    /// file is dropped before a new one is added.
    #[test]
    fn a_name_linked_again_is_not_counted_twice() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/o")).unwrap();
        assert!(t.check("scope/b").is_err());
        fs::remove_file(t.base.join("scope/a")).unwrap();
        t.link("scope/b", "scope/A");
        assert!(t.check("scope/b").is_err());
        assert_eq!(fs::read(t.base.join("outside/o")).unwrap(), b"shared");
    }

    /// Someone else removes a name inside and links the file outside, so its
    /// link count stays as it was listed: the name removed no longer counts.
    /// Making the name again inside raises the link count with it. On a
    /// filesystem that folds case, the name made again under another
    /// spelling is still the one entry.
    #[test]
    fn a_name_moved_out_with_the_link_count_unchanged_is_refused() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        t.check("scope/a").unwrap();
        let links = || fs::metadata(t.base.join("scope/a")).unwrap().nlink();
        fs::remove_file(t.base.join("scope/b")).unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/o")).unwrap();
        assert_eq!(links(), 2);
        assert!(t.check("scope/a").is_err());
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        assert_eq!(links(), 3);
        assert!(t.check("scope/a").is_err());
        if t.base.join("scope/B").exists() {
            fs::remove_file(t.base.join("scope/b")).unwrap();
            fs::hard_link(t.base.join("scope/a"), t.base.join("scope/B")).unwrap();
            assert!(t.check("scope/a").is_err());
            assert!(t.check("scope/B").is_err());
        }
        assert_eq!(fs::read(t.base.join("outside/o")).unwrap(), b"shared");
    }

    /// A name this receiver links again after it was removed, even under
    /// its very name, counts once.
    #[test]
    fn a_name_linked_again_under_its_own_name_counts_once() {
        let temporary = crate::test_support::tempdir().unwrap();
        let t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        t.check("scope/a").unwrap();
        fs::remove_file(t.base.join("scope/b")).unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/o")).unwrap();
        t.link("scope/a", "scope/b");
        assert_eq!(fs::metadata(t.base.join("scope/a")).unwrap().nlink(), 3);
        assert!(t.check("scope/a").is_err());
        assert!(t.check("scope/b").is_err());
    }

    /// Approved paths that the filesystem makes one entry (folding case,
    /// composition, or invisible characters HFS+ skips), beside a link
    /// nobody approved, count as one entry, so the file is refused. Pairs
    /// this filesystem keeps apart are not checked. (The reviewers'
    /// reproducers.)
    #[test]
    fn approved_spellings_of_one_entry_do_not_confirm_another_name() {
        let temporary = crate::test_support::tempdir().unwrap();
        let mut checked = Vec::new();
        for (index, (first, second)) in [
            ("a", "A"),
            ("ab", "a\u{200b}b"),
            ("ab", "a\u{200c}b"),
            ("ab", "a\u{200d}b"),
            ("ab", "a\u{feff}b"),
            ("ab", "a\u{ad}b"),
            ("ab", "a\u{34f}b"),
            ("ab", "a\u{2060}b"),
            ("ab", "a\u{fe0f}b"),
            ("K", "\u{212a}"),
            ("\u{e9}", "e\u{301}"),
            ("STRASSE", "stra\u{df}e"),
            ("\u{3a3}\u{3a3}", "\u{3c3}\u{3c3}"),
        ]
        .into_iter()
        .enumerate()
        {
            let base = temporary.path().join(index.to_string());
            fs::create_dir(&base).unwrap();
            fs::write(base.join(first), b"protected").unwrap();
            let same = fs::metadata(base.join(second))
                .is_ok_and(|alias| alias.ino() == fs::metadata(base.join(first)).unwrap().ino());
            if !same {
                continue;
            }
            fs::hard_link(base.join(first), base.join("unapproved")).unwrap();
            let t = Fixture::with_scopes(&base, &[(first, false), (second, false)]);
            assert!(t.check(first).is_err(), "{first:?} and {second:?}");
            assert!(t.check(second).is_err(), "{first:?} and {second:?}");
            checked.push(second);
        }
        eprintln!("spellings this filesystem makes one: {checked:?}");
    }

    /// A directory reached twice, here through nested approved directories,
    /// is read once: its entry counts once.
    #[test]
    fn a_directory_reached_twice_is_read_once() {
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        fs::create_dir_all(base.join("scope/sub")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(base.join("scope/sub/a"), b"shared").unwrap();
        fs::hard_link(base.join("scope/sub/a"), base.join("outside/o")).unwrap();
        for scopes in [
            &[("scope", true), ("scope/sub", true)][..],
            &[("scope/sub", true), ("scope", true)],
            &[("scope/sub", true), ("scope/sub/a", false)],
        ] {
            let t = Fixture::with_scopes(base, scopes);
            assert!(t.check("scope/sub/a").is_err(), "{scopes:?}");
        }
        fs::remove_file(base.join("outside/o")).unwrap();
        fs::hard_link(base.join("scope/sub/a"), base.join("scope/b")).unwrap();
        let t = Fixture::with_scopes(base, &[("scope", true), ("scope/sub", true)]);
        t.check("scope/sub/a").unwrap();
    }

    /// Several names in one directory count as its entries; a name outside
    /// does not. Where the filesystem folds case, `scope/A` is the entry
    /// `scope/a`.
    #[test]
    fn names_in_one_directory_count_as_its_entries() {
        let temporary = crate::test_support::tempdir().unwrap();
        let mut t = Fixture::new(temporary.path());
        fs::write(t.base.join("scope/a"), b"shared").unwrap();
        fs::hard_link(t.base.join("scope/a"), t.base.join("outside/a")).unwrap();
        assert!(t.check("scope/a").is_err());
        if t.base.join("scope/A").exists() {
            assert!(t.check("scope/A").is_err());
        }
        fs::hard_link(t.base.join("scope/a"), t.base.join("scope/b")).unwrap();
        t.next_copy();
        assert!(t.check("scope/a").is_err());
        fs::remove_file(t.base.join("outside/a")).unwrap();
        t.next_copy();
        t.check("scope/a").unwrap();
        if t.base.join("scope/A").exists() {
            t.check("scope/A").unwrap();
        }
    }

    /// Paths relative to an enrollment root of `/`.
    #[test]
    fn paths_beneath_the_root_directory_are_relative_to_it() {
        let names = ScopeNames::new(b"/".to_vec(), [(b"/data".to_vec(), true)]);
        assert_eq!(names.relative(b"/data/a"), Some(&b"data/a"[..]));
        assert_eq!(names.relative(b"/"), Some(&b""[..]));
        assert_eq!(names.scope_of(b"/data/a"), Some(&b"/data"[..]));
        assert_eq!(names.scope_of(b"/database/a"), None);
        let rooted = ScopeNames::new(b"/srv".to_vec(), [(b"/srv/data".to_vec(), true)]);
        assert_eq!(rooted.relative(b"/srv/data/a"), Some(&b"data/a"[..]));
        assert_eq!(rooted.relative(b"/srvdata/a"), None);
        assert_eq!(rooted.relative(b"/srv"), Some(&b""[..]));
        assert_eq!(
            rooted.absolute(&RelativePath::new(b"data/a").unwrap()),
            b"/srv/data/a"
        );
    }

    /// A held file whose name inside was removed keeps only its name
    /// outside: finishing it there must not change that file.
    #[test]
    fn removed_inside_name_must_not_allow_finishing_outside_basis() {
        finish_after(true, |base| fs::remove_file(base.join("scope/a")).unwrap());
    }

    /// A held file with one name, moved outside before its metadata is
    /// finished, is not changed there.
    #[test]
    fn moved_outside_basis_is_not_finished_there() {
        finish_after(false, |base| {
            fs::rename(base.join("scope/a"), base.join("outside/a")).unwrap()
        });
    }

    /// Hold `scope/a` (also linked as `outside/a` when `linked`) as a
    /// comparison basis, run `between`, then finish its metadata: that must
    /// fail and leave `outside/a` as it was.
    fn finish_after(linked: bool, between: impl Fn(&Path)) {
        use std::os::unix::fs::PermissionsExt;
        let temporary = crate::test_support::tempdir().unwrap();
        let base = temporary.path();
        let t = Fixture::new(base);
        fs::write(base.join("scope/a"), b"held").unwrap();
        fs::set_permissions(base.join("scope/a"), fs::Permissions::from_mode(0o600)).unwrap();
        if linked {
            fs::hard_link(base.join("scope/a"), base.join("outside/a")).unwrap();
        }
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
        between(base);
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

    fn status_kb(field: &str) -> u64 {
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .and_then(|value| value.trim().trim_end_matches(" kB").trim().parse().ok())
            .unwrap()
    }

    fn cpu_seconds() -> (f64, f64) {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        let usage = unsafe { usage.assume_init() };
        let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
        (seconds(usage.ru_utime), seconds(usage.ru_stime))
    }

    /// `entries` empty files in `scope`, 1,000 to a directory, one of them
    /// also linked as `d0000/linked`.
    pub(super) fn create_measured_tree(scope: &Path, entries: usize) {
        fs::create_dir(scope).unwrap();
        for index in 0..entries {
            let directory = scope.join(format!("d{:04}", index / 1000));
            if index % 1000 == 0 {
                fs::create_dir(&directory).unwrap();
            }
            File::create(directory.join(format!("f{index:07}"))).unwrap();
        }
        fs::hard_link(scope.join("d0000/f0000000"), scope.join("d0000/linked")).unwrap();
    }

    /// The tree `create_measured_tree` makes, at `SYQ_MEASURE_DIRECTORY`/scope
    /// with `SYQ_MEASURE_ENTRIES` entries. Run explicitly.
    #[test]
    #[ignore]
    fn create_measured_scope() {
        let base = PathBuf::from(std::env::var_os("SYQ_MEASURE_DIRECTORY").unwrap());
        let entries = std::env::var("SYQ_MEASURE_ENTRIES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(500_000);
        create_measured_tree(&base.join("scope"), entries);
    }

    /// The listing of an approved directory of `SYQ_MEASURE_ENTRIES` files
    /// (500,000 by default, 1,000 to a directory), which one file with two
    /// names among them makes the receiver read; and a check of a file with
    /// one name, which reads nothing. `SYQ_MEASURE_DIRECTORY` names a
    /// directory holding such a tree (`create_measured_scope`) to use
    /// instead. Run explicitly in a release build.
    #[test]
    #[ignore]
    fn measure_scope_listing() {
        let entries: usize = std::env::var("SYQ_MEASURE_ENTRIES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(500_000);
        let temporary = crate::test_support::tempdir().unwrap();
        let given = std::env::var_os("SYQ_MEASURE_DIRECTORY").map(PathBuf::from);
        let base = given.as_deref().unwrap_or(temporary.path());
        let scope = base.join("scope");
        if given.is_none() {
            create_measured_tree(&scope, entries);
        }
        let bytes = |path: &Path| path.as_os_str().as_bytes().to_vec();
        let names = ScopeNames::new(bytes(base), [(bytes(&scope), true)]);
        let root = Arc::new(Root::open(base).unwrap());
        let check = |name: &str| {
            let file = File::open(base.join(name)).unwrap();
            names.require_inside(
                &root,
                &RelativePath::new(name.as_bytes()).unwrap(),
                &base.join(name),
                &|| {
                    let metadata = file.metadata()?;
                    Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
                },
                None,
            )
        };
        let (rss, peak, (user, system)) = (status_kb("VmRSS:"), status_kb("VmHWM:"), cpu_seconds());
        let started = std::time::Instant::now();
        check("scope/d0001/f0001000").unwrap();
        assert!(names.listing.lock().unwrap().is_none());
        eprintln!(
            "MEASURE one-name check: {:.6}s, no listing, RSS {} kB before and {} kB after",
            started.elapsed().as_secs_f64(),
            rss,
            status_kb("VmRSS:"),
        );
        // The listing itself, as a check of a file with two names reads it.
        // Read directly, so that it is measured on filesystems that report
        // one link for every file too (SSHFS).
        let linked = fs::metadata(scope.join("d0000/linked")).unwrap().nlink() > 1;
        let started = std::time::Instant::now();
        let listing = names.list(&root);
        let (user_after, system_after) = cpu_seconds();
        eprintln!(
            "MEASURE listing {} directories: {:.3}s elapsed, {:.3}s user, {:.3}s system; peak RSS {} kB (before {} kB, peak before {} kB), RSS after {} kB; {} files with several links",
            fs::read_dir(&scope).unwrap().count(),
            started.elapsed().as_secs_f64(),
            user_after - user,
            system_after - system,
            status_kb("VmHWM:"),
            rss,
            peak,
            status_kb("VmRSS:"),
            listing.len(),
        );
        if linked {
            *names.listing.lock().unwrap() = Some(listing);
            let started = std::time::Instant::now();
            check("scope/d0000/f0000000").unwrap();
            check("scope/d0000/linked").unwrap();
            eprintln!(
                "MEASURE two checks after it: {:.6}s",
                started.elapsed().as_secs_f64()
            );
        } else {
            eprintln!("MEASURE this filesystem reports one link for every file");
        }
        let _ = entries;
    }
}
