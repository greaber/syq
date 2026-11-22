//! What a restricted receiver found when it looked names up for its
//! planner (`Request::StatMany`, and `Request::PlanBatch` without strict
//! metadata), and the directories it found empty or created, kept so that
//! its authority can hold a file's publication to the grant without looking
//! again.
//!
//! The record is kept only where the filesystem cannot hold a publication
//! to the grant for free. Without a no-replace rename, a copy that keeps
//! existing files must otherwise link each new file into place; without an
//! exchange, a copy that replaces only existing files must otherwise look
//! each one up. A name the receiver found absent, or one beneath a
//! directory it found missing or empty or created itself, can then be
//! renamed into place, once, and a file it found present replaced, with no
//! second trip to the server. Another program that creates or removes the
//! name in between is the accepted race, as for an ordinary copy. Only the
//! receiver's own answers are recorded, never what the sender says about a
//! name.
//!
//! The record compares exact Unix path bytes. Both the number of entries and
//! the total bytes of their keys are bounded. Beyond either budget, publication
//! uses the same checks as a name the receiver never looked up.

use super::*;
use std::hash::{BuildHasher, RandomState};
use std::sync::RwLock;

const MAX_NAMES: usize = 1 << 20;
const MAX_PATH_BYTES: usize = 32 << 20;

#[derive(Default)]
struct Names<S> {
    entries: HashMap<Box<[u8]>, Looked, S>,
    path_bytes: usize,
}

impl<S: BuildHasher> Names<S> {
    /// Called only for a name known to be vacant under the write lock.
    fn insert(&mut self, path: &[u8], looked: Looked, limit: usize) -> bool {
        if self.entries.len() >= limit || path.len() > MAX_PATH_BYTES - self.path_bytes {
            return false;
        }
        self.entries.insert(path.into(), looked);
        self.path_bytes += path.len();
        true
    }
}

/// What the receiver found at a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Looked {
    /// No entry, in a directory that exists.
    Absent,
    /// An entry, with a regular file's permission bits.
    Present { file_mode: Option<u32> },
    /// A directory the receiver found empty or created: nothing beneath it
    /// was there then. Later lookups do not change it.
    Empty,
    /// Found absent, and since given to one publication: another is held
    /// to the grant as if the receiver had not looked. Later lookups do not
    /// change it.
    Claimed,
}

/// Which names a copy records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recording {
    /// Keeping existing files: names found absent and names found present,
    /// and directories found empty or created, on filesystems without a
    /// no-replace rename.
    Keep,
    /// Replacing only existing files: regular files found, on filesystems
    /// without an exchange.
    Existing,
}

/// What `PlanningLookups::claim` found for a publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Claim {
    /// Found absent, itself or by a directory above it, and now given to
    /// this publication.
    Absent,
    /// Found present.
    Present,
    /// Not known, or already given to another publication.
    Unknown,
}

pub(crate) struct PlanningLookups<S = RandomState> {
    recording: Recording,
    limit: usize,
    names: RwLock<Names<S>>,
}

impl PlanningLookups {
    pub(crate) fn new(recording: Recording) -> Self {
        Self::with_limit(recording, MAX_NAMES)
    }

    pub(crate) fn with_limit(recording: Recording, limit: usize) -> Self {
        Self {
            recording,
            limit,
            names: RwLock::default(),
        }
    }
}
impl<S: BuildHasher> PlanningLookups<S> {
    /// Whether a filesystem with `profile` needs this copy's record.
    fn needed_on(&self, profile: Profile) -> bool {
        match self.recording {
            Recording::Keep => !profile.atomic_no_replace_rename,
            Recording::Existing => !profile.exchange,
        }
    }

    /// Look `path` up for the planner, as `stat_with_parent` does, and
    /// record what was found where this copy needs it.
    pub(super) fn look_up(
        &self,
        root: &Arc<Root>,
        parent: &mut Option<HeldMetadataParent>,
        path: &[u8],
    ) -> Option<Entry> {
        let found = lookup_with_parent(root, parent, path);
        let looked = match (&found, self.recording) {
            (Lookup::Missing, Recording::Keep) => Some(Looked::Absent),
            (Lookup::Found(entry), Recording::Keep) => Some(Looked::Present {
                file_mode: (entry.kind == Kind::File).then_some(entry.mode & 0o7777),
            }),
            (Lookup::Found(entry), Recording::Existing) if entry.kind == Kind::File => {
                Some(Looked::Present {
                    file_mode: Some(entry.mode & 0o7777),
                })
            }
            _ => None,
        };
        if let Some(looked) = looked.filter(|_| self.needed_for(root, parent.as_ref(), path)) {
            self.record(path, looked);
        }
        match found {
            Lookup::Found(entry) => Some(entry),
            Lookup::Missing | Lookup::Unknown => None,
        }
    }

    /// Whether the directory holding `path` is on a filesystem where this
    /// copy's publications need the record: a name directly beneath the
    /// root is in the root, and any other in the parent `look_up` held
    /// open, judged by that parent's own device, where the name is
    /// published; an entry found there can be another filesystem mounted
    /// on it. A name whose parent did not open is not recorded.
    fn needed_for(
        &self,
        root: &Arc<Root>,
        parent: Option<&HeldMetadataParent>,
        path: &[u8],
    ) -> bool {
        let profile = match path.iter().rposition(|byte| *byte == b'/') {
            None => root.profile(),
            Some(separator) => {
                let Some(held) = parent
                    .filter(|held| Arc::ptr_eq(&held.root, root) && held.path == path[..separator])
                else {
                    return false;
                };
                let Some(dev) = *held.dev.get_or_init(|| cached_device(&held.directory)) else {
                    return false;
                };
                root.profile_on(dev, &held.directory)
            }
        };
        self.needed_on(profile)
    }

    /// Record that the directory at `relative` beneath `root` (the root
    /// itself when empty) was found empty or created by this receiver,
    /// where this copy needs it: `directory` is it, or the directory it was
    /// made in, on the same filesystem.
    pub(super) fn record_empty(&self, root: &Root, relative: &[u8], directory: &File) {
        if self.recording != Recording::Keep {
            return;
        }
        let Some(dev) = cached_device(directory) else {
            return;
        };
        if self.needed_on(root.profile_on(dev, directory)) {
            self.record(relative, Looked::Empty);
        }
    }

    /// Record what a lookup of `relative`, beneath the destination root,
    /// found. A claimed name, and a directory found empty or created, keep
    /// what they hold. Past the limit, a name not yet recorded stays so.
    pub(crate) fn record(&self, relative: &[u8], looked: Looked) {
        let mut names = self.names.write().unwrap();
        match names.entries.get_mut(relative) {
            Some(Looked::Claimed | Looked::Empty) => {}
            Some(previous) => *previous = looked,
            None => {
                names.insert(relative, looked, self.limit);
            }
        }
    }

    /// What the receiver found at `relative`, if it recorded it.
    pub(crate) fn get(&self, relative: &[u8]) -> Option<Looked> {
        self.names.read().unwrap().entries.get(relative).copied()
    }

    /// What the receiver found at `relative`, for a publication there,
    /// giving the name to that publication when it was found absent: by its
    /// own lookup, or because the nearest directory above it the record
    /// names, the root last, was found missing or empty, or created by this
    /// receiver. The name is then `Claimed`; one that cannot be recorded is
    /// not given.
    pub(crate) fn claim(&self, relative: &[u8]) -> Claim {
        let claim = self.claim_name(relative);
        // Tests count what the record gave each publication.
        #[cfg(debug_assertions)]
        let _ = record_test_event("SYQ_TEST_PUBLICATION_CLAIMS", format_args!("{claim:?}"));
        claim
    }

    fn claim_name(&self, relative: &[u8]) -> Claim {
        let mut names = self.names.write().unwrap();
        if names.entries.is_empty() {
            return Claim::Unknown;
        }
        match names.entries.get_mut(relative) {
            Some(state @ Looked::Absent) => {
                *state = Looked::Claimed;
                return Claim::Absent;
            }
            Some(Looked::Present { .. }) => return Claim::Present,
            Some(Looked::Claimed | Looked::Empty) => return Claim::Unknown,
            None => {}
        }
        let mut end = relative.len();
        loop {
            let separator = relative[..end].iter().rposition(|byte| *byte == b'/');
            let above = &relative[..separator.unwrap_or(0)];
            match names.entries.get(above) {
                Some(Looked::Absent | Looked::Empty) => {
                    return if names.insert(relative, Looked::Claimed, self.limit) {
                        Claim::Absent
                    } else {
                        Claim::Unknown
                    };
                }
                Some(_) => return Claim::Unknown,
                None => match separator {
                    Some(separator) => end = separator,
                    None => return Claim::Unknown,
                },
            }
        }
    }

    /// Forget `relative`, once the grant deletes it.
    pub(crate) fn forget(&self, relative: &[u8]) {
        let mut names = self.names.write().unwrap();
        if names.entries.remove(relative).is_some() {
            names.path_bytes -= relative.len();
        }
    }

    /// How many names are recorded.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.names.read().unwrap().entries.len()
    }
}

/// The device `file` is on, from what the kernel already holds: on NFS a
/// plain `fstat` can ask the server for fresh attributes, which the device
/// needs none of.
pub(crate) fn cached_device(file: &File) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::statx(
                file.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
                0,
                stat.as_mut_ptr(),
            )
        };
        if result != 0 {
            return None;
        }
        let stat = unsafe { stat.assume_init() };
        Some(libc::makedev(stat.stx_dev_major, stat.stx_dev_minor))
    }
    #[cfg(not(target_os = "linux"))]
    {
        file.metadata().ok().map(|metadata| metadata.dev())
    }
}

impl FsOps {
    /// Record what this executor's lookups for the planner find in
    /// `lookups`, as a restricted receiver's authority asks.
    pub(crate) fn set_planning_lookups(&mut self, lookups: Option<Arc<PlanningLookups>>) {
        self.planning_lookups = lookups;
    }

    /// The destination directories this executor has listed before its
    /// lookups, or found it need not list. Another executor for the same
    /// destination given them with `settle_listings` does not list them
    /// again.
    pub(crate) fn settled_listings(&self) -> Vec<PathBytes> {
        #[cfg(target_os = "linux")]
        return self
            .listing_requests
            .iter()
            .filter(|(_, asked)| asked.is_none())
            .map(|(directory, _)| directory.clone())
            .collect();
        #[cfg(not(target_os = "linux"))]
        Vec::new()
    }

    /// Treat `directories` of the destination as listed already.
    pub(crate) fn settle_listings(&mut self, directories: &[PathBytes]) {
        #[cfg(target_os = "linux")]
        for directory in directories {
            self.listing_requests.insert(directory.clone(), None);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = directories;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colliding_names_have_independent_authority() {
        #[derive(Default)]
        struct ConstantHash;
        impl std::hash::Hasher for ConstantHash {
            fn write(&mut self, _: &[u8]) {}
            fn finish(&self) -> u64 {
                0
            }
        }
        let lookups = PlanningLookups::<std::hash::BuildHasherDefault<ConstantHash>> {
            recording: Recording::Keep,
            limit: 10,
            names: RwLock::default(),
        };
        lookups.record(b"missing", Looked::Absent);
        lookups.record(b"dir", Looked::Empty);
        assert_eq!(lookups.claim(b"unknown"), Claim::Unknown);
        assert_eq!(lookups.claim(b"dir/file"), Claim::Absent);
        lookups.forget(b"other");
        assert_eq!(lookups.claim(b"missing"), Claim::Absent);
        assert_eq!(lookups.claim(b"dir/file"), Claim::Unknown);
    }

    #[test]
    fn exact_path_claims_respect_component_boundaries_and_the_byte_budget() {
        let lookups = PlanningLookups::new(Recording::Keep);
        lookups.record(b"a/\xff", Looked::Empty);
        assert_eq!(lookups.claim(b"a/\xffx/file"), Claim::Unknown);
        assert_eq!(lookups.claim(b"a/\xff/file"), Claim::Absent);
        assert_eq!(lookups.claim(b"a/\xff/file"), Claim::Unknown);

        // Model the last few bytes of the budget without a large allocation.
        lookups.names.write().unwrap().path_bytes = MAX_PATH_BYTES - 2;
        lookups.record(b"ab", Looked::Absent);
        assert_eq!(lookups.claim(b"a/\xff/new"), Claim::Unknown);
        lookups.forget(b"aa");
        lookups.record(b"aa", Looked::Absent);
        assert_eq!(lookups.claim(b"aa"), Claim::Unknown);
        lookups.forget(b"ab");
        lookups.record(b"aa", Looked::Absent);
        assert_eq!(lookups.claim(b"aa"), Claim::Absent);
    }

    #[test]
    fn the_cached_device_is_the_files_own() {
        let directory = crate::test_support::tempdir().unwrap();
        let file = File::open(directory.path()).unwrap();
        assert_eq!(cached_device(&file), Some(file.metadata().unwrap().dev()));
    }
}
