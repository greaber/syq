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
//! Names are kept by a hash keyed at random for this process, so a sender
//! cannot choose a name that passes for another, 16 bytes a name. Beyond
//! `MAX_NAMES` nothing more is recorded, so a copy of many files holds the
//! rest to the grant as if the receiver had not looked.

use super::*;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

/// The most names recorded: as many as a table of 2^22 entries holds,
/// which takes 68 MiB (102 MiB while it last grows).
pub(crate) const MAX_NAMES: usize = (1 << 22) / 8 * 7;

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

pub(crate) struct PlanningLookups {
    recording: Recording,
    limit: usize,
    key: RandomState,
    names: Mutex<HashMap<u64, Looked>>,
}

impl PlanningLookups {
    pub(crate) fn new(recording: Recording) -> Self {
        Self::with_limit(recording, MAX_NAMES)
    }

    pub(crate) fn with_limit(recording: Recording, limit: usize) -> Self {
        Self {
            recording,
            limit,
            key: RandomState::new(),
            names: Mutex::new(HashMap::new()),
        }
    }

    fn key(&self, relative: &[u8]) -> u64 {
        self.key.hash_one(relative)
    }

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
    /// open. A name whose parent did not open is not recorded.
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
                let Some(dev) = *held
                    .dev
                    .get_or_init(|| held.directory.metadata().ok().map(|m| m.dev()))
                else {
                    return false;
                };
                root.profile_on(dev, &held.directory)
            }
        };
        self.needed_on(profile)
    }

    /// Record that `directory`, open at `relative` beneath `root`, was found
    /// empty or created by this receiver, where this copy needs it.
    pub(super) fn record_empty(&self, root: &Root, relative: &[u8], directory: &File) {
        if self.recording != Recording::Keep || relative.is_empty() {
            return;
        }
        let Ok(metadata) = directory.metadata() else {
            return;
        };
        if self.needed_on(root.profile_on(metadata.dev(), directory)) {
            self.record(relative, Looked::Empty);
        }
    }

    /// Record that this receiver created the directory at `relative`
    /// beneath `root`, where this copy needs it.
    pub(super) fn record_created_directory(&self, root: &Root, relative: &[u8]) {
        if self.recording != Recording::Keep {
            return;
        }
        let Ok(path) = RelativePath::new(relative) else {
            return;
        };
        if let Ok(directory) = root.open_directory(&path) {
            self.record_empty(root, relative, &directory);
        }
    }

    /// Record what a lookup of `relative`, beneath the destination root,
    /// found. A claimed name, and a directory found empty or created, keep
    /// what they hold. Past the limit, a name not yet recorded stays so.
    pub(crate) fn record(&self, relative: &[u8], looked: Looked) {
        let key = self.key(relative);
        let mut names = self.names.lock().unwrap();
        let full = names.len() >= self.limit;
        match names.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if !matches!(entry.get(), Looked::Claimed | Looked::Empty) {
                    entry.insert(looked);
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if !full {
                    entry.insert(looked);
                }
            }
        }
    }

    /// What the receiver found at `relative`, if it recorded it.
    pub(crate) fn get(&self, relative: &[u8]) -> Option<Looked> {
        let key = self.key(relative);
        self.names.lock().unwrap().get(&key).copied()
    }

    /// What the receiver found at `relative`, for a publication there,
    /// giving the name to that publication when it was found absent: by its
    /// own lookup, or because the nearest directory above it the record
    /// names was found missing or empty, or created by this receiver. The
    /// name is then `Claimed`; one that cannot be recorded is not given.
    pub(crate) fn claim(&self, relative: &[u8]) -> Claim {
        let key = self.key(relative);
        let mut names = self.names.lock().unwrap();
        match names.get(&key).copied() {
            Some(Looked::Absent) => {
                names.insert(key, Looked::Claimed);
                return Claim::Absent;
            }
            Some(Looked::Present { .. }) => return Claim::Present,
            Some(Looked::Claimed | Looked::Empty) => return Claim::Unknown,
            None if names.is_empty() => return Claim::Unknown,
            None => {}
        }
        let mut end = relative.len();
        while let Some(separator) = relative[..end].iter().rposition(|byte| *byte == b'/') {
            match names.get(&self.key(&relative[..separator])) {
                Some(Looked::Absent | Looked::Empty) if names.len() < self.limit => {
                    names.insert(key, Looked::Claimed);
                    return Claim::Absent;
                }
                Some(_) => return Claim::Unknown,
                None => end = separator,
            }
        }
        Claim::Unknown
    }

    /// Forget `relative`, once the grant deletes it.
    pub(crate) fn forget(&self, relative: &[u8]) {
        let key = self.key(relative);
        self.names.lock().unwrap().remove(&key);
    }

    /// How many names are recorded.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.names.lock().unwrap().len()
    }
}

impl FsOps {
    /// Record what this executor's lookups for the planner find in
    /// `lookups`, as a restricted receiver's authority asks.
    pub(crate) fn set_planning_lookups(&mut self, lookups: Option<Arc<PlanningLookups>>) {
        self.planning_lookups = lookups;
    }
}
