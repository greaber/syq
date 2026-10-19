//! What a restricted receiver found when it looked names up for its
//! planner (`Request::StatMany`, and `Request::PlanBatch` without strict
//! metadata), kept so that its authority can hold a file's publication to
//! the grant without looking again.
//!
//! The record is kept only where the filesystem cannot hold a publication
//! to the grant for free. Without a no-replace rename, a copy that keeps
//! existing files must otherwise link each new file into place; without an
//! exchange, a copy that replaces only existing files must otherwise look
//! each one up. A name the receiver found absent can then be renamed into
//! place, once, and one it found present replaced, with no second trip to
//! the server. Another program that creates or removes the name in between
//! is the accepted race, as for an ordinary copy. Only the receiver's own
//! answers are recorded, never what the sender says about a name.
//!
//! Names are kept by a hash keyed at random for this process, so a sender
//! cannot choose a name that passes for another.

use super::*;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

/// What the receiver found at a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Looked {
    /// No entry, in a directory that exists.
    Absent,
    /// An entry, with a regular file's permission bits.
    Present { file_mode: Option<u32> },
    /// Found absent, and since given to one publication: another is held
    /// to the grant as if the receiver had not looked.
    Claimed,
}

/// Which names a copy records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recording {
    /// Keeping existing files: names found absent, and names found present,
    /// in directories on filesystems without a no-replace rename.
    Keep,
    /// Replacing only existing files: regular files found, in directories
    /// on filesystems without an exchange.
    Existing,
}

pub(crate) struct PlanningLookups {
    recording: Recording,
    key: RandomState,
    names: Mutex<HashMap<u64, Looked>>,
}

impl PlanningLookups {
    pub(crate) fn new(recording: Recording) -> Self {
        Self {
            recording,
            key: RandomState::new(),
            names: Mutex::new(HashMap::new()),
        }
    }

    fn key(&self, relative: &[u8]) -> u64 {
        self.key.hash_one(relative)
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
        match self.recording {
            Recording::Keep => !profile.atomic_no_replace_rename,
            Recording::Existing => !profile.exchange,
        }
    }

    /// Record what a lookup of `relative`, beneath the destination root,
    /// found. A claimed name stays claimed.
    pub(crate) fn record(&self, relative: &[u8], looked: Looked) {
        let key = self.key(relative);
        let mut names = self.names.lock().unwrap();
        let entry = names.entry(key).or_insert(looked);
        if *entry != Looked::Claimed {
            *entry = looked;
        }
    }

    /// What the receiver found at `relative`, if it looked.
    pub(crate) fn get(&self, relative: &[u8]) -> Option<Looked> {
        let key = self.key(relative);
        self.names.lock().unwrap().get(&key).copied()
    }

    /// What the receiver found at `relative`, giving a name it found
    /// absent to the publication that asks: it is then `Claimed`.
    pub(crate) fn claim(&self, relative: &[u8]) -> Option<Looked> {
        let key = self.key(relative);
        let mut names = self.names.lock().unwrap();
        let looked = names.get_mut(&key)?;
        let found = *looked;
        if found == Looked::Absent {
            *looked = Looked::Claimed;
        }
        Some(found)
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
