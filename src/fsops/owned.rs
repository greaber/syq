//! A copy that keeps existing files lets a receiver replace a file or
//! change metadata only at a name the copy created. The one step
//! that could bring an existing file under such a name is a hard link to
//! it, so under such a grant a hard link may give a new name only to a file
//! this receiver created for the grant. The receiver records those files
//! here by device and inode, read from the file it just created or
//! published, and only when the grant copies hard links.
//!
//! Checking the link's identity before linking needs no lock held across
//! the link. The publication links only the file with that identity: on
//! Linux through the descriptor it opened and checked, elsewhere checking
//! the new link before publishing it. Both checks compare inode numbers, so
//! where a filesystem's numbers cannot show which file a name leads to
//! (`fsops::Profile::link_counts_trusted`), the link is refused. Nor can any other step such a grant
//! permits make a name lead to an existing file: the names of existing
//! objects are never replaced, existing objects are never renamed, and
//! every link leads to a recorded file. A name this grant created therefore
//! leads only to an object it created whenever a change through it runs,
//! so changes run exactly as on any receiver.
//!
//! An existing file's inode is in use for as long as the file exists, so its
//! number cannot be given to another file while the copy runs. Only files
//! this grant created can leave numbers to reuse, so a number in this
//! record names, at worst, a newer file, never one the grant keeps.

use super::*;
use std::collections::HashSet;

/// The files each copy that keeps existing files created in this process,
/// by the copy's scope (`stages::new_scope`): every connection of an
/// ordinary copy shares them, as a restricted receiver's connections share
/// their authority's.
fn shared() -> &'static Mutex<HashMap<u64, Arc<OwnedObjects>>> {
    static SHARED: OnceLock<Mutex<HashMap<u64, Arc<OwnedObjects>>>> = OnceLock::new();
    SHARED.get_or_init(Default::default)
}

/// Forget the files the copy `scope` created, when its control ends.
pub(crate) fn release(scope: u64) {
    shared().lock().unwrap().remove(&scope);
}

#[derive(Default)]
pub(crate) struct OwnedObjects(Mutex<HashSet<(u64, u64)>>);

impl OwnedObjects {
    /// Remember the file `created` describes, which this receiver created.
    pub(crate) fn record(&self, created: &fs::Metadata) {
        self.0
            .lock()
            .unwrap()
            .insert((created.dev(), created.ino()));
    }

    /// Refuse the hard link `label` to the file `identity` unless this
    /// receiver created that file for this grant.
    pub(crate) fn require_link(&self, identity: (u64, u64), label: &Path) -> Result<()> {
        if self.0.lock().unwrap().contains(&identity) {
            return Ok(());
        }
        bail!(
            "hard link {} would give a new name to a file this copy did not create, \
             and it keeps existing files",
            label.display()
        )
    }
}

impl FsOps {
    /// Give new names by hard link only to the files recorded in `owned`,
    /// as a grant that keeps existing objects requires.
    pub(crate) fn set_owned_objects(&mut self, owned: Option<Arc<OwnedObjects>>) {
        self.owned = owned;
    }

    /// Give new names by hard link only to the files this copy created, as
    /// a copy that keeps existing files and copies hard links does on every
    /// receiver. A restricted receiver's authority may already have set
    /// them; that stays.
    pub(super) fn keep_links_to_own_files(&mut self) {
        if self.owned.is_none() {
            self.owned = Some(
                shared()
                    .lock()
                    .unwrap()
                    .entry(self.stage_scope)
                    .or_default()
                    .clone(),
            );
        }
    }
}
