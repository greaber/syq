//! A grant that keeps existing objects lets a restricted receiver replace a
//! file or change metadata only at a name this grant created. The one step
//! that could bring an existing file under such a name is a hard link to
//! it, so under such a grant a hard link may give a new name only to a file
//! this receiver created for the grant. The receiver records those files
//! here by device and inode, read from the file it just created or
//! published.
//!
//! Checking the link's identity before linking needs no lock held across
//! the link. The publication links only the file with that identity: on
//! Linux through the descriptor it opened and checked, elsewhere checking
//! the new link before publishing it. Nor can any other step such a grant
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
}
