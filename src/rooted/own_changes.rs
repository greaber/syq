//! Changes this process made itself to files that other names share.
//!
//! A command-restricted receiver that chooses a replaced file's mode from
//! the file it replaces pins that file to its change time when it authorizes
//! the request (`TargetCondition::MatchesFingerprint`), so that the mode it
//! chose still applies when the request is carried out. Keeping or replacing
//! one name of a hard-linked file changes the change time all its names
//! share, so the pins of its other names, authorized before, would no longer
//! match, although nothing but this receiver changed the file. That held for
//! the other names in the same request and for those other workers had in
//! flight; a replaced name then failed to publish.
//!
//! Such a change of a file with other names is therefore recorded here, by
//! device and inode, when the file it left behind differs only as the change
//! itself implies: the same identity, mode, ownership and size, the link
//! count lowered only by the links the change removed, and the modification
//! time either unchanged or the one the change set. A pin then holds for a
//! change time reached from it through recorded changes alone. Any other
//! change, from outside this process or one that changed what a pin protects,
//! breaks that chain, and the pin no longer holds. A recorded change never
//! changes the mode, owner or group, so a mode chosen before it still matches
//! the file after it.
//!
//! A change is observed from a stat taken just before it to one taken just
//! after it. Checks of the file wait meanwhile, and so do other recorded
//! changes of it. The window holds only those system calls. A change from
//! outside that lands within it and leaves the fields above as this change
//! would have (rewriting contents of the same size before the times are set,
//! or changing the mode and back) is taken for part of this change. It cannot
//! alter a chosen mode, and reused contents are hashed again before use.
//!
//! The record is per process: every connection of a restricted copy is
//! served by the one receiver process that holds its grant, so changes made
//! for one worker are recorded for checks made for another. It holds two
//! change times per recorded change for at least `KEPT`, and only for files
//! that had other names when changed under a pin.

use super::RootMetadata;
use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// Recorded change times are kept at least this long. A pin lasts from a
/// request's authorization to its execution; one that outlives its record
/// fails as if the file had changed, which is safe.
const KEPT: Duration = Duration::from_secs(10 * 60);
/// The ledger is pruned of records older than `KEPT` once it holds this many,
/// and again each time it has doubled since.
const PRUNE_ABOVE: usize = 4096;

#[derive(Default)]
struct Ledger {
    /// Each recorded change time of a file, by device, inode and change
    /// time: the chain of recorded changes it belongs to, and when it was
    /// recorded.
    chains: HashMap<(u64, u64, i64, u32), (u64, Instant)>,
    next_chain: u64,
    /// How many records the ledger may hold before it is pruned again.
    prune_above: usize,
    /// Files with a change in progress.
    busy: HashSet<(u64, u64)>,
}

fn ledger() -> &'static (Mutex<Ledger>, Condvar) {
    static LEDGER: OnceLock<(Mutex<Ledger>, Condvar)> = OnceLock::new();
    LEDGER.get_or_init(Default::default)
}

/// Wait until no recorded change of the file is in progress.
fn idle<'a>(
    mut state: MutexGuard<'a, Ledger>,
    file: (u64, u64),
    changed: &Condvar,
) -> MutexGuard<'a, Ledger> {
    while state.busy.contains(&file) {
        state = changed.wait(state).unwrap();
    }
    state
}

/// Whether a pin of the file `dev`/`ino` at change time `pinned` still
/// holds for the file found at change time `current`: it has not changed, or
/// only through changes recorded here.
pub(crate) fn pin_holds(dev: u64, ino: u64, pinned: (i64, u32), current: (i64, u32)) -> bool {
    if pinned == current {
        return true;
    }
    let (ledger, changed) = ledger();
    let state = idle(ledger.lock().unwrap(), (dev, ino), changed);
    let chain = |(ctime, nanoseconds): (i64, u32)| {
        state
            .chains
            .get(&(dev, ino, ctime, nanoseconds))
            .map(|(chain, _)| *chain)
    };
    matches!((chain(pinned), chain(current)), (Some(a), Some(b)) if a == b)
}

/// A change in progress of a file other names may share. Checks of the file,
/// and other changes of it, wait until it is finished or dropped.
pub(crate) struct OwnChange {
    file: (u64, u64),
}

/// Begin a change of the file `seen` describes, if it has other names, after
/// any change of it already in progress. Stat the file again before the
/// change and after it, and `finish` with both.
pub(crate) fn begin(seen: &RootMetadata) -> Option<OwnChange> {
    if seen.nlink <= 1 {
        return None;
    }
    let file = (seen.dev, seen.ino);
    let (ledger, changed) = ledger();
    let mut state = idle(ledger.lock().unwrap(), file, changed);
    state.busy.insert(file);
    Some(OwnChange { file })
}

impl OwnChange {
    /// Record the change from `before` to `after`, if `after` differs from
    /// `before` only as a change removing `links` links and leaving the
    /// modification time unchanged or at `mtime` would make it.
    pub(crate) fn finish(
        self,
        before: &RootMetadata,
        after: &RootMetadata,
        links: u64,
        mtime: Option<i64>,
    ) {
        if !consistent(self.file, before, after, links, mtime) {
            return;
        }
        let (ledger, _) = ledger();
        let mut state = ledger.lock().unwrap();
        let now = Instant::now();
        if state.chains.len() >= state.prune_above.max(PRUNE_ABOVE) {
            state
                .chains
                .retain(|_, (_, recorded)| now.duration_since(*recorded) < KEPT);
            state.prune_above = 2 * state.chains.len();
        }
        let (dev, ino) = self.file;
        let from = (dev, ino, before.ctime, before.ctime_nsec);
        let chain = match state.chains.get(&from) {
            Some(&(chain, _)) => chain,
            None => {
                let chain = state.next_chain;
                state.next_chain += 1;
                chain
            }
        };
        state.chains.insert(from, (chain, now));
        state
            .chains
            .insert((dev, ino, after.ctime, after.ctime_nsec), (chain, now));
    }
}

impl Drop for OwnChange {
    fn drop(&mut self) {
        let (ledger, changed) = ledger();
        ledger.lock().unwrap().busy.remove(&self.file);
        changed.notify_all();
    }
}

/// Whether `after` is `before` changed only as a change of `file` removing
/// `links` links, and leaving the modification time unchanged or at the
/// second `mtime`, makes it: anything else changed it from outside.
fn consistent(
    file: (u64, u64),
    before: &RootMetadata,
    after: &RootMetadata,
    links: u64,
    mtime: Option<i64>,
) -> bool {
    (before.dev, before.ino) == file
        && (after.dev, after.ino) == file
        && after.nlink.checked_add(links) == Some(before.nlink)
        && after.nlink >= 1
        && (after.mode, after.uid, after.gid, after.len)
            == (before.mode, before.uid, before.gid, before.len)
        && ((after.mtime, after.mtime_nsec) == (before.mtime, before.mtime_nsec)
            || mtime == Some(after.mtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(ino: u64, nlink: u64, ctime: i64) -> RootMetadata {
        RootMetadata {
            dev: 7,
            ino,
            mode: 0o100644,
            nlink,
            len: 10,
            mtime: 100,
            mtime_nsec: 0,
            atime: Default::default(),
            ctime,
            ctime_nsec: 0,
            uid: 1,
            gid: 2,
            rdev: 0,
        }
    }

    fn change(before: RootMetadata, after: RootMetadata, links: u64, mtime: Option<i64>) {
        begin(&before)
            .expect("a file with other names")
            .finish(&before, &after, links, mtime);
    }

    #[test]
    fn a_pin_holds_through_recorded_changes_only() {
        // Inodes of their own, apart from other tests sharing the ledger.
        let ino = 0x5157_0001;
        assert!(pin_holds(7, ino, (5, 0), (5, 0)));
        assert!(!pin_holds(7, ino, (5, 0), (6, 0)));
        // Keeping one name sets its time; replacing another removes a link.
        change(
            seen(ino, 3, 5),
            RootMetadata {
                mtime: 50,
                ..seen(ino, 3, 6)
            },
            0,
            Some(50),
        );
        change(
            RootMetadata {
                mtime: 50,
                ..seen(ino, 3, 6)
            },
            RootMetadata {
                mtime: 50,
                ..seen(ino, 2, 7)
            },
            1,
            None,
        );
        assert!(pin_holds(7, ino, (5, 0), (7, 0)));
        assert!(pin_holds(7, ino, (6, 0), (7, 0)));
        // A change from outside breaks the chain, and a recorded change after
        // it starts a new one.
        change(seen(ino, 2, 8), seen(ino, 2, 9), 0, None);
        assert!(!pin_holds(7, ino, (5, 0), (9, 0)));
        assert!(pin_holds(7, ino, (8, 0), (9, 0)));
        // Other files are not affected.
        assert!(!pin_holds(7, ino + 1, (5, 0), (7, 0)));
        assert!(!pin_holds(8, ino, (5, 0), (7, 0)));
    }

    #[test]
    fn a_change_that_did_more_than_itself_is_not_recorded() {
        let ino = 0x5157_0100;
        let before = seen(ino, 2, 10);
        for (case, after, links, mtime) in [
            (
                "mode",
                RootMetadata {
                    mode: 0o100600,
                    ..seen(ino, 2, 11)
                },
                0,
                None,
            ),
            (
                "owner",
                RootMetadata {
                    uid: 9,
                    ..seen(ino, 2, 11)
                },
                0,
                None,
            ),
            (
                "group",
                RootMetadata {
                    gid: 9,
                    ..seen(ino, 2, 11)
                },
                0,
                None,
            ),
            (
                "size",
                RootMetadata {
                    len: 11,
                    ..seen(ino, 2, 11)
                },
                0,
                None,
            ),
            ("links", seen(ino, 1, 11), 0, None),
            ("last link", seen(ino, 1, 11), 2, None),
            (
                "time",
                RootMetadata {
                    mtime: 70,
                    ..seen(ino, 2, 11)
                },
                0,
                Some(60),
            ),
            ("inode", seen(ino + 1, 2, 11), 0, None),
        ] {
            change(before, after, links, mtime);
            assert!(!pin_holds(7, ino, (10, 0), (11, 0)), "{case}");
        }
        // The file was last seen without other names: nothing to record.
        assert!(begin(&seen(ino, 1, 10)).is_none());
    }

    #[test]
    fn checks_wait_for_a_change_in_progress() {
        let ino = 0x5157_0200;
        let before = seen(ino, 2, 20);
        let change = begin(&before).unwrap();
        std::thread::scope(|scope| {
            let check = scope.spawn(|| pin_holds(7, ino, (20, 0), (21, 0)));
            std::thread::sleep(Duration::from_millis(50));
            assert!(!check.is_finished());
            change.finish(&before, &seen(ino, 2, 21), 0, None);
            assert!(check.join().unwrap());
        });
    }
}
