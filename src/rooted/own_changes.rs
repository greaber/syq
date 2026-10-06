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
//! time either unchanged or the one the change set. Changes recorded one
//! after another, each starting where the last ended, form a chain, kept as
//! the span of change times from the first one's start to the last one's
//! end. A pin holds while the change time it holds and the file's current
//! one both lie in the file's chain. One system call can move the change
//! time more than once, and a stat in between sees a time inside the span,
//! which is also only this receiver's doing. Any other change, from outside
//! this process or one that changed what a pin protects, is not recorded,
//! so the next recorded change starts a new chain, and pins from before
//! fail. A recorded change never changes the mode, owner or group, so a
//! mode chosen before it still matches the file after it.
//!
//! A change is observed from a stat taken just before it to one taken just
//! after it. Checks of the file wait meanwhile, and so do other recorded
//! changes of it. The window holds only those system calls. A change from
//! outside that lands within it and leaves the fields above as this change
//! would have (rewriting contents of the same size before the times are set,
//! or changing the mode and back) is taken for part of this change. It cannot
//! alter a chosen mode, and reused contents are hashed again before use.
//! Spans assume change times do not go back: should the clock be set back
//! during a copy, a change from outside could land inside a recorded span.
//!
//! The record is per process: every connection of a restricted copy is
//! served by the one receiver process that holds its grant, so changes made
//! for one worker are recorded for checks made for another. It holds one
//! span per file that had other names when changed under a pin, for at
//! least `KEPT` after the span last grew.

use super::RootMetadata;
use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// Recorded spans are kept at least this long after they last grow. A pin
/// lasts from a request's authorization to its execution; one that outlives
/// its record fails as if the file had changed, which is safe.
const KEPT: Duration = Duration::from_secs(10 * 60);
/// The ledger is pruned of spans older than `KEPT` once it holds this many,
/// and again each time it has doubled since.
const PRUNE_ABOVE: usize = 4096;

type ChangeTime = (i64, u32);

/// The change times a chain of recorded changes of one file spans, and
/// when it last grew.
struct Span {
    first: ChangeTime,
    last: ChangeTime,
    grown: Instant,
}

impl Span {
    fn holds(&self, time: ChangeTime) -> bool {
        self.first <= time && time <= self.last
    }
}

#[derive(Default)]
struct Ledger {
    /// The latest chain of recorded changes of each file, by device and
    /// inode.
    spans: HashMap<(u64, u64), Span>,
    /// How many spans the ledger may hold before it is pruned again.
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
pub(crate) fn pin_holds(dev: u64, ino: u64, pinned: ChangeTime, current: ChangeTime) -> bool {
    if pinned == current {
        return true;
    }
    let (ledger, changed) = ledger();
    let state = idle(ledger.lock().unwrap(), (dev, ino), changed);
    state
        .spans
        .get(&(dev, ino))
        .is_some_and(|span| span.holds(pinned) && span.holds(current))
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
        if state.spans.len() >= state.prune_above.max(PRUNE_ABOVE) {
            state
                .spans
                .retain(|_, span| now.duration_since(span.grown) < KEPT);
            state.prune_above = 2 * state.spans.len();
        }
        let from = (before.ctime, before.ctime_nsec);
        let to = (after.ctime, after.ctime_nsec);
        match state.spans.get_mut(&self.file) {
            // The change starts within the file's chain: it extends it.
            Some(span) if span.holds(from) => {
                span.last = span.last.max(to);
                span.grown = now;
            }
            // Something not recorded changed the file since: a new chain
            // starts, and pins from the last no longer hold.
            _ => {
                state.spans.insert(
                    self.file,
                    Span {
                        first: from.min(to),
                        last: from.max(to),
                        grown: now,
                    },
                );
            }
        }
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
        let kept = RootMetadata {
            mtime: 50,
            ..seen(ino, 3, 6)
        };
        change(seen(ino, 3, 5), kept, 0, Some(50));
        let replaced = RootMetadata {
            mtime: 50,
            ..seen(ino, 2, 7)
        };
        change(kept, replaced, 1, None);
        assert!(pin_holds(7, ino, (5, 0), (7, 0)));
        assert!(pin_holds(7, ino, (6, 0), (7, 0)));
        // A stat in the middle of a recorded change saw only its doing.
        assert!(pin_holds(7, ino, (5, 0), (6, 500)));
        assert!(pin_holds(7, ino, (6, 500), (7, 0)));
        // A change from outside breaks the chain, and a recorded change after
        // it starts a new one.
        change(seen(ino, 2, 8), seen(ino, 2, 9), 0, None);
        assert!(!pin_holds(7, ino, (5, 0), (9, 0)));
        assert!(!pin_holds(7, ino, (7, 0), (9, 0)));
        assert!(pin_holds(7, ino, (8, 0), (9, 0)));
        // Other files are not affected.
        assert!(!pin_holds(7, ino + 1, (8, 0), (9, 0)));
        assert!(!pin_holds(8, ino, (8, 0), (9, 0)));
    }

    #[test]
    fn a_change_that_did_more_than_itself_is_not_recorded() {
        let ino = 0x5157_0100;
        let before = seen(ino, 2, 10);
        let after = seen(ino, 2, 11);
        for (case, after, links, mtime) in [
            (
                "mode",
                RootMetadata {
                    mode: 0o100600,
                    ..after
                },
                0,
                None,
            ),
            ("owner", RootMetadata { uid: 9, ..after }, 0, None),
            ("group", RootMetadata { gid: 9, ..after }, 0, None),
            ("size", RootMetadata { len: 11, ..after }, 0, None),
            ("links", seen(ino, 1, 11), 0, None),
            ("last link", seen(ino, 1, 11), 2, None),
            ("time", RootMetadata { mtime: 70, ..after }, 0, Some(60)),
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
