//! On a network destination, a batch's new directories are created in small
//! requests sent back to back, and the files that go into each directory are
//! handed to workers as soon as its request has been answered
//! (`Planner::create_directories_streaming`). This module decides which
//! directories each request creates and how large the requests are.

use crate::proto::PathBytes;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Requests kept in flight. The control connection's reader queues this many
/// replies (`conn::reply_queue`), and the receiver this many requests, so
/// every reply can be written while more requests are sent: with more in
/// flight, large replies (many failures, say) could leave both ends waiting
/// to write.
pub(super) const REQUESTS_IN_FLIGHT: usize = crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH;

/// Directories a request creates in one parent at its smallest. A
/// filesystem creates names in one directory one at a time (on Linux each
/// creation holds the parent's lock), and the receiver runs at most two
/// creations in a parent at once.
const PER_PARENT: usize = 2;
/// Directories a request creates in all at its smallest: enough to keep the
/// receiver's metadata threads busy when they are spread over many parents.
const PER_REQUEST: usize = 64;
/// Requests grow by doubling up to this factor: 4,096 directories, 128 in
/// one parent, 64 levels deep.
const MAX_GROWTH: usize = 64;

/// The directories of one batch still to be created, by level: a directory
/// whose parent this batch also creates is one level below it.
///
/// A restricted receiver's new `--mapping` parents are created only where
/// nothing is (no-replace). The receiver runs a request's no-replace
/// creations first, all at once, and skips what lies beneath a failed one
/// only within that request. So a no-replace directory goes only once its
/// parent's creation has been answered, and nothing beneath one goes in a
/// later request until its reply has arrived.
pub(super) struct DirectoryQueue {
    levels: Vec<Level>,
    /// The first level with directories left.
    first: usize,
    /// The nearest of each directory's ancestors that this batch creates
    /// too. Those between them exist already: the scan found them.
    parent: Vec<Option<usize>>,
    /// Which directories are created only where nothing is.
    no_replace: Vec<bool>,
    /// Where each directory's creation stands.
    state: Vec<Creation>,
    /// Requests taken so far.
    requests: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Creation {
    Queued,
    /// Taken by this request, and not yet answered.
    Sent(usize),
    Answered,
}

#[derive(Default)]
struct Level {
    /// Each parent's directories, in batch order.
    parents: Vec<VecDeque<usize>>,
    remaining: usize,
}

impl DirectoryQueue {
    /// `paths[i]` is the destination path of the batch's `i`th new
    /// directory, and `no_replace[i]` whether it is created only where
    /// nothing is.
    pub(super) fn new(paths: &[&[u8]], no_replace: &[bool]) -> Self {
        let index: HashMap<&[u8], usize> = paths
            .iter()
            .enumerate()
            .map(|(i, path)| (*path, i))
            .collect();
        let parent: Vec<Option<usize>> = paths
            .iter()
            .map(|path| {
                let mut current: &[u8] = path;
                while let Some(above) = parent_of(current).filter(|above| *above != current) {
                    if let Some(&found) = index.get(above) {
                        return Some(found);
                    }
                    current = above;
                }
                None
            })
            .collect();
        // Ancestors have fewer components than their descendants, so this
        // order finds every parent's level before its children's.
        let mut order: Vec<usize> = (0..paths.len()).collect();
        order.sort_by_key(|&i| paths[i].iter().filter(|&&c| c == b'/').count());
        let mut level = vec![0usize; paths.len()];
        for &i in &order {
            if let Some(parent) = parent[i] {
                level[i] = level[parent] + 1;
            }
        }
        let depth = level.iter().max().map_or(0, |deepest| deepest + 1);
        let mut levels: Vec<Level> = (0..depth).map(|_| Level::default()).collect();
        let mut slots: Vec<HashMap<&[u8], usize>> = vec![HashMap::new(); depth];
        for (i, path) in paths.iter().enumerate() {
            let parent = parent_of(path).unwrap_or_default();
            let level_of = &mut levels[level[i]];
            let slot = *slots[level[i]].entry(parent).or_insert_with(|| {
                level_of.parents.push(VecDeque::new());
                level_of.parents.len() - 1
            });
            level_of.parents[slot].push_back(i);
            level_of.remaining += 1;
        }
        Self {
            levels,
            first: 0,
            parent,
            no_replace: no_replace.to_vec(),
            state: vec![Creation::Queued; paths.len()],
            requests: 0,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.first >= self.levels.len()
    }

    /// The next request's directories at `growth`: at most `PER_PARENT *
    /// growth` in one parent, `PER_REQUEST * growth` in all and `growth`
    /// levels deep, within `byte_limit` by `sizes` (each directory's share
    /// of the request). A deeper level joins only once the levels above it
    /// are all in this or an earlier request, so a directory is never
    /// created before its parent. The request ends before the first
    /// directory that must wait for an earlier request's reply
    /// (`DirectoryQueue`), which stays queued: it is empty when that is the
    /// next one.
    pub(super) fn next(&mut self, growth: usize, sizes: &[usize], byte_limit: usize) -> Vec<usize> {
        self.requests += 1;
        let request = self.requests;
        let total = PER_REQUEST * growth;
        let per_parent = PER_PARENT * growth;
        let mut chosen = Vec::new();
        let mut bytes = 0usize;
        let mut full = false;
        let mut level = self.first;
        while level < self.levels.len() && level < self.first + growth && !full {
            let current = &mut self.levels[level];
            for queue in &mut current.parents {
                let mut taken = 0;
                while taken < per_parent {
                    let Some(&index) = queue.front() else {
                        break;
                    };
                    if chosen.len() == total
                        || (!chosen.is_empty() && bytes.saturating_add(sizes[index]) > byte_limit)
                        || waits(&self.parent, &self.no_replace, &self.state, index, request)
                    {
                        full = true;
                        break;
                    }
                    queue.pop_front();
                    chosen.push(index);
                    self.state[index] = Creation::Sent(request);
                    bytes = bytes.saturating_add(sizes[index]);
                    taken += 1;
                    current.remaining -= 1;
                }
                if full {
                    break;
                }
            }
            current.parents.retain(|queue| !queue.is_empty());
            if current.remaining > 0 {
                break;
            }
            level += 1;
        }
        while self
            .levels
            .get(self.first)
            .is_some_and(|level| level.remaining == 0)
        {
            self.first += 1;
        }
        chosen
    }

    /// The creations of `indices` have been answered, or will not be sent.
    pub(super) fn answered(&mut self, indices: &[usize]) {
        for &index in indices {
            self.state[index] = Creation::Answered;
        }
    }
}

/// Whether directory `index` must wait for an earlier creation's reply
/// before request `request` may take it (`DirectoryQueue`).
fn waits(
    parent: &[Option<usize>],
    no_replace: &[bool],
    state: &[Creation],
    index: usize,
    request: usize,
) -> bool {
    if no_replace[index] && parent[index].is_some_and(|p| state[p] != Creation::Answered) {
        return true;
    }
    let mut ancestor = parent[index];
    while let Some(above) = ancestor {
        if no_replace[above] && matches!(state[above], Creation::Sent(sent) if sent != request) {
            return true;
        }
        ancestor = parent[above];
    }
    false
}

pub(super) fn parent_of(path: &[u8]) -> Option<&[u8]> {
    match path.iter().rposition(|&c| c == b'/') {
        Some(0) if path.len() > 1 => Some(b"/"),
        Some(0) | None => None,
        Some(position) => Some(&path[..position]),
    }
}

/// Whether `path` is one of `roots` or lies beneath one.
pub(super) fn beneath_any(path: &[u8], roots: &[PathBytes]) -> bool {
    roots.iter().any(|root| {
        path == root.as_slice() || (path.starts_with(root) && path.get(root.len()) == Some(&b'/'))
    })
}

/// The nearest of `path`'s ancestors that `index` holds.
pub(super) fn nearest_ancestor(path: &[u8], index: &HashMap<PathBytes, usize>) -> Option<usize> {
    let mut current = path;
    while let Some(parent) = parent_of(current) {
        if let Some(&found) = index.get(parent) {
            return Some(found);
        }
        current = parent;
    }
    None
}

/// The regular files a batch will queue once the directories still being
/// created exist, so that workers starting meanwhile start with the count
/// the whole batch calls for.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Anticipated {
    pub(super) files: usize,
    pub(super) bytes: u64,
    /// The largest of them, which decides whether all of them are small.
    pub(super) largest: u64,
    /// They are queued a few at a time, as their directories are created,
    /// rather than in bursts (`Pacing::link_bound`).
    pub(super) trickling: bool,
}

impl Anticipated {
    pub(super) fn add(&mut self, size: u64) {
        self.files += 1;
        self.bytes = self.bytes.saturating_add(size);
        self.largest = self.largest.max(size);
    }

    /// One of them was planned: queued, or found to need no copy.
    pub(super) fn remove(&mut self, size: u64) {
        self.files = self.files.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(size);
    }
}

/// How large directory requests are, kept across batches. They start small,
/// so the first files go out early, and double for each reply showing that
/// the receiver finished a request before the next reached it: over a slow
/// link to a fast filesystem, small requests would leave it waiting a round
/// trip for each. Where creating directories is what takes the time, as on
/// a slow filesystem, the receiver never waits and requests stay small.
#[derive(Debug)]
pub(super) struct Pacing {
    growth: usize,
    /// The shortest time from sending a request to its reply: about a round
    /// trip, plus the least time the receiver took over one.
    floor: Option<Duration>,
}

impl Default for Pacing {
    fn default() -> Self {
        Self {
            growth: 1,
            floor: None,
        }
    }
}

impl Pacing {
    pub(super) fn growth(&self) -> usize {
        self.growth
    }

    /// A request sent at `sent` began to be answered at `arrival`; the one
    /// before it in the same batch at `previous`.
    pub(super) fn observe(&mut self, sent: Instant, arrival: Instant, previous: Option<Instant>) {
        let latency = arrival.saturating_duration_since(sent);
        let floor = *self
            .floor
            .insert(self.floor.map_or(latency, |floor| floor.min(latency)));
        let Some(previous) = previous else {
            return;
        };
        // Sent less than about half a round trip before the previous reply
        // began: the receiver had finished that request, and so had nothing
        // to do, before this one reached it. Or answered so soon after the
        // previous one that the requests in flight take the receiver less
        // than a round trip: it will wait for the next ones. Each such reply
        // doubles the size, those of requests sent before the last doubling
        // included, so a slow link costs a round trip or two, not one for
        // each doubling.
        let waited = previous.saturating_duration_since(sent) < floor / 2;
        let outpaces =
            arrival.saturating_duration_since(previous) < floor / (REQUESTS_IN_FLIGHT as u32 + 1);
        if waited || outpaces {
            self.growth = (self.growth * 2).min(MAX_GROWTH);
        }
    }

    /// Requests have grown: the link, not creating directories, takes the
    /// time, so a batch's files come in bursts rather than a few at a time.
    pub(super) fn link_bound(&self) -> bool {
        self.growth > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queued(paths: &[&str]) -> (DirectoryQueue, Vec<usize>) {
        queued_no_replace(paths, &[])
    }

    /// The directories of `paths` named in `no_replace` are created only
    /// where nothing is.
    fn queued_no_replace(paths: &[&str], no_replace: &[&str]) -> (DirectoryQueue, Vec<usize>) {
        let flags: Vec<bool> = paths.iter().map(|path| no_replace.contains(path)).collect();
        let paths: Vec<&[u8]> = paths.iter().map(|path| path.as_bytes()).collect();
        (DirectoryQueue::new(&paths, &flags), vec![100; paths.len()])
    }

    fn drain(queue: &mut DirectoryQueue, sizes: &[usize], growth: usize) -> Vec<Vec<usize>> {
        let mut requests = Vec::new();
        while !queue.is_empty() {
            let request = queue.next(growth, sizes, usize::MAX);
            assert!(!request.is_empty(), "a request creates something");
            requests.push(request);
        }
        requests
    }

    #[test]
    fn directories_in_one_parent_go_two_at_a_time() {
        let paths: Vec<String> = (0..5).map(|i| format!("/d/{i}")).collect();
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        let (mut queue, sizes) = queued(&paths);
        assert_eq!(
            drain(&mut queue, &sizes, 1),
            vec![vec![0, 1], vec![2, 3], vec![4]]
        );
    }

    #[test]
    fn a_request_spans_parents_but_not_levels() {
        // Two parents created by this batch, each with three children.
        let (mut queue, sizes) = queued(&[
            "/d/a", "/d/a/1", "/d/a/2", "/d/a/3", "/d/b", "/d/b/1", "/d/b/2", "/d/b/3",
        ]);
        assert_eq!(
            drain(&mut queue, &sizes, 1),
            vec![vec![0, 4], vec![1, 2, 5, 6], vec![3, 7]]
        );
    }

    #[test]
    fn children_never_go_before_their_parents() {
        // Listed child first: levels still put the parent ahead.
        let (mut queue, sizes) = queued(&["/d/a/b/c", "/d/a/b", "/d/a", "/d/x"]);
        let requests = drain(&mut queue, &sizes, 1);
        assert_eq!(requests, vec![vec![2, 3], vec![1], vec![0]]);
        // Grown requests may hold several levels, still parents first.
        let (mut queue, sizes) = queued(&["/d/a/b/c", "/d/a/b", "/d/a", "/d/x"]);
        assert_eq!(drain(&mut queue, &sizes, 4), vec![vec![2, 3, 1, 0]]);
    }

    #[test]
    fn a_deeper_level_waits_until_the_one_above_is_sent() {
        // Three directories in one parent and a child of the first: at growth
        // 2 the first request takes all three (four per parent), then the child.
        let (mut queue, sizes) = queued(&["/d/a", "/d/b", "/d/c", "/d/a/x"]);
        assert_eq!(drain(&mut queue, &sizes, 2), vec![vec![0, 1, 2, 3]]);
        // At growth 1 the level is not finished by the first request, so the
        // child waits for the level to be sent.
        let (mut queue, sizes) = queued(&["/d/a", "/d/b", "/d/c", "/d/a/x"]);
        assert_eq!(
            drain(&mut queue, &sizes, 1),
            vec![vec![0, 1], vec![2], vec![3]]
        );
    }

    #[test]
    fn requests_respect_their_total_and_byte_limits() {
        let paths: Vec<String> = (0..200).map(|i| format!("/d/{i}/x")).collect();
        let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
        let (mut queue, sizes) = queued(&paths);
        let requests = drain(&mut queue, &sizes, 1);
        assert_eq!(
            requests.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![64, 64, 64, 8]
        );
        let (mut queue, sizes) = queued(&paths);
        assert_eq!(queue.next(1, &sizes, 250).len(), 2);
        // One directory goes alone even past the limit.
        assert_eq!(queue.next(1, &sizes, 50).len(), 1);
    }

    #[test]
    fn no_replace_creations_wait_only_for_the_creations_they_depend_on() {
        // A restricted receiver's new mapping parents in one existing
        // directory depend on none of each other: requests keep coming while
        // earlier ones are unanswered.
        let siblings: Vec<String> = (0..8).map(|i| format!("/d/{i}")).collect();
        let mut paths: Vec<&str> = siblings.iter().map(String::as_str).collect();
        paths.extend(["/d/7/child", "/d/7/child/grandchild"]);
        let (mut queue, sizes) = queued_no_replace(&paths, &paths);
        let mut sent = Vec::new();
        for expected in [[0, 1], [2, 3], [4, 5], [6, 7]] {
            let request = queue.next(1, &sizes, usize::MAX);
            assert_eq!(request, expected);
            sent.extend(request);
        }
        // A child waits for its parent's reply.
        assert!(queue.next(1, &sizes, usize::MAX).is_empty());
        queue.answered(&sent);
        // Grown requests span levels, but never take a no-replace directory
        // with its parent: the receiver would create both at once.
        assert_eq!(queue.next(8, &sizes, usize::MAX), vec![8]);
        assert!(queue.next(8, &sizes, usize::MAX).is_empty());
        queue.answered(&[8]);
        assert_eq!(queue.next(8, &sizes, usize::MAX), vec![9]);
        assert!(queue.is_empty());

        // Nor with a parent created as usual, which the receiver creates
        // after its no-replace creations.
        let (mut queue, sizes) = queued_no_replace(&["/d/a", "/d/a/b"], &["/d/a/b"]);
        assert_eq!(queue.next(4, &sizes, usize::MAX), vec![0]);
        assert!(queue.next(4, &sizes, usize::MAX).is_empty());
        queue.answered(&[0]);
        assert_eq!(queue.next(4, &sizes, usize::MAX), vec![1]);

        // What is created as usual beneath a no-replace directory may go in
        // its request, where the receiver skips it if that creation fails,
        // but not in a later one before its reply, nor deeper beneath.
        let paths = ["/d/a", "/d/a/x", "/d/a/x/y", "/d/b"];
        let (mut queue, sizes) = queued_no_replace(&paths, &["/d/a"]);
        assert_eq!(queue.next(2, &sizes, usize::MAX), vec![0, 3, 1]);
        assert!(queue.next(2, &sizes, usize::MAX).is_empty());
        queue.answered(&[0, 3, 1]);
        assert_eq!(queue.next(2, &sizes, usize::MAX), vec![2]);
        let (mut queue, sizes) = queued_no_replace(&paths, &["/d/a"]);
        assert_eq!(queue.next(1, &sizes, usize::MAX), vec![0, 3]);
        assert!(queue.next(1, &sizes, usize::MAX).is_empty());
        queue.answered(&[0, 3]);
        assert_eq!(queue.next(4, &sizes, usize::MAX), vec![1, 2]);

        // A directory the scan found between two new ones, say made by
        // another process meanwhile, does not hide the one above it.
        let (mut queue, sizes) =
            queued_no_replace(&["/d/a", "/d/x", "/d/a/b/c"], &["/d/a", "/d/x", "/d/a/b/c"]);
        assert_eq!(queue.next(2, &sizes, usize::MAX), vec![0, 1]);
        assert!(queue.next(2, &sizes, usize::MAX).is_empty());
        queue.answered(&[0, 1]);
        assert_eq!(queue.next(2, &sizes, usize::MAX), vec![2]);

        // A request ends at the first directory that waits.
        let (mut queue, sizes) =
            queued_no_replace(&["/d/a", "/d/b", "/d/a/x", "/d/b/x"], &["/d/b/x"]);
        assert_eq!(queue.next(4, &sizes, usize::MAX), vec![0, 1, 2]);
    }

    #[test]
    fn nearest_ancestor_finds_the_closest_new_directory() {
        let index: HashMap<PathBytes, usize> =
            [(b"/d/a".to_vec(), 0), (b"/d/a/b".to_vec(), 1)].into();
        assert_eq!(nearest_ancestor(b"/d/a/b/c/file", &index), Some(1));
        assert_eq!(nearest_ancestor(b"/d/a/file", &index), Some(0));
        assert_eq!(nearest_ancestor(b"/d/file", &index), None);
        assert_eq!(parent_of(b"/file"), Some(&b"/"[..]));
        let failed = vec![b"/d/new".to_vec()];
        assert!(beneath_any(b"/d/new", &failed));
        assert!(beneath_any(b"/d/new/a/b", &failed));
        assert!(!beneath_any(b"/d/newer", &failed));
        assert!(!beneath_any(b"/d", &failed));
        assert_eq!(parent_of(b"/"), None);
    }

    #[test]
    fn requests_grow_only_when_the_receiver_waited() {
        let start = Instant::now();
        let ms = Duration::from_millis;
        let mut pacing = Pacing::default();
        // A local receiver on a slow filesystem: the request after the first
        // window was sent long before the previous reply came back, and
        // replies come as far apart as a request takes.
        pacing.observe(start, start + ms(200), None);
        pacing.observe(start, start + ms(400), Some(start + ms(200)));
        pacing.observe(start, start + ms(600), Some(start + ms(400)));
        pacing.observe(start + ms(200), start + ms(1000), Some(start + ms(800)));
        assert_eq!(pacing.growth(), 1);
        assert!(!pacing.link_bound());
        // A slow link to a fast filesystem: the first replies come back
        // together a round trip after their requests, so the requests in
        // flight take the receiver far less than a round trip.
        let mut pacing = Pacing::default();
        pacing.observe(start, start + ms(61), None);
        assert_eq!(pacing.growth(), 1);
        pacing.observe(start, start + ms(62), Some(start + ms(61)));
        assert_eq!(pacing.growth(), 2);
        assert!(pacing.link_bound());
        // A request sent as those replies came back reached a receiver that
        // had nothing to do, though its reply was not soon after the last.
        pacing.observe(start + ms(61), start + ms(150), Some(start + ms(80)));
        assert_eq!(pacing.growth(), 4);
        for step in 0..10 {
            let sent = start + ms(200 + step);
            pacing.observe(sent, sent + ms(61), Some(sent + ms(1)));
        }
        assert_eq!(pacing.growth(), MAX_GROWTH);
    }
}
