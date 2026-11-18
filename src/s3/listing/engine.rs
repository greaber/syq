//! Prefix-directed discovery inspired by s3glob v0.4.17:
//! https://github.com/quodlibetor/s3glob/blob/v0.4.17/src/glob_matcher.rs
//! This implementation uses bounded page-sized work and the listing command's
//! own pattern semantics; no upstream source is copied.
use super::pattern::Pattern;
use anyhow::{ensure, Result};
use futures_util::{stream::FuturesUnordered, StreamExt};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
};

const MAX_CHILDREN: usize = 256;
const SPLIT_QUEUE_LIMIT: usize = 4096;
/// Keys in a full ListObjectsV2 page.
const PAGE: usize = 1000;
// A recursive listing hands parts of its keys to further listings that run at
// the same time. Each of those, and each request for a directory's children
// to choose them from, can be a request the sequential listing would not have
// made. It may make this many once it is known to need a third page, and one
// more for every `PAGES_PER_EXTRA` pages of keys listed, so a listing never
// costs more than a fixed share over its sequential pages.
const EXTRA_REQUESTS: usize = 2;
const PAGES_PER_EXTRA: usize = 4;
// A first page with this many keys in one directory asks for the children a
// page sooner: such a directory is unlikely to be the listing's last.
const DENSE_DIRECTORY: usize = 256;
// Directories are handed to another listing only while those not yet handed
// over are expected to hold twice this many pages.
const PART_PAGES: usize = 4;
// A listing that shows two dense directories within three pages, under a
// prefix with at most this many children, lists every remaining child at
// once. Unfiltered listings did so before parts existed and keep that start.
const BURST_CHILDREN: usize = 64;
const BURST_PAGES: usize = 3;

#[derive(Clone, Debug, Serialize)]
pub(in crate::s3) struct Entry {
    pub key: String,
    pub size: u64,
    /// Seconds and nanoseconds since the Unix epoch.
    #[serde(serialize_with = "serialize_time")]
    pub last_modified: Option<(i64, u32)>,
    pub etag: Option<String>,
}

fn serialize_time<S: serde::Serializer>(
    time: &Option<(i64, u32)>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match time {
        Some((secs, nanos)) => serializer.serialize_str(
            &aws_smithy_types::DateTime::from_secs_and_nanos(*secs, *nanos)
                .fmt(aws_smithy_types::date_time::Format::DateTime)
                .map_err(serde::ser::Error::custom)?,
        ),
        None => serializer.serialize_none(),
    }
}

/// Directories to skip while listing, such as subtrees a copy ignores.
pub(in crate::s3) struct Prune<'a> {
    /// The byte length of the topmost pruned directory containing `key`, or
    /// of `key` itself when it names a directory (a common prefix or a marker).
    pub subtree: &'a (dyn Fn(&str, bool) -> Option<usize> + Sync),
    /// Delimiter requests left for looking past a first page in which every
    /// object lies in a pruned directory. Shared by the whole enumeration.
    pub probes: AtomicUsize,
}
impl Prune<'_> {
    fn take_probe(&self) -> bool {
        self.probes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok()
    }
}

#[derive(Default)]
pub(in crate::s3) struct Page {
    pub entries: Vec<Entry>,
    pub prefixes: Vec<String>,
    pub next: Option<String>,
}

pub(in crate::s3) trait Store {
    fn ordered(&self) -> bool {
        true
    }

    fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> impl Future<Output = Result<Page>>;
}

// A task can make more than one request at a time; bound actual HTTP requests
// as well as task count, including with an explicit limit of two.
struct LimitedStore<'a, S> {
    inner: &'a S,
    slots: tokio::sync::Semaphore,
}
impl<S: Store> Store for LimitedStore<'_, S> {
    fn ordered(&self) -> bool {
        self.inner.ordered()
    }
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        let _permit = self.slots.acquire().await?;
        self.inner.page(prefix, delimiter, token, start_after).await
    }
}

/// Keys arrived out of order after part of a listing was handed to other
/// listings, so the listing may have stopped before its last key. A listing
/// with a concurrency of one hands nothing over and does not depend on the
/// order.
#[derive(Debug)]
pub(in crate::s3) struct Unordered;
impl std::fmt::Display for Unordered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "S3 listing returned keys out of order; a listing with a concurrency of 1 does not rely on the order",
        )
    }
}
impl std::error::Error for Unordered {}

#[derive(Clone)]
enum Job {
    Discover {
        prefix: String,
        component: usize,
    },
    Scan {
        prefix: String,
        delimiter: bool,
        token: Option<String>,
    },
    /// The first page of everything under a prefix.
    Recursive {
        prefix: String,
    },
    /// A later page of a walk's listing, or the first page of one of its parts.
    Keys {
        walk: usize,
        part: usize,
        prefix: String,
        token: Option<String>,
    },
    /// One page of a directory's children, to choose parts from.
    Children {
        walk: usize,
        part: usize,
        directory: String,
        token: Option<String>,
    },
}

struct Batch {
    entries: Vec<Entry>,
    jobs: Vec<Job>,
    pruned: Vec<String>,
}

enum Done {
    Batch(Batch),
    First {
        prefix: String,
        page: Page,
    },
    Keys {
        walk: usize,
        part: usize,
        page: Page,
    },
    Children {
        walk: usize,
        part: usize,
        directory: String,
        page: Page,
    },
}

fn scan_batch(prefix: String, delimiter: bool, page: Page) -> Done {
    Done::Batch(Batch {
        entries: page.entries,
        jobs: page
            .next
            .map(|token| Job::Scan {
                prefix,
                delimiter,
                token: Some(token),
            })
            .into_iter()
            .collect(),
        pruned: Vec::new(),
    })
}

pub(in crate::s3) async fn read(
    store: &impl Store,
    prefix: &str,
    delimiter: bool,
    token: Option<&str>,
) -> Result<Page> {
    // The engine starts every listing at its prefix. Other listings of the
    // same store start after a key.
    let page = store.page(prefix, delimiter, token, None).await?;
    ensure!(
        page.entries.len() + page.prefixes.len() <= PAGE,
        "S3 listing exceeded the requested page size"
    );
    ensure!(
        page.next
            .as_deref()
            .is_none_or(|next| !next.is_empty() && Some(next) != token),
        "S3 listing returned an invalid continuation token"
    );
    for entry in &page.entries {
        ensure!(
            entry.key.starts_with(prefix),
            "S3 listing returned a key outside the requested prefix"
        );
    }
    for child in &page.prefixes {
        ensure!(
            delimiter
                && child.starts_with(prefix)
                && child.len() > prefix.len()
                && child.ends_with('/'),
            "S3 listing returned an invalid common prefix"
        );
    }
    Ok(page)
}

async fn execute(
    store: &impl Store,
    pattern: Option<&Pattern>,
    prune: Option<&Prune<'_>>,
    job: Job,
    split: bool,
) -> Result<Done> {
    let (mut prefix, mut component) = match job {
        Job::Recursive { prefix } => return recursive(store, prune, prefix).await,
        Job::Keys {
            walk,
            part,
            prefix,
            token,
        } => {
            let page = read(store, &prefix, false, token.as_deref()).await?;
            return Ok(Done::Keys { walk, part, page });
        }
        Job::Children {
            walk,
            part,
            directory,
            token,
        } => {
            let page = read(store, &directory, true, token.as_deref()).await?;
            return Ok(Done::Children {
                walk,
                part,
                directory,
                page,
            });
        }
        Job::Scan {
            prefix,
            delimiter,
            token,
        } => {
            let page = read(store, &prefix, delimiter, token.as_deref()).await?;
            return Ok(scan_batch(prefix, delimiter, page));
        }
        Job::Discover { prefix, component } => (prefix, component),
    };
    let pattern = pattern.expect("discovery jobs require a pattern");
    // Literal intermediate components need no existence probes: the eventual
    // LIST establishes whether the narrowed prefix exists.
    while component + 1 < pattern.components.len() {
        if !pattern.components[component].literal() {
            break;
        }
        prefix.push_str(&pattern.components[component].literal_prefix());
        prefix.push('/');
        component += 1;
    }
    let part = &pattern.components[component];
    let query = format!("{prefix}{}", part.literal_prefix());
    if part.recursive() {
        return recursive(store, None, query).await;
    }
    if !split && component + 1 < pattern.components.len() {
        let page = read(store, &query, false, None).await?;
        return Ok(scan_batch(query, false, page));
    }
    let page = read(store, &query, true, None).await?;
    if component + 1 == pattern.components.len() {
        return Ok(scan_batch(query, true, page));
    }
    if page.next.is_some() || page.prefixes.len() > MAX_CHILDREN {
        let flat = read(store, &query, false, None).await?;
        return Ok(scan_batch(query, false, flat));
    }
    Ok(Done::Batch(Batch {
        entries: page.entries,
        jobs: page
            .prefixes
            .into_iter()
            .filter(|child| {
                let segment = child
                    .strip_prefix(&prefix)
                    .unwrap()
                    .strip_suffix('/')
                    .unwrap();
                !segment.contains('/') && part.matches(segment)
            })
            .map(|prefix| Job::Discover {
                prefix,
                component: component + 1,
            })
            .collect(),
        pruned: Vec::new(),
    }))
}

/// Keys on a page in each directory directly under `prefix`.
fn directories<'a>(prefix: &str, page: &'a Page, counts: &mut HashMap<&'a str, usize>) {
    for entry in &page.entries {
        if let Some(slash) = entry.key[prefix.len()..].find('/') {
            *counts
                .entry(&entry.key[..prefix.len() + slash + 1])
                .or_default() += 1;
        }
    }
}

/// When every object on a truncated first page, apart from directory markers,
/// lies in a pruned directory, list directories instead, so that the pruned
/// ones need not be enumerated.
/// Follow a single unpruned child at most as deep as the probe budget allows.
/// Returns `None` when probing was not tried or did not pay off.
async fn lookahead(
    store: &impl Store,
    prune: &Prune<'_>,
    query: &str,
    flat: &Page,
) -> Result<Option<Batch>> {
    let budget = prune.probes.load(Ordering::Relaxed);
    let mut reachable = false;
    if budget == 0
        || flat.next.is_none()
        || flat.entries.is_empty()
        || !flat.entries.iter().all(|entry| {
            let directory = entry.size == 0 && entry.key.ends_with('/');
            match (prune.subtree)(&entry.key, directory) {
                Some(boundary) => {
                    reachable |= entry.key[..boundary]
                        .strip_prefix(query)
                        .is_some_and(|relative| relative.matches('/').count() < budget);
                    true
                }
                // A kept directory's marker sorts before the pruned objects
                // under it; the directory listing returns it again.
                None => directory,
            }
        })
        || !reachable
    {
        return Ok(None);
    }
    let mut probe = query.to_owned();
    let mut parents = Vec::new();
    while prune.take_probe() {
        let page = read(store, &probe, true, None).await?;
        let (pruned, included): (Vec<_>, Vec<_>) = page
            .prefixes
            .into_iter()
            .partition(|child| (prune.subtree)(child, true).is_some());
        if page.next.is_some() || included.len() > 1 {
            break;
        }
        parents.extend(page.entries);
        if !pruned.is_empty() {
            // Objects at the visited levels and the pruned and remaining
            // children together replace the flat sample.
            return Ok(Some(Batch {
                entries: parents,
                jobs: included
                    .into_iter()
                    .map(|prefix| Job::Recursive { prefix })
                    .collect(),
                pruned,
            }));
        }
        let Some(child) = included.into_iter().next() else {
            break;
        };
        // The sampled objects all lie in pruned directories under this one
        // child. Follow it rather than refetching the flat sample per level.
        probe = child;
    }
    Ok(None)
}

async fn recursive(store: &impl Store, prune: Option<&Prune<'_>>, prefix: String) -> Result<Done> {
    let page = read(store, &prefix, false, None).await?;
    if let Some(prune) = prune {
        if let Some(batch) = lookahead(store, prune, &prefix, &page).await? {
            return Ok(Done::Batch(batch));
        }
    }
    Ok(Done::First { prefix, page })
}

/// Where a part stands with the children of the directory it is in.
enum Children {
    Unlisted,
    /// A page is on its way.
    Asked,
    /// Pages so far end at a continuation token.
    More(String),
    Complete,
    /// Nothing further to hand over from this part.
    Closed,
}

/// One listing of a walk: every key under `prefix`, page after page, up to
/// the first key that belongs to a part handed over.
struct Part {
    prefix: String,
    /// Keys with no slash after this many bytes are objects of a directory
    /// whose own listing reports them.
    above: Option<usize>,
    done: bool,
    /// The first and last key of the latest page.
    first: String,
    last: String,
    dense: bool,
    /// The first key that belongs to another part.
    stop: Option<String>,
    /// The directory whose children the part is working through, and how
    /// many pages and children of it the listing has reached.
    directory: String,
    pages: usize,
    reached: usize,
    children: Children,
    /// Children after the listing's position not yet handed over, in order,
    /// and where the latest page of them ended.
    ahead: VecDeque<String>,
    listed: String,
    /// Objects of the directories listed so far that sort after the
    /// listing's position, in order. Those past `stop` are reported when it
    /// is set; the listing itself reaches the others.
    objects: Vec<Entry>,
    /// Hand over each child by itself, whatever its size.
    burst: bool,
}

impl Part {
    fn new(prefix: String, above: Option<usize>) -> Self {
        Self {
            directory: prefix.clone(),
            prefix,
            above,
            done: false,
            first: String::new(),
            last: String::new(),
            dense: false,
            stop: None,
            pages: 0,
            reached: 0,
            children: Children::Unlisted,
            ahead: VecDeque::new(),
            listed: String::new(),
            objects: Vec::new(),
            burst: false,
        }
    }

    /// The child of the directory that holds the last key, or the key itself
    /// when it is one of the directory's own objects. `None` once the listing
    /// has left the directory.
    fn inside(&self) -> Option<&str> {
        let rest = self.last.strip_prefix(self.directory.as_str())?;
        Some(match rest.find('/') {
            Some(slash) => &self.last[..self.directory.len() + slash + 1],
            None => &self.last,
        })
    }

    /// Drop the children and objects the listing has reached.
    fn advance(&mut self) {
        while let Some(child) = self.ahead.front() {
            if child.as_str() > self.last.as_str() && !self.last.starts_with(child.as_str()) {
                break;
            }
            self.ahead.pop_front();
            self.reached += 1;
        }
        let reached = self.objects.partition_point(|entry| entry.key <= self.last);
        self.objects.drain(..reached);
    }

    /// Pages the children ahead are expected to hold, taking each to be as
    /// large as those the listing has reached.
    fn expected(&self) -> usize {
        self.ahead.len() * self.pages / self.reached.max(1)
    }
}

/// The shortest start of `name` that the item the listing is inside, and so
/// every key before it, does not share: the names it covers are all ahead.
pub(super) fn block(inside: &str, name: &str) -> String {
    let mut shared = inside
        .bytes()
        .zip(name.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    while !name.is_char_boundary(shared) {
        shared -= 1;
    }
    let next = name[shared..].chars().next().map_or(0, char::len_utf8);
    name[..shared + next].to_owned()
}

/// Everything under a prefix that needs more than one page.
///
/// One request after another lists the keys in order. To finish sooner, the
/// walk asks for the children of the directory the listing is in and hands
/// the last of them to listings of their own, which run at the same time.
/// Each of those lists a prefix that the directories before it do not share
/// (`block`), so it covers whole directories and ends where they end; the
/// first listing stops at the first key handed over. No key is reported
/// twice, and a listing is cut short only where it has handed the rest over:
/// some servers go on reading a listing that is abandoned, so cutting many
/// short would cost them far more than the keys are worth.
///
/// A part is a walk in small: it can hand over its own children the same way.
/// When a directory has no children left to hand over, the listing asks for
/// those of the child it is inside.
///
/// A listing relies on keys arriving in order to know where to stop, as
/// general purpose buckets list them. Each page is checked against the one
/// before. The parts rely on the children listing naming every directory.
struct Walk {
    parts: Vec<Part>,
    /// Keys listed, which earn the extra requests.
    keys: usize,
    /// Extra requests made: child listings and parts started.
    spent: usize,
    /// Whether the walk may still make extra requests.
    dividing: bool,
    /// Keys in each child of the prefix on the first pages, until the burst
    /// is decided, and whether the prefix has few enough children for one.
    sample: Option<HashMap<String, usize>>,
    narrow: Option<bool>,
    /// Extra requests granted at once.
    burst: usize,
}

impl Walk {
    fn new(prefix: String, dividing: bool, burst: bool) -> Self {
        Self {
            parts: vec![Part::new(prefix, None)],
            keys: 0,
            spent: 0,
            dividing,
            sample: burst.then(HashMap::new),
            narrow: None,
            burst: 0,
        }
    }

    /// Take a page of a part's keys. Returns the keys that belong to it and
    /// the request for its next page.
    fn keys(&mut self, id: usize, at: usize, mut page: Page) -> Result<(Vec<Entry>, Option<Job>)> {
        let part = &mut self.parts[at];
        let mut before = part.last.as_str();
        let mut ordered = true;
        for entry in &page.entries {
            ordered &= entry.key.as_str() > before;
            before = &entry.key;
        }
        if !ordered {
            if part.stop.is_some() {
                return Err(Unordered.into());
            }
            // Nothing depends on the order yet, and nothing will.
            self.dividing = false;
        }
        let mut finished = page.next.is_none();
        if let Some(stop) = &part.stop {
            let within = page.entries.partition_point(|entry| entry.key < *stop);
            if within < page.entries.len() {
                page.entries.truncate(within);
                finished = true;
            }
        }
        self.keys += page.entries.len();
        if part.pages == 0 {
            let mut counts = HashMap::new();
            directories(&part.prefix, &page, &mut counts);
            part.dense = counts.values().any(|keys| *keys >= DENSE_DIRECTORY);
        }
        if at == 0 {
            if let Some(sample) = &mut self.sample {
                let mut counts = HashMap::new();
                directories(&part.prefix, &page, &mut counts);
                for (directory, keys) in counts {
                    *sample.entry(directory.to_owned()).or_default() += keys;
                }
            }
        }
        if let (Some(first), Some(last)) = (page.entries.first(), page.entries.last()) {
            part.first.clone_from(&first.key);
            part.last.clone_from(&last.key);
        }
        if let Some(above) = part.above {
            page.entries
                .retain(|entry| entry.key[above..].contains('/'));
        }
        part.pages += 1;
        if finished {
            part.done = true;
            part.ahead = VecDeque::new();
            part.objects = Vec::new();
            return Ok((page.entries, None));
        }
        part.advance();
        let job = Job::Keys {
            walk: id,
            part: at,
            prefix: part.prefix.clone(),
            token: page.next,
        };
        Ok((page.entries, Some(job)))
    }

    /// Take a page of the children of the directory a part is in.
    fn children(&mut self, at: usize, directory: &str, page: Page) {
        let part = &mut self.parts[at];
        if part.done || part.directory != directory || !matches!(part.children, Children::Asked) {
            return;
        }
        let mut before = part.listed.as_str();
        let mut ordered = true;
        for child in &page.prefixes {
            ordered &= child.as_str() > before;
            before = child;
        }
        if !ordered {
            // The children are of no use out of order. Parts already handed
            // over do not depend on them.
            part.children = Children::Closed;
            return;
        }
        if at == 0 && self.narrow.is_none() {
            self.narrow =
                Some(page.next.is_none() && (2..=BURST_CHILDREN).contains(&page.prefixes.len()));
        }
        if let Some(last) = page.prefixes.last() {
            part.listed.clone_from(last);
        }
        part.ahead.extend(page.prefixes);
        let above = part.above;
        part.objects.extend(
            page.entries
                .into_iter()
                .filter(|entry| above.is_none_or(|above| entry.key[above..].contains('/'))),
        );
        part.objects.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        part.advance();
        part.children = match page.next {
            // Children the listing has already passed are too small to be
            // worth a request for every thousand of them.
            Some(_) if part.ahead.is_empty() && part.listed < part.last => Children::Closed,
            Some(token) => Children::More(token),
            None => Children::Complete,
        };
    }

    fn allowance(&self) -> usize {
        let pages = self.keys / PAGE;
        if pages < 2 && !self.parts[0].dense {
            return 0;
        }
        EXTRA_REQUESTS + pages / PAGES_PER_EXTRA + self.burst
    }

    /// Grant the burst once the first pages and the prefix's children say
    /// whether it applies.
    fn decide_burst(&mut self) {
        let (Some(sample), Some(narrow)) = (&self.sample, self.narrow) else {
            return;
        };
        let dense = sample
            .values()
            .filter(|keys| **keys >= DENSE_DIRECTORY)
            .count();
        if narrow && dense >= 2 {
            self.burst = self.parts[0].ahead.len();
            self.parts[0].burst = true;
        } else if narrow && self.parts[0].pages < BURST_PAGES {
            return;
        }
        self.sample = None;
    }

    /// Queue the extra requests the walk has earned and has room for.
    /// Objects past a part handed over, and pruned directories left out, are
    /// added to `entries` and `pruned`.
    fn divide(
        &mut self,
        id: usize,
        mut room: usize,
        prune: Option<&Prune<'_>>,
        jobs: &mut VecDeque<Job>,
        entries: &mut Vec<Entry>,
        pruned: &mut Vec<String>,
    ) {
        self.decide_burst();
        let mut at = 0;
        while self.dividing && at < self.parts.len() {
            if let Some(prune) = prune {
                self.leave_out(at, prune, entries, pruned);
            }
            if room == 0 || self.spent >= self.allowance() {
                at += 1;
                continue;
            }
            match self.step(id, at, entries) {
                Some(job) => {
                    self.spent += 1;
                    room -= 1;
                    jobs.push_back(job);
                }
                None => at += 1,
            }
        }
    }

    /// Stop a part's listing short of pruned directories at its end: nothing
    /// needs to list them.
    fn leave_out(
        &mut self,
        at: usize,
        prune: &Prune<'_>,
        entries: &mut Vec<Entry>,
        pruned: &mut Vec<String>,
    ) {
        let part = &mut self.parts[at];
        if part.done || !matches!(part.children, Children::Complete) {
            return;
        }
        while let Some(child) = part.ahead.pop_back() {
            if (prune.subtree)(&child, true).is_none() {
                part.ahead.push_back(child);
                break;
            }
            let past = part.objects.partition_point(|entry| entry.key < child);
            entries.extend(part.objects.drain(past..));
            part.stop = Some(child.clone());
            pruned.push(child);
        }
    }

    /// The next extra request for a part, if one is worth making.
    fn step(&mut self, id: usize, at: usize, entries: &mut Vec<Entry>) -> Option<Job> {
        let part = &mut self.parts[at];
        if part.done {
            return None;
        }
        let children = |part: &mut Part, token| {
            part.children = Children::Asked;
            Some(Job::Children {
                walk: id,
                part: at,
                directory: part.directory.clone(),
                token,
            })
        };
        match std::mem::replace(&mut part.children, Children::Closed) {
            Children::Unlisted if part.dense || part.pages >= 2 => children(part, None),
            Children::More(token) => children(part, Some(token)),
            Children::Complete => {
                part.children = Children::Complete;
                let inside = part.inside()?.to_owned();
                let Some(name) = part.ahead.back() else {
                    // Nothing left to hand over here. Look inside the child
                    // the listing is in, if it holds the whole latest page.
                    if !inside.ends_with('/')
                        || inside.len() <= part.directory.len()
                        || !part.first.starts_with(&inside)
                    {
                        return None;
                    }
                    part.directory = inside;
                    part.pages = 1;
                    part.reached = 1;
                    part.burst = false;
                    part.listed.clear();
                    return children(part, None);
                };
                // Small directories are not worth a request each. Leave them
                // to the listing unless enough of them remain.
                if !part.burst && part.expected() < 2 * PART_PAGES {
                    return None;
                }
                let prefix = if part.burst {
                    name.clone()
                } else {
                    block(&inside, name)
                };
                let from = part
                    .ahead
                    .iter()
                    .rposition(|name| !name.starts_with(&prefix))
                    .map_or(0, |before| before + 1);
                let names = part.ahead.split_off(from);
                let past = part.objects.partition_point(|entry| entry.key < prefix);
                entries.extend(part.objects.drain(past..));
                part.stop = Some(prefix.clone());
                // Objects directly in this directory are reported from its
                // child listing above, wherever the new part's prefix ends.
                let above = part.directory.rfind('/').map_or(0, |slash| slash + 1);
                let above = Some(above.max(part.above.unwrap_or(0)));
                let directory = part.directory.clone();
                let mut new = Part::new(prefix.clone(), above);
                if !prefix.ends_with('/') {
                    // The part covers several of this directory's children,
                    // which are already known.
                    new.directory = directory;
                    new.ahead = names;
                    new.children = Children::Complete;
                }
                self.parts.push(new);
                Some(Job::Keys {
                    walk: id,
                    part: self.parts.len() - 1,
                    prefix,
                    token: None,
                })
            }
            other => {
                part.children = other;
                None
            }
        }
    }
}

pub(super) async fn enumerate(
    store: &impl Store,
    pattern: &Pattern,
    concurrency: usize,
    mut emit: impl FnMut(Entry) -> Result<()>,
) -> Result<()> {
    ensure!(
        (1..=256).contains(&concurrency),
        "concurrency must be between 1 and 256"
    );
    if store.ordered() && pattern.components.iter().all(|part| part.literal()) {
        // General-purpose S3 listings are sorted: the exact prefix itself, if
        // present, precedes every longer key. Keep LIST permissions (no HEAD).
        let key = pattern
            .components
            .iter()
            .map(|part| part.literal_prefix())
            .collect::<Vec<_>>()
            .join("/");
        let page = read(store, &key, false, None).await?;
        for entry in page.entries {
            if entry.key == key {
                emit(entry)?;
            }
        }
        return Ok(());
    }
    enumerate_jobs(
        store,
        Some(pattern),
        None,
        concurrency,
        Job::Discover {
            prefix: String::new(),
            component: 0,
        },
        &mut emit,
    )
    .await?;
    Ok(())
}

/// Literal prefixes from copy/removal selectors must never be parsed as globs.
/// This only changes request scheduling; callers still validate and interpret
/// object metadata, source types and destination mappings.
///
/// Keys arrive in no particular order. With `prune`, directories it names may
/// be skipped: their common prefixes are returned instead of being listed.
/// Objects in pruned directories may still be emitted, so callers must
/// classify every entry themselves.
///
/// Fails with [`Unordered`] when keys arrive out of order after part of the
/// listing was handed to others; a concurrency of one hands nothing over.
pub(in crate::s3) async fn enumerate_prefix(
    store: &impl Store,
    prefix: &str,
    concurrency: usize,
    prune: Option<&Prune<'_>>,
    mut emit: impl FnMut(Entry) -> Result<()>,
) -> Result<Vec<String>> {
    enumerate_jobs(
        store,
        None,
        prune,
        concurrency,
        Job::Recursive {
            prefix: prefix.to_owned(),
        },
        &mut emit,
    )
    .await
}

async fn enumerate_jobs(
    store: &impl Store,
    pattern: Option<&Pattern>,
    prune: Option<&Prune<'_>>,
    concurrency: usize,
    first: Job,
    emit: &mut impl FnMut(Entry) -> Result<()>,
) -> Result<Vec<String>> {
    ensure!(
        (1..=256).contains(&concurrency),
        "concurrency must be between 1 and 256"
    );
    // Directory buckets do not list in key order, and take only prefixes that
    // end in a slash, so their listings stay whole.
    let dividing = concurrency > 1 && store.ordered();
    let store = LimitedStore {
        inner: store,
        slots: tokio::sync::Semaphore::new(concurrency),
    };
    let mut pending = VecDeque::from([first]);
    let mut pruned = Vec::new();
    let mut walks: Vec<Walk> = Vec::new();
    let mut active = FuturesUnordered::new();
    loop {
        while active.len() < concurrency {
            let Some(job) = pending.pop_front() else {
                break;
            };
            let split = concurrency > 1 && pending.len() + active.len() < SPLIT_QUEUE_LIMIT;
            active.push(execute(&store, pattern, prune, job, split));
        }
        let Some(done) = active.next().await else {
            return Ok(pruned);
        };
        let (mut entries, walk) = match done? {
            Done::Batch(batch) => {
                pending.extend(batch.jobs);
                pruned.extend(batch.pruned);
                (batch.entries, None)
            }
            Done::First { page, .. } if page.next.is_none() => (page.entries, None),
            Done::First { prefix, page } => {
                let id = walks.len();
                walks.push(Walk::new(prefix, dividing, prune.is_none()));
                let (entries, job) = walks[id].keys(id, 0, page)?;
                pending.extend(job);
                (entries, Some(id))
            }
            Done::Keys { walk, part, page } => {
                let (entries, job) = walks[walk].keys(walk, part, page)?;
                pending.extend(job);
                (entries, Some(walk))
            }
            Done::Children {
                walk,
                part,
                directory,
                page,
            } => {
                walks[walk].children(part, &directory, page);
                (Vec::new(), Some(walk))
            }
        };
        if let Some(id) = walk {
            let room = concurrency.saturating_sub(active.len() + pending.len());
            walks[id].divide(id, room, prune, &mut pending, &mut entries, &mut pruned);
        }
        for entry in entries {
            if pattern.is_none_or(|pattern| pattern.matches(&entry.key)) {
                emit(entry)?;
            }
        }
    }
}
