//! Listing a prefix as separate listings of its directories, for stores that
//! do not document the order in which they return keys.
//!
//! Every listing here runs to its end and is never resumed with `StartAfter`,
//! so the order never matters. A prefix is divided only into prefixes that do
//! not overlap. When the listing of a prefix `P` with the delimiter `/` fits on
//! one page, that page names every object directly under `P` and every
//! directory `P/c/` below it, and every other key under `P` lies in exactly
//! one of those directories. The objects on the page and the listings of the
//! directories then return each key once.
//!
//! Only the first page of a delimiter listing is read. Tigris leaves the key
//! `Q0` out of the page after one that ends with the common prefix `Q/`, so a
//! delimiter listing that goes on is never used: a prefix with more children
//! than a page holds is listed whole.
//!
//! A prefix is first listed without a delimiter. When the first page leaves
//! more to list and shows directories that are not tiny, the page is held and
//! the first page of the delimiter listing is asked for. If that page says
//! that the listing ends there and passes every check, the held page is
//! dropped and the directories are listed instead. Otherwise the held page is
//! reported and the listing goes on from it, having cost one request. A
//! prefix with a single directory may be followed down a few levels while the
//! page stays held. Only a few pages are held at once.
//!
//! When there are more directories than listings worth starting, neighboring
//! directories are listed together under the start of their names that they
//! share: `P/d1` lists `P/d1/`, `P/d10/` and `P/d1x/`. Such a group also
//! returns objects directly under `P` whose names start the same way, which
//! the delimiter page already reported; they are left out. A group whose first
//! page shows that it is large is divided again among its directories, which
//! are known, without another delimiter request. A group never covers a
//! directory that is left out (`Prune`), and the part of its prefix after `P`
//! holds only ASCII characters and is followed by one in every directory it
//! covers, since some stores compare other characters in another Unicode
//! normalization. A directory that cannot be grouped is listed by itself, and
//! a prefix whose directories would need many more listings than its keys
//! need pages is listed whole.
//!
//! Splits are limited by the requests they cost (`Lister::affords`) and by
//! the listings they have started whose first page has not shown yet how
//! large they are (`Lister::unproven`).
use super::{
    lookahead, read, refused, Batch, Entry, Job, LimitedStore, Page, PartFailed, Prune, Store,
    SPLIT_QUEUE_LIMIT,
};
use crate::s3::listing::pattern::Pattern;
use anyhow::Result;
use futures_util::{stream::FuturesUnordered, StreamExt};
use std::{
    collections::{HashMap, VecDeque},
    sync::atomic::{AtomicUsize, Ordering},
};

/// Keys in a full ListObjectsV2 page.
const PAGE: usize = 1000;
/// Most listings a split starts at once, with a lower concurrency.
const LISTINGS: usize = 32;
/// Most listings a split starts when its directories cannot be grouped into
/// fewer.
const MOST_LISTINGS: usize = 48;
/// A first page whose keys average fewer than this per directory shows
/// directories too small to list one by one.
const DENSE_KEYS: usize = 50;
/// A prefix is split only when the directories its first page shows suggest
/// at least this many pages, or when that leaves directories out: shorter
/// listings finish as soon by going on.
const SPLIT_PAGES: usize = 3;
/// Levels a listing follows a prefix that holds a single directory.
const DESCENT: usize = 4;
// Delimiter requests and dropped pages are requests a listing one page after
// another would not make; so are the last pages of the separate listings,
// which are rarely full. Those beyond the pages of keys listed so far may
// reach the number of listings a split starts at once, plus a few, and grow
// by one for every `PAGES_PER_EXTRA` pages of keys.
const EXTRA_REQUESTS: usize = 2;
const PAGES_PER_EXTRA: usize = 4;
/// Listings that splits started and whose first page has not returned may
/// reach this many times the listings a split starts at once, or
/// `MOST_LISTINGS` if that is more. Until their first pages return, nothing
/// shows whether the directories are as large as the estimate took them to
/// be, and a listing that waits behind several rounds of others gains little.
const UNPROVEN_ROUNDS: usize = 4;

/// A listing of everything under `prefix`.
struct Node {
    prefix: String,
    /// For a group of a directory's children, the length of the directory.
    /// Keys without a slash after it are the directory's own objects, which
    /// its delimiter page reported.
    above: Option<usize>,
    /// The group's directories, until its first page decides whether to
    /// divide it.
    children: Vec<String>,
    /// Whether the prefix is narrower than the one the caller asked for.
    part: bool,
    /// Whether a split started the listing, which counts in
    /// `Lister::unproven` until its first page returns.
    unproven: bool,
}

impl Node {
    fn new(prefix: String, part: bool) -> Self {
        Self {
            prefix,
            above: None,
            children: Vec::new(),
            part,
            unproven: false,
        }
    }
}

/// The first page of a node, held while the first page of a delimiter
/// listing decides whether to list its directories instead.
struct Split {
    node: Node,
    /// The held page, whose `next` goes on with the node's listing.
    page: Page,
    /// The prefix of the delimiter listing: the node's, or the single
    /// directory below it that the listing followed.
    level: String,
    descended: usize,
    /// Objects directly in the levels the listing followed down from.
    direct: Vec<Entry>,
}

enum Task {
    /// A step of a pattern's discovery other than a recursive listing.
    Base(Job, bool),
    /// A page of a node's listing without a delimiter.
    Flat { node: Node, token: Option<String> },
    /// The first page of a delimiter listing.
    Probe(Split),
}

enum Done {
    /// Keys and further jobs, and whether the jobs list narrower prefixes.
    Batch(Batch, bool),
    Flat {
        node: Node,
        first: bool,
        page: Page,
    },
    /// `None` when the delimiter page is of no use.
    Probe(Split, Option<Page>),
}

/// Counts requests that have returned, which the allowance weighs against
/// the keys listed.
struct Counted<'a, S> {
    inner: &'a S,
    requests: AtomicUsize,
}
impl<S: Store> Store for Counted<'_, S> {
    fn ordered(&self) -> bool {
        self.inner.ordered()
    }
    fn slash_only(&self) -> bool {
        self.inner.slash_only()
    }
    fn divides(&self) -> bool {
        self.inner.divides()
    }
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        let page = self.inner.page(prefix, delimiter, token, start_after).await;
        self.requests.fetch_add(1, Ordering::Relaxed);
        page
    }
}

/// The first page of the delimiter listing of `prefix`, if it says that it is
/// the whole listing and follows the delimiter's rules: objects with no slash
/// after the prefix, and directories that each add one name and a slash.
/// `None` when a policy refused the request, the listing goes on or does not
/// say that it ends, or the page breaks those rules, as a store that returns
/// common prefixes in another Unicode normalization can.
async fn probe(store: &impl Store, prefix: &str) -> Result<Option<Page>> {
    let page = match store.page(prefix, true, None, None).await {
        Ok(page) => page,
        // A policy may allow listing the prefix only without a delimiter.
        Err(error) if refused(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let object = |key: &str| {
        key.strip_prefix(prefix)
            .is_some_and(|rest| !rest.contains('/'))
    };
    let directory = |child: &str| {
        child
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix('/'))
            .is_some_and(|name| !name.contains('/'))
    };
    let whole = page.complete
        && page.next.is_none()
        && page.entries.len() + page.prefixes.len() <= PAGE
        && page.entries.iter().all(|entry| object(&entry.key))
        && page.prefixes.iter().all(|child| directory(child));
    Ok(whole.then_some(page))
}

/// Whether the delimiter page of `level` agrees with the held page about
/// every key under `level` that the held page shows: each object is on the
/// delimiter page, and each directory is one of its common prefixes.
fn agrees(level: &str, held: &[Entry], delimited: &Page) -> bool {
    let objects: std::collections::HashSet<&str> = delimited
        .entries
        .iter()
        .map(|entry| entry.key.as_str())
        .collect();
    let children: std::collections::HashSet<&str> =
        delimited.prefixes.iter().map(String::as_str).collect();
    held.iter().all(|entry| {
        let Some(rest) = entry.key.strip_prefix(level) else {
            return true;
        };
        match rest.find('/') {
            Some(slash) => children.contains(&entry.key[..level.len() + slash + 1]),
            None => objects.contains(entry.key.as_str()),
        }
    })
}

/// The directory directly under `parent` that holds `key`.
fn directory<'a>(parent: &str, key: &'a str) -> Option<&'a str> {
    let slash = key.strip_prefix(parent)?.find('/')?;
    Some(&key[..parent.len() + slash + 1])
}

/// Keys on a page in each directory directly under `parent`.
fn directories<'a>(parent: &str, entries: &'a [Entry]) -> HashMap<&'a str, usize> {
    let mut counts = HashMap::new();
    for entry in entries {
        if let Some(directory) = directory(parent, &entry.key) {
            *counts.entry(directory).or_default() += 1;
        }
    }
    counts
}

/// Keys expected in `children` directories directly under `parent` that
/// `counted` accepts, taking each to hold as many as those a first page that
/// goes on shows. The page may end inside the directory of its last key,
/// which is left out unless it is the only one. A page that shows only that
/// directory ends inside it, as far as it shows, so the directory is taken to
/// hold twice the keys the page shows: two directories that each fill a page
/// are worth listing apart. With none on the page, take each to fill a page.
fn estimate(
    parent: &str,
    entries: &[Entry],
    children: usize,
    counted: impl Fn(&str) -> bool,
) -> usize {
    let mut counts = directories(parent, entries);
    counts.retain(|child, _| counted(child));
    if let Some(last) = entries
        .last()
        .and_then(|entry| directory(parent, &entry.key))
    {
        if counts.len() > 1 {
            counts.remove(last);
        } else if let Some(keys) = counts.get_mut(last) {
            *keys = keys.saturating_mul(2);
        }
    }
    if counts.is_empty() {
        return children.saturating_mul(PAGE);
    }
    let keys: usize = counts.values().sum();
    children.saturating_mul(keys) / counts.len()
}

/// The listings worth starting for `expected` keys, at most `listings`, and
/// the most a split may start: half again as many, or one for each page the
/// keys are expected to fill if that is more, but never more than
/// `MOST_LISTINGS`.
fn listings_for(expected: usize, listings: usize) -> (usize, usize) {
    let pages = expected.div_ceil(PAGE);
    let target = pages.clamp(2, listings);
    let most = (target + target / 2)
        .max(target + 1)
        .max(pages)
        .min(MOST_LISTINGS);
    (target, most)
}

/// Children of one directory that start with the first `depth` bytes of
/// `names[start]`: `names[start..end]`. A single child is a leaf, whose depth
/// is its length.
#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
    depth: usize,
}

impl Span {
    fn new(names: &[String], start: usize, end: usize) -> Self {
        let depth = if end - start == 1 {
            names[start].len()
        } else {
            let (first, last) = (names[start].as_bytes(), names[end - 1].as_bytes());
            first.iter().zip(last).take_while(|(a, b)| a == b).count()
        };
        Self { start, end, depth }
    }

    fn leaf(self) -> bool {
        self.end - self.start == 1
    }

    /// The spans below this one, by the byte after its depth. Sorted names
    /// with the same byte there are next to each other.
    fn branches(self, names: &[String]) -> Vec<Self> {
        let byte = |at: usize| names[at].as_bytes().get(self.depth);
        let mut spans = Vec::new();
        let mut start = self.start;
        for at in self.start + 1..=self.end {
            if at == self.end || byte(at) != byte(start) {
                spans.push(Self::new(names, start, at));
                start = at;
            }
        }
        spans
    }

    /// Whether the start of the names this span shares can be listed as a
    /// prefix: past their directory, `above` bytes long, it holds only ASCII
    /// characters and every name goes on with one, so no store reads it as
    /// part of another character or compares it in another normalization,
    /// and it covers no directory left out.
    fn listable(self, names: &[String], pruned: &[bool], above: usize) -> bool {
        self.depth > above
            && names[self.start].as_bytes()[above..self.depth].is_ascii()
            && names[self.start..self.end]
                .iter()
                .all(|name| name.as_bytes().get(self.depth).is_some_and(u8::is_ascii))
            && !pruned[self.start..self.end].contains(&true)
    }

    /// The fewest listable spans that cover `self`, apart from directories
    /// left out.
    fn cover(self, names: &[String], pruned: &[bool], above: usize, spans: &mut Vec<Self>) {
        let mut stack = vec![self];
        while let Some(span) = stack.pop() {
            if span.leaf() {
                if !pruned[span.start] {
                    spans.push(span);
                }
            } else if span.listable(names, pruned, above) {
                spans.push(span);
            } else {
                stack.extend(span.branches(names).into_iter().rev());
            }
        }
    }
}

/// Divide `names`, the sorted, distinct children of one directory `above`
/// bytes long, among about `target` listings whose prefixes do not overlap,
/// leaving out those `pruned` marks. Each listing is a prefix and the children
/// it covers; a single child is listed by itself. The largest groups are
/// divided first, while that keeps the listings within half again of
/// `target`. `None` when the children need more than `most` listings.
fn group(
    names: &[String],
    pruned: &[bool],
    above: usize,
    target: usize,
    most: usize,
) -> Option<Vec<(String, Vec<String>)>> {
    let finer_most = (target + target / 2).max(target + 1).min(most);
    let mut spans = Vec::new();
    if !names.is_empty() {
        // The whole directory is not a group.
        for span in Span::new(names, 0, names.len()).branches(names) {
            span.cover(names, pruned, above, &mut spans);
        }
    }
    let mut whole = vec![false; spans.len()];
    while spans.len() < target {
        let Some(at) = (0..spans.len())
            .filter(|&at| !whole[at] && !spans[at].leaf())
            .max_by_key(|&at| spans[at].end - spans[at].start)
        else {
            break;
        };
        let mut finer = Vec::new();
        for span in spans[at].branches(names) {
            span.cover(names, pruned, above, &mut finer);
        }
        if spans.len() - 1 + finer.len() > finer_most {
            whole[at] = true;
            continue;
        }
        let added = finer.len();
        spans.splice(at..=at, finer);
        whole.splice(at..=at, std::iter::repeat_n(false, added));
    }
    (spans.len() <= most).then(|| {
        spans
            .into_iter()
            .map(|span| {
                let prefix = names[span.start][..span.depth].to_owned();
                (prefix, names[span.start..span.end].to_vec())
            })
            .collect()
    })
}

/// Each child listed by itself.
fn each(children: Vec<String>) -> Vec<(String, Vec<String>)> {
    children
        .into_iter()
        .map(|child| (child.clone(), vec![child]))
        .collect()
}

struct Lister<'a, F> {
    pattern: Option<&'a Pattern>,
    prune: Option<&'a Prune<'a>>,
    emit: &'a mut F,
    /// Whether the store takes prefixes that do not end in a slash.
    groupable: bool,
    /// Listings a split starts at most, unless its directories cannot be
    /// grouped into fewer.
    listings: usize,
    /// Keys reported or held, which earn extra requests.
    keys: usize,
    /// Pages held while their delimiter page is asked for. Each holds up to
    /// a page of keys, and may cost the delimiter request and the page.
    held: usize,
    /// Listings that splits started and whose first page has not returned.
    unproven: usize,
    pruned: Vec<String>,
    pending: VecDeque<Task>,
    splits: usize,
    /// The most pages held at once.
    #[cfg(test)]
    most_held: usize,
}

impl<F: FnMut(Entry) -> Result<()>> Lister<'_, F> {
    fn report(&mut self, entries: Vec<Entry>) -> Result<()> {
        for entry in entries {
            if self
                .pattern
                .is_none_or(|pattern| pattern.matches(&entry.key))
            {
                (self.emit)(entry)?;
            }
        }
        Ok(())
    }

    /// Whether `cost` more requests than the keys listed so far need stay
    /// within the allowance, once `requests` have returned.
    fn affords(&self, requests: usize, cost: usize) -> bool {
        let allowance = (self.listings + EXTRA_REQUESTS) * PAGE;
        (requests + cost) * PAGE <= allowance + self.keys + self.keys / PAGES_PER_EXTRA
    }

    /// Whether another page may be held: few are held, and the requests that
    /// each held page may cost, its delimiter request and the page itself,
    /// stay within the allowance.
    fn may_hold(&self, requests: usize) -> bool {
        self.held < self.listings && self.affords(requests, 2 * (self.held + 1))
    }

    /// Whether a split may start `listings` listings, dropping the page that
    /// showed it was worth it: the requests stay within the allowance, and
    /// the listings that splits started and whose size is not known yet stay
    /// few.
    fn may_start(&self, requests: usize, listings: usize) -> bool {
        let unproven = (UNPROVEN_ROUNDS * self.listings).max(MOST_LISTINGS);
        self.affords(requests, 1) && self.unproven + listings <= unproven
    }

    /// Hold the page of `split` while its delimiter page is asked for, before
    /// other work so that held pages are decided soon.
    fn hold_page(&mut self, split: Split) {
        self.held += 1;
        #[cfg(test)]
        {
            self.most_held = self.most_held.max(self.held);
        }
        self.pending.push_front(Task::Probe(split));
    }

    fn pruned(&self, child: &str) -> bool {
        self.prune
            .is_some_and(|prune| (prune.subtree)(child, true).is_some())
    }

    fn add(&mut self, job: Job, part: bool) {
        self.pending.push_back(match job {
            Job::Recursive { prefix } => Task::Flat {
                node: Node::new(prefix, part),
                token: None,
            },
            job => Task::Base(job, true),
        });
    }

    fn done(&mut self, done: Done, requests: usize, busy: bool) -> Result<()> {
        match done {
            Done::Batch(batch, part) => {
                self.keys += batch.entries.len();
                self.report(batch.entries)?;
                for job in batch.jobs {
                    self.add(job, part);
                }
                self.pruned.extend(batch.pruned);
                Ok(())
            }
            Done::Flat {
                node,
                first,
                mut page,
            } => {
                if let Some(above) = node.above {
                    page.entries.retain(|entry| {
                        entry
                            .key
                            .get(above..)
                            .is_some_and(|rest| rest.contains('/'))
                    });
                }
                self.keys += page.entries.len();
                match (first && page.next.is_some(), node.above) {
                    (true, None) => self.hold(node, page, requests, busy),
                    (true, Some(above)) => self.divide(node, above, page, requests, busy),
                    (false, _) => self.stream(node, page),
                }
            }
            Done::Probe(split, page) => self.probed(split, page, requests, busy),
        }
    }

    /// Report a page and go on with the node's listing.
    fn stream(&mut self, mut node: Node, page: Page) -> Result<()> {
        node.children = Vec::new();
        self.report(page.entries)?;
        if let Some(token) = page.next {
            self.pending.push_back(Task::Flat {
                node,
                token: Some(token),
            });
        }
        Ok(())
    }

    /// The first page of a directory's listing, which goes on: ask for its
    /// directories if the page shows some that are not tiny.
    fn hold(&mut self, node: Node, page: Page, requests: usize, busy: bool) -> Result<()> {
        let found = directories(&node.prefix, &page.entries).len();
        if found == 0 || found * DENSE_KEYS > page.entries.len() || busy || !self.may_hold(requests)
        {
            return self.stream(node, page);
        }
        self.hold_page(Split {
            level: node.prefix.clone(),
            node,
            page,
            descended: 0,
            direct: Vec::new(),
        });
        Ok(())
    }

    /// The first page of a group's listing, which goes on: divide the group
    /// among its directories if they look large enough.
    fn divide(
        &mut self,
        mut node: Node,
        above: usize,
        page: Page,
        requests: usize,
        busy: bool,
    ) -> Result<()> {
        let children = std::mem::take(&mut node.children);
        let parent = &node.prefix[..above];
        let found = directories(parent, &page.entries).len();
        let expected = estimate(parent, &page.entries, children.len(), |_| true);
        if found * DENSE_KEYS <= page.entries.len() && expected >= SPLIT_PAGES * PAGE && !busy {
            let (target, most) = listings_for(expected, self.listings);
            let groups = if children.len() <= target {
                Some(each(children))
            } else {
                group(&children, &vec![false; children.len()], above, target, most)
            };
            if let Some(groups) = groups.filter(|groups| self.may_start(requests, groups.len())) {
                self.keys -= page.entries.len();
                self.start(groups, above);
                return Ok(());
            }
        }
        self.stream(node, page)
    }

    /// The delimiter page for a held first page: list the directories it
    /// names instead, follow a single one down, or go on with the held page.
    fn probed(
        &mut self,
        mut split: Split,
        page: Option<Page>,
        requests: usize,
        busy: bool,
    ) -> Result<()> {
        self.held -= 1;
        let Some(delimited) = page.filter(|page| agrees(&split.level, &split.page.entries, page))
        else {
            return self.stream(split.node, split.page);
        };
        let mut names = delimited.prefixes;
        names.sort_unstable();
        names.dedup();
        let pruned: Vec<bool> = names.iter().map(|child| self.pruned(child)).collect();
        let kept: Vec<String> = names
            .iter()
            .zip(&pruned)
            .filter(|(_, pruned)| !**pruned)
            .map(|(child, _)| child.clone())
            .collect();
        let any_pruned = kept.len() < names.len();
        if !any_pruned && kept.len() == 1 {
            // Follow the single directory if the held page shows
            // directories inside it.
            let deeper = split.page.entries.iter().any(|entry| {
                entry
                    .key
                    .strip_prefix(kept[0].as_str())
                    .is_some_and(|rest| rest.contains('/'))
            });
            if deeper && split.descended < DESCENT && !busy && self.may_hold(requests) {
                split.direct.extend(delimited.entries);
                split.level = kept.into_iter().next().unwrap();
                split.descended += 1;
                self.hold_page(split);
                return Ok(());
            }
            return self.stream(split.node, split.page);
        }
        let expected = estimate(&split.level, &split.page.entries, kept.len(), |child| {
            !self.pruned(child)
        });
        if !any_pruned && (kept.len() < 2 || expected < SPLIT_PAGES * PAGE) {
            return self.stream(split.node, split.page);
        }
        let (target, most) = listings_for(expected, self.listings);
        // Directories left out are not counted and may hold many more keys,
        // which listing the others apart saves listing.
        let most = if any_pruned { MOST_LISTINGS } else { most };
        let groups = if kept.len() <= target {
            Some(each(kept))
        } else if self.groupable {
            group(&names, &pruned, split.level.len(), target, most)
        } else {
            // Directory buckets and their access points take only prefixes
            // that end in a slash.
            (kept.len() <= most).then(|| each(kept))
        };
        let Some(groups) = groups.filter(|groups| self.may_start(requests, groups.len())) else {
            return self.stream(split.node, split.page);
        };
        self.keys -= split.page.entries.len();
        let mut direct = split.direct;
        direct.extend(delimited.entries);
        self.keys += direct.len();
        self.report(direct)?;
        self.pruned.extend(
            names
                .into_iter()
                .zip(pruned)
                .filter_map(|(child, pruned)| pruned.then_some(child)),
        );
        self.start(groups, split.level.len());
        self.splits += 1;
        Ok(())
    }

    /// Start listings of directories of a directory `above` bytes long, each
    /// by itself or in groups.
    fn start(&mut self, groups: Vec<(String, Vec<String>)>, above: usize) {
        self.unproven += groups.len();
        for (prefix, children) in groups {
            let mut node = Node::new(prefix, true);
            node.unproven = true;
            if children.len() > 1 {
                node.above = Some(above);
                node.children = children;
            }
            self.pending.push_back(Task::Flat { node, token: None });
        }
    }
}

async fn run(
    store: &impl Store,
    pattern: Option<&Pattern>,
    prune: Option<&Prune<'_>>,
    task: Task,
) -> Result<Done> {
    match task {
        Task::Base(job, split) => {
            let batch = super::execute(store, pattern, prune, job, split, true).await?;
            Ok(Done::Batch(batch, false))
        }
        Task::Flat { node, token } => {
            // A policy may allow listing only the prefix the caller named.
            let part = node.part;
            let context = |error: anyhow::Error| {
                if part {
                    error.context(PartFailed)
                } else {
                    error
                }
            };
            let page = read(store, &node.prefix, false, token.as_deref())
                .await
                .map_err(context)?;
            if let (None, None, Some(prune)) = (&token, node.above, prune) {
                if let Some(batch) = lookahead(store, prune, &node.prefix, &page)
                    .await
                    .map_err(context)?
                {
                    return Ok(Done::Batch(batch, true));
                }
            }
            Ok(Done::Flat {
                node,
                first: token.is_none(),
                page,
            })
        }
        Task::Probe(split) => {
            let part = split.node.part || split.descended > 0;
            let page = probe(store, &split.level).await.map_err(|error| {
                if part {
                    error.context(PartFailed)
                } else {
                    error
                }
            })?;
            Ok(Done::Probe(split, page))
        }
    }
}

/// Everything `first` leads to, as [`super::enumerate_jobs`] lists it, with
/// recursive listings split by directory.
pub(super) async fn enumerate_jobs(
    store: &impl Store,
    pattern: Option<&Pattern>,
    prune: Option<&Prune<'_>>,
    concurrency: usize,
    first: Job,
    emit: &mut impl FnMut(Entry) -> Result<()>,
) -> Result<Vec<String>> {
    let lister = drive(store, pattern, prune, concurrency, first, emit).await?;
    // The S3 suite confirms through this that a listing was split.
    #[cfg(debug_assertions)]
    if lister.splits > 0 && crate::s3::listing::test_reports_splits() {
        crate::output::diagnostic!("syq: test hook: listing split by directory");
    }
    Ok(lister.pruned)
}

/// List everything `first` leads to, and return the finished lister.
async fn drive<'a, F: FnMut(Entry) -> Result<()>>(
    store: &impl Store,
    pattern: Option<&'a Pattern>,
    prune: Option<&'a Prune<'a>>,
    concurrency: usize,
    first: Job,
    emit: &'a mut F,
) -> Result<Lister<'a, F>> {
    let counted = Counted {
        inner: store,
        requests: AtomicUsize::new(0),
    };
    let store = &LimitedStore {
        inner: &counted,
        slots: tokio::sync::Semaphore::new(concurrency),
    };
    let mut lister = Lister {
        pattern,
        prune,
        emit,
        groupable: !store.slash_only(),
        listings: concurrency.clamp(2, LISTINGS),
        keys: 0,
        held: 0,
        unproven: 0,
        pruned: Vec::new(),
        pending: VecDeque::new(),
        splits: 0,
        #[cfg(test)]
        most_held: 0,
    };
    lister.add(first, false);
    let mut active = FuturesUnordered::new();
    loop {
        while active.len() < concurrency {
            let Some(mut task) = lister.pending.pop_front() else {
                break;
            };
            if let Task::Base(_, split) = &mut task {
                *split = lister.pending.len() + active.len() < SPLIT_QUEUE_LIMIT;
            }
            // The first page of a listing a split started shows how large
            // it is, whatever becomes of the page.
            let unproven = matches!(&task, Task::Flat { node, token: None } if node.unproven);
            active.push(async move { (unproven, run(store, pattern, prune, task).await) });
        }
        let Some((unproven, done)) = active.next().await else {
            break;
        };
        lister.unproven -= usize::from(unproven);
        let requests = counted.requests.load(Ordering::Relaxed);
        let busy = lister.pending.len() + active.len() >= SPLIT_QUEUE_LIMIT;
        lister.done(done?, requests, busy)?;
    }
    Ok(lister)
}

#[cfg(test)]
mod tests;
