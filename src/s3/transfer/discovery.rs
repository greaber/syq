//! Which planned destination keys already exist, learned from LIST pages
//! while the copy runs.
//!
//! A key the listing shows absent needs no HEAD. The listing follows the plan
//! in key order and each request starts at the next undecided key, so its cost
//! follows the copy rather than the size of the destination prefix. Workers
//! use each page as it arrives instead of waiting for the last one.
//!
//! The listing reads one prefix, the destination, unless the copy may list
//! only some prefixes inside it: then it reads each of those for the planned
//! keys beneath it ([`segments`]), several at once ([`LISTINGS`]).
use super::super::listing::{
    self,
    engine::{Page, Store},
};
use crate::cli::{Args, IfExists};
use crate::progress::Progress;
use anyhow::{ensure, Result};
use std::{
    borrow::Cow,
    future::Future,
    ops::Range,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc,
    },
};
use tokio::sync::watch;

/// Whether a planned key that the listing shows absent may go without its
/// HEAD. The listing concludes absence from where a key would fall in a page,
/// so a provider that orders keys differently could show an existing object
/// as absent. That may cost an upload the comparison would have skipped. It
/// must not change what the copy does, so these copies ask about every key.
pub(super) fn trusts_absence(args: &Args) -> bool {
    // The object would be skipped by --only-existing, refused instead of kept
    // by keep, overwritten though newer by update-if-older, and judged by
    // --copy-if as if nothing were there.
    if args.existing || args.ignore_existing || args.update || args.expressions.update.is_some() {
        return false;
    }
    match args.if_exists {
        // An object with the same contents is accepted, where a write that
        // must create its object would be refused.
        Some(IfExists::ErrorIfDifferent) => false,
        // Either way a file is refused, here by the write's
        // `If-None-Match: *`. A dry run sends no write and would report
        // nothing. Directory markers are `trusts_absence_of`'s concern.
        Some(IfExists::Error) => !args.dry_run,
        _ => true,
    }
}

/// Whether a listed absence may also be relied on for `key`, in a copy that
/// relies on them at all. A directory marker that exists is accepted under
/// `--if-exists=error`, where a write that must create it would be refused.
pub(super) fn trusts_absence_of(args: &Args, key: &str) -> bool {
    !(key.ends_with('/') && args.protects_existing_contents())
}

/// Whether a copy to `bucket` lists its destination to learn which planned
/// keys are absent. A directory bucket's keys come in no order, so its listing
/// decides absence only when complete, never from a key's place in a page.
pub(super) fn lists_destination(args: &Args, bucket: &str) -> bool {
    !listing::lists_in_key_order(bucket) || trusts_absence(args)
}

/// What the destination listing says about one planned key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Listed {
    /// No listing covers the key: ask with HEAD.
    Unknown,
    Absent,
    Present(u64),
}

/// About how many HEAD requests a LIST request costs: S3 bills LIST at about
/// twelve times a HEAD.
const LIST_COST: usize = 12;

/// Planned keys a page must decide to be worth requesting. LIST is billed
/// about [`LIST_COST`] times a HEAD, and a worker waiting for the page could
/// have sent its own HEAD instead.
const KEYS_PER_PAGE: usize = 64;

/// Prefixes listed at once. A copy whose requests another machine signs lists
/// each named prefix on its own, and listing them one after another would
/// cost a round trip to the storage service each. The listings that run at
/// once share the prefixes in turn, so earlier ones are decided first.
const LISTINGS: usize = 16;

/// Pages' worth of shortfall allowed before the listing stops, so one sparse
/// stretch does not end a listing that pays for itself overall.
const SLACK_PAGES: usize = 2;

/// Pages each listing awaits before the copy starts. The copy sizes its
/// request concurrency from the fastest listing response seen by then, and the
/// first response also opened the connection.
const PAGES_BEFORE_COPY: usize = 2;

/// The longest key S3 stores, in bytes.
const MAX_KEY: usize = 1024;

const UNKNOWN: u64 = u64::MAX;
const ABSENT: u64 = u64::MAX - 1;

/// The plan's keys in plan order, which is key order, in one allocation.
pub(super) struct Keys {
    text: String,
    ends: Vec<usize>,
}
impl Keys {
    pub fn new<'a>(keys: impl Iterator<Item = Cow<'a, str>>) -> Self {
        let mut text = String::new();
        let mut ends = Vec::with_capacity(keys.size_hint().0);
        for key in keys {
            text.push_str(&key);
            ends.push(text.len());
        }
        Self { text, ends }
    }
    fn len(&self) -> usize {
        self.ends.len()
    }
    fn get(&self, index: usize) -> &str {
        let start = index.checked_sub(1).map_or(0, |before| self.ends[before]);
        &self.text[start..self.ends[index]]
    }
    /// The first position from which `before` is false. It must be true for
    /// every position before that one and false for every one after.
    fn partition_point(&self, before: impl Fn(&str) -> bool) -> usize {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let middle = low + (high - low) / 2;
            if before(self.get(middle)) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low
    }
    fn find(&self, key: &str) -> Option<usize> {
        let (mut low, mut high) = (0, self.len());
        while low < high {
            let middle = low + (high - low) / 2;
            match self.get(middle).cmp(key) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return Some(middle),
            }
        }
        None
    }
}

/// Planned keys, at plan positions `range`, that one listing of `prefix`
/// decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Segment {
    pub prefix: String,
    pub range: Range<usize>,
}
impl Segment {
    /// Every planned key, listed under the destination prefix.
    pub fn whole(prefix: String, keys: &Keys) -> Self {
        Self {
            prefix,
            range: 0..keys.len(),
        }
    }
}

/// One segment for each of `prefixes` that has planned keys beneath it worth
/// a listing, in key order. Keys sharing a prefix are contiguous in key order,
/// which is the order of `keys`. A prefix inside another adds nothing to it.
/// Fewer planned keys than a listing costs in HEAD requests are each checked
/// with HEAD instead, which costs less and needs no wait for a listing.
///
/// The copy sends one listing request whether or not it lists anything, to
/// size its concurrency from. So when no prefix has that many planned keys,
/// the one with the most is listed, if it has at least two: that request then
/// decides them too. Like a plan of one key, a single key under a prefix is
/// always checked with HEAD.
pub(super) fn segments(keys: &Keys, prefixes: &[String]) -> Vec<Segment> {
    let mut prefixes: Vec<&String> = prefixes.iter().collect();
    prefixes.sort_unstable();
    let mut segments: Vec<Segment> = Vec::new();
    for prefix in prefixes {
        // A prefix's extensions sort right after it.
        if segments
            .last()
            .is_some_and(|outer| prefix.starts_with(&outer.prefix))
        {
            continue;
        }
        let start = keys.partition_point(|key| key < prefix.as_str());
        let end =
            keys.partition_point(|key| key < prefix.as_str() || key.starts_with(prefix.as_str()));
        if end - start >= 2 {
            segments.push(Segment {
                prefix: prefix.clone(),
                range: start..end,
            });
        }
    }
    if segments
        .iter()
        .any(|segment| segment.range.len() >= LIST_COST)
    {
        segments.retain(|segment| segment.range.len() >= LIST_COST);
        return segments;
    }
    // The first of those with the most keys.
    let most = segments.into_iter().reduce(|most, next| {
        if next.range.len() > most.range.len() {
            next
        } else {
            most
        }
    });
    most.into_iter().collect()
}

/// The first request the listing sends for each of `segments`, as its prefix
/// and where it starts: the pages that do not depend on an earlier response.
/// A copy whose requests another machine signs has these signed together
/// before the listing starts, rather than one round trip to that machine as
/// the listing reaches each segment. The listing sends them as [`Walk`]
/// enters each segment, or as [`Walk::whole`] lists it in a bucket that does
/// not list in key order. A segment whose planned keys are all too long for
/// S3 is not listed.
pub(super) fn first_pages<'a>(
    segments: &'a [Segment],
    keys: &'a Keys,
    ordered: bool,
) -> impl Iterator<Item = (&'a str, Option<String>)> + 'a {
    segments
        .iter()
        .filter_map(move |Segment { prefix, range }| {
            if !ordered {
                // `Walk::whole` spends fewer requests than the segment's keys.
                return (range.len() >= 2).then_some((prefix.as_str(), None));
            }
            let start = range
                .clone()
                .map(|index| keys.get(index))
                .find(|key| key.len() <= MAX_KEY)?;
            Some((prefix.as_str(), Some(predecessor(start))))
        })
}

/// A key just below `key`: a listing that starts after it begins at `key`.
/// Keys between the two are listed needlessly, so stay close without
/// inventing characters a provider might reject in a request.
fn predecessor(key: &str) -> String {
    let mut bound = key.to_owned();
    if let Some(last) = bound.pop() {
        let lower = (last as u32).checked_sub(1).and_then(char::from_u32);
        if let Some(lower) = lower.filter(|lower| *lower >= ' ') {
            bound.push(lower);
        }
    }
    bound
}

#[derive(Clone, Copy)]
struct Reach {
    /// Plan positions below this, in the listing's own segments, are decided.
    decided: usize,
    finished: bool,
}

/// What the listings have decided about each planned key.
struct Decisions {
    /// By plan position.
    sizes: Box<[AtomicU64]>,
    /// A page came back out of key order. A key's place in this provider's
    /// listing says nothing about the keys around it, on any page of any
    /// prefix, so nothing listed is relied on.
    withdrawn: AtomicBool,
}
impl Decisions {
    fn new(len: usize) -> Self {
        Self {
            sizes: (0..len).map(|_| AtomicU64::new(UNKNOWN)).collect(),
            withdrawn: AtomicBool::new(false),
        }
    }
    fn store(&self, index: usize, size: u64) {
        self.sizes[index].store(size, Relaxed);
    }
    /// The decision recorded for a key a listing has passed.
    fn get(&self, index: usize) -> Listed {
        if self.withdrawn.load(Relaxed) {
            return Listed::Unknown;
        }
        match self.sizes[index].load(Relaxed) {
            UNKNOWN => Listed::Unknown,
            ABSENT => Listed::Absent,
            size => Listed::Present(size),
        }
    }
}

/// One listing, of some segments in turn.
struct Walk {
    /// What to list, in key order, and which of them is being listed.
    segments: Vec<Segment>,
    segment: usize,
    keys: Arc<Keys>,
    decisions: Arc<Decisions>,
    decided: usize,
    /// Planned keys by which the pages so far fell short of paying their way.
    shortfall: usize,
    /// The listing has passed every key up to this one.
    passed: String,
    /// Continues the listing from there, unless the last page decided so few
    /// planned keys that the next request should skip to the next one.
    token: Option<String>,
}
impl Walk {
    fn new(segments: Vec<Segment>, keys: Arc<Keys>, decisions: Arc<Decisions>) -> Self {
        Self {
            decided: segments
                .first()
                .map_or(keys.len(), |first| first.range.start),
            segments,
            segment: 0,
            keys,
            decisions,
            shortfall: 0,
            passed: String::new(),
            token: None,
        }
    }
    /// Start listing the next segment. Returns whether there is one. The
    /// planned keys this one left undecided stay unknown.
    fn next_segment(&mut self) -> bool {
        self.segment += 1;
        let Some(segment) = self.segments.get(self.segment) else {
            return false;
        };
        self.decided = segment.range.start;
        self.shortfall = 0;
        self.passed.clear();
        self.token = None;
        true
    }
    /// Request the next page and record what it decides. Returns whether
    /// another page is worth requesting.
    async fn page(&mut self, store: &impl Store) -> Result<bool> {
        if self.decisions.withdrawn.load(Relaxed) {
            return Ok(false);
        }
        let start;
        let (token, after) = match &self.token {
            Some(token) => (Some(token.as_str()), self.passed.as_str()),
            None => {
                // A planned key too long for S3 fails on its own when it is
                // copied. A listing asked to start there might be refused,
                // which would fail every key instead.
                while self.keys.get(self.decided).len() > MAX_KEY {
                    self.decided += 1;
                    if self.decided == self.segments[self.segment].range.end && !self.next_segment()
                    {
                        return Ok(false);
                    }
                }
                start = predecessor(self.keys.get(self.decided));
                (None, start.as_str())
            }
        };
        let Segment { prefix, range } = &self.segments[self.segment];
        let end = range.end;
        let page = store
            .page(prefix, false, token, token.is_none().then_some(after))
            .await?;
        for entry in &page.entries {
            ensure!(
                entry.key.starts_with(prefix.as_str()),
                "S3 listing returned a key outside the requested prefix"
            );
        }
        if !in_key_order(&page, after) {
            self.decisions.withdrawn.store(true, Relaxed);
            return Ok(false);
        }
        let complete = page.next.is_none();
        let last = page.entries.last().map(|entry| entry.key.as_str());
        let mut listed = page.entries.iter().peekable();
        let before = self.decided;
        while self.decided < end {
            let key = self.keys.get(self.decided);
            if !complete && last.is_none_or(|last| key > last) {
                break;
            }
            while listed.next_if(|entry| entry.key.as_str() < key).is_some() {}
            let size = match listed.peek() {
                Some(entry) if entry.key == key => entry.size,
                // The listing cannot show a key outside its prefix.
                _ if key.starts_with(prefix.as_str()) => ABSENT,
                _ => UNKNOWN,
            };
            self.decisions.store(self.decided, size);
            self.decided += 1;
        }
        if complete || self.decided == end {
            return Ok(self.next_segment());
        }
        let decided = self.decided - before;
        self.shortfall = (self.shortfall + KEYS_PER_PAGE).saturating_sub(decided);
        self.passed = last.unwrap_or(after).to_owned();
        // A continuation token is how providers page fastest, so keep to it
        // while pages pay their way. After one that did not, start again at
        // the next planned key to skip the destination keys before it.
        let skip =
            decided < KEYS_PER_PAGE && predecessor(self.keys.get(self.decided)) > self.passed;
        self.token = page.next.filter(|_| !skip);
        // The keys still undecided could not make up a larger shortfall.
        let undecided = end - self.decided;
        Ok(self.shortfall <= undecided.min(SLACK_PAGES * KEYS_PER_PAGE) || self.next_segment())
    }

    /// Request the pages the copy waits for. Returns whether another page
    /// is worth requesting.
    async fn before_copy(&mut self, store: &impl Store) -> Result<bool> {
        if !store.ordered() {
            self.whole(store).await?;
            return Ok(false);
        }
        for _ in 0..PAGES_BEFORE_COPY {
            if !self.page(store).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Directory buckets list in no particular order and cannot start after a
    /// key, so only a complete listing decides anything.
    async fn whole(&mut self, store: &impl Store) -> Result<()> {
        for Segment { prefix, range } in &self.segments {
            let mut token: Option<String> = None;
            let mut found = 0;
            // Never spend as many LIST requests as checking each key with HEAD.
            for _ in 0..range.len().saturating_sub(1) {
                let page = store.page(prefix, false, token.as_deref(), None).await?;
                for entry in &page.entries {
                    ensure!(
                        entry.key.starts_with(prefix.as_str()),
                        "S3 listing returned a key outside the requested prefix"
                    );
                    // Every planned key beneath the prefix is in the range.
                    if let Some(index) = self.keys.find(&entry.key) {
                        // A key listed twice still counts once.
                        if self.decisions.sizes[index].swap(entry.size, Relaxed) == UNKNOWN {
                            found += 1;
                        }
                    }
                }
                if page.next.is_none() || found == range.len() {
                    for index in range.clone() {
                        let size = &self.decisions.sizes[index];
                        if size.load(Relaxed) == UNKNOWN
                            && self.keys.get(index).starts_with(prefix.as_str())
                        {
                            size.store(ABSENT, Relaxed);
                        }
                    }
                    break;
                }
                ensure!(
                    page.next != token,
                    "S3 listing repeated its continuation token"
                );
                token = page.next;
            }
        }
        self.decided = self.keys.len();
        Ok(())
    }

    /// Request the remaining pages, while the copy runs.
    async fn rest(
        mut self,
        store: &impl Store,
        cancelled: &AtomicBool,
        stopped: &AtomicBool,
        progress: &Progress,
        sender: &watch::Sender<Reach>,
    ) {
        let mut more = true;
        while more && !cancelled.load(Relaxed) {
            more = self.page(store).await.unwrap_or_else(|error| {
                // The copy is still complete: the keys this listing did not
                // reach are checked with HEAD.
                if !stopped.swap(true, Relaxed) {
                    progress.warning(&format!(
                        "S3 destination listing stopped; each destination key it did not reach is checked with its own request: {error:#}"
                    ));
                }
                false
            });
            sender.send_replace(Reach {
                decided: self.decided,
                finished: !more,
            });
        }
        sender.send_replace(Reach {
            decided: self.decided,
            finished: true,
        });
    }
}

/// Whether a page is what a listing in key order returns after `after`.
/// Some S3-compatible services order keys differently or ignore the start.
fn in_key_order(page: &Page, after: &str) -> bool {
    page.entries
        .first()
        .is_none_or(|entry| entry.key.as_str() > after)
        && page
            .entries
            .windows(2)
            .all(|pair| pair[0].key < pair[1].key)
}

pub(super) struct Discovery {
    /// The plan positions some listing decides, in key order, each with the
    /// listing that decides them; the others are unknown.
    listed: Vec<(Range<usize>, usize)>,
    decisions: Arc<Decisions>,
    /// How far each listing has come.
    reach: Vec<watch::Receiver<Reach>>,
    tasks: Vec<tokio::task::AbortHandle>,
}
impl Discovery {
    /// List the destination for `keys`, which must be in key order, under
    /// each of `segments`, which must not be empty. A destination that cannot
    /// be listed fails the copy here, before it starts; later pages arrive
    /// while the copy runs.
    pub(super) async fn start(
        client: aws_sdk_s3::Client,
        bucket: &str,
        segments: Vec<Segment>,
        keys: Keys,
        cancelled: Arc<AtomicBool>,
        progress: Arc<Progress>,
    ) -> Result<Self> {
        ensure!(!segments.is_empty(), "no destination prefix to list");
        let decisions = Arc::new(Decisions::new(keys.len()));
        let listings = segments.len().min(LISTINGS);
        let listed = segments
            .iter()
            .enumerate()
            .map(|(index, segment)| (segment.range.clone(), index % listings))
            .collect();
        let keys = Arc::new(keys);
        let mut walks: Vec<Walk> = (0..listings)
            .map(|listing| {
                let segments = segments.iter().skip(listing).step_by(listings);
                Walk::new(segments.cloned().collect(), keys.clone(), decisions.clone())
            })
            .collect();
        // These listings read pages one by one; they never divide.
        let store = listing::S3 {
            client: client.clone(),
            bucket,
            divides: false,
        };
        let more = futures_util::future::try_join_all(
            walks.iter_mut().map(|walk| walk.before_copy(&store)),
        )
        .await?;
        let stopped = Arc::new(AtomicBool::new(false));
        let mut reach = Vec::with_capacity(listings);
        let mut tasks = Vec::new();
        for (walk, more) in walks.into_iter().zip(more) {
            let (sender, receiver) = watch::channel(Reach {
                decided: walk.decided,
                finished: !more,
            });
            reach.push(receiver);
            if !more {
                continue;
            }
            let (client, bucket) = (client.clone(), bucket.to_owned());
            let (cancelled, stopped) = (cancelled.clone(), stopped.clone());
            let progress = progress.clone();
            let task = tokio::spawn(async move {
                let store = listing::S3 {
                    client,
                    bucket: &bucket,
                    divides: false,
                };
                walk.rest(&store, &cancelled, &stopped, &progress, &sender)
                    .await;
            });
            tasks.push(task.abort_handle());
        }
        Ok(Self {
            listed,
            decisions,
            reach,
            tasks,
        })
    }

    /// How far the listing that decides the key at plan position `index` has
    /// come, if one does.
    fn reach(&self, index: usize) -> Option<&watch::Receiver<Reach>> {
        let segment = self.listed.partition_point(|(range, _)| range.end <= index);
        let (range, listing) = self.listed.get(segment)?;
        (range.start <= index).then(|| &self.reach[*listing])
    }

    /// What the listing says about the key at plan position `index`, once the
    /// listing has passed it or ended.
    pub(super) fn lookup(&self, index: usize) -> impl Future<Output = Listed> + Send + 'static {
        let reach = self.reach(index).cloned();
        let decisions = self.decisions.clone();
        async move {
            // A key no listing reaches need not wait for one.
            let Some(mut reach) = reach else {
                return Listed::Unknown;
            };
            // A listing that ended early or was dropped leaves the rest to HEAD.
            let decided = reach
                .wait_for(|reach| reach.decided > index || reach.finished)
                .await
                .is_ok_and(|reach| reach.decided > index);
            if decided {
                decisions.get(index)
            } else {
                Listed::Unknown
            }
        }
    }

    /// What the listing has decided about the key at plan position `index`
    /// so far, without waiting: `None` while it may still decide.
    pub(super) fn known(&self, index: usize) -> Option<Listed> {
        let Some(reach) = self.reach(index) else {
            return Some(Listed::Unknown);
        };
        let reach = *reach.borrow();
        if reach.decided > index {
            Some(self.decisions.get(index))
        } else if reach.finished {
            Some(Listed::Unknown)
        } else {
            None
        }
    }
}

/// What the copy relies on about `key`, the plan's `position`th, once the
/// destination listing has reached it. `complete` is the whole destination,
/// listed before a copy that prunes; `discovery` is the listing that follows
/// the plan.
pub(super) fn listed(
    args: &Args,
    complete: Option<&super::DestinationListing>,
    discovery: Option<&Discovery>,
    position: usize,
    key: &str,
) -> impl Future<Output = Listed> + Send + 'static {
    let complete = complete.map(|keys| in_complete(keys, key));
    let reached = discovery
        .filter(|_| complete.is_none())
        .map(|discovery| discovery.lookup(position));
    let trusted = trusts_absence_of(args, key);
    async move {
        let reached = match reached {
            Some(reached) => Some(reached.await),
            None => None,
        };
        rely(complete, reached, trusted)
    }
}

/// What `listed` will say about `key`, if the listings have already decided
/// it: `None` while the destination listing has yet to reach it.
pub(super) fn known(
    args: &Args,
    complete: Option<&super::DestinationListing>,
    discovery: Option<&Discovery>,
    position: usize,
    key: &str,
) -> Option<Listed> {
    let complete = complete.map(|keys| in_complete(keys, key));
    let reached = match discovery.filter(|_| complete.is_none()) {
        Some(discovery) => Some(discovery.known(position)?),
        None => None,
    };
    Some(rely(complete, reached, trusts_absence_of(args, key)))
}

/// A key outside the prefixes the complete listing covers is unknown, not
/// absent: a copy another machine signs for lists only some prefixes.
fn in_complete(listed: &super::DestinationListing, key: &str) -> Listed {
    match listed.size(key) {
        Some(Some(size)) => Listed::Present(size),
        Some(None) => Listed::Absent,
        None => Listed::Unknown,
    }
}

/// Which answer to rely on, shared by `listed` and `known` so they agree.
fn rely(complete: Option<Listed>, reached: Option<Listed>, trusted: bool) -> Listed {
    match (complete, reached) {
        (Some(listed), _) => listed,
        (None, Some(Listed::Absent)) if !trusted => Listed::Unknown,
        (None, Some(listed)) => listed,
        (None, None) => Listed::Unknown,
    }
}
impl Drop for Discovery {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;
