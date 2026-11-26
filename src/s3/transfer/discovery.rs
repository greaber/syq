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
//!
//! Some copies that do not follow the plan this way still learn from one
//! short request that a prefix holds nothing at all ([`shows_empty`]): every
//! planned key beneath it is then absent, whatever order the store lists in,
//! where the policy may rely on that ([`trusts_empty_prefix`]).
use super::super::authorization::Unsigned;
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
/// HEAD. The listing concludes absence from where a key would fall in a page
/// only where the store lists in byte order, and otherwise only from a
/// complete listing (`Discovery::start`): elsewhere an existing object could
/// look absent, and an upload in its place would drop metadata only the
/// destination has. Copies whose overwrite policy needs current metadata
/// ask with HEAD before proceeding. Existence-only uploads can separately
/// use a listing to rule out keys they would skip, and most policies rely on
/// a prefix shown empty ([`trusts_empty_prefix`]).
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
    args.existing || !(key.ends_with('/') && args.protects_existing_contents())
}

/// Whether a destination prefix shown empty when the copy started
/// ([`shows_empty`]) may spare the planned keys beneath it their HEADs.
/// Another writer can create one of those keys after the probe. Where the
/// policy writes nothing (`--only-existing`, a dry run), writes a key it
/// finds absent with `If-None-Match: *` (`--if-exists=keep`,
/// `error-if-different`, `error`), or replaces whatever is there, that
/// object meets the outcome it would meet if created between a HEAD and the
/// write. `--if-exists=update-if-older` and `--copy-if` would replace it
/// without judging it, so their keys keep their HEADs, which leave only the
/// time from each HEAD to its write.
pub(super) fn trusts_empty_prefix(args: &Args) -> bool {
    !(args.update || args.expressions.update.is_some())
}

/// Planned keys beneath a prefix worth one request to learn that it is
/// empty, for a copy that would not otherwise list its destination. A copy
/// that already sends the request ([`lists_destination`]) uses it at any
/// size.
pub(super) const EMPTY_PROBE_KEYS: usize = KEYS_PER_PAGE;

/// Whether one listing request of a prefix, made without a start or
/// continuation, shows it holds no object at all. Every key beneath it is
/// then absent, whatever order the store lists in. An empty page that is
/// truncated, which a directory bucket may return, shows nothing.
pub(super) fn shows_empty(
    page: &aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output,
) -> bool {
    page.contents().is_empty()
        && page.common_prefixes().is_empty()
        && page.is_truncated() == Some(false)
        && page.next_continuation_token().is_none()
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
pub(super) const KEYS_PER_PAGE: usize = 64;
/// Planned keys beneath a prefix worth its complete listing alongside the
/// copy where the order is unknown. A smaller plan has its keys checked
/// before a page could come back.
const BACKGROUND_KEYS: usize = KEYS_PER_PAGE;

/// Prefixes listed at once. A copy whose requests another machine signs lists
/// each named prefix on its own, and listing them one after another would
/// cost a round trip to the storage service each. The listings that run at
/// once share the prefixes in turn, so earlier ones are decided first.
/// Pruning's complete listings of those prefixes use the same bound.
pub(super) const LISTINGS: usize = 16;

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
/// decides them too (where the order is unknown, only when the prefix holds
/// at most one object). Like a plan of one key, a single key under a prefix
/// is always checked with HEAD.
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

/// The requests the listing sends that do not depend on an earlier response:
/// the first page of each of `segments` it lists, and where the store is in
/// key order but not known to be in byte order (`divides`), the short request
/// that comes first ([`Discovery::start_unordered`]). A copy whose requests
/// another machine signs has these signed together before the listing
/// starts, rather than one round trip to that machine as the listing reaches
/// each segment. The listing sends the pages as [`Walk`] enters each segment,
/// or as [`Walk::whole`] lists it where a key's place in a page shows
/// nothing: in a bucket not in key order, and alongside the copy for a
/// segment of at least [`BACKGROUND_KEYS`] planned keys where the order is
/// unknown. A segment whose planned keys are all too long for S3 is not
/// listed.
pub(super) fn first_pages<'a>(
    segments: &'a [Segment],
    keys: &'a Keys,
    ordered: bool,
    divides: bool,
) -> impl Iterator<Item = Unsigned> + 'a {
    let probe = segments
        .first()
        .filter(|_| ordered && !divides)
        .map(|first| listing::first_key_request(&first.prefix));
    probe.into_iter().chain(
        segments
            .iter()
            .filter_map(move |Segment { prefix, range }| {
                if !ordered || !divides {
                    // `Walk::whole` spends fewer requests than the segment's
                    // keys, and alongside the copy lists only larger plans.
                    let least = if ordered { BACKGROUND_KEYS } else { 2 };
                    return (range.len() >= least)
                        .then(|| listing::first_page_request(prefix, None));
                }
                let start = range
                    .clone()
                    .map(|index| keys.get(index))
                    .find(|key| key.len() <= MAX_KEY)?;
                Some(listing::first_page_request(
                    prefix,
                    Some(&predecessor(start)),
                ))
            }),
    )
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
    saves_head: HeadSavings,
    /// Planned keys by which the pages so far fell short of paying their way.
    shortfall: usize,
    /// The listing has passed every key up to this one.
    passed: String,
    /// Continues the listing from there, unless the last page decided so few
    /// planned keys that the next request should skip to the next one.
    token: Option<String>,
}

#[derive(Clone, Copy)]
enum HeadSavings {
    AnyDecision,
    Present,
    Absent,
}

impl HeadSavings {
    fn counts(self, size: u64) -> bool {
        match self {
            Self::AnyDecision => size != UNKNOWN,
            Self::Present => size < ABSENT,
            Self::Absent => size == ABSENT,
        }
    }
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
            saves_head: HeadSavings::AnyDecision,
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
        debug_assert!(store.divides(), "absence from a page needs byte order");
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
        let mut saved_heads = 0;
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
            saved_heads += usize::from(self.saves_head.counts(size));
            self.decided += 1;
        }
        if complete || self.decided == end {
            return Ok(self.next_segment());
        }
        self.shortfall = (self.shortfall + KEYS_PER_PAGE).saturating_sub(saved_heads);
        self.passed = last.unwrap_or(after).to_owned();
        // A continuation token is how providers page fastest, so keep to it
        // while pages pay their way. After one that did not, start again at
        // the next planned key to skip the destination keys before it.
        let skip =
            saved_heads < KEYS_PER_PAGE && predecessor(self.keys.get(self.decided)) > self.passed;
        self.token = page.next.filter(|_| !skip);
        // The keys still undecided could not make up a larger shortfall.
        let undecided = end - self.decided;
        Ok(self.shortfall <= undecided.min(SLACK_PAGES * KEYS_PER_PAGE) || self.next_segment())
    }

    /// Request the pages the copy waits for. Returns whether another page
    /// is worth requesting.
    async fn before_copy(&mut self, store: &impl Store) -> Result<bool> {
        if !store.ordered() {
            self.whole(store, usize::MAX, 0).await?;
            return Ok(false);
        }
        for _ in 0..PAGES_BEFORE_COPY {
            if !self.page(store).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Decide the only segment from a complete listing of it, which shows at
    /// most `object` and its size.
    fn settle(&mut self, object: Option<(&str, u64)>) {
        let Segment { prefix, range } = &self.segments[0];
        for index in range.clone() {
            let key = self.keys.get(index);
            let size = match object {
                Some((listed, size)) if listed == key => size,
                _ if key.starts_with(prefix.as_str()) => ABSENT,
                _ => UNKNOWN,
            };
            self.decisions.store(index, size);
        }
        self.decided = self.keys.len();
    }

    /// Directory buckets list in no particular order and cannot start after a
    /// key, and other stores may list in an order other than bytes, so only a
    /// complete listing of a prefix shows a key absent. At most `pages`
    /// requests go to each prefix, and none to a prefix with fewer than
    /// `least` planned keys.
    async fn whole(&mut self, store: &impl Store, pages: usize, least: usize) -> Result<()> {
        for Segment { prefix, range } in &self.segments {
            if range.len() < least {
                continue;
            }
            let mut token: Option<String> = None;
            let mut found = 0;
            // Never spend as many LIST requests as checking each key with HEAD.
            for _ in 0..range.len().saturating_sub(1).min(pages) {
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
    /// Whether a key waits for the listing to reach it. Otherwise a key the
    /// listing has not decided yet is unknown.
    waits: bool,
    tasks: Vec<tokio::task::AbortHandle>,
}
impl Discovery {
    /// List the destination for `keys`, which must be in key order, under
    /// each of `segments`, which must not be empty. A destination that cannot
    /// be listed fails the copy here, before it starts; later pages arrive
    /// while the copy runs.
    pub(super) async fn start(
        client: aws_sdk_s3::Client,
        options: &super::super::Options,
        args: &Args,
        segments: Vec<Segment>,
        keys: Keys,
        cancelled: Arc<AtomicBool>,
        progress: Arc<Progress>,
    ) -> Result<Self> {
        ensure!(!segments.is_empty(), "no destination prefix to list");
        // `divides` says only whether these listings may rely on byte order.
        let bucket = options.bucket.as_str();
        let divides = listing::lists_in_byte_order(options.endpoint.as_deref(), bucket);
        if listing::lists_in_key_order(bucket) && !divides {
            return Self::start_unordered(client, bucket, segments, keys, progress).await;
        }
        let decisions = Arc::new(Decisions::new(keys.len()));
        let listings = segments.len().min(LISTINGS);
        let listed = segments
            .iter()
            .enumerate()
            .map(|(index, segment)| (segment.range.clone(), index % listings))
            .collect();
        let keys = Arc::new(keys);
        let saves_head = if args.ignore_existing {
            HeadSavings::Present
        } else if args.existing {
            HeadSavings::Absent
        } else {
            HeadSavings::AnyDecision
        };
        let mut walks: Vec<Walk> = (0..listings)
            .map(|listing| {
                let segments = segments.iter().skip(listing).step_by(listings);
                let mut walk =
                    Walk::new(segments.cloned().collect(), keys.clone(), decisions.clone());
                walk.saves_head = saves_head;
                walk
            })
            .collect();
        // These listings read pages one by one.
        let store = listing::S3 {
            client: client.clone(),
            bucket,
            divides,
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
                    divides,
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
            waits: true,
            tasks,
        })
    }

    /// `start` where the store lists in key order, but not known to be byte
    /// order. A key's place in a page shows it absent only in byte order
    /// (`trusts_absence`); in another order only a complete listing does.
    /// So each prefix is listed whole, within the pages the copy would
    /// otherwise wait for, while the copy goes on: a key the listing has not
    /// decided by the time the copy reaches it gets a HEAD.
    async fn start_unordered(
        client: aws_sdk_s3::Client,
        bucket: &str,
        segments: Vec<Segment>,
        keys: Keys,
        progress: Arc<Progress>,
    ) -> Result<Self> {
        let decisions = Arc::new(Decisions::new(keys.len()));
        let listed = segments
            .iter()
            .map(|segment| (segment.range.clone(), 0))
            .collect();
        let mut walk = Walk::new(segments, Arc::new(keys), decisions.clone());
        let store = listing::S3 {
            client: client.clone(),
            bucket,
            divides: false,
        };
        // A destination that cannot be listed still fails the copy here, from
        // one short request. When the prefix holds at most one object, that
        // request lists it completely.
        let prefix = walk.segments[0].prefix.clone();
        let first = store.first_key(&prefix).await?;
        for entry in &first.entries {
            ensure!(
                entry.key.starts_with(prefix.as_str()),
                "S3 listing returned a key outside the requested prefix"
            );
        }
        // A service that returns more than asked for settles nothing.
        let complete = walk.segments.len() == 1 && first.next.is_none() && first.entries.len() <= 1;
        if complete {
            walk.settle(
                first
                    .entries
                    .first()
                    .map(|entry| (entry.key.as_str(), entry.size)),
            );
        }
        // A small plan reaches its keys before a page could come back.
        let more = !complete
            && walk
                .segments
                .iter()
                .any(|segment| segment.range.len() >= BACKGROUND_KEYS);
        let (sender, reach) = watch::channel(Reach {
            decided: walk.decided,
            finished: !more,
        });
        let mut tasks = Vec::new();
        if more {
            let bucket = bucket.to_owned();
            let task = tokio::spawn(async move {
                let store = listing::S3 {
                    client,
                    bucket: &bucket,
                    divides: false,
                };
                if let Err(error) = walk.whole(&store, PAGES_BEFORE_COPY, BACKGROUND_KEYS).await {
                    progress.warning(&format!(
                        "S3 destination listing stopped; each destination key it did not reach is checked with its own request: {error:#}"
                    ));
                }
                sender.send_replace(Reach {
                    decided: walk.decided,
                    finished: true,
                });
            });
            tasks.push(task.abort_handle());
        }
        Ok(Self {
            listed,
            decisions,
            reach: vec![reach],
            waits: false,
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
    /// listing has passed it or ended; where the order is unknown, at once
    /// (`waits`).
    pub(super) fn lookup(&self, index: usize) -> impl Future<Output = Listed> + Send + 'static {
        let reach = self.reach(index).cloned();
        let decisions = self.decisions.clone();
        let waits = self.waits;
        async move {
            // A key no listing reaches need not wait for one.
            let Some(mut reach) = reach else {
                return Listed::Unknown;
            };
            if !waits {
                // A complete listing of a prefix records its absences only
                // once complete, and a listed key is present: what is
                // recorded holds before the other prefixes are listed.
                return decisions.get(index);
            }
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
        if !self.waits {
            let listed = self.decisions.get(index);
            if listed != Listed::Unknown {
                return Some(listed);
            }
        }
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
/// listed before a copy that prunes; `empty` is a destination prefix that
/// held nothing when the copy started ([`shows_empty`]); `discovery` is the
/// listing that follows the plan.
pub(super) fn listed(
    args: &Args,
    complete: Option<&super::DestinationListing>,
    empty: Option<&str>,
    discovery: Option<&Discovery>,
    position: usize,
    key: &str,
) -> impl Future<Output = Listed> + Send + 'static {
    let complete = complete.map(|keys| in_complete(keys, key));
    let empty_absent = in_empty(args, empty, key);
    let reached = discovery
        .filter(|_| complete.is_none())
        .map(|discovery| discovery.lookup(position));
    let trusted = trusts_listed_absence_of(args, key);
    async move {
        let reached = match reached {
            Some(reached) => Some(reached.await),
            None => None,
        };
        rely(complete, empty_absent, reached, trusted)
    }
}

/// What `listed` will say about `key`, if the listings have already decided
/// it: `None` while the destination listing has yet to reach it.
pub(super) fn known(
    args: &Args,
    complete: Option<&super::DestinationListing>,
    empty: Option<&str>,
    discovery: Option<&Discovery>,
    position: usize,
    key: &str,
) -> Option<Listed> {
    let complete = complete.map(|keys| in_complete(keys, key));
    let empty_absent = in_empty(args, empty, key);
    let reached = match discovery.filter(|_| complete.is_none()) {
        Some(discovery) => Some(discovery.known(position)?),
        None => None,
    };
    Some(rely(
        complete,
        empty_absent,
        reached,
        trusts_listed_absence_of(args, key),
    ))
}

/// Whether an absence the listing that follows the plan reports may be
/// relied on for `key`. Under `--if-exists=keep` it never is: that listing
/// may conclude absence from a key's place in a page, and the write that
/// follows must create its object, so a key it missed would fail the copy
/// rather than be kept. Only a prefix shown empty, or a complete listing,
/// spares that policy its HEAD.
fn trusts_listed_absence_of(args: &Args, key: &str) -> bool {
    !args.ignore_existing && trusts_absence_of(args, key)
}

/// `key` is absent if it lies beneath `empty`, a prefix that held nothing
/// when the copy started, and the policy may rely on its absence
/// ([`trusts_empty_prefix`]). A key outside it, such as a named file beside a
/// signed prefix, is not decided.
fn in_empty(args: &Args, empty: Option<&str>, key: &str) -> Option<Listed> {
    empty
        .filter(|prefix| {
            key.starts_with(prefix) && trusts_empty_prefix(args) && trusts_absence_of(args, key)
        })
        .map(|_| Listed::Absent)
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
fn rely(
    complete: Option<Listed>,
    empty_absent: Option<Listed>,
    reached: Option<Listed>,
    trusted: bool,
) -> Listed {
    match (complete, reached, empty_absent) {
        (Some(listed), _, _) => listed,
        // A positive listing result from a concurrent listing always beats an
        // earlier empty probe so an object that appeared after the probe is
        // not treated as absent.
        (None, Some(present @ Listed::Present(_)), _) => present,
        (None, _, Some(absent)) => absent,
        (None, Some(Listed::Absent), None) if !trusted => Listed::Unknown,
        (None, Some(listed), None) => listed,
        (None, None, None) => Listed::Unknown,
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
