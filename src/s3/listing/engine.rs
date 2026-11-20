//! Prefix-directed discovery inspired by s3glob v0.4.17:
//! https://github.com/quodlibetor/s3glob/blob/v0.4.17/src/glob_matcher.rs
//! This implementation uses bounded page-sized work and the listing command's
//! own pattern semantics; no upstream source is copied.
use super::pattern::Pattern;
use anyhow::{ensure, Context, Result};
use futures_util::{stream::FuturesUnordered, StreamExt};
use serde::Serialize;
use std::{
    collections::VecDeque,
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
};

mod parts;

const MAX_CHILDREN: usize = 256;
const SPLIT_QUEUE_LIMIT: usize = 4096;

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

    /// Whether a listing may rely on the store returning keys in UTF-8 byte
    /// order. Only stores whose provider documents that order divide: a
    /// listing with more than one request slot is then divided into parts
    /// that run at the same time (`parts`), and an exact key is looked for on
    /// the first page only. Every part but the last stops at the first key
    /// handed over, so a key that the store returns out of order after that
    /// point would be missed without an error. Other stores are listed one
    /// page after another, which does not depend on the order.
    fn divides(&self) -> bool {
        false
    }

    fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> impl Future<Output = Result<Page>>;
}

// A task can overlap a delimiter probe and a continuation page; bound actual
// HTTP requests as well as task count, including with an explicit limit of two.
struct LimitedStore<'a, S> {
    inner: &'a S,
    slots: tokio::sync::Semaphore,
}
impl<S: Store> Store for LimitedStore<'_, S> {
    fn ordered(&self) -> bool {
        self.inner.ordered()
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
        let _permit = self.slots.acquire().await?;
        self.inner.page(prefix, delimiter, token, start_after).await
    }
}

/// Keys arrived out of order after part of a listing was handed to other
/// listings, so the listing may have stopped before its last key. A listing
/// that is not divided does not depend on the order.
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

/// The context of a failed listing of a narrower prefix that a listing in
/// parts made: a policy may allow listing only the prefix itself.
#[derive(Debug)]
pub(in crate::s3) struct PartFailed;
impl std::fmt::Display for PartFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("listing part of the prefix by itself failed")
    }
}

/// Whether a request failed because a policy refused it.
fn refused(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<crate::s3::client::RequestFailure>()
        .is_some_and(crate::s3::client::RequestFailure::denied)
}

/// Whether a key the pattern wants could be missing from the page after
/// `page`, in a store that skips only the key `P0` after a common prefix `P/`
/// in whatever order it lists.
fn may_hide(page: &Page, wanted: impl Fn(&str) -> bool) -> bool {
    page.next.is_some()
        && page.prefixes.iter().any(|prefix| {
            prefix.strip_suffix('/').is_some_and(|stem| {
                let key = format!("{stem}0");
                // A key the page already holds is not missing.
                wanted(&key) && page.entries.iter().all(|entry| entry.key != key)
            })
        })
}

/// Whether the store's listings may rely on UTF-8 byte order.
fn byte_ordered(store: &impl Store) -> bool {
    store.ordered() && store.divides()
}

/// Whether this listing is divided into parts rather than listed as below.
fn in_parts(store: &impl Store, concurrency: usize) -> bool {
    concurrency > 1 && byte_ordered(store)
}

#[derive(Clone)]
enum Job {
    Discover {
        prefix: String,
        component: usize,
    },
    Recursive {
        prefix: String,
    },
    Scan {
        prefix: String,
        delimiter: bool,
        token: String,
        gap: Gap,
    },
}

struct Batch {
    entries: Vec<Entry>,
    jobs: Vec<Job>,
    pruned: Vec<String>,
}

/// A page and the request for the next one. `gap` is the key that request
/// must make sure of (`Gap::after`).
fn scan_batch(prefix: String, delimiter: bool, page: Page, gap: Gap) -> Batch {
    Batch {
        entries: page.entries,
        jobs: page
            .next
            .map(|token| Job::Scan {
                prefix,
                delimiter,
                token,
                gap,
            })
            .into_iter()
            .collect(),
        pruned: Vec::new(),
    }
}

/// The key a store may leave out of the page after one that ends with a
/// common prefix.
///
/// After a delimiter page that ends with the common prefix `P/`, Tigris
/// resumes the listing past the key `P0` instead of at it, so that key, if it
/// exists, is missing from the next page. In byte order nothing else can come
/// between the two, and a listing of `P0` itself shows the key first. So the
/// next page is read together with that listing, and the key is added if the
/// page left it out. That check relies on byte order, so it is made only
/// where the store's order is known (`byte_ordered`); every such store is
/// checked, since the same mistake is easy to make elsewhere. Elsewhere a
/// delimiter listing goes on past its first page only while no page that
/// goes on holds a common prefix whose skipped key the pattern could match
/// (`may_hide`).
#[derive(Clone, Default)]
pub(super) struct Gap {
    /// The key to make sure of on the next page.
    key: Option<String>,
    /// Where the order is unknown, a policy refused the listing without a
    /// delimiter that was to replace this one. Reported if a page that goes
    /// on holds a common prefix whose skipped key the pattern could match.
    refused: Option<String>,
}

impl Gap {
    /// The key to make sure of after `page`, if it ends with a common prefix
    /// and the key is `wanted`.
    pub(super) fn after(page: &Page, wanted: impl Fn(&str) -> bool) -> Self {
        Self {
            key: page
                .next
                .as_ref()
                .and(page.prefixes.last())
                .filter(|last| page.entries.last().is_none_or(|entry| entry.key < **last))
                .and_then(|last| last.strip_suffix('/'))
                .map(|stem| format!("{stem}0"))
                .filter(|key| wanted(key)),
            refused: None,
        }
    }

    /// Read the page at `token`, adding the key if the store left it out,
    /// and return it with what to make sure of on the page after it.
    pub(super) async fn read(
        self,
        store: &impl Store,
        prefix: &str,
        delimiter: bool,
        token: &str,
        wanted: impl Fn(&str) -> bool,
    ) -> Result<(Page, Gap)> {
        let Gap { key, refused } = self;
        let page = match key {
            None => read(store, prefix, delimiter, Some(token)).await?,
            Some(key) => {
                debug_assert!(byte_ordered(store), "checks rely on byte order");
                // The check runs while the page is read, and is dropped
                // unfinished if the page settles the question.
                let main = read(store, prefix, delimiter, Some(token));
                let check = read(store, &key, true, None);
                tokio::pin!(main, check);
                let mut checked = None;
                let mut page = loop {
                    tokio::select! {
                        // With one request slot free, the page goes first.
                        biased;
                        page = &mut main => break page?,
                        result = &mut check, if checked.is_none() => checked = Some(result),
                    }
                };
                if page.entries.is_empty() && page.prefixes.is_empty() && page.next.is_some() {
                    // An empty page shows nothing; the next one starts at
                    // the key or past it.
                    return Ok((
                        page,
                        Gap {
                            key: Some(key.clone()),
                            refused,
                        },
                    ));
                }
                if page.entries.first().is_none_or(|entry| entry.key != key) {
                    let check = match checked {
                        Some(check) => check,
                        None => check.await,
                    };
                    if let Some(entry) = Self::find(store, &key, check).await? {
                        page.entries.insert(0, entry);
                    }
                }
                page
            }
        };
        if let Some(refused) = &refused {
            ensure!(!may_hide(&page, &wanted), "{refused}");
        }
        // Where the order is unknown, nothing is checked (`may_hide` above).
        let next = match refused {
            Some(refused) => Gap {
                key: None,
                refused: Some(refused),
            },
            None => Gap::after(&page, wanted),
        };
        Ok((page, next))
    }

    /// The object `key`, from a listing of it whose first page is `first`.
    async fn find(store: &impl Store, key: &str, first: Result<Page>) -> Result<Option<Entry>> {
        let context = || {
            format!("listing {key:?} to check for a key the store may have skipped after the common prefix before it")
        };
        let mut page = first.with_context(context)?;
        // In byte order the key comes first, but an empty page shows nothing.
        while page.entries.is_empty() && page.prefixes.is_empty() {
            let Some(token) = page.next else {
                break;
            };
            page = read(store, key, true, Some(&token))
                .await
                .with_context(context)?;
        }
        Ok(page
            .entries
            .into_iter()
            .next()
            .filter(|entry| entry.key == key))
    }
}

pub(in crate::s3) async fn read(
    store: &impl Store,
    prefix: &str,
    delimiter: bool,
    token: Option<&str>,
) -> Result<Page> {
    let page = store.page(prefix, delimiter, token, None).await?;
    ensure!(
        page.entries.len() + page.prefixes.len() <= 1000,
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
) -> Result<Batch> {
    let (mut prefix, mut component) = match job {
        Job::Recursive { prefix } => return recursive(store, prune, prefix).await,
        Job::Scan {
            prefix,
            delimiter,
            token,
            gap,
        } => {
            // Only the last component of a pattern pages with a delimiter.
            let (page, gap) = gap
                .read(store, &prefix, delimiter, &token, |key| {
                    pattern.is_none_or(|pattern| pattern.matches(key))
                })
                .await?;
            return Ok(scan_batch(prefix, delimiter, page, gap));
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
        return Ok(scan_batch(query, false, page, Gap::default()));
    }
    let page = read(store, &query, true, None).await?;
    if component + 1 == pattern.components.len() {
        if page.next.is_some() && !byte_ordered(store) && !part.literal() && part.may_end_with('0')
        {
            // Making sure of a key a page may leave out (`Gap`) relies on
            // byte order. List everything under the prefix instead, unless
            // the pattern cannot match that key: it ends in '0' and is
            // longer than the prefix, so a literal name is never it. That
            // assumes a store in another order would leave out only that
            // key, as Tigris does in byte order; none is known to leave out
            // any.
            let why = || {
                format!("listing {query:?} without a delimiter, since a later delimiter page could leave out a key")
            };
            match read(store, &query, false, None).await {
                Ok(flat) => {
                    static SAID: std::sync::Once = std::sync::Once::new();
                    SAID.call_once(|| {
                        crate::output::diagnostic!(
                            "syq _ls: listing every key under {query:?} without a delimiter, which can take much longer; other prefixes the pattern's last part reaches are listed the same way when their listings need more than one page: this store may not list keys in byte order, and its later delimiter pages could leave a key out"
                        );
                    });
                    return Ok(scan_batch(query, false, flat, Gap::default()));
                }
                // A policy may require a delimiter. Go on with it while no
                // page could be followed by a wanted key left out.
                Err(error) if refused(&error) && !may_hide(&page, |key| pattern.matches(key)) => {
                    let gap = Gap {
                        key: None,
                        refused: Some(format!("{:#}", error.context(why()))),
                    };
                    return Ok(scan_batch(query, true, page, gap));
                }
                Err(error) => return Err(error.context(why())),
            }
        }
        let gap = Gap::after(&page, |key| pattern.matches(key));
        return Ok(scan_batch(query, true, page, gap));
    }
    if page.next.is_some() || page.prefixes.len() > MAX_CHILDREN {
        let flat = read(store, &query, false, None).await?;
        return Ok(scan_batch(query, false, flat, Gap::default()));
    }
    Ok(Batch {
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
    })
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

/// List everything under `query` one page after another, apart from the
/// lookahead when filtered. Any store's order will do.
async fn recursive(store: &impl Store, prune: Option<&Prune<'_>>, query: String) -> Result<Batch> {
    let flat = read(store, &query, false, None).await?;
    if let Some(prune) = prune {
        if let Some(batch) = lookahead(store, prune, &query, &flat).await? {
            return Ok(batch);
        }
    }
    Ok(scan_batch(query, false, flat, Gap::default()))
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
    if pattern.components.iter().all(|part| part.literal()) {
        let key = pattern
            .components
            .iter()
            .map(|part| part.literal_prefix())
            .collect::<Vec<_>>()
            .join("/");
        // Keep LIST permissions (no HEAD). In byte order the exact key, if
        // present, precedes every longer key on the first page that holds
        // anything; an empty page that goes on settles nothing.
        let mut page = read(store, &key, false, None).await?;
        if byte_ordered(store) {
            while page.entries.is_empty() {
                let Some(token) = page.next else {
                    break;
                };
                page = read(store, &key, false, Some(&token)).await?;
            }
        }
        let flat = page.next;
        if let Some(entry) = page.entries.into_iter().find(|entry| entry.key == key) {
            return emit(entry);
        }
        if flat.is_none() || byte_ordered(store) {
            return Ok(());
        }
        // In another order it can come after longer keys. A delimiter
        // listing leaves out the deeper ones; stop at the key. Where a policy
        // refuses delimiter listings, the flat one goes on instead.
        let (mut delimiter, mut token) = (true, None);
        loop {
            let page = match read(store, &key, delimiter, token.as_deref()).await {
                Err(error) if delimiter && token.is_none() && refused(&error) => {
                    (delimiter, token) = (false, flat.clone());
                    continue;
                }
                page => page?,
            };
            if let Some(entry) = page.entries.into_iter().find(|entry| entry.key == key) {
                return emit(entry);
            }
            let Some(next) = page.next else {
                return Ok(());
            };
            token = Some(next);
        }
    }
    if in_parts(store, concurrency) {
        return parts::enumerate(store, pattern, concurrency, &mut emit).await;
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
/// With `prune`, directories it names may be skipped: their common prefixes
/// are returned instead of being listed. Objects in pruned directories may
/// still be emitted, so callers must classify every entry themselves. Unless
/// the listing is divided into parts, it stays flat apart from the lookahead.
///
/// A listing in parts fails with [`Unordered`] when keys arrive out of order
/// after part of it was handed to others; with a concurrency of one, or a
/// store that does not divide, it is never in parts.
pub(in crate::s3) async fn enumerate_prefix(
    store: &impl Store,
    prefix: &str,
    concurrency: usize,
    prune: Option<&Prune<'_>>,
    mut emit: impl FnMut(Entry) -> Result<()>,
) -> Result<Vec<String>> {
    ensure!(
        (1..=256).contains(&concurrency),
        "concurrency must be between 1 and 256"
    );
    if in_parts(store, concurrency) {
        return parts::enumerate_prefix(store, prefix, concurrency, prune, &mut emit).await;
    }
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
    let store = LimitedStore {
        inner: store,
        slots: tokio::sync::Semaphore::new(concurrency),
    };
    let mut pending = VecDeque::from([first]);
    let mut pruned = Vec::new();
    let mut active = FuturesUnordered::new();
    loop {
        while active.len() < concurrency {
            let Some(job) = pending.pop_front() else {
                break;
            };
            let split = concurrency > 1 && pending.len() + active.len() < SPLIT_QUEUE_LIMIT;
            active.push(execute(&store, pattern, prune, job, split));
        }
        let Some(batch) = active.next().await else {
            return Ok(pruned);
        };
        let batch = batch?;
        for entry in batch.entries {
            if pattern.is_none_or(|pattern| pattern.matches(&entry.key)) {
                emit(entry)?;
            }
        }
        pending.extend(batch.jobs);
        pruned.extend(batch.pruned);
    }
}
