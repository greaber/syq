//! Prefix-directed discovery inspired by s3glob v0.4.17:
//! https://github.com/quodlibetor/s3glob/blob/v0.4.17/src/glob_matcher.rs
//! This implementation uses bounded page-sized work and the listing command's
//! own pattern semantics; no upstream source is copied.
use super::pattern::Pattern;
use anyhow::{ensure, Result};
use futures_util::{stream::FuturesUnordered, StreamExt};
use serde::Serialize;
use std::{collections::VecDeque, future::Future};

const MAX_CHILDREN: usize = 256;
// Recursive discovery has no selective pattern to amortize empty/small child
// requests. Require evidence of substantial child prefixes and bound speculative fanout.
const MAX_RECURSIVE_CHILDREN: usize = 64;
const SPLIT_QUEUE_LIMIT: usize = 4096;
const MAX_RECURSIVE_PROBES: usize = 4;

#[derive(Clone, Debug, Serialize)]
pub(in crate::s3) struct Entry {
    pub key: String,
    pub size: u64,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
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

#[derive(Clone)]
enum Job {
    Discover {
        prefix: String,
        component: usize,
        depth: usize,
    },
    Recursive {
        prefix: String,
        depth: usize,
        start_after: Option<String>,
    },
    Scan {
        prefix: String,
        delimiter: bool,
        token: Option<String>,
        start_after: Option<String>,
    },
}

struct Batch {
    entries: Vec<Entry>,
    jobs: Vec<Job>,
}

fn scan_batch(prefix: String, delimiter: bool, page: Page, start_after: Option<&str>) -> Batch {
    Batch {
        entries: page.entries,
        jobs: page
            .next
            .map(|token| Job::Scan {
                prefix,
                delimiter,
                token: Some(token),
                start_after: start_after.map(str::to_owned),
            })
            .into_iter()
            .collect(),
    }
}

pub(in crate::s3) async fn read(
    store: &impl Store,
    prefix: &str,
    delimiter: bool,
    token: Option<&str>,
) -> Result<Page> {
    read_after(store, prefix, delimiter, token, None).await
}

async fn read_after(
    store: &impl Store,
    prefix: &str,
    delimiter: bool,
    token: Option<&str>,
    start_after: Option<&str>,
) -> Result<Page> {
    // Keep the wire request unchanged for continuation pages. The token carries
    // the service position; StartAfter remains a local lower bound even when a
    // provider silently ignores it on the initial request.
    let mut page = store
        .page(
            prefix,
            delimiter,
            token,
            start_after.filter(|_| token.is_none()),
        )
        .await?;
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
    if let Some(after) = start_after {
        page.entries.retain(|entry| entry.key.as_str() > after);
    }
    Ok(page)
}

async fn execute(
    store: &impl Store,
    pattern: Option<&Pattern>,
    job: Job,
    split: bool,
) -> Result<Batch> {
    let (mut prefix, mut component, depth) = match job {
        Job::Recursive {
            prefix,
            depth,
            start_after,
        } => return recursive(store, prefix, depth, split, start_after.as_deref()).await,
        Job::Scan {
            prefix,
            delimiter,
            token,
            start_after,
        } => {
            let page = read_after(
                store,
                &prefix,
                delimiter,
                token.as_deref(),
                start_after.as_deref(),
            )
            .await?;
            return Ok(scan_batch(prefix, delimiter, page, start_after.as_deref()));
        }
        Job::Discover {
            prefix,
            component,
            depth,
        } => (prefix, component, depth),
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
        return recursive(store, query, depth, split, None).await;
    }
    if !split && component + 1 < pattern.components.len() {
        let page = read(store, &query, false, None).await?;
        return Ok(scan_batch(query, false, page, None));
    }
    let page = read(store, &query, true, None).await?;
    if component + 1 == pattern.components.len() {
        return Ok(scan_batch(query, true, page, None));
    }
    if page.next.is_some() || page.prefixes.len() > MAX_CHILDREN {
        let flat = read(store, &query, false, None).await?;
        return Ok(scan_batch(query, false, flat, None));
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
                depth: 0,
            })
            .collect(),
    })
}

fn dense_children(query: &str, page: &Page) -> usize {
    let mut counts = std::collections::HashMap::new();
    for entry in &page.entries {
        if let Some(slash) = entry
            .key
            .strip_prefix(query)
            .and_then(|suffix| suffix.find('/'))
        {
            *counts
                .entry(&entry.key[..query.len() + slash + 1])
                .or_insert(0usize) += 1;
        }
    }
    // A quarter-page child can amortize parallel requests at network latency;
    // tiny directories cannot. This estimates density, not the total key count.
    counts.values().filter(|count| **count >= 256).count()
}

async fn recursive(
    store: &impl Store,
    query: String,
    depth: usize,
    split: bool,
    start_after: Option<&str>,
) -> Result<Batch> {
    let mut flat = read_after(store, &query, false, None, start_after).await?;
    if flat.next.is_none()
        || !split
        || !store.ordered()
        || depth >= MAX_RECURSIVE_PROBES
        || flat.entries.len() < 1000
        || dense_children(&query, &flat) == 0
    {
        return Ok(scan_batch(query, false, flat, start_after));
    }
    // Continue useful enumeration while probing. Small two-page trees finish
    // here, and rejected probes add no sequential round trip to flat scans.
    let (branches, continuation) = tokio::join!(
        read(store, &query, true, None),
        read_after(store, &query, false, flat.next.as_deref(), start_after),
    );
    let continuation = continuation?;
    flat.entries.extend(continuation.entries);
    flat.next = continuation.next;
    if flat.next.is_none() {
        return Ok(scan_batch(query, false, flat, start_after));
    }
    let branches = branches?;
    if branches.next.is_some() || !(2..=MAX_RECURSIVE_CHILDREN).contains(&branches.prefixes.len()) {
        return Ok(scan_batch(query, false, flat, start_after));
    }
    // One dense leading directory says little about its siblings. Spend at
    // most one more useful flat page looking for a second substantial child.
    if dense_children(&query, &flat) < 2 {
        let next = read_after(store, &query, false, flat.next.as_deref(), start_after).await?;
        flat.entries.extend(next.entries);
        flat.next = next.next;
    }
    if flat.next.is_none() || dense_children(&query, &flat) < 2
        || !flat.entries.windows(2).all(|pair| pair[0].key < pair[1].key)
        // Do not replace an observed key with an incomplete directory view.
        || flat.entries.iter().any(|entry| {
            !branches.entries.iter().any(|direct| direct.key == entry.key)
                && !branches.prefixes.iter().any(|child| entry.key.starts_with(child))
        })
    {
        return Ok(scan_batch(query, false, flat, start_after));
    }
    // Retain every sampled child entry, then resume the partial last child
    // strictly after the last sampled key. Continuation tokens stay with their
    // original request; StartAfter establishes a new child-prefix listing.
    let last = flat.entries.last().unwrap().key.clone();
    let mut entries: Vec<_> = branches
        .entries
        .into_iter()
        .filter(|entry| start_after.is_none_or(|start| entry.key.as_str() > start))
        .collect();
    entries.extend(flat.entries.into_iter().filter(|entry| {
        branches
            .prefixes
            .iter()
            .any(|prefix| entry.key.starts_with(prefix))
    }));
    Ok(Batch {
        entries,
        jobs: branches
            .prefixes
            .into_iter()
            .filter(|prefix| prefix >= &last || last.starts_with(prefix))
            .map(|prefix| Job::Recursive {
                start_after: last.starts_with(&prefix).then(|| last.clone()),
                prefix,
                depth: depth + 1,
            })
            .collect(),
    })
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
        concurrency,
        Job::Discover {
            prefix: String::new(),
            component: 0,
            depth: 0,
        },
        &mut emit,
    )
    .await
}

/// Literal prefixes from copy/removal selectors must never be parsed as globs.
/// This only changes request scheduling; callers still validate and interpret
/// object metadata, source types and destination mappings.
pub(in crate::s3) async fn enumerate_prefix(
    store: &impl Store,
    prefix: &str,
    concurrency: usize,
    mut emit: impl FnMut(Entry) -> Result<()>,
) -> Result<()> {
    enumerate_jobs(
        store,
        None,
        concurrency,
        Job::Recursive {
            prefix: prefix.to_owned(),
            depth: 0,
            start_after: None,
        },
        &mut emit,
    )
    .await
}

async fn enumerate_jobs(
    store: &impl Store,
    pattern: Option<&Pattern>,
    concurrency: usize,
    first: Job,
    emit: &mut impl FnMut(Entry) -> Result<()>,
) -> Result<()> {
    ensure!(
        (1..=256).contains(&concurrency),
        "concurrency must be between 1 and 256"
    );
    let store = LimitedStore {
        inner: store,
        slots: tokio::sync::Semaphore::new(concurrency),
    };
    let mut pending = VecDeque::from([first]);
    let mut active = FuturesUnordered::new();
    loop {
        while active.len() < concurrency {
            let Some(job) = pending.pop_front() else {
                break;
            };
            let split = concurrency > 1 && pending.len() + active.len() < SPLIT_QUEUE_LIMIT;
            active.push(execute(&store, pattern, job, split));
        }
        let Some(batch) = active.next().await else {
            return Ok(());
        };
        let batch = batch?;
        for entry in batch.entries {
            if pattern.is_none_or(|pattern| pattern.matches(&entry.key)) {
                emit(entry)?;
            }
        }
        pending.extend(batch.jobs);
    }
}
