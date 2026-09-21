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
const SPLIT_QUEUE_LIMIT: usize = 4096;
const MAX_RECURSIVE_PROBES: usize = 4;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Entry {
    pub key: String,
    pub size: u64,
    pub last_modified: Option<String>,
    pub etag: Option<String>,
}

#[derive(Default)]
pub(super) struct Page {
    pub entries: Vec<Entry>,
    pub prefixes: Vec<String>,
    pub next: Option<String>,
}

pub(super) trait Store {
    fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
    ) -> impl Future<Output = Result<Page>>;
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
    },
    Scan {
        prefix: String,
        delimiter: bool,
        token: Option<String>,
    },
}

struct Batch {
    entries: Vec<Entry>,
    jobs: Vec<Job>,
}

fn scan_batch(prefix: String, delimiter: bool, page: Page) -> Batch {
    Batch {
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
    }
}

async fn read(
    store: &impl Store,
    prefix: &str,
    delimiter: bool,
    token: Option<&str>,
) -> Result<Page> {
    let page = store.page(prefix, delimiter, token).await?;
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

async fn execute(store: &impl Store, pattern: &Pattern, job: Job, split: bool) -> Result<Batch> {
    let (mut prefix, mut component, depth) = match job {
        Job::Recursive { prefix, depth } => return recursive(store, prefix, depth, split).await,
        Job::Scan {
            prefix,
            delimiter,
            token,
        } => {
            let page = read(store, &prefix, delimiter, token.as_deref()).await?;
            return Ok(scan_batch(prefix, delimiter, page));
        }
        Job::Discover {
            prefix,
            component,
            depth,
        } => (prefix, component, depth),
    };
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
        return recursive(store, query, depth, split).await;
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

async fn recursive(store: &impl Store, query: String, depth: usize, split: bool) -> Result<Batch> {
    let flat = read(store, &query, false, None).await?;
    if flat.next.is_none() || !split || depth >= MAX_RECURSIVE_PROBES {
        return Ok(scan_batch(query, false, flat));
    }
    let branches = read(store, &query, true, None).await?;
    if branches.next.is_some()
        || branches.prefixes.is_empty()
        || branches.prefixes.len() > MAX_CHILDREN
    {
        // Keep the original flat page and its token; never mix tokens from
        // delimiter and recursive listings or re-emit a sampled page.
        return Ok(scan_batch(query, false, flat));
    }
    Ok(Batch {
        entries: branches.entries,
        jobs: branches
            .prefixes
            .into_iter()
            .map(|prefix| Job::Recursive {
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
    let mut pending = VecDeque::from([Job::Discover {
        prefix: String::new(),
        component: 0,
        depth: 0,
    }]);
    let mut active = FuturesUnordered::new();
    loop {
        while active.len() < concurrency {
            let Some(job) = pending.pop_front() else {
                break;
            };
            let split = concurrency > 1 && pending.len() + active.len() < SPLIT_QUEUE_LIMIT;
            active.push(execute(store, pattern, job, split));
        }
        let Some(batch) = active.next().await else {
            return Ok(());
        };
        let batch = batch?;
        for entry in batch.entries {
            if pattern.matches(&entry.key) {
                emit(entry)?;
            }
        }
        pending.extend(batch.jobs);
    }
}
