//! Listing a prefix level by level to a bounded depth, for `syq find --depth`
//! and `syq ls`.
//!
//! Each directory is listed with the delimiter `/`, so its common prefixes
//! name its subdirectories without listing what they hold, and those are
//! listed in turn while they are shallower than the depth. A directory
//! marker is hidden in its common prefix at its parent's level, and shows
//! only as the first key of its own listing, where it is left out: every
//! directory is reported once, by its common prefix.
//!
//! A delimiter listing that goes past a page uses [`Gap`] to check for a key
//! after the page's last common prefix (except on directory buckets, which
//! require trailing slashes on prefixes).
use super::{byte_ordered, read, refused, Entry, Gap, LimitedStore, Page, Store};
use anyhow::{ensure, Context, Result};
use futures_util::{stream::FuturesUnordered, StreamExt};

/// What a level listing found.
pub(in crate::s3) enum Found {
    Object(Entry),
    /// A directory, ending with `/`: a common prefix, a directory marker, or
    /// the parent of a deeper key.
    Directory(String),
}

enum Job {
    /// The delimiter listing of the directory `prefix` at `depth`: its
    /// first page, or the page at `token`. `last` is the last common prefix
    /// of the page before, which a store might repeat.
    Level {
        prefix: String,
        depth: u32,
        token: Option<String>,
        gap: Gap,
        last: Option<String>,
    },
}

struct Batch {
    found: Vec<Found>,
    jobs: Vec<Job>,
}

/// List `root`, empty or ending with `/`, to `max_depth` levels, at least 1.
/// `descend(prefix)` says whether the directory `prefix` is listed; its
/// entry is reported either way. A directory beyond the first level is
/// listed only when its parent is.
pub(in crate::s3) async fn walk(
    store: &impl Store,
    root: &str,
    max_depth: u32,
    concurrency: usize,
    descend: &(dyn Fn(&str) -> bool + Sync),
    mut emit: impl FnMut(Found) -> Result<()>,
) -> Result<()> {
    ensure!(max_depth >= 1, "the depth must be at least 1");
    ensure!(
        (1..=256).contains(&concurrency),
        "concurrency must be between 1 and 256"
    );
    let store = LimitedStore {
        inner: store,
        slots: tokio::sync::Semaphore::new(concurrency),
    };
    let mut pending = vec![Job::Level {
        prefix: root.to_owned(),
        depth: 0,
        token: None,
        gap: Gap::default(),
        last: None,
    }];
    let mut active = FuturesUnordered::new();
    loop {
        while active.len() < concurrency {
            let Some(job) = pending.pop() else {
                break;
            };
            active.push(execute(&store, job, max_depth, descend));
        }
        let Some(batch) = active.next().await else {
            return Ok(());
        };
        let batch = batch?;
        for found in batch.found {
            emit(found)?;
        }
        pending.extend(batch.jobs);
    }
}

async fn execute(
    store: &impl Store,
    job: Job,
    max_depth: u32,
    descend: &(dyn Fn(&str) -> bool + Sync),
) -> Result<Batch> {
    match job {
        Job::Level {
            prefix,
            depth,
            token: Some(token),
            gap,
            last,
        } => {
            let (page, gap) = gap.read(store, &prefix, true, &token, |_| true).await?;
            Ok(level(prefix, depth, page, gap, last, max_depth, descend))
        }
        Job::Level {
            prefix,
            depth,
            token: None,
            ..
        } => {
            let page = read(store, &prefix, true, None).await?;
            let gap = Gap::after(store, &page, |_| true);
            Ok(level(prefix, depth, page, gap, None, max_depth, descend))
        }
    }
}

/// A page of the delimiter listing of `prefix`, the directory at `depth`.
fn level(
    prefix: String,
    depth: u32,
    page: Page,
    gap: Gap,
    last: Option<String>,
    max_depth: u32,
    descend: &(dyn Fn(&str) -> bool + Sync),
) -> Batch {
    let mut found = Vec::with_capacity(page.entries.len() + page.prefixes.len());
    let mut jobs = Vec::new();
    let next_last = page.prefixes.last().cloned().or(last.clone());
    // Report the page in key order: its objects and its subdirectories come
    // in two lists, each in that order.
    let mut entries = page.entries.into_iter().peekable();
    let mut objects = |found: &mut Vec<Found>, before: Option<&str>| {
        while let Some(entry) =
            entries.next_if(|entry| before.is_none_or(|child| entry.key.as_str() < child))
        {
            // The directory's own marker was reported by its common
            // prefix; an object of the same name with contents is not.
            if entry.key != prefix || (entry.size > 0 && depth > 0) {
                found.push(Found::Object(entry));
            }
        }
    };
    for child in page.prefixes {
        objects(&mut found, Some(&child));
        if last.as_ref() == Some(&child) {
            continue;
        }
        if depth + 1 < max_depth && descend(&child) {
            jobs.push(Job::Level {
                prefix: child.clone(),
                depth: depth + 1,
                token: None,
                gap: Gap::default(),
                last: None,
            });
        }
        found.push(Found::Directory(child));
    }
    objects(&mut found, None);
    if let Some(token) = page.next {
        jobs.push(Job::Level {
            prefix,
            depth,
            token: Some(token),
            gap,
            last: next_last,
        });
    }
    Batch { found, jobs }
}

/// Look for the object `key` with listings only: the object, if any, and
/// whether a key under `key/` showed on the way. As in [`super::enumerate`],
/// in byte order the key comes first on the first page that holds anything;
/// in another order, a delimiter listing stops at it.
pub(in crate::s3) async fn exact(store: &impl Store, key: &str) -> Result<(Option<Entry>, bool)> {
    let directory = format!("{key}/");
    let under = |page: &Page| {
        page.entries
            .iter()
            .any(|entry| entry.key.starts_with(&directory))
            || page.prefixes.contains(&directory)
    };
    let mut page = read(store, key, false, None).await?;
    if byte_ordered(store) {
        while page.entries.is_empty() {
            let Some(token) = page.next else {
                break;
            };
            page = read(store, key, false, Some(&token)).await?;
        }
    }
    let mut seen = under(&page);
    let flat = page.next.take();
    if let Some(entry) = page.entries.into_iter().find(|entry| entry.key == key) {
        return Ok((Some(entry), seen));
    }
    if flat.is_none() || byte_ordered(store) {
        return Ok((None, seen));
    }
    let (mut delimiter, mut token) = (true, None);
    loop {
        let page = match read(store, key, delimiter, token.as_deref()).await {
            Err(error) if delimiter && token.is_none() && refused(&error) => {
                (delimiter, token) = (false, flat.clone());
                continue;
            }
            page => page.with_context(|| format!("looking for the S3 object {key:?}"))?,
        };
        seen |= under(&page);
        if let Some(entry) = page.entries.into_iter().find(|entry| entry.key == key) {
            return Ok((Some(entry), seen));
        }
        let Some(next) = page.next else {
            return Ok((None, seen));
        };
        token = Some(next);
    }
}

#[cfg(test)]
mod tests;
