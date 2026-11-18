//! Which planned destination keys already exist, learned from LIST pages
//! while the copy runs.
//!
//! A key the listing shows absent needs no HEAD. The listing follows the plan
//! in key order and each request starts at the next undecided key, so its cost
//! follows the copy rather than the size of the destination prefix. Workers
//! use each page as it arrives instead of waiting for the last one.
use super::super::listing::{
    self,
    engine::{Page, Store},
};
use crate::progress::Progress;
use anyhow::{ensure, Result};
use std::{
    borrow::Cow,
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc,
    },
};
use tokio::sync::watch;

/// What the destination listing says about one planned key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Listed {
    /// No listing covers the key: ask with HEAD.
    Unknown,
    Absent,
    Present(u64),
}

/// Planned keys a page must decide to be worth requesting. LIST is billed
/// about twelve times a HEAD, and a worker waiting for the page could have
/// sent its own HEAD instead.
const KEYS_PER_PAGE: usize = 64;
/// Pages' worth of shortfall allowed before the listing stops, so one sparse
/// stretch does not end a listing that pays for itself overall.
const SLACK_PAGES: usize = 2;

/// Pages awaited before the copy starts. The copy sizes its request
/// concurrency from the fastest listing response seen by then, and the first
/// response also opened the connection.
const PAGES_BEFORE_COPY: usize = 2;

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
    /// Plan positions below this are decided.
    decided: usize,
    finished: bool,
}

struct Walk {
    prefix: String,
    keys: Keys,
    sizes: Arc<[AtomicU64]>,
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
    /// Request the next page and record what it decides. Returns whether
    /// another page is worth requesting.
    async fn page(&mut self, store: &impl Store) -> Result<bool> {
        let bound = predecessor(self.keys.get(self.decided));
        let (token, after) = match &self.token {
            Some(token) => (Some(token.as_str()), self.passed.as_str()),
            None => (None, bound.as_str()),
        };
        let page = store
            .page(&self.prefix, false, token, token.is_none().then_some(after))
            .await?;
        for entry in &page.entries {
            ensure!(
                entry.key.starts_with(&self.prefix),
                "S3 listing returned a key outside the requested prefix"
            );
        }
        if !in_key_order(&page, after) {
            // A key's place in this provider's listing says nothing about the
            // keys around it, on this page or the earlier ones.
            for size in self.sizes.iter() {
                size.store(UNKNOWN, Relaxed);
            }
            return Ok(false);
        }
        let complete = page.next.is_none();
        let last = page.entries.last().map(|entry| entry.key.as_str());
        let mut listed = page.entries.iter().peekable();
        let before = self.decided;
        while self.decided < self.keys.len() {
            let key = self.keys.get(self.decided);
            if !complete && last.is_none_or(|last| key > last) {
                break;
            }
            while listed.next_if(|entry| entry.key.as_str() < key).is_some() {}
            let size = match listed.peek() {
                Some(entry) if entry.key == key => entry.size,
                // The listing cannot show a key outside its prefix.
                _ if key.starts_with(&self.prefix) => ABSENT,
                _ => UNKNOWN,
            };
            self.sizes[self.decided].store(size, Relaxed);
            self.decided += 1;
        }
        if complete || self.decided == self.keys.len() {
            return Ok(false);
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
        let undecided = self.keys.len() - self.decided;
        Ok(self.shortfall <= undecided.min(SLACK_PAGES * KEYS_PER_PAGE))
    }

    /// Directory buckets list in no particular order and cannot start after a
    /// key, so only a complete listing decides anything.
    async fn whole(&mut self, store: &impl Store) -> Result<()> {
        let mut token: Option<String> = None;
        let mut found = 0;
        // Never spend as many LIST requests as checking each key with HEAD.
        for _ in 0..self.keys.len().saturating_sub(1) {
            let page = store
                .page(&self.prefix, false, token.as_deref(), None)
                .await?;
            for entry in &page.entries {
                ensure!(
                    entry.key.starts_with(&self.prefix),
                    "S3 listing returned a key outside the requested prefix"
                );
                if let Some(index) = self.keys.find(&entry.key) {
                    self.sizes[index].store(entry.size, Relaxed);
                    found += 1;
                }
            }
            if page.next.is_none() || found == self.keys.len() {
                for (index, size) in self.sizes.iter().enumerate() {
                    if size.load(Relaxed) == UNKNOWN
                        && self.keys.get(index).starts_with(&self.prefix)
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
        self.decided = self.keys.len();
        Ok(())
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
    sizes: Arc<[AtomicU64]>,
    reach: watch::Receiver<Reach>,
    task: Option<tokio::task::AbortHandle>,
}
impl Discovery {
    /// List the destination for `keys`, which must be in key order. A
    /// destination that cannot be listed fails the copy here, before it
    /// starts; later pages arrive while the copy runs.
    pub(super) async fn start(
        client: aws_sdk_s3::Client,
        bucket: &str,
        prefix: String,
        keys: Keys,
        cancelled: Arc<AtomicBool>,
        progress: Arc<Progress>,
    ) -> Result<Self> {
        let sizes: Arc<[AtomicU64]> = (0..keys.len()).map(|_| AtomicU64::new(UNKNOWN)).collect();
        let mut walk = Walk {
            prefix,
            keys,
            sizes: sizes.clone(),
            decided: 0,
            shortfall: 0,
            passed: String::new(),
            token: None,
        };
        let store = listing::S3 {
            client: client.clone(),
            bucket,
        };
        let mut more = store.ordered();
        if more {
            for _ in 0..PAGES_BEFORE_COPY {
                more = walk.page(&store).await?;
                if !more {
                    break;
                }
            }
        } else {
            walk.whole(&store).await?;
        }
        let (sender, reach) = watch::channel(Reach {
            decided: walk.decided,
            finished: !more,
        });
        let task = more.then(|| {
            let bucket = bucket.to_owned();
            tokio::spawn(async move {
                let store = listing::S3 {
                    client,
                    bucket: &bucket,
                };
                let mut more = true;
                while more && !cancelled.load(Relaxed) {
                    more = walk.page(&store).await.unwrap_or_else(|error| {
                        progress.error(&format!("list S3 destination: {error:#}"));
                        false
                    });
                    sender.send_replace(Reach {
                        decided: walk.decided,
                        finished: !more,
                    });
                }
                sender.send_replace(Reach {
                    decided: walk.decided,
                    finished: true,
                });
            })
            .abort_handle()
        });
        Ok(Self { sizes, reach, task })
    }

    /// What the listing says about the key at plan position `index`, once the
    /// listing has passed it or ended.
    pub(super) fn lookup(&self, index: usize) -> impl Future<Output = Listed> + Send + 'static {
        let sizes = self.sizes.clone();
        let mut reach = self.reach.clone();
        async move {
            // A listing that ended early or was dropped leaves the rest to HEAD.
            let decided = reach
                .wait_for(|reach| reach.decided > index || reach.finished)
                .await
                .is_ok_and(|reach| reach.decided > index);
            match sizes[index].load(Relaxed) {
                _ if !decided => Listed::Unknown,
                UNKNOWN => Listed::Unknown,
                ABSENT => Listed::Absent,
                size => Listed::Present(size),
            }
        }
    }
}
impl Drop for Discovery {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests;
