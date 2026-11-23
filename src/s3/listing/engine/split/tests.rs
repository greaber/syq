//! Listings by directory, through stores in orders other than UTF-8 bytes.
use super::*;
use crate::s3::listing::engine;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    time::Duration,
};

#[derive(Clone, Copy, Debug)]
enum Order {
    Bytes,
    Reversed,
    /// A key sorts after longer keys that extend it.
    ShorterLast,
    Scrambled,
    /// As measured on Cloudflare R2: as if every key ended in a byte just
    /// above `9`.
    R2,
}
const ORDERS: [Order; 5] = [
    Order::Bytes,
    Order::Reversed,
    Order::ShorterLast,
    Order::Scrambled,
    Order::R2,
];

fn rank(order: Order, item: &str) -> Vec<u8> {
    match order {
        Order::Bytes => item.as_bytes().to_vec(),
        Order::Reversed => item.bytes().map(|b| !b).chain([0]).collect(),
        Order::ShorterLast => item.bytes().chain([0xff]).collect(),
        Order::Scrambled => {
            let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
            for b in item.bytes() {
                hash = (hash ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
            }
            hash.to_be_bytes().into_iter().chain(item.bytes()).collect()
        }
        Order::R2 => item.bytes().chain([b'9', 0xff]).collect(),
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Call {
    prefix: String,
    delimiter: bool,
    token: bool,
}

type Rewrite = Box<dyn Fn(&str, &mut Page)>;

struct Fake {
    keys: BTreeSet<String>,
    order: Order,
    /// Make Tigris's mistake: after a delimiter page whose last item is the
    /// common prefix `Q/`, leave the key `Q0` out of the next page.
    drops: bool,
    /// A directory bucket: not in key order, and every prefix must end in a
    /// slash.
    directory_bucket: bool,
    /// Refuse delimiter listings, as a policy can.
    refuse_delimiter: bool,
    /// Refuse listings of every prefix but this one.
    only: Option<String>,
    /// In listings without a delimiter, compare keys with the prefix after
    /// composing `e` and U+0301 into `é`, as a store that normalizes Unicode
    /// can. Keys are returned as stored.
    normalizes: bool,
    /// Change each first delimiter page, given its prefix.
    rewrite: Option<Rewrite>,
    calls: RefCell<Vec<Call>>,
    active: Cell<usize>,
    peak: Cell<usize>,
}

impl Fake {
    fn new(keys: impl IntoIterator<Item = String>, order: Order) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            order,
            drops: false,
            directory_bucket: false,
            refuse_delimiter: false,
            only: None,
            normalizes: false,
            rewrite: None,
            calls: RefCell::default(),
            active: Cell::new(0),
            peak: Cell::new(0),
        }
    }

    fn under(&self, prefix: &str) -> Vec<String> {
        self.keys
            .range(prefix.to_owned()..)
            .take_while(|key| key.starts_with(prefix))
            .cloned()
            .collect()
    }

    fn flat_calls(&self, prefix: &str) -> Vec<Call> {
        self.calls
            .borrow()
            .iter()
            .filter(|call| call.prefix == prefix && !call.delimiter)
            .cloned()
            .collect()
    }

    fn delimited(&self) -> Vec<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|call| call.delimiter)
            .map(|call| call.prefix.clone())
            .collect()
    }

    /// Prefixes listed without a delimiter, each once.
    fn listed(&self) -> BTreeSet<String> {
        self.calls
            .borrow()
            .iter()
            .filter(|call| !call.delimiter)
            .map(|call| call.prefix.clone())
            .collect()
    }
}

fn denied() -> anyhow::Error {
    anyhow::Error::msg("AccessDenied").context(crate::s3::client::RequestFailure::refused_for_test(
        "S3 listing",
    ))
}

impl Store for Fake {
    fn ordered(&self) -> bool {
        !self.directory_bucket
    }

    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        assert!(start_after.is_none(), "StartAfter for {prefix:?}");
        if self.directory_bucket {
            assert!(prefix.ends_with('/'), "directory bucket listing {prefix:?}");
        }
        self.calls.borrow_mut().push(Call {
            prefix: prefix.to_owned(),
            delimiter,
            token: token.is_some(),
        });
        /// Counts a request in flight until it ends or is dropped.
        struct Active<'a>(&'a Cell<usize>);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() - 1);
            }
        }
        self.active.set(self.active.get() + 1);
        let active = Active(&self.active);
        self.peak.set(self.peak.get().max(self.active.get()));
        tokio::time::sleep(Duration::from_millis(1)).await;
        drop(active);
        if (delimiter && self.refuse_delimiter)
            || self.only.as_deref().is_some_and(|only| only != prefix)
        {
            return Err(denied());
        }
        let marker = format!("{}:{prefix}:", u8::from(delimiter));
        let start = token.map_or(0, |token| {
            token
                .strip_prefix(&marker)
                .expect("token stays with its query")
                .parse::<usize>()
                .unwrap()
        });
        let object = |key: &String| Entry {
            size: u64::from(!key.ends_with('/')),
            key: key.clone(),
            last_modified: None,
            etag: None,
        };
        if let (Order::Bytes, false, false) = (self.order, delimiter, self.normalizes) {
            // The same page, without sorting every key under a large prefix.
            let mut keys = self
                .keys
                .range(prefix.to_owned()..)
                .take_while(|key| key.starts_with(prefix))
                .skip(start);
            let entries: Vec<Entry> = keys.by_ref().take(PAGE).map(object).collect();
            let next = keys
                .next()
                .is_some()
                .then(|| format!("{marker}{}", start + PAGE));
            return Ok(Page {
                entries,
                complete: next.is_none(),
                next,
                ..Page::default()
            });
        }
        let mut items: Vec<(String, bool)> = if self.normalizes && !delimiter {
            let fold = |key: &str| key.replace("e\u{301}", "é");
            let wanted = fold(prefix);
            self.keys
                .iter()
                .filter(|key| fold(key).starts_with(&wanted))
                .map(|key| (key.clone(), false))
                .collect()
        } else {
            self.under(prefix)
                .into_iter()
                .map(
                    |key| match delimiter.then(|| key[prefix.len()..].find('/')).flatten() {
                        Some(slash) => (key[..prefix.len() + slash + 1].to_owned(), true),
                        None => (key, false),
                    },
                )
                .collect()
        };
        items.sort();
        items.dedup();
        items.sort_by_cached_key(|(item, _)| rank(self.order, item));
        let dropped = (self.drops && delimiter && start > 0)
            .then(|| &items[start - 1])
            .filter(|(_, directory)| *directory)
            .map(|(item, _)| format!("{}0", item.strip_suffix('/').unwrap()));
        let next = (items.len() > start + PAGE).then(|| format!("{marker}{}", start + PAGE));
        let mut page = Page {
            complete: next.is_none(),
            next,
            ..Page::default()
        };
        for (item, directory) in items.into_iter().skip(start).take(PAGE) {
            if Some(&item) == dropped.as_ref() {
                continue;
            }
            if directory {
                page.prefixes.push(item);
            } else {
                page.entries.push(object(&item));
            }
        }
        if let (true, None, Some(rewrite)) = (delimiter, token, &self.rewrite) {
            rewrite(prefix, &mut page);
        }
        Ok(page)
    }
}

/// Everything under `prefix`, and the directories left out.
async fn list(
    store: &Fake,
    prefix: &str,
    concurrency: usize,
    prune: Option<&engine::Prune<'_>>,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut keys = Vec::new();
    let pruned = engine::enumerate_prefix(store, prefix, concurrency, prune, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await?;
    Ok((keys, pruned))
}

/// Check that `keys` holds each of `expected` once and nothing else.
#[track_caller]
fn exact(mut keys: Vec<String>, expected: &[String], case: &str) {
    let listed = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), listed, "duplicates: {case}");
    let missing: Vec<_> = expected
        .iter()
        .filter(|key| keys.binary_search(key).is_err())
        .take(5)
        .collect();
    assert!(missing.is_empty(), "missing {missing:?}: {case}");
    assert_eq!(keys.len(), expected.len(), "extra keys: {case}");
}

/// Checks that hold for every listing: no delimiter listing goes past its
/// first page.
#[track_caller]
fn first_delimiter_pages_only(store: &Fake) {
    assert!(
        store
            .calls
            .borrow()
            .iter()
            .all(|call| !(call.delimiter && call.token)),
        "a delimiter listing went past its first page"
    );
}

fn tree(directories: usize, keys: usize) -> impl Iterator<Item = String> {
    (0..directories).flat_map(move |d| (0..keys).map(move |k| format!("t/d{d:03}/k{k:04}")))
}

/// 999 objects, then a directory whose common prefix ends the first
/// delimiter page, then the key Tigris leaves out after it: 2001 keys.
fn counterexample() -> Vec<String> {
    (0..999)
        .map(|i| format!("t/a{i:03}"))
        .chain((0..1001).map(|i| format!("t/d/k{i:04}")))
        .chain(["t/d0".to_owned()])
        .collect()
}

fn trees() -> Vec<(&'static str, Vec<String>)> {
    let mut wide: Vec<String> = (0..30)
        .flat_map(|d| (0..120).map(move |i| format!("t/d{d}/k{i}")))
        .collect();
    wide.extend(
        [
            "t/a",
            "t/a0",
            "t/d3",
            "t/d30",
            "t/d3/0",
            "t/d1.png",
            "t/d1-",
            "t/d10/",
            "t/é/1",
            "t/e\u{301}/2",
            "t/b//c",
            "t/c/",
            "t/z0",
            "t/z/",
            "t/z/0",
            "u/d1/k1",
            "t",
            "t0",
            "t/",
        ]
        .map(String::from),
    );
    let deep: Vec<String> = (0..4)
        .flat_map(|x| (0..6).flat_map(move |y| (0..150).map(move |k| format!("t/x{x}/y{y}/k{k}"))))
        .chain((0..60).map(|k| format!("t/flat{k}")))
        .chain((0..40).map(|k| format!("t/x1{k}")))
        .collect();
    // Each directory's key Tigris may leave out sits next to it.
    let traps: Vec<String> = (0..25)
        .flat_map(|d| {
            (0..80)
                .map(move |i| format!("t/p{d}/q{i}"))
                .chain([format!("t/p{d}0"), format!("t/p{d}0/r")])
        })
        .collect();
    let flat: Vec<String> = (0..2500).map(|k| format!("t/f{k:04}")).collect();
    let medium: Vec<String> = (0..60)
        .flat_map(|d| (0..100).map(move |k| format!("t/m{d:02}/k{k:03}")))
        .collect();
    vec![
        ("wide", wide),
        ("deep", deep),
        ("traps", traps),
        ("flat", flat),
        ("counterexample", counterexample()),
        ("medium", medium),
    ]
}

#[tokio::test]
async fn every_order_lists_each_key_once() {
    let (mut cases, mut split) = (0, 0);
    for (name, tree) in trees() {
        let expected: Vec<String> = tree
            .iter()
            .filter(|key| key.starts_with("t/"))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for order in ORDERS {
            for drops in [false, true] {
                for concurrency in [2, 8, 32] {
                    let mut store = Fake::new(tree.iter().cloned(), order);
                    store.drops = drops;
                    let case = format!("{name} {order:?} drops={drops} c={concurrency}");
                    let (keys, _) = list(&store, "t/", concurrency, None).await.unwrap();
                    exact(keys, &expected, &case);
                    first_delimiter_pages_only(&store);
                    assert!(store.peak.get() <= concurrency, "{case}");
                    // Trees of large directories split where their keys
                    // come grouped by directory. With two request slots,
                    // `wide` would need more listings than pages.
                    if ["wide", "deep", "medium"].contains(&name)
                        && matches!(order, Order::Bytes | Order::ShorterLast | Order::R2)
                        && concurrency >= 8
                    {
                        cases += 1;
                        split += usize::from(store.listed().len() > 1);
                    }
                }
            }
        }
    }
    assert_eq!(split, cases);
}

#[tokio::test]
async fn a_delimiter_listing_is_never_read_past_its_first_page() {
    let expected = counterexample();
    for order in [Order::Bytes, Order::ShorterLast, Order::R2] {
        let mut store = Fake::new(expected.iter().cloned(), order);
        store.drops = true;
        // Read page after page, the delimiter listing leaves `t/d0` out.
        let mut objects = Vec::new();
        let mut token = None;
        loop {
            let page = store
                .page("t/", true, token.as_deref(), None)
                .await
                .unwrap();
            objects.extend(page.entries.into_iter().map(|entry| entry.key));
            let Some(next) = page.next else { break };
            token = Some(next);
        }
        assert_eq!(objects.len(), 999, "{order:?}");
        assert!(!objects.contains(&"t/d0".to_owned()), "{order:?}");
        store.calls.borrow_mut().clear();
        let (keys, _) = list(&store, "t/", 32, None).await.unwrap();
        exact(keys, &expected, &format!("{order:?}"));
        first_delimiter_pages_only(&store);
        // The truncated delimiter page is dropped, and the held page goes on.
        assert_eq!(store.delimited(), ["t/"], "{order:?}");
        assert_eq!(
            store.flat_calls("t/"),
            [false, true, true].map(|token| Call {
                prefix: "t/".into(),
                delimiter: false,
                token,
            }),
            "{order:?}"
        );
    }
}

#[tokio::test]
async fn more_children_than_a_page_holds_are_listed_whole() {
    let keys: Vec<String> = (0..1000)
        .map(|k| format!("t/a/k{k:04}"))
        .chain((0..1200).map(|d| format!("t/z{d:04}/k")))
        .collect();
    let store = Fake::new(keys.iter().cloned(), Order::Bytes);
    let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
    exact(listed, &keys, "wide");
    assert_eq!(
        *store.calls.borrow(),
        [
            ("t/", false, false),
            ("t/", true, false),
            ("t/", false, true),
            ("t/", false, true),
        ]
        .map(|(prefix, delimiter, token)| Call {
            prefix: prefix.into(),
            delimiter,
            token,
        })
    );
}

#[tokio::test]
async fn one_large_directory_among_many_small_ones_costs_few_requests() {
    let keys: Vec<String> = (0..5000)
        .map(|k| format!("t/big/k{k:04}"))
        .chain((0..900).map(|d| format!("t/s{d:03}/k")))
        .collect();
    let store = Fake::new(keys.iter().cloned(), Order::Bytes);
    let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
    exact(listed, &keys, "skewed");
    let requests = store.calls.borrow().len();
    assert!(requests < 50, "{requests} requests");
    // The large directory is listed by itself.
    assert_eq!(store.flat_calls("t/big/").len(), 5);
}

#[tokio::test]
async fn medium_directories_are_listed_in_groups() {
    let keys: Vec<String> = tree(500, 100).collect();
    let store = Fake::new(keys.iter().cloned(), Order::Bytes);
    let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
    exact(listed, &keys, "500 x 100");
    let requests = store.calls.borrow().len();
    // One page after another takes 50 requests.
    assert!(requests <= 80, "{requests} requests");
    assert!(store.peak.get() >= 16, "peak {}", store.peak.get());
    let groups = store
        .listed()
        .into_iter()
        .filter(|prefix| !prefix.ends_with('/'))
        .count();
    assert!(groups >= 8, "{groups} groups");
    assert_eq!(store.delimited(), ["t/"]);
}

#[tokio::test]
async fn pruned_directories_are_never_listed_and_objects_beside_them_once() {
    let excluded: BTreeSet<String> = ["t/archive/", "t/d004/", "t/d037/", "t/d071/", "t/d1/"]
        .map(String::from)
        .into();
    let mut keys: Vec<String> = (0..100)
        .map(|d| format!("t/d{d:03}/"))
        .chain(["t/archive/".into(), "t/d1/".into()])
        .flat_map(|dir| {
            let count = if excluded.contains(&dir) { 300 } else { 100 };
            (0..count).map(move |k| format!("{dir}k{k:03}"))
        })
        .collect();
    keys.extend(["t/d004", "t/d00", "t/d01.txt", "t/d1", "t/d10", "t/top"].map(String::from));
    let subtree = |key: &str, _directory: bool| {
        excluded
            .iter()
            .find(|dir| key.starts_with(dir.as_str()))
            .map(|dir| dir.len() - 1)
    };
    let expected: Vec<String> = keys
        .iter()
        .filter(|key| subtree(key, false).is_none())
        .cloned()
        .collect();
    for concurrency in [4, 32] {
        let store = Fake::new(keys.iter().cloned(), Order::Bytes);
        let prune = engine::Prune {
            subtree: &subtree,
            probes: 4.into(),
        };
        let (listed, pruned) = list(&store, "t/", concurrency, Some(&prune)).await.unwrap();
        let case = format!("c={concurrency}");
        exact(listed, &expected, &case);
        assert_eq!(
            pruned.into_iter().collect::<BTreeSet<_>>(),
            excluded,
            "{case}"
        );
        for prefix in store.listed() {
            if prefix == "t/" {
                continue;
            }
            assert!(
                !excluded
                    .iter()
                    .any(|dir| dir.starts_with(&prefix) || prefix.starts_with(dir.as_str())),
                "{case}: {prefix:?} covers a pruned directory"
            );
        }
        assert!(
            store.listed().iter().any(|prefix| !prefix.ends_with('/')),
            "{case}: no groups"
        );
    }
}

#[tokio::test]
async fn group_prefixes_hold_only_ascii_past_their_directory() {
    let names: Vec<String> = (0..40)
        .flat_map(|i| [format!("a{i}"), format!("caf{i}")])
        .chain((0..20).map(|i| format!("cafe\u{301}{i}")))
        .chain((0..4).flat_map(|i| [format!("café{i}"), format!("日本{i}")]))
        .collect();
    let keys: Vec<String> = names
        .iter()
        .flat_map(|name| (0..300).map(move |k| format!("t/{name}/k{k:03}")))
        .collect();
    for order in [Order::Bytes, Order::R2] {
        let store = Fake::new(keys.iter().cloned(), order);
        let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
        exact(listed, &keys, &format!("{order:?}"));
        let groups: Vec<String> = store
            .listed()
            .into_iter()
            .filter(|prefix| !prefix.ends_with('/'))
            .collect();
        assert!(!groups.is_empty(), "{order:?}: no groups");
        for group in groups {
            // `t/cafe\u{301}1` would cover `t/cafe\u{301}1/` to
            // `t/cafe\u{301}19/`.
            assert!(group["t/".len()..].is_ascii(), "{group:?}");
            for key in store.under(&group) {
                assert!(key.as_bytes()[group.len()].is_ascii(), "{group:?}: {key:?}");
            }
        }
    }
}

#[tokio::test]
async fn groups_never_reach_a_directory_in_another_normalization() {
    // A store that composes `e` and U+0301 would list `t/café0z/` under
    // `t/cafe\u{301}0`, the start that `t/cafe\u{301}0a/` and
    // `t/cafe\u{301}0b/` share.
    let names: Vec<String> = ["cafe\u{301}0a", "cafe\u{301}0b", "café0z"]
        .map(String::from)
        .into_iter()
        .chain((0..40).map(|i| format!("a{i}")))
        .collect();
    let keys: Vec<String> = names
        .iter()
        .flat_map(|name| (0..100).map(move |k| format!("t/{name}/k{k:03}")))
        .collect();
    let mut store = Fake::new(keys.iter().cloned(), Order::Bytes);
    store.normalizes = true;
    let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
    exact(listed, &keys, "normalized");
    let listed = store.listed();
    assert!(listed.contains("t/a"), "{listed:?}");
    for prefix in &listed {
        assert!(
            prefix["t/".len()..].is_ascii() || prefix.ends_with('/'),
            "{prefix:?}"
        );
    }
    for name in &names[..3] {
        assert!(
            listed.contains(&format!("t/{name}/")),
            "{name:?}: {listed:?}"
        );
    }
}

#[tokio::test]
async fn directory_buckets_list_only_prefixes_that_end_in_a_slash() {
    for (directories, keys, children) in [(100, 100, 0), (10, 1000, 10)] {
        let expected: Vec<String> = tree(directories, keys).collect();
        let mut store = Fake::new(expected.iter().cloned(), Order::Bytes);
        store.directory_bucket = true;
        let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
        let case = format!("{directories} x {keys}");
        exact(listed, &expected, &case);
        assert_eq!(store.listed().len() - 1, children, "{case}");
    }
}

#[tokio::test]
async fn a_refused_or_malformed_delimiter_page_goes_on_from_the_held_page() {
    let keys: Vec<String> = tree(20, 500).collect();
    let entry = |key: &str| Entry {
        key: key.into(),
        size: 1,
        last_modified: None,
        etag: None,
    };
    let rewrites: Vec<(&str, Rewrite)> = vec![
        (
            "common prefix past the delimiter",
            Box::new(|_, page| page.prefixes.push("t/d000/k0000/".into())),
        ),
        (
            "common prefix outside the prefix",
            Box::new(|_, page| page.prefixes.push("u/".into())),
        ),
        (
            "common prefix without a slash",
            Box::new(|_, page| {
                page.prefixes[0].pop();
            }),
        ),
        (
            "object below a common prefix",
            Box::new(move |_, page| page.entries.push(entry("t/d000/k0000"))),
        ),
        (
            // The held page shows a directory the delimiter page does not.
            "directory in another normalization",
            Box::new(|_, page| page.prefixes[0] = "t/d00\u{301}/".into()),
        ),
        (
            "directory missing",
            Box::new(|_, page| drop(page.prefixes.remove(0))),
        ),
        (
            // A response without IsTruncated, or with a continuation token
            // although it says it is not truncated.
            "end of the listing not stated",
            Box::new(|_, page| page.complete = false),
        ),
        (
            "too many items",
            Box::new(move |_, page| {
                page.entries
                    .extend((0..990).map(|i| entry(&format!("t/x{i:03}"))))
            }),
        ),
    ];
    for rewrite in rewrites.into_iter().map(Some).chain([None]) {
        let mut store = Fake::new(keys.iter().cloned(), Order::Bytes);
        let case = match rewrite {
            Some((case, rewrite)) => {
                store.rewrite = Some(rewrite);
                case
            }
            None => {
                store.refuse_delimiter = true;
                "refused"
            }
        };
        let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
        exact(listed, &keys, case);
        // The prefix is listed once, from the held first page on.
        assert_eq!(store.delimited(), ["t/"], "{case}");
        assert_eq!(store.listed().len(), 1, "{case}");
        let flat = store.flat_calls("t/");
        assert_eq!(flat.len(), 10, "{case}");
        assert_eq!(flat.iter().filter(|call| !call.token).count(), 1, "{case}");
    }
}

#[tokio::test]
async fn a_listing_too_small_to_split_goes_on_from_its_held_page() {
    for (directories, keys) in [(2, 600), (3, 800)] {
        let expected: Vec<String> = tree(directories, keys).collect();
        let store = Fake::new(expected.iter().cloned(), Order::Bytes);
        let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
        let case = format!("{directories} x {keys}");
        exact(listed, &expected, &case);
        assert_eq!(store.delimited(), ["t/"], "{case}");
        assert_eq!(store.listed().len(), 1, "{case}");
        assert_eq!(
            store.flat_calls("t/").len(),
            expected.len().div_ceil(PAGE),
            "{case}"
        );
    }
}

#[tokio::test]
async fn a_refused_listing_of_a_part_says_so() {
    for keys in [tree(10, 1000).collect::<Vec<_>>(), tree(500, 100).collect()] {
        let mut store = Fake::new(keys, Order::Bytes);
        store.only = Some("t/".into());
        let error = list(&store, "t/", 32, None).await.unwrap_err();
        assert!(error.downcast_ref::<PartFailed>().is_some(), "{error:#}");
        assert!(error
            .downcast_ref::<crate::s3::client::RequestFailure>()
            .is_some_and(crate::s3::client::RequestFailure::denied));
        // With one request slot, nothing narrower is listed.
        let (listed, _) = list(&store, "t/", 1, None).await.unwrap();
        assert_eq!(listed.len(), store.keys.len());
    }
}

#[tokio::test]
async fn nested_directories_split_at_every_level() {
    let keys: Vec<String> = (0..10)
        .flat_map(|d| {
            (0..10).flat_map(move |e| (0..1000).map(move |k| format!("t/d{d}/e{e}/k{k:03}")))
        })
        .collect();
    let store = Fake::new(keys.iter().cloned(), Order::Bytes);
    let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
    exact(listed, &keys, "10 x 10 x 1000");
    // Every directory of the first level is split as well.
    let mut delimited = store.delimited();
    delimited.sort();
    let expected: Vec<String> = std::iter::once("t/".to_owned())
        .chain((0..10).map(|d| format!("t/d{d}/")))
        .collect();
    assert_eq!(delimited, expected);
    let listed = store.listed();
    for d in 0..10 {
        for e in 0..10 {
            assert!(listed.contains(&format!("t/d{d}/e{e}/")), "t/d{d}/e{e}/");
        }
    }
    let requests = store.calls.borrow().len();
    // One page after another takes 100 requests.
    assert!(requests <= 125, "{requests} requests");
    assert!(store.peak.get() >= 30, "peak {}", store.peak.get());
}

#[tokio::test]
async fn a_single_directory_is_followed_down_a_few_levels() {
    let keys: Vec<String> = (0..20)
        .flat_map(|d| (0..200).map(move |k| format!("t/a/b/c/d{d:02}/k{k:03}")))
        .collect();
    let store = Fake::new(keys.iter().cloned(), Order::Bytes);
    let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
    exact(listed, &keys, "chain");
    assert_eq!(store.delimited(), ["t/", "t/a/", "t/a/b/", "t/a/b/c/"]);
    // The first page of `t/` is the only one dropped.
    assert_eq!(store.flat_calls("t/").len(), 1);
    assert!(store
        .listed()
        .iter()
        .all(|prefix| prefix == "t/" || prefix.starts_with("t/a/b/c/d")));
    // A chain that ends in one directory of objects goes on from the held
    // page.
    let keys: Vec<String> = (0..3000)
        .map(|k| format!("t/a/b/c/d/e/f/g/k{k:04}"))
        .collect();
    let store = Fake::new(keys.iter().cloned(), Order::Bytes);
    let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
    exact(listed, &keys, "deep chain");
    assert!(store.delimited().len() <= DESCENT + 1);
    assert_eq!(store.listed().len(), 1);
    assert_eq!(store.flat_calls("t/").len(), 3);
}

#[tokio::test]
async fn deep_trees_of_small_directories_cost_a_bounded_share_more() {
    for (fanout, depth, objects) in [(8, 3, 20), (6, 4, 10), (4, 6, 3)] {
        let mut keys = vec!["t/".to_owned()];
        for _ in 0..depth {
            keys = keys
                .iter()
                .flat_map(|parent| (0..fanout).map(move |d| format!("{parent}{d}/")))
                .collect();
        }
        let keys: Vec<String> = keys
            .iter()
            .flat_map(|leaf| (0..objects).map(move |k| format!("{leaf}k{k:02}")))
            .collect();
        let store = Fake::new(keys.iter().cloned(), Order::Bytes);
        let (listed, _) = list(&store, "t/", 32, None).await.unwrap();
        let case = format!("{fanout}^{depth} x {objects}");
        exact(listed, &keys, &case);
        let pages = keys.len().div_ceil(PAGE);
        let requests = store.calls.borrow().len();
        assert!(
            requests <= 3 * pages + LISTINGS,
            "{case}: {requests} requests"
        );
    }
}

#[test]
fn groups_cover_every_child_once_without_overlap() {
    let names: Vec<String> = ["t/a/", "t/b0/", "t/b1/", "t/b10/", "t/b2/", "t/c/", "t/é/"]
        .map(String::from)
        .to_vec();
    let pruned = [false, false, false, false, false, true, false];
    for target in [2, 3, 4, 8] {
        let most = (target + target / 2).max(target + 1);
        let groups = group(&names, &pruned, 2, target, most).unwrap();
        let covered: Vec<&String> = groups.iter().flat_map(|(_, children)| children).collect();
        assert_eq!(
            covered,
            ["t/a/", "t/b0/", "t/b1/", "t/b10/", "t/b2/", "t/é/"]
                .iter()
                .collect::<Vec<_>>()
        );
        for (prefix, children) in &groups {
            assert!(children
                .iter()
                .all(|child| child.starts_with(prefix.as_str())));
            for (other, _) in &groups {
                assert!(other == prefix || !other.starts_with(prefix.as_str()));
            }
        }
        if target <= 3 {
            assert_eq!(groups.len(), 3, "{groups:?}");
        }
    }
    // More children than listings that cannot be grouped: each starts with
    // a different character outside ASCII.
    let names: Vec<String> = (0..60)
        .map(|i| format!("t/{}/", char::from_u32(0xc0 + i).unwrap()))
        .collect();
    assert!(group(&names, &[false; 60], 2, 32, MOST_LISTINGS).is_none());
    assert_eq!(
        group(&names[..40], &[false; 40], 2, 32, MOST_LISTINGS)
            .unwrap()
            .len(),
        40
    );
    // Nor are they listed apart when a few listings would do.
    assert!(group(&names[..40], &[false; 40], 2, 4, 6).is_none());
    let (target, most) = listings_for(3200, 32);
    assert_eq!((target, most), (4, 6));
    assert!(group(&names[..40], &[false; 40], 2, target, most).is_none());
}

/// Keys `t/{a}/{b}/k...` for every `a` in `top` and `b` in `below`.
fn three_levels(top: &[String], below: &[String], keys: usize) -> Vec<String> {
    top.iter()
        .flat_map(|a| {
            below
                .iter()
                .flat_map(move |b| (0..keys).map(move |k| format!("t/{a}/{b}/k{k:03}")))
        })
        .collect()
}

/// List `keys` under `t/` with `concurrency`, check the result, and return
/// the requests and the round trips the listing took one after another.
async fn measure(keys: &[String], concurrency: usize, case: &str) -> (Fake, usize, u128) {
    let store = Fake::new(keys.iter().cloned(), Order::Bytes);
    let started = tokio::time::Instant::now();
    let (listed, _) = list(&store, "t/", concurrency, None).await.unwrap();
    // Each request takes a millisecond.
    let rounds = started.elapsed().as_millis();
    exact(listed, keys, case);
    first_delimiter_pages_only(&store);
    assert!(store.peak.get() <= concurrency, "{case}");
    let requests = store.calls.borrow().len();
    (store, requests, rounds)
}

#[tokio::test(start_paused = true)]
async fn two_large_directories_are_listed_apart() {
    let test_and_train: Vec<String> = (0..50)
        .flat_map(|d| (0..100).map(move |k| format!("t/test/d{d:02}/k{k:03}")))
        .chain((0..200).flat_map(|d| (0..100).map(move |k| format!("t/train/d{d:03}/k{k:03}"))))
        .collect();
    let halves: Vec<String> = ["a", "b"]
        .iter()
        .flat_map(|d| (0..5000).map(move |k| format!("t/{d}/k{k:04}")))
        .collect();
    for (case, keys, children, most_requests, most_rounds) in [
        (
            "50 x 100 and 200 x 100",
            test_and_train,
            ["t/test/", "t/train/"],
            35,
            6,
        ),
        ("2 x 5,000", halves, ["t/a/", "t/b/"], 12, 7),
    ] {
        let (store, requests, rounds) = measure(&keys, 32, case).await;
        let listed = store.listed();
        for child in children {
            assert!(listed.contains(child), "{case}: {listed:?}");
        }
        // One page after another takes a request and a round trip a page.
        let pages = keys.len().div_ceil(PAGE);
        assert!(
            requests <= most_requests,
            "{case}: {requests} requests, {pages} pages"
        );
        assert!(
            rounds <= most_rounds,
            "{case}: {rounds} round trips, {pages} pages"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn directories_that_cannot_be_grouped_cost_few_more_requests() {
    let letters: Vec<String> = ('A'..='Z').chain('a'..='n').map(String::from).collect();
    let alphabet: Vec<String> = ('a'..='z').map(String::from).collect();
    let hex: Vec<String> = (0..256).map(|i| format!("{i:02x}")).collect();
    let shapes = [
        ("40 x 40 x 80", three_levels(&letters, &letters, 80)),
        ("26 x 26 x 200", three_levels(&alphabet, &alphabet, 200)),
        (
            "256 x 400",
            hex.iter()
                .flat_map(|d| (0..400).map(move |k| format!("t/{d}/k{k:03}")))
                .collect(),
        ),
    ];
    for (case, keys) in &shapes {
        let pages = keys.len().div_ceil(PAGE);
        for concurrency in [4, 32] {
            let case = format!("{case} c={concurrency}");
            let (_, requests, rounds) = measure(keys, concurrency, &case).await;
            // Listing each directory of the second level by itself took up
            // to 1,682 requests. A delimiter request for each directory of
            // the first level is the most this spends.
            assert!(
                requests <= pages + pages / 2 + 2,
                "{case}: {requests} requests, {pages} pages"
            );
            // Listing apart still pays: one page after another takes a
            // round trip a page.
            assert!(
                rounds as usize <= 2 * pages / concurrency + 8,
                "{case}: {rounds} round trips, {pages} pages"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn many_directories_that_look_large_at_once_cost_bounded_requests() {
    // 32 directories each hold one directory whose 1,001 keys fill their
    // first page, and 47 of a key each whose names cannot be grouped: each
    // looks like 48 large directories.
    let letters: Vec<char> = ('A'..='Z').chain('a'..='z').collect();
    let keys: Vec<String> = (0..32)
        .flat_map(|s| {
            (0..1001)
                .map(move |k| format!("t/s{s:02}/A/k{k:04}"))
                .chain(
                    letters[1..48]
                        .iter()
                        .map(move |c| format!("t/s{s:02}/{c}/k")),
                )
        })
        .collect();
    let (store, requests, _) = measure(&keys, 32, "32 x 48").await;
    // One page after another takes 34 requests, and listing each of the 32
    // directories by itself 64 and their delimiter requests. Listing each
    // directory below them by itself took 1,634.
    assert!(requests <= 200, "{requests} requests");
    let deeper = store
        .listed()
        .iter()
        .filter(|prefix| prefix.matches('/').count() > 2)
        .count();
    assert!(deeper <= 2 * 48, "{deeper} listings below the second level");
}

#[tokio::test]
async fn few_pages_are_held_at_once() {
    // A pattern reaches 64 prefixes, each with directories and more keys
    // than a page holds.
    let keys: Vec<String> = (0..8)
        .flat_map(|a| {
            (0..8).flat_map(move |b| {
                (0..3).flat_map(move |d| (0..400).map(move |k| format!("t/a{a}/b{b}/d{d}/k{k:03}")))
            })
        })
        .collect();
    let pattern = Pattern::parse("s3://bucket/t/*/*/**").unwrap();
    for concurrency in [2, 4, 8, 32] {
        let store = Fake::new(keys.iter().cloned(), Order::Bytes);
        let mut listed = Vec::new();
        let mut emit = |entry: Entry| {
            listed.push(entry.key);
            Ok(())
        };
        let first = Job::Discover {
            prefix: String::new(),
            component: 0,
        };
        let lister = drive(&store, Some(&pattern), None, concurrency, first, &mut emit)
            .await
            .unwrap();
        let (most_held, held, unproven) = (lister.most_held, lister.held, lister.unproven);
        drop(lister);
        let case = format!("c={concurrency}");
        exact(listed, &keys, &case);
        assert!(most_held > 0, "{case}");
        assert!(
            most_held <= concurrency.clamp(2, LISTINGS),
            "{case}: {most_held}"
        );
        assert_eq!((held, unproven), (0, 0), "{case}");
    }
}

#[tokio::test]
async fn held_pages_beyond_the_listings_go_on_at_once() {
    let store = Fake::new(std::iter::empty(), Order::Bytes);
    let mut emit = |_: Entry| -> Result<()> { Ok(()) };
    let mut lister = Lister {
        pattern: None,
        prune: None,
        emit: &mut emit,
        groupable: !store.slash_only(),
        listings: 8,
        // Enough keys listed to afford many delimiter requests.
        keys: 1_000_000,
        held: 0,
        unproven: 0,
        pruned: Vec::new(),
        pending: VecDeque::new(),
        splits: 0,
        most_held: 0,
    };
    for i in 0..20 {
        let prefix = format!("t/p{i:02}/");
        let page = Page {
            entries: (0..PAGE)
                .map(|k| Entry {
                    key: format!("{prefix}d{}/k{k:03}", k / 100),
                    size: 1,
                    last_modified: None,
                    etag: None,
                })
                .collect(),
            next: Some("next".into()),
            ..Page::default()
        };
        let node = Node::new(prefix, true);
        lister
            .done(
                Done::Flat {
                    node,
                    first: true,
                    page,
                },
                0,
                false,
            )
            .unwrap();
    }
    assert_eq!((lister.held, lister.most_held), (8, 8));
    let probes = lister
        .pending
        .iter()
        .take_while(|task| matches!(task, Task::Probe(_)))
        .count();
    assert_eq!(probes, 8, "held pages are asked about first");
    let going_on = lister
        .pending
        .iter()
        .filter(|task| matches!(task, Task::Flat { token: Some(_), .. }))
        .count();
    assert_eq!(going_on, 12);
}

#[tokio::test]
async fn incomplete_lookahead_delimiter_page_falls_back_to_held_listing() {
    // Root holds a direct object plus two subdirectories (`a/` and `b/`).
    // `a/` has > 1,000 objects starting in ignored `a/cache/` followed by
    // kept `a/live/keep`; an incomplete delimiter response for `a/` that
    // omits `IsTruncated` and `a/live/` must not drop `a/live/keep`.
    let keys: Vec<String> = std::iter::once("t/00_root".to_owned())
        .chain((0..1005).map(|i| format!("t/a/cache/k{i:04}")))
        .chain([
            "t/a/live/keep".to_owned(),
            "t/b/k0".to_owned(),
            "t/b/k1".to_owned(),
        ])
        .chain((0..2500).map(|i| format!("t/b/f{i:04}")))
        .collect();
    let mut store = Fake::new(keys.iter().cloned(), Order::Bytes);
    store.rewrite = Some(Box::new(|prefix, page| {
        if prefix == "t/a/" {
            page.prefixes.retain(|p| p == "t/a/cache/");
            page.complete = false;
        }
    }));
    let subtree =
        |key: &str, _directory: bool| key.starts_with("t/a/cache/").then_some("t/a/cache".len());
    let prune = engine::Prune {
        subtree: &subtree,
        probes: 4.into(),
    };
    let expected: Vec<String> = keys
        .iter()
        .filter(|key| subtree(key, false).is_none())
        .cloned()
        .collect();
    let (listed, pruned) = list(&store, "t/", 32, Some(&prune)).await.unwrap();
    assert!(
        listed.iter().any(|k| k == "t/a/live/keep"),
        "missing kept key after incomplete lookahead delimiter page"
    );
    assert!(
        expected.iter().all(|k| listed.contains(k)),
        "expected every kept key"
    );
    assert!(
        pruned.is_empty(),
        "incomplete lookahead must not prune: {pruned:?}"
    );
}
