use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    ops::Bound,
    time::Duration,
};

struct Memory {
    keys: BTreeSet<String>,
    calls: RefCell<Vec<(String, bool)>>,
    /// Listings of keys that were read to their last page.
    ended: RefCell<BTreeSet<String>>,
    active: Cell<usize>,
    peak: Cell<usize>,
}
impl Memory {
    fn new(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            calls: RefCell::default(),
            ended: RefCell::default(),
            active: Cell::new(0),
            peak: Cell::new(0),
        }
    }
    /// The requests a listing of everything under `prefix` makes one page
    /// after another.
    fn pages(&self, prefix: &str) -> usize {
        let keys = self.keys.iter().filter(|key| key.starts_with(prefix));
        keys.count().div_ceil(1000).max(1)
    }
    /// The prefixes whose keys were listed, and those among them whose
    /// listing stopped before its last page.
    fn listings(&self) -> (BTreeSet<String>, BTreeSet<String>) {
        let calls = self.calls.borrow();
        let listed: BTreeSet<_> = calls
            .iter()
            .filter(|(_, delimiter)| !delimiter)
            .map(|(prefix, _)| prefix.clone())
            .collect();
        let cut = listed.difference(&self.ended.borrow()).cloned().collect();
        (listed, cut)
    }
}
impl Store for Memory {
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        _: Option<&str>,
    ) -> Result<Page> {
        self.calls.borrow_mut().push((prefix.into(), delimiter));
        self.active.set(self.active.get() + 1);
        self.peak.set(self.peak.get().max(self.active.get()));
        tokio::time::sleep(Duration::from_millis(1)).await;
        self.active.set(self.active.get() - 1);
        // A token names its query and where the next page starts: after a
        // key, or at the first key past a directory.
        let marker = format!("{}:{prefix}:", u8::from(delimiter));
        let mut cursor = match token {
            Some(token) => {
                let position = token
                    .strip_prefix(&marker)
                    .expect("token must stay with its original query");
                match position.split_at(1) {
                    ("+", at) => Bound::Included(at.to_owned()),
                    (_, after) => Bound::Excluded(after.to_owned()),
                }
            }
            None => Bound::Included(prefix.to_owned()),
        };
        let mut page = Page::default();
        loop {
            let Some(key) = self.keys.range((cursor.clone(), Bound::Unbounded)).next() else {
                break;
            };
            if !key.starts_with(prefix) {
                break;
            }
            if page.entries.len() + page.prefixes.len() == 1000 {
                page.next = Some(match &cursor {
                    Bound::Included(at) => format!("{marker}+{at}"),
                    Bound::Excluded(after) => format!("{marker}-{after}"),
                    Bound::Unbounded => unreachable!(),
                });
                break;
            }
            let child = delimiter
                .then(|| key[prefix.len()..].find('/'))
                .flatten()
                .map(|slash| &key[..prefix.len() + slash]);
            if let Some(child) = child {
                page.prefixes.push(format!("{child}/"));
                // '0' follows '/': the first key past the directory.
                cursor = Bound::Included(format!("{child}0"));
            } else {
                page.entries.push(Entry {
                    // Directory markers are empty.
                    size: u64::from(!key.ends_with('/')),
                    key: key.clone(),
                    last_modified: None,
                    etag: None,
                });
                cursor = Bound::Excluded(key.clone());
            }
        }
        if page.next.is_none() && !delimiter {
            self.ended.borrow_mut().insert(prefix.to_owned());
        }
        Ok(page)
    }
}

/// List everything under `prefix`, checking the keys against the store.
/// Returns the requests made and the round trips the listing took.
async fn walked(
    store: &Memory,
    prefix: &str,
    concurrency: usize,
    prune: Option<&engine::Prune<'_>>,
) -> (usize, u128) {
    let before = store.calls.borrow().len();
    store.peak.set(0);
    let started = tokio::time::Instant::now();
    let mut keys = Vec::new();
    engine::enumerate_prefix(store, prefix, concurrency, prune, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    let elapsed = started.elapsed().as_millis();
    keys.sort();
    let expected: Vec<_> = store
        .keys
        .iter()
        .filter(|key| key.starts_with(prefix))
        .cloned()
        .collect();
    assert!(
        keys == expected,
        "listing of {prefix:?} differs from the store"
    );
    assert!(store.peak.get() <= concurrency);
    (store.calls.borrow().len() - before, elapsed)
}

async fn listed(store: &Memory, input: &str, concurrency: usize) -> Vec<String> {
    let pattern = Pattern::parse(&format!("s3://bucket/{input}")).unwrap();
    let mut keys = Vec::new();
    engine::enumerate(store, &pattern, concurrency, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    let unique: BTreeSet<_> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len(), "duplicate keys for {input}");
    keys.sort();
    keys
}

#[tokio::test]
async fn optimized_enumeration_equals_full_key_filter() {
    let mut keys: Vec<_> = (0..8)
        .flat_map(|d| (0..180).map(move |i| format!("logs/day{d}/file{i:03}")))
        .collect();
    keys.extend(
        [
            "logs",
            "logs/",
            "logs/file",
            "logs//file",
            "logs/day0/",
            "logs/day0/nested/file",
            "logs-old/a",
            "a/b",
            "ab",
            "a%2Fb",
            "[a]",
            "é/文",
            "logs/a\nb",
        ]
        .map(String::from),
    );
    let store = Memory::new(keys);
    for input in [
        "logs",
        "logs/",
        "logs/*",
        "logs/**",
        "logs/**/file",
        "logs**",
        "logs/day?/*",
        "logs/day*/**file*",
        "logs/d*y?/file0?0",
        "**",
        "*",
        "a**b",
        "é/?",
        "a%2Fb",
        "[a]",
        "missing/**",
    ] {
        let pattern = Pattern::parse(&format!("s3://bucket/{input}")).unwrap();
        let expected: Vec<_> = store
            .keys
            .iter()
            .filter(|key| pattern.matches(key))
            .cloned()
            .collect();
        for concurrency in [1, 4] {
            assert_eq!(
                listed(&store, input, concurrency).await,
                expected,
                "{input}"
            );
        }
    }
    assert!(store.peak.get() > 1);
    assert!(store.peak.get() <= 4);
}

#[tokio::test]
async fn selective_patterns_push_literals_into_requests() {
    let store =
        Memory::new((0..8).flat_map(|d| (0..2).map(move |t| format!("logs/day{d}/type{t}/file"))));
    let keys = listed(&store, "logs/day*/type0/*", 4).await;
    assert_eq!(keys.len(), 8);
    let calls = store.calls.borrow();
    assert_eq!(calls.len(), 9);
    assert_eq!(calls[0], ("logs/day".into(), true));
    assert!(calls[1..]
        .iter()
        .all(|(prefix, _)| prefix.ends_with("/type0/")));
}

#[tokio::test]
async fn flat_wide_and_deep_fallbacks_preserve_pagination() {
    for keys in [
        (0..2100)
            .map(|i| format!("flat/file{i:04}"))
            .collect::<Vec<_>>(),
        (0..1100).map(|i| format!("wide/dir{i:04}/file")).collect(),
        (0..2100)
            .map(|i| format!("deep/a/b/c/d/e/f/file{i:04}"))
            .collect(),
    ] {
        let store = Memory::new(keys);
        assert_eq!(listed(&store, "**", 4).await.len(), store.keys.len());
        assert!(
            store.calls.borrow().len() <= 15,
            "discovery must stop on deep or unhelpful trees"
        );
    }
    let store = Memory::new((0..1100).map(|i| format!("wide/dir{i:04}/file")));
    assert_eq!(listed(&store, "wide/*/file", 4).await.len(), 1100);
}

#[tokio::test]
async fn partial_listing_and_output_failures_propagate() {
    struct Fault;
    impl Store for Fault {
        async fn page(
            &self,
            _: &str,
            _: bool,
            token: Option<&str>,
            _: Option<&str>,
        ) -> Result<Page> {
            anyhow::ensure!(token.is_none(), "injected page failure");
            Ok(Page {
                entries: vec![Entry {
                    key: "a".into(),
                    size: 1,
                    last_modified: None,
                    etag: None,
                }],
                next: Some("next".into()),
                ..Page::default()
            })
        }
    }
    let pattern = Pattern::parse("s3://bucket/**").unwrap();
    let mut emitted = 0;
    let error = engine::enumerate(&Fault, &pattern, 1, |_| {
        emitted += 1;
        Ok(())
    })
    .await
    .unwrap_err();
    assert_eq!(emitted, 1);
    assert!(error.to_string().contains("injected page failure"));
    let error = engine::enumerate(&Fault, &pattern, 1, |_| {
        anyhow::bail!("injected output failure")
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("injected output failure"));
}

#[tokio::test]
async fn malformed_pages_fail() {
    struct Bad(bool);
    impl Store for Bad {
        async fn page(&self, _: &str, _: bool, _: Option<&str>, _: Option<&str>) -> Result<Page> {
            Ok(if self.0 {
                Page {
                    next: Some(String::new()),
                    ..Page::default()
                }
            } else {
                Page {
                    entries: vec![Entry {
                        key: "outside".into(),
                        size: 1,
                        last_modified: None,
                        etag: None,
                    }],
                    ..Page::default()
                }
            })
        }
    }
    let pattern = Pattern::parse("s3://bucket/prefix/**").unwrap();
    for bad in [Bad(false), Bad(true)] {
        assert!(engine::enumerate(&bad, &pattern, 1, |_| Ok(()))
            .await
            .is_err());
    }
}

#[tokio::test]
async fn literal_prefix_enumeration_preserves_metacharacters_and_overlap() {
    let prefix = "literal*?**[x]/";
    let mut keys: Vec<_> = (0..8)
        .flat_map(|d| (0..1200).map(move |i| format!("{prefix}day{d}/file{i:03}")))
        .collect();
    keys.extend([
        prefix.to_owned(),
        format!("{prefix}day0"),
        format!("{prefix}day0/"),
        "literal-other/file".into(),
        "literal*?**[x]-other/file".into(),
    ]);
    let store = Memory::new(keys);
    let expected: Vec<_> = store
        .keys
        .iter()
        .filter(|key| key.starts_with(prefix))
        .cloned()
        .collect();
    for concurrency in [1, 4] {
        let mut actual = Vec::new();
        engine::enumerate_prefix(&store, prefix, concurrency, None, |entry| {
            actual.push(entry.key);
            Ok(())
        })
        .await
        .unwrap();
        actual.sort();
        assert_eq!(actual, expected);
    }
    assert!(store.peak.get() > 1);
    assert!(store.peak.get() <= 4);
}

#[tokio::test]
async fn nested_probes_respect_the_actual_request_limit() {
    let store = Memory::new((0..4).flat_map(|a| {
        (0..2).flat_map(move |b| (0..2000).map(move |i| format!("tree/{a}/{b}/file{i:04}")))
    }));
    assert_eq!(listed(&store, "tree/**", 2).await.len(), 16000);
    assert_eq!(store.peak.get(), 2);
}

#[tokio::test]
async fn unordered_stores_do_not_apply_exact_key_shortcut() {
    struct Unordered;
    impl Store for Unordered {
        fn ordered(&self) -> bool {
            false
        }
        async fn page(
            &self,
            _: &str,
            _: bool,
            token: Option<&str>,
            _: Option<&str>,
        ) -> Result<Page> {
            Ok(Page {
                entries: vec![Entry {
                    key: if token.is_none() {
                        "exact-other"
                    } else {
                        "exact"
                    }
                    .into(),
                    size: 1,
                    last_modified: None,
                    etag: None,
                }],
                next: token.is_none().then(|| "next".into()),
                ..Page::default()
            })
        }
    }
    let mut keys = Vec::new();
    engine::enumerate(
        &Unordered,
        &Pattern::parse("s3://bucket/exact").unwrap(),
        32,
        |entry| {
            keys.push(entry.key);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(keys, ["exact"]);
}

#[tokio::test]
async fn directory_markers_do_not_stop_pruning_an_ignored_first_page() {
    let ignored = |key: &str, _directory: bool| {
        ["tree/d3/", "tree/a/d3/"]
            .into_iter()
            .find(|dir| key.starts_with(dir))
            .map(|dir| dir.len() - 1)
    };
    // The listed prefix's own marker, and a kept directory's marker, sort
    // before the ignored objects that fill the rest of the first page.
    for (marker, ignored_dir, kept, calls) in [
        (
            "tree/",
            "tree/d3/",
            ["tree/d4/a", "tree/top"],
            &[("tree/", false), ("tree/", true), ("tree/d4/", false)][..],
        ),
        (
            "tree/a/",
            "tree/a/d3/",
            ["tree/a/top", "tree/a/z/b"],
            &[
                ("tree/", false),
                ("tree/", true),
                ("tree/a/", true),
                ("tree/a/z/", false),
            ][..],
        ),
    ] {
        let store = Memory::new(
            (0..5000)
                .map(|i| format!("{ignored_dir}file{i:04}"))
                .chain([marker.to_owned()])
                .chain(kept.map(str::to_owned)),
        );
        let prune = engine::Prune {
            subtree: &ignored,
            probes: 4.into(),
        };
        let mut keys = Vec::new();
        let pruned = engine::enumerate_prefix(&store, "tree/", 8, Some(&prune), |entry| {
            keys.push(entry.key);
            Ok(())
        })
        .await
        .unwrap();
        keys.sort();
        let mut expected = vec![marker.to_owned()];
        expected.extend(kept.map(str::to_owned));
        assert_eq!(keys, expected);
        assert_eq!(pruned, [ignored_dir]);
        assert_eq!(
            *store.calls.borrow(),
            calls
                .iter()
                .map(|(prefix, delimiter)| (prefix.to_string(), *delimiter))
                .collect::<Vec<_>>()
        );
    }
}

fn tree(directories: usize, keys: usize) -> impl Iterator<Item = String> {
    (0..directories).flat_map(move |d| (0..keys).map(move |i| format!("t/d{d:04}/f{i:05}")))
}

/// The most requests a listing of `pages` sequential pages may make.
fn allowance(pages: usize) -> usize {
    pages + 2 + pages / 4
}

#[tokio::test(start_paused = true)]
async fn wide_and_deep_trees_list_in_parts_within_the_request_allowance() {
    let deep = (0..243usize).flat_map(|leaf| {
        let path: Vec<_> = (0..5)
            .rev()
            .map(|level| format!("n{}", (leaf / 3usize.pow(level)) % 3))
            .collect();
        let path = format!("t/a/b/c/d/{}", path.join("/"));
        (0..600).map(move |i| format!("{path}/f{i:03}"))
    });
    let partitioned = (0..3).flat_map(|year| {
        (0..12).flat_map(move |month| {
            (0..30).flat_map(move |day| {
                (0..200).map(move |i| format!("t/y={year}/m={month:02}/d={day:02}/part-{i:03}"))
            })
        })
    });
    // name, keys, the least factor by which round trips must fall
    let shapes: Vec<(&str, Vec<String>, usize)> = vec![
        ("few large directories", tree(8, 40_000).collect(), 5),
        ("a thousand shards", tree(1000, 300).collect(), 8),
        (
            "twenty thousand directories",
            tree(20_000, 100).collect(),
            8,
        ),
        ("date partitions", partitioned.collect(), 4),
        ("deep and narrow", deep.collect(), 2),
    ];
    for (name, keys, faster) in shapes {
        let store = Memory::new(keys);
        let pages = store.pages("t/");
        let (requests, trips) = walked(&store, "t/", 32, None).await;
        assert!(
            requests <= allowance(pages),
            "{name}: {requests} requests for {pages} pages"
        );
        assert!(
            trips as usize * faster <= pages,
            "{name}: {trips} round trips for {pages} pages"
        );
        // Every listing runs to its end, except those that handed part of
        // their keys to a listing of a longer prefix.
        let (listed, cut) = store.listings();
        for prefix in &cut {
            assert!(
                listed
                    .iter()
                    .any(|part| part.len() > prefix.len() && part.starts_with(prefix)),
                "{name}: the listing of {prefix:?} was cut short for nothing"
            );
        }
        // Without concurrency the listing is the sequential one.
        let (requests, _) = walked(&store, "t/", 1, None).await;
        assert_eq!(requests, pages, "{name}");
    }
}

#[tokio::test(start_paused = true)]
async fn small_sparse_and_flat_trees_cost_at_most_two_more_requests() {
    // name, keys, the most requests beyond the sequential pages
    let shapes: Vec<(&str, Vec<String>, usize)> = vec![
        ("one page", tree(5, 10).collect(), 0),
        ("two sparse pages", tree(256, 4).collect(), 0),
        ("eleven sparse pages", tree(256, 40).collect(), 2),
        ("two dense pages", tree(1, 1001).collect(), 1),
        ("three sparse pages", tree(30, 90).collect(), 0),
        ("three pages in one directory", tree(1, 2500).collect(), 1),
        ("four pages in two directories", tree(2, 1700).collect(), 1),
        ("one flat directory", tree(1, 30_000).collect(), 2),
        ("two keys a directory", tree(30_000, 2).collect(), 2),
        (
            "a dense directory before sparse ones",
            tree(1, 2001)
                .chain((0..200).map(|d| format!("t/z{d:03}/only")))
                .collect(),
            2,
        ),
        (
            "seven dense directories before a thousand sparse ones",
            tree(7, 300)
                .chain((0..993).map(|d| format!("t/z{d:03}/only")))
                .collect(),
            2,
        ),
    ];
    for (name, keys, extra) in shapes {
        let store = Memory::new(keys);
        let pages = store.pages("t/");
        let (requests, _) = walked(&store, "t/", 32, None).await;
        assert!(
            requests <= pages + extra,
            "{name}: {requests} requests for {pages} pages"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn dense_directories_under_a_narrow_prefix_are_listed_at_once() {
    // Two dense directories within three pages and at most 64 children:
    // unfiltered listings give every remaining child a listing of its own.
    let store = Memory::new(tree(64, 400));
    let (requests, trips) = walked(&store, "t/", 32, None).await;
    assert!(requests <= 63, "{requests} requests");
    assert!(trips <= 5, "{trips} round trips");
    assert!(store.peak.get() > 16);
    // The directories the first pages covered are not listed again.
    let (listed, _) = store.listings();
    for d in 0..4 {
        assert!(!listed.contains(&format!("t/d{d:04}/")));
    }
    // A third page finds the second dense directory.
    let store = Memory::new(tree(8, 2000));
    let (requests, trips) = walked(&store, "t/", 32, None).await;
    assert!(requests <= allowance(16) + 6, "{requests} requests");
    assert!(trips <= 6, "{trips} round trips");
    // Filtered listings keep to the allowance: sparse siblings of two dense
    // directories would cost a request each.
    let keys = || tree(2, 1500).chain((2..64).map(|d| format!("t/e{d:02}/file")));
    let kept = |_: &str, _: bool| None;
    let prune = engine::Prune {
        subtree: &kept,
        probes: 4.into(),
    };
    let store = Memory::new(keys());
    let (requests, _) = walked(&store, "t/", 32, Some(&prune)).await;
    assert!(requests <= 4 + 2, "{requests} requests");
    let store = Memory::new(keys());
    let (requests, _) = walked(&store, "t/", 32, None).await;
    assert!(requests <= 4 + 2 + 62, "{requests} requests");
}

#[tokio::test(start_paused = true)]
async fn objects_beside_directories_are_reported_once() {
    // Objects of the listed directory sort among, and after, the children
    // that parts take over, and some share a child's name or its start.
    let keys = tree(40, 1500)
        .chain(
            [
                "t/",
                "t/d0003",
                "t/d0003.txt",
                "t/d0005/",
                "t/d001",
                "t/d002-notes",
                "t/d0039/",
                "t/d0039x",
                "t/d1",
                "t/zz",
                "t/é/文",
                "t/é文",
                "t-other/file",
            ]
            .map(String::from),
        )
        .chain((0..1500).map(|i| format!("t/e é/sp +%{i:04}")))
        .chain((0..1500).map(|i| format!("t/e é文/{i:04}")));
    let store = Memory::new(keys);
    for concurrency in [2, 32] {
        // Forty children, the first of them dense: each gets its own listing.
        let (requests, _) = walked(&store, "t/", concurrency, None).await;
        assert!(requests <= allowance(store.pages("t/")) + 40);
        assert!(store.listings().0.len() > 4, "the tree was listed in parts");
    }
    // A pattern's recursive part can start in the middle of a name.
    let expected: Vec<_> = store
        .keys
        .iter()
        .filter(|key| key.starts_with("t/d00"))
        .cloned()
        .collect();
    assert_eq!(listed(&store, "t/d00**", 32).await, expected);
}

#[tokio::test]
async fn parts_take_the_shortest_prefix_the_listing_has_not_passed() {
    for (inside, name, expected) in [
        ("t/s0006/", "t/s0999/", "t/s09"),
        ("t/s0006/", "t/s0007/", "t/s0007"),
        ("t/s0006/", "t/x/", "t/x"),
        ("t/a", "t/a/", "t/a/"),
        ("t/a/", "t/ab/", "t/ab"),
        ("t/file", "t/zebra/", "t/z"),
        ("t/é/", "t/ê/", "t/ê"),
        ("t/é/", "t/é文/", "t/é文"),
    ] {
        assert_eq!(engine::block(inside, name), expected, "{inside} {name}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_children_listing_that_misses_a_directory_ahead_loses_nothing() {
    struct Incomplete(Memory);
    impl Store for Incomplete {
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            _: Option<&str>,
        ) -> Result<Page> {
            let mut page = self.0.page(prefix, delimiter, token, None).await?;
            if delimiter {
                page.prefixes.retain(|prefix| prefix != "t/d0001/");
            }
            Ok(page)
        }
    }
    // The listing has yet to reach the directory when it hands the later
    // ones over, and stops only where the first of those begins.
    let store = Incomplete(Memory::new(tree(8, 2000)));
    let mut keys = Vec::new();
    engine::enumerate_prefix(&store, "t/", 32, None, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(keys.len(), 16000);
    assert_eq!(keys.into_iter().collect::<BTreeSet<_>>(), store.0.keys);
    assert!(
        store.0.listings().0.len() > 1,
        "the tree was listed in parts"
    );
}

#[tokio::test(start_paused = true)]
async fn keys_out_of_order_stop_a_listing_in_parts() {
    /// Returns the keys of each page of `t/` in reverse from the given page on.
    struct Reversed {
        inner: Memory,
        from: usize,
        pages: Cell<usize>,
    }
    impl Store for Reversed {
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            _: Option<&str>,
        ) -> Result<Page> {
            let mut page = self.inner.page(prefix, delimiter, token, None).await?;
            if prefix == "t/" && !delimiter {
                self.pages.set(self.pages.get() + 1);
                if self.pages.get() >= self.from {
                    page.entries.reverse();
                }
            }
            Ok(page)
        }
    }
    let list = |from, concurrency| async move {
        let store = Reversed {
            inner: Memory::new(tree(100, 300)),
            from,
            pages: Cell::new(0),
        };
        let mut keys = BTreeSet::new();
        let outcome = engine::enumerate_prefix(&store, "t/", concurrency, None, |entry| {
            assert!(keys.insert(entry.key));
            Ok(())
        })
        .await;
        (
            outcome,
            keys == store.inner.keys,
            store.inner.listings().0.len(),
        )
    };
    // Out of order from the start: the listing is never divided.
    let (outcome, complete, listings) = list(1, 32).await;
    assert!(outcome.is_ok() && complete);
    assert_eq!(listings, 1);
    // Out of order once parts were handed over: where to stop is unknown.
    let (outcome, _, listings) = list(4, 32).await;
    assert!(outcome.unwrap_err().is::<engine::Unordered>());
    assert!(listings > 1);
    // One request at a time relies on no order.
    let (outcome, complete, listings) = list(4, 1).await;
    assert!(outcome.is_ok() && complete);
    assert_eq!(listings, 1);
}

#[tokio::test(start_paused = true)]
async fn stores_without_key_order_are_listed_whole() {
    struct Unordered(Memory);
    impl Store for Unordered {
        fn ordered(&self) -> bool {
            false
        }
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            _: Option<&str>,
        ) -> Result<Page> {
            self.0.page(prefix, delimiter, token, None).await
        }
    }
    let store = Unordered(Memory::new(tree(100, 300)));
    let mut keys = 0;
    engine::enumerate_prefix(&store, "t/", 32, None, |_| {
        keys += 1;
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(keys, 30_000);
    assert_eq!(*store.0.calls.borrow(), vec![("t/".to_owned(), false); 30]);
}

#[tokio::test(start_paused = true)]
async fn filtered_listings_leave_out_pruned_directories_at_the_end() {
    let ignored = |key: &str, _directory: bool| {
        ["t/d0003/", "t/d0006/", "t/d0007/"]
            .into_iter()
            .find(|directory| key.starts_with(directory))
            .map(|directory| directory.len() - 1)
    };
    let prune = engine::Prune {
        subtree: &ignored,
        probes: 4.into(),
    };
    let store = Memory::new(tree(8, 5000).chain(["t/d0007.txt".to_owned(), "t/zz".to_owned()]));
    let mut keys = Vec::new();
    let mut pruned = engine::enumerate_prefix(&store, "t/", 32, Some(&prune), |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    pruned.sort();
    // The last directories are never listed. The one in the middle is left
    // out once everything after it has a listing of its own.
    assert_eq!(pruned, ["t/d0003/", "t/d0006/", "t/d0007/"]);
    keys.sort();
    let expected: Vec<_> = store
        .keys
        .iter()
        .filter(|key| ignored(key, false).is_none())
        .cloned()
        .collect();
    assert!(keys == expected);
    assert!(store.calls.borrow().len() <= allowance(25));
}

#[tokio::test(start_paused = true)]
async fn a_part_never_covers_a_pruned_directory_that_starts_like_it() {
    // `t/build/` is left out; the part for the directories before it must
    // not be `t/b`, which would list it whole.
    let ignored = |key: &str, _directory: bool| key.starts_with("t/build/").then_some(7);
    let prune = engine::Prune {
        subtree: &ignored,
        probes: 4.into(),
    };
    let keys = (0..12_000)
        .map(|i| format!("t/a/f{i:05}"))
        .chain((0..3).flat_map(|d| (0..300).map(move |i| format!("t/b{d:02}/f{i:03}"))))
        .chain((0..20_000).map(|i| format!("t/build/f{i:05}")));
    let store = Memory::new(keys);
    let mut keys = Vec::new();
    let pruned = engine::enumerate_prefix(&store, "t/", 32, Some(&prune), |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(pruned, ["t/build/"]);
    assert!(keys.iter().all(|key| !key.starts_with("t/build/")));
    assert_eq!(keys.len(), 12_900);
    assert!(store.calls.borrow().len() <= allowance(13));
}
