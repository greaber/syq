use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

struct Memory {
    keys: BTreeSet<String>,
    calls: RefCell<Vec<(String, bool)>>,
    active: Cell<usize>,
    peak: Cell<usize>,
}
impl Memory {
    fn new(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            calls: RefCell::default(),
            active: Cell::new(0),
            peak: Cell::new(0),
        }
    }
}
impl Store for Memory {
    async fn page(&self, prefix: &str, delimiter: bool, token: Option<&str>) -> Result<Page> {
        self.calls.borrow_mut().push((prefix.into(), delimiter));
        self.active.set(self.active.get() + 1);
        self.peak.set(self.peak.get().max(self.active.get()));
        tokio::time::sleep(Duration::from_millis(1)).await;
        self.active.set(self.active.get() - 1);
        let start = token
            .map(|t| {
                let marker = format!("{}:{prefix}:", u8::from(delimiter));
                t.strip_prefix(&marker)
                    .expect("token must stay with its original query")
                    .parse::<usize>()
                    .unwrap()
            })
            .unwrap_or(0);
        let mut items = BTreeMap::new();
        for key in &self.keys {
            let Some(suffix) = key.strip_prefix(prefix) else {
                continue;
            };
            if let Some(slash) = delimiter.then(|| suffix.find('/')).flatten() {
                items.insert(format!("{prefix}{}", &suffix[..slash + 1]), true);
            } else {
                items.insert(key.clone(), false);
            }
        }
        let next = (items.len() > start + 1000)
            .then(|| format!("{}:{prefix}:{}", u8::from(delimiter), start + 1000));
        let mut page = Page {
            next,
            ..Page::default()
        };
        for (key, directory) in items.into_iter().skip(start).take(1000) {
            if directory {
                page.prefixes.push(key);
            } else {
                page.entries.push(Entry {
                    key,
                    size: 1,
                    last_modified: None,
                    etag: None,
                });
            }
        }
        Ok(page)
    }
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
        async fn page(&self, _: &str, _: bool, token: Option<&str>) -> Result<Page> {
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
        async fn page(&self, _: &str, _: bool, _: Option<&str>) -> Result<Page> {
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
        engine::enumerate_prefix(&store, prefix, concurrency, |entry| {
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
async fn sparse_trees_stay_flat_and_exact_keys_stop_after_one_page() {
    for per_directory in [4, 40] {
        let store =
            Memory::new((0..256).flat_map(|d| {
                (0..per_directory).map(move |i| format!("tree/dir{d:03}/file{i:03}"))
            }));
        let keys = listed(&store, "tree/**", 32).await;
        assert_eq!(keys.len(), 256 * per_directory);
        assert_eq!(store.calls.borrow().len(), keys.len().div_ceil(1000));
        assert!(store.calls.borrow().iter().all(|(_, delimiter)| !delimiter));
    }
    let store = Memory::new(
        std::iter::once("exact".into()).chain((0..3000).map(|i| format!("exact{i:04}"))),
    );
    assert_eq!(listed(&store, "exact", 32).await, ["exact"]);
    assert_eq!(store.calls.borrow().len(), 1);
}

#[tokio::test]
async fn two_page_dense_tree_finishes_flat_and_dense_branches_overlap() {
    let store = Memory::new((0..1001).map(|i| format!("tree/a/file{i:04}")));
    assert_eq!(listed(&store, "tree/**", 32).await.len(), 1001);
    assert_eq!(store.calls.borrow().len(), 3);
    assert!(store
        .calls
        .borrow()
        .iter()
        .all(|(prefix, _)| prefix == "tree/"));
    assert_eq!(store.peak.get(), 2, "probe overlaps useful continuation");
    let store = Memory::new(
        (0..8).flat_map(|d| (0..2000).map(move |i| format!("tree/dir{d:02}/file{i:04}"))),
    );
    assert_eq!(listed(&store, "tree/**", 32).await.len(), 16000);
    assert_eq!(store.calls.borrow().len(), 18);
    assert!(store.peak.get() > 1);
    assert!(store.peak.get() <= 8);
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
async fn dense_head_with_sparse_siblings_does_not_fan_out() {
    let store = Memory::new(
        (0..2001)
            .map(|i| format!("tree/a/file{i:04}"))
            .chain((1..8).map(|i| format!("tree/dir{i}/file"))),
    );
    assert_eq!(listed(&store, "tree/**", 32).await.len(), 2008);
    assert_eq!(store.calls.borrow().len(), 4);
    assert!(store
        .calls
        .borrow()
        .iter()
        .all(|(prefix, _)| prefix == "tree/"));
}

#[tokio::test]
async fn unordered_stores_do_not_apply_exact_key_shortcut() {
    struct Unordered;
    impl Store for Unordered {
        fn ordered(&self) -> bool {
            false
        }
        async fn page(&self, _: &str, _: bool, token: Option<&str>) -> Result<Page> {
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
async fn medium_density_keeps_latency_parallelism_and_reuses_complete_children() {
    let store = Memory::new(
        (0..64).flat_map(|d| (0..400).map(move |i| format!("tree/dir{d:03}/file{i:04}"))),
    );
    assert_eq!(listed(&store, "tree/**", 32).await.len(), 25600);
    let calls = store.calls.borrow();
    assert_eq!(calls.len(), 63);
    // The first four children are fully covered by the two sampled pages.
    for d in 0..4 {
        assert!(!calls
            .iter()
            .any(|(prefix, _)| prefix == &format!("tree/dir{d:03}/")));
    }
    assert!(store.peak.get() > 1);
    assert!(store.peak.get() <= 32);
}

#[tokio::test]
async fn incomplete_directory_probe_cannot_discard_observed_objects() {
    struct Incomplete(Memory);
    impl Store for Incomplete {
        async fn page(&self, prefix: &str, delimiter: bool, token: Option<&str>) -> Result<Page> {
            let mut page = self.0.page(prefix, delimiter, token).await?;
            if delimiter {
                page.prefixes.retain(|prefix| prefix != "tree/dir01/");
            }
            Ok(page)
        }
    }
    let store =
        Incomplete(Memory::new((0..8).flat_map(|d| {
            (0..2000).map(move |i| format!("tree/dir{d:02}/file{i:04}"))
        })));
    let mut keys = Vec::new();
    engine::enumerate_prefix(&store, "tree/", 32, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(keys.len(), 16000);
    assert_eq!(keys.into_iter().collect::<BTreeSet<_>>(), store.0.keys);
    assert!(store
        .0
        .calls
        .borrow()
        .iter()
        .all(|(prefix, _)| prefix == "tree/"));
}
