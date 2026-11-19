use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

struct Memory {
    keys: BTreeSet<String>,
    calls: RefCell<Vec<(String, bool)>>,
    resumes: RefCell<Vec<(String, String)>>,
    active: Cell<usize>,
    peak: Cell<usize>,
}
impl Memory {
    fn new(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            calls: RefCell::default(),
            resumes: RefCell::default(),
            active: Cell::new(0),
            peak: Cell::new(0),
        }
    }
}
impl Store for Memory {
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        self.calls.borrow_mut().push((prefix.into(), delimiter));
        if let Some(after) = start_after {
            assert!(!delimiter && token.is_none());
            self.resumes
                .borrow_mut()
                .push((prefix.into(), after.into()));
        }
        self.active.set(self.active.get() + 1);
        self.peak.set(self.peak.get().max(self.active.get()));
        tokio::time::sleep(Duration::from_millis(1)).await;
        self.active.set(self.active.get() - 1);
        let token_start = token.map(|t| {
            let marker = format!("{}:{prefix}:", u8::from(delimiter));
            t.strip_prefix(&marker)
                .expect("token must stay with its original query")
                .parse::<usize>()
                .unwrap()
        });
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
        let start = token_start.unwrap_or_else(|| {
            items
                .keys()
                .take_while(|key| start_after.is_some_and(|after| key.as_str() <= after))
                .count()
        });
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
                    // Directory markers are empty.
                    size: u64::from(!key.ends_with('/')),
                    key,
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
    assert_eq!(store.calls.borrow().len(), 17);
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
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            start_after: Option<&str>,
        ) -> Result<Page> {
            let mut page = self.0.page(prefix, delimiter, token, start_after).await?;
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
    engine::enumerate_prefix(&store, "tree/", 32, None, |entry| {
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

#[tokio::test]
async fn resumed_child_can_split_again_without_losing_or_duplicating_keys() {
    let store = Memory::new(
        (0..1200)
            .map(|i| format!("tree/a/{i:04}"))
            .chain((0..8).flat_map(|d| (0..1200).map(move |i| format!("tree/b/{d}/sp +%é{i:04}"))))
            .chain([
                "tree/b/".into(),
                "tree/b/0/".into(),
                "tree/b/8-direct".into(),
                "tree/z".into(),
            ]),
    );
    let expected: Vec<_> = store.keys.iter().cloned().collect();
    assert_eq!(listed(&store, "tree/**", 8).await, expected);
    let resumes = store.resumes.borrow();
    assert!(resumes.iter().any(|(prefix, _)| prefix == "tree/b/"));
    assert!(resumes
        .iter()
        .any(|(prefix, _)| prefix.starts_with("tree/b/") && prefix != "tree/b/"));
}

#[tokio::test]
async fn ignored_start_after_filters_every_continuation_page() {
    struct IgnoresStartAfter {
        inner: Memory,
        resumes: Cell<usize>,
    }
    impl Store for IgnoresStartAfter {
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            start_after: Option<&str>,
        ) -> Result<Page> {
            if start_after.is_some() {
                assert!(token.is_none());
                self.resumes.set(self.resumes.get() + 1);
            }
            self.inner.page(prefix, delimiter, token, None).await
        }
    }
    // Exercise a completely filtered first page followed by a partially
    // filtered page, as well as a cursor exactly on a page boundary.
    for leading in [256, 600, 1000, 1200] {
        for glob in [false, true] {
            let store = IgnoresStartAfter {
                inner: Memory::new(
                    (0..leading)
                        .map(|i| format!("tree/a/{i:04}"))
                        .chain((0..6200).map(|i| format!("tree/b/sp +%é{i:04}"))),
                ),
                resumes: Cell::new(0),
            };
            let mut actual = Vec::new();
            if glob {
                engine::enumerate(
                    &store,
                    &Pattern::parse("s3://bucket/tree/**").unwrap(),
                    8,
                    |entry| {
                        actual.push(entry.key);
                        Ok(())
                    },
                )
                .await
                .unwrap();
            } else {
                engine::enumerate_prefix(&store, "tree/", 8, None, |entry| {
                    actual.push(entry.key);
                    Ok(())
                })
                .await
                .unwrap();
            }
            actual.sort();
            assert_eq!(actual, store.inner.keys.iter().cloned().collect::<Vec<_>>());
            assert_eq!(store.resumes.get(), 1);
            assert_eq!(
                store
                    .inner
                    .calls
                    .borrow()
                    .iter()
                    .filter(|(prefix, delimiter)| prefix == "tree/b/" && !delimiter)
                    .count(),
                7
            );
        }
    }
}

#[tokio::test]
async fn filtered_listings_stay_flat_and_prune_ignored_first_pages() {
    async fn pruned(store: &Memory, prune: &engine::Prune<'_>) -> (Vec<String>, Vec<String>) {
        let mut keys = Vec::new();
        let pruned = engine::enumerate_prefix(store, "tree/", 8, Some(prune), |entry| {
            keys.push(entry.key);
            Ok(())
        })
        .await
        .unwrap();
        (keys, pruned)
    }
    let ignored =
        |key: &str, _directory: bool| key.starts_with("tree/d3/").then_some("tree/d3".len());
    // Filtered listings do not split dense directories: with many small
    // siblings that would cost a request per sibling.
    let store = Memory::new(
        (0..2)
            .flat_map(|d| (0..1500).map(move |i| format!("tree/d{d}/file{i:04}")))
            .chain((2..64).map(|d| format!("tree/e{d:02}/file"))),
    );
    let prune = engine::Prune {
        subtree: &ignored,
        probes: 4.into(),
    };
    let (keys, pruned_prefixes) = pruned(&store, &prune).await;
    assert!(pruned_prefixes.is_empty());
    assert_eq!(keys.len(), store.keys.len());
    assert_eq!(*store.calls.borrow(), vec![("tree/".to_owned(), false); 4]);
    // A first page entirely in a pruned directory switches to a directory
    // listing at once, following a single included child.
    let store = Memory::new(
        (0..5000)
            .map(|i| format!("tree/d3/file{i:04}"))
            .chain(["tree/d4/a".into(), "tree/top".into()]),
    );
    let prune = engine::Prune {
        subtree: &ignored,
        probes: 4.into(),
    };
    let (mut keys, pruned_prefixes) = pruned(&store, &prune).await;
    keys.sort();
    assert_eq!(keys, ["tree/d4/a", "tree/top"]);
    assert_eq!(pruned_prefixes, ["tree/d3/"]);
    assert_eq!(
        *store.calls.borrow(),
        [
            ("tree/".to_owned(), false),
            ("tree/".to_owned(), true),
            ("tree/d4/".to_owned(), false)
        ]
    );
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

#[test]
fn only_aws_general_purpose_endpoints_divide_listings() {
    if std::env::var_os("SYQ_TEST_S3_DIVIDE_LISTINGS").is_some() {
        return;
    }
    // The AWS endpoint the SDK chooses, and the base URLs of it a user can
    // name; the client addresses buckets path-style.
    assert!(lists_in_byte_order(None, "bucket"));
    for endpoint in [
        "https://s3.amazonaws.com",
        "http://s3.amazonaws.com:80",
        "https://s3.us-west-2.amazonaws.com",
        "https://S3.EU-CENTRAL-1.AMAZONAWS.COM/",
        "https://s3-us-west-2.amazonaws.com",
        "https://s3-external-1.amazonaws.com",
        "https://s3.dualstack.eu-central-1.amazonaws.com",
        "https://s3-fips.us-gov-west-1.amazonaws.com",
        "https://s3-fips.dualstack.us-east-1.amazonaws.com",
        "https://s3.cn-north-1.amazonaws.com.cn",
        "https://s3.dualstack.cn-northwest-1.amazonaws.com.cn",
        "https://bucket.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
    ] {
        assert!(lists_in_byte_order(Some(endpoint), "bucket"), "{endpoint}");
    }
    for endpoint in [
        // Providers that do not document byte order, and look-alikes.
        "https://account.r2.cloudflarestorage.com",
        "https://r2.cloudflarestorage.com.example.org",
        "https://storage.googleapis.com",
        "https://s3.us-west-002.backblazeb2.com",
        "https://t3.storage.dev",
        "https://fly.storage.tigris.dev",
        "https://s3.amazonaws.com.example.org",
        "https://s3.us-east-1.amazonaws.com.example.org",
        "https://s3.amazonaws.com.",
        "https://s3.us-east-1.amazonaws.co",
        "https://evils3.us-east-1.amazonaws.com",
        "https://s3.notaregion.amazonaws.com",
        "https://s3-fips.amazonaws.com",
        // Hosts that already name a bucket: path-style requests to them do
        // not list that bucket.
        "https://bucket.s3.us-east-1.amazonaws.com",
        "https://my.dotted.bucket.s3.amazonaws.com",
        // VPC interface endpoint roles other than buckets.
        "https://vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
        "https://accesspoint.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
        "https://control.vpce-1a2b3c4d-5e6f.s3.us-east-1.vpce.amazonaws.com",
        "https://s3.us-east-1.vpce.amazonaws.com",
        "https://bucket.vpce-1a2b3c4d-5e6f.vpce-svc-0123.us-east-1.vpce.amazonaws.com",
        // AWS hosts that are not general purpose bucket endpoints.
        "https://bucket--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com",
        "https://s3express-control.us-west-2.amazonaws.com",
        "https://ap-123456789012.s3-accesspoint.us-east-1.amazonaws.com",
        "https://s3-outposts.us-east-1.amazonaws.com",
        "https://s3-object-lambda.us-east-1.amazonaws.com",
        "https://alias.accesspoint.s3-global.amazonaws.com",
        "https://s3-website-us-east-1.amazonaws.com",
        "https://s3-website.us-east-1.amazonaws.com",
        "https://s3-123456.us-east-1.elb.amazonaws.com",
        "https://s3.us-east-1.elb.amazonaws.com",
        // Self-hosted and local endpoints.
        "http://127.0.0.1:9000",
        "http://[::1]:9000",
        "http://localhost:9000",
        "https://minio.example.internal",
        "not a url",
        // A path names another bucket on the way.
        "https://s3.us-east-1.amazonaws.com/archive/",
        "https://s3.us-east-1.amazonaws.com/archive",
    ] {
        assert!(!lists_in_byte_order(Some(endpoint), "bucket"), "{endpoint}");
    }
    // Names that are not general purpose buckets, at any endpoint.
    for bucket in [
        "dir--usw2-az1--x-s3",
        "point--usw2-az1--xa-s3",
        "banner-123456789012--ol-s3",
        "outpost-alias--op-s3",
        "point-abcdefghij-s3alias",
        "mfzwi23gnjvgw.mrap",
        "tables--table-s3",
        "arn:aws:s3:us-east-1:123456789012:accesspoint/point",
    ] {
        assert!(!lists_in_byte_order(None, bucket), "{bucket}");
        assert!(
            !lists_in_byte_order(Some("https://s3.us-east-1.amazonaws.com"), bucket),
            "{bucket}"
        );
    }
}
