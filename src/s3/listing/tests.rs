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
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        assert!(start_after.is_none());
        self.calls.borrow_mut().push((prefix.into(), delimiter));
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
        let start = token_start.unwrap_or(0);
        let next = (items.len() > start + 1000)
            .then(|| format!("{}:{prefix}:{}", u8::from(delimiter), start + 1000));
        let mut page = Page {
            complete: next.is_none(),
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
}

#[tokio::test]
async fn sparse_trees_stay_flat_and_exact_keys_stop_after_one_page_in_byte_order() {
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
    // In byte order an exact key comes first, before longer ones.
    struct ByteOrder(Memory);
    impl Store for ByteOrder {
        fn divides(&self) -> bool {
            true
        }
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            start_after: Option<&str>,
        ) -> Result<Page> {
            self.0.page(prefix, delimiter, token, start_after).await
        }
    }
    let keys = || std::iter::once("exact".into()).chain((0..3000).map(|i| format!("exact{i:04}")));
    let store = ByteOrder(Memory::new(keys()));
    let mut found = Vec::new();
    engine::enumerate(
        &store,
        &Pattern::parse("s3://bucket/exact").unwrap(),
        32,
        |entry| {
            found.push(entry.key);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(found, ["exact"]);
    assert_eq!(store.0.calls.borrow().len(), 1);
    // Without that order, a key found on the first page needs no more, and
    // that page is the same request: a policy that refuses delimiters allows
    // it.
    let store = NoDelimiter(Memory::new(keys()));
    let mut found = Vec::new();
    engine::enumerate(
        &store,
        &Pattern::parse("s3://bucket/exact").unwrap(),
        32,
        |entry| {
            found.push(entry.key);
            Ok(())
        },
    )
    .await
    .unwrap();
    assert_eq!(found, ["exact"]);
    assert_eq!(*store.0.calls.borrow(), [("exact".to_owned(), false)]);
}

#[tokio::test]
async fn unordered_stores_look_past_the_first_page_for_an_exact_key() {
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
async fn filtered_listings_stay_flat_and_prune_ignored_first_pages() {
    async fn pruned(store: &Memory, prune: &engine::Prune<'_>) -> (Vec<String>, Vec<String>) {
        listed_with(store, prune, 8).await
    }
    async fn listed_with(
        store: &Memory,
        prune: &engine::Prune<'_>,
        concurrency: usize,
    ) -> (Vec<String>, Vec<String>) {
        let mut keys = Vec::new();
        let pruned = engine::enumerate_prefix(store, "tree/", concurrency, Some(prune), |entry| {
            keys.push(entry.key);
            Ok(())
        })
        .await
        .unwrap();
        (keys, pruned)
    }
    let ignored =
        |key: &str, _directory: bool| key.starts_with("tree/d3/").then_some("tree/d3".len());
    // With one request slot, a first page with included objects stays flat.
    let store = Memory::new(
        (0..2)
            .flat_map(|d| (0..1500).map(move |i| format!("tree/d{d}/file{i:04}")))
            .chain((2..64).map(|d| format!("tree/e{d:02}/file"))),
    );
    let prune = engine::Prune {
        subtree: &ignored,
        probes: 4.into(),
    };
    let (keys, pruned_prefixes) = listed_with(&store, &prune, 1).await;
    assert!(pruned_prefixes.is_empty());
    assert_eq!(keys.len(), store.keys.len());
    assert_eq!(*store.calls.borrow(), vec![("tree/".to_owned(), false); 4]);
    // With more, its directories are listed by themselves or in groups.
    store.calls.borrow_mut().clear();
    let (mut keys, pruned_prefixes) = pruned(&store, &prune).await;
    assert!(pruned_prefixes.is_empty());
    keys.sort();
    assert_eq!(keys, store.keys.iter().cloned().collect::<Vec<_>>());
    assert_eq!(
        store.calls.borrow()[..2],
        [("tree/".into(), false), ("tree/".into(), true)]
    );
    assert!(store.calls.borrow()[2..]
        .iter()
        .all(|(prefix, delimiter)| !delimiter && prefix != "tree/"));
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
        "https://s3.us-east-1.amazonaws.com/archive/../",
        "https://s3.us-east-1.amazonaws.com/./",
        "https://s3.us-east-1.amazonaws.com//",
        "https://s3.us-east-1.amazonaws.com\\archive",
        "https:/s3.us-east-1.amazonaws.com/archive/",
        "https:s3.us-east-1.amazonaws.com/archive/",
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

/// Refuses listings with a delimiter, as a policy can.
struct NoDelimiter<S>(S);
impl<S: Store> Store for NoDelimiter<S> {
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        if delimiter {
            return Err(anyhow::Error::msg("AccessDenied").context(
                crate::s3::client::RequestFailure::refused_for_test("S3 listing"),
            ));
        }
        self.0.page(prefix, delimiter, token, start_after).await
    }
}

/// Lists in the order measured on Cloudflare R2: as if every key ended in a
/// byte just above `9`, so `a0`, `a/b` and `a19` come before `a1`.
/// StartAfter follows the same order.
struct R2Order(Memory);
impl R2Order {
    fn position(key: &str) -> Vec<u8> {
        let mut position = key.as_bytes().to_vec();
        position.extend([b'9', 0xff]);
        position
    }
}
impl Store for R2Order {
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        self.0.calls.borrow_mut().push((prefix.into(), delimiter));
        let mut keys: Vec<_> = self
            .0
            .keys
            .iter()
            .filter(|key| key.starts_with(prefix))
            .collect();
        keys.sort_by_key(|key| Self::position(key));
        let mut items: Vec<(String, bool)> = Vec::new();
        for key in keys {
            match delimiter.then(|| key[prefix.len()..].find('/')).flatten() {
                Some(slash) => {
                    let child = key[..prefix.len() + slash + 1].to_owned();
                    if !items.contains(&(child.clone(), true)) {
                        items.push((child, true));
                    }
                }
                None => items.push((key.clone(), false)),
            }
        }
        let start = match token {
            Some(token) => token.parse().unwrap(),
            None => items
                .iter()
                .take_while(|(item, _)| {
                    start_after.is_some_and(|after| Self::position(item) <= Self::position(after))
                })
                .count(),
        };
        let next = (items.len() > start + 1000).then(|| (start + 1000).to_string());
        let mut page = Page {
            complete: next.is_none(),
            next,
            ..Page::default()
        };
        for (item, directory) in items.into_iter().skip(start).take(1000) {
            if directory {
                page.prefixes.push(item);
            } else {
                page.entries.push(Entry {
                    size: u64::from(!item.ends_with('/')),
                    key: item,
                    last_modified: None,
                    etag: None,
                });
            }
        }
        Ok(page)
    }
}

#[tokio::test]
async fn listings_from_a_store_not_in_byte_order_miss_no_key() {
    // Two pages end at `c03/k199`; R2 returns `c03/k19` first on the third.
    let store = R2Order(Memory::new(
        ["c00", "c01", "c02", "c03"]
            .into_iter()
            .flat_map(|d| (0..600).map(move |i| format!("trap/{d}/k{i:03}")))
            .chain(["trap/c03/k19".into()]),
    ));
    let expected: Vec<_> = store.0.keys.iter().cloned().collect();
    for concurrency in [1, 32] {
        let mut keys = Vec::new();
        engine::enumerate_prefix(&store, "trap/", concurrency, None, |entry| {
            keys.push(entry.key);
            Ok(())
        })
        .await
        .unwrap();
        let missing: Vec<_> = expected.iter().filter(|key| !keys.contains(key)).collect();
        assert!(missing.is_empty(), "concurrency {concurrency}: {missing:?}");
        assert_eq!(keys.len(), expected.len());
        let mut keys = Vec::new();
        engine::enumerate(
            &store,
            &Pattern::parse("s3://bucket/trap/**").unwrap(),
            concurrency,
            |entry| {
                keys.push(entry.key);
                Ok(())
            },
        )
        .await
        .unwrap();
        let missing: Vec<_> = expected.iter().filter(|key| !keys.contains(key)).collect();
        assert!(missing.is_empty(), "concurrency {concurrency}: {missing:?}");
        assert_eq!(keys.len(), expected.len());
    }
    // A whole page of longer keys comes before the exact key; deeper ones
    // are left out once the first page shows that.
    let store = R2Order(Memory::new((0..1000).map(|i| format!("a/{i:04}")).chain([
        "a".into(),
        "a0".into(),
        "b".into(),
    ])));
    for concurrency in [1, 32] {
        let mut keys = Vec::new();
        engine::enumerate(
            &store,
            &Pattern::parse("s3://bucket/a").unwrap(),
            concurrency,
            |entry| {
                keys.push(entry.key);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(keys, ["a"], "concurrency {concurrency}");
        assert_eq!(
            store.0.calls.borrow_mut().split_off(0),
            [("a".into(), false), ("a".into(), true)]
        );
    }
    // Where a policy refuses the delimiter listing, the flat one goes on to
    // the key on its second page, or to its end.
    for present in [true, false] {
        let store = NoDelimiter(R2Order(Memory::new(
            (0..1001)
                .map(|i| format!("a{i:04}"))
                .chain(present.then(|| "a".to_owned())),
        )));
        let mut keys = Vec::new();
        engine::enumerate(
            &store,
            &Pattern::parse("s3://bucket/a").unwrap(),
            1,
            |entry| {
                keys.push(entry.key);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(keys, if present { vec!["a"] } else { vec![] });
        assert_eq!(
            *store.0 .0.calls.borrow(),
            [("a".to_owned(), false), ("a".to_owned(), false)]
        );
    }
}

#[tokio::test]
async fn a_glob_that_needs_more_than_a_page_stays_delimited_where_order_is_unknown() {
    // In R2's order the first page of `edge/` ends with `p/`, `p0` and `p`:
    // `edge/p0` is already on the page, so no extra probe or flat scan runs.
    let store = R2Order(Memory::new(
        (0..997)
            .map(|i| format!("edge/f{i:03}"))
            .chain(["edge/p/x", "edge/p0", "edge/p", "edge/z"].map(String::from)),
    ));
    let pattern = Pattern::parse("s3://bucket/edge/*").unwrap();
    for concurrency in [1, 8] {
        let mut keys = Vec::new();
        engine::enumerate(&store, &pattern, concurrency, |entry| {
            keys.push(entry.key);
            Ok(())
        })
        .await
        .unwrap();
        keys.sort();
        let expected: Vec<_> = store
            .0
            .keys
            .iter()
            .filter(|key| pattern.matches(key))
            .cloned()
            .collect();
        assert_eq!(keys, expected);
        assert_eq!(
            store.0.calls.borrow_mut().split_off(0),
            [("edge/".to_owned(), true), ("edge/".to_owned(), true)]
        );
    }

    // Here `edge/p/` ends page 1, `edge/p0000..edge/p0999` fill page 2, and
    // `edge/p0` appears on page 3. `Gap` stops probing `edge/p0` after one
    // non-empty page (never scanning all dense `p0*` siblings) while page 3
    // still yields `edge/p0` cleanly.
    let store = R2Order(Memory::new(
        (0..999)
            .map(|i| format!("edge/f{i:03}"))
            .chain(["edge/p/x".to_owned()])
            .chain((0..1000).map(|i| format!("edge/p0{i:03}")))
            .chain(["edge/p0".to_owned()]),
    ));
    let mut keys = Vec::new();
    engine::enumerate(&store, &pattern, 1, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    let unique: BTreeSet<_> = keys.iter().cloned().collect();
    let expected: BTreeSet<_> = store
        .0
        .keys
        .iter()
        .filter(|key| pattern.matches(key))
        .cloned()
        .collect();
    assert_eq!(keys.len(), expected.len());
    assert_eq!(unique, expected);
    {
        let calls = store.0.calls.borrow();
        assert!(calls.iter().all(|(_, delimiter)| *delimiter), "{calls:?}");
        assert_eq!(
            calls.iter().filter(|(p, _)| p == "edge/p0").count(),
            1,
            "{calls:?}"
        );
    }

    // When `Gap` injects `P0` across an empty continuation page and a later page
    // returns `P0` again, `injected` deduplicates the later copy.
    struct Scripted(RefCell<Vec<(String, bool)>>);
    impl Store for Scripted {
        fn ordered(&self) -> bool {
            false
        }
        fn slash_only(&self) -> bool {
            false
        }
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            _: Option<&str>,
        ) -> Result<Page> {
            self.0.borrow_mut().push((prefix.into(), delimiter));
            let entry = |key: &str| Entry {
                key: key.to_owned(),
                size: 1,
                last_modified: None,
                etag: None,
            };
            if prefix == "edge/p0" {
                return Ok(Page {
                    entries: vec![entry("edge/p0")],
                    complete: true,
                    ..Page::default()
                });
            }
            Ok(match token {
                None => Page {
                    prefixes: vec!["edge/p/".into()],
                    next: Some("t1".into()),
                    ..Page::default()
                },
                Some("t1") => Page {
                    next: Some("t2".into()),
                    ..Page::default()
                },
                Some("t2") => Page {
                    entries: vec![entry("edge/a")],
                    next: Some("t3".into()),
                    ..Page::default()
                },
                Some("t3") => Page {
                    entries: vec![entry("edge/p0"), entry("edge/z")],
                    complete: true,
                    ..Page::default()
                },
                Some(other) => panic!("unexpected token {other}"),
            })
        }
    }
    let scripted = Scripted(RefCell::default());
    let mut keys = Vec::new();
    engine::enumerate(&scripted, &pattern, 1, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    keys.sort();
    assert_eq!(keys, ["edge/a", "edge/p0", "edge/z"]);
    assert_eq!(
        scripted
            .0
            .borrow()
            .iter()
            .filter(|(p, _)| p == "edge/p0")
            .count(),
        1
    );
}

#[tokio::test]
async fn a_delimiter_listing_in_another_order_checks_no_key() {
    /// Refuses listings without a delimiter, as a policy can.
    struct FlatRefused(R2Order);
    impl Store for FlatRefused {
        async fn page(
            &self,
            prefix: &str,
            delimiter: bool,
            token: Option<&str>,
            start_after: Option<&str>,
        ) -> Result<Page> {
            if !delimiter {
                return Err(anyhow::Error::msg("AccessDenied").context(
                    crate::s3::client::RequestFailure::refused_for_test("S3 listing"),
                ));
            }
            self.0.page(prefix, delimiter, token, start_after).await
        }
    }
    // In R2's order the second page ends with `p/`, `p0` and `p`: it holds
    // the key that could be missing, and nothing is checked after it.
    let store = FlatRefused(R2Order(Memory::new(
        (0..1000)
            .map(|i| format!("edge/a{i:04}"))
            .chain((0..997).map(|i| format!("edge/f{i:03}")))
            .chain(["edge/p/x", "edge/p0", "edge/p", "edge/z"].map(String::from)),
    )));
    let pattern = Pattern::parse("s3://bucket/edge/*").unwrap();
    let mut keys = Vec::new();
    engine::enumerate(&store, &pattern, 1, |entry| {
        keys.push(entry.key);
        Ok(())
    })
    .await
    .unwrap();
    let unique: BTreeSet<_> = keys.iter().collect();
    assert_eq!((keys.len(), unique.len()), (2000, 2000));
    assert!(store
        .0
         .0
        .calls
        .borrow()
        .iter()
        .all(|(prefix, _)| prefix == "edge/"));
}

/// Serves ListObjectsV2 for a set of keys in byte order, recording the prefix
/// and delimiter of each request.
#[derive(Clone, Debug)]
struct Served {
    keys: std::sync::Arc<BTreeSet<String>>,
    /// The IsTruncated and NextContinuationToken elements of every response,
    /// in place of those that describe the listing.
    ending: Option<&'static str>,
    requests: std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>,
}

impl Served {
    fn new(keys: impl IntoIterator<Item = String>, ending: Option<&'static str>) -> Self {
        Self {
            keys: std::sync::Arc::new(keys.into_iter().collect()),
            ending,
            requests: Default::default(),
        }
    }

    fn client(&self) -> aws_sdk_s3::Client {
        use aws_smithy_runtime_api::client::http::{http_client_fn, SharedHttpConnector};
        let connector = self.clone();
        aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "fixture",
                ))
                .endpoint_url("http://127.0.0.1:9")
                .force_path_style(true)
                .disable_s3_express_session_auth(true)
                .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
                .http_client(http_client_fn(move |_, _| {
                    SharedHttpConnector::new(connector.clone())
                }))
                .build(),
        )
    }
}

impl aws_smithy_runtime_api::client::http::HttpConnector for Served {
    fn call(
        &self,
        request: aws_smithy_runtime_api::client::orchestrator::HttpRequest,
    ) -> aws_smithy_runtime_api::client::http::HttpConnectorFuture {
        let url = url::Url::parse(request.uri()).unwrap();
        let query: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        let prefix = query.get("prefix").cloned().unwrap_or_default();
        let delimiter = query.contains_key("delimiter");
        let start: usize = query
            .get("continuation-token")
            .map_or(0, |token| token.parse().unwrap());
        let most: usize = query["max-keys"].parse().unwrap();
        self.requests
            .lock()
            .unwrap()
            .push((prefix.clone(), delimiter));
        let items: BTreeSet<(String, bool)> = self
            .keys
            .range(prefix.clone()..)
            .take_while(|key| key.starts_with(&prefix))
            .map(
                |key| match delimiter.then(|| key[prefix.len()..].find('/')).flatten() {
                    Some(slash) => (key[..prefix.len() + slash + 1].to_owned(), true),
                    None => (key.clone(), false),
                },
            )
            .collect();
        let mut body = String::from("<ListBucketResult>");
        body.push_str(&match self.ending {
            Some(ending) => ending.to_owned(),
            None if items.len() > start + most => format!(
                "<IsTruncated>true</IsTruncated><NextContinuationToken>{}</NextContinuationToken>",
                start + most
            ),
            None => "<IsTruncated>false</IsTruncated>".to_owned(),
        });
        for (item, directory) in items.iter().skip(start).take(most) {
            body.push_str(&if *directory {
                format!("<CommonPrefixes><Prefix>{item}</Prefix></CommonPrefixes>")
            } else {
                format!("<Contents><Key>{item}</Key><Size>1</Size></Contents>")
            });
        }
        body.push_str("</ListBucketResult>");
        aws_smithy_runtime_api::client::http::HttpConnectorFuture::ready(Ok(
            aws_smithy_runtime_api::client::orchestrator::HttpResponse::new(
                200.try_into().unwrap(),
                aws_smithy_types::body::SdkBody::from(body),
            ),
        ))
    }
}

#[tokio::test]
async fn only_a_response_that_says_it_is_not_truncated_completes_a_listing() {
    for (ending, next, complete) in [
        (None, None, true),
        (Some("<IsTruncated>false</IsTruncated>"), None, true),
        // IsTruncated left out.
        (Some(""), None, false),
        (
            Some(
                "<IsTruncated>false</IsTruncated><NextContinuationToken>1</NextContinuationToken>",
            ),
            None,
            false,
        ),
        (
            Some("<IsTruncated>true</IsTruncated><NextContinuationToken>1</NextContinuationToken>"),
            Some("1"),
            false,
        ),
    ] {
        let served = Served::new(["p/a".to_owned(), "p/b/c".to_owned()], ending);
        let store = S3 {
            client: served.client(),
            bucket: "bucket",
            divides: false,
        };
        for delimiter in [false, true] {
            let page = store.page("p/", delimiter, None, None).await.unwrap();
            assert_eq!(page.next.as_deref(), next, "{ending:?}");
            assert_eq!(page.complete, complete, "{ending:?}");
        }
    }
}

#[tokio::test]
async fn directory_buckets_and_their_access_points_list_only_prefixes_that_end_in_a_slash() {
    assert!(!lists_in_key_order("dir--usw2-az1--x-s3"));
    assert!(lists_in_key_order("point--usw2-az1--xa-s3"));
    for bucket in ["dir--usw2-az1--x-s3", "point--usw2-az1--xa-s3"] {
        // Ten directories are listed each by itself; forty would be grouped
        // in a store that takes any prefix.
        for (directories, per_directory) in [(10, 1000), (40, 200)] {
            let keys: Vec<String> = (0..directories)
                .flat_map(|d| (0..per_directory).map(move |k| format!("t/d{d}/k{k:04}")))
                .collect();
            let served = Served::new(keys.iter().cloned(), None);
            let store = S3 {
                client: served.client(),
                bucket,
                divides: lists_in_byte_order(None, bucket),
            };
            assert!(store.slash_only() && !store.divides(), "{bucket}");
            let mut listed = Vec::new();
            engine::enumerate_prefix(&store, "t/", 32, None, |entry| {
                listed.push(entry.key);
                Ok(())
            })
            .await
            .unwrap();
            listed.sort();
            let mut expected = keys.clone();
            expected.sort();
            let case = format!("{bucket} {directories} x {per_directory}");
            assert_eq!(listed, expected, "{case}");
            let requests = served.requests.lock().unwrap();
            assert!(
                requests.iter().all(|(prefix, _)| prefix.ends_with('/')),
                "{case}: {requests:?}"
            );
            if directories == 10 {
                assert!(
                    (0..10).all(|d| requests.contains(&(format!("t/d{d}/"), false))),
                    "{case}: {requests:?}"
                );
            }
        }
    }
}
