use super::*;
use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
};

/// Keys in byte order, served a few to a page.
struct Memory {
    keys: BTreeSet<String>,
    page: usize,
    ordered: bool,
    divides: bool,
    /// Make Tigris's mistake: after a page that ends with the common prefix
    /// `P/`, start the next page past the key `P0`.
    skips: bool,
    /// Show the last common prefix of a page again on the next.
    repeats: bool,
    /// Refuse listings without a delimiter, as a policy may.
    refuses_flat: bool,
    /// Keys ending with '/' that have contents.
    filled: BTreeSet<String>,
    calls: RefCell<Vec<(String, bool)>>,
}

impl Memory {
    fn new(keys: &[&str]) -> Self {
        Self {
            keys: keys.iter().map(|key| (*key).to_owned()).collect(),
            page: 1000,
            ordered: true,
            divides: true,
            skips: false,
            repeats: false,
            refuses_flat: false,
            filled: BTreeSet::new(),
            calls: RefCell::default(),
        }
    }
}

impl Store for Memory {
    fn ordered(&self) -> bool {
        self.ordered
    }

    fn divides(&self) -> bool {
        self.divides
    }

    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        _: Option<&str>,
    ) -> Result<Page> {
        self.calls.borrow_mut().push((prefix.into(), delimiter));
        anyhow::ensure!(
            self.ordered || prefix.is_empty() || prefix.ends_with('/'),
            "directory bucket requires trailing slash on {prefix:?}"
        );
        if self.refuses_flat && !delimiter {
            return Err(anyhow::Error::msg("AccessDenied").context(
                crate::s3::client::RequestFailure::refused_for_test("S3 listing"),
            ));
        }
        let mut items: Vec<(String, bool)> = Vec::new();
        for key in self.keys.iter().filter(|key| key.starts_with(prefix)) {
            match delimiter.then(|| key[prefix.len()..].find('/')).flatten() {
                Some(slash) => {
                    let child = key[..prefix.len() + slash + 1].to_owned();
                    if items.last() != Some(&(child.clone(), true)) {
                        items.push((child, true));
                    }
                }
                None => items.push((key.clone(), false)),
            }
        }
        let start: usize = token.map_or(0, |token| token.parse().unwrap());
        let end = items.len().min(start + self.page);
        let mut next = end;
        if let Some((last, true)) = items.get(end.wrapping_sub(1)).filter(|_| end > start) {
            let skipped = format!("{}0", last.trim_end_matches('/'));
            if self.skips && items.get(end).is_some_and(|(item, _)| *item == skipped) {
                next += 1;
            }
            if self.repeats && end < items.len() {
                next -= 1;
            }
        }
        let mut page = Page {
            next: (next < items.len()).then(|| next.to_string()),
            ..Page::default()
        };
        page.complete = page.next.is_none();
        for (item, directory) in &items[start..end] {
            if *directory {
                page.prefixes.push(item.clone());
            } else {
                page.entries.push(Entry {
                    size: u64::from(!item.ends_with('/') || self.filled.contains(item)),
                    key: item.clone(),
                    last_modified: None,
                    etag: None,
                });
            }
        }
        Ok(page)
    }
}

async fn walked(
    store: &Memory,
    root: &str,
    depth: u32,
    descend: &(dyn Fn(&str) -> bool + Sync),
) -> Result<Vec<String>> {
    let mut found = Vec::new();
    walk(store, root, depth, 4, descend, |item| {
        found.push(match item {
            Found::Object(entry) => entry.key,
            Found::Directory(prefix) => format!("{prefix} (dir)"),
        });
        Ok(())
    })
    .await?;
    found.sort();
    Ok(found)
}

const TREE: &[&str] = &[
    "top", "a/", "a/x", "a/b/", "a/b/c", "a/b/d/e", "empty/", "full/", "z/y",
];

#[tokio::test]
async fn each_directory_shows_once_to_the_depth() {
    let store = Memory::new(TREE);
    let all = |_: &str| true;
    assert_eq!(
        walked(&store, "", 1, &all).await.unwrap(),
        ["a/ (dir)", "empty/ (dir)", "full/ (dir)", "top", "z/ (dir)"]
    );
    // Only directories shallower than the depth are listed.
    assert_eq!(store.calls.borrow().as_slice(), [(String::new(), true)]);
    assert_eq!(
        walked(&store, "", 2, &all).await.unwrap(),
        [
            "a/ (dir)",
            "a/b/ (dir)",
            "a/x",
            "empty/ (dir)",
            "full/ (dir)",
            "top",
            "z/ (dir)",
            "z/y"
        ]
    );
    assert_eq!(
        walked(&store, "a/", 9, &all).await.unwrap(),
        ["a/b/ (dir)", "a/b/c", "a/b/d/ (dir)", "a/b/d/e", "a/x"]
    );
}

#[tokio::test]
async fn an_object_with_contents_named_like_a_directory_is_an_object() {
    let all = |_: &str| true;
    for divides in [true, false] {
        let mut store = Memory::new(&["d/x", "e/", "e/y", "f0", "f1", "f2", "f3"]);
        store.filled.insert("e/".into());
        store.page = 2;
        store.divides = divides;
        assert_eq!(
            walked(&store, "", 2, &all).await.unwrap(),
            ["d/ (dir)", "d/x", "e/", "e/ (dir)", "e/y", "f0", "f1", "f2", "f3"]
        );
    }
}

#[tokio::test]
async fn directories_a_condition_excludes_are_not_listed() {
    let store = Memory::new(TREE);
    let descend = |prefix: &str| prefix != "a/b/";
    assert_eq!(
        walked(&store, "", 9, &descend).await.unwrap(),
        [
            "a/ (dir)",
            "a/b/ (dir)",
            "a/x",
            "empty/ (dir)",
            "full/ (dir)",
            "top",
            "z/ (dir)",
            "z/y"
        ]
    );
    assert!(!store
        .calls
        .borrow()
        .iter()
        .any(|(prefix, _)| prefix == "a/b/"));
}

fn wide() -> Vec<String> {
    // More children than a page holds. The first page of `w/` ends with the
    // prefix `w/P/`, and the key `w/P0` follows it.
    let mut keys: Vec<String> = (0..3)
        .map(|i| format!("w/A{i}"))
        .chain((0..7).map(|i| format!("w/k{i}")))
        .collect();
    keys.extend(["w/P/a", "w/P0", "w/P1/b", "w/Q/c", "w/Q0/d"].map(String::from));
    keys
}

fn paged(keys: &[String]) -> Memory {
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let mut store = Memory::new(&keys);
    store.page = 4;
    store
}

#[tokio::test]
async fn pages_in_byte_order_recover_a_key_skipped_after_a_common_prefix() {
    let all = |_: &str| true;
    let expected = {
        let store = paged(&wide());
        walked(&store, "", 3, &all).await.unwrap()
    };
    assert!(expected.contains(&"w/P0".to_owned()));
    for (skips, repeats) in [(true, false), (false, true), (true, true)] {
        let mut store = paged(&wide());
        store.skips = skips;
        store.repeats = repeats;
        assert_eq!(walked(&store, "", 3, &all).await.unwrap(), expected);
        // The skipped key is looked for by itself. A repeated prefix
        // starts the next page before the key, which then shows.
        assert_eq!(
            store.calls.borrow().contains(&("w/P0".into(), true)),
            skips && !repeats
        );
    }
}

#[tokio::test]
async fn where_the_order_is_unknown_a_wide_directory_still_paginates_with_a_delimiter() {
    let all = |_: &str| true;
    let expected = walked(&paged(&wide()), "", 3, &all).await.unwrap();
    for depth in [1, 2, 3] {
        let mut store = paged(&wide());
        store.divides = false;
        store.skips = true;
        store.refuses_flat = true;
        let found = walked(&store, "", depth, &all).await.unwrap();
        let wanted: Vec<_> = expected
            .iter()
            .filter(|item| {
                let key = item.trim_end_matches(" (dir)").trim_end_matches('/');
                key.matches('/').count() < depth as usize
            })
            .cloned()
            .collect();
        assert_eq!(found, wanted, "depth {depth}");
        let calls = store.calls.borrow();
        assert!(calls.iter().all(|(_, delimiter)| *delimiter), "{calls:?}");
        assert_eq!(calls.contains(&("w/P0".into(), true)), depth > 1);
    }
    // Directory buckets (slash_only) stay delimited without checking non-slash prefixes.
    for depth in [1, 2, 3] {
        let mut store = paged(&wide());
        store.ordered = false;
        store.divides = false;
        store.refuses_flat = true;
        let found = walked(&store, "", depth, &all).await.unwrap();
        let wanted: Vec<_> = expected
            .iter()
            .filter(|item| {
                let key = item.trim_end_matches(" (dir)").trim_end_matches('/');
                key.matches('/').count() < depth as usize
            })
            .cloned()
            .collect();
        assert_eq!(found, wanted, "slash_only depth {depth}");
        let calls = store.calls.borrow();
        assert!(
            calls
                .iter()
                .all(|(prefix, delimiter)| *delimiter
                    && (prefix.is_empty() || prefix.ends_with('/'))),
            "{calls:?}"
        );
    }
}

#[tokio::test]
async fn exact_keys_are_found_with_listings() {
    let keys: Vec<String> = ["k", "k.bak", "k/x", "kk/", "m-x", "m0"]
        .into_iter()
        .map(String::from)
        .chain((0..9).map(|i| format!("m-{i}")))
        .collect();
    for divides in [true, false] {
        let mut store = paged(&keys);
        store.divides = divides;
        let (object, under) = exact(&store, "k").await.unwrap();
        assert_eq!(object.unwrap().key, "k");
        assert!(under);
        let (object, under) = exact(&store, "kk").await.unwrap();
        assert!(object.is_none());
        assert!(under || divides, "{divides}");
        let (object, under) = exact(&store, "m").await.unwrap();
        assert!(object.is_none());
        assert!(!under);
        let (object, _) = exact(&store, "m0").await.unwrap();
        assert!(object.is_some());
    }
    let unique: HashSet<_> = keys.iter().collect();
    assert_eq!(unique.len(), keys.len());
}
