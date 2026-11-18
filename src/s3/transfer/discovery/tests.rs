use super::super::super::listing::engine::Entry;
use super::*;
use std::{cell::RefCell, collections::BTreeMap, ops::Bound};

/// A bucket in key order. A continuation token names the last key returned.
struct Bucket {
    objects: BTreeMap<String, u64>,
    ordered: bool,
    honors_start: bool,
    /// The request, counted from one, whose page comes back out of order.
    disordered: Option<usize>,
    /// Each request's lower bound, and whether it continued the last one.
    requests: RefCell<Vec<(String, bool)>>,
}
impl Bucket {
    fn new(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            objects: keys.into_iter().zip(1..).collect(),
            ordered: true,
            honors_start: true,
            disordered: None,
            requests: RefCell::default(),
        }
    }
}
impl Store for Bucket {
    fn ordered(&self) -> bool {
        self.ordered
    }
    async fn page(
        &self,
        prefix: &str,
        delimiter: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        assert!(!delimiter);
        assert!(token.is_none() || start_after.is_none());
        let after = token.or(start_after.filter(|_| self.honors_start));
        self.requests
            .borrow_mut()
            .push((after.unwrap_or("").to_owned(), token.is_some()));
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut matching = self
            .objects
            .range::<str, _>((lower, Bound::Unbounded))
            .filter(|(key, _)| key.starts_with(prefix));
        let mut entries: Vec<_> = matching
            .by_ref()
            .take(1000)
            .map(|(key, size)| Entry {
                key: key.clone(),
                size: *size,
                last_modified: None,
                etag: None,
            })
            .collect();
        let next = matching.next().map(|_| entries.last().unwrap().key.clone());
        if self.disordered == Some(self.requests.borrow().len()) {
            entries.swap(10, 20);
        }
        Ok(Page {
            next,
            entries,
            prefixes: Vec::new(),
        })
    }
}

/// Run the listing to its end, as `Discovery::start` and its task do, and
/// return what it decided about each planned key.
async fn discover(bucket: &Bucket, prefix: &str, plan: &[String]) -> Vec<Listed> {
    let mut walk = Walk {
        prefix: prefix.to_owned(),
        keys: Keys::new(plan.iter().map(|key| key.as_str().into())),
        sizes: (0..plan.len()).map(|_| AtomicU64::new(UNKNOWN)).collect(),
        decided: 0,
        shortfall: 0,
        passed: String::new(),
        token: None,
    };
    if bucket.ordered {
        while walk.page(bucket).await.unwrap() {}
    } else {
        walk.whole(bucket).await.unwrap();
    }
    (0..plan.len())
        .map(|index| match walk.sizes[index].load(Relaxed) {
            _ if index >= walk.decided => Listed::Unknown,
            UNKNOWN => Listed::Unknown,
            ABSENT => Listed::Absent,
            size => Listed::Present(size),
        })
        .collect()
}

/// Every decision must be what a HEAD would have found.
fn assert_true(bucket: &Bucket, plan: &[String], listed: &[Listed]) {
    for (key, listed) in plan.iter().zip(listed) {
        match listed {
            Listed::Unknown => {}
            Listed::Absent => assert!(!bucket.objects.contains_key(key), "{key} exists"),
            Listed::Present(size) => assert_eq!(bucket.objects.get(key), Some(size), "{key}"),
        }
    }
}

fn large() -> Vec<String> {
    (0..300)
        .flat_map(|d| (0..100).map(move |f| format!("big/d{d:03}/f{f:03}")))
        .collect()
}

#[tokio::test]
async fn new_directory_in_a_large_prefix_takes_one_request() {
    let bucket = Bucket::new(large());
    let plan: Vec<_> = (0..500).map(|f| format!("big/m-new/f{f:03}")).collect();
    let listed = discover(&bucket, "big/", &plan).await;
    assert!(listed.iter().all(|listed| *listed == Listed::Absent));
    // Every existing key sorts before the new directory.
    assert_eq!(
        *bucket.requests.borrow(),
        [("big/m-new/f00/".to_owned(), false)]
    );
}

#[tokio::test]
async fn similar_destination_is_paged_once_in_order() {
    let existing: Vec<_> = (0..2500).map(|f| format!("data/f{f:04}")).collect();
    let bucket = Bucket::new(existing.iter().cloned().chain(["data/zz".to_owned()]));
    let mut plan = existing.clone();
    plan.extend((0..200).map(|f| format!("data/new{f:03}")));
    plan.sort();
    let listed = discover(&bucket, "data/", &plan).await;
    assert_true(&bucket, &plan, &listed);
    assert!(listed.iter().all(|listed| *listed != Listed::Unknown));
    assert_eq!(listed.iter().filter(|l| **l == Listed::Absent).count(), 200);
    // Three pages hold the destination; the last planned key ends the listing
    // before the page that would show there is nothing more.
    let requests = bucket.requests.borrow();
    assert_eq!(requests.len(), 3);
    assert!(requests[1..].iter().all(|(_, continued)| *continued));
}

#[tokio::test]
async fn sparse_plan_stops_listing_and_leaves_the_rest_unknown() {
    let bucket = Bucket::new(large());
    // One planned key in each directory of 100: about ten to a page.
    let plan: Vec<_> = (0..300).map(|d| format!("big/d{d:03}/f050")).collect();
    let listed = discover(&bucket, "big/", &plan).await;
    assert_true(&bucket, &plan, &listed);
    assert_eq!(bucket.requests.borrow().len(), SLACK_PAGES + 1);
    let decided = listed.iter().filter(|l| **l != Listed::Unknown).count();
    assert!((20..40).contains(&decided), "{decided}");
    assert!(listed[decided..].iter().all(|l| *l == Listed::Unknown));
}

#[tokio::test]
async fn few_keys_never_cost_more_pages_than_they_could_save() {
    let bucket = Bucket::new(large());
    let plan = ["big/d000/new".to_owned(), "big/d200/new".to_owned()];
    let listed = discover(&bucket, "big/", &plan).await;
    assert_eq!(listed, [Listed::Absent, Listed::Unknown]);
    assert_eq!(bucket.requests.borrow().len(), 1);
}

#[tokio::test]
async fn destination_keys_between_planned_directories_are_skipped() {
    let bucket = Bucket::new(
        large()
            .into_iter()
            .chain(["big/a/f001".to_owned(), "big/z/f199".to_owned()]),
    );
    let plan: Vec<_> = ["a", "z"]
        .iter()
        .flat_map(|d| (0..200).map(move |f| format!("big/{d}/f{f:03}")))
        .collect();
    let listed = discover(&bucket, "big/", &plan).await;
    assert_true(&bucket, &plan, &listed);
    assert_eq!(listed.iter().filter(|l| **l == Listed::Absent).count(), 398);
    // The first page decides the first directory and pays its way, so the
    // listing continues. The second decides nothing, so the third starts at
    // the next planned key rather than paging through the 30,000 keys between.
    assert_eq!(
        *bucket.requests.borrow(),
        [
            ("big/a/f00/".to_owned(), false),
            ("big/d009/f098".to_owned(), true),
            ("big/z/f00/".to_owned(), false)
        ]
    );
}

#[tokio::test]
async fn key_outside_the_listed_prefix_stays_unknown() {
    let bucket = Bucket::new(["data".to_owned(), "data/a".to_owned()]);
    let plan = ["data".to_owned(), "data/a".to_owned(), "data/b".to_owned()];
    assert_eq!(
        discover(&bucket, "data/", &plan).await,
        [Listed::Unknown, Listed::Present(2), Listed::Absent]
    );
}

#[tokio::test]
async fn listing_that_ignores_the_start_decides_nothing() {
    let mut bucket = Bucket::new(large());
    bucket.honors_start = false;
    let plan: Vec<_> = (0..500).map(|f| format!("big/m-new/f{f:03}")).collect();
    let listed = discover(&bucket, "big/", &plan).await;
    assert!(listed.iter().all(|listed| *listed == Listed::Unknown));
    assert_eq!(bucket.requests.borrow().len(), 1);
}

#[tokio::test]
async fn page_out_of_order_withdraws_every_decision() {
    let existing: Vec<_> = (0..5000).map(|f| format!("data/f{f:04}")).collect();
    let mut bucket = Bucket::new(existing.clone());
    bucket.disordered = Some(3);
    let listed = discover(&bucket, "data/", &existing).await;
    // Two pages decided 2,000 keys before the third showed that this
    // listing's order cannot be relied on.
    assert!(listed.iter().all(|listed| *listed == Listed::Unknown));
    assert_eq!(bucket.requests.borrow().len(), 3);
}

#[tokio::test]
async fn listing_never_starts_at_a_key_too_long_for_s3() {
    let bucket = Bucket::new(["data/b".to_owned(), "data/c".to_owned()]);
    let long = format!("data/a{}", "a".repeat(MAX_KEY));
    let plan = [long, "data/b".to_owned(), "data/d".to_owned()];
    assert_eq!(
        discover(&bucket, "data/", &plan).await,
        [Listed::Unknown, Listed::Present(1), Listed::Absent]
    );
    assert_eq!(*bucket.requests.borrow(), [("data/a".to_owned(), false)]);

    // Nothing is requested for a plan of such keys alone.
    let bucket = Bucket::new(["data/b".to_owned()]);
    let plan = [format!("data/a{}", "a".repeat(MAX_KEY))];
    assert_eq!(discover(&bucket, "data/", &plan).await, [Listed::Unknown]);
    assert!(bucket.requests.borrow().is_empty());
}

#[tokio::test]
async fn directory_bucket_needs_the_whole_listing() {
    let existing: Vec<_> = (0..1500).map(|f| format!("data/f{f:04}")).collect();
    let mut bucket = Bucket::new(existing.clone());
    bucket.ordered = false;
    let mut plan = vec!["data/f0000".to_owned(), "data/f1400".to_owned()];
    plan.extend((0..3).map(|f| format!("data/new{f}")));
    let listed = discover(&bucket, "data/", &plan).await;
    assert_eq!(
        listed,
        [
            Listed::Present(1),
            Listed::Present(1401),
            Listed::Absent,
            Listed::Absent,
            Listed::Absent
        ]
    );
    assert_eq!(bucket.requests.borrow().len(), 2);

    // Two keys allow one page, which cannot show that the second is absent.
    bucket.requests.borrow_mut().clear();
    let plan = ["data/f0000".to_owned(), "data/new".to_owned()];
    assert_eq!(
        discover(&bucket, "data/", &plan).await,
        [Listed::Present(1), Listed::Unknown]
    );
    assert_eq!(bucket.requests.borrow().len(), 1);
}

#[tokio::test]
async fn decisions_match_the_bucket_for_varied_plans() {
    // A fixed pseudo-random sequence: reproducible without a dependency.
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut random = move |below: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % below
    };
    for round in 0..40 {
        let directories = 1 + random(40);
        let name = |random: &mut dyn FnMut(u64) -> u64| {
            format!(
                "p/d{:02}{}f{:04}",
                random(directories),
                ["/", ".", "-", "/s/"][random(4) as usize],
                random(6000)
            )
        };
        let existing: Vec<_> = (0..random(9000)).map(|_| name(&mut random)).collect();
        let mut plan: Vec<_> = (0..1 + random(3000)).map(|_| name(&mut random)).collect();
        plan.extend(existing.iter().take(random(2000) as usize).cloned());
        plan.sort();
        plan.dedup();
        let bucket = Bucket::new(existing);
        let listed = discover(&bucket, "p/", &plan).await;
        assert_true(&bucket, &plan, &listed);
        let pages = bucket.requests.borrow().len();
        let decided = listed.iter().filter(|l| **l != Listed::Unknown).count();
        assert!(
            pages <= 1 + SLACK_PAGES + decided / KEYS_PER_PAGE,
            "round {round}: {pages} pages decided {decided} keys"
        );
    }
}

#[test]
fn absence_is_trusted_only_where_a_wrong_answer_costs_no_more_than_an_upload() {
    for (flags, trusted) in [
        (&[][..], true),
        (&["--if-exists=update"][..], true),
        (&["--where", "src.size > 0B"][..], true),
        // The write carries `If-None-Match: *`; a dry run sends none.
        (&["--if-exists=error"][..], true),
        (&["--if-exists=error", "--dry-run"][..], false),
        (&["--dry-run"][..], true),
        (&["--if-exists=error-if-different"][..], false),
        (&["--if-exists=update-if-older"][..], false),
        (&["--if-exists=keep"][..], false),
        (&["--only-existing"][..], false),
        (&["--copy-if", "not dst.exists"][..], false),
        (&["--copy-if", "src.size > 0B"][..], false),
    ] {
        for route in [
            &["cp", "tree", "--to", "s3://bucket", "--into", "data"][..],
            &[
                "cp",
                "--from",
                "s3://source",
                "tree",
                "--to",
                "s3://bucket",
                "--into",
                "data",
            ][..],
        ] {
            let argv: Vec<_> = route
                .iter()
                .chain(flags)
                .map(std::ffi::OsString::from)
                .collect();
            let args = Args::parse_args(&argv).unwrap();
            assert_eq!(trusts_absence(&args), trusted, "{route:?} {flags:?}");
            assert_eq!(lists_destination(&args, "bucket"), trusted);
            // A directory bucket's listing decides nothing from order.
            assert!(lists_destination(&args, "bucket--usw2-az1--x-s3"));
        }
    }
}

#[test]
fn predecessor_sorts_just_below_its_key() {
    for (key, below) in [
        ("data/file", "data/fild"),
        ("data/", "data."),
        ("data/a b", "data/a a"),
        // No character below a space, or below the first one, is used.
        ("data/ ", "data/"),
        ("data/\u{0}", "data/"),
        ("data/\u{e000}", "data/"),
        ("é", "è"),
    ] {
        assert_eq!(predecessor(key), below);
        assert!(below < key);
    }
}

#[test]
fn keys_are_found_by_position_and_by_name() {
    let keys = Keys::new(["a", "b/", "b/c"].into_iter().map(Cow::Borrowed));
    assert_eq!(keys.len(), 3);
    assert_eq!((keys.get(0), keys.get(1), keys.get(2)), ("a", "b/", "b/c"));
    assert_eq!(keys.find("b/c"), Some(2));
    assert_eq!(keys.find("b"), None);
}
