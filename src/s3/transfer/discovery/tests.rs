use super::super::super::listing::engine::Entry;
use super::super::DestinationListing;
use super::*;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    ops::Bound,
};

/// A bucket in key order. A continuation token names the last key returned.
struct Bucket {
    objects: BTreeMap<String, u64>,
    ordered: bool,
    /// Whether the listing may rely on byte order (`Store::divides`).
    divides: bool,
    honors_start: bool,
    /// The request, counted from one, whose page comes back out of order.
    disordered: Option<usize>,
    /// A key that every page of an unordered listing repeats first.
    repeated: Option<String>,
    /// Each request's lower bound, and whether it continued the last one.
    requests: RefCell<Vec<(String, bool)>>,
    /// Each request's prefix.
    prefixes: RefCell<Vec<String>>,
    /// Each request without a continuation token: its prefix and start.
    starts: RefCell<Vec<(String, Option<String>)>>,
}
impl Bucket {
    fn new(keys: impl IntoIterator<Item = String>) -> Self {
        Self {
            objects: keys.into_iter().zip(1..).collect(),
            ordered: true,
            divides: true,
            honors_start: true,
            disordered: None,
            repeated: None,
            requests: RefCell::default(),
            prefixes: RefCell::default(),
            starts: RefCell::default(),
        }
    }
}
impl Store for Bucket {
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
        start_after: Option<&str>,
    ) -> Result<Page> {
        assert!(!delimiter);
        assert!(token.is_none() || start_after.is_none());
        self.prefixes.borrow_mut().push(prefix.to_owned());
        if token.is_none() {
            self.starts
                .borrow_mut()
                .push((prefix.to_owned(), start_after.map(str::to_owned)));
        }
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
        if let Some(key) = &self.repeated {
            // In addition to the page's own keys, so that none is left out.
            entries.insert(
                0,
                Entry {
                    key: key.clone(),
                    size: self.objects[key],
                    last_modified: None,
                    etag: None,
                },
            );
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
    let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
    let whole = Segment::whole(prefix.to_owned(), &keys);
    discover_segments(bucket, vec![whole], keys).await
}

/// Like `discover`, listing each of `prefixes` for the planned keys beneath
/// it, as a copy that may list only those does.
async fn discover_under(bucket: &Bucket, prefixes: &[&str], plan: &[String]) -> Vec<Listed> {
    let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
    let prefixes: Vec<String> = prefixes.iter().map(|prefix| (*prefix).to_owned()).collect();
    let segments = segments(&keys, &prefixes);
    discover_segments(bucket, segments, keys).await
}

async fn discover_segments(bucket: &impl Store, segments: Vec<Segment>, keys: Keys) -> Vec<Listed> {
    let len = keys.len();
    let mut walk = Walk::new(segments, Arc::new(keys), Arc::new(Decisions::new(len)));
    let plan = 0..len;
    if walk.segments.is_empty() {
        return plan.map(|_| Listed::Unknown).collect();
    }
    // As `Discovery::start` does, without the copy going on meanwhile.
    if !bucket.ordered() {
        walk.whole(bucket, usize::MAX, 0).await.unwrap();
    } else if !bucket.divides() {
        walk.whole(bucket, PAGES_BEFORE_COPY, BACKGROUND_KEYS)
            .await
            .unwrap();
    } else {
        while walk.page(bucket).await.unwrap() {}
    }
    plan.map(|index| {
        if index >= walk.decided {
            Listed::Unknown
        } else {
            walk.decisions.get(index)
        }
    })
    .collect()
}

fn walk(prefix: &str, plan: &[String]) -> Walk {
    let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
    let whole = Segment::whole(prefix.to_owned(), &keys);
    let decisions = Arc::new(Decisions::new(plan.len()));
    Walk::new(vec![whole], Arc::new(keys), decisions)
}

/// The listing as the copy finds it when preparation starts, as
/// `Discovery::start` leaves it, without the later pages.
async fn at_copy_start(bucket: &Bucket, prefix: &str, plan: &[String]) -> Discovery {
    let mut walk = walk(prefix, plan);
    let more = walk.before_copy(bucket).await.unwrap();
    let (_, reach) = watch::channel(Reach {
        decided: walk.decided,
        finished: !more,
    });
    Discovery {
        listed: vec![(0..plan.len(), 0)],
        decisions: walk.decisions,
        reach: vec![reach],
        waits: true,
        tasks: Vec::new(),
    }
}

fn cp(flags: &[&str]) -> Args {
    let argv: Vec<_> = ["cp", "tree", "--to", "s3://bucket", "--into", "data"]
        .iter()
        .chain(flags)
        .map(std::ffi::OsString::from)
        .collect();
    Args::parse_args(&argv).unwrap()
}

/// The keys whose existence checks an authorized upload signs before
/// preparation. Checks that every key decided by then is decided as
/// preparation will see it.
async fn presigned(
    args: &Args,
    complete: Option<&DestinationListing>,
    discovery: Option<&Discovery>,
    plan: &[String],
) -> Vec<String> {
    for (position, key) in plan.iter().enumerate() {
        if let Some(known) = known(args, complete, discovery, position, key) {
            let listed = listed(args, complete, discovery, position, key).await;
            assert_eq!(known, listed, "{key}");
        }
    }
    super::super::authorization::upload_checks(plan.iter().map(String::as_str), |position, key| {
        known(args, complete, discovery, position, key)
    })
    .map(|check| {
        assert_eq!(check.method, "HEAD");
        check.key
    })
    .collect()
}

#[tokio::test]
async fn new_upload_presigns_no_existence_checks() {
    // A new directory in a large prefix, and new files in an empty one.
    for (bucket, plan) in [
        (
            Bucket::new(large()),
            (0..500).map(|f| format!("big/m-new/f{f:03}")).collect(),
        ),
        (
            Bucket::new([]),
            (0..20).map(|f| format!("big/f{f:02}")).collect::<Vec<_>>(),
        ),
    ] {
        let discovery = at_copy_start(&bucket, "big/", &plan).await;
        for flags in [&[][..], &["--dry-run"], &["--if-exists=error"]] {
            let args = cp(flags);
            assert!(lists_destination(&args, "bucket"));
            assert_eq!(
                presigned(&args, None, Some(&discovery), &plan).await,
                Vec::<String>::new(),
                "{flags:?}"
            );
        }
    }
}

#[tokio::test]
async fn existing_keys_and_untrusted_absences_keep_their_checks() {
    let existing: Vec<_> = (0..300).map(|f| format!("data/f{f:03}")).collect();
    let bucket = Bucket::new(existing.iter().cloned());
    let mut plan = existing.clone();
    plan.extend((0..300).map(|f| format!("data/g{f:03}")));
    plan.push("data/new/".to_owned());
    plan.sort();
    let discovery = at_copy_start(&bucket, "data/", &plan).await;
    assert_eq!(
        presigned(&cp(&[]), None, Some(&discovery), &plan).await,
        existing
    );
    // A directory marker that exists is accepted here, so only a HEAD may
    // say it is absent.
    let mut checked = existing.clone();
    checked.push("data/new/".to_owned());
    checked.sort();
    assert_eq!(
        presigned(&cp(&["--if-exists=error"]), None, Some(&discovery), &plan).await,
        checked
    );
    // Pruning lists the whole destination first.
    let complete = DestinationListing {
        prefixes: vec!["data/".to_owned()],
        keys: existing.iter().map(|key| (key.clone(), 1)).collect(),
    };
    assert_eq!(
        presigned(&cp(&[]), Some(&complete), None, &plan).await,
        existing
    );
}

#[tokio::test]
async fn keys_outside_a_complete_listing_keep_their_checks() {
    // Pruning under signatures for named sources lists only the named
    // directory; the named file beside it exists, and the listing cannot say.
    let plan = ["data/dir/new".to_owned(), "data/file".to_owned()];
    let complete = DestinationListing {
        prefixes: vec!["data/dir/".to_owned()],
        keys: HashMap::new(),
    };
    let args = cp(&["--prune"]);
    assert_eq!(
        listed(&args, Some(&complete), None, 1, "data/file").await,
        Listed::Unknown
    );
    assert_eq!(
        presigned(&args, Some(&complete), None, &plan).await,
        ["data/file"]
    );
}

#[tokio::test]
async fn keys_outside_every_named_prefix_are_decided_at_once() {
    let plan = named_plan();
    let bucket = Bucket::new(["dst/a/1".to_owned(), "dst/a.txt".to_owned()]);
    let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
    let prefixes: Vec<String> = NAMED.map(str::to_owned).into();
    let found = segments(&keys, &prefixes);
    let listed: Vec<_> = found
        .iter()
        .map(|segment| (segment.range.clone(), 0))
        .collect();
    let decisions = Arc::new(Decisions::new(plan.len()));
    let mut walk = Walk::new(found, Arc::new(keys), decisions.clone());
    // Before any page: the walk has not reached the named directories.
    let (sender, reach) = watch::channel(Reach {
        decided: walk.decided,
        finished: false,
    });
    let discovery = Discovery {
        listed,
        decisions,
        reach: vec![reach],
        waits: true,
        tasks: Vec::new(),
    };
    let at = |key: &str| plan.iter().position(|planned| planned == key).unwrap();
    // A named file and a lone key are checked with HEAD, whatever the walk.
    assert_eq!(discovery.known(at("dst/a.txt")), Some(Listed::Unknown));
    assert_eq!(discovery.lookup(at("dst/c/q")).await, Listed::Unknown);
    assert_eq!(discovery.known(at("dst/a/2")), None);
    while walk.page(&bucket).await.unwrap() {}
    sender.send_replace(Reach {
        decided: walk.decided,
        finished: true,
    });
    assert_eq!(discovery.known(at("dst/a/2")), Some(Listed::Absent));
    assert_eq!(discovery.lookup(at("dst/a/1")).await, Listed::Present(1));
}

#[tokio::test]
async fn keys_the_listing_has_not_decided_are_presigned() {
    let existing: Vec<_> = (0..5000).map(|f| format!("data/f{f:04}")).collect();
    let bucket = Bucket::new(existing.iter().cloned());
    let mut plan = existing.clone();
    plan.extend((0..5000).map(|f| format!("data/f{f:04}n")));
    plan.sort();
    let discovery = at_copy_start(&bucket, "data/", &plan).await;
    let decided = discovery.reach[0].borrow().decided;
    assert!((1000..plan.len() / 2).contains(&decided), "{decided}");
    let checked = presigned(&cp(&[]), None, Some(&discovery), &plan).await;
    let expected: Vec<_> = plan
        .iter()
        .enumerate()
        .filter(|(position, key)| *position >= decided || !key.ends_with('n'))
        .map(|(_, key)| key.clone())
        .collect();
    assert_eq!(checked, expected);
    // A listing that ended early leaves the rest to their checks too.
    let (_, reach) = watch::channel(Reach {
        decided,
        finished: true,
    });
    let ended = Discovery {
        listed: discovery.listed.clone(),
        decisions: discovery.decisions.clone(),
        reach: vec![reach],
        waits: true,
        tasks: Vec::new(),
    };
    assert_eq!(
        presigned(&cp(&[]), None, Some(&ended), &plan).await,
        expected
    );
}

#[tokio::test]
async fn copies_that_do_not_list_presign_every_check() {
    let plan: Vec<_> = (0..20).map(|f| format!("data/f{f:02}")).collect();
    let args = cp(&["--if-exists=error", "--dry-run"]);
    assert!(!lists_destination(&args, "bucket"));
    assert_eq!(presigned(&args, None, None, &plan).await, plan);
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
async fn page_out_of_order_withdraws_the_other_listings_decisions() {
    let existing: Vec<_> = (0..5000).map(|f| format!("data/f{f:04}")).collect();
    let mut bucket = Bucket::new(existing.iter().cloned().chain(["more/f1".to_owned()]));
    let mut plan = existing.clone();
    plan.extend((0..20).map(|f| format!("more/f{f}")));
    plan.sort();
    let keys = Arc::new(Keys::new(plan.iter().map(|key| key.as_str().into())));
    let found = segments(&keys, &["data/".to_owned(), "more/".to_owned()]);
    let decisions = Arc::new(Decisions::new(plan.len()));
    let mut walks = found
        .into_iter()
        .map(|segment| Walk::new(vec![segment], keys.clone(), decisions.clone()));
    let (mut data, mut more) = (walks.next().unwrap(), walks.next().unwrap());
    // `more/` is listed in full and `data/` in part before a page of
    // `data/` shows that this listing's order cannot be relied on.
    assert!(!more.page(&bucket).await.unwrap());
    assert!(data.page(&bucket).await.unwrap());
    let decided = |decisions: &Decisions| {
        (0..plan.len())
            .filter(|index| decisions.get(*index) != Listed::Unknown)
            .count()
    };
    assert_eq!(decided(&decisions), 1020);
    bucket.disordered = Some(3);
    assert!(!data.page(&bucket).await.unwrap());
    assert_eq!(decided(&decisions), 0);
    // A listing still running requests nothing more.
    let mut again = Walk::new(
        segments(&keys, &["more/".to_owned()]),
        keys.clone(),
        decisions.clone(),
    );
    let sent = bucket.requests.borrow().len();
    assert!(!again.page(&bucket).await.unwrap());
    assert_eq!(bucket.requests.borrow().len(), sent);
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

    // A key the listing repeats is one key found, not two. The first page
    // holds `f0000` twice and `f0001`: three matches for three planned keys,
    // but the third key is on the next page and must not be called absent.
    bucket.repeated = Some("data/f0000".to_owned());
    bucket.requests.borrow_mut().clear();
    let plan = [
        "data/f0000".to_owned(),
        "data/f0001".to_owned(),
        "data/f1400".to_owned(),
    ];
    assert_eq!(
        discover(&bucket, "data/", &plan).await,
        [
            Listed::Present(1),
            Listed::Present(2),
            Listed::Present(1401)
        ]
    );
    assert_eq!(bucket.requests.borrow().len(), 2);
    bucket.repeated = None;

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
            // An existing directory marker is accepted under the policies
            // that protect contents, so only a HEAD may say one is absent.
            let protecting = flags
                .iter()
                .any(|flag| flag.starts_with("--if-exists=error"));
            assert!(trusts_absence_of(&args, "data/file"));
            assert_eq!(trusts_absence_of(&args, "data/directory/"), !protecting);
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

/// Named sources at the destination `dst/`: directories `a`, `a-b` and `c`
/// and the file `a.txt`. `a.txt` and every `a-b/` key sort between `a` and
/// its contents. `a` and `a-b` hold enough keys to be worth a listing each,
/// and `c` one key.
fn named_plan() -> Vec<String> {
    let mut plan: Vec<String> = [
        "dst/a/",
        "dst/a/1",
        "dst/a/2",
        "dst/a/3",
        "dst/a-b/x",
        "dst/a-b/y",
        "dst/a.txt",
        "dst/c/q",
    ]
    .map(str::to_owned)
    .into();
    plan.extend((0..10).map(|f| format!("dst/a/f{f}")));
    plan.extend((0..10).map(|f| format!("dst/a-b/z{f}")));
    plan.sort();
    plan
}
const NAMED: [&str; 4] = ["dst/a/", "dst/a-b/", "dst/a.txt/", "dst/c/"];

#[test]
fn keys_beneath_each_prefix_form_one_segment() {
    let plan = named_plan();
    let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
    let prefixes: Vec<String> = NAMED.map(str::to_owned).into();
    let found = segments(&keys, &prefixes);
    let at = |key: &str| plan.iter().position(|planned| planned == key).unwrap();
    // `a.txt` has nothing beneath it and `c` one key, which HEAD checks.
    assert_eq!(
        found,
        [
            Segment {
                prefix: "dst/a-b/".into(),
                range: at("dst/a-b/x")..at("dst/a-b/z9") + 1,
            },
            Segment {
                prefix: "dst/a/".into(),
                range: at("dst/a/")..at("dst/a/f9") + 1,
            },
        ]
    );
    // A prefix inside another is listed with it, not again.
    let nested: Vec<String> = ["dst/a/", "dst/a/1/"].map(str::to_owned).into();
    assert_eq!(segments(&keys, &nested).len(), 1);
    // The whole destination is one segment.
    assert_eq!(
        segments(&keys, &["dst/".to_owned()]),
        [Segment::whole("dst/".into(), &keys)]
    );
}

#[tokio::test]
async fn named_prefixes_are_listed_each_for_its_own_keys() {
    let plan = named_plan();
    // Siblings outside every named prefix, also between them in key order.
    let bucket = Bucket::new(
        [
            "dst/a-a",
            "dst/a-b/x",
            "dst/a.txt",
            "dst/a/1",
            "dst/a/3",
            "dst/b",
            "dst/c/q",
        ]
        .map(str::to_owned),
    );
    let listed = discover_under(&bucket, &NAMED, &plan).await;
    assert_true(&bucket, &plan, &listed);
    let by_key: BTreeMap<_, _> = plan.iter().map(String::as_str).zip(listed).collect();
    assert_eq!(by_key["dst/a-b/x"], Listed::Present(2));
    assert_eq!(by_key["dst/a-b/y"], Listed::Absent);
    assert_eq!(by_key["dst/a/"], Listed::Absent);
    assert_eq!(by_key["dst/a/1"], Listed::Present(4));
    assert_eq!(by_key["dst/a/2"], Listed::Absent);
    assert_eq!(by_key["dst/a/3"], Listed::Present(5));
    // Checked with HEAD: a named file, and a lone key.
    assert_eq!(by_key["dst/a.txt"], Listed::Unknown);
    assert_eq!(by_key["dst/c/q"], Listed::Unknown);
    // One request per listed prefix, and none outside them.
    assert_eq!(*bucket.prefixes.borrow(), ["dst/a-b/", "dst/a/"]);
}

#[tokio::test]
async fn unordered_bucket_lists_each_named_prefix_whole() {
    let plan = named_plan();
    let mut bucket = Bucket::new(
        [
            "dst/a-a",
            "dst/a-b/x",
            "dst/a.txt",
            "dst/a/1",
            "dst/a/3",
            "dst/b",
            "dst/c/q",
        ]
        .map(str::to_owned),
    );
    bucket.ordered = false;
    let listed = discover_under(&bucket, &NAMED, &plan).await;
    assert_true(&bucket, &plan, &listed);
    let decided = listed.iter().filter(|listed| **listed != Listed::Unknown);
    let beneath = plan
        .iter()
        .filter(|key| key.starts_with("dst/a/") || key.starts_with("dst/a-b/"));
    assert_eq!(decided.count(), beneath.count());
    assert_eq!(*bucket.prefixes.borrow(), ["dst/a-b/", "dst/a/"]);
}

#[tokio::test]
async fn sparse_named_prefix_stops_only_its_own_listing() {
    // A sparse plan under "big/" stops listing there, as for the whole
    // destination; the next prefix is still listed.
    let bucket = Bucket::new(large().into_iter().chain(["more/f00".to_owned()]));
    let mut plan: Vec<_> = (0..300).map(|d| format!("big/d{d:03}/f050")).collect();
    plan.extend((0..LIST_COST).map(|f| format!("more/f{f:02}")));
    let listed = discover_under(&bucket, &["big/", "more/"], &plan).await;
    assert_true(&bucket, &plan, &listed);
    assert_eq!(bucket.requests.borrow().len(), SLACK_PAGES + 2);
    assert_eq!(listed[299], Listed::Unknown);
    assert_eq!(listed[300], Listed::Present(30001));
    assert!(listed[301..].iter().all(|listed| *listed == Listed::Absent));
    assert_eq!(bucket.prefixes.borrow().last().unwrap(), "more/");
}

#[tokio::test]
async fn named_prefixes_with_fewer_keys_than_a_listing_costs_are_not_listed() {
    let prefixes: Vec<String> = (0..300).map(|d| format!("big/d{d:03}/")).collect();
    for keys in [1, 4, LIST_COST - 1, LIST_COST] {
        let mut plan: Vec<String> = prefixes
            .iter()
            .flat_map(|prefix| (0..keys).map(move |f| format!("{prefix}new{f:02}")))
            .collect();
        // One prefix with a key more than the others.
        plan.push(format!("big/d150/new{keys:02}"));
        plan.sort();
        let bucket = Bucket::new(large());
        let found = segments(
            &Keys::new(plan.iter().map(|key| key.as_str().into())),
            &prefixes,
        );
        let prefixes: Vec<&str> = prefixes.iter().map(String::as_str).collect();
        let listed = discover_under(&bucket, &prefixes, &plan).await;
        let decided = listed.iter().filter(|listed| **listed != Listed::Unknown);
        let requests = bucket.requests.borrow().len();
        if keys < LIST_COST {
            // Their HEAD requests cost less than a listing of each prefix.
            // The copy's one listing request lists the prefix with the most
            // keys instead, if it has at least two.
            let most: Vec<_> = found
                .iter()
                .map(|segment| segment.prefix.as_str())
                .collect();
            assert_eq!(most, ["big/d150/"], "{keys}");
            assert_eq!((decided.count(), requests), (keys + 1, 1), "{keys}");
        } else {
            assert_eq!(found.len(), 300);
            assert_eq!((decided.count(), requests), (plan.len(), 300));
        }
    }
    // Each single key is checked with HEAD.
    let plan: Vec<String> = prefixes
        .iter()
        .map(|prefix| format!("{prefix}new"))
        .collect();
    let found = segments(
        &Keys::new(plan.iter().map(|key| key.as_str().into())),
        &prefixes,
    );
    assert!(found.is_empty());
}

#[test]
fn the_first_prefix_with_the_most_keys_is_listed_when_none_is_worth_a_listing() {
    let plan: Vec<String> = [
        "a/1", "a/2", "b/1", "b/2", "b/3", "c/1", "c/2", "c/3", "d/1",
    ]
    .map(str::to_owned)
    .into();
    let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
    let prefixes: Vec<String> = ["a/", "b/", "c/", "d/"].map(str::to_owned).into();
    assert_eq!(
        segments(&keys, &prefixes),
        [Segment {
            prefix: "b/".into(),
            range: 2..5,
        }]
    );
}

#[tokio::test]
async fn first_pages_are_where_each_prefix_listing_starts() {
    // Sorts before every other key beneath the same prefix.
    let long = |name: &str| format!("dst/{name}/{}", "a".repeat(MAX_KEY));
    let mut plan = named_plan();
    // The listing of `l` starts after its long first key; every key of `m` is
    // too long to start a listing at.
    plan.extend([long("l"), "dst/l/b".into(), "dst/l/c".into(), long("m")]);
    plan.extend((0..10).map(|f| format!("dst/l/d{f}")));
    plan.extend((0..11).map(|f| format!("{}y{f}", long("m"))));
    plan.sort();
    let first_of_l = plan.iter().find(|key| key.starts_with("dst/l/"));
    assert_eq!(first_of_l, Some(&long("l")));
    let prefixes: Vec<String> = NAMED
        .into_iter()
        .chain(["dst/l/", "dst/m/"])
        .map(str::to_owned)
        .collect();
    for ordered in [true, false] {
        let mut bucket = Bucket::new(["dst/a-b/x", "dst/a/1", "dst/l/c"].map(str::to_owned));
        bucket.ordered = ordered;
        let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
        let segments = segments(&keys, &prefixes);
        let first: Vec<_> = first_pages(&segments, &keys, ordered, true)
            .map(|request| {
                (
                    request.query["prefix"].clone(),
                    request.query.get("start-after").cloned(),
                )
            })
            .collect();
        let expected_prefixes: &[&str] = if ordered {
            &["dst/a-b/", "dst/a/", "dst/l/"]
        } else {
            &["dst/a-b/", "dst/a/", "dst/l/", "dst/m/"]
        };
        assert_eq!(
            first.iter().map(|(prefix, _)| prefix).collect::<Vec<_>>(),
            expected_prefixes
        );
        discover_segments(&bucket, segments.clone(), keys).await;
        // The first request under each prefix, in the order sent.
        let mut sent: Vec<(String, Option<String>)> = Vec::new();
        for (prefix, after) in bucket.starts.borrow().iter() {
            if !sent.iter().any(|(listed, _)| listed == prefix) {
                sent.push((prefix.clone(), after.clone()));
            }
        }
        assert_eq!(sent, first, "ordered: {ordered}");
        if ordered {
            assert_eq!(first[2].1.as_deref(), Some(predecessor("dst/l/b").as_str()));
        }
    }
}

/// Lists in the order measured on Cloudflare R2: as if every key ended in a
/// byte just above `9`, so `a0000` comes before `a`. StartAfter follows the
/// same order, and a continuation token names the last key returned.
struct R2Order {
    objects: Vec<(String, u64)>,
    divides: bool,
}
impl R2Order {
    fn position(key: &str) -> Vec<u8> {
        let mut position = key.as_bytes().to_vec();
        position.extend([b'9', 0xff]);
        position
    }
    fn new(keys: impl IntoIterator<Item = String>) -> Self {
        let mut objects: Vec<_> = keys.into_iter().zip(1..).collect();
        objects.sort_by_key(|(key, _)| Self::position(key));
        Self {
            objects,
            divides: false,
        }
    }
}
impl Store for R2Order {
    fn divides(&self) -> bool {
        self.divides
    }
    async fn page(
        &self,
        prefix: &str,
        _: bool,
        token: Option<&str>,
        start_after: Option<&str>,
    ) -> Result<Page> {
        let after = token.or(start_after).map(Self::position);
        let mut matching = self.objects.iter().filter(|(key, _)| {
            key.starts_with(prefix)
                && after
                    .as_ref()
                    .is_none_or(|after| Self::position(key) > *after)
        });
        let entries: Vec<_> = matching
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
        Ok(Page {
            next,
            entries,
            prefixes: Vec::new(),
        })
    }
}

#[tokio::test]
async fn absence_is_concluded_only_where_the_store_lists_in_byte_order() {
    // The destination holds `d/a` after a thousand longer keys in R2's
    // order; a page of them looks ordered and passes `d/a` and `d/a-`.
    let destination = || {
        (0..1000)
            .map(|i| format!("d/a{i:04}"))
            .chain(["d/a".to_owned()])
    };
    let plan = ["d/a".to_owned(), "d/a-".to_owned()];
    let keys = || Keys::new(plan.iter().map(|key| key.as_str().into()));
    let decide =
        |store| discover_segments(store, vec![Segment::whole("d/".into(), &keys())], keys());
    // Taken to be in byte order, the listing would call the existing `d/a`
    // absent, and an upload would replace it, dropping metadata only the
    // destination has.
    let mut store = R2Order::new(destination());
    store.divides = true;
    assert_eq!(decide(&store).await, [Listed::Absent, Listed::Absent]);
    // Where the order is not known, the incomplete listing decides nothing:
    // both get a HEAD.
    let store = R2Order::new(destination());
    assert_eq!(decide(&store).await, [Listed::Unknown, Listed::Unknown]);
    // A listing that completes shows absence in any order, for a plan large
    // enough to list for.
    let plan: Vec<String> = ["d/a".to_owned(), "d/a-".to_owned()]
        .into_iter()
        .chain((0..BACKGROUND_KEYS).map(|i| format!("d/n{i:03}")))
        .collect();
    let keys = Keys::new(plan.iter().map(|key| key.as_str().into()));
    let store = R2Order::new(
        (0..10)
            .map(|i| format!("d/a{i:04}"))
            .chain(["d/a".to_owned()]),
    );
    let listed = discover_segments(&store, vec![Segment::whole("d/".into(), &keys)], keys).await;
    assert_eq!(listed[..2], [Listed::Present(11), Listed::Absent]);
    assert!(listed[2..].iter().all(|listed| *listed == Listed::Absent));
}

#[tokio::test]
async fn in_another_order_only_a_short_complete_listing_decides() {
    // A small prefix: one complete page decides every key.
    let plan: Vec<String> = (0..300)
        .map(|i| format!("d/f{i:03}"))
        .chain(["d/new".to_owned()])
        .collect();
    let mut bucket = Bucket::new(plan.iter().filter(|key| *key != "d/new").cloned());
    bucket.divides = false;
    let listed = discover(&bucket, "d/", &plan).await;
    assert!(listed[..300]
        .iter()
        .all(|listed| matches!(listed, Listed::Present(_))));
    assert_eq!(listed[300], Listed::Absent);
    assert_eq!(bucket.requests.borrow().len(), 1);
    // A large prefix costs the pages the copy waits for, then every key
    // gets a HEAD.
    let mut bucket = Bucket::new(large());
    bucket.divides = false;
    let plan: Vec<String> = (0..200).map(|i| format!("big/zz/new{i:03}")).collect();
    let listed = discover(&bucket, "big/", &plan).await;
    assert!(listed.iter().all(|listed| *listed == Listed::Unknown));
    assert_eq!(bucket.requests.borrow().len(), PAGES_BEFORE_COPY);
}

#[tokio::test]
async fn in_another_order_no_key_waits_for_the_listing() {
    // The complete listing runs alongside the copy; a key it has not decided
    // gets a HEAD at once, and one it has decided is relied on at once, before
    // the listing of later prefixes ends.
    let (_sender, reach) = watch::channel(Reach {
        decided: 0,
        finished: false,
    });
    let discovery = Discovery {
        listed: vec![(0..2, 0)],
        decisions: Arc::new(Decisions::new(2)),
        reach: vec![reach],
        waits: false,
        tasks: Vec::new(),
    };
    let lookup = discovery.lookup(1);
    let listed = tokio::time::timeout(std::time::Duration::from_secs(5), lookup).await;
    assert_eq!(listed.unwrap(), Listed::Unknown);
    assert_eq!(discovery.known(1), None);
    // The first prefix's listing completed and showed the key absent.
    discovery.decisions.store(1, ABSENT);
    assert_eq!(discovery.lookup(1).await, Listed::Absent);
    assert_eq!(discovery.known(1), Some(Listed::Absent));
}

#[test]
fn a_listing_of_at_most_one_object_settles_every_key() {
    let plan = ["d/a".to_owned(), "d/b".to_owned()];
    for (object, expected) in [
        (None, [Listed::Absent, Listed::Absent]),
        (Some(("d/a", 3)), [Listed::Present(3), Listed::Absent]),
    ] {
        let mut walk = walk("d/", &plan);
        walk.settle(object);
        assert_eq!(walk.decided, 2);
        assert_eq!([0, 1].map(|index| walk.decisions.get(index)), expected);
    }
}

mod signed {
    //! A named upload's destination listing through the signing transport.
    use super::super::super::super::authorization::{
        http_client, request_for, Authorization, Signer,
    };
    use super::super::super::super::listing::first_page_request;
    use super::*;
    use aws_smithy_runtime_api::client::{
        http::{http_client_fn, HttpConnector, HttpConnectorFuture, SharedHttpConnector},
        orchestrator::{HttpRequest, HttpResponse},
    };
    use std::{
        sync::{atomic::AtomicUsize, Mutex},
        time::Duration,
    };

    /// The destination bucket `fixture`, answering ListObjectsV2 requests
    /// 1000 keys at a time. A continuation token names the last key returned.
    #[derive(Clone, Debug)]
    struct Served {
        objects: Arc<BTreeMap<String, u64>>,
        /// Each request's query, without the signature.
        requests: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
        /// How long each answer takes.
        delay: Duration,
        /// Requests under way, and the most there have been at once.
        in_flight: Arc<AtomicUsize>,
        most: Arc<AtomicUsize>,
        /// Answer every listing with every key, whatever its prefix.
        ignores_prefix: bool,
    }
    impl HttpConnector for Served {
        fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
            let url = url::Url::parse(request.uri()).unwrap();
            let query: BTreeMap<String, String> = url
                .query_pairs()
                .filter(|(name, _)| !name.starts_with("X-Amz-") && name != "x-id")
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect();
            self.requests.lock().unwrap().push(query.clone());
            let prefix = &query["prefix"];
            let lower = query
                .get("continuation-token")
                .or(query.get("start-after"))
                .map_or(Bound::Unbounded, |after| Bound::Excluded(after.as_str()));
            let mut matching = self
                .objects
                .range::<str, _>((lower, Bound::Unbounded))
                .filter(|(key, _)| self.ignores_prefix || key.starts_with(prefix.as_str()));
            let entries: Vec<_> = matching.by_ref().take(1000).collect();
            let next = matching.next().map(|_| entries.last().unwrap().0);
            let mut xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>fixture</Name><Prefix>{prefix}</Prefix><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>{}</IsTruncated>",
                entries.len(),
                next.is_some()
            );
            for (key, size) in &entries {
                xml.push_str(&format!(
                    "<Contents><Key>{key}</Key><Size>{size}</Size></Contents>"
                ));
            }
            if let Some(next) = next {
                xml.push_str(&format!(
                    "<NextContinuationToken>{next}</NextContinuationToken>"
                ));
            }
            xml.push_str("</ListBucketResult>");
            let now = self.in_flight.fetch_add(1, Relaxed) + 1;
            self.most.fetch_max(now, Relaxed);
            let (delay, in_flight) = (self.delay, self.in_flight.clone());
            HttpConnectorFuture::new(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                in_flight.fetch_sub(1, Relaxed);
                Ok(HttpResponse::new(
                    200.try_into().unwrap(),
                    aws_smithy_types::body::SdkBody::from(xml),
                ))
            })
        }
    }

    /// Named directories `a`, `b` and `c` uploaded into `dst`, each holding
    /// enough keys to be worth a listing. `b` holds more existing keys than
    /// two pages list.
    fn plan() -> Vec<String> {
        let mut plan: Vec<String> = ["a", "c"]
            .iter()
            .flat_map(|d| (1..=LIST_COST).map(move |f| format!("dst/{d}/{f:02}")))
            .collect();
        plan.extend((0..2500).map(|f| format!("dst/b/{f:04}")));
        plan.sort();
        plan
    }
    fn served() -> Served {
        let mut objects: BTreeMap<String, u64> = [
            ("dst/a-a", 1),
            ("dst/a/01", 2),
            ("dst/c/02", 3),
            ("dst/z", 4),
        ]
        .map(|(key, size)| (key.to_owned(), size))
        .into();
        objects.extend((0..2500).map(|f| (format!("dst/b/{f:04}"), 5)));
        Served {
            objects: Arc::new(objects),
            requests: Arc::default(),
            delay: Duration::ZERO,
            in_flight: Arc::default(),
            most: Arc::default(),
            ignores_prefix: false,
        }
    }
    const ARGV: &[&str] = &[
        "cp",
        "/src/a",
        "/src/b",
        "/src/c",
        "--to",
        "s3://fixture",
        "--into",
        "dst",
    ];

    /// An engine for `argv` whose requests `served` answers, signed by a
    /// signing machine that holds the authorization the command implies
    /// when `signs`.
    fn engine(
        argv: &[&str],
        served: &Served,
        signs: bool,
    ) -> (super::super::super::Engine, Option<Arc<Authorization>>) {
        use aws_sdk_s3::config::{Builder, Credentials, Region};
        let mut engine = super::super::super::tests::engine(argv);
        let authorization = signs.then(|| {
            let signer = Signer::fixture(request_for(&engine.args, &engine.options).unwrap());
            let (local, mut remote) = std::os::unix::net::UnixStream::pair().unwrap();
            let configuration = signer.configuration.clone();
            std::thread::spawn(move || {
                crate::destination::storage::serve_signing(&mut remote, &signer, || false)
            });
            Arc::new(Authorization::new("fixture".into(), configuration, local))
        });
        let inner = served.clone();
        let inner = http_client_fn(move |_, _| SharedHttpConnector::new(inner.clone()));
        let config = Builder::new()
            .behavior_version_latest()
            .region(Region::new("auto"))
            .endpoint_url("https://storage.example")
            .force_path_style(true)
            .credentials_provider(Credentials::new("fixture", "fixture", None, None, "test"));
        let config = match &authorization {
            Some(authorization) => config.http_client(http_client(inner, authorization.clone())),
            None => config.http_client(inner),
        };
        engine.client = aws_sdk_s3::Client::from_conf(config.build());
        engine.authorization = authorization.clone();
        (engine, authorization)
    }

    /// The listing requests signed so far, as `(prefix, start, continued)`.
    fn signed_listings(authorization: &Authorization) -> Vec<(String, Option<String>, bool)> {
        authorization
            .signed_so_far()
            .into_iter()
            .filter(|request| request.query.contains_key("list-type"))
            .map(|request| {
                (
                    request.query["prefix"].clone(),
                    request.query.get("start-after").cloned(),
                    request.query.contains_key("continuation-token"),
                )
            })
            .collect()
    }

    async fn decisions(engine: &super::super::super::Engine, plan: &[String]) -> Vec<Listed> {
        let discovery = engine.discovery.get().unwrap();
        let mut listed = Vec::new();
        for index in 0..plan.len() {
            listed.push(discovery.lookup(index).await);
        }
        listed
    }

    fn expected(plan: &[String], served: &Served) -> Vec<Listed> {
        plan.iter()
            .map(|key| {
                served
                    .objects
                    .get(key)
                    .map_or(Listed::Absent, |size| Listed::Present(*size))
            })
            .collect()
    }

    #[tokio::test]
    async fn each_named_prefix_first_page_is_signed_before_the_listing_starts() {
        for dry_run in [false, true] {
            let argv: Vec<&str> = ARGV
                .iter()
                .copied()
                .chain(dry_run.then_some("--dry-run"))
                .collect();
            let served = served();
            let (engine, authorization) = engine(&argv, &served, true);
            let authorization = authorization.unwrap();
            let mut plan = plan();
            engine
                .discover_destination(&mut plan, &[], |key: &String| key.as_str().into())
                .await
                .unwrap();
            // Each prefix's listing has sent the pages the copy waits for:
            // `a` and `c` their only one, `b` two. Every prefix's first page
            // was signed in one exchange, and nothing else: not the
            // destination directory itself. `b`'s second page continues from
            // its first response, so it needed an exchange of its own.
            let first =
                |prefix: &str, key: &str| (prefix.to_owned(), Some(predecessor(key)), false);
            let presigned = vec![
                first("dst/a/", "dst/a/01"),
                first("dst/b/", "dst/b/0000"),
                first("dst/c/", "dst/c/01"),
            ];
            let continued = ("dst/b/".to_owned(), None, true);
            let mut signed = signed_listings(&authorization);
            signed.sort();
            let mut all = presigned.clone();
            all.push(continued.clone());
            all.sort();
            assert_eq!(signed, all);
            assert_eq!(authorization.exchanges_so_far(), 2);
            assert_eq!(served.requests.lock().unwrap().len(), 4);

            assert_eq!(decisions(&engine, &plan).await, expected(&plan, &served));
            // `b`'s third page was signed only when the listing reached it.
            // The pages sent are the ones signed: the descriptions match what
            // the SDK sends.
            let mut signed = signed_listings(&authorization);
            signed.sort();
            all.push(continued);
            all.sort();
            assert_eq!(signed, all);
            assert_eq!(authorization.exchanges_so_far(), 3);
            assert_eq!(served.requests.lock().unwrap().len(), 5);
        }
    }

    #[tokio::test]
    async fn one_small_named_directory_is_listed_with_the_copy_s_one_listing_request() {
        // Named directories of 4 and 3 keys: neither is worth a listing, but
        // the copy sends one listing request anyway.
        let argv = &[
            "cp",
            "/src/a",
            "/src/c",
            "--to",
            "s3://fixture",
            "--into",
            "dst",
        ];
        let served = served();
        let (engine, authorization) = engine(argv, &served, true);
        let authorization = authorization.unwrap();
        let mut plan: Vec<String> = ["dst/a/", "dst/a/01", "dst/a/02", "dst/a/03"]
            .into_iter()
            .chain(["dst/c/01", "dst/c/02", "dst/c/03"])
            .map(str::to_owned)
            .collect();
        plan.sort();
        engine
            .discover_destination(&mut plan, &[], |key: &String| key.as_str().into())
            .await
            .unwrap();
        let listed = decisions(&engine, &plan).await;
        // That request lists `a` and decides its keys; `c`'s keys are left
        // to their HEAD requests.
        let in_a = plan.iter().map(|key| key.starts_with("dst/a/"));
        for ((key, listed), in_a) in plan.iter().zip(&listed).zip(in_a) {
            let expected = if in_a {
                expected(std::slice::from_ref(key), &served)[0]
            } else {
                Listed::Unknown
            };
            assert_eq!(*listed, expected, "{key}");
        }
        let requests = served.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["prefix"], "dst/a/");
        assert_eq!(requests[0].get("start-after"), Some(&predecessor("dst/a/")));
        // Its page was signed with the first pages, before it was sent.
        assert_eq!(
            signed_listings(&authorization),
            [("dst/a/".to_owned(), Some(predecessor("dst/a/")), false)]
        );
        assert_eq!(authorization.exchanges_so_far(), 1);
    }

    #[tokio::test]
    async fn named_prefixes_are_listed_at_once_up_to_a_bound() {
        let sources: Vec<String> = (0..40).map(|d| format!("/src/d{d:02}")).collect();
        let mut argv = vec!["cp"];
        argv.extend(sources.iter().map(String::as_str));
        argv.extend(["--to", "s3://fixture", "--into", "dst"]);
        let mut served = served();
        served.delay = Duration::from_millis(100);
        let (engine, _) = engine(&argv, &served, true);
        let mut plan: Vec<String> = (0..40)
            .flat_map(|d| (0..LIST_COST).map(move |f| format!("dst/d{d:02}/{f:02}")))
            .collect();
        plan.sort();
        let started = std::time::Instant::now();
        engine
            .discover_destination(&mut plan, &[], |key: &String| key.as_str().into())
            .await
            .unwrap();
        assert_eq!(decisions(&engine, &plan).await, expected(&plan, &served));
        // Far sooner than one prefix after another.
        assert!(
            started.elapsed() < served.delay * 20,
            "{:?}",
            started.elapsed()
        );
        // One request for each prefix, as many at once as allowed.
        let requests = served.requests.lock().unwrap();
        let mut prefixes: Vec<_> = requests.iter().map(|query| &query["prefix"]).collect();
        prefixes.sort();
        prefixes.dedup();
        assert_eq!((requests.len(), prefixes.len()), (40, 40));
        assert_eq!(served.most.load(Relaxed), LISTINGS);
    }

    #[tokio::test]
    async fn where_order_is_unknown_the_requests_sent_are_the_ones_signed() {
        let served = served();
        let (mut engine, authorization) = engine(ARGV, &served, true);
        let authorization = authorization.unwrap();
        // Not known to list in byte order.
        engine.options.endpoint = Some("https://account.r2.cloudflarestorage.com".into());
        let mut plan = plan();
        engine
            .discover_destination(&mut plan, &[], |key: &String| key.as_str().into())
            .await
            .unwrap();
        // The short request first, then each prefix's first page without a
        // start: all signed up front.
        let mut presigned: Vec<_> = authorization
            .signed_so_far()
            .into_iter()
            .filter(|request| request.query.contains_key("list-type"))
            .map(|request| {
                (
                    request.query["prefix"].clone(),
                    request.query["max-keys"].clone(),
                )
            })
            .collect();
        presigned.sort();
        // Only `b` plans enough keys to list for.
        let expected_pages = [("dst/a/", "1"), ("dst/b/", "1000")];
        assert_eq!(
            presigned,
            expected_pages.map(|(prefix, size)| (prefix.to_owned(), size.to_owned()))
        );
        let discovery = engine.discovery.get().unwrap();
        discovery.reach[0]
            .clone()
            .wait_for(|reach| reach.finished)
            .await
            .unwrap();
        // `a` and `c` are left to HEAD. `b`'s two pages show the keys they
        // list present, and nothing absent: the listing did not complete.
        let listed = decisions(&engine, &plan).await;
        for (listed, key) in listed.iter().zip(&plan) {
            if key.starts_with("dst/b/") {
                assert!(
                    matches!(listed, Listed::Present(5) | Listed::Unknown),
                    "{key}"
                );
            } else {
                assert_eq!(*listed, Listed::Unknown, "{key}");
            }
        }
        let shown = listed
            .iter()
            .filter(|listed| matches!(listed, Listed::Present(_)))
            .count();
        assert_eq!(shown, 2000);
        // Only `b`'s second page, which continues from its first response,
        // was signed later; nothing started after a key.
        let listings = signed_listings(&authorization);
        assert!(listings.iter().all(|(_, after, _)| after.is_none()));
        assert_eq!(
            listings
                .iter()
                .filter(|(_, _, continued)| *continued)
                .count(),
            1
        );
        assert_eq!(served.requests.lock().unwrap().len(), listings.len());
    }

    #[tokio::test]
    async fn a_short_listing_that_returns_more_than_asked_settles_nothing() {
        // `Served` ignores `max-keys`: the short request returns both keys.
        let served = Served {
            objects: Arc::new(
                [("dst/a/1", 1), ("dst/a/2", 2)]
                    .map(|(key, size)| (key.to_owned(), size))
                    .into(),
            ),
            requests: Arc::default(),
            delay: Duration::ZERO,
            in_flight: Arc::default(),
            most: Arc::default(),
            ignores_prefix: false,
        };
        let (mut engine, _) = engine(
            &["cp", "/src/a", "--to", "s3://fixture", "--into", "dst"],
            &served,
            false,
        );
        engine.options.endpoint = Some("https://account.r2.cloudflarestorage.com".into());
        let mut plan = vec!["dst/a/1".to_owned(), "dst/a/2".to_owned()];
        engine
            .discover_destination(&mut plan, &[], |key: &String| key.as_str().into())
            .await
            .unwrap();
        // Both get a HEAD; neither is taken to be absent.
        assert_eq!(
            decisions(&engine, &plan).await,
            [Listed::Unknown, Listed::Unknown]
        );
        assert_eq!(served.requests.lock().unwrap()[0]["max-keys"], "1");
    }

    #[tokio::test]
    async fn a_short_listing_outside_its_prefix_fails_the_copy() {
        let served = Served {
            objects: Arc::new([("unrelated/a".to_owned(), 1)].into()),
            requests: Arc::default(),
            delay: Duration::ZERO,
            in_flight: Arc::default(),
            most: Arc::default(),
            ignores_prefix: true,
        };
        let (mut engine, _) = engine(
            &["cp", "/src/a", "--to", "s3://fixture", "--into", "dst"],
            &served,
            false,
        );
        engine.options.endpoint = Some("https://account.r2.cloudflarestorage.com".into());
        let mut plan = vec!["dst/a/1".to_owned(), "dst/a/2".to_owned()];
        let error = engine
            .discover_destination(&mut plan, &[], |key: &String| key.as_str().into())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("outside the requested prefix"));
    }

    #[test]
    fn a_first_page_outside_the_named_prefixes_is_refused() {
        let engine = super::super::super::tests::engine(ARGV);
        let signer = Signer::fixture(request_for(&engine.args, &engine.options).unwrap());
        assert!(signer
            .sign(&first_page_request("dst/b/", Some("dst/b/0")))
            .is_ok());
        for prefix in ["dst/", "dst/a", "dst/d/", ""] {
            assert!(
                signer.sign(&first_page_request(prefix, None)).is_err(),
                "{prefix}"
            );
        }
    }

    #[tokio::test]
    async fn without_a_signer_the_destination_is_listed_as_before() {
        let served = served();
        let (engine, _) = engine(ARGV, &served, false);
        let mut plan = plan();
        engine
            .discover_destination(&mut plan, &[], |key: &String| key.as_str().into())
            .await
            .unwrap();
        assert_eq!(decisions(&engine, &plan).await, expected(&plan, &served));
        // One listing of the whole destination.
        let requests = served.requests.lock().unwrap();
        assert!(requests.iter().all(|query| query["prefix"] == "dst/"));
        assert_eq!(
            requests[0].get("start-after"),
            Some(&predecessor("dst/a/01"))
        );
    }
}
