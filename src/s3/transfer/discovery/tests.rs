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

async fn discover_segments(bucket: &Bucket, segments: Vec<Segment>, keys: Keys) -> Vec<Listed> {
    let len = keys.len();
    let mut walk = Walk::new(segments, Arc::new(keys), Arc::new(Decisions::new(len)));
    let plan = 0..len;
    if walk.segments.is_empty() {
        return plan.map(|_| Listed::Unknown).collect();
    }
    if bucket.ordered {
        while walk.page(bucket).await.unwrap() {}
    } else {
        walk.whole(bucket).await.unwrap();
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
        let first: Vec<_> = first_pages(&segments, &keys, ordered)
            .map(|(prefix, after)| (prefix.to_owned(), after))
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
        /// A prefix whose pages come back in reverse key order.
        reversed: Option<String>,
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
                .filter(|(key, _)| key.starts_with(prefix.as_str()));
            let mut entries: Vec<_> = matching.by_ref().take(1000).collect();
            let next = matching.next().map(|_| entries.last().unwrap().0);
            if self.reversed.as_ref() == Some(prefix) {
                entries.reverse();
            }
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
            reversed: None,
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

    /// Named directories `d00`…`d39` uploaded into `dst` with `--prune`, and
    /// `extra` options. The endpoint is not AWS, so listings are not divided.
    fn pruning_argv(extra: &[&str]) -> Vec<String> {
        let mut argv = vec!["cp".to_owned()];
        argv.extend((0..40).map(|d| format!("/src/d{d:02}")));
        argv.extend(
            [
                "--to",
                "s3://fixture",
                "--into",
                "dst",
                "--prune",
                "--s3-endpoint",
                "https://storage.example",
            ]
            .into_iter()
            .chain(extra.iter().copied())
            .map(str::to_owned),
        );
        argv
    }

    /// Each named directory's new file `02` and existing file `01`, in key
    /// order, and the pruning plan for them.
    fn pruning_plan() -> (Vec<String>, crate::s3::prune::Plan) {
        let mut plan: Vec<String> = (0..40)
            .flat_map(|d| ["01", "02"].map(|f| format!("dst/d{d:02}/{f}")))
            .collect();
        plan.sort();
        let mut prune = crate::s3::prune::Plan::default();
        for d in 0..40 {
            prune.scope(format!("dst/d{d:02}").as_bytes());
        }
        for key in &plan {
            prune.claim_file(key.as_bytes());
        }
        (plan, prune)
    }

    /// Each named directory's `01`, and an object to prune in every even
    /// one. Others lie beside the named directories, and one in a directory
    /// whose name extends a named one's.
    fn pruning_served() -> Served {
        let mut objects: BTreeMap<String, u64> = BTreeMap::new();
        for d in 0..40 {
            objects.insert(format!("dst/d{d:02}/01"), 1);
            if d % 2 == 0 {
                objects.insert(format!("dst/d{d:02}/zz"), 2);
            }
        }
        for key in [
            "dst/a",
            "dst/d00-x/zz",
            "dst/d40/zz",
            "dst/z",
            "other/d00/zz",
        ] {
            objects.insert(key.to_owned(), 3);
        }
        Served {
            objects: Arc::new(objects),
            ..served()
        }
    }

    /// The keys pruning would delete, from the signed DELETE requests.
    fn signed_deletions(authorization: &Authorization) -> Vec<String> {
        let mut keys: Vec<String> = authorization
            .signed_so_far()
            .into_iter()
            .filter(|request| request.method == "DELETE")
            .map(|request| request.key)
            .collect();
        keys.sort();
        keys
    }

    #[tokio::test]
    async fn pruned_prefixes_are_listed_at_once_after_their_first_pages_are_signed_together() {
        // A copy that keeps existing objects leaves the listing to preparing
        // the deletions.
        for extra in [&[][..], &["--if-exists=keep"], &["--dry-run"]] {
            let argv = pruning_argv(extra);
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            let mut served = pruning_served();
            served.delay = Duration::from_millis(100);
            let (engine, authorization) = engine(&argv, &served, true);
            let authorization = authorization.unwrap();
            let (mut plan, prune) = pruning_plan();
            let started = std::time::Instant::now();
            engine
                .discover_destination(&mut plan, &prune.scopes, |key: &String| key.as_str().into())
                .await
                .unwrap();
            engine.prepare_pruning(&prune).await.unwrap();
            // Far sooner than one prefix after another.
            assert!(
                started.elapsed() < served.delay * 10,
                "{extra:?}: {:?}",
                started.elapsed()
            );
            // One request for each pruned directory, as many at once as the
            // destination listing allows, each first signed in one exchange.
            let requests = served.requests.lock().unwrap().clone();
            let mut prefixes: Vec<&str> = requests.iter().map(|q| q["prefix"].as_str()).collect();
            prefixes.sort();
            let expected: Vec<String> = (0..40).map(|d| format!("dst/d{d:02}/")).collect();
            assert_eq!(prefixes, expected, "{extra:?}");
            assert!(requests
                .iter()
                .all(|q| !q.contains_key("start-after") && !q.contains_key("continuation-token")));
            assert_eq!(served.most.load(Relaxed), LISTINGS, "{extra:?}");
            let mut signed = signed_listings(&authorization);
            signed.sort();
            let first_pages: Vec<_> = expected.iter().map(|p| (p.clone(), None, false)).collect();
            assert_eq!(signed, first_pages, "{extra:?}");
            // The DELETE requests are signed in one more exchange, except in
            // a dry run, which signs none.
            let dry_run = extra.contains(&"--dry-run");
            assert_eq!(
                authorization.exchanges_so_far(),
                if dry_run { 1 } else { 2 },
                "{extra:?}"
            );
            let deleted: Vec<String> = if dry_run {
                Vec::new()
            } else {
                (0..40)
                    .step_by(2)
                    .map(|d| format!("dst/d{d:02}/zz"))
                    .collect()
            };
            assert_eq!(signed_deletions(&authorization), deleted, "{extra:?}");
            // The listing is complete for each planned key.
            let listed = engine.upload_keys.get().unwrap();
            for key in &plan {
                let size = served.objects.get(key).copied();
                assert_eq!(listed.size(key), Some(size), "{key}");
            }
        }
    }

    #[tokio::test]
    async fn pruning_lists_nothing_and_deletes_nothing_outside_the_pruned_directories() {
        // `d00` and `d01` are pruned, `d02` is named but not pruned: as a
        // file, its key is checked on its own.
        let argv = &[
            "cp",
            "/src/d00",
            "/src/d01",
            "/src/d02",
            "--to",
            "s3://fixture",
            "--into",
            "dst",
            "--prune",
            "--s3-endpoint",
            "https://storage.example",
        ];
        let served = pruning_served();
        let (engine, authorization) = engine(argv, &served, true);
        let authorization = authorization.unwrap();
        let mut plan: Vec<String> = ["dst/d00/01", "dst/d01/01", "dst/d02"]
            .map(str::to_owned)
            .into();
        let mut prune = crate::s3::prune::Plan::default();
        prune.scope(b"dst/d00");
        prune.scope(b"dst/d01");
        for key in &plan {
            prune.claim_file(key.as_bytes());
        }
        engine
            .discover_destination(&mut plan, &prune.scopes, |key: &String| key.as_str().into())
            .await
            .unwrap();
        engine.prepare_pruning(&prune).await.unwrap();
        let mut prefixes: Vec<String> = served
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|q| q["prefix"].clone())
            .collect();
        prefixes.sort();
        assert_eq!(prefixes, ["dst/d00/", "dst/d01/"]);
        assert_eq!(signed_deletions(&authorization), ["dst/d00/zz"]);
    }

    #[tokio::test]
    async fn a_pruning_listing_out_of_key_order_is_still_complete() {
        // A complete listing finds every key wherever the page puts it, so
        // its order decides nothing, for that prefix or the others.
        let argv = pruning_argv(&[]);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let mut served = pruning_served();
        served.reversed = Some("dst/d04/".to_owned());
        let (engine, authorization) = engine(&argv, &served, true);
        let authorization = authorization.unwrap();
        let (mut plan, prune) = pruning_plan();
        engine
            .discover_destination(&mut plan, &prune.scopes, |key: &String| key.as_str().into())
            .await
            .unwrap();
        engine.prepare_pruning(&prune).await.unwrap();
        let listed = engine.upload_keys.get().unwrap();
        for key in &plan {
            assert_eq!(listed.size(key), Some(served.objects.get(key).copied()));
        }
        let deleted: Vec<String> = (0..40)
            .step_by(2)
            .map(|d| format!("dst/d{d:02}/zz"))
            .collect();
        assert_eq!(signed_deletions(&authorization), deleted);
        assert_eq!(engine.progress.errors.load(Relaxed), 0);
    }

    #[tokio::test]
    async fn pruning_listings_at_once_send_no_more_requests_than_the_copy_s_concurrency() {
        let argv = pruning_argv(&[]);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let mut served = pruning_served();
        served.delay = Duration::from_millis(20);
        let (mut engine, _) = engine(&argv, &served, true);
        engine.options.concurrency = 4;
        let (mut plan, prune) = pruning_plan();
        engine
            .discover_destination(&mut plan, &prune.scopes, |key: &String| key.as_str().into())
            .await
            .unwrap();
        assert_eq!(served.requests.lock().unwrap().len(), 40);
        assert_eq!(served.most.load(Relaxed), 4);
    }

    #[tokio::test]
    async fn a_pruned_prefix_s_later_pages_are_signed_as_its_listing_reaches_them() {
        // `b` holds 2500 keys: three pages, the first signed with `a`'s and
        // `c`'s, each later one continuing from the page before.
        let argv: Vec<&str> = ARGV
            .iter()
            .copied()
            .chain(["--prune", "--s3-endpoint", "https://storage.example"])
            .collect();
        let served = served();
        let (engine, authorization) = engine(&argv, &served, true);
        let authorization = authorization.unwrap();
        let mut plan = plan();
        let scopes = [b"dst/a".to_vec(), b"dst/b".to_vec(), b"dst/c".to_vec()];
        engine
            .discover_destination(&mut plan, &scopes, |key: &String| key.as_str().into())
            .await
            .unwrap();
        let mut signed = signed_listings(&authorization);
        signed.sort();
        let continued = ("dst/b/".to_owned(), None, true);
        assert_eq!(
            signed,
            [
                ("dst/a/".to_owned(), None, false),
                ("dst/b/".to_owned(), None, false),
                continued.clone(),
                continued,
                ("dst/c/".to_owned(), None, false),
            ]
        );
        assert_eq!(authorization.exchanges_so_far(), 3);
        assert_eq!(served.requests.lock().unwrap().len(), 5);
        assert_eq!(engine.upload_keys.get().unwrap().keys.len(), 2502);
    }

    #[tokio::test]
    async fn without_a_signer_pruning_lists_the_destination_as_before() {
        let argv: Vec<&str> = ARGV
            .iter()
            .copied()
            .chain(["--prune", "--s3-endpoint", "https://storage.example"])
            .collect();
        let served = served();
        let (engine, _) = engine(&argv, &served, false);
        let mut plan = plan();
        let scopes = [b"dst/a".to_vec(), b"dst/b".to_vec(), b"dst/c".to_vec()];
        engine
            .discover_destination(&mut plan, &scopes, |key: &String| key.as_str().into())
            .await
            .unwrap();
        // One listing of the whole destination, page after page.
        let requests = served.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|query| query["prefix"] == "dst/"));
        assert!(!requests[0].contains_key("start-after"));
        assert_eq!(engine.upload_keys.get().unwrap().keys.len(), 2504);
    }

    #[tokio::test]
    async fn a_long_pruning_listing_does_not_hold_up_the_others() {
        // `d00` holds eleven pages of keys; the other directories one each.
        let argv = pruning_argv(&[]);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        let mut served = pruning_served();
        let mut objects = (*served.objects).clone();
        objects.extend((0..10_000).map(|f| (format!("dst/d00/k{f:05}"), 1)));
        served.objects = Arc::new(objects);
        served.delay = Duration::from_millis(20);
        let (engine, _) = engine(&argv, &served, true);
        let (mut plan, prune) = pruning_plan();
        engine
            .discover_destination(&mut plan, &prune.scopes, |key: &String| key.as_str().into())
            .await
            .unwrap();
        // Every other directory was listed before `d00`'s last page.
        let requests = served.requests.lock().unwrap();
        let prefixes: Vec<&str> = requests.iter().map(|q| q["prefix"].as_str()).collect();
        assert_eq!(prefixes.len(), 50);
        assert_eq!(prefixes.last(), Some(&"dst/d00/"));
        assert_eq!(engine.upload_keys.get().unwrap().keys.len(), 10_060);
    }
}
