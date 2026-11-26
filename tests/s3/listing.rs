use super::*;
use std::{collections::BTreeMap, sync::Mutex};

/// A bucket served from memory, under any name: ListObjectsV2 with
/// prefixes, the delimiter `/` and pages of up to `max-keys`, and HEAD with
/// syq metadata. Every request is logged. A directory bucket's name, ending
/// in `--x-s3` or `--xa-s3`, also gets the session its client asks for
/// first, and refuses a prefix that is neither empty nor ends with `/`.
struct Bucket {
    address: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

/// How the bucket fails: `only` lists only that prefix, refusing others;
/// `partial` refuses the second page of every listing; `list_only` refuses
/// every HEAD request; `deny_head` refuses HEAD for one key; `omit_list_time`
/// leaves LastModified out of listings.
#[derive(Clone, Copy, Default)]
struct Faults {
    only: Option<&'static str>,
    partial: bool,
    missing_token: bool,
    list_only: bool,
    deny_head: Option<&'static str>,
    omit_list_time: bool,
}

impl Bucket {
    fn start(keys: &[(&str, &str)], faults: Faults) -> Self {
        let keys: Arc<BTreeMap<String, Vec<u8>>> = Arc::new(
            keys.iter()
                .map(|(key, body)| ((*key).to_owned(), body.as_bytes().to_vec()))
                .collect(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopping = stop.clone();
        let observed = requests.clone();
        let worker = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopping.load(Ordering::Relaxed) {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                let keys = keys.clone();
                let observed = observed.clone();
                workers.push(thread::spawn(move || {
                    serve_bucket(socket, &keys, faults, &observed)
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn find(&self, temp: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .args([
                "--s3-region",
                "us-east-1",
                "--s3-retries",
                "0",
                "--s3-endpoint",
                &self.address,
            ])
            .env("AWS_ACCESS_KEY_ID", "test-access")
            .env("AWS_SECRET_ACCESS_KEY", "test-secret")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_ENDPOINT_URL")
            .env_remove("AWS_ENDPOINT_URL_S3")
            .env_remove("SYQ_TEST_S3_DIVIDE_LISTINGS")
            .env("AWS_CONFIG_FILE", temp.join("no-config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", temp.join("no-credentials"))
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("XDG_CACHE_HOME", temp.join("cache"))
            .current_dir(temp)
            .capture_output()
            .unwrap()
    }

    /// The requests since the last call: `HEAD key`, or `LIST prefix` with
    /// `/` after it for a delimiter listing. A directory bucket's session is
    /// left out.
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

impl Drop for Bucket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn serve_bucket(
    mut socket: TcpStream,
    keys: &BTreeMap<String, Vec<u8>>,
    faults: Faults,
    observed: &Mutex<Vec<String>>,
) {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        if socket.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        request.push(byte[0]);
    }
    let request = String::from_utf8(request).unwrap();
    let mut words = request.split_whitespace();
    let method = words.next().unwrap();
    let target = words.next().unwrap();
    let url = url::Url::parse(&format!("http://fixture{target}")).unwrap();
    let path = percent_encoding::percent_decode_str(url.path())
        .decode_utf8()
        .unwrap();
    let (bucket, key) = path[1..].split_once('/').unwrap_or((&path[1..], ""));
    let directory_bucket = bucket.ends_with("--x-s3") || bucket.ends_with("--xa-s3");
    let query: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    if method == "GET" && query.contains_key("session") {
        assert!(directory_bucket, "{request}");
        let body = "<CreateSessionResult><Credentials><SessionToken>session</SessionToken><SecretAccessKey>secret</SecretAccessKey><AccessKeyId>access</AccessKeyId><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></CreateSessionResult>";
        reply(&mut socket, 200, &[], body.as_bytes(), false);
        return;
    }
    if method == "HEAD" {
        observed.lock().unwrap().push(format!("HEAD {key}"));
        if faults.list_only || faults.deny_head == Some(key) {
            reply(&mut socket, 403, &[], b"", true);
            return;
        }
        let Some(body) = keys.get(key) else {
            reply(&mut socket, 404, &[], b"", true);
            return;
        };
        let mut fields = vec![
            ("Content-Length".to_owned(), body.len().to_string()),
            ("ETag".into(), "\"tag\"".into()),
            (
                "Last-Modified".into(),
                "Thu, 01 Jan 2026 00:00:00 GMT".into(),
            ),
        ];
        // Objects whose name holds `meta` carry syq metadata.
        if key.contains("meta") {
            for (name, value) in [
                ("format", "1"),
                (
                    "kind",
                    if key.ends_with("link") {
                        "symlink"
                    } else {
                        "file"
                    },
                ),
                ("mode", "420"),
                ("uid", "1000"),
                ("gid", "1001"),
                ("mtime", "1700000000"),
                ("mtime-nsec", "0"),
            ] {
                fields.push((format!("x-amz-meta-syq-{name}"), value.into()));
            }
        }
        reply(&mut socket, 200, &fields, b"", true);
        return;
    }
    assert_eq!(method, "GET", "{request}");
    assert_eq!(key, "", "{request}");
    assert_eq!(query.get("list-type").map(String::as_str), Some("2"));
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    let delimiter = query.contains_key("delimiter");
    observed.lock().unwrap().push(format!(
        "LIST {prefix}{}",
        if delimiter { " /" } else { "" }
    ));
    let token = query.get("continuation-token");
    if directory_bucket && !(prefix.is_empty() || prefix.ends_with('/')) {
        reply(
            &mut socket,
            400,
            &[],
            b"<Error><Code>InvalidArgument</Code><Message>Prefix must end in a slash</Message></Error>",
            false,
        );
        return;
    }
    if faults.only.is_some_and(|only| only != prefix) || (faults.partial && token.is_some()) {
        reply(
            &mut socket,
            403,
            &[],
            b"<Error><Code>AccessDenied</Code></Error>",
            false,
        );
        return;
    }
    let max: usize = query.get("max-keys").map_or(1000, |n| n.parse().unwrap());
    let mut items: Vec<(String, bool)> = Vec::new();
    for key in keys.keys().filter(|key| key.starts_with(&prefix)) {
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
    let end = items.len().min(start + max);
    let truncated = end < items.len();
    let encode =
        |text: &str| -> String { url::form_urlencoded::byte_serialize(text.as_bytes()).collect() };
    let mut body = format!(
        "<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>{truncated}</IsTruncated>"
    );
    if truncated && !faults.missing_token {
        body.push_str(&format!(
            "<NextContinuationToken>{end}</NextContinuationToken>"
        ));
    }
    for (item, directory) in &items[start..end] {
        if *directory {
            body.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                encode(item)
            ));
        } else {
            let last_modified = if faults.omit_list_time {
                ""
            } else {
                "<LastModified>2026-01-01T00:00:00.500Z</LastModified>"
            };
            body.push_str(&format!(
                "<Contents><Key>{}</Key><Size>{}</Size>{last_modified}<ETag>&quot;tag&quot;</ETag></Contents>",
                encode(item),
                keys[item].len()
            ));
        }
    }
    body.push_str("</ListBucketResult>");
    reply(&mut socket, 200, &[], body.as_bytes(), false);
}

const BUCKET: &[(&str, &str)] = &[
    ("top.txt", "top"),
    ("logs/", ""),
    ("logs/2026/a.json", "aa"),
    ("logs/2026/b.log", "b"),
    ("logs/2025/c.json", "c"),
    ("empty/", ""),
    ("deep/x/y/z", "z"),
    ("meta/file", "f"),
    ("meta/link", "target"),
    ("sp ace/a+b%2F", "x"),
];

/// The lines a successful command printed, in order.
fn printed(output: &Output) -> Vec<String> {
    assert!(output.status.success(), "{}", output_text(output));
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn sorted(output: &Output) -> Vec<String> {
    let mut lines = printed(output);
    lines.sort();
    lines
}

fn lists(requests: &[String]) -> Vec<&String> {
    requests.iter().filter(|r| r.starts_with("LIST")).collect()
}

#[test]
fn find_and_ls_need_only_listings_and_report_each_directory_once() {
    let temp = test_support::tempdir().unwrap();
    let bucket = Bucket::start(BUCKET, Faults::default());
    let everything = [
        "deep",
        "deep/x",
        "deep/x/y",
        "deep/x/y/z",
        "empty",
        "logs",
        "logs/2025",
        "logs/2025/c.json",
        "logs/2026",
        "logs/2026/a.json",
        "logs/2026/b.log",
        "meta",
        "meta/file",
        "meta/link",
        "sp ace",
        "sp ace/a+b%2F",
        "top.txt",
    ];
    for requests in ["1", "4"] {
        let output = bucket.find(
            temp.path(),
            &[
                "find",
                "--on",
                "s3://bucket",
                "--performance-tuning",
                &format!("s3-requests={requests}"),
            ],
        );
        assert_eq!(sorted(&output), everything);
    }
    bucket.take();
    for args in [vec!["ls"], vec!["find", "--depth", "1"]] {
        let output = bucket.find(temp.path(), &[args, vec!["--on", "s3://bucket"]].concat());
        // A page's objects and directories print together in key order.
        assert_eq!(
            printed(&output),
            ["deep", "empty", "logs", "meta", "sp ace", "top.txt"]
        );
        // One delimiter listing of the bucket's root.
        assert_eq!(bucket.take(), ["LIST  /"]);
    }
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "--depth", "3"],
    );
    let shallow: Vec<&str> = everything
        .iter()
        .copied()
        .filter(|path| path.matches('/').count() < 3)
        .collect();
    assert_eq!(sorted(&output), shallow);
    // Roots: a directory, a directory with a slash, an object, a prefix base.
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "logs", "top.txt", "deep/"],
    );
    assert_eq!(
        sorted(&output),
        [
            "deep/x",
            "deep/x/y",
            "deep/x/y/z",
            "logs/2025",
            "logs/2025/c.json",
            "logs/2026",
            "logs/2026/a.json",
            "logs/2026/b.log",
            "top.txt",
        ]
    );
    let output = bucket.find(
        temp.path(),
        &["ls", "--on", "s3://bucket", "-C", "logs", "2026"],
    );
    assert_eq!(sorted(&output), ["2026/a.json", "2026/b.log"]);
    let output = bucket.find(temp.path(), &["ls", "--on", "s3://bucket", "empty"]);
    assert_eq!(sorted(&output), Vec::<String>::new());
    // Long and JSON output come from the listing too.
    let output = bucket.find(
        temp.path(),
        &["ls", "--on", "s3://bucket", "--long", "logs/2026"],
    );
    let long = sorted(&output);
    assert!(
        long.iter()
            .any(|line| line == "file          2 B 2026-01-01 00:00:00  logs/2026/a.json"),
        "{long:?}"
    );
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "--json", "logs"],
    );
    let json = sorted(&output);
    assert_eq!(json[0], r#"{"path":"logs/2025","kind":"dir"}"#);
    assert_eq!(
        json[1],
        r#"{"path":"logs/2025/c.json","kind":"file","size":1,"s3_last_modified":1767225600,"etag":"\"tag\""}"#
    );
    assert!(bucket
        .take()
        .iter()
        .all(|request| request.starts_with("LIST")));

    // A missing root fails before any output.
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "logs", "missing"],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("missing"),
        "{}",
        output_text(&output)
    );
}

#[test]
fn path_conditions_narrow_listings_and_other_fields_need_head_requests() {
    let temp = test_support::tempdir().unwrap();
    let bucket = Bucket::start(BUCKET, Faults::default());
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "path glob 'logs/2026/*' and size > 1B",
        ],
    );
    assert_eq!(sorted(&output), ["logs/2026/a.json"]);
    let requests = bucket.take();
    assert!(
        lists(&requests)
            .iter()
            .all(|r| r.starts_with("LIST logs/2026/")),
        "{requests:?}"
    );
    // To a depth, only directories that may hold a match are listed.
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--depth",
            "9",
            "--where",
            "path glob 'logs/*/*.json'",
        ],
    );
    assert_eq!(sorted(&output), ["logs/2025/c.json", "logs/2026/a.json"]);
    let requests = bucket.take();
    assert!(
        !requests
            .iter()
            .any(|r| r.starts_with("LIST deep") || r.starts_with("LIST meta")),
        "{requests:?}"
    );
    // A condition that no path beneath the root can meet lists nothing.
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "logs",
            "--where",
            "path = 'top.txt'",
        ],
    );
    assert_eq!(sorted(&output), Vec::<String>::new());
    assert_eq!(lists(&bucket.take()).len(), 1, "finding the root only");
    // Directories are filtered too, from the listing alone.
    let output = bucket.find(
        temp.path(),
        &[
            "ls",
            "--on",
            "s3://bucket",
            "--where",
            "size is null and name != 'meta'",
        ],
    );
    assert_eq!(sorted(&output), ["deep", "empty", "logs", "sp ace"]);
    assert!(bucket.take().iter().all(|r| r.starts_with("LIST")));

    // Stored metadata needs a HEAD request for each object, not directory.
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "meta",
            "--json",
            "--include",
            "kind,mtime,mode,uid,gid",
        ],
    );
    assert_eq!(
        sorted(&output),
        [
            r#"{"path":"meta/file","kind":"file","mtime":1700000000,"mode":420,"uid":1000,"gid":1001}"#,
            r#"{"path":"meta/link","kind":"symlink","mtime":1700000000,"mode":420,"uid":1000,"gid":1001}"#,
        ]
    );
    let heads: Vec<_> = bucket
        .take()
        .into_iter()
        .filter(|r| r.starts_with("HEAD"))
        .collect();
    assert_eq!(heads.len(), 2, "{heads:?}");
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "kind = 'symlink' or (kind = 'dir' and name = 'deep')",
        ],
    );
    assert_eq!(sorted(&output), ["deep", "meta/link"]);

    // A path condition after one that may fail narrows nothing: division by
    // zero fails on the first listed object instead of skipping `tree`.
    bucket.take();
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "size / 0 = 0B and path = 'tree/missing'",
        ],
    );
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("division by zero"),
        "{}",
        output_text(&output)
    );
    let requests = bucket.take();
    assert!(
        lists(&requests).iter().all(|r| !r.contains("tree")),
        "{requests:?}"
    );
}

/// Whether an object is a directory is known from its key, so comparing
/// its kind with "dir" needs no HEAD request, which a policy that allows
/// only listing refuses.
#[test]
fn kind_compared_with_dir_needs_no_head_request() {
    let temp = test_support::tempdir().unwrap();
    let bucket = Bucket::start(
        BUCKET,
        Faults {
            list_only: true,
            ..Faults::default()
        },
    );
    let output = bucket.find(
        temp.path(),
        &["ls", "--on", "s3://bucket", "--where", "kind = \"dir\""],
    );
    assert_eq!(sorted(&output), ["deep", "empty", "logs", "meta", "sp ace"]);
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "--where", "kind != \"dir\""],
    );
    assert_eq!(
        sorted(&output),
        [
            "deep/x/y/z",
            "logs/2025/c.json",
            "logs/2026/a.json",
            "logs/2026/b.log",
            "meta/file",
            "meta/link",
            "sp ace/a+b%2F",
            "top.txt",
        ]
    );
    let requests = bucket.take();
    assert!(
        requests.iter().all(|r| r.starts_with("LIST")),
        "{requests:?}"
    );
    // Another kind still needs the object's metadata.
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "--where", "kind = \"file\""],
    );
    assert!(!output.status.success(), "{}", output_text(&output));
}

/// A HEAD request gives Last-Modified to the second, a listing to the
/// millisecond; an object that needed a HEAD request is compared with the
/// listing's time.
#[test]
fn a_head_request_keeps_the_listed_time() {
    let temp = test_support::tempdir().unwrap();
    let bucket = Bucket::start(&[("plain", "x")], Faults::default());
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "s3_last_modified > timestamp('2026-01-01T00:00:00.250Z') and mtime is null",
        ],
    );
    assert_eq!(sorted(&output), ["plain"]);
    assert_eq!(
        bucket
            .take()
            .iter()
            .filter(|r| r.starts_with("HEAD"))
            .count(),
        1
    );
    // An omitted listing LastModified stays null when HEAD returns one.
    let bucket = Bucket::start(
        &[("plain", "x")],
        Faults {
            omit_list_time: true,
            ..Faults::default()
        },
    );
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "s3_last_modified is null and mtime is null",
        ],
    );
    assert_eq!(sorted(&output), ["plain"]);
    assert_eq!(
        bucket
            .take()
            .iter()
            .filter(|r| r.starts_with("HEAD"))
            .count(),
        1
    );
    // A path condition after one that may send HEAD narrows nothing, so a
    // HEAD failure is still reported regardless of concurrency.
    let bucket = Bucket::start(
        &[("tree/private", "x"), ("tree/public", "x")],
        Faults {
            deny_head: Some("tree/private"),
            ..Faults::default()
        },
    );
    for extra in [&[][..], &["--performance-tuning", "s3-requests=1"][..]] {
        let mut args = vec![
            "find",
            "--on",
            "s3://bucket",
            "tree/",
            "--where",
            "mtime is null and path = 'tree/public'",
        ];
        args.extend_from_slice(extra);
        let output = bucket.find(temp.path(), &args);
        assert!(
            !output.status.success(),
            "{extra:?}: {}",
            output_text(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("403"),
            "{extra:?}: {}",
            output_text(&output)
        );
    }
}

/// An object and keys under its name followed by `/` both print as that
/// name; `--json` tells them apart by kind. A `PATH` names the object.
#[test]
fn an_object_and_a_directory_can_share_a_name() {
    let temp = test_support::tempdir().unwrap();
    let bucket = Bucket::start(
        &[("tree/a", "object"), ("tree/a/child", "c"), ("tree/b", "b")],
        Faults::default(),
    );
    let output = bucket.find(temp.path(), &["find", "--on", "s3://bucket", "tree"]);
    assert_eq!(
        sorted(&output),
        ["tree/a", "tree/a", "tree/a/child", "tree/b"]
    );
    let output = bucket.find(
        temp.path(),
        &["ls", "--on", "s3://bucket", "tree", "--json"],
    );
    let json = printed(&output);
    assert_eq!(json.len(), 3, "{json:?}");
    assert!(
        json[0].starts_with(r#"{"path":"tree/a","kind":"file","size":6,"#),
        "{json:?}"
    );
    assert_eq!(json[1], r#"{"path":"tree/a","kind":"dir"}"#);
    assert!(
        json[2].starts_with(r#"{"path":"tree/b","kind":"file","#),
        "{json:?}"
    );
    let output = bucket.find(temp.path(), &["find", "--on", "s3://bucket", "tree/a"]);
    assert_eq!(sorted(&output), ["tree/a"]);
    let output = bucket.find(temp.path(), &["find", "--on", "s3://bucket", "tree/a/"]);
    assert_eq!(sorted(&output), ["tree/a/child"]);
}

/// S3 directory buckets and their access points list only prefixes that
/// are empty or end with `/`, and the fixture refuses others. Roots and
/// path conditions still find what they name, and a glob still keeps the
/// listing to the directories that can hold a match.
#[test]
fn directory_buckets_are_listed_with_prefixes_that_end_with_a_slash() {
    let temp = test_support::tempdir().unwrap();
    let bucket = Bucket::start(
        &[
            ("file", "f"),
            ("logs/file", "x"),
            ("logs/filed/more", "x"),
            ("logs/2025-12/service-a/old.json", "x"),
            ("logs/2026-01/service-a/a.json", "x"),
            ("logs/2026-01/service-a/a.txt", "x"),
            ("logs/2026-01/service-b/b.json", "x"),
            ("logs/2026-02/service-a/c.json", "x"),
            ("other/x", "x"),
        ],
        Faults::default(),
    );
    for name in ["dir--usw2-az1--x-s3", "point--usw2-az1--xa-s3"] {
        let on = format!("s3://{name}");
        for slots in ["1", "32"] {
            let find = |args: &[&str]| {
                let tuning = format!("s3-requests={slots}");
                let output = bucket.find(
                    temp.path(),
                    &[args, &["--on", &on, "--performance-tuning", &tuning][..]].concat(),
                );
                let case = format!("{name} {slots} {args:?}");
                let requests = bucket.take();
                assert!(
                    lists(&requests)
                        .iter()
                        .all(|r| r.trim_end_matches(" /") == "LIST "
                            || r.trim_end_matches(" /").ends_with('/')),
                    "{case}: {requests:?}"
                );
                (sorted(&output), requests)
            };
            assert_eq!(
                find(&["ls", "logs"]).0,
                [
                    "logs/2025-12",
                    "logs/2026-01",
                    "logs/2026-02",
                    "logs/file",
                    "logs/filed",
                ]
            );
            assert_eq!(find(&["find", "file"]).0, ["file"]);
            assert_eq!(find(&["find", "logs/file"]).0, ["logs/file"]);
            assert_eq!(find(&["find", "logs/filed"]).0, ["logs/filed/more"]);
            assert_eq!(
                find(&["find", "--where", "path = 'logs/file'"]).0,
                ["logs/file"]
            );
            let (found, requests) = find(&[
                "find",
                "--where",
                "path glob 'logs/2026-*/service-a/*.json'",
            ]);
            assert_eq!(
                found,
                [
                    "logs/2026-01/service-a/a.json",
                    "logs/2026-02/service-a/c.json",
                ]
            );
            if slots == "32" {
                assert!(
                    !requests.iter().any(|r| r.contains("2025-12")
                        || r.contains("service-b")
                        || r.contains("other")),
                    "{name}: {requests:?}"
                );
            }
            let output = bucket.find(temp.path(), &["find", "--on", &on, "missing"]);
            assert!(!output.status.success(), "{}", output_text(&output));
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("no objects under"),
                "{}",
                output_text(&output)
            );
            bucket.take();
        }
    }
}

#[test]
fn keys_are_decoded_and_a_failed_page_fails_the_listing() {
    let temp = test_support::tempdir().unwrap();
    let keys: Vec<(String, &str)> = (0..1001)
        .map(|i| (format!("prefix/k{i:04}"), "x"))
        .chain([
            ("prefix/line\nbreak%2F".to_owned(), "x"),
            ("prefix/a+b".into(), "x"),
        ])
        .collect();
    let keys: Vec<(&str, &str)> = keys
        .iter()
        .map(|(key, body)| (key.as_str(), *body))
        .collect();
    let bucket = Bucket::start(&keys, Faults::default());
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "--null", "prefix"],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    let paths: Vec<&[u8]> = output
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .collect();
    assert_eq!(paths.len(), 1003);
    assert!(paths.contains(&&b"prefix/line\nbreak%2F"[..]));
    assert!(paths.contains(&&b"prefix/a+b"[..]));

    let bucket = Bucket::start(
        &keys,
        Faults {
            partial: true,
            ..Faults::default()
        },
    );
    for args in [vec!["find"], vec!["ls"]] {
        let output = bucket.find(
            temp.path(),
            &[
                args,
                vec![
                    "--on",
                    "s3://bucket",
                    "prefix/",
                    "--performance-tuning",
                    "s3-requests=1",
                ],
            ]
            .concat(),
        );
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("403"),
            "{}",
            output_text(&output)
        );
    }
    let bucket = Bucket::start(
        &keys,
        Faults {
            missing_token: true,
            ..Faults::default()
        },
    );
    let output = bucket.find(temp.path(), &["find", "--on", "s3://bucket", "prefix/"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("continuation token"),
        "{}",
        output_text(&output)
    );
}

/// Where a policy lets only the prefix itself be listed, a listing divided
/// by directory or narrowed by a path condition fails; with nothing printed
/// yet, the listing starts over with one request at a time, which lists
/// only the prefix.
#[test]
fn a_listing_only_the_prefix_may_make_starts_over_with_one_request() {
    let temp = test_support::tempdir().unwrap();
    let keys: Vec<(String, &str)> = (0..40)
        .flat_map(|d| (0..60).map(move |i| (format!("tree/d{d:02}/{i:04}"), "x")))
        .chain([("tree/a".to_owned(), "a"), ("tree/sub/x".to_owned(), "x")])
        .collect();
    let keys: Vec<(&str, &str)> = keys
        .iter()
        .map(|(key, body)| (key.as_str(), *body))
        .collect();
    let bucket = Bucket::start(
        &keys,
        Faults {
            only: Some("tree/"),
            ..Faults::default()
        },
    );
    let output = bucket.find(temp.path(), &["find", "--on", "s3://bucket", "tree/"]);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).lines().count(),
        40 * 60 + 40 + 3
    );
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "tree/",
            "--where",
            "path = 'tree/a'",
        ],
    );
    assert_eq!(sorted(&output), ["tree/a"]);
    // With one request at a time, an unfiltered listing sends only requests
    // for the prefix itself; a narrowed listing still narrows and falls back
    // if refused before printing.
    bucket.take();
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "tree/",
            "--performance-tuning",
            "s3-requests=1",
        ],
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).lines().count(),
        40 * 60 + 40 + 3
    );
    let requests = bucket.take();
    assert!(requests.iter().all(|r| r == "LIST tree/"), "{requests:?}");

    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "tree/",
            "--where",
            "path glob 'tree/sub/**'",
            "--performance-tuning",
            "s3-requests=1",
        ],
    );
    assert_eq!(sorted(&output), ["tree/sub/x"]);
    let requests = bucket.take();
    assert_eq!(
        requests,
        [
            "LIST tree/",
            "LIST tree/sub/",
            "LIST tree/",
            "LIST tree/",
            "LIST tree/",
        ],
        "{requests:?}"
    );
    // On a normal bucket, s3-requests=1 still narrows to the path condition.
    let normal = Bucket::start(&keys, Faults::default());
    let output = normal.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "tree/",
            "--where",
            "path = 'tree/a'",
            "--performance-tuning",
            "s3-requests=1",
        ],
    );
    assert_eq!(sorted(&output), ["tree/a"]);
    let requests = normal.take();
    assert_eq!(requests, ["LIST tree/", "LIST tree/a"], "{requests:?}");
    // A PATH without a slash names the object or the directory; a policy
    // that refuses the listing of the object's key leaves the directory.
    let output = bucket.find(temp.path(), &["ls", "--on", "s3://bucket", "tree"]);
    let listed = sorted(&output);
    assert_eq!(listed.len(), 42, "{listed:?}");
    assert!(
        ["tree/a", "tree/d00", "tree/sub"]
            .iter()
            .all(|path| listed.iter().any(|line| line == path)),
        "{listed:?}"
    );
    // To a depth, every directory needs its own listing.
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "tree/", "--depth", "2"],
    );
    assert!(!output.status.success());

    // Sequential mode also disables ignore lookahead probes, so --ignore works
    // when only the root prefix may be listed.
    let ignored_keys: Vec<(String, &str)> = (0..1001)
        .map(|i| (format!("tree/a/{i:04}"), "x"))
        .chain([("tree/z/keep".to_owned(), "x")])
        .collect();
    let ignored_keys: Vec<(&str, &str)> = ignored_keys
        .iter()
        .map(|(key, body)| (key.as_str(), *body))
        .collect();
    let bucket = Bucket::start(
        &ignored_keys,
        Faults {
            only: Some("tree/"),
            ..Faults::default()
        },
    );
    for extra in [&[][..], &["--performance-tuning", "s3-requests=1"][..]] {
        let mut args = vec!["find", "--on", "s3://bucket", "tree/", "--ignore", "a/"];
        args.extend_from_slice(extra);
        let output = bucket.find(temp.path(), &args);
        assert_eq!(sorted(&output), ["tree/z", "tree/z/keep"], "{extra:?}");
        let requests = bucket.take();
        if !extra.is_empty() {
            assert!(requests.iter().all(|r| r == "LIST tree/"), "{requests:?}");
        }
    }
}

#[test]
fn find_and_ls_help_and_invalid_arguments() {
    for (args, visible) in [
        (vec!["help"], true),
        (vec!["--help"], true),
        (vec!["--help-all"], true),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .capture_output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert_eq!(help.contains("\n  find "), visible, "{help}");
        assert_eq!(help.contains("\n  ls "), visible, "{help}");
        assert!(!help.contains("_ls"));
    }
    for args in [["find", "--help"], ["help", "ls"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .capture_output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--where"), "{help}");
        assert!(help.contains("--on"), "{help}");
    }
    for (args, message) in [
        (vec!["_ls", "s3://bucket/**"], "unrecognized command"),
        (
            vec![
                "find",
                "--on",
                "s3://bucket",
                "--performance-tuning",
                "s3-requests=0",
            ],
            "s3-requests",
        ),
        (
            vec![
                "find",
                "--on",
                "s3://bucket",
                "--performance-tuning",
                "workers=2",
            ],
            "s3-requests",
        ),
        (
            vec!["find", "--performance-tuning", "s3-requests=2"],
            "S3 listings",
        ),
        (vec!["find", "--s3-region", "us-east-1"], "--on s3://BUCKET"),
        (
            vec!["find", "--on", "s3://bucket", "--follow"],
            "filesystem endpoint",
        ),
        (vec!["find", "--rsh", "ssh"], "SSH endpoint"),
        (vec!["find", "--json", "--include", "etag"], "S3 endpoint"),
        (
            vec![
                "find",
                "--on",
                "s3://bucket",
                "--json",
                "--include",
                "ctime",
            ],
            "filesystem endpoint",
        ),
        (vec!["find", "--include", "kind"], "--json"),
        (vec!["find", "--depth", "0"], "0"),
        (vec!["find", "--long", "--json"], "cannot be used"),
        (vec!["find", "--where", "dst.size > 0B"], "no destination"),
        (vec!["find", "--ignore", "-"], "--ignore=-"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(&args)
            .capture_output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{args:?}: {}",
            output_text(&output)
        );
    }
}

#[test]
fn null_comparisons_do_not_fail_and_skip_s3_directories_when_possible() {
    let temp = test_support::tempdir().unwrap();
    let bucket = Bucket::start(BUCKET, Faults::default());

    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "--where", "size > 1B"],
    );
    assert_eq!(
        sorted(&output),
        ["logs/2026/a.json", "meta/link", "top.txt"]
    );
    let output = bucket.find(
        temp.path(),
        &["ls", "--on", "s3://bucket", "--where", "size > 1B"],
    );
    assert_eq!(sorted(&output), ["top.txt"]);
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "s3_last_modified > timestamp('2020-01-01T00:00:00Z')",
        ],
    );
    assert_eq!(
        sorted(&output),
        [
            "deep/x/y/z",
            "logs/2025/c.json",
            "logs/2026/a.json",
            "logs/2026/b.log",
            "meta/file",
            "meta/link",
            "sp ace/a+b%2F",
            "top.txt",
        ]
    );
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "--where", "not (size > 1B)"],
    );
    assert_eq!(
        sorted(&output),
        [
            "deep/x/y/z",
            "logs/2025/c.json",
            "logs/2026/b.log",
            "meta/file",
            "sp ace/a+b%2F",
        ]
    );

    bucket.take();
    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "size > 1B and path glob 'logs/*'",
        ],
    );
    assert_eq!(sorted(&output), Vec::<String>::new());
    let requests = bucket.take();
    assert_eq!(requests, ["LIST logs/ /"], "{requests:?}");

    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "size > 1B and path glob 'logs/*/*.json'",
        ],
    );
    assert_eq!(sorted(&output), ["logs/2026/a.json"]);
    let requests = bucket.take();
    assert!(
        !requests
            .iter()
            .any(|r| r.starts_with("LIST deep") || r.starts_with("LIST meta")),
        "{requests:?}"
    );

    let output = bucket.find(
        temp.path(),
        &[
            "find",
            "--on",
            "s3://bucket",
            "--where",
            "s3_last_modified > now - 36500d and path glob 'logs/2026/*'",
        ],
    );
    assert_eq!(sorted(&output), ["logs/2026/a.json", "logs/2026/b.log"]);
    let requests = bucket.take();
    assert_eq!(requests, ["LIST logs/2026/ /"], "{requests:?}");
}
