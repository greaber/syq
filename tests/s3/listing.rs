use super::*;
use std::{collections::BTreeMap, sync::Mutex};

/// A bucket served from memory: ListObjectsV2 with prefixes, the delimiter
/// `/` and pages of up to `max-keys`, and HEAD with syq metadata. Every
/// request is logged.
struct Bucket {
    address: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

/// How the bucket fails: `only` lists only that prefix, refusing others;
/// `partial` refuses the second page of every listing.
#[derive(Clone, Copy, Default)]
struct Faults {
    only: Option<&'static str>,
    partial: bool,
    missing_token: bool,
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
    /// `/` after it for a delimiter listing.
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
    if method == "HEAD" {
        let key = path.strip_prefix("/bucket/").unwrap();
        observed.lock().unwrap().push(format!("HEAD {key}"));
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
    let query: BTreeMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query.get("list-type").map(String::as_str), Some("2"));
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    let delimiter = query.contains_key("delimiter");
    observed.lock().unwrap().push(format!(
        "LIST {prefix}{}",
        if delimiter { " /" } else { "" }
    ));
    let token = query.get("continuation-token");
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
            body.push_str(&format!(
                "<Contents><Key>{}</Key><Size>{}</Size><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;tag&quot;</ETag></Contents>",
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

fn sorted(output: &Output) -> Vec<String> {
    assert!(output.status.success(), "{}", output_text(output));
    let mut lines: Vec<String> = String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
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
        assert_eq!(
            sorted(&output),
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
/// by directory fails; with nothing printed yet, the listing starts over
/// with one request at a time.
#[test]
fn a_listing_only_the_prefix_may_make_starts_over_with_one_request() {
    let temp = test_support::tempdir().unwrap();
    let keys: Vec<(String, &str)> = (0..40)
        .flat_map(|d| (0..60).map(move |i| (format!("tree/d{d:02}/{i:04}"), "x")))
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
        40 * 60 + 40
    );
    // To a depth, every directory needs its own listing.
    let output = bucket.find(
        temp.path(),
        &["find", "--on", "s3://bucket", "tree/", "--depth", "2"],
    );
    assert!(!output.status.success());
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
