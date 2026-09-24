use super::*;
use std::sync::Mutex;

struct MapServer {
    address: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl MapServer {
    fn new(mode: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopping = stop.clone();
        let observed = requests.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    if socket.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap();
                let first = request.lines().next().unwrap_or("").to_owned();
                observed.lock().unwrap().push(first.clone());
                let mut parts = first.split_whitespace();
                let method = parts.next().unwrap();
                let path = parts.next().unwrap();
                if path.contains("list-type=2") {
                    assert_eq!(method, "GET");
                    assert!(path.contains("encoding-type=url"));
                    let second = path.contains("continuation-token=next");
                    if mode == "bad-token" {
                        reply(&mut socket, 200, &[], b"<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken></NextContinuationToken></ListBucketResult>", false);
                        continue;
                    }
                    if second && mode == "fail" {
                        reply(
                            &mut socket,
                            403,
                            &[],
                            b"<Error><Code>AccessDenied</Code></Error>",
                            false,
                        );
                        continue;
                    }
                    let contents = if mode == "nonempty-slash" {
                        "<Contents><Key>prefix%2F</Key><Size>4</Size></Contents>".to_owned()
                    } else if mode == "nonempty-child-slash" {
                        "<Contents><Key>prefix%2Fchild%2F</Key><Size>4</Size></Contents>".to_owned()
                    } else if mode == "invalid" {
                        "<Contents><Key>prefix%2Fa%2F%2Fb</Key><Size>1</Size></Contents>".to_owned()
                    } else if second {
                        "<Contents><Key>prefix%2Fempty%2F</Key><Size>0</Size><LastModified>2026-01-01T00:00:00Z</LastModified></Contents><Contents><Key>prefix%2Flink</Key><Size>4</Size><LastModified>2026-01-01T00:00:00Z</LastModified></Contents>".to_owned()
                    } else {
                        "<Contents><Key>prefix%2F</Key><Size>0</Size></Contents><Contents><Key>prefix%2Fnested%2Fline%0A%252F%2B</Key><Size>4</Size><LastModified>2026-01-01T00:00:00Z</LastModified></Contents>".to_owned()
                    };
                    let truncated = !second && mode != "invalid";
                    let body = format!("<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>{truncated}</IsTruncated>{}{contents}</ListBucketResult>", if truncated { "<NextContinuationToken>next</NextContinuationToken>" } else { "" });
                    reply(&mut socket, 200, &[], body.as_bytes(), false);
                    continue;
                }
                let key = percent_encoding::percent_decode_str(path.split('?').next().unwrap())
                    .decode_utf8()
                    .unwrap();
                let key = key.strip_prefix("/bucket/").unwrap();
                let marker = key == "prefix/empty/" || key == "prefix/";
                let link = key == "prefix/link";
                let file = key == "prefix/nested/line\n%2F+";
                if !marker && !link && !file {
                    reply(&mut socket, 404, &[], b"", method == "HEAD");
                    continue;
                }
                assert!(method == "HEAD" || method == "GET", "{first}");
                let body: &[u8] = if marker { b"" } else { b"data" };
                let mut fields = vec![
                    ("Content-Length".into(), body.len().to_string()),
                    ("ETag".into(), "\"fixture\"".into()),
                    (
                        "Last-Modified".into(),
                        "Thu, 01 Jan 2026 00:00:00 GMT".into(),
                    ),
                ];
                // A third-party directory marker has no syq timestamp.
                if file || link {
                    for (name, value) in [
                        (
                            "syq-format",
                            if mode == "unknown-metadata" {
                                "99"
                            } else {
                                "1"
                            },
                        ),
                        ("syq-kind", if link { "symlink" } else { "file" }),
                        ("syq-mode", "420"),
                        ("syq-uid", "0"),
                        ("syq-gid", "0"),
                        ("syq-mtime", "123"),
                        ("syq-mtime-nsec", "0"),
                    ] {
                        fields.push((format!("x-amz-meta-{name}"), value.to_owned()));
                    }
                }
                reply(&mut socket, 200, &fields, body, method == "HEAD");
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    fn command(&self, temp: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(args)
            .args(["--s3-region", "us-east-1", "--s3-endpoint", &self.address])
            .env("AWS_ACCESS_KEY_ID", "test-access")
            .env("AWS_SECRET_ACCESS_KEY", "test-secret")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env("AWS_CONFIG_FILE", temp.join("no-config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", temp.join("no-credentials"))
            .env("AWS_EC2_METADATA_DISABLED", "true");
        command
    }
}
impl Drop for MapServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn records(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn s3_map_default_round_trip_uses_only_listing_and_selector_head() {
    let temp = test_support::tempdir().unwrap();
    let server = MapServer::new("ok");
    let output = server
        .command(
            temp.path(),
            &["map", "--from", "s3://bucket", "--srcs-in", "prefix"],
        )
        .capture_output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let entries = records(&output);
    assert_eq!(entries.len(), 3);
    assert!(entries
        .iter()
        .all(|entry| entry.as_object().unwrap().len() == 2));
    assert_eq!(entries[0]["src"]["value"], "nested/line\n%2F+");
    assert_eq!(entries[1]["src"]["value"], "empty");
    let observed = server.requests.lock().unwrap().clone();
    assert_eq!(observed.len(), 3, "{observed:?}");
    assert_eq!(
        observed.iter().filter(|r| r.starts_with("HEAD ")).count(),
        1
    );
    let mut entries = entries;
    for entry in &mut entries {
        entry["dst"]["value"] =
            format!("renamed/{}", entry["dst"]["value"].as_str().unwrap()).into();
    }
    let manifest = temp.path().join("mapping.ndjson");
    std::fs::write(
        &manifest,
        entries
            .iter()
            .map(|entry| format!("{entry}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let dest = temp.path().join("copied");
    let copied = server
        .command(
            temp.path(),
            &[
                "cp",
                "--from",
                "s3://bucket",
                "-C",
                "prefix",
                "--mapping",
                manifest.to_str().unwrap(),
                "--into",
                dest.to_str().unwrap(),
                "-q",
            ],
        )
        .capture_output()
        .unwrap();
    assert!(
        copied.status.success(),
        "{}",
        String::from_utf8_lossy(&copied.stderr)
    );
    assert_eq!(
        std::fs::read(dest.join("renamed/nested/line\n%2F+")).unwrap(),
        b"data"
    );
    assert!(dest.join("renamed/empty").is_dir());
    assert_eq!(
        std::fs::read_link(dest.join("renamed/link")).unwrap(),
        Path::new("data")
    );
}

#[test]
fn s3_map_fields_keep_times_distinct_and_request_only_needed_metadata() {
    let temp = test_support::tempdir().unwrap();
    for (include, expected_heads) in [
        ("size,s3_last_modified", 1),
        ("kind,mtime,s3_last_modified", 4),
    ] {
        let server = MapServer::new("ok");
        let output = server
            .command(
                temp.path(),
                &[
                    "map",
                    "--from",
                    "s3://bucket",
                    "--srcs-in",
                    "prefix",
                    "--include",
                    include,
                ],
            )
            .capture_output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let entries = records(&output);
        assert_eq!(entries[0]["s3_last_modified"], 1767225600i64);
        if include.contains("mtime") {
            assert_eq!(entries[0]["mtime"], 123);
            assert_eq!(entries[2]["kind"], "symlink");
            assert!(entries[1].get("mtime").is_none());
            assert!(entries[0].get("size").is_none());
        } else {
            assert_eq!(entries[0]["size"], 4);
            assert!(entries[0].get("mtime").is_none());
            assert!(entries[0].get("kind").is_none());
        }
        assert_eq!(
            server
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.starts_with("HEAD "))
                .count(),
            expected_heads
        );
    }
}

#[test]
fn s3_map_refuses_partial_listing_and_unrepresentable_keys() {
    let temp = test_support::tempdir().unwrap();
    for mode in ["fail", "invalid", "bad-token"] {
        let server = MapServer::new(mode);
        let output = server
            .command(
                temp.path(),
                &["map", "--from", "s3://bucket", "--srcs-in", "prefix"],
            )
            .capture_output()
            .unwrap();
        assert!(!output.status.success());
        if mode == "fail" {
            assert_eq!(records(&output).len(), 1);
        } else {
            assert!(output.stdout.is_empty());
        }
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn s3_map_exact_object_keeps_source_base_and_does_not_decode_unused_metadata() {
    let temp = test_support::tempdir().unwrap();
    let server = MapServer::new("unknown-metadata");
    let args = [
        "map",
        "--from",
        "s3://bucket",
        "-C",
        "prefix",
        "nested/line\n%2F+",
        "--as",
        "renamed/file",
        "--include",
        "size,s3_last_modified",
    ];
    let output = server.command(temp.path(), &args).capture_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let entries = records(&output);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["src"]["value"], "nested/line\n%2F+");
    assert_eq!(entries[0]["dst"]["value"], "renamed/file");
    assert_eq!(entries[0]["size"], 4);
    assert_eq!(entries[0]["s3_last_modified"], 1767225600i64);
    assert_eq!(server.requests.lock().unwrap().len(), 1);
    let output = server
        .command(temp.path(), &args)
        .args(["--include", "mtime"])
        .capture_output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn s3_map_rejects_nonempty_slash_objects_for_named_and_contents_selectors() {
    let temp = test_support::tempdir().unwrap();
    for mode in ["nonempty-slash", "nonempty-child-slash"] {
        for selector in ["--srcs-in", "--src-dir", "--src"] {
            for include in [None, Some("kind,mtime")] {
                let server = MapServer::new(mode);
                let mut command = server.command(
                    temp.path(),
                    &["map", "--from", "s3://bucket", selector, "prefix"],
                );
                if let Some(include) = include {
                    command.args(["--include", include]);
                }
                let output = command.capture_output().unwrap();
                assert!(!output.status.success(), "{mode} {selector}: {output:?}");
                assert!(output.stdout.is_empty());
                assert!(String::from_utf8_lossy(&output.stderr).contains("not a directory marker"));
                assert_eq!(
                    server.requests.lock().unwrap().len(),
                    2,
                    "no object metadata or body should be read"
                );
            }
        }
    }
}
