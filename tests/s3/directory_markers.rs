use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone)]
struct StoredObject {
    body: Vec<u8>,
    meta: BTreeMap<String, String>,
}

type InitialObject<'a> = (&'a str, &'a str, &'a [u8], &'a [(&'a str, &'a str)]);

struct MemoryStore {
    address: String,
    objects: Arc<Mutex<BTreeMap<(String, String), StoredObject>>>,
    puts: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn extract_xml_keys(xml: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Key>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</Key>") else {
            break;
        };
        keys.push(after[..end].to_owned());
        rest = &after[end + 6..];
    }
    keys
}

impl MemoryStore {
    fn start(initial: &[InitialObject<'_>]) -> Self {
        let mut seed = BTreeMap::new();
        for &(bucket, key, body, meta_pairs) in initial {
            let meta = meta_pairs
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), (*v).to_owned()))
                .collect();
            seed.insert(
                (bucket.to_owned(), key.to_owned()),
                StoredObject {
                    body: body.to_vec(),
                    meta,
                },
            );
        }
        let objects = Arc::new(Mutex::new(seed));
        let puts = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());

        let worker_objects = objects.clone();
        let worker_puts = puts.clone();
        let stopping = stop.clone();
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let (mut socket, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut raw = Vec::new();
                let mut byte = [0];
                while !raw.ends_with(b"\r\n\r\n") {
                    if socket.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    raw.push(byte[0]);
                    if raw.len() > 65536 {
                        break;
                    }
                }
                if raw.is_empty() {
                    continue;
                }
                let text = String::from_utf8(raw).unwrap();
                let first = text.lines().next().unwrap_or("");
                let mut parts = first.split_whitespace();
                let Some(method) = parts.next() else {
                    continue;
                };
                let Some(target) = parts.next() else {
                    continue;
                };
                let headers = text
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
                    .collect::<std::collections::HashMap<_, _>>();
                let content_len: usize = headers
                    .get("content-length")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0; content_len];
                if content_len > 0 {
                    socket.read_exact(&mut body).unwrap();
                }

                let url = url::Url::parse(&format!("http://fixture{target}")).unwrap();
                let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
                let path = percent_decode(url.path());
                let trimmed = path.strip_prefix('/').unwrap_or(&path);
                let (bucket, key) = match trimmed.split_once('/') {
                    Some((b, k)) => (b.to_owned(), k.to_owned()),
                    None => (trimmed.to_owned(), String::new()),
                };

                match method {
                    "GET" if query.contains_key("list-type") => {
                        let prefix = query.get("prefix").map(|v| v.as_ref()).unwrap_or("");
                        let delimiter = query.get("delimiter").map(|v| v.as_ref());
                        let mut contents = Vec::new();
                        let mut common_prefixes = std::collections::BTreeSet::new();
                        let guard = worker_objects.lock().unwrap();
                        for ((b, k), obj) in guard.iter() {
                            if b != &bucket || !k.starts_with(prefix) {
                                continue;
                            }
                            let rest = &k[prefix.len()..];
                            if let Some(delim) = delimiter {
                                if let Some(pos) = rest.find(delim) {
                                    common_prefixes
                                        .insert(format!("{prefix}{}", &rest[..pos + delim.len()]));
                                    continue;
                                }
                            }
                            contents.push((k.clone(), obj.body.len()));
                        }
                        drop(guard);
                        let mut xml =
                            String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
                        for (k, size) in contents {
                            xml.push_str(&format!(
                                "<Contents><Key>{k}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>\"e\"</ETag><Size>{size}</Size></Contents>"
                            ));
                        }
                        for p in common_prefixes {
                            xml.push_str(&format!(
                                "<CommonPrefixes><Prefix>{p}</Prefix></CommonPrefixes>"
                            ));
                        }
                        xml.push_str("</ListBucketResult>");
                        reply(&mut socket, 200, &[], xml.as_bytes(), false);
                    }
                    "HEAD" => {
                        let found = worker_objects
                            .lock()
                            .unwrap()
                            .get(&(bucket.clone(), key.clone()))
                            .cloned();
                        if let Some(obj) = found {
                            let mut fields = vec![
                                ("Content-Length".into(), obj.body.len().to_string()),
                                ("ETag".into(), "\"e\"".into()),
                                (
                                    "Last-Modified".into(),
                                    "Thu, 01 Jan 2026 00:00:00 GMT".into(),
                                ),
                            ];
                            for (k, v) in obj.meta {
                                fields.push((k, v));
                            }
                            reply(&mut socket, 200, &fields, b"", true);
                        } else {
                            reply(&mut socket, 404, &[], b"", true);
                        }
                    }
                    "PUT" => {
                        if let Some(copy_source) = headers.get("x-amz-copy-source") {
                            let copy_source = copy_source.split('?').next().unwrap_or(copy_source);
                            let decoded = percent_decode(copy_source.trim_start_matches('/'));
                            let (src_bucket, src_key) = decoded.split_once('/').unwrap();
                            let src_obj = worker_objects
                                .lock()
                                .unwrap()
                                .get(&(src_bucket.to_owned(), src_key.to_owned()))
                                .cloned();
                            let Some(src_obj) = src_obj else {
                                reply(
                                    &mut socket,
                                    404,
                                    &[],
                                    b"<Error><Code>NoSuchKey</Code></Error>",
                                    false,
                                );
                                continue;
                            };
                            let replace = headers
                                .get("x-amz-metadata-directive")
                                .is_some_and(|v| v.eq_ignore_ascii_case("REPLACE"));
                            let mut meta = if replace {
                                BTreeMap::new()
                            } else {
                                src_obj.meta.clone()
                            };
                            if replace {
                                for (k, v) in &headers {
                                    if k.starts_with("x-amz-meta-") {
                                        meta.insert(k.clone(), v.clone());
                                    }
                                }
                            }
                            worker_objects.lock().unwrap().insert(
                                (bucket.clone(), key.clone()),
                                StoredObject {
                                    body: src_obj.body,
                                    meta,
                                },
                            );
                            worker_puts.lock().unwrap().push(format!("{bucket}/{key}"));
                            reply(
                                &mut socket,
                                200,
                                &[("ETag".into(), "\"e\"".into())],
                                b"<CopyObjectResult><ETag>\"e\"</ETag></CopyObjectResult>",
                                false,
                            );
                        } else {
                            let mut meta = BTreeMap::new();
                            for (k, v) in &headers {
                                if k.starts_with("x-amz-meta-") {
                                    meta.insert(k.clone(), v.clone());
                                }
                            }
                            worker_objects
                                .lock()
                                .unwrap()
                                .insert((bucket.clone(), key.clone()), StoredObject { body, meta });
                            worker_puts.lock().unwrap().push(format!("{bucket}/{key}"));
                            reply(
                                &mut socket,
                                200,
                                &[("ETag".into(), "\"e\"".into())],
                                b"",
                                false,
                            );
                        }
                    }
                    "POST" if query.contains_key("delete") => {
                        let xml = String::from_utf8_lossy(&body);
                        let keys = extract_xml_keys(&xml);
                        let mut response = String::from("<?xml version=\"1.0\"?><DeleteResult>");
                        let mut guard = worker_objects.lock().unwrap();
                        for k in keys {
                            guard.remove(&(bucket.clone(), k.clone()));
                            response.push_str(&format!("<Deleted><Key>{k}</Key></Deleted>"));
                        }
                        response.push_str("</DeleteResult>");
                        reply(&mut socket, 200, &[], response.as_bytes(), false);
                    }
                    "DELETE" => {
                        worker_objects
                            .lock()
                            .unwrap()
                            .remove(&(bucket.clone(), key.clone()));
                        reply(&mut socket, 204, &[], b"", false);
                    }
                    _ => panic!("unexpected {method} {target}"),
                }
            }
        });
        Self {
            address,
            objects,
            puts,
            stop,
            worker: Some(worker),
        }
    }

    fn command(&self, temp: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "cp",
                "--s3-region",
                "us-east-1",
                "--s3-endpoint",
                &self.address,
                "--s3-retries=0",
                "--no-progress",
            ])
            .env("AWS_ACCESS_KEY_ID", "test-access")
            .env("AWS_SECRET_ACCESS_KEY", "test-secret")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AWS_ENDPOINT_URL")
            .env_remove("AWS_ENDPOINT_URL_S3")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_CONFIG_FILE", temp.join("no-config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", temp.join("no-credentials"))
            .env("XDG_CACHE_HOME", temp.join("cache"))
            .env(TREAT_HTTP_AS_HTTPS, "1")
            .current_dir(temp);
        command
    }

    fn cp(&self, temp: &Path, args: &[&str]) -> Output {
        self.command(temp).args(args).capture_output().unwrap()
    }

    fn keys(&self, bucket: &str) -> std::collections::BTreeSet<String> {
        self.objects
            .lock()
            .unwrap()
            .keys()
            .filter(|(b, _)| b == bucket)
            .map(|(_, k)| k.clone())
            .collect()
    }
}

impl Drop for MemoryStore {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn cli_refuses_invalid_and_non_destination_s3_directory_markers() {
    let temp = crate::test_support::tempdir().unwrap();
    std::fs::write(temp.path().join("f"), b"hi").unwrap();
    let store = MemoryStore::start(&[("bucket", "a", b"hi", &[])]);

    let bogus = store.cp(
        temp.path(),
        &[
            "f",
            "--to",
            "s3://bucket",
            "--into",
            "dst",
            "--s3-directory-markers=bogus",
        ],
    );
    assert_eq!(bogus.status.code(), Some(2), "{}", output_text(&bogus));

    let download = store.cp(
        temp.path(),
        &[
            "--from",
            "s3://bucket",
            "a",
            "--into",
            "local",
            "--s3-directory-markers=all",
        ],
    );
    assert_eq!(
        download.status.code(),
        Some(2),
        "{}",
        output_text(&download)
    );
    assert!(
        output_text(&download).contains("--s3-directory-markers requires an S3 destination"),
        "{}",
        output_text(&download)
    );
}

#[test]
fn local_to_s3_directory_markers_all_empty_and_none() {
    let temp = crate::test_support::tempdir().unwrap();
    let src = temp.path().join("src");
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::create_dir_all(src.join("nested/deep_empty")).unwrap();
    std::fs::create_dir_all(src.join("nested/empty_parent/only_subdir")).unwrap();
    std::fs::create_dir_all(src.join("with_file")).unwrap();
    std::fs::write(src.join("with_file/f"), b"hello").unwrap();
    std::fs::create_dir_all(src.join("filtered_out")).unwrap();
    std::fs::write(src.join("filtered_out/skip.txt"), b"ignored").unwrap();
    std::fs::create_dir_all(src.join("where_empty")).unwrap();
    std::fs::write(src.join("where_empty/drop.tmp"), b"dropped").unwrap();

    // 1. Default (`all`): every directory gets a marker.
    let store = MemoryStore::start(&[]);
    let out = store.cp(temp.path(), &["src", "--to", "s3://all", "--into", "dst"]);
    assert!(out.status.success(), "{}", output_text(&out));
    assert_eq!(
        store.keys("all"),
        [
            "dst/src/",
            "dst/src/empty/",
            "dst/src/filtered_out/",
            "dst/src/filtered_out/skip.txt",
            "dst/src/nested/",
            "dst/src/nested/deep_empty/",
            "dst/src/nested/empty_parent/",
            "dst/src/nested/empty_parent/only_subdir/",
            "dst/src/where_empty/",
            "dst/src/where_empty/drop.tmp",
            "dst/src/with_file/",
            "dst/src/with_file/f",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    // 2. `empty` with --ignore and --where: only leaf directories with no
    // surviving descendants emit markers, and trace/result counts match.
    let results = temp.path().join("empty-results.ndjson");
    let out = store.cp(
        temp.path(),
        &[
            "src",
            "--to",
            "s3://empty",
            "--into",
            "dst",
            "--s3-directory-markers=empty",
            "--ignore=*.txt",
            "--where",
            "src.extension != 'tmp'",
            "--results",
            results.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", output_text(&out));
    assert_eq!(
        store.keys("empty"),
        [
            "dst/src/empty/",
            "dst/src/filtered_out/",
            "dst/src/nested/deep_empty/",
            "dst/src/nested/empty_parent/only_subdir/",
            "dst/src/where_empty/",
            "dst/src/with_file/f",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    let records: Vec<serde_json::Value> = std::fs::read_to_string(&results)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let dir_ops: Vec<_> = records
        .iter()
        .filter(|r| r["type"] == "operation_result" && r["action"] == "create_directory")
        .collect();
    assert_eq!(dir_ops.len(), 5, "{records:?}");
    let summary = records.last().unwrap();
    assert_eq!(summary["type"], "result");
    assert_eq!(summary["directories_created"], 5);
    assert_eq!(summary["files_transferred"], 1);

    // 3. `empty` + `--copy-if "src.name != 'f'"`: files skipped only by destination
    // policy still keep parent directories non-empty (no spurious marker).
    let out = store.cp(
        temp.path(),
        &[
            "src",
            "--to",
            "s3://copyif",
            "--into",
            "dst",
            "--s3-directory-markers=empty",
            "--ignore=*.txt",
            "--where",
            "src.extension != 'tmp'",
            "--copy-if",
            "src.name != 'f'",
        ],
    );
    assert!(out.status.success(), "{}", output_text(&out));
    assert_eq!(
        store.keys("copyif"),
        [
            "dst/src/empty/",
            "dst/src/filtered_out/",
            "dst/src/nested/deep_empty/",
            "dst/src/nested/empty_parent/only_subdir/",
            "dst/src/where_empty/",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    // 4. `none`: no directory markers at all.
    let none_results = temp.path().join("none-results.ndjson");
    let out = store.cp(
        temp.path(),
        &[
            "src",
            "--to",
            "s3://none",
            "--into",
            "dst",
            "--s3-directory-markers=none",
            "--results",
            none_results.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", output_text(&out));
    assert_eq!(
        store.keys("none"),
        [
            "dst/src/filtered_out/skip.txt",
            "dst/src/where_empty/drop.tmp",
            "dst/src/with_file/f",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    let none_records: Vec<serde_json::Value> = std::fs::read_to_string(&none_results)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(none_records.last().unwrap()["directories_created"], 0);
    let puts = store.puts.lock().unwrap();
    assert!(
        !puts
            .iter()
            .any(|k| k.starts_with("none/") && k.ends_with('/')),
        "{puts:?}"
    );
}

#[test]
fn placement_collisions_and_pruning_hold_when_markers_are_omitted() {
    let temp = crate::test_support::tempdir().unwrap();
    let empty_dir = temp.path().join("empty_dir");
    std::fs::create_dir(&empty_dir).unwrap();
    let with_child = temp.path().join("with_child");
    std::fs::create_dir(&with_child).unwrap();
    std::fs::write(with_child.join("child"), b"data").unwrap();
    let a = temp.path().join("a");
    std::fs::create_dir(&a).unwrap();
    let b = temp.path().join("b");
    std::fs::write(&b, b"file").unwrap();

    // Exact object `file_target` vs existing prefix `dir_target/...` + prune fixture.
    let store = MemoryStore::start(&[
        ("bucket", "file_target", b"exact", &[]),
        ("bucket", "dir_target/existing", b"ok", &[]),
        ("bucket", "mirror/live/", b"", &[]),
        ("bucket", "mirror/live/keep", b"v1", &[]),
        ("bucket", "mirror/stale/", b"", &[]),
        ("bucket", "mirror/stale/extra", b"old", &[]),
        ("bucket", "empty_mirror/stale_file", b"old", &[]),
        ("bucket", "empty_mirror/stale_dir/", b"", &[]),
    ]);

    // An empty upload plan from a directory must reject an exact non-prefix object.
    let exact_rejected = store.cp(
        temp.path(),
        &[
            "empty_dir",
            "--to",
            "s3://bucket",
            "--as-existing",
            "file_target",
            "--s3-directory-markers=none",
        ],
    );
    assert!(
        !exact_rejected.status.success(),
        "{}",
        output_text(&exact_rejected)
    );
    assert!(
        output_text(&exact_rejected).contains("S3 destination existence condition failed"),
        "{}",
        output_text(&exact_rejected)
    );

    // Directory with children whose root marker is suppressed uses prefix existence.
    let prefix_ok = store.cp(
        temp.path(),
        &[
            "with_child",
            "--to",
            "s3://bucket",
            "--as-existing",
            "dir_target",
            "--s3-directory-markers=none",
        ],
    );
    assert!(prefix_ok.status.success(), "{}", output_text(&prefix_ok));
    assert!(store.keys("bucket").contains("dir_target/child"));
    assert!(!store.keys("bucket").contains("dir_target/"));

    // File/directory collision is still caught when the empty directory creates no marker.
    std::fs::create_dir_all(temp.path().join("coll_dir/dup")).unwrap();
    std::fs::create_dir_all(temp.path().join("coll_file")).unwrap();
    std::fs::write(temp.path().join("coll_file/dup"), b"file").unwrap();
    let collision = store.cp(
        temp.path(),
        &[
            "coll_dir/dup",
            "coll_file/dup",
            "--to",
            "s3://bucket",
            "--into",
            "coll",
            "--s3-directory-markers=none",
        ],
    );
    assert!(!collision.status.success(), "{}", output_text(&collision));
    assert!(
        output_text(&collision).contains("multiple sources map"),
        "{}",
        output_text(&collision)
    );

    // Pruning keeps existing live markers and deletes destination-only objects/markers.
    let live = temp.path().join("live_src");
    std::fs::create_dir_all(live.join("live")).unwrap();
    std::fs::write(live.join("live/keep"), b"v1").unwrap();
    let prune_live = store.cp(
        temp.path(),
        &[
            "--srcs-in",
            "live_src",
            "--to",
            "s3://bucket",
            "--into",
            "mirror",
            "--prune",
            "--s3-directory-markers=none",
        ],
    );
    assert!(prune_live.status.success(), "{}", output_text(&prune_live));
    let keys = store.keys("bucket");
    assert!(keys.contains("mirror/live/"), "{keys:?}");
    assert!(keys.contains("mirror/live/keep"), "{keys:?}");
    assert!(!keys.contains("mirror/stale/"), "{keys:?}");
    assert!(!keys.contains("mirror/stale/extra"), "{keys:?}");

    // Empty upload plan (`none` on an empty directory) still prunes extras.
    let prune_empty = store.cp(
        temp.path(),
        &[
            "--srcs-in",
            "empty_dir",
            "--to",
            "s3://bucket",
            "--into",
            "empty_mirror",
            "--prune",
            "--s3-directory-markers=none",
        ],
    );
    assert!(
        prune_empty.status.success(),
        "{}",
        output_text(&prune_empty)
    );
    let keys = store.keys("bucket");
    assert!(!keys.contains("empty_mirror/stale_file"), "{keys:?}");
    assert!(!keys.contains("empty_mirror/stale_dir/"), "{keys:?}");
}

#[test]
fn s3_to_s3_directory_markers_and_head_where_filtering() {
    let dir_meta = [
        ("x-amz-meta-syq-format", "1"),
        ("x-amz-meta-syq-kind", "dir"),
        ("x-amz-meta-syq-mode", "493"),
        ("x-amz-meta-syq-uid", "1000"),
        ("x-amz-meta-syq-gid", "1000"),
        ("x-amz-meta-syq-mtime", "10"),
        ("x-amz-meta-syq-mtime-nsec", "0"),
    ];
    let mode_700 = [
        ("x-amz-meta-syq-format", "1"),
        ("x-amz-meta-syq-kind", "file"),
        ("x-amz-meta-syq-mode", "448"),
        ("x-amz-meta-syq-uid", "1000"),
        ("x-amz-meta-syq-gid", "1000"),
        ("x-amz-meta-syq-mtime", "10"),
        ("x-amz-meta-syq-mtime-nsec", "0"),
    ];
    let mode_600 = [
        ("x-amz-meta-syq-format", "1"),
        ("x-amz-meta-syq-kind", "file"),
        ("x-amz-meta-syq-mode", "384"),
        ("x-amz-meta-syq-uid", "1000"),
        ("x-amz-meta-syq-gid", "1000"),
        ("x-amz-meta-syq-mtime", "10"),
        ("x-amz-meta-syq-mtime-nsec", "0"),
    ];
    let store = MemoryStore::start(&[
        ("src", "tree/", b"", &dir_meta),
        ("src", "tree/empty/", b"", &dir_meta),
        ("src", "tree/nested/", b"", &dir_meta),
        ("src", "tree/nested/leaf_empty/", b"", &dir_meta),
        ("src", "tree/keep_dir/", b"", &dir_meta),
        ("src", "tree/keep_dir/match", b"keep", &mode_700),
        ("src", "tree/empty_by_where/", b"", &dir_meta),
        ("src", "tree/empty_by_where/skip", b"skip", &mode_600),
        ("src", "tree/skipped_by_copy_if/", b"", &dir_meta),
        ("src", "tree/skipped_by_copy_if/only", b"keep", &mode_700),
        ("dst", "file_target", b"exact", &mode_600),
        ("dst", "dir_target/existing", b"ok", &mode_600),
        ("src", "only_marker/", b"", &dir_meta),
    ]);
    let temp = crate::test_support::tempdir().unwrap();

    // 1. `all`: copies source markers.
    let out = store.cp(
        temp.path(),
        &[
            "--from",
            "s3://src",
            "tree",
            "--to",
            "s3://dst_all",
            "--into",
            "out",
        ],
    );
    assert!(out.status.success(), "{}", output_text(&out));
    assert_eq!(
        store.keys("dst_all"),
        [
            "out/tree/",
            "out/tree/empty/",
            "out/tree/empty_by_where/",
            "out/tree/empty_by_where/skip",
            "out/tree/keep_dir/",
            "out/tree/keep_dir/match",
            "out/tree/nested/",
            "out/tree/nested/leaf_empty/",
            "out/tree/skipped_by_copy_if/",
            "out/tree/skipped_by_copy_if/only",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    // 2. `empty` with HEAD-requiring `--where` and `--copy-if` skipping a child:
    // - `tree/empty_by_where/` becomes empty (only child rejected by --where) -> keeps marker.
    // - `tree/skipped_by_copy_if/` had a `--where`-selected child (`only`), so `--copy-if`
    //   skipping `only` does NOT emit a `tree/skipped_by_copy_if/` marker!
    let out = store.cp(
        temp.path(),
        &[
            "--from",
            "s3://src",
            "tree",
            "--to",
            "s3://dst_empty",
            "--into",
            "out",
            "--s3-directory-markers=empty",
            "--where",
            "src.mode = 0o700",
            "--copy-if",
            "src.path != 'skipped_by_copy_if/only'",
        ],
    );
    assert!(out.status.success(), "{}", output_text(&out));
    assert_eq!(
        store.keys("dst_empty"),
        [
            "out/tree/empty/",
            "out/tree/empty_by_where/",
            "out/tree/keep_dir/match",
            "out/tree/nested/leaf_empty/",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    // 3. `none`: copies zero markers.
    let out = store.cp(
        temp.path(),
        &[
            "--from",
            "s3://src",
            "tree",
            "--to",
            "s3://dst_none",
            "--into",
            "out",
            "--s3-directory-markers=none",
            "--where",
            "src.mode = 0o700",
        ],
    );
    assert!(out.status.success(), "{}", output_text(&out));
    assert_eq!(
        store.keys("dst_none"),
        [
            "out/tree/keep_dir/match",
            "out/tree/skipped_by_copy_if/only",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );

    // 4. `--as-existing` still treats an omitted-marker empty prefix as a prefix.
    let exact_rejected = store.cp(
        temp.path(),
        &[
            "--from",
            "s3://src",
            "only_marker",
            "--to",
            "s3://dst",
            "--as-existing",
            "file_target",
            "--s3-directory-markers=none",
        ],
    );
    assert!(
        !exact_rejected.status.success(),
        "{}",
        output_text(&exact_rejected)
    );

    // 5. Same-bucket overlap is still refused even when markers are suppressed.
    let overlap = store.cp(
        temp.path(),
        &[
            "--from",
            "s3://src",
            "only_marker",
            "--to",
            "s3://src",
            "--into",
            "only_marker",
            "--s3-directory-markers=none",
        ],
    );
    assert!(!overlap.status.success(), "{}", output_text(&overlap));
    assert!(
        output_text(&overlap).contains("overlap"),
        "{}",
        output_text(&overlap)
    );
}
