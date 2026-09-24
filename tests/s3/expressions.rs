use super::*;
use std::sync::Mutex;

struct ExpressionServer {
    address: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl ExpressionServer {
    fn new() -> Self {
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
                    Ok(pair) => pair,
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
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
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
                    let mut contents = String::new();
                    for name in ["keep", "skip", "link"] {
                        contents.push_str(&format!("<Contents><Key>tree/{name}</Key><Size>4</Size><LastModified>2026-01-01T00:00:00Z</LastModified></Contents>"));
                    }
                    let body = format!("<ListBucketResult><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>");
                    reply(&mut socket, 200, &[], body.as_bytes(), false);
                    continue;
                }
                let key = path.split('?').next().unwrap();
                if !matches!(
                    key,
                    "/bucket/tree/keep" | "/bucket/tree/skip" | "/bucket/tree/link"
                ) {
                    reply(&mut socket, 404, &[], b"", method == "HEAD");
                    continue;
                }
                // An excluded object cannot be inspected successfully. This
                // catches request regressions as well as mistaken selection.
                if key.ends_with("/skip") && method == "HEAD" {
                    reply(&mut socket, 403, &[], b"", true);
                    continue;
                }
                let mut headers = vec![
                    ("Content-Length".into(), "4".into()),
                    ("ETag".into(), "\"fixture\"".into()),
                    (
                        "Last-Modified".into(),
                        "Thu, 01 Jan 2026 00:00:00 GMT".into(),
                    ),
                ];
                for (name, value) in [
                    ("syq-format", "1"),
                    (
                        "syq-kind",
                        if key.ends_with("/link") {
                            "symlink"
                        } else {
                            "file"
                        },
                    ),
                    ("syq-mode", "448"),
                    ("syq-uid", "0"),
                    ("syq-gid", "0"),
                    // Deliberately different from LIST / provider time.
                    ("syq-mtime", "123"),
                    ("syq-mtime-nsec", "0"),
                ] {
                    headers.push((format!("x-amz-meta-{name}"), value.into()));
                }
                let range = request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:"));
                if range {
                    headers.push(("Content-Range".into(), "bytes 0-3/4".into()));
                }
                reply(
                    &mut socket,
                    if range { 206 } else { 200 },
                    &headers,
                    b"data",
                    method == "HEAD",
                );
            }
        });
        Self {
            address,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    fn copy(&self, root: &Path, options: &[&str]) -> Output {
        self.copy_to(root, None, options)
    }
    fn copy_to(&self, root: &Path, s3_destination: Option<&str>, options: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args(["cp", "--from", "s3://bucket", "--srcs-in", "tree"]);
        if let Some(destination) = s3_destination {
            command.args(["--to", "s3://bucket", "--into", destination]);
        } else {
            command.arg("--into").arg(root.join("out"));
        }
        command
            .args([
                "--s3-region",
                "us-east-1",
                "--s3-endpoint",
                &self.address,
                "--no-progress",
                "--performance-tuning=s3-retries=0",
            ])
            .args(options)
            .env("AWS_ACCESS_KEY_ID", "test-access")
            .env("AWS_SECRET_ACCESS_KEY", "test-secret")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env("AWS_CONFIG_FILE", root.join("no-config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", root.join("no-credentials"))
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("XDG_CACHE_HOME", root.join("cache"))
            .capture_output()
            .unwrap()
    }
    fn object_heads(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("HEAD /bucket/tree/"))
            .cloned()
            .collect()
    }
    fn gets(&self) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("GET /bucket/tree/"))
            .count()
    }
}
impl Drop for ExpressionServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn listing_fields_select_without_object_heads() {
    for options in [
        vec!["--where", "src.size > 1B"],
        vec!["--where", "src.name = 'keep'"],
        vec![
            "--where",
            "src.name = 'keep' and src.s3_last_modified = timestamp('2026-01-01T00:00:00Z')",
        ],
        vec!["--copy-if", "src.path = 'keep' and not dst.exists"],
        vec![
            "--where",
            "src.name = 'keep'",
            "--copy-if",
            "src.size > 1B and dst.path = 'keep'",
        ],
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = ExpressionServer::new();
        let output = server.copy(temp.path(), &options);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(temp.path().join("out/keep")).unwrap(),
            b"data"
        );
        assert!(
            server.object_heads().is_empty(),
            "{:?}",
            server.object_heads()
        );
        assert_eq!(
            server.gets(),
            if options[1] == "src.size > 1B" { 3 } else { 1 }
        );
    }
}

#[test]
fn cheap_rejection_precedes_metadata_and_preserves_stored_time() {
    for predicate in [
        "src.name = 'keep' and src.mtime < timestamp('2000-01-01T00:00:00Z')",
        "src.name = 'keep' and src.mode = 0o700",
        "src.name = 'link' and src.kind = 'symlink'",
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = ExpressionServer::new();
        let output = server.copy(temp.path(), &["--where", predicate]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            server.object_heads().len(),
            1,
            "{:?}",
            server.object_heads()
        );
        assert_eq!(server.gets(), 1);
        if predicate.contains("'link'") {
            assert_eq!(
                std::fs::read_link(temp.path().join("out/link")).unwrap(),
                Path::new("data")
            );
        } else {
            assert_eq!(
                std::fs::read(temp.path().join("out/keep")).unwrap(),
                b"data"
            );
        }
        assert!(!temp.path().join("out/skip").exists());
    }
}

#[test]
fn required_metadata_errors_fail_and_protect_pruning() {
    let temp = test_support::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("out")).unwrap();
    std::fs::write(temp.path().join("out/extra"), b"keep").unwrap();
    let server = ExpressionServer::new();
    let output = server.copy(
        temp.path(),
        &[
            "--where",
            "src.name = 'skip' and src.uid is null",
            "--prune",
        ],
    );
    assert!(!output.status.success());
    assert_eq!(server.object_heads().len(), 1);
    assert_eq!(server.gets(), 0);
    assert_eq!(
        std::fs::read(temp.path().join("out/extra")).unwrap(),
        b"keep"
    );
}

#[test]
fn listing_rejection_avoids_server_copy_metadata_requests() {
    for options in [
        vec!["--where", "src.name = 'absent'"],
        vec!["--copy-if", "src.size < 1B"],
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = ExpressionServer::new();
        let output = server.copy_to(temp.path(), Some("copied"), &options);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let requests = server.requests.lock().unwrap();
        // Only source-prefix validation and listing; no object HEADs or copies.
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests.iter().any(|r| r.starts_with("HEAD /bucket/tree ")));
        assert!(requests.iter().any(|r| r.contains("list-type=2")));
    }
}

#[test]
fn listing_rejection_protects_existing_counterparts_during_prune() {
    let temp = test_support::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("out")).unwrap();
    std::fs::write(temp.path().join("out/keep"), b"existing").unwrap();
    std::fs::write(temp.path().join("out/extra"), b"remove").unwrap();
    let server = ExpressionServer::new();
    let output = server.copy(temp.path(), &["--where", "false", "--prune"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(server.object_heads().is_empty());
    assert_eq!(server.gets(), 0);
    assert_eq!(
        std::fs::read(temp.path().join("out/keep")).unwrap(),
        b"existing"
    );
    assert!(!temp.path().join("out/extra").exists());
}
