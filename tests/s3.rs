//! Network fault tests use a local independent HTTP fixture. Real S3 protocol
//! and signature interoperability are exercised by scripts/test-s3.sh.
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

struct Server {
    address: String,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    thread: Option<thread::JoinHandle<()>>,
    gate: Arc<(AtomicBool, AtomicBool)>,
}
impl Server {
    fn start(fault: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((AtomicBool::new(false), AtomicBool::new(false)));
        let worker_gate = gate.clone();
        let stopping = stop.clone();
        let count = requests.clone();
        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let count = count.clone();
                        let gate = worker_gate.clone();
                        workers.push(thread::spawn(move || serve(socket, fault, count, gate)));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            address,
            stop,
            requests,
            thread: Some(handle),
            gate,
        }
    }
    fn command(&self, temp: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "cp",
                "--s3-region",
                "us-east-1",
                "--s3-retries",
                "0",
                "--s3-header",
                "X-Tigris-Consistent: true",
                "--no-progress",
                "-p",
                "5",
                "-c",
                "3",
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
            .current_dir(temp);
        command
    }
    fn cp(&self, temp: &Path, args: &[&str]) -> Output {
        self.command(temp)
            .args(["--s3-endpoint", &self.address])
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

const SIZE: usize = 6 * 1024 * 1024 + 7;
fn serve(
    mut socket: TcpStream,
    fault: &str,
    requests: Arc<AtomicUsize>,
    gate: Arc<(AtomicBool, AtomicBool)>,
) {
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
            return;
        }
        raw.push(byte[0]);
        if raw.len() > 65536 {
            return;
        }
    }
    requests.fetch_add(1, Ordering::Relaxed);
    let text = String::from_utf8(raw).unwrap();
    let first = text.lines().next().unwrap();
    let method = first.split_whitespace().next().unwrap();
    let headers = text
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect::<std::collections::HashMap<_, _>>();
    let authorization = headers.get("authorization").unwrap();
    assert!(
        authorization.contains("x-tigris-consistent"),
        "custom header was not signed"
    );
    assert_eq!(
        headers.get("x-tigris-consistent").map(String::as_str),
        Some("true")
    );
    if fault == "missing" {
        reply(&mut socket, 404, &[], b"", false);
        return;
    }
    let size = if fault.starts_with("single") || fault.starts_with("prefix-") {
        65536
    } else {
        SIZE
    };
    let data = vec![b'x'; size];
    let hash = blake3::hash(&data).to_hex().to_string();
    let mut fields = vec![
        ("ETag".to_owned(), "\"fixture-v1\"".to_owned()),
        (
            "Last-Modified".into(),
            "Tue, 14 Nov 2023 22:13:20 GMT".into(),
        ),
        ("x-amz-meta-syq-format".into(), "1".into()),
        ("x-amz-meta-syq-kind".into(), "file".into()),
        ("x-amz-meta-syq-mode".into(), "420".into()),
        ("x-amz-meta-syq-uid".into(), "0".into()),
        ("x-amz-meta-syq-gid".into(), "0".into()),
        ("x-amz-meta-syq-mtime".into(), "1700000000".into()),
        ("x-amz-meta-syq-mtime-nsec".into(), "0".into()),
        ("x-amz-meta-syq-blake3".into(), hash),
    ];
    if fault.starts_with("prefix-") {
        let target = first.split_whitespace().nth(1).unwrap();
        let path = target.split('?').next().unwrap();
        if method == "HEAD" && path == "/bucket/data" {
            // Hold HEAD until LIST arrives: sequential discovery cannot pass.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut report = std::time::Instant::now() + Duration::from_secs(1);
            while !gate.1.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
                if std::time::Instant::now() >= report {
                    eprintln!("prefix fixture: HEAD is waiting for LIST");
                    report += Duration::from_secs(1);
                }
            }
            assert!(gate.1.load(Ordering::Acquire), "LIST did not overlap HEAD");
            if fault != "prefix-collision" {
                reply(&mut socket, 404, &[], b"", false);
                return;
            }
        } else if method == "GET" && target.contains("list-type=2") {
            assert!(target.contains("prefix=data%2F"));
            gate.1.store(true, Ordering::Release);
            if fault == "prefix-list-error" {
                reply(
                    &mut socket,
                    403,
                    &[],
                    b"<Error><Code>AccessDenied</Code></Error>",
                    false,
                );
            } else {
                let listing = format!("<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>data/file</Key><Size>{size}</Size></Contents></ListBucketResult>");
                reply(&mut socket, 200, &[], listing.as_bytes(), false);
            }
            return;
        } else {
            assert_eq!(path, "/bucket/data/file");
            assert_eq!(fault, "prefix-ok", "copied before validating discovery");
        }
    }
    if method == "HEAD" {
        fields.push(("Content-Length".into(), size.to_string()));
        reply(&mut socket, 200, &fields, b"", true);
        return;
    }
    assert_eq!(method, "GET");
    let Some(range) = headers.get("range") else {
        if fault == "single-swap" {
            let mut head =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n");
            for (name, value) in &fields {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            socket.write_all(head.as_bytes()).unwrap();
            socket.write_all(&data[..size / 2]).unwrap();
            gate.0.store(true, Ordering::Release);
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !gate.1.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
            }
            assert!(
                gate.1.load(Ordering::Acquire),
                "pathname-swap fixture timed out awaiting release"
            );
            let _ = socket.write_all(&data[size / 2..]);
            return;
        }
        let mut data = data;
        if fault == "single-corrupt" {
            data[0] = b'!';
        }
        if fault == "single-truncated" {
            fields.push(("Content-Length".into(), size.to_string()));
            data.truncate(size / 2);
        }
        if fault == "single-length" {
            data.push(b'!');
        }
        reply(&mut socket, 200, &fields, &data, false);
        return;
    };
    let (start, end) = range
        .strip_prefix("bytes=")
        .unwrap()
        .split_once('-')
        .unwrap();
    let start: usize = start.parse().unwrap();
    let end: usize = end.parse().unwrap();
    if fault == "ignore-range" {
        reply(&mut socket, 200, &fields, &data, false);
        return;
    }
    fields.push((
        "Content-Range".into(),
        format!("bytes {start}-{end}/{SIZE}"),
    ));
    if fault == "etag" {
        fields[0].1 = "\"different\"".into();
    }
    let mut body = data[start..=end].to_vec();
    if fault == "initial-range-overlap" {
        if start == 0 {
            let mut head = format!(
                "HTTP/1.1 206 Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in &fields {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            socket.write_all(head.as_bytes()).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut report = std::time::Instant::now() + Duration::from_secs(1);
            while !gate.1.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
                if std::time::Instant::now() >= report {
                    eprintln!("range fixture: first body is waiting for the next range");
                    report += Duration::from_secs(1);
                }
            }
            assert!(
                gate.1.load(Ordering::Acquire),
                "next range did not overlap first body"
            );
            let _ = socket.write_all(&body);
            return;
        }
        assert_eq!(
            headers.get("if-match").map(String::as_str),
            Some("\"fixture-v1\"")
        );
        gate.1.store(true, Ordering::Release);
    }
    if fault == "corrupt" {
        body[0] = b'!';
    }
    if fault == "truncated" {
        fields.push(("Content-Length".into(), body.len().to_string()));
        body.truncate(body.len() / 2);
    }
    reply(&mut socket, 206, &fields, &body, false);
}
fn reply(
    socket: &mut TcpStream,
    status: u16,
    fields: &[(String, String)],
    body: &[u8],
    head: bool,
) {
    let mut response = format!("HTTP/1.1 {status} Fixture\r\nConnection: close\r\n");
    for (k, v) in fields {
        response.push_str(&format!("{k}: {v}\r\n"));
    }
    if !fields
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    response.push_str("\r\n");
    let _ = socket.write_all(response.as_bytes());
    if !head {
        let _ = socket.write_all(body);
    }
}
fn output_text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
fn validate_results(temp: &Path) {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/automation.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let text = std::fs::read_to_string(temp.join("results.jsonl")).unwrap();
    let values = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .collect::<Vec<_>>();
    for value in &values {
        let errors = validator
            .iter_errors(value)
            .map(|e| e.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{value}: {errors:?}");
    }
    assert_eq!(values.last().unwrap()["type"], "result");
    assert!(values[0]["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "s3" && e["host"] == "s3://bucket"));
}
#[test]
fn s3_ranges_signed_headers_metadata_and_results() {
    let server = Server::start("ok");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://bucket",
            "data",
            "--as",
            "download",
            "--results",
            "results.jsonl",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        std::fs::read(temp.path().join("download")).unwrap(),
        vec![b'x'; SIZE]
    );
    validate_results(temp.path());
    assert!(server.requests.load(Ordering::Relaxed) >= 3);
}
#[test]
fn s3_prefix_discovery_overlaps_reads_and_checks_both_results() {
    for fault in ["prefix-ok", "prefix-collision", "prefix-list-error"] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://bucket",
                "--srcs-in",
                "data",
                "--into",
                "download",
            ],
        );
        assert_eq!(
            output.status.success(),
            fault == "prefix-ok",
            "{fault}: {}",
            output_text(&output)
        );
        if fault == "prefix-ok" {
            assert_eq!(
                std::fs::read(temp.path().join("download/file")).unwrap(),
                vec![b'x'; 65536]
            );
            assert_eq!(server.requests.load(Ordering::Relaxed), 3);
        } else {
            assert!(!temp.path().join("download/file").exists());
            assert_eq!(server.requests.load(Ordering::Relaxed), 2);
            let error = output_text(&output);
            assert!(
                error.contains(if fault == "prefix-collision" {
                    "selector requires a prefix but an object exists"
                } else {
                    "S3 listing failed"
                }),
                "{error}"
            );
        }
    }
}
#[test]
fn s3_first_range_supplies_metadata_without_serializing_the_remaining_ranges() {
    let server = Server::start("initial-range-overlap");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &["--from", "s3://bucket", "data", "--as", "download"],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        std::fs::read(temp.path().join("download")).unwrap(),
        vec![b'x'; SIZE]
    );
    // One selector HEAD, two range GETs, and the final identity HEAD.
    assert_eq!(server.requests.load(Ordering::Relaxed), 4);
}

#[test]
fn s3_invalid_initial_ranges_never_publish_a_fresh_download() {
    for fault in ["ignore-range", "etag", "corrupt", "truncated"] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let output = server.cp(
            temp.path(),
            &["--from", "s3://bucket", "data", "--as", "download"],
        );
        assert!(
            !output.status.success(),
            "{fault}: {}",
            output_text(&output)
        );
        assert!(
            !temp.path().join("download").exists(),
            "{fault}: incomplete file was published"
        );
    }
}
#[test]
fn s3_bad_responses_preserve_existing_destination() {
    for fault in ["ignore-range", "etag", "corrupt", "truncated"] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("download"), b"original").unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://bucket",
                "data",
                "--as",
                "download",
                "--results",
                "results.jsonl",
            ],
        );
        assert!(
            !output.status.success(),
            "{fault}: {}",
            output_text(&output)
        );
        assert_eq!(
            std::fs::read(temp.path().join("download")).unwrap(),
            b"original"
        );
        assert_eq!(output.status.code(), Some(23), "{}", output_text(&output));
        let records = std::fs::read_to_string(temp.path().join("results.jsonl")).unwrap();
        let terminal: serde_json::Value =
            serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(terminal["status"], "partial");
        validate_results(temp.path());
    }
}
#[test]
fn s3_dry_run_never_creates_destination_or_recovery() {
    let server = Server::start("ok");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://bucket",
            "data",
            "--as",
            "nested/download",
            "--dry-run",
            "--results",
            "results.jsonl",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(!temp.path().join("nested").exists());
    assert!(!temp.path().join("cache").exists());
    validate_results(temp.path());
}
#[test]
fn s3_usage_errors_do_not_contact_storage() {
    let server = Server::start("ok");
    let temp = tempfile::tempdir().unwrap();
    for args in [
        vec!["--from", "s3://bucket", "data", "--as", "out", "--inplace"],
        vec![
            "--from",
            "s3://bucket",
            "data",
            "--as",
            "out",
            "--s3-header",
            "Authorization: secret",
        ],
        vec!["--from", "s3://bucket/path", "data", "--as", "out"],
        vec!["data", "--into", "out"],
    ] {
        let output = server.cp(temp.path(), &args);
        assert_eq!(output.status.code(), Some(2), "{}", output_text(&output));
    }
    assert_eq!(server.requests.load(Ordering::Relaxed), 0);
}

#[test]
fn s3_single_get_validates_metadata_length_and_contents() {
    for fault in [
        "single-ok",
        "single-corrupt",
        "single-truncated",
        "single-length",
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://bucket",
                "object",
                "--as",
                "result",
                "--results",
                "results.jsonl",
            ],
        );
        assert_eq!(
            output.status.success(),
            fault == "single-ok",
            "{fault}: {}",
            output_text(&output)
        );
        validate_results(temp.path());
        if fault == "single-ok" {
            assert_eq!(
                std::fs::read(temp.path().join("result")).unwrap(),
                vec![b'x'; 65536]
            );
        } else {
            assert!(!temp.path().join("result").exists());
        }
        assert!(!std::fs::read_dir(temp.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")));
    }
}

#[test]
fn s3_temporary_name_replacement_cannot_redirect_metadata() {
    use std::os::unix::fs::PermissionsExt;
    let server = Server::start("single-swap");
    let temp = tempfile::tempdir().unwrap();
    let victim = temp.path().join("victim");
    std::fs::write(&victim, b"keep this inode untouched").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
    thread::scope(|scope| {
        let copy = scope.spawn(|| {
            server.cp(
                temp.path(),
                &[
                    "--from",
                    "s3://bucket",
                    "object",
                    "--as",
                    "result",
                    "--preserve=permissions",
                ],
            )
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut replaced = false;
        while std::time::Instant::now() < deadline {
            if server.gate.0.load(Ordering::Acquire) {
                let partial = std::fs::read_dir(temp.path())
                    .unwrap()
                    .filter_map(Result::ok)
                    .find(|entry| entry.file_name().to_string_lossy().ends_with(".partial"));
                if let Some(partial) = partial {
                    std::fs::rename(partial.path(), temp.path().join("original-inode")).unwrap();
                    std::fs::hard_link(&victim, partial.path()).unwrap();
                    replaced = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        server.gate.1.store(true, Ordering::Release);
        let output = copy.join().unwrap();
        assert!(
            replaced,
            "temporary file did not appear before the fixture deadline"
        );
        assert!(!output.status.success(), "{}", output_text(&output));
    });
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"keep this inode untouched"
    );
    assert_eq!(
        std::fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(!temp.path().join("result").exists());
}

#[test]
fn s3_service_profile_endpoints_keep_recovery_separate() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config");
    for server in [Server::start("corrupt"), Server::start("corrupt")] {
        std::fs::write(
            &config,
            format!(
                "[profile fixture]\nservices = fixture\nendpoint_url = http://127.0.0.1:9\n\n[services fixture]\ns3 =\n  endpoint_url = {}\n",
                server.address
            ),
        )
        .unwrap();
        let output = server
            .command(temp.path())
            .env("AWS_CONFIG_FILE", &config)
            .args([
                "--s3-profile",
                "fixture",
                "--from",
                "s3://bucket",
                "data",
                "--as",
                "download",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(23), "{}", output_text(&output));
        assert!(server.requests.load(Ordering::Relaxed) >= 3);
    }
    let records = std::fs::read_dir(temp.path().join("cache/syq/s3"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .count();
    assert_eq!(
        records, 2,
        "different providers must not share recovery records"
    );
}
