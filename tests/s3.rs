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
}
impl Server {
    fn start(fault: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let stopping = stop.clone();
        let count = requests.clone();
        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let count = count.clone();
                        workers.push(thread::spawn(move || serve(socket, fault, count)));
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
        }
    }
    fn cp(&self, temp: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .args([
                "cp",
                "--s3-endpoint",
                &self.address,
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
            .args(args)
            .env("AWS_ACCESS_KEY_ID", "test-access")
            .env("AWS_SECRET_ACCESS_KEY", "test-secret")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_CONFIG_FILE", temp.join("no-config"))
            .env("AWS_SHARED_CREDENTIALS_FILE", temp.join("no-credentials"))
            .env("XDG_CACHE_HOME", temp.join("cache"))
            .current_dir(temp)
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
fn serve(mut socket: TcpStream, fault: &str, requests: Arc<AtomicUsize>) {
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
    let size = if fault.starts_with("single") {
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
    if method == "HEAD" {
        fields.push(("Content-Length".into(), size.to_string()));
        reply(&mut socket, 200, &fields, b"", true);
        return;
    }
    assert_eq!(method, "GET");
    let Some(range) = headers.get("range") else {
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
