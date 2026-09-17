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
        self.command_with_retries(temp, 0)
    }
    fn command_with_retries(&self, temp: &Path, retries: u32) -> Command {
        let retry_option = format!("s3-retries={retries}");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "cp",
                "--s3-region",
                "us-east-1",
                "--performance-tuning",
                &retry_option,
                "--s3-header",
                "X-Tigris-Consistent: true",
                "--no-progress",
                "--performance-tuning",
                "s3-part-size=5M",
                "--performance-tuning",
                "s3-max-concurrent-parts-per-object=3",
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
    // BSD can inherit the listener's nonblocking mode; this handler uses
    // blocking I/O with timeouts on every platform.
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
    if fault == "latency-pages" {
        serve_latency_pages(&mut socket, first);
        return;
    }
    if fault == "wrong-region" {
        let region = ("x-amz-bucket-region".to_owned(), "eu-central-1".to_owned());
        reply(&mut socket, 301, &[region], b"", method == "HEAD");
        return;
    }
    if fault.starts_with("prune-") {
        if method == "GET" {
            let keys: Vec<String> = match fault {
                "prune-outside" => vec!["elsewhere/extra".into()],
                "prune-invalid" => vec!["mirror/bad//key".into()],
                "prune-folder-content" => vec!["mirror/bad/".into()],
                "prune-batch" | "prune-request-failure" | "prune-concurrent" => {
                    (0..1001).map(|i| format!("mirror/extra{i:04}")).collect()
                }
                "prune-mixed" => vec!["mirror/extra".into(), "mirror/good".into()],
                _ => vec!["mirror/extra".into()],
            };
            let contents = keys
                .iter()
                .map(|key| format!("<Contents><Key>{key}</Key><Size>1</Size></Contents>"))
                .collect::<String>();
            let body = format!(
                "<ListBucketResult><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>"
            );
            reply(&mut socket, 200, &[], body.as_bytes(), false);
        } else {
            assert_eq!(method, "POST");
            assert!(first.contains("delete"));
            let length: usize = headers["content-length"].parse().unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            let keys: Vec<_> = body
                .split("<Key>")
                .skip(1)
                .map(|s| s.split("</Key>").next().unwrap())
                .collect();
            assert!(!keys.is_empty() && keys.len() <= 1000);
            if fault == "prune-concurrent" {
                let (arrived, peer) = if keys.len() == 1000 {
                    (&gate.0, &gate.1)
                } else {
                    (&gate.1, &gate.0)
                };
                arrived.store(true, Ordering::SeqCst);
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !peer.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(2));
                }
                assert!(peer.load(Ordering::SeqCst), "deletion batches ran serially");
            }
            if fault == "prune-denied" || (fault == "prune-request-failure" && keys.len() == 1000) {
                reply(
                    &mut socket,
                    403,
                    &[],
                    b"<Error><Code>AccessDenied</Code><Message>denied</Message></Error>",
                    false,
                );
            } else {
                let entries = keys.iter().map(|key| if fault == "prune-mixed" && *key == "mirror/extra" {
                    format!("<Error><Key>{key}</Key><Code>AccessDenied</Code><Message>denied</Message></Error>")
                } else {
                    format!("<Deleted><Key>{key}</Key></Deleted>")
                }).collect::<String>();
                reply(
                    &mut socket,
                    200,
                    &[],
                    format!("<DeleteResult>{entries}</DeleteResult>").as_bytes(),
                    false,
                );
            }
        }
        return;
    }
    if fault.starts_with("listing-") {
        let target = first.split_whitespace().nth(1).unwrap();
        let url = url::Url::parse(&format!("http://fixture{target}")).unwrap();
        let query = url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        if method == "HEAD"
            && (url.path() == "/bucket/data"
                || fault.starts_with("listing-budget")
                || fault == "listing-complete")
        {
            reply(&mut socket, 404, &[], b"", true);
            return;
        }
        if query.contains_key("list-type") {
            assert_eq!(method, "GET");
            let prefix = query.get("prefix").unwrap().as_ref();
            if !matches!(
                fault,
                "listing-nested" | "listing-deep" | "listing-nested-wide"
            ) {
                assert_eq!(prefix, "data/");
            }
            let object =
                |key: &str| format!("<Contents><Key>{key}</Key><Size>{SIZE}</Size></Contents>");
            let (body, truncated) = match fault {
                "listing-nested" | "listing-deep" | "listing-nested-wide" => {
                    let depth = if fault == "listing-deep" { 12 } else { 1 };
                    let parent = format!("data/{}", "level/".repeat(depth));
                    let excluded = format!("{parent}archive/");
                    if query.contains_key("delimiter") {
                        if prefix == parent {
                            let mut body = format!(
                                "<CommonPrefixes><Prefix>{excluded}</Prefix></CommonPrefixes>"
                            );
                            if fault == "listing-nested-wide" {
                                body.push_str(&format!("<CommonPrefixes><Prefix>{parent}a/</Prefix></CommonPrefixes><CommonPrefixes><Prefix>{parent}b/</Prefix></CommonPrefixes>"));
                            }
                            (body, false)
                        } else {
                            assert!(parent.starts_with(prefix));
                            (format!("<CommonPrefixes><Prefix>{prefix}level/</Prefix></CommonPrefixes>"), false)
                        }
                    } else {
                        (
                            object(&format!("{excluded}file")),
                            !query.contains_key("continuation-token"),
                        )
                    }
                }
                "listing-ignored-root" | "listing-empty" => {
                    assert_eq!(query.get("max-keys").map(|s| s.as_ref()), Some("1"));
                    (
                        if fault == "listing-empty" {
                            String::new()
                        } else {
                            object("data/archive/file")
                        },
                        false,
                    )
                }
                "listing-exists" => {
                    assert_eq!(query.get("max-keys").map(|s| s.as_ref()), Some("1"));
                    (object("data/other"), true)
                }
                "listing-budget-many" => (
                    object("data/other"),
                    !query.contains_key("continuation-token"),
                ),
                "listing-budget" => {
                    assert!(
                        !query.contains_key("continuation-token"),
                        "upload enumerated a large destination"
                    );
                    (object("data/other"), true)
                }
                "listing-complete" => (String::new(), false),
                "listing-adaptive" | "listing-all-ignored" | "listing-wide" => {
                    assert!(
                        fault == "listing-wide" || !query.contains_key("continuation-token"),
                        "enumerated an excluded subtree"
                    );
                    if query.contains_key("delimiter") {
                        assert_eq!(query["delimiter"], "/");
                        let mut body =
                            "<CommonPrefixes><Prefix>data/archive/</Prefix></CommonPrefixes>"
                                .to_owned();
                        if fault == "listing-adaptive" {
                            body.push_str(&object("data/file"));
                        }
                        if fault == "listing-wide" {
                            body.push_str("<CommonPrefixes><Prefix>data/a/</Prefix></CommonPrefixes><CommonPrefixes><Prefix>data/b/</Prefix></CommonPrefixes>");
                        }
                        (body, false)
                    } else {
                        // Even a malformed descendant need not be interpreted
                        // when its whole directory is excluded.
                        (
                            object("data/archive/../invalid"),
                            !query.contains_key("continuation-token"),
                        )
                    }
                }
                "listing-flat" | "listing-mixed" => {
                    assert!(
                        !query.contains_key("delimiter"),
                        "filename filter caused directory traversal"
                    );
                    let mut body = object("data/dir/file.tmp");
                    if fault == "listing-mixed" && !query.contains_key("continuation-token") {
                        body.push_str(&object("data/archive/file"));
                    }
                    (body, !query.contains_key("continuation-token"))
                }
                _ => panic!("unknown listing fixture"),
            };
            let next = if truncated {
                "<NextContinuationToken>next</NextContinuationToken>"
            } else {
                ""
            };
            let xml = format!("<ListBucketResult><IsTruncated>{truncated}</IsTruncated>{next}{body}</ListBucketResult>");
            reply(&mut socket, 200, &[], xml.as_bytes(), false);
            return;
        }
    }
    if fault.starts_with("upload-") {
        if method == "HEAD" {
            reply(&mut socket, 404, &[], b"", true);
            return;
        }
        assert_eq!(method, "PUT");
        let length: usize = headers["content-length"].parse().unwrap();
        let mut body = vec![0; length];
        socket.read_exact(&mut body).unwrap();
        if let Some(status) = match fault {
            "upload-throttle-always" => Some(429),
            "upload-transient-always" => Some(503),
            _ => None,
        } {
            reply(&mut socket, status, &[], b"", false);
            return;
        }
        if fault == "upload-timeout-code-once" {
            if !gate.0.swap(true, Ordering::SeqCst) {
                // S3 reports a slow request body as RequestTimeout with HTTP 400.
                reply(
                    &mut socket,
                    400,
                    &[],
                    b"<Error><Code>RequestTimeout</Code><Message>slow</Message></Error>",
                    false,
                );
            } else {
                reply(
                    &mut socket,
                    200,
                    &[("ETag".into(), "\"stored\"".into())],
                    b"",
                    false,
                );
            }
            return;
        }
        use base64::Engine as _;
        use sha2::Digest as _;
        assert_eq!(
            headers["x-amz-checksum-sha256"],
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&body))
        );
        assert!(!headers.contains_key("x-amz-meta-syq-blake3"));
        if fault == "upload-default" {
            assert_eq!(headers["x-amz-meta-syq-format"], "1");
            assert!(!headers.contains_key("x-amz-meta-syq-hash"));
        } else {
            let digest = if fault == "upload-md5" {
                md5::Md5::digest(&body)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            } else {
                sha2::Sha256::digest(&body)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            assert_eq!(headers["x-amz-meta-syq-format"], "2");
            assert_eq!(headers["x-amz-meta-syq-hash"], digest);
            assert_eq!(
                headers["x-amz-meta-syq-hash-algorithm"],
                if fault == "upload-md5" {
                    "md5"
                } else {
                    "sha256"
                }
            );
        }
        gate.0.store(true, Ordering::Release);
        reply(
            &mut socket,
            200,
            &[("ETag".into(), "\"uploaded\"".into())],
            b"",
            false,
        );
        return;
    }
    if (method == "HEAD"
        && (fault == "single-throttle-always"
            || (matches!(fault, "single-throttle-once" | "single-transient-once")
                && !gate.0.swap(true, Ordering::SeqCst))))
        || (method == "GET"
            && fault == "single-get-throttle-once"
            && !gate.0.swap(true, Ordering::SeqCst))
    {
        let status = if fault == "single-transient-once" {
            503
        } else {
            429
        };
        reply(&mut socket, status, &[], b"", false);
        return;
    }
    if method == "GET" {
        if let Some((status, body)) = match fault {
            "single-get-throttle-always" => Some((429, &b""[..])),
            "single-get-transient-always" => Some((503, &b""[..])),
            "single-get-timeout-code-always" => Some((
                400,
                &b"<Error><Code>RequestTimeout</Code><Message>slow</Message></Error>"[..],
            )),
            _ => None,
        } {
            reply(&mut socket, status, &[], body, false);
            return;
        }
    }
    if fault == "head-denied" && method == "HEAD" {
        reply(&mut socket, 403, &[], b"", false);
        return;
    }
    if fault == "missing" {
        reply(&mut socket, 404, &[], b"", false);
        return;
    }
    let size = if fault.starts_with("single") || fault.starts_with("prefix-") {
        65536
    } else {
        SIZE
    };
    let data = if fault == "patterned" {
        (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>()
    } else {
        vec![b'x'; size]
    };
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
    if fault.starts_with("single-upload-") {
        if fault == "single-upload-nohash" {
            fields.retain(|(key, _)| key != "x-amz-meta-syq-blake3");
        }
        if method == "PUT" {
            let length: usize = headers["content-length"].parse().unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            gate.0.store(true, Ordering::Release);
            reply(
                &mut socket,
                200,
                &[("ETag".into(), "\"replaced\"".into())],
                b"",
                false,
            );
            return;
        }
        if method == "GET" {
            gate.1.store(true, Ordering::Release);
        }
    }
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
        format!("bytes {start}-{end}/{size}"),
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
#[test]
fn s3_fixture_completes_response_on_inherited_nonblocking_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (socket, _) = listener.accept().unwrap();
    // Reproduce BSD's accepted-socket mode on every platform and force the
    // response to exceed the available send buffer before the client reads.
    socket.set_nonblocking(true).unwrap();
    socket2::SockRef::from(&socket)
        .set_send_buffer_size(4096)
        .unwrap();
    client
        .write_all(b"GET /bucket/data HTTP/1.1\r\nAuthorization: x-tigris-consistent\r\nX-Tigris-Consistent: true\r\n\r\n")
        .unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        serve(
            socket,
            "ok",
            Arc::new(AtomicUsize::new(0)),
            Arc::new((AtomicBool::new(false), AtomicBool::new(false))),
        );
        done_tx.send(()).unwrap();
    });
    assert_eq!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout),
        "fixture closed before the client could drain the response"
    );
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    worker.join().unwrap();
    let body = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|end| &response[end + 4..])
        .expect("HTTP response headers");
    assert_eq!(body.len(), SIZE);
    assert!(body.iter().all(|&byte| byte == b'x'));
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
        let mut args = vec!["--from", "s3://bucket", "data", "--as", "download"];
        if fault == "corrupt" {
            args.push("--integrity-checking=transfer=blake3");
        }
        let output = server.cp(temp.path(), &args);
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
fn s3_fast_queued_ranges_preserve_bytes_and_fail_without_publication() {
    for fault in ["patterned", "ignore-range", "etag", "truncated"] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("download"), b"original").unwrap();
        let output = server.cp(
            temp.path(),
            &["--from", "s3://bucket", "data", "--as", "download"],
        );
        assert_eq!(
            output.status.success(),
            fault == "patterned",
            "{fault}: {}",
            output_text(&output)
        );
        let expected = if fault == "patterned" {
            (0..SIZE).map(|i| (i % 251) as u8).collect::<Vec<_>>()
        } else {
            b"original".to_vec()
        };
        assert_eq!(
            std::fs::read(temp.path().join("download")).unwrap(),
            expected
        );
    }
}

#[test]
fn s3_one_request_slot_supports_multipart_and_content_verification() {
    let server = Server::start("ok");
    let temp = tempfile::tempdir().unwrap();
    for extra in [None, Some("--verify-only")] {
        let mut args = vec![
            "--from",
            "s3://bucket",
            "data",
            "--as",
            "result",
            "--performance-tuning=s3-max-concurrent-requests=1",
        ];
        if let Some(flag) = extra {
            args.push(flag);
        }
        let output = server.cp(temp.path(), &args);
        assert!(output.status.success(), "{}", output_text(&output));
    }
    assert_eq!(
        std::fs::metadata(temp.path().join("result")).unwrap().len(),
        SIZE as u64
    );
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
                "--integrity-checking=transfer=blake3",
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
fn s3_wrong_region_redirects_name_the_bucket_region() {
    let server = Server::start("wrong-region");
    let temp = tempfile::tempdir().unwrap();
    // A named object is found with HEAD, a prefix with a listing.
    for selector in [&["object"][..], &["--srcs-in", "prefix"][..]] {
        let mut args = vec!["--from", "s3://bucket"];
        args.extend_from_slice(selector);
        args.extend_from_slice(&["--into", "output"]);
        let output = server.cp(temp.path(), &args);
        let text = output_text(&output);
        assert!(!output.status.success(), "{text}");
        assert!(
            text.contains("(HTTP 301): the bucket is in region eu-central-1")
                && text.contains("--s3-region eu-central-1"),
            "{text}"
        );
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
                "--integrity-checking=transfer=blake3",
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
                "--integrity-checking=transfer=blake3",
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

#[test]
fn s3_expected_hash_checks_single_and_multipart_before_publication() {
    use sha2::Digest as _;
    for (fault, size) in [("single-ok", 65536), ("ok", SIZE)] {
        for correct in [true, false] {
            let server = Server::start(fault);
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(temp.path().join("result"), b"original").unwrap();
            let bytes = vec![if correct { b'x' } else { b'y' }; size];
            let expected = format!(
                "md5:{}",
                md5::Md5::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let output = server.cp(
                temp.path(),
                &[
                    "--expected-hash",
                    &expected,
                    "--from",
                    "s3://bucket",
                    "object",
                    "--as",
                    "result",
                ],
            );
            assert_eq!(
                output.status.success(),
                correct,
                "{fault}: {}",
                output_text(&output)
            );
            let actual = std::fs::read(temp.path().join("result")).unwrap();
            assert_eq!(actual, if correct { bytes } else { b"original".to_vec() });
        }
    }
}

#[test]
fn s3_expected_hash_checks_unchanged_destination_and_recovers_corruption() {
    use sha2::Digest as _;
    let server = Server::start("single-ok");
    let temp = tempfile::tempdir().unwrap();
    let expected = format!(
        "sha256:{}",
        sha2::Sha256::digest(vec![b'x'; 65536])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let args = [
        "--expected-hash",
        &expected,
        "--from",
        "s3://bucket",
        "object",
        "--as",
        "result",
    ];
    let output = server.cp(temp.path(), &args);
    assert!(output.status.success(), "{}", output_text(&output));
    let destination = temp.path().join("result");
    let time = std::fs::metadata(&destination).unwrap().modified().unwrap();
    std::fs::write(&destination, vec![b'y'; 65536]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&destination)
        .unwrap()
        .set_modified(time)
        .unwrap();
    let output = server.cp(temp.path(), &args);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(std::fs::read(destination).unwrap(), vec![b'x'; 65536]);
}

#[test]
fn s3_transfer_integrity_is_opt_in_but_framing_stays_mandatory() {
    for fault in ["single-corrupt", "single-truncated"] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let output = server.cp(
            temp.path(),
            &["--from", "s3://bucket", "object", "--as", "result"],
        );
        assert_eq!(
            output.status.success(),
            fault == "single-corrupt",
            "{}",
            output_text(&output)
        );
    }
}

#[test]
fn s3_upload_native_checksum_reuse_and_expected_hash() {
    use sha2::Digest as _;
    for (fault, options) in [
        ("upload-default", Vec::new()),
        (
            "upload-sha256",
            vec!["--integrity-checking=transfer=sha256".to_owned()],
        ),
        (
            "upload-md5",
            vec![
                "--expected-hash".to_owned(),
                format!(
                    "md5:{}",
                    md5::Md5::digest(b"payload")
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
            ],
        ),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("source"), b"payload").unwrap();
        let output = server
            .command(temp.path())
            .args(["--s3-endpoint", &server.address])
            .args(options)
            .args(["source", "--to", "s3://bucket", "--as", "object"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert!(server.gate.0.load(Ordering::Acquire));
    }
    let server = Server::start("upload-default");
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("source"), b"payload").unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--expected-hash",
            "md5:00000000000000000000000000000000",
            "source",
            "--to",
            "s3://bucket",
            "--as",
            "object",
        ],
    );
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        !server.gate.0.load(Ordering::Acquire),
        "mismatching source was uploaded"
    );
}

#[test]
fn s3_mapping_preserves_expected_hashes_in_failed_results() {
    use sha2::Digest as _;
    let server = Server::start("single-ok");
    let temp = tempfile::tempdir().unwrap();
    let digest = md5::Md5::digest(vec![b'x'; 65536])
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let entries = [
        ("good", digest.as_str()),
        ("bad", "00000000000000000000000000000000"),
    ]
    .map(|(name, value)| {
        serde_json::json!({
        "src": {"encoding": "utf-8", "value": name}, "dst": {"encoding": "utf-8", "value": name},
        "kind": "file", "expected_digest": {"algorithm": "md5", "value": value},
    }).to_string()
    })
    .join("\n");
    std::fs::write(temp.path().join("mapping"), entries).unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--mapping",
            "mapping",
            "--from",
            "s3://bucket",
            "--into",
            "output",
            "--results",
            "results.jsonl",
        ],
    );
    assert_eq!(output.status.code(), Some(23), "{}", output_text(&output));
    assert_eq!(
        std::fs::read(temp.path().join("output/good")).unwrap(),
        vec![b'x'; 65536]
    );
    assert!(!temp.path().join("output/bad").exists());
    let records = std::fs::read_to_string(temp.path().join("results.jsonl")).unwrap();
    let failed = records
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|record| record["disposition"] == "failed")
        .unwrap();
    assert_eq!(failed["expected_digest"]["algorithm"], "md5");
    assert_eq!(
        failed["expected_digest"]["value"],
        "00000000000000000000000000000000"
    );
}

#[test]
fn s3_hash_comparison_reuses_only_the_selected_algorithm() {
    let server = Server::start("single-ok");
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("result"), vec![b'x'; 65536]).unwrap();
    let mut counts = Vec::new();
    for algorithm in ["blake3", "sha256"] {
        let before = server.requests.load(Ordering::Relaxed);
        let output = server.cp(
            temp.path(),
            &[
                "--integrity-checking",
                &format!("compare={algorithm}"),
                "--from",
                "s3://bucket",
                "object",
                "--as",
                "result",
            ],
        );
        assert!(output.status.success(), "{}", output_text(&output));
        counts.push(server.requests.load(Ordering::Relaxed) - before);
    }
    // The fixture publishes only BLAKE3 metadata. SHA256 comparison must
    // obtain object bytes instead of silently comparing using BLAKE3.
    assert_eq!(counts[1], counts[0] + 1);
}

#[test]
fn s3_dry_run_does_not_validate_expected_hash() {
    let expected = "md5:00000000000000000000000000000000";
    let server = Server::start("upload-default");
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("source"), b"payload").unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--dry-run",
            "--expected-hash",
            expected,
            "source",
            "--to",
            "s3://bucket",
            "--as",
            "object",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        !server.gate.0.load(Ordering::Acquire),
        "dry run uploaded bytes"
    );

    let server = Server::start("single-ok");
    let destination = temp.path().join("result");
    std::fs::write(&destination, vec![b'x'; 65536]).unwrap();
    let remote_time = std::time::UNIX_EPOCH + Duration::from_secs(1700000000);
    std::fs::File::options()
        .write(true)
        .open(&destination)
        .unwrap()
        .set_modified(remote_time)
        .unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--dry-run",
            "-v",
            "--expected-hash",
            expected,
            "--from",
            "s3://bucket",
            "object",
            "--as",
            "result",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        !output_text(&output).contains("would copy"),
        "dry run compared an expected digest instead of keeping the metadata quick check: {}",
        output_text(&output)
    );
    assert_eq!(std::fs::read(destination).unwrap(), vec![b'x'; 65536]);
}

#[test]
fn s3_review_upload_hash_compares_objects_without_matching_stored_digest() {
    for (fault, algorithm, changed) in [
        ("single-upload-nohash", "blake3", false),
        ("single-upload-otherhash", "sha256", false),
        ("single-upload-nohash", "blake3", true),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::write(&source, vec![if changed { b'y' } else { b'x' }; 65536]).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1700000000))
            .unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--integrity-checking",
                &format!("compare={algorithm}"),
                "source",
                "--to",
                "s3://bucket",
                "--as",
                "object",
            ],
        );
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert!(
            server.gate.1.load(Ordering::Acquire),
            "{fault}: --hash did not compare object contents"
        );
        assert_eq!(
            server.gate.0.load(Ordering::Acquire),
            changed,
            "{fault}: unchanged object was uploaded again"
        );
    }
}

#[test]
fn s3_review_verify_only_reports_expected_hash_mismatch() {
    let server = Server::start("single-ok");
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("result"), vec![b'x'; 65536]).unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--verify-only",
            "--expected-hash",
            "md5:00000000000000000000000000000000",
            "--from",
            "s3://bucket",
            "object",
            "--as",
            "result",
        ],
    );
    assert_eq!(output.status.code(), Some(23), "{}", output_text(&output));
    let message = output_text(&output);
    assert!(message.contains("expected md5 hash"), "{message}");
    assert!(
        !message.contains("file missing, type differs, or size differs"),
        "{message}"
    );
    assert_eq!(
        std::fs::read(temp.path().join("result")).unwrap(),
        vec![b'x'; 65536]
    );
}

#[test]
fn s3_prune_reports_delete_failure_and_rejects_outside_listing() {
    for (fault, code, requests, planned) in [
        ("prune-denied", 23, 2, 1),
        ("prune-outside", 23, 1, 0),
        ("prune-invalid", 23, 1, 0),
        ("prune-folder-content", 23, 1, 0),
    ] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("empty")).unwrap();
        let server = Server::start(fault);
        let output = server.cp(
            temp.path(),
            &[
                "--srcs-in",
                "empty",
                "--to",
                "s3://bucket",
                "--into",
                "mirror",
                "--prune",
                "--results",
                "results.ndjson",
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), requests);
        let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
        let result: serde_json::Value =
            serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(result["deletions_planned"], planned);
        assert_eq!(result["deletions_completed"], 0);
    }
}

#[test]
fn s3_prune_limit_refuses_without_sending_delete() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("empty")).unwrap();
    let server = Server::start("prune-denied");
    let output = server.cp(
        temp.path(),
        &[
            "--srcs-in",
            "empty",
            "--to",
            "s3://bucket",
            "--into",
            "mirror",
            "--prune",
            "--max-delete",
            "0",
            "--results",
            "results.ndjson",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(25),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);
    let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
    let result: serde_json::Value = serde_json::from_str(records.lines().last().unwrap()).unwrap();
    assert_eq!(result["status"], "refused");
    assert_eq!(result["errors"], 0);
    assert_eq!(result["deletions_planned"], 1);
    assert_eq!(result["deletions_blocked"], 1);
    assert_eq!(result["deletions_completed"], 0);
}

#[test]
fn s3_prune_batches_account_for_every_key_and_continue_after_errors() {
    for (fault, code, planned, completed, requests) in [
        ("prune-batch", 0, 1001, 1001, 3),
        ("prune-concurrent", 0, 1001, 1001, 3),
        ("prune-mixed", 23, 2, 1, 2),
        ("prune-request-failure", 23, 1001, 1, 3),
    ] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("empty")).unwrap();
        let server = Server::start(fault);
        let output = server.cp(
            temp.path(),
            &[
                "--srcs-in",
                "empty",
                "--to",
                "s3://bucket",
                "--into",
                "mirror",
                "--prune",
                "--results",
                "results.ndjson",
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), requests);
        let text = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        assert_eq!(records.last().unwrap()["deletions_planned"], planned);
        assert_eq!(records.last().unwrap()["deletions_completed"], completed);
        assert_eq!(
            records.iter().filter(|r| r["action"] == "delete").count(),
            planned as usize
        );
    }
}

#[test]
fn s3_prune_can_ignore_unrepresentable_destination_keys() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir(temp.path().join("empty")).unwrap();
    let server = Server::start("prune-invalid");
    let output = server.cp(
        temp.path(),
        &[
            "--srcs-in",
            "empty",
            "--to",
            "s3://bucket",
            "--into",
            "mirror",
            "--prune",
            "--ignore",
            "bad/",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);
    let output = server.cp(
        temp.path(),
        &[
            "--srcs-in",
            "empty",
            "--to",
            "s3://bucket",
            "--into",
            "mirror",
            "--prune",
            "--delete-excluded",
        ],
    );
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument '--delete-excluded'")
    );
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn s3_unchanged_upload_does_not_read_body_unless_content_check_requested() {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source");
    std::fs::write(&path, vec![b'x'; 65536]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1700000000))
        .unwrap();
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(fd >= 0);
    let mut watch = unsafe { std::fs::File::from_raw_fd(fd) };
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert!(
        unsafe { libc::inotify_add_watch(watch.as_raw_fd(), name.as_ptr(), libc::IN_ACCESS) } >= 0
    );
    for flag in [None, Some("--hash")] {
        let server = Server::start("single-upload-nohash");
        let mut args = vec!["source", "--to", "s3://bucket", "--as", "object"];
        if let Some(flag) = flag {
            args.push(flag);
        }
        let output = server.cp(temp.path(), &args);
        assert!(output.status.success(), "{}", output_text(&output));
        assert!(
            !server.gate.0.load(Ordering::Acquire),
            "unchanged body uploaded"
        );
        let mut events = [0; 4096];
        match flag {
            None => assert_eq!(
                watch.read(&mut events).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            ),
            Some(_) => assert!(
                watch.read(&mut events).unwrap() > 0,
                "checksum did not read source"
            ),
        }
    }
}

#[test]
fn s3_head_failure_reports_http_status_without_a_response_body() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("source"), b"source").unwrap();
    let server = Server::start("head-denied");
    let output = server.cp(
        temp.path(),
        &["source", "--to", "s3://bucket", "--as", "object"],
    );
    assert_eq!(output.status.code(), Some(23), "{}", output_text(&output));
    assert!(
        output_text(&output).contains("S3 HEAD failed (HTTP 403)"),
        "{}",
        output_text(&output)
    );
}

#[test]
fn s3_get_throttling_without_a_body_is_retried() {
    for (retries, expected_exit, requests) in [(2, 0, 3), (0, 23, 2)] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start("single-get-throttle-once");
        let output = server
            .command_with_retries(temp.path(), retries)
            .args([
                "--s3-endpoint",
                &server.address,
                "--from",
                "s3://bucket",
                "object",
                "--as",
                "result",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "retries {retries}: {}",
            output_text(&output)
        );
        // One HEAD, then the throttled GET and its retry.
        assert_eq!(server.requests.load(Ordering::Relaxed), requests);
        assert_eq!(
            temp.path().join("result").exists(),
            expected_exit == 0,
            "retries {retries}"
        );
    }
}

#[test]
fn s3_download_retries_share_one_budget_across_statuses_and_error_codes() {
    for fault in [
        "single-get-throttle-always",
        "single-get-transient-always",
        "single-get-timeout-code-always",
    ] {
        let temp = tempfile::tempdir().unwrap();
        // An existing, different file takes the HEAD-then-download-loop path;
        // a fresh file would fetch its metadata with an SDK-only initial GET.
        std::fs::write(temp.path().join("result"), b"stale").unwrap();
        let server = Server::start(fault);
        let output = server
            .command_with_retries(temp.path(), 1)
            .args([
                "--s3-endpoint",
                &server.address,
                "--from",
                "s3://bucket",
                "object",
                "--as",
                "result",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(23),
            "{fault}: {}",
            output_text(&output)
        );
        // A HEAD to plan the named object, a HEAD to compare the existing
        // file, then the GET and exactly one retry from the download loop:
        // the SDK must not retry inside it (six requests when it does).
        assert_eq!(server.requests.load(Ordering::Relaxed), 4, "{fault}");
        assert_eq!(
            std::fs::read(temp.path().join("result")).unwrap(),
            b"stale",
            "{fault}"
        );
    }
}

#[test]
fn s3_upload_retries_share_one_budget_for_throttling_and_transient_errors() {
    for fault in ["upload-throttle-always", "upload-transient-always"] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("source"), b"small body").unwrap();
        let server = Server::start(fault);
        let output = server
            .command_with_retries(temp.path(), 1)
            .args([
                "--s3-endpoint",
                &server.address,
                "source",
                "--to",
                "s3://bucket",
                "--as",
                "object",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(23),
            "{fault}: {}",
            output_text(&output)
        );
        // One HEAD, then the PUT and exactly one retry: the in-memory body
        // must not also be retried inside the SDK.
        assert_eq!(server.requests.load(Ordering::Relaxed), 3, "{fault}");
    }
}

#[test]
fn s3_upload_retries_request_timeout_error_codes_within_the_budget() {
    for (retries, expected_exit, requests) in [(1, 0, 3), (0, 23, 2)] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("source"), b"small body").unwrap();
        let server = Server::start("upload-timeout-code-once");
        let output = server
            .command_with_retries(temp.path(), retries)
            .args([
                "--s3-endpoint",
                &server.address,
                "source",
                "--to",
                "s3://bucket",
                "--as",
                "object",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "retries {retries}: {}",
            output_text(&output)
        );
        // One HEAD, the PUT answered with HTTP 400 RequestTimeout, and one retry.
        assert_eq!(
            server.requests.load(Ordering::Relaxed),
            requests,
            "retries {retries}"
        );
    }
}

#[test]
fn s3_head_throttling_uses_the_retry_budget_and_keeps_permanent_errors_final() {
    for (fault, retries, expected_exit, requests) in [
        ("single-throttle-once", 2, 0, 2),
        ("single-transient-once", 2, 0, 2),
        ("single-throttle-once", 0, 23, 1),
        ("single-throttle-always", 2, 23, 3),
        ("head-denied", 2, 23, 1),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        std::fs::write(&path, vec![b'x'; 65536]).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1700000000))
            .unwrap();
        let server = Server::start(fault);
        let output = server
            .command_with_retries(temp.path(), retries)
            .args([
                "--s3-endpoint",
                &server.address,
                "source",
                "--to",
                "s3://bucket",
                "--as",
                "object",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{fault}: {}",
            output_text(&output)
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), requests, "{fault}");
    }
}

#[test]
fn s3_listing_costs_are_bounded_without_changing_selection() {
    for (fault, rules, expected_requests) in [
        ("listing-adaptive", vec!["--ignore", "archive/"], 4),
        ("listing-all-ignored", vec!["--ignore", "archive/"], 3),
        ("listing-flat", vec!["--ignore", "*.tmp"], 3),
        ("listing-wide", vec!["--ignore", "archive/"], 4),
        ("listing-nested", vec!["--ignore", "archive/"], 4),
        ("listing-deep", vec!["--ignore", "archive/"], 3),
        ("listing-nested-wide", vec!["--ignore", "archive/"], 5),
        (
            "listing-mixed",
            vec!["--ignore", "archive/", "--ignore", "*.tmp"],
            3,
        ),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let mut args = vec![
            "--from",
            "s3://bucket",
            "--srcs-in",
            "data",
            "--into",
            "out",
            "--dry-run",
            "--results",
            "results.jsonl",
        ];
        args.extend(rules);
        let output = server.cp(temp.path(), &args);
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert_eq!(
            server.requests.load(Ordering::Relaxed),
            expected_requests,
            "{fault}"
        );
        validate_results(temp.path());
        let records: Vec<serde_json::Value> =
            std::fs::read_to_string(temp.path().join("results.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
        let terminal = records
            .iter()
            .find(|record| record["type"] == "result")
            .unwrap();
        assert_eq!(
            terminal["files_transferred"],
            if fault == "listing-adaptive" { 1 } else { 0 },
            "{records:?}"
        );
        assert_eq!(
            terminal["files_excluded"],
            if fault == "listing-mixed" {
                3
            } else if fault == "listing-flat" {
                2
            } else {
                1
            }
        );
        if fault == "listing-adaptive" {
            let trace = records
                .iter()
                .find(|record| record["type"] == "trace")
                .unwrap();
            assert_eq!(trace["dst"]["value"], "out/file");
        }
    }
}

#[test]
fn s3_upload_destination_discovery_is_bounded() {
    for (fault, placement, success, expected_requests) in [
        ("listing-exists", "--into-new", false, 2),
        ("listing-budget", "--into", true, 3),
        ("listing-budget-many", "--into", true, 2),
        ("listing-complete", "--into", true, 1),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("one"), b"one").unwrap();
        std::fs::write(temp.path().join("two"), b"two").unwrap();
        let mut args = vec![
            "one",
            "two",
            "--to",
            "s3://bucket",
            placement,
            "data",
            "--dry-run",
        ];
        if fault == "listing-budget-many" {
            std::fs::write(temp.path().join("three"), b"three").unwrap();
            args.insert(0, "three");
        }
        let output = server.cp(temp.path(), &args);
        assert_eq!(
            output.status.success(),
            success,
            "{fault}: {}",
            output_text(&output)
        );
        assert_eq!(
            server.requests.load(Ordering::Relaxed),
            expected_requests,
            "{fault}"
        );
    }
}

#[test]
fn s3_ignored_subtree_counts_span_selectors_and_require_existence() {
    for (fault, sources, rule, success, excluded, requests) in [
        (
            "listing-ignored-root",
            vec!["--srcs-in", "data", "--srcs-in", "data"],
            "data/",
            true,
            1,
            4,
        ),
        (
            "listing-exact",
            vec!["data/archive/a", "data/archive/b"],
            "archive/",
            true,
            1,
            2,
        ),
        (
            "listing-empty",
            vec!["--srcs-in", "data"],
            "data/",
            false,
            0,
            2,
        ),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let mut args = vec![
            "--from",
            "s3://bucket",
            "--ignore",
            rule,
            "--dry-run",
            "--results",
            "results.jsonl",
        ];
        args.extend(sources);
        args.extend(["--into", "out"]);
        let output = server.cp(temp.path(), &args);
        assert_eq!(
            output.status.success(),
            success,
            "{fault}: {}",
            output_text(&output)
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), requests, "{fault}");
        let records = std::fs::read_to_string(temp.path().join("results.jsonl")).unwrap();
        let terminal: serde_json::Value =
            serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(terminal["files_excluded"], excluded, "{fault}: {terminal}");
        assert_eq!(terminal["files_transferred"], 0, "{fault}: {terminal}");
    }
}

// Eight quick listing pages take longer together than the high-latency
// threshold, although no single response is slow.
fn serve_latency_pages(socket: &mut TcpStream, first: &str) {
    let target = first.split_whitespace().nth(1).unwrap();
    if first.starts_with("HEAD ") {
        reply(socket, 404, &[], b"", true);
        return;
    }
    if target.contains("list-type=2") {
        let page = target
            .split(['?', '&'])
            .find_map(|field| field.strip_prefix("continuation-token=page"))
            .map_or(0, |page| page.parse::<usize>().unwrap());
        thread::sleep(Duration::from_millis(15));
        let next = if page < 7 {
            format!(
                "<IsTruncated>true</IsTruncated><NextContinuationToken>page{}</NextContinuationToken>",
                page + 1
            )
        } else {
            "<IsTruncated>false</IsTruncated>".into()
        };
        let xml = format!(
            "<ListBucketResult>{next}<Contents><Key>data/{page:05}</Key><Size>4</Size></Contents></ListBucketResult>"
        );
        reply(socket, 200, &[], xml.as_bytes(), false);
        return;
    }
    let fields = vec![
        ("ETag".into(), "\"fixture-v1\"".into()),
        (
            "Last-Modified".into(),
            "Tue, 14 Nov 2023 22:13:20 GMT".into(),
        ),
    ];
    reply(socket, 200, &fields, b"data", false);
}

#[test]
fn s3_path_latency_is_one_response_not_the_whole_listing() {
    let server = Server::start("latency-pages");
    let temp = tempfile::tempdir().unwrap();
    let output = server
        .command(temp.path())
        .env("SYQ_S3_DIAGNOSTICS", "1")
        .args(["--s3-endpoint", &server.address])
        .args([
            "--from",
            "s3://bucket",
            "--srcs-in",
            "data",
            "--into",
            "download",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    for page in 0..8 {
        assert_eq!(
            std::fs::read(temp.path().join(format!("download/{page:05}"))).unwrap(),
            b"data"
        );
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let trace = stderr
        .lines()
        .find_map(|line| line.strip_prefix("S3_DIAGNOSTICS "))
        .expect("diagnostics record");
    let trace: serde_json::Value = serde_json::from_str(trace).unwrap();
    let plan = trace["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["phase"] == "plan")
        .expect("plan record");
    let control = plan["control_s"].as_f64().expect("observed latency");
    assert!(control < 0.05, "listing time was taken for latency: {plan}");
    assert_eq!(plan["request_limit"], 64, "{plan}");
}
