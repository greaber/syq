//! Network fault tests use a local independent HTTP fixture. Real S3 protocol
//! and signature interoperability are exercised by scripts/test-s3.sh.
#[path = "s3/streams.rs"]
mod streams;

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
    fn command_for(&self, temp: &Path, mode: &str) -> Command {
        self.command_mode(temp, mode, 0)
    }
    fn command_with_retries(&self, temp: &Path, retries: u32) -> Command {
        self.command_mode(temp, "cp", retries)
    }
    fn command_mode(&self, temp: &Path, mode: &str, retries: u32) -> Command {
        self.command_mode_with_part_size(temp, mode, retries, true)
    }
    fn command_with_part_size(&self, temp: &Path, retries: u32, explicit: bool) -> Command {
        self.command_mode_with_part_size(temp, "cp", retries, explicit)
    }
    fn command_mode_with_part_size(
        &self,
        temp: &Path,
        mode: &str,
        retries: u32,
        explicit: bool,
    ) -> Command {
        let retry_option = format!("s3-retries={retries}");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        if mode == "rm" {
            command.args([
                "rm",
                "--s3-region",
                "us-east-1",
                "--s3-header",
                "X-Tigris-Consistent: true",
                "--no-progress",
            ]);
        } else {
            command.args([
                "cp",
                "--s3-region",
                "us-east-1",
                "--performance-tuning",
                &retry_option,
                "--s3-header",
                "X-Tigris-Consistent: true",
                "--no-progress",
                "--performance-tuning",
                "s3-max-concurrent-parts-per-object=3",
            ]);
        }
        command
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
        if mode == "cp" && explicit {
            command.args(["--performance-tuning", "s3-part-size=5M"]);
        }
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
    if fault == "copy-root-marker" {
        let path = first.split_whitespace().nth(1).unwrap();
        match (method, path.split('?').next().unwrap()) {
            ("HEAD", "/source/data" | "/destination/child") =>
                reply(&mut socket, 404, &[], b"", true),
            ("GET", "/source/") if path.contains("list-type=2") => reply(&mut socket, 200, &[],
                b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>data/</Key><Size>0</Size></Contents><Contents><Key>data/child</Key><Size>4</Size></Contents></ListBucketResult>", false),
            ("HEAD", "/source/data/") => reply(&mut socket, 200,
                &[("Content-Length".into(), "0".into()), ("ETag".into(), "\"marker\"".into()),
                  ("Last-Modified".into(), "Wed, 01 Jan 2020 00:00:00 GMT".into())], b"", true),
            ("GET", "/source/data/child") => reply(&mut socket, 200,
                &[("ETag".into(), "\"source\"".into())], b"data", false),
            ("HEAD", "/source/data/child") => reply(&mut socket, 200,
                &[("Content-Length".into(), "4".into()), ("ETag".into(), "\"source\"".into())], b"", true),
            ("PUT", "/destination/child") => reply(&mut socket, 200, &[],
                b"<CopyObjectResult><ETag>&quot;copied&quot;</ETag></CopyObjectResult>", false),
            _ => panic!("unexpected root-marker request: {first}"),
        }
        return;
    }
    if fault == "marker-head-failure" {
        let path = first.split_whitespace().nth(1).unwrap();
        if method == "HEAD" {
            reply(
                &mut socket,
                if path == "/source/data/marker/" {
                    403
                } else {
                    404
                },
                &[],
                b"",
                true,
            );
        } else {
            assert_eq!(method, "GET", "mutation after failed source HEAD");
            let body = if path.starts_with("/source/") {
                "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>data/marker/</Key><Size>0</Size></Contents></ListBucketResult>"
            } else {
                "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"
            };
            reply(&mut socket, 200, &[], body.as_bytes(), false);
        }
        return;
    }
    if fault == "server-tree-region"
        && first
            .split_whitespace()
            .nth(1)
            .unwrap()
            .starts_with("/destination")
    {
        assert_eq!(method, "GET", "copying continued after discovery failed");
        reply(
            &mut socket,
            301,
            &[("x-amz-bucket-region".into(), "eu-central-1".into())],
            b"",
            false,
        );
        return;
    }
    if fault.starts_with("server-tree") {
        let path = first.split_whitespace().nth(1).unwrap();
        if method == "HEAD" {
            if path == "/source/data" {
                reply(&mut socket, 404, &[], b"", true);
            } else if path.starts_with("/destination/")
                && (fault.ends_with("skipped") || fault.ends_with("missing"))
            {
                if fault.ends_with("missing") {
                    reply(&mut socket, 404, &[], b"", true);
                } else {
                    reply(
                        &mut socket,
                        200,
                        &[
                            ("Content-Length".into(), "4".into()),
                            ("ETag".into(), "\"source\"".into()),
                        ],
                        b"",
                        true,
                    );
                }
            } else {
                assert!(
                    path.starts_with("/source/data/"),
                    "unnecessary destination HEAD: {path}"
                );
                if fault.ends_with("unsupported") && headers.contains_key("x-amz-checksum-mode") {
                    assert!(
                        !gate.0.swap(true, Ordering::SeqCst),
                        "unsupported checksum mode retried on another object"
                    );
                    reply(&mut socket, 501, &[], b"", true);
                } else if fault.ends_with("denied")
                    && path.ends_with("/a")
                    && headers.contains_key("x-amz-checksum-mode")
                {
                    reply(&mut socket, 403, &[], b"", true);
                } else {
                    if fault.ends_with("denied") && path.ends_with("/b") {
                        assert!(
                            headers.contains_key("x-amz-checksum-mode"),
                            "one object's permission failure disabled other checksum reads"
                        );
                    }
                    reply(
                        &mut socket,
                        200,
                        &[
                            ("Content-Length".into(), "4".into()),
                            ("ETag".into(), "\"source\"".into()),
                        ],
                        b"",
                        true,
                    );
                }
            }
        } else if method == "GET" {
            let keys: &[&str] = if path.starts_with("/source?") || path.starts_with("/source/?") {
                &["data/a", "data/b"]
            } else {
                assert!(
                    !gate.1.swap(true, Ordering::SeqCst),
                    "destination listing was not reused for prune"
                );
                if fault.ends_with("skipped") || fault.ends_with("missing") {
                    &["out/a/part1", "out/b/part1"]
                } else if fault.ends_with("prune") || fault.ends_with("changed") {
                    &["out/a/part1"]
                } else {
                    &[]
                }
            };
            let entries: String = keys
                .iter()
                .map(|key| format!("<Contents><Key>{key}</Key><Size>4</Size></Contents>"))
                .collect();
            let body = format!(
                "<ListBucketResult><IsTruncated>false</IsTruncated>{entries}</ListBucketResult>"
            );
            reply(&mut socket, 200, &[], body.as_bytes(), false);
        } else if method == "PUT" {
            assert!(
                matches!(
                    path.split('?').next().unwrap(),
                    "/destination/out/a" | "/destination/out/b"
                ),
                "{path}"
            );
            assert!(!headers.contains_key("if-none-match"));
            assert_eq!(headers["x-amz-copy-source-if-match"], "\"source\"");
            if fault.ends_with("changed") {
                reply(
                    &mut socket,
                    412,
                    &[],
                    b"<Error><Code>PreconditionFailed</Code></Error>",
                    false,
                );
                return;
            }
            reply(
                &mut socket,
                200,
                &[],
                b"<CopyObjectResult><ETag>&quot;copied&quot;</ETag></CopyObjectResult>",
                false,
            );
        } else if method == "POST" && path.contains("delete") {
            assert!(fault.ends_with("prune"));
            let mut body = vec![0; headers["content-length"].parse().unwrap()];
            socket.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("<Key>out/a/part1</Key>"), "{body}");
            assert_eq!(body.matches("<Key>").count(), 1);
            reply(
                &mut socket,
                200,
                &[],
                b"<DeleteResult><Deleted><Key>out/a/part1</Key></Deleted></DeleteResult>",
                false,
            );
        } else {
            panic!("unexpected server-copy request: {first}");
        }
        return;
    }
    if fault == "symlink-transfer-denied" {
        let path = first.split_whitespace().nth(1).unwrap();
        if method == "GET" && path.contains("list-type=2") {
            reply(&mut socket, 200, &[],
                b"<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>data/original</Key><Size>4</Size></Contents></ListBucketResult>", false);
        } else if method == "HEAD" && path == "/source/data" {
            reply(&mut socket, 404, &[], b"", true);
        } else if method == "HEAD" && path.starts_with("/source/") {
            let mut fields = vec![
                ("Content-Length".into(), "4".into()),
                ("ETag".into(), "\"source-etag\"".into()),
            ];
            for (name, value) in [
                ("syq-format", "1"),
                ("syq-kind", "symlink"),
                ("syq-mode", "511"),
                ("syq-uid", "0"),
                ("syq-gid", "0"),
                ("syq-mtime", "1700000000"),
                ("syq-mtime-nsec", "0"),
            ] {
                fields.push((format!("x-amz-meta-{name}"), value.into()));
            }
            reply(&mut socket, 200, &fields, b"", true);
        } else {
            assert!(method == "HEAD" || method == "GET", "{first}");
            reply(
                &mut socket,
                403,
                &[],
                b"<Error><Code>AccessDenied</Code></Error>",
                method == "HEAD",
            );
        }
        return;
    }
    if fault.starts_with("server-copy") {
        let path = first.split_whitespace().nth(1).unwrap();
        let multipart = fault.contains("multipart");
        let comparison = fault.contains("compare");
        if fault.contains("storage-class") {
            assert_eq!(headers["x-amz-storage-class"], "INTELLIGENT_TIERING");
        } else {
            assert!(
                !headers.contains_key("x-amz-storage-class"),
                "source class must not be preserved by default"
            );
        }
        if method == "GET"
            && path.contains("list-type=2")
            && fault == "server-copy-multipart-cached-unsupported"
        {
            reply(
                &mut socket,
                200,
                &[],
                b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
                false,
            );
        } else if method == "HEAD" {
            if fault == "server-copy-heads-overlap" && path.starts_with("/source/") {
                let (mine, other) = if path == "/source/original" {
                    (&gate.0, &gate.1)
                } else {
                    (&gate.1, &gate.0)
                };
                mine.store(true, Ordering::Release);
                let deadline = std::time::Instant::now() + Duration::from_secs(3);
                while !other.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(2));
                }
                assert!(
                    other.load(Ordering::Acquire),
                    "source planning HEADs did not overlap"
                );
            }
            if matches!(
                fault,
                "server-copy-compare-unavailable"
                    | "server-copy-compare-bad-request"
                    | "server-copy-compare-unsupported"
            ) && headers.contains_key("x-amz-checksum-mode")
            {
                let status = match fault {
                    "server-copy-compare-bad-request" => 400,
                    "server-copy-compare-unsupported" => 501,
                    _ => 403,
                };
                reply(&mut socket, status, &[], b"", true);
                return;
            }
            let source = path.starts_with("/source/");
            if source || comparison {
                let same_etag = !matches!(
                    fault,
                    "server-copy-compare-checksum" | "server-copy-compare-composite"
                );
                let mut fields = vec![
                    (
                        "Content-Length".into(),
                        if fault == "server-copy-automatic" {
                            (32 * 1024 * 1024).to_string()
                        } else if multipart {
                            (6 * 1024 * 1024).to_string()
                        } else {
                            "4".into()
                        },
                    ),
                    (
                        "ETag".into(),
                        if source || same_etag {
                            "\"source-etag\"".into()
                        } else {
                            "\"different-etag\"".into()
                        },
                    ),
                    ("Expires".into(), "0".into()),
                    ("x-amz-storage-class".into(), "STANDARD_IA".into()),
                    (
                        "x-amz-website-redirect-location".into(),
                        "/new-location".into(),
                    ),
                    (
                        "Last-Modified".into(),
                        if source {
                            "Wed, 01 Jan 2020 00:00:00 GMT".into()
                        } else {
                            "Thu, 02 Jan 2020 00:00:00 GMT".into()
                        },
                    ),
                ];
                if matches!(
                    fault,
                    "server-copy-compare-checksum"
                        | "server-copy-compare-composite"
                        | "server-copy-compare-conflict"
                ) {
                    fields.push((
                        "x-amz-checksum-type".into(),
                        if fault.ends_with("composite") {
                            "COMPOSITE".into()
                        } else {
                            "FULL_OBJECT".into()
                        },
                    ));
                    fields.push((
                        "x-amz-checksum-sha256".into(),
                        if !source && fault.ends_with("conflict") {
                            "BBBB".into()
                        } else {
                            "AAAA".into()
                        },
                    ));
                }
                if fault == "server-copy-versioned" && source {
                    fields.push(("x-amz-version-id".into(), "snapshot-version".into()));
                }
                if fault.ends_with("zero-tags") {
                    fields.push(("x-amz-tagging-count".into(), "0".into()));
                }
                if fault.ends_with("tags-denied") || fault.ends_with("-known-unsupported") {
                    fields.push(("x-amz-tagging-count".into(), "1".into()));
                }
                if fault == "server-copy-compare-metadata" {
                    fields.push((
                        "x-amz-meta-project".into(),
                        if source { "new".into() } else { "old".into() },
                    ));
                }
                reply(&mut socket, 200, &fields, b"", true);
            } else {
                reply(&mut socket, 404, &[], b"", true);
            }
        } else if multipart && path.contains("tagging") {
            assert!(!fault.ends_with("zero-tags"));
            if fault.ends_with("unsupported") {
                assert!(
                    !gate.0.swap(true, Ordering::Relaxed),
                    "tag probe was not cached"
                );
                reply(
                    &mut socket,
                    501,
                    &[],
                    b"<Error><Code>NotImplemented</Code></Error>",
                    false,
                );
                return;
            }
            if fault.ends_with("denied") {
                reply(
                    &mut socket,
                    403,
                    &[],
                    b"<Error><Code>AccessDenied</Code></Error>",
                    false,
                );
                return;
            }
            assert_eq!(method, "GET");
            reply(
                &mut socket,
                200,
                &[],
                if fault == "server-copy-multipart-tag-encoding" {
                    "<Tagging><TagSet><Tag><Key>project name</Key><Value>a b+c/é</Value></Tag></TagSet></Tagging>".as_bytes()
                } else {
                    b"<Tagging><TagSet/></Tagging>"
                },
                false,
            );
        } else if multipart && method == "POST" && path.contains("uploads") {
            if fault == "server-copy-multipart-tag-encoding" {
                assert_eq!(
                    headers["x-amz-tagging"],
                    "project%20name=a%20b%2Bc%2F%C3%A9"
                );
            }
            assert_eq!(headers.get("expires").map(String::as_str), Some("0"));
            reply(&mut socket, 200, &[], b"<InitiateMultipartUploadResult><UploadId>owned</UploadId></InitiateMultipartUploadResult>", false);
        } else if multipart && method == "POST" {
            assert!(!headers.contains_key("if-none-match"));
            let length: usize = headers["content-length"].parse().unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            assert!(
                body.find("<PartNumber>1</PartNumber>").unwrap()
                    < body.find("<PartNumber>2</PartNumber>").unwrap()
            );
            assert!(!fault.ends_with("fails"));
            reply(&mut socket, 200, &[], b"<CompleteMultipartUploadResult><ETag>&quot;complete&quot;</ETag></CompleteMultipartUploadResult>", false);
        } else if multipart && method == "DELETE" {
            assert!(path.contains("uploadId=owned"));
            if fault == "server-copy-multipart-drain-fails" {
                assert!(
                    gate.1.load(Ordering::Acquire),
                    "abort raced unfinished second part"
                );
            }
            reply(&mut socket, 204, &[], b"", false);
        } else if method == "PUT" {
            if fault == "server-copy-multipart-cached-unsupported" {
                assert!(matches!(
                    path.split('?').next().unwrap(),
                    "/destination/copied/original" | "/destination/copied/other"
                ));
            } else {
                assert_eq!(path.split('?').next().unwrap(), "/destination/copied");
            }
            assert_eq!(
                headers["x-amz-copy-source"],
                if fault == "server-copy-versioned" {
                    "source/original?versionId=snapshot-version"
                } else if fault == "server-copy-multipart-cached-unsupported"
                    && path.starts_with("/destination/copied/other?")
                {
                    "source/other"
                } else {
                    "source/original"
                }
            );
            assert_eq!(headers["x-amz-copy-source-if-match"], "\"source-etag\"");
            if multipart {
                assert!(path.contains("uploadId=owned"));
                let first = headers["x-amz-copy-source-range"] == "bytes=0-5242879";
                if !first {
                    assert_eq!(headers["x-amz-copy-source-range"], "bytes=5242880-6291455");
                }
                if matches!(
                    fault,
                    "server-copy-multipart-parallel" | "server-copy-multipart-drain-fails"
                ) {
                    if first {
                        gate.0.store(true, Ordering::Release);
                        let deadline = std::time::Instant::now() + Duration::from_secs(3);
                        while !gate.1.load(Ordering::Acquire)
                            && std::time::Instant::now() < deadline
                        {
                            thread::sleep(Duration::from_millis(2));
                        }
                        assert!(gate.1.load(Ordering::Acquire), "parts did not overlap");
                        if fault.ends_with("fails") {
                            gate.0.store(false, Ordering::Release);
                            while gate.1.load(Ordering::Acquire)
                                && std::time::Instant::now() < deadline
                            {
                                thread::sleep(Duration::from_millis(2));
                            }
                            assert!(
                                !gate.1.load(Ordering::Acquire),
                                "second part did not acknowledge failure"
                            );
                        }
                    } else {
                        let deadline = std::time::Instant::now() + Duration::from_secs(3);
                        while !gate.0.load(Ordering::Acquire)
                            && std::time::Instant::now() < deadline
                        {
                            thread::sleep(Duration::from_millis(2));
                        }
                        assert!(gate.0.load(Ordering::Acquire), "first part did not start");
                        gate.1.store(true, Ordering::Release);
                        if fault.ends_with("fails") {
                            while gate.0.load(Ordering::Acquire)
                                && std::time::Instant::now() < deadline
                            {
                                thread::sleep(Duration::from_millis(2));
                            }
                            assert!(
                                !gate.0.load(Ordering::Acquire),
                                "first part did not acknowledge overlap"
                            );
                            gate.1.store(false, Ordering::Release);
                            thread::sleep(Duration::from_millis(100));
                            gate.1.store(true, Ordering::Release);
                        }
                    }
                }
                if fault.ends_with("fails") && first {
                    reply(
                        &mut socket,
                        412,
                        &[],
                        b"<Error><Code>PreconditionFailed</Code></Error>",
                        false,
                    );
                } else {
                    reply(
                        &mut socket,
                        200,
                        &[],
                        b"<CopyPartResult><ETag>&quot;part&quot;</ETag></CopyPartResult>",
                        false,
                    );
                }
            } else {
                if fault == "server-copy-only-new" {
                    assert_eq!(headers["if-none-match"], "*");
                } else {
                    assert!(!headers.contains_key("if-none-match"));
                }
                assert_eq!(headers["x-amz-website-redirect-location"], "/new-location");
                assert!(
                    !matches!(
                        fault,
                        "server-copy-compare-etag"
                            | "server-copy-compare-checksum"
                            | "server-copy-compare-unavailable"
                    ),
                    "unchanged object was copied"
                );
                if fault.ends_with("fails") {
                    reply(
                        &mut socket,
                        412,
                        &[],
                        b"<Error><Code>PreconditionFailed</Code></Error>",
                        false,
                    );
                } else {
                    reply(
                        &mut socket,
                        200,
                        &[],
                        b"<CopyObjectResult><ETag>&quot;copied&quot;</ETag></CopyObjectResult>",
                        false,
                    );
                }
            }
        } else {
            panic!("server-side copy must not read or relay contents: {first}");
        }
        return;
    }
    if fault == "rm-explicit-collision" {
        let body = if method == "HEAD" {
            assert!(first.contains("/bucket/foo "));
            ""
        } else if first.contains("versions") {
            if first.contains("delimiter=") {
                "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>foo</Key><VersionId>file</VersionId><IsLatest>true</IsLatest></Version></ListVersionsResult>"
            } else {
                assert!(first.contains("prefix=foo%2F"));
                "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>foo/</Key><VersionId>root</VersionId></Version><Version><Key>foo/nested/child</Key><VersionId>child</VersionId></Version></ListVersionsResult>"
            }
        } else {
            assert!(first.contains("prefix=foo%2F"));
            "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>foo/</Key><Size>0</Size></Contents><Contents><Key>foo/nested/child</Key><Size>4</Size></Contents></ListBucketResult>"
        };
        reply(&mut socket, 200, &[], body.as_bytes(), method == "HEAD");
        return;
    }
    if fault == "remove-planning-interrupt" {
        assert_eq!(method, "GET");
        gate.0.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !gate.1.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        // The client must exit before this response is released.
        return;
    }
    if fault == "remove-exact-bounded" {
        assert_eq!(method, "GET");
        assert!(first.contains("delimiter="));
        let body = if first.contains("version-id-marker=old") {
            br#"<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>ghost-other/</NextKeyMarker><DeleteMarker><Key>ghost</Key><VersionId>hidden</VersionId><IsLatest>true</IsLatest></DeleteMarker><CommonPrefixes><Prefix>ghost-other/</Prefix></CommonPrefixes></ListVersionsResult>"#.as_slice()
        } else {
            assert!(!first.contains("key-marker="));
            br#"<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>ghost[opaque-cache-state]</NextKeyMarker><NextVersionIdMarker>old</NextVersionIdMarker><Version><Key>ghost</Key><VersionId>old</VersionId><IsLatest>false</IsLatest></Version></ListVersionsResult>"#.as_slice()
        };
        reply(&mut socket, 200, &[], body, false);
        return;
    }
    if fault == "remove-ghost" {
        assert_eq!(method, "GET");
        assert!(first.contains("versions"));
        if first.contains("delimiter=") {
            reply(&mut socket, 200, &[], br#"<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>ghost</Key><VersionId>old</VersionId><IsLatest>false</IsLatest></Version><DeleteMarker><Key>ghost</Key><VersionId>hidden</VersionId><IsLatest>true</IsLatest></DeleteMarker></ListVersionsResult>"#, false);
            return;
        }
        reply(&mut socket, 200, &[], br#"<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>ghost/child</Key><VersionId>child</VersionId><IsLatest>true</IsLatest></Version></ListVersionsResult>"#, false);
        return;
    }
    if fault == "remove-prefix-check" {
        if method == "HEAD" {
            reply(&mut socket, 404, &[], b"", true);
        } else {
            assert_eq!(method, "GET");
            assert!(
                first.contains("max-keys=1"),
                "existence probe must be bounded"
            );
            assert!(first.contains("prefix=tree%2F"));
            reply(&mut socket, 200, &[], b"<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>tree/child</Key><Size>0</Size></Contents></ListBucketResult>", false);
        }
        return;
    }
    if fault == "remove-head-throttle" {
        assert_eq!(method, "HEAD");
        if requests.load(Ordering::Relaxed) == 1 {
            reply(&mut socket, 429, &[], b"", true);
        } else {
            // rm only needs existence; even metadata from a future format is removable.
            reply(
                &mut socket,
                200,
                &[("x-amz-meta-syq-format".into(), "999".into())],
                b"",
                true,
            );
        }
        return;
    }
    if fault.starts_with("remove-bulk") && method == "GET" && !first.contains("delimiter=") {
        let second = first.contains("version-id-marker=");
        let range = if second { 1000..1001 } else { 0..1000 };
        let mut entries = range.map(|i| format!("<Version><Key>tree/key</Key><VersionId>v{i}</VersionId><IsLatest>false</IsLatest></Version>")).collect::<String>();
        if second {
            entries.push_str("<DeleteMarker><Key>tree/key</Key><VersionId>marker</VersionId><IsLatest>true</IsLatest></DeleteMarker>");
        }
        let cursor = if second {
            "<IsTruncated>false</IsTruncated>"
        } else {
            "<IsTruncated>true</IsTruncated><NextKeyMarker>tree/key</NextKeyMarker><NextVersionIdMarker>v999</NextVersionIdMarker>"
        };
        reply(
            &mut socket,
            200,
            &[],
            format!("<ListVersionsResult>{cursor}{entries}</ListVersionsResult>").as_bytes(),
            false,
        );
        return;
    }
    if fault.starts_with("remove-") {
        if method == "GET" && first.contains("delimiter=") {
            reply(
                &mut socket,
                200,
                &[],
                b"<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>",
                false,
            );
            return;
        }
        if method == "GET" {
            assert!(first.contains("versions"));
            let body = if fault == "remove-outside" {
                "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>outside/key</Key><VersionId>v</VersionId></Version></ListVersionsResult>"
            } else if fault == "remove-no-id" {
                "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>tree/key</Key></Version></ListVersionsResult>"
            } else if fault == "remove-no-cursor" {
                "<ListVersionsResult><IsTruncated>true</IsTruncated><Version><Key>tree/key</Key><VersionId>v</VersionId></Version></ListVersionsResult>"
            } else if first.contains("version-id-marker=v1") {
                "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>tree/key</Key><VersionId>v2</VersionId></Version></ListVersionsResult>"
            } else {
                "<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>tree/key</NextKeyMarker><NextVersionIdMarker>v1</NextVersionIdMarker><DeleteMarker><Key>tree/key</Key><VersionId>marker</VersionId></DeleteMarker><Version><Key>tree/key</Key><VersionId>v1</VersionId></Version></ListVersionsResult>"
            };
            let body = if fault.starts_with("remove-null") {
                body.replace("<VersionId>v1</VersionId>", "<VersionId>null</VersionId>")
            } else {
                body.to_owned()
            };
            reply(&mut socket, 200, &[], body.as_bytes(), false);
        } else {
            assert_eq!(method, "POST");
            assert!(first.contains("delete"));
            let length: usize = headers["content-length"].parse().unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            let versions: Vec<_> = body
                .split("<VersionId>")
                .skip(1)
                .map(|s| s.split("</VersionId>").next().unwrap())
                .collect();
            assert!(!versions.is_empty() && versions.len() <= 1000);
            let markers = versions.contains(&"marker");
            assert!(
                !markers || versions.len() == 1,
                "mixed data and marker phase"
            );
            if !matches!(fault, "remove-ok" | "remove-null" | "remove-bulk") {
                assert!(!markers, "must preserve markers after data failure");
            }
            if fault == "remove-bulk-interrupt" {
                gate.0.store(true, Ordering::SeqCst);
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while !gate.1.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(2));
                }
                assert!(
                    gate.1.load(Ordering::SeqCst),
                    "test did not release in-flight deletion"
                );
            }
            if matches!(fault, "remove-bulk" | "remove-bulk-failure") && !markers {
                let (arrived, peer) = if versions.len() == 1000 {
                    (&gate.0, &gate.1)
                } else {
                    (&gate.1, &gate.0)
                };
                arrived.store(true, Ordering::SeqCst);
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !peer.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(2));
                }
                assert!(peer.load(Ordering::SeqCst), "removal batches ran serially");
                if versions.len() == 1000 {
                    thread::sleep(Duration::from_millis(200));
                }
            }
            if fault == "remove-denied"
                || (fault == "remove-bulk-failure" && versions.len() == 1000)
            {
                reply(
                    &mut socket,
                    403,
                    &[],
                    b"<Error><Code>AccessDenied</Code><Message>denied</Message></Error>",
                    false,
                );
            } else {
                let entries = versions.iter().rev().map(|version| {
                    if fault == "remove-null-marker-created" && *version == "null" {
                        "<Deleted><Key>tree/key</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>new-marker</DeleteMarkerVersionId></Deleted>".to_owned()
                    } else if fault == "remove-null-marker-ambiguous" && *version == "null" {
                        "<Deleted><Key>tree/key</Key><DeleteMarker>true</DeleteMarker></Deleted>".to_owned()
                    } else if fault == "remove-marker-created" && *version == "v1" {
                        "<Deleted><Key>tree/key</Key><VersionId>v1</VersionId><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>new-marker</DeleteMarkerVersionId></Deleted>".to_owned()
                    } else if *version == "marker" {
                        "<Deleted><Key>tree/key</Key><VersionId>marker</VersionId><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>marker</DeleteMarkerVersionId></Deleted>".to_owned()
                    } else if fault == "remove-null" && *version == "null" {
                        "<Deleted><Key>tree/key</Key></Deleted>".to_owned()
                    } else if fault == "remove-mixed" && *version == "v1" {
                        format!("<Error><Key>tree/key</Key><VersionId>{version}</VersionId><Code>AccessDenied</Code><Message>denied</Message></Error>")
                    } else if fault == "remove-omitted" && *version == "v1" {
                        String::new()
                    } else {
                        format!("<Deleted><Key>tree/key</Key><VersionId>{version}</VersionId></Deleted>")
                    }
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
    if fault == "latency-pages" {
        serve_latency_pages(&mut socket, first);
        return;
    }
    if fault.starts_with("wrong-region") {
        // A prefix is looked up with a HEAD and a listing at once. Hold one of
        // them back so each gets a turn at being the first failure.
        let held_back = match fault {
            "wrong-region-head-last" => "HEAD",
            "wrong-region-listing-last" => "GET",
            _ => "",
        };
        if method == held_back {
            thread::sleep(Duration::from_millis(300));
        }
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
    let worker = thread::spawn(move || {
        serve(
            socket,
            "ok",
            Arc::new(AtomicUsize::new(0)),
            Arc::new((AtomicBool::new(false), AtomicBool::new(false))),
        )
    });
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
fn parsed_results(temp: &Path) -> Vec<serde_json::Value> {
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
    values
}
fn validate_results(temp: &Path) {
    let values = parsed_results(temp);
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
    for control in [
        "--performance-tuning=s3-max-concurrent-requests=1",
        "--resource-limits=s3-max-concurrent-requests=1,s3-max-concurrent-objects=1",
    ] {
        let temp = tempfile::tempdir().unwrap();
        for extra in [false, true] {
            let mut args = vec!["--from", "s3://bucket", "data", "--as", "result", control];
            if extra {
                args.extend(["--dry-run", "--hash"]);
            }
            let output = server.cp(temp.path(), &args);
            assert!(output.status.success(), "{}", output_text(&output));
        }
        assert_eq!(
            std::fs::metadata(temp.path().join("result")).unwrap().len(),
            SIZE as u64
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
    let temp = tempfile::tempdir().unwrap();
    // A named object is found with a HEAD. A prefix is found with a HEAD and
    // a listing sent together, and either may be the first to fail.
    for (fault, selector) in [
        ("wrong-region", &["object"][..]),
        ("wrong-region-listing-last", &["--srcs-in", "prefix"][..]),
        ("wrong-region-head-last", &["--srcs-in", "prefix"][..]),
    ] {
        let server = Server::start(fault);
        let mut args = vec!["--from", "s3://bucket"];
        args.extend_from_slice(selector);
        args.extend_from_slice(&["--into", "output"]);
        let output = server.cp(temp.path(), &args);
        let text = output_text(&output);
        assert!(!output.status.success(), "{text}");
        assert!(
            text.contains("(HTTP 301): the bucket is in region eu-central-1")
                && text.contains("--s3-region eu-central-1"),
            "{fault}: {text}"
        );
    }
    let server = Server::start("wrong-region");
    for flags in [vec![], vec!["--s3-all-versions"]] {
        let output = server
            .command_for(temp.path(), "rm")
            .args([
                "--s3-endpoint",
                &server.address,
                "--on",
                "s3://bucket",
                "object",
            ])
            .args(flags)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            output_text(&output).contains("--s3-region eu-central-1"),
            "{}",
            output_text(&output)
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
fn s3_unreadable_recovery_record_is_named_and_stale_temporaries_are_removed() {
    let temp = tempfile::tempdir().unwrap();
    let server = Server::start("corrupt");
    let download = |server: &Server| {
        server.cp(
            temp.path(),
            &[
                "--integrity-checking=transfer=blake3",
                "--from",
                "s3://bucket",
                "data",
                "--as",
                "download",
            ],
        )
    };
    let output = download(&server);
    assert_eq!(output.status.code(), Some(23), "{}", output_text(&output));
    let cache = temp.path().join("cache/syq/s3");
    let record = std::fs::read_dir(&cache)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|e| e == "json"))
        .expect("failed multipart download keeps its recovery record");
    // A machine crash can persist the rename without the record's contents.
    std::fs::write(&record, b"").unwrap();
    let stale = record.with_extension("tmp");
    std::fs::write(&stale, b"{").unwrap();
    let unrelated = cache.join("unrelated.tmp");
    std::fs::write(&unrelated, b"{").unwrap();

    let output = download(&server);
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        output_text(&output).contains(record.to_str().unwrap()),
        "{}",
        output_text(&output)
    );
    assert!(!stale.exists());
    assert!(unrelated.exists());
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
                    "--mapping",
                    &expected_mapping(temp.path(), "object", "result", &expected),
                    "--from",
                    "s3://bucket",
                    "--into",
                    ".",
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
        "--mapping",
        &expected_mapping(temp.path(), "object", "result", &expected),
        "--from",
        "s3://bucket",
        "--into",
        ".",
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
    for (fault, options) in [
        ("upload-default", Vec::new()),
        (
            "upload-sha256",
            vec!["--integrity-checking=transfer=sha256".to_owned()],
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
            "--mapping",
            &expected_mapping(
                temp.path(),
                "source",
                "object",
                "md5:00000000000000000000000000000000",
            ),
            "--to",
            "s3://bucket",
            "--into",
            ".",
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
        "kind": "file", "expected_hash": {"algorithm": "md5", "value": value},
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
    assert_eq!(failed["expected_hash"]["algorithm"], "md5");
    assert_eq!(
        failed["expected_hash"]["value"],
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
            "--mapping",
            &expected_mapping(temp.path(), "source", "object", expected),
            "--to",
            "s3://bucket",
            "--into",
            ".",
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
            "--mapping",
            &expected_mapping(temp.path(), "object", "result", expected),
            "--from",
            "s3://bucket",
            "--into",
            ".",
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
fn s3_remove_versions_validates_listing_before_deleting_and_reports_failures() {
    for (fault, exit, requests) in [
        ("remove-outside", 1, 1),
        ("remove-no-id", 1, 1),
        ("remove-no-cursor", 1, 1),
        ("remove-denied", 23, 3),
        ("remove-ok", 0, 4),
        ("remove-null", 0, 4),
        ("remove-null-marker-created", 23, 3),
        ("remove-null-marker-ambiguous", 23, 3),
        ("remove-marker-created", 23, 3),
        ("remove-mixed", 23, 3),
        ("remove-omitted", 23, 3),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start(fault);
        let output = server
            .command_for(temp.path(), "rm")
            .args([
                "--s3-endpoint",
                &server.address,
                "--on",
                "s3://bucket",
                "--src-dir",
                "tree",
                "--s3-all-versions",
                "--results",
                "results.ndjson",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), requests, "{fault}");
        let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/automation.schema.json")).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for line in records.lines() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(validator.is_valid(&value), "{value}");
            if fault == "remove-denied"
                && value["type"] == "removal_result"
                && value["s3_delete_marker"] == false
            {
                assert_eq!(value["class"], "io");
                assert_eq!(value["os_kind"], "permission_denied");
                assert_eq!(value["retryable"], "no");
            }
        }
        let outcomes: Vec<serde_json::Value> = records
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|r: &serde_json::Value| r["type"] == "removal_result")
            .collect();
        if exit == 23 || exit == 0 {
            assert_eq!(outcomes.len(), 3);
        }
        if exit == 23 {
            let marker = outcomes
                .iter()
                .find(|r| r["s3_delete_marker"] == true)
                .unwrap();
            assert_eq!(marker["attempts"], 0);
            assert_eq!(marker["retryable"], "unknown");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("S3 removal preserved 1 delete markers"));
            assert!(!stderr.contains("delete marker preserved because"));
            assert_eq!(marker["disposition"], "failed");
            assert!(marker["message"].as_str().unwrap().contains("preserved"));
        }
        let result: serde_json::Value =
            serde_json::from_str(records.lines().last().unwrap()).unwrap();
        assert_eq!(
            result["entries_removed"],
            match fault {
                "remove-ok" | "remove-null" => 3,
                "remove-mixed"
                | "remove-omitted"
                | "remove-null-marker-created"
                | "remove-null-marker-ambiguous"
                | "remove-marker-created" => 1,
                _ => 0,
            }
        );
        assert_eq!(
            result["entries_failed"],
            match fault {
                "remove-denied" => 3,
                "remove-mixed"
                | "remove-omitted"
                | "remove-null-marker-created"
                | "remove-null-marker-ambiguous"
                | "remove-marker-created" => 2,
                _ => 0,
            }
        );
    }
}

#[test]
fn s3_remove_dry_run_and_usage_errors_do_not_delete() {
    let temp = tempfile::tempdir().unwrap();
    let server = Server::start("remove-ok");
    let output = server
        .command_for(temp.path(), "rm")
        .args([
            "--s3-endpoint",
            &server.address,
            "--on",
            "s3://bucket",
            "--src-dir",
            "tree",
            "--s3-all-versions",
            "--dry-run",
            "-v",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(server.requests.load(Ordering::Relaxed), 2);
    for options in [
        vec![
            "--on",
            "s3://bucket",
            "--s3-all-versions",
            "--s3-version-id",
            "v",
            "key",
        ],
        vec![
            "--on",
            "s3://bucket",
            "--s3-version-id",
            "v",
            "--src-dir",
            "tree",
        ],
        vec!["--s3-all-versions", "local"],
        vec!["--on", "s3://bucket", "--s3-version-id", "v", "a", "b"],
        vec!["--on", "s3://bucket", "--pscope", "/missing", "key"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .arg("rm")
            .args(options)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

#[test]
fn s3_remove_retries_bodyless_head_throttling_without_decoding_copy_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let server = Server::start("remove-head-throttle");
    let output = server
        .command_for(temp.path(), "rm")
        .args(["--s3-endpoint", &server.address])
        .args(["--on", "s3://bucket", "key", "--dry-run"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(server.requests.load(Ordering::Relaxed), 2);
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

#[test]
fn s3_remove_prefix_existence_is_bounded_and_usage_mentions_removal() {
    let temp = tempfile::tempdir().unwrap();
    let server = Server::start("remove-prefix-check");
    let output = server
        .command_for(temp.path(), "rm")
        .args([
            "--s3-endpoint",
            &server.address,
            "--on",
            "s3://bucket",
            "--src-non-dir",
            "tree",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("non-directory selector names a prefix"));
    assert_eq!(server.requests.load(Ordering::Relaxed), 2);
    for (args, message) in [
        (
            vec!["--s3-region", "us-east-1", "key"],
            "S3 options require --on s3://BUCKET",
        ),
        (
            vec!["--on", "s3://bucket", "--pscope", "/missing", "key"],
            "not supported for S3 removal",
        ),
        (
            vec!["--on", "s3://bucket", "--follow-src", "key"],
            "--follow-src is not supported for S3 removal",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .arg("rm")
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            output_text(&output).contains(message),
            "{}",
            output_text(&output)
        );
    }
}

#[test]
fn s3_remove_follow_still_allows_local_results_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let results = temp.path().join("results");
    std::os::unix::fs::symlink("actual-results", &results).unwrap();
    let server = Server::start("remove-head-throttle");
    let output = server
        .command_for(temp.path(), "rm")
        .args([
            "--s3-endpoint",
            &server.address,
            "--on",
            "s3://bucket",
            "key",
            "--dry-run",
            "--follow",
            "--results",
        ])
        .arg(&results)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(std::fs::symlink_metadata(&results)
        .unwrap()
        .file_type()
        .is_symlink());
    let records = std::fs::read_to_string(temp.path().join("actual-results")).unwrap();
    assert!(records.contains("removal_trace"));
}

#[test]
fn s3_remove_exact_history_and_tree_are_selected_explicitly() {
    for (selector, expected) in [
        (vec!["ghost"], vec!["old", "hidden"]),
        (vec!["--src-dir", "ghost"], vec!["child"]),
        (vec!["--srcs-in", "ghost"], vec!["child"]),
        (vec!["--src-non-dir", "ghost"], vec!["old", "hidden"]),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start("remove-ghost");
        let output = server
            .command_for(temp.path(), "rm")
            .args([
                "--s3-endpoint",
                &server.address,
                "--on",
                "s3://bucket",
                "--s3-all-versions",
                "--dry-run",
                "--results",
                "results.ndjson",
            ])
            .args(selector)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
        let versions: Vec<String> = records
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|r| r["type"] == "removal_trace")
            .map(|r| r["s3_version_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(versions, expected);
        assert_eq!(server.requests.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn s3_remove_exact_versions_stops_before_unrelated_prefixes() {
    let temp = tempfile::tempdir().unwrap();
    let server = Server::start("remove-exact-bounded");
    let output = server
        .command_for(temp.path(), "rm")
        .args([
            "--s3-endpoint",
            &server.address,
            "--on",
            "s3://bucket",
            "--src-non-dir",
            "ghost",
            "--s3-all-versions",
            "--dry-run",
            "-v",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(output_text(&output).contains("old"));
    assert!(output_text(&output).contains("hidden"));
    assert!(output_text(&output).contains("2 entries"));
    assert_eq!(server.requests.load(Ordering::Relaxed), 2);
}

#[test]
fn s3_remove_batches_are_concurrent_and_preserve_markers_after_late_failure() {
    for (fault, exit, requests, removed, failed) in [
        ("remove-bulk", 0, 5, 1002, 0),
        ("remove-bulk-failure", 23, 4, 1, 1001),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start(fault);
        let output = server
            .command_for(temp.path(), "rm")
            .args([
                "--s3-endpoint",
                &server.address,
                "--on",
                "s3://bucket",
                "--src-dir",
                "tree",
                "--s3-all-versions",
                "--results",
                "results.ndjson",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit), "{}", output_text(&output));
        assert_eq!(server.requests.load(Ordering::Relaxed), requests);
        let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
        let records: Vec<serde_json::Value> = records
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let summary = records.last().unwrap();
        assert_eq!(summary["entries_removed"], removed);
        assert_eq!(summary["entries_failed"], failed);
        let outcomes: Vec<_> = records
            .iter()
            .filter(|r| r["type"] == "removal_result")
            .collect();
        assert_eq!(outcomes.len(), 1002);
        let ids: std::collections::HashSet<_> = outcomes
            .iter()
            .map(|r| r["s3_version_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 1002);
        let marker = outcomes
            .iter()
            .find(|r| r["s3_delete_marker"] == true)
            .unwrap();
        if failed != 0 {
            assert_eq!(marker["attempts"], 0);
            assert_eq!(marker["retryable"], "unknown");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("S3 removal preserved 1 delete markers"));
            assert!(!stderr.contains("delete marker preserved because"));
        }
    }
}

#[test]
fn s3_remove_interrupt_cancels_stalled_planning_without_deleting() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start("remove-planning-interrupt");
        let mut child = server
            .command_for(temp.path(), "rm")
            .args([
                "--s3-endpoint",
                &server.address,
                "--on",
                "s3://bucket",
                "--src-dir",
                "tree",
                "--s3-all-versions",
                "--results",
                "results.ndjson",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !server.gate.0.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            assert!(
                child.try_wait().unwrap().is_none(),
                "rm exited before listing"
            );
            thread::sleep(Duration::from_millis(5));
        }
        if !server.gate.0.load(Ordering::SeqCst) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("planning request was not received before deadline");
        }
        assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            thread::sleep(Duration::from_millis(5));
        };
        server.gate.1.store(true, Ordering::SeqCst);
        if status.is_none() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert_eq!(
            status
                .expect("rm waited for read-only planning after interruption")
                .code(),
            Some(1)
        );
        assert_eq!(server.requests.load(Ordering::SeqCst), 1);
        let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
        let records: Vec<serde_json::Value> = records
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(!records.iter().any(|r| r["type"] == "removal_result"));
        assert_eq!(records.last().unwrap()["entries_removed"], 0);
        assert_eq!(records.last().unwrap()["exit_code"], 1);
    }
}

#[test]
fn s3_remove_interrupt_drains_in_flight_results_before_exiting() {
    let temp = tempfile::tempdir().unwrap();
    let server = Server::start("remove-bulk-interrupt");
    let mut child = server
        .command_for(temp.path(), "rm")
        .args([
            "--s3-endpoint",
            &server.address,
            "--on",
            "s3://bucket",
            "--src-dir",
            "tree",
            "--s3-all-versions",
            "--results",
            "results.ndjson",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while server.requests.load(Ordering::SeqCst) < 4 && std::time::Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "rm exited before sending batches"
        );
        thread::sleep(Duration::from_millis(5));
    }
    if server.requests.load(Ordering::SeqCst) < 4 {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!(
            "timed out waiting for removal requests: {}",
            server.requests.load(Ordering::SeqCst)
        );
    }
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    thread::sleep(Duration::from_millis(100));
    let premature = child.try_wait().unwrap();
    server.gate.1.store(true, Ordering::SeqCst);
    let status = child.wait().unwrap();
    assert!(premature.is_none(), "rm discarded its in-flight requests");
    assert_eq!(status.code(), Some(1));
    assert_eq!(server.requests.load(Ordering::SeqCst), 4);
    let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
    let records: Vec<serde_json::Value> = records
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        records
            .iter()
            .filter(|r| r["type"] == "removal_result")
            .count(),
        1001
    );
    assert_eq!(records.last().unwrap()["entries_removed"], 1001);
}

// Keep real HTTP pagination and production interceptor wiring covered here.
// Timing policy is tested separately with a virtual clock.
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
fn s3_paginated_download_records_control_latency() {
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
    assert!(control.is_finite() && control >= 0.0, "{plan}");
    // Check the measured latency reaches planning without requiring a loaded
    // runner to finish real HTTP requests within a wall-clock deadline.
    let expected_limit = if control >= 0.050 { 256 } else { 64 };
    assert_eq!(plan["request_limit"], expected_limit, "{plan}");
}

#[test]
fn s3_remove_explicit_types_disambiguate_live_object_and_tree_without_extra_probes() {
    for all_versions in [false, true] {
        for (selector, paths) in [
            (vec!["foo"], vec!["foo"]),
            (vec!["--src-dir", "foo"], vec!["foo/", "foo/nested/child"]),
            (vec!["--srcs-in", "foo"], vec!["foo/nested/child"]),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let server = Server::start("rm-explicit-collision");
            let mut command = server.command_for(temp.path(), "rm");
            command
                .args([
                    "--s3-endpoint",
                    &server.address,
                    "--on",
                    "s3://bucket",
                    "--dry-run",
                    "--results",
                    "results.ndjson",
                ])
                .args(selector);
            if all_versions {
                command.arg("--s3-all-versions");
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "{}", output_text(&output));
            let records = std::fs::read_to_string(temp.path().join("results.ndjson")).unwrap();
            let selected: Vec<String> = records
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
                .filter(|r| r["type"] == "removal_trace")
                .map(|r| r["path"]["value"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(selected, paths);
            assert_eq!(server.requests.load(Ordering::Relaxed), 1);
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let server = Server::start("rm-explicit-collision");
    let output = server
        .command_for(temp.path(), "rm")
        .args([
            "--s3-endpoint",
            &server.address,
            "--on",
            "s3://bucket",
            "foo/",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("--src-dir"));
    assert_eq!(server.requests.load(Ordering::Relaxed), 0);
}

#[test]
fn server_copy_rejects_metadata_headers_before_requests() {
    let server = Server::start("ok");
    let temp = tempfile::tempdir().unwrap();
    for name in [
        "X-Amz-Meta-Project",
        "Content-Type",
        "Content-Encoding",
        "Content-Language",
        "Content-Disposition",
        "Cache-Control",
        "Expires",
        "X-Amz-Tagging",
        "X-Amz-Website-Redirect-Location",
    ] {
        let header = format!("{name}: private-value");
        for dry_run in [false, true] {
            let mut args = vec![
                "--from",
                "s3://source",
                "data",
                "--to",
                "s3://bucket",
                "--as",
                "out",
                "--s3-header",
                &header,
            ];
            if dry_run {
                args.push("--dry-run");
            }
            let output = server.cp(temp.path(), &args);
            let text = output_text(&output);
            assert_eq!(output.status.code(), Some(2), "{text}");
            assert!(text.contains("single-request and multipart"), "{text}");
            assert!(text.contains(&name.to_ascii_lowercase()), "{text}");
            assert!(!text.contains("private-value"), "{text}");
        }
    }
    assert_eq!(server.requests.load(Ordering::Relaxed), 0);
}

#[test]
fn server_copy_never_reads_or_relays_object_contents() {
    for fault in [
        "server-copy",
        "server-copy-fails",
        "server-copy-multipart-fails",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start(fault);
        let mut command = server.command(temp.path());
        command.args(["--s3-endpoint", &server.address]);
        // Server copies need sockets, but no per-object source file handles or
        // upload buffers. A large configured maximum must still work here.
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                let mut limit = std::mem::zeroed::<libc::rlimit>();
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                limit.rlim_cur = limit.rlim_cur.min(128);
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command
            .args([
                "--from",
                "s3://source",
                "original",
                "--performance-tuning=s3-max-concurrent-objects=4096,s3-max-concurrent-requests=1",
                "--to",
                "s3://destination",
                "--as",
                "copied",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            fault == "server-copy",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            server.requests.load(Ordering::Relaxed),
            if fault == "server-copy-multipart-fails" {
                6
            } else {
                3
            }
        );
    }
}

#[test]
fn server_copy_compares_remote_checksums_etags_and_metadata_without_body_reads() {
    for (fault, requests) in [
        ("server-copy-compare-etag", 2),
        ("server-copy-compare-checksum", 2),
        ("server-copy-compare-composite", 3),
        ("server-copy-compare-conflict", 3),
        ("server-copy-compare-metadata", 3),
        ("server-copy-compare-unavailable", 4),
        ("server-copy-compare-bad-request", 4),
        ("server-copy-compare-unsupported", 3),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start(fault);
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://source",
                "original",
                "--to",
                "s3://destination",
                "--as",
                "copied",
            ],
        );
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert_eq!(server.requests.load(Ordering::Relaxed), requests, "{fault}");
    }
}

#[test]
fn server_copy_parts_overlap_and_respect_one_request_limit() {
    for (fault, limit, success) in [
        ("server-copy-multipart-parallel", "2", true),
        ("server-copy-multipart-serial", "1", true),
        ("server-copy-multipart-drain-fails", "2", false),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let server = Server::start(fault);
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://source",
                "original",
                "--to",
                "s3://destination",
                "--as",
                "copied",
                "--performance-tuning",
                &format!("s3-max-concurrent-requests={limit}"),
            ],
        );
        assert_eq!(
            output.status.success(),
            success,
            "{fault}: {}",
            output_text(&output)
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), 7, "{fault}");
    }
}

#[test]
fn server_copy_only_new_uses_a_conditional_write() {
    let server = Server::start("server-copy-only-new");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "original",
            "--to",
            "s3://destination",
            "--as",
            "copied",
            "--only-new",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
}

#[test]
fn server_copy_reuses_destination_discovery_and_prunes_beneath_file_keys() {
    for (fault, extra, requests) in [
        ("server-tree-fresh", "--dry-run", 5),
        ("server-tree-prune", "--prune", 8),
        ("server-tree-unsupported", "--dry-run", 6),
        ("server-tree-denied", "--dry-run", 6),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://source",
                "--srcs-in",
                "data",
                "--to",
                "s3://destination",
                "--into",
                "out",
                extra,
                "--performance-tuning",
                "s3-max-concurrent-objects=1",
            ],
        );
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert_eq!(server.requests.load(Ordering::Relaxed), requests, "{fault}");
    }
}

#[test]
fn server_copy_heads_overlap_and_storage_class_is_explicit() {
    for fault in [
        "server-copy-heads-overlap",
        "server-copy-storage-class",
        "server-copy-multipart-storage-class",
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let mut args = vec![
            "--from",
            "s3://source",
            "original",
            "--to",
            "s3://destination",
            "--as",
            "copied",
            "--performance-tuning",
            "s3-max-concurrent-requests=2",
        ];
        if fault == "server-copy-heads-overlap" {
            args = vec![
                "--from",
                "s3://source",
                "original",
                "other",
                "--to",
                "s3://destination",
                "--into",
                "copied",
                "--dry-run",
                "--only-new",
            ];
        }
        if fault.contains("storage-class") {
            args.extend(["--s3-header", "x-amz-storage-class: INTELLIGENT_TIERING"]);
        }
        let output = server.cp(temp.path(), &args);
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
    }
}

#[test]
fn server_copy_automatic_sizing_uses_one_copy_request() {
    let server = Server::start("server-copy-automatic");
    let temp = tempfile::tempdir().unwrap();
    let output = server
        .command_with_part_size(temp.path(), 0, false)
        .args([
            "--s3-endpoint",
            &server.address,
            "--from",
            "s3://source",
            "original",
            "--to",
            "s3://destination",
            "--as",
            "copied",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(server.requests.load(Ordering::Relaxed), 3);
}

#[test]
fn server_copy_prune_protects_keys_under_skip_options() {
    for (fault, option) in [
        ("server-tree-skipped", "--only-new"),
        ("server-tree-missing", "--only-existing"),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://source",
                "--srcs-in",
                "data",
                "--to",
                "s3://destination",
                "--into",
                "out",
                "--prune",
                option,
            ],
        );
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert_eq!(server.requests.load(Ordering::Relaxed), 7);
    }
}

#[test]
fn server_copy_tag_reads_handle_zero_denied_and_unsupported() {
    for (fault, success, requests) in [
        ("server-copy-multipart-zero-tags", true, 6),
        ("server-copy-multipart-tags-denied", false, 3),
        ("server-copy-multipart-unknown-denied", false, 3),
        ("server-copy-multipart-unknown-unsupported", true, 7),
        ("server-copy-multipart-known-unsupported", false, 3),
    ] {
        let server = Server::start(fault);
        let temp = tempfile::tempdir().unwrap();
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://source",
                "original",
                "--to",
                "s3://destination",
                "--as",
                "copied",
            ],
        );
        assert_eq!(
            output.status.success(),
            success,
            "{fault}: {}",
            output_text(&output)
        );
        if !success {
            let diagnostic = output_text(&output);
            assert!(
                diagnostic.contains("S3 GetObjectTagging for multipart copy"),
                "{diagnostic}"
            );
            assert!(diagnostic.contains("s3:GetObjectTagging"), "{diagnostic}");
            let status = if fault.ends_with("unsupported") {
                "HTTP 501"
            } else {
                "HTTP 403"
            };
            assert!(diagnostic.contains(status), "{diagnostic}");
        }
        let diagnostic = output_text(&output);
        assert_eq!(
            diagnostic.contains("Tags may be omitted"),
            success && fault.ends_with("unsupported"),
            "{diagnostic}"
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), requests, "{fault}");
    }
}

#[test]
fn server_copy_caches_unsupported_tag_reads() {
    let server = Server::start("server-copy-multipart-cached-unsupported");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "original",
            "other",
            "--to",
            "s3://destination",
            "--into",
            "copied",
            "--performance-tuning",
            "s3-max-concurrent-objects=1",
        ],
    );
    let diagnostic = output_text(&output);
    assert!(output.status.success(), "{diagnostic}");
    assert_eq!(
        diagnostic.matches("Tags may be omitted").count(),
        1,
        "{diagnostic}"
    );
    assert!(server.gate.0.load(Ordering::Relaxed));
}

#[test]
fn server_copy_region_error_explains_both_endpoints() {
    let server = Server::start("wrong-region");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "original",
            "--to",
            "s3://destination",
            "--as",
            "copied",
        ],
    );
    let text = output_text(&output);
    assert!(!output.status.success());
    assert!(
        text.contains("source")
            && text.contains("destination")
            && text.contains("--s3-region applies to both endpoints")
            && text.contains("eu-central-1"),
        "{text}"
    );
    assert!(text.contains("pass --s3-region eu-central-1"), "{text}");
    assert_eq!(server.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn server_copy_discovery_region_failure_stops_before_copying() {
    let server = Server::start("server-tree-region");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "--srcs-in",
            "data",
            "--to",
            "s3://destination",
            "--into",
            "out",
            "--prune",
        ],
    );
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains("--s3-region applies to both endpoints"),
        "{text}"
    );
    assert!(text.contains("pass --s3-region eu-central-1"), "{text}");
    assert_eq!(server.requests.load(Ordering::Relaxed), 3);
}

#[test]
fn server_copy_changed_source_prevents_pruning() {
    let server = Server::start("server-tree-changed");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "--srcs-in",
            "data",
            "--to",
            "s3://destination",
            "--into",
            "out",
            "--prune",
        ],
    );
    let text = output_text(&output);
    assert!(!output.status.success(), "{text}");
    assert!(text.contains("skipping deletions"), "{text}");
    assert_eq!(server.requests.load(Ordering::Relaxed), 7);
}

#[test]
fn server_copy_reuses_versioned_source_snapshot() {
    let server = Server::start("server-copy-versioned");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "original",
            "--to",
            "s3://destination",
            "--as",
            "copied",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(server.requests.load(Ordering::Relaxed), 3);
}

#[test]
fn server_copy_multipart_preserves_tag_characters() {
    let server = Server::start("server-copy-multipart-tag-encoding");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "original",
            "--to",
            "s3://destination",
            "--as",
            "copied",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
}

#[test]
fn server_copy_filters_exact_and_mapping_overlap() {
    for mapping in [false, true] {
        for filter in [None, Some(("--ignore", "original"))] {
            let server = Server::start("server-copy");
            let temp = tempfile::tempdir().unwrap();
            std::fs::write(
                temp.path().join("mapping"),
                serde_json::json!({
                    "src": {"encoding": "utf-8", "value": "original"},
                    "dst": {"encoding": "utf-8", "value": "original"}, "kind": "file"
                })
                .to_string(),
            )
            .unwrap();
            let mut args = vec!["--from", "s3://source"];
            if mapping {
                args.extend(["--mapping", "mapping"]);
            } else {
                args.push("original");
            }
            args.extend(["--to", "s3://source", "--dry-run"]);
            if mapping {
                args.extend(["--into", "."]);
            } else {
                args.extend(["--as", "original"]);
            }
            if let Some((name, value)) = filter {
                args.extend([name, value]);
            }
            let output = server.cp(temp.path(), &args);
            let diagnostic = output_text(&output);
            assert_eq!(
                output.status.success(),
                filter.is_some(),
                "mapping={mapping}, filter={filter:?}: {diagnostic}"
            );
            if filter.is_none() {
                assert!(diagnostic.contains("overlap"), "{diagnostic}");
            }
        }
    }
}

#[test]
fn upload_region_discovery_failure_stops_with_and_without_prune() {
    for prune in [false, true] {
        let server = Server::start("wrong-region");
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("source")).unwrap();
        for name in ["a", "b"] {
            std::fs::write(temp.path().join("source").join(name), b"data").unwrap();
        }
        let mut args = vec![
            "--srcs-in",
            "source",
            "--to",
            "s3://destination",
            "--into",
            "out",
        ];
        if prune {
            args.push("--prune");
        }
        let output = server.cp(temp.path(), &args);
        assert!(!output.status.success());
        assert!(
            output_text(&output).contains("pass --s3-region eu-central-1"),
            "{}",
            output_text(&output)
        );
        assert_eq!(server.requests.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn failed_marker_reports_directory_action_on_both_routes() {
    for server_copy in [false, true] {
        let server = Server::start("marker-head-failure");
        let temp = tempfile::tempdir().unwrap();
        let mut args = vec!["--from", "s3://source", "--srcs-in", "data"];
        if server_copy {
            args.extend(["--to", "s3://destination"]);
        }
        args.extend(["--into", "out", "--results", "results.jsonl"]);
        let output = server.cp(temp.path(), &args);
        assert!(!output.status.success(), "{}", output_text(&output));
        let records = parsed_results(temp.path());
        let results = serde_json::to_string(&records).unwrap();
        assert!(
            records
                .iter()
                .any(|record| record["action"] == "create_directory"
                    && record["disposition"] == "failed"),
            "{results}"
        );
        assert!(
            !records
                .iter()
                .any(|record| record["action"] == "transfer_file"),
            "{results}"
        );
    }
}

#[test]
fn failed_transfers_report_known_symlink_action_on_both_routes() {
    for server_copy in [false, true] {
        for mapping in [false, true] {
            let server = Server::start("symlink-transfer-denied");
            let temp = tempfile::tempdir().unwrap();
            let mut args = vec!["--from", "s3://source"];
            if mapping {
                let entry = serde_json::json!({
                    "src": {"encoding": "utf-8", "value": "original"},
                    "dst": {"encoding": "utf-8", "value": "copied"},
                    "kind": "symlink"
                });
                std::fs::write(temp.path().join("mapping.jsonl"), format!("{entry}\n")).unwrap();
                args.extend(["--mapping", "mapping.jsonl", "--into", "."]);
            } else {
                args.extend(["original", "--as", "copied"]);
            }
            if server_copy {
                args.extend(["--to", "s3://destination"]);
            }
            args.extend(["--results", "results.jsonl"]);
            let output = server.cp(temp.path(), &args);
            assert!(!output.status.success(), "{}", output_text(&output));
            let records = parsed_results(temp.path());
            let results = serde_json::to_string(&records).unwrap();
            assert!(
                records
                    .iter()
                    .any(|record| record["action"] == "create_symlink"
                        && record["disposition"] == "failed"),
                "{results}"
            );
            assert!(
                !records
                    .iter()
                    .any(|record| record["action"] == "transfer_file"),
                "{results}"
            );
        }
    }
}

#[test]
fn skipped_download_markers_do_not_count_as_unchanged_files() {
    let flag = "--only-existing";
    let server = Server::start("marker-head-failure");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "--srcs-in",
            "data",
            "--into",
            "out",
            flag,
            "--results",
            "results.jsonl",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    let records = parsed_results(temp.path());
    let results = serde_json::to_string(&records).unwrap();
    assert!(
        records
            .iter()
            .any(|r| r["type"] == "progress" && r["files_total"] == 1 && r["scan_done"] == true),
        "{results}"
    );
    assert_eq!(records.last().unwrap()["files_unchanged"], 0, "{results}");
}

#[test]
fn skipped_download_symlinks_use_the_kind_known_from_selection() {
    for (selection, flag) in [
        ("exact", "--only-new"),
        ("mapping", "--only-existing"),
        ("prefix", "--only-existing"),
    ] {
        let server = Server::start("symlink-transfer-denied");
        let temp = tempfile::tempdir().unwrap();
        if flag == "--only-new" {
            std::fs::create_dir(temp.path().join("out")).unwrap();
            std::os::unix::fs::symlink("target", temp.path().join("out/original")).unwrap();
        }
        let mut args = vec!["--from", "s3://source"];
        match selection {
            "exact" => args.extend(["data/original", "--as", "out/original"]),
            "mapping" => {
                let entry = serde_json::json!({
                    "src": {"encoding": "utf-8", "value": "data/original"},
                    "dst": {"encoding": "utf-8", "value": "original"},
                    "kind": "symlink"
                });
                std::fs::write(temp.path().join("mapping.jsonl"), format!("{entry}\n")).unwrap();
                args.extend(["--mapping", "mapping.jsonl", "--into", "out"]);
            }
            "prefix" => args.extend(["--srcs-in", "data", "--into", "out"]),
            _ => unreachable!(),
        }
        args.extend([flag, "--results", "results.jsonl"]);
        let output = server.cp(temp.path(), &args);
        assert!(
            output.status.success(),
            "{selection} {flag}: {}",
            output_text(&output)
        );
        let records = parsed_results(temp.path());
        let results = serde_json::to_string(&records).unwrap();
        assert!(
            records.iter().any(|r| r["type"] == "progress"
                && r["files_total"] == 1
                && r["scan_done"] == true),
            "{results}"
        );
        let expected = u64::from(selection == "prefix");
        assert_eq!(
            records.last().unwrap()["files_unchanged"],
            expected,
            "{selection} {flag}: {results}"
        );
        assert_eq!(
            server.requests.load(Ordering::Relaxed),
            if selection == "prefix" { 2 } else { 1 },
            "skipped objects must not trigger transfer-time metadata requests"
        );
    }
}

#[test]
fn server_copy_directory_to_bucket_root_skips_root_marker() {
    let server = Server::start("copy-root-marker");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "--src-dir",
            "data",
            "--to",
            "s3://destination",
            "--as",
            ".",
            "--results",
            "results.jsonl",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(server.requests.load(Ordering::Relaxed), 5);
    let records = parsed_results(temp.path());
    assert!(records
        .iter()
        .any(|r| r["type"] == "progress" && r["scan_done"] == true && r["files_total"] == 1));
    assert_eq!(records.last().unwrap()["files_transferred"], 1);
}

#[test]
fn download_directory_to_root_keeps_root_metadata() {
    use std::os::unix::fs::MetadataExt;
    let server = Server::start("copy-root-marker");
    let temp = tempfile::tempdir().unwrap();
    let output = server.cp(
        temp.path(),
        &[
            "--from",
            "s3://source",
            "--src-dir",
            "data",
            "--as",
            ".",
            "--results",
            "results.jsonl",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(std::fs::read(temp.path().join("child")).unwrap(), b"data");
    assert_eq!(std::fs::metadata(temp.path()).unwrap().mtime(), 1577836800);
    assert_eq!(server.requests.load(Ordering::Relaxed), 4);
    let records = parsed_results(temp.path());
    assert!(records.iter().any(|r| r["action"] == "create_directory"));
}

fn expected_mapping(root: &Path, source: &str, destination: &str, expected: &str) -> String {
    let (algorithm, value) = expected.split_once(':').unwrap();
    let record = serde_json::json!({
        "src": {"encoding": "utf-8", "value": source},
        "dst": {"encoding": "utf-8", "value": destination}, "kind": "file",
        "expected_hash": {"algorithm": algorithm, "value": value}
    });
    let path = root.join("expected.mapping");
    std::fs::write(&path, record.to_string()).unwrap();
    path.to_str().unwrap().to_owned()
}
