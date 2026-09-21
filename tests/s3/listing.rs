use super::*;

struct ListingServer {
    address: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl ListingServer {
    fn start(fail_second: bool, missing_token: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
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
                assert!(
                    request.starts_with("GET "),
                    "listing must not HEAD or download objects"
                );
                assert!(request.contains("list-type=2"));
                assert!(request.contains("encoding-type=url"));
                if request.contains("continuation-token=") {
                    assert!(request.contains("continuation-token=next"));
                    if fail_second {
                        reply(
                            &mut socket,
                            403,
                            &[],
                            b"<Error><Code>AccessDenied</Code></Error>",
                            false,
                        );
                    } else {
                        reply(&mut socket, 200, &[], b"<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>prefix%2Fsecond</Key><Size>2</Size></Contents></ListBucketResult>", false);
                    }
                } else {
                    let next = if missing_token {
                        ""
                    } else {
                        "<NextContinuationToken>next</NextContinuationToken>"
                    };
                    let body = format!("<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated>{next}<Contents><Key>prefix%2Fline%0Abreak%252F</Key><Size>7</Size><LastModified>2026-01-01T00:00:00Z</LastModified><ETag>&quot;opaque&quot;</ETag></Contents></ListBucketResult>");
                    reply(&mut socket, 200, &[], body.as_bytes(), false);
                }
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
    fn command(&self, temp: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args([
                "_ls",
                "s3://bucket/prefix/**",
                "--concurrency",
                "1",
                "--s3-region",
                "us-east-1",
                "--s3-endpoint",
                &self.address,
            ])
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
impl Drop for ListingServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn experimental_listing_streams_encoded_keys_and_reports_partial_failure() {
    let temp = test_support::tempdir().unwrap();
    for fail in [false, true] {
        let server = ListingServer::start(fail, false);
        let output = server.command(temp.path()).output().unwrap();
        assert_eq!(
            output.status.success(),
            !fail,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let records: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), if fail { 1 } else { 2 });
        assert_eq!(records[0]["key"], "prefix/line\nbreak%2F");
        assert_eq!(records[0]["bucket"], "bucket");
        assert_eq!(records[0]["size"], 7);
        assert_eq!(records[0]["etag"], "\"opaque\"");
        assert_eq!(records[0]["last_modified"], "2026-01-01T00:00:00Z");
        if fail {
            assert!(String::from_utf8_lossy(&output.stderr).contains("403"));
        } else {
            assert!(records[1]["last_modified"].is_null());
        }
    }
    let server = ListingServer::start(false, true);
    let output = server.command(temp.path()).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("continuation token"));
}

#[test]
fn experimental_listing_help_and_invalid_arguments() {
    for args in [["_ls", "--help"], ["help", "_ls"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("experimental"));
        assert!(help.contains("--s3-profile"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["_ls", "s3://bucket/**", "--concurrency", "0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["_ls", "/local/path"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("s3://"));
}
