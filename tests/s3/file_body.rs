//! Ordinary file uploads through the SDK body that reads the file in pooled
//! chunks. syq uses it unless a control request answered in under 3 ms, so
//! these servers answer control requests slowly.
use super::*;

const CONTROL_DELAY: Duration = Duration::from_millis(10);

/// `fault` is `file-body-<case>:<source directory>`; an object's file is the
/// last segment of its key in that directory.
pub(super) fn serve(
    socket: &mut TcpStream,
    fault: &str,
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
    gate: &(AtomicBool, AtomicBool),
) {
    let (case, directory) = fault.split_once(':').unwrap();
    let path = target.split('?').next().unwrap();
    match method {
        "HEAD" => {
            thread::sleep(CONTROL_DELAY);
            reply(socket, 404, &[], b"", true);
            return;
        }
        "GET" => {
            assert!(target.contains("list-type="), "{target}");
            thread::sleep(CONTROL_DELAY);
            let listing = b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
            reply(socket, 200, &[], listing, false);
            return;
        }
        _ => assert_eq!(method, "PUT", "{target}"),
    }
    let length: usize = headers["content-length"].parse().unwrap();
    let source = Path::new(directory).join(path.rsplit('/').next().unwrap());
    let expected = std::fs::read(&source).unwrap();
    match case {
        "file-body-cut-once" if !gate.0.swap(true, Ordering::AcqRel) => {
            // Drop the connection part-way through the first body.
            let mut start = vec![0; 1024 * 1024];
            socket.read_exact(&mut start).unwrap();
            assert_eq!(start, expected[..start.len()]);
            let _ = socket.shutdown(std::net::Shutdown::Both);
            return;
        }
        "file-body-shrink" | "file-body-change" => {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&source)
                .unwrap();
            if case == "file-body-shrink" {
                file.set_len(1024 * 1024).unwrap();
            } else {
                use std::os::unix::fs::FileExt;
                file.write_all_at(&[!expected[length - 1]], length as u64 - 1)
                    .unwrap();
            }
            // Record whether the whole body still arrived.
            let mut body = Vec::new();
            let _ = (&mut *socket).take(length as u64).read_to_end(&mut body);
            if body.len() == length {
                gate.1.store(true, Ordering::Release);
                reply(socket, 200, &[("ETag".into(), "\"x\"".into())], b"", false);
            }
            return;
        }
        _ => {}
    }
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    assert!(body == expected, "{target}: the body differs from the file");
    match case {
        "file-body-busy-once" if !gate.0.swap(true, Ordering::AcqRel) => {
            let error = b"<Error><Code>SlowDown</Code></Error>";
            reply(socket, 503, &[], error, false);
            return;
        }
        "file-body-checksum" => {
            use sha2::Digest as _;
            if let Some(md5) = headers.get("content-md5") {
                assert_eq!(*md5, content_md5(&body));
            } else if let Some(sha256) = headers.get("x-amz-checksum-sha256") {
                use base64::Engine as _;
                let digest = sha2::Sha256::digest(&body);
                assert_eq!(
                    *sha256,
                    base64::engine::general_purpose::STANDARD.encode(digest)
                );
            } else {
                assert!(
                    !gate.0.swap(true, Ordering::AcqRel),
                    "uploaded again without a checksum"
                );
                reply_checksum_required(socket);
                return;
            }
        }
        _ => {}
    }
    gate.1.store(true, Ordering::Release);
    reply(socket, 200, &[("ETag".into(), "\"x\"".into())], b"", false);
}

fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn start(case: &str, temp: &Path) -> Server {
    let fault = format!("file-body-{case}:{}", temp.join("source").display());
    std::fs::create_dir(temp.join("source")).unwrap();
    Server::start(Box::leak(fault.into_boxed_str()))
}

/// Uploads `source/object`, larger than a pooled chunk and than the bodies
/// syq reads into memory, as one PutObject.
fn upload_command(server: &Server, temp: &Path, retries: u32) -> Command {
    let mut command = server.command_with_part_size(temp, retries, false);
    command
        .env("SYQ_S3_DIAGNOSTICS", "1")
        .args(["--s3-endpoint", &server.address])
        .args(["--performance-tuning", "s3-part-size=64M"])
        .args(["source/object", "--to", "s3://bucket", "--as", "object"]);
    command
}

fn upload(server: &Server, temp: &Path, retries: u32) -> Output {
    upload_command(server, temp, retries)
        .capture_output()
        .unwrap()
}

/// A failed attempt, whether cut off mid-body or refused after it, resends
/// the whole file from its first byte.
#[test]
fn s3_file_body_retries_resend_the_file_from_the_start() {
    for case in ["cut-once", "busy-once"] {
        let temp = crate::test_support::tempdir().unwrap();
        let server = start(case, temp.path());
        std::fs::write(temp.path().join("source/object"), patterned(3 << 20 | 5)).unwrap();
        let output = upload(&server, temp.path(), 1);
        assert!(output.status.success(), "{case}: {}", output_text(&output));
        assert!(server.gate.1.load(Ordering::Acquire), "{case}");
        // HEAD, then the failed and the resent PUT.
        assert_eq!(server.requests.load(Ordering::Relaxed), 3, "{case}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The HEAD is the only control request.
        let control = stderr
            .lines()
            .find_map(|line| line.strip_prefix("S3_DIAGNOSTICS "))
            .map(|trace| serde_json::from_str::<serde_json::Value>(trace).unwrap())
            .and_then(|trace| {
                trace["events"]
                    .as_array()?
                    .iter()
                    .find(|event| event["operation"] == "HeadObject")?["headers_s"]
                    .as_f64()
            })
            .unwrap_or_else(|| panic!("{case}: no control latency: {stderr}"));
        assert!(control >= 0.003, "{case}: took the synchronous path");
    }
}

/// The body agrees with the Content-MD5 syq sends: added after a rejection
/// over HTTPS, and from the first request over plain HTTP.
#[test]
fn s3_file_body_matches_its_content_md5() {
    for plain_http in [false, true] {
        let temp = crate::test_support::tempdir().unwrap();
        let server = start("checksum", temp.path());
        std::fs::write(temp.path().join("source/object"), patterned(2 << 20 | 3)).unwrap();
        let mut command = upload_command(&server, temp.path(), 0);
        if plain_http {
            command.env_remove(TREAT_HTTP_AS_HTTPS);
        }
        let output = command.capture_output().unwrap();
        assert!(
            output.status.success(),
            "{plain_http}: {}",
            output_text(&output)
        );
        assert!(server.gate.1.load(Ordering::Acquire), "{plain_http}");
        // Release builds ignore the HTTPS override and send it at once.
        let rejected = !plain_http && cfg!(debug_assertions);
        assert_eq!(
            server.gate.0.load(Ordering::Acquire),
            rejected,
            "{plain_http}"
        );
    }
}

/// A source that shrinks or changes while its body is read fails the upload
/// before the destination receives the whole body.
#[test]
fn s3_file_body_fails_when_the_source_changes() {
    for case in ["shrink", "change"] {
        let temp = crate::test_support::tempdir().unwrap();
        let server = start(case, temp.path());
        let source = temp.path().join("source/object");
        std::fs::write(&source, patterned(32 << 20)).unwrap();
        // Writing within the clock tick of creation could leave the
        // timestamps unchanged; start from an old modification time.
        std::fs::File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1 << 30))
            .unwrap();
        let output = upload(&server, temp.path(), 1);
        assert!(!output.status.success(), "{case}: {}", output_text(&output));
        assert!(
            output_text(&output).contains("source changed during S3 copy"),
            "{case}: {}",
            output_text(&output)
        );
        assert!(
            !server.gate.1.load(Ordering::Acquire),
            "{case}: the destination received a whole body"
        );
    }
}

/// A bandwidth limit still spaces the requests that carry file bodies.
#[test]
fn s3_file_body_uploads_follow_the_bandwidth_limit() {
    let temp = crate::test_support::tempdir().unwrap();
    let server = start("paced", temp.path());
    for name in ["first", "second"] {
        std::fs::write(temp.path().join("source").join(name), patterned(2 << 20)).unwrap();
    }
    let started = std::time::Instant::now();
    let output = server
        .command(temp.path())
        .args(["--s3-endpoint", &server.address])
        .arg("--resource-limits=bandwidth=2M")
        .args([
            "--srcs-in",
            "source",
            "--to",
            "s3://bucket",
            "--into",
            "prefix",
        ])
        .capture_output()
        .unwrap();
    let elapsed = started.elapsed();
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.gate.1.load(Ordering::Acquire));
    // 4 MiB at 2 MiB/s: the second body waits about a second.
    assert!(elapsed >= Duration::from_millis(900), "{elapsed:?}");
}
