//! Optional recovery storage must not be required to finish a copy.
use super::*;
use std::os::unix::fs::PermissionsExt;

static REJECTED_PARTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static CORRUPTED_ONCE: AtomicBool = AtomicBool::new(false);
/// The source file that `recovery-upload-source-*` changes while it is sent.
static CHANGING_SOURCE: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

pub(super) fn serve_upload(
    socket: &mut TcpStream,
    fault: &str,
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
    gate: &(AtomicBool, AtomicBool),
) {
    let length = headers
        .get("content-length")
        .map_or(0, |s| s.parse::<usize>().unwrap());
    if method == "PUT" && fault.starts_with("recovery-upload-source-") {
        let path = CHANGING_SOURCE.lock().unwrap().clone().unwrap();
        if matches!(
            fault,
            "recovery-upload-source-replaced" | "recovery-upload-source-removed"
        ) {
            // Take the whole part, then replace or remove the selected
            // file; the copy must not complete the upload.
            let mut body = vec![0; length];
            if socket.read_exact(&mut body).is_err() {
                return;
            }
            if fault == "recovery-upload-source-replaced" {
                // Parts are sent in parallel, so each replacement is
                // written under a name of its own.
                static REPLACEMENTS: std::sync::atomic::AtomicUsize =
                    std::sync::atomic::AtomicUsize::new(0);
                let next = path.with_extension(format!(
                    "next{}",
                    REPLACEMENTS.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::write(&next, vec![b'x'; SIZE]).unwrap();
                std::fs::rename(&next, &path).unwrap();
            } else {
                let _ = std::fs::remove_file(&path);
            }
            reply(
                socket,
                200,
                &[("ETag".into(), "\"part\"".into())],
                b"",
                false,
            );
            return;
        }
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        if fault == "recovery-upload-source-shrinks" {
            // Shrink the file while the part is still being sent; the body
            // then ends early, and the connection closes without a reply.
            file.set_len(0).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = std::io::copy(&mut socket.take(length as u64), &mut std::io::sink());
        } else {
            // Another part's body can see this change and stop early.
            let mut body = vec![0; length];
            if socket.read_exact(&mut body).is_err() {
                return;
            }
            (&file).write_all(b"more").unwrap();
            reply(
                socket,
                200,
                &[("ETag".into(), "\"part\"".into())],
                b"",
                false,
            );
        }
        return;
    }
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    match method {
        "HEAD" => reply(socket, 404, &[], b"", true),
        "GET" => {
            assert!(target.contains("list-type="), "{target}");
            reply(
                socket,
                200,
                &[],
                b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
                false,
            );
        }
        "POST" if target.contains("uploads") => {
            assert!(!headers
                .keys()
                .any(|name| name.starts_with("x-amz-checksum")));
            if fault == "recovery-upload-default-hash" {
                assert_eq!(headers["x-amz-meta-syq-format"], "1");
                assert_eq!(
                    headers["x-amz-meta-syq-blake3"],
                    blake3::hash(&vec![b'x'; SIZE]).to_hex().to_string()
                );
            }
            reply(socket, 200, &[],
                b"<InitiateMultipartUploadResult><UploadId>new-upload</UploadId></InitiateMultipartUploadResult>", false);
        }
        "PUT" => {
            assert!(target.contains("uploadId=new-upload"));
            assert!(body.iter().all(|b| *b == b'x'));
            if fault == "recovery-upload-object-lock" {
                match headers.get("content-md5") {
                    Some(checksum) => assert_eq!(*checksum, content_md5(&body)),
                    None => {
                        REJECTED_PARTS.fetch_add(1, Ordering::Relaxed);
                        reply_checksum_required(socket);
                        return;
                    }
                }
            } else if fault == "recovery-upload-plain-http" {
                assert_eq!(headers["content-md5"], content_md5(&body));
            } else {
                assert_unchecked_upload(headers);
            }
            if fault == "recovery-upload-corrupt-once"
                && !CORRUPTED_ONCE.swap(true, Ordering::SeqCst)
            {
                reply(
                    socket,
                    400,
                    &[],
                    b"<Error><Code>BadDigest</Code></Error>",
                    false,
                );
                return;
            }
            if fault == "recovery-upload-fail" {
                reply(
                    socket,
                    403,
                    &[],
                    b"<Error><Code>AccessDenied</Code></Error>",
                    false,
                );
            } else {
                reply(
                    socket,
                    200,
                    &[("ETag".into(), "\"part\"".into())],
                    b"",
                    false,
                );
            }
        }
        "POST" => {
            assert!(target.contains("uploadId=new-upload"));
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("<PartNumber>1</PartNumber>"), "{body}");
            assert!(body.contains("<PartNumber>2</PartNumber>"), "{body}");
            assert!(!body.contains("<Checksum"), "{body}");
            gate.0.store(true, Ordering::Relaxed);
            reply(
                socket,
                200,
                &[],
                b"<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>",
                false,
            );
        }
        "DELETE" => {
            gate.1.store(true, Ordering::Relaxed);
            reply(socket, 204, &[], b"", false);
        }
        _ => panic!("unexpected request {method} {target}"),
    }
}

struct ReadOnlyDirectory(std::path::PathBuf);
impl ReadOnlyDirectory {
    fn new(path: std::path::PathBuf) -> Self {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
        Self(path)
    }
}
impl Drop for ReadOnlyDirectory {
    fn drop(&mut self) {
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn configure_cache(command: &mut Command, root: &Path, mode: &str) -> Option<ReadOnlyDirectory> {
    command.env_remove("HOME").env_remove("XDG_CACHE_HOME");
    match mode {
        "read-only-home" => {
            let home = ReadOnlyDirectory::new(root.join("home"));
            command.env("HOME", &home.0);
            Some(home)
        }
        "blocked-cache" => {
            let cache = root.join("blocked-cache");
            std::fs::write(&cache, b"unrelated file").unwrap();
            command.env("XDG_CACHE_HOME", cache);
            None
        }
        "untrusted-cache" => {
            // A symlinked recovery directory fails the same check as one owned
            // by another user, which a non-root test cannot create.
            let elsewhere = root.join("elsewhere");
            std::fs::create_dir_all(root.join("cache/syq")).unwrap();
            std::fs::create_dir(&elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, root.join("cache/syq/s3")).unwrap();
            command.env("XDG_CACHE_HOME", root.join("cache"));
            None
        }
        "no-home" => None,
        _ => unreachable!(),
    }
}

#[test]
fn multipart_upload_accepts_read_only_source_and_unavailable_cache() {
    for (mode, algorithm) in [
        ("read-only-home", "sha256"),
        ("blocked-cache", "sha256"),
        ("no-home", "sha256"),
        ("untrusted-cache", "sha256"),
        ("blocked-cache", "md5"),
    ] {
        // Root bypasses permission bits; the other cases still exercise absent
        // and unusable recovery storage when this suite is run as root.
        if mode == "read-only-home" && unsafe { libc::geteuid() } == 0 {
            continue;
        }
        let temp = crate::test_support::tempdir().unwrap();
        let server = Server::start("recovery-upload-ok");
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let bytes = vec![b'x'; SIZE];
        let files = ["first", "second"].map(|name| source.join(name));
        for file in &files {
            std::fs::write(file, &bytes).unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        let _source = ReadOnlyDirectory::new(source);
        let mut command = server.command(temp.path());
        let _home = configure_cache(&mut command, temp.path(), mode);
        command.arg(format!("--integrity-checking=transfer={algorithm}"));
        let output = command
            .args(["--s3-endpoint", &server.address])
            .arg("--srcs-in")
            .arg(&_source.0)
            .args(["--to", "s3://bucket", "--into", "prefix"])
            .args(["--s3-write-header", &format!("{WRITE_PROBE}: yes")])
            .capture_output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {}", output_text(&output));
        // Only each object's CreateMultipartUpload, not its parts or completion.
        assert_eq!(server.probes.load(Ordering::Relaxed), 2, "{mode}");
        // Each multipart object opens its own record, but one warning suffices.
        assert_eq!(
            output_text(&output)
                .matches("without saving recovery progress")
                .count(),
            1,
            "{mode}: {}",
            output_text(&output)
        );
        assert!(server.gate.0.load(Ordering::Relaxed));
        assert!(!server.gate.1.load(Ordering::Relaxed));
        for file in files {
            assert_eq!(std::fs::read(file).unwrap(), bytes);
        }
        assert_eq!(std::fs::read_dir(&_source.0).unwrap().count(), 2);
        if let Some(home) = _home {
            assert_eq!(std::fs::read_dir(&home.0).unwrap().count(), 0);
        }
        if mode == "untrusted-cache" {
            assert_eq!(
                std::fs::read_dir(temp.path().join("elsewhere"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }
}

#[test]
fn failed_upload_without_recovery_record_aborts_multipart_work() {
    let temp = crate::test_support::tempdir().unwrap();
    let server = Server::start("recovery-upload-fail");
    let file = temp.path().join("source");
    std::fs::write(&file, vec![b'x'; SIZE]).unwrap();
    let mut command = server.command(temp.path());
    configure_cache(&mut command, temp.path(), "blocked-cache");
    let output = command
        .args(["--s3-endpoint", &server.address])
        .arg(file)
        .args(["--to", "s3://bucket", "--as", "object"])
        .capture_output()
        .unwrap();
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(!server.gate.0.load(Ordering::Relaxed));
    assert!(server.gate.1.load(Ordering::Relaxed));
}

/// A source file that changes while a part is sent fails the copy at once,
/// without backing off as if the request might yet succeed.
#[test]
fn a_source_that_changes_during_a_part_fails_without_retries() {
    for fault in [
        "recovery-upload-source-grows",
        "recovery-upload-source-shrinks",
    ] {
        let temp = crate::test_support::tempdir().unwrap();
        let server = Server::start(fault);
        let file = temp.path().join("source");
        std::fs::write(&file, vec![b'x'; SIZE]).unwrap();
        *CHANGING_SOURCE.lock().unwrap() = Some(file.clone());
        // Eight retries would back off for at least 22 seconds.
        let started = std::time::Instant::now();
        let output = server
            .command_with_retries(temp.path(), 8)
            .args(["--s3-endpoint", &server.address])
            .arg(&file)
            .args(["--to", "s3://bucket", "--as", "object"])
            .capture_output()
            .unwrap();
        let elapsed = started.elapsed();
        let text = output_text(&output);
        assert!(!output.status.success(), "{fault}: {text}");
        assert!(
            text.contains("source changed during S3 copy"),
            "{fault}: {text}"
        );
        assert!(elapsed < Duration::from_secs(10), "{fault}: {elapsed:?}");
        assert!(!server.gate.0.load(Ordering::Relaxed), "{fault}");
    }
}

/// The parts of a multipart upload read one opened file. A source replaced
/// or removed at its path after a part was sent, even with identical
/// contents, still stops the copy before it completes the upload.
#[test]
fn a_source_replaced_or_removed_during_a_multipart_upload_is_not_published() {
    for fault in [
        "recovery-upload-source-replaced",
        "recovery-upload-source-removed",
    ] {
        let temp = crate::test_support::tempdir().unwrap();
        let server = Server::start(fault);
        let file = temp.path().join("source");
        std::fs::write(&file, vec![b'x'; SIZE]).unwrap();
        *CHANGING_SOURCE.lock().unwrap() = Some(file.clone());
        let output = server
            .command_with_retries(temp.path(), 8)
            .args(["--s3-endpoint", &server.address])
            .arg(&file)
            .args(["--to", "s3://bucket", "--as", "object"])
            .capture_output()
            .unwrap();
        let text = output_text(&output);
        assert!(!output.status.success(), "{fault}: {text}");
        if fault == "recovery-upload-source-replaced" {
            assert!(
                text.contains("source changed during S3 copy"),
                "{fault}: {text}"
            );
        }
        assert!(!server.gate.0.load(Ordering::Relaxed), "{fault}: completed");
    }
}

#[test]
fn multipart_download_without_cache_publishes_or_cleans_up() {
    for fault in ["ok", "truncated"] {
        let temp = crate::test_support::tempdir().unwrap();
        let server = Server::start(fault);
        let mut command = server.command(temp.path());
        configure_cache(&mut command, temp.path(), "blocked-cache");
        let output = command
            .args([
                "--s3-endpoint",
                &server.address,
                "--from",
                "s3://bucket",
                "data",
                "--as",
                "download",
            ])
            .capture_output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            fault == "ok",
            "{}",
            output_text(&output)
        );
        if fault == "ok" {
            assert_eq!(
                std::fs::read(temp.path().join("download")).unwrap(),
                vec![b'x'; SIZE]
            );
        } else {
            assert!(!temp.path().join("download").exists());
        }
        assert!(!std::fs::read_dir(temp.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")));
    }
}

#[test]
fn ordinary_multipart_upload_stores_whole_file_hash() {
    let temp = crate::test_support::tempdir().unwrap();
    let server = Server::start("recovery-upload-default-hash");
    std::fs::write(temp.path().join("source"), vec![b'x'; SIZE]).unwrap();
    let output = server.cp(
        temp.path(),
        &["source", "--to", "s3://bucket", "--as", "object"],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.gate.0.load(Ordering::Relaxed));
}

#[test]
fn plain_http_multipart_parts_send_content_md5() {
    let temp = crate::test_support::tempdir().unwrap();
    let server = Server::start("recovery-upload-plain-http");
    std::fs::write(temp.path().join("source"), vec![b'x'; SIZE]).unwrap();
    let output = server
        .command(temp.path())
        .env_remove(TREAT_HTTP_AS_HTTPS)
        .args(["--s3-endpoint", &server.address])
        .args(["source", "--to", "s3://bucket", "--as", "object"])
        .capture_output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.gate.0.load(Ordering::Relaxed));
}

#[test]
fn multipart_parts_are_resent_after_corruption_with_a_warning() {
    let temp = crate::test_support::tempdir().unwrap();
    let server = Server::start("recovery-upload-corrupt-once");
    std::fs::write(temp.path().join("source"), vec![b'x'; SIZE]).unwrap();
    let output = server
        .command_with_retries(temp.path(), 1)
        .args(["--s3-endpoint", &server.address])
        .args(["source", "--to", "s3://bucket", "--as", "object"])
        .capture_output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.gate.0.load(Ordering::Relaxed), "upload completed");
    let text = output_text(&output);
    assert!(
        text.contains("the destination received corrupted data in part")
            && text.contains("(BadDigest); retrying"),
        "{text}"
    );
}

#[test]
fn multipart_parts_add_content_md5_when_the_destination_requires_a_checksum() {
    let temp = crate::test_support::tempdir().unwrap();
    let server = Server::start("recovery-upload-object-lock");
    std::fs::write(temp.path().join("source"), vec![b'x'; SIZE]).unwrap();
    let output = server.cp(
        temp.path(),
        &["source", "--to", "s3://bucket", "--as", "object"],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.gate.0.load(Ordering::Relaxed));
    // Parts already in flight may each be rejected once before the switch.
    let rejected = REJECTED_PARTS.load(Ordering::Relaxed);
    assert!((1..=2).contains(&rejected), "{rejected}");
}
