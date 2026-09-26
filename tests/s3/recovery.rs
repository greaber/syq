//! Optional recovery storage must not be required to finish a copy.
use super::*;
use std::os::unix::fs::PermissionsExt;

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
    let mut body = vec![0; length];
    socket.read_exact(&mut body).unwrap();
    match method {
        "HEAD" => reply(socket, 404, &[], b"", true),
        "GET" => {
            assert!(target.contains("list-type="), "{target}");
            reply(socket, 200, &[], b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>", false);
        }
        "POST" if target.contains("uploads") => reply(socket, 200, &[],
            b"<InitiateMultipartUploadResult><UploadId>new-upload</UploadId></InitiateMultipartUploadResult>", false),
        "PUT" => {
            use base64::Engine as _;
            use sha2::Digest as _;
            assert!(target.contains("uploadId=new-upload"));
            assert!(body.iter().all(|b| *b == b'x'));
            if let Some(checksum) = headers.get("content-md5") {
                assert_eq!(*checksum, base64::engine::general_purpose::STANDARD.encode(md5::Md5::digest(&body)));
            } else {
                assert_eq!(headers["x-amz-checksum-sha256"], base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&body)));
            }
            if fault == "recovery-upload-fail" {
                reply(socket, 403, &[], b"<Error><Code>AccessDenied</Code></Error>", false);
            } else {
                reply(socket, 200, &[("ETag".into(), "\"part\"".into())], b"", false);
            }
        }
        "POST" => {
            assert!(target.contains("uploadId=new-upload"));
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("<PartNumber>1</PartNumber>"), "{body}");
            assert!(body.contains("<PartNumber>2</PartNumber>"), "{body}");
            gate.0.store(true, Ordering::Relaxed);
            reply(socket, 200, &[], b"<CompleteMultipartUploadResult><ETag>done</ETag></CompleteMultipartUploadResult>", false);
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
        let file = source.join("data");
        std::fs::write(&file, &bytes).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
        let _source = ReadOnlyDirectory::new(source);
        let mut command = server.command(temp.path());
        let _home = configure_cache(&mut command, temp.path(), mode);
        command.arg(format!("--integrity-checking=transfer={algorithm}"));
        let output = command
            .args(["--s3-endpoint", &server.address])
            .arg(&file)
            .args(["--to", "s3://bucket", "--as", "object"])
            .capture_output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {}", output_text(&output));
        assert!(output_text(&output).contains("without saving recovery progress"));
        assert!(server.gate.0.load(Ordering::Relaxed));
        assert!(!server.gate.1.load(Ordering::Relaxed));
        assert_eq!(std::fs::read(file).unwrap(), bytes);
        assert_eq!(std::fs::read_dir(&_source.0).unwrap().count(), 1);
        if let Some(home) = _home {
            assert_eq!(std::fs::read_dir(&home.0).unwrap().count(), 0);
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
