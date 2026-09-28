use super::*;
use std::os::unix::fs::PermissionsExt;

const LARGE: u64 = 5 * 1024 * 1024 * 1024 + 1;

pub(super) fn serve(
    socket: &mut TcpStream,
    fault: &str,
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
    gate: &(AtomicBool, AtomicBool),
) {
    let source = target.starts_with("/source/");
    let size = if fault.contains("large") { LARGE } else { 6 };
    if fault.ends_with("missing") || fault.ends_with("conflict") {
        assert_eq!(
            method, "HEAD",
            "unsafe metadata update sent {method} {target}"
        );
    }
    match method {
        "HEAD" => {
            let mut fields = vec![
                ("Content-Length".into(), size.to_string()),
                (
                    "ETag".into(),
                    if source {
                        "\"source\""
                    } else {
                        "\"destination\""
                    }
                    .into(),
                ),
                (
                    "x-amz-storage-class".into(),
                    if source {
                        "STANDARD"
                    } else {
                        "REDUCED_REDUNDANCY"
                    }
                    .into(),
                ),
                ("x-amz-server-side-encryption".into(), "aws:kms".into()),
                (
                    "x-amz-server-side-encryption-aws-kms-key-id".into(),
                    if source {
                        "source-key"
                    } else {
                        "destination-key"
                    }
                    .into(),
                ),
                (
                    "x-amz-server-side-encryption-bucket-key-enabled".into(),
                    "false".into(),
                ),
                ("Content-Type".into(), "application/example".into()),
                ("Content-Encoding".into(), "identity".into()),
                ("Content-Language".into(), "en".into()),
                ("Content-Disposition".into(), "inline".into()),
                ("Cache-Control".into(), "max-age=60".into()),
                ("Expires".into(), "0".into()),
                (
                    "x-amz-website-redirect-location".into(),
                    if source { "/source" } else { "/destination" }.into(),
                ),
                (
                    "x-amz-meta-other".into(),
                    if source { "source" } else { "destination" }.into(),
                ),
                ("x-amz-tagging-count".into(), "1".into()),
                ("x-amz-meta-syq-format".into(), "1".into()),
                ("x-amz-meta-syq-kind".into(), "file".into()),
                (
                    "x-amz-meta-syq-mode".into(),
                    if source { "384" } else { "416" }.into(),
                ),
                ("x-amz-meta-syq-mtime".into(), "10".into()),
                ("x-amz-meta-syq-mtime-nsec".into(), "0".into()),
            ];
            if fault.contains("lock") {
                if !fault.contains("hold-only") {
                    fields.push((
                        "x-amz-object-lock-mode".into(),
                        if source { "GOVERNANCE" } else { "COMPLIANCE" }.into(),
                    ));
                    fields.push((
                        "x-amz-object-lock-retain-until-date".into(),
                        if source {
                            "2099-01-01T00:00:00Z"
                        } else if fault.contains("expired") {
                            "2000-01-01T00:00:00Z"
                        } else {
                            "2099-02-03T04:05:06.123Z"
                        }
                        .into(),
                    ));
                }
                if !fault.contains("retention-only") {
                    fields.push((
                        "x-amz-object-lock-legal-hold".into(),
                        if source { "OFF" } else { "ON" }.into(),
                    ));
                }
            }
            for (name, id) in [
                ("uid", unsafe { libc::geteuid() }),
                ("gid", unsafe { libc::getegid() }),
            ] {
                fields.push((format!("x-amz-meta-syq-{name}"), id.to_string()));
            }
            fields.push((
                "x-amz-missing-meta".into(),
                if fault.ends_with("missing") { "1" } else { "0" }.into(),
            ));
            reply(socket, 200, &fields, b"", true);
        }
        "GET" if target.contains("tagging") => {
            assert!(!source, "must preserve destination tags");
            reply(socket, 200, &[], b"<Tagging><TagSet><Tag><Key>keep</Key><Value>destination tag</Value></Tag></TagSet></Tagging>", false);
        }
        "POST" if target.contains("uploads") => {
            check_metadata(headers, fault);
            if fault.ends_with("lock-denied") {
                reply(socket, 403, &[], b"<Error><Code>AccessDenied</Code><Message>lock permission required</Message></Error>", false);
                return;
            }
            assert_eq!(headers["x-amz-tagging"], "keep=destination%20tag");
            reply(socket, 200, &[], b"<InitiateMultipartUploadResult><UploadId>metadata-update</UploadId></InitiateMultipartUploadResult>", false);
        }
        "PUT" => {
            assert!(!source);
            let copy = percent_encoding::percent_decode_str(&headers["x-amz-copy-source"])
                .decode_utf8()
                .unwrap();
            assert_eq!(copy, "destination/copied");
            assert_eq!(headers["x-amz-copy-source-if-match"], "\"destination\"");
            if size == LARGE {
                assert!(target.contains("uploadId=metadata-update"));
                assert!(matches!(
                    headers["x-amz-copy-source-range"].as_str(),
                    "bytes=0-5368709119" | "bytes=5368709120-5368709120"
                ));
                gate.0.store(true, Ordering::Relaxed);
                reply(
                    socket,
                    200,
                    &[],
                    b"<CopyPartResult><ETag>part</ETag></CopyPartResult>",
                    false,
                );
            } else {
                check_metadata(headers, fault);
                if fault.ends_with("lock-denied") {
                    reply(socket, 403, &[], b"<Error><Code>AccessDenied</Code><Message>lock permission required</Message></Error>", false);
                    return;
                }
                assert_eq!(headers["x-amz-tagging-directive"], "COPY");
                gate.1.store(true, Ordering::Relaxed);
                reply(
                    socket,
                    200,
                    &[],
                    b"<CopyObjectResult><ETag>updated</ETag></CopyObjectResult>",
                    false,
                );
            }
        }
        "POST" if target.contains("uploadId=metadata-update") => {
            assert!(gate.0.load(Ordering::Relaxed));
            assert_eq!(headers["if-match"], "\"destination\"");
            let mut body = vec![0; headers["content-length"].parse().unwrap()];
            socket.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            assert!(body.contains("<PartNumber>1</PartNumber>"));
            assert!(body.contains("<PartNumber>2</PartNumber>"));
            gate.1.store(true, Ordering::Relaxed);
            reply(socket, 200, &[], b"<CompleteMultipartUploadResult><ETag>updated</ETag></CompleteMultipartUploadResult>", false);
        }
        _ => panic!(
            "unexpected {method} {target}; metadata updates must not read or upload object bodies"
        ),
    }
}

fn check_metadata(headers: &std::collections::HashMap<String, String>, fault: &str) {
    for (name, expected) in [
        ("x-amz-object-lock-mode", "COMPLIANCE"),
        (
            "x-amz-object-lock-retain-until-date",
            "2099-02-03T04:05:06.123Z",
        ),
        ("x-amz-object-lock-legal-hold", "ON"),
    ] {
        let present = fault.contains("lock")
            && if name.ends_with("legal-hold") {
                !fault.contains("retention-only")
            } else {
                !fault.contains("hold-only") && !fault.contains("expired")
            };
        assert_eq!(
            headers.get(name).map(String::as_str),
            present.then_some(expected),
            "{name}"
        );
    }
    let aes = fault.ends_with("aes");
    assert_eq!(
        headers["x-amz-server-side-encryption"],
        if aes { "AES256" } else { "aws:kms" }
    );
    if aes {
        assert!(!headers.contains_key("x-amz-server-side-encryption-aws-kms-key-id"));
        assert!(!headers.contains_key("x-amz-server-side-encryption-bucket-key-enabled"));
    } else {
        assert_eq!(
            headers["x-amz-server-side-encryption-aws-kms-key-id"],
            if fault.ends_with("key") {
                "selected-key"
            } else {
                "destination-key"
            }
        );
        assert_eq!(
            headers["x-amz-server-side-encryption-bucket-key-enabled"],
            if fault.ends_with("bucket") {
                "true"
            } else {
                "false"
            }
        );
    }
    for (name, value) in [
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ("content-type", "application/example"),
        ("content-encoding", "identity"),
        ("content-language", "en"),
        ("content-disposition", "inline"),
        ("cache-control", "max-age=60"),
        ("expires", "0"),
        ("x-amz-website-redirect-location", "/destination"),
        ("x-amz-meta-other", "destination"),
        ("x-amz-meta-syq-mode", "384"),
        ("x-amz-meta-syq-mtime", "10"),
    ] {
        assert_eq!(headers[name], value, "{name}");
    }
}

#[test]
fn metadata_only_bucket_copy_uses_destination_bytes_and_attributes() {
    for fault in ["metadata-update-small", "metadata-update-large"] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start(fault);
        // The objects have different ETags/contents but equal size/stored time:
        // accepting the quick check must never authorize replacing their bytes.
        let output = server
            .command_with_part_size(temp.path(), 0, false)
            .args(["--s3-endpoint", &server.address])
            .args([
                "--from",
                "s3://source",
                "original",
                "--to",
                "s3://destination",
                "--as",
                "copied",
                "--copy-metadata=permissions",
                "--if-exists=error-if-different",
                "--performance-tuning=s3-part-size=5G",
            ])
            .capture_output()
            .unwrap();
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert!(server.gate.1.load(Ordering::Relaxed));
    }
}

#[test]
fn permission_only_upload_handles_large_objects_without_reading_local_contents() {
    for fault in ["metadata-update-small", "metadata-update-large"] {
        let temp = test_support::tempdir().unwrap();
        let path = temp.path().join("source");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(if fault.contains("large") { LARGE } else { 6 })
            .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        file.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(10))
            .unwrap();
        let server = Server::start(fault);
        let output = server
            .command_with_part_size(temp.path(), 0, false)
            .args(["--s3-endpoint", &server.address])
            .args([
                path.to_str().unwrap(),
                "--to",
                "s3://destination",
                "--as",
                "copied",
                "--copy-metadata=permissions",
                "--performance-tuning=s3-part-size=5G",
            ])
            .capture_output()
            .unwrap();
        assert!(output.status.success(), "{fault}: {}", output_text(&output));
        assert!(server.gate.1.load(Ordering::Relaxed));
    }
}

#[test]
fn metadata_encryption_overrides_work_for_single_and_multipart_copies() {
    for (fault, headers) in [
        (
            "metadata-update-small-aes",
            vec!["x-amz-server-side-encryption: AES256"],
        ),
        (
            "metadata-update-large-aes",
            vec!["x-amz-server-side-encryption: AES256"],
        ),
        (
            "metadata-update-small-key",
            vec!["x-amz-server-side-encryption-aws-kms-key-id: selected-key"],
        ),
        (
            "metadata-update-large-key",
            vec!["x-amz-server-side-encryption-aws-kms-key-id: selected-key"],
        ),
        (
            "metadata-update-small-bucket",
            vec!["x-amz-server-side-encryption-bucket-key-enabled: true"],
        ),
        (
            "metadata-update-large-bucket",
            vec!["x-amz-server-side-encryption-bucket-key-enabled: true"],
        ),
        (
            "metadata-update-small-conflict",
            vec![
                "x-amz-server-side-encryption: AES256",
                "x-amz-server-side-encryption-aws-kms-key-id: selected-key",
            ],
        ),
        (
            "metadata-update-large-conflict",
            vec![
                "x-amz-server-side-encryption: AES256",
                "x-amz-server-side-encryption-aws-kms-key-id: selected-key",
            ],
        ),
    ] {
        for upload in [false, true] {
            for flag in ["--s3-header", "--s3-write-header"] {
                run_metadata_update(fault, upload, flag, &headers, true);
            }
        }
    }
}

#[test]
fn metadata_updates_keep_reported_lock_settings_and_do_not_drop_rejected_protection() {
    for fault in [
        "metadata-update-small-lock",
        "metadata-update-large-lock",
        "metadata-update-small-lock-hold-only",
        "metadata-update-large-lock-hold-only",
        "metadata-update-small-lock-retention-only",
        "metadata-update-large-lock-retention-only",
        "metadata-update-small-lock-expired",
        "metadata-update-large-lock-expired",
        "metadata-update-small-lock-denied",
        "metadata-update-large-lock-denied",
    ] {
        for upload in [false, true] {
            run_metadata_update(fault, upload, &[], true);
        }
    }
}

#[test]
fn incomplete_metadata_blocks_only_requested_metadata_updates() {
    for fault in [
        "metadata-update-small-missing",
        "metadata-update-large-missing",
    ] {
        for upload in [false, true] {
            for update in [false, true] {
                run_metadata_update(fault, upload, "--s3-header", &[], update);
            }
        }
    }
}

fn run_metadata_update(
    fault: &'static str,
    upload: bool,
    flag: &str,
    headers: &[&str],
    update: bool,
) {
    let temp = test_support::tempdir().unwrap();
    let path = temp.path().join("source");
    if upload {
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(if fault.contains("large") { LARGE } else { 6 })
            .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        file.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(10))
            .unwrap();
    }
    let server = Server::start(fault);
    let mut command = server.command_with_part_size(temp.path(), 0, false);
    command.args(["--s3-endpoint", &server.address]);
    if upload {
        command.arg(path.to_str().unwrap());
    } else {
        command.args(["--from", "s3://source", "original"]);
    }
    command.args([
        "--to",
        "s3://destination",
        "--as",
        "copied",
        "--performance-tuning=s3-part-size=5G",
    ]);
    if update {
        command.arg("--copy-metadata=permissions");
    }
    for header in headers {
        command.args([flag, header]);
    }
    // Metadata updates are self-copies: CopyObject or CreateMultipartUpload.
    command.args(["--s3-write-header", &format!("{}: yes", super::WRITE_PROBE)]);
    let output = command.capture_output().unwrap();
    let text = output_text(&output);
    let rejected = update
        && (fault.ends_with("missing")
            || fault.ends_with("conflict")
            || fault.ends_with("lock-denied"));
    assert_eq!(
        output.status.success(),
        !rejected,
        "{fault} upload={upload} update={update}: {text}"
    );
    if rejected {
        let expected = if fault.ends_with("missing") {
            "x-amz-missing-meta"
        } else if fault.ends_with("lock-denied") {
            "lock permission required"
        } else {
            "conflicting S3 header encryption settings"
        };
        assert!(text.contains(expected), "{fault}: {text}");
    }
    assert_eq!(
        server.gate.1.load(Ordering::Relaxed),
        update && !rejected,
        "{fault}"
    );
    assert_eq!(
        server.probes.load(Ordering::Relaxed),
        usize::from(update && !rejected),
        "{fault} upload={upload} update={update} {flag}"
    );
}
