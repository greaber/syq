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
            for (name, id) in [
                ("uid", unsafe { libc::geteuid() }),
                ("gid", unsafe { libc::getegid() }),
            ] {
                fields.push((format!("x-amz-meta-syq-{name}"), id.to_string()));
            }
            reply(socket, 200, &fields, b"", true);
        }
        "GET" if target.contains("tagging") => {
            assert!(!source, "must preserve destination tags");
            reply(socket, 200, &[], b"<Tagging><TagSet><Tag><Key>keep</Key><Value>destination tag</Value></Tag></TagSet></Tagging>", false);
        }
        "POST" if target.contains("uploads") => {
            check_metadata(headers);
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
                check_metadata(headers);
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

fn check_metadata(headers: &std::collections::HashMap<String, String>) {
    for (name, value) in [
        ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ("x-amz-server-side-encryption", "aws:kms"),
        (
            "x-amz-server-side-encryption-aws-kms-key-id",
            "destination-key",
        ),
        ("x-amz-server-side-encryption-bucket-key-enabled", "false"),
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
