use super::*;

const LARGE: u64 = 5 * 1024 * 1024 * 1024 + 1;
const CONTENT_FIELDS: &[(&str, &str, &str)] = &[
    (
        "content-type",
        "application/source",
        "application/destination",
    ),
    ("content-encoding", "gzip", "identity"),
    ("content-language", "de", "en"),
    ("content-disposition", "attachment", "inline"),
    ("cache-control", "no-cache", "max-age=60"),
    ("expires", "0", "1"),
    ("x-amz-website-redirect-location", "/source", "/destination"),
];

pub(super) fn serve(
    socket: &mut TcpStream,
    fault: &str,
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
    gate: &(AtomicBool, AtomicBool),
) {
    let source = target.starts_with("/source/");
    let large = fault.contains("large");
    let fresh = fault.contains("fresh");
    let all = fault.contains("all");
    let empty = fault.contains("empty");
    let tags = fault.contains("tags") || all;
    match method {
        "HEAD" => {
            if !source && fresh {
                reply(socket, 404, &[], b"", true);
                return;
            }
            let mut fields = vec![
                (
                    "Content-Length".into(),
                    if large { LARGE } else { 6 }.to_string(),
                ),
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
                    "x-amz-version-id".into(),
                    if source {
                        "source-version"
                    } else {
                        "destination-version"
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
                ("x-amz-server-side-encryption".into(), "AES256".into()),
                ("x-amz-meta-syq-format".into(), "1".into()),
                ("x-amz-meta-syq-kind".into(), "file".into()),
                (
                    "x-amz-meta-syq-mode".into(),
                    if source { "384" } else { "416" }.into(),
                ),
                ("x-amz-meta-syq-mtime".into(), "10".into()),
                ("x-amz-meta-syq-mtime-nsec".into(), "0".into()),
                ("x-amz-meta-syq-uid".into(), "1000".into()),
                ("x-amz-meta-syq-gid".into(), "1000".into()),
                (
                    "x-amz-tagging-count".into(),
                    if source && empty { "0" } else { "1" }.into(),
                ),
            ];
            if !source || !empty {
                for (name, src, dst) in CONTENT_FIELDS {
                    fields.push(((*name).into(), if source { *src } else { *dst }.into()));
                }
                fields.push((
                    "x-amz-meta-app".into(),
                    if source { "source" } else { "destination" }.into(),
                ));
            }
            if !source {
                fields.push((
                    "x-amz-meta-destination-only".into(),
                    "remove-if-selected".into(),
                ));
            }
            if source && fault.contains("missing") {
                fields.push(("x-amz-missing-meta".into(), "1".into()));
            }
            reply(socket, 200, &fields, b"", true);
        }
        "GET" if target.contains("tagging") => {
            if fault.contains("unsupported") {
                reply(
                    socket,
                    501,
                    &[],
                    b"<Error><Code>NotImplemented</Code></Error>",
                    false,
                );
                return;
            }
            assert!(
                tags || large,
                "unselected tags must not be inspected for a small metadata update"
            );
            assert!(target.contains(if source {
                "versionId=source-version"
            } else {
                "versionId=destination-version"
            }));
            let body = if source || fault.contains("same-tags") {
                b"<Tagging><TagSet><Tag><Key>source</Key><Value>a b</Value></Tag></TagSet></Tagging>".as_slice()
            } else {
                b"<Tagging><TagSet><Tag><Key>destination</Key><Value>keep</Value></Tag></TagSet></Tagging>".as_slice()
            };
            reply(socket, 200, &[], body, false);
        }
        "PUT" if target.contains("tagging") => {
            assert!(!source);
            assert!(tags && !all);
            assert!(target.contains("versionId=destination-version"));
            let mut body = vec![0; headers["content-length"].parse().unwrap()];
            socket.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            if empty {
                assert!(!body.contains("<Tag>"));
            } else {
                assert!(
                    body.contains("<Key>source</Key><Value>a b</Value>"),
                    "{body}"
                );
            }
            assert!(!body.contains("destination"));
            assert!(!headers.contains_key("x-amz-copy-source"));
            gate.1.store(true, Ordering::Relaxed);
            reply(socket, 200, &[], b"", false);
        }
        "POST" if target.contains("uploads") => {
            check_fields(headers, all, empty, fresh);
            assert_eq!(headers["x-amz-tagging"], "source=a%20b");
            reply(socket, 200, &[], b"<InitiateMultipartUploadResult><UploadId>fields</UploadId></InitiateMultipartUploadResult>", false);
        }
        "PUT" => {
            assert!(!source);
            assert!(!fault.contains("same-tags"));
            assert!(!fault.contains("missing") || (fresh && !large));
            let copy = percent_encoding::percent_decode_str(&headers["x-amz-copy-source"])
                .decode_utf8()
                .unwrap();
            assert_eq!(
                copy,
                if fresh {
                    "source/original?versionId=source-version"
                } else {
                    "destination/copied"
                }
            );
            assert_eq!(
                headers["x-amz-copy-source-if-match"],
                if fresh {
                    "\"source\""
                } else {
                    "\"destination\""
                }
            );
            if large {
                assert!(target.contains("uploadId=fields"));
                reply(
                    socket,
                    200,
                    &[],
                    b"<CopyPartResult><ETag>part</ETag></CopyPartResult>",
                    false,
                );
            } else {
                check_fields(headers, all, empty, fresh);
                if fresh {
                    assert_eq!(headers["x-amz-metadata-directive"], "COPY");
                }
                if tags && fresh {
                    assert_eq!(headers["x-amz-tagging-directive"], "REPLACE");
                    assert_eq!(headers["x-amz-tagging"], "source=a%20b");
                }
                if !fresh {
                    assert_eq!(headers["x-amz-metadata-directive"], "REPLACE");
                    assert_eq!(
                        headers["x-amz-tagging-directive"],
                        if all { "REPLACE" } else { "COPY" }
                    );
                    if all {
                        assert_eq!(
                            headers
                                .get("x-amz-tagging")
                                .map(String::as_str)
                                .unwrap_or(""),
                            if empty { "" } else { "source=a%20b" }
                        );
                    }
                }
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
        "POST" if target.contains("uploadId=fields") => {
            let mut body = vec![0; headers["content-length"].parse().unwrap()];
            socket.read_exact(&mut body).unwrap();
            gate.1.store(true, Ordering::Relaxed);
            reply(socket, 200, &[], b"<CompleteMultipartUploadResult><ETag>updated</ETag></CompleteMultipartUploadResult>", false);
        }
        _ => panic!("unexpected {method} {target}; selected metadata must not read object bodies"),
    }
}

fn check_fields(
    headers: &std::collections::HashMap<String, String>,
    all: bool,
    empty: bool,
    fresh: bool,
) {
    assert_eq!(
        headers["x-amz-storage-class"],
        if all || fresh {
            "STANDARD"
        } else {
            "REDUCED_REDUNDANCY"
        }
    );
    if fresh {
        // Small COPY preserves metadata at the service; multipart supplies it.
        if headers.contains_key("x-amz-copy-source") {
            return;
        }
    } else {
        assert_eq!(headers["x-amz-server-side-encryption"], "AES256");
        assert_eq!(
            headers["x-amz-meta-syq-mode"], "416",
            "application metadata must not replace stored file attributes"
        );
    }
    for (name, src, dst) in CONTENT_FIELDS {
        let selected = all || *name == "content-type";
        let expected = if empty && selected {
            None
        } else {
            Some(if selected || fresh { *src } else { *dst })
        };
        assert_eq!(headers.get(*name).map(String::as_str), expected, "{name}");
    }
    assert_eq!(
        headers.get("x-amz-meta-app").map(String::as_str),
        if all && empty {
            None
        } else {
            Some(if all || fresh {
                "source"
            } else {
                "destination"
            })
        }
    );
    assert_eq!(
        headers.contains_key("x-amz-meta-destination-only"),
        !all && !fresh
    );
}

#[test]
fn selected_s3_metadata_keeps_destination_contents_and_unselected_attributes() {
    for (fault, selected) in [
        ("metadata-fields-type", "content-type"),
        ("metadata-fields-type-empty", "content-type"),
        ("metadata-fields-all", "content-type,content-encoding,content-language,content-disposition,cache-control,expires,website-redirect,user-metadata,tags,storage-class"),
        ("metadata-fields-all-large", "content-type,content-encoding,content-language,content-disposition,cache-control,expires,website-redirect,user-metadata,tags,storage-class"),
        ("metadata-fields-all-empty", "content-type,content-encoding,content-language,content-disposition,cache-control,expires,website-redirect,user-metadata,tags,storage-class"),
        ("metadata-fields-tags", "tags"),
        ("metadata-fields-tags-empty", "tags"),
        ("metadata-fields-same-tags", "tags"),
        ("metadata-fields-all-missing", "user-metadata"),
        ("metadata-fields-fresh", "storage-class"),
        ("metadata-fields-fresh-missing", "storage-class,user-metadata"),
        ("metadata-fields-fresh-large-missing", "storage-class,user-metadata"),
        ("metadata-fields-fresh-tags", "storage-class,tags"),
        ("metadata-fields-fresh-tags-unsupported", "storage-class,tags"),
        ("metadata-fields-fresh-large", "storage-class,tags"),
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start(fault);
        let out = server.command_with_part_size(temp.path(), 0, false)
            .args(["--s3-endpoint", &server.address, "--from", "s3://source", "original", "--to", "s3://destination", "--as", "copied", "--copy-metadata", selected, "--performance-tuning=s3-part-size=5G"])
            .capture_output().unwrap();
        let incomplete_copy = fault.contains("missing")
            && (!fault.contains("fresh") || fault.contains("large"));
        if fault.contains("unsupported") {
            assert!(!out.status.success(), "{fault}");
            assert!(output_text(&out).contains("read explicitly selected S3 tags"), "{}", output_text(&out));
        } else if incomplete_copy {
            assert!(!out.status.success(), "{fault}");
            assert!(output_text(&out).contains("omitted source metadata"), "{}", output_text(&out));
        } else {
            assert!(out.status.success(), "{fault}: {}", output_text(&out));
        }
        assert_eq!(server.gate.1.load(Ordering::Relaxed), !fault.contains("same-tags") && !incomplete_copy && !fault.contains("unsupported"), "{fault}");
    }
}

#[test]
fn s3_metadata_selections_reject_filesystem_and_stream_routes() {
    let temp = test_support::tempdir().unwrap();
    for args in [
        vec!["source", "--as", "target"],
        vec!["--from", "s3://bucket", "source", "--as", "target"],
        vec!["source", "--to", "s3://bucket", "--as", "target"],
        vec!["--src-fd", "0", "--to", "s3://bucket", "--as", "target"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .arg("cp")
            .args(args)
            .arg("--copy-metadata=content-type")
            .current_dir(temp.path())
            .capture_output()
            .unwrap();
        assert!(!out.status.success());
        assert!(
            output_text(&out).contains("require named S3-to-S3 copies"),
            "{}",
            output_text(&out)
        );
    }
}
