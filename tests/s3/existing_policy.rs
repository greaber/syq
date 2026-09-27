use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(super) fn serve(
    socket: &mut TcpStream,
    fault: &str,
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
    gate: &(AtomicBool, AtomicBool),
) {
    let mut fields = vec![
        ("ETag".into(), "\"stored\"".into()),
        (
            "Last-Modified".into(),
            "Sun, 13 Sep 2020 12:26:40 GMT".into(),
        ),
        ("Content-Type".into(), "application/example".into()),
        ("Cache-Control".into(), "max-age=60".into()),
        ("x-amz-meta-other".into(), "keep".into()),
        ("x-amz-meta-syq-format".into(), "1".into()),
        ("x-amz-meta-syq-kind".into(), "file".into()),
        ("x-amz-meta-syq-mode".into(), "416".into()),
        (
            "x-amz-meta-syq-uid".into(),
            unsafe { libc::geteuid() }.to_string(),
        ),
        (
            "x-amz-meta-syq-gid".into(),
            unsafe { libc::getegid() }.to_string(),
        ),
        ("x-amz-meta-syq-mtime".into(), "10".into()),
        ("x-amz-meta-syq-mtime-nsec".into(), "0".into()),
    ];
    if let Some(algorithm) = fault.strip_prefix("existing-policy-hash-") {
        use sha2::Digest as _;
        if algorithm == "blake3" {
            fields.push((
                "x-amz-meta-syq-blake3".into(),
                blake3::hash(b"stored").to_hex().to_string(),
            ));
        } else {
            fields.retain(|(name, _)| name != "x-amz-meta-syq-format");
            fields.push(("x-amz-meta-syq-format".into(), "2".into()));
            fields.push(("x-amz-meta-syq-hash-algorithm".into(), algorithm.into()));
            let hash = match algorithm {
                "sha256" => sha2::Sha256::digest(b"stored")
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                "md5" => md5::Md5::digest(b"stored")
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                _ => panic!("unknown fixture algorithm"),
            };
            fields.push(("x-amz-meta-syq-hash".into(), hash));
        }
    }
    let foreign = fault == "existing-policy-foreign";
    if foreign {
        fields.retain(|(name, _): &(String, String)| !name.starts_with("x-amz-meta-syq-"));
    }
    match method {
        "HEAD" => reply(socket, 200, &fields, b"stored", true),
        "GET" if target.contains("list-type=") => reply(
            socket,
            200,
            &[],
            b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>",
            false,
        ),
        "GET" => {
            let already_read = gate.0.swap(true, Ordering::Relaxed);
            if fault.starts_with("existing-policy-hash-") || fault == "existing-policy-nohash-once"
            {
                assert!(!already_read, "comparison downloaded the object twice");
            }
            let mut fields = fields;
            let ranged = headers.contains_key("range");
            if ranged {
                fields.push(("Content-Range".into(), "bytes 0-5/6".into()));
            }
            reply(
                socket,
                if ranged { 206 } else { 200 },
                &fields,
                b"stored",
                false,
            );
        }
        "PUT" if headers.contains_key("x-amz-copy-source") => {
            assert_eq!(headers["x-amz-copy-source-if-match"], "\"stored\"");
            assert_eq!(headers["content-type"], "application/example");
            assert_eq!(headers["cache-control"], "max-age=60");
            assert_eq!(headers["x-amz-meta-other"], "keep");
            assert_eq!(
                headers["x-amz-meta-syq-mode"],
                if foreign { "438" } else { "416" }
            );
            assert!(!headers.contains_key("x-amz-meta-syq-blake3"));
            assert_eq!(headers["x-amz-meta-syq-mtime"], "20");
            gate.1.store(true, Ordering::Relaxed);
            reply(
                socket,
                200,
                &[],
                b"<CopyObjectResult><ETag>updated</ETag></CopyObjectResult>",
                false,
            );
        }
        "PUT" => {
            let mut bytes = vec![0; headers["content-length"].parse().unwrap()];
            socket.read_exact(&mut bytes).unwrap();
            assert_eq!(
                bytes,
                if fault == "existing-policy-tie" {
                    b"changed".as_slice()
                } else {
                    b"change".as_slice()
                }
            );
            gate.1.store(true, Ordering::Relaxed);
            reply(
                socket,
                200,
                &[("ETag".into(), "updated".into())],
                b"",
                false,
            );
        }
        _ => panic!("unexpected {method} {target}"),
    }
}

fn file(path: &Path, bytes: &[u8], time: u64) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::File::open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(time))
        .unwrap();
}

#[test]
fn existing_uploads_obey_policy_and_update_only_requested_metadata() {
    for (contents, extra, succeeds, writes) in [
        (
            b"stored".as_slice(),
            &["--if-exists=error-if-different"][..],
            true,
            false,
        ),
        (
            b"stored".as_slice(),
            &["--if-exists=error"][..],
            false,
            false,
        ),
        (b"change".as_slice(), &[][..], true, true),
        (
            b"change".as_slice(),
            &["--if-exists=error-if-different"][..],
            false,
            false,
        ),
        (b"change".as_slice(), &["--if-exists=keep"][..], true, false),
        (
            b"change".as_slice(),
            &["--if-exists=update"][..],
            true,
            true,
        ),
        (
            b"stored".as_slice(),
            &["--copy-metadata=mtime", "--if-exists=error-if-different"][..],
            true,
            true,
        ),
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start("existing-policy");
        file(&temp.path().join("source"), contents, 20);
        let mut args = vec!["source", "--to", "s3://bucket", "--as", "object"];
        args.extend_from_slice(extra);
        let output = server.cp(temp.path(), &args);
        assert_eq!(
            output.status.success(),
            succeeds,
            "{extra:?}: {}",
            output_text(&output)
        );
        assert_eq!(server.gate.1.load(Ordering::Relaxed), writes, "{extra:?}");
    }
}

#[test]
fn existing_downloads_obey_policy_and_leave_unselected_metadata_alone() {
    for (contents, extra, succeeds, expected, time) in [
        (
            b"stored".as_slice(),
            &[][..],
            true,
            b"stored".as_slice(),
            10,
        ),
        (
            b"stored".as_slice(),
            &["--if-exists=error-if-different"][..],
            true,
            b"stored".as_slice(),
            20,
        ),
        (
            b"stored".as_slice(),
            &["--if-exists=error"][..],
            false,
            b"stored".as_slice(),
            20,
        ),
        (
            b"change".as_slice(),
            &[][..],
            true,
            b"stored".as_slice(),
            10,
        ),
        (
            b"change".as_slice(),
            &["--if-exists=error-if-different"][..],
            false,
            b"change".as_slice(),
            20,
        ),
        (
            b"change".as_slice(),
            &["--if-exists=keep"][..],
            true,
            b"change".as_slice(),
            20,
        ),
        (
            b"change".as_slice(),
            &["--if-exists=update"][..],
            true,
            b"stored".as_slice(),
            10,
        ),
        (
            b"stored".as_slice(),
            &["--copy-metadata=mtime", "--if-exists=error-if-different"][..],
            true,
            b"stored".as_slice(),
            10,
        ),
        (
            b"change".as_slice(),
            &["--if-exists=update-if-older"][..],
            true,
            b"change".as_slice(),
            20,
        ),
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start("existing-policy");
        let dest = temp.path().join("destination");
        file(&dest, contents, 20);
        let mut args = vec!["--from", "s3://bucket", "object", "--as", "destination"];
        args.extend_from_slice(extra);
        let output = server.cp(temp.path(), &args);
        assert_eq!(
            output.status.success(),
            succeeds,
            "{extra:?}: {}",
            output_text(&output)
        );
        assert_eq!(std::fs::read(&dest).unwrap(), expected);
        let meta = std::fs::metadata(dest).unwrap();
        assert_eq!(meta.mtime(), time);
        assert_eq!(meta.mode() & 0o777, 0o600);
    }
}

#[test]
fn expected_upload_hash_does_not_allow_a_metadata_only_update_of_wrong_contents() {
    use sha2::Digest as _;
    for policy in ["error-if-different", "update"] {
        let server = Server::start("existing-policy");
        let temp = crate::test_support::tempdir().unwrap();
        file(&temp.path().join("source"), b"change", 10);
        let digest = format!(
            "sha256:{}",
            sha2::Sha256::digest(b"change")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let mapping = expected_mapping(temp.path(), "source", "object", &digest);
        let output = server.cp(
            temp.path(),
            &[
                "--mapping",
                &mapping,
                "--to",
                "s3://bucket",
                "--into",
                ".",
                "--if-exists",
                policy,
                "--copy-metadata=permissions",
            ],
        );
        assert_eq!(
            output.status.success(),
            policy == "update",
            "{}",
            output_text(&output)
        );
        assert_eq!(server.gate.1.load(Ordering::Relaxed), policy == "update");
    }
}

#[test]
fn metadata_only_upload_to_foreign_object_keeps_unselected_defaults() {
    let temp = test_support::tempdir().unwrap();
    let server = Server::start("existing-policy-foreign");
    // The source is private (0600); copying only mtime must not also copy mode
    // or attach a hash computed solely to compare the existing contents.
    file(&temp.path().join("source"), b"stored", 20);
    let output = server.cp(
        temp.path(),
        &[
            "source",
            "--to",
            "s3://bucket",
            "--as",
            "object",
            "--copy-metadata=mtime",
            "--if-exists=error-if-different",
        ],
    );
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(server.gate.1.load(Ordering::Relaxed));
}

#[test]
fn stored_hashes_avoid_comparison_downloads() {
    for fault in [
        "existing-policy-hash-blake3",
        "existing-policy-hash-sha256",
        "existing-policy-hash-md5",
    ] {
        for direction in ["download", "upload"] {
            for different in [false, true] {
                let temp = test_support::tempdir().unwrap();
                let server = Server::start(fault);
                let local = temp.path().join("local");
                let contents = if different { b"change" } else { b"stored" };
                file(&local, contents, 20);
                let mut args = if direction == "download" {
                    vec!["--from", "s3://bucket", "object", "--as", "local"]
                } else {
                    vec!["local", "--to", "s3://bucket", "--as", "object"]
                };
                args.push("--if-exists=error-if-different");
                let output = server.cp(temp.path(), &args);
                assert_eq!(
                    output.status.success(),
                    !different,
                    "{fault} {direction}: {}",
                    output_text(&output)
                );
                assert!(
                    !server.gate.0.load(Ordering::Relaxed),
                    "object body downloaded for {fault} {direction}"
                );
                assert!(!server.gate.1.load(Ordering::Relaxed), "object was changed");
                assert_eq!(std::fs::read(&local).unwrap(), contents);
                assert_eq!(std::fs::metadata(&local).unwrap().mtime(), 20);
            }
        }
    }
}

#[test]
fn default_download_reuses_stored_hash_without_changing_mtime() {
    for fault in [
        "existing-policy-hash-blake3",
        "existing-policy-hash-sha256",
        "existing-policy-hash-md5",
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start(fault);
        let local = temp.path().join("local");
        file(&local, b"stored", 20);
        let output = server.cp(
            temp.path(),
            &["--from", "s3://bucket", "object", "--as", "local"],
        );
        assert!(output.status.success(), "{}", output_text(&output));
        assert!(
            !server.gate.0.load(Ordering::Relaxed),
            "unchanged object body was downloaded"
        );
        assert_eq!(std::fs::metadata(local).unwrap().mtime(), 20);
    }
}

#[test]
fn explicit_hash_uses_requested_algorithm_and_compares_only_once() {
    for fault in ["existing-policy-hash-sha256", "existing-policy-nohash-once"] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start(fault);
        let local = temp.path().join("local");
        file(&local, b"change", 10);
        let output = server.cp(
            temp.path(),
            &[
                "--from",
                "s3://bucket",
                "object",
                "--as",
                "local",
                "--if-exists=error-if-different",
                "--hash",
            ],
        );
        assert!(!output.status.success(), "{}", output_text(&output));
        assert!(
            server.gate.0.load(Ordering::Relaxed),
            "BLAKE3 comparison must read an object with no stored BLAKE3 hash"
        );
        assert_eq!(std::fs::read(local).unwrap(), b"change");
    }
}

#[test]
fn update_if_older_copies_different_sizes_on_timestamp_ties() {
    for upload in [false, true] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start("existing-policy-tie");
        let local = temp.path().join("local");
        file(&local, b"changed", 10);
        let mut args = if upload {
            vec!["local", "--to", "s3://bucket", "--as", "object"]
        } else {
            vec!["--from", "s3://bucket", "object", "--as", "local"]
        };
        args.push("--if-exists=update-if-older");
        let output = server.cp(temp.path(), &args);
        assert!(output.status.success(), "{}", output_text(&output));
        if upload {
            assert!(server.gate.1.load(Ordering::Relaxed));
        } else {
            assert_eq!(std::fs::read(local).unwrap(), b"stored");
        }
    }
}

#[test]
fn update_if_older_uses_service_time_for_foreign_objects() {
    for (time, writes) in [
        (1_599_999_999, false),
        (1_600_000_000, true),
        (1_600_000_001, true),
    ] {
        let temp = test_support::tempdir().unwrap();
        let server = Server::start("existing-policy-foreign");
        file(&temp.path().join("source"), b"change", time);
        let output = server.cp(
            temp.path(),
            &[
                "source",
                "--to",
                "s3://bucket",
                "--as",
                "object",
                "--if-exists=update-if-older",
            ],
        );
        assert!(output.status.success(), "{}", output_text(&output));
        assert_eq!(
            server.gate.1.load(Ordering::Relaxed),
            writes,
            "source timestamp {time}"
        );
    }
}
