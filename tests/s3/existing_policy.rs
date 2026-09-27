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
            gate.0.store(true, Ordering::Relaxed);
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
            assert_eq!(bytes, b"change");
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
