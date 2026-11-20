use super::*;
use std::collections::BTreeSet;
fn approval() -> Request {
    Request {
        bucket: "fixture".into(),
        endpoint: None,
        region: None,
        profile: None,
        scopes: vec![Scope {
            key: "allowed".into(),
            descendants: true,
        }],
        source: None,
        removal: None,
        acl: BTreeMap::new(),
        upload: true,
        delete: false,
        create_only: true,
        lifetime: DEFAULT_LIFETIME,
        headers: Default::default(),
    }
}
#[test]
fn scope_rejects_siblings_and_unapproved_operations() {
    let permission = approval();
    for request in [
        Unsigned::new("GET", "allowed/file"),
        Unsigned::new("HEAD", "allowed"),
        Unsigned::new("PUT", "allowed/file").header("if-none-match", "*"),
        Unsigned::new("POST", "allowed/file").query("uploads", ""),
    ] {
        permission.permits(&request).unwrap();
    }
    for request in [
        Unsigned::new("GET", "allowed-sibling/file"),
        Unsigned::new("DELETE", "allowed/file"),
        Unsigned::new("PUT", "allowed/file"),
        Unsigned::new("GET", "allowed/file").query("acl", ""),
        Unsigned::new("POST", "").query("delete", ""),
    ] {
        assert!(permission.permits(&request).is_err(), "{request:?}");
    }
    permission
        .permits(
            &Unsigned::new("GET", "")
                .query("list-type", "2")
                .query("prefix", "allowed/"),
        )
        .unwrap();
    assert!(permission
        .permits(
            &Unsigned::new("GET", "")
                .query("list-type", "2")
                .query("prefix", "")
        )
        .is_err());
}
#[test]
fn old_request_shapes_do_not_acquire_storage_authority() {
    assert!(
        serde_json::from_str::<Request>(r#"{"destination":[],"copy":{},"constraints":{}}"#)
            .is_err()
    );
    let mut value = serde_json::to_value(approval()).unwrap();
    value["future_permission"] = true.into();
    assert!(serde_json::from_value::<Request>(value).is_err());
}
#[test]
fn upload_authorization_signs_object_lock_and_retention_bypass_only_when_the_command_adds_them() {
    // Keep the v0.7.1 JSON shapes literal: tightening signing policy must not
    // change how existing approval/request fields are read.
    let approval: Request = serde_json::from_str(
        r#"{
        "bucket":"fixture","endpoint":null,"region":null,"profile":null,
        "scopes":[{"key":"allowed","descendants":true}],
        "source":null,"removal":null,"acl":{},"upload":true,"delete":true,
        "create_only":false,"lifetime":60
    }"#,
    )
    .unwrap();
    approval.validate().unwrap();
    let upload: Unsigned = serde_json::from_str(
        r#"{
        "bucket":null,"method":"PUT","key":"allowed/file","query":{},"headers":{}
    }"#,
    )
    .unwrap();
    let mut signer = Signer {
        request: approval,
        configuration: Configuration {
            endpoint: "https://storage.example".into(),
            region: "auto".into(),
            expires_at: now().unwrap() + 60,
            requested_lifetime: 60,
        },
        credentials: aws_sdk_s3::config::Credentials::new(
            "fixture-key",
            "fixture-secret",
            None,
            None,
            "test",
        ),
    };
    for request in [
        upload.clone(),
        upload
            .clone()
            .header("x-amz-copy-source", "fixture/allowed/file"),
        Unsigned::new("POST", "allowed/file").query("uploads", ""),
        upload
            .clone()
            .query("uploadId", "id")
            .query("partNumber", "1"),
        Unsigned::new("POST", "allowed/file").query("uploadId", "id"),
        Unsigned::new("DELETE", "allowed/file"),
    ] {
        signer.request.permits(&request).unwrap();
        signer.sign(&request).unwrap();
        for (name, value) in [
            ("x-amz-object-lock-mode", "COMPLIANCE"),
            (
                "x-amz-object-lock-retain-until-date",
                "2099-01-01T00:00:00Z",
            ),
            ("x-amz-object-lock-legal-hold", "ON"),
            ("x-amz-object-lock-event-hold", "ON"),
            ("x-amz-object-lock-event-hold-duration-days", "10"),
            ("x-amz-object-lock-future-setting", "yes"),
            ("x-amz-bypass-governance-retention", "true"),
            ("x-amz-bucket-object-lock-enabled", "true"),
            ("x-amz-bucket-object-lock-token", "1"),
        ] {
            let forbidden = request.clone().header(name, value);
            assert!(signer.request.permits(&forbidden).is_err(), "{name}");
            let error = signer.sign(&forbidden).unwrap_err().to_string();
            assert!(
                error.contains(&format!("does not permit the {name} header")),
                "{name}: {error}"
            );
            // A header shown in the approved command is signed with that value.
            signer.request.headers.insert((name.into(), value.into()));
            signer.sign(&forbidden).unwrap();
            assert!(signer.sign(&request.clone().header(name, "other")).is_err());
            signer.request.headers.clear();
            // Forged wire requests cannot evade the lowercase-header check.
            assert!(signer
                .sign(&request.clone().header(&name.to_ascii_uppercase(), value))
                .is_err());
        }
    }
    // The subresource/query routes cannot be used instead of denied headers.
    for query in [
        "retention",
        "legal-hold",
        "object-lock",
        "x-amz-object-lock-mode",
    ] {
        assert!(
            signer.sign(&upload.clone().query(query, "")).is_err(),
            "{query}"
        );
    }
    signer
        .sign(&upload.header("x-amz-meta-object-lock-note", "ordinary user metadata"))
        .unwrap();
    // Bucket-wide path approval must not turn object access into bucket control.
    signer.request.scopes[0].key.clear();
    for header in [
        "x-amz-bucket-object-lock-enabled",
        "x-amz-bucket-object-lock-token",
    ] {
        let bucket_lock = Unsigned::new("PUT", "").header(header, "true");
        assert!(signer.request.permits(&bucket_lock).is_err());
        assert!(signer.sign(&bucket_lock).is_err());
    }
    for request in [
        Unsigned::new("HEAD", ""),
        Unsigned::new("GET", ""),
        Unsigned::new("GET", "")
            .query("list-type", "2")
            .query("prefix", "allowed/"),
        Unsigned::new("PUT", "allowed/file"),
    ] {
        signer.sign(&request).unwrap();
    }
    for upload_allowed in [true, false] {
        signer.request.upload = upload_allowed;
        signer.request.removal = Some(Removal::Current);
        signer.request.validate().unwrap();
        // Object removal remains authorized, including for removal-only approval.
        signer
            .sign(&Unsigned::new("DELETE", "allowed/file"))
            .unwrap();
        for request in [
            Unsigned::new("PUT", ""),
            Unsigned::new("POST", ""),
            Unsigned::new("POST", "").query("uploads", ""),
            Unsigned::new("POST", "").query("uploadId", "id"),
            Unsigned::new("DELETE", ""),
        ] {
            assert!(signer.request.permits(&request).is_err());
            let error = signer.sign(&request).unwrap_err().to_string();
            assert!(error.contains("bucket mutations"), "{request:?}: {error}");
        }
    }
}

#[test]
fn paths_and_query_are_encoded_without_changing_key_scope() {
    let request = Unsigned::new("PUT", "allowed/a +?#雪")
        .query("uploadId", "a+/=")
        .query("partNumber", "1");
    let url =
        url::Url::parse(&request_url("https://storage.example", "fixture", &request).unwrap())
            .unwrap();
    assert_eq!(url.path(), "/fixture/allowed/a%20%2B%3F%23%E9%9B%AA");
    assert_eq!(
        percent_encoding::percent_decode_str(url.path())
            .decode_utf8()
            .unwrap(),
        "/fixture/allowed/a +?#雪"
    );
    assert_eq!(
        url.query_pairs().find(|(k, _)| k == "uploadId").unwrap().1,
        "a+/="
    );
}

#[test]
fn read_only_and_create_only_authority_cannot_be_widened() {
    let mut permission = approval();
    permission.upload = false;
    permission.create_only = false;
    for request in [
        Unsigned::new("PUT", "allowed/a"),
        Unsigned::new("POST", "allowed/a").query("uploads", ""),
        Unsigned::new("POST", "allowed/a").query("uploadId", "opaque"),
        Unsigned::new("DELETE", "allowed/a").query("uploadId", "opaque"),
        Unsigned::new("GET", "allowed/a").query("tagging", ""),
    ] {
        assert!(permission.permits(&request).is_err(), "{request:?}");
    }
    permission = approval();
    for request in [
        Unsigned::new("PUT", "allowed/a")
            .header("if-none-match", "*")
            .header("x-amz-copy-source", "other/secret"),
        Unsigned::new("PUT", "allowed/a")
            .header("if-none-match", "*")
            .header("x-amz-acl", "public-read"),
        Unsigned::new("POST", "allowed/a").query("uploadId", "opaque"),
        Unsigned::new("PUT", "allowed/a")
            .query("uploadId", "opaque")
            .query("partNumber", "10001"),
    ] {
        assert!(permission.permits(&request).is_err(), "{request:?}");
    }
    permission
        .permits(
            &Unsigned::new("POST", "allowed/a")
                .query("uploadId", "opaque")
                .header("if-none-match", "*"),
        )
        .unwrap();
}

#[test]
fn sealed_authorization_reuses_requests_but_cannot_acquire_more() {
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut authorization = Authorization::new(
        "fixture".into(),
        Configuration {
            endpoint: "https://storage.example".into(),
            region: "auto".into(),
            expires_at: now().unwrap() + 60,
            requested_lifetime: 60,
        },
        socket,
    );
    let request = Unsigned::new("GET", "allowed/a");
    let mut state = authorization.state.lock().unwrap();
    state.connection = None;
    state
        .requests
        .insert(request.clone(), "fixture-bearer-url".into());
    drop(state);
    assert_eq!(
        authorization.signed(request.clone()).unwrap(),
        "fixture-bearer-url"
    );
    assert_eq!(
        authorization.signed(request.clone()).unwrap(),
        "fixture-bearer-url"
    );
    let error = authorization
        .signed(Unsigned::new("GET", "allowed/b"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("not prepared"), "{error}");
    assert!(!format!("{authorization:?}").contains("fixture-bearer-url"));
    authorization.configuration.expires_at = now().unwrap() - 1;
    assert!(authorization
        .signed(request)
        .unwrap_err()
        .to_string()
        .contains("expired"));
}

#[test]
fn presigns_bind_the_payload_marker_and_write_condition() {
    let signer = Signer {
        request: approval(),
        configuration: Configuration {
            endpoint: "https://storage.example".into(),
            region: "auto".into(),
            expires_at: now().unwrap() + DEFAULT_LIFETIME,
            requested_lifetime: DEFAULT_LIFETIME,
        },
        credentials: aws_sdk_s3::config::Credentials::new(
            "fixture-key",
            "fixture-secret",
            None,
            None,
            "test",
        ),
    };
    for request in [
        Unsigned::new("HEAD", "allowed/file"),
        Unsigned::new("PUT", "allowed/file").header("if-none-match", "*"),
        Unsigned::new("PUT", "allowed/file")
            .header("if-none-match", "*")
            .header(
                "x-amz-checksum-sha256",
                &crate::s3::checksum::Algorithm::Sha256
                    .digest(b"abc")
                    .unwrap(),
            ),
    ] {
        let url = url::Url::parse(&signer.sign(&request).unwrap()).unwrap();
        let headers = url
            .query_pairs()
            .find(|(key, _)| key == "X-Amz-SignedHeaders")
            .unwrap()
            .1;
        assert!(headers
            .split(';')
            .any(|header| header == "x-amz-content-sha256"));
        if request.method == "PUT" {
            assert!(headers.split(';').any(|header| header == "if-none-match"));
        }
        assert!(!url.as_str().contains("fixture-secret"));
    }
}

#[test]
fn server_copy_binds_both_buckets_and_preserves_read_only_source() {
    let mut permission = approval();
    permission.source = Some(ReadAccess {
        bucket: "source".into(),
        scopes: vec![Scope {
            key: "input".into(),
            descendants: true,
        }],
    });
    let read = Unsigned::new("GET", "input/a").bucket("source", "fixture");
    permission.permits(&read).unwrap();
    permission
        .permits(&read.clone().query("tagging", ""))
        .unwrap();
    let copy = Unsigned::new("PUT", "allowed/a")
        .header("if-none-match", "*")
        .header("x-amz-copy-source", "source/input/a%20b?versionId=v1");
    permission.permits(&copy).unwrap();
    for request in [
        Unsigned::new("PUT", "input/a")
            .bucket("source", "fixture")
            .header("if-none-match", "*"),
        Unsigned::new("DELETE", "input/a").bucket("source", "fixture"),
        read.bucket("another", "fixture"),
        copy.clone()
            .header("x-amz-copy-source", "source/input-sibling/a"),
        copy.clone()
            .header("x-amz-copy-source", "unapproved/input/a"),
        copy.header("x-amz-copy-source", "source/input/a?acl="),
    ] {
        assert!(permission.permits(&request).is_err(), "{request:?}");
    }
}

#[test]
fn deletion_distinguishes_current_objects_exact_versions_and_purges() {
    let mut permission = approval();
    permission.upload = false;
    permission.create_only = false;
    permission.delete = true;
    permission.removal = Some(Removal::Current);
    permission.validate().unwrap();
    let remove = Unsigned::new("DELETE", "allowed/key");
    permission.permits(&remove).unwrap();
    assert!(permission
        .permits(&remove.clone().query("versionId", "v1"))
        .is_err());
    let listing = Unsigned::new("GET", "")
        .query("versions", "")
        .query("prefix", "allowed");
    assert!(permission.permits(&listing).is_err());
    permission.removal = Some(Removal::Version("v1".into()));
    permission.permits(&listing).unwrap();
    permission
        .permits(&remove.clone().query("versionId", "v1"))
        .unwrap();
    assert!(permission
        .permits(&remove.clone().query("versionId", "v2"))
        .is_err());
    assert!(permission.permits(&remove).is_err());
    permission.removal = Some(Removal::AllVersions);
    permission
        .permits(&remove.clone().query("versionId", "v2"))
        .unwrap();
    assert!(permission.permits(&remove).is_err());
    assert!(permission
        .permits(&listing.query("prefix", "outside"))
        .is_err());
}

#[test]
fn explicitly_approved_acl_headers_cannot_be_replaced() {
    let mut permission = approval();
    permission.acl.insert("x-amz-acl".into(), "private".into());
    let request = Unsigned::new("PUT", "allowed/key").header("if-none-match", "*");
    permission
        .permits(&request.clone().header("x-amz-acl", "private"))
        .unwrap();
    assert!(permission
        .permits(&request.clone().header("x-amz-acl", "public-read"))
        .is_err());
    assert!(permission
        .permits(&request.header("x-amz-grant-read", "uri=anyone"))
        .is_err());
}

#[test]
fn stream_capabilities_accept_late_checksums_but_preserve_part_and_condition() {
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let authorization = Authorization::new(
        "fixture".into(),
        Configuration {
            endpoint: "https://storage.example".into(),
            region: "auto".into(),
            expires_at: now().unwrap() + 60,
            requested_lifetime: 60,
        },
        socket,
    );
    let request = Unsigned::new("PUT", "allowed/key")
        .query("uploadId", "owned")
        .query("partNumber", "1");
    let mut state = authorization.state.lock().unwrap();
    state.connection = None;
    state
        .requests
        .insert(request.clone(), "fixture-stream-url".into());
    drop(state);
    assert_eq!(
        authorization
            .signed(
                request
                    .clone()
                    .header("content-length", "17")
                    .header("content-md5", "checksum-known-after-producing")
            )
            .unwrap(),
        "fixture-stream-url"
    );
    assert!(authorization
        .signed(request.clone().query("partNumber", "2"))
        .is_err());
    assert!(authorization
        .signed(request.query("uploadId", "unapproved"))
        .is_err());
}

#[test]
fn literal_object_keys_keep_their_scope_through_signing_and_transport() {
    let signer = Signer {
        request: approval(),
        configuration: Configuration {
            endpoint: "https://storage.example/base".into(),
            region: "auto".into(),
            expires_at: now().unwrap() + 60,
            requested_lifetime: 60,
        },
        credentials: aws_sdk_s3::config::Credentials::new("key", "secret", None, None, "test"),
    };
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let authorization = Authorization::new("fixture".into(), signer.configuration.clone(), socket);
    for key in [
        "allowed/../literal",
        "allowed/./literal",
        "allowed//literal",
        "allowed/%2e%2e/literal",
    ] {
        let unsigned = Unsigned::new("GET", key);
        let signed = signer.sign(&unsigned).unwrap();
        let mut request = http::Request::builder().uri(&signed).body(()).unwrap();
        let path = percent_encoding::percent_decode_str(request.uri().path())
            .decode_utf8()
            .unwrap();
        assert_eq!(path, format!("/base/fixture/{key}"));
        // Strip the signing query as the transport receives SDK requests.
        *request.uri_mut() = request_url(&signer.configuration.endpoint, "fixture", &unsigned)
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            transport::describe(&mut request, &authorization).unwrap(),
            unsigned
        );
    }
    assert!(signer.sign(&Unsigned::new("GET", "literal")).is_err());
}

#[test]
fn signer_rejects_caller_supplied_host() {
    let signer = Signer {
        request: approval(),
        configuration: Configuration {
            endpoint: "https://storage.example".into(),
            region: "auto".into(),
            expires_at: now().unwrap() + DEFAULT_LIFETIME,
            requested_lifetime: DEFAULT_LIFETIME,
        },
        credentials: aws_sdk_s3::config::Credentials::new(
            "fixture-key",
            "fixture-secret",
            None,
            None,
            "test",
        ),
    };
    for name in ["host", "Host", "HOST", "hOsT"] {
        for host in ["other-bucket.storage.example", "storage.example"] {
            let error = signer
                .sign(&Unsigned::new("GET", "allowed/file").header(name, host))
                .unwrap_err();
            assert!(error.to_string().contains("Host"), "{error:#}");
        }
    }
    let signed = signer.sign(&Unsigned::new("GET", "allowed/file")).unwrap();
    assert_eq!(
        url::Url::parse(&signed).unwrap().host_str(),
        Some("storage.example")
    );
}

#[test]
fn uploads_can_update_their_own_metadata_but_cannot_copy_other_destination_keys() {
    let mut permission = approval();
    permission.create_only = false;
    let copy = Unsigned::new("PUT", "allowed/a").header("x-amz-copy-source", "fixture/allowed/a");
    permission.permits(&copy).unwrap();
    permission
        .permits(
            &copy
                .clone()
                .query("uploadId", "id")
                .query("partNumber", "1"),
        )
        .unwrap();
    permission
        .permits(&Unsigned::new("GET", "allowed/a").query("tagging", ""))
        .unwrap();
    for source in ["fixture/allowed/b", "fixture/outside", "another/allowed/a"] {
        assert!(permission
            .permits(&copy.clone().header("x-amz-copy-source", source))
            .is_err());
    }
    assert!(permission
        .permits(&Unsigned::new("GET", "outside").query("tagging", ""))
        .is_err());
    permission.create_only = true;
    assert!(permission
        .permits(&copy.header("if-none-match", "*"))
        .is_err());
    assert!(permission
        .permits(&Unsigned::new("GET", "allowed/a").query("tagging", ""))
        .is_err());
}

#[test]
fn tag_updates_require_overwritable_destination_scope() {
    let mut permission = approval();
    let write = Unsigned::new("PUT", "allowed/a").query("tagging", "");
    assert!(permission.permits(&write).is_err());
    permission.create_only = false;
    permission.permits(&write).unwrap();
    for version in ["known-version", "historical-version", "null", ""] {
        assert!(permission
            .permits(&write.clone().query("versionId", version))
            .is_err());
        permission
            .permits(
                &Unsigned::new("GET", "allowed/a")
                    .query("tagging", "")
                    .query("versionId", version),
            )
            .unwrap();
    }
    assert!(permission
        .permits(&Unsigned::new("PUT", "outside").query("tagging", ""))
        .is_err());
    assert!(permission
        .permits(&write.clone().bucket("other", "fixture"))
        .is_err());
    assert!(permission.permits(&write.clone().query("acl", "")).is_err());
    permission.source = Some(ReadAccess {
        bucket: "source".into(),
        scopes: vec![Scope {
            key: "input".into(),
            descendants: true,
        }],
    });
    assert!(permission
        .permits(
            &Unsigned::new("PUT", "input/a")
                .bucket("source", "fixture")
                .query("tagging", "")
        )
        .is_err());
    permission.upload = false;
    assert!(permission.permits(&write).is_err());
}

#[test]
fn signing_adds_only_syq_headers_and_those_the_command_shows() {
    let mut request = approval();
    request.create_only = false;
    let permits = |request: &Request, name: &str, value: &str| {
        request.permits(&Unsigned::new("PUT", "allowed/file").header(name, value))
    };
    for (name, value) in [
        ("x-amz-checksum-crc64nvme", "AAAAAAAAAAA="),
        ("x-amz-meta-syq-mtime", "1"),
        ("content-md5", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ("x-amz-storage-class", "STANDARD"),
    ] {
        permits(&request, name, value).unwrap();
    }
    for (name, value) in [
        ("x-amz-request-payer", "requester"),
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        ("x-goog-meta-probe", "1"),
        ("x-tigris-regions", "fra"),
    ] {
        assert!(permits(&request, name, value).is_err(), "{name}");
        request.headers.insert((name.into(), value.into()));
        permits(&request, name, value).unwrap();
        assert!(permits(&request, name, "changed").is_err(), "{name}");
    }
    request.validate().unwrap();
    request.headers.insert(("Bad Name".into(), "x".into()));
    assert!(request.validate().is_err());
}

#[test]
fn validation_rejects_bad_buckets_and_scope_counts_on_both_sides() {
    let error = |request: Request| request.validate().unwrap_err().to_string();
    let source = || ReadAccess {
        bucket: "source".into(),
        scopes: approval().scopes,
    };
    approval().validate().unwrap();
    let mut request = approval();
    request.source = Some(source());
    request.validate().unwrap();
    for bucket in ["", "a/b"] {
        let mut request = approval();
        request.bucket = bucket.into();
        assert_eq!(error(request), "invalid storage bucket");
        let mut request = approval();
        request.source = Some(ReadAccess {
            bucket: bucket.into(),
            ..source()
        });
        assert_eq!(error(request), "invalid storage source bucket");
    }
    for count in [0, 1025] {
        let scopes = vec![approval().scopes[0].clone(); count];
        let mut request = approval();
        request.scopes = scopes.clone();
        assert_eq!(
            error(request),
            "storage authorization requires 1 to 1024 source or destination scopes"
        );
        let mut request = approval();
        request.source = Some(ReadAccess { scopes, ..source() });
        assert_eq!(
            error(request),
            "storage authorization requires 1 to 1024 source scopes"
        );
    }
    let mut request = approval();
    request.scopes = vec![approval().scopes[0].clone(); 1024];
    request.source = Some(ReadAccess {
        scopes: request.scopes.clone(),
        ..source()
    });
    request.validate().unwrap();
}

/// A signing session against the authorizing machine's own signing loop.
/// `stop_after` makes that machine stop receiving after so many messages.
fn session(stop_after: Option<usize>) -> (Authorization, std::thread::JoinHandle<Result<()>>) {
    let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    for socket in [&client, &server] {
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
    }
    let signer = Signer::fixture(approval());
    let configuration = signer.configuration.clone();
    let served = std::thread::spawn(move || {
        let messages = std::sync::atomic::AtomicUsize::new(0);
        crate::destination::storage::serve_signing(&mut server, &signer, || {
            let seen = messages.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            stop_after.is_some_and(|limit| seen >= limit)
        })
    });
    (
        Authorization::new("fixture".into(), configuration, client),
        served,
    )
}
fn upload(index: usize) -> Unsigned {
    Unsigned::new("PUT", &format!("allowed/{index}")).header("if-none-match", "*")
}
fn prepared(authorization: &Authorization) -> usize {
    authorization.state.lock().unwrap().requests.len()
}

#[test]
fn exchanges_carry_at_most_the_request_limit() {
    let sizes = |count: usize| -> Vec<usize> {
        exchanges((0..count).map(upload), EXCHANGE_REQUESTS)
            .map(|exchange| exchange.len())
            .collect()
    };
    assert_eq!(sizes(0), Vec::<usize>::new());
    assert_eq!(sizes(1), [1]);
    assert_eq!(sizes(EXCHANGE_REQUESTS), [EXCHANGE_REQUESTS]);
    assert_eq!(sizes(EXCHANGE_REQUESTS + 1), [EXCHANGE_REQUESTS, 1]);
    assert_eq!(
        sizes(2 * EXCHANGE_REQUESTS),
        [EXCHANGE_REQUESTS, EXCHANGE_REQUESTS]
    );
}

#[test]
fn requests_over_one_exchange_are_all_signed_before_preparation_finishes() {
    let (authorization, served) = session(None);
    let count = EXCHANGE_REQUESTS + 1;
    for exchange in exchanges((0..count).map(upload), EXCHANGE_REQUESTS) {
        authorization.authorize(exchange).unwrap();
    }
    assert_eq!(prepared(&authorization), count);
    authorization.finish_preparation().unwrap();
    served.join().unwrap().unwrap();
    // The last request crossed into a second exchange and is still usable
    // after the authorizing machine has gone.
    for index in [0, EXCHANGE_REQUESTS - 1, EXCHANGE_REQUESTS] {
        let url = authorization.signed(upload(index)).unwrap();
        assert!(
            url.contains(&format!("/fixture/allowed/{index}?")) && url.contains("X-Amz-Signature="),
            "{index}"
        );
    }
}

#[test]
fn a_refusal_inside_a_batch_fails_preparation_and_issues_nothing_from_it() {
    let (authorization, served) = session(None);
    // An earlier exchange that succeeded stays prepared.
    authorization.authorize(vec![upload(0)]).unwrap();
    let mut requests: Vec<_> = (1..=1000).map(upload).collect();
    requests[500] = Unsigned::new("PUT", "sibling/file").header("if-none-match", "*");
    let error = authorization.authorize(requests).unwrap_err();
    assert!(
        format!("{error:#}").contains("storage request is outside the approved paths"),
        "{error:#}"
    );
    // The authorizing machine ended the session at the refusal.
    served.join().unwrap().unwrap();
    // Requests signed earlier in the refused exchange are not kept, so none
    // of its uploads can run, and the session signs nothing further.
    assert_eq!(prepared(&authorization), 1);
    for index in [1, 400, 600] {
        assert!(authorization.signed(upload(index)).is_err(), "{index}");
    }
    assert!(authorization.authorize(vec![upload(2000)]).is_err());
    // Preparation cannot finish, so the copy never reaches its data phase.
    assert!(authorization.finish_preparation().is_err());
}

#[test]
fn losing_the_authorizing_machine_inside_a_batch_fails_preparation() {
    // It signs two messages of a larger exchange and then stops receiving.
    let (authorization, served) = session(Some(2));
    let error = authorization
        .authorize((0..1000).map(upload).collect())
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("authorizing machine disconnected during preparation"),
        "{error:#}"
    );
    assert!(served.join().unwrap().is_err());
    assert_eq!(prepared(&authorization), 0);
    assert!(authorization.signed(upload(0)).is_err());
    assert!(authorization.finish_preparation().is_err());
}

/// A refusal ends the signing session; later requests it has not prepared
/// report that refusal, not a disconnection, and preparation cannot finish.
#[test]
fn later_requests_report_an_earlier_refusal() {
    let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    // Sign the first request, then refuse the next.
    let authorizer = std::thread::spawn(move || {
        crate::destination::read_message::<serde_json::Value>(&mut peer).unwrap();
        crate::destination::write_message(
            &mut peer,
            &serde_json::json!({ "Signed": ["https://storage.example/fixture/allowed/a?X-Amz-Signature=a"] }),
        )
        .unwrap();
        crate::destination::read_message::<serde_json::Value>(&mut peer).unwrap();
        crate::destination::write_message(
            &mut peer,
            &serde_json::json!({ "Error": "outside approved paths" }),
        )
        .unwrap();
    });
    let authorization = Authorization::new(
        "fixture".into(),
        Configuration {
            endpoint: "https://storage.example".into(),
            region: "auto".into(),
            expires_at: now().unwrap() + 60,
            requested_lifetime: 60,
        },
        socket,
    );
    authorization
        .signed(Unsigned::new("GET", "allowed/a"))
        .unwrap();
    let refused = authorization
        .signed(Unsigned::new("GET", "outside/b"))
        .unwrap_err();
    assert_eq!(
        format!("{refused:#}"),
        "authorizing machine: outside approved paths"
    );
    let earlier = "storage authorization ended after an earlier request failed (authorizing machine: outside approved paths); rerun the copy for fresh approval";
    let later = authorization
        .signed(Unsigned::new("GET", "allowed/c"))
        .unwrap_err();
    assert_eq!(format!("{later:#}"), earlier);
    // A request prepared before the refusal is still signed, so cleanup can
    // use it, but preparation does not finish: the copy stops there.
    authorization
        .signed(Unsigned::new("GET", "allowed/a"))
        .unwrap();
    let finish = authorization.finish_preparation().unwrap_err();
    assert_eq!(format!("{finish:#}"), earlier);
    authorizer.join().unwrap();
}

/// What the fake authorizing machine saw in each signing message: how many
/// requests it carried, and how many were in the exchange under way.
type Messages = Vec<(usize, usize)>;

/// A signing session with an authorizing machine that answers each request
/// with a URL naming its key. It holds its reply to the first message until
/// the test releases it, with `Some(error)` to refuse that message instead.
/// It refuses any later message with a key under `allowed/refused`.
#[allow(clippy::type_complexity)]
fn held_session() -> (
    Arc<Authorization>,
    std::thread::JoinHandle<Messages>,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<Option<String>>,
) {
    use crate::destination::{read_message, write_message};
    let (client, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    for socket in [&client, &peer] {
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
    }
    let authorization = Arc::new(Authorization::new(
        "fixture".into(),
        Signer::fixture(approval()).configuration,
        client,
    ));
    let (arrived, first) = std::sync::mpsc::channel();
    let (release, held) = std::sync::mpsc::channel::<Option<String>>();
    let shared = authorization.clone();
    let authorizer = std::thread::spawn(move || {
        let mut messages = Messages::new();
        loop {
            let Ok(message) = read_message::<serde_json::Value>(&mut peer) else {
                return messages;
            };
            let Some(batch) = message.get("Sign").and_then(|b| b.as_array()) else {
                assert_eq!(message, "Finish");
                write_message(&mut peer, &"Finished").unwrap();
                return messages;
            };
            let in_flight = shared.state.lock().unwrap().in_flight;
            messages.push((batch.len(), in_flight));
            if messages.len() == 1 {
                arrived.send(()).unwrap();
                if let Some(error) = held.recv_timeout(Duration::from_secs(30)).unwrap() {
                    write_message(&mut peer, &serde_json::json!({ "Error": error })).unwrap();
                    return messages;
                }
            }
            if batch.iter().any(|request| {
                request["key"]
                    .as_str()
                    .unwrap()
                    .starts_with("allowed/refused")
            }) {
                write_message(&mut peer, &serde_json::json!({ "Error": "refused" })).unwrap();
                return messages;
            }
            let urls: Vec<_> = batch
                .iter()
                .map(|request| {
                    format!(
                        "https://storage.example/fixture/{}?X-Amz-Signature=fake",
                        request["key"].as_str().unwrap()
                    )
                })
                .collect();
            write_message(&mut peer, &serde_json::json!({ "Signed": urls })).unwrap();
        }
    });
    (authorization, authorizer, first, release)
}
fn queued_reaches(authorization: &Authorization, count: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let queued: usize = (authorization.state.lock().unwrap().queued.iter())
            .map(|(_, batch)| batch.len())
            .sum();
        if queued == count {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{queued} of {count} requests queued"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn get(key: &str) -> Unsigned {
    Unsigned::new("GET", &format!("allowed/{key}"))
}
fn sign_in_thread(
    authorization: &Arc<Authorization>,
    request: Unsigned,
) -> std::thread::JoinHandle<Result<String>> {
    let authorization = authorization.clone();
    std::thread::spawn(move || authorization.signed(request))
}

#[test]
fn requests_arriving_during_an_exchange_share_the_next_one() {
    let (authorization, authorizer, first, release) = held_session();
    let leader = sign_in_thread(&authorization, get("0"));
    first.recv_timeout(Duration::from_secs(30)).unwrap();
    // While that exchange is under way, more callers each ask for one
    // request, the last for the request already in flight.
    let keys: Vec<String> = (1..63).map(|i| i.to_string()).chain(["0".into()]).collect();
    let callers: Vec<_> = keys
        .iter()
        .map(|key| sign_in_thread(&authorization, get(key)))
        .collect();
    queued_reaches(&authorization, 63);
    release.send(None).unwrap();
    for (key, caller) in std::iter::once("0")
        .zip([leader])
        .chain(keys.iter().map(String::as_str).zip(callers))
    {
        let url = caller.join().unwrap().unwrap();
        assert!(
            url.contains(&format!("/fixture/allowed/{key}?")),
            "{key}: {url}"
        );
    }
    authorization.finish_preparation().unwrap();
    // Two round trips instead of 63, and the shared request was signed once.
    assert_eq!(authorizer.join().unwrap(), [(1, 1), (62, 62)]);
}

#[test]
fn combined_exchanges_keep_the_request_limit_without_splitting_a_batch() {
    let (authorization, authorizer, first, release) = held_session();
    let leader = sign_in_thread(&authorization, get("0"));
    first.recv_timeout(Duration::from_secs(30)).unwrap();
    let batch = |prefix: &str, count: usize| -> Vec<Unsigned> {
        (0..count).map(|i| get(&format!("{prefix}/{i}"))).collect()
    };
    let callers: Vec<_> = ["a", "b", "c"]
        .into_iter()
        .map(|prefix| {
            let authorization = authorization.clone();
            let requests = batch(prefix, 6_000);
            std::thread::spawn(move || authorization.authorize(requests))
        })
        .collect();
    queued_reaches(&authorization, 18_000);
    release.send(None).unwrap();
    leader.join().unwrap().unwrap();
    for caller in callers {
        caller.join().unwrap().unwrap();
    }
    // One caller's batch above the limit still goes in one exchange.
    authorization
        .authorize(batch("d", EXCHANGE_REQUESTS + 4_000))
        .unwrap();
    assert_eq!(prepared(&authorization), 18_001 + EXCHANGE_REQUESTS + 4_000);
    authorization.finish_preparation().unwrap();
    let messages = authorizer.join().unwrap();
    assert!(messages.iter().all(|&(count, _)| count <= 128));
    assert_eq!(
        messages.iter().map(|m| m.0).sum::<usize>(),
        prepared(&authorization)
    );
    // Two 6,000-request batches fit together within the limit; a third does
    // not, so it waits for the next exchange.
    let exchanges: Vec<_> = messages
        .iter()
        .map(|m| m.1)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(exchanges, [1, 6_000, 12_000, EXCHANGE_REQUESTS + 4_000]);
}

/// A caller whose request an earlier exchange signed while it waited keeps
/// that signature, even if the exchange its batch was queued for fails.
#[test]
fn a_request_signed_while_queued_survives_a_later_refusal() {
    for refused_first in [true, false] {
        let (authorization, authorizer, first, release) = held_session();
        let leader = sign_in_thread(&authorization, get("0"));
        first.recv_timeout(Duration::from_secs(30)).unwrap();
        let queue = |key: &str, queued: usize| {
            let caller = sign_in_thread(&authorization, get(key));
            queued_reaches(&authorization, queued);
            caller
        };
        let (duplicate, refused) = if refused_first {
            let refused = queue("refused", 1);
            (queue("0", 2), refused)
        } else {
            let duplicate = queue("0", 1);
            (duplicate, queue("refused", 2))
        };
        release.send(None).unwrap();
        leader.join().unwrap().unwrap();
        let url = duplicate.join().unwrap().unwrap();
        assert!(url.contains("/fixture/allowed/0?"), "{url}");
        let error = refused.join().unwrap().unwrap_err();
        assert!(format!("{error:#}").contains("refused"), "{error:#}");
        assert_eq!(authorizer.join().unwrap(), [(1, 1), (1, 1)]);
        assert!(authorization.finish_preparation().is_err());
    }
}

#[test]
fn a_failed_exchange_fails_every_waiting_request() {
    let (authorization, authorizer, first, release) = held_session();
    let leader = sign_in_thread(&authorization, get("0"));
    first.recv_timeout(Duration::from_secs(30)).unwrap();
    let callers: Vec<_> = (1..=20)
        .map(|i| sign_in_thread(&authorization, get(&i.to_string())))
        .collect();
    queued_reaches(&authorization, 20);
    release.send(Some("outside approved paths".into())).unwrap();
    let error = leader.join().unwrap().unwrap_err();
    assert_eq!(
        format!("{error:#}"),
        "authorizing machine: outside approved paths"
    );
    for caller in callers {
        let error = caller.join().unwrap().unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            "storage authorization ended after an earlier request failed (authorizing machine: outside approved paths); rerun the copy for fresh approval"
        );
    }
    // The waiting requests never reached the authorizing machine.
    assert_eq!(authorizer.join().unwrap(), [(1, 1)]);
    assert_eq!(prepared(&authorization), 0);
    assert!(authorization.finish_preparation().is_err());
}
