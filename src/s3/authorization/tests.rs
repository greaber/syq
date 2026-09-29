use super::*;
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
                &crate::s3::checksum::Algorithm::Sha256.digest(b"abc"),
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
