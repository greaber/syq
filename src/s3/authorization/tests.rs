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
        upload: true,
        delete: false,
        create_only: true,
        lifetime: DEFAULT_LIFETIME,
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
        Unsigned::new("GET", "allowed/../outside"),
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
