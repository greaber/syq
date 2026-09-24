use super::*;
fn source() -> File {
    File {
        exists: true,
        kind: Some(Kind::File),
        size: Some(2 * 1024 * 1024),
        mtime: Some((100, 123)),
        mode: Some(0o640),
        ..File::default()
    }
}
fn evaluate(text: &str) -> Result<bool> {
    Expression::compile(text, true)?.evaluate(
        &source(),
        b"images/a.JPG",
        &File::default(),
        b"renamed/a.jpg",
        200_000_000_000,
    )
}
#[test]
fn quantities_boolean_precedence_and_arithmetic() {
    for s in [
        "src.size between 1MiB and 3MiB",
        "src.size / 1MiB = 2",
        "src.size + 512KiB = 2.5MiB",
        "src.mtime < now - 30s",
        "src.mode = 0o640",
        "src.mode & 0o077 = 0o040",
        "false or true and true",
        "not src.size < 1B",
        "src.mtime = timestamp('1970-01-01T00:01:40.000000123Z')",
        "if(dst.exists, dst.size, src.size) = 2MiB",
    ] {
        assert!(evaluate(s).unwrap(), "{s}");
    }
}
#[test]
fn missing_values_and_short_circuit() {
    for s in [
        "not dst.exists or src.size > dst.size",
        "dst.size is null",
        "coalesce(dst.size, 0B) = 0B",
        "dst.path = 'renamed/a.jpg'",
        "false and 1 / 0 = 0 or true",
    ] {
        assert!(evaluate(s).unwrap(), "{s}");
    }
    assert!(evaluate("src.size > dst.size").is_err());
    assert!(!evaluate("dst.exists and src.size > dst.size").unwrap());
}
#[test]
fn patterns_membership_and_raw_paths() {
    for s in [
        "src.path glob 'images/*.JPG'",
        "src.name matches '(?i)jpg$'",
        "src.extension in ['jpg', 'JPG']",
        "src.extension not in ('png', 'gif')",
        "src.name not glob '*.png'",
    ] {
        assert!(evaluate(s).unwrap(), "{s}");
    }
    assert!(!evaluate("src.path glob '*.JPG'").unwrap());
    assert!(Expression::compile("src.name = '\\xff.jpg'", false)
        .unwrap()
        .evaluate(&source(), b"\xff.jpg", &File::default(), b"", 0)
        .unwrap());
}
#[test]
fn invalid_expressions_fail_before_evaluation() {
    for s in [
        "src.size > 3s",
        "src.size > '10MiB'",
        "src.no_such_field = 0",
        "src.size",
        "true and",
        "'unterminated",
        "src.name matches '['",
        "src.name glob '['",
        "1MiB + now > now",
        "src.mode > 0.5",
        "true garbage",
        "dst.exists or 1 + 'x' = 2",
    ] {
        assert!(Expression::compile(s, true).is_err(), "{s}");
    }
    assert!(Expression::compile("dst.exists", false).is_err());
}
#[test]
fn overflow_limits_and_zero_division() {
    assert!(evaluate("1 / 0 = 0").is_err());
    assert!(evaluate("170141183460469231731687303715884105727 + 1 = 0").is_err());
    assert!(
        Expression::compile(&format!("{}true{}", "(".repeat(65), ")".repeat(65)), true).is_err()
    );
    assert!(Expression::compile(&"true or ".repeat(300), true).is_err());
}

#[test]
fn partial_facts_keep_unread_metadata_distinct_from_null() {
    let listed = Facts::S3Listing {
        size: 12,
        last_modified: Some((123, 0)),
    };
    for (expression, expected) in [
        ("src.size > 1B and src.name = 'keep.jpg'", Some(true)),
        ("src.name = 'skip' and src.mtime > now - 1d", Some(false)),
        ("src.name = 'keep.jpg' and src.mtime > now - 1d", None),
        ("src.mtime is null", None),
        ("coalesce(src.mtime, now) = now", None),
        ("src.kind = 'file'", None),
        ("src.uid is null", None),
        ("src.ctime is null and src.link_target is null", Some(true)),
        ("if(src.size > 1B, true, src.uid = 0)", Some(true)),
    ] {
        let policy = Policy::compile(Some(expression), None).unwrap();
        assert_eq!(
            policy.selects_known(listed, b"nested/keep.jpg").unwrap(),
            expected,
            "{expression}"
        );
    }
    // A real error in an evaluated branch must not become "need metadata".
    let error = Policy::compile(Some("1 / 0 = 0 or src.uid = 0"), None)
        .unwrap()
        .selects_known(listed, b"keep.jpg")
        .unwrap_err();
    assert!(format!("{error:#}").contains("division by zero"));
    let policy = Policy::compile(None, Some("dst.path = 'missing' and dst.exists")).unwrap();
    assert_eq!(
        policy
            .permits_known(listed, b"keep.jpg", Facts::Unread, b"actual")
            .unwrap(),
        Some(false)
    );
    assert_eq!(
        policy
            .permits_known(listed, b"keep.jpg", Facts::Unread, b"missing")
            .unwrap(),
        None
    );
}

#[test]
fn directory_selection_uses_the_same_predicate_as_files() {
    let directory = File {
        exists: true,
        kind: Some(Kind::Dir),
        ..File::default()
    };
    assert!(!Policy::compile(Some("src.kind = 'file'"), None)
        .unwrap()
        .selects(&directory, b"dir")
        .unwrap());
    assert!(Policy::compile(Some("1 / 0 = 0"), None)
        .unwrap()
        .selects(&directory, b"dir")
        .is_err());
    assert_eq!(
        Policy::compile(Some("src.name = 'keep'"), None)
            .unwrap()
            .selects_known(
                Facts::S3Listing {
                    size: 0,
                    last_modified: None
                },
                b"dir"
            )
            .unwrap(),
        Some(false)
    );
}

#[test]
fn service_time_is_distinct_and_available_from_listing() {
    let facts = Facts::S3Listing {
        size: 4,
        last_modified: Some((123, 123_456_789)),
    };
    let policy = Policy::compile(
        Some("src.s3_last_modified = timestamp('1970-01-01T00:02:03.123456789Z')"),
        None,
    )
    .unwrap();
    assert!(policy.uses_source_s3_time());
    assert_eq!(policy.selects_known(facts, b"file").unwrap(), Some(true));
    let file = File {
        exists: true,
        s3_last_modified: Some((123, 0)),
        ..File::default()
    };
    assert!(Policy::compile(
        Some("src.mtime is null and src.s3_last_modified is not null"),
        None
    )
    .unwrap()
    .selects(&file, b"file")
    .unwrap());
}
