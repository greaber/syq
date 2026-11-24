use super::*;
fn source() -> File<'static> {
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
        directory_marker: false,
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
fn directory_selection_bypasses_where_but_not_copy_if() {
    let directory = File {
        exists: true,
        kind: Some(Kind::Dir),
        ..File::default()
    };
    let policy = Policy::compile(Some("1 / 0 = 0"), Some("false")).unwrap();
    assert!(policy.selects(&directory, b"dir").unwrap());
    assert!(!policy
        .permits(&directory, b"dir", &File::default(), b"dir")
        .unwrap());
    // A listed marker is a directory without reading its metadata, because
    // syq rejects file or symlink metadata under marker-shaped keys. The
    // failing expression shows --where is not evaluated for it.
    assert_eq!(
        policy
            .selects_known(
                Facts::S3Listing {
                    size: 0,
                    directory_marker: true,
                    last_modified: None
                },
                b"dir"
            )
            .unwrap(),
        Some(true)
    );
}

#[test]
fn service_time_is_distinct_and_available_from_listing() {
    let facts = Facts::S3Listing {
        size: 4,
        directory_marker: false,
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

#[test]
fn raw_link_targets_compare_as_borrowed_bytes() {
    let file = File {
        link_target: Some((&b"../raw-\xff"[..]).into()),
        ..source()
    };
    let expr = Expression::compile(r"src.link_target in ['other', '../raw-\xff']", false).unwrap();
    assert!(expr
        .evaluate(&file, b"link", &File::default(), b"", 0)
        .unwrap());
    let Value::String(bytes) = file.field(b"link", Field::LinkTarget) else {
        panic!("missing target")
    };
    assert_eq!(bytes.as_ptr(), file.link_target.as_ref().unwrap().as_ptr());
}
#[test]
fn listing_names_fields_bare_and_filters_directories() {
    let policy = Policy::compile_listing(Some("kind = 'dir' and src.name = 'logs'")).unwrap();
    let directory = File {
        exists: true,
        kind: Some(Kind::Dir),
        ..File::default()
    };
    assert!(policy.selects_listing(&directory, b"logs").unwrap());
    assert!(!policy.selects_listing(&directory, b"other").unwrap());
    // Copies keep directories regardless of --where.
    assert!(policy.selects(&directory, b"other").unwrap());
    let policy = Policy::compile_listing(Some("size > 1MiB")).unwrap();
    assert!(policy.selects_listing(&source(), b"a").unwrap());
    assert!(!policy
        .selects_listing(&directory, b"a")
        .is_ok_and(|selected| selected));
    for text in ["dst.size > 0B", "dst.exists", "unknown = 1"] {
        assert!(Policy::compile_listing(Some(text)).is_err(), "{text}");
    }
    // Copy selection still needs the prefix.
    assert!(Policy::compile(Some("size > 1MiB"), None).is_err());
}

#[test]
fn s3_directories_are_known_from_the_listing() {
    let policy = Policy::compile_listing(Some(
        "kind = 'dir' and size is null and mtime is null and s3_last_modified is null and exists",
    ))
    .unwrap();
    assert_eq!(
        policy
            .selects_listing_known(Facts::S3Directory, b"logs/day00")
            .unwrap(),
        Some(true)
    );
    let policy = Policy::compile_listing(Some("kind = 'file'")).unwrap();
    assert_eq!(
        policy
            .selects_listing_known(Facts::S3Directory, b"logs")
            .unwrap(),
        Some(false)
    );
    // An object's kind needs its metadata, but not whether it is a
    // directory: only a directory marker is.
    let object = Facts::S3Listing {
        size: 3,
        directory_marker: false,
        last_modified: None,
    };
    assert_eq!(policy.selects_listing_known(object, b"a").unwrap(), None);
    for (text, expected) in [
        ("kind = 'dir'", Some(false)),
        ("'dir' = kind", Some(false)),
        ("kind != 'dir'", Some(true)),
        ("kind != 'dir' and size = 3B", Some(true)),
        ("not kind = 'dir' and kind = 'file'", None),
        ("kind = 'symlink'", None),
    ] {
        let policy = Policy::compile_listing(Some(text)).unwrap();
        assert_eq!(
            policy.selects_listing_known(object, b"a").unwrap(),
            expected,
            "{text}"
        );
    }
    let marker = Facts::S3Listing {
        size: 0,
        directory_marker: true,
        last_modified: None,
    };
    let policy = Policy::compile_listing(Some("kind != 'dir'")).unwrap();
    assert_eq!(policy.selects_listing_known(marker, b"a").unwrap(), None);
    let policy = Policy::compile_listing(Some("size = 3B and path glob '*'")).unwrap();
    assert_eq!(
        policy.selects_listing_known(object, b"a").unwrap(),
        Some(true)
    );
}

#[test]
fn path_conditions_joined_by_and_are_pushed_down() {
    use PathToken::{Literal as L, Recursive as R, Star as S};
    let lit = |text: &str| text.chars().map(L).collect::<Vec<_>>();
    let pushed = |text: &str| {
        Expression::compile_listing(text)
            .unwrap()
            .s3_path_pushdown()
    };
    assert_eq!(
        pushed("path glob 'logs/*.json'"),
        [[lit("logs/"), vec![S], lit(".json")].concat()]
    );
    assert_eq!(
        pushed("extension = 'b' and (src.path = 'a/b' and path glob 'a/**')"),
        [lit("a/b"), [lit("a/"), vec![R]].concat()]
    );
    assert_eq!(pushed("'x' = path"), [lit("x")]);
    // A condition that may fail stops the narrowing: an entry a later path
    // condition rules out must still reach it, and report its error.
    assert_eq!(
        pushed("path glob 'logs/2026-*/*' and size > 1MiB"),
        [[lit("logs/2026-"), vec![S], lit("/"), vec![S]].concat()]
    );
    assert_eq!(
        pushed("extension = 'json' and path glob 'logs/2026-*/*'"),
        [[lit("logs/2026-"), vec![S], lit("/"), vec![S]].concat()]
    );
    assert_eq!(
        pushed("path = 'a' and size > 0B and path = 'b'"),
        [lit("a")]
    );
    for text in [
        "size is null and s3_last_modified is not null and name in ['a', null]",
        "exists and not (name glob 'x*' or extension < 'm') and name between 'a' and 'z'",
        "coalesce(size, 0B) = 0B and if(exists, s3_last_modified, now) is null and now > timestamp('2020-01-01T00:00:00Z')",
        "if(exists, name, extension) glob '*' and coalesce(link_target, name) glob '*'",
        "true",
    ] {
        assert_eq!(
            pushed(&format!("{text} and path = 'p'")),
            [lit("p")],
            "{text}"
        );
    }
    for text in [
        "size > 0B",
        "kind = 'file'",
        "kind is not null",
        "kind glob 'f*'",
        "mtime is null",
        "mtime < now",
        "mode is null",
        "uid is null",
        "gid is null",
        "size + 1B = 2B",
        "size / 0 = 0B",
        "-size = 0B",
        "size between 0B and 1B",
        "not if(exists, true, null)",
        "coalesce(size, null) > 0B",
        "if(size > 0B, true, false)",
        "link_target glob '*'",
    ] {
        assert!(
            pushed(&format!("{text} and path = 'p'")).is_empty(),
            "{text}"
        );
    }
    // Conditions that are not necessary for a match narrow nothing.
    for text in [
        "path glob 'a/*' or size > 0B",
        "not path glob 'a/*'",
        "path not glob 'a/*'",
        "if(true, path glob 'a/*', true)",
        "path matches '^a/'",
        "name glob 'a*'",
        "path = '\\xff'",
        "path != 'a'",
    ] {
        assert!(pushed(text).is_empty(), "{text}");
    }
}
