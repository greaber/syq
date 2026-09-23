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
