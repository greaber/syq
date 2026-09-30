//! Numeric release-version predicates: comma is AND, single `|` is OR.

use anyhow::{ensure, Context, Result};

pub(crate) fn check(expression: &str) -> Result<()> {
    let version = numeric_version(env!("CARGO_PKG_VERSION"))
        .context("--version-is only supports x.y.z release versions")?;
    let matches = matches(expression, version).map_err(|error| {
        clap::Error::raw(
            clap::error::ErrorKind::InvalidValue,
            format!("invalid --version-is expression {expression:?}: {error:#}\n"),
        )
    })?;
    ensure!(
        crate::identity::is_release_build(),
        "--version-is only supports release builds; invoked development build {}",
        crate::identity::build()
    );
    ensure!(
        matches,
        "invoked syq {} does not satisfy --version-is {expression:?}",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

fn numeric_version(raw: &str) -> Result<[u64; 3]> {
    let mut parts = raw.split('.');
    let mut version = [0; 3];
    for component in &mut version {
        let part = parts.next().unwrap_or_default();
        ensure!(
            !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()),
            "expected a numeric x.y.z version, got {raw:?}"
        );
        *component = part
            .parse()
            .with_context(|| format!("version component {part:?} exceeds {}", u64::MAX))?;
    }
    ensure!(
        parts.next().is_none(),
        "expected a numeric x.y.z version, got {raw:?}"
    );
    Ok(version)
}

enum Operator {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

fn matches(expression: &str, version: [u64; 3]) -> Result<bool> {
    let mut any = false;
    for group in expression.split('|') {
        let mut all = true;
        for comparison in group.split(',') {
            let comparison = comparison.trim();
            ensure!(!comparison.is_empty(), "expected a comparison");
            let (operator, raw) = [
                ("==", Operator::Equal),
                ("!=", Operator::NotEqual),
                ("<=", Operator::LessEqual),
                (">=", Operator::GreaterEqual),
                ("<", Operator::Less),
                (">", Operator::Greater),
            ]
            .into_iter()
            .find_map(|(prefix, operator)| {
                comparison.strip_prefix(prefix).map(|raw| (operator, raw))
            })
            .unwrap_or((Operator::Equal, comparison));
            let other = numeric_version(raw.trim())?;
            // Validate every comparison, even in an already decided group.
            all &= match operator {
                Operator::Equal => version == other,
                Operator::NotEqual => version != other,
                Operator::Less => version < other,
                Operator::LessEqual => version <= other,
                Operator::Greater => version > other,
                Operator::GreaterEqual => version >= other,
            };
        }
        any |= all;
    }
    Ok(any)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_comparisons_and_boundaries() {
        for (expression, version, expected) in [
            ("1.2.3", [1, 2, 3], true),
            ("1.2.3", [1, 2, 4], false),
            ("== 1.2.3", [1, 2, 3], true),
            ("==1.2.3", [1, 2, 4], false),
            ("!=1.2.3", [1, 2, 3], false),
            ("!=1.2.3", [1, 2, 4], true),
            ("<1.2.3", [1, 2, 2], true),
            ("<1.2.3", [1, 2, 3], false),
            ("<=1.2.3", [1, 2, 3], true),
            ("<=1.2.3", [1, 2, 4], false),
            (">1.2.3", [1, 2, 3], false),
            (">1.2.3", [1, 2, 4], true),
            (">=1.2.3", [1, 2, 3], true),
            (">=1.2.3", [1, 2, 2], false),
            (">1.9.9", [1, 10, 0], true),
            (">1.99.99", [2, 0, 0], true),
            ("<1.2.3", [0, u64::MAX, u64::MAX], true),
            (">=0.0.0", [0, 0, 0], true),
            ("<0.0.0", [0, 0, 0], false),
            ("18446744073709551615.0.0", [u64::MAX, 0, 0], true),
            ("01.002.0003", [1, 2, 3], true),
        ] {
            assert_eq!(
                matches(expression, version).unwrap(),
                expected,
                "{expression}"
            );
        }
    }

    #[test]
    fn disjunctions_conjunctions_and_exclusions() {
        let expression = " >= 1.2.3 , < 2.0.0 , != 1.2.5 | >= 3.1.0, <4.0.0 ";
        for (version, expected) in [
            ([1, 2, 2], false),
            ([1, 2, 3], true),
            ([1, 2, 5], false),
            ([1, 2, 6], true),
            ([2, 0, 0], false),
            ([3, 0, 9], false),
            ([3, 1, 0], true),
            ([4, 0, 0], false),
        ] {
            assert_eq!(
                matches(expression, version).unwrap(),
                expected,
                "{version:?}"
            );
        }
        assert!(matches("1.2.3 | >9.0.0, <10.0.0", [1, 2, 3]).unwrap());
        assert!(matches("1.2.3 | 2.0.0", [2, 0, 0]).unwrap());
        assert!(!matches(">2.0.0, <1.0.0", [1, 2, 3]).unwrap());
    }

    #[test]
    fn invalid_syntax_is_never_hidden_by_a_matching_or_failing_clause() {
        for expression in [
            "",
            " ",
            "|",
            ",",
            "1.2.3|",
            "|1.2.3",
            "1.2.3,",
            ",1.2.3",
            "1.2.3 || 2.0.0",
            "1.2.3,,2.0.0",
            "1.2.3/2.0.0",
            "1.2.3 & 2.0.0",
            "1.2.3 && 2.0.0",
            "(1.2.3)",
            "!1.2.3",
            "=1.2.3",
            "===1.2.3",
            "~1.2.3",
            "^1.2.3",
            "~=1.2.3",
            "1",
            "1.2",
            "1.2.*",
            "*",
            "1.2.3.4",
            "v1.2.3",
            "1.2.3-beta",
            "1.2.3+dev.abc",
            "-1.2.3",
            "+1.2.3",
            "1.-2.3",
            "1.2.NaN",
            "1.2.inf",
            "1.2.３",
            "1.2. 3",
            "1.2.3 <2.0.0",
            "<",
            "18446744073709551616.0.0",
            "0.18446744073709551616.0",
            "0.0.18446744073709551616",
            "1.2.3 | nonsense",
            "1.2.3, nonsense",
            ">9.0.0, nonsense",
        ] {
            assert!(matches(expression, [1, 2, 3]).is_err(), "{expression:?}");
        }
    }
}
