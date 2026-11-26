use anyhow::Result;

#[derive(Clone, Debug)]
pub(in crate::s3) enum Token {
    Literal(char),
    Star,
    Recursive,
    /// One character other than `/`; only the tests' text patterns have it.
    #[cfg_attr(not(test), allow(dead_code))]
    Any,
}

/// The tokens of a pattern written as text: `?`, `*` and `**`, everything
/// else literal.
#[cfg(test)]
fn tokens(text: &str) -> Vec<Token> {
    let mut chars = text.chars().peekable();
    let mut out = Vec::new();
    while let Some(c) = chars.next() {
        out.push(match c {
            '*' if chars.peek() == Some(&'*') => {
                chars.next();
                Token::Recursive
            }
            '*' => Token::Star,
            '?' => Token::Any,
            c => Token::Literal(c),
        });
    }
    out
}

fn matcher(tokens: &[Token]) -> Result<regex::Regex> {
    let mut expression = String::from(r"(?s)\A");
    for token in tokens {
        match token {
            Token::Literal(c) => expression.push_str(&regex::escape(&c.to_string())),
            Token::Star => expression.push_str("[^/]*"),
            Token::Recursive => expression.push_str(".*"),
            Token::Any => expression.push_str("[^/]"),
        }
    }
    expression.push_str(r"\z");
    Ok(regex::Regex::new(&expression)?)
}

fn matches(tokens: &[Token], text: &str) -> bool {
    let chars: Vec<_> = text.chars().collect();
    let mut matched = vec![false; chars.len() + 1];
    matched[0] = true;
    for token in tokens {
        match token {
            Token::Star | Token::Recursive => {
                for i in 1..matched.len() {
                    matched[i] |= matched[i - 1]
                        && (matches!(token, Token::Recursive) || chars[i - 1] != '/');
                }
            }
            Token::Literal(_) | Token::Any => {
                for i in (1..matched.len()).rev() {
                    matched[i] = matched[i - 1]
                        && match token {
                            Token::Literal(c) => *c == chars[i - 1],
                            _ => chars[i - 1] != '/',
                        };
                }
                matched[0] = false;
            }
        }
    }
    matched[chars.len()]
}

#[derive(Clone, Debug)]
pub(in crate::s3) struct Component(Vec<Token>);
impl Component {
    pub fn literal_prefix(&self) -> String {
        self.0
            .iter()
            .take_while(|t| matches!(t, Token::Literal(_)))
            .map(|t| match t {
                Token::Literal(c) => *c,
                _ => unreachable!(),
            })
            .collect()
    }
    pub fn literal(&self) -> bool {
        self.0.iter().all(|t| matches!(t, Token::Literal(_)))
    }
    pub fn recursive(&self) -> bool {
        self.0.iter().any(|t| matches!(t, Token::Recursive))
    }
    pub fn matches(&self, text: &str) -> bool {
        matches(&self.0, text)
    }
}

/// A pattern of whole S3 keys, split into the components between slashes so
/// that a listing can be directed by them.
#[derive(Debug)]
pub(in crate::s3) struct Pattern {
    pub components: Vec<Component>,
    matcher: regex::Regex,
}
impl Pattern {
    /// A key pattern from a path pattern that `find` narrows its listing
    /// with: `key_prefix` literally, then `tokens`.
    pub fn from_tokens(key_prefix: &str, tokens: &[crate::expression::PathToken]) -> Result<Self> {
        use crate::expression::PathToken;
        let tokens: Vec<Token> = key_prefix
            .chars()
            .map(Token::Literal)
            .chain(tokens.iter().map(|token| match token {
                PathToken::Literal(c) => Token::Literal(*c),
                PathToken::Star => Token::Star,
                PathToken::Recursive => Token::Recursive,
            }))
            .collect();
        Ok(Self {
            components: tokens
                .split(|token| matches!(token, Token::Literal('/')))
                .map(|part| Component(part.to_vec()))
                .collect(),
            matcher: matcher(&tokens)?,
        })
    }
    /// Whether a key under the directory `prefix`, which ends with `/`, may
    /// match. Only whole components of `prefix` are compared, so this can
    /// say yes for a directory that holds no match, never no for one that
    /// does.
    pub fn may_match_under(&self, prefix: &str) -> bool {
        let Some(directory) = prefix.strip_suffix('/') else {
            return true;
        };
        if directory.is_empty() && !prefix.is_empty() {
            // An empty component: compare nothing.
            return true;
        }
        for (part, name) in self.components.iter().zip(directory.split('/')) {
            if part.recursive() {
                // Everything before the first recursive token is literal or
                // a single component, so only its literal start can be
                // compared without knowing where the component ends.
                return name.starts_with(&part.literal_prefix());
            }
            if !part.matches(name) {
                return false;
            }
        }
        directory.split('/').count() < self.components.len()
    }
    #[cfg(test)]
    pub fn parse(input: &str) -> Result<Self> {
        let input = input
            .strip_prefix("s3://")
            .ok_or_else(|| anyhow::anyhow!("expected s3://BUCKET/PATTERN"))?;
        let (bucket, path) = input.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("include a key or pattern, for example s3://BUCKET/**")
        })?;
        anyhow::ensure!(
            !bucket.is_empty() && !bucket.contains(['*', '?']),
            "expected a literal S3 bucket name"
        );
        anyhow::ensure!(
            !path.is_empty(),
            "include a key or pattern, for example s3://BUCKET/**"
        );
        Ok(Self {
            components: path.split('/').map(|s| Component(tokens(s))).collect(),
            matcher: matcher(&tokens(path))?,
        })
    }
    pub fn matches(&self, key: &str) -> bool {
        self.matcher.is_match(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn string_matching_semantics() {
        let examples = [
            ("logs", vec!["logs"], vec!["logs/", "logs/a", "logs-old"]),
            ("logs/", vec!["logs/"], vec!["logs", "logs/a"]),
            ("logs/*", vec!["logs/", "logs/a"], vec!["logs", "logs/a/b"]),
            (
                "logs/?",
                vec!["logs/a", "logs/é"],
                vec!["logs/", "logs/xy", "logs//"],
            ),
            (
                "logs/**",
                vec!["logs/", "logs/a", "logs/a/b"],
                vec!["logs", "logs-old/a"],
            ),
            (
                "logs/**/file",
                vec!["logs//file", "logs/a/file", "logs/a/b/file"],
                vec!["logs/file"],
            ),
            (
                "logs**",
                vec!["logs", "logs/a", "logs-old/a", "logstash"],
                vec!["log"],
            ),
            ("a**b", vec!["ab", "a/x/b"], vec!["a/x/c"]),
            (r"a[bc]{d}\", vec![r"a[bc]{d}\"], vec!["abd"]),
            ("a%2Fb", vec!["a%2Fb"], vec!["a/b"]),
        ];
        for (pattern, yes, no) in examples {
            let p = Pattern::parse(&format!("s3://bucket/{pattern}")).unwrap();
            for key in yes {
                assert!(p.matches(key), "{pattern}: {key}");
            }
            for key in no {
                assert!(!p.matches(key), "{pattern}: {key}");
            }
        }
        for input in ["bucket/x", "s3:///x", "s3://bucket", "s3://bucket/"] {
            assert!(Pattern::parse(input).is_err());
        }
    }

    #[test]
    fn token_patterns_and_the_directories_that_may_hold_matches() {
        use crate::expression::PathToken::{self, Literal as L, Recursive as R, Star as S};
        let lit = |text: &str| text.chars().map(L).collect::<Vec<PathToken>>();
        let tokens = [
            lit("logs/2026-"),
            vec![S],
            lit("/*"),
            vec![S],
            lit(".json"),
            vec![R],
        ]
        .concat();
        let pattern = Pattern::from_tokens("base/", &tokens).unwrap();
        for key in [
            "base/logs/2026-01/*a.json",
            "base/logs/2026-/*.json/",
            "base/logs/2026-1/*.json/x",
        ] {
            assert!(pattern.matches(key), "{key}");
        }
        for key in [
            "base/logs/2026-01/a.json",
            "base/logs/2025-01/*a.json",
            "logs/2026-01/*a.json",
        ] {
            assert!(!pattern.matches(key), "{key}");
        }
        for prefix in [
            "",
            "base/",
            "base/logs/",
            "base/logs/2026-01/",
            "base/logs/2026-01/*x/",
        ] {
            assert!(pattern.may_match_under(prefix), "{prefix}");
        }
        for prefix in [
            "other/",
            "base/other/",
            "base/logs/2025-01/",
            "base/logs/2026-01/x/",
        ] {
            assert!(!pattern.may_match_under(prefix), "{prefix}");
        }
        // A recursive component compares only its literal start.
        let pattern = Pattern::from_tokens("", &[lit("day0"), vec![R]].concat()).unwrap();
        assert!(pattern.may_match_under("day05/"));
        assert!(pattern.may_match_under("day0/x/"));
        assert!(!pattern.may_match_under("day1/"));
    }
}
