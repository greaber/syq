use anyhow::{ensure, Result};

#[derive(Clone, Debug)]
pub(super) enum Token {
    Literal(char),
    Star,
    Recursive,
    Any,
}

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
pub(super) struct Component(Vec<Token>);
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

#[derive(Debug)]
pub(super) struct Pattern {
    pub bucket: String,
    pub components: Vec<Component>,
    matcher: regex::Regex,
}
impl Pattern {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input
            .strip_prefix("s3://")
            .ok_or_else(|| anyhow::anyhow!("expected s3://BUCKET/PATTERN"))?;
        let (bucket, path) = input.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("include a key or pattern, for example s3://BUCKET/**")
        })?;
        ensure!(
            !bucket.is_empty() && !bucket.contains(['*', '?']),
            "expected a literal S3 bucket name"
        );
        ensure!(
            !path.is_empty(),
            "include a key or pattern, for example s3://BUCKET/**"
        );
        Ok(Self {
            bucket: bucket.into(),
            components: path.split('/').map(|s| Component(tokens(s))).collect(),
            matcher: {
                let mut expression = String::from(r"(?s)\A");
                for token in tokens(path) {
                    match token {
                        Token::Literal(c) => expression.push_str(&regex::escape(&c.to_string())),
                        Token::Star => expression.push_str("[^/]*"),
                        Token::Recursive => expression.push_str(".*"),
                        Token::Any => expression.push_str("[^/]"),
                    }
                }
                expression.push_str(r"\z");
                regex::Regex::new(&expression)?
            },
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
}
