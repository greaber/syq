//! Path patterns that an S3 listing can request instead of listing every key.
//!
//! A `path glob` condition is converted into a coarser pattern of literal
//! characters, `*` (any characters but `/`) and `**` (any characters) that
//! matches every path the glob matches, and possibly more. Glob matching
//! works on bytes (`globset` builds a regex without Unicode), so `?` and a
//! character class can match part of a character; they become `*`, which
//! matches any run of whole characters. Anything that may match `/`, such as
//! a negated class or an alternative with a slash, becomes `**`. Paths read
//! from S3 are UTF-8, and a literal character always starts and ends at a
//! character boundary, so each run of wildcards matches whole characters.
use super::{Field, Node, Op, Value};

/// One element of a path pattern from [`super::Expression::s3_path_pushdown`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PathToken {
    Literal(char),
    /// Zero or more characters other than `/`.
    Star,
    /// Zero or more characters, including `/`.
    Recursive,
}

/// Collect a pattern for each path condition among the top-level `and`
/// conjuncts of `node`. Conditions under `or`, `not`, `if` or `coalesce`
/// are not necessary for a match, so they are left alone.
pub(super) fn conjuncts(node: &Node, patterns: &mut Vec<Vec<PathToken>>) {
    match node {
        Node::Binary(Op::And, a, b) => {
            conjuncts(a, patterns);
            conjuncts(b, patterns);
        }
        Node::Pattern(subject, _, Some(glob)) if is_path(subject) => {
            if let Some(tokens) = glob_tokens(glob) {
                patterns.push(tokens);
            }
        }
        Node::Binary(Op::Eq, a, b) => {
            let literal = match (&**a, &**b) {
                (field, Node::Literal(Value::String(text)))
                | (Node::Literal(Value::String(text)), field)
                    if is_path(field) =>
                {
                    text
                }
                _ => return,
            };
            // S3 paths are UTF-8; other bytes match no key, which the full
            // evaluation decides.
            if let Ok(text) = std::str::from_utf8(literal) {
                patterns.push(text.chars().map(PathToken::Literal).collect());
            }
        }
        _ => {}
    }
}

fn is_path(node: &Node) -> bool {
    matches!(node, Node::Field(false, Field::Path))
}

/// The tokens of `globset`'s parser (version 0.4), kept as it builds them.
#[derive(Clone, Debug)]
enum Glob {
    Literal(char),
    Any,
    ZeroOrMore,
    RecursivePrefix,
    RecursiveSuffix,
    RecursiveZeroOrMore,
    /// Whether the class may match `/`.
    Class(bool),
    Alternates(Vec<Vec<Glob>>),
}

/// Convert `glob`, which `globset` already accepted with
/// `literal_separator(true)` and its default backslash escapes. `None` when
/// the text is not understood here, so nothing is pushed down.
fn glob_tokens(glob: &str) -> Option<Vec<PathToken>> {
    let mut parser = Parser {
        chars: glob.chars().peekable(),
        prev: None,
        cur: None,
        stack: Vec::new(),
        branches: vec![Vec::new()],
    };
    parser.parse()?;
    if !parser.stack.is_empty() || parser.branches.len() != 1 {
        return None;
    }
    let mut out = Vec::new();
    convert(&parser.branches[0], &mut out);
    Some(out)
}

fn convert(tokens: &[Glob], out: &mut Vec<PathToken>) {
    for token in tokens {
        match token {
            Glob::Literal(c) => out.push(PathToken::Literal(*c)),
            Glob::Any | Glob::ZeroOrMore | Glob::Class(false) => out.push(PathToken::Star),
            Glob::RecursivePrefix | Glob::Class(true) => out.push(PathToken::Recursive),
            // `/.*` and `(?:/|/.*/)`.
            Glob::RecursiveSuffix | Glob::RecursiveZeroOrMore => {
                out.extend([PathToken::Literal('/'), PathToken::Recursive]);
            }
            Glob::Alternates(branches) => {
                let branches: Vec<Vec<PathToken>> = branches
                    .iter()
                    .map(|branch| {
                        let mut tokens = Vec::new();
                        convert(branch, &mut tokens);
                        tokens
                    })
                    .collect();
                // Keep the literal start every branch shares; the rest of
                // any branch matches `*`, or `**` if it may hold a slash.
                let shared = branches
                    .iter()
                    .map(|branch| {
                        branch
                            .iter()
                            .take_while(|token| matches!(token, PathToken::Literal(_)))
                            .count()
                    })
                    .min()
                    .unwrap_or(0);
                let shared = (0..shared)
                    .take_while(|&i| branches.iter().all(|branch| branch[i] == branches[0][i]))
                    .count();
                out.extend(branches.first().into_iter().flatten().take(shared).cloned());
                let rests = branches.iter().map(|branch| &branch[shared..]);
                if rests.clone().any(|rest| {
                    rest.iter().any(|token| {
                        matches!(token, PathToken::Recursive | PathToken::Literal('/'))
                    })
                }) {
                    out.push(PathToken::Recursive);
                } else if rests.clone().any(|rest| !rest.is_empty()) {
                    out.push(PathToken::Star);
                }
            }
        }
    }
}

/// A port of `globset::glob::Parser` (0.4.21) that records only what the
/// conversion needs.
struct Parser<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    prev: Option<char>,
    cur: Option<char>,
    /// Where each open alternation's branches start in `branches`.
    stack: Vec<usize>,
    branches: Vec<Vec<Glob>>,
}

impl Parser<'_> {
    fn bump(&mut self) -> Option<char> {
        self.prev = self.cur;
        self.cur = self.chars.next();
        self.cur
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }

    fn push(&mut self, token: Glob) -> Option<()> {
        self.branches.last_mut()?.push(token);
        Some(())
    }

    fn parse(&mut self) -> Option<()> {
        while let Some(c) = self.bump() {
            match c {
                '?' => self.push(Glob::Any)?,
                '*' => self.star()?,
                '[' => self.class()?,
                '{' => {
                    self.stack.push(self.branches.len());
                    self.branches.push(Vec::new());
                }
                '}' => {
                    let start = self.stack.pop()?;
                    let alternates = self.branches.drain(start..).collect();
                    self.push(Glob::Alternates(alternates))?;
                }
                ',' if !self.stack.is_empty() => self.branches.push(Vec::new()),
                '\\' => {
                    let escaped = self.bump()?;
                    self.push(Glob::Literal(escaped))?;
                }
                c => self.push(Glob::Literal(c))?,
            }
        }
        Some(())
    }

    fn star(&mut self) -> Option<()> {
        let prev = self.prev;
        if self.peek() != Some('*') {
            return self.push(Glob::ZeroOrMore);
        }
        self.bump();
        if self.branches.last()?.is_empty() {
            if self.peek().is_some_and(|c| c != '/') {
                self.push(Glob::ZeroOrMore)?;
                self.push(Glob::ZeroOrMore)?;
            } else {
                self.push(Glob::RecursivePrefix)?;
                self.bump();
            }
            return Some(());
        }
        if prev != Some('/') && (self.branches.len() <= 1 || !matches!(prev, Some(',' | '{'))) {
            self.push(Glob::ZeroOrMore)?;
            return self.push(Glob::ZeroOrMore);
        }
        let suffix = match self.peek() {
            None => {
                self.bump();
                true
            }
            Some(',' | '}') if self.branches.len() >= 2 => true,
            Some('/') => {
                self.bump();
                false
            }
            _ => {
                self.push(Glob::ZeroOrMore)?;
                return self.push(Glob::ZeroOrMore);
            }
        };
        let token = match self.branches.last_mut()?.pop()? {
            Glob::RecursivePrefix => Glob::RecursivePrefix,
            Glob::RecursiveSuffix => Glob::RecursiveSuffix,
            _ if suffix => Glob::RecursiveSuffix,
            _ => Glob::RecursiveZeroOrMore,
        };
        self.push(token)
    }

    /// A class: whether it may match `/`. Matching works on bytes, so a
    /// class with a character outside ASCII is assumed to match anything.
    fn class(&mut self) -> Option<()> {
        let negated = matches!(self.peek(), Some('!' | '^'));
        if negated {
            self.bump();
        }
        let mut ranges: Vec<(char, char)> = Vec::new();
        let mut first = true;
        let mut in_range = false;
        loop {
            let c = self.bump()?;
            match c {
                ']' if !first => break,
                '-' if !first && !in_range => in_range = true,
                c => {
                    if in_range {
                        ranges.last_mut()?.1 = c;
                        in_range = false;
                    } else {
                        ranges.push((c, c));
                    }
                }
            }
            first = false;
        }
        if in_range {
            ranges.push(('-', '-'));
        }
        let slash = negated
            || ranges.iter().any(|&(low, high)| {
                !low.is_ascii() || !high.is_ascii() || (low..=high).contains(&'/')
            });
        self.push(Glob::Class(slash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PathToken::{Literal as L, Recursive as R, Star as S};

    fn tokens(text: &str) -> Vec<PathToken> {
        glob_tokens(text).unwrap()
    }

    fn lit(text: &str) -> Vec<PathToken> {
        text.chars().map(L).collect()
    }

    #[test]
    fn globs_become_coarser_listing_patterns() {
        assert_eq!(
            tokens("logs/*.json"),
            [lit("logs/"), vec![S], lit(".json")].concat()
        );
        assert_eq!(tokens("a?b"), [lit("a"), vec![S], lit("b")].concat());
        assert_eq!(tokens("**"), vec![R]);
        assert_eq!(tokens("**/x"), [vec![R], lit("x")].concat());
        assert_eq!(tokens("a/**"), [lit("a/"), vec![R]].concat());
        assert_eq!(tokens("a/**/b"), [lit("a/"), vec![R], lit("b")].concat());
        assert_eq!(tokens("a**b"), [lit("a"), vec![S, S], lit("b")].concat());
        assert_eq!(tokens("[ab]c"), [vec![S], lit("c")].concat());
        assert_eq!(tokens("[!a]c"), [vec![R], lit("c")].concat());
        assert_eq!(tokens("[.-0]c"), [vec![R], lit("c")].concat());
        assert_eq!(tokens("[]]c"), [vec![S], lit("c")].concat());
        assert_eq!(tokens("[é]c"), [vec![R], lit("c")].concat());
        assert_eq!(tokens(r"a\*b"), lit("a*b"));
        assert_eq!(
            tokens("{2025,2026}-*"),
            [lit("202"), vec![S], lit("-"), vec![S]].concat()
        );
        assert_eq!(tokens("{a/b,a/c}"), [lit("a/"), vec![S]].concat());
        assert_eq!(tokens("{a,b/c}d"), [vec![R], lit("d")].concat());
        assert_eq!(tokens("x{a,}"), [lit("x"), vec![S]].concat());
        assert_eq!(tokens("a,b"), lit("a,b"));
    }

    /// Every path a glob matches also matches its conversion.
    #[test]
    fn conversions_never_drop_a_match() {
        let paths = [
            "",
            "a",
            "b",
            "ab",
            "a/b",
            "a//b",
            "a/x/b",
            "/",
            "a/",
            "x.json",
            "logs/x.json",
            "logs/2026/x.json",
            "logs/day00",
            "文",
            "文/x",
            "é",
            "aé",
            "a/é/b",
            "{a}",
            "a,b",
            "[x]",
            "a*b",
            "a?b",
            "2025-x",
            "2026-01/y",
            "-",
            ".",
            "a.b/c.d",
        ];
        let globs = [
            "*",
            "?",
            "??",
            "???",
            "**",
            "**/*",
            "*/**",
            "a/**",
            "**/b",
            "a/**/b",
            "a**",
            "**a",
            "a*",
            "*b",
            "a?b",
            "[ab]",
            "[!a]",
            "[^/]",
            "[/]",
            "[a-z]*",
            "[.-0]*",
            "{a,b}",
            "{a,b/c}",
            "{a/**,b}",
            "{**/b,a}",
            "x{a,}",
            "{,}",
            "[é]",
            "?/?",
            "*/*",
            "logs/*",
            "logs/**",
            "logs/*/x.json",
            r"a\*b",
            r"\[x\]",
            "{2025,2026}-*/**",
            "*.{json,d}",
            "文",
            "?",
            "a/{b,é}/**",
            "[[]x]",
        ];
        for glob in globs {
            let matcher = globset::GlobBuilder::new(glob)
                .literal_separator(true)
                .build()
                .unwrap()
                .compile_matcher();
            let tokens = tokens(glob);
            let mut expression = String::from(r"(?s)\A");
            for token in &tokens {
                match token {
                    L(c) => expression.push_str(&regex::escape(&c.to_string())),
                    S => expression.push_str("[^/]*"),
                    R => expression.push_str(".*"),
                }
            }
            expression.push_str(r"\z");
            let coarse = regex::Regex::new(&expression).unwrap();
            for path in paths {
                if matcher.is_match(path) {
                    assert!(
                        coarse.is_match(path),
                        "{glob:?} matches {path:?}: {tokens:?}"
                    );
                }
            }
        }
    }
}
