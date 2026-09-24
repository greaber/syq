use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Word(String),
    String(Vec<u8>),
    Number(String),
    Symbol(&'static str),
    End,
}
struct Parser {
    tokens: Vec<(Token, usize)>,
    at: usize,
    depth: usize,
    destination: bool,
}
pub(super) fn parse(text: &str, destination: bool) -> Result<Node> {
    require(text.len() <= 65536, "expression exceeds 64 KiB")?;
    let mut p = Parser {
        tokens: lex(text)?,
        at: 0,
        depth: 0,
        destination,
    };
    let result = p
        .expression(0)
        .with_context(|| format!("at byte {}", p.tokens[p.at].1 + 1))?;
    require(
        p.peek() == &Token::End,
        "unexpected tokens after expression",
    )?;
    Ok(result)
}
impl Parser {
    fn peek(&self) -> &Token {
        &self.tokens[self.at].0
    }
    fn take(&mut self) -> Token {
        let v = self.peek().clone();
        if v != Token::End {
            self.at += 1;
        }
        v
    }
    fn is(&self, s: &str) -> bool {
        matches!(self.peek(),Token::Word(w) if w==s)
            || matches!(self.peek(),Token::Symbol(w) if *w==s)
    }
    fn eat(&mut self, s: &str) -> bool {
        if self.is(s) {
            self.take();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, s: &str) -> Result<()> {
        require(self.eat(s), &format!("expected {s:?}"))
    }
    fn expression(&mut self, min: u8) -> Result<Node> {
        self.depth += 1;
        require(self.depth <= 64, "expression nesting exceeds 64 levels")?;
        let mut left = self.prefix()?;
        loop {
            let (precedence, op) = match self.peek() {
                Token::Word(s) => match s.as_str() {
                    "or" => (1, Some(Op::Or)),
                    "and" => (2, Some(Op::And)),
                    "in" | "between" | "glob" | "matches" | "is" | "not" => (3, None),
                    _ => (0, None),
                },
                Token::Symbol(s) => match *s {
                    "=" | "==" => (3, Some(Op::Eq)),
                    "!=" | "<>" => (3, Some(Op::Ne)),
                    "<" => (3, Some(Op::Lt)),
                    "<=" => (3, Some(Op::Le)),
                    ">" => (3, Some(Op::Gt)),
                    ">=" => (3, Some(Op::Ge)),
                    "=~" => (3, None),
                    "|" => (4, Some(Op::BitOr)),
                    "^" => (5, Some(Op::BitXor)),
                    "&" => (6, Some(Op::BitAnd)),
                    "+" => (7, Some(Op::Add)),
                    "-" => (7, Some(Op::Sub)),
                    "*" => (8, Some(Op::Mul)),
                    "/" => (8, Some(Op::Div)),
                    "%" => (8, Some(Op::Rem)),
                    _ => (0, None),
                },
                _ => (0, None),
            };
            if precedence == 0 || precedence < min {
                break;
            }
            let token = self.take();
            if let Some(op) = op {
                left = Node::Binary(
                    op,
                    Box::new(left),
                    Box::new(self.expression(precedence + 1)?),
                );
                continue;
            }
            let negate = token == Token::Word("not".into());
            let special = if negate { self.take() } else { token };
            left = match special {
                Token::Word(s) if s == "in" => {
                    let close = if self.eat("[") {
                        "]"
                    } else {
                        self.expect("(")?;
                        ")"
                    };
                    let mut items = Vec::new();
                    if !self.eat(close) {
                        loop {
                            items.push(self.expression(0)?);
                            if self.eat(close) {
                                break;
                            }
                            self.expect(",")?;
                        }
                    }
                    Node::In(Box::new(left), items)
                }
                Token::Word(s) if s == "between" => {
                    let low = self.expression(4)?;
                    self.expect("and")?;
                    let high = self.expression(4)?;
                    Node::Between(Box::new(left), Box::new(low), Box::new(high))
                }
                Token::Word(s) if s == "is" && !negate => {
                    let not = self.eat("not");
                    self.expect("null")?;
                    Node::Binary(
                        if not { Op::Ne } else { Op::Eq },
                        Box::new(left),
                        Box::new(Node::Literal(Value::Null)),
                    )
                }
                Token::Word(s) if s == "glob" || s == "matches" => {
                    self.pattern(left, s == "glob")?
                }
                Token::Symbol("=~") if !negate => self.pattern(left, false)?,
                _ => bail!("expected in, between, glob, or matches after not"),
            };
            if negate {
                left = Node::Not(Box::new(left));
            }
        }
        self.depth -= 1;
        Ok(left)
    }
    fn pattern(&mut self, left: Node, glob: bool) -> Result<Node> {
        let Token::String(pattern) = self.take() else {
            bail!("pattern must be a quoted literal");
        };
        let pattern = String::from_utf8(pattern).context("pattern must be UTF-8")?;
        let pattern = if glob {
            globset::GlobBuilder::new(&pattern)
                .literal_separator(true)
                .build()?
                .regex()
                .to_owned()
        } else {
            pattern
        };
        let regex = regex::bytes::RegexBuilder::new(&pattern)
            .size_limit(1024 * 1024)
            .build()
            .context("invalid pattern")?;
        Ok(Node::Pattern(Box::new(left), regex))
    }
    fn prefix(&mut self) -> Result<Node> {
        Ok(match self.take() {
            Token::String(v) => Node::Literal(Value::String(v)),
            Token::Number(v) => Node::Literal(number(&v)?),
            Token::Symbol("(") => {
                let n = self.expression(0)?;
                self.expect(")")?;
                n
            }
            Token::Symbol("-") => Node::Negative(Box::new(self.expression(9)?)),
            Token::Word(w) if w == "not" => Node::Not(Box::new(self.expression(3)?)),
            Token::Word(w) if w == "true" || w == "false" => {
                Node::Literal(Value::Bool(w == "true"))
            }
            Token::Word(w) if w == "null" => Node::Literal(Value::Null),
            Token::Word(w) if w == "now" => Node::Now,
            Token::Word(w) if w == "timestamp" => {
                self.expect("(")?;
                let Token::String(v) = self.take() else {
                    bail!("timestamp requires a quoted RFC 3339 literal");
                };
                self.expect(")")?;
                let v = String::from_utf8(v)?;
                let time =
                    time::OffsetDateTime::parse(&v, &time::format_description::well_known::Rfc3339)
                        .context("invalid RFC 3339 timestamp (include a timezone)")?;
                Node::Literal(Value::Quantity(
                    time.unix_timestamp_nanos(),
                    Type::Timestamp,
                ))
            }
            Token::Word(w) if w == "if" || w == "coalesce" => {
                self.expect("(")?;
                let a = self.expression(0)?;
                self.expect(",")?;
                let b = self.expression(0)?;
                if w == "if" {
                    self.expect(",")?;
                    let c = self.expression(0)?;
                    self.expect(")")?;
                    Node::If(Box::new(a), Box::new(b), Box::new(c))
                } else {
                    self.expect(")")?;
                    Node::Coalesce(Box::new(a), Box::new(b))
                }
            }
            Token::Word(w) => {
                let (side, field) = w
                    .split_once('.')
                    .context("expected src.FIELD, dst.FIELD, or a quoted string")?;
                require(
                    side == "src" || side == "dst",
                    "field must start with src. or dst.",
                )?;
                require(
                    side != "dst" || self.destination,
                    "--where accepts source fields only; use --copy-if for destination conditions",
                )?;
                Node::Field(side == "dst", Field::parse(field)?)
            }
            _ => bail!("expected a value, field, or parenthesized expression"),
        })
    }
}
fn number(s: &str) -> Result<Value> {
    if let Some(octal) = s.strip_prefix("0o") {
        return Ok(Value::Quantity(
            i128::from_str_radix(octal, 8).context("invalid octal number")?,
            Type::Number,
        ));
    }
    if let Some(hex) = s.strip_prefix("0x") {
        return Ok(Value::Quantity(
            i128::from_str_radix(hex, 16).context("invalid hexadecimal number")?,
            Type::Number,
        ));
    }
    let end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (digits, suffix) = s.split_at(end);
    let (multiplier, ty): (i128, Type) = match suffix {
        "" => (1, Type::Number),
        "B" => (1, Type::Size),
        "kB" | "KB" => (1000, Type::Size),
        "MB" => (1_000_000, Type::Size),
        "GB" => (1_000_000_000, Type::Size),
        "TB" => (1_000_000_000_000, Type::Size),
        "KiB" => (1 << 10, Type::Size),
        "MiB" => (1 << 20, Type::Size),
        "GiB" => (1 << 30, Type::Size),
        "TiB" => (1 << 40, Type::Size),
        "ns" => (1, Type::Duration),
        "us" => (1000, Type::Duration),
        "ms" => (1_000_000, Type::Duration),
        "s" => (1_000_000_000, Type::Duration),
        "m" => (60_000_000_000, Type::Duration),
        "h" => (3_600_000_000_000, Type::Duration),
        "d" => (86_400_000_000_000, Type::Duration),
        "w" => (604_800_000_000_000, Type::Duration),
        _ => bail!("unknown quantity suffix {suffix:?}; use B/KiB/MiB/GB or ns/ms/s/m/h/d/w"),
    };
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
    require(
        fraction.len() <= 18 && !fraction.contains('.'),
        "invalid decimal quantity",
    )?;
    let scale = 10i128.pow(fraction.len() as u32);
    let n = whole
        .parse::<i128>()?
        .checked_mul(scale)
        .and_then(|n| {
            n.checked_add(if fraction.is_empty() {
                0
            } else {
                fraction.parse::<i128>().unwrap_or(-1)
            })
        })
        .and_then(|n| n.checked_mul(multiplier))
        .context("quantity overflow")?;
    require(
        n % scale == 0,
        "quantity must resolve to whole bytes, nanoseconds, or integers",
    )?;
    Ok(Value::Quantity(n / scale, ty))
}
fn lex(s: &str) -> Result<Vec<(Token, usize)>> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut tokens = Vec::new();
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let token = match b[i] {
            quote @ (b'\'' | b'"') => {
                i += 1;
                let mut value = Vec::new();
                let mut closed = false;
                while i < b.len() {
                    let c = b[i];
                    i += 1;
                    if c == quote {
                        closed = true;
                        break;
                    }
                    if c != b'\\' {
                        value.push(c);
                        continue;
                    }
                    let c = *b.get(i).context("unfinished escape")?;
                    i += 1;
                    value.push(match c {
                        b'\\' | b'\'' | b'"' => c,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'x' => {
                            let hex = s
                                .get(i..i + 2)
                                .context("expected two hexadecimal digits after \\x")?;
                            i += 2;
                            u8::from_str_radix(hex, 16).context("invalid byte escape")?
                        }
                        _ => bail!("unknown string escape; escape a backslash as \\\\"),
                    });
                }
                require(closed, "unterminated string")?;
                Token::String(value)
            }
            b'0'..=b'9' => {
                i += 1;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.') {
                    i += 1;
                }
                Token::Number(s[start..i].into())
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                i += 1;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'.')) {
                    i += 1;
                }
                Token::Word(s[start..i].into())
            }
            _ => {
                let mut matched = None;
                for symbol in [
                    "==", "!=", "<=", ">=", "<>", "=~", "=", "<", ">", "+", "-", "*", "/", "%",
                    "&", "|", "^", "(", ")", "[", "]", ",",
                ] {
                    if s[start..].starts_with(symbol) {
                        matched = Some(symbol);
                        break;
                    }
                }
                let symbol =
                    matched.with_context(|| format!("unexpected character at byte {}", i + 1))?;
                i += symbol.len();
                Token::Symbol(symbol)
            }
        };
        tokens.push((token, start));
        require(tokens.len() <= 512, "expression exceeds 512 tokens")?;
    }
    tokens.push((Token::End, s.len()));
    Ok(tokens)
}
