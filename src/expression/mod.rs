//! Typed, side-effect-free predicates over a source and its mapped destination.
//! Compilation resolves fields and patterns once; evaluation performs no I/O.
mod parser;
#[cfg(test)]
mod tests;

use crate::proto::{Entry, Kind};
use anyhow::{bail, Context, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Type {
    Bool,
    String,
    Number,
    Size,
    Duration,
    Timestamp,
    Null,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Bool(bool),
    String(Vec<u8>),
    Quantity(i128, Type),
    Null,
}
impl Value {
    fn ty(&self) -> Type {
        match self {
            Self::Bool(_) => Type::Bool,
            Self::String(_) => Type::String,
            Self::Quantity(_, t) => *t,
            Self::Null => Type::Null,
        }
    }
    fn boolean(self) -> Result<bool> {
        match self {
            Self::Bool(v) => Ok(v),
            _ => bail!("expected a boolean value"),
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum Field {
    Path,
    Name,
    Extension,
    Kind,
    Exists,
    Size,
    Mtime,
    Ctime,
    Mode,
    Uid,
    Gid,
    Device,
    Inode,
    Links,
    LinkTarget,
}
impl Field {
    fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "path" => Self::Path,
            "name" => Self::Name,
            "extension" => Self::Extension,
            "kind" => Self::Kind,
            "exists" => Self::Exists,
            "size" => Self::Size,
            "mtime" => Self::Mtime,
            "ctime" => Self::Ctime,
            "mode" => Self::Mode,
            "uid" => Self::Uid,
            "gid" => Self::Gid,
            "device" => Self::Device,
            "inode" => Self::Inode,
            "nlink" => Self::Links,
            "link_target" => Self::LinkTarget,
            _ => bail!("unknown field {name:?}"),
        })
    }
    fn ty(self) -> Type {
        match self {
            Self::Path | Self::Name | Self::Extension | Self::Kind | Self::LinkTarget => {
                Type::String
            }
            Self::Exists => Type::Bool,
            Self::Size => Type::Size,
            Self::Mtime | Self::Ctime => Type::Timestamp,
            _ => Type::Number,
        }
    }
}

/// Metadata already acquired by the copy path. Missing fields are distinct
/// from zero values; a failed metadata read must be reported by the caller.
#[derive(Clone, Debug, Default)]
pub(crate) struct File {
    pub exists: bool,
    pub kind: Option<Kind>,
    pub size: Option<u64>,
    pub mtime: Option<(i64, u32)>,
    pub ctime: Option<(i64, u32)>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub nlink: Option<u64>,
    pub link_target: Option<Vec<u8>>,
}
impl File {
    pub fn from_entry(e: &Entry) -> Self {
        Self {
            exists: true,
            kind: Some(e.kind),
            size: Some(e.size),
            mtime: Some((e.mtime, e.mtime_nsec)),
            ctime: Some((e.ctime, e.ctime_nsec)),
            mode: Some(e.mode & 0o7777),
            uid: Some(e.uid),
            gid: Some(e.gid),
            device: Some(e.dev),
            inode: Some(e.ino),
            nlink: Some(e.nlink),
            link_target: e.link.clone(),
        }
    }
    pub fn from_root(m: crate::rooted::RootMetadata) -> Self {
        let kind = match m.mode & libc::S_IFMT {
            libc::S_IFREG => Kind::File,
            libc::S_IFDIR => Kind::Dir,
            libc::S_IFLNK => Kind::Symlink,
            libc::S_IFIFO => Kind::Fifo,
            libc::S_IFSOCK => Kind::Socket,
            libc::S_IFCHR => Kind::CharDev,
            libc::S_IFBLK => Kind::BlockDev,
            _ => Kind::Other,
        };
        Self {
            exists: true,
            kind: Some(kind),
            size: Some(m.len),
            mtime: Some((m.mtime, m.mtime_nsec)),
            ctime: Some((m.ctime, m.ctime_nsec)),
            mode: Some(m.mode & 0o7777),
            uid: Some(m.uid),
            gid: Some(m.gid),
            device: Some(m.dev),
            inode: Some(m.ino),
            nlink: Some(m.nlink),
            link_target: None,
        }
    }
    fn field(&self, path: &[u8], field: Field) -> Value {
        use Field::*;
        let string = |s: &[u8]| Value::String(s.to_vec());
        let quantity = |n: Option<i128>, t| n.map_or(Value::Null, |n| Value::Quantity(n, t));
        // Placement is known even if the destination does not exist.
        let name = path.rsplit(|b| *b == b'/').next().unwrap_or(path);
        match field {
            Path => return string(path),
            Name => return string(name),
            Extension => {
                return string(
                    name.iter()
                        .rposition(|b| *b == b'.')
                        .filter(|i| *i != 0)
                        .map_or(&[][..], |i| &name[i + 1..]),
                )
            }
            Exists => return Value::Bool(self.exists),
            _ => {}
        }
        if !self.exists {
            return Value::Null;
        }
        match field {
            Kind => self.kind.map_or(Value::Null, |k| {
                string(match k {
                    crate::proto::Kind::File => b"file",
                    crate::proto::Kind::Dir => b"dir",
                    crate::proto::Kind::Symlink => b"symlink",
                    crate::proto::Kind::Fifo => b"fifo",
                    crate::proto::Kind::Socket => b"socket",
                    crate::proto::Kind::CharDev => b"char",
                    crate::proto::Kind::BlockDev => b"block",
                    crate::proto::Kind::Other => b"other",
                })
            }),
            Size => quantity(self.size.map(i128::from), Type::Size),
            Mtime | Ctime => quantity(
                if matches!(field, Mtime) {
                    self.mtime
                } else {
                    self.ctime
                }
                .map(|(s, n)| i128::from(s) * 1_000_000_000 + i128::from(n)),
                Type::Timestamp,
            ),
            Mode => quantity(self.mode.map(i128::from), Type::Number),
            Uid => quantity(self.uid.map(i128::from), Type::Number),
            Gid => quantity(self.gid.map(i128::from), Type::Number),
            Device => quantity(self.device.map(i128::from), Type::Number),
            Inode => quantity(self.inode.map(i128::from), Type::Number),
            Links => quantity(self.nlink.map(i128::from), Type::Number),
            LinkTarget => self.link_target.as_deref().map_or(Value::Null, string),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    BitAnd,
    BitOr,
    BitXor,
}
#[derive(Clone, Debug)]
enum Node {
    Literal(Value),
    Field(bool, Field),
    Now,
    Not(Box<Node>),
    Negative(Box<Node>),
    Binary(Op, Box<Node>, Box<Node>),
    In(Box<Node>, Vec<Node>),
    Between(Box<Node>, Box<Node>, Box<Node>),
    Pattern(Box<Node>, regex::bytes::Regex),
    If(Box<Node>, Box<Node>, Box<Node>),
    Coalesce(Box<Node>, Box<Node>),
}
impl Node {
    fn ty(&self) -> Result<Type> {
        use Type::*;
        Ok(match self {
            Self::Literal(v) => v.ty(),
            Self::Field(_, f) => f.ty(),
            Self::Now => Timestamp,
            Self::Not(n) => {
                require(n.ty()? == Bool, "not requires a boolean")?;
                Bool
            }
            Self::Negative(n) => {
                let t = n.ty()?;
                require(
                    matches!(t, Number | Size | Duration),
                    "unary minus requires a number, size, or duration",
                )?;
                t
            }
            Self::Binary(op, a, b) => binary_type(*op, a.ty()?, b.ty()?)?,
            Self::Between(a, b, c) => {
                binary_type(Op::Ge, a.ty()?, b.ty()?)?;
                binary_type(Op::Le, a.ty()?, c.ty()?)?;
                Bool
            }
            Self::In(a, items) => {
                for b in items {
                    binary_type(Op::Eq, a.ty()?, b.ty()?)?;
                }
                Bool
            }
            Self::Pattern(a, _) => {
                require(a.ty()? == String, "pattern matching requires a string")?;
                Bool
            }
            Self::If(c, a, b) => {
                require(c.ty()? == Bool, "if requires a boolean condition")?;
                common_type(a.ty()?, b.ty()?)?
            }
            Self::Coalesce(a, b) => common_type(a.ty()?, b.ty()?)?,
        })
    }
    fn eval(&self, c: &ContextValues<'_>) -> Result<Value> {
        Ok(match self {
            Self::Literal(v) => v.clone(),
            Self::Now => Value::Quantity(c.now, Type::Timestamp),
            Self::Field(dst, f) => {
                if *dst {
                    c.dst.field(c.dst_path, *f)
                } else {
                    c.src.field(c.src_path, *f)
                }
            }
            Self::Not(n) => Value::Bool(!n.eval(c)?.boolean()?),
            Self::Negative(n) => match n.eval(c)? {
                Value::Quantity(v, t) => {
                    Value::Quantity(v.checked_neg().context("arithmetic overflow")?, t)
                }
                _ => bail!("cannot negate an unavailable value"),
            },
            Self::Binary(Op::And, a, b) => {
                Value::Bool(a.eval(c)?.boolean()? && b.eval(c)?.boolean()?)
            }
            Self::Binary(Op::Or, a, b) => {
                Value::Bool(a.eval(c)?.boolean()? || b.eval(c)?.boolean()?)
            }
            Self::Binary(op, a, b) => binary(*op, a.eval(c)?, b.eval(c)?)?,
            Self::Between(a, b, d) => {
                let value = a.eval(c)?;
                Value::Bool(
                    binary(Op::Ge, value.clone(), b.eval(c)?)?.boolean()?
                        && binary(Op::Le, value, d.eval(c)?)?.boolean()?,
                )
            }
            Self::In(a, items) => {
                let value = a.eval(c)?;
                let mut found = false;
                for item in items {
                    if binary(Op::Eq, value.clone(), item.eval(c)?)?.boolean()? {
                        found = true;
                        break;
                    }
                }
                Value::Bool(found)
            }
            Self::Pattern(n, pattern) => match n.eval(c)? {
                Value::String(v) => Value::Bool(pattern.is_match(&v)),
                _ => bail!("cannot match an unavailable value; test it against null first"),
            },
            Self::If(cond, a, b) => {
                if cond.eval(c)?.boolean()? {
                    a.eval(c)?
                } else {
                    b.eval(c)?
                }
            }
            Self::Coalesce(a, b) => {
                let v = a.eval(c)?;
                if v == Value::Null {
                    b.eval(c)?
                } else {
                    v
                }
            }
        })
    }
}
fn require(ok: bool, message: &str) -> Result<()> {
    if !ok {
        bail!("{message}");
    }
    Ok(())
}
fn common_type(a: Type, b: Type) -> Result<Type> {
    if a == Type::Null {
        Ok(b)
    } else if b == Type::Null || a == b {
        Ok(a)
    } else {
        bail!("incompatible types: {a:?} and {b:?}")
    }
}
fn binary_type(op: Op, a: Type, b: Type) -> Result<Type> {
    use Op::*;
    use Type::*;
    Ok(match op {
        And | Or => {
            require(a == Bool && b == Bool, "and/or require booleans")?;
            Bool
        }
        Eq | Ne => {
            common_type(a, b)?;
            Bool
        }
        Lt | Le | Gt | Ge => {
            require(
                a == b && matches!(a, Number | Size | Duration | Timestamp | String),
                "ordered comparisons require matching numbers, sizes, durations, timestamps, or strings",
            )?;
            Bool
        }
        BitAnd | BitOr | BitXor if a == Number && b == Number => Number,
        Add if a == Timestamp && b == Duration || a == Duration && b == Timestamp => Timestamp,
        Sub if a == Timestamp && b == Duration => Timestamp,
        Sub if a == Timestamp && b == Timestamp => Duration,
        Add | Sub if a == b && matches!(a, Number | Size | Duration) => a,
        Mul if a == Number && matches!(b, Number | Size | Duration) => b,
        Mul | Div if b == Number && matches!(a, Number | Size | Duration) => a,
        Div if a == b && matches!(a, Size | Duration) => Number,
        Rem if a == b && matches!(a, Number | Size | Duration) => a,
        _ => bail!("invalid arithmetic between {a:?} and {b:?}"),
    })
}
fn binary(op: Op, a: Value, b: Value) -> Result<Value> {
    use Op::*;
    if matches!(op, Eq | Ne) {
        return Ok(Value::Bool(if op == Eq { a == b } else { a != b }));
    }
    if a == Value::Null || b == Value::Null {
        bail!("field is unavailable; test it against null or use coalesce first");
    }
    let ty = binary_type(op, a.ty(), b.ty())?;
    let ordering = match (&a, &b) {
        (Value::Quantity(a, _), Value::Quantity(b, _)) => Some(a.cmp(b)),
        (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
        _ => None,
    };
    if let Some(order) = ordering {
        let result = match op {
            Lt => Some(order.is_lt()),
            Le => Some(order.is_le()),
            Gt => Some(order.is_gt()),
            Ge => Some(order.is_ge()),
            _ => None,
        };
        if let Some(v) = result {
            return Ok(Value::Bool(v));
        }
    }
    let (Value::Quantity(a, _), Value::Quantity(b, _)) = (a, b) else {
        bail!("arithmetic requires quantities");
    };
    let n = match op {
        Add => a.checked_add(b),
        Sub => a.checked_sub(b),
        Mul => a.checked_mul(b),
        Div => a.checked_div(b),
        Rem => a.checked_rem(b),
        BitAnd => Some(a & b),
        BitOr => Some(a | b),
        BitXor => Some(a ^ b),
        _ => None,
    }
    .context("arithmetic overflow or division by zero")?;
    Ok(Value::Quantity(n, ty))
}
struct ContextValues<'a> {
    src: &'a File,
    dst: &'a File,
    src_path: &'a [u8],
    dst_path: &'a [u8],
    now: i128,
}
#[derive(Clone, Debug)]
pub(crate) struct Expression {
    root: Node,
}
impl Expression {
    pub fn compile(text: &str, destination: bool) -> Result<Self> {
        let root = parser::parse(text, destination)?;
        require(
            root.ty()? == Type::Bool,
            "expression must produce a boolean",
        )?;
        Ok(Self { root })
    }
    pub fn evaluate(
        &self,
        src: &File,
        src_path: &[u8],
        dst: &File,
        dst_path: &[u8],
        now: i128,
    ) -> Result<bool> {
        self.root
            .eval(&ContextValues {
                src,
                dst,
                src_path,
                dst_path,
                now,
            })?
            .boolean()
    }
}
#[derive(Clone, Debug, Default)]
pub(crate) struct Policy {
    pub selection: Option<Expression>,
    pub update: Option<Expression>,
    pub now: i128,
}
impl Policy {
    pub fn compile(selection: Option<&str>, update: Option<&str>) -> Result<Self> {
        Ok(Self {
            selection: selection
                .map(|s| Expression::compile(s, false).context("--where"))
                .transpose()?,
            update: update
                .map(|s| Expression::compile(s, true).context("--copy-if"))
                .transpose()?,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as i128,
        })
    }
    pub fn active(&self) -> bool {
        self.selection.is_some() || self.update.is_some()
    }
    pub fn selects(&self, src: &File, path: &[u8]) -> Result<bool> {
        self.selection
            .as_ref()
            .map_or(Ok(true), |e| {
                e.evaluate(src, path, &File::default(), b"", self.now)
            })
            .context("--where")
    }
    pub fn permits(
        &self,
        src: &File,
        src_path: &[u8],
        dst: &File,
        dst_path: &[u8],
    ) -> Result<bool> {
        self.update
            .as_ref()
            .map_or(Ok(true), |e| {
                e.evaluate(src, src_path, dst, dst_path, self.now)
            })
            .context("--copy-if")
    }
}

/// An explicit file root has an empty scanner-relative path. Give expressions
/// its supplied basename instead of an empty name.
pub(crate) fn source_path<'a>(root: &'a [u8], relative: &'a [u8]) -> &'a [u8] {
    if relative.is_empty() {
        root.rsplit(|b| *b == b'/')
            .find(|p| !p.is_empty())
            .unwrap_or(b"")
    } else {
        relative
    }
}
