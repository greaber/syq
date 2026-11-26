//! Typed, side-effect-free predicates over a source and its mapped destination.
//! Compilation resolves fields and patterns once; evaluation performs no I/O.
mod parser;
mod pushdown;
#[cfg(test)]
mod tests;

pub(crate) use pushdown::PathToken;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value<S> {
    Bool(bool),
    String(S),
    Quantity(i128, Type),
    Null,
}
impl<S> Value<S> {
    fn ty(&self) -> Type {
        match self {
            Self::Bool(_) => Type::Bool,
            Self::String(_) => Type::String,
            Self::Quantity(_, t) => *t,
            Self::Null => Type::Null,
        }
    }
    fn tristate(self) -> Result<Option<bool>> {
        match self {
            Self::Bool(v) => Ok(Some(v)),
            Self::Null => Ok(None),
            _ => bail!("expected a boolean value"),
        }
    }
    fn from_tristate(v: Option<bool>) -> Self {
        match v {
            Some(b) => Self::Bool(b),
            None => Self::Null,
        }
    }
    fn is_true(&self) -> Result<bool> {
        Ok(match self {
            Self::Bool(v) => *v,
            Self::Null => false,
            _ => bail!("expected a boolean value"),
        })
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
    S3LastModified,
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
    fn path_bytes(self, path: &[u8]) -> Option<&[u8]> {
        use Field::*;
        // Placement is known even if the destination does not exist.
        let name = path.rsplit(|b| *b == b'/').next().unwrap_or(path);
        match self {
            Path => Some(path),
            Name => Some(name),
            Extension => Some(
                name.iter()
                    .rposition(|b| *b == b'.')
                    .filter(|i| *i != 0)
                    .map_or(&[][..], |i| &name[i + 1..]),
            ),
            _ => None,
        }
    }
    fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "path" => Self::Path,
            "name" => Self::Name,
            "extension" => Self::Extension,
            "kind" => Self::Kind,
            "exists" => Self::Exists,
            "size" => Self::Size,
            "mtime" => Self::Mtime,
            "s3_last_modified" => Self::S3LastModified,
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
            Self::Mtime | Self::Ctime | Self::S3LastModified => Type::Timestamp,
            _ => Type::Number,
        }
    }
}

/// Metadata already acquired by the copy path. Missing fields are distinct
/// from zero values; a failed metadata read must be reported by the caller.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct File<'a> {
    pub exists: bool,
    pub kind: Option<Kind>,
    pub size: Option<u64>,
    pub mtime: Option<(i64, u32)>,
    pub ctime: Option<(i64, u32)>,
    pub s3_last_modified: Option<(i64, u32)>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub device: Option<u64>,
    pub inode: Option<u64>,
    pub nlink: Option<u64>,
    pub link_target: Option<std::borrow::Cow<'a, [u8]>>,
}
impl<'a> File<'a> {
    pub fn from_entry(e: &'a Entry) -> Self {
        Self::entry_fields(e, e.link.as_deref().map(Into::into))
    }
    pub fn owned_entry(e: &Entry) -> File<'static> {
        File::entry_fields(e, e.link.clone().map(Into::into))
    }
    fn entry_fields(e: &Entry, link_target: Option<std::borrow::Cow<'a, [u8]>>) -> Self {
        Self {
            exists: true,
            kind: Some(e.kind),
            size: (e.kind != Kind::Dir).then_some(e.size),
            mtime: Some((e.mtime, e.mtime_nsec)),
            ctime: Some((e.ctime, e.ctime_nsec)),
            mode: Some(e.mode & 0o7777),
            uid: Some(e.uid),
            gid: Some(e.gid),
            device: Some(e.dev),
            inode: Some(e.ino),
            nlink: Some(e.nlink),
            link_target,
            s3_last_modified: None,
        }
    }
    pub fn from_root(m: crate::rooted::RootMetadata) -> Self {
        let kind = match (m.mode as libc::mode_t) & libc::S_IFMT {
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
            size: (kind != Kind::Dir).then_some(m.len),
            mtime: Some((m.mtime, m.mtime_nsec)),
            ctime: Some((m.ctime, m.ctime_nsec)),
            mode: Some(m.mode & 0o7777),
            uid: Some(m.uid),
            gid: Some(m.gid),
            device: Some(m.dev),
            inode: Some(m.ino),
            nlink: Some(m.nlink),
            link_target: None,
            s3_last_modified: None,
        }
    }
    fn field<'b>(&'b self, path: &'b [u8], field: Field) -> Value<&'b [u8]> {
        use Field::*;
        let quantity = |n: Option<i128>, t| n.map_or(Value::Null, |n| Value::Quantity(n, t));
        if let Some(bytes) = field.path_bytes(path) {
            return Value::String(bytes);
        }
        if matches!(field, Exists) {
            return Value::Bool(self.exists);
        }
        if !self.exists {
            return Value::Null;
        }
        match field {
            Kind => self.kind.map_or(Value::Null, |k| {
                Value::String(match k {
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
            Mtime | Ctime | S3LastModified => quantity(
                match field {
                    Mtime => self.mtime,
                    Ctime => self.ctime,
                    S3LastModified => self.s3_last_modified,
                    _ => unreachable!(),
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
            LinkTarget => self
                .link_target
                .as_deref()
                .map_or(Value::Null, Value::String),
            _ => unreachable!(),
        }
    }
}

/// Facts available without another metadata request. Unread fields are distinct
/// from known-unavailable (`null`) fields, so short-circuiting stays exact.
#[derive(Clone, Copy)]
pub(crate) enum Facts<'a> {
    Complete(&'a File<'a>),
    S3Listing {
        size: u64,
        directory_marker: bool,
        last_modified: Option<(i64, u32)>,
    },
    /// A directory in an S3 listing, from a common prefix or a directory
    /// marker. Listings report it with no metadata of its own.
    S3Directory,
    Unread,
}
#[derive(Debug)]
struct NeedMetadata;
impl std::fmt::Display for NeedMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("expression needs metadata")
    }
}
impl std::error::Error for NeedMetadata {}
impl<'a> Facts<'a> {
    fn field(self, path: &'a [u8], field: Field) -> Result<Value<&'a [u8]>> {
        if let Self::Complete(file) = self {
            return Ok(file.field(path, field));
        }
        if let Some(bytes) = field.path_bytes(path) {
            return Ok(Value::String(bytes));
        }
        if let Self::S3Directory = self {
            return Ok(match field {
                Field::Exists => Value::Bool(true),
                Field::Kind => Value::String(b"dir"),
                _ => Value::Null,
            });
        }
        if let Self::S3Listing {
            size,
            directory_marker,
            last_modified,
        } = self
        {
            return Ok(match field {
                Field::Exists => Value::Bool(true),
                Field::Size => {
                    if directory_marker {
                        Value::Null
                    } else {
                        Value::Quantity(i128::from(size), Type::Size)
                    }
                }
                Field::S3LastModified => last_modified.map_or(Value::Null, |(s, n)| {
                    Value::Quantity(
                        i128::from(s) * 1_000_000_000 + i128::from(n),
                        Type::Timestamp,
                    )
                }),
                // S3 never exposes these fields, including through HEAD.
                Field::Ctime | Field::Device | Field::Inode | Field::Links | Field::LinkTarget => {
                    Value::Null
                }
                // Stored Unix metadata determines kind, mtime and ownership.
                _ => return Err(NeedMetadata.into()),
            });
        }
        Err(NeedMetadata.into())
    }

    /// Whether the entry is known not to be a directory before its metadata
    /// is read: an S3 object whose key is not a directory marker, which syq
    /// refuses to read as a directory.
    fn never_directory(self) -> bool {
        matches!(
            self,
            Self::S3Listing {
                directory_marker: false,
                ..
            }
        )
    }
}

/// Whether `a` and `b` compare the entry's own kind with `"dir"`.
fn compares_kind_with_dir(a: &Node, b: &Node) -> bool {
    matches!(
        (a, b),
        (Node::Field(false, Field::Kind), Node::Literal(Value::String(text)))
            | (Node::Literal(Value::String(text)), Node::Field(false, Field::Kind))
            if text.as_slice() == b"dir"
    )
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
    Literal(Value<Vec<u8>>),
    Field(bool, Field),
    Now,
    IsNull(Box<Node>, bool),
    Not(Box<Node>),
    Negative(Box<Node>),
    Binary(Op, Box<Node>, Box<Node>),
    In(Box<Node>, Vec<Node>),
    Between(Box<Node>, Box<Node>, Box<Node>),
    /// A pattern match, with the glob's text when it is a glob.
    Pattern(Box<Node>, regex::bytes::Regex, Option<Box<str>>),
    If(Box<Node>, Box<Node>, Box<Node>),
    Coalesce(Box<Node>, Box<Node>),
}
impl Node {
    fn uses_source_s3_time(&self) -> bool {
        match self {
            Self::Field(false, Field::S3LastModified) => true,
            Self::IsNull(n, _) | Self::Not(n) | Self::Negative(n) | Self::Pattern(n, ..) => {
                n.uses_source_s3_time()
            }
            Self::Binary(_, a, b) | Self::Coalesce(a, b) => {
                a.uses_source_s3_time() || b.uses_source_s3_time()
            }
            Self::Between(a, b, c) | Self::If(a, b, c) => {
                a.uses_source_s3_time() || b.uses_source_s3_time() || c.uses_source_s3_time()
            }
            Self::In(a, items) => {
                a.uses_source_s3_time() || items.iter().any(Self::uses_source_s3_time)
            }
            _ => false,
        }
    }
    fn ty(&self) -> Result<Type> {
        use Type::*;
        Ok(match self {
            Self::Literal(v) => v.ty(),
            Self::Field(_, f) => f.ty(),
            Self::Now => Timestamp,
            Self::IsNull(n, _) => {
                n.ty()?;
                Bool
            }
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
                let left = a.ty()?;
                require(
                    left != Null,
                    "use 'is null' or 'is not null' instead of comparing with null",
                )?;
                for b in items {
                    binary_type(Op::Eq, left, b.ty()?)?;
                }
                Bool
            }
            Self::Pattern(a, ..) => {
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
    fn eval<'a>(&'a self, c: &ContextValues<'a>) -> Result<Value<&'a [u8]>> {
        Ok(match self {
            Self::Literal(v) => match v {
                Value::String(s) => Value::String(s.as_slice()),
                Value::Quantity(n, ty) => Value::Quantity(*n, *ty),
                Value::Bool(b) => Value::Bool(*b),
                Value::Null => Value::Null,
            },
            Self::Now => Value::Quantity(c.now, Type::Timestamp),
            Self::Field(dst, f) => {
                if *dst {
                    c.dst.field(c.dst_path, *f)?
                } else {
                    c.src.field(c.src_path, *f)?
                }
            }
            Self::IsNull(n, negated) => {
                let is_null = n.eval(c)? == Value::Null;
                Value::Bool(if *negated { !is_null } else { is_null })
            }
            Self::Not(n) => Value::from_tristate(n.eval(c)?.tristate()?.map(|b| !b)),
            Self::Negative(n) => match n.eval(c)? {
                Value::Quantity(v, t) => {
                    Value::Quantity(v.checked_neg().context("arithmetic overflow")?, t)
                }
                Value::Null => Value::Null,
                _ => bail!("unary minus requires a number, size, or duration"),
            },
            Self::Binary(Op::And, a, b) => match a.eval(c)?.tristate()? {
                Some(false) => Value::Bool(false),
                Some(true) => Value::from_tristate(b.eval(c)?.tristate()?),
                None => match b.eval(c)?.tristate()? {
                    Some(false) => Value::Bool(false),
                    _ => Value::Null,
                },
            },
            Self::Binary(Op::Or, a, b) => match a.eval(c)?.tristate()? {
                Some(true) => Value::Bool(true),
                Some(false) => Value::from_tristate(b.eval(c)?.tristate()?),
                None => match b.eval(c)?.tristate()? {
                    Some(true) => Value::Bool(true),
                    _ => Value::Null,
                },
            },
            // An object's kind needs its metadata, but whether it is a
            // directory does not.
            Self::Binary(op @ (Op::Eq | Op::Ne), a, b)
                if c.src.never_directory() && compares_kind_with_dir(a, b) =>
            {
                Value::Bool(*op == Op::Ne)
            }
            Self::Binary(op, a, b) => binary(*op, a.eval(c)?, b.eval(c)?)?,
            Self::Between(a, b, d) => {
                let value = a.eval(c)?;
                let lo = binary(Op::Ge, value, b.eval(c)?)?.tristate()?;
                if lo == Some(false) {
                    Value::Bool(false)
                } else {
                    let hi = binary(Op::Le, value, d.eval(c)?)?.tristate()?;
                    match (lo, hi) {
                        (Some(true), Some(true)) => Value::Bool(true),
                        (_, Some(false)) => Value::Bool(false),
                        _ => Value::Null,
                    }
                }
            }
            Self::In(a, items) => {
                let value = a.eval(c)?;
                let mut saw_null = false;
                for item in items {
                    match binary(Op::Eq, value, item.eval(c)?)?.tristate()? {
                        Some(true) => return Ok(Value::Bool(true)),
                        Some(false) => {}
                        None => saw_null = true,
                    }
                }
                if saw_null {
                    Value::Null
                } else {
                    Value::Bool(false)
                }
            }
            Self::Pattern(n, pattern, _) => match n.eval(c)? {
                Value::String(v) => Value::Bool(pattern.is_match(v)),
                Value::Null => Value::Null,
                _ => bail!("pattern matching requires a string"),
            },
            Self::If(cond, a, b) => {
                if cond.eval(c)?.is_true()? {
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
    /// Abstractly evaluate this expression for `Facts::S3Directory`.
    /// Sound over-approximation: returns `Abs::MayFail` if a runtime error
    /// may happen, so callers never drop directories that would fail evaluation.
    fn eval_s3_dir(&self, now: i128) -> Abs<'_> {
        match self {
            Self::Literal(v) => Abs::Exact(match v {
                Value::String(s) => Value::String(s.as_slice()),
                Value::Quantity(n, ty) => Value::Quantity(*n, *ty),
                Value::Bool(b) => Value::Bool(*b),
                Value::Null => Value::Null,
            }),
            Self::Now => Abs::Exact(Value::Quantity(now, Type::Timestamp)),
            Self::Field(dst, f) => {
                if *dst {
                    return Abs::MayFail;
                }
                match f {
                    Field::Path | Field::Name | Field::Extension => Abs::AnyNonNull,
                    Field::Exists => Abs::Exact(Value::Bool(true)),
                    Field::Kind => Abs::Exact(Value::String(b"dir")),
                    _ => Abs::Exact(Value::Null),
                }
            }
            Self::IsNull(n, negated) => match n.eval_s3_dir(now) {
                Abs::MayFail => Abs::MayFail,
                Abs::Exact(v) => Abs::Exact(Value::Bool(if *negated {
                    v != Value::Null
                } else {
                    v == Value::Null
                })),
                Abs::AnyNonNull => Abs::Exact(Value::Bool(*negated)),
                Abs::Bool(s) if !s.n => Abs::Exact(Value::Bool(*negated)),
                Abs::Bool(s) if !s.t && !s.f => Abs::Exact(Value::Bool(!*negated)),
                Abs::Bool(_) | Abs::Any => Abs::Bool(BoolSet {
                    t: true,
                    f: true,
                    n: false,
                }),
            },
            Self::Not(n) => match n.eval_s3_dir(now) {
                Abs::MayFail => Abs::MayFail,
                v => Abs::from_bool_set(v.bool_set().not()),
            },
            Self::Negative(n) => match n.eval_s3_dir(now) {
                Abs::MayFail => Abs::MayFail,
                Abs::Exact(Value::Null) => Abs::Exact(Value::Null),
                Abs::Exact(Value::Quantity(v, t)) => v
                    .checked_neg()
                    .map_or(Abs::MayFail, |r| Abs::Exact(Value::Quantity(r, t))),
                _ => Abs::MayFail,
            },
            Self::Binary(Op::And, a, b) => {
                let va = a.eval_s3_dir(now);
                if matches!(va, Abs::MayFail) {
                    return Abs::MayFail;
                }
                let sa = va.bool_set();
                if !sa.t && !sa.n {
                    return Abs::Exact(Value::Bool(false));
                }
                let vb = b.eval_s3_dir(now);
                if matches!(vb, Abs::MayFail) {
                    return Abs::MayFail;
                }
                Abs::from_bool_set(sa.and(vb.bool_set()))
            }
            Self::Binary(Op::Or, a, b) => {
                let va = a.eval_s3_dir(now);
                if matches!(va, Abs::MayFail) {
                    return Abs::MayFail;
                }
                let sa = va.bool_set();
                if !sa.f && !sa.n {
                    return Abs::Exact(Value::Bool(true));
                }
                let vb = b.eval_s3_dir(now);
                if matches!(vb, Abs::MayFail) {
                    return Abs::MayFail;
                }
                Abs::from_bool_set(sa.or(vb.bool_set()))
            }
            Self::Binary(op @ (Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge), a, b) => {
                let va = a.eval_s3_dir(now);
                let vb = b.eval_s3_dir(now);
                if matches!(va, Abs::MayFail) || matches!(vb, Abs::MayFail) {
                    return Abs::MayFail;
                }
                cmp_abs(*op, va, vb)
            }
            Self::Binary(op @ (Op::BitAnd | Op::BitOr | Op::BitXor), a, b) => {
                let va = a.eval_s3_dir(now);
                let vb = b.eval_s3_dir(now);
                if matches!(va, Abs::MayFail) || matches!(vb, Abs::MayFail) {
                    return Abs::MayFail;
                }
                if matches!(va, Abs::Exact(Value::Null)) || matches!(vb, Abs::Exact(Value::Null)) {
                    return Abs::Exact(Value::Null);
                }
                if let (Abs::Exact(x), Abs::Exact(y)) = (va, vb) {
                    binary(*op, x, y).map_or(Abs::MayFail, Abs::Exact)
                } else if va.never_null() && vb.never_null() {
                    Abs::AnyNonNull
                } else {
                    Abs::Any
                }
            }
            Self::Binary(op, a, b) => {
                let va = a.eval_s3_dir(now);
                let vb = b.eval_s3_dir(now);
                if matches!(va, Abs::MayFail) || matches!(vb, Abs::MayFail) {
                    return Abs::MayFail;
                }
                if matches!(va, Abs::Exact(Value::Null)) || matches!(vb, Abs::Exact(Value::Null)) {
                    return Abs::Exact(Value::Null);
                }
                if let (Abs::Exact(x), Abs::Exact(y)) = (va, vb) {
                    binary(*op, x, y).map_or(Abs::MayFail, Abs::Exact)
                } else {
                    Abs::MayFail
                }
            }
            Self::Between(a, lo, hi) => {
                let va = a.eval_s3_dir(now);
                let vlo = lo.eval_s3_dir(now);
                if matches!(va, Abs::MayFail) || matches!(vlo, Abs::MayFail) {
                    return Abs::MayFail;
                }
                let s_lo = cmp_abs(Op::Ge, va, vlo).bool_set();
                if !s_lo.t && !s_lo.n {
                    return Abs::Exact(Value::Bool(false));
                }
                let vhi = hi.eval_s3_dir(now);
                if matches!(vhi, Abs::MayFail) {
                    return Abs::MayFail;
                }
                Abs::from_bool_set(s_lo.and(cmp_abs(Op::Le, va, vhi).bool_set()))
            }
            Self::In(a, items) => {
                let va = a.eval_s3_dir(now);
                if matches!(va, Abs::MayFail) {
                    return Abs::MayFail;
                }
                let mut acc = BoolSet::FALSE;
                for item in items {
                    if !acc.f && !acc.n {
                        return Abs::Exact(Value::Bool(true));
                    }
                    let vi = item.eval_s3_dir(now);
                    if matches!(vi, Abs::MayFail) {
                        return Abs::MayFail;
                    }
                    acc = acc.or(cmp_abs(Op::Eq, va, vi).bool_set());
                }
                Abs::from_bool_set(acc)
            }
            Self::Pattern(n, regex, _) => match n.eval_s3_dir(now) {
                Abs::MayFail => Abs::MayFail,
                Abs::Exact(Value::Null) => Abs::Exact(Value::Null),
                Abs::Exact(Value::String(s)) => Abs::Exact(Value::Bool(regex.is_match(s))),
                Abs::AnyNonNull => Abs::Bool(BoolSet {
                    t: true,
                    f: true,
                    n: false,
                }),
                Abs::Any => Abs::Bool(BoolSet::ANY),
                Abs::Exact(_) | Abs::Bool(_) => Abs::MayFail,
            },
            Self::If(cond, a, b) => {
                let vc = cond.eval_s3_dir(now);
                if matches!(vc, Abs::MayFail) {
                    return Abs::MayFail;
                }
                let sc = vc.bool_set();
                let then_branch = sc.t.then(|| a.eval_s3_dir(now));
                let else_branch = (sc.f || sc.n).then(|| b.eval_s3_dir(now));
                match (then_branch, else_branch) {
                    (Some(x), None) | (None, Some(x)) => x,
                    (Some(x), Some(y)) => Abs::join(x, y),
                    (None, None) => Abs::Any,
                }
            }
            Self::Coalesce(a, b) => match a.eval_s3_dir(now) {
                Abs::MayFail => Abs::MayFail,
                Abs::Exact(Value::Null) => b.eval_s3_dir(now),
                va @ (Abs::Exact(_) | Abs::AnyNonNull) => va,
                va @ Abs::Bool(s) if !s.n => va,
                Abs::Bool(s) if !s.t && !s.f => b.eval_s3_dir(now),
                Abs::Bool(s) => Abs::join(
                    Abs::from_bool_set(BoolSet {
                        t: s.t,
                        f: s.f,
                        n: false,
                    }),
                    b.eval_s3_dir(now),
                ),
                Abs::Any => Abs::join(Abs::AnyNonNull, b.eval_s3_dir(now)),
            },
        }
    }
}
#[derive(Clone, Copy)]
struct BoolSet {
    t: bool,
    f: bool,
    n: bool,
}
impl BoolSet {
    const TRUE: Self = Self {
        t: true,
        f: false,
        n: false,
    };
    const FALSE: Self = Self {
        t: false,
        f: true,
        n: false,
    };
    const NULL: Self = Self {
        t: false,
        f: false,
        n: true,
    };
    const ANY: Self = Self {
        t: true,
        f: true,
        n: true,
    };
    fn from_value(v: Value<&[u8]>) -> Self {
        match v {
            Value::Bool(true) => Self::TRUE,
            Value::Bool(false) => Self::FALSE,
            Value::Null => Self::NULL,
            _ => Self::ANY,
        }
    }
    fn join(self, other: Self) -> Self {
        Self {
            t: self.t || other.t,
            f: self.f || other.f,
            n: self.n || other.n,
        }
    }
    fn not(self) -> Self {
        Self {
            t: self.f,
            f: self.t,
            n: self.n,
        }
    }
    fn and(self, other: Self) -> Self {
        Self {
            t: self.t && other.t,
            f: self.f || ((self.t || self.n) && other.f),
            n: (self.t && other.n) || (self.n && (other.t || other.n)),
        }
    }
    fn or(self, other: Self) -> Self {
        Self {
            t: self.t || other.t,
            f: self.f && other.f,
            n: (self.f && other.n) || (self.n && (other.f || other.n)),
        }
    }
}
#[derive(Clone, Copy)]
enum Abs<'a> {
    Exact(Value<&'a [u8]>),
    Bool(BoolSet),
    AnyNonNull,
    Any,
    MayFail,
}
impl<'a> Abs<'a> {
    fn from_bool_set(s: BoolSet) -> Self {
        match (s.t, s.f, s.n) {
            (true, false, false) => Self::Exact(Value::Bool(true)),
            (false, true, false) => Self::Exact(Value::Bool(false)),
            (false, false, true) => Self::Exact(Value::Null),
            _ => Self::Bool(s),
        }
    }
    fn bool_set(self) -> BoolSet {
        match self {
            Self::Exact(v) => BoolSet::from_value(v),
            Self::Bool(s) => s,
            Self::AnyNonNull => BoolSet {
                t: true,
                f: true,
                n: false,
            },
            Self::Any | Self::MayFail => BoolSet::ANY,
        }
    }
    fn never_null(self) -> bool {
        match self {
            Self::Exact(v) => v != Value::Null,
            Self::Bool(s) => !s.n,
            Self::AnyNonNull => true,
            Self::Any | Self::MayFail => false,
        }
    }
    fn join(a: Self, b: Self) -> Self {
        match (a, b) {
            (Self::MayFail, _) | (_, Self::MayFail) => Self::MayFail,
            (Self::Exact(x), Self::Exact(y)) if x == y => Self::Exact(x),
            (
                Self::Exact(Value::Bool(_) | Value::Null) | Self::Bool(_),
                Self::Exact(Value::Bool(_) | Value::Null) | Self::Bool(_),
            ) => Self::from_bool_set(a.bool_set().join(b.bool_set())),
            _ if a.never_null() && b.never_null() => Self::AnyNonNull,
            _ => Self::Any,
        }
    }
}
fn cmp_abs<'a>(op: Op, a: Abs<'a>, b: Abs<'a>) -> Abs<'a> {
    if matches!(a, Abs::Exact(Value::Null)) || matches!(b, Abs::Exact(Value::Null)) {
        return Abs::Exact(Value::Null);
    }
    if let (Abs::Exact(x), Abs::Exact(y)) = (a, b) {
        return binary(op, x, y).map_or(Abs::MayFail, Abs::Exact);
    }
    Abs::from_bool_set(BoolSet {
        t: true,
        f: true,
        n: !(a.never_null() && b.never_null()),
    })
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
            require(
                a != Null && b != Null,
                "use 'is null' or 'is not null' instead of comparing with null",
            )?;
            require(a == b, &format!("incompatible types: {a:?} and {b:?}"))?;
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
fn binary<'a>(op: Op, a: Value<&'a [u8]>, b: Value<&'a [u8]>) -> Result<Value<&'a [u8]>> {
    use Op::*;
    if a == Value::Null || b == Value::Null {
        return Ok(Value::Null);
    }
    if matches!(op, Eq | Ne) {
        return Ok(Value::Bool(if op == Eq { a == b } else { a != b }));
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
    src: Facts<'a>,
    dst: Facts<'a>,
    src_path: &'a [u8],
    dst_path: &'a [u8],
    now: i128,
}
/// Which fields an expression may name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fields {
    /// `src.` fields: copy selection.
    Source,
    /// `src.` and `dst.` fields: update conditions.
    SourceAndDestination,
    /// A listed entry's own fields, bare or with `src.`: `find` and `ls`.
    Listing,
}
#[derive(Clone, Debug)]
pub(crate) struct Expression {
    root: Node,
}
impl Expression {
    pub fn compile(text: &str, destination: bool) -> Result<Self> {
        Self::compile_with(
            text,
            if destination {
                Fields::SourceAndDestination
            } else {
                Fields::Source
            },
        )
    }
    /// Compile a filter of listed entries, whose fields may be named
    /// without `src.`.
    pub fn compile_listing(text: &str) -> Result<Self> {
        Self::compile_with(text, Fields::Listing)
    }
    fn compile_with(text: &str, fields: Fields) -> Result<Self> {
        let root = parser::parse(text, fields)?;
        require(
            root.ty()? == Type::Bool,
            "expression must produce a boolean",
        )?;
        Ok(Self { root })
    }
    /// Path patterns that every path the expression selects matches: one
    /// for each `path glob` or `path =` condition joined to the rest by
    /// `and` alone, with no condition before it that may fail. Each pattern
    /// can match more paths than its condition does, never fewer, so a
    /// listing may skip whatever matches none of them, but must still
    /// evaluate the expression on what it lists.
    pub fn s3_path_pushdown(&self, now: i128) -> Vec<Vec<PathToken>> {
        let mut patterns = Vec::new();
        pushdown::conjuncts(&self.root, now, &mut patterns);
        patterns
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
                src: Facts::Complete(src),
                dst: Facts::Complete(dst),
                src_path,
                dst_path,
                now,
            })?
            .is_true()
    }
    fn evaluate_known(
        &self,
        src: Facts<'_>,
        src_path: &[u8],
        dst: Facts<'_>,
        dst_path: &[u8],
        now: i128,
    ) -> Result<Option<bool>> {
        match self.root.eval(&ContextValues {
            src,
            dst,
            src_path,
            dst_path,
            now,
        }) {
            Ok(value) => Ok(Some(value.is_true()?)),
            Err(error) if error.is::<NeedMetadata>() => Ok(None),
            Err(error) => Err(error),
        }
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
    /// Compile `--where` for `find` and `ls`: fields may be named without
    /// `src.`, and directories are filtered like other entries.
    pub fn compile_listing(selection: Option<&str>) -> Result<Self> {
        Ok(Self {
            selection: selection
                .map(|s| Expression::compile_listing(s).context("--where"))
                .transpose()?,
            update: None,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as i128,
        })
    }
    pub fn s3_path_pushdown(&self) -> Vec<Vec<PathToken>> {
        self.selection
            .as_ref()
            .map(|e| e.s3_path_pushdown(self.now))
            .unwrap_or_default()
    }
    /// Whether `--where` can select (or fail on) an `S3Directory` in a listing.
    /// When `false`, recursive S3 listings skip inferring virtual directories
    /// and omit trailing `/**` on pushed-down `path` patterns.
    pub fn may_select_s3_directory(&self) -> bool {
        let Some(expression) = &self.selection else {
            return true;
        };
        expression.root.eval_s3_dir(self.now).bool_set().t
    }
    /// Whether a listed entry passes `--where`. Unlike [`Self::selects`],
    /// directories are filtered too.
    pub fn selects_listing(&self, entry: &File, path: &[u8]) -> Result<bool> {
        self.selection
            .as_ref()
            .map_or(Ok(true), |e| {
                e.evaluate(entry, path, &File::default(), b"", self.now)
            })
            .context("--where")
    }
    /// As [`Self::selects_listing`], from what a listing shows. `None` means
    /// that evaluation reached a field the listing does not provide.
    pub fn selects_listing_known(&self, entry: Facts<'_>, path: &[u8]) -> Result<Option<bool>> {
        if let Facts::Complete(file) = entry {
            return self.selects_listing(file, path).map(Some);
        }
        let Some(expression) = &self.selection else {
            return Ok(Some(true));
        };
        expression
            .evaluate_known(entry, path, Facts::Unread, b"", self.now)
            .context("--where")
    }
    pub fn uses_source_s3_time(&self) -> bool {
        [&self.selection, &self.update]
            .into_iter()
            .flatten()
            .any(|e| e.root.uses_source_s3_time())
    }
    pub fn active(&self) -> bool {
        self.selection.is_some() || self.update.is_some()
    }
    pub fn selects(&self, src: &File, path: &[u8]) -> Result<bool> {
        if src.kind == Some(Kind::Dir) {
            return Ok(true);
        }
        self.selection
            .as_ref()
            .map_or(Ok(true), |e| {
                e.evaluate(src, path, &File::default(), b"", self.now)
            })
            .context("--where")
    }
    /// None means evaluation reached a field not provided by the listing.
    pub fn selects_known(&self, src: Facts<'_>, path: &[u8]) -> Result<Option<bool>> {
        if let Facts::Complete(file) = src {
            return self.selects(file, path).map(Some);
        }
        let Some(expression) = &self.selection else {
            return Ok(Some(true));
        };
        if matches!(
            src,
            Facts::S3Listing {
                directory_marker: true,
                ..
            }
        ) {
            // syq rejects file or symlink metadata under a marker-shaped key
            // when it reads the object, so the listing identifies a directory.
            // Directories bypass --where.
            return Ok(Some(true));
        }
        expression
            .evaluate_known(src, path, Facts::Unread, b"", self.now)
            .context("--where")
    }
    pub fn permits_known(
        &self,
        src: Facts<'_>,
        src_path: &[u8],
        dst: Facts<'_>,
        dst_path: &[u8],
    ) -> Result<Option<bool>> {
        self.update
            .as_ref()
            .map_or(Ok(Some(true)), |e| {
                e.evaluate_known(src, src_path, dst, dst_path, self.now)
            })
            .context("--copy-if")
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
