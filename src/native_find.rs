//! `syq find` and `syq ls`: list entries beneath search roots on a local, SSH,
//! or S3 endpoint.
//!
//! A filesystem walk is descriptor-relative, never follows a symlink found
//! inside a directory, and holds only the entries of the directories on the
//! current path. Output streams as entries are found, in one of four forms:
//! plain paths, `--long` lines, `--json` objects, or `--null`-terminated raw
//! paths.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::fsops::{PinnedSource, SourceSelector};
use crate::proto::{Entry, Kind, OperatorSymlinkPolicy, SourceRootBase};
use crate::rooted::{RelativePath, Root};

/// A field `--include` adds to `--json` output.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[value(rename_all = "snake_case")]
pub enum Field {
    Kind,
    Size,
    Mtime,
    S3LastModified,
    Etag,
    Mode,
    Uid,
    Gid,
    Ctime,
    LinkTarget,
}

impl Field {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Kind => "kind",
            Self::Size => "size",
            Self::Mtime => "mtime",
            Self::S3LastModified => "s3_last_modified",
            Self::Etag => "etag",
            Self::Mode => "mode",
            Self::Uid => "uid",
            Self::Gid => "gid",
            Self::Ctime => "ctime",
            Self::LinkTarget => "link_target",
        }
    }

    /// Whether S3 gives the field when `--include` names it only through a
    /// HEAD request per object: stored metadata, and the kind of an object,
    /// which may be a symlink.
    pub(crate) fn needs_s3_head(self) -> bool {
        matches!(
            self,
            Self::Kind | Self::Mtime | Self::Mode | Self::Uid | Self::Gid
        )
    }
}

/// The JSON fields without `--include`: what a listing or `stat` returns.
const FILESYSTEM_FIELDS: &[Field] = &[Field::Kind, Field::Size, Field::Mtime];
const S3_FIELDS: &[Field] = &[Field::Kind, Field::Size, Field::S3LastModified, Field::Etag];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Format {
    /// One path per line.
    #[default]
    Plain,
    /// Kind, size, time and path, one entry per line.
    Long,
    /// One JSON object per line.
    Json,
    /// Raw paths, each followed by NUL.
    Null,
}

/// Endpoint-local input to the walk. A filesystem walk on an SSH endpoint
/// receives it over the exactly pinned helper protocol.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Options {
    pub cwd: Option<Vec<u8>>,
    pub root: Option<Vec<u8>>,
    /// Search roots as given; none means the base directory.
    pub paths: Vec<Vec<u8>>,
    pub follow: bool,
    /// The deepest level listed beneath each root; direct children are 1.
    pub depth: Option<u32>,
    /// Gitignore-style lines from `--ignore` and `--ignore-from`, in order.
    pub ignore: Vec<String>,
    pub where_expression: Option<String>,
    pub expression_now: i128,
    pub format: Format,
    /// Explicit `--include` fields; `None` selects the default JSON fields.
    pub include: Option<Vec<Field>>,
}

impl Options {
    /// Check fields against the endpoint: `s3_last_modified` and `etag` exist
    /// only on S3, and `ctime` and symlink targets only on filesystems.
    pub(crate) fn check_fields(&self, s3: bool) -> Result<()> {
        for field in self.include.iter().flatten() {
            match field {
                Field::S3LastModified | Field::Etag if !s3 => {
                    bail!("--include {} requires an S3 endpoint", field.name())
                }
                Field::Ctime | Field::LinkTarget if s3 => bail!(
                    "--include {} requires a filesystem endpoint; S3 does not record it",
                    field.name()
                ),
                _ => {}
            }
        }
        Ok(())
    }

    /// The JSON fields that output carries after `path`.
    pub(crate) fn fields(&self, s3: bool) -> Vec<Field> {
        match &self.include {
            Some(fields) => fields.clone(),
            None if s3 => S3_FIELDS.to_vec(),
            None => FILESYSTEM_FIELDS.to_vec(),
        }
    }
}

/// One listed entry, as output shows it. Each field is `None` when the
/// entry has no such value or the walk did not read it.
#[derive(Default)]
pub(crate) struct Record<'a> {
    pub path: &'a [u8],
    pub kind: &'static str,
    pub size: Option<u64>,
    pub mtime: Option<i64>,
    pub s3_last_modified: Option<i64>,
    pub etag: Option<&'a str>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub ctime: Option<i64>,
    pub link_target: Option<&'a [u8]>,
}

pub(crate) fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::File => "file",
        Kind::Dir => "dir",
        Kind::Symlink => "symlink",
        Kind::Fifo => "fifo",
        Kind::Socket => "socket",
        Kind::CharDev => "char",
        Kind::BlockDev => "block",
        Kind::Other => "other",
    }
}

/// Writes records in the chosen format.
pub(crate) struct Printer {
    format: Format,
    fields: Vec<Field>,
    s3: bool,
}

impl Printer {
    pub(crate) fn new(options: &Options, s3: bool) -> Self {
        Self {
            format: options.format,
            fields: options.fields(s3),
            s3,
        }
    }

    pub(crate) fn write(&self, out: &mut impl Write, record: &Record) -> Result<()> {
        match self.format {
            Format::Plain => {
                out.write_all(record.path)?;
                out.write_all(b"\n")?;
            }
            Format::Null => {
                out.write_all(record.path)?;
                out.write_all(b"\0")?;
            }
            Format::Long => {
                let size = match record.size {
                    Some(size) if record.kind != "dir" => crate::progress::human(size),
                    _ => "-".into(),
                };
                let time = if self.s3 {
                    record.s3_last_modified
                } else {
                    record.mtime
                };
                write!(out, "{:<7} {size:>9} {}  ", record.kind, utc(time))?;
                out.write_all(record.path)?;
                if let Some(target) = record.link_target {
                    out.write_all(b" -> ")?;
                    out.write_all(target)?;
                }
                out.write_all(b"\n")?;
            }
            Format::Json => {
                let wants = |field| self.fields.contains(&field);
                let json = Json {
                    path: utf8(record.path, "path")?,
                    kind: wants(Field::Kind).then_some(record.kind),
                    size: record.size.filter(|_| wants(Field::Size)),
                    mtime: record.mtime.filter(|_| wants(Field::Mtime)),
                    s3_last_modified: record
                        .s3_last_modified
                        .filter(|_| wants(Field::S3LastModified)),
                    etag: record.etag.filter(|_| wants(Field::Etag)),
                    mode: record.mode.filter(|_| wants(Field::Mode)),
                    uid: record.uid.filter(|_| wants(Field::Uid)),
                    gid: record.gid.filter(|_| wants(Field::Gid)),
                    ctime: record.ctime.filter(|_| wants(Field::Ctime)),
                    link_target: record
                        .link_target
                        .filter(|_| wants(Field::LinkTarget))
                        .map(|target| utf8(target, "symlink target"))
                        .transpose()?,
                };
                serde_json::to_writer(&mut *out, &json)?;
                out.write_all(b"\n")?;
            }
        }
        Ok(())
    }
}

/// A `--json` line: `path`, then the selected fields the entry has.
#[derive(serde::Serialize)]
struct Json<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_last_modified: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    etag: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ctime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_target: Option<&'a str>,
}

fn utf8<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        anyhow::anyhow!(
            "{what} {:?} is not valid UTF-8, which JSON cannot hold exactly; use --null to list raw names",
            String::from_utf8_lossy(bytes)
        )
    })
}

/// `YYYY-MM-DD HH:MM:SS` in UTC, or `-`.
fn utc(seconds: Option<i64>) -> String {
    seconds
        .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
        .map_or_else(
            || format!("{:<19}", "-"),
            |time| {
                format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                    time.year(),
                    u8::from(time.month()),
                    time.day(),
                    time.hour(),
                    time.minute(),
                    time.second()
                )
            },
        )
}

/// The path output shows for `relative` beneath a root shown as `root`.
pub(crate) fn join(root: &[u8], relative: &[u8]) -> Vec<u8> {
    if root.is_empty() {
        return relative.to_vec();
    }
    if relative.is_empty() {
        return root.to_vec();
    }
    let mut joined = Vec::with_capacity(root.len() + 1 + relative.len());
    joined.extend_from_slice(root);
    if !root.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(relative);
    joined
}

/// How output shows a root given as `path`: without trailing slashes,
/// except for `/` itself, and empty for the base directory.
pub(crate) fn root_display(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];
    if trimmed == b"." {
        b""
    } else {
        trimmed
    }
}

pub fn run(args: &crate::cli::Args) -> Result<i32> {
    let options = args
        .native_find
        .as_deref()
        .context("find options were not parsed")?;
    let mut out = std::io::BufWriter::new(crate::output::command_stdout());
    let unreadable = if args.s3.is_some() {
        crate::s3::find::run(args, options, &mut out)?;
        0
    } else if args
        .locations
        .first()
        .is_some_and(|location| location.is_remote())
    {
        let endpoint = crate::transfer::endpoint(&args.locations[0], args)?;
        let mut connection = crate::transfer::connect_ctl(&endpoint, args)?;
        connection.send(crate::proto::Request::NativeFind(options.clone()))?;
        let mut unreadable = 0;
        loop {
            match connection.recv()? {
                crate::proto::Response::NativeFindData(data) => {
                    out.write_all(&data)?;
                    out.flush()?;
                }
                crate::proto::Response::NativeFindUnreadable(message) => {
                    out.flush()?;
                    crate::output::diagnostic!("syq: {message}");
                    unreadable += 1;
                }
                crate::proto::Response::NativeFindDone => break,
                crate::proto::Response::Err(error) => bail!("remote find: {error}"),
                other => bail!("unexpected remote find response: {other:?}"),
            }
        }
        unreadable
    } else {
        write_local(options, &mut Terminal(&mut out))?
    };
    out.flush().context("writing to stdout")?;
    if unreadable > 0 {
        bail!(
            "{unreadable} {} could not be read; the listing is incomplete",
            if unreadable == 1 { "entry" } else { "entries" }
        );
    }
    Ok(0)
}

/// Where a filesystem walk writes: output, and reports of entries it skips.
pub trait Sink: Write {
    /// Report an entry the walk could not read and skipped, after the
    /// output written before it.
    fn unreadable(&mut self, message: String) -> Result<()>;
}

/// Output to stdout, and reports to stderr.
struct Terminal<'a, W>(&'a mut W);

impl<W: Write> Write for Terminal<'_, W> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.write(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<W: Write> Sink for Terminal<'_, W> {
    fn unreadable(&mut self, message: String) -> Result<()> {
        self.0.flush()?;
        crate::output::diagnostic!("syq: {message}");
        Ok(())
    }
}

/// A pinned search root and how output shows it.
struct Selection {
    root: Arc<Root>,
    relative: Vec<u8>,
    expected_leaf: Option<crate::proto::SourceLeafIdentity>,
    _leaf_object: Option<std::fs::File>,
    display: Vec<u8>,
}

/// How long output may wait in a buffer while a walk goes on.
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

struct Walk<'a, W> {
    out: &'a mut W,
    printer: Printer,
    policy: crate::expression::Policy,
    ignore: Option<ignore::gitignore::Gitignore>,
    depth: Option<u32>,
    read_link_targets: bool,
    skipped: usize,
    /// When output was last flushed, and whether any was written since.
    flushed: Instant,
    unflushed: bool,
}

struct Pending {
    root_relative: Vec<u8>,
    entry: Entry,
    metadata: crate::rooted::RootMetadata,
    depth: u32,
}

/// List every root on this machine. Output stops at the first error, except
/// that an entry that cannot be read is reported to `out` and skipped;
/// returns how many were.
pub fn write_local(options: &Options, out: &mut impl Sink) -> Result<usize> {
    options.check_fields(false)?;
    if options.depth == Some(0) {
        bail!("--depth must be at least 1");
    }
    let symlink_policy = if options.follow {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    };
    let paths: Vec<&[u8]> = if options.paths.is_empty() {
        vec![b"."]
    } else {
        options.paths.iter().map(Vec::as_slice).collect()
    };
    let selector = source_selector(options, &paths, symlink_policy)?;
    let mut policy =
        crate::expression::Policy::compile_listing(options.where_expression.as_deref())?;
    policy.now = options.expression_now;
    let mut walk = Walk {
        out,
        printer: Printer::new(options, false),
        read_link_targets: options.format == Format::Long
            || policy.selection.is_some()
            || options
                .include
                .as_ref()
                .is_some_and(|fields| fields.contains(&Field::LinkTarget)),
        policy,
        ignore: crate::scan::build_ignore(&options.ignore)?,
        depth: options.depth,
        skipped: 0,
        flushed: Instant::now(),
        unflushed: false,
    };
    // Check every root before writing anything, so that a missing one
    // fails before any output. Each is pinned again to list it, so many
    // roots do not hold descriptors open.
    for path in &paths {
        select(&selector, path, options.follow)?;
    }
    for path in &paths {
        let selection = select(&selector, path, options.follow)?;
        walk.root(selection)?;
    }
    Ok(walk.skipped)
}

fn source_selector(
    options: &Options,
    paths: &[&[u8]],
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<SourceSelector> {
    if options.cwd.is_some() && options.root.is_some() {
        bail!("--cwd and --root are mutually exclusive");
    }
    let base = SourceRootBase {
        path: options.root.clone().or_else(|| options.cwd.clone()),
        confined: options.root.is_some(),
    };
    base.validate()?;
    for path in paths {
        crate::cli::validate_native_source_selector(path, base.confined)?;
    }
    let needs_base = paths
        .iter()
        .any(|path| !crate::fsops::resolve(path).is_absolute());
    SourceSelector::new("syq find base", &base, None, symlink_policy, needs_base)
}

fn select(selector: &SourceSelector, path: &[u8], follow: bool) -> Result<Selection> {
    let resolved = crate::fsops::resolve(path);
    let pinned = selector.resolve(&resolved, follow, || {
        format!("cannot list {}", display(path))
    })?;
    let source = PinnedSource::new(pinned, false)?;
    Ok(Selection {
        root: Arc::new(Root::from_directory(source.directory)?),
        relative: source.relative,
        expected_leaf: source.expected_leaf,
        _leaf_object: source.object,
        display: root_display(path).to_vec(),
    })
}

impl<W: Sink> Walk<'_, W> {
    fn root(&mut self, selection: Selection) -> Result<()> {
        let (metadata, mut entry) = crate::scan::read_selected_root(
            &selection.root,
            &selection.relative,
            selection.expected_leaf.as_ref(),
        )?;
        if entry.kind != Kind::Dir {
            // A named non-directory is listed by itself, at depth 1.
            if crate::scan::selected_file_is_ignored(self.ignore.as_ref(), &selection.display) {
                return Ok(());
            }
            if !self.read_link_targets {
                entry.link = None;
            }
            return self.emit(&selection.display, &entry);
        }
        let mut pending = Vec::new();
        self.push_children(
            &selection.root,
            (&selection.relative, &selection.display),
            b"",
            metadata,
            0,
            &mut pending,
        )?;
        while let Some(Pending {
            root_relative,
            entry,
            metadata,
            depth,
        }) = pending.pop()
        {
            self.emit(&join(&selection.display, &entry.path), &entry)?;
            self.pace()?;
            if entry.kind == Kind::Dir && self.depth.is_none_or(|max| depth < max) {
                self.push_children(
                    &selection.root,
                    (&root_relative, &selection.display),
                    &entry.path,
                    metadata,
                    depth,
                    &mut pending,
                )?;
            }
        }
        Ok(())
    }

    /// Queue the children of the directory at `depth`, in byte order, apart
    /// from ignored ones. The directory is `root_relative` beneath `root`,
    /// and `output_relative` beneath the search root shown as `shown_root`.
    /// A directory or child that cannot be read is reported and skipped.
    fn push_children(
        &mut self,
        root: &Root,
        (root_relative, shown_root): (&[u8], &[u8]),
        output_relative: &[u8],
        expected: crate::rooted::RootMetadata,
        depth: u32,
        pending: &mut Vec<Pending>,
    ) -> Result<()> {
        let shown = |relative: &[u8]| match join(shown_root, relative) {
            path if path.is_empty() => ".".to_owned(),
            path => display(&path),
        };
        let names = (|| {
            let directory =
                root.open_directory_verified(&RelativePath::new(root_relative)?, expected)?;
            let mut names = root.read_open_directory(&directory)?;
            names.sort();
            Ok::<_, anyhow::Error>((directory, names))
        })();
        let (directory, names) = match names {
            Ok(found) => found,
            Err(error) if depth > 0 => {
                self.out.unreadable(format!(
                    "cannot read directory {}: {error:#}",
                    shown(output_relative)
                ))?;
                self.skipped += 1;
                return Ok(());
            }
            Err(error) => {
                return Err(
                    error.context(format!("cannot read directory {}", shown(output_relative)))
                )
            }
        };
        let start = pending.len();
        pending.reserve(names.len());
        // Inspect a bounded chunk at a time, so a wide directory holds one
        // chunk's results beside its pending entries rather than a second copy.
        for names in names.chunks(crate::scan::FIRST_BATCH) {
            let inspected = crate::scan::inspect_descriptor_children(
                root,
                &directory,
                output_relative,
                names,
                true,
                self.read_link_targets,
            );
            for (name, (relative, inspected)) in names.iter().zip(inspected) {
                let (entry, metadata) = match inspected {
                    Ok(inspected) => inspected,
                    Err(error) => {
                        self.out
                            .unreadable(format!("cannot read {}: {error:#}", shown(&relative)))?;
                        self.skipped += 1;
                        continue;
                    }
                };
                if let Some(ignore) = &self.ignore {
                    // Ignored directories are never entered, so only the
                    // entry itself needs matching.
                    let path = Path::new(OsStr::from_bytes(&entry.path));
                    if ignore.matched(path, entry.kind == Kind::Dir).is_ignore() {
                        continue;
                    }
                }
                pending.push(Pending {
                    root_relative: join(root_relative, name),
                    entry,
                    metadata,
                    depth: depth + 1,
                });
            }
        }
        pending[start..].reverse();
        Ok(())
    }

    /// Flush what was written since the last flush if that was a while
    /// ago, so that output shows while a slow walk goes on.
    fn pace(&mut self) -> Result<()> {
        if self.unflushed && self.flushed.elapsed() >= FLUSH_INTERVAL {
            self.out.flush()?;
            self.flushed = Instant::now();
            self.unflushed = false;
        }
        Ok(())
    }

    fn emit(&mut self, path: &[u8], entry: &Entry) -> Result<()> {
        if self.policy.selection.is_some()
            && !self
                .policy
                .selects_listing(&crate::expression::File::from_entry(entry), path)?
        {
            return Ok(());
        }
        self.unflushed = true;
        self.printer.write(
            self.out,
            &Record {
                path,
                kind: kind_name(entry.kind),
                size: (entry.kind == Kind::File).then_some(entry.size),
                mtime: Some(entry.mtime),
                s3_last_modified: None,
                etag: None,
                mode: Some(entry.mode & 0o7777),
                uid: Some(entry.uid),
                gid: Some(entry.gid),
                ctime: Some(entry.ctime),
                link_target: entry.link.as_deref(),
            },
        )
    }
}

fn display(path: &[u8]) -> String {
    Path::new(OsStr::from_bytes(path)).display().to_string()
}

#[cfg(test)]
mod tests;
