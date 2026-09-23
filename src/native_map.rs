//! `syq map`: print source selections as NDJSON mappings, one JSON object per line.
//!
//! Emission is read-only and destination-independent by design:
//! `dst` values are relative to the target container, so the same manifest
//! can be executed against any target with `syq cp --mapping`. Only `--as`
//! changes emitted values, by placing the single selected root at a chosen
//! container-relative path. Names must
//! be valid UTF-8; a non-UTF-8 name aborts emission with an error so that
//! text transforms downstream cannot silently corrupt a base64 value.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::cli::{native_basename, Args, SourceSelection};
use crate::fsops::{require_source_leaf_identity, rooted_entry_in_directory, rooted_source_entry};
use crate::proto::{Entry, Kind, OperatorSymlinkPolicy, SourceLeafIdentity};
use crate::rooted::{
    read_open_symlink, OperatorFinalComponent, OperatorResolver, PinnedPath, RelativePath, Root,
    OPERATOR_SYMLINK_FOLLOW_ADVICE,
};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[value(rename_all = "snake_case")]
pub enum Field {
    Kind,
    Size,
    Mtime,
    S3LastModified,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Source {
    pub path: Vec<u8>,
    pub selection: SourceSelection,
}

/// Endpoint-local input to the map walker. This travels only over the exactly
/// pinned helper protocol; manifests remain independent of helper versions.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Options {
    pub cwd: Option<Vec<u8>>,
    pub root: Option<Vec<u8>>,
    pub target: Option<Vec<u8>>,
    pub sources: Vec<Source>,
    pub follow: bool,
    pub include: Vec<Field>,
}

impl Options {
    pub fn from_args(args: &Args) -> Self {
        Self {
            cwd: args.native_map_cwd.clone(),
            root: args.native_map_root.clone(),
            target: args.native_map_target.clone(),
            sources: args
                .locations
                .iter()
                .map(|location| Source {
                    path: location.path.clone(),
                    selection: location.selection,
                })
                .collect(),
            follow: args.follows_native_source_paths(),
            include: args.native_map_include.clone(),
        }
    }

    pub fn destinations(&self) -> Result<Vec<Vec<u8>>> {
        let mut names = HashSet::new();
        self.sources
            .iter()
            .map(|source| {
                if source.selection == SourceSelection::Contents {
                    return Ok(Vec::new());
                }
                let destination = match &self.target {
                    Some(target) => target.clone(),
                    None => native_basename(&source.path)
                        .context("named source has no target basename")?
                        .to_vec(),
                };
                crate::mapping::validate_manifest_path(&destination, "dst")?;
                if !names.insert(destination.clone()) {
                    bail!(
                        "two selectors map to the same destination name {:?}",
                        String::from_utf8_lossy(&destination)
                    );
                }
                Ok(destination)
            })
            .collect()
    }
}

pub struct Emitter<'a, W> {
    pub out: &'a mut W,
    pub fields: &'a [Field],
}

impl<W: Write> Emitter<'_, W> {
    pub fn entry(
        &mut self,
        src: &[u8],
        dst: &[u8],
        kind: Option<&str>,
        size: Option<u64>,
        mtime: Option<i64>,
        s3_last_modified: Option<i64>,
    ) -> Result<()> {
        crate::mapping::validate_manifest_path(src, "src")?;
        crate::mapping::validate_manifest_path(dst, "dst")?;
        let record = MapRecord {
            src: tagged(utf8(src)?),
            dst: tagged(utf8(dst)?),
            kind: kind.filter(|_| self.fields.contains(&Field::Kind)),
            size: size.filter(|_| self.fields.contains(&Field::Size)),
            mtime: mtime.filter(|_| self.fields.contains(&Field::Mtime)),
            s3_last_modified: s3_last_modified
                .filter(|_| self.fields.contains(&Field::S3LastModified)),
        };
        serde_json::to_writer(&mut *self.out, &record).context("writing mapping to stdout")?;
        self.out
            .write_all(b"\n")
            .context("writing mapping to stdout")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct TaggedPath<'a> {
    encoding: &'static str,
    value: &'a str,
}

#[derive(Serialize)]
struct MapRecord<'a> {
    src: TaggedPath<'a>,
    dst: TaggedPath<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    s3_last_modified: Option<i64>,
}

struct MapSelection {
    root: Arc<Root>,
    relative: Vec<u8>,
    expected_leaf: Option<SourceLeafIdentity>,
    _leaf_object: Option<File>,
    emitted_source: Vec<u8>,
}

struct MapBase {
    directory: Option<File>,
    confined: bool,
}

struct PendingMapEntry {
    root_relative: Vec<u8>,
    entry: Entry,
    metadata: crate::rooted::RootMetadata,
}

pub fn run(args: &Args) -> Result<i32> {
    let options = Options::from_args(args);
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    if args.s3.is_some() {
        crate::s3::map::run(args, &options, &mut out)?;
    } else if args.locations[0].is_remote() {
        let endpoint = crate::transfer::endpoint(&args.locations[0], args)?;
        let mut connection = crate::transfer::connect_ctl(&endpoint, args)?;
        connection.send(crate::proto::Request::NativeMap(options))?;
        loop {
            match connection.recv()? {
                crate::proto::Response::NativeMapData(data) => out.write_all(&data)?,
                crate::proto::Response::NativeMapDone => break,
                crate::proto::Response::Err(error) => bail!("remote map: {error}"),
                other => bail!("unexpected remote map response: {other:?}"),
            }
        }
    } else {
        write_local(&options, &mut out)?;
    }
    out.flush().context("writing mapping to stdout")?;
    Ok(0)
}

pub fn write_local(options: &Options, out: &mut impl Write) -> Result<()> {
    let follow_src = options.follow;
    let symlink_policy = if follow_src {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    };
    let base = pin_base(options, &options.sources, symlink_policy)?;
    let destinations = options.destinations()?;
    let mut emitter = Emitter {
        out,
        fields: &options.include,
    };
    for (location, destination) in options.sources.iter().zip(destinations) {
        let selection = pin_selection(&base, location, follow_src, symlink_policy)?;
        hold_map_selection_for_test()?;
        emit_selection(location, selection, &destination, &mut emitter)?;
    }
    Ok(())
}

fn pin_base(
    args: &Options,
    locations: &[Source],
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<MapBase> {
    if args.cwd.is_some() && args.root.is_some() {
        bail!("--cwd and --root are mutually exclusive");
    }
    let (path, confined) = if let Some(path) = args.root.as_deref() {
        (Some(path), true)
    } else {
        (args.cwd.as_deref(), false)
    };
    if let Some(path) = path {
        if path.is_empty() {
            bail!("source base may not be empty");
        }
        if path.contains(&0) {
            bail!("source base contains NUL");
        }
    }
    let needs_base = confined
        || locations
            .iter()
            .any(|location| !crate::fsops::resolve(&location.path).is_absolute());
    if !needs_base {
        return Ok(MapBase {
            directory: None,
            confined,
        });
    }
    let path = crate::fsops::resolve(path.unwrap_or(b"."));
    let mut hops = Vec::new();
    let selection = OperatorResolver::resolve_process(
        path.as_os_str().as_bytes(),
        symlink_policy,
        OperatorFinalComponent::Directory,
        false,
        &mut hops,
    )
    .with_context(|| format!("resolve syq map source base {}", path.display()))?;
    match selection {
        PinnedPath::Directory(directory) => Ok(MapBase {
            directory: Some(directory.into_parts().0),
            confined,
        }),
        PinnedPath::Leaf(_) | PinnedPath::OpenFile(_) => {
            bail!("syq map source base is not a directory")
        }
        PinnedPath::Missing(_) => unreachable!("map base resolution requires an existing path"),
    }
}

fn pin_selection(
    base: &MapBase,
    location: &Source,
    follow_src: bool,
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<MapSelection> {
    let path = crate::fsops::resolve(&location.path);
    let mut hops = Vec::new();
    let selection = if path.is_absolute() {
        if base.confined {
            bail!(
                "source {} beneath --root must be relative",
                display(&location.path)
            );
        }
        OperatorResolver::resolve_process(
            path.as_os_str().as_bytes(),
            symlink_policy,
            OperatorFinalComponent::Entry {
                follow_symlink: follow_src,
            },
            false,
            &mut hops,
        )
    } else {
        OperatorResolver::beneath(
            base.directory
                .as_ref()
                .expect("relative map selection requires a pinned base"),
            base.confined,
            symlink_policy,
        )?
        .resolve(
            path.as_os_str().as_bytes(),
            OperatorFinalComponent::Entry {
                follow_symlink: follow_src,
            },
            false,
            &mut hops,
        )
    };
    let selection =
        selection.with_context(|| format!("resolve source {}", display(&location.path)))?;
    match selection {
        PinnedPath::Directory(directory) => {
            let emitted_source = emitted_source(location, directory.resolved_relative())?;
            let (directory, _) = directory.into_parts();
            Ok(MapSelection {
                root: Arc::new(Root::from_directory(directory)?),
                relative: Vec::new(),
                expected_leaf: None,
                _leaf_object: None,
                emitted_source,
            })
        }
        PinnedPath::Leaf(leaf) => {
            if location.selection == SourceSelection::Contents && leaf.metadata().is_symlink() {
                bail!(
                    "--srcs-in {} encounters a last-component symlink; {OPERATOR_SYMLINK_FOLLOW_ADVICE}",
                    display(&location.path)
                );
            }
            let emitted_source = emitted_source(location, leaf.resolved_relative())?;
            let (parent, name, metadata, object) = leaf.into_parts();
            if object.is_none() && !metadata.is_fifo() {
                bail!("this platform cannot retain the selected map source leaf safely");
            }
            let symlink_target = if metadata.is_symlink() {
                Some(
                    read_open_symlink(object.as_ref().expect("symlink object was checked"))?.context(
                        "this platform cannot snapshot a selected map symlink through its pinned object (macOS 13 or newer is required on Darwin)",
                    )?,
                )
            } else {
                None
            };
            Ok(MapSelection {
                root: Arc::new(Root::from_directory(parent)?),
                relative: name.as_bytes().to_vec(),
                expected_leaf: Some(SourceLeafIdentity {
                    dev: metadata.dev,
                    ino: metadata.ino,
                    file_type: metadata.file_type(),
                    symlink_atime: metadata.is_symlink().then_some(metadata.atime),
                    symlink_target,
                }),
                _leaf_object: object,
                emitted_source,
            })
        }
        PinnedPath::Missing(_) => unreachable!("map selection requires an existing path"),
        PinnedPath::OpenFile(_) => unreachable!("map selection never opens a procfs input"),
    }
}

fn emitted_source(location: &Source, resolved_relative: Option<&[u8]>) -> Result<Vec<u8>> {
    if location.selection == SourceSelection::Contents {
        return Ok(Vec::new());
    }
    let resolved_relative = resolved_relative.with_context(|| {
        format!(
            "source {} resolves outside the mapping source base; choose a source base that contains it",
            display(&location.path)
        )
    })?;
    if resolved_relative.is_empty() {
        bail!(
            "source {} resolves to the source base itself; select its contents instead",
            display(&location.path)
        );
    }
    Ok(resolved_relative.to_vec())
}

fn emit_selection(
    location: &Source,
    selection: MapSelection,
    destination_prefix: &[u8],
    out: &mut Emitter<'_, impl Write>,
) -> Result<()> {
    let contents = location.selection == SourceSelection::Contents;
    let scan_relative = RelativePath::new(&selection.relative)?;
    let metadata = selection.root.metadata(&scan_relative)?;
    if let Some(expected) = selection.expected_leaf.as_ref() {
        require_source_leaf_identity(expected, metadata)?;
    }
    let root_entry = rooted_source_entry(
        &selection.root,
        &scan_relative,
        Vec::new(),
        metadata,
        selection.expected_leaf.as_ref(),
    )?;
    if let Some(expected) = selection.expected_leaf.as_ref() {
        require_source_leaf_identity(expected, selection.root.metadata(&scan_relative)?)?;
    }
    if contents {
        if root_entry.kind != Kind::Dir {
            bail!("--srcs-in {} is not a directory", display(&location.path));
        }
    } else {
        crate::transfer::validate_native_source_type(
            &location.path,
            location.selection,
            root_entry.kind,
        )?;
        emit(
            out,
            &selection.emitted_source,
            destination_prefix,
            &root_entry,
        )?;
    }
    if root_entry.kind != Kind::Dir {
        return Ok(());
    }
    walk_directory(
        &selection.root,
        &selection.relative,
        metadata,
        &selection.emitted_source,
        destination_prefix,
        contents,
        out,
    )
}

/// Emit a descriptor-relative, byte-sorted depth-first walk. Pending entries
/// carry strict root-relative names and observed identities, never open parent
/// descriptors, so deep trees do not consume one fd per component. Each
/// directory is reopened beneath the retained root without following links
/// and checked against the identity observed by its opened parent.
fn walk_directory(
    root: &Root,
    scan_root: &[u8],
    scan_root_metadata: crate::rooted::RootMetadata,
    source_prefix: &[u8],
    destination_prefix: &[u8],
    contents: bool,
    out: &mut Emitter<'_, impl Write>,
) -> Result<()> {
    let mut pending = Vec::new();
    push_directory_children(root, scan_root, b"", scan_root_metadata, &mut pending)?;
    while let Some(PendingMapEntry {
        root_relative,
        entry,
        metadata,
    }) = pending.pop()
    {
        let relative = &entry.path;
        let source = if contents {
            relative.clone()
        } else {
            join_rel(source_prefix, relative)
        };
        let destination = if contents {
            relative.clone()
        } else {
            join_rel(destination_prefix, relative)
        };
        emit(out, &source, &destination, &entry)?;
        if entry.kind == Kind::Dir {
            push_directory_children(root, &root_relative, relative, metadata, &mut pending)?;
        }
    }
    Ok(())
}

fn push_directory_children(
    root: &Root,
    root_relative: &[u8],
    output_relative: &[u8],
    expected: crate::rooted::RootMetadata,
    pending: &mut Vec<PendingMapEntry>,
) -> Result<()> {
    let directory_relative = RelativePath::new(root_relative)?;
    let directory = root.open_directory_verified(&directory_relative, expected)?;
    let mut names = root.read_open_directory(&directory)?;
    names.sort();
    let mut children = Vec::with_capacity(names.len());
    for name in names {
        let metadata = root.metadata_in_directory(&directory, &name)?;
        let output_relative = join_rel(output_relative, &name);
        let entry = rooted_entry_in_directory(root, &directory, &name, output_relative, metadata)?;
        children.push(PendingMapEntry {
            root_relative: join_rel(root_relative, &name),
            entry,
            metadata,
        });
    }
    children.reverse();
    pending.extend(children);
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_map_selection_for_test() -> Result<()> {
    crate::fsops::test_race_barrier(
        "SYQ_TEST_MAP_SELECTION_READY_FILE",
        "SYQ_TEST_MAP_SELECTION_CONTINUE_FILE",
        "map selection",
    )
}

#[cfg(not(debug_assertions))]
fn hold_map_selection_for_test() -> Result<()> {
    Ok(())
}

fn emit(out: &mut Emitter<'_, impl Write>, src: &[u8], dst: &[u8], entry: &Entry) -> Result<()> {
    let kind = match entry.kind {
        Kind::Dir => "dir",
        Kind::File => "file",
        Kind::Symlink => "symlink",
        _ => "special",
    };
    out.entry(
        src,
        dst,
        Some(kind),
        (entry.kind == Kind::File).then_some(entry.size),
        (entry.kind == Kind::File).then_some(entry.mtime),
        None,
    )
}

fn tagged(value: &str) -> TaggedPath<'_> {
    TaggedPath {
        encoding: "utf-8",
        value,
    }
}

fn utf8(path: &[u8]) -> Result<&str> {
    std::str::from_utf8(path).map_err(|_| {
        anyhow!(
            "name {:?} is not valid UTF-8; syq map emits UTF-8 mappings only",
            String::from_utf8_lossy(path)
        )
    })
}

fn join_rel(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        return name.to_vec();
    }
    let mut joined = prefix.to_vec();
    joined.push(b'/');
    joined.extend_from_slice(name);
    joined
}

fn display(path: &[u8]) -> String {
    Path::new(OsStr::from_bytes(path)).display().to_string()
}
