//! `syq map`: print a local source selection as an NDJSON mapping, one JSON
//! object per line.
//!
//! Emission is local and read-only, and destination-independent by design:
//! `dst` values are relative to the target container, so the same manifest
//! can be executed against any target with `syq cp --mapping`. Only `--as`
//! changes emitted values, by renaming the single selected root. Names must
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

use crate::cli::{native_basename, Args, Placement, SourceSelection};
use crate::fsops::{require_source_leaf_identity, rooted_entry_in_directory, rooted_source_entry};
use crate::proto::{Entry, Kind, OperatorSymlinkPolicy, SourceLeafIdentity};
use crate::rooted::{
    read_open_symlink, OperatorFinalComponent, OperatorResolver, PinnedPath, RelativePath, Root,
    OPERATOR_SYMLINK_FOLLOW_ADVICE,
};

#[derive(Serialize)]
struct TaggedPath<'a> {
    encoding: &'static str,
    value: &'a str,
}

#[derive(Serialize)]
struct MapRecord<'a> {
    src: TaggedPath<'a>,
    dst: TaggedPath<'a>,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime: Option<i64>,
}

struct MapSelection {
    root: Arc<Root>,
    relative: Vec<u8>,
    expected_leaf: Option<SourceLeafIdentity>,
    _leaf_object: Option<File>,
    emitted_source: Vec<u8>,
}

struct PendingMapEntry {
    root_relative: Vec<u8>,
    entry: Entry,
    metadata: crate::rooted::RootMetadata,
}

pub fn run(args: &Args) -> Result<i32> {
    let follow_src = args.follows_native_source_paths();
    let symlink_policy = if follow_src {
        OperatorSymlinkPolicy::FollowAll
    } else {
        OperatorSymlinkPolicy::Refuse
    };
    let base = pin_base(args, symlink_policy)?;
    let mut top_level_dst: HashSet<Vec<u8>> = HashSet::new();
    let destination_prefixes = args
        .locations
        .iter()
        .map(|location| {
            if location.selection == SourceSelection::Contents {
                return Ok(Vec::new());
            }
            let destination = match (args.placement, &args.native_map_target) {
                (Placement::As, Some(target)) => native_basename(target)
                    .ok_or_else(|| anyhow!("--as destination has no basename"))?
                    .to_vec(),
                _ => native_basename(&location.path)
                    .expect("parse validated that named selectors have a basename")
                    .to_vec(),
            };
            if !top_level_dst.insert(destination.clone()) {
                bail!(
                    "two selectors map to the same destination name {:?}",
                    String::from_utf8_lossy(&destination)
                );
            }
            Ok(destination)
        })
        .collect::<Result<Vec<_>>>()?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for (location, destination) in args.locations.iter().zip(destination_prefixes) {
        let selection = pin_selection(&base, location, follow_src, symlink_policy)?;
        hold_map_selection_for_test()?;
        emit_selection(location, selection, &destination, &mut out)?;
    }
    out.flush().context("writing mapping to stdout")?;
    Ok(0)
}

fn pin_base(args: &Args, symlink_policy: OperatorSymlinkPolicy) -> Result<File> {
    let path = args.native_map_cwd.as_deref().unwrap_or(b".");
    let mut hops = Vec::new();
    let selection = OperatorResolver::resolve_process(
        path,
        symlink_policy,
        OperatorFinalComponent::Directory,
        false,
        &mut hops,
    )
    .with_context(|| {
        format!(
            "resolve syq map source base {}",
            Path::new(OsStr::from_bytes(path)).display()
        )
    })?;
    match selection {
        PinnedPath::Directory(directory) => Ok(directory.into_parts().0),
        PinnedPath::Leaf(_) | PinnedPath::OpenFile(_) => {
            bail!("syq map source base is not a directory")
        }
        PinnedPath::Missing(_) => unreachable!("map base resolution requires an existing path"),
    }
}

fn pin_selection(
    base: &File,
    location: &crate::cli::Location,
    follow_src: bool,
    symlink_policy: OperatorSymlinkPolicy,
) -> Result<MapSelection> {
    // `-C` is a resolution base, not a containment boundary. A followed
    // selector may leave it; named selectors are checked separately below
    // because their emitted `src` still has to be relative to this base.
    let resolver = OperatorResolver::beneath(base, false, symlink_policy)?;
    let mut hops = Vec::new();
    let selection = resolver
        .resolve(
            &location.path,
            OperatorFinalComponent::Entry {
                follow_symlink: follow_src,
            },
            false,
            &mut hops,
        )
        .with_context(|| format!("resolve source {}", display(&location.path)))?;
    match selection {
        PinnedPath::Directory(directory) => {
            let emitted_source =
                emitted_source(location, follow_src, directory.resolved_relative())?;
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
                    "--src-src {} encounters a last-component symlink; {OPERATOR_SYMLINK_FOLLOW_ADVICE}",
                    display(&location.path)
                );
            }
            let emitted_source = emitted_source(location, follow_src, leaf.resolved_relative())?;
            let (parent, name, metadata, object) = leaf.into_parts();
            let object = object
                .context("this platform cannot retain the selected map source leaf safely")?;
            let symlink_target = if metadata.is_symlink() {
                Some(
                    read_open_symlink(&object)?.context(
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
                    symlink_target,
                }),
                _leaf_object: Some(object),
                emitted_source,
            })
        }
        PinnedPath::Missing(_) => unreachable!("map selection requires an existing path"),
        PinnedPath::OpenFile(_) => unreachable!("map selection never opens a procfs input"),
    }
}

fn emitted_source(
    location: &crate::cli::Location,
    follow_src: bool,
    resolved_relative: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if !follow_src || location.selection == SourceSelection::Contents {
        return Ok(location.path.clone());
    }
    let resolved_relative = resolved_relative.with_context(|| {
        format!(
            "followed source {} resolves outside the mapping source base; choose a source base that contains it",
            display(&location.path)
        )
    })?;
    if resolved_relative.is_empty() {
        bail!(
            "followed source {} resolves to the source base itself; select its contents instead",
            display(&location.path)
        );
    }
    Ok(resolved_relative.to_vec())
}

fn emit_selection(
    location: &crate::cli::Location,
    selection: MapSelection,
    destination_prefix: &[u8],
    out: &mut impl Write,
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
            bail!("--src-src {} is not a directory", display(&location.path));
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
    out: &mut impl Write,
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
    if let Some(ready) = std::env::var_os("SYQ_TEST_MAP_SELECTION_READY_FILE") {
        std::fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write map-selection-ready signal {}",
                Path::new(&ready).display()
            )
        })?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_MAP_SELECTION_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_map_selection_for_test() -> Result<()> {
    Ok(())
}

fn emit(out: &mut impl Write, src: &[u8], dst: &[u8], entry: &Entry) -> Result<()> {
    let src = utf8(src)?;
    let dst = utf8(dst)?;
    let kind = match entry.kind {
        Kind::Dir => "dir",
        Kind::File => "file",
        Kind::Symlink => "symlink",
        _ => "special",
    };
    let (size, mtime) = if kind == "file" {
        (Some(entry.size), Some(entry.mtime))
    } else {
        (None, None)
    };
    let record = MapRecord {
        src: tagged(src),
        dst: tagged(dst),
        kind,
        size,
        mtime,
    };
    serde_json::to_writer(&mut *out, &record).context("writing mapping to stdout")?;
    out.write_all(b"\n").context("writing mapping to stdout")?;
    Ok(())
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
