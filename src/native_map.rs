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
use std::fs::Metadata;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::cli::{native_basename, Args, Placement, SourceSelection};

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

pub fn run(args: &Args) -> Result<i32> {
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut top_level_dst: HashSet<Vec<u8>> = HashSet::new();
    let follow_src = args.follows_native_source_paths();
    for location in &args.locations {
        let full = full_path(args, &location.path);
        if !follow_src {
            crate::fsops::check_operator_path_no_symlinks(
                full.as_os_str().as_bytes(),
                location.selection != SourceSelection::Contents,
                false,
            )?;
        }
        if location.selection == SourceSelection::Contents {
            let md = metadata(&full, follow_src)
                .with_context(|| format!("--src-src {}", full.display()))?;
            if !md.is_dir() {
                bail!("--src-src {} is not a directory", full.display());
            }
            walk_children(&full, &location.path, b"", b"", &mut out)?;
        } else {
            let md = metadata(&full, follow_src)
                .with_context(|| format!("source {}", full.display()))?;
            crate::transfer::validate_native_source_type(
                &location.path,
                location.selection,
                metadata_kind(&md),
            )?;
            let src_name = if follow_src {
                resolved_named_source(args, &full)?
            } else {
                location.path.clone()
            };
            let dst_name = match (args.placement, &args.native_map_target) {
                (Placement::As, Some(target)) => native_basename(target)
                    .ok_or_else(|| anyhow!("--as destination has no basename"))?
                    .to_vec(),
                _ => native_basename(&location.path)
                    .expect("parse validated that named selectors have a basename")
                    .to_vec(),
            };
            if !top_level_dst.insert(dst_name.clone()) {
                bail!(
                    "two selectors map to the same destination name {:?}",
                    String::from_utf8_lossy(&dst_name)
                );
            }
            emit(&mut out, &src_name, &dst_name, &md)?;
            if md.is_dir() {
                walk_children(&full, &location.path, &src_name, &dst_name, &mut out)?;
            }
        }
    }
    out.flush().context("writing mapping to stdout")?;
    Ok(0)
}

/// Emit every descendant of `dir`, byte-sorted, parents before children.
/// `sel` is the selector spelling used only in error messages; `src_prefix`
/// and `dst_prefix` are the emitted relative prefixes (empty for a contents
/// root).
fn walk_children(
    dir: &Path,
    sel: &[u8],
    src_prefix: &[u8],
    dst_prefix: &[u8],
    out: &mut impl Write,
) -> Result<()> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        names.push(entry.file_name().as_bytes().to_vec());
    }
    names.sort();
    for name in names {
        let full = dir.join(OsStr::from_bytes(&name));
        let md = std::fs::symlink_metadata(&full)
            .with_context(|| format!("under {}", String::from_utf8_lossy(sel)))?;
        let src_rel = join_rel(src_prefix, &name);
        let dst_rel = join_rel(dst_prefix, &name);
        emit(out, &src_rel, &dst_rel, &md)?;
        if md.is_dir() {
            walk_children(&full, sel, &src_rel, &dst_rel, out)?;
        }
    }
    Ok(())
}

fn emit(out: &mut impl Write, src: &[u8], dst: &[u8], md: &Metadata) -> Result<()> {
    let src = utf8(src)?;
    let dst = utf8(dst)?;
    let file_type = md.file_type();
    let kind = if file_type.is_dir() {
        "dir"
    } else if file_type.is_file() {
        "file"
    } else if file_type.is_symlink() {
        "symlink"
    } else {
        "special"
    };
    let (size, mtime) = if kind == "file" {
        (Some(md.len()), Some(md.mtime()))
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

fn metadata_kind(md: &Metadata) -> crate::proto::Kind {
    use crate::proto::Kind;
    use std::os::unix::fs::FileTypeExt;
    let file_type = md.file_type();
    if file_type.is_dir() {
        Kind::Dir
    } else if file_type.is_file() {
        Kind::File
    } else if file_type.is_symlink() {
        Kind::Symlink
    } else if file_type.is_fifo() {
        Kind::Fifo
    } else if file_type.is_socket() {
        Kind::Socket
    } else if file_type.is_char_device() {
        Kind::CharDev
    } else if file_type.is_block_device() {
        Kind::BlockDev
    } else {
        Kind::Other
    }
}

fn metadata(path: &Path, follow: bool) -> std::io::Result<Metadata> {
    if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    }
}

/// Mapping entries are data and are never affected by the consumer's
/// `--follow`. Materialize a followed named selector as the referent's path
/// relative to the mapping base so the emitted manifest still selects the
/// same object when it is consumed.
fn resolved_named_source(args: &Args, full: &Path) -> Result<Vec<u8>> {
    let base = match &args.native_map_cwd {
        Some(cwd) => PathBuf::from(OsStr::from_bytes(cwd)),
        None => std::env::current_dir().context("resolve syq map working directory")?,
    };
    let base = std::fs::canonicalize(&base)
        .with_context(|| format!("resolve syq map source base {}", base.display()))?;
    let resolved = std::fs::canonicalize(full)
        .with_context(|| format!("resolve followed source {}", full.display()))?;
    let relative = resolved.strip_prefix(&base).map_err(|_| {
        anyhow!(
            "followed source {} resolves outside source base {}; pass its real path with a matching -C base",
            full.display(),
            base.display()
        )
    })?;
    let bytes = relative.as_os_str().as_bytes();
    if bytes.is_empty() {
        bail!(
            "followed source {} resolves to the source base itself; select its contents instead",
            full.display()
        );
    }
    Ok(bytes.to_vec())
}

fn full_path(args: &Args, selector: &[u8]) -> PathBuf {
    let full = match &args.native_map_cwd {
        Some(cwd) => crate::fsops::join(cwd, selector),
        None => selector.to_vec(),
    };
    PathBuf::from(OsStr::from_bytes(&full).to_os_string())
}
