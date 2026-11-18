use super::*;

pub fn resolve(p: &[u8]) -> PathBuf {
    if p.is_empty() {
        return PathBuf::from(".");
    }
    if p == b"~" || p.starts_with(b"~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let mut pb = PathBuf::from(home);
            if p.len() > 2 {
                pb.push(OsStr::from_bytes(&p[2..]));
            }
            return pb;
        }
    }
    PathBuf::from(OsStr::from_bytes(p))
}

pub fn path_bytes(p: &Path) -> PathBytes {
    p.as_os_str().as_bytes().to_vec()
}

pub fn join(root: &[u8], rel: &[u8]) -> PathBytes {
    if rel.is_empty() {
        return root.to_vec();
    }
    if root.is_empty() {
        return rel.to_vec();
    }
    let separator = !root.ends_with(b"/");
    // Queued file paths can live for the whole copy. Allocate their final
    // length instead of growing the prefix and retaining spare capacity.
    let mut v = Vec::with_capacity(root.len() + usize::from(separator) + rel.len());
    v.extend_from_slice(root);
    if separator {
        v.push(b'/');
    }
    v.extend_from_slice(rel);
    v
}

pub(super) fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bits = 0u32;
    let mut nbits = 0u8;
    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits != 0 {
        out.push(ALPHABET[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

/// `path` made absolute with `.` and `..` resolved by name, without looking
/// at the filesystem: `/a/b/../c` is `/a/c`, and `..` at `/` stays at `/`.
pub(crate) fn lexical_absolute(path: &Path) -> PathBuf {
    use std::path::Component;
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    normalized
}

pub(super) fn safe_prefix_len(name: &[u8], requested: usize) -> usize {
    let mut keep = requested.min(name.len());
    if let Ok(name) = std::str::from_utf8(name) {
        while !name.is_char_boundary(keep) {
            keep -= 1;
        }
    }
    keep
}

pub(super) fn path_component_budget(parent: &Path, component_limit: usize) -> usize {
    let parent_len = parent.as_os_str().as_bytes().len();
    let separator = usize::from(
        !parent.as_os_str().is_empty() && !parent.as_os_str().as_bytes().ends_with(b"/"),
    );
    let path_limit = libc::PATH_MAX as usize;
    let path_budget = path_limit
        .saturating_sub(1)
        .saturating_sub(parent_len)
        .saturating_sub(separator);
    component_limit.min(path_budget)
}

/// The sidecar name tests expect beside `final_` on a filesystem with the
/// common name limit.
#[cfg(test)]
pub fn partial_path(final_: &Path, copy_id: &CopyId) -> Result<PathBuf> {
    partial_path_with_name_max(final_, copy_id, COMMON_NAME_MAX)
}

/// Private adjacent partial for this invocation and file. Keep a readable
/// basename prefix where space allows; the suffix always identifies the file
/// independently of prefix truncation.
pub(crate) fn partial_path_with_name_max(
    final_: &Path,
    copy_id: &CopyId,
    component_limit: usize,
) -> Result<PathBuf> {
    let name = final_.file_name().map(OsStr::as_bytes).unwrap_or(b"root");
    // A fresh invocation nonce makes this suffix unpredictable. Hash the full
    // logical destination spelling so different names (including aliased
    // parent directories) have independent staging files. The readable prefix
    // and opaque suffix format stay compatible with older resume candidates.
    let mut hash = Sha256::new();
    hash.update(copy_id);
    hash.update(final_.as_os_str().as_bytes());
    let suffix = base32(&hash.finalize()[..10]);
    let parent = final_.parent().unwrap_or_else(|| Path::new(""));
    let budget = path_component_budget(parent, component_limit);
    let overhead = PARTIAL_MARKER.len() + suffix.len();
    if budget < overhead {
        bail!(
            "cannot create a partial beside {}: path is too long",
            final_.display()
        );
    }
    let keep = safe_prefix_len(name, budget.saturating_sub(overhead + 1));
    let mut component = Vec::with_capacity(budget.min(name.len() + overhead + 1));
    if keep > 0 {
        component.push(b'.');
        component.extend_from_slice(&name[..keep]);
    }
    component.extend_from_slice(PARTIAL_MARKER.as_bytes());
    component.extend_from_slice(suffix.as_bytes());
    Ok(parent.join(OsString::from_vec(component)))
}

/// An S3 download writes its partial file beside the destination as
/// `.syq-s3-HASH.partial`, with a 64-digit lowercase hex hash.
pub(crate) const S3_PARTIAL_PREFIX: &str = ".syq-s3-";
pub(crate) const S3_PARTIAL_SUFFIX: &str = ".partial";

pub(crate) fn is_s3_partial_name(name: &OsStr) -> bool {
    name.as_bytes()
        .strip_prefix(S3_PARTIAL_PREFIX.as_bytes())
        .and_then(|rest| rest.strip_suffix(S3_PARTIAL_SUFFIX.as_bytes()))
        .is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

/// Names of the partial files that copies and S3 downloads resume from:
/// pruning keeps them and `clean-partials` removes them.
pub(crate) fn is_resumable_partial_name(name: &OsStr) -> bool {
    is_partial_name(name) || is_s3_partial_name(name)
}

pub(super) const RECOVERY_PREFIX: &str = ".syq-swap-";

pub(crate) fn recovery_name(process: u32, counter: u64) -> String {
    format!("{RECOVERY_PREFIX}{process}-{counter}")
}

/// Names used for displaced entries during interrupted replacement. Keep
/// this separate from resumable partials: clean-partials must not remove them.
pub fn is_recovery_name(name: &OsStr) -> bool {
    let Some(suffix) = name.as_bytes().strip_prefix(RECOVERY_PREFIX.as_bytes()) else {
        return false;
    };
    let mut fields = suffix.split(|byte| *byte == b'-');
    let decimal = |field: Option<&[u8]>| {
        field.is_some_and(|field| !field.is_empty() && field.iter().all(u8::is_ascii_digit))
    };
    decimal(fields.next()) && decimal(fields.next()) && fields.next().is_none()
}

pub fn is_partial_name(name: &OsStr) -> bool {
    let name = name.as_bytes();
    name.starts_with(b".")
        && name
            .windows(PARTIAL_MARKER.len())
            .rposition(|part| part == PARTIAL_MARKER.as_bytes())
            .is_some_and(|at| {
                let suffix = &name[at + PARTIAL_MARKER.len()..];
                suffix.len() == 16
                    && suffix
                        .iter()
                        .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
            })
}

/// Absolute, normalized form of a path, resolved the way the kernel resolves
/// it: component by component, symlinks followed as they are met, so `..`
/// after a symlink pops the link's *target*. Once a component does not exist
/// the rest is normalized lexically. Stable across spellings of one place.
pub fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::from("/");
    let mut exists = true;
    for c in abs.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(name);
                if exists {
                    match fs::canonicalize(&out) {
                        Ok(real) => out = real,
                        Err(_) => exists = false,
                    }
                }
            }
        }
    }
    out
}

/// Apply the installed destination prefix without changing its spelling.
pub(crate) fn destination_relative_to(prefix: &[u8], path: &[u8]) -> Result<PathBytes> {
    let relative = if prefix == b"." {
        if path == b"." {
            b"".as_slice()
        } else if path.starts_with(b"/") {
            bail!("destination path is outside the retained root");
        } else {
            path.strip_prefix(b"./").unwrap_or(path)
        }
    } else if path == prefix {
        b"".as_slice()
    } else if prefix == b"/" {
        path.strip_prefix(b"/")
            .context("destination path is outside the retained root")?
    } else {
        path.strip_prefix(prefix)
            .and_then(|suffix| suffix.strip_prefix(b"/"))
            .context("destination path is outside the retained root")?
    };
    if relative.starts_with(b"/")
        || relative.contains(&0)
        || relative.split(|byte| *byte == b'/').any(|component| {
            !relative.is_empty()
                && (component.is_empty() || component == b"." || component == b"..")
        })
    {
        bail!("destination path contains an unsafe relative component");
    }
    Ok(relative.to_vec())
}
