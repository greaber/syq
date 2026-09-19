use super::*;

#[derive(Default)]
pub(super) struct NameMaxCache {
    pub(super) paths: HashMap<PathBuf, usize>,
    pub(super) devices: HashMap<u64, usize>,
}

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
    let mut v = root.to_vec();
    if !v.ends_with(b"/") {
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

pub(super) fn name_max(parent: &Path) -> usize {
    static CACHE: OnceLock<Mutex<NameMaxCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(NameMaxCache::default()));
    name_max_cached(parent, cache, |_candidate, directory| {
        let limit = unsafe { libc::fpathconf(directory.as_raw_fd(), libc::_PC_NAME_MAX) };
        if limit > 0 {
            limit as usize
        } else {
            COMMON_NAME_MAX
        }
    })
}

pub(super) fn name_max_cached(
    parent: &Path,
    cache: &Mutex<NameMaxCache>,
    query: impl Fn(&Path, &File) -> usize,
) -> usize {
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let key = lexical_absolute(parent);
    if let Some(limit) = cache.lock().unwrap().paths.get(&key).copied() {
        return limit;
    }

    // Resolve from a retained root one component at a time. A pathname lstat
    // would still follow symlinks in intermediate components when a descendant
    // exists. Planning refuses directory copies onto such a symlink; use the
    // containing real directory's limit until that conflict is reported.
    let Ok(root) = Root::open(Path::new("/")) else {
        return COMMON_NAME_MAX;
    };
    let Ok(relative) = key.strip_prefix(Path::new("/")) else {
        return COMMON_NAME_MAX;
    };
    let Ok(relative) = RelativePath::new(relative.as_os_str().as_bytes()) else {
        return COMMON_NAME_MAX;
    };
    let Ok((directory, consumed)) = root.open_nearest_directory(&relative) else {
        return COMMON_NAME_MAX;
    };
    let mut candidate = PathBuf::from("/");
    for component in key
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => Some(component),
            _ => None,
        })
        .take(consumed)
    {
        candidate.push(component);
    }
    let Ok(metadata) = directory.metadata() else {
        return COMMON_NAME_MAX;
    };
    let dev = metadata.dev();
    let cached = cache.lock().unwrap().devices.get(&dev).copied();
    let limit = cached.unwrap_or_else(|| query(&candidate, &directory));
    let mut cache = cache.lock().unwrap();
    if cache.paths.len() >= NAME_MAX_CACHE_CAP {
        cache.paths.clear();
    }
    cache.devices.entry(dev).or_insert(limit);
    cache.paths.insert(candidate, limit);
    cache.paths.insert(key, limit);
    limit
}

pub(super) fn lexical_absolute(path: &Path) -> PathBuf {
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

/// Private adjacent partial for this invocation and file. Keep a readable
/// basename prefix where space allows; the suffix always identifies the file
/// independently of prefix truncation.
pub fn partial_path(final_: &Path, copy_id: &CopyId) -> Result<PathBuf> {
    let parent = final_.parent().unwrap_or_else(|| Path::new(""));
    partial_path_with_name_max(final_, copy_id, name_max(parent))
}

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

/// Identify a temporary-name reservation independently of its readable prefix.
/// The opaque suffix already includes the complete destination spelling and
/// copy identity. Reserving it covers every shorter spelling after a rejected
/// filename without another filesystem lookup during collision preflight.
pub(crate) fn partial_reservation_key(path: &[u8]) -> Vec<u8> {
    let parent_end = path
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |at| at + 1);
    debug_assert!(is_partial_name(OsStr::from_bytes(&path[parent_end..])));
    let mut key = path[..parent_end].to_vec();
    key.extend_from_slice(&path[path.len() - 16..]);
    key
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
