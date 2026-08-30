//! Local filesystem operations. Used directly by the local endpoint and
//! by `syq --server` for remote endpoints, so both sides behave identically.

use crate::proto::*;
use crate::rooted::{RelativePath, Root, RootIdentity, RootMetadata};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use xxhash_rust::xxh3::{xxh3_128, xxh3_64, Xxh3};

pub const PARTIAL_MARKER: &str = ".syq-part.";
const FD_CACHE_MAX: usize = 16;
const COMMON_NAME_MAX: usize = 255;
const COMPACT_HASH_BYTES: usize = 10;
const NAME_MAX_CACHE_CAP: usize = 1024;

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

fn base32(bytes: &[u8]) -> String {
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

fn name_max(parent: &Path) -> usize {
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let key = parent.to_path_buf();
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(limit) = cache.lock().unwrap().get(&key).copied() {
        return limit;
    }
    // Preflight often runs before mapped destination subdirectories have been
    // created. Query the nearest existing directory on the same path instead
    // of silently assuming 255; absent a concurrent mount change, descendants
    // inherit that filesystem's component limit.
    let query_parent = nearest_existing_directory(parent);
    let Ok(c_parent) = cstr(&query_parent) else {
        return COMMON_NAME_MAX;
    };
    let limit = unsafe { libc::pathconf(c_parent.as_ptr(), libc::_PC_NAME_MAX) };
    let limit = if limit > 0 {
        limit as usize
    } else {
        COMMON_NAME_MAX
    };
    let mut cache = cache.lock().unwrap();
    if cache.len() >= NAME_MAX_CACHE_CAP {
        cache.clear();
    }
    cache.insert(key, limit);
    limit
}

fn nearest_existing_directory(path: &Path) -> PathBuf {
    let mut candidate = if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path.to_path_buf()
    };
    loop {
        // An in-tree symlink is replaced during planning, not traversed. Use
        // lstat semantics here too so preflight and the eventual worker query
        // the containing filesystem rather than the symlink target.
        if fs::symlink_metadata(&candidate).is_ok_and(|metadata| metadata.is_dir()) {
            return candidate;
        }
        if !candidate.pop() || candidate.as_os_str().is_empty() {
            return PathBuf::from(".");
        }
    }
}

fn safe_prefix_len(name: &[u8], requested: usize) -> usize {
    let mut keep = requested.min(name.len());
    if let Ok(name) = std::str::from_utf8(name) {
        while !name.is_char_boundary(keep) {
            keep -= 1;
        }
    }
    keep
}

fn path_component_budget(parent: &Path, component_limit: usize) -> usize {
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

/// Adjacent deterministic sidecar for this logical job. The common form keeps
/// both the destination basename and job ID visible. Long basenames are
/// truncated and disambiguated; near PATH_MAX a compact combined digest keeps
/// a little more of rsync's practical path reach.
pub fn partial_path(final_: &Path, partial_id: &PartialId) -> Result<PathBuf> {
    let parent = final_.parent().unwrap_or_else(|| Path::new(""));
    partial_path_with_name_max(final_, partial_id, name_max(parent))
}

fn partial_path_with_name_max(
    final_: &Path,
    partial_id: &PartialId,
    component_limit: usize,
) -> Result<PathBuf> {
    let name = final_.file_name().map(OsStr::as_bytes).unwrap_or(b"root");
    let job_id = base32(partial_id);
    let mut normal = Vec::with_capacity(1 + name.len() + PARTIAL_MARKER.len() + job_id.len());
    normal.push(b'.');
    normal.extend_from_slice(name);
    normal.extend_from_slice(PARTIAL_MARKER.as_bytes());
    normal.extend_from_slice(job_id.as_bytes());

    let parent = final_.parent().unwrap_or_else(|| Path::new(""));
    let budget = path_component_budget(parent, component_limit);
    let component = if normal.len() <= budget {
        normal
    } else {
        let basename_hash = Sha256::digest(name);
        let basename_hash = base32(&basename_hash[..12]);
        let overhead = 1 + 1 + basename_hash.len() + PARTIAL_MARKER.len() + job_id.len();
        if budget > overhead {
            let keep = safe_prefix_len(name, budget - overhead);
            let mut shortened = Vec::with_capacity(budget);
            shortened.push(b'.');
            shortened.extend_from_slice(&name[..keep]);
            shortened.push(b'.');
            shortened.extend_from_slice(basename_hash.as_bytes());
            shortened.extend_from_slice(PARTIAL_MARKER.as_bytes());
            shortened.extend_from_slice(job_id.as_bytes());
            shortened
        } else {
            let mut hash = Sha256::new();
            hash.update(partial_id);
            hash.update([0]);
            hash.update(name);
            let digest = hash.finalize();
            let compact = format!("{PARTIAL_MARKER}{}", base32(&digest[..COMPACT_HASH_BYTES]));
            if compact.len() > budget {
                bail!(
                    "cannot create a safe partial name beside {}: path is too long",
                    final_.display()
                );
            }
            compact.into_bytes()
        }
    };
    let component = OsString::from_vec(component);
    Ok(if parent.as_os_str().is_empty() {
        PathBuf::from(component)
    } else {
        parent.join(component)
    })
}

pub fn is_partial_name(name: &OsStr) -> bool {
    let b = name.as_bytes();
    let valid_id = |id: &[u8], len: usize| {
        id.len() == len
            && id
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    };
    if !b.starts_with(b".") {
        return false;
    }
    if let Some(pos) = b
        .windows(PARTIAL_MARKER.len())
        .rposition(|part| part == PARTIAL_MARKER.as_bytes())
    {
        let id = &b[pos + PARTIAL_MARKER.len()..];
        return if pos == 0 {
            valid_id(id, 16)
        } else {
            valid_id(id, 26)
        };
    }
    false
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

pub fn entry_from_meta(rel: PathBytes, full: &Path, md: &fs::Metadata) -> Entry {
    let ft = md.file_type();
    let kind = if ft.is_dir() {
        Kind::Dir
    } else if ft.is_file() {
        Kind::File
    } else if ft.is_symlink() {
        Kind::Symlink
    } else {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            Kind::Fifo
        } else if ft.is_socket() {
            Kind::Socket
        } else if ft.is_char_device() {
            Kind::CharDev
        } else if ft.is_block_device() {
            Kind::BlockDev
        } else {
            Kind::Other
        }
    };
    let link = if kind == Kind::Symlink {
        fs::read_link(full)
            .ok()
            .map(|t| t.into_os_string().into_vec())
    } else {
        None
    };
    Entry {
        path: rel,
        kind,
        size: if kind == Kind::File { md.len() } else { 0 },
        mtime: md.mtime(),
        mtime_nsec: md.mtime_nsec() as u32,
        mode: md.mode(),
        uid: md.uid(),
        gid: md.gid(),
        rdev: md.rdev(),
        dev: md.dev(),
        ino: md.ino(),
        ctime: md.ctime(),
        ctime_nsec: md.ctime_nsec() as u32,
        link,
    }
}

pub fn lstat_entry(rel: PathBytes, full: &Path) -> io::Result<Entry> {
    let md = fs::symlink_metadata(full)?;
    Ok(entry_from_meta(rel, full, &md))
}

fn errstr(e: &anyhow::Error) -> String {
    format!("{e:#}")
}

fn cstr(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| anyhow!("path contains NUL"))
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub struct FsOps {
    fds: HashMap<FdKey, File>,
    fd_order: Vec<FdKey>,
    /// One final-file descriptor retained between the hash response and the
    /// controller's decision to repair or accept that exact inode.
    held_basis: Option<HeldBasis>,
}

struct HeldBasis {
    path: PathBuf,
    partial_id: PartialId,
    file: File,
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct FdKey {
    path: PathBuf,
    /// Source files and partials get a fresh cache entry after a source-change
    /// retry. An old descriptor may point at an inode that was renamed away.
    attempt: u32,
    /// Keep a validated sidecar from sharing an unchecked cache entry.
    private: bool,
}

struct PartialTarget<'a> {
    path: &'a [u8],
    id: &'a PartialId,
    guard: Option<&'a ContainerGuard>,
}

struct TargetMutation<'a> {
    condition: TargetCondition,
    guard: Option<&'a ContainerGuard>,
}

impl Default for FsOps {
    fn default() -> Self {
        Self::new()
    }
}

impl FsOps {
    pub fn new() -> Self {
        FsOps {
            fds: HashMap::new(),
            fd_order: Vec::new(),
            held_basis: None,
        }
    }

    fn cached(&mut self, p: &Path, write: bool, attempt: u32, private: bool) -> Result<&File> {
        let key = FdKey {
            path: p.to_path_buf(),
            attempt,
            private,
        };
        if !self.fds.contains_key(&key) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            let f = open_existing_regular(p, write)?;
            if private {
                require_safe_partial(&f, p)?;
            }
            self.fds.insert(key.clone(), f);
            self.fd_order.push(key.clone());
        }
        Ok(self.fds.get(&key).unwrap())
    }

    fn uncache(&mut self, p: &Path) -> Option<File> {
        let mut removed = None;
        self.fd_order.retain(|key| {
            if key.path == p {
                removed = self.fds.remove(key).or(removed.take());
                false
            } else {
                true
            }
        });
        removed
    }

    fn create_container(&mut self, path: &[u8], mode: u32) -> Result<ContainerGuard> {
        let target = resolve(path);
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create parent {}", parent.display()))?;
            }
        }
        let (parent, relative) = exact_parent(&target)?;
        // The container has to remain writable while descendants are copied.
        // Deferred directory metadata restores the requested final mode.
        let identity = parent.create_directory_noreplace(&relative, (mode & 0o7777) | 0o700)?;
        hold_after_created_container_for_test(&target)?;
        Ok(ContainerGuard {
            root: path.to_vec(),
            dev: identity.dev,
            ino: identity.ino,
        })
    }

    fn cached_rooted(
        &mut self,
        label: &Path,
        root: &Root,
        relative: &RelativePath,
        attempt: u32,
        private: bool,
    ) -> Result<&File> {
        let key = FdKey {
            path: label.to_path_buf(),
            attempt,
            private,
        };
        if !self.fds.contains_key(&key) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            let file = root.open_regular_write(relative, false)?;
            if private {
                require_safe_partial(&file, label)?;
                let named = root.metadata(relative)?;
                let opened = file.metadata()?;
                if opened.dev() != named.dev || opened.ino() != named.ino {
                    bail!("partial {} changed while opening it", label.display());
                }
            }
            self.fds.insert(key.clone(), file);
            self.fd_order.push(key.clone());
        }
        Ok(self.fds.get(&key).unwrap())
    }

    /// Batches are statted on several threads: on network filesystems each
    /// lstat is a round trip and the planner would otherwise starve the workers.
    pub fn stat_many(&mut self, paths: &[PathBytes], follow: bool) -> Vec<Option<Entry>> {
        parallel_map(paths, |p| {
            let full = resolve(p);
            let md = if follow {
                fs::metadata(&full)
            } else {
                fs::symlink_metadata(&full)
            };
            md.ok().map(|md| entry_from_meta(Vec::new(), &full, &md))
        })
    }

    pub fn partial_paths(
        &mut self,
        paths: &[PathBytes],
        partial_id: &PartialId,
    ) -> Vec<std::result::Result<PathBytes, String>> {
        parallel_map(paths, |path| {
            let requested = Path::new(OsStr::from_bytes(path));
            partial_path(&resolve(path), partial_id)
                .map(|resolved| {
                    let name = resolved.file_name().expect("partial always has a name");
                    let parent = requested.parent().unwrap_or_else(|| Path::new(""));
                    path_bytes(&parent.join(name))
                })
                .map_err(|error| format!("{error:#}"))
        })
    }

    /// Ops within a batch are independent (the planner orders batches so that
    /// parents come first), so they run in parallel too.
    pub fn apply(&mut self, ops: &[Op], guard: Option<&ContainerGuard>) -> Vec<Option<String>> {
        // SetMeta depends on the object existing, so create everything first,
        // then apply metadata — otherwise a parallel SetMeta can beat its
        // Symlink/Mknod/Mkdir. Both phases still run in parallel internally.
        let is_meta = |op: &Op| matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. });
        let is_guarded_create = |op: &Op| match op {
            Op::Mkdir { condition, .. }
            | Op::Symlink { condition, .. }
            | Op::Mknod { condition, .. } => *condition != TargetCondition::Any,
            _ => false,
        };
        let guarded_idx: Vec<usize> = (0..ops.len())
            .filter(|&i| !is_meta(&ops[i]) && is_guarded_create(&ops[i]))
            .collect();
        let create_idx: Vec<usize> = (0..ops.len())
            .filter(|&i| !is_meta(&ops[i]) && !is_guarded_create(&ops[i]))
            .collect();
        let meta_idx: Vec<usize> = (0..ops.len()).filter(|&i| is_meta(&ops[i])).collect();
        let mut out: Vec<Option<String>> = vec![None; ops.len()];
        let gres = parallel_map(&guarded_idx, |&i| {
            apply_one(&ops[i], guard).err().as_ref().map(errstr)
        });
        for (i, r) in guarded_idx.iter().zip(gres) {
            out[*i] = r;
        }
        if guarded_idx.iter().any(|&i| out[i].is_some()) {
            for i in create_idx.iter().chain(meta_idx.iter()) {
                out[*i] =
                    Some("operation skipped because the placement-root precondition failed".into());
            }
            return out;
        }
        let cres = parallel_map(&create_idx, |&i| {
            apply_one(&ops[i], guard).err().as_ref().map(errstr)
        });
        for (i, r) in create_idx.iter().zip(cres) {
            out[*i] = r;
        }
        let mres = parallel_map(&meta_idx, |&i| {
            apply_one(&ops[i], guard).err().as_ref().map(errstr)
        });
        for (i, r) in meta_idx.iter().zip(mres) {
            out[*i] = r;
        }
        out
    }

    fn _unused_apply_one(&mut self, op: &Op) -> Result<()> {
        apply_one(op, None)
    }
}

fn op_path(op: &Op) -> &[u8] {
    match op {
        Op::Mkdir { path, .. }
        | Op::Symlink { path, .. }
        | Op::Mknod { path, .. }
        | Op::SetMeta { path, .. }
        | Op::SetFileMetaIfSame { path, .. }
        | Op::Remove { path }
        | Op::Rmdir { path }
        | Op::Unlink { path } => path,
    }
}

fn apply_one(op: &Op, guard: Option<&ContainerGuard>) -> Result<()> {
    #[cfg(debug_assertions)]
    if matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. }) {
        fail_set_meta_for_test(&resolve(op_path(op)))?;
    }
    if let Some(guard) = guard {
        let target = guarded_target(op_path(op), guard)?;
        return apply_one_rooted(op, &target);
    }
    apply_one_unrooted(op)
}

fn apply_one_unrooted(op: &Op) -> Result<()> {
    {
        match op {
            Op::Mkdir {
                path,
                mode,
                condition,
            } => {
                let p = resolve(path);
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() && !parent.exists() {
                        fs::create_dir_all(parent)?;
                    }
                }
                // The orchestrator resolves an explicitly supplied root
                // symlink. Symlinks found inside the destination tree are
                // payload conflicts and must be replaced, never traversed.
                match condition {
                    TargetCondition::Absent => mkdir(&p, *mode).map_err(Into::into),
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let md = require_target_condition(&p, *condition)?
                            .expect("matching target condition returns metadata");
                        if !md.is_dir() {
                            bail!(
                                "target {} cannot change type under --as-existing",
                                p.display()
                            );
                        }
                        make_dir_writable(&p, &md)
                    }
                    TargetCondition::Any => match fs::symlink_metadata(&p) {
                        Ok(md) if md.is_dir() => make_dir_writable(&p, &md),
                        Ok(_) => {
                            fs::remove_file(&p)?;
                            mkdir_or_existing_dir(&p, *mode)
                        }
                        Err(_) => mkdir_or_existing_dir(&p, *mode),
                    },
                }
                .with_context(|| format!("mkdir {}", p.display()))
            }
            Op::Symlink {
                path,
                target,
                condition,
            } => {
                let p = resolve(path);
                match condition {
                    TargetCondition::Any => match fs::symlink_metadata(&p) {
                        Ok(md) if md.is_dir() => fs::remove_dir(&p)?,
                        Ok(_) => fs::remove_file(&p)?,
                        Err(_) => {}
                    },
                    TargetCondition::Absent => {}
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let metadata = require_target_condition(&p, *condition)?
                            .expect("matching target condition returns metadata");
                        if !metadata.file_type().is_symlink() {
                            bail!(
                                "target {} cannot change type under --as-existing",
                                p.display()
                            );
                        }
                        replace_exact_symlink(&p, target, *condition)?;
                        return Ok(());
                    }
                }
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &p)
                    .with_context(|| format!("symlink {}", p.display()))
            }
            Op::Mknod {
                path,
                mode,
                rdev,
                condition,
            } => {
                let p = resolve(path);
                match condition {
                    TargetCondition::Any => match fs::symlink_metadata(&p) {
                        Ok(md) if md.is_dir() => fs::remove_dir(&p)?,
                        Ok(_) => fs::remove_file(&p)?,
                        Err(_) => {}
                    },
                    TargetCondition::Absent => {}
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let metadata = require_target_condition(&p, *condition)?
                            .expect("matching target condition returns metadata");
                        if file_type_bits(metadata.mode()) != file_type_bits(*mode) {
                            bail!(
                                "target {} cannot change type under --as-existing",
                                p.display()
                            );
                        }
                        replace_exact_node(&p, *mode, *rdev, *condition)?;
                        return Ok(());
                    }
                }
                let c = cstr(&p)?;
                let r =
                    unsafe { libc::mknod(c.as_ptr(), *mode as libc::mode_t, *rdev as libc::dev_t) };
                if r != 0 {
                    return Err(io::Error::last_os_error())
                        .with_context(|| format!("mknod {}", p.display()));
                }
                Ok(())
            }
            Op::SetMeta {
                path,
                meta,
                flags,
                condition,
            } => {
                let p = resolve(path);
                match condition {
                    TargetCondition::Any => set_meta_path(&p, meta, *flags),
                    TargetCondition::Absent => {
                        bail!("target {} appeared before metadata update", p.display())
                    }
                    TargetCondition::Matches { .. }
                    | TargetCondition::MatchesFingerprint { .. } => {
                        let file = OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                            .open(&p)
                            .with_context(|| format!("open {} for metadata", p.display()))?;
                        require_open_target(&file, &p, *condition)?;
                        set_meta_file(&file, meta, *flags)
                    }
                }
                .with_context(|| format!("set metadata {}", p.display()))
            }
            Op::SetFileMetaIfSame {
                path,
                condition,
                meta,
                flags,
            } => {
                let p = resolve(path);
                #[cfg(debug_assertions)]
                if let Some(ready) = std::env::var_os("SYQ_TEST_QUICK_META_READY_FILE") {
                    fs::write(&ready, b"ready").with_context(|| {
                        format!(
                            "write quick-metadata-ready signal {}",
                            Path::new(&ready).display()
                        )
                    })?;
                }
                #[cfg(debug_assertions)]
                if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_QUICK_META_MS") {
                    if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                        std::thread::sleep(std::time::Duration::from_millis(ms));
                    }
                }
                let file = match open_metadata_handle(&p) {
                    Ok(file) => file,
                    Err(open_error) => {
                        // Preserve the useful open error only while the
                        // planner's target is still present.
                        require_target_condition(&p, *condition)?;
                        return Err(open_error)
                            .with_context(|| format!("open {} for metadata repair", p.display()));
                    }
                };
                let md = file.metadata()?;
                if !md.file_type().is_file() {
                    bail!("destination {} changed before metadata repair", p.display());
                }
                require_open_target(&file, &p, *condition)?;
                set_meta_handle(&file, meta, *flags)
                    .with_context(|| format!("set metadata {}", p.display()))?;
                require_named_target_identity(&file, &p, *condition)
            }
            Op::Rmdir { path } => {
                let p = resolve(path);
                match fs::remove_dir(&p) {
                    // Already gone (a concurrent removal): the desired end state.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                    r => r.with_context(|| format!("rmdir {}", p.display())),
                }
            }
            // Remove follows the path's current type and may recurse. Planned
            // deletion paths use Unlink/Rmdir below so a type change fails
            // safely instead of broadening the selected deletion scope.
            Op::Remove { path } => {
                let p = resolve(path);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => fs::remove_dir_all(&p)?,
                    Ok(_) => fs::remove_file(&p)?,
                    Err(_) => {}
                }
                Ok(())
            }
            Op::Unlink { path } => {
                let p = resolve(path);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => {
                        bail!("{}: is now a directory; not deleting it", p.display())
                    }
                    Ok(_) => {
                        fs::remove_file(&p).with_context(|| format!("unlink {}", p.display()))?
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).with_context(|| format!("unlink {}", p.display())),
                }
                Ok(())
            }
        }
    }
}

struct GuardedTarget {
    root: Root,
    root_path: PathBuf,
    relative: RelativePath,
    label: PathBuf,
}

fn guarded_target(path: &[u8], guard: &ContainerGuard) -> Result<GuardedTarget> {
    hold_before_guarded_mutation_for_test(path)?;
    let root_path = resolve(&guard.root);
    let target = resolve(path);
    let relative = relative_under(&root_path, &target)?;
    let root = Root::open_verified(
        &root_path,
        RootIdentity {
            dev: guard.dev,
            ino: guard.ino,
        },
    )?;
    Ok(GuardedTarget {
        root,
        root_path,
        relative,
        label: target,
    })
}

fn relative_under(root: &Path, target: &Path) -> Result<RelativePath> {
    let relative = target.strip_prefix(root).with_context(|| {
        format!(
            "target {} is outside guarded root {}",
            target.display(),
            root.display()
        )
    })?;
    RelativePath::new(relative.as_os_str().as_bytes())
}

fn apply_one_rooted(op: &Op, target: &GuardedTarget) -> Result<()> {
    let root = &target.root;
    let path = &target.relative;
    match op {
        Op::Mkdir { mode, .. } => {
            if path.is_empty() {
                let metadata = root.metadata(path)?;
                if metadata.mode & 0o700 != 0o700 {
                    root.chmod(path, metadata.mode | 0o700)?;
                }
                return Ok(());
            }
            match root.metadata_optional(path)? {
                Some(metadata) if metadata.is_dir() => {
                    if metadata.mode & 0o700 != 0o700 {
                        let directory = root.open_metadata(path)?;
                        require_rooted_metadata(&directory, metadata, &target.label)?;
                        set_mode_handle(&directory, metadata.mode | 0o700)?;
                    }
                    Ok(())
                }
                Some(_) => {
                    root.unlink(path)?;
                    root.create_directory(path, (*mode & 0o7777) | 0o700)
                }
                None => root.create_directory(path, (*mode & 0o7777) | 0o700),
            }
        }
        Op::Symlink { target: link, .. } => {
            if let Some(metadata) = root.metadata_optional(path)? {
                if metadata.is_dir() {
                    root.remove_directory(path)?;
                } else {
                    root.unlink(path)?;
                }
            }
            root.create_symlink(path, link)
        }
        Op::Mknod { mode, rdev, .. } => {
            if let Some(metadata) = root.metadata_optional(path)? {
                if metadata.is_dir() {
                    root.remove_directory(path)?;
                } else {
                    root.unlink(path)?;
                }
            }
            root.create_node(path, *mode, *rdev)
        }
        Op::SetMeta { meta, flags, .. } => set_meta_rooted(target, meta, *flags),
        Op::SetFileMetaIfSame {
            condition,
            meta,
            flags,
            ..
        } => {
            let file = root.open_metadata(path)?;
            if !file.metadata()?.file_type().is_file() {
                bail!(
                    "destination {} changed before metadata repair",
                    target.label.display()
                );
            }
            require_open_target(&file, &target.label, *condition)?;
            set_meta_handle(&file, meta, *flags)?;
            require_rooted_named_identity(target, &file, *condition)
        }
        Op::Rmdir { .. } => match root.metadata_optional(path)? {
            None => Ok(()),
            Some(_) => root.remove_directory(path),
        },
        Op::Unlink { .. } => match root.metadata_optional(path)? {
            None => Ok(()),
            Some(metadata) if metadata.is_dir() => {
                bail!(
                    "{}: is now a directory; not deleting it",
                    target.label.display()
                )
            }
            Some(_) => root.unlink(path),
        },
        Op::Remove { .. } => bail!("recursive remove cannot use a container guard"),
    }
}

fn set_meta_rooted(target: &GuardedTarget, meta: &Meta, flags: u8) -> Result<()> {
    if target.relative.is_empty() {
        apply_owner(flags, meta, |uid, gid| {
            target.root.chown(&target.relative, uid, gid)
        })?;
        if flags & flags::MODE != 0 {
            target.root.chmod(&target.relative, meta.mode)?;
        }
    }
    let metadata = target.root.metadata(&target.relative)?;
    if target.relative.is_empty() {
        // Ownership and mode were applied through descriptor-relative "."
        // above; only timestamps remain below.
    } else if metadata.is_symlink() {
        apply_owner(flags, meta, |uid, gid| {
            target.root.chown(&target.relative, uid, gid)
        })?;
    } else {
        let handle = target.root.open_metadata(&target.relative)?;
        require_rooted_metadata(&handle, metadata, &target.label)?;
        // Timestamp mutation is performed separately with no-follow
        // descriptor-relative semantics. All other metadata is applied to
        // the stable opened inode, so a raced leaf symlink cannot redirect it.
        set_meta_handle(&handle, meta, flags & !flags::TIMES)?;
    }
    if flags & flags::TIMES != 0 {
        let times = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        target.root.set_times(&target.relative, &times)?;
    }
    Ok(())
}

fn require_rooted_metadata(file: &File, expected: RootMetadata, label: &Path) -> Result<()> {
    let opened = file.metadata()?;
    if opened.dev() != expected.dev || opened.ino() != expected.ino {
        bail!(
            "confined target {} changed while opening it",
            label.display()
        );
    }
    Ok(())
}

fn require_rooted_named_identity(
    target: &GuardedTarget,
    file: &File,
    condition: TargetCondition,
) -> Result<()> {
    let (dev, ino) = match condition {
        TargetCondition::Any => {
            let metadata = file.metadata()?;
            (metadata.dev(), metadata.ino())
        }
        TargetCondition::Absent => bail!("new target unexpectedly received metadata repair"),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => (dev, ino),
    };
    let opened = file.metadata()?;
    let named = target.root.metadata(&target.relative)?;
    if opened.dev() != dev || opened.ino() != ino || named.dev != dev || named.ino != ino {
        bail!("target {} changed during update", target.label.display());
    }
    Ok(())
}

fn condition_identity(condition: TargetCondition) -> Result<(u64, u64)> {
    match condition {
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => Ok((dev, ino)),
        TargetCondition::Any | TargetCondition::Absent => {
            bail!("target condition does not identify an existing object")
        }
    }
}

#[cfg(target_os = "linux")]
fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT
}

#[cfg(not(target_os = "linux"))]
fn file_type_bits(mode: u32) -> u32 {
    mode & libc::S_IFMT as u32
}

fn exact_parent(path: &Path) -> Result<(Root, RelativePath)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let leaf = path
        .file_name()
        .context("exact replacement target has no leaf name")?;
    Ok((Root::open(parent)?, RelativePath::new(leaf.as_bytes())?))
}

fn replace_exact_symlink(path: &Path, link: &[u8], condition: TargetCondition) -> Result<()> {
    let (dev, ino) = condition_identity(condition)?;
    let (root, relative) = exact_parent(path)?;
    root.replace_symlink_if_same(&relative, link, dev, ino)
}

fn replace_exact_node(path: &Path, mode: u32, rdev: u64, condition: TargetCondition) -> Result<()> {
    let (dev, ino) = condition_identity(condition)?;
    let (root, relative) = exact_parent(path)?;
    root.replace_node_if_same(&relative, mode, rdev, dev, ino)
}

#[cfg(debug_assertions)]
fn hold_after_created_container_for_test(path: &Path) -> Result<()> {
    if let Some(ready) = std::env::var_os("SYQ_TEST_CREATED_CONTAINER_READY_FILE") {
        fs::write(&ready, b"ready").with_context(|| {
            format!(
                "write created-container-ready signal {} for {}",
                Path::new(&ready).display(),
                path.display()
            )
        })?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_CREATED_CONTAINER_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_after_created_container_for_test(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn hold_before_guarded_mutation_for_test(path: &[u8]) -> Result<()> {
    let Some(suffix) = std::env::var_os("SYQ_TEST_GUARDED_MUTATION_SUFFIX") else {
        return Ok(());
    };
    if !path.ends_with(suffix.as_bytes()) {
        return Ok(());
    }
    if let Some(ready) = std::env::var_os("SYQ_TEST_GUARDED_MUTATION_READY_FILE") {
        fs::write(&ready, b"ready")?;
    }
    if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_GUARDED_MUTATION_MS") {
        if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn hold_before_guarded_mutation_for_test(_path: &[u8]) -> Result<()> {
    Ok(())
}

fn require_target_condition(
    path: &Path,
    condition: TargetCondition,
) -> Result<Option<fs::Metadata>> {
    match condition {
        TargetCondition::Any => Ok(fs::symlink_metadata(path).ok()),
        TargetCondition::Absent => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Ok(_) => bail!(
                "target {} appeared after the new-path precondition was checked",
                path.display()
            ),
            Err(error) => Err(error).with_context(|| format!("stat {}", path.display())),
        },
        TargetCondition::Matches { dev, ino } => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.dev() == dev && metadata.ino() == ino => Ok(Some(metadata)),
            Ok(_) | Err(_) => bail!(
                "target {} changed after the existing-path precondition was checked",
                path.display()
            ),
        },
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.dev() == dev
                    && metadata.ino() == ino
                    && metadata.ctime() == ctime
                    && metadata.ctime_nsec() as u32 == ctime_nsec =>
            {
                Ok(Some(metadata))
            }
            Ok(_) | Err(_) => bail!(
                "target {} changed after the existing-path precondition was checked",
                path.display()
            ),
        },
    }
}

fn require_open_target(file: &File, path: &Path, condition: TargetCondition) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "target {} appeared after the new-path precondition was checked",
            path.display()
        ),
        TargetCondition::Matches { dev, ino } => {
            let metadata = file.metadata()?;
            if metadata.dev() != dev || metadata.ino() != ino {
                bail!(
                    "target {} changed after the existing-path precondition was checked",
                    path.display()
                );
            }
            Ok(())
        }
        TargetCondition::MatchesFingerprint {
            dev,
            ino,
            ctime,
            ctime_nsec,
        } => {
            let metadata = file.metadata()?;
            if metadata.dev() != dev
                || metadata.ino() != ino
                || metadata.ctime() != ctime
                || metadata.ctime_nsec() as u32 != ctime_nsec
            {
                bail!(
                    "target {} changed after the existing-path precondition was checked",
                    path.display()
                );
            }
            Ok(())
        }
    }
}

/// Confirm that a pathname still names the held object after this operation
/// has intentionally changed that object's ctime.
fn require_named_target_identity(
    file: &File,
    path: &Path,
    condition: TargetCondition,
) -> Result<()> {
    match condition {
        TargetCondition::Any => Ok(()),
        TargetCondition::Absent => bail!(
            "new-target condition cannot validate an in-place update of {}",
            path.display()
        ),
        TargetCondition::Matches { dev, ino }
        | TargetCondition::MatchesFingerprint { dev, ino, .. } => {
            let opened = file.metadata()?;
            let named =
                fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
            if opened.dev() != dev
                || opened.ino() != ino
                || named.dev() != dev
                || named.ino() != ino
            {
                bail!(
                    "target {} changed during the existing-path update",
                    path.display()
                );
            }
            Ok(())
        }
    }
}

/// Open a stable reference suitable for metadata-only repair without reading
/// file contents. O_NONBLOCK prevents a concurrent FIFO/device replacement
/// from hanging before fstat can reject it.
fn open_metadata_handle(path: &Path) -> Result<File> {
    let path = cstr(path)?;
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn set_meta_handle(file: &File, meta: &Meta, flags: u8) -> Result<()> {
    let fd = file.as_raw_fd();
    let empty = c"";
    // Owner first: chown clears setuid/setgid, so mode must follow it.
    apply_owner(flags, meta, |uid, gid| {
        let r = unsafe {
            libc::fchownat(
                fd,
                empty.as_ptr(),
                uid.unwrap_or(u32::MAX),
                gid.unwrap_or(u32::MAX),
                libc::AT_EMPTY_PATH,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })?;
    if flags & flags::MODE != 0 {
        let current = file.metadata()?.mode() & 0o7777;
        let wanted = meta.mode & 0o7777;
        if current != wanted || (flags & (flags::OWNER | flags::GROUP) != 0 && wanted & 0o6000 != 0)
        {
            set_mode_handle(file, wanted)?;
        }
    }
    if flags & flags::TIMES != 0 {
        bail!("metadata-only O_PATH repair does not support timestamp changes");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_meta_handle(file: &File, meta: &Meta, flags: u8) -> Result<()> {
    set_meta_file(file, meta, flags)
}

#[cfg(target_os = "linux")]
fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    let fd = file.as_raw_fd();
    let r = unsafe { libc::fchmodat(fd, c"".as_ptr(), mode as libc::mode_t, libc::AT_EMPTY_PATH) };
    if r == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if !matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    ) {
        return Err(error.into());
    }
    // Older libc/kernel combinations do not expose fchmodat2's AT_EMPTY_PATH
    // support. procfs still resolves this stable O_PATH descriptor, never the
    // possibly replaced pathname.
    fs::set_permissions(
        PathBuf::from("/proc/self/fd").join(fd.to_string()),
        fs::Permissions::from_mode(mode),
    )?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_mode_handle(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(debug_assertions)]
fn fail_set_meta_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_SETMETA") {
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            return Err(anyhow!("set metadata {}: injected failure", p.display()));
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn fail_put_small_before_rename_for_test(p: &Path) -> Result<()> {
    if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME") {
        // Model interruption after the sidecar is complete but before it
        // becomes the final name.
        if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
            bail!("put small {}: injected failure before rename", p.display());
        }
    }
    Ok(())
}

const PAR_THREADS: usize = 32;
const PAR_MIN: usize = 32;

fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if items.len() < PAR_MIN {
        return items.iter().map(&f).collect();
    }
    let chunk = items.len().div_ceil(PAR_THREADS).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|c| s.spawn(|| c.iter().map(&f).collect::<Vec<R>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("stat thread"))
            .collect()
    })
}

/// Hash exactly `len` bytes in fixed blocks. A short reader contributes the
/// bytes it has and empty hashes for the missing blocks, matching both source
/// and destination behavior through one implementation.
fn hash_reader(reader: &mut impl Read, block: u64, len: u64) -> Result<Vec<u64>> {
    let n = len.div_ceil(block) as usize;
    let mut hashes = Vec::with_capacity(n);
    let mut buf = vec![0u8; block as usize];
    let mut remaining = len;
    while remaining > 0 {
        let want = remaining.min(block) as usize;
        let mut got = 0;
        while got < want {
            let read = reader.read(&mut buf[got..want])?;
            if read == 0 {
                break;
            }
            got += read;
        }
        hashes.push(xxh3_64(&buf[..got]));
        if got < want {
            while hashes.len() < n {
                hashes.push(xxh3_64(&[]));
            }
            break;
        }
        remaining -= want as u64;
    }
    Ok(hashes)
}

impl FsOps {
    pub fn probe_partial(&mut self, path: &[u8], partial_id: &PartialId) -> Result<Response> {
        let p = resolve(path);
        let pp = partial_path(&p, partial_id)?;
        let partial_size = match fs::symlink_metadata(&pp) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Ok(metadata) if is_safe_partial(&metadata) => Some(metadata.len()),
            Ok(_) => None,
            Err(error) => return Err(error).with_context(|| format!("stat {}", pp.display())),
        };
        Ok(Response::PartialSize(partial_size))
    }

    /// Open this job's adjacent sidecar without following symlinks or modifying
    /// hardlinked files. A crash may leave final metadata (including 0444) on
    /// the sidecar, so make a safe regular leftover writable before reuse.
    fn open_private_partial(&mut self, pp: &Path) -> Result<(File, Option<u64>)> {
        self.uncache(pp);
        let mut repaired_permissions = false;
        for _ in 0..8 {
            match fs::symlink_metadata(pp) {
                Ok(md) if is_safe_partial(&md) => {
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(pp)
                    {
                        Ok(file) => {
                            let fd_meta = file.metadata()?;
                            let path_meta = fs::symlink_metadata(pp)?;
                            if !is_safe_partial(&fd_meta)
                                || !is_safe_partial(&path_meta)
                                || fd_meta.dev() != path_meta.dev()
                                || fd_meta.ino() != path_meta.ino()
                            {
                                continue;
                            }
                            if fd_meta.mode() & 0o7777 != 0o600 {
                                let repair = (|| -> Result<()> {
                                    fail_partial_chmod_for_test()?;
                                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                                    Ok(())
                                })();
                                if let Err(error) = repair {
                                    drop(file);
                                    discard_safe_partial_if_same(pp, &fd_meta).with_context(
                                        || {
                                            format!(
                                                "replace partial {} after chmod failed: {error:#}",
                                                pp.display()
                                            )
                                        },
                                    )?;
                                    continue;
                                }
                            }
                            return Ok((file, Some(fd_meta.len())));
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                            if repaired_permissions {
                                discard_safe_partial_if_same(pp, &md).with_context(|| {
                                    format!(
                                        "replace partial {} after it remained unreadable",
                                        pp.display()
                                    )
                                })?;
                                repaired_permissions = false;
                                continue;
                            }
                            // Open a metadata-only descriptor and chmod that,
                            // not the pathname: this works for mode-000 files
                            // and a co-writer cannot redirect the repair to a
                            // symlink target between lstat and chmod.
                            let handle = match open_metadata_handle(pp) {
                                Ok(handle) => handle,
                                Err(repair_error) => {
                                    discard_safe_partial_if_same(pp, &md).with_context(|| {
                                        format!(
                                            "replace partial {} after permission repair failed: {repair_error:#}",
                                            pp.display()
                                        )
                                    })?;
                                    continue;
                                }
                            };
                            let fd_meta = handle.metadata()?;
                            let path_meta = fs::symlink_metadata(pp)?;
                            if !is_safe_partial(&fd_meta)
                                || !is_safe_partial(&path_meta)
                                || fd_meta.dev() != md.dev()
                                || fd_meta.ino() != md.ino()
                                || fd_meta.dev() != path_meta.dev()
                                || fd_meta.ino() != path_meta.ino()
                            {
                                continue;
                            }
                            let repair = (|| -> Result<()> {
                                fail_partial_chmod_for_test()?;
                                set_mode_handle(&handle, 0o600)?;
                                Ok(())
                            })();
                            if let Err(error) = repair {
                                drop(handle);
                                discard_safe_partial_if_same(pp, &fd_meta).with_context(|| {
                                    format!(
                                        "replace partial {} after chmod failed: {error:#}",
                                        pp.display()
                                    )
                                })?;
                                continue;
                            }
                            repaired_permissions = true;
                            continue;
                        }
                        Err(error) => {
                            return Err(error).with_context(|| format!("open {}", pp.display()))
                        }
                    }
                }
                Ok(_) => {
                    fs::remove_file(pp).with_context(|| format!("replace {}", pp.display()))?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(pp)
                    {
                        Ok(file) => {
                            require_safe_partial(&file, pp)?;
                            Ok((file, None))
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            Err(error).with_context(|| format!("create {}", pp.display()))
                        }
                    };
                }
                Err(error) => return Err(error).with_context(|| format!("stat {}", pp.display())),
            }
        }
        bail!(
            "partial {} changed repeatedly while opening it",
            pp.display()
        )
    }

    fn open_private_partial_rooted(
        &mut self,
        root: &Root,
        relative: &RelativePath,
        label: &Path,
    ) -> Result<(File, Option<u64>)> {
        self.uncache(label);
        for _ in 0..8 {
            match root.metadata_optional(relative)? {
                Some(metadata) if is_safe_rooted_partial(metadata) => {
                    match root.open_regular_read_write(relative) {
                        Ok(file) => {
                            let opened = file.metadata()?;
                            let named = root.metadata(relative)?;
                            if !is_safe_partial(&opened)
                                || opened.dev() != named.dev
                                || opened.ino() != named.ino
                            {
                                continue;
                            }
                            if opened.mode() & 0o7777 != 0o600 {
                                fail_partial_chmod_for_test()?;
                                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                            }
                            return Ok((file, Some(opened.len())));
                        }
                        Err(error)
                            if error.downcast_ref::<io::Error>().is_some_and(|error| {
                                error.kind() == io::ErrorKind::PermissionDenied
                            }) =>
                        {
                            fail_partial_chmod_for_test()?;
                            let handle = root.open_metadata(relative)?;
                            require_rooted_metadata(&handle, metadata, label)?;
                            set_mode_handle(&handle, 0o600)?;
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Some(_) => root.unlink(relative)?,
                None => match root.create_file(relative, 0o600) {
                    Ok(file) => return Ok((file, None)),
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists) =>
                    {
                        continue
                    }
                    Err(error) => return Err(error),
                },
            }
        }
        bail!(
            "partial {} changed repeatedly while opening it",
            label.display()
        )
    }

    pub fn prepare(
        &mut self,
        path: &[u8],
        size: u64,
        inplace: bool,
        partial_id: &PartialId,
        mode: u32,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let p = resolve(path);
        if let Some(guard) = guard {
            if inplace {
                bail!("guarded destination cannot be prepared in place");
            }
            let target = guarded_target(path, guard)?;
            let pp = partial_path(&p, partial_id)?;
            let relative = relative_under(&target.root_path, &pp)?;
            let (file, basis_size) =
                self.open_private_partial_rooted(&target.root, &relative, &pp)?;
            if basis_size.is_none() {
                preallocate(&file, size)?;
            }
            file.set_len(size)?;
            return Ok(());
        }
        if inplace {
            self.uncache(&p);
            // A stale partial from an interrupted run would otherwise be orphaned.
            if let Ok(pp) = partial_path(&p, partial_id) {
                let _ = fs::remove_file(pp);
            }
            let f = open_regular_write(&p, mode, false)?;
            f.set_len(size)?;
            return Ok(());
        }
        let pp = partial_path(&p, partial_id)?;
        let (f, basis_size) = self.open_private_partial(&pp)?;
        if basis_size.is_some() {
            f.set_len(size)?;
            return Ok(());
        }
        preallocate(&f, size)?;
        f.set_len(size)?; // exact length: fallocate never shrinks an already-longer file
        #[cfg(debug_assertions)]
        if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_PARTIAL_MS") {
            if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        Ok(())
    }

    pub fn hash_and_hold(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        block: u64,
        len: u64,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<(Vec<u64>, u64)> {
        let p = resolve(path);
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_HASH_BASIS").is_some() {
            bail!("injected retained-basis hash failure");
        }
        let mut file = if let Some(guard) = guard {
            let target = guarded_target(path, guard)?;
            target.root.open_regular_read(&target.relative)?
        } else {
            open_existing_regular(&p, false)
                .with_context(|| format!("open {} as repair basis", p.display()))?
        };
        require_open_target(&file, &p, condition)?;
        let hashes = hash_reader(&mut file, block, len)?;
        self.held_basis = Some(HeldBasis {
            path: p,
            partial_id: *partial_id,
            file,
        });
        #[cfg(debug_assertions)]
        if let Some(ready) = std::env::var_os("SYQ_TEST_BASIS_READY_FILE") {
            fs::write(&ready, b"ready").with_context(|| {
                format!("write basis-ready signal {}", Path::new(&ready).display())
            })?;
        }
        #[cfg(debug_assertions)]
        if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_BASIS_MS") {
            if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        // Hashing is intentionally limited to the source length. Report the
        // retained inode's length afterward so a file that grew since the
        // planner's stat cannot be mistaken for an exact content match.
        let held_len = self
            .held_basis
            .as_ref()
            .expect("basis retained above")
            .file
            .metadata()?
            .len();
        Ok((hashes, held_len))
    }

    fn take_held_basis(&mut self, path: &[u8], partial_id: &PartialId) -> Result<HeldBasis> {
        let expected = resolve(path);
        let held = self
            .held_basis
            .take()
            .context("no retained destination basis")?;
        if held.path != expected || held.partial_id != *partial_id {
            bail!("retained destination basis does not match requested file");
        }
        Ok(held)
    }

    pub fn finish_basis(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
        condition: TargetCondition,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let held = self.take_held_basis(path, partial_id)?;
        require_open_target(&held.file, &held.path, condition)?;
        set_meta_file(&held.file, meta, flags)
            .with_context(|| format!("set metadata on basis {}", held.path.display()))?;
        if let Some(guard) = guard {
            let target = guarded_target(path, guard)?;
            require_rooted_named_identity(&target, &held.file, condition)?;
        } else {
            require_named_target_identity(&held.file, &held.path, condition)?;
        }
        Ok(())
    }

    pub fn seed_basis(
        &mut self,
        path: &[u8],
        partial_id: &PartialId,
        len: u64,
        guard: Option<&ContainerGuard>,
    ) -> Result<()> {
        let mut held = self.take_held_basis(path, partial_id)?;
        let pp = partial_path(&held.path, partial_id)?;
        let dst = if let Some(guard) = guard {
            let target = guarded_target(path, guard)?;
            let relative = relative_under(&target.root_path, &pp)?;
            self.open_private_partial_rooted(&target.root, &relative, &pp)?
                .0
        } else {
            self.open_private_partial(&pp)?.0
        };
        dst.set_len(0)?;
        preallocate(&dst, len)?;
        dst.set_len(len)?;
        held.file.seek(SeekFrom::Start(0))?;
        let mut writer = &dst;
        writer.seek(SeekFrom::Start(0))?;
        io::copy(&mut held.file.take(len), &mut writer)
            .with_context(|| format!("seed partial from {}", held.path.display()))?;
        dst.set_len(len)?;
        Ok(())
    }

    /// Copy a whole file in the kernel via copy_file_range. Falls back with a
    /// distinct "EXDEV" error when the kernel can't offload (different mounts
    /// without server-side copy, or an unsupported filesystem) so the caller
    /// can use the normal streaming path.
    #[cfg(target_os = "linux")]
    pub fn copy_local(
        &mut self,
        src: &[u8],
        dst: &[u8],
        inplace: bool,
        partial_id: &PartialId,
        size: u64,
        mode: u32,
    ) -> Result<()> {
        let sp = resolve(src);
        let s = open_existing_regular(&sp, false)?;
        let dp = resolve(dst);
        // Never truncate the source: if the destination resolves to the same
        // file (same path, a hardlink, or a symlink pointing back), refuse.
        if let (Ok(sm), Ok(dm)) = (s.metadata(), fs::metadata(&dp)) {
            if sm.dev() == dm.dev() && sm.ino() == dm.ino() {
                bail!("source and destination are the same file: {}", dp.display());
            }
        }
        self.uncache(&dp);
        let target = if inplace {
            dp.clone()
        } else {
            partial_path(&dp, partial_id)?
        };
        self.uncache(&target);
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).ok();
            }
        }
        let d = if inplace {
            open_regular_write(&target, mode, true)?
        } else {
            let (d, _) = self.open_private_partial(&target)?;
            d.set_len(0)?;
            d
        };
        #[cfg(debug_assertions)]
        if !inplace && std::env::var_os("SYQ_TEST_COPY_LOCAL_EXDEV").is_some() {
            drop(d);
            fs::remove_file(&target).with_context(|| format!("remove {}", target.display()))?;
            bail!("EXDEV");
        }
        let mut off: i64 = 0;
        let mut remaining = size;
        while remaining > 0 {
            let n = unsafe {
                libc::copy_file_range(
                    s.as_raw_fd(),
                    &mut off as *mut i64 as *mut _,
                    d.as_raw_fd(),
                    &mut off as *mut i64 as *mut _,
                    remaining as usize,
                    0,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                let raw = e.raw_os_error().unwrap_or(0);
                // First-block failure with a "can't offload" errno: signal fallback.
                if remaining == size
                    && matches!(
                        raw,
                        libc::EXDEV | libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL
                    )
                {
                    if inplace {
                        drop(d);
                        let _ = fs::remove_file(&target);
                    } else {
                        // The planner probed before this empty sidecar existed.
                        // A content-identical fallback completes through its
                        // retained basis fd and would otherwise orphan it.
                        drop(d);
                        fs::remove_file(&target)
                            .with_context(|| format!("remove {}", target.display()))?;
                    }
                    bail!("EXDEV");
                }
                if raw == libc::EINTR {
                    continue;
                }
                return Err(e).with_context(|| {
                    format!("copy_file_range {} -> {}", sp.display(), target.display())
                });
            }
            if n == 0 {
                break; // source shorter than expected; finalize what we have
            }
            remaining -= n as u64;
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn copy_local(
        &mut self,
        _src: &[u8],
        _dst: &[u8],
        _inplace: bool,
        _partial_id: &PartialId,
        _size: u64,
        _mode: u32,
    ) -> Result<()> {
        bail!("EXDEV")
    }

    /// Write a whole small file through its deterministic sidecar and atomically
    /// rename it into place. Keeping this as one request preserves pipelining;
    /// unlike an in-place write, no partial final-named file is ever visible.
    fn put_small(
        &mut self,
        target: PartialTarget<'_>,
        data: &[u8],
        hash: u64,
        meta: &Meta,
        flags: u8,
        condition: TargetCondition,
    ) -> Result<()> {
        if xxh3_64(data) != hash {
            bail!("block hash mismatch on receive");
        }
        let p = resolve(target.path);
        self.uncache(&p);
        if let Some(guard) = target.guard {
            let guarded = guarded_target(target.path, guard)?;
            let pp = partial_path(&p, target.id)?;
            let relative = relative_under(&guarded.root_path, &pp)?;
            self.uncache(&pp);
            let (file, _) = self.open_private_partial_rooted(&guarded.root, &relative, &pp)?;
            file.set_len(0)?;
            file.write_all_at(data, 0)
                .with_context(|| format!("write {}", pp.display()))?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", pp.display()))?;
            #[cfg(debug_assertions)]
            fail_put_small_before_rename_for_test(&p)?;
            guarded.root.rename(&relative, &guarded.relative)?;
            return Ok(());
        }
        if matches!(
            condition,
            TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
        ) {
            let file = open_existing_regular(&p, true)?;
            require_open_target(&file, &p, condition)?;
            file.set_len(0)?;
            file.write_all_at(data, 0)
                .with_context(|| format!("write existing {}", p.display()))?;
            file.set_len(data.len() as u64)?;
            set_meta_file(&file, meta, flags)
                .with_context(|| format!("set metadata {}", p.display()))?;
            require_named_target_identity(&file, &p, condition)?;
            return Ok(());
        }
        let pp = partial_path(&p, target.id)?;
        self.uncache(&pp);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).ok();
            }
        }
        let (f, _) = self.open_private_partial(&pp)?;
        f.set_len(0)?;
        f.write_all_at(data, 0)
            .with_context(|| format!("write {}", pp.display()))?;
        set_meta_file(&f, meta, flags).with_context(|| format!("set metadata {}", pp.display()))?;
        #[cfg(debug_assertions)]
        fail_put_small_before_rename_for_test(&p)?;
        publish_partial(&pp, &p, condition)?;
        drop(f);
        Ok(())
    }

    pub fn hash_blocks(
        &mut self,
        path: &[u8],
        which: Which,
        partial_id: &PartialId,
        block: u64,
        len: u64,
    ) -> Result<Vec<u64>> {
        let p = resolve(path);
        let p = if which == Which::Partial {
            partial_path(&p, partial_id)?
        } else {
            p
        };
        let mut f = open_existing_regular(&p, false)?;
        if which == Which::Partial {
            require_safe_partial(&f, &p)?;
        }
        hash_reader(&mut f, block, len)
    }

    pub fn read_range(
        &mut self,
        path: &[u8],
        attempt: u32,
        off: u64,
        len: u32,
    ) -> Result<Response> {
        let p = resolve(path);
        let f = self.cached(&p, false, attempt, false)?;
        let mut data = vec![0u8; len as usize];
        f.read_exact_at(&mut data, off)
            .with_context(|| format!("read {} @{off}+{len}", p.display()))?;
        let hash = xxh3_64(&data);
        Ok(Response::Block { off, hash, data })
    }

    fn write_range(
        &mut self,
        target: PartialTarget<'_>,
        inplace: bool,
        attempt: u32,
        off: u64,
        hash: u64,
        data: &[u8],
    ) -> Result<()> {
        if xxh3_64(data) != hash {
            bail!("block hash mismatch on receive @{off}");
        }
        let p = resolve(target.path);
        let p = if inplace {
            p
        } else {
            partial_path(&p, target.id)?
        };
        let f = if let Some(guard) = target.guard {
            if inplace {
                bail!("guarded destination cannot be written in place");
            }
            let final_target = guarded_target(target.path, guard)?;
            let relative = relative_under(&final_target.root_path, &p)?;
            self.cached_rooted(&p, &final_target.root, &relative, attempt, true)?
        } else {
            self.cached(&p, true, attempt, !inplace)?
        };
        f.write_all_at(data, off)
            .with_context(|| format!("write {} @{off}", p.display()))
    }

    fn finalize(
        &mut self,
        path: &[u8],
        inplace: bool,
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
        mutation: TargetMutation<'_>,
    ) -> Result<()> {
        let TargetMutation { condition, guard } = mutation;
        if let Some(guard) = guard {
            return self.finalize_rooted(path, inplace, partial_id, meta, flags, guard);
        }
        let p = resolve(path);
        let src = if inplace {
            p.clone()
        } else {
            partial_path(&p, partial_id)?
        };
        let f = self
            .uncache(&src)
            .map(Ok)
            .unwrap_or_else(|| open_existing_regular(&src, true))?;
        if inplace {
            if !f.metadata()?.file_type().is_file() {
                bail!("destination {} is not a regular file", src.display());
            }
            require_open_target(&f, &p, condition)?;
        } else {
            require_safe_partial(&f, &src)?;
        }
        if !inplace
            && matches!(
                condition,
                TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. }
            )
        {
            // Range writes cache the private sidecar write-only. Retain that
            // descriptor while opening the same safe inode for reading, so a
            // pathname swap cannot substitute bytes before copy-back.
            let staged_metadata = f.metadata()?;
            let mut staged = open_existing_regular(&src, false)?;
            let reopened_metadata = staged.metadata()?;
            require_safe_partial(&staged, &src)?;
            if staged_metadata.dev() != reopened_metadata.dev()
                || staged_metadata.ino() != reopened_metadata.ino()
            {
                bail!("partial {} changed before publication", src.display());
            }
            self.uncache(&p);
            let mut target = open_existing_regular(&p, true)?;
            require_open_target(&target, &p, condition)?;
            let size = reopened_metadata.len();
            target.set_len(0)?;
            staged.seek(SeekFrom::Start(0))?;
            target.seek(SeekFrom::Start(0))?;
            io::copy(&mut staged, &mut target)
                .with_context(|| format!("update existing {}", p.display()))?;
            target.set_len(size)?;
            set_meta_file(&target, meta, flags)
                .with_context(|| format!("set metadata {}", p.display()))?;
            require_named_target_identity(&target, &p, condition)?;
            fs::remove_file(&src).with_context(|| format!("remove {}", src.display()))?;
            return Ok(());
        }
        set_meta_file(&f, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        if !inplace {
            if fs::symlink_metadata(&p).is_ok_and(|metadata| metadata.is_dir()) {
                bail!("destination {} is a directory", p.display());
            }
            publish_partial(&src, &p, condition)?;
        } else {
            require_named_target_identity(&f, &p, condition)?;
        }
        drop(f);
        Ok(())
    }

    fn finalize_rooted(
        &mut self,
        path: &[u8],
        inplace: bool,
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
        guard: &ContainerGuard,
    ) -> Result<()> {
        if inplace {
            bail!("guarded destination cannot be finalized in place");
        }
        let target = guarded_target(path, guard)?;
        let src = partial_path(&target.label, partial_id)?;
        let src_relative = relative_under(&target.root_path, &src)?;
        let file = self
            .uncache(&src)
            .map(Ok)
            .unwrap_or_else(|| target.root.open_regular_write(&src_relative, false))?;
        let opened = file.metadata()?;
        let named = target.root.metadata(&src_relative)?;
        if !is_safe_partial(&opened)
            || !is_safe_rooted_partial(named)
            || opened.dev() != named.dev
            || opened.ino() != named.ino
        {
            bail!("partial {} changed before publication", src.display());
        }
        set_meta_file(&file, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        if target
            .root
            .metadata_optional(&target.relative)?
            .is_some_and(RootMetadata::is_dir)
        {
            bail!("destination {} is a directory", target.label.display());
        }
        target.root.rename(&src_relative, &target.relative)?;
        Ok(())
    }

    pub fn file_hash(&mut self, path: &[u8]) -> Result<Response> {
        let p = resolve(path);
        let mut f = open_existing_regular(&p, false)?;
        let mut h = Xxh3::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut size = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            size += n as u64;
        }
        let _ = xxh3_128; // keep the symbol in case of future use
        Ok(Response::FileHash {
            size,
            hash: h.digest128(),
        })
    }

    /// Dispatch a request that has a single response (everything except Scan).
    pub fn handle(&mut self, req: &Request) -> Response {
        // HashAndHold's next request must consume the retained descriptor.
        // Any other request means the controller abandoned that comparison
        // (for example because the source hash failed), so release it here.
        if !matches!(req, Request::FinishBasis { .. } | Request::SeedBasis { .. }) {
            self.held_basis.take();
        }
        let r: Result<Response> = match req {
            Request::StatMany { paths, follow } => {
                Ok(Response::Stats(self.stat_many(paths, *follow)))
            }
            Request::PartialPaths { paths, partial_id } => {
                Ok(Response::PathResults(self.partial_paths(paths, partial_id)))
            }
            Request::Apply { ops, guard } => Ok(Response::Applied(self.apply(ops, guard.as_ref()))),
            Request::CreateContainer { path, mode } => {
                self.create_container(path, *mode).map(Response::Container)
            }
            Request::ProbePartial { path, partial_id } => self.probe_partial(path, partial_id),
            Request::Prepare {
                path,
                size,
                inplace,
                partial_id,
                mode,
                guard,
            } => self
                .prepare(path, *size, *inplace, partial_id, *mode, guard.as_ref())
                .map(|_| Response::Ok),
            Request::HashAndHold {
                path,
                partial_id,
                block,
                len,
                condition,
                guard,
            } => self
                .hash_and_hold(path, partial_id, *block, *len, *condition, guard.as_ref())
                .map(|(hashes, len)| Response::HeldHashes { hashes, len }),
            Request::FinishBasis {
                path,
                partial_id,
                meta,
                flags,
                condition,
                guard,
            } => self
                .finish_basis(path, partial_id, meta, *flags, *condition, guard.as_ref())
                .map(|_| Response::Ok),
            Request::SeedBasis {
                path,
                partial_id,
                len,
                guard,
            } => self
                .seed_basis(path, partial_id, *len, guard.as_ref())
                .map(|_| Response::Ok),
            Request::CopyLocal {
                src,
                dst,
                inplace,
                partial_id,
                size,
                mode,
            } => self
                .copy_local(src, dst, *inplace, partial_id, *size, *mode)
                .map(|_| Response::Ok),
            Request::PutSmall {
                path,
                partial_id,
                data,
                hash,
                meta,
                flags,
                condition,
                guard,
            } => self
                .put_small(
                    PartialTarget {
                        path,
                        id: partial_id,
                        guard: guard.as_ref(),
                    },
                    data,
                    *hash,
                    meta,
                    *flags,
                    *condition,
                )
                .map(|_| Response::Ok),
            Request::HashBlocks {
                path,
                which,
                partial_id,
                block,
                len,
            } => self
                .hash_blocks(path, *which, partial_id, *block, *len)
                .map(Response::Hashes),
            Request::ReadRange {
                path,
                attempt,
                off,
                len,
            } => self.read_range(path, *attempt, *off, *len),
            Request::WriteRange {
                path,
                inplace,
                partial_id,
                attempt,
                off,
                hash,
                data,
                guard,
            } => self
                .write_range(
                    PartialTarget {
                        path,
                        id: partial_id,
                        guard: guard.as_ref(),
                    },
                    *inplace,
                    *attempt,
                    *off,
                    *hash,
                    data,
                )
                .map(|_| Response::Ok),
            Request::Finalize {
                path,
                inplace,
                partial_id,
                meta,
                flags,
                condition,
                guard,
            } => self
                .finalize(
                    path,
                    *inplace,
                    partial_id,
                    meta,
                    *flags,
                    TargetMutation {
                        condition: *condition,
                        guard: guard.as_ref(),
                    },
                )
                .map(|_| Response::Ok),
            Request::FileHash { path } => self.file_hash(path),
            Request::Canonicalize { path } => {
                Ok(Response::Path(path_bytes(&normalize(&resolve(path)))))
            }
            Request::Hello { .. }
            | Request::Scan { .. }
            | Request::TransportStats
            | Request::Shutdown
            | Request::TcpListen { .. } => Err(anyhow!("unexpected request")),
        };
        match r {
            Ok(resp) => resp,
            Err(e) => Response::Err(errstr(&e)),
        }
    }
}

fn publish_partial(src: &Path, dst: &Path, condition: TargetCondition) -> Result<()> {
    match condition {
        TargetCondition::Any => fs::rename(src, dst)
            .with_context(|| format!("publish {} as destination {}", src.display(), dst.display())),
        TargetCondition::Absent => {
            // The sidecar is adjacent to the destination, so hard-linking it
            // creates the final name atomically and fails with EEXIST instead
            // of replacing a target that raced the planner.
            fs::hard_link(src, dst).with_context(|| {
                format!(
                    "publish new {} as destination {} without replacement",
                    src.display(),
                    dst.display()
                )
            })?;
            fs::remove_file(src).with_context(|| format!("remove {}", src.display()))
        }
        TargetCondition::Matches { .. } | TargetCondition::MatchesFingerprint { .. } => {
            bail!("internal error: matched publication must update the held target inode")
        }
    }
}

/// Open `target` for writing as a regular file, replacing any existing
/// symlink/dir/special and refusing to follow a symlink (O_NOFOLLOW), then
/// verify the opened fd is a regular file. Used for every write target so a
/// malicious or stale `.syq-part` symlink can't redirect the write.
fn open_regular_write(target: &Path, mode: u32, truncate: bool) -> Result<File> {
    for _ in 0..8 {
        match fs::symlink_metadata(target) {
            Ok(md) if md.is_file() => {
                // Do not pass O_CREAT for an existing file. Linux
                // fs.protected_regular can reject that combination in a
                // sticky directory even when the caller is allowed to open
                // and update the inode (rsync's --inplace case).
                match OpenOptions::new()
                    .write(true)
                    .truncate(truncate)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(target)
                {
                    Ok(file) if file.metadata()?.file_type().is_file() => return Ok(file),
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        return Err(error).with_context(|| format!("open {}", target.display()))
                    }
                }
            }
            Ok(md) if md.is_dir() => {
                bail!("destination {} is a directory", target.display())
            }
            Ok(_) => {
                fs::remove_file(target).with_context(|| format!("replace {}", target.display()))?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .truncate(truncate)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .mode(mode & 0o7777)
                    .open(target)
                {
                    Ok(file) if file.metadata()?.file_type().is_file() => return Ok(file),
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).with_context(|| format!("create {}", target.display()))
                    }
                }
            }
            Err(error) => return Err(error).with_context(|| format!("stat {}", target.display())),
        }
    }
    bail!(
        "destination {} changed repeatedly while opening it",
        target.display()
    )
}

/// Open an existing leaf without following a last-component symlink. Parent
/// component confinement is a separate, root-fd-based design problem.
fn open_existing_regular(target: &Path, write: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(!write)
        .write(write)
        // Validate the opened type below. O_NONBLOCK ensures a concurrent FIFO
        // or device replacement cannot hang us before that validation.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(target)
        .with_context(|| format!("open {}", target.display()))?;
    if !file.metadata()?.file_type().is_file() {
        bail!("{} is not a regular file", target.display());
    }
    Ok(file)
}

fn require_safe_partial(file: &File, target: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !is_safe_partial(&metadata) {
        bail!(
            "partial {} is not a singly-linked regular file",
            target.display()
        );
    }
    Ok(())
}

fn is_safe_partial(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && metadata.nlink() == 1
}

fn is_safe_rooted_partial(metadata: RootMetadata) -> bool {
    metadata.is_file() && metadata.nlink == 1
}

/// Remove only the same safe sidecar that was just inspected. If the pathname
/// changed, let the caller retry the normal validation loop instead.
fn discard_safe_partial_if_same(path: &Path, expected: &fs::Metadata) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(current)
            if is_safe_partial(&current)
                && current.dev() == expected.dev()
                && current.ino() == expected.ino() =>
        {
            fs::remove_file(path).with_context(|| format!("replace {}", path.display()))?;
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn fail_partial_chmod_for_test() -> Result<()> {
    if std::env::var_os("SYQ_TEST_FAIL_PARTIAL_CHMOD").is_some() {
        bail!("injected partial chmod failure");
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn fail_partial_chmod_for_test() -> Result<()> {
    Ok(())
}

fn mkdir(p: &Path, mode: u32) -> io::Result<()> {
    std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), (mode & 0o7777) | 0o700)
        .create(p)
}

fn followed_metadata(p: &Path) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(p).map(|md| {
        if md.file_type().is_symlink() {
            fs::metadata(p).unwrap_or(md)
        } else {
            md
        }
    })
}

fn make_dir_writable(p: &Path, md: &fs::Metadata) -> Result<()> {
    if md.mode() & 0o700 != 0o700 {
        fs::set_permissions(p, fs::Permissions::from_mode(md.mode() | 0o700))?;
    }
    Ok(())
}

fn mkdir_or_existing_dir(p: &Path, mode: u32) -> Result<()> {
    match mkdir(p, mode) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => match followed_metadata(p) {
            Ok(md) if md.is_dir() => make_dir_writable(p, &md),
            _ => Err(err.into()),
        },
        Err(err) => Err(err.into()),
    }
}

fn preallocate(f: &File, size: u64) -> Result<()> {
    if size == 0 {
        f.set_len(0)?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let r = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, size as libc::off_t) };
        if r == 0 {
            return Ok(());
        }
        // Unsupported filesystem (tmpfs, some NFS): fall through to sparse.
    }
    // Portable fallback (also macOS): a sparse file of the right size.
    f.set_len(size)?;
    Ok(())
}

fn timespec(sec: i64, nsec: u32) -> libc::timespec {
    libc::timespec {
        tv_sec: sec as libc::time_t,
        tv_nsec: nsec as libc::c_long,
    }
}

fn set_meta_file(f: &File, meta: &Meta, flags: u8) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    // Owner first: chown clears setuid/setgid, so mode must be set afterwards.
    apply_owner(flags, meta, |uid, gid| {
        std::os::unix::fs::fchown(f, uid, gid)
    })?;
    if flags & flags::MODE != 0 {
        // On network filesystems every setattr is a round trip; skip it when
        // the mode is already right (but always run it after a chown that could
        // have cleared setuid/setgid bits we need to restore).
        let cur = f.metadata().map(|m| m.mode() & 0o7777).unwrap_or(u32::MAX);
        let want = meta.mode & 0o7777;
        if cur != want || (flags & (flags::OWNER | flags::GROUP) != 0 && want & 0o6000 != 0) {
            f.set_permissions(fs::Permissions::from_mode(want))?;
        }
    }
    if flags & flags::TIMES != 0 {
        let ts = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        let r = unsafe { libc::futimens(f.as_raw_fd(), ts.as_ptr()) };
        if r != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_meta_path(p: &Path, meta: &Meta, flags: u8) -> Result<()> {
    let md = fs::symlink_metadata(p)?;
    let is_link = md.file_type().is_symlink();
    // Owner first: chown clears setuid/setgid, so mode is applied afterwards.
    apply_owner(flags, meta, |uid, gid| {
        std::os::unix::fs::lchown(p, uid, gid)
    })?;
    if flags & flags::MODE != 0 && !is_link {
        fs::set_permissions(p, fs::Permissions::from_mode(meta.mode & 0o7777))?;
    }
    if flags & flags::TIMES != 0 {
        let ts = [
            timespec(0, libc::UTIME_OMIT as u32),
            timespec(meta.mtime, meta.mtime_nsec),
        ];
        let c = cstr(p)?;
        let r = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c.as_ptr(),
                ts.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Owner only as root; group as anyone (may fail with EPERM, which we ignore
/// like rsync does for groups the user isn't a member of).
fn apply_owner(
    flags: u8,
    meta: &Meta,
    chown: impl Fn(Option<u32>, Option<u32>) -> io::Result<()>,
) -> Result<()> {
    let uid = if flags & flags::OWNER != 0 && is_root() {
        Some(meta.uid)
    } else {
        None
    };
    let gid = if flags & flags::GROUP != 0 {
        Some(meta.gid)
    } else {
        None
    };
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    match chown(uid, gid) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && uid.is_none() => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, FileTypeExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "syq-fsops-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn existing_regular_open_does_not_follow_leaf_symlinks() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let file = dir.join("file");
        let link = dir.join("link");
        fs::write(&file, b"data").unwrap();
        symlink(&file, &link).unwrap();

        let regular_opened = open_existing_regular(&file, false).is_ok();
        let link_rejected = open_existing_regular(&link, false).is_err();
        fs::remove_dir_all(&dir).unwrap();

        assert!(regular_opened);
        assert!(link_rejected);
    }

    #[test]
    fn existing_regular_open_does_not_block_on_fifo() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let fifo = dir.join("fifo");
        let fifo_c = cstr(&fifo).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        let started = std::time::Instant::now();
        let read_result = open_existing_regular(&fifo, false);
        let write_result = open_existing_regular(&fifo, true);
        fs::remove_dir_all(&dir).unwrap();

        assert!(read_result.is_err());
        assert!(write_result.is_err());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "opening a FIFO must not wait for a reader"
        );
    }

    #[test]
    fn matching_condition_can_replace_a_same_type_special_file() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let fifo = dir.join("fifo");
        let fifo_c = cstr(&fifo).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o644) }, 0);
        let before = fs::symlink_metadata(&fifo).unwrap();

        let errors = FsOps::new().apply(
            &[Op::Mknod {
                path: path_bytes(&fifo),
                mode: file_type_bits(before.mode()) | 0o600,
                rdev: 0,
                condition: TargetCondition::Matches {
                    dev: before.dev(),
                    ino: before.ino(),
                },
            }],
            None,
        );
        let after = fs::symlink_metadata(&fifo).unwrap();
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!(errors, vec![None]);
        assert!(after.file_type().is_fifo());
        assert_ne!(after.ino(), before.ino());
        assert_eq!(after.mode() & 0o777, 0o600);
    }

    #[test]
    fn safe_partial_must_have_one_link() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let file = dir.join("partial");
        let alias = dir.join("alias");
        fs::write(&file, b"data").unwrap();
        fs::hard_link(&file, &alias).unwrap();

        let opened = open_existing_regular(&file, true).unwrap();
        let rejected = require_safe_partial(&opened, &file).is_err();
        drop(opened);
        fs::remove_dir_all(&dir).unwrap();

        assert!(rejected);
    }

    #[test]
    fn unlink_never_recurses_into_a_directory() {
        let dir = std::env::temp_dir().join(format!("syq-unlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("d/inside")).unwrap();
        fs::write(dir.join("f"), b"f").unwrap();
        let mut ops = FsOps::new();
        let path = |n: &str| path_bytes(&dir.join(n));
        let errs = ops.apply(
            &[
                Op::Unlink { path: path("d") },
                Op::Unlink { path: path("f") },
                Op::Unlink {
                    path: path("missing"),
                },
            ],
            None,
        );
        assert!(errs[0]
            .as_deref()
            .is_some_and(|e| e.contains("is now a directory")));
        assert!(
            dir.join("d/inside").is_dir(),
            "the directory and its contents survive"
        );
        assert!(errs[1].is_none() && !dir.join("f").exists());
        assert!(errs[2].is_none(), "a vanished leaf is not an error");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_name_keeps_job_id_and_fits_name_max() {
        let id = [7u8; 16];
        let short = partial_path(Path::new("file"), &id).unwrap();
        let short_name = short.file_name().unwrap();
        assert!(short_name.to_string_lossy().starts_with(".file.syq-part."));
        assert!(is_partial_name(short_name));

        let long = PathBuf::from("n".repeat(240));
        let partial = partial_path(&long, &id).unwrap();
        let name = partial.file_name().unwrap();
        assert!(name.as_bytes().len() <= COMMON_NAME_MAX);
        assert!(is_partial_name(name));
        assert!(name.to_string_lossy().ends_with(&base32(&id)));
    }

    #[test]
    fn partial_name_honors_filesystems_with_smaller_name_max() {
        let id = [8u8; 16];
        let final_path = PathBuf::from("dir").join("n".repeat(120));
        let partial = partial_path_with_name_max(&final_path, &id, 143).unwrap();
        let name = partial.file_name().unwrap();
        assert!(name.as_bytes().len() <= 143);
        assert!(is_partial_name(name));
        assert!(name.to_string_lossy().ends_with(&base32(&id)));
    }

    #[test]
    fn shortened_partial_name_preserves_utf8_boundaries() {
        let id = [10u8; 16];
        let final_path = PathBuf::from("dir").join("界".repeat(80));
        let partial = partial_path_with_name_max(&final_path, &id, 143).unwrap();
        let name = partial.file_name().unwrap();

        assert!(name.as_bytes().len() <= 143);
        assert!(name.to_str().is_some());
        assert!(is_partial_name(name));
    }

    #[test]
    fn name_limit_uses_nearest_existing_ancestor() {
        let dir = test_dir();
        fs::create_dir(&dir).unwrap();
        let missing = dir.join("not-yet-created/deeper");
        let target = dir.join("symlink-target");
        let link = dir.join("in-tree-link");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert_eq!(nearest_existing_directory(&missing), dir);
        assert_eq!(nearest_existing_directory(&link.join("deeper")), dir);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compact_partial_name_is_recognized() {
        let name = OsStr::from_bytes(b".syq-part.aaaaaaaaaaaaaaaa");
        assert!(is_partial_name(name));
        assert!(!is_partial_name(OsStr::from_bytes(b".syq-part.notes")));

        let id = [9u8; 16];
        let parent_len = libc::PATH_MAX as usize - 28;
        let final_path = PathBuf::from("a".repeat(parent_len)).join("x");
        let partial = partial_path(&final_path, &id).unwrap();
        assert_eq!(partial.file_name().unwrap().as_bytes().len(), 26);
        assert!(is_partial_name(partial.file_name().unwrap()));

        let too_deep = PathBuf::from("a".repeat(parent_len + 1)).join("x");
        assert!(partial_path(&too_deep, &id).is_err());
    }

    #[test]
    fn shared_block_hasher_handles_short_readers_consistently() {
        let data = b"abcdefghij";
        let hashes = hash_reader(&mut &data[..], 4, 16).unwrap();
        assert_eq!(
            hashes,
            vec![
                xxh3_64(b"abcd"),
                xxh3_64(b"efgh"),
                xxh3_64(b"ij"),
                xxh3_64(b""),
            ]
        );
    }
}
