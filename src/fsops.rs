//! Local filesystem operations. Used directly by the local endpoint and
//! by `pcp --server` for remote endpoints, so both sides behave identically.

use crate::proto::*;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::{xxh3_128, xxh3_64, Xxh3};

pub const PARTIAL_SUFFIX: &str = ".pcp-partial";
const FD_CACHE_MAX: usize = 16;

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

pub fn partial_path(final_: &Path) -> PathBuf {
    let name = final_
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| OsString::from("root"));
    let mut pn = OsString::from(".");
    pn.push(&name);
    pn.push(PARTIAL_SUFFIX);
    match final_.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(pn),
        _ => PathBuf::from(pn),
    }
}

pub fn is_partial_name(name: &OsStr) -> bool {
    let b = name.as_bytes();
    b.starts_with(b".") && b.ends_with(PARTIAL_SUFFIX.as_bytes())
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
    fds: HashMap<PathBuf, File>,
    fd_order: Vec<PathBuf>,
    /// Exclusive advisory locks on deterministic partials claimed by this
    /// connection. The lock stays held until the file is finalized or the
    /// connection closes, so another pcp process cannot write the same inode.
    partial_leases: HashMap<PathBuf, PartialLease>,
}

struct PartialLease {
    file: File,
    /// Size before this transfer claimed the partial; None means we created it.
    basis_size: Option<u64>,
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
            partial_leases: HashMap::new(),
        }
    }

    fn cached(&mut self, p: &Path, write: bool) -> Result<&File> {
        if !self.fds.contains_key(p) {
            if self.fds.len() >= FD_CACHE_MAX {
                let victim = self.fd_order.remove(0);
                self.fds.remove(&victim);
            }
            let f = if write {
                OpenOptions::new().write(true).open(p)
            } else {
                File::open(p)
            }
            .with_context(|| format!("open {}", p.display()))?;
            self.fds.insert(p.to_path_buf(), f);
            self.fd_order.push(p.to_path_buf());
        }
        Ok(self.fds.get(p).unwrap())
    }

    fn uncache(&mut self, p: &Path) -> Option<File> {
        self.fd_order.retain(|x| x != p);
        self.fds.remove(p)
    }

    /// Batches are statted on several threads: on network filesystems each
    /// lstat is a round trip and the planner would otherwise starve the workers.
    pub fn stat_many(&mut self, paths: &[PathBytes]) -> Vec<Option<Entry>> {
        parallel_map(paths, |p| lstat_entry(Vec::new(), &resolve(p)).ok())
    }

    /// Ops within a batch are independent (the planner orders batches so that
    /// parents come first), so they run in parallel too.
    pub fn apply(&mut self, ops: &[Op]) -> Vec<Option<String>> {
        // SetMeta depends on the object existing, so create everything first,
        // then apply metadata — otherwise a parallel SetMeta can beat its
        // Symlink/Mknod/Mkdir. Both phases still run in parallel internally.
        let is_meta = |op: &Op| matches!(op, Op::SetMeta { .. });
        let create_idx: Vec<usize> = (0..ops.len()).filter(|&i| !is_meta(&ops[i])).collect();
        let meta_idx: Vec<usize> = (0..ops.len()).filter(|&i| is_meta(&ops[i])).collect();
        let mut out: Vec<Option<String>> = vec![None; ops.len()];
        let cres = parallel_map(&create_idx, |&i| {
            apply_one(&ops[i]).err().as_ref().map(errstr)
        });
        for (i, r) in create_idx.iter().zip(cres) {
            out[*i] = r;
        }
        let mres = parallel_map(&meta_idx, |&i| {
            apply_one(&ops[i]).err().as_ref().map(errstr)
        });
        for (i, r) in meta_idx.iter().zip(mres) {
            out[*i] = r;
        }
        out
    }

    fn _unused_apply_one(&mut self, op: &Op) -> Result<()> {
        apply_one(op)
    }
}

fn apply_one(op: &Op) -> Result<()> {
    {
        match op {
            Op::Mkdir { path, mode } => {
                let p = resolve(path);
                // The orchestrator resolves an explicitly supplied root
                // symlink. Symlinks found inside the destination tree are
                // payload conflicts and must be replaced, never traversed.
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => {
                        // Make sure we can write into it while transferring.
                        if md.mode() & 0o700 != 0o700 {
                            fs::set_permissions(&p, fs::Permissions::from_mode(md.mode() | 0o700))?;
                        }
                        Ok(())
                    }
                    Ok(_) => {
                        fs::remove_file(&p)?;
                        mkdir(&p, *mode)
                    }
                    Err(_) => {
                        if let Some(parent) = p.parent() {
                            if !parent.as_os_str().is_empty() && !parent.exists() {
                                fs::create_dir_all(parent)?;
                            }
                        }
                        match mkdir(&p, *mode) {
                            Ok(()) => Ok(()),
                            Err(error) => match fs::symlink_metadata(&p) {
                                // Another pcp may have created this same
                                // destination directory after our first stat.
                                Ok(md) if md.is_dir() => {
                                    if md.mode() & 0o700 != 0o700 {
                                        fs::set_permissions(
                                            &p,
                                            fs::Permissions::from_mode(md.mode() | 0o700),
                                        )?;
                                    }
                                    Ok(())
                                }
                                _ => Err(error),
                            },
                        }
                    }
                }
                .with_context(|| format!("mkdir {}", p.display()))
            }
            Op::Symlink { path, target } => {
                let p = resolve(path);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => fs::remove_dir(&p)?,
                    Ok(_) => fs::remove_file(&p)?,
                    Err(_) => {}
                }
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &p)
                    .with_context(|| format!("symlink {}", p.display()))
            }
            Op::Mknod { path, mode, rdev } => {
                let p = resolve(path);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => fs::remove_dir(&p)?,
                    Ok(_) => fs::remove_file(&p)?,
                    Err(_) => {}
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
            Op::SetMeta { path, meta, flags } => {
                let p = resolve(path);
                #[cfg(debug_assertions)]
                if let Some(pat) = std::env::var_os("PCP_TEST_FAIL_SETMETA") {
                    // Test hook (debug builds only): fail metadata for matching paths.
                    if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
                        return Err(anyhow!("set metadata {}: injected failure", p.display()));
                    }
                }
                set_meta_path(&p, meta, *flags)
                    .with_context(|| format!("set metadata {}", p.display()))
            }
            Op::Rmdir { path } => {
                let p = resolve(path);
                fs::remove_dir(&p).with_context(|| format!("rmdir {}", p.display()))
            }
            Op::Remove { path } => {
                let p = resolve(path);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => fs::remove_dir_all(&p)?,
                    Ok(_) => fs::remove_file(&p)?,
                    Err(_) => {}
                }
                Ok(())
            }
        }
    }
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

impl FsOps {
    pub fn probe_partial(&mut self, path: &[u8]) -> Result<Response> {
        let p = resolve(path);
        let pp = partial_path(&p);
        // Preserve the cheap, read-only missing-sidecar probe. We only need to
        // claim an inode that already exists; Prepare/CopyLocal will atomically
        // create and claim one if this transfer later decides to write.
        let partial_size = match fs::symlink_metadata(&pp) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Ok(metadata) if metadata.is_file() && metadata.nlink() == 1 => {
                self.acquire_partial(&pp)?
            }
            Ok(_) => None,
            Err(error) => return Err(error).with_context(|| format!("stat {}", pp.display())),
        };
        Ok(Response::PartialSize(partial_size))
    }

    /// Claim a deterministic partial for this transfer. flock is advisory,
    /// but all pcp writers participate; unlike a process-local mutex it also
    /// coordinates separate local invocations and remote worker processes.
    fn acquire_partial(&mut self, pp: &Path) -> Result<Option<u64>> {
        if let Some(lease) = self.partial_leases.get(pp) {
            return Ok(lease.basis_size);
        }
        self.uncache(pp);
        loop {
            // The optional directory guard serializes replacement of an
            // unsafe sidecar (symlink, hardlink, or special file). Missing and
            // ordinary private-file claims remain per-path and parallel.
            let (file, basis_size, claim_guard) = match fs::symlink_metadata(pp) {
                Ok(md) if md.is_file() && md.nlink() == 1 => {
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(pp)
                    {
                        Ok(file) => {
                            let fd_meta = file.metadata()?;
                            let path_meta = fs::symlink_metadata(pp)?;
                            if !fd_meta.file_type().is_file()
                                || fd_meta.nlink() != 1
                                || fd_meta.dev() != path_meta.dev()
                                || fd_meta.ino() != path_meta.ino()
                            {
                                continue;
                            }
                            (file, Some(fd_meta.len()), None)
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => {
                            return Err(error).with_context(|| format!("open {}", pp.display()))
                        }
                    }
                }
                Ok(_) => {
                    let parent = pp
                        .parent()
                        .filter(|path| !path.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."));
                    let guard =
                        File::open(parent).with_context(|| format!("open {}", parent.display()))?;
                    if unsafe { libc::flock(guard.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
                    {
                        bail!(
                            "destination partial {} is being replaced by another pcp process: {}",
                            pp.display(),
                            io::Error::last_os_error()
                        );
                    }
                    match fs::symlink_metadata(pp) {
                        Ok(metadata) if metadata.is_file() && metadata.nlink() == 1 => continue,
                        Ok(_) => fs::remove_file(pp)
                            .with_context(|| format!("replace {}", pp.display()))?,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(error).with_context(|| format!("stat {}", pp.display()))
                        }
                    }
                    let file = match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(pp)
                    {
                        Ok(file) => file,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(error) => {
                            return Err(error).with_context(|| format!("create {}", pp.display()))
                        }
                    };
                    (file, None, Some(guard))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(pp)
                    {
                        Ok(file) => (file, None, None),
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(e) => {
                            return Err(e).with_context(|| format!("create {}", pp.display()))
                        }
                    }
                }
                Err(e) => return Err(e).with_context(|| format!("stat {}", pp.display())),
            };
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = io::Error::last_os_error();
                bail!(
                    "destination partial {} is in use by another pcp process: {error}",
                    pp.display()
                );
            }
            self.partial_leases
                .insert(pp.to_path_buf(), PartialLease { file, basis_size });
            drop(claim_guard);
            #[cfg(debug_assertions)]
            if let Some(ms) = std::env::var_os("PCP_TEST_HOLD_PARTIAL_MS") {
                if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                }
            }
            return Ok(basis_size);
        }
    }

    pub fn prepare(
        &mut self,
        path: &[u8],
        size: u64,
        inplace: bool,
        from_final: bool,
        mode: u32,
    ) -> Result<()> {
        let p = resolve(path);
        if inplace {
            self.uncache(&p);
            // A stale partial from an interrupted run would otherwise be orphaned.
            let _ = fs::remove_file(partial_path(&p));
            // Don't follow a symlink (or write onto a dir/special): replace it
            // with a regular file, like rsync does.
            if let Ok(md) = fs::symlink_metadata(&p) {
                if !md.is_file() {
                    if md.is_dir() {
                        bail!("destination {} is a directory", p.display());
                    }
                    fs::remove_file(&p).with_context(|| format!("replace {}", p.display()))?;
                }
            }
            let f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(mode & 0o7777)
                .open(&p)
                .with_context(|| format!("open {}", p.display()))?;
            if !f.metadata()?.file_type().is_file() {
                bail!("destination {} is not a regular file", p.display());
            }
            f.set_len(size)?;
            return Ok(());
        }
        let pp = partial_path(&p);
        self.acquire_partial(&pp)?;
        let lease = self
            .partial_leases
            .get(&pp)
            .with_context(|| format!("partial {} was not claimed", pp.display()))?;
        let f = &lease.file;
        if from_final {
            f.set_len(0)?;
            // Seed the partial with the existing file for block-diff, but never
            // keep more than `size` bytes (a longer destination must shrink).
            let mut src =
                File::open(&p).with_context(|| format!("open {} to seed repair", p.display()))?;
            let mut dst = f;
            io::copy(&mut (&mut src).take(size), &mut dst)
                .with_context(|| format!("seed partial from {}", p.display()))?;
        } else if lease.basis_size.is_some() {
            f.set_len(size)?;
            return Ok(());
        }
        preallocate(f, size)?;
        f.set_len(size)?; // exact length: fallocate never shrinks an already-longer file
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
        size: u64,
        mode: u32,
    ) -> Result<()> {
        let sp = resolve(src);
        let s = File::open(&sp).with_context(|| format!("open {}", sp.display()))?;
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
            partial_path(&dp)
        };
        self.uncache(&target);
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).ok();
            }
        }
        if !inplace {
            self.acquire_partial(&target)?;
        }
        let d = if inplace {
            open_regular_write(&target, mode)?
        } else {
            let d = self.partial_leases[&target].file.try_clone()?;
            d.set_len(0)?;
            d
        };
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
                        // Keep the claimed inode and its lock for the normal
                        // streaming fallback.
                        d.set_len(0)?;
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
        _size: u64,
        _mode: u32,
    ) -> Result<()> {
        bail!("EXDEV")
    }

    /// Write a whole small file through its deterministic sidecar and atomically
    /// rename it into place. Keeping this as one request preserves pipelining;
    /// unlike an in-place write, no partial final-named file is ever visible.
    pub fn put_small(
        &mut self,
        path: &[u8],
        data: &[u8],
        hash: u64,
        meta: &Meta,
        flags: u8,
        fsync: bool,
    ) -> Result<()> {
        if xxh3_64(data) != hash {
            bail!("block hash mismatch on receive");
        }
        let p = resolve(path);
        self.uncache(&p);
        let pp = partial_path(&p);
        self.uncache(&pp);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent).ok();
            }
        }

        self.acquire_partial(&pp)?;
        let lease = self.partial_leases.remove(&pp).unwrap();
        let f = lease.file;
        f.set_len(0)?;
        f.write_all_at(data, 0)
            .with_context(|| format!("write {}", pp.display()))?;
        set_meta_file(&f, meta, flags).with_context(|| format!("set metadata {}", pp.display()))?;
        if fsync {
            f.sync_all()
                .with_context(|| format!("fsync {}", pp.display()))?;
        }
        #[cfg(debug_assertions)]
        if let Some(pat) = std::env::var_os("PCP_TEST_FAIL_PUT_SMALL_BEFORE_RENAME") {
            // Test hook (debug builds only): model interruption after the
            // sidecar is complete but before it becomes the final name.
            if !pat.is_empty() && p.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
                bail!("put small {}: injected failure before rename", p.display());
            }
        }
        fs::rename(&pp, &p)
            .with_context(|| format!("rename {} to {}", pp.display(), p.display()))?;
        drop(f);
        if fsync {
            fsync_parent(&p)?;
        }
        Ok(())
    }

    pub fn hash_blocks(
        &mut self,
        path: &[u8],
        which: Which,
        block: u64,
        len: u64,
    ) -> Result<Vec<u64>> {
        let p = resolve(path);
        let p = if which == Which::Partial {
            partial_path(&p)
        } else {
            p
        };
        let mut f = File::open(&p).with_context(|| format!("open {}", p.display()))?;
        let n = len.div_ceil(block) as usize;
        let mut out = Vec::with_capacity(n);
        let mut buf = vec![0u8; block as usize];
        let mut remaining = len;
        while remaining > 0 {
            let want = remaining.min(block) as usize;
            let mut got = 0;
            while got < want {
                let r = f.read(&mut buf[got..want])?;
                if r == 0 {
                    break;
                }
                got += r;
            }
            out.push(xxh3_64(&buf[..got]));
            if got < want {
                // Short file: remaining blocks hash as empty (won't match anything real).
                while out.len() < n {
                    out.push(xxh3_64(&[]));
                }
                break;
            }
            remaining -= want as u64;
        }
        Ok(out)
    }

    pub fn read_range(&mut self, path: &[u8], off: u64, len: u32) -> Result<Response> {
        let p = resolve(path);
        let f = self.cached(&p, false)?;
        let mut data = vec![0u8; len as usize];
        f.read_exact_at(&mut data, off)
            .with_context(|| format!("read {} @{off}+{len}", p.display()))?;
        let hash = xxh3_64(&data);
        Ok(Response::Block { off, hash, data })
    }

    pub fn write_range(
        &mut self,
        path: &[u8],
        inplace: bool,
        off: u64,
        hash: u64,
        data: &[u8],
    ) -> Result<()> {
        if xxh3_64(data) != hash {
            bail!("block hash mismatch on receive @{off}");
        }
        let p = resolve(path);
        let p = if inplace { p } else { partial_path(&p) };
        let f = self.cached(&p, true)?;
        f.write_all_at(data, off)
            .with_context(|| format!("write {} @{off}", p.display()))
    }

    pub fn finalize(
        &mut self,
        path: &[u8],
        inplace: bool,
        meta: &Meta,
        flags: u8,
        fsync: bool,
    ) -> Result<()> {
        let p = resolve(path);
        let src = if inplace { p.clone() } else { partial_path(&p) };
        let lease = self.partial_leases.remove(&src).map(|lease| lease.file);
        let cached = self.uncache(&src);
        // Prefer the lease descriptor so its lock remains held through rename.
        let f = lease.or(cached).map(Ok).unwrap_or_else(|| {
            OpenOptions::new()
                .write(true)
                .open(&src)
                .with_context(|| format!("open {}", src.display()))
        })?;
        set_meta_file(&f, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        if fsync {
            f.sync_all()
                .with_context(|| format!("fsync {}", src.display()))?;
        }
        if !inplace {
            if fs::symlink_metadata(&p).is_ok_and(|metadata| metadata.is_dir()) {
                bail!("destination {} is a directory", p.display());
            }
            fs::rename(&src, &p).with_context(|| {
                format!("publish {} as destination {}", src.display(), p.display())
            })?;
        }
        drop(f);
        if fsync {
            // Make the rename (or in-place write) itself durable.
            fsync_parent(&p)?;
        }
        Ok(())
    }

    pub fn file_hash(&mut self, path: &[u8]) -> Result<Response> {
        let p = resolve(path);
        let mut f = File::open(&p).with_context(|| format!("open {}", p.display()))?;
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
        let r: Result<Response> = match req {
            Request::StatMany(paths) => Ok(Response::Stats(self.stat_many(paths))),
            Request::Apply(ops) => Ok(Response::Applied(self.apply(ops))),
            Request::ProbePartial { path } => self.probe_partial(path),
            Request::Prepare {
                path,
                size,
                inplace,
                from_final,
                mode,
            } => self
                .prepare(path, *size, *inplace, *from_final, *mode)
                .map(|_| Response::Ok),
            Request::CopyLocal {
                src,
                dst,
                inplace,
                size,
                mode,
            } => self
                .copy_local(src, dst, *inplace, *size, *mode)
                .map(|_| Response::Ok),
            Request::PutSmall {
                path,
                data,
                hash,
                meta,
                flags,
                fsync,
            } => self
                .put_small(path, data, *hash, meta, *flags, *fsync)
                .map(|_| Response::Ok),
            Request::HashBlocks {
                path,
                which,
                block,
                len,
            } => self
                .hash_blocks(path, *which, *block, *len)
                .map(Response::Hashes),
            Request::ReadRange { path, off, len } => self.read_range(path, *off, *len),
            Request::WriteRange {
                path,
                inplace,
                off,
                hash,
                data,
            } => self
                .write_range(path, *inplace, *off, *hash, data)
                .map(|_| Response::Ok),
            Request::Finalize {
                path,
                inplace,
                meta,
                flags,
                fsync,
            } => self
                .finalize(path, *inplace, meta, *flags, *fsync)
                .map(|_| Response::Ok),
            Request::FileHash { path } => self.file_hash(path),
            Request::Canonicalize { path } => {
                Ok(Response::Path(path_bytes(&normalize(&resolve(path)))))
            }
            Request::Hello { .. }
            | Request::Scan { .. }
            | Request::Shutdown
            | Request::TcpListen { .. } => Err(anyhow!("unexpected request")),
        };
        match r {
            Ok(resp) => resp,
            Err(e) => Response::Err(errstr(&e)),
        }
    }
}

/// Open `target` for writing as a regular file, replacing any existing
/// symlink/dir/special and refusing to follow a symlink (O_NOFOLLOW), then
/// verify the opened fd is a regular file. Used for every write target so a
/// malicious or stale `.pcp-partial` symlink can't redirect the write.
fn open_regular_write(target: &Path, mode: u32) -> Result<File> {
    if let Ok(md) = fs::symlink_metadata(target) {
        if !md.is_file() {
            if md.is_dir() {
                bail!("destination {} is a directory", target.display());
            }
            fs::remove_file(target).with_context(|| format!("replace {}", target.display()))?;
        }
    }
    let f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode & 0o7777)
        .open(target)
        .with_context(|| format!("create {}", target.display()))?;
    let md = f.metadata()?;
    if !md.file_type().is_file() {
        bail!("{} is not a regular file", target.display());
    }
    Ok(f)
}

fn mkdir(p: &Path, mode: u32) -> Result<()> {
    std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), (mode & 0o7777) | 0o700)
        .create(p)?;
    Ok(())
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

fn fsync_parent(path: &Path) -> Result<()> {
    let dir = path
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file = File::open(dir).with_context(|| format!("open {} for fsync", dir.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync directory {}", dir.display()))
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
