//! Local filesystem operations. Used directly by the local endpoint and
//! by `syq --server` for remote endpoints, so both sides behave identically.

use crate::proto::*;
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, OsStr, OsString};
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

/// A receiver-side selection retained from the ownership walk until it is
/// either created or made the connection's working directory. Keeping the fd,
/// rather than just its identity, closes the post-check pathname race.
struct OperatorDirectorySelection {
    path: PathBytes,
    directory: File,
    missing: VecDeque<Vec<u8>>,
}

impl OperatorDirectorySelection {
    fn anchor(&self) -> Result<DirectoryAnchor> {
        let metadata = self.directory.metadata()?;
        Ok(DirectoryAnchor {
            path: self.path.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn create_missing(&mut self, mode: u32) -> Result<DirectoryAnchor> {
        while let Some(component) = self.missing.pop_front() {
            if component == b"." {
                continue;
            }
            if component == b".." {
                self.directory = open_operator_directory_at(&self.directory, b"..")?;
                continue;
            }
            match operator_lstat_at(&self.directory, &component) {
                Ok(metadata) if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
                Ok(_) => bail!(
                    "destination path component {:?} appeared with an unsafe type while creating the destination",
                    OsStr::from_bytes(&component)
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // Match create_dir_all's historical behavior: intermediate
                    // components start at 0777 (subject to umask), while the
                    // requested mode applies to the selected destination root.
                    let component_mode = if self.missing.is_empty() { mode } else { 0o777 };
                    match mkdir_operator_directory_at(
                        &self.directory,
                        &component,
                        component_mode,
                    ) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            match operator_lstat_at(&self.directory, &component) {
                                Ok(metadata)
                                    if metadata.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
                                Ok(_) => bail!(
                                    "destination path component {:?} appeared with an unsafe type while creating the destination",
                                    OsStr::from_bytes(&component)
                                ),
                                Err(error) => return Err(error.into()),
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
            self.directory = open_operator_directory_at(&self.directory, &component)?;
        }
        self.anchor()
    }
}

/// Resolve an operator-selected directory with rsync's ownership rule:
/// symlinks at any component are followed only when owned by uid 0 or by this
/// process's effective uid. The descriptor remains in the returned selection.
fn select_operator_directory(
    path: &[u8],
    allow_missing: bool,
    insecure_links: bool,
) -> Result<(OperatorDirectorySelection, Option<DirectoryAnchor>)> {
    let path = resolve(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let raw = path.as_os_str().as_bytes();
    if raw.contains(&0) {
        bail!("destination path contains NUL");
    }

    let absolute = raw.starts_with(b"/");
    let mut directory = open_operator_directory_start(absolute)?;
    let mut remaining: VecDeque<Vec<u8>> = raw
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    let mut symlink_hops = 0usize;

    while let Some(component) = remaining.pop_front() {
        if component == b"." {
            continue;
        }
        if component == b".." {
            directory = open_operator_directory_at(&directory, b"..")?;
            continue;
        }

        let metadata = match operator_lstat_at(&directory, &component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound && allow_missing => {
                remaining.push_front(component);
                let selection = OperatorDirectorySelection {
                    path: path_bytes(&path),
                    directory,
                    missing: remaining,
                };
                return Ok((selection, None));
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
            let euid = unsafe { libc::geteuid() };
            if !insecure_links && !operator_symlink_owner_is_trusted(metadata.st_uid, euid) {
                bail!(
                    "refusing symlink component {:?} owned by uid {}; expected uid 0 or receiver uid {}",
                    OsStr::from_bytes(&component),
                    metadata.st_uid,
                    euid
                );
            }
            symlink_hops += 1;
            if symlink_hops > 40 {
                bail!("too many symlink levels in destination path");
            }
            let target = operator_readlink_at(&directory, &component)?;
            if target.starts_with(b"/") {
                directory = open_operator_directory_start(true)?;
            }
            let mut expanded: VecDeque<Vec<u8>> = target
                .split(|byte| *byte == b'/')
                .filter(|part| !part.is_empty())
                .map(<[u8]>::to_vec)
                .collect();
            expanded.append(&mut remaining);
            remaining = expanded;
            continue;
        }

        if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR).into());
        }
        directory = open_operator_directory_at(&directory, &component)?;
    }

    let selection = OperatorDirectorySelection {
        path: path_bytes(&path),
        directory,
        missing: VecDeque::new(),
    };
    let anchor = selection.anchor()?;
    Ok((selection, Some(anchor)))
}

fn operator_symlink_owner_is_trusted(owner: u32, euid: u32) -> bool {
    owner == 0 || owner == euid
}

fn operator_directory_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }
}

fn open_operator_directory_start(absolute: bool) -> Result<File> {
    let component = if absolute { c"/" } else { c"." };
    open_operator_directory_fd(libc::AT_FDCWD, component)
}

fn open_operator_directory_at(parent: &File, component: &[u8]) -> Result<File> {
    let component = CString::new(component).expect("path component was checked for NUL");
    open_operator_directory_fd(parent.as_raw_fd(), &component)
}

fn open_operator_directory_fd(parent: libc::c_int, component: &CStr) -> Result<File> {
    loop {
        let fd = unsafe { libc::openat(parent, component.as_ptr(), operator_directory_flags()) };
        if fd >= 0 {
            let file = unsafe { File::from_raw_fd(fd) };
            if !file.metadata()?.is_dir() {
                bail!("destination path component is not a directory");
            }
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn mkdir_operator_directory_at(parent: &File, component: &[u8], mode: u32) -> io::Result<()> {
    let component = CString::new(component).expect("path component was checked for NUL");
    loop {
        let result = unsafe {
            libc::mkdirat(
                parent.as_raw_fd(),
                component.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn operator_lstat_at(parent: &File, component: &[u8]) -> io::Result<libc::stat> {
    let component = CString::new(component).expect("path component was checked for NUL");
    loop {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                component.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(unsafe { metadata.assume_init() });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn operator_readlink_at(parent: &File, component: &[u8]) -> io::Result<Vec<u8>> {
    let component = CString::new(component).expect("path component was checked for NUL");
    let mut capacity = 256usize;
    loop {
        let mut target = Vec::<u8>::with_capacity(capacity);
        let length = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                component.as_ptr(),
                target.as_mut_ptr().cast(),
                capacity,
            )
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let length = length as usize;
        if length < capacity {
            unsafe { target.set_len(length) };
            return Ok(target);
        }
        capacity = capacity
            .checked_mul(2)
            .filter(|next| *next <= libc::PATH_MAX as usize * 2)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENAMETOOLONG))?;
    }
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

fn process_initial_cwd() -> PathBuf {
    static INITIAL_CWD: OnceLock<PathBuf> = OnceLock::new();
    INITIAL_CWD
        .get_or_init(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        .clone()
}

pub struct FsOps {
    fds: HashMap<FdKey, File>,
    fd_order: Vec<FdKey>,
    /// One final-file descriptor retained between the hash response and the
    /// controller's decision to repair or accept that exact inode.
    held_basis: Option<HeldBasis>,
    operator_selection: Option<OperatorDirectorySelection>,
    destination_root: Option<File>,
    destination_prefix: Option<PathBytes>,
    initial_cwd: PathBuf,
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
            operator_selection: None,
            destination_root: None,
            destination_prefix: None,
            initial_cwd: process_initial_cwd(),
        }
    }

    fn check_operator_directory(
        &mut self,
        path: &[u8],
        allow_missing: bool,
        insecure_links: bool,
    ) -> Result<Option<DirectoryAnchor>> {
        let (selection, anchor) = select_operator_directory(path, allow_missing, insecure_links)?;
        self.operator_selection = Some(selection);
        Ok(anchor)
    }

    fn create_operator_directory(&mut self, mode: u32) -> Result<DirectoryAnchor> {
        self.operator_selection
            .as_mut()
            .context("no checked destination directory to create")?
            .create_missing(mode)
    }

    fn anchor_destination(
        &mut self,
        path: Option<&[u8]>,
        expected_dev: u64,
        expected_ino: u64,
        request_prefix: &[u8],
        insecure_links: bool,
    ) -> Result<()> {
        let selection = if let Some(path) = path {
            match select_operator_directory(path, false, insecure_links) {
                Ok((selection, Some(anchor)))
                    if (anchor.dev, anchor.ino) == (expected_dev, expected_ino) =>
                {
                    selection
                }
                result => {
                    // TCP workers share the receiver process with the already
                    // anchored control connection. If the external spelling
                    // was replaced after selection, its cwd is still the exact
                    // retained directory and is safe to reuse.
                    let directory = open_operator_directory_start(false)?;
                    let metadata = directory.metadata()?;
                    if (metadata.dev(), metadata.ino()) != (expected_dev, expected_ino) {
                        match result {
                            Ok((_, Some(anchor))) => bail!(
                                "destination root changed identity (expected {expected_dev}:{expected_ino}, found {}:{})",
                                anchor.dev,
                                anchor.ino
                            ),
                            Ok((_, None)) => bail!("destination root disappeared before worker setup"),
                            Err(error) => return Err(error),
                        }
                    }
                    OperatorDirectorySelection {
                        path: path.to_vec(),
                        directory,
                        missing: VecDeque::new(),
                    }
                }
            }
        } else {
            self.operator_selection
                .take()
                .context("destination directory was not checked on this connection")?
        };
        if !selection.missing.is_empty() {
            bail!("destination directory has not been created");
        }
        let anchor = selection.anchor()?;
        if (anchor.dev, anchor.ino) != (expected_dev, expected_ino) {
            bail!(
                "destination root changed identity (expected {expected_dev}:{expected_ino}, found {}:{})",
                anchor.dev,
                anchor.ino
            );
        }
        loop {
            if unsafe { libc::fchdir(selection.directory.as_raw_fd()) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("enter retained destination root");
            }
        }
        self.fds.clear();
        self.fd_order.clear();
        self.held_basis.take();
        self.destination_prefix = Some(request_prefix.to_vec());
        self.destination_root = Some(selection.directory);

        #[cfg(debug_assertions)]
        if path.is_none() {
            if let Some(ready) = std::env::var_os("SYQ_TEST_DESTINATION_ANCHORED_FILE") {
                fs::write(&ready, b"ready").with_context(|| {
                    format!(
                        "write destination-anchor-ready signal {}",
                        Path::new(&ready).display()
                    )
                })?;
            }
            if let Some(ms) = std::env::var_os("SYQ_TEST_HOLD_DESTINATION_ANCHOR_MS") {
                if let Ok(ms) = ms.to_string_lossy().parse::<u64>() {
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                }
            }
        }
        Ok(())
    }

    fn destination_relative(&self, path: &[u8]) -> Result<PathBytes> {
        let Some(prefix) = self.destination_prefix.as_deref() else {
            return Ok(path.to_vec());
        };
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

    fn destination_full(&self, relative: &[u8]) -> PathBytes {
        let prefix = self
            .destination_prefix
            .as_deref()
            .expect("relative response requires an active destination root");
        join(prefix, relative)
    }

    fn partial_path(&self, final_path: &Path, partial_id: &PartialId) -> Result<PathBuf> {
        if self.destination_prefix.is_none() {
            return partial_path(final_path, partial_id);
        }
        let relative = path_bytes(final_path);
        let logical = PathBuf::from(OsStr::from_bytes(&self.destination_full(&relative)));
        let parent = if final_path
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty())
        {
            final_path.parent().unwrap()
        } else {
            Path::new(".")
        };
        let logical_partial = partial_path_with_name_max(&logical, partial_id, name_max(parent))?;
        Ok(PathBuf::from(OsStr::from_bytes(
            &self.destination_relative(logical_partial.as_os_str().as_bytes())?,
        )))
    }

    fn logical_destination_path(&self, relative: &Path) -> PathBuf {
        if self.destination_prefix.is_some() {
            PathBuf::from(OsStr::from_bytes(
                &self.destination_full(relative.as_os_str().as_bytes()),
            ))
        } else {
            relative.to_path_buf()
        }
    }

    fn initial_absolute(&self, path: &[u8]) -> PathBytes {
        let path = resolve(path);
        let absolute = if path.is_absolute() {
            path
        } else {
            self.initial_cwd.join(path)
        };
        path_bytes(&absolute)
    }

    fn map_request(&self, req: &Request) -> Result<Request> {
        if self.destination_prefix.is_none() {
            return Ok(req.clone());
        }
        let mut req = req.clone();
        let map = |path: &mut PathBytes| -> Result<()> {
            *path = self.destination_relative(path)?;
            Ok(())
        };
        match &mut req {
            Request::Scan { root, .. } => map(root)?,
            Request::StatMany { paths, .. } | Request::PartialPaths { paths, .. } => {
                for path in paths {
                    map(path)?;
                }
            }
            Request::PlanBatch {
                partial_paths,
                directories,
                others,
                ..
            } => {
                for path in partial_paths.iter_mut().chain(directories).chain(others) {
                    map(path)?;
                }
            }
            Request::Apply(ops) => {
                for op in ops {
                    let path = match op {
                        Op::Mkdir { path, .. }
                        | Op::Symlink { path, .. }
                        | Op::Mknod { path, .. }
                        | Op::SetMeta { path, .. }
                        | Op::SetFileMetaIfSame { path, .. }
                        | Op::Remove { path }
                        | Op::Rmdir { path }
                        | Op::Unlink { path } => path,
                    };
                    map(path)?;
                }
            }
            Request::ProbePartial { path, .. }
            | Request::Prepare { path, .. }
            | Request::HashAndHold { path, .. }
            | Request::FinishBasis { path, .. }
            | Request::SeedBasis { path, .. }
            | Request::HashBlocks { path, .. }
            | Request::ReadRange { path, .. }
            | Request::WriteRange { path, .. }
            | Request::Finalize { path, .. }
            | Request::FileHash { path }
            | Request::Canonicalize { path } => map(path)?,
            Request::CopyLocal { src, dst, .. } => {
                *src = self.initial_absolute(src);
                map(dst)?;
            }
            Request::ReadSmallBatch(reads) => {
                for read in reads {
                    map(&mut read.path)?;
                }
            }
            Request::PutSmallBatch(puts) => {
                for put in puts {
                    map(&mut put.path)?;
                }
            }
            Request::Hello { .. }
            | Request::TcpListen { .. }
            | Request::CheckOperatorDirectory { .. }
            | Request::CreateOperatorDirectory { .. }
            | Request::AnchorDestination { .. }
            | Request::TransportStats
            | Request::Shutdown => {}
        }
        Ok(req)
    }

    pub fn scan_root(&self, root: &[u8]) -> Result<PathBytes> {
        self.destination_relative(root)
    }

    fn rebase_response(&self, response: Response) -> Response {
        if self.destination_prefix.is_none() {
            return response;
        }
        match response {
            Response::PathResults(paths) => Response::PathResults(
                paths
                    .into_iter()
                    .map(|path| path.map(|path| self.destination_full(&path)))
                    .collect(),
            ),
            Response::BatchPlan {
                partial_paths,
                directories,
                others,
            } => Response::BatchPlan {
                partial_paths: partial_paths
                    .into_iter()
                    .map(|path| path.map(|path| self.destination_full(&path)))
                    .collect(),
                directories,
                others,
            },
            response => response,
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
            self.partial_path(&resolve(path), partial_id)
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
    pub fn apply(&mut self, ops: &[Op]) -> Vec<Option<String>> {
        // SetMeta depends on the object existing, so create everything first,
        // then apply metadata — otherwise a parallel SetMeta can beat its
        // Symlink/Mknod/Mkdir. Both phases still run in parallel internally.
        let is_meta = |op: &Op| matches!(op, Op::SetMeta { .. } | Op::SetFileMetaIfSame { .. });
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
                    Ok(md) if md.is_dir() => make_dir_writable(&p, &md),
                    Ok(_) => {
                        fs::remove_file(&p)?;
                        mkdir_or_existing_dir(&p, *mode)
                    }
                    Err(_) => {
                        if let Some(parent) = p.parent() {
                            if !parent.as_os_str().is_empty() && !parent.exists() {
                                fs::create_dir_all(parent)?;
                            }
                        }
                        mkdir_or_existing_dir(&p, *mode)
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
                fail_set_meta_for_test(&p)?;
                set_meta_path(&p, meta, *flags)
                    .with_context(|| format!("set metadata {}", p.display()))
            }
            Op::SetFileMetaIfSame {
                path,
                expected_dev,
                expected_ino,
                meta,
                flags,
            } => {
                let p = resolve(path);
                #[cfg(debug_assertions)]
                fail_set_meta_for_test(&p)?;
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
                        // If the original inode is still present, preserve the
                        // useful open error. Otherwise the planned repair is no
                        // longer complete and must be visible as a copy error.
                        match fs::symlink_metadata(&p) {
                            Ok(md)
                                if md.file_type().is_file()
                                    && md.dev() == *expected_dev
                                    && md.ino() == *expected_ino =>
                            {
                                return Err(open_error).with_context(|| {
                                    format!("open {} for metadata repair", p.display())
                                });
                            }
                            _ => {
                                bail!("destination {} changed before metadata repair", p.display())
                            }
                        }
                    }
                };
                let md = file.metadata()?;
                if !md.file_type().is_file()
                    || md.dev() != *expected_dev
                    || md.ino() != *expected_ino
                {
                    bail!("destination {} changed before metadata repair", p.display());
                }
                set_meta_handle(&file, meta, *flags)
                    .with_context(|| format!("set metadata {}", p.display()))
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
        let pp = self.partial_path(&p, partial_id)?;
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

    pub fn prepare(
        &mut self,
        path: &[u8],
        size: u64,
        inplace: bool,
        partial_id: &PartialId,
        mode: u32,
    ) -> Result<()> {
        let p = resolve(path);
        if inplace {
            self.uncache(&p);
            // A stale partial from an interrupted run would otherwise be orphaned.
            if let Ok(pp) = self.partial_path(&p, partial_id) {
                let _ = fs::remove_file(pp);
            }
            let f = open_regular_write(&p, mode, false)?;
            f.set_len(size)?;
            return Ok(());
        }
        let pp = self.partial_path(&p, partial_id)?;
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
    ) -> Result<(Vec<u64>, u64)> {
        let p = resolve(path);
        #[cfg(debug_assertions)]
        if std::env::var_os("SYQ_TEST_FAIL_HASH_BASIS").is_some() {
            bail!("injected retained-basis hash failure");
        }
        let mut file = open_existing_regular(&p, false)
            .with_context(|| format!("open {} as repair basis", p.display()))?;
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
    ) -> Result<()> {
        let held = self.take_held_basis(path, partial_id)?;
        set_meta_file(&held.file, meta, flags)
            .with_context(|| format!("set metadata on basis {}", held.path.display()))?;
        Ok(())
    }

    pub fn seed_basis(&mut self, path: &[u8], partial_id: &PartialId, len: u64) -> Result<()> {
        let mut held = self.take_held_basis(path, partial_id)?;
        let pp = self.partial_path(&held.path, partial_id)?;
        let (dst, _) = self.open_private_partial(&pp)?;
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
            self.partial_path(&dp, partial_id)?
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
    ) -> Result<()> {
        if xxh3_64(data) != hash {
            bail!("block hash mismatch on receive");
        }
        let p = resolve(target.path);
        self.uncache(&p);
        let pp = self.partial_path(&p, target.id)?;
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
        if let Some(pat) = std::env::var_os("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME") {
            // Test hook (debug builds only): model interruption after the
            // sidecar is complete but before it becomes the final name.
            let logical = self.logical_destination_path(&p);
            if !pat.is_empty() && logical.as_os_str().as_bytes().ends_with(pat.as_bytes()) {
                bail!("put small {}: injected failure before rename", p.display());
            }
        }
        fs::rename(&pp, &p)
            .with_context(|| format!("rename {} to {}", pp.display(), p.display()))?;
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
            self.partial_path(&p, partial_id)?
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
            self.partial_path(&p, target.id)?
        };
        let f = self.cached(&p, true, attempt, !inplace)?;
        f.write_all_at(data, off)
            .with_context(|| format!("write {} @{off}", p.display()))
    }

    pub fn finalize(
        &mut self,
        path: &[u8],
        inplace: bool,
        partial_id: &PartialId,
        meta: &Meta,
        flags: u8,
    ) -> Result<()> {
        let p = resolve(path);
        let src = if inplace {
            p.clone()
        } else {
            self.partial_path(&p, partial_id)?
        };
        let f = self
            .uncache(&src)
            .map(Ok)
            .unwrap_or_else(|| open_existing_regular(&src, true))?;
        if inplace {
            if !f.metadata()?.file_type().is_file() {
                bail!("destination {} is not a regular file", src.display());
            }
        } else {
            require_safe_partial(&f, &src)?;
        }
        set_meta_file(&f, meta, flags)
            .with_context(|| format!("set metadata {}", src.display()))?;
        if !inplace {
            if fs::symlink_metadata(&p).is_ok_and(|metadata| metadata.is_dir()) {
                bail!("destination {} is a directory", p.display());
            }
            fs::rename(&src, &p).with_context(|| {
                format!("publish {} as destination {}", src.display(), p.display())
            })?;
        }
        drop(f);
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
        let req = match self.map_request(req) {
            Ok(req) => req,
            Err(error) => return Response::Err(errstr(&error)),
        };
        // HashAndHold's next request must consume the retained descriptor.
        // Any other request means the controller abandoned that comparison
        // (for example because the source hash failed), so release it here.
        if !matches!(
            &req,
            Request::FinishBasis { .. } | Request::SeedBasis { .. }
        ) {
            self.held_basis.take();
        }
        let r: Result<Response> = match &req {
            Request::StatMany { paths, follow } => {
                Ok(Response::Stats(self.stat_many(paths, *follow)))
            }
            Request::CheckOperatorDirectory {
                path,
                allow_missing,
                insecure_links,
            } => self
                .check_operator_directory(path, *allow_missing, *insecure_links)
                .with_context(|| {
                    format!(
                        "resolve operator destination directory {}",
                        resolve(path).display()
                    )
                })
                .map(Response::DirectorySelection),
            Request::CreateOperatorDirectory { mode } => self
                .create_operator_directory(*mode)
                .map(|anchor| Response::DirectorySelection(Some(anchor))),
            Request::AnchorDestination {
                path,
                expected_dev,
                expected_ino,
                request_prefix,
                insecure_links,
            } => self
                .anchor_destination(
                    path.as_deref(),
                    *expected_dev,
                    *expected_ino,
                    request_prefix,
                    *insecure_links,
                )
                .map(|_| Response::Ok),
            Request::PartialPaths { paths, partial_id } => {
                Ok(Response::PathResults(self.partial_paths(paths, partial_id)))
            }
            Request::PlanBatch {
                partial_paths,
                partial_id,
                directories,
                others,
            } => {
                let partial_paths = self.partial_paths(partial_paths, partial_id);
                let directories = self.stat_many(directories, false);
                let safe_to_stat_others = directories.iter().all(|entry| {
                    entry
                        .as_ref()
                        .is_some_and(|entry| entry.kind == Kind::Dir && entry.mode & 0o700 == 0o700)
                });
                let others = safe_to_stat_others.then(|| self.stat_many(others, false));
                Ok(Response::BatchPlan {
                    partial_paths,
                    directories,
                    others,
                })
            }
            Request::Apply(ops) => Ok(Response::Applied(self.apply(ops))),
            Request::ProbePartial { path, partial_id } => self.probe_partial(path, partial_id),
            Request::Prepare {
                path,
                size,
                inplace,
                partial_id,
                mode,
            } => self
                .prepare(path, *size, *inplace, partial_id, *mode)
                .map(|_| Response::Ok),
            Request::HashAndHold {
                path,
                partial_id,
                block,
                len,
            } => self
                .hash_and_hold(path, partial_id, *block, *len)
                .map(|(hashes, len)| Response::HeldHashes { hashes, len }),
            Request::FinishBasis {
                path,
                partial_id,
                meta,
                flags,
            } => self
                .finish_basis(path, partial_id, meta, *flags)
                .map(|_| Response::Ok),
            Request::SeedBasis {
                path,
                partial_id,
                len,
            } => self
                .seed_basis(path, partial_id, *len)
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
            Request::PutSmallBatch(puts) => Ok(Response::Applied(
                puts.iter()
                    .map(|put| {
                        self.put_small(
                            PartialTarget {
                                path: &put.path,
                                id: &put.partial_id,
                            },
                            &put.data,
                            put.hash,
                            &put.meta,
                            put.flags,
                        )
                        .err()
                        .map(|error| errstr(&error))
                    })
                    .collect(),
            )),
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
            Request::ReadSmallBatch(reads) => Ok(Response::SmallBlocks(
                reads
                    .iter()
                    .map(
                        |read| match self.read_range(&read.path, read.attempt, 0, read.len) {
                            Ok(Response::Block { data, hash, .. }) => Ok(SmallBlock { data, hash }),
                            Ok(other) => Err(format!("unexpected response {other:?}")),
                            Err(error) => Err(errstr(&error)),
                        },
                    )
                    .collect(),
            )),
            Request::WriteRange {
                path,
                inplace,
                partial_id,
                attempt,
                off,
                hash,
                data,
            } => self
                .write_range(
                    PartialTarget {
                        path,
                        id: partial_id,
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
            } => self
                .finalize(path, *inplace, partial_id, meta, *flags)
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
            Ok(resp) => self.rebase_response(resp),
            Err(e) => Response::Err(errstr(&e)),
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
    use std::os::unix::fs::symlink;
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
    fn operator_directory_walk_follows_owned_links_and_reports_missing_suffixes() {
        let dir = test_dir();
        let real = dir.join("real/nested");
        fs::create_dir_all(&real).unwrap();
        symlink("real", dir.join("relative-link")).unwrap();
        symlink(dir.join("real"), dir.join("absolute-link")).unwrap();

        let expected = fs::metadata(&real).unwrap();
        for selected in [
            dir.join("relative-link/nested"),
            dir.join("absolute-link/nested"),
        ] {
            let (_, anchor) =
                select_operator_directory(selected.as_os_str().as_bytes(), false, false).unwrap();
            let anchor = anchor.unwrap();
            assert_eq!((anchor.dev, anchor.ino), (expected.dev(), expected.ino()));
        }
        assert!(select_operator_directory(
            dir.join("relative-link/missing/deeper")
                .as_os_str()
                .as_bytes(),
            true,
            false,
        )
        .unwrap()
        .1
        .is_none());
        assert!(select_operator_directory(
            dir.join("relative-link/missing").as_os_str().as_bytes(),
            false,
            false,
        )
        .is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_operator_directory_is_created_under_retained_ancestor() {
        let dir = test_dir();
        fs::create_dir_all(dir.join("parent")).unwrap();
        fs::create_dir_all(dir.join("outside")).unwrap();
        let (mut selection, anchor) = select_operator_directory(
            dir.join("parent/missing/deeper").as_os_str().as_bytes(),
            true,
            false,
        )
        .unwrap();
        assert!(anchor.is_none());

        fs::rename(dir.join("parent"), dir.join("selected-and-moved")).unwrap();
        symlink(dir.join("outside"), dir.join("parent")).unwrap();
        selection.create_missing(0o755).unwrap();

        assert!(dir.join("selected-and-moved/missing/deeper").is_dir());
        assert!(!dir.join("outside/missing").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_operator_directory_creation_reuses_the_real_directory() {
        let dir = test_dir();
        fs::create_dir_all(dir.join("parent")).unwrap();
        let selected = dir.join("parent/missing/deeper");
        let (mut first, first_anchor) =
            select_operator_directory(selected.as_os_str().as_bytes(), true, false).unwrap();
        let (mut second, second_anchor) =
            select_operator_directory(selected.as_os_str().as_bytes(), true, false).unwrap();
        assert!(first_anchor.is_none());
        assert!(second_anchor.is_none());

        let first_anchor = first.create_missing(0o755).unwrap();
        let second_anchor = second.create_missing(0o755).unwrap();
        assert_eq!(
            (first_anchor.dev, first_anchor.ino),
            (second_anchor.dev, second_anchor.ino)
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn operator_symlink_trust_is_root_or_receiver_ownership() {
        assert!(operator_symlink_owner_is_trusted(0, 1000));
        assert!(operator_symlink_owner_is_trusted(1000, 1000));
        assert!(!operator_symlink_owner_is_trusted(1001, 1000));
        assert!(!operator_symlink_owner_is_trusted(1000, 0));
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
        let errs = ops.apply(&[
            Op::Unlink { path: path("d") },
            Op::Unlink { path: path("f") },
            Op::Unlink {
                path: path("missing"),
            },
        ]);
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
    fn plan_batch_only_stats_leaves_below_ready_directories() {
        let root = test_dir();
        let ready = root.join("ready");
        let leaf = ready.join("leaf");
        fs::create_dir_all(&ready).unwrap();
        fs::write(&leaf, b"data").unwrap();
        let mut ops = FsOps::new();
        let request = |directory: &Path| Request::PlanBatch {
            partial_paths: vec![path_bytes(&leaf)],
            partial_id: [7; 16],
            directories: vec![path_bytes(directory)],
            others: vec![path_bytes(&leaf)],
        };

        let Response::BatchPlan {
            partial_paths,
            directories,
            others,
        } = ops.handle(&request(&ready))
        else {
            panic!("expected a batch plan");
        };
        assert!(partial_paths[0].is_ok());
        assert_eq!(directories[0].as_ref().unwrap().kind, Kind::Dir);
        assert_eq!(others.unwrap()[0].as_ref().unwrap().kind, Kind::File);

        let Response::BatchPlan {
            directories,
            others,
            ..
        } = ops.handle(&request(&root.join("missing")))
        else {
            panic!("expected a batch plan");
        };
        assert!(directories[0].is_none());
        assert!(
            others.is_none(),
            "leaf stats must wait for directory repair"
        );

        fs::set_permissions(&ready, fs::Permissions::from_mode(0o500)).unwrap();
        let Response::BatchPlan {
            directories,
            others,
            ..
        } = ops.handle(&request(&ready))
        else {
            panic!("expected a batch plan");
        };
        assert_eq!(directories[0].as_ref().unwrap().kind, Kind::Dir);
        assert!(
            others.is_none(),
            "leaf stats must wait until the directory is writable"
        );
        fs::set_permissions(&ready, fs::Permissions::from_mode(0o700)).unwrap();

        fs::remove_dir_all(&root).unwrap();
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
