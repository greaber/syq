//! End-to-end enrollment and signed restricted-transfer integration.

use crate::cli::{Args, Existence, Interface, Location, Placement};
use crate::delegation::{
    self, CopyLimitsV1, CopyOperationV1, CopyOptionsV1, CopyPolicyV1, DeletionPolicyV1,
    DestinationPlacementV1, ExistingDestinationPolicyV1, GrantOperationV1, GrantV1,
    MutationScopeV1, PublicationPolicyV1, RequestId,
};
use crate::enrollment::{
    self, AuthorizedKeyEntry, AuthorizedKeysChange, EnrollmentId, EnrollmentRoute, SshEndpoint,
    TransportPublicKey,
};
use crate::proto::{self, ContainerGuard, Op, Request};
use crate::rooted::{Root, RootIdentity};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{LineEnding, PrivateKey};
use std::collections::HashSet;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

const CONFIG_VERSION: u16 = 1;
const MAX_STATE_FILE: usize = 256 * 1024;
const MAX_AUTHORIZED_KEYS: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 100_000_000;
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;
const DEFAULT_RUNTIME_SECONDS: u32 = 23 * 60 * 60;
const GRANT_VALIDITY_SECONDS: i64 = 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ReceiverEnrollment {
    version: u16,
    pub(crate) id: EnrollmentId,
    pub(crate) target_login: String,
    pub(crate) signer: String,
    pub(crate) root: String,
    pub(crate) root_dev: u64,
    pub(crate) root_ino: u64,
    pub(crate) ssh_keygen: String,
    pub(crate) receiver_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    requested_destination: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallResponse {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    remote_home: String,
    requested_parent: String,
    canonical_root: String,
    canonical_destination: String,
    receiver_path: String,
    change: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RevokeRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    target_login: String,
    remote_home: String,
    requested_parent: String,
    canonical_root: String,
    receiver_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    target_login: String,
    requested_destination: String,
}

pub(crate) struct PreparedTransfer {
    pub(crate) private_key: PrivateKey,
    pub(crate) canonical_destination: String,
    pub(crate) grant: String,
    pub(crate) enrollment_id: EnrollmentId,
}

struct AuthorityState {
    paths: HashSet<Vec<u8>>,
    transferred_bytes: u64,
    deletions: u64,
    live_connections: u16,
    tcp_listener_started: bool,
}

/// Shared capability inherited by the authorized SSH control process and all
/// of its token-authenticated TCP workers. HostA may choose protocol messages,
/// but it cannot remove or replace this receiver-side authority.
pub(crate) struct RestrictedAuthority {
    guard: ContainerGuard,
    destination: Vec<u8>,
    copy: CopyOperationV1,
    deadline: Instant,
    control_open: AtomicBool,
    state: Mutex<AuthorityState>,
}

impl RestrictedAuthority {
    fn new(config: &ReceiverEnrollment, grant: GrantV1, deadline: Instant) -> Result<Self> {
        let GrantOperationV1::Copy(copy) = grant.operation;
        let root_path = Path::new(&config.root);
        let destination = Path::new(std::ffi::OsStr::from_bytes(&copy.destination));
        let relative = destination.strip_prefix(root_path).with_context(|| {
            format!(
                "signed destination {} is outside enrolled root {}",
                destination.display(),
                root_path.display()
            )
        })?;
        if relative.as_os_str().is_empty() {
            bail!("signed destination must be a child of the enrolled root");
        }
        crate::rooted::RelativePath::new(relative.as_os_str().as_bytes())?;
        Root::open_verified(
            root_path,
            RootIdentity {
                dev: config.root_dev,
                ino: config.root_ino,
            },
        )?;
        Ok(Self {
            guard: ContainerGuard {
                root: config.root.as_bytes().to_vec(),
                dev: config.root_dev,
                ino: config.root_ino,
            },
            destination: copy.destination.clone(),
            copy,
            deadline,
            control_open: AtomicBool::new(true),
            state: Mutex::new(AuthorityState {
                paths: HashSet::new(),
                transferred_bytes: 0,
                deletions: 0,
                live_connections: 0,
                tcp_listener_started: false,
            }),
        })
    }

    pub(crate) fn validate_hello(&self, compressed: bool) -> Result<()> {
        self.check_deadline()?;
        if compressed != self.copy.options.compressed_transport {
            bail!("transport compression does not match the signed grant");
        }
        Ok(())
    }

    pub(crate) fn maximum_connections(&self) -> u16 {
        self.copy.limits.max_connections
    }

    pub(crate) fn control_is_open(&self) -> bool {
        self.control_open.load(Ordering::Acquire) && Instant::now() <= self.deadline
    }

    pub(crate) fn close_control(&self) {
        self.control_open.store(false, Ordering::Release);
    }

    pub(crate) fn acquire_connection(&self) -> Result<()> {
        self.check_deadline()?;
        let mut state = self.state.lock().unwrap();
        if state.live_connections >= self.copy.limits.max_connections {
            bail!("signed grant connection limit exceeded");
        }
        state.live_connections += 1;
        Ok(())
    }

    pub(crate) fn release_connection(&self) {
        let mut state = self.state.lock().unwrap();
        state.live_connections = state.live_connections.saturating_sub(1);
    }

    fn check_deadline(&self) -> Result<()> {
        if Instant::now() > self.deadline {
            bail!("signed transfer execution deadline has expired");
        }
        Ok(())
    }

    fn validate_request_path(path: &[u8]) -> Result<()> {
        if path.contains(&0)
            || !path.starts_with(b"/")
            || path
                .split(|byte| *byte == b'/')
                .skip(1)
                .any(|component| component.is_empty() || component == b"." || component == b"..")
        {
            bail!("signed receiver request contains a noncanonical path");
        }
        Ok(())
    }

    fn scope_allows(scope: &MutationScopeV1, path: &[u8]) -> bool {
        path == scope.path
            || (scope.descendants
                && path.starts_with(&scope.path)
                && path.get(scope.path.len()) == Some(&b'/'))
    }

    fn record_path(&self, path: &[u8]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.paths.insert(path.to_vec())
            && state.paths.len() as u64 > self.copy.limits.max_entries
        {
            bail!("signed grant entry limit exceeded");
        }
        Ok(())
    }

    fn check_observation_path(&self, path: &[u8]) -> Result<()> {
        Self::validate_request_path(path)?;
        if path != self.destination
            && !self
                .copy
                .mutation_scopes
                .iter()
                .any(|scope| Self::scope_allows(scope, path))
        {
            bail!("receiver observation is outside the signed destination scopes");
        }
        self.record_path(path)
    }

    fn check_mutation_path(&self, path: &[u8]) -> Result<()> {
        if self.copy.options.dry_run || self.copy.options.verify_only {
            bail!("signed read-only transfer forbids destination mutations");
        }
        Self::validate_request_path(path)?;
        if !self
            .copy
            .mutation_scopes
            .iter()
            .any(|scope| Self::scope_allows(scope, path))
        {
            bail!("receiver mutation is outside the signed destination scopes");
        }
        self.record_path(path)
    }

    fn check_flags(&self, flags: u8) -> Result<()> {
        let known =
            proto::flags::MODE | proto::flags::OWNER | proto::flags::GROUP | proto::flags::TIMES;
        if flags & !known != 0 {
            bail!("request contains unknown metadata flags");
        }
        if flags & proto::flags::MODE != 0 && !self.copy.options.preserve_permissions {
            bail!("request tries to preserve permissions not authorized by the grant");
        }
        if flags & proto::flags::OWNER != 0 && !self.copy.options.preserve_owner {
            bail!("request tries to preserve ownership not authorized by the grant");
        }
        if flags & proto::flags::GROUP != 0 && !self.copy.options.preserve_group {
            bail!("request tries to preserve group not authorized by the grant");
        }
        if flags & proto::flags::TIMES != 0 && !self.copy.options.preserve_times {
            bail!("request tries to preserve timestamps not authorized by the grant");
        }
        Ok(())
    }

    fn charge_bytes(&self, path: &[u8], offset: u64, bytes: usize) -> Result<()> {
        self.check_mutation_path(path)?;
        let bytes = u64::try_from(bytes).context("request byte count overflow")?;
        let end = offset.checked_add(bytes).context("file offset overflow")?;
        if end > self.copy.limits.max_file_bytes {
            bail!("signed grant per-file byte limit exceeded");
        }
        let mut state = self.state.lock().unwrap();
        state.transferred_bytes = state
            .transferred_bytes
            .checked_add(bytes)
            .context("signed transfer byte counter overflow")?;
        if state.transferred_bytes > self.copy.limits.max_total_bytes {
            bail!("signed grant total-byte limit exceeded");
        }
        Ok(())
    }

    fn charge_deletion(&self, path: &[u8]) -> Result<()> {
        if path == self.destination {
            bail!("the signed destination root itself may not be deleted");
        }
        self.check_mutation_path(path)?;
        if self.copy.policy.deletion == DeletionPolicyV1::Forbid {
            bail!("deletion is not authorized by the signed grant");
        }
        let mut state = self.state.lock().unwrap();
        state.deletions += 1;
        if state.deletions > self.copy.limits.max_deletions {
            bail!("signed grant deletion limit exceeded");
        }
        Ok(())
    }

    fn authorize_op(&self, operation: &mut Op) -> Result<()> {
        let path = match operation {
            Op::Mkdir { path, mode, .. } => {
                if !self.copy.options.preserve_permissions {
                    *mode = 0o700;
                }
                path
            }
            Op::SetMeta { path, .. } | Op::SetFileMetaIfSame { path, .. } => path,
            Op::Symlink { path, .. } => {
                if !self.copy.options.preserve_symlinks {
                    bail!("symlink creation is not authorized by the signed grant");
                }
                path
            }
            Op::Mknod { path, mode, .. } => {
                if !self.copy.options.preserve_devices {
                    bail!("special-file creation is not authorized by the signed grant");
                }
                if !self.copy.options.preserve_permissions {
                    #[cfg(target_os = "linux")]
                    let file_type = *mode & libc::S_IFMT;
                    #[cfg(not(target_os = "linux"))]
                    let file_type = *mode & libc::S_IFMT as u32;
                    *mode = file_type | 0o600;
                }
                path
            }
            Op::Remove { .. } => {
                bail!("recursive remove is not supported by the root-confined receiver")
            }
            Op::Rmdir { path } | Op::Unlink { path } => {
                self.charge_deletion(path)?;
                return Ok(());
            }
        };
        self.check_mutation_path(path)?;
        match operation {
            Op::SetMeta { flags, .. } | Op::SetFileMetaIfSame { flags, .. } => {
                self.check_flags(*flags)
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn authorize(&self, request: &mut Request, over_ssh: bool) -> Result<()> {
        self.check_deadline()?;
        match request {
            Request::TcpListen {
                key,
                token,
                port_lo,
                port_hi,
            } => {
                if !over_ssh {
                    bail!("TCP listener request is allowed only on the signed control connection");
                }
                if key
                    .as_ref()
                    .is_none_or(|key| key.len() != crate::crypto::KEY_LEN)
                    || token.len() != 16
                {
                    bail!("signed transfers require encrypted TCP data connections");
                }
                if (*port_lo, *port_hi)
                    != (self.copy.options.tcp_port_lo, self.copy.options.tcp_port_hi)
                {
                    bail!("TCP listener range does not match the signed grant");
                }
                let mut state = self.state.lock().unwrap();
                if state.tcp_listener_started {
                    bail!("signed grant permits only one TCP listener");
                }
                state.tcp_listener_started = true;
            }
            Request::Scan {
                root,
                follow_root,
                guard,
                ..
            } => {
                if *follow_root {
                    bail!("signed destination scans cannot follow a root symlink");
                }
                self.check_observation_path(root)?;
                *guard = Some(self.guard.clone());
            }
            Request::StatMany {
                paths,
                follow,
                guard,
            } => {
                if *follow {
                    bail!("signed destination stat cannot follow symlinks");
                }
                for path in paths {
                    self.check_observation_path(path)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::PartialPaths { paths, guard, .. } => {
                for path in paths {
                    self.check_observation_path(path)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::Apply { ops, guard } => {
                for operation in ops {
                    self.authorize_op(operation)?;
                }
                *guard = Some(self.guard.clone());
            }
            Request::ProbePartial { path, guard, .. }
            | Request::FileHash { path, guard }
            | Request::Canonicalize { path, guard } => {
                self.check_observation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::HashBlocks {
                path, len, guard, ..
            } => {
                if *len > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_observation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::HashAndHold {
                path, len, guard, ..
            } => {
                if *len > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_observation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::SeedBasis {
                path, len, guard, ..
            } => {
                if *len > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_mutation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::FinishBasis {
                path, flags, guard, ..
            } => {
                self.check_mutation_path(path)?;
                self.check_flags(*flags)?;
                *guard = Some(self.guard.clone());
            }
            Request::Prepare {
                path,
                size,
                inplace,
                guard,
                ..
            } => {
                if *inplace || self.copy.policy.publication != PublicationPolicyV1::AtomicStaged {
                    bail!("signed receiver requires atomic staged publication");
                }
                if *size > self.copy.limits.max_file_bytes {
                    bail!("signed grant per-file byte limit exceeded");
                }
                self.check_mutation_path(path)?;
                *guard = Some(self.guard.clone());
            }
            Request::WriteRange {
                path,
                inplace,
                off,
                data,
                guard,
                ..
            } => {
                if *inplace {
                    bail!("signed receiver requires atomic staged publication");
                }
                self.charge_bytes(path, *off, data.len())?;
                *guard = Some(self.guard.clone());
            }
            Request::Finalize {
                path,
                inplace,
                flags,
                guard,
                ..
            } => {
                if *inplace {
                    bail!("signed receiver requires atomic staged publication");
                }
                self.check_mutation_path(path)?;
                self.check_flags(*flags)?;
                *guard = Some(self.guard.clone());
            }
            Request::PutSmallBatch(puts) => {
                for put in puts {
                    self.charge_bytes(&put.path, 0, put.data.len())?;
                    self.check_flags(put.flags)?;
                    put.guard = Some(self.guard.clone());
                }
            }
            Request::CopyLocal { .. } | Request::ReadRange { .. } | Request::ReadSmallBatch(_) => {
                bail!("request is not valid on a command-restricted destination")
            }
            Request::Hello { .. } => bail!("unexpected second receiver handshake"),
            Request::TransportStats | Request::Shutdown => {}
        }
        Ok(())
    }
}

fn current_account() -> Result<(String, PathBuf)> {
    let uid = unsafe { libc::geteuid() };
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let capacity = if suggested > 0 {
        usize::try_from(suggested).unwrap_or(16 * 1024)
    } else {
        16 * 1024
    }
    .clamp(1024, 1024 * 1024);
    let mut buffer = vec![0u8; capacity];
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let result = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result)).context("resolve current account");
    }
    if found.is_null() || record.pw_name.is_null() || record.pw_dir.is_null() {
        bail!("current effective uid has no passwd entry");
    }
    let name = unsafe { CStr::from_ptr(record.pw_name) }
        .to_str()
        .context("current account name is not UTF-8")?
        .to_owned();
    let home = OsString::from_vec(unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes().to_vec());
    Ok((name, PathBuf::from(home)))
}

fn ensure_directory(path: &Path, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("{} is not a real directory", path.display());
            }
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                bail!(
                    "{} is not a private owner-controlled directory",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(mode)
                .create(path)
                .with_context(|| format!("create private directory {}", path.display()))?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect directory {}", path.display()))
        }
    }
    delegation::validate_trusted_directory_path(path)
}

fn ensure_private_chain(home: &Path, components: &[&str]) -> Result<PathBuf> {
    delegation::validate_trusted_directory_path(home)
        .with_context(|| format!("validate account home {}", home.display()))?;
    let mut path = home.to_path_buf();
    for component in components {
        path.push(component);
        ensure_directory(&path, 0o700)?;
    }
    delegation::validate_private_directory_path(&path)?;
    Ok(path)
}

fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open private directory {}", path.display()))
}

fn lock_directory(directory: &File) -> Result<()> {
    loop {
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("lock private directory");
        }
    }
}

fn leaf_name(name: &str) -> Result<CString> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        bail!("invalid private state filename");
    }
    CString::new(name).context("private state filename contains NUL")
}

fn read_leaf(
    directory: &File,
    name: &str,
    maximum: usize,
    private: bool,
) -> Result<Option<Vec<u8>>> {
    let name = leaf_name(name)?;
    let fd = loop {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
            )
        };
        if fd >= 0 {
            break fd;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).with_context(|| format!("open private state {name:?}"));
        }
    };
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
    {
        bail!("private state file has unsafe type, owner, or permissions");
    }
    let mut contents = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut contents)?;
    if contents.len() > maximum {
        bail!("private state file exceeds {maximum} bytes");
    }
    Ok(Some(contents))
}

fn atomic_write(directory_path: &Path, name: &str, contents: &[u8], mode: u32) -> Result<()> {
    delegation::validate_private_directory_path(directory_path)?;
    let directory = open_directory(directory_path)?;
    lock_directory(&directory)?;
    atomic_write_locked(&directory, name, contents, mode, true)
}

fn atomic_write_locked(
    directory: &File,
    name: &str,
    contents: &[u8],
    mode: u32,
    existing_private: bool,
) -> Result<()> {
    let destination = leaf_name(name)?;
    if let Some(existing) = read_leaf(directory, name, MAX_AUTHORIZED_KEYS, existing_private)? {
        let _ = existing;
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).context("generate atomic state filename")?;
    let temporary_name = format!(
        ".syq-write-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    );
    let temporary = leaf_name(&temporary_name)?;
    let fd = loop {
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NOCTTY
                    | libc::O_CLOEXEC,
                (mode & 0o600) as libc::c_int,
            )
        };
        if fd >= 0 {
            break fd;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("create atomic private state file");
        }
    };
    let mut file = unsafe { File::from_raw_fd(fd) };
    let write_result = (|| -> Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        loop {
            let result = unsafe {
                libc::renameat(
                    directory.as_raw_fd(),
                    temporary.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                )
            };
            if result == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("publish atomic private state file");
            }
        }
        directory.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = unsafe { libc::unlinkat(directory.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    write_result
}

fn remove_leaf_locked(directory: &File, name: &str) -> Result<()> {
    let name = leaf_name(name)?;
    loop {
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            directory.sync_all()?;
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("remove private state file");
        }
    }
}

fn generate_transport_key(id: EnrollmentId) -> Result<PrivateKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("generate restricted transport key")?;
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.fill(0);
    PrivateKey::new(keypair.into(), format!("syq-enrollment:{id}"))
        .context("construct restricted transport key")
}

fn signer_name(id: EnrollmentId) -> String {
    format!("syq-enrollment-{id}")
}

fn normalize_absolute(path: &str, home: &Path) -> Result<PathBuf> {
    let raw = if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        home.join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in raw.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                bail!("restricted destination must not contain .. components")
            }
            std::path::Component::Prefix(_) => bail!("unsupported destination prefix"),
        }
    }
    Ok(normalized)
}

fn requested_parent(destination: &Path) -> &Path {
    destination.parent().unwrap_or_else(|| Path::new("/"))
}

fn install_state_paths(home: &Path, id: EnrollmentId) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let base = ensure_private_chain(home, &[".local", "share", "syq", "restricted"])?;
    let enrollment = base.join(id.to_string());
    ensure_directory(&enrollment, 0o700)?;
    let replay = enrollment.join("replay");
    ensure_directory(&replay, 0o700)?;
    Ok((
        enrollment.clone(),
        enrollment.join("allowed-signers"),
        replay,
    ))
}

fn resolve_ssh_keygen() -> Result<PathBuf> {
    let candidates = std::iter::once(PathBuf::from("/usr/bin/ssh-keygen")).chain(
        std::env::var_os("PATH")
            .into_iter()
            .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
            .map(|directory| directory.join("ssh-keygen")),
    );
    for candidate in candidates {
        if candidate.is_absolute()
            && candidate
                .metadata()
                .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        {
            return fs::canonicalize(&candidate)
                .with_context(|| format!("canonicalize {}", candidate.display()));
        }
    }
    bail!("restricted receiver requires ssh-keygen for SSHSIG verification")
}

pub(crate) fn remote_install() -> Result<()> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_STATE_FILE as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_STATE_FILE {
        bail!("restricted enrollment request is too large");
    }
    let request: InstallRequest =
        serde_json::from_slice(&encoded).context("decode restricted enrollment request")?;
    if request.version != CONFIG_VERSION {
        bail!("unsupported restricted enrollment request version");
    }
    request.id.validate()?;
    let (account, home) = current_account()?;
    if account != request.target_login {
        bail!("enrollment target login does not match the remote account");
    }
    let destination = normalize_absolute(&request.requested_destination, &home)?;
    let parent = requested_parent(&destination);
    let canonical_root = fs::canonicalize(parent)
        .with_context(|| format!("resolve restricted destination parent {}", parent.display()))?;
    if !fs::metadata(&canonical_root)?.is_dir() {
        bail!("restricted destination parent is not a directory");
    }
    let leaf = destination
        .file_name()
        .context("restricted destination / is not supported")?;
    let canonical_destination = canonical_root.join(leaf);
    if fs::symlink_metadata(&canonical_destination).is_ok_and(|metadata| metadata.is_symlink()) {
        bail!(
            "command-restricted enrollment does not follow a destination-root symlink; enroll its explicit referent instead"
        );
    }
    let root = crate::rooted::Root::open(&canonical_root)?;
    let root_identity = root.identity();
    let transport = TransportPublicKey::parse(&request.public_key)?;
    let signer = signer_name(request.id);
    let public_words: Vec<&str> = request.public_key.split_ascii_whitespace().collect();
    if public_words.len() < 2 {
        bail!("transport public key is malformed");
    }
    let receiver_path = std::env::current_exe().context("resolve restricted receiver path")?;
    delegation::validate_secure_executable(&receiver_path, "restricted receiver")?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &transport)?;
    let ssh = ensure_private_chain(&home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, change) = enrollment::install_authorized_key(&normalized, &entry)?;

    // Publish the forced authorization last. A failed preflight therefore
    // cannot leave a usable key, and a later state-write failure leaves only
    // inert private state that an idempotent retry can complete.
    let (state, _allowed_signers, _replay) = install_state_paths(&home, request.id)?;
    atomic_write(
        &state,
        "allowed-signers",
        format!("{signer} {} {}\n", public_words[0], public_words[1]).as_bytes(),
        0o600,
    )?;
    let config = ReceiverEnrollment {
        version: CONFIG_VERSION,
        id: request.id,
        target_login: request.target_login.clone(),
        signer,
        root: canonical_root
            .to_str()
            .context("canonical restricted root is not UTF-8")?
            .to_owned(),
        root_dev: root_identity.dev,
        root_ino: root_identity.ino,
        ssh_keygen: resolve_ssh_keygen()?
            .to_str()
            .context("ssh-keygen path is not UTF-8")?
            .to_owned(),
        receiver_path: receiver_path
            .to_str()
            .context("restricted receiver path is not UTF-8")?
            .to_owned(),
    };
    atomic_write(&state, "config.json", &serde_json::to_vec(&config)?, 0o600)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;

    let response = InstallResponse {
        version: CONFIG_VERSION,
        id: request.id,
        target_login: request.target_login,
        remote_home: home
            .to_str()
            .context("remote account home is not UTF-8")?
            .to_owned(),
        requested_parent: parent
            .to_str()
            .context("requested destination parent is not UTF-8")?
            .to_owned(),
        canonical_root: config.root,
        canonical_destination: canonical_destination
            .to_str()
            .context("canonical destination is not UTF-8")?
            .to_owned(),
        receiver_path: receiver_path
            .to_str()
            .context("restricted receiver path is not UTF-8")?
            .to_owned(),
        change: match change {
            AuthorizedKeysChange::Installed => "installed",
            AuthorizedKeysChange::Unchanged => "unchanged",
            AuthorizedKeysChange::Revoked => unreachable!("install cannot revoke"),
        }
        .to_owned(),
    };
    serde_json::to_writer(std::io::stdout().lock(), &response)?;
    Ok(())
}

pub(crate) fn remote_revoke() -> Result<()> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take(MAX_STATE_FILE as u64 + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_STATE_FILE {
        bail!("restricted revocation request is too large");
    }
    let request: RevokeRequest = serde_json::from_slice(&encoded)?;
    if request.version != CONFIG_VERSION {
        bail!("unsupported restricted revocation request version");
    }
    request.id.validate()?;
    let (account, home) = current_account()?;
    if account != request.target_login {
        bail!("revocation target login does not match the remote account");
    }
    let state = home
        .join(".local/share/syq/restricted")
        .join(request.id.to_string());
    let (receiver_path, remove_state) = match fs::symlink_metadata(&state) {
        Ok(_) => {
            let (config, allowed_signers, _) = receiver_config(request.id)?;
            if config.target_login != request.target_login {
                bail!("revocation target login does not match receiver state");
            }
            let state = allowed_signers
                .parent()
                .context("restricted receiver state has no enrollment directory")?;
            (
                PathBuf::from(config.receiver_path),
                Some(state.to_path_buf()),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            std::env::current_exe().context("resolve restricted receiver path")?,
            None,
        ),
        Err(error) => return Err(error).context("inspect restricted receiver state"),
    };
    let transport = TransportPublicKey::parse(&request.public_key)?;
    let entry = AuthorizedKeyEntry::new(request.id, &receiver_path, &transport)?;
    let ssh = ensure_private_chain(&home, &[".ssh"])?;
    let directory = open_directory(&ssh)?;
    lock_directory(&directory)?;
    let original =
        read_leaf(&directory, "authorized_keys", MAX_AUTHORIZED_KEYS, false)?.unwrap_or_default();
    let normalized = normalize_managed_authorized_keys(&original, &entry.marker());
    let (updated, _) = enrollment::revoke_authorized_key(&normalized, &entry)?;
    atomic_write_locked(&directory, "authorized_keys", &updated, 0o600, false)?;
    drop(directory);
    if let Some(state) = remove_state {
        delegation::validate_private_directory_path(&state)?;
        fs::remove_dir_all(&state)
            .with_context(|| format!("remove revoked receiver state {}", state.display()))?;
    }
    println!("revoked {}", request.id);
    Ok(())
}

fn normalize_managed_authorized_keys(original: &[u8], marker: &str) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(original.len());
    for raw in original.split_inclusive(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let trimmed = line
            .iter()
            .copied()
            .skip_while(u8::is_ascii_whitespace)
            .collect::<Vec<_>>();
        let commented_managed = trimmed.starts_with(b"#")
            && line
                .rsplit(|byte| byte.is_ascii_whitespace())
                .find(|word| !word.is_empty())
                == Some(marker.as_bytes());
        if !commented_managed {
            normalized.extend_from_slice(line);
            normalized.push(b'\n');
        }
    }
    normalized
}

fn local_state_base() -> Result<PathBuf> {
    let (_, home) = current_account()?;
    ensure_private_chain(&home, &[".local", "state", "syq", "restricted"])
}

fn store_pending_enrollment(
    pending: &PendingEnrollment,
    private_key: &PrivateKey,
) -> Result<PathBuf> {
    let base = local_state_base()?;
    let directory = base.join(pending.id.to_string());
    ensure_directory(&directory, 0o700)?;
    store_pending_files(&directory, pending, private_key)?;
    Ok(directory)
}

fn store_pending_files(
    directory: &Path,
    pending: &PendingEnrollment,
    private_key: &PrivateKey,
) -> Result<()> {
    let private = private_key
        .to_openssh(LineEnding::LF)
        .context("encode restricted transport private key")?;
    atomic_write(directory, "transport", private.as_bytes(), 0o600)?;
    atomic_write(
        directory,
        "pending.json",
        &serde_json::to_vec(pending)?,
        0o600,
    )
}

fn complete_local_enrollment(directory: &Path, metadata: &LocalEnrollment) -> Result<()> {
    atomic_write(
        directory,
        "metadata.json",
        &serde_json::to_vec(metadata)?,
        0o600,
    )?;
    let directory = open_directory(directory)?;
    lock_directory(&directory)?;
    remove_leaf_locked(&directory, "pending.json")
}

fn load_local_enrollments() -> Result<Vec<(LocalEnrollment, PathBuf)>> {
    let base = local_state_base()?;
    let mut enrollments = Vec::new();
    for entry in fs::read_dir(&base).with_context(|| format!("list {}", base.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if delegation::validate_private_directory_path(&directory).is_err() {
            continue;
        }
        let metadata_path = directory.join("metadata.json");
        let Ok(encoded) = delegation::read_secure_regular(
            &metadata_path,
            "local enrollment metadata",
            MAX_STATE_FILE,
        ) else {
            continue;
        };
        let Ok(metadata) = serde_json::from_slice::<LocalEnrollment>(&encoded) else {
            continue;
        };
        if metadata.version == CONFIG_VERSION
            && metadata.id.to_string() == entry.file_name().to_string_lossy()
        {
            enrollments.push((metadata, directory));
        }
    }
    Ok(enrollments)
}

fn load_pending_enrollments() -> Result<Vec<(PendingEnrollment, PathBuf)>> {
    let base = local_state_base()?;
    let mut enrollments = Vec::new();
    for entry in fs::read_dir(&base).with_context(|| format!("list {}", base.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory = entry.path();
        if delegation::validate_private_directory_path(&directory).is_err() {
            continue;
        }
        let metadata_path = directory.join("pending.json");
        let Ok(encoded) = delegation::read_secure_regular(
            &metadata_path,
            "pending local enrollment metadata",
            MAX_STATE_FILE,
        ) else {
            continue;
        };
        let Ok(metadata) = serde_json::from_slice::<PendingEnrollment>(&encoded) else {
            continue;
        };
        if metadata.version == CONFIG_VERSION
            && metadata.id.to_string() == entry.file_name().to_string_lossy()
        {
            enrollments.push((metadata, directory));
        }
    }
    enrollments.sort_by_key(|(metadata, _)| metadata.id.to_string());
    Ok(enrollments)
}

fn load_private_key(directory: &Path) -> Result<PrivateKey> {
    let encoded = delegation::read_secure_regular(
        &directory.join("transport"),
        "restricted transport private key",
        128 * 1024,
    )?;
    PrivateKey::from_openssh(&encoded).context("parse restricted transport private key")
}

fn run_ssh(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    remote_command: &str,
    input: &[u8],
) -> Result<Vec<u8>> {
    let args = enrollment::enrollment_ssh_args_raw(target, route, remote_command);
    let mut command = Command::new("ssh");
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("start restricted enrollment SSH")?;
    let mut stdin = child
        .stdin
        .take()
        .context("enrollment SSH stdin unavailable")?;
    stdin.write_all(input)?;
    drop(stdin);
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "restricted enrollment SSH failed ({}): {}",
            output.status,
            if diagnostic.is_empty() {
                "no diagnostic"
            } else {
                &diagnostic
            }
        );
    }
    Ok(output.stdout)
}

fn install_over_route(
    target: &SshEndpoint,
    route: EnrollmentRoute<'_>,
    request: &InstallRequest,
) -> Result<InstallResponse> {
    let executable = std::env::current_exe().context("resolve local syq executable")?;
    let mut binary = File::open(&executable)
        .with_context(|| format!("open local syq executable {}", executable.display()))?;
    let metadata = binary.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o022 != 0 {
        bail!("local syq executable is not a trusted regular file");
    }
    let mut bytes = Vec::new();
    binary.read_to_end(&mut bytes)?;
    let upload = "set -eu; d=\"$HOME/.local/libexec\"; umask 077; mkdir -p -- \"$d\"; t=\"$d/.syq-receiver.$$\"; trap 'rm -f -- \"$t\"' EXIT HUP INT TERM; cat >\"$t\"; chmod 700 \"$t\"; mv -f -- \"$t\" \"$d/syq-receiver\"; trap - EXIT HUP INT TERM";
    run_ssh(target, route.clone(), upload, &bytes)?;
    let expected_id = request.id;
    let expected_login = request.target_login.clone();
    let request = serde_json::to_vec(request)?;
    let output = run_ssh(
        target,
        route,
        "exec \"$HOME/.local/libexec/syq-receiver\" --restricted-install",
        &request,
    )?;
    let response: InstallResponse =
        serde_json::from_slice(&output).context("decode restricted enrollment response")?;
    if response.version != CONFIG_VERSION
        || response.id != expected_id
        || response.target_login != expected_login
    {
        bail!("restricted enrollment response did not match the request");
    }
    Ok(response)
}

fn endpoint(login: &str, host: &str) -> Result<SshEndpoint> {
    SshEndpoint::parse(&format!("{login}@{host}"))
}

fn enroll(
    host: &str,
    login: &str,
    requested_destination: &str,
    jump: Option<&SshEndpoint>,
    refresh_existing: bool,
) -> Result<(LocalEnrollment, PathBuf, String)> {
    let base = local_state_base()?;
    let base_lock = open_directory(&base)?;
    lock_directory(&base_lock)?;

    let mut active = None;
    for (metadata, directory) in load_local_enrollments()? {
        if metadata.host == host && metadata.target_login == login {
            if let Some(canonical_destination) = destination_for(&metadata, requested_destination)?
            {
                active = Some((metadata, directory, canonical_destination));
                break;
            }
        }
    }
    if !refresh_existing {
        if let Some(existing) = active.take() {
            return Ok(existing);
        }
    }
    let retry_state = if active.is_some() {
        "remains active with its previous metadata; the receiver refresh can be retried"
    } else {
        "remains pending for a safe retry"
    };

    let pending = if active.is_none() {
        load_pending_enrollments()?
            .into_iter()
            .find(|(pending, _)| {
                pending.host == host
                    && pending.target_login == login
                    && pending.requested_destination == requested_destination
            })
    } else {
        None
    };
    let (pending, directory, private_key) = match (active, pending) {
        (Some((metadata, directory, _)), _) => {
            let private_key = load_private_key(&directory)?;
            let pending = PendingEnrollment {
                version: CONFIG_VERSION,
                id: metadata.id,
                host: metadata.host,
                target_login: metadata.target_login,
                requested_destination: requested_destination.to_owned(),
            };
            (pending, directory, private_key)
        }
        (None, Some((pending, directory))) => {
            let private_key = load_private_key(&directory)?;
            (pending, directory, private_key)
        }
        (None, None) => {
            let id = EnrollmentId::random();
            let private_key = generate_transport_key(id)?;
            let pending = PendingEnrollment {
                version: CONFIG_VERSION,
                id,
                host: host.to_owned(),
                target_login: login.to_owned(),
                requested_destination: requested_destination.to_owned(),
            };
            let directory = store_pending_enrollment(&pending, &private_key)?;
            (pending, directory, private_key)
        }
    };
    let public_key = private_key.public_key().to_openssh()?;
    let request = InstallRequest {
        version: CONFIG_VERSION,
        id: pending.id,
        target_login: login.to_owned(),
        requested_destination: requested_destination.to_owned(),
        public_key,
    };
    let target = endpoint(login, host)?;
    let direct = install_over_route(&target, EnrollmentRoute::Direct, &request);
    let response = match (direct, jump) {
        (Ok(response), _) => response,
        (Err(direct_error), Some(jump)) => {
            install_over_route(&target, EnrollmentRoute::ProxyJump { jump }, &request)
                .with_context(|| {
                    format!(
                "enrollment {} {retry_state}; direct enrollment also failed: {direct_error:#}",
                pending.id,
            )
                })?
        }
        (Err(error), None) => {
            return Err(error).with_context(|| format!("enrollment {} {retry_state}", pending.id,))
        }
    };
    let metadata = LocalEnrollment {
        version: CONFIG_VERSION,
        id: pending.id,
        host: host.to_owned(),
        target_login: login.to_owned(),
        remote_home: response.remote_home,
        requested_parent: response.requested_parent,
        canonical_root: response.canonical_root,
        receiver_path: response.receiver_path,
    };
    complete_local_enrollment(&directory, &metadata)?;
    Ok((metadata, directory, response.canonical_destination))
}

fn destination_for(metadata: &LocalEnrollment, requested: &str) -> Result<Option<String>> {
    let normalized = normalize_absolute(requested, Path::new(&metadata.remote_home))?;
    if requested_parent(&normalized) != Path::new(&metadata.requested_parent) {
        return Ok(None);
    }
    let leaf = normalized
        .file_name()
        .context("restricted destination / is not supported")?;
    Ok(Some(
        Path::new(&metadata.canonical_root)
            .join(leaf)
            .to_str()
            .context("canonical restricted destination is not UTF-8")?
            .to_owned(),
    ))
}

fn now() -> Result<i64> {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
        .context("current time exceeds signed grant range")
}

fn validate_restricted_args(args: &Args) -> Result<()> {
    if args.no_tcp || args.tcp_plain {
        bail!("command-restricted transfers require encrypted TCP data connections");
    }
    if args.inplace {
        bail!("command-restricted transfers currently require atomic staged publication");
    }
    if args.update
        || args.ignore_existing
        || args.existing
        || args.target_existence != Existence::Any
    {
        bail!(
            "--update, --ignore-existing, --existing, and destination-existence constraints are not yet enforceable by the command-restricted receiver"
        );
    }
    if !args.ignore_lines.is_empty()
        || !args.files_from_lines.is_empty()
        || args.files_from.is_some()
        || args.min_size.is_some()
        || args.bwlimit_bytes != 0
    {
        bail!(
            "--ignore/--ignore-from, --files-from, --min-size, and --bwlimit are not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.syq_path.is_some() || args.no_bootstrap {
        bail!(
            "--syq-path and --no-bootstrap cannot select the pre-enrolled command-restricted receiver"
        );
    }
    if !args.dry_run
        && !args.verify_only
        && (args.delete || args.interface == Interface::NativeCprm)
        && args.max_size.is_some()
    {
        bail!(
            "--max-size with deletion is not yet independently enforceable by the command-restricted receiver"
        );
    }
    if args.connections_opt.is_some() && args.connections > crate::tune::MAX {
        bail!(
            "command-restricted transfers support at most {} connections",
            crate::tune::MAX
        );
    }
    crate::transfer::parse_ports(&args.tcp_ports)?;
    if let Some(maximum) = args.max_size.as_deref() {
        crate::cli::parse_size(maximum)?;
    }
    Ok(())
}

fn grant_for(
    args: &Args,
    sources: &[Location],
    id: EnrollmentId,
    login: &str,
    destination: &str,
) -> Result<GrantV1> {
    validate_restricted_args(args)?;
    let issued_at = now()?;
    let read_only = args.dry_run || args.verify_only;
    let deletion = if !read_only && (args.delete || args.interface == Interface::NativeCprm) {
        DeletionPolicyV1::DeleteDestinationOnly
    } else {
        DeletionPolicyV1::Forbid
    };
    let max_deletions = match deletion {
        DeletionPolicyV1::Forbid => 0,
        DeletionPolicyV1::DeleteDestinationOnly => args.max_delete.unwrap_or(DEFAULT_MAX_ENTRIES),
    };
    let copies_contents = sources.iter().any(Location::copies_contents);
    let placement = match args.placement {
        Placement::As => DestinationPlacementV1::ExactPath,
        Placement::Into | Placement::Rsync if copies_contents => {
            DestinationPlacementV1::DirectoryContents
        }
        Placement::Into | Placement::Rsync => DestinationPlacementV1::DirectoryAsChild,
    };
    let destination_bytes = destination.as_bytes().to_vec();
    let mut mutation_scopes = match placement {
        DestinationPlacementV1::ExactPath | DestinationPlacementV1::DirectoryContents => {
            vec![MutationScopeV1 {
                path: destination_bytes.clone(),
                descendants: args.recursive,
            }]
        }
        DestinationPlacementV1::DirectoryAsChild => {
            let mut scopes = vec![MutationScopeV1 {
                path: destination_bytes.clone(),
                descendants: false,
            }];
            for source in sources {
                let basename = source.basename();
                if basename.is_empty() {
                    bail!("named source has no destination basename for signed scope");
                }
                scopes.push(MutationScopeV1 {
                    path: crate::fsops::join(&destination_bytes, &basename),
                    descendants: args.recursive,
                });
            }
            scopes
        }
    };
    mutation_scopes.sort_by(|left, right| left.path.cmp(&right.path));
    mutation_scopes.dedup_by(|left, right| left.path == right.path);
    let existing = if args.ignore_existing {
        ExistingDestinationPolicyV1::Skip
    } else if args.update {
        ExistingDestinationPolicyV1::UpdateIfOlder
    } else if args.existing || args.target_existence == Existence::Existing {
        ExistingDestinationPolicyV1::MustExist
    } else {
        ExistingDestinationPolicyV1::Replace
    };
    let (tcp_port_lo, tcp_port_hi) = crate::transfer::parse_ports(&args.tcp_ports)?;
    let grant = GrantV1 {
        enrollment_id: id,
        target_login: login.to_owned(),
        signer: signer_name(id),
        request_id: RequestId::random()?,
        issued_at,
        not_before: issued_at.saturating_sub(CLOCK_SKEW_SECONDS),
        not_after: issued_at
            .checked_add(GRANT_VALIDITY_SECONDS - CLOCK_SKEW_SECONDS)
            .context("signed grant expiration overflow")?,
        operation: GrantOperationV1::Copy(CopyOperationV1 {
            destination: destination_bytes,
            mutation_scopes,
            policy: CopyPolicyV1 {
                placement,
                existing,
                deletion,
                publication: if args.inplace {
                    PublicationPolicyV1::InPlace
                } else {
                    PublicationPolicyV1::AtomicStaged
                },
            },
            options: CopyOptionsV1 {
                recursive: args.recursive,
                preserve_symlinks: args.links,
                preserve_permissions: args.perms,
                preserve_times: args.times,
                preserve_owner: args.owner,
                preserve_group: args.group,
                preserve_devices: args.devices,
                compare_existing_by_content: args.checksum,
                dry_run: args.dry_run,
                verify_only: args.verify_only,
                compressed_transport: args.compress,
                tcp_port_lo,
                tcp_port_hi,
            },
            limits: CopyLimitsV1 {
                max_entries: DEFAULT_MAX_ENTRIES,
                max_total_bytes: DEFAULT_MAX_BYTES,
                max_file_bytes: args
                    .max_size
                    .as_deref()
                    .map(crate::cli::parse_size)
                    .transpose()?
                    .unwrap_or(DEFAULT_MAX_BYTES)
                    .min(DEFAULT_MAX_BYTES),
                max_connections: u16::try_from(if args.connections_opt.is_some() {
                    args.connections
                } else {
                    crate::tune::MAX
                })
                .context("connection maximum exceeds grant representation")?,
                max_deletions,
                max_runtime_seconds: DEFAULT_RUNTIME_SECONDS,
            },
        }),
    };
    Ok(grant)
}

pub(crate) fn prepare_transfer(
    args: &Args,
    sources: &[Location],
    destination: &Location,
    source_login: &str,
    destination_login: &str,
    allow_enrollment: bool,
) -> Result<PreparedTransfer> {
    validate_restricted_args(args)?;
    let host = destination
        .host
        .as_deref()
        .context("destination host missing")?;
    let requested = std::str::from_utf8(&destination.path)
        .context("restricted destination path is not UTF-8")?;
    let mut selected = None;
    for (metadata, directory) in load_local_enrollments()? {
        if metadata.host == host && metadata.target_login == destination_login {
            if let Some(canonical_destination) = destination_for(&metadata, requested)? {
                selected = Some((metadata, directory, canonical_destination));
                break;
            }
        }
    }
    let (metadata, directory, canonical_destination) = match selected {
        Some(selected) => selected,
        None => {
            if !allow_enrollment {
                bail!(
                    "dry-run will not install a receiver enrollment; pre-enroll this destination with `syq enroll` or explicitly use --agent-broker-only"
                );
            }
            let jump = endpoint(
                source_login,
                sources[0].host.as_deref().context("source host missing")?,
            )?;
            enroll(host, destination_login, requested, Some(&jump), false)?
        }
    };
    let private_key = load_private_key(&directory)?;
    let grant = delegation::sign_grant(
        grant_for(
            args,
            sources,
            metadata.id,
            destination_login,
            &canonical_destination,
        )?,
        &private_key,
    )?;
    Ok(PreparedTransfer {
        private_key,
        canonical_destination,
        grant: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(grant),
        enrollment_id: metadata.id,
    })
}

pub(crate) fn receiver_config(id: EnrollmentId) -> Result<(ReceiverEnrollment, PathBuf, PathBuf)> {
    let (_, home) = current_account()?;
    let state = home
        .join(".local/share/syq/restricted")
        .join(id.to_string());
    let encoded = delegation::read_secure_regular(
        &state.join("config.json"),
        "restricted receiver configuration",
        MAX_STATE_FILE,
    )?;
    let config: ReceiverEnrollment = serde_json::from_slice(&encoded)?;
    if config.version != CONFIG_VERSION || config.id != id {
        bail!("restricted receiver configuration does not match enrollment");
    }
    Ok((config, state.join("allowed-signers"), state.join("replay")))
}

pub(crate) fn run_receiver(enrollment: &str) -> Result<()> {
    let enrollment = EnrollmentId::parse(enrollment)?;
    let original = std::env::var("SSH_ORIGINAL_COMMAND")
        .context("restricted receiver requires SSH_ORIGINAL_COMMAND from sshd")?;
    let envelope = decode_receiver_command(&original)?;
    let (config, allowed_signers, replay_path) = receiver_config(enrollment)?;
    let replay = delegation::ReplayStore::open(&replay_path)?;
    let observed_at = Instant::now();
    let context = delegation::ReceiverContext {
        enrollment_id: enrollment,
        target_login: &config.target_login,
        expected_signer: &config.signer,
        clock: delegation::ClockObservation {
            unix_seconds: now()?,
            monotonic: observed_at,
        },
        clock_skew_seconds: CLOCK_SKEW_SECONDS,
    };
    let policy = delegation::SshsigPolicy {
        ssh_keygen: PathBuf::from(&config.ssh_keygen),
        allowed_signers,
        revocation_file: None,
    };
    let verified = delegation::verify_and_claim(&envelope, &context, &policy, &replay)?;
    let (grant, deadline) = verified.into_parts();
    let authority = std::sync::Arc::new(RestrictedAuthority::new(&config, grant, deadline)?);
    crate::server::run_restricted(authority)
}

fn decode_receiver_command(original: &str) -> Result<Vec<u8>> {
    if original.len() > 128 * 1024 {
        bail!("restricted receiver command exceeds size limit");
    }
    let words = shell_words::split(original).context("parse restricted receiver command")?;
    if words.len() != 3 || words[0] != "syq" || words[1] != "--server" {
        bail!("restricted credential accepts only a syq server request with one signed grant");
    }
    let encoded = words[2]
        .strip_prefix("--restricted-grant=")
        .context("restricted receiver command is missing its signed grant")?;
    let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode restricted receiver grant")?;
    Ok(envelope)
}

fn management_via(arguments: &[OsString]) -> Result<Option<SshEndpoint>> {
    if arguments.is_empty() {
        return Ok(None);
    }
    if arguments.len() != 2 || arguments[0] != "--via" {
        bail!("expected optional --via [USER@]HOST");
    }
    Ok(Some(SshEndpoint::parse(
        arguments[1]
            .to_str()
            .context("--via endpoint is not UTF-8")?,
    )?))
}

pub(crate) fn dispatch_management(argv: &[OsString]) -> Option<Result<i32>> {
    let command = argv.get(1)?.to_str()?;
    match command {
        "enrollments" => {
            Some((|| {
                if argv.get(2).is_some_and(|argument| argument == "--help") {
                    println!("Usage: syq enrollments\n\nList local command-restricted receiver enrollments.");
                    return Ok(0);
                }
                if argv.len() != 2 {
                    bail!("usage: syq enrollments");
                }
                let active = load_local_enrollments()?;
                let active_ids = active
                    .iter()
                    .map(|(metadata, _)| metadata.id)
                    .collect::<HashSet<_>>();
                for (metadata, _) in active {
                    println!(
                        "{}\tactive\t{}@{}\t{}",
                        metadata.id, metadata.target_login, metadata.host, metadata.canonical_root
                    );
                }
                for (pending, _) in load_pending_enrollments()? {
                    if !active_ids.contains(&pending.id) {
                        println!(
                            "{}\tpending\t{}@{}\t{}",
                            pending.id,
                            pending.target_login,
                            pending.host,
                            pending.requested_destination
                        );
                    }
                }
                Ok(0)
            })())
        }
        "enroll" => Some((|| {
            if argv.get(2).is_some_and(|argument| argument == "--help") {
                println!(
                    "Usage: syq enroll [USER@]HOST:DESTINATION [--via [USER@]HOST]\n\nPre-enroll a command-restricted receiver for DESTINATION's existing parent."
                );
                return Ok(0);
            }
            if argv.len() < 3 {
                bail!("usage: syq enroll [USER@]HOST:DESTINATION [--via [USER@]HOST]");
            }
            let target = argv[2].to_str().context("enrollment target is not UTF-8")?;
            let location = Location::parse(target)?;
            let host = location
                .host
                .as_deref()
                .context("enrollment target must be remote")?;
            let requested = std::str::from_utf8(&location.path)
                .context("enrollment destination is not UTF-8")?;
            let via = management_via(&argv[3..])?;
            let policy = crate::agent_broker::resolve_host_policy(
                "ssh",
                location.user.as_deref(),
                host,
                true,
            )?;
            let (metadata, _, destination) =
                enroll(host, &policy.login_user, requested, via.as_ref(), true)?;
            println!(
                "enrolled {} for {}@{}:{}",
                metadata.id, metadata.target_login, metadata.host, destination
            );
            Ok(0)
        })()),
        "revoke" => Some((|| {
            if argv.get(2).is_some_and(|argument| argument == "--help") {
                println!(
                    "Usage: syq revoke ENROLLMENT-ID [--via [USER@]HOST]\n\nRemove the forced key and per-enrollment state from both machines."
                );
                return Ok(0);
            }
            if argv.len() < 3 {
                bail!("usage: syq revoke ENROLLMENT-ID [--via [USER@]HOST]");
            }
            let id = EnrollmentId::parse(argv[2].to_str().context("enrollment ID is not UTF-8")?)?;
            let via = management_via(&argv[3..])?;
            let active = load_local_enrollments()?
                .into_iter()
                .find(|(metadata, _)| metadata.id == id);
            let (target_login, host, remote_command, directory) = match active {
                Some((metadata, directory)) => {
                    let command = enrollment::EnrollmentRemoteCommand::new(
                        Path::new(&metadata.receiver_path),
                        &["--restricted-revoke".into()],
                    )?;
                    (
                        metadata.target_login,
                        metadata.host,
                        command.as_str().to_owned(),
                        directory,
                    )
                }
                None => {
                    let (pending, directory) = load_pending_enrollments()?
                        .into_iter()
                        .find(|(pending, _)| pending.id == id)
                        .context("no local enrollment has that ID")?;
                    (
                        pending.target_login,
                        pending.host,
                        "exec \"$HOME/.local/libexec/syq-receiver\" --restricted-revoke".to_owned(),
                        directory,
                    )
                }
            };
            let private_key = load_private_key(&directory)?;
            let request = RevokeRequest {
                version: CONFIG_VERSION,
                id,
                target_login: target_login.clone(),
                public_key: private_key.public_key().to_openssh()?,
            };
            let target = endpoint(&target_login, &host)?;
            let encoded = serde_json::to_vec(&request)?;
            let direct = run_ssh(&target, EnrollmentRoute::Direct, &remote_command, &encoded);
            match (direct, via.as_ref()) {
                (Ok(_), _) => {}
                (Err(direct_error), Some(via)) => {
                    run_ssh(
                        &target,
                        EnrollmentRoute::ProxyJump { jump: via },
                        &remote_command,
                        &encoded,
                    )
                    .with_context(|| format!("direct revocation also failed: {direct_error:#}"))?;
                }
                (Err(error), None) => return Err(error),
            }
            delegation::validate_private_directory_path(&directory)?;
            fs::remove_dir_all(&directory)
                .with_context(|| format!("remove local enrollment {}", directory.display()))?;
            println!("revoked {id} from {target_login}@{host}");
            Ok(0)
        })()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn test_authority(
        root: &Path,
        deletion: DeletionPolicyV1,
        maximum_bytes: u64,
    ) -> RestrictedAuthority {
        let opened = Root::open(root).unwrap();
        let identity = opened.identity();
        let id = EnrollmentId::random();
        let config = ReceiverEnrollment {
            version: CONFIG_VERSION,
            id,
            target_login: "receiver".into(),
            signer: signer_name(id),
            root: root.to_str().unwrap().into(),
            root_dev: identity.dev,
            root_ino: identity.ino,
            ssh_keygen: "/usr/bin/ssh-keygen".into(),
            receiver_path: "/usr/bin/syq".into(),
        };
        let destination = root.join("target");
        let grant = GrantV1 {
            enrollment_id: id,
            target_login: "receiver".into(),
            signer: signer_name(id),
            request_id: RequestId::random().unwrap(),
            issued_at: 1,
            not_before: 1,
            not_after: 100,
            operation: GrantOperationV1::Copy(CopyOperationV1 {
                destination: destination.as_os_str().as_bytes().to_vec(),
                mutation_scopes: vec![MutationScopeV1 {
                    path: destination.as_os_str().as_bytes().to_vec(),
                    descendants: true,
                }],
                policy: CopyPolicyV1 {
                    placement: DestinationPlacementV1::ExactPath,
                    existing: ExistingDestinationPolicyV1::Replace,
                    deletion,
                    publication: PublicationPolicyV1::AtomicStaged,
                },
                options: CopyOptionsV1 {
                    recursive: true,
                    preserve_symlinks: true,
                    preserve_permissions: false,
                    preserve_times: false,
                    preserve_owner: false,
                    preserve_group: false,
                    preserve_devices: false,
                    compare_existing_by_content: false,
                    dry_run: false,
                    verify_only: false,
                    compressed_transport: true,
                    tcp_port_lo: 47_600,
                    tcp_port_hi: 47_699,
                },
                limits: CopyLimitsV1 {
                    max_entries: 8,
                    max_total_bytes: maximum_bytes,
                    max_file_bytes: maximum_bytes,
                    max_connections: 2,
                    max_deletions: u64::from(deletion != DeletionPolicyV1::Forbid) * 2,
                    max_runtime_seconds: 60,
                },
            }),
        };
        RestrictedAuthority::new(
            &config,
            grant,
            Instant::now() + std::time::Duration::from_secs(60),
        )
        .unwrap()
    }

    #[test]
    fn managed_crlf_and_commented_tombstones_normalize_without_touching_other_content() {
        let marker = "syq-enrollment:00112233445566778899aabbccddeeff";
        let original = format!(
            "# unrelated\r\n# restrict ssh-ed25519 AAAA {marker}\r\nssh-ed25519 BBBB user\r\n"
        );
        assert_eq!(
            normalize_managed_authorized_keys(original.as_bytes(), marker),
            b"# unrelated\nssh-ed25519 BBBB user\n"
        );
    }

    #[test]
    fn relative_destination_resolution_rejects_parent_components() {
        assert_eq!(
            normalize_absolute("archive/file", Path::new("/home/backup")).unwrap(),
            Path::new("/home/backup/archive/file")
        );
        assert!(normalize_absolute("archive/../escape", Path::new("/home/backup")).is_err());
    }

    #[test]
    fn receiver_command_accepts_only_one_encoded_signed_grant() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"signed grant");
        assert_eq!(
            decode_receiver_command(&format!("syq --server --restricted-grant={encoded}")).unwrap(),
            b"signed grant"
        );
        assert!(decode_receiver_command(&format!(
            "syq --server --restricted-grant={encoded} extra"
        ))
        .is_err());
        assert!(decode_receiver_command(&format!(
            "env X=1 syq --server --restricted-grant={encoded}"
        ))
        .is_err());
    }

    #[test]
    fn pending_enrollment_keeps_its_key_until_active_metadata_is_durable() {
        let (_, home) = current_account().unwrap();
        let temporary = tempfile::tempdir_in(home).unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = EnrollmentId::random();
        let directory = temporary.path().join(id.to_string());
        ensure_directory(&directory, 0o700).unwrap();
        let pending = PendingEnrollment {
            version: CONFIG_VERSION,
            id,
            host: "host-b".into(),
            target_login: "backup".into(),
            requested_destination: "/archive/item".into(),
        };
        let private_key = generate_transport_key(id).unwrap();
        store_pending_files(&directory, &pending, &private_key).unwrap();
        assert!(directory.join("pending.json").is_file());
        assert_eq!(
            fs::metadata(directory.join("transport")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_private_key(&directory)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
            private_key.public_key().to_openssh().unwrap()
        );

        let metadata = LocalEnrollment {
            version: CONFIG_VERSION,
            id,
            host: pending.host,
            target_login: pending.target_login,
            remote_home: "/home/backup".into(),
            requested_parent: "/archive".into(),
            canonical_root: "/archive".into(),
            receiver_path: "/home/backup/.local/libexec/syq-receiver".into(),
        };
        complete_local_enrollment(&directory, &metadata).unwrap();
        assert!(!directory.join("pending.json").exists());
        assert!(directory.join("metadata.json").is_file());
        assert!(directory.join("transport").is_file());
    }

    #[test]
    fn authority_overwrites_client_guards_and_rejects_scope_and_option_escalation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 4);
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let outside = temporary
            .path()
            .join("outside")
            .as_os_str()
            .as_bytes()
            .to_vec();

        let mut stat = Request::StatMany {
            paths: vec![target.clone()],
            follow: false,
            guard: Some(ContainerGuard {
                root: outside.clone(),
                dev: 1,
                ino: 2,
            }),
        };
        authority.authorize(&mut stat, false).unwrap();
        let Request::StatMany {
            guard: Some(guard), ..
        } = stat
        else {
            panic!("authority did not install a guard")
        };
        assert_eq!(guard.root, root.as_os_str().as_bytes());

        let mut outside_stat = Request::StatMany {
            paths: vec![outside.clone()],
            follow: false,
            guard: None,
        };
        assert!(authority.authorize(&mut outside_stat, false).is_err());

        let mut mkdir = Request::Apply {
            ops: vec![Op::Mkdir {
                path: target.clone(),
                mode: 0o777,
                condition: proto::TargetCondition::Absent,
            }],
            guard: None,
        };
        authority.authorize(&mut mkdir, false).unwrap();
        let Request::Apply { ops, .. } = mkdir else {
            unreachable!()
        };
        assert!(matches!(ops[0], Op::Mkdir { mode: 0o700, .. }));

        let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
            path: target.clone(),
            partial_id: [1; 16],
            data: vec![0; 4],
            hash: 0,
            meta: proto::Meta {
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: 0,
            condition: proto::TargetCondition::Any,
            guard: Some(ContainerGuard {
                root: outside,
                dev: 1,
                ino: 2,
            }),
        }]);
        authority.authorize(&mut small, false).unwrap();
        let Request::PutSmallBatch(puts) = small else {
            unreachable!()
        };
        assert_eq!(
            puts[0].guard.as_ref().unwrap().root,
            root.as_os_str().as_bytes()
        );

        let mut write = Request::WriteRange {
            path: target,
            inplace: false,
            partial_id: [0; 16],
            attempt: 0,
            off: 0,
            hash: 0,
            data: vec![0; 5],
            guard: None,
        };
        assert!(authority.authorize(&mut write, false).is_err());
    }

    #[test]
    fn authority_binds_one_encrypted_listener_and_known_metadata_flags() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let mut listener = Request::TcpListen {
            key: Some(vec![7; crate::crypto::KEY_LEN]),
            token: vec![8; 16],
            port_lo: 47_600,
            port_hi: 47_699,
        };
        authority.authorize(&mut listener, true).unwrap();
        assert!(authority.authorize(&mut listener, true).is_err());
        assert!(authority.control_is_open());
        authority.close_control();
        assert!(!authority.control_is_open());

        let wrong_range = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let mut listener = Request::TcpListen {
            key: Some(vec![7; crate::crypto::KEY_LEN]),
            token: vec![8; 16],
            port_lo: 1,
            port_hi: 2,
        };
        assert!(wrong_range.authorize(&mut listener, true).is_err());

        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let mut metadata = Request::Apply {
            ops: vec![Op::SetMeta {
                path: target,
                meta: proto::Meta {
                    mode: 0,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                    mtime_nsec: 0,
                },
                flags: 0x80,
                condition: proto::TargetCondition::Any,
            }],
            guard: None,
        };
        assert!(wrong_range.authorize(&mut metadata, false).is_err());
    }

    #[test]
    fn signed_read_only_modes_reject_every_destination_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        authority.copy.options.dry_run = true;
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let mut mutation = Request::Apply {
            ops: vec![Op::Mkdir {
                path: target.clone(),
                mode: 0o700,
                condition: proto::TargetCondition::Absent,
            }],
            guard: None,
        };
        assert!(authority.authorize(&mut mutation, false).is_err());

        let mut small = Request::PutSmallBatch(vec![proto::SmallPut {
            path: target.clone(),
            partial_id: [1; 16],
            data: vec![0],
            hash: 0,
            meta: proto::Meta {
                mode: 0o600,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
            },
            flags: 0,
            condition: proto::TargetCondition::Any,
            guard: None,
        }]);
        assert!(authority.authorize(&mut small, false).is_err());

        let mut observation = Request::StatMany {
            paths: vec![target],
            follow: false,
            guard: None,
        };
        authority.authorize(&mut observation, false).unwrap();
    }

    #[test]
    fn directory_as_child_scope_does_not_authorize_unrelated_siblings() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        fs::create_dir(&root).unwrap();
        let mut authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);
        let target = root.join("target").as_os_str().as_bytes().to_vec();
        let allowed = root.join("target/source").as_os_str().as_bytes().to_vec();
        authority.copy.mutation_scopes = vec![
            MutationScopeV1 {
                path: target.clone(),
                descendants: false,
            },
            MutationScopeV1 {
                path: allowed,
                descendants: true,
            },
        ];
        let mut request = Request::Apply {
            ops: vec![Op::Mkdir {
                path: root
                    .join("target/unrelated")
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
                mode: 0o700,
                condition: proto::TargetCondition::Absent,
            }],
            guard: None,
        };
        assert!(authority.authorize(&mut request, false).is_err());

        let mut observe_container = Request::StatMany {
            paths: vec![target],
            follow: false,
            guard: None,
        };
        authority.authorize(&mut observe_container, false).unwrap();
    }

    #[test]
    fn signed_scopes_distinguish_named_children_from_directory_contents() {
        let id = EnrollmentId::random();
        let mut named_args =
            Args::try_parse_from(["syq rsync", "-r", "host-a:source", "host-b:/backup"]).unwrap();
        named_args.normalize();
        let named_source = Location::parse("host-a:source").unwrap();
        let named = grant_for(&named_args, &[named_source], id, "backup", "/backup").unwrap();
        let GrantOperationV1::Copy(named) = named.operation;
        assert_eq!(
            named.mutation_scopes,
            vec![
                MutationScopeV1 {
                    path: b"/backup".to_vec(),
                    descendants: false,
                },
                MutationScopeV1 {
                    path: b"/backup/source".to_vec(),
                    descendants: true,
                },
            ]
        );

        let mut contents_args =
            Args::try_parse_from(["syq rsync", "-r", "host-a:source/", "host-b:/backup"]).unwrap();
        contents_args.normalize();
        let contents_source = Location::parse("host-a:source/").unwrap();
        let contents =
            grant_for(&contents_args, &[contents_source], id, "backup", "/backup").unwrap();
        let GrantOperationV1::Copy(contents) = contents.operation;
        assert_eq!(
            contents.mutation_scopes,
            vec![MutationScopeV1 {
                path: b"/backup".to_vec(),
                descendants: true,
            }]
        );

        let mut nonrecursive_args =
            Args::try_parse_from(["syq rsync", "host-a:file", "host-b:/backup"]).unwrap();
        nonrecursive_args.normalize();
        let file = Location::parse("host-a:file").unwrap();
        let nonrecursive = grant_for(&nonrecursive_args, &[file], id, "backup", "/backup").unwrap();
        let GrantOperationV1::Copy(nonrecursive) = nonrecursive.operation;
        assert!(nonrecursive
            .mutation_scopes
            .iter()
            .all(|scope| !scope.descendants));

        let mut unsupported = nonrecursive_args;
        unsupported.min_size = Some("1".into());
        let file = Location::parse("host-a:file").unwrap();
        assert!(grant_for(&unsupported, &[file], id, "backup", "/backup").is_err());
    }

    #[test]
    fn rooted_scan_and_hash_never_follow_a_payload_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("root");
        let target = root.join("target");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(target.join("inside"), b"inside").unwrap();
        fs::write(outside.join("secret"), b"secret").unwrap();
        symlink(&outside, target.join("escape")).unwrap();
        let authority = test_authority(&root, DeletionPolicyV1::Forbid, 1024);

        let mut scan = Request::Scan {
            root: target.as_os_str().as_bytes().to_vec(),
            follow_root: false,
            ignore: Vec::new(),
            report_ignored: false,
            guard: None,
        };
        authority.authorize(&mut scan, true).unwrap();
        let Request::Scan {
            guard: Some(guard), ..
        } = scan
        else {
            panic!("authority did not install a scan guard")
        };
        let mut entries = Vec::new();
        crate::scan::scan_rooted(
            target.as_os_str().as_bytes(),
            false,
            &[],
            false,
            &guard,
            &mut |batch| {
                entries.extend(batch);
                Ok(())
            },
            &mut |_| Ok(()),
            &mut |_| {},
        )
        .unwrap();
        assert!(entries.iter().any(|entry| entry.path == b"inside"));
        assert!(entries
            .iter()
            .any(|entry| { entry.path == b"escape" && entry.kind == proto::Kind::Symlink }));
        assert!(!entries.iter().any(|entry| entry.path == b"escape/secret"));

        let response = crate::fsops::FsOps::new().handle(&Request::HashBlocks {
            path: target.join("escape").as_os_str().as_bytes().to_vec(),
            which: proto::Which::Final,
            partial_id: [0; 16],
            block: 4096,
            len: 1,
            guard: Some(guard),
        });
        assert!(matches!(response, proto::Response::Err(_)));
        assert_eq!(fs::metadata(outside.join("secret")).unwrap().len(), 6);
    }
}
