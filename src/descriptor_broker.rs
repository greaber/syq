//! Session-scoped descriptor registration and exact cross-process handoff.
//!
//! A control process owns the registry and keeps every registered root and
//! exact source-leaf object open. Threads in that process clone descriptors
//! directly; independent workers use a private, secret-authenticated Unix
//! socket and receive the same open file descriptions with `SCM_RIGHTS`. No
//! worker reopens an operator pathname.

use crate::private_broker::{PrivateBroker, PrivateBrokerConfig, TrackedStream};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CLAIM_MAGIC: &[u8; 8] = b"SYQFD001";
const SECRET_LEN: usize = 32;
const CLAIM_LEN: usize = CLAIM_MAGIC.len() + SECRET_LEN + size_of::<u64>() + 1;
const RESPONSE_OK: u8 = 0;
const RESPONSE_REJECTED: u8 = 1;
const RESPONSE_INTERNAL: u8 = 2;
const BROKER_IO_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_MAX_ROOTS: usize = 256;
const DEFAULT_MAX_CONNECTIONS: usize = 256;
const FD_CONTROL_LEN: usize =
    unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as libc::c_uint) as usize };

#[repr(C)]
union FdControl {
    _align: libc::cmsghdr,
    bytes: [u8; FD_CONTROL_LEN],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct RegisteredRootId(u64);

impl RegisteredRootId {
    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

struct RegisteredRoot {
    directory: File,
    source_leaf: Option<File>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum RegisteredDescriptorKind {
    Directory,
    SourceLeaf,
}

impl RegisteredDescriptorKind {
    fn wire_byte(self) -> u8 {
        match self {
            Self::Directory => 0,
            Self::SourceLeaf => 1,
        }
    }

    fn from_wire_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Directory),
            1 => Some(Self::SourceLeaf),
            _ => None,
        }
    }
}

struct RegistryState {
    next_id: u64,
    roots: HashMap<RegisteredRootId, RegisteredRoot>,
}

#[derive(Clone)]
pub(crate) struct RegisteredRootRegistry {
    state: Arc<Mutex<RegistryState>>,
    max_roots: usize,
}

impl RegisteredRootRegistry {
    fn new(max_roots: usize) -> Result<Self> {
        if max_roots == 0 {
            bail!("descriptor session needs at least one root slot");
        }
        Ok(Self {
            state: Arc::new(Mutex::new(RegistryState {
                next_id: 1,
                roots: HashMap::new(),
            })),
            max_roots,
        })
    }

    pub(crate) fn register(&self, directory: File) -> Result<RegisteredRootId> {
        Ok(self.register_many(vec![directory])?.remove(0))
    }

    pub(crate) fn register_many(&self, directories: Vec<File>) -> Result<Vec<RegisteredRootId>> {
        if directories.is_empty() {
            return Ok(Vec::new());
        }
        for directory in &directories {
            let metadata = directory
                .metadata()
                .context("inspect directory registered with descriptor session")?;
            if !metadata.is_dir() {
                bail!("only directories may be registered as session roots");
            }
        }
        self.register_entries(
            directories
                .into_iter()
                .map(|directory| RegisteredRoot {
                    directory,
                    source_leaf: None,
                })
                .collect(),
        )
    }

    fn register_source_handles(
        &self,
        handles: Vec<(File, Option<File>)>,
    ) -> Result<Vec<RegisteredRootId>> {
        for (directory, source_leaf) in &handles {
            let metadata = directory
                .metadata()
                .context("inspect source directory registered with descriptor session")?;
            if !metadata.is_dir() {
                bail!("source authority roots must be directories");
            }
            if let Some(source_leaf) = source_leaf {
                let metadata = source_leaf
                    .metadata()
                    .context("inspect source leaf registered with descriptor session")?;
                if metadata.is_dir() {
                    bail!("exact source objects must not be directories");
                }
            }
        }
        self.register_entries(
            handles
                .into_iter()
                .map(|(directory, source_leaf)| RegisteredRoot {
                    directory,
                    source_leaf,
                })
                .collect(),
        )
    }

    fn register_entries(&self, roots: Vec<RegisteredRoot>) -> Result<Vec<RegisteredRootId>> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let new_len = state
            .roots
            .len()
            .checked_add(roots.len())
            .context("descriptor session root count overflow")?;
        if new_len > self.max_roots {
            bail!(
                "descriptor session root limit ({}) exceeded; split the operation into fewer distinct roots",
                self.max_roots
            );
        }
        let count = u64::try_from(roots.len()).context("too many session roots")?;
        let next_id = state
            .next_id
            .checked_add(count)
            .context("descriptor session exhausted root identifiers")?;
        let first_id = state.next_id;
        state.next_id = next_id;
        let mut ids = Vec::with_capacity(roots.len());
        for (offset, root) in roots.into_iter().enumerate() {
            let id = RegisteredRootId(first_id + offset as u64);
            state.roots.insert(id, root);
            ids.push(id);
        }
        Ok(ids)
    }

    /// Used by local workers and TCP workers hosted by the control process.
    pub(crate) fn acquire(&self, id: RegisteredRootId) -> Result<File> {
        self.acquire_optional(id, RegisteredDescriptorKind::Directory)?
            .with_context(|| format!("unknown descriptor session root {}", id.0))
    }

    fn acquire_optional(
        &self,
        id: RegisteredRootId,
        kind: RegisteredDescriptorKind,
    ) -> Result<Option<File>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .roots
            .get(&id)
            .and_then(|root| match kind {
                RegisteredDescriptorKind::Directory => Some(&root.directory),
                RegisteredDescriptorKind::SourceLeaf => root.source_leaf.as_ref(),
            })
            .map(File::try_clone)
            .transpose()
            .context("duplicate registered session descriptor")
    }

    fn contains(&self, id: RegisteredRootId, kind: RegisteredDescriptorKind) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .roots
            .get(&id)
            .is_some_and(|root| match kind {
                RegisteredDescriptorKind::Directory => true,
                RegisteredDescriptorKind::SourceLeaf => root.source_leaf.is_some(),
            })
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DescriptorTicket {
    #[serde(with = "serde_bytes")]
    socket_path: Vec<u8>,
    secret: [u8; SECRET_LEN],
    root_id: RegisteredRootId,
    kind: RegisteredDescriptorKind,
}

impl std::fmt::Debug for DescriptorTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DescriptorTicket")
            .field("socket_path", &self.socket_path())
            .field("root_id", &self.root_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl DescriptorTicket {
    fn socket_path(&self) -> PathBuf {
        PathBuf::from(OsStr::from_bytes(&self.socket_path))
    }

    pub(crate) fn root_id(&self) -> RegisteredRootId {
        self.root_id
    }

    /// Tickets belong to the same endpoint session only when both the private
    /// broker address and unguessable session secret match. Root IDs restart
    /// per registry and therefore cannot establish this relationship alone.
    pub(crate) fn same_session(&self, other: &Self) -> bool {
        self.socket_path == other.socket_path && self.secret == other.secret
    }

    pub(crate) fn is_directory(&self) -> bool {
        self.kind == RegisteredDescriptorKind::Directory
    }

    pub(crate) fn is_source_leaf(&self) -> bool {
        self.kind == RegisteredDescriptorKind::SourceLeaf
    }

    #[cfg(test)]
    pub(crate) fn broker_path(&self) -> PathBuf {
        self.socket_path()
    }
}

/// Owns the endpoint session's roots and its independent-worker handoff
/// broker. Dropping it closes the broker before releasing the registered roots.
pub(crate) struct DescriptorSession {
    broker: PrivateBroker,
    registry: RegisteredRootRegistry,
    secret: [u8; SECRET_LEN],
}

impl DescriptorSession {
    pub(crate) fn start(max_roots: usize, max_connections: usize) -> Result<Self> {
        let registry = RegisteredRootRegistry::new(max_roots)?;
        let secret: [u8; SECRET_LEN] = crate::crypto::random_bytes(SECRET_LEN)
            .try_into()
            .map_err(|_| anyhow!("generated descriptor broker secret has the wrong length"))?;
        let server_registry = registry.clone();
        let server_secret = secret;
        let broker = PrivateBroker::start(
            PrivateBrokerConfig {
                directory_prefix: "syq-fd-",
                socket_name: "broker.sock",
                listener_thread: "syq-fd-listener",
                client_thread: "syq-fd-client",
                max_connections,
                io_timeout: BROKER_IO_TIMEOUT,
            },
            move |mut stream, _connections| {
                let _ = serve_claim(&mut stream, &server_registry, &server_secret);
            },
        )?;
        Ok(Self {
            broker,
            registry,
            secret,
        })
    }

    pub(crate) fn registry(&self) -> RegisteredRootRegistry {
        self.registry.clone()
    }

    pub(crate) fn register(&self, directory: File) -> Result<RegisteredRootId> {
        self.registry.register(directory)
    }

    pub(crate) fn ticket(&self, root_id: RegisteredRootId) -> Result<DescriptorTicket> {
        self.ticket_for(root_id, RegisteredDescriptorKind::Directory)
    }

    fn source_leaf_ticket(&self, root_id: RegisteredRootId) -> Result<DescriptorTicket> {
        self.ticket_for(root_id, RegisteredDescriptorKind::SourceLeaf)
    }

    fn ticket_for(
        &self,
        root_id: RegisteredRootId,
        kind: RegisteredDescriptorKind,
    ) -> Result<DescriptorTicket> {
        if !self.registry.contains(root_id, kind) {
            bail!("unknown descriptor session root {}", root_id.0);
        }
        Ok(DescriptorTicket {
            socket_path: self.broker.socket_path().as_os_str().as_bytes().to_vec(),
            secret: self.secret,
            root_id,
            kind,
        })
    }

    fn acquire(&self, ticket: &DescriptorTicket) -> Result<File> {
        if ticket.secret != self.secret
            || ticket.socket_path != self.broker.socket_path().as_os_str().as_bytes()
        {
            bail!("descriptor ticket does not belong to this endpoint session");
        }
        self.registry
            .acquire_optional(ticket.root_id, ticket.kind)?
            .with_context(|| format!("unknown descriptor session root {}", ticket.root_id.0))
    }
}

/// A process-local view of one endpoint session. The control connection
/// creates the descriptor broker lazily when it registers a root. TCP workers
/// share this slot and clone the root directly; a fresh independent-worker
/// process has an empty slot and claims the same root over the broker socket.
#[derive(Clone)]
pub(crate) struct DescriptorSessionSlot {
    session: Arc<Mutex<Option<DescriptorSession>>>,
    closed: Arc<AtomicBool>,
    max_roots: usize,
    max_connections: usize,
}

impl Default for DescriptorSessionSlot {
    fn default() -> Self {
        Self {
            session: Arc::new(Mutex::new(None)),
            closed: Arc::new(AtomicBool::new(false)),
            max_roots: DEFAULT_MAX_ROOTS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

impl DescriptorSessionSlot {
    pub(crate) fn register(&self, directory: File) -> Result<DescriptorTicket> {
        Ok(self.register_many(vec![directory])?.remove(0))
    }

    pub(crate) fn register_many(&self, directories: Vec<File>) -> Result<Vec<DescriptorTicket>> {
        if directories.is_empty() {
            return Ok(Vec::new());
        }
        if self.closed.load(Ordering::Acquire) {
            bail!("descriptor session is closed");
        }
        let mut session = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.closed.load(Ordering::Acquire) {
            bail!("descriptor session is closed");
        }
        if session.is_none() {
            *session = Some(DescriptorSession::start(
                self.max_roots,
                self.max_connections,
            )?);
        }
        let session = session.as_ref().expect("descriptor session initialized");
        session
            .registry
            .register_many(directories)?
            .into_iter()
            .map(|root_id| session.ticket(root_id))
            .collect()
    }

    /// Atomically register each source authority directory together with its
    /// optional exact-leaf object. Both tickets share one opaque root ID but
    /// carry distinct descriptor kinds, so neither can be substituted for the
    /// other during worker initialization.
    pub(crate) fn register_source_handles(
        &self,
        handles: Vec<(File, Option<File>)>,
    ) -> Result<Vec<(DescriptorTicket, Option<DescriptorTicket>)>> {
        if handles.is_empty() {
            return Ok(Vec::new());
        }
        if self.closed.load(Ordering::Acquire) {
            bail!("descriptor session is closed");
        }
        let mut session = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.closed.load(Ordering::Acquire) {
            bail!("descriptor session is closed");
        }
        if session.is_none() {
            *session = Some(DescriptorSession::start(
                self.max_roots,
                self.max_connections,
            )?);
        }
        let session = session.as_ref().expect("descriptor session initialized");
        let has_leaf: Vec<_> = handles.iter().map(|(_, leaf)| leaf.is_some()).collect();
        session
            .registry
            .register_source_handles(handles)?
            .into_iter()
            .zip(has_leaf)
            .map(|(root_id, has_leaf)| {
                Ok((
                    session.ticket(root_id)?,
                    has_leaf
                        .then(|| session.source_leaf_ticket(root_id))
                        .transpose()?,
                ))
            })
            .collect()
    }

    pub(crate) fn acquire(&self, ticket: &DescriptorTicket) -> Result<File> {
        let session = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(session) = session.as_ref() {
            return session.acquire(ticket);
        }
        drop(session);
        if self.closed.load(Ordering::Acquire) {
            bail!("descriptor session is closed");
        }
        claim_descriptor(ticket)
    }

    /// End the control session even if its detached TCP listener still holds
    /// a clone of this slot. This synchronously stops the broker and releases
    /// its private socket directory.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let session = self
            .session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(session);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// Claim a registered root from an independent process. The returned
/// descriptor refers to the exact registered object even if its original
/// pathname has been renamed or replaced.
pub(crate) fn claim_descriptor(ticket: &DescriptorTicket) -> Result<File> {
    let socket_path = ticket.socket_path();
    let mut stream = UnixStream::connect(&socket_path)
        .with_context(|| format!("connect to descriptor broker {}", socket_path.display()))?;
    stream.set_read_timeout(Some(BROKER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(BROKER_IO_TIMEOUT))?;
    let mut claim = [0u8; CLAIM_LEN];
    claim[..CLAIM_MAGIC.len()].copy_from_slice(CLAIM_MAGIC);
    let secret_start = CLAIM_MAGIC.len();
    claim[secret_start..secret_start + SECRET_LEN].copy_from_slice(&ticket.secret);
    let root_start = secret_start + SECRET_LEN;
    let root_end = root_start + size_of::<u64>();
    claim[root_start..root_end].copy_from_slice(&ticket.root_id.0.to_be_bytes());
    claim[root_end] = ticket.kind.wire_byte();
    stream.write_all(&claim)?;

    let (status, descriptor) = receive_descriptor(stream.as_raw_fd())?;
    match (status, descriptor) {
        (RESPONSE_OK, Some(descriptor)) => Ok(descriptor),
        (RESPONSE_OK, None) => bail!("descriptor broker returned success without a descriptor"),
        (RESPONSE_REJECTED, None) => bail!("descriptor broker rejected the session root claim"),
        (RESPONSE_INTERNAL, None) => {
            bail!("descriptor broker could not duplicate the session root")
        }
        (_, Some(_)) => bail!("descriptor broker attached a descriptor to an error response"),
        (status, None) => bail!("descriptor broker returned unknown status {status}"),
    }
}

fn serve_claim(
    stream: &mut TrackedStream,
    registry: &RegisteredRootRegistry,
    secret: &[u8; SECRET_LEN],
) -> Result<()> {
    let mut claim = [0u8; CLAIM_LEN];
    stream.read_exact(&mut claim)?;
    let secret_start = CLAIM_MAGIC.len();
    let authenticated = claim[..secret_start] == *CLAIM_MAGIC
        && claim[secret_start..secret_start + SECRET_LEN] == *secret;
    if !authenticated {
        stream.write_all(&[RESPONSE_REJECTED])?;
        return Ok(());
    }
    let root_start = secret_start + SECRET_LEN;
    let root_end = root_start + size_of::<u64>();
    let root_id = RegisteredRootId(u64::from_be_bytes(
        claim[root_start..root_end]
            .try_into()
            .expect("claim root identifier has a fixed length"),
    ));
    let Some(kind) = RegisteredDescriptorKind::from_wire_byte(claim[root_end]) else {
        stream.write_all(&[RESPONSE_REJECTED])?;
        return Ok(());
    };
    match registry.acquire_optional(root_id, kind) {
        Ok(Some(directory)) => send_descriptor(stream.as_raw_fd(), directory.as_raw_fd())?,
        Ok(None) => stream.write_all(&[RESPONSE_REJECTED])?,
        Err(_) => stream.write_all(&[RESPONSE_INTERNAL])?,
    }
    Ok(())
}

fn send_descriptor(socket: RawFd, descriptor: RawFd) -> io::Result<()> {
    let mut status = [RESPONSE_OK];
    let mut iovec = libc::iovec {
        iov_base: status.as_mut_ptr().cast(),
        iov_len: status.len(),
    };
    let mut control = FdControl {
        bytes: [0; FD_CONTROL_LEN],
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = FD_CONTROL_LEN as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(io::Error::other("SCM_RIGHTS control buffer is too small"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as libc::c_uint) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
    }
    loop {
        let sent = unsafe { libc::sendmsg(socket, &message, 0) };
        if sent == 1 {
            return Ok(());
        }
        if sent >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "descriptor broker sent an incomplete response",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn receive_descriptor(socket: RawFd) -> io::Result<(u8, Option<File>)> {
    let mut status = [0u8];
    let mut iovec = libc::iovec {
        iov_base: status.as_mut_ptr().cast(),
        iov_len: status.len(),
    };
    let mut control = FdControl {
        bytes: [0; FD_CONTROL_LEN],
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = FD_CONTROL_LEN as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    // Darwin does not expose an atomic close-on-exec receive flag. The future
    // worker protocol must therefore claim its roots during single-threaded
    // initialization, before it can spawn children, and acknowledge startup
    // only after this function has applied FD_CLOEXEC.
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    loop {
        let received = unsafe { libc::recvmsg(socket, &mut message, flags) };
        if received == 1 {
            break;
        }
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "descriptor broker closed without a response",
            ));
        }
        if received > 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "descriptor broker returned an oversized response",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }

    let mut descriptors = Vec::new();
    let mut malformed = message.msg_flags & libc::MSG_CTRUNC != 0;
    // SAFETY: recvmsg filled `control` through `message` and set
    // `msg_controllen` to the bytes it wrote, which bounds the header walk.
    // Every SCM_RIGHTS payload holds descriptors this process now owns; each
    // is wrapped exactly once so a later rejection closes all of them.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let header_len = libc::CMSG_LEN(0) as usize;
            let control_len = (*header).cmsg_len as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && control_len >= header_len
            {
                let data_len = control_len - header_len;
                malformed |= data_len == 0 || !data_len.is_multiple_of(size_of::<RawFd>());
                for index in 0..data_len / size_of::<RawFd>() {
                    let raw = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    );
                    descriptors.push(File::from_raw_fd(raw));
                }
            } else {
                malformed = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if malformed || descriptors.len() > 1 {
        drop(descriptors);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "descriptor broker returned malformed ancillary data",
        ));
    }
    let descriptor = descriptors.pop();
    if let Some(file) = &descriptor {
        set_close_on_exec(file)?;
    }
    Ok((status[0], descriptor))
}

fn set_close_on_exec(file: &File) -> io::Result<()> {
    let flags = loop {
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        if flags >= 0 {
            break flags;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };
    loop {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    const CHILD_ENV: &str = "SYQ_TEST_DESCRIPTOR_BROKER_CHILD";
    const CHILD_TEST: &str =
        "descriptor_broker::tests::independent_process_receives_exact_registered_descriptor";

    fn read_at(directory: &File, name: &CStr) -> Vec<u8> {
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(
            descriptor >= 0,
            "openat failed: {}",
            io::Error::last_os_error()
        );
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn ticket_from_environment() -> DescriptorTicket {
        let socket_path = std::env::var_os("SYQ_TEST_DESCRIPTOR_BROKER_SOCKET")
            .unwrap()
            .as_bytes()
            .to_vec();
        let secret_bytes = hex_decode(&std::env::var("SYQ_TEST_DESCRIPTOR_BROKER_SECRET").unwrap());
        DescriptorTicket {
            socket_path,
            secret: secret_bytes.try_into().unwrap(),
            root_id: RegisteredRootId(
                std::env::var("SYQ_TEST_DESCRIPTOR_BROKER_ROOT")
                    .unwrap()
                    .parse()
                    .unwrap(),
            ),
            kind: RegisteredDescriptorKind::Directory,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn hex_decode(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|digits| u8::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn shared_process_workers_clone_the_registered_root() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        std::fs::write(selected.join("marker"), b"original").unwrap();
        let original = File::open(&selected).unwrap();
        let identity = original.metadata().unwrap();
        let session = DescriptorSessionSlot::default();
        let ticket = session.register(original).unwrap();

        std::fs::rename(&selected, temp.path().join("moved")).unwrap();
        std::fs::create_dir(&selected).unwrap();
        std::fs::write(selected.join("marker"), b"replacement").unwrap();

        let local_session = session.clone();
        let local_ticket = ticket.clone();
        let local = std::thread::spawn(move || local_session.acquire(&local_ticket).unwrap());
        let tcp = std::thread::spawn(move || session.acquire(&ticket).unwrap());
        for directory in [local.join().unwrap(), tcp.join().unwrap()] {
            let metadata = directory.metadata().unwrap();
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (identity.dev(), identity.ino())
            );
            assert_eq!(read_at(&directory, c"marker"), b"original");
        }
    }

    #[test]
    fn source_parent_and_object_are_distinct_repeatable_capabilities() {
        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("selected");
        std::fs::write(&selected, b"selected").unwrap();
        let object = File::open(&selected).unwrap();
        let object_identity = object.metadata().unwrap();
        let session = DescriptorSessionSlot::default();
        let mut registrations = session
            .register_source_handles(vec![(File::open(temp.path()).unwrap(), Some(object))])
            .unwrap();
        let (directory_ticket, leaf_ticket) = registrations.remove(0);
        let leaf_ticket = leaf_ticket.unwrap();
        assert!(directory_ticket.is_directory());
        assert!(leaf_ticket.is_source_leaf());
        assert_eq!(directory_ticket.root_id(), leaf_ticket.root_id());
        assert!(directory_ticket.same_session(&leaf_ticket));

        // An empty slot takes the independent-worker SCM_RIGHTS path. Both
        // kinds can be claimed repeatedly and each receipt is close-on-exec.
        let fresh = DescriptorSessionSlot::default();
        let directory = fresh.acquire(&directory_ticket).unwrap();
        assert!(directory.metadata().unwrap().is_dir());
        for object in [
            fresh.acquire(&leaf_ticket).unwrap(),
            fresh.acquire(&leaf_ticket).unwrap(),
        ] {
            let metadata = object.metadata().unwrap();
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (object_identity.dev(), object_identity.ino())
            );
            assert_ne!(
                unsafe { libc::fcntl(object.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }

        let mut missing_object = session.register(File::open(temp.path()).unwrap()).unwrap();
        missing_object.kind = RegisteredDescriptorKind::SourceLeaf;
        assert!(claim_descriptor(&missing_object)
            .unwrap_err()
            .to_string()
            .contains("rejected"));
    }

    #[test]
    fn independent_process_receives_exact_registered_descriptor() {
        if std::env::var_os(CHILD_ENV).is_some() {
            let ticket = ticket_from_environment();
            let directory = claim_descriptor(&ticket).unwrap();
            let metadata = directory.metadata().unwrap();
            let expected_dev: u64 = std::env::var("SYQ_TEST_DESCRIPTOR_BROKER_DEV")
                .unwrap()
                .parse()
                .unwrap();
            let expected_ino: u64 = std::env::var("SYQ_TEST_DESCRIPTOR_BROKER_INO")
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (expected_dev, expected_ino)
            );
            assert_eq!(read_at(&directory, c"marker"), b"original");
            assert_ne!(
                unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let selected = temp.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        std::fs::write(selected.join("marker"), b"original").unwrap();
        let original = File::open(&selected).unwrap();
        let identity = original.metadata().unwrap();
        let session = DescriptorSessionSlot::default();
        let ticket = session.register(original).unwrap();

        std::fs::rename(&selected, temp.path().join("moved")).unwrap();
        std::fs::create_dir(&selected).unwrap();
        std::fs::write(selected.join("marker"), b"replacement").unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env("SYQ_TEST_DESCRIPTOR_BROKER_SOCKET", ticket.socket_path())
            .env("SYQ_TEST_DESCRIPTOR_BROKER_SECRET", hex(&ticket.secret))
            .env(
                "SYQ_TEST_DESCRIPTOR_BROKER_ROOT",
                ticket.root_id.0.to_string(),
            )
            .env("SYQ_TEST_DESCRIPTOR_BROKER_DEV", identity.dev().to_string())
            .env("SYQ_TEST_DESCRIPTOR_BROKER_INO", identity.ino().to_string())
            .status()
            .unwrap();
        assert!(status.success(), "descriptor handoff subprocess failed");
    }

    #[test]
    fn broker_rejects_bad_secrets_and_unknown_roots() {
        let temp = tempfile::tempdir().unwrap();
        let session = DescriptorSession::start(2, 2).unwrap();
        let root = session.register(File::open(temp.path()).unwrap()).unwrap();

        let mut bad_secret = session.ticket(root).unwrap();
        bad_secret.secret[0] ^= 1;
        assert!(claim_descriptor(&bad_secret)
            .unwrap_err()
            .to_string()
            .contains("rejected"));

        let mut unknown = session.ticket(root).unwrap();
        unknown.root_id = RegisteredRootId(root.0 + 1);
        assert!(claim_descriptor(&unknown)
            .unwrap_err()
            .to_string()
            .contains("rejected"));
    }

    #[test]
    fn registration_requires_explicit_root_reuse_and_enforces_the_limit() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        std::fs::create_dir(&first).unwrap();
        let session = DescriptorSession::start(1, 1).unwrap();
        let first_id = session.register(File::open(&first).unwrap()).unwrap();
        assert!(session.registry().acquire(first_id).is_ok());
        let error = session.register(File::open(&first).unwrap()).unwrap_err();
        assert!(error.to_string().contains("root limit (1) exceeded"));
    }

    #[test]
    fn batch_registration_checks_capacity_before_consuming_any_root_id() {
        let temp = tempfile::tempdir().unwrap();
        let session = DescriptorSession::start(1, 1).unwrap();
        let error = session
            .registry()
            .register_many(vec![
                File::open(temp.path()).unwrap(),
                File::open(temp.path()).unwrap(),
            ])
            .unwrap_err();
        assert!(error.to_string().contains("root limit (1) exceeded"));

        let id = session.register(File::open(temp.path()).unwrap()).unwrap();
        assert_eq!(id.get(), 1);
    }

    #[test]
    fn repeated_inode_registrations_keep_distinct_authority_ids() {
        let temp = tempfile::tempdir().unwrap();
        let session = DescriptorSession::start(2, 1).unwrap();
        let ids = session
            .registry()
            .register_many(vec![
                File::open(temp.path()).unwrap(),
                File::open(temp.path()).unwrap(),
            ])
            .unwrap();
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn populated_slot_rejects_another_sessions_ticket() {
        let temp = tempfile::tempdir().unwrap();
        let first = DescriptorSessionSlot::default();
        first.register(File::open(temp.path()).unwrap()).unwrap();
        let second = DescriptorSessionSlot::default();
        let foreign = second.register(File::open(temp.path()).unwrap()).unwrap();

        let error = first.acquire(&foreign).unwrap_err();
        assert!(error.to_string().contains("does not belong"));
    }

    #[test]
    fn explicit_close_removes_broker_while_slot_clones_remain() {
        let temp = tempfile::tempdir().unwrap();
        let session = DescriptorSessionSlot::default();
        let listener_clone = session.clone();
        let ticket = session.register(File::open(temp.path()).unwrap()).unwrap();
        let broker_directory = ticket.socket_path().parent().unwrap().to_path_buf();
        assert!(broker_directory.exists());

        session.close();

        assert!(listener_clone.is_closed());
        assert!(!broker_directory.exists());
        assert!(listener_clone.acquire(&ticket).is_err());
    }

    #[test]
    fn ticket_debug_output_does_not_expose_the_secret() {
        let temp = tempfile::tempdir().unwrap();
        let session = DescriptorSession::start(1, 1).unwrap();
        let root = session.register(File::open(temp.path()).unwrap()).unwrap();
        let ticket = session.ticket(root).unwrap();
        let debug = format!("{ticket:?}");
        assert!(debug.contains("root_id"));
        assert!(!debug.contains(&hex(&ticket.secret)));
    }
}
