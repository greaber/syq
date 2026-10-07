//! Ephemeral read authority for one approved source selection.
//!
//! This uses the native source descriptor registry rather than granting
//! authority to request pathnames. The caller constructs the policy from an
//! approved request; this module neither obtains approval nor accepts policy
//! from a worker. No enrollment, signed-grant, or durable-state format changes.
//!
//! Server integration must retain a `SourceConnection` per admitted connection,
//! initialize its executor before HelloOk, use `register` for source registration,
//! and call `authorize` before every
//! other request (including each generated ReadRange in a ReadStream). Call
//! `check_response` before emitting ordinary replies and `record_scan` before
//! emitting scan/ignored batches. FsOps still executes the approved requests:
//! its registered descriptors enforce symlink and exact-leaf confinement.
//! FileHash must execute through `file_hash`, which checks each hashing chunk.
//! TCP listeners and sender budgets use only the approved transport settings.

use crate::delegation::CopyLimits;
use crate::descriptor_broker::{DescriptorSessionSlot, DescriptorTicket, RegisteredRootId};
use crate::fsops::FsOps;
use crate::proto::{
    ConnectionRole, OperatorSymlinkPolicy, RegisteredPath, RegisteredSourceRoot, Request, Response,
    SourceRootBase, SourceRootSelection, Which,
};
use anyhow::{bail, ensure, Context, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) struct SourcePolicy {
    pub base: SourceRootBase,
    pub selections: Vec<SourceRootSelection>,
    pub selection_types: Vec<crate::cli::SourceSelection>,
    pub symlink_policy: OperatorSymlinkPolicy,
    pub hashing: crate::hashing::HashPolicy,
    pub preservation: crate::inode_metadata::Selection,
    pub sparse: bool,
    pub compressed: bool,
    pub tcp: Option<SourceTcpPolicy>,
    pub send_rate: Option<u64>,
    pub limits: CopyLimits,
    pub deadline: Instant,
}

pub(crate) struct SourceTcpPolicy {
    pub port_lo: u16,
    pub port_hi: u16,
    pub congestion_control: Option<String>,
}

struct State {
    open: bool,
    control_admitted: bool,
    live_connections: u16,
    roots: HashMap<RegisteredRootId, RegisteredSourceRoot>,
    paths: HashSet<(RegisteredRootId, Vec<u8>)>,
    requested_bytes: u64,
    tcp_listener_started: bool,
    send_budget: Option<DescriptorTicket>,
}

pub(crate) struct SourceAuthority {
    policy: SourcePolicy,
    state: Mutex<State>,
}

/// Dropping the control permit revokes the whole authority. Already admitted
/// bounded operations may finish; later requests and stream chunks fail.
pub(crate) struct SourceConnection {
    authority: Arc<SourceAuthority>,
    control: bool,
}

impl SourceAuthority {
    pub(crate) fn new(policy: SourcePolicy) -> Result<Arc<Self>> {
        policy.base.validate()?;
        ensure!(
            !policy.selections.is_empty(),
            "source approval has no selections"
        );
        ensure!(
            policy.selection_types.len() == policy.selections.len(),
            "source selection types differ in length"
        );
        ensure!(
            policy.limits.max_connections > 0,
            "source connection limit is zero"
        );
        ensure!(policy.limits.max_entries > 0, "source entry limit is zero");
        ensure!(policy.send_rate != Some(0), "source sender rate is zero");
        if let Some(tcp) = &policy.tcp {
            ensure!(
                tcp.port_lo <= tcp.port_hi,
                "source TCP port range is reversed"
            );
        }
        for selection in &policy.selections {
            ensure!(
                !selection.path.is_empty() && !selection.path.contains(&0),
                "source approval contains an invalid selection"
            );
        }
        Ok(Arc::new(Self {
            policy,
            state: Mutex::new(State {
                open: true,
                control_admitted: false,
                live_connections: 0,
                roots: HashMap::new(),
                paths: HashSet::new(),
                requested_bytes: 0,
                tcp_listener_started: false,
                send_budget: None,
            }),
        }))
    }

    pub(crate) fn close(&self) {
        self.state.lock().unwrap().open = false;
    }

    pub(crate) fn is_open(&self) -> bool {
        self.check_open(&self.state.lock().unwrap()).is_ok()
    }

    /// The descriptor session owns one rate and one budget across TCP and SSH
    /// workers. Worker omission of a ticket never disables the approved rate.
    pub(crate) fn sending_budget(
        &self,
        session: &DescriptorSessionSlot,
    ) -> Result<Option<(Arc<crate::bwlimit::transport::Budget>, DescriptorTicket)>> {
        let mut state = self.state.lock().unwrap();
        self.check_open(&state)?;
        let Some(rate) = self.policy.send_rate else {
            return Ok(None);
        };
        let (budget, ticket) = session.send_budget(rate)?;
        state.send_budget = Some(ticket.clone());
        Ok(Some((budget, ticket)))
    }

    pub(crate) fn check_response(&self, response: &Response) -> Result<()> {
        if matches!(
            response,
            Response::Err(_) | Response::EndpointError(_) | Response::ReadStreamDone
        ) {
            return Ok(());
        }
        let state = self.state.lock().unwrap();
        self.check_open(&state)?;
        if let Response::FileHash { size, .. } = response {
            ensure!(
                *size <= self.policy.limits.max_file_bytes,
                "source per-file byte limit exceeded"
            );
        }
        Ok(())
    }

    fn check_open(&self, state: &State) -> Result<()> {
        ensure!(state.open, "source authorization is closed");
        ensure!(
            Instant::now() <= self.policy.deadline,
            "source authorization expired"
        );
        Ok(())
    }

    pub(crate) fn acquire(
        self: &Arc<Self>,
        role: &ConnectionRole,
        compressed: bool,
    ) -> Result<SourceConnection> {
        let mut state = self.state.lock().unwrap();
        self.check_open(&state)?;
        ensure!(
            compressed == self.policy.compressed,
            "source compression differs from approval"
        );
        ensure!(
            state.live_connections < self.policy.limits.max_connections,
            "source connection limit exceeded"
        );
        let control = match role {
            ConnectionRole::Control => {
                ensure!(
                    !state.control_admitted,
                    "source control connection already admitted"
                );
                state.control_admitted = true;
                true
            }
            ConnectionRole::SourceWorker { roots, send_budget } => {
                if let Some(ticket) = send_budget {
                    let approved = state
                        .send_budget
                        .as_ref()
                        .context("source sender budget was not issued")?;
                    ensure!(
                        ticket.is_bandwidth()
                            && ticket.same_session(approved)
                            && ticket.root_id() == approved.root_id(),
                        "source worker sender budget differs from approval"
                    );
                }
                ensure!(!roots.is_empty(), "source worker has no approved roots");
                let mut seen = HashSet::new();
                for root in roots {
                    root.validate()?;
                    ensure!(
                        seen.insert(root.selection.root()),
                        "duplicate source worker root"
                    );
                    let approved = state
                        .roots
                        .get(&root.selection.root())
                        .context("source worker root was not approved")?;
                    ensure!(
                        !root.allow_unconfined_paths
                            && root.ticket.same_session(&approved.ticket)
                            && root.selection == approved.selection
                            && root.expected_leaf == approved.expected_leaf
                            && match (&root.leaf_ticket, &approved.leaf_ticket) {
                                (Some(actual), Some(expected)) =>
                                    actual.same_session(expected)
                                        && actual.root_id() == expected.root_id(),
                                (None, None) => true,
                                _ => false,
                            },
                        "source worker capability differs from approval"
                    );
                }
                false
            }
            _ => bail!("connection role is not valid on an approved source"),
        };
        state.live_connections += 1;
        Ok(SourceConnection {
            authority: Arc::clone(self),
            control,
        })
    }

    fn check_path(&self, state: &State, source: &RegisteredPath) -> Result<()> {
        let root = state
            .roots
            .get(&source.root())
            .context("source root was not approved")?;
        ensure!(
            root.selection.relative().is_empty() || root.selection == *source,
            "exact source selection does not authorize another path"
        );
        Ok(())
    }

    fn record_paths(&self, state: &mut State, paths: &[RegisteredPath]) -> Result<()> {
        let mut additions = HashSet::new();
        for source in paths {
            self.check_path(state, source)?;
            let key = (source.root(), source.relative().to_vec());
            if !state.paths.contains(&key) {
                additions.insert(key);
            }
        }
        ensure!(
            (state.paths.len() as u64).saturating_add(additions.len() as u64)
                <= self.policy.limits.max_entries,
            "source entry limit exceeded"
        );
        state.paths.extend(additions);
        Ok(())
    }
}

impl SourceConnection {
    /// Install approved read settings even when the client omits their optional
    /// configuration requests. Workers receive the same settings as control.
    pub(crate) fn initialize(&self, ops: &mut FsOps) -> Result<()> {
        self.authority
            .check_open(&self.authority.state.lock().unwrap())?;
        let policy = &self.authority.policy;
        ops.set_hash_policy(policy.hashing);
        let response = ops.handle_in_place(&mut Request::ConfigurePreservation {
            selection: policy.preservation,
            sparse: policy.sparse,
            destination: false,
            narrow_new_directories: false,
        });
        match response {
            Response::Ok => Ok(()),
            Response::Err(error) => bail!("configure approved source: {error}"),
            Response::EndpointError(error) => bail!("configure approved source: {}", error.message),
            _ => bail!("unexpected approved-source configuration response"),
        }
    }

    /// Only this trusted executor may turn the approved path selections into
    /// capabilities. Never accept a registration response supplied by a peer.
    pub(crate) fn register(&self, ops: &mut FsOps, request: &Request) -> Result<Response> {
        ensure!(
            self.control,
            "source registration requires the control connection"
        );
        self.initialize(ops)?;
        let mut state = self.authority.state.lock().unwrap();
        self.authority.check_open(&state)?;
        ensure!(
            state.roots.is_empty(),
            "approved source roots are already registered"
        );
        let Request::RegisterSourceRoots {
            base,
            selections,
            symlink_policy,
            allow_unconfined_paths,
            shared_workers,
            independent_handoff_workers,
        } = request
        else {
            bail!("expected approved source registration")
        };
        let policy = &self.authority.policy;
        ensure!(
            base == &policy.base
                && *symlink_policy == policy.symlink_policy
                && !allow_unconfined_paths
                && selections.len() == policy.selections.len()
                && selections
                    .iter()
                    .zip(&policy.selections)
                    .all(|(actual, approved)| actual.path == approved.path
                        && actual.follow_root == approved.follow_root),
            "source registration differs from approval"
        );
        // These are separate descriptor-capacity estimates, not two sets of
        // live workers: TCP workers may also need an independent SSH handoff.
        // Actual admission below remains shared across every transport.
        ensure!(
            *shared_workers < usize::from(policy.limits.max_connections)
                && *independent_handoff_workers < usize::from(policy.limits.max_connections),
            "source registration exceeds the connection limit"
        );
        let response = ops.handle_in_place(&mut request.clone());
        if let Response::SourceRootsRegistered(roots) = &response {
            for (root, kind) in roots.iter().zip(&policy.selection_types) {
                root.validate()?;
                match kind {
                    crate::cli::SourceSelection::File => ensure!(
                        root.expected_leaf.is_some(),
                        "approved exact source is a directory"
                    ),
                    crate::cli::SourceSelection::Directory
                    | crate::cli::SourceSelection::Contents => ensure!(
                        root.expected_leaf.is_none(),
                        "approved source directory is a non-directory entry"
                    ),
                    _ => {}
                }
                ensure!(
                    !root.allow_unconfined_paths,
                    "unconfined source registration refused"
                );
            }
            for root in roots {
                state.roots.insert(root.selection.root(), root.clone());
            }
        }
        self.authority.check_open(&state)?;
        Ok(response)
    }

    /// Admit one request before execution. Payload limits count requested
    /// bytes, including retries and requests that subsequently fail, just as
    /// the destination's transfer limit counts submitted writes. Hashing has
    /// its own per-file bound and does not consume the payload allowance.
    pub(crate) fn authorize(&self, request: &Request) -> Result<()> {
        if matches!(
            request,
            Request::Shutdown | Request::StopReadStream | Request::ShrinkReadStream { .. }
        ) {
            return Ok(());
        }
        let mut state = self.authority.state.lock().unwrap();
        self.authority.check_open(&state)?;
        let policy = &self.authority.policy;
        let mut paths = Vec::new();
        let mut bytes = 0u64;
        ensure!(
            !self.control
                || !matches!(
                    request,
                    Request::ReadRange { .. }
                        | Request::ReadComparedRange { .. }
                        | Request::ReadSmallBatch(_)
                        | Request::ReadStream(_)
                ),
            "source payload requires a direct data worker"
        );
        let source = |source: &Option<RegisteredPath>| -> Result<RegisteredPath> {
            source
                .clone()
                .context("approved source request omitted its registered reference")
        };
        let no_guard = |guard: &Option<crate::proto::ContainerGuard>| -> Result<()> {
            ensure!(
                guard.is_none(),
                "approved source rejects caller-supplied guards"
            );
            Ok(())
        };
        let range = |off: u64, len: u64| -> Result<()> {
            ensure!(
                off.checked_add(len).is_some_and(
                    |end| end <= policy.limits.max_file_bytes && end <= i64::MAX as u64
                ),
                "source per-file byte limit exceeded"
            );
            Ok(())
        };
        match request {
            Request::TcpListen {
                key,
                token,
                port_lo,
                port_hi,
                congestion_control,
                send_rate,
            } => {
                ensure!(
                    self.control,
                    "source TCP listener requires the control connection"
                );
                let tcp = policy
                    .tcp
                    .as_ref()
                    .context("source TCP listener was not approved")?;
                ensure!(
                    key.as_ref()
                        .is_some_and(|key| key.len() == crate::tcp_records::KEY_LEN)
                        && token.len() == 16,
                    "approved source requires encrypted authenticated TCP"
                );
                ensure!(
                    (*port_lo, *port_hi) == (tcp.port_lo, tcp.port_hi)
                        && congestion_control == &tcp.congestion_control
                        && *send_rate == policy.send_rate,
                    "source TCP settings differ from approval"
                );
                ensure!(
                    !state.tcp_listener_started,
                    "approved source TCP listener already started"
                );
                state.tcp_listener_started = true;
            }
            Request::CreateSendBudget { rate } => {
                ensure!(
                    self.control && Some(*rate) == policy.send_rate,
                    "source sender budget differs from approval"
                );
            }
            Request::ConfigureHashing(hashing) => {
                ensure!(
                    *hashing == policy.hashing,
                    "source hashing differs from approval"
                );
            }
            Request::ConfigurePreservation {
                selection,
                sparse,
                destination,
                ..
            } => {
                ensure!(
                    !destination && *selection == policy.preservation && *sparse == policy.sparse,
                    "source metadata policy differs from approval"
                );
            }
            Request::Scan {
                source: reference,
                guard,
                ..
            } => {
                no_guard(guard)?;
                paths.push(source(reference)?);
            }
            Request::StatMany {
                paths: labels,
                sources,
                guard,
                ..
            } => {
                no_guard(guard)?;
                paths = sources
                    .clone()
                    .context("source stat omitted registered references")?;
                ensure!(
                    paths.len() == labels.len(),
                    "source stat reference count differs"
                );
            }
            Request::ReadRange {
                source: reference,
                off,
                len,
                ..
            }
            | Request::ReadComparedRange {
                source: reference,
                off,
                len,
                ..
            } => {
                range(*off, u64::from(*len))?;
                bytes = u64::from(*len);
                ensure!(
                    bytes <= crate::proto::MAX_READ_BYTES,
                    "source read exceeds frame limit"
                );
                paths.push(source(reference)?);
            }
            Request::ReadSmallBatch(reads) => {
                for read in reads {
                    range(0, u64::from(read.len))?;
                    bytes = bytes
                        .checked_add(u64::from(read.len))
                        .context("source byte count overflow")?;
                    paths.push(source(&read.source)?);
                }
                ensure!(
                    bytes <= crate::proto::MAX_READ_BYTES,
                    "source batch exceeds frame limit"
                );
            }
            Request::ReadStream(stream) => {
                stream.validate()?;
                range(stream.off, stream.end - stream.off)?;
                paths.push(source(&stream.source)?);
                // Each generated ReadRange must be admitted separately. This
                // permits cancellation and charges only the requested chunks.
            }
            Request::HashBlocks {
                source: reference,
                off,
                len,
                block,
                which,
                guard,
                ..
            } => {
                no_guard(guard)?;
                ensure!(
                    matches!(which, Which::Final),
                    "approved source cannot hash a partial"
                );
                ensure!(
                    *block == policy.limits.hash_block_bytes
                        && crate::proto::hash_response_fits(*block, *len),
                    "source hash block policy differs from approval"
                );
                range(*off, *len)?;
                paths.push(source(reference)?);
            }
            Request::FileHash {
                source: reference,
                guard,
                ..
            } => {
                no_guard(guard)?;
                paths.push(source(reference)?);
            }
            Request::TransportStats => {}
            _ => bail!("request is not valid on an approved source"),
        }
        let requested_bytes = state
            .requested_bytes
            .checked_add(bytes)
            .context("source byte count overflow")?;
        ensure!(
            requested_bytes <= policy.limits.max_total_bytes,
            "source total-byte limit exceeded"
        );
        self.authority.record_paths(&mut state, &paths)?;
        state.requested_bytes = requested_bytes;
        Ok(())
    }

    /// Scan entries are relative to the already-authorized scan root. Count
    /// distinct paths across connections, including reported ignored entries.
    pub(crate) fn record_scan<'a>(
        &self,
        root: &RegisteredPath,
        entries: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<()> {
        let mut state = self.authority.state.lock().unwrap();
        self.authority.check_open(&state)?;
        self.authority.check_path(&state, root)?;
        let paths = entries
            .into_iter()
            .map(|entry| root.join(entry))
            .collect::<Result<Vec<_>>>()?;
        self.authority.record_paths(&mut state, &paths)
    }

    /// Whole-file hashing has no length in its wire request. Bound it while
    /// reading, rather than learning that it exceeded approval after EOF.
    pub(crate) fn file_hash(&self, ops: &mut FsOps, request: &Request) -> Result<Response> {
        self.authorize(request)?;
        let Request::FileHash {
            path,
            source,
            guard,
        } = request
        else {
            bail!("expected an approved source file hash")
        };
        let mut first = true;
        ops.file_hash_checked(path, source.as_ref(), guard.as_ref(), &mut |file, size| {
            let state = self.authority.state.lock().unwrap();
            self.authority.check_open(&state)?;
            drop(state);
            if first {
                ensure!(
                    file.metadata()?.len() <= self.authority.policy.limits.max_file_bytes,
                    "source per-file byte limit exceeded"
                );
                first = false;
            }
            ensure!(
                size <= self.authority.policy.limits.max_file_bytes,
                "source per-file byte limit exceeded"
            );
            Ok(())
        })
    }
}

impl Drop for SourceConnection {
    fn drop(&mut self) {
        let mut state = self.authority.state.lock().unwrap();
        state.live_connections -= 1;
        if self.control {
            state.open = false;
        }
    }
}

#[cfg(test)]
mod tests;
