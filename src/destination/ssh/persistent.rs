//! A reusable approved SSH login, owned by a keeper while its laptop is connected.
use super::{foreground, local_config::LocalPlan, resolution, SessionRequest, Tty};
use crate::auth_from::Provider;
use crate::cli::{AuthFrom, NativeEndpoint};
use crate::persistence::Domain;
use crate::process::CommandExt as _;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

mod cleanup;
pub(crate) use cleanup::cleanup_domain;

const INTERNAL: &str = "--approved-ssh-master";
const POLL: Duration = Duration::from_millis(100);
const GENERATION: &str = "account-generation";
const MASTER_SESSION_OPTIONS: &[&str] = &[
    "RemoteCommand=none",
    "RequestTTY=no",
    "ForkAfterAuthentication=no",
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Startup {
    command: Vec<Vec<u8>>,
    authorizer: Provider,
    requested: NativeEndpoint,
    generation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    selected: Option<resolution::Selection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_identity: Option<(u64, u64)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    authorizer: Provider,
    requested: NativeEndpoint,
    endpoint: NativeEndpoint,
    control: PathBuf,
}

fn master_parent(domain: &Domain) -> PathBuf {
    if domain.is_default() {
        crate::persistence::runtime_parent_path()
    } else {
        domain.runtime_path()
    }
}
fn ensure_master_parent(domain: &Domain) -> Result<PathBuf> {
    if domain.is_default() {
        crate::persistence::ensure_runtime_parent()
    } else {
        domain.ensure_runtime()
    }
}
pub(super) fn directory(domain: &Domain) -> Result<PathBuf> {
    ensure_master_parent(domain)?;
    let path = domain.approved_index_path();
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    existing_directory(domain)?.context("SSH authority directory disappeared")
}
pub(super) fn existing_directory(domain: &Domain) -> Result<Option<PathBuf>> {
    let path = domain.approved_index_path();
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("SSH authority index must be an owner-only directory");
    }
    Ok(Some(path))
}
// Separate from ordinary persistence: account authorization follows its return
// connection even when global persistence/automatic receiving is disabled.
fn read_generation(path: &Path) -> Result<Option<String>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() == 64,
        "SSH account generation must be a bounded owner-only file"
    );
    use std::io::Read as _;
    let mut generation = String::new();
    file.take(65).read_to_string(&mut generation)?;
    anyhow::ensure!(
        generation.len() == 64 && generation.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid SSH account generation"
    );
    Ok(Some(generation))
}
fn generation_path(domain: &Domain) -> PathBuf {
    domain.approved_index_path().join(GENERATION)
}
pub(super) fn ensure_generation(domain: &Domain) -> Result<String> {
    ensure_generation_at(&directory(domain)?)
}
fn ensure_generation_at(directory: &Path) -> Result<String> {
    let path = directory.join(GENERATION);
    if let Some(generation) = read_generation(&path)? {
        return Ok(generation);
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)?;
    let generation = blake3::hash(&random).to_hex().to_string();
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(generation.as_bytes())?;
    match file.persist_noclobber(&path) {
        Ok(_) => Ok(generation),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_generation(&path)?.context("SSH account generation changed during startup; retry")
        }
        Err(error) => Err(error.error.into()),
    }
}
pub(super) fn generation_open(domain: &Domain, generation: &str) -> Result<bool> {
    if !domain.is_default() && !domain.enabled()? {
        return Ok(false);
    }
    Ok(read_generation(&generation_path(domain))?.as_deref() == Some(generation))
}
fn startup_open(domain: &Domain, startup: &Startup) -> Result<bool> {
    if let Some(identity) = startup.scope_identity {
        if !domain.is_current(identity) {
            return Ok(false);
        }
    }
    generation_open(domain, &startup.generation)
}

pub(super) fn provider_state_version(provider: &Provider) -> u16 {
    match provider {
        Provider::Return(_) => 1,
        Provider::Ssh { .. } => 2,
    }
}

fn index_path(domain: &Domain, authorizer: &str, destination: &NativeEndpoint) -> Result<PathBuf> {
    let identity = serde_json::to_vec(&(authorizer, destination))?;
    Ok(domain
        .approved_index_path()
        .join(format!("{}.json", blake3::hash(&identity).to_hex())))
}
fn read_record(path: &Path) -> Result<Option<Record>> {
    read_record_inner(path).with_context(|| format!("read SSH account record {}", path.display()))
}
fn read_record_inner(path: &Path) -> Result<Option<Record>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 16384
    {
        bail!("SSH authority record must be a bounded owner-only file");
    }
    let record: Record = serde_json::from_reader(file)?;
    record.authorizer.validate()?;
    if record.version != provider_state_version(&record.authorizer) {
        bail!("unsupported SSH authority record; reconnect with syq persist connect");
    }
    Ok(Some(record))
}
fn master_options(record: &Record) -> Vec<OsString> {
    let mut options: Vec<OsString> = ["-F", "/dev/null", "-a", "-x", "-k", "-S"]
        .into_iter()
        .map(Into::into)
        .collect();
    options.push(crate::persistence::openssh_control_path(&record.control));
    // A missing master must fail, never start another authentication attempt.
    for option in [
        "ControlMaster=no",
        "ProxyCommand=false",
        "ProxyJump=none",
        "PubkeyAuthentication=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
    ] {
        options.extend(["-o".into(), option.into()]);
    }
    options
}
fn master_command(record: &Record) -> Command {
    let mut command = Command::new("ssh");
    command.args(master_options(record));
    command
}
fn validate_record(domain: &Domain, record: &Record) -> Result<()> {
    let scope = record
        .control
        .parent()
        .context("SSH authority control path has no scope")?;
    if scope.parent() != Some(master_parent(domain).as_path())
        || !scope
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("approved-"))
    {
        bail!("SSH authority record has an invalid scope");
    }
    crate::persistence::validate_scope(scope)?;
    crate::persistence::validate_openssh_socket_path(&record.control)?;
    Ok(())
}

pub(crate) struct Cached(
    Record,
    Option<std::sync::Arc<super::workers::Authorization>>,
);
impl Cached {
    /// Only an actual operation freezes worker authorization. Lookup-only
    /// completion/export paths never connect to the authorization provider.
    pub(crate) fn worker_authorization(
        &self,
        domain: &Domain,
    ) -> Result<std::sync::Arc<super::workers::Authorization>> {
        let workers = self
            .1
            .as_ref()
            .context("approved account has no data-worker authorization context")?;
        anyhow::ensure!(
            workers.belongs_to(domain),
            "approved worker authorization belongs to another persistence scope"
        );
        Ok(workers.clone())
    }

    fn with_workers(
        mut self,
        domain: &Domain,
        request: SessionRequest,
        selected: &resolution::Selection,
        generation: String,
        proxy: Option<String>,
    ) -> Result<Self> {
        self.1 = Some(std::sync::Arc::new(super::workers::Authorization::new(
            domain,
            request,
            selected,
            generation,
            proxy,
            self.0.control.clone(),
        )?));
        Ok(self)
    }

    pub(crate) fn control(&self) -> &Path {
        &self.0.control
    }
    pub(crate) fn endpoint(&self) -> &NativeEndpoint {
        &self.0.endpoint
    }
    pub(crate) fn options(&self) -> Vec<OsString> {
        master_options(&self.0)
    }
    /// Optional process-lifetime metadata; old account records remain usable.
    pub(crate) fn peer(&self) -> Result<super::super::forward::ssh::Peer> {
        read_peer(&self.0)
    }
}

fn peer_path(record: &Record) -> std::path::PathBuf {
    record.control.with_extension("peer.json")
}

fn read_peer(record: &Record) -> Result<super::super::forward::ssh::Peer> {
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(peer_path(record))
        .context("approved account has no pinned peer metadata; reconnect with syq persist connect ENDPOINT --auth-from @NAME")?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= 128 * 1024,
        "approved SSH peer metadata must be a bounded owner-only file"
    );
    let peer: super::super::forward::ssh::Peer = serde_json::from_reader(file)?;
    peer.validate_endpoint(&record.endpoint)?;
    Ok(peer)
}

pub(crate) fn cached(
    domain: &Domain,
    authorizer: &str,
    requested: &NativeEndpoint,
) -> Result<Option<Cached>> {
    if existing_directory(domain)?.is_none() {
        return Ok(None);
    }
    let Some(record) = read_record(&index_path(domain, authorizer, requested)?)? else {
        return Ok(None);
    };
    if record.authorizer != Provider::Return(authorizer.to_owned())
        || record.requested != *requested
    {
        bail!("SSH authority record does not match the requested login");
    }
    active_record(domain, record)
}

fn selected_index_path(
    domain: &Domain,
    authorizer: &Provider,
    requested: &NativeEndpoint,
    selected: &resolution::Selection,
) -> Result<PathBuf> {
    let local = selected
        .local
        .as_ref()
        .context("SSH account selection lacks requester configuration")?;
    let identity = serde_json::to_vec(&(
        "local-account-v1",
        authorizer,
        requested,
        &selected.provider,
        &selected.policy,
        &local.config_digest,
    ))?;
    Ok(domain
        .approved_index_path()
        .join(format!("{}.json", blake3::hash(&identity).to_hex())))
}

fn cached_selected(
    domain: &Domain,
    authorizer: &Provider,
    requested: &NativeEndpoint,
    selected: &resolution::Selection,
) -> Result<Option<Cached>> {
    if existing_directory(domain)?.is_none() {
        return Ok(None);
    }
    // Old records have no provider binding. They remain readable for status,
    // shutdown and explicit export, but commands require newly bound authority.
    let path = selected_index_path(domain, authorizer, requested, selected)?;
    let Some(record) = read_record(&path)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        record.authorizer == *authorizer && record.requested == *requested,
        "SSH authority record does not match the requested login"
    );
    if record.endpoint != selected.policy.endpoint || !record.control.exists() {
        return Ok(None);
    }
    validate_record(domain, &record)?;
    let peer = read_peer(&record)?;
    anyhow::ensure!(
        crate::destination::ssh_auth::ResolvedPolicy::from_peer(&peer)? == selected.policy,
        "SSH authority peer policy does not match the selected provider"
    );
    active_record(domain, record)
}

fn lookup_request(authorizer: &Provider, requested: &NativeEndpoint) -> SessionRequest {
    SessionRequest {
        provider: authorizer.clone(),
        destination: requested.clone(),
        tty: Tty::Disabled,
        command: Vec::new(),
    }
}

fn active_record(domain: &Domain, record: Record) -> Result<Option<Cached>> {
    // A crashed keeper can leave an expired index. Never reconnect through it.
    if !record.control.exists() {
        return Ok(None);
    }
    validate_record(domain, &record)?;
    // Older v1 records have no sidecar and retain their original keeper rules.
    match read_generation(&record.control.with_extension("generation"))? {
        Some(generation) if !generation_open(domain, &generation)? => return Ok(None),
        None if !domain.is_default() => return Ok(None),
        _ => {}
    }
    if record
        .control
        .parent()
        .unwrap()
        .join(crate::receive_service::CLOSING)
        .exists()
    {
        return Ok(None);
    }
    // Authority was checked above. The actual SSH command remains mux-only;
    // a dead or replaced master cannot trigger authentication or a retry.
    // When the OS reports busy distinctly from refused, do not replace the login.
    if !crate::persistence::socket_is_ready(&record.control)
        .context("approved SSH master is temporarily unavailable; retry the command")?
    {
        return Ok(None);
    }
    Ok(Some(Cached(record, None)))
}

/// Look up only the account authority selected by command policy. Native
/// auto/ssh never inspect account records or probe an incidental live master.
pub(crate) fn select_cached(
    domain: &Domain,
    requested: &NativeEndpoint,
    mode: &AuthFrom,
) -> Result<Option<Cached>> {
    match mode {
        AuthFrom::Provider(authorizer) => {
            let request = lookup_request(authorizer, requested);
            let Some(selected) = resolution::cached(domain, &request)? else {
                return Ok(None);
            };
            cached_selected(domain, authorizer, requested, &selected)
        }
        AuthFrom::Auto | AuthFrom::Ssh => Ok(None),
    }
}

/// An explicit ssh-config snapshot may discover a unique existing approval.
/// This lookup never chooses the account used by an ordinary command.
pub(crate) fn select_export(
    domain: &Domain,
    requested: &NativeEndpoint,
    mode: &AuthFrom,
) -> Result<Option<Cached>> {
    match mode {
        AuthFrom::Provider(authorizer) => return export_selected(domain, authorizer, requested),
        AuthFrom::Ssh => return Ok(None),
        AuthFrom::Auto => {}
    }
    let mut matches = match export_matches(domain, requested) {
        Ok(matches) => matches,
        Err(error) => {
            // This is optional cached authority. Discard the entire scan on
            // failure rather than selecting an incompletely checked result.
            crate::output::diagnostic!("syq: warning: cannot inspect approved SSH connections ({error:#}); continuing without account connection reuse");
            return Ok(None);
        }
    };
    anyhow::ensure!(matches.len() <= 1,
        "more than one authorization provider has approved this SSH endpoint; select one with --auth-from PROVIDER or syq persist auth-from PROVIDER --for {}",
        requested.host);
    Ok(matches.pop())
}

/// Actual operations may establish explicitly selected account authority.
/// Completion and config export use lookup-only entrypoints and never prompt.
pub(crate) fn select_or_connect(
    domain: &Domain,
    requested: &NativeEndpoint,
    mode: &AuthFrom,
) -> Result<Option<Cached>> {
    super::super::handoff::validate_account_selection(mode)?;
    let AuthFrom::Provider(authorizer) = mode else {
        return Ok(None);
    };
    let request = lookup_request(authorizer, requested);
    super::super::ssh_auth::prepare(&request)?;
    // Resolve all account and route choices locally before consulting any
    // cached provider policy or connection, including every ProxyJump hop.
    let local = LocalPlan::resolve(requested)?;
    connect_local(domain, authorizer, local).map(Some)
}

fn connect_local(domain: &Domain, authorizer: &Provider, local: LocalPlan) -> Result<Cached> {
    let request = lookup_request(authorizer, &local.requested);
    let proxy = if let Some(hop) = &local.hop {
        let cached = connect_local(domain, authorizer, (**hop).clone())?;
        let mut args = vec!["ssh".to_owned()];
        for option in cached.options() {
            args.push(
                option
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("ProxyJump socket path is not UTF-8"))?,
            );
        }
        // OpenSSH transports bytes through the separately approved jump
        // account; it never lends the destination's agent to a proxy process.
        args.extend([
            "-o".into(),
            "RemoteCommand=none".into(),
            "-T".into(),
            "-W".into(),
            format!("[{}]:{}", local.endpoint.host, local.endpoint.port.unwrap()),
        ]);
        args.extend(
            super::ssh_arguments(Tty::Disabled, &[], cached.endpoint())?
                .into_iter()
                .map(|arg| {
                    arg.into_string()
                        .map_err(|_| anyhow::anyhow!("invalid ProxyJump argument"))
                })
                .collect::<Result<Vec<_>>>()?,
        );
        // The outer SSH expands ProxyCommand tokens once before executing it;
        // preserve escaped tokens intended for the strict inner SSH command.
        Some(shell_words::join(args).replace('%', "%%"))
    } else {
        None
    };
    let plan = resolution::select(domain, &request, local, proxy)?;
    let selected = plan.selected.clone();
    let generation = plan.generation.clone();
    let proxy = plan.proxy.clone();
    if let Some(cached) = cached_selected(domain, authorizer, &request.destination, &selected)? {
        return cached.with_workers(domain, request, &selected, generation, proxy);
    }
    if let Err(error) = start(domain, request.clone(), plan) {
        if let Err(invalidation) = resolution::invalidate(domain, &request, &selected) {
            crate::output::diagnostic!("syq: warning: cannot clear failed SSH policy metadata ({invalidation:#}); retry after removing the stale cache");
        }
        return Err(error);
    }
    cached_selected(domain, authorizer, &request.destination, &selected)?
        .context("approved SSH account connection ended before use")?
        .with_workers(domain, request, &selected, generation, proxy)
}

fn export_selected(
    domain: &Domain,
    authorizer: &Provider,
    requested: &NativeEndpoint,
) -> Result<Option<Cached>> {
    if let Some(selected) = resolution::cached(domain, &lookup_request(authorizer, requested))? {
        return cached_selected(domain, authorizer, requested, &selected);
    }
    // An explicit snapshot can still export one legacy typed-endpoint record.
    // It never guesses between historical policy-keyed records or authorizes.
    match authorizer.receiving_name() {
        Some(name) => cached(domain, name, requested),
        None => Ok(None),
    }
}

fn export_matches(domain: &Domain, requested: &NativeEndpoint) -> Result<Vec<Cached>> {
    let index = domain.approved_index_path();
    let mut matches = Vec::new();
    if !index.exists() {
        return Ok(matches);
    }
    // Validate the existing directory before looking at any of its records.
    let Some(index) = existing_directory(domain)? else {
        return Ok(matches);
    };
    let mut authorizers = std::collections::BTreeMap::new();
    for entry in fs::read_dir(index)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let Some(record) = read_record(&path)? else {
            continue;
        };
        if record.requested == *requested {
            authorizers.insert(
                serde_json::to_string(&record.authorizer)?,
                record.authorizer,
            );
        }
    }
    for authorizer in authorizers.into_values() {
        if let Some(cached) = export_selected(domain, &authorizer, requested)? {
            matches.push(cached);
        }
    }
    Ok(matches)
}

#[derive(Serialize)]
pub(crate) struct Status {
    authorizer: Provider,
    requested: NativeEndpoint,
    endpoint: NativeEndpoint,
    control: PathBuf,
    connected: bool,
}
#[derive(Default)]
pub(crate) struct StatusSnapshot {
    pub rows: Vec<Status>,
    pub errors: Vec<String>,
}
pub(crate) fn status(domain: &Domain) -> Result<StatusSnapshot> {
    if !domain.approved_index_path().exists() {
        return Ok(StatusSnapshot::default());
    }
    let Some(directory) = existing_directory(domain)? else {
        return Ok(StatusSnapshot::default());
    };
    let mut snapshot = StatusSnapshot::default();
    for entry in fs::read_dir(&directory)? {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => {
                snapshot.errors.push(format!(
                    "read SSH account index {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let result = (|| -> Result<Option<Status>> {
            let Some(record) = read_record(&path)? else {
                return Ok(None);
            };
            if !record.control.exists() {
                return Ok(None);
            }
            validate_record(domain, &record)?;
            let connected = live(&record);
            Ok(Some(Status {
                authorizer: record.authorizer,
                requested: record.requested,
                endpoint: record.endpoint,
                control: record.control,
                connected,
            }))
        })();
        match result {
            Ok(Some(row)) => snapshot.rows.push(row),
            Ok(None) => {}
            Err(error) => snapshot
                .errors
                .push(format!("SSH account record {}: {error:#}", path.display())),
        }
    }
    snapshot
        .rows
        .sort_by_cached_key(|row| (row.authorizer.label(), row.requested.host.clone()));
    snapshot.errors.sort();
    Ok(snapshot)
}

pub(crate) fn print_status(rows: &[Status]) {
    for row in rows {
        crate::output::human_stdout!(
            "  {} through {}  {} (reusable account access)\n    SSH control socket: {}",
            row.requested.host,
            row.authorizer,
            if row.connected { "ready" } else { "inactive" },
            row.control.display()
        );
    }
}
pub(crate) fn stop_all(domain: &Domain) -> Result<()> {
    let index = domain.approved_index_path();
    if !index.exists() {
        return Ok(());
    }
    let Some(index) = existing_directory(domain)? else {
        return Ok(());
    };
    let mut errors = Vec::new();
    // Invalidates both live keepers and approval requests that have not yet
    // published a control socket. A later operation gets a fresh generation.
    if let Err(error) = fs::remove_file(index.join(GENERATION)) {
        if error.kind() != std::io::ErrorKind::NotFound {
            errors.push(format!("cancel SSH account generation: {error}"));
        }
    }
    let mut controls = Vec::new();
    for entry in fs::read_dir(index)? {
        let result: Result<()> = (|| {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                return Ok(());
            }
            let Some(record) = read_record(&path)? else {
                return Ok(());
            };
            // Generation cancellation may already have made the keeper remove
            // this socket and scope while off was inspecting its index record.
            if !mark_closing(domain, &record)? {
                return Ok(());
            }
            controls.push(record.control.clone());
            close_master(&record)?;
            Ok(())
        })();
        if let Err(error) = result {
            errors.push(format!("{error:#}"));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut progress = Instant::now();
    loop {
        let remaining = controls.iter().filter(|control| control.exists()).count();
        if remaining == 0 {
            break;
        }
        if Instant::now() >= deadline {
            errors.push(format!(
                "{remaining} approved SSH connections did not close within 5 seconds"
            ));
            break;
        }
        if progress.elapsed() >= Duration::from_secs(1) {
            crate::output::diagnostic!(
                "syq: waiting for {remaining} approved SSH connections to close"
            );
            progress = Instant::now();
        }
        std::thread::sleep(POLL);
    }
    if let Err(error) = resolution::wait(domain) {
        errors.push(format!("{error:#}"));
    }
    if !domain.is_default() {
        if let Err(error) = cleanup::wait_for_keepers(domain) {
            errors.push(format!("{error:#}"));
        }
    }
    anyhow::ensure!(
        errors.is_empty(),
        "could not close every approved SSH account connection: {}",
        errors.join("; ")
    );
    Ok(())
}

fn mark_closing(domain: &Domain, record: &Record) -> Result<bool> {
    let result: Result<()> = (|| {
        validate_record(domain, record)?;
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(
                record
                    .control
                    .parent()
                    .unwrap()
                    .join(crate::receive_service::CLOSING),
            )?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(true),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                && record
                    .control
                    .symlink_metadata()
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn live(record: &Record) -> bool {
    master_command(record)
        .args(["-O", "check", "--", &record.endpoint.host])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status_guarded()
        .is_ok_and(|status| status.success())
}

pub(super) fn command(
    domain: &Domain,
    request: &super::Invocation,
    mode: &AuthFrom,
) -> Result<Option<Command>> {
    let Some(cached) = select_or_connect(domain, &request.destination, mode)? else {
        return Ok(None);
    };
    let mut command = Command::new("ssh");
    let mut options = cached.options().into_iter();
    while let Some(option) = options.next() {
        if option == "-F" {
            options.next();
            continue;
        }
        command.arg(option);
    }
    command.args(["-o", &format!("HostName={}", cached.endpoint().host)]);
    let mut endpoint = cached.endpoint().clone();
    endpoint.host = request.destination.host.clone();
    command.args(request.ssh_arguments(&endpoint)?);
    Ok(Some(command))
}

struct Starting(Option<Child>);
impl Drop for Starting {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
        }
    }
}

pub(crate) fn connect(domain: &Domain, request: SessionRequest) -> Result<()> {
    let authorizer = request.provider.clone();
    let cached = select_or_connect(
        domain,
        &request.destination,
        &AuthFrom::Provider(authorizer.clone()),
    )?
    .context("SSH account connection missing after approval")?;
    crate::output::human_stdout!(
        "{} ready through {}; account access remains available while the provider is connected\nSSH control socket: {}",
        cached.endpoint().host, authorizer, cached.control().display()
    );
    Ok(())
}

pub(crate) fn protect_keeper_inheritance(command: &mut Command) -> Result<()> {
    #[cfg(target_os = "linux")]
    let directory = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    let directory = "/dev/fd";
    let descriptors = fs::read_dir(directory)?
        .map(|entry| {
            Ok(entry?
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok()))
        })
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .filter(|fd| *fd > 2)
        .collect::<Vec<_>>();
    use std::os::unix::process::CommandExt as _;
    // SAFETY: fcntl is async-signal-safe. The descriptor list is prepared before
    // fork; changing flags in the child leaves caller-owned pipes untouched.
    // Rust has already duplicated the startup socket onto fd 0/1 at this point.
    unsafe {
        command.pre_exec(move || {
            for fd in &descriptors {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EBADF) {
                        continue;
                    }
                    return Err(error);
                }
                if libc::fcntl(*fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

fn start(domain: &Domain, request: SessionRequest, plan: resolution::Plan) -> Result<()> {
    anyhow::ensure!(
        generation_open(domain, &plan.generation)?,
        "SSH account setup was cancelled"
    );
    let startup = Startup {
        command: crate::approval_command::current()?,
        authorizer: request.provider,
        requested: request.destination,
        generation: plan.generation,
        selected: Some(plan.selected),
        proxy: plan.proxy,
        scope: domain.explicit_path().map(Path::to_path_buf),
        scope_identity: if domain.is_default() {
            None
        } else {
            Some(domain.identity()?)
        },
    };
    let signals = foreground::Signals::new()?;
    let (mut parent, child) = crate::process::with_inheritance_guard(UnixStream::pair)?;
    let mut process = Command::new(std::env::current_exe()?);
    use std::os::unix::process::CommandExt as _;
    process
        .arg(INTERNAL)
        .process_group(0)
        .stdin(Stdio::from(File::from(OwnedFd::from(child.try_clone()?))))
        .stdout(Stdio::from(File::from(OwnedFd::from(child))))
        .stderr(Stdio::null());
    protect_keeper_inheritance(&mut process)?;
    let mut process = Starting(Some(process.spawn_guarded()?));
    super::super::write_message(&mut parent, &startup)?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let result: Result<std::result::Result<String, String>> =
            super::super::read_message(&mut parent);
        let _ = sender.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(360);
    let mut progress = Instant::now();
    let result = loop {
        match receiver.recv_timeout(POLL) {
            Ok(result) => break result,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break Err(anyhow::anyhow!(
                    "SSH connection setup ended without readiness"
                ))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if signals.received.load(Ordering::Acquire) != 0 {
            break Err(anyhow::anyhow!("SSH connection setup interrupted"));
        }
        if Instant::now() >= deadline {
            break Err(anyhow::anyhow!(
                "SSH connection setup exceeded its approval/start deadline"
            ));
        }
        if progress.elapsed() >= Duration::from_secs(5) {
            crate::output::diagnostic!(
                "syq: waiting for account approval and SSH connection readiness"
            );
            progress = Instant::now();
        }
    };
    if result.as_ref().is_ok_and(|reply| reply.is_ok()) {
        let mut child = process.0.take().unwrap();
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    drop(process);
    let _ = reader.join();
    result?.map_err(anyhow::Error::msg)?;
    Ok(())
}

struct Index(PathBuf);
impl Drop for Index {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn keeper(startup: Startup) -> Result<()> {
    let domain = Domain::select(startup.scope.as_deref())?;
    anyhow::ensure!(
        domain.is_default() == startup.scope_identity.is_none(),
        "SSH account startup is missing its persistence scope identity"
    );
    let request = SessionRequest {
        provider: startup.authorizer.clone(),
        destination: startup.requested.clone(),
        tty: Tty::Disabled,
        command: Vec::new(),
    };
    super::validate_endpoint(&request.destination)?;
    if !startup_open(&domain, &startup)? {
        bail!("SSH account setup was cancelled before startup");
    }
    let selected = startup
        .selected
        .as_ref()
        .context("SSH account startup lacks a resolved policy; retry the command")?;
    selected.policy.validate()?;
    let local = selected
        .local
        .as_ref()
        .context("SSH account startup lacks requester configuration")?
        .clone();
    local.validate()?;
    anyhow::ensure!(
        local.requested == request.destination && local.endpoint == selected.policy.endpoint,
        "SSH account startup changed the selected requester endpoint"
    );
    anyhow::ensure!(
        super::super::ssh_auth::local_binding(&domain, &request.provider)?.as_deref()
            == Some(selected.provider.as_str()),
        "SSH provider connection changed before account setup; retry the command"
    );
    let path = selected_index_path(&domain, &request.provider, &request.destination, selected)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path.with_extension("lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("SSH authority lock must be an owner-only file");
    }
    let signals = foreground::Signals::new()?;
    let deadline = Instant::now() + Duration::from_secs(330);
    loop {
        if !startup_open(&domain, &startup)? || signals.received.load(Ordering::Acquire) != 0 {
            bail!("SSH account setup cancelled while waiting for another request");
        }
        if let Some(cached) =
            cached_selected(&domain, &request.provider, &request.destination, selected)?
        {
            return super::super::write_message(
                &mut std::io::stdout(),
                &Ok::<_, String>(cached.endpoint().host.clone()),
            );
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error.into());
        }
        if Instant::now() >= deadline {
            bail!("another SSH account request did not become ready within 330 seconds");
        }
        signals.wait(POLL)?;
    }
    let approval_request = request.clone();
    let approval_domain = domain.clone();
    let shown_command = startup.command.clone();
    let selected = selected.clone();
    let approval_local = local.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    // The keeper is a dedicated child process. If setup is cancelled, it exits
    // and closes the pending return request even while approval is blocked.
    std::thread::Builder::new()
        .name("syq-ssh-approve".into())
        .spawn(move || {
            let _ = sender.send(super::super::ssh_auth::authorize_expected(
                &approval_domain,
                &approval_request,
                shown_command,
                &selected.provider,
                &selected.policy,
                &approval_local,
            ));
        })?;
    let approval_deadline = Instant::now() + Duration::from_secs(330);
    let session = loop {
        if signals.received.load(Ordering::Acquire) != 0 || !startup_open(&domain, &startup)? {
            bail!("persistent SSH setup cancelled before approval");
        }
        match receiver.recv_timeout(POLL) {
            Ok(result) => break result?,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("persistent SSH authorization ended without a result")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if Instant::now() >= approval_deadline {
            bail!("persistent SSH authorization exceeded its deadline");
        }
    };
    let options = session.options();
    // Keep released endpoint records byte-compatible and separate from native masters.
    let scope = tempfile::Builder::new()
        .prefix("approved-")
        .tempdir_in(ensure_master_parent(&domain)?)?;
    crate::persistence::initialize_scope(scope.path())?;
    let endpoint = session.endpoint();
    let control = crate::persistence::prepare_endpoint(
        scope.path(),
        endpoint.user.as_deref(),
        &endpoint.host,
        endpoint.port,
        None,
    )?;
    let mut master = Command::new("ssh");
    master
        .args(local.options())
        .args(local.route_options(startup.proxy.as_deref())?);
    let mut iter = options.iter();
    while let Some(option) = iter.next() {
        if option == "-o" {
            let value = iter.next().context("incomplete SSH option")?;
            if value == "ControlMaster=no" || value == "ControlPath=none" {
                continue;
            }
            master.arg(option).arg(value);
        } else {
            master.arg(option);
        }
    }
    let persist = if domain.is_default() {
        "ControlPersist=no"
    } else {
        "ControlPersist=300"
    };
    master
        .args(["-M", "-N", "-S"])
        .arg(crate::persistence::openssh_control_path(&control))
        .args(["-o", persist]);
    for option in MASTER_SESSION_OPTIONS {
        master.args(["-o", *option]);
    }
    master
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    master.args(["--", &local.requested.host]);
    let record = Record {
        version: provider_state_version(&request.provider),
        authorizer: request.provider,
        requested: request.destination,
        endpoint: endpoint.clone(),
        control,
    };
    // Default account masters keep their existing foreground PTY ownership.
    // Scoped masters use OpenSSH's native active-channel-aware idle timer;
    // ControlPersist forks after authentication, so cleanup uses its socket.
    let _lifetime = if domain.is_default() {
        Some(super::master_lifetime::attach(&mut master)?)
    } else {
        None
    };
    let mut daemon = (!domain.is_default()).then(|| DaemonMaster {
        record: &record,
        active: true,
    });
    let mut master = foreground::ForegroundChild::spawn(&mut master, &signals)?;
    // Declared after the child so early returns stop prepared helpers before
    // dropping the foreground master (or the daemon guard below it).
    let mut pool = KeeperPool::new(&record.control);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if signals.received.load(Ordering::Acquire) != 0
            || session.cancelled()
            || !startup_open(&domain, &startup)?
        {
            bail!("persistent SSH authorization ended during connection setup");
        }
        if let Some(status) = master.poll()? {
            if domain.is_default() || !status.success() {
                bail!("persistent SSH client exited before readiness ({status})");
            }
        }
        if record.control.exists() && live(&record) {
            break;
        }
        if Instant::now() >= deadline {
            bail!("persistent SSH client did not become ready within 30 seconds");
        }
        signals.wait(POLL)?;
    }
    // Keep the unchanged v1 index readable by older helpers. The optional peer
    // policy lives only with this master, in its owner-only temporary scope.
    let mut peer_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(peer_path(&record))?;
    serde_json::to_writer(&mut peer_file, session.peer())?;
    peer_file.write_all(b"\n")?;
    let mut generation_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(record.control.with_extension("generation"))?;
    generation_file.write_all(startup.generation.as_bytes())?;
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    serde_json::to_writer(&mut temporary, &record)?;
    temporary.write_all(b"\n")?;
    temporary.persist(&path)?;
    let _index = Index(path);
    super::super::write_message(
        &mut std::io::stdout(),
        &Ok::<_, String>(format!(
            "{}@{}:{}; SSH control socket: {}",
            endpoint.user.as_deref().unwrap_or(""),
            endpoint.host,
            endpoint.port.unwrap_or(22),
            record.control.display()
        )),
    )?;
    // Close the startup channel without keeping the original caller's pipe alive.
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
            return Err(std::io::Error::last_os_error())
                .context("detach persistent SSH startup channel");
        }
    }
    loop {
        if domain.is_default() {
            if master.poll()?.is_some() {
                break;
            }
        } else {
            if let Some(status) = master.poll()? {
                anyhow::ensure!(
                    status.success(),
                    "persistent SSH launcher exited ({status})"
                );
            }
            // Polling with -O check would itself create mux channels and reset
            // OpenSSH's idle timer. Normal exit unlinks the control socket.
            if !record.control.exists() {
                break;
            }
        }
        if signals.received.load(Ordering::Acquire) != 0
            || session.cancelled()
            || !startup_open(&domain, &startup)?
            || scope.path().join(crate::receive_service::CLOSING).exists()
        {
            break;
        }
        signals.wait(POLL)?;
    }
    let pool_result = pool.stop();
    let master_result = master.stop(libc::SIGTERM);
    let daemon_result = daemon.as_mut().map_or(Ok(()), DaemonMaster::stop);
    // A broken pool must not leave an approved login alive.
    master_result?;
    daemon_result?;
    pool_result
}

struct KeeperPool<'a> {
    control: &'a Path,
    active: bool,
}
impl<'a> KeeperPool<'a> {
    fn new(control: &'a Path) -> Self {
        Self {
            control,
            active: true,
        }
    }

    fn stop(&mut self) -> Result<()> {
        if std::mem::take(&mut self.active) {
            cleanup::stop_pool(self.control)?;
        }
        Ok(())
    }
}
impl Drop for KeeperPool<'_> {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// An explicit-domain master daemonizes so OpenSSH can count idle channels.
/// Graceful keeper exit closes it; a killed keeper has the same native idle
/// expiry as other explicit-domain SSH masters.
struct DaemonMaster<'a> {
    record: &'a Record,
    active: bool,
}
impl DaemonMaster<'_> {
    fn stop(&mut self) -> Result<()> {
        if self.active {
            close_master(self.record)?;
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for DaemonMaster<'_> {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn close_master(record: &Record) -> Result<()> {
    let pool_result = cleanup::stop_pool(&record.control);
    let master_result = retire_master(record);
    // Evaluate both before returning either error: pool failure cannot retain
    // the account connection, and a missing master may still have a stale pool.
    master_result.and(pool_result)
}

fn retire_master(record: &Record) -> Result<()> {
    if !record.control.exists() {
        return Ok(());
    }
    use std::os::unix::fs::FileTypeExt as _;
    let metadata = match record.control.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
        "SSH account control path is not an owned socket"
    );
    let mut child = master_command(record)
        .args(["-O", "exit", "--", &record.endpoint.host])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn_guarded()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() && record.control.exists() {
                anyhow::ensure!(
                    !live(record),
                    "SSH account connection {} refused shutdown ({status})",
                    record.endpoint.host
                );
                match fs::remove_file(&record.control) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "SSH account connection {} shutdown timed out",
                record.endpoint.host
            );
        }
        std::thread::sleep(POLL);
    }
    while record.control.exists() {
        if Instant::now() >= deadline {
            bail!(
                "SSH account connection {} did not close within 5 seconds",
                record.endpoint.host
            );
        }
        std::thread::sleep(POLL);
    }
    Ok(())
}

pub(crate) fn dispatch(argv: &[OsString]) -> Option<Result<i32>> {
    if argv.len() == 2
        && (argv[1] == "--account-ssh-probe" || argv[1] == "--requester-ssh-policy-probe")
    {
        return Some(Ok(0));
    }
    if argv.len() != 2 || argv[1] != INTERNAL {
        return None;
    }
    Some((|| {
        let result = super::super::read_message(&mut std::io::stdin()).and_then(keeper);
        if let Err(error) = result {
            let _ = super::super::write_message(
                &mut std::io::stdout(),
                &Err::<String, _>(format!("{error:#}")),
            );
            return Err(error);
        }
        Ok(0)
    })())
}

#[cfg(test)]
mod scope_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn owned_master_disables_configured_forking() {
        let root = crate::test_support::tempdir().unwrap();
        let config = root.path().join("config");
        fs::write(
            &config,
            "Host *\n ForkAfterAuthentication yes\n RequestTTY force\n",
        )
        .unwrap();
        let mut command = Command::new("ssh");
        command.args(["-G", "-MN", "-F"]).arg(config);
        for option in MASTER_SESSION_OPTIONS {
            command.args(["-o", *option]);
        }
        let output = command.arg("host.invalid").capture_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let config = String::from_utf8(output.stdout).unwrap();
        assert!(
            config
                .lines()
                .any(|line| line == "forkafterauthentication no"),
            "{config}"
        );
        assert!(
            config.lines().any(|line| line == "requesttty false"),
            "{config}"
        );
    }

    #[test]
    fn native_selection_does_not_require_readable_account_records() {
        let root = tempfile::tempdir_in(fs::canonicalize("/tmp").unwrap()).unwrap();
        let scope = root.path().join("scope");
        crate::persistence::initialize_scope(&scope).unwrap();
        let domain = Domain::select(Some(&scope)).unwrap();
        let requested = NativeEndpoint {
            user: None,
            host: "unused.invalid".into(),
            port: None,
        };
        let index = domain.approved_index_path();
        fs::create_dir(&index).unwrap();
        fs::set_permissions(&index, fs::Permissions::from_mode(0o700)).unwrap();
        let path = index_path(&domain, "laptop", &requested).unwrap();
        fs::write(&path, b"{").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for unreadable in [false, true] {
            if unreadable {
                fs::set_permissions(&index, fs::Permissions::from_mode(0o0)).unwrap();
            }
            // Native selection needs no provider record or SSH process. The
            // legacy authority reader still reports corrupt/unreadable state.
            for mode in [AuthFrom::Auto, AuthFrom::Ssh] {
                assert!(select_cached(&domain, &requested, &mode).unwrap().is_none());
                assert!(select_or_connect(&domain, &requested, &mode)
                    .unwrap()
                    .is_none());
            }
            assert!(cached(&domain, "laptop", &requested).is_err());
        }
        fs::set_permissions(&index, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn policy_bound_indices_keep_old_authority_separate() {
        let root = tempfile::tempdir_in(fs::canonicalize("/tmp").unwrap()).unwrap();
        let scope = root.path().join("scope");
        crate::persistence::initialize_scope(&scope).unwrap();
        let domain = Domain::select(Some(&scope)).unwrap();
        directory(&domain).unwrap();
        let requested = NativeEndpoint {
            user: None,
            host: "alias".into(),
            port: None,
        };
        let key = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]).into(),
            "",
        )
        .unwrap();
        let selected = resolution::Selection {
            provider: "a".repeat(64),
            local: Some(LocalPlan {
                requested: requested.clone(),
                endpoint: NativeEndpoint {
                    user: Some("user".into()),
                    host: "resolved.invalid".into(),
                    port: Some(22),
                },
                host_key_alias: None,
                config_digest: "b".repeat(64),
                route: super::super::local_config::Route::Direct,
                host_key_algorithms: "ssh-ed25519".into(),
                hop: None,
            }),
            policy: crate::destination::ssh_auth::ResolvedPolicy::new(
                NativeEndpoint {
                    user: Some("user".into()),
                    host: "resolved.invalid".into(),
                    port: Some(22),
                },
                &format!(
                    "syq-approved-peer {}\n",
                    key.public_key().to_openssh().unwrap()
                ),
                "ssh-ed25519",
            )
            .unwrap(),
        };
        let first = selected_index_path(
            &domain,
            &Provider::Return("laptop".into()),
            &requested,
            &selected,
        )
        .unwrap();
        let mut changed = selected.clone();
        changed.policy.endpoint.host = "other.invalid".into();
        assert_ne!(
            first,
            selected_index_path(
                &domain,
                &Provider::Return("laptop".into()),
                &requested,
                &changed
            )
            .unwrap()
        );
        changed = selected.clone();
        changed.provider = "b".repeat(64);
        assert_ne!(
            first,
            selected_index_path(
                &domain,
                &Provider::Return("laptop".into()),
                &requested,
                &changed
            )
            .unwrap()
        );
        let old = Record {
            version: 1,
            authorizer: Provider::Return("laptop".into()),
            requested: requested.clone(),
            endpoint: selected.policy.endpoint.clone(),
            control: scope.join("old-control"),
        };
        let legacy = index_path(&domain, "laptop", &requested).unwrap();
        fs::write(&legacy, serde_json::to_vec(&old).unwrap()).unwrap();
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o600)).unwrap();
        // Even identical resolved accounts cannot establish the provider binding
        // of an old record. Do not probe/reuse its control socket for commands.
        assert!(cached_selected(
            &domain,
            &Provider::Return("laptop".into()),
            &requested,
            &selected
        )
        .unwrap()
        .is_none());
        assert!(read_record(&legacy).unwrap().is_some());
        assert!(!first.exists());
    }

    #[test]
    fn keeper_does_not_inherit_caller_payload_descriptors() {
        use std::os::fd::FromRawFd;
        let root = crate::test_support::tempdir().unwrap();
        let file = File::create(root.path().join("caller-output")).unwrap();
        // F_DUPFD deliberately creates a caller-style inheritable descriptor.
        let descriptor = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 100) };
        assert!(descriptor >= 100);
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        let mut command = Command::new("sh");
        command.args([
            "-c",
            &format!("test ! -e /dev/fd/{}", descriptor.as_raw_fd()),
        ]);
        protect_keeper_inheritance(&mut command).unwrap();
        assert!(command.status_guarded().unwrap().success());
        assert_eq!(
            unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }

    #[test]
    fn account_generation_is_shared_until_off_and_never_resurrects_old_sessions() {
        let root = crate::test_support::tempdir().unwrap();
        let first = ensure_generation_at(root.path()).unwrap();
        assert_eq!(ensure_generation_at(root.path()).unwrap(), first);
        let path = root.path().join(GENERATION);
        fs::remove_file(&path).unwrap();
        assert!(read_generation(&path).unwrap().is_none());
        let second = ensure_generation_at(root.path()).unwrap();
        assert_ne!(second, first);
        assert_eq!(
            read_generation(&path).unwrap().as_deref(),
            Some(second.as_str())
        );
        // Generation state is temporary, independent of a global persistence
        // configuration file or an ordinary receiving scope.
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_account_starts_use_the_same_generation() {
        let root = crate::test_support::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|threads| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    threads.spawn(|| {
                        barrier.wait();
                        ensure_generation_at(root.path()).unwrap()
                    })
                })
                .collect();
            let generations: Vec<_> = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();
            assert!(generations.iter().all(|value| *value == generations[0]));
        });
    }

    #[test]
    fn account_generation_rejects_symlinks_public_files_and_unbounded_contents() {
        let root = crate::test_support::tempdir().unwrap();
        ensure_generation_at(root.path()).unwrap();
        let path = root.path().join(GENERATION);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_generation(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, vec![b'a'; 65]).unwrap();
        assert!(read_generation(&path).is_err());
        let saved = root.path().join("saved");
        fs::rename(&path, &saved).unwrap();
        std::os::unix::fs::symlink(&saved, &path).unwrap();
        assert!(ensure_generation_at(root.path()).is_err());
    }

    #[test]
    fn authority_index_rejects_links_public_files_and_unknown_versions() {
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("record");
        let record = Record {
            version: 1,
            authorizer: Provider::Return("laptop".into()),
            requested: NativeEndpoint {
                user: None,
                host: "alias".into(),
                port: None,
            },
            endpoint: NativeEndpoint {
                user: Some("user".into()),
                host: "server".into(),
                port: Some(22),
            },
            control: root.path().join("socket"),
        };
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_record(&path).unwrap().unwrap().requested.host, "alias");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_record(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_record(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &path,
            serde_json::to_vec(&Record {
                version: 2,
                ..record
            })
            .unwrap(),
        )
        .unwrap();
        assert!(read_record(&path).is_err());
        assert!(read_record(&root.path().join("missing")).unwrap().is_none());
    }

    #[test]
    fn native_provider_records_are_versioned_and_not_return_names() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct OldRecord {
            version: u16,
            authorizer: String,
            requested: NativeEndpoint,
            endpoint: NativeEndpoint,
            control: PathBuf,
        }
        let old = r#"{"version":1,"authorizer":"laptop","requested":{"user":null,"host":"alias","port":null},"endpoint":{"user":"user","host":"server","port":22},"control":"/tmp/old/socket"}"#;
        let mut record: Record = serde_json::from_str(old).unwrap();
        assert_eq!(serde_json::to_string(&record).unwrap(), old);
        serde_json::from_str::<OldRecord>(old).unwrap();
        record.authorizer = Provider::parse("helper@provider.example:2222").unwrap();
        record.version = provider_state_version(&record.authorizer);
        let encoded = serde_json::to_vec(&record).unwrap();
        assert!(serde_json::from_slice::<OldRecord>(&encoded).is_err());
        let root = crate::test_support::tempdir().unwrap();
        let path = root.path().join("record");
        fs::write(&path, &encoded).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_record(&path).unwrap().unwrap().authorizer,
            record.authorizer
        );
        record.version = 1;
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(read_record(&path).is_err());
    }

    #[test]
    fn peer_sidecar_preserves_old_account_records_and_requires_exact_endpoint() {
        // Unchanged v1 shape: an old reader also rejects unknown Record fields.
        let old = r#"{"version":1,"authorizer":"laptop","requested":{"user":null,"host":"alias","port":null},"endpoint":{"user":"user","host":"server","port":22},"control":"/tmp/old/socket"}"#;
        let mut record: Record = serde_json::from_str(old).unwrap();
        assert_eq!(serde_json::to_string(&record).unwrap(), old);
        assert!(master_options(&record)
            .iter()
            .any(|word| word == "ForwardAgent=no"));
        let root = crate::test_support::tempdir().unwrap();
        record.control = root.path().join("socket");
        let missing = read_peer(&record).unwrap_err();
        assert!(format!("{missing:#}").contains("reconnect with syq persist connect"));
        let key = ssh_key::PrivateKey::new(
            ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]).into(),
            "",
        )
        .unwrap();
        let peer = super::super::super::forward::ssh::Peer::from_approved(
            &record.endpoint,
            &format!(
                "syq-approved-peer {}\n",
                key.public_key().to_openssh().unwrap()
            ),
            "ssh-ed25519",
        )
        .unwrap();
        let path = peer_path(&record);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        serde_json::to_writer(&mut file, &peer).unwrap();
        assert!(read_peer(&record).is_ok());
        record.endpoint.host = "different".into();
        assert!(read_peer(&record).is_err());
        record.endpoint.host = "server".into();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_peer(&record).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let saved = root.path().join("saved");
        fs::rename(&path, &saved).unwrap();
        std::os::unix::fs::symlink(saved, path).unwrap();
        assert!(read_peer(&record).is_err());
    }

    #[test]
    fn cached_commands_cannot_authenticate_when_the_master_is_gone() {
        let root = crate::test_support::tempdir().unwrap();
        let record = Record {
            version: 1,
            authorizer: Provider::Return("laptop".into()),
            requested: NativeEndpoint {
                user: None,
                host: "alias".into(),
                port: None,
            },
            endpoint: NativeEndpoint {
                user: Some("user".into()),
                host: "127.0.0.1".into(),
                port: Some(1),
            },
            control: root.path().join("missing"),
        };
        let result = master_command(&record)
            .args(["-p", "1", "--", "127.0.0.1", "exit 17"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status_guarded()
            .unwrap();
        assert_eq!(result.code(), Some(255));
    }
}
