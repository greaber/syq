//! User-managed OpenSSH control-connection persistence.
//!
//! A durable preference selects a well-known per-user runtime scope. Scripts
//! can instead create an ephemeral scope and pass its path back with
//! `--pscope`, avoiding shared configuration state.

use crate::cli::Args;
use crate::process::CommandExt as _;
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

mod domain;
pub(crate) use domain::Domain;
mod ssh_config;

const CONFIG_FILE: &str = "persistence.json";
const SCOPE_MARKER: &str = ".syq-persistence";
const SCOPE_MARKER_CONTENT: &[u8] = b"syq persistence scope\n";

#[derive(Parser, Debug)]
#[command(
    name = "syq persist",
    about = "Keep SSH connections open, and receive files and requests from connected servers",
    long_about = "syq persist on keeps SSH connections open for later syq commands, and syq persist connect HOST connects now. Receiving lets connected servers send files and requests to this machine, each with your approval by default; set it up with syq persist receive. For an isolated setup, see on --ephemeral and --pscope."
)]
struct PersistCommand {
    /// Use the isolated connections and settings at PATH instead of the default ones
    #[arg(long, global = true, value_name = "PATH")]
    pscope: Option<PathBuf>,
    #[command(subcommand)]
    action: PersistAction,
}

#[derive(Subcommand, Debug)]
enum PersistAction {
    /// Save the --auth-from choice that later commands use by default
    AuthFrom(crate::auth_from::PreferenceCommand),
    /// Print an OpenSSH config that lets ssh, scp, or Git use an approved connection
    SshConfig(ssh_config::ExportCommand),
    /// Set up receiving, and approve or deny incoming copy and command requests
    Receive(crate::receive_service::ReceiveCommand),
    Destinations(crate::destination::Destinations),
    /// Connect to a server now and keep the connection open for later commands
    Connect {
        /// SSH endpoint ([USER@]HOST[:PORT]); receiving names are not accepted
        host: String,
        /// Whose SSH access to connect with: this machine's own (auto or ssh), or access approved by a receiving machine (@NAME) or SSH authorization provider (HOST)
        #[arg(long, value_name = "auto|ssh|@NAME|HOST")]
        auth_from: Option<String>,
        /// Run the remote syq at PATH instead of syq's automatically installed copy
        #[arg(long, value_name = "PATH", conflicts_with = "no_bootstrap")]
        syq_path: Option<String>,
        /// Run the syq found in the remote $PATH instead of syq's automatically installed copy
        #[arg(long)]
        no_bootstrap: bool,
        /// After connecting, wait up to this many seconds for receiving to be ready
        #[arg(long, value_name = "SECONDS", default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
        /// Replace a receiving service from another build only once it is
        /// idle, as a switch to a new build does (`receive_service::switch`)
        #[arg(long, hide = true)]
        when_idle: bool,
        /// With --when-idle: replace it at once, even when busy, as a
        /// settings change does (`receive_service::Replace::NowBounded`)
        #[arg(long, hide = true, requires = "when_idle")]
        replace_now: bool,
    },
    /// Keep SSH connections open for later syq commands
    On {
        /// Create a new isolated set of connections and settings and print its path for --pscope, instead of turning persistence on for your user
        #[arg(long, conflicts_with = "pscope")]
        ephemeral: bool,
    },
    /// Turn persistence off and close its SSH connections, including receiving; a set made by on --ephemeral is deleted with its settings
    Off {},
    /// Show connection readiness and any receiving problem
    Status {
        /// Print the status as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistenceConfig {
    enabled: bool,
}

/// An `--rsh` ssh command's own options, with relative file paths made
/// absolute, and the working directory when an option runs a local command
/// (see `conn::persistent_ssh_options`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SshOptions {
    pub(crate) options: Vec<String>,
    pub(crate) directory: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointRecord {
    pub(crate) user: Option<String>,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
    /// The `--rsh` ssh command's own options for this connection, with
    /// relative file paths made absolute. Omitted for default connections,
    /// which keep the original record format.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ssh_options: Vec<String>,
    /// The directory a local command in those options, such as a
    /// ProxyCommand, runs in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ssh_options_directory: Option<String>,
}

impl EndpointRecord {
    fn new(user: Option<&str>, host: &str, port: Option<u16>, ssh: Option<&SshOptions>) -> Self {
        Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
            ssh_options: ssh.map(|ssh| ssh.options.clone()).unwrap_or_default(),
            ssh_options_directory: ssh.and_then(|ssh| ssh.directory.clone()),
        }
    }

    fn ssh(&self) -> Option<SshOptions> {
        (!self.ssh_options.is_empty()).then(|| SshOptions {
            options: self.ssh_options.clone(),
            directory: self.ssh_options_directory.clone(),
        })
    }

    pub(crate) fn label(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let endpoint = match &self.user {
            Some(user) => format!("{user}@{host}"),
            None => host,
        };
        match self.port {
            Some(port) => format!("{endpoint}:{port}"),
            None => endpoint,
        }
    }
}

/// Endpoint records in the persistence scope relevant to the command being
/// completed. Completion is advisory, so an absent global runtime scope is an
/// empty source rather than a reason to create one.
pub(crate) fn completion_endpoints(explicit_scope: Option<&Path>) -> Result<Vec<EndpointRecord>> {
    let scope = match explicit_scope {
        Some(scope) => {
            let scope = crate::fsops::resolve(scope.as_os_str().as_bytes());
            validate_scope(&scope)?;
            scope
        }
        None if global_enabled()? => global_scope_path()?,
        None => return Ok(Vec::new()),
    };
    match scope.symlink_metadata() {
        Ok(_) => Ok(scope_records(&scope)?
            .into_iter()
            .map(|(_, record)| record)
            .collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect persistence scope for completion {}",
                scope.display()
            )
        }),
    }
}

pub(crate) fn run(argv: &[OsString]) -> Result<i32> {
    let mut full_argv = vec![OsString::from("syq persist")];
    full_argv.extend_from_slice(argv);
    let matches = command_for_help()
        .try_get_matches_from(&full_argv)
        .unwrap_or_else(|error| {
            crate::output::exit_with(crate::receive_service::option_migration_hint(
                &full_argv, error,
            ))
        });
    let command = PersistCommand::from_arg_matches(&matches)?;
    crate::fsops::reserve_startup_descriptors();
    let domain = Domain::select(command.pscope.as_deref())?;
    match command.action {
        PersistAction::AuthFrom(command) => return crate::auth_from::run(&domain, command),
        PersistAction::SshConfig(command) => return ssh_config::run(&domain, command),
        PersistAction::Receive(command) => {
            return crate::receive_service::run_command(&domain, command);
        }
        PersistAction::Destinations(command) => return crate::destination::run_command(command),
        PersistAction::Connect {
            host,
            auth_from,
            syq_path,
            no_bootstrap,
            timeout,
            when_idle,
            replace_now,
        } => {
            let endpoint =
                crate::cli::parse_native_endpoint(Some(&host))?.context("SSH endpoint missing")?;
            reject_receiving_name(&endpoint.host)?;
            let explicit = auth_from
                .as_deref()
                .map(crate::cli::parse_auth_from)
                .transpose()?;
            let explicit_mode = explicit.is_some();
            let mode = crate::auth_from::resolve(&domain, &endpoint.host, explicit)?;
            if let crate::cli::AuthFrom::Provider(authorizer) = &mode {
                let explicit_timeout = matches.subcommand_matches("connect").is_some_and(|args| {
                    args.value_source("timeout") == Some(clap::parser::ValueSource::CommandLine)
                });
                anyhow::ensure!(
                    !explicit_timeout,
                    "--timeout applies only to native SSH receiving setup; selected authorization uses {authorizer}"
                );
                anyhow::ensure!(
                    syq_path.is_none() && !no_bootstrap,
                    "approved account connections do not accept helper overrides"
                );
                let request = crate::destination::ssh::parse(&[
                    "ssh".into(),
                    "--auth-from".into(),
                    authorizer.label().into(),
                    host.into(),
                ])?;
                crate::auth_from::selected_context(
                    crate::destination::ssh::persistent::connect(&domain, request),
                    &mode,
                    explicit_mode,
                )?;
            } else {
                let connected = connect_domain(
                    &domain,
                    &host,
                    syq_path,
                    no_bootstrap,
                    Duration::from_secs(timeout),
                    match (when_idle, replace_now) {
                        (true, true) => crate::receive_service::Replace::NowBounded,
                        (true, false) => crate::receive_service::Replace::WhenIdle,
                        (false, _) => crate::receive_service::Replace::Now,
                    },
                    if when_idle {
                        Login::Unattended
                    } else {
                        Login::Ask
                    },
                );
                // A switch to a new build tells the service that started it
                // that it waits for the user (`switch::LOGIN_NEEDED_EXIT`).
                if let Err(error) = &connected {
                    if when_idle
                        && error
                            .downcast_ref::<crate::receive_service::switch::LoginNeeded>()
                            .is_some()
                    {
                        crate::output::diagnostic!("syq persist: {error:#}");
                        crate::receive_service::switch::end_own_group();
                        return Ok(crate::receive_service::switch::LOGIN_NEEDED_EXIT);
                    }
                }
                connected?;
                // Other connections from before an update follow too.
                if !when_idle {
                    crate::receive_service::switch_outdated_now(&domain);
                }
            }
        }
        PersistAction::On { ephemeral: true } => {
            let scope = create_ephemeral_scope()?;
            // stdout is exactly a native path and newline for scripts.
            let mut stdout = crate::output::command_stdout();
            stdout.write_all(scope.as_os_str().as_bytes())?;
            stdout.write_all(b"\n")?;
        }
        PersistAction::On { ephemeral: false } => {
            let scope = domain.enable()?;
            crate::output::command_human_stdout!("SSH connection persistence is on");
            crate::output::command_human_stdout!("scope: {}", scope.display());
            crate::receive_service::switch_outdated_now(&domain);
        }
        PersistAction::Off {} => {
            if domain.is_default() {
                write_global_config(false)?;
            }
            let scope = domain.runtime_path();
            // Close admission before invalidating approved connections. Every
            // cleanup path runs even when another reports damaged state.
            if scope.exists() {
                validate_scope(&scope)?;
                mark_closing(&scope)?;
            }
            let provider = crate::receive_service::provider::stop(&domain);
            let provider_links = crate::destination::ssh::provider::stop_all(&domain)
                .and_then(|()| crate::destination::ssh::provider::cleanup_domain(&domain));
            let accounts = crate::destination::ssh::persistent::stop_all(&domain)
                .and_then(|()| crate::destination::ssh::persistent::cleanup_domain(&domain));
            let ordinary = match scope.symlink_metadata() {
                Ok(_) => close_scope(&scope),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => {
                    Err(error).with_context(|| format!("inspect scope {}", scope.display()))
                }
            };
            let failures: Vec<_> = [
                ("authorization provider cleanup", provider),
                ("provider connection cleanup", provider_links),
                ("approved SSH cleanup", accounts),
                ("ordinary connection cleanup", ordinary),
            ]
            .into_iter()
            .filter_map(|(step, result)| result.err().map(|error| format!("{step}: {error:#}")))
            .collect();
            anyhow::ensure!(failures.is_empty(), "{}", failures.join("; "));
            crate::output::command_human_stdout!("SSH connection persistence is off");
        }
        PersistAction::Status { json } => {
            // Scripts asking for structured status never wait for a login.
            if !json {
                crate::receive_service::switch_outdated_now(&domain);
            }
            let enabled = domain.enabled()?;
            if !json {
                crate::output::command_human_stdout!(
                    "SSH connection persistence is {}",
                    if enabled { "on" } else { "off" }
                );
            }
            let scope = domain.runtime_path();
            match scope.symlink_metadata() {
                Ok(_) => print_scope_status(&domain, json)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let authorized = crate::destination::ssh::persistent::status(&domain)?;
                    if json {
                        crate::output::command_println!(
                            "{}",
                            serde_json::json!({"enabled": enabled, "scope": scope, "connections": [], "authorized_ssh": authorized.rows, "authorized_ssh_errors": authorized.errors})
                        );
                    } else {
                        crate::output::command_human_stdout!("connections: 0");
                        crate::destination::ssh::persistent::print_status(&authorized.rows);
                    }
                    anyhow::ensure!(
                        authorized.errors.is_empty(),
                        "{}",
                        authorized.errors.join("; ")
                    );
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect scope {}", scope.display()));
                }
            }
        }
    }
    Ok(0)
}

/// Establish authority through ordinary SSH, without selecting or copying files.
/// Repeated connects leave a healthy receiving process and its approvals alone.
/// Parse only the displayed command; the approving laptop must not consult
/// its own authorization preferences when checking a server's request.
pub(crate) fn parse_account_connect(
    argv: &[OsString],
    authorizer: &str,
) -> Result<crate::destination::ssh::SessionRequest> {
    if argv.first().is_none_or(|arg| arg != "persist") {
        bail!("persistent SSH approval needs a syq persist connect command");
    }
    let matches = command_for_help().try_get_matches_from(argv)?;
    let command = PersistCommand::from_arg_matches(&matches)?;
    let PersistAction::Connect {
        host,
        auth_from,
        syq_path,
        no_bootstrap,
        ..
    } = command.action
    else {
        bail!("persistent SSH approval needs a syq persist connect command");
    };
    if syq_path.is_some() || no_bootstrap {
        bail!("laptop-authorized SSH persistence does not take helper overrides");
    }
    let selected = auth_from.context("persistent SSH approval requires --auth-from @NAME")?;
    if selected != format!("@{authorizer}") {
        bail!("persistent SSH authorizer does not match the shown command");
    }
    crate::destination::ssh::parse(&[
        "ssh".into(),
        "--auth-from".into(),
        selected.into(),
        host.into(),
    ])
}

/// `persist connect` runs on the receiving machine and names an SSH server.
fn reject_receiving_name(host: &str) -> Result<()> {
    if let Some(name) = host.strip_prefix('@') {
        bail!(crate::destination::notices::connect_takes_server(
            name,
            crate::destination::notices::here()
        ));
    }
    Ok(())
}

/// How `connect_domain` logs in to the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Login {
    /// As ssh does, as for `persist connect` run by hand.
    Ask,
    /// As ssh does, but giving up on an unreachable server after ten
    /// seconds, as for a switch to a new build that a command makes in a
    /// terminal on the way.
    Bounded,
    /// Never asking: a login that needs the user fails as
    /// `switch::LoginNeeded`, as for a switch without a terminal.
    Unattended,
}
/// `replace` says what to do with a receiving service from another build:
/// replace it at once, as when the user runs `persist connect`, or only
/// once idle, as a switch to a new build does. A switch to a new build
/// (`Replace::WhenIdle`) always logs in `Login::Unattended`.
pub(crate) fn connect_domain(
    domain: &Domain,
    host: &str,
    syq_path: Option<String>,
    no_bootstrap: bool,
    timeout: Duration,
    replace: crate::receive_service::Replace,
    login: Login,
) -> Result<()> {
    let endpoint =
        crate::cli::parse_native_endpoint(Some(host))?.context("SSH endpoint missing")?;
    reject_receiving_name(&endpoint.host)?;
    let was_enabled = domain.enabled()?;
    let when_idle = replace == crate::receive_service::Replace::WhenIdle;
    // Run as a switch to a new build is: one at a time, bounded, recorded.
    let switching = when_idle || replace == crate::receive_service::Replace::NowBounded;
    // A switch to a new build never turns persistence back on.
    if switching && !was_enabled {
        return Ok(());
    }
    let scope = domain.enable()?;
    if !was_enabled {
        crate::output::command_human_stdout!(
            "SSH connection persistence is on (kept on if connecting fails; disable with syq persist off)"
        );
    }
    let mut multiplexer = crate::conn::SshMultiplexer::persistent(
        &scope,
        endpoint.user.as_deref(),
        &endpoint.host,
        endpoint.port,
        None,
    )?;
    multiplexer.defer_receiving();
    let mut _switching = None;
    let control = multiplexer.control_path().to_path_buf();
    use crate::receive_service::{record_attempt, Attempt};
    // A switch runs where nobody waits for it: bound its time, with what it
    // started, and keep how it went for status
    // (`receive_service::record_attempt`).
    let bound = || {
        let timed_out = control.clone();
        crate::receive_service::switch::end_switch_at(move || {
            record_attempt(
                &timed_out,
                &Attempt::new("failed", Some(crate::receive_service::switch::timed_out())),
            )
        });
    };
    if switching {
        // One switch at a time per connection. A switch to a new build
        // leaves it to the other; a settings change, which must apply,
        // waits for it, within its own time.
        let lock = if when_idle {
            let Some(lock) = lock_endpoint_record(&control)? else {
                return Ok(());
            };
            lock
        } else {
            bound();
            wait_endpoint_record(&control)?
        };
        _switching = Some(lock);
        // Leave a busy service, or one following another installed syq,
        // before logging in to the server for nothing.
        if let Some(ready) = when_idle
            .then(|| crate::receive_service::keeps_running(multiplexer.control_path()))
            .flatten()
        {
            report_ready(domain, &endpoint_label(&endpoint), ready);
            return Ok(());
        }
    }
    let multiplexer = Arc::new(multiplexer);
    if !switching {
        return connect_receiving(
            domain,
            multiplexer,
            endpoint,
            syq_path,
            no_bootstrap,
            timeout,
            replace,
            login,
        );
    }
    record_attempt(&control, &Attempt::new("switching", None));
    if when_idle {
        bound();
    }
    let result = connect_receiving(
        domain,
        multiplexer,
        endpoint,
        syq_path,
        no_bootstrap,
        timeout,
        replace,
        Login::Unattended,
    );
    match &result {
        Ok(()) => crate::receive_service::clear_attempt(&control),
        Err(error) => {
            let login = error
                .downcast_ref::<crate::receive_service::switch::LoginNeeded>()
                .is_some();
            record_attempt(
                &control,
                &Attempt::new(
                    if login { "login" } else { "failed" },
                    Some(format!("{error:#}")),
                ),
            );
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn connect_receiving(
    domain: &Domain,
    multiplexer: Arc<crate::conn::SshMultiplexer>,
    endpoint: crate::cli::NativeEndpoint,
    syq_path: Option<String>,
    no_bootstrap: bool,
    timeout: Duration,
    replace: crate::receive_service::Replace,
    login: Login,
) -> Result<()> {
    let when_idle = replace == crate::receive_service::Replace::WhenIdle;
    let unattended = login == Login::Unattended;
    let remote = crate::conn::RemoteSpec {
        local_process: false,
        user: endpoint.user,
        host: endpoint.host,
        port: endpoint.port,
        // A switch runs in the background: a login that needs the user fails
        // rather than asks, as receiving's own reconnects do.
        // An unreachable server fails soon, as an ordinary failure, rather
        // than at the login's deadline as one that needs the user
        // (`switch::LoginWatch`); as the login check does.
        rsh: match login {
            Login::Ask => vec!["ssh".into()],
            Login::Bounded => vec!["ssh".into(), "-o".into(), "ConnectTimeout=10".into()],
            Login::Unattended => vec![
                "ssh".into(),
                "-o".into(),
                "BatchMode=yes".into(),
                "-o".into(),
                "ConnectTimeout=10".into(),
            ],
        },
        bootstrap_helper: syq_path.is_none() && !no_bootstrap,
        syq_path,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: Some(multiplexer.clone()),
        quiet: false,
        pacing: Default::default(),
        tcp: Default::default(),
        diagnostics: Default::default(),
        primed_control: Default::default(),
        forwarded: None,
        receiver_host: None,
        read_ahead: crate::transfer_tuning::DEFAULT_PIPELINE_DEPTH,
    };
    crate::output::command_human_stdout!("Connecting to {}...", remote.label());
    // This uses the same pinned-helper bootstrap and authentication as a copy.
    // No source roots, data workers or filesystem operations are requested.
    // A switch reads ssh's errors to tell a login that needs the user from
    // other failures, and bounds a login that waits for one.
    let connected = if unattended {
        let _login = crate::receive_service::switch::LoginWatch::start(
            multiplexer.control_path(),
            remote.label(),
        );
        remote.connect_for_authorization(true)
    } else {
        remote.connect_with(true, false)
    };
    let connection = match connected {
        Ok(connection) => connection,
        Err(error) if unattended && crate::conn::ssh_login_needs_user(&error) => {
            crate::receive_service::switch::defer_after_login(multiplexer.control_path());
            return Err(error.context(crate::receive_service::switch::LoginNeeded(remote.label())));
        }
        Err(error) => return Err(error),
    };
    // Tests stand for work after the login that takes too long.
    #[cfg(debug_assertions)]
    if let Some(millis) = when_idle
        .then(|| std::env::var("SYQ_TEST_SWITCH_STALL_MS").ok())
        .flatten()
        .and_then(|millis| millis.parse().ok())
    {
        std::thread::sleep(Duration::from_millis(millis));
    }
    let receiving = crate::receive_service::ensure_ready(
        domain,
        multiplexer.control_path(),
        &remote,
        timeout,
        replace,
    )?;
    drop(connection);
    report_ready(domain, &remote.label(), receiving);
    Ok(())
}

fn endpoint_label(endpoint: &crate::cli::NativeEndpoint) -> String {
    EndpointRecord::new(
        endpoint.user.as_deref(),
        &endpoint.host,
        endpoint.port,
        None,
    )
    .label()
}

fn report_ready(domain: &Domain, label: &str, ready: crate::receive_service::Ready) {
    use crate::receive_service::Ready;
    match ready {
        Ready::Online(names) => {
            crate::output::command_human_stdout!("{label} ready; receiving as @{}", names.join(", @"))
        }
        Ready::Off => {
            crate::output::command_human_stdout!("{label} ready; receiving is disabled")
        }
        Ready::Other {
            build,
            busy: Some(busy),
            follows_this_file,
        } => crate::output::command_human_stdout!(
            "{}",
            crate::receive_service::busy_notice(
                label,
                &build,
                &busy,
                follows_this_file,
                &crate::receive_service::connect_command(label, domain.explicit_path())
            )
        ),
        Ready::Other {
            build, busy: None, ..
        } => crate::output::command_human_stdout!(
            "receiving through {label} keeps running syq {build}, which follows another installed syq; `{}` replaces it",
            crate::receive_service::connect_command(label, domain.explicit_path())
        ),
    }
}

/// Take the endpoint record's lock for one switch to a new build at a time,
/// or None while another holds it. The record is never rewritten, so its
/// lock stays on one file while the scope lasts.
fn lock_endpoint_record(control: &Path) -> Result<Option<File>> {
    let mut path = control.as_os_str().to_owned();
    path.push(".json");
    let record = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .with_context(|| format!("open endpoint record {}", Path::new(&path).display()))?;
    if unsafe { libc::flock(record.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(record));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(error.into())
}

/// Take the endpoint record's lock as `lock_endpoint_record` does, waiting
/// for another switch that holds it.
fn wait_endpoint_record(control: &Path) -> Result<File> {
    let mut path = control.as_os_str().to_owned();
    path.push(".json");
    let record = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .with_context(|| format!("open endpoint record {}", Path::new(&path).display()))?;
    loop {
        if unsafe { libc::flock(record.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(record);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

/// Keep commands from starting a switch for this connection for `wait`
/// (`claim_switch_attempt`).
pub(crate) fn defer_switch_attempts(control: &Path, wait: Duration) {
    let mut path = control.as_os_str().to_owned();
    path.push(".json");
    if let Ok(record) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        let _ = record.set_modified(std::time::SystemTime::now() + wait);
    }
}

/// Whether a command may start a switch for this connection now: at most
/// one in `interval`, so that commands run while its server is unreachable
/// do not each log in again, and none while a switch holds the endpoint
/// record's lock. A claim, made under that lock, sets the record's
/// modification time ahead to when the next one is due; nothing else uses
/// that time, as the record is never rewritten.
pub(crate) fn claim_switch_attempt(control: &Path, interval: Duration) -> bool {
    let Ok(Some(record)) = lock_endpoint_record(control) else {
        return false;
    };
    let now = std::time::SystemTime::now();
    let due = record
        .metadata()
        .and_then(|metadata| metadata.modified())
        .is_ok_and(|next| next <= now);
    due && record.set_modified(now + interval).is_ok()
}

/// Whether a switch a command makes on the way may start for a connection
/// (`receive_service::switch_outdated_now`).
pub(crate) enum SwitchClaim {
    /// Another switch holds the endpoint record's lock.
    Underway,
    /// The endpoint record could not be locked.
    Unavailable(anyhow::Error),
    /// Held for this switch; `due` says whether commands may try again now
    /// (`claim_switch_attempt`).
    Claimed { lock: File, due: bool },
}
pub(crate) fn claim_switch_now(control: &Path) -> SwitchClaim {
    let record = match lock_endpoint_record(control) {
        Ok(Some(record)) => record,
        Ok(None) => return SwitchClaim::Underway,
        Err(error) => return SwitchClaim::Unavailable(error),
    };
    let due = record
        .metadata()
        .and_then(|metadata| metadata.modified())
        .is_ok_and(|next| next <= std::time::SystemTime::now());
    SwitchClaim::Claimed { lock: record, due }
}

/// Remember whether the command explicitly selected a scope without touching
/// configuration or runtime state. Commands that never construct an eligible
/// local SSH connection must not depend on either location being accessible.
pub(crate) fn mark_explicit_scope(args: &mut Args) -> Result<()> {
    args.pscope_explicit = args.pscope.is_some();
    if args.pscope.is_some()
        && args
            .rsh
            .as_deref()
            .is_some_and(|rsh| !crate::conn::rsh_persists_connections(rsh))
    {
        bail!(
            "--pscope requires the default ssh or an --rsh ssh command without its own connection-sharing options or debug logging"
        );
    }
    Ok(())
}

/// Resolve persistence only for an implicit local SSH edge. Explicit scopes
/// are validated here, and the durable policy is read here. Local commands and
/// transports that do not use managed SSH avoid an unrelated state dependency.
pub(crate) fn scope_for_implicit_ssh(explicit_scope: Option<&Path>) -> Result<Option<PathBuf>> {
    let domain = Domain::select(explicit_scope)?;
    if !domain.is_default() || domain.enabled()? {
        Ok(Some(domain.ensure_runtime()?))
    } else {
        Ok(None)
    }
}

/// OpenSSH expands percent tokens in control paths, including paths supplied
/// through `-S`. Double each percent byte so that expansion yields the literal,
/// byte-exact filesystem path. Keeping the path in an `OsString` also avoids
/// lossy UTF-8 conversion and makes whitespace one argv value rather than SSH
/// configuration syntax.
pub(crate) fn openssh_control_path(path: &Path) -> OsString {
    debug_assert!(validate_openssh_control_path(path).is_ok());
    let bytes = path.as_os_str().as_bytes();
    let mut escaped =
        Vec::with_capacity(bytes.len() + bytes.iter().filter(|&&b| b == b'%').count());
    for &byte in bytes {
        if byte == b'%' {
            escaped.push(b'%');
        }
        escaped.push(byte);
    }
    OsString::from_vec(escaped)
}

/// OpenSSH expands a leading `~` and `${ENV}` in `ControlPath` even when the
/// path is supplied as a separate `-S` argument. Those forms have no escaping
/// contract comparable to `%%`, so refuse them before creating or accepting a
/// control directory.
pub(crate) fn validate_openssh_control_path(path: &Path) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.first() == Some(&b'~') || bytes.windows(2).any(|pair| pair == b"${") {
        bail!(
            "SSH control path {} contains OpenSSH expansion syntax; it may not begin with `~` or contain `${{`",
            path.display()
        );
    }
    Ok(())
}

/// OpenSSH binds a temporary name with a dot and 16 random characters
/// before linking the control socket into place (openssh-portable/mux.c).
/// Account for that name and the terminating NUL, not only the final path.
pub(crate) fn validate_openssh_socket_path(path: &Path) -> Result<()> {
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    validate_openssh_socket_capacity(path, address.sun_path.len())
}

fn validate_openssh_socket_capacity(path: &Path, capacity: usize) -> Result<()> {
    validate_openssh_control_path(path)?;
    let limit = capacity - 18;
    if path.as_os_str().as_bytes().len() > limit {
        bail!(
            "SSH control socket path {} is too long (maximum {limit} bytes, including room for OpenSSH's temporary suffix); use a shorter XDG_RUNTIME_DIR or persistence scope",
            path.display()
        );
    }
    Ok(())
}

fn closing_scope_error(scope: &Path) -> anyhow::Error {
    let recovery = match scope.to_str() {
        Some(path) => format!(
            "finish its cleanup with `syq persist --pscope {} off`",
            shell_words::quote(path)
        ),
        None => "finish its cleanup by repeating `syq persist off` with the original `--pscope` argument".into(),
    };
    anyhow::anyhow!(
        "persistence scope is closing: {}; {recovery}",
        scope.display()
    )
}

/// Return the stable socket path for one endpoint and record enough metadata
/// for `persist status` and `persist off` to inspect or close it later.
pub(crate) fn prepare_endpoint(
    scope: &Path,
    user: Option<&str>,
    host: &str,
    port: Option<u16>,
    ssh: Option<&SshOptions>,
) -> Result<PathBuf> {
    validate_scope(scope)?;
    if scope.join(crate::receive_service::CLOSING).exists() {
        return Err(closing_scope_error(scope));
    }
    let key = endpoint_key(user, host, port, ssh);
    let socket = scope.join(&key);
    validate_openssh_socket_path(&socket)?;
    let record_path = scope.join(format!("{key}.json"));
    let expected = EndpointRecord::new(user, host, port, ssh);
    let record_bytes = serde_json::to_vec(&expected)?;
    let mut temporary = tempfile::NamedTempFile::new_in(scope)
        .with_context(|| format!("create endpoint record in {}", scope.display()))?;
    temporary
        .write_all(&record_bytes)
        .and_then(|()| temporary.write_all(b"\n"))
        .with_context(|| format!("write endpoint record {}", record_path.display()))?;
    match temporary.persist_noclobber(&record_path) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let actual = read_endpoint_record(&record_path)?;
            if actual != expected {
                bail!(
                    "persistence scope endpoint-key collision at {}",
                    record_path.display()
                );
            }
        }
        Err(error) => {
            return Err(error.error)
                .with_context(|| format!("create endpoint record {}", record_path.display()));
        }
    }

    if let Ok(metadata) = socket.symlink_metadata() {
        if !socket_is_live(&socket) {
            if metadata.is_dir() {
                bail!(
                    "SSH control socket path {} is unexpectedly a directory",
                    socket.display()
                );
            }
            std::fs::remove_file(&socket)
                .with_context(|| format!("remove stale SSH control socket {}", socket.display()))?;
        }
    }
    Ok(socket)
}

pub(crate) fn config_path() -> Option<PathBuf> {
    crate::user_dirs::config_dir().map(|root| root.join("syq").join(CONFIG_FILE))
}

fn read_global_config() -> Result<Option<PersistenceConfig>> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "persistence configuration {} must be a regular file owned by the current user",
            path.display()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "persistence configuration {} must not be group- or other-writable",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let config: PersistenceConfig = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse persistence configuration {}", path.display()))?;
    Ok(Some(config))
}

pub(crate) fn global_enabled() -> Result<bool> {
    Ok(read_global_config()?.is_some_and(|config| config.enabled))
}

fn write_global_config(enabled: bool) -> Result<()> {
    let path = config_path()
        .context("cannot change persistence: no home directory or absolute XDG_CONFIG_HOME")?;
    let parent = path.parent().expect("configuration path has a parent");
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create configuration directory {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary configuration in {}", parent.display()))?;
    serde_json::to_writer_pretty(&mut temporary, &PersistenceConfig { enabled })?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace persistence configuration {}", path.display()))?;
    Ok(())
}

pub(crate) fn runtime_parent_path() -> PathBuf {
    let base = crate::user_dirs::runtime_dir().unwrap_or_else(|| {
        // Darwin's default TMPDIR is long enough that even the global
        // endpoint socket exceeds sun_path once OpenSSH adds its suffix.
        // This parent is still checked for ownership, mode and symlinks.
        if cfg!(target_os = "macos") {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        }
    });
    base.join(format!("syq-persist-{}", unsafe { libc::geteuid() }))
}

fn global_scope_path() -> Result<PathBuf> {
    Ok(runtime_parent_path().join("global"))
}

pub(crate) fn is_global_scope(scope: &Path) -> Result<bool> {
    let candidate = std::fs::metadata(scope)
        .with_context(|| format!("inspect persistence scope {}", scope.display()))?;
    // An unrelated unavailable default location cannot block an explicit domain.
    let Ok(global) = std::fs::metadata(global_scope_path()?) else {
        return Ok(false);
    };
    Ok((candidate.dev(), candidate.ino()) == (global.dev(), global.ino()))
}

pub(crate) fn ensure_runtime_parent() -> Result<PathBuf> {
    let path = runtime_parent_path();
    validate_openssh_control_path(&path)?;
    if let Err(error) = secure_directory(&path, true, true) {
        return Err(held_by_another_user(&path, unsafe { libc::geteuid() }).unwrap_or(error));
    }
    Ok(path)
}

/// Without XDG_RUNTIME_DIR the runtime directory's name is predictable, so
/// another user can create it first, as a directory or a link. Say who did
/// and how to get around it.
fn held_by_another_user(path: &Path, uid: u32) -> Option<anyhow::Error> {
    let owner = std::fs::symlink_metadata(path).ok()?.uid();
    if owner == uid {
        return None;
    }
    Some(anyhow::anyhow!(
        "{} belongs to another user (uid {owner}), so syq cannot keep persistent connections there; ask that user or an administrator to remove it, or set XDG_RUNTIME_DIR to a short private directory of your own",
        path.display()
    ))
}

fn ensure_global_scope() -> Result<PathBuf> {
    let parent = ensure_runtime_parent()?;
    let scope = parent.join("global");
    initialize_scope(&scope)?;
    Ok(scope)
}

fn create_ephemeral_scope() -> Result<PathBuf> {
    let parent = ensure_runtime_parent()?;
    let temporary = tempfile::Builder::new()
        .prefix("domain-")
        .tempdir_in(&parent)
        .with_context(|| format!("create persistence scope in {}", parent.display()))?;
    // Validate while TempDir still owns cleanup of a rejected scope.
    initialize_scope(temporary.path())?;
    let scope = temporary.keep();
    if scope.as_os_str().as_bytes().contains(&b'\n') {
        let _ = std::fs::remove_file(scope.join(SCOPE_MARKER));
        let _ = std::fs::remove_dir(&scope);
        bail!("persistence scope path contains a newline and cannot be returned safely");
    }
    Ok(scope)
}

pub(crate) fn initialize_scope(scope: &Path) -> Result<()> {
    validate_openssh_socket_path(&scope.join(endpoint_key(None, "", None, None)))?;
    secure_directory(scope, true, true)?;
    create_marker(scope)?;
    validate_scope(scope)
}

fn create_marker(scope: &Path) -> Result<()> {
    let path = scope.join(SCOPE_MARKER);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(mut marker) => marker.write_all(SCOPE_MARKER_CONTENT)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create scope marker {}", path.display()));
        }
    }
    Ok(())
}

pub(crate) fn validate_scope(scope: &Path) -> Result<()> {
    validate_openssh_control_path(scope)?;
    secure_directory(scope, false, false)?;
    let marker_path = scope.join(SCOPE_MARKER);
    let mut marker = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&marker_path)
        .with_context(|| {
            format!(
                "open persistence scope marker {} (is this a path printed by `syq persist on --ephemeral`?)",
                marker_path.display()
            )
        })?;
    let metadata = marker.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "persistence scope marker {} must be a regular file owned by the current user",
            marker_path.display()
        );
    }
    let mut content = Vec::new();
    marker.read_to_end(&mut content)?;
    if content != SCOPE_MARKER_CONTENT {
        bail!("invalid persistence scope marker {}", marker_path.display());
    }
    Ok(())
}

/// Open and validate a directory without following a final-component symlink.
/// Only internally selected directories are permission-tightened; an explicit
/// `--pscope` that is too broad is refused without modifying it.
fn secure_directory(path: &Path, create: bool, tighten: bool) -> Result<File> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("persistence directory path contains NUL")?;
    if create && unsafe { libc::mkdir(c_path.as_ptr(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).with_context(|| format!("create {}", path.display()));
        }
    }
    let descriptor = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "open persistence directory {} (symlinks are refused)",
                path.display()
            )
        });
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "persistence directory {} must be owned by the current user",
            path.display()
        );
    }
    if metadata.mode() & 0o077 != 0 {
        if !tighten {
            bail!(
                "persistence directory {} must not be accessible by group or other users",
                path.display()
            );
        }
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("restrict {}", path.display()));
        }
    }
    Ok(directory)
}

/// An `--rsh` ssh command's options select a separate connection, so a login
/// made with one key, jump host, or configuration is never reused by a command
/// that asked for another. Without them the key is unchanged.
fn endpoint_key(
    user: Option<&str>,
    host: &str,
    port: Option<u16>,
    ssh: Option<&SshOptions>,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(user.unwrap_or("").as_bytes());
    hasher.update(b"@");
    hasher.update(host.as_bytes());
    if let Some(port) = port {
        hasher.update(b":");
        hasher.update(port.to_be_bytes());
    }
    if let Some(ssh) = ssh {
        hasher.update(b"\0ssh-options");
        if let Some(directory) = &ssh.directory {
            hasher.update(b"\0directory");
            hasher.update((directory.len() as u64).to_be_bytes());
            hasher.update(directory.as_bytes());
        }
        for option in &ssh.options {
            hasher.update((option.len() as u64).to_be_bytes());
            hasher.update(option.as_bytes());
        }
    }
    let digest = hasher.finalize();
    let mut name = String::from("cm-");
    for byte in &digest[..8] {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

fn read_endpoint_record(path: &Path) -> Result<EndpointRecord> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open endpoint record {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "endpoint record {} must be a regular file owned by the current user",
            path.display()
        );
    }
    let record: EndpointRecord = serde_json::from_reader(file)
        .with_context(|| format!("parse endpoint record {}", path.display()))?;
    Ok(record)
}

fn record_key(name: &OsStr) -> Option<&str> {
    let name = name.to_str()?;
    let key = name.strip_suffix(".json")?;
    valid_endpoint_key(key).then_some(key)
}

fn valid_endpoint_key(name: &str) -> bool {
    name.len() == 19
        && name.starts_with("cm-")
        && name[3..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn scope_records(scope: &Path) -> Result<Vec<(String, EndpointRecord)>> {
    validate_scope(scope)?;
    let mut records = Vec::new();
    for entry in std::fs::read_dir(scope)
        .with_context(|| format!("read persistence scope {}", scope.display()))?
    {
        let entry = entry?;
        if let Some(key) = record_key(&entry.file_name()) {
            let record = read_endpoint_record(&entry.path())?;
            let expected_key = endpoint_key(
                record.user.as_deref(),
                &record.host,
                record.port,
                record.ssh().as_ref(),
            );
            if key != expected_key {
                bail!(
                    "endpoint record {} does not match its recorded endpoint {}",
                    entry.path().display(),
                    record.label()
                );
            }
            records.push((key.to_owned(), record));
        }
    }
    records.sort_by(|left, right| left.1.label().cmp(&right.1.label()));
    Ok(records)
}

/// Inspect only existing, owned scopes; status must not enable persistence.
pub(crate) fn receiving_controls(domain: &Domain) -> Result<Vec<PathBuf>> {
    let scope = domain.runtime_path();
    match scope.symlink_metadata() {
        Ok(_) => Ok(scope_records(&scope)?
            .into_iter()
            .map(|(key, _)| scope.join(key))
            .collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn socket_is_live(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// A fast local readiness check, without spawning SSH or waiting for a full
/// listen queue. An explicit busy error is not evidence that a socket is
/// stale, so native cleanup keeps its separate predicate above. Some systems
/// (including Darwin) report refused for both full and abandoned sockets.
pub(crate) fn socket_is_ready(path: &Path) -> std::io::Result<bool> {
    let socket = crate::process::with_inheritance_guard(|| {
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
    })?;
    socket.set_nonblocking(true)?;
    match socket.connect(&socket2::SockAddr::unix(path)?) {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

#[derive(Serialize)]
struct ConnectionStatus {
    endpoint: String,
    /// The `--rsh` ssh command's own options for this connection, and the
    /// directory a local command among them runs in.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ssh_options: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_options_directory: Option<String>,
    state: String,
    ssh_connected: bool,
    receiving_enabled: Option<bool>,
    receiving_name: Option<String>,
    receiving_profiles: Vec<crate::receive_service::NamedConnection>,
    receiving: Option<crate::receive_service::ConnectionState>,
    /// The receiving service's build, when it is running.
    #[serde(skip_serializing_if = "Option::is_none")]
    receiving_build: Option<String>,
    /// Its switch to a new build, while waiting for one or after one failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    receiving_switch: Option<crate::receive_service::switch::Report>,
    #[serde(skip)]
    receiving_note: Option<String>,
    session_pool: bool,
}

fn print_scope_status(domain: &Domain, json: bool) -> Result<()> {
    let scope_path = domain.runtime_path();
    let scope = scope_path.as_path();
    let kind = if domain.is_default() {
        "global"
    } else {
        "ephemeral"
    };
    let records = scope_records(scope)?;
    let receiving_setting = crate::receive_service::enabled_servers(domain);
    let receiving_error = receiving_setting
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));
    let receiving_servers = receiving_setting.ok();
    let mut connections = Vec::new();
    for (key, record) in records {
        // Receiving connects with plain ssh, so it never serves a connection
        // opened with other ssh options.
        let receiving_enabled = receiving_servers
            .as_ref()
            .filter(|_| record.ssh().is_none())
            .map(|profiles| {
                profiles
                    .iter()
                    .any(|servers| servers.is_empty() || servers.contains(&record.label()))
            });
        let control = scope.join(&key);
        let ssh_live = socket_is_live(&control);
        let receiving = crate::receive_service::connection_status(&control);
        let state = match &receiving {
            _ if receiving_error.is_some() => "failed",
            Some(receiving) if receiving_enabled == Some(true) => {
                if receiving.connection.phase == "online" {
                    "ready"
                } else {
                    &receiving.connection.phase
                }
            }
            _ if receiving_enabled == Some(true) => "inactive",
            _ if ssh_live => "ready",
            _ => "inactive",
        };
        let receiving_note = receiving.as_ref().and_then(|receiving| {
            crate::receive_service::build_note(
                &receiving.build,
                receiving.started_from.as_deref(),
                receiving.switch.as_ref(),
                receiving.busy.as_ref(),
                Some(&record.label()),
                &crate::receive_service::connect_command(&record.label(), domain.explicit_path()),
                true,
            )
        });
        connections.push(ConnectionStatus {
            receiving_build: receiving.as_ref().map(|s| s.build.clone()),
            receiving_switch: receiving.as_ref().and_then(|s| s.switch.clone()),
            receiving_note,
            endpoint: record.label(),
            ssh_options: record.ssh_options.clone(),
            ssh_options_directory: record.ssh_options_directory.clone(),
            state: state.to_owned(),
            ssh_connected: ssh_live,
            receiving_enabled,
            receiving_name: receiving.as_ref().map(|s| s.name.clone()),
            receiving: receiving.as_ref().map(|s| s.connection.clone()),
            receiving_profiles: receiving.map(|s| s.profiles).unwrap_or_default(),
            session_pool: crate::session_pool::is_running(&control),
        });
    }
    let authorized_ssh = crate::destination::ssh::persistent::status(domain)?;
    // The local SSH authorization provider, when it runs another build or is
    // switching to a new one.
    let provider = crate::receive_service::provider::snapshot(domain)
        .ok()
        .flatten()
        .filter(|provider| provider.build != crate::identity::build() || provider.switch.is_some());
    if json {
        crate::output::command_println!(
            "{}",
            serde_json::json!({
                "enabled": domain.enabled()?,
                "scope": scope, "connections": connections, "receiving_error": receiving_error,
                "authorized_ssh": authorized_ssh.rows,
                "authorized_ssh_errors": authorized_ssh.errors,
                "provider": provider.as_ref().map(|provider| serde_json::json!({
                    "build": provider.build, "switch": provider.switch,
                })),
            })
        );
        anyhow::ensure!(
            authorized_ssh.errors.is_empty(),
            "{}",
            authorized_ssh.errors.join("; ")
        );
        return Ok(());
    }
    crate::output::command_human_stdout!("scope ({kind}): {}", scope.display());
    if let Some(error) = &receiving_error {
        crate::output::command_human_stdout!("Receiving configuration failed: {error}");
    }
    crate::output::command_human_stdout!("connections: {}", connections.len());
    crate::destination::ssh::persistent::print_status(&authorized_ssh.rows);
    for connection in connections {
        let mut line = format!("  {}", connection.endpoint);
        if !connection.ssh_options.is_empty() {
            line.push_str(&format!(
                " (ssh options: {}",
                shell_words::join(&connection.ssh_options)
            ));
            if let Some(directory) = &connection.ssh_options_directory {
                line.push_str(&format!("; run in {directory}"));
            }
            line.push(')');
        }
        line.push_str(&format!("  {}", connection.state));
        if connection.receiving_enabled == Some(false) {
            line.push_str(" (receiving disabled)");
        } else if let Some(name) = connection
            .receiving_name
            .as_deref()
            .filter(|name| !name.is_empty())
        {
            line.push_str(&format!(" (receiving as @{name})"));
        }
        if let Some(error) = connection
            .receiving
            .as_ref()
            .and_then(|state| state.error.as_deref())
        {
            line.push_str(&format!(": {error}"));
        }
        for profile in &connection.receiving_profiles {
            line.push_str(&format!("; @{} {}", profile.name, profile.connection.phase));
            if let Some(error) = &profile.connection.error {
                line.push_str(&format!(": {error}"));
            }
        }
        if let Some(note) = &connection.receiving_note {
            line.push_str(&format!("; receiving {note}"));
        }
        // Only a copy with the same --rsh options reopens such a connection.
        if connection.state == "inactive" && connection.ssh_options.is_empty() {
            line.push_str(&format!(
                "; run syq persist connect {}",
                shell_words::quote(&connection.endpoint)
            ));
            if kind != "global" {
                line.push_str(&format!(
                    " --pscope {}",
                    shell_words::quote(&scope.to_string_lossy())
                ));
            }
        }
        crate::output::command_human_stdout!("{line}");
    }
    if let Some(provider) = provider {
        let mut fix = "syq persist receive on".to_owned();
        if kind != "global" {
            fix.push_str(&format!(
                " --pscope {}",
                shell_words::quote(&scope.to_string_lossy())
            ));
        }
        if let Some(note) = crate::receive_service::build_note(
            &provider.build,
            provider.started_from.as_deref(),
            provider.switch.as_ref(),
            provider.busy().as_ref(),
            None,
            &fix,
            false,
        ) {
            crate::output::command_human_stdout!("  local SSH provider: {note}");
        }
    }
    anyhow::ensure!(
        authorized_ssh.errors.is_empty(),
        "{}",
        authorized_ssh.errors.join("; ")
    );
    Ok(())
}

fn mark_closing(scope: &Path) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(scope.join(crate::receive_service::CLOSING))?;
    Ok(())
}

const DOMAIN_SETTINGS: &[&str] = &[
    "auth-from.json",
    "receive.json",
    "receive.lock",
    "account-permissions-v1.json",
    "account-permissions-v1.lock",
    crate::receive_approval::provider_accounts::STATE_FILE,
    crate::receive_approval::provider_accounts::LOCK_FILE,
    crate::receive_service::provider::SOCKET_FILE,
    crate::receive_service::provider::LOCK_FILE,
];

fn close_scope(scope: &Path) -> Result<()> {
    let records = scope_records(scope)?;
    let closing = scope.join(crate::receive_service::CLOSING);
    mark_closing(scope)?;
    // Unknown or damaged auxiliary state must not keep known connections alive.
    // Validate all entries before deleting anything, but stop every known owner
    // first even if one service has already failed.
    let mut failures = Vec::new();
    for (key, record) in &records {
        let socket = scope.join(key);
        for result in [
            crate::receive_service::stop(&socket),
            crate::session_pool::stop(&socket),
        ] {
            if let Err(error) = result {
                failures.push(format!("{}: {error:#}", record.label()));
            }
        }
        if socket_is_live(&socket) {
            if let Err(error) = close_master(&socket, record) {
                failures.push(format!("{}: {error:#}", record.label()));
            }
        }
    }
    anyhow::ensure!(failures.is_empty(), "{}", failures.join("; "));
    let record_keys: std::collections::HashSet<&str> =
        records.iter().map(|(key, _)| key.as_str()).collect();
    for entry in std::fs::read_dir(scope)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == OsStr::new(SCOPE_MARKER)
            || name == OsStr::new(crate::receive_service::CLOSING)
            || record_key(&name).is_some()
            || DOMAIN_SETTINGS
                .iter()
                .any(|setting| name == OsStr::new(setting))
        {
            continue;
        }
        if let Some(name) = name.to_str() {
            if valid_endpoint_key(name) && record_keys.contains(name) {
                continue;
            }
        }
        if let Some(owner) = crate::session_pool::owned_name(name.as_bytes())
            .or_else(|| crate::receive_service::owned_name(name.as_bytes()))
            .and_then(|owner| std::str::from_utf8(owner).ok())
        {
            if valid_endpoint_key(owner) && record_keys.contains(owner) {
                continue;
            }
        }
        bail!(
            "refusing to remove persistence scope {} because it contains unrecognized entry {:?}",
            scope.display(),
            name
        );
    }

    for (key, _) in records {
        let socket = scope.join(&key);
        if let Ok(metadata) = socket.symlink_metadata() {
            if metadata.is_dir() {
                bail!(
                    "refusing to remove unexpected directory at SSH control path {}",
                    socket.display()
                );
            }
            std::fs::remove_file(&socket)
                .with_context(|| format!("remove SSH control socket {}", socket.display()))?;
        }
        let record_path = scope.join(format!("{key}.json"));
        std::fs::remove_file(&record_path)
            .with_context(|| format!("remove endpoint record {}", record_path.display()))?;
    }
    for name in DOMAIN_SETTINGS {
        match std::fs::remove_file(scope.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove scope setting {name}"));
            }
        }
    }
    std::fs::remove_file(closing)?;
    std::fs::remove_file(scope.join(SCOPE_MARKER))
        .with_context(|| format!("remove persistence marker from {}", scope.display()))?;
    std::fs::remove_dir(scope)
        .with_context(|| format!("remove persistence scope {}", scope.display()))?;
    Ok(())
}

fn close_master(socket: &Path, record: &EndpointRecord) -> Result<()> {
    let output = master_exit_command(socket, record)
        .capture_output()
        .with_context(|| format!("ask SSH master for {} to exit", record.label()))?;
    if output.status.success() || !socket_is_live(socket) {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "SSH master for {} refused to exit ({}): {}",
        record.label(),
        output.status,
        stderr.trim()
    )
}

fn master_exit_command(socket: &Path, record: &EndpointRecord) -> Command {
    let mut command = Command::new("ssh");
    command
        .arg("-S")
        .arg(openssh_control_path(socket))
        .args(["-O", "exit"]);
    if let Some(user) = &record.user {
        command.args(["-l", user]);
    }
    if let Some(port) = record.port {
        command.args(["-p", &port.to_string()]);
    }
    command.arg("--").arg(&record.host);
    command
}

pub(crate) fn command_for_help() -> clap::Command {
    let mut command = crate::help::configure(PersistCommand::command().bin_name("syq persist"));
    // Help and completion inspect child commands independently of parsing.
    // Propagate the shared domain selector before a child is extracted.
    command.build();
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn closing_scope_removes_linked_preferences_without_removing_the_target() {
        let root = crate::test_support::short_tempdir().unwrap();
        let scope = root.path().join("scope");
        initialize_scope(&scope).unwrap();
        let target = root.path().join("saved.json");
        std::fs::write(&target, br#"{"default":"ssh"}"#).unwrap();
        std::os::unix::fs::symlink(&target, scope.join("auth-from.json")).unwrap();
        close_scope(&scope).unwrap();
        assert!(!scope.exists());
        assert_eq!(std::fs::read(&target).unwrap(), br#"{"default":"ssh"}"#);
    }

    #[test]
    fn runtime_directory_held_by_another_user_names_them_and_the_way_out() {
        let root = crate::test_support::short_tempdir().unwrap();
        let path = root.path().join("syq-persist-test");
        // The test's own files stand for another user's: `held_by_another_user`
        // is asked on behalf of a different uid.
        let owner = unsafe { libc::geteuid() };
        let other = owner.wrapping_add(1);
        assert!(held_by_another_user(&path, other).is_none());
        for link in [false, true] {
            if link {
                std::os::unix::fs::symlink(root.path(), &path).unwrap();
            } else {
                std::fs::create_dir(&path).unwrap();
            }
            assert!(held_by_another_user(&path, owner).is_none());
            let message = held_by_another_user(&path, other).unwrap().to_string();
            assert!(
                message.contains(&format!("another user (uid {owner})")),
                "{message}"
            );
            assert!(message.contains("XDG_RUNTIME_DIR"), "{message}");
            if link {
                std::fs::remove_file(&path).unwrap();
            } else {
                std::fs::remove_dir(&path).unwrap();
            }
        }
    }

    #[test]
    fn control_socket_budget_includes_openssh_temporary_suffix() {
        let reported = Path::new(
            "/var/folders/bb/zjydfp6x4zsbx55jb_zqhksr0000gn/T/syq-persist-501/global/cm-0123456789abcdef",
        );
        assert_eq!(reported.as_os_str().len(), 91);
        for capacity in [104, 108] {
            assert!(validate_openssh_socket_capacity(reported, capacity).is_err());
            let fits = "/".to_owned() + &"x".repeat(capacity - 19);
            assert!(validate_openssh_socket_capacity(Path::new(&fits), capacity).is_ok());
            assert!(validate_openssh_socket_capacity(Path::new(&(fits + "x")), capacity).is_err());
        }
    }

    #[test]
    fn approved_records_preserve_v0_7_1_json_and_endpoint_keys() {
        // Unchanged released v0.7.1 EndpointRecord representation and key algorithm.
        const FIXTURE: &str = r#"{"user":"alice","host":"example","port":2222}"#;
        const KEY: &str = "cm-4adf1f61aa19aead";
        let temporary = crate::test_support::short_tempdir().unwrap();
        let scope = temporary.path().join("approved-fixture");
        initialize_scope(&scope).unwrap();
        let path = scope.join(format!("{KEY}.json"));
        std::fs::write(&path, FIXTURE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let records = scope_records(&scope).unwrap();
        assert_eq!(records[0].0, KEY);
        assert_eq!(serde_json::to_string(&records[0].1).unwrap(), FIXTURE);
        let socket = prepare_endpoint(&scope, Some("alice"), "example", Some(2222), None).unwrap();
        assert_eq!(socket.file_name().unwrap(), KEY);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), FIXTURE);
        close_scope(&scope).unwrap();
    }

    #[test]
    fn persistent_account_approval_requires_the_explicit_matching_connect_command() {
        let parse = |args: &[&str]| {
            parse_account_connect(
                &args.iter().map(OsString::from).collect::<Vec<_>>(),
                "laptop",
            )
        };
        let request = parse(&[
            "persist",
            "connect",
            "alice@hostB:2222",
            "--auth-from",
            "@laptop",
        ])
        .unwrap();
        assert_eq!(request.destination.user.as_deref(), Some("alice"));
        assert_eq!(request.destination.port, Some(2222));
        // Scope paths are requester-local metadata, not a dependency on the
        // approving machine's filesystem.
        let scoped = parse(&[
            "persist",
            "--pscope",
            "/requester-only/scope",
            "connect",
            "alice@hostB:2222",
            "--auth-from",
            "@laptop",
        ])
        .unwrap();
        assert_eq!(scoped.destination, request.destination);
        for args in [
            vec!["persist", "connect", "hostB"],
            vec!["persist", "connect", "hostB", "--auth-from", "@other"],
            vec!["persist", "off"],
            vec!["ssh", "--auth-from", "@laptop", "hostB"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn endpoint_records_are_stable_and_inactive_scopes_close_cleanly() {
        let temporary = crate::test_support::short_tempdir().unwrap();
        let scope = temporary.path().join("scope");
        initialize_scope(&scope).unwrap();
        let first = prepare_endpoint(&scope, Some("alice"), "example", None, None).unwrap();
        let same = prepare_endpoint(&scope, Some("alice"), "example", None, None).unwrap();
        let alternate =
            prepare_endpoint(&scope, Some("alice"), "example", Some(2222), None).unwrap();
        assert_eq!(first, same);
        assert_ne!(first, alternate);
        assert_eq!(scope_records(&scope).unwrap().len(), 2);
        close_scope(&scope).unwrap();
        assert!(!scope.exists());
    }

    #[test]
    fn over_budget_existing_scope_can_be_inspected_and_closed() {
        let temporary = crate::test_support::short_tempdir().unwrap();
        let scope = temporary.path().join("scope");
        initialize_scope(&scope).unwrap();
        prepare_endpoint(&scope, None, "example", None, None).unwrap();
        // An older version could create this scope; moving a scope can also
        // make a previously valid endpoint path exceed the creation budget.
        let long = temporary.path().join("x".repeat(100));
        std::fs::rename(scope, &long).unwrap();
        assert!(validate_scope(&long).is_ok());
        assert!(print_scope_status(&Domain::select(Some(&long)).unwrap(), false).is_ok());
        assert!(prepare_endpoint(&long, None, "example", None, None).is_err());
        close_scope(&long).unwrap();
        assert!(!long.exists());
    }

    /// Many commands at once claim at most one switch for a connection in
    /// its interval, and none while a switch holds its record's lock.
    #[test]
    fn concurrent_commands_claim_one_switch_attempt() {
        let temporary = crate::test_support::short_tempdir().unwrap();
        let scope = temporary.path().join("scope");
        initialize_scope(&scope).unwrap();
        let control = prepare_endpoint(&scope, None, "example", None, None).unwrap();
        for _ in 0..5 {
            defer_switch_attempts(&control, Duration::ZERO);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(64));
            let claims: usize = (0..64)
                .map(|_| {
                    let (control, barrier) = (control.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        claim_switch_attempt(&control, Duration::from_secs(60))
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|join| usize::from(join.join().unwrap()))
                .sum();
            assert_eq!(claims, 1);
        }
        defer_switch_attempts(&control, Duration::ZERO);
        let switching = lock_endpoint_record(&control).unwrap().unwrap();
        assert!(!claim_switch_attempt(&control, Duration::from_secs(60)));
        drop(switching);
        assert!(claim_switch_attempt(&control, Duration::from_secs(60)));
    }

    #[test]
    fn concurrent_endpoint_registration_publishes_one_complete_record() {
        let temporary = crate::test_support::short_tempdir().unwrap();
        let scope = temporary.path().join("scope");
        initialize_scope(&scope).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let joins: Vec<_> = (0..8)
            .map(|_| {
                let scope = scope.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    prepare_endpoint(&scope, Some("alice"), "example", Some(2222), None).unwrap()
                })
            })
            .collect();
        let sockets: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        assert!(sockets.iter().all(|socket| socket == &sockets[0]));
        assert_eq!(scope_records(&scope).unwrap().len(), 1);
    }

    #[test]
    fn explicit_scope_validation_never_follows_or_chmods_a_symlink() {
        let temporary = crate::test_support::tempdir().unwrap();
        let victim = temporary.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o755)).unwrap();
        let attack = temporary.path().join("scope");
        std::os::unix::fs::symlink(&victim, &attack).unwrap();
        assert!(validate_scope(&attack).is_err());
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn master_exit_targets_the_recorded_endpoint_and_socket() {
        let record = EndpointRecord::new(Some("alice"), "example", Some(2222), None);
        let command =
            master_exit_command(Path::new("/run/user/1/scope/cm-deadbeefdeadbeef"), &record);
        let args: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "-S",
                "/run/user/1/scope/cm-deadbeefdeadbeef",
                "-O",
                "exit",
                "-l",
                "alice",
                "-p",
                "2222",
                "--",
                "example"
            ]
        );
    }

    #[test]
    fn master_exit_preserves_path_bytes_and_escapes_openssh_percent_tokens() {
        let path = PathBuf::from(OsString::from_vec(
            b"/tmp/scope with space/%h/non-utf8-\xff/socket".to_vec(),
        ));
        let command = master_exit_command(&path, &EndpointRecord::new(None, "example", None, None));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args[0], OsStr::new("-S"));
        assert_eq!(
            args[1].as_bytes(),
            b"/tmp/scope with space/%%h/non-utf8-\xff/socket"
        );
    }

    #[test]
    fn openssh_environment_and_tilde_expansion_forms_are_refused() {
        assert!(validate_openssh_control_path(Path::new("/tmp/scope with space/%h")).is_ok());
        assert!(validate_openssh_control_path(Path::new("~/scope")).is_err());
        assert!(validate_openssh_control_path(Path::new("/tmp/${HOME}/scope")).is_err());
    }
}
