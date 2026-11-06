// Product code writes stdout and stderr through crate::output, never std's
// print!, println!, eprint! or eprintln!, which panic when the stream is
// closed (see clippy.toml).
#![cfg_attr(not(test), deny(clippy::disallowed_macros))]

// The receiver modules below forbid subprocess launches on macOS: SCM_RIGHTS
// has no atomic close-on-exec receive there. Other executable roles can spawn.

mod advanced;
mod agent_broker;
mod agent_socket;
mod approval_command;
mod auth_from;
mod bwlimit;
mod checks;
mod cli;
mod completion;
mod completion_details;
mod compression;
mod conn;
mod copy_policy;
mod delegation;
mod deletion;
#[cfg_attr(all(target_os = "macos", not(test)), deny(clippy::disallowed_methods))]
mod descriptor_broker;
mod descriptor_copy;
mod destination;
mod destination_results;
mod directive;
pub mod enrollment;
mod expression;
#[cfg_attr(all(target_os = "macos", not(test)), deny(clippy::disallowed_methods))]
mod fsops;
mod hashing;
mod help;
mod identity;
mod inode_metadata;
mod janky_cat;
#[cfg(target_os = "linux")]
mod local_copy;
mod mapping;
mod native_map;
mod native_rm;
mod output;
mod persistence;
#[cfg_attr(all(target_os = "macos", not(test)), deny(clippy::disallowed_methods))]
mod private_broker;
mod process;
use process::group as process_group;
mod progress;
mod proto;
#[cfg(target_os = "linux")]
mod read_ahead;
mod receive_approval;
mod receive_service;
mod remote_helper;
mod remote_to_remote;
mod remote_user_install;
mod resources;
mod restricted;
mod results;
mod resume;
mod rm;
#[cfg_attr(all(target_os = "macos", not(test)), deny(clippy::disallowed_methods))]
mod rooted;
mod s3;
mod scan;
mod sched;
#[cfg_attr(all(target_os = "macos", not(test)), deny(clippy::disallowed_methods))]
mod server;
mod session_pool;
mod sparse;
mod stream_mapping;
mod streaming;
#[cfg_attr(all(target_os = "macos", not(test)), deny(clippy::disallowed_methods))]
mod sys;
mod tcp_records;
#[cfg(test)]
mod test_support;
mod tls;
mod transfer;
mod transfer_observations;
mod transfer_tuning;
mod tune;
mod update;
mod use_version;
mod user_dirs;
mod version_is;
mod wire_budget;
mod write_gate;

/// Keep multi-megabyte block buffers in the heap instead of mmap/munmap-ing
/// each one: page faults and TLB shootdowns across many threads otherwise
/// dominate at high throughput.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn tune_allocator() {
    unsafe {
        // glibc caps this at 32 MiB; larger values are rejected.
        libc::mallopt(libc::M_MMAP_THRESHOLD, 32 << 20);
        libc::mallopt(libc::M_TRIM_THRESHOLD, 1 << 30);
        libc::mallopt(libc::M_TOP_PAD, 64 << 20);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn tune_allocator() {}

/// Many workers each keep a few files open; the default soft limit (1024 on
/// Linux, 256 on macOS) is too small for -j32, so use whatever the hard limit
/// allows. Best effort: the source descriptor budget later reports what the
/// endpoint actually permits.
fn raise_nofile() {
    let Some((limits, wanted)) = nofile_raise_target() else {
        return;
    };
    let _ = fsops::set_nofile_limits(&libc::rlimit {
        rlim_cur: wanted,
        rlim_max: limits.rlim_max,
    });
}

/// The current limits and the soft limit worth requesting, or `None` when the
/// soft limit is already as high as it can usefully go. The request stays at
/// or below one million descriptors and the platform ceiling.
fn nofile_raise_target() -> Option<(libc::rlimit, libc::rlim_t)> {
    let limits = fsops::nofile_limits().ok()?;
    let wanted = platform_nofile_ceiling(limits.rlim_max.min(1 << 20));
    (wanted > limits.rlim_cur).then_some((limits, wanted))
}

/// macOS usually reports an unlimited hard limit but enforces
/// `kern.maxfilesperproc` as the real per-process ceiling. macOS 11 and later
/// store a higher soft limit and apply the ceiling internally; macOS 10.15 and
/// earlier rejected such a request with EINVAL instead of clamping it, which
/// left the default soft limit of 256 in place. Requesting at most the ceiling
/// behaves the same on both. `OPEN_MAX` is the kernel's initial value for the
/// ceiling and stands in when the sysctl is unavailable.
#[cfg(target_os = "macos")]
fn platform_nofile_ceiling(wanted: libc::rlim_t) -> libc::rlim_t {
    const OPEN_MAX: libc::rlim_t = 10240;
    wanted.min(max_files_per_process().unwrap_or(OPEN_MAX))
}

#[cfg(not(target_os = "macos"))]
fn platform_nofile_ceiling(wanted: libc::rlim_t) -> libc::rlim_t {
    wanted
}

#[cfg(target_os = "macos")]
fn max_files_per_process() -> Option<libc::rlim_t> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>();
    // SAFETY: sysctlbyname writes at most `length` bytes into `value` and
    // stores the bytes written back through `length`; no new value is set.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    (result == 0 && length == std::mem::size_of::<libc::c_int>() && value > 0)
        .then_some(value as libc::rlim_t)
}

/// Whether a parsed copy, removal or listing names an SSH endpoint, so that
/// it can start ssh: among its locations, its rsync-style paths, or a
/// descriptor copy's one location. Receiving names and object storage use no
/// SSH login.
fn reaches_ssh(args: &cli::Args) -> bool {
    if args.s3.is_some() {
        return false;
    }
    let ssh = |location: &cli::Location| {
        location
            .host
            .as_deref()
            .is_some_and(|host| !host.starts_with('@'))
    };
    args.locations.iter().any(ssh)
        || args
            .descriptor_copy
            .as_ref()
            .and_then(|plan| plan.location.as_ref())
            .is_some_and(ssh)
        || args
            .paths
            .iter()
            .any(|path| cli::Location::parse(path).is_ok_and(|location| ssh(&location)))
}

fn main() {
    run();
    // A command that returned normally succeeds, unless its output could
    // not all be written (crate::output::exit).
    crate::output::exit(0);
}

fn run() {
    #[cfg(target_os = "linux")]
    process::restore_self_started_name();
    let argv = match use_version::enter(std::env::args_os().collect()) {
        Ok(argv) => argv,
        Err(error) => {
            if let Some(error) = error.downcast_ref::<clap::Error>() {
                crate::output::exit_with(error);
            }
            crate::output::exit_on_error(&error, 1, "syq");
        }
    };
    let environment_options = cli::EnvironmentOptions::take_from_environment();
    tune_allocator();
    raise_nofile();
    fsops::capture_process_umask();
    let mut argv = match destination::handoff::enter(argv) {
        Ok(argv) => argv,
        Err(error) => {
            crate::output::exit_on_error(&error, 1, "syq");
        }
    };
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("help") {
        if let Err(error) = help::show_topic(&argv[2..]) {
            crate::output::exit_on_error(&error, 2, "syq");
        }
        return;
    }
    if argv.len() == 2 && argv[1] == "--install-remote-command" {
        fsops::reserve_startup_descriptors();
        remote_user_install::install();
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--build-identity") {
        crate::output::command_println!("{}", identity::build());
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--release-manifest-signing-payload") {
        if argv.len() != 3 {
            crate::output::diagnostic!(
                "syq: --release-manifest-signing-payload requires one manifest path"
            );
            crate::output::exit(2);
        }
        fsops::reserve_startup_descriptors();
        if let Err(e) = update::write_manifest_signing_payload(std::path::Path::new(&argv[2])) {
            crate::output::exit_on_error(&e, 1, "syq");
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-install") {
        if argv.len() != 2 {
            crate::output::diagnostic!("syq: restricted installer takes no command-line arguments");
            crate::output::exit(2);
        }
        fsops::reserve_startup_descriptors();
        if let Err(error) = restricted::remote_install() {
            crate::output::exit_on_error(&error, 1, "syq restricted installer");
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-revoke") {
        if argv.len() != 2 {
            crate::output::diagnostic!("syq: restricted revoker takes no command-line arguments");
            crate::output::exit(2);
        }
        fsops::reserve_startup_descriptors();
        if let Err(error) = restricted::remote_revoke() {
            crate::output::exit_on_error(&error, 1, "syq restricted revoker");
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-receiver") {
        let value = |index: usize, prefix: &str| {
            argv.get(index)
                .and_then(|argument| argument.to_str())
                .and_then(|argument| argument.strip_prefix(prefix))
        };
        let (enrollment, generation) = (value(2, "--enrollment="), value(3, "--generation="));
        let (Some(enrollment), Some(generation)) = (enrollment, generation) else {
            crate::output::diagnostic!(
                "syq: restricted receiver requires exactly --enrollment=ID --generation=N"
            );
            crate::output::exit(2);
        };
        if argv.len() != 4 {
            crate::output::diagnostic!(
                "syq: restricted receiver requires exactly --enrollment=ID --generation=N"
            );
            crate::output::exit(2);
        }
        fsops::reserve_startup_descriptors();
        if let Err(error) = server::run_checker(enrollment, generation) {
            if error.is::<server::ClientGone>() {
                crate::output::exit(1);
            }
            let code = if crate::restricted::is_sessions_full(&error) {
                crate::restricted::SESSIONS_FULL_EXIT
            } else if error.is::<crate::restricted::Refused>() {
                crate::restricted::REFUSED_EXIT
            } else {
                1
            };
            crate::output::exit_on_error(&error, code, "syq restricted receiver");
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--session-pool") {
        fsops::reserve_startup_descriptors();
        if let Err(error) = session_pool::run(&argv[2..]) {
            crate::output::exit_on_error(&error, 1, "syq session pool");
        }
        return;
    }
    // Remote launches may invoke either `syq --server` or
    // `syq rsync --server`; both enter the same internal server.
    let server_mode = argv.get(1).and_then(|arg| arg.to_str()) == Some("--server")
        || (argv.get(1).and_then(|arg| arg.to_str()) == Some("rsync")
            && argv.get(2).and_then(|arg| arg.to_str()) == Some("--server"));
    if server_mode {
        fsops::reserve_startup_descriptors();
        let local_receiver = argv.get(1).and_then(|arg| arg.to_str()) == Some("--server")
            && argv.get(2).and_then(|arg| arg.to_str()) == Some("--local-receiver");
        if let Err(e) = server::run(local_receiver) {
            if e.is::<server::ClientGone>() {
                crate::output::exit(1);
            }
            crate::output::exit_on_error(&e, 1, "syq server");
        }
        return;
    }
    // Internal entry points above never see environment options. Insert them
    // here, before `exec` and the copy commands, and record the result for
    // the return-helper handoff, which both of those may perform.
    if let Err(error) = environment_options.insert(&mut argv) {
        crate::output::exit_on_error(&error, 2, "syq");
    }
    destination::handoff::record_command_line(&argv);
    // Before these commands start ssh, or any thread. The copy commands
    // check their endpoints after parsing, below, and completion before it
    // lists a remote directory.
    if matches!(
        argv.get(1).and_then(|arg| arg.to_str()),
        Some("ssh" | "persist" | "receiver")
    ) {
        agent_socket::repair_from_tmux();
    }
    // `syq ssh` does this once it knows its persistence domain.
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("exec")
        && !destination::handoff::handed_off()
    {
        receive_service::refresh_outdated(&persistence::Domain::default(), false);
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("ssh") {
        match destination::ssh::run(&argv[1..]) {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                if let Some(error) = error.downcast_ref::<clap::Error>() {
                    crate::output::exit_with(error);
                }
                crate::output::exit_on_error(&error, 255, "syq ssh");
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("exec") {
        match destination::exec::run(&argv[1..]) {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                if let Some(error) = error.downcast_ref::<clap::Error>() {
                    crate::output::exit_with(error);
                }
                crate::output::exit_on_error(&error, 1, "syq exec");
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("cat") {
        fsops::reserve_startup_descriptors();
        match janky_cat::run(&argv[2..]) {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                crate::output::exit_on_error(&error, 1, "syq cat");
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("persist") {
        match persistence::run(&argv[2..]) {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                crate::output::exit_on_error(&error, 1, "syq persist");
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("_ls") {
        match s3::listing::run(&argv[2..]) {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                crate::output::exit_on_error(&error, 1, "syq _ls");
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("tuning-cache") {
        match tune::history::run(&argv[2..]) {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                crate::output::exit_on_error(&error, 1, "syq tuning-cache");
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("completion") {
        match completion::run(&argv[2..]) {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                crate::output::exit_on_error(&error, 1, "syq completion");
            }
        }
    }
    if let Some(result) = restricted::dispatch_receiver_command(&argv) {
        match result {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                crate::output::exit_on_error(&error, 1, "syq");
            }
        }
    }
    if let Some(result) = receive_service::dispatch(&argv).or_else(|| destination::dispatch(&argv))
    {
        match result {
            Ok(code) => crate::output::exit(code),
            Err(error) => {
                crate::output::exit_on_error(&error, 1, "syq");
            }
        }
    }
    let mut args = match cli::Args::parse_args(&argv[1..]) {
        Ok(a) => a,
        Err(e) => {
            if let Some(error) = e.downcast_ref::<clap::Error>() {
                crate::output::exit_with(error);
            }
            crate::output::exit_on_error(&e, 2, "syq");
        }
    };
    if reaches_ssh(&args) {
        agent_socket::repair_from_tmux();
    }
    fsops::reserve_startup_descriptors();
    args.warn_unsupported_options();
    args.normalize();
    if args.self_update {
        if let Err(e) = update::self_update() {
            crate::output::exit_on_error(&e, 1, "syq");
        }
        return;
    }
    if args.register_standalone_install {
        if let Err(e) = update::register_standalone_install() {
            crate::output::exit_on_error(&e, 1, "syq");
        }
        return;
    }
    if let Err(error) = persistence::mark_explicit_scope(&mut args) {
        crate::output::exit_on_error(&error, 2, "syq");
    }
    if let Err(error) = destination::account_copy::prepare_handoff(&args) {
        crate::output::exit_on_error(&error, 2, "syq");
    }
    if args.interface != cli::Interface::NativeCp && args.s3.is_none() {
        if let Err(error) = destination::prepare(&mut args) {
            crate::output::exit_on_error(&error, 2, "syq");
        }
    }
    let quiet = args.quiet;
    // A command handed off to another build's helper leaves the services to
    // the build that started them.
    if !destination::handoff::handed_off() {
        if let Ok(domain) = persistence::Domain::select(args.pscope.as_deref()) {
            receive_service::refresh_outdated(&domain, quiet);
        }
    }
    let result = if args.stream_mapping_fd.is_some() {
        stream_mapping::run(args)
    } else if args.descriptor_copy.is_some() {
        descriptor_copy::run(args)
    } else if args.interface == cli::Interface::NativeMap {
        native_map::run(&args)
    } else if args.s3.is_some() {
        s3::run(args)
    } else if args.rm {
        rm::run(args)
    } else {
        transfer::run(args)
    };
    match result {
        Ok(code) => {
            if code == 0 {
                update::after_success(quiet);
            }
            crate::output::exit(code)
        }
        Err(e) => {
            crate::output::exit_on_error(&e, 1, "syq");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn raise_nofile_reaches_its_target() {
        let target = super::nofile_raise_target();
        super::raise_nofile();
        let after = crate::fsops::nofile_limits().unwrap();
        if let Some((before, wanted)) = target {
            assert!(wanted > before.rlim_cur);
            assert_eq!(
                after.rlim_cur, wanted,
                "soft descriptor limit {} did not reach {wanted} under hard limit {}",
                after.rlim_cur, before.rlim_max
            );
        }
        assert!(
            super::nofile_raise_target().is_none(),
            "soft descriptor limit {} can still be raised under hard limit {}",
            after.rlim_cur,
            after.rlim_max
        );
    }
}
