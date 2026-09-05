mod agent_broker;
mod bwlimit;
mod cli;
mod completion;
mod conn;
mod delegation;
#[allow(dead_code)]
mod descriptor_broker;
mod destination;
pub mod enrollment;
mod fsops;
mod help;
mod identity;
mod janky_cat;
mod native_map;
mod native_rm;
mod output;
mod persistence;
mod private_broker;
mod progress;
mod proto;
mod receipt;
mod remote_helper;
mod remote_to_remote;
mod restricted;
mod results;
mod resume;
mod rm;
#[allow(dead_code)]
mod rooted;
mod scan;
mod sched;
mod server;
mod session_pool;
mod tcp_records;
#[cfg(test)]
mod test_support;
mod transfer;
mod tune;
mod update;

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

fn main() {
    tune_allocator();
    raise_nofile();
    fsops::capture_process_umask();
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("help") {
        if let Err(error) = help::show_topic(&argv[2..]) {
            crate::output::diagnostic!("syq: {error:#}");
            std::process::exit(2);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--build-identity") {
        println!("{}", identity::build());
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--release-manifest-signing-payload") {
        if argv.len() != 3 {
            crate::output::diagnostic!(
                "syq: --release-manifest-signing-payload requires one manifest path"
            );
            std::process::exit(2);
        }
        if let Err(e) = update::write_manifest_signing_payload(std::path::Path::new(&argv[2])) {
            crate::output::diagnostic!("syq: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-install") {
        if argv.len() != 2 {
            crate::output::diagnostic!("syq: restricted installer takes no command-line arguments");
            std::process::exit(2);
        }
        if let Err(error) = restricted::remote_install() {
            crate::output::diagnostic!("syq restricted installer: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-revoke") {
        if argv.len() != 2 {
            crate::output::diagnostic!("syq: restricted revoker takes no command-line arguments");
            std::process::exit(2);
        }
        if let Err(error) = restricted::remote_revoke() {
            crate::output::diagnostic!("syq restricted revoker: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-receiver") {
        let enrollment = argv
            .get(2)
            .and_then(|argument| argument.to_str())
            .and_then(|argument| argument.strip_prefix("--enrollment="));
        if argv.len() != 3 || enrollment.is_none() {
            crate::output::diagnostic!("syq: restricted receiver requires exactly --enrollment=ID");
            std::process::exit(2);
        }
        if let Err(error) = restricted::run_receiver(enrollment.unwrap()) {
            crate::output::diagnostic!("syq restricted receiver: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--session-pool") {
        if let Err(error) = session_pool::run(&argv[2..]) {
            crate::output::diagnostic!("syq session pool: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    // Remote launches may invoke either `syq --server` or
    // `syq rsync --server`; both enter the same internal server.
    let server_mode = argv.get(1).and_then(|arg| arg.to_str()) == Some("--server")
        || (argv.get(1).and_then(|arg| arg.to_str()) == Some("rsync")
            && argv.get(2).and_then(|arg| arg.to_str()) == Some("--server"));
    if server_mode {
        if let Err(e) = server::run() {
            crate::output::diagnostic!("syq server: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("cat") {
        match janky_cat::run(&argv[2..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                crate::output::diagnostic!("syq cat: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("persist") {
        match persistence::run(&argv[2..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                crate::output::diagnostic!("syq persist: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("completion") {
        match completion::run(&argv[2..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                crate::output::diagnostic!("syq completion: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if let Some(result) = restricted::dispatch_receiver_command(&argv) {
        match result {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                crate::output::diagnostic!("syq: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if let Some(result) = destination::dispatch(&argv) {
        match result {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                crate::output::diagnostic!("syq: {error:#}");
                std::process::exit(1);
            }
        }
    }
    let mut args = match cli::Args::parse_args() {
        Ok(a) => a,
        Err(e) => {
            crate::output::diagnostic!("syq: {e:#}");
            std::process::exit(2);
        }
    };
    args.normalize();
    if args.self_update {
        if let Err(e) = update::self_update() {
            crate::output::diagnostic!("syq: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if args.register_standalone_install {
        if let Err(e) = update::register_standalone_install() {
            crate::output::diagnostic!("syq: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    persistence::mark_explicit_scope(&mut args);
    if args.interface != cli::Interface::NativeCp {
        if let Err(error) = destination::prepare(&mut args) {
            crate::output::diagnostic!("syq: {error:#}");
            std::process::exit(2);
        }
    }
    let quiet = args.quiet;
    let result = if args.interface == cli::Interface::NativeMap {
        native_map::run(&args)
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
            std::process::exit(code)
        }
        Err(e) => {
            crate::output::diagnostic!("syq: {e:#}");
            std::process::exit(1);
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
