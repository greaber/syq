mod agent_broker;
mod bwlimit;
mod cli;
mod conn;
mod crypto;
mod delegation;
#[allow(dead_code)]
mod descriptor_broker;
mod direct;
pub mod enrollment;
mod fsops;
mod identity;
mod janky_cat;
mod native_map;
mod native_rm;
mod persistence;
mod private_broker;
mod progress;
mod proto;
mod receipt_v2;
mod remote_helper;
mod restricted;
mod results;
mod resume;
mod rm;
#[allow(dead_code)]
mod rooted;
mod scan;
mod sched;
mod server;
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
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes only into the local struct passed by pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0
        || limits.rlim_cur >= limits.rlim_max
    {
        return;
    }
    for candidate in nofile_candidates(limits.rlim_max) {
        let wanted = candidate.min(limits.rlim_max);
        if wanted <= limits.rlim_cur {
            continue;
        }
        let raised = libc::rlimit {
            rlim_cur: wanted,
            rlim_max: limits.rlim_max,
        };
        // SAFETY: setrlimit reads only the local struct. A rejected value
        // leaves the limit unchanged, so the next candidate can be tried.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
            return;
        }
    }
}

/// Soft limits to try, highest first. Linux accepts anything up to the hard
/// limit, so one candidate suffices. macOS usually reports an unlimited hard
/// limit but rejects a soft limit above `kern.maxfilesperproc` with EINVAL
/// instead of clamping it, so that ceiling and then `OPEN_MAX` follow.
fn nofile_candidates(hard_limit: libc::rlim_t) -> Vec<libc::rlim_t> {
    let ceiling = hard_limit.min(1 << 20);
    #[cfg(target_os = "macos")]
    {
        let mut candidates = vec![ceiling];
        candidates.extend(max_files_per_process());
        candidates.push(10240);
        candidates
    }
    #[cfg(not(target_os = "macos"))]
    {
        vec![ceiling]
    }
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
        .then(|| value as libc::rlim_t)
}

fn main() {
    tune_allocator();
    raise_nofile();
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--build-identity") {
        println!("{}", identity::build());
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--release-manifest-signing-payload") {
        if argv.len() != 3 {
            eprintln!("syq: --release-manifest-signing-payload requires one manifest path");
            std::process::exit(2);
        }
        if let Err(e) = update::write_manifest_signing_payload(std::path::Path::new(&argv[2])) {
            eprintln!("syq: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-install") {
        if argv.len() != 2 {
            eprintln!("syq: restricted installer takes no command-line arguments");
            std::process::exit(2);
        }
        if let Err(error) = restricted::remote_install() {
            eprintln!("syq restricted installer: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--restricted-revoke") {
        if argv.len() != 2 {
            eprintln!("syq: restricted revoker takes no command-line arguments");
            std::process::exit(2);
        }
        if let Err(error) = restricted::remote_revoke() {
            eprintln!("syq restricted revoker: {error:#}");
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
            eprintln!("syq: restricted receiver requires exactly --enrollment=ID");
            std::process::exit(2);
        }
        if let Err(error) = restricted::run_receiver(enrollment.unwrap()) {
            eprintln!("syq restricted receiver: {error:#}");
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
            eprintln!("syq server: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("cat") {
        match janky_cat::run(&argv[2..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("syq cat: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("persist") {
        match persistence::run(&argv[2..]) {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("syq persist: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if let Some(result) = restricted::dispatch_management(&argv) {
        match result {
            Ok(code) => std::process::exit(code),
            Err(error) => {
                eprintln!("syq: {error:#}");
                std::process::exit(1);
            }
        }
    }
    let mut args = match cli::Args::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("syq: {e:#}");
            std::process::exit(2);
        }
    };
    args.normalize();
    if args.self_update {
        if let Err(e) = update::self_update() {
            eprintln!("syq: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if args.register_standalone_install {
        if let Err(e) = update::register_standalone_install() {
            eprintln!("syq: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    persistence::mark_explicit_scope(&mut args);
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
            eprintln!("syq: {e:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn raise_nofile_lifts_the_soft_limit_to_a_usable_value() {
        super::raise_nofile();
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes only into the local struct.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
            0
        );
        // A rejected raise would leave macOS at its default soft limit of 256.
        assert!(
            limits.rlim_cur >= limits.rlim_max.min(1024),
            "soft descriptor limit {} was not raised toward hard limit {}",
            limits.rlim_cur,
            limits.rlim_max
        );
    }
}
