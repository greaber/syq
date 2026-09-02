mod agent_broker;
mod bwlimit;
mod checkpoint;
mod cli;
mod conn;
mod crypto;
mod delegation;
mod direct;
pub mod enrollment;
mod fsops;
mod identity;
mod janky_cat;
mod native_map;
mod native_rm;
mod progress;
mod proto;
mod remote_helper;
mod restricted;
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

/// Many workers each keep a few files open; the default soft limit (1024) is
/// too small for -j32, so use whatever the hard limit allows.
fn raise_nofile() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 && rl.rlim_cur < rl.rlim_max {
            rl.rlim_cur = rl.rlim_max.min(1 << 20);
            libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        }
    }
}

fn main() {
    tune_allocator();
    raise_nofile();
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--build-identity") {
        println!("{}", identity::build());
        return;
    }
    // Compatibility with the 0.1.0 standalone updater. New code uses the
    // release/build identity above and never interprets this as a protocol.
    if argv.get(1).and_then(|arg| arg.to_str()) == Some("--remote-helper-id") {
        println!("{}", identity::legacy_helper_id());
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
    // Keep accepting the historical root spelling for managed helpers. A
    // compatibility wrapper whose public prefix is `syq rsync` naturally
    // turns its remote `--server` launch into `syq rsync --server`.
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
    let quiet = args.quiet;
    let result = if args.follow {
        direct::follow(&args)
    } else if args.interface == cli::Interface::NativeMap {
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
