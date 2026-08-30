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
mod progress;
mod proto;
mod remote_helper;
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
