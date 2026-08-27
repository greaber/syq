mod bwlimit;
mod cli;
mod conn;
mod crypto;
mod direct;
mod fsops;
mod progress;
mod proto;
mod remote_helper;
mod resume;
mod rm;
mod scan;
mod sched;
mod server;
mod transfer;

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
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("--remote-helper-id") {
        println!("{}", remote_helper::release_key());
        return;
    }
    if argv.get(1).map(String::as_str) == Some("--server") {
        if let Err(e) = server::run() {
            eprintln!("pcp server: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    let mut args = match cli::Args::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pcp: {e:#}");
            std::process::exit(2);
        }
    };
    args.normalize();
    let result = if args.follow {
        direct::follow(&args)
    } else if args.rm {
        rm::run(args)
    } else {
        transfer::run(args)
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("pcp: {e:#}");
            std::process::exit(1);
        }
    }
}
