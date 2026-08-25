mod cli;
mod conn;
mod direct;
mod fsops;
mod progress;
mod proto;
mod scan;
mod sched;
mod server;
mod transfer;

use clap::Parser;

/// Keep multi-megabyte block buffers in the heap instead of mmap/munmap-ing
/// each one: page faults and TLB shootdowns across many threads otherwise
/// dominate at high throughput.
fn tune_allocator() {
    unsafe {
        // glibc caps this at 32 MiB; larger values are rejected.
        libc::mallopt(libc::M_MMAP_THRESHOLD, 32 << 20);
        libc::mallopt(libc::M_TRIM_THRESHOLD, 1 << 30);
        libc::mallopt(libc::M_TOP_PAD, 64 << 20);
    }
}

fn main() {
    tune_allocator();
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("--server") {
        if let Err(e) = server::run() {
            eprintln!("pcp server: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    let mut args = cli::Args::parse();
    args.normalize();
    match transfer::run(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("pcp: {e:#}");
            std::process::exit(1);
        }
    }
}
