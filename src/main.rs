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

fn main() {
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
