use super::*;
use std::time::Duration;

fn command(t: &Tmp, pull: bool, rate: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
    cmd.args(["cp", "-v", "--no-progress", "--rsh"])
        .arg(fake_rsh(t))
        .args([
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
            "--performance-tuning=workers=4",
            "--resource-limits",
            &format!("bandwidth={rate}"),
        ])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_REQUIRE_TCP", "1")
        .env("SYQ_TEST_TCP_LOOPBACK_ONLY", "1")
        .env("SYQ_TEST_NO_INTERFACE_ADDRESSES", "1")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"));
    if pull {
        cmd.args(["--from", "127.0.0.1"]);
    }
    cmd
}

fn paths(t: &Tmp, pull: bool, directory: bool) -> Vec<String> {
    let mut args = Vec::new();
    if directory {
        args.push("--srcs-in".into());
    }
    args.push(t.s("src"));
    if !pull {
        args.extend(["--to".into(), "127.0.0.1".into()]);
    }
    args.extend([if directory { "--into" } else { "--as" }.into(), t.s("dst")]);
    args
}

#[test]
fn tcp_cap_is_aggregate_and_keeps_small_file_batches() {
    for pull in [false, true] {
        let t = Tmp::new();
        for n in 0..64 {
            write(&t.path(&format!("src/{n}")), &prng(16 << 10, 1200 + n));
        }
        let start = std::time::Instant::now();
        let out = command(&t, pull, "1M")
            .arg("--no-compress")
            .arg("--performance-tuning=batch-files=4")
            .env("SYQ_TEST_WORKER_EVENTS", t.path("workers"))
            .args(paths(&t, pull, true))
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_same_tree(&t.path("src"), &t.path("dst"));
        assert!(
            start.elapsed() >= Duration::from_millis(900),
            "aggregate rate exceeded: {out:?}"
        );
        let events = fs::read_to_string(t.path("workers")).unwrap();
        let workers: std::collections::BTreeSet<_> = events
            .lines()
            .filter(|line| line.starts_with("batch "))
            .map(|line| line.split_whitespace().nth(1).unwrap())
            .collect();
        assert!(
            workers.len() > 1,
            "test needs multiple sending workers: {events}"
        );
        let observed = tuning_observed(&out);
        assert!(observed["max_batch_files"].as_u64().unwrap() > 1, "{out:?}");
    }
}

#[test]
fn tcp_compression_is_charged_after_compressing() {
    for pull in [false, true] {
        let t = Tmp::new();
        write(&t.path("src"), &vec![b'x'; 4 << 20]);
        let mut cmd = command(&t, pull, "1M");
        cmd.args(paths(&t, pull, false));
        let start = std::time::Instant::now();
        let out = cmd.run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), read(&t.path("src")));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "logical bytes appear to be paced: {out:?}"
        );
    }
}

#[test]
fn high_tcp_cap_keeps_single_read_comparison() {
    for pull in [false, true] {
        let t = Tmp::new();
        let source = prng(8 << 20, 1301);
        write(&t.path("src"), &source);
        write(&t.path("dst"), &vec![0; source.len()]);
        set_mtime(&t.path("dst"), 1);
        let out = command(&t, pull, "1G")
            .args(paths(&t, pull, false))
            .env("SYQ_TEST_COMPARED_READ_EVENTS", t.path("reads"))
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), source);
        // Only ReadComparedRange emits these events. The old capped path
        // hashes the source separately and then uses ordinary ReadRange.
        let events = fs::read_to_string(t.path("reads")).unwrap();
        let total: u64 = events
            .lines()
            .map(|line| {
                line.split_whitespace()
                    .nth(2)
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            })
            .sum();
        assert_eq!(total, source.len() as u64, "{events}");
    }
}
