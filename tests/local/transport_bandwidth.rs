use super::*;
use std::time::Duration;

fn command(t: &Tmp, pull: bool, rate: &str) -> Command {
    let mut cmd = automatic_command(t, pull, rate);
    cmd.arg("--performance-tuning=workers=4");
    cmd
}

fn automatic_command(t: &Tmp, pull: bool, rate: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
    cmd.args(["cp", "-v", "--no-progress", "--rsh"])
        .arg(fake_rsh(t))
        .args([
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
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

// Exercise normal small-file batches: completion acknowledgments can be seconds
// apart under a cap, while the transport and tuner must keep seeing activity.
#[cfg(debug_assertions)]
#[test]
fn capped_batches_provide_continuous_tuning_activity() {
    for pull in [false, true] {
        let t = Tmp::new();
        for n in 0..8192 {
            write(&t.path(&format!("src/{n}")), &prng(8192, 8000 + n));
        }
        let history = t.path("history.sqlite");
        let out = automatic_command(&t, pull, "4M")
            .arg("--no-compress")
            .env("SYQ_TUNING_CACHE", t.path("tuning.json"))
            .env("SYQ_TUNING_HISTORY", &history)
            .env("SYQ_TEST_TUNE_SAMPLE_MS", "100")
            .args(paths(&t, pull, true))
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_same_tree(&t.path("src"), &t.path("dst"));
        let db = rusqlite::Connection::open(history).unwrap();
        let observations: Vec<serde_json::Value> = db
            .prepare("SELECT data FROM events WHERE json_extract(data,'$.kind')='observation'")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|row| serde_json::from_str(&row.unwrap()).unwrap())
            .collect();
        assert!(observations.len() >= 20, "{out:?}");
        let active = observations
            .iter()
            .filter(|event| event["data"]["rate"].as_f64().unwrap() > 0.0)
            .count();
        assert!(
            active * 2 > observations.len(),
            "bursty completion accounting: {observations:?}"
        );
        // Workers may claim the entire queue before the first observation.
        // Those samples still verify accounting, but the remaining-work gate
        // can exclude them from worker-count comparisons and cache inference.
        // Learning eligibility is tested separately with sufficient queued work.
        let mode: String = db
            .query_row("SELECT mode FROM runs LIMIT 1", [], |row| row.get(0))
            .unwrap();
        assert!(mode.contains("bandwidth=4194304;"), "{mode}");
        assert!(
            mode.contains("bandwidth-accounting=transport-v1;activity=wire-bytes-v1"),
            "{mode}"
        );
    }
}
