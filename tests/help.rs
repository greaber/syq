//! Public help must be useful without invoking filesystem or update operations.
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .env("NO_COLOR", "1")
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap()
}

fn help(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty(), "{args:?}: {:?}", output.stderr);
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn short_and_long_help_spellings_are_identical_at_every_public_level() {
    for path in [
        vec![],
        vec!["cp"],
        vec!["exec"],
        vec!["rm"],
        vec!["map"],
        vec!["--self-update"],
        vec!["persist"],
        vec!["persist", "on"],
        vec!["persist", "connect"],
        vec!["persist", "off"],
        vec!["persist", "status"],
        vec!["completion"],
        vec!["completion", "bash"],
        vec!["completion", "zsh"],
        vec!["completion", "fish"],
        vec!["completion", "cache"],
        vec!["completion", "cache", "list"],
        vec!["completion", "cache", "forget"],
        vec!["completion", "cache", "clear"],
        vec!["persist", "receive"],
        vec!["persist", "receive", "on"],
        vec!["persist", "receive", "off"],
        vec!["persist", "receive", "status"],
        vec!["persist", "receive", "wait"],
        vec!["persist", "receive", "pending"],
        vec!["persist", "receive", "approve"],
        vec!["persist", "receive", "deny"],
        vec!["persist", "destinations"],
        vec!["persist", "destinations", "list"],
        vec!["persist", "destinations", "wait"],
        vec!["persist", "destinations", "forget"],
        vec!["receiver"],
        vec!["receiver", "enroll"],
        vec!["receiver", "list"],
        vec!["receiver", "revoke"],
    ] {
        let page = |flag| {
            let mut args = path.clone();
            args.push(flag);
            help(&args)
        };
        let short = page("-h");
        assert_eq!(short, page("--help"), "{path:?}");
        assert!(short.contains("--help-all"), "{path:?}");
        assert!(!page("--help-all").is_empty());
    }
}

#[test]
fn full_reference_reveals_specialized_options_without_exposing_internal_switches() {
    for (command, common, advanced) in [
        ("cp", "--into", "--coordinate-at"),
        ("rm", "--srcs-in", "--results-fd"),
        ("map", "--as", "--src-files"),
        ("rsync", "--archive", "--syq-tcp-ports"),
    ] {
        let short = help(&[command, "--help"]);
        let full = help(&[command, "--help-all"]);
        assert!(short.contains(common));
        assert!(!short.contains(advanced), "{short}");
        assert!(full.contains(advanced), "{full}");
        assert!(short.lines().count() < full.lines().count());
        for internal in [
            "--delegated-operands-b64",
            "--suppress-summary",
            "--register-standalone-install",
            "--server",
        ] {
            assert!(!full.contains(internal), "{command}: {internal}");
        }
    }
}

#[test]
fn lifecycle_and_root_help_describe_the_real_commands() {
    let root = help(&["--help"]);
    for option in ["--help", "--help-all", "--version", "--self-update"] {
        assert!(root.contains(option));
    }
    assert!(root.contains("source-to-destination mappings"));
    let update = help(&["--self-update", "--help"]);
    for term in [
        "Standalone",
        "brew upgrade syq",
        "SYQ_NO_UPDATE_CHECK",
        "signed",
    ] {
        assert!(update.contains(term));
    }
    assert!(!update.contains("--archive"));
    assert!(!update.contains("syq rsync"));
    assert!(!run(&["--self-update", "unexpected"]).status.success());
    for path in [
        vec!["cp"],
        vec!["exec"],
        vec!["receiver", "enroll"],
        vec!["persist", "on"],
        vec!["persist", "connect"],
        vec!["persist", "receive", "pending"],
        vec!["persist", "destinations", "wait"],
        vec!["completion", "cache", "forget"],
    ] {
        let mut direct = path.clone();
        direct.push("--help");
        let mut topic = vec!["help"];
        topic.extend(path);
        assert_eq!(help(&direct), help(&topic));
    }
    assert!(!run(&["help", "unknown"]).status.success());
    for removed in ["recv", "destination"] {
        assert!(!run(&[removed, "--help"]).status.success());
        assert!(!run(&["help", removed]).status.success());
    }
}

#[test]
fn help_like_operands_are_data_and_rsync_h_remains_human_readable() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap();
    for name in ["--help", "--help-all", "-h"] {
        std::fs::write(dir.join(name), b"file data").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .current_dir(&dir)
            .args(["cp", &format!("--src={name}"), "--as", "copied", "-q"])
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(dir.join("copied")).unwrap(), b"file data");
        let output = Command::new(env!("CARGO_BIN_EXE_syq"))
            .current_dir(&dir)
            .args(["map", "--", name])
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("\"dst\""));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .current_dir(&dir)
        .args(["rsync", "-h", "copied", "rsync-copy"])
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(dir.join("rsync-copy")).unwrap(), b"file data");
    // A detached option value is also not a help request when the grammar permits it.
    let output = Command::new(env!("CARGO_BIN_EXE_syq"))
        .current_dir(&dir)
        .args([
            "rsync",
            "--syq-ignore",
            "--help-all",
            "copied",
            "filtered-copy",
        ])
        .env("SYQ_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.join("filtered-copy").exists());
}
