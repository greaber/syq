//! Destination lookups a remote copy sends before their batch's turn.
//!
//! `SYQ_TEST_SCAN_AHEAD_WAIT` makes the scan hold every batch it may before
//! the planner takes the next one, so each lookup that can be sent early is.
//! `SYQ_TEST_EARLY_LOOKUPS` records what became of each: `sent`, then `used`,
//! `repeated` in the batch's turn, `withdrawn` while its batch still waits,
//! or `discarded`.

use super::*;

/// Files in each of the fixtures' large directories: more than a scan batch.
const FILES: usize = 6000;

fn fill(directory: &Path, prefix: &str) {
    fs::create_dir_all(directory).unwrap();
    for index in 0..FILES {
        fs::write(directory.join(format!("{prefix}{index:04}")), b"data").unwrap();
    }
}

fn copy(t: &Tmp, rsh: &Path, extra: &[&str]) -> Output {
    for log in ["early", "lookups"] {
        let _ = fs::remove_file(t.path(log));
    }
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--srcs-in", &t.s("src"), "--to", "host", "--into"])
        .arg(t.path("dst"))
        .arg("--rsh")
        .arg(rsh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args(["--no-tcp", "--no-progress"])
        .args(extra)
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .env("SYQ_TEST_SCAN_AHEAD_WAIT", "1")
        .env("SYQ_TEST_EARLY_LOOKUPS", t.path("early"))
        .env("SYQ_TEST_DESTINATION_LOOKUPS", t.path("lookups"))
        .run()
        .unwrap()
}

/// How many early lookups met each fate, in the order of the module comment.
fn fates(t: &Tmp) -> [usize; 5] {
    let log = fs::read_to_string(t.path("early")).unwrap_or_default();
    ["sent", "used", "repeated", "withdrawn", "discarded"].map(|fate| {
        log.lines()
            .filter(|line| line.split(' ').next() == Some(fate))
            .count()
    })
}

fn batch_lookups(t: &Tmp) -> usize {
    fs::read_to_string(t.path("lookups"))
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("batch "))
        .count()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// An unchanged tree asks about every batch after the first before its
/// turn, uses each reply, and asks about none twice.
#[test]
fn unchanged_rerun_uses_every_lookup_it_sent_early() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f");
    fill(&t.path("src/b"), "g");
    assert_output_ok(&copy(&t, &rsh, &[]));

    let output = copy(&t, &rsh, &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (12,000 files)"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
    // The first batch asks in its turn.
    assert_eq!(batch_lookups(&t), sent + 1);

    // Pruning plans the same way, then removes what the source lacks.
    fs::write(t.path("dst/b/extra"), b"extra").unwrap();
    let output = copy(&t, &rsh, &["--prune"]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(!t.path("dst/b/extra").exists());
    assert!(t.path("dst/b/g5999").exists());
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
}

/// A destination directory without search permission hides its files. The
/// batch holding the directory widens it, after the lookups for the batches
/// holding its files have been sent: those replies call the files missing,
/// and must not be used.
#[test]
fn lookups_sent_before_a_directory_was_widened_are_repeated() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    // `locked` sorts after the files beside it, so its own entry comes at
    // least a batch into the scan and its files fill the batches after.
    fill(&t.path("src/a"), "f");
    fill(&t.path("src/a/locked"), "g");
    assert_output_ok(&copy(&t, &rsh, &[]));
    let locked = t.path("dst/a/locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();

    let output = copy(&t, &rsh, &["--widen-dirs=rsync"]);
    let restored = fs::metadata(&locked).unwrap().mode() & 0o7777;
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (12,000 files)"), "{out}");
    assert_eq!(restored, 0o600);
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(
        withdrawn + repeated >= 1,
        "no lookup was in flight when the directory was widened: \
         sent {sent}, used {used}, discarded {discarded}"
    );
    // Each one dropped was asked again.
    assert!(batch_lookups(&t) > sent - withdrawn - repeated);
}

/// A new source directory is created by the batch that holds it, after the
/// lookups for the batches holding its files have been sent. Those lookups
/// are dropped before the creations go out, and their batches ask again.
#[test]
fn lookups_sent_before_a_directory_was_created_are_repeated() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f");
    assert_output_ok(&copy(&t, &rsh, &[]));
    fill(&t.path("src/a/new"), "g");

    let output = copy(&t, &rsh, &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 6,000 files"), "{out}");
    assert!(out.contains("unchanged (6,000 files)"), "{out}");
    assert!(out.contains("1 dirs created"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(
        withdrawn + repeated >= 1,
        "no lookup was in flight when the directory was created: \
         sent {sent}, used {used}, discarded {discarded}"
    );
    for index in [0, FILES - 1] {
        assert_eq!(
            read(&t.path(&format!("dst/a/new/g{index:04}"))),
            b"data",
            "file {index}"
        );
    }

    // And the copy that follows finds everything there.
    let output = copy(&t, &rsh, &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (12,000 files)"), "{out}");
}

/// Planning that fails with lookups in flight takes their replies before it
/// reports the failure, and reports what it would have without them: here a
/// destination directory that `--copy-if` cannot look inside, whose files
/// the early lookups asked about too.
#[test]
fn a_failed_batch_leaves_no_early_reply_unread() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f");
    fill(&t.path("src/a/locked"), "g");
    assert_output_ok(&copy(&t, &rsh, &[]));
    let locked = t.path("dst/a/locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();

    let output = copy(&t, &rsh, &["--copy-if", "not dst.exists"]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!output.status.success(), "{}", stdout(&output));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("a/locked"), "{err}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 1, "no lookup was sent early\n{err}");
    assert_eq!(
        used + repeated + withdrawn + discarded,
        sent,
        "an early reply was left unread"
    );
    assert!(
        repeated + withdrawn + discarded >= 1,
        "none was in flight at the failure"
    );
}
