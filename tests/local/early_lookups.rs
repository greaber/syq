//! Destination lookups a remote copy sends before their batch's turn.
//!
//! `SYQ_TEST_SCAN_AHEAD_WAIT` makes the scan hold every batch it may before
//! the planner takes the next one, so each lookup that can be sent early is.
//! `SYQ_TEST_EARLY_LOOKUPS` records what became of each: `sent`, then `used`,
//! `repeated` in the batch's turn, `withdrawn` while its batch still waits,
//! or `discarded`. `SYQ_TEST_EARLY_LOOKUPS_UNFILTERED` makes an early lookup
//! ask about the entries `--where` leaves out too.

use super::*;

/// Files in each of the fixtures' large directories: more than a scan batch.
const FILES: usize = 6000;

/// Put `files` files named `prefix` and a number in `directory`.
fn fill(directory: &Path, prefix: &str, files: usize) {
    fs::create_dir_all(directory).unwrap();
    for index in 0..files {
        fs::write(directory.join(format!("{prefix}{index:05}")), b"data").unwrap();
    }
}

/// A source whose directory `a/<last>` comes at least two batches after the
/// first, behind files that sort before it, with its own files filling the
/// batches after: by then lookups are being sent more than one batch ahead.
fn fill_with_late_directory(t: &Tmp, last: Option<&str>) {
    fill(&t.path("src/a"), "f", 2 * FILES);
    if let Some(last) = last {
        fill(&t.path(&format!("src/a/{last}")), "g", FILES);
    }
}

fn copy(t: &Tmp, rsh: &Path, extra: &[&str]) -> Output {
    copy_with(t, rsh, extra, &[])
}

fn copy_with(t: &Tmp, rsh: &Path, extra: &[&str], env: &[(&str, &str)]) -> Output {
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
        .envs(env.iter().copied())
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

/// How many non-directory paths the batch lookups asked about.
fn looked_up(t: &Tmp) -> usize {
    fs::read_to_string(t.path("lookups"))
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("batch "))
        .map(|counts| counts.split(' ').nth(1).unwrap().parse::<usize>().unwrap())
        .sum()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Selects the fixtures' files whose number ends in 0 or 5: a fifth.
const FIFTH: &str = r#"src.name matches "[05]$""#;

/// Whether the destination holds exactly the files `FIFTH` selects.
fn holds_the_fifth(t: &Tmp) -> bool {
    [("a", "f"), ("b", "g")].iter().all(|(directory, prefix)| {
        (0..FILES).all(|index| {
            t.path(&format!("dst/{directory}/{prefix}{index:05}"))
                .exists()
                == (index % 5 == 0)
        })
    })
}

/// An unchanged tree asks about every batch after the first before its
/// turn, uses each reply, and asks about none twice.
#[test]
fn unchanged_rerun_uses_every_lookup_it_sent_early() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", FILES);
    fill(&t.path("src/b"), "g", FILES);
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
    assert!(t.path("dst/b/g05999").exists());
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
    fill_with_late_directory(&t, Some("locked"));
    assert_output_ok(&copy(&t, &rsh, &[]));
    let locked = t.path("dst/a/locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();

    let output = copy(&t, &rsh, &["--widen-dirs=rsync"]);
    let restored = fs::metadata(&locked).unwrap().mode() & 0o7777;
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (18,000 files)"), "{out}");
    assert_eq!(restored, 0o600);
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(
        withdrawn + repeated >= 1,
        "no lookup was in flight when the directory was widened: \
         sent {sent}, used {used}, discarded {discarded}"
    );
    // The first batch asks in its turn, and so does the first batch after
    // the widening, whose early lookup was dropped.
    assert!(batch_lookups(&t) >= sent + 2);
}

/// A new source directory is created by the batch that holds it, after the
/// lookups for the batches holding its files have been sent. Those lookups
/// are dropped before the creations go out, and their batches ask again.
#[test]
fn lookups_sent_before_a_directory_was_created_are_repeated() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill_with_late_directory(&t, None);
    assert_output_ok(&copy(&t, &rsh, &[]));
    fill(&t.path("src/a/new"), "g", FILES);

    let output = copy(&t, &rsh, &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 6,000 files"), "{out}");
    assert!(out.contains("unchanged (12,000 files)"), "{out}");
    assert!(out.contains("1 dirs created"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(
        withdrawn + repeated >= 1,
        "no lookup was in flight when the directory was created: \
         sent {sent}, used {used}, discarded {discarded}"
    );
    for index in [0, FILES - 1] {
        assert_eq!(
            read(&t.path(&format!("dst/a/new/g{index:05}"))),
            b"data",
            "file {index}"
        );
    }

    // And the copy that follows finds everything there.
    let output = copy(&t, &rsh, &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (18,000 files)"), "{out}");
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
    fill_with_late_directory(&t, Some("locked"));
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

/// A copy with `--where` asks early about the entries it selects and no
/// others, so every early reply is used.
#[test]
fn a_filtered_rerun_uses_every_lookup_it_sent_early() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", FILES);
    fill(&t.path("src/b"), "g", FILES);
    let output = copy(&t, &rsh, &["--where", FIFTH]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 2,400 files"), "{out}");
    assert!(holds_the_fifth(&t));

    let output = copy_with(
        &t,
        &rsh,
        &["--where", FIFTH],
        &[("SYQ_TEST_SCANNED_SELECTION", &t.s("selection"))],
    );
    assert_output_ok(&output);
    assert_eq!(
        fs::read_to_string(t.path("selection"))
            .unwrap()
            .lines()
            .count(),
        2 * FILES
    );
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (2,400 files)"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
    // The first batch asks in its turn, and none asks about a file the
    // expression leaves out.
    assert_eq!(batch_lookups(&t), sent + 1);
    assert_eq!(looked_up(&t), 2400);

    // Changed and missing selected files are copied, and pruning keeps the
    // destination's copy of a source file the expression leaves out.
    fs::write(t.path("src/a/f00005"), b"longer").unwrap();
    fs::remove_file(t.path("dst/b/g05995")).unwrap();
    fs::write(t.path("dst/b/g00001"), b"kept").unwrap();
    fs::write(t.path("dst/b/extra"), b"extra").unwrap();
    let output = copy(&t, &rsh, &["--where", FIFTH, "--prune"]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 2 files"), "{out}");
    assert!(out.contains("unchanged (2,398 files)"), "{out}");
    assert_eq!(read(&t.path("dst/a/f00005")), b"longer");
    assert_eq!(read(&t.path("dst/b/g05995")), b"data");
    assert_eq!(read(&t.path("dst/b/g00001")), b"kept");
    assert!(!t.path("dst/b/extra").exists());
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
}

/// An early lookup that names entries the batch turns out not to hold once
/// `--where` has been applied is not used: the batch asks again in its turn
/// and the copy does what it would have.
#[test]
fn an_early_lookup_naming_unselected_entries_is_repeated() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", FILES);
    fill(&t.path("src/b"), "g", FILES);
    assert_output_ok(&copy(&t, &rsh, &["--where", FIFTH]));
    fs::remove_file(t.path("dst/b/g05995")).unwrap();
    // A file the expression leaves out is at the destination with other
    // content: the unfiltered lookup finds it, and it must stay as it is.
    fs::write(t.path("dst/b/g00001"), b"kept").unwrap();

    let output = copy_with(
        &t,
        &rsh,
        &["--where", FIFTH],
        &[("SYQ_TEST_EARLY_LOOKUPS_UNFILTERED", "1")],
    );
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 1 files"), "{out}");
    assert!(out.contains("unchanged (2,399 files)"), "{out}");
    assert_eq!(read(&t.path("dst/b/g00001")), b"kept");
    fs::remove_file(t.path("dst/b/g00001")).unwrap();
    assert!(holds_the_fifth(&t));
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (0, sent, 0, 0));
    // Every batch asked again in its turn.
    assert_eq!(batch_lookups(&t), 2 * sent + 1);
    assert!(looked_up(&t) > 2400);
}

/// An entry `--where` cannot be evaluated for ends the copy in its batch's
/// turn with the error it always gave. Nothing is asked early for that
/// batch, and no reply to an earlier one is left unread.
#[test]
fn a_batch_whose_selection_fails_is_not_looked_up_early() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", FILES);
    fill(&t.path("src/b"), "g", FILES);
    assert_output_ok(&copy(&t, &rsh, &[]));

    // Matching the link target of a regular file is an error.
    let failing = r#"src.name != "g05999" or src.link_target matches "x""#;
    let output = copy(&t, &rsh, &["--where", failing]);
    assert!(!output.status.success(), "{}", stdout(&output));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("--where"), "{err}");
    assert!(err.contains("b/g05999"), "{err}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    // The last batch holds the file. Had its lookup been sent, the failure
    // would have discarded the reply; the earlier ones were used.
    assert!(sent >= 1, "no lookup was sent early\n{err}");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
}

#[test]
fn remote_metadata_rerun_uses_early_lookups() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", FILES);
    // Preserve mtime for the unchanged-file comparison. Only macOS
    // destinations can set arbitrary birth times.
    let flags = if cfg!(target_os = "macos") {
        "--copy-metadata=mtime,permissions,acls,xattrs,atimes,crtimes"
    } else {
        "--copy-metadata=mtime,permissions,acls,xattrs,atimes"
    };
    assert_output_ok(&copy(&t, &rsh, &[flags]));
    let output = copy(&t, &rsh, &[flags]);
    assert_output_ok(&output);
    assert!(
        stdout(&output).contains("transferred 0 files"),
        "{}",
        stdout(&output)
    );
    assert!(fates(&t)[1] > 0, "expected an early rich lookup to be used");
}
