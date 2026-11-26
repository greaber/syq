//! Destination lookups a remote copy sends before their batch's turn.
//!
//! `SYQ_TEST_SCAN_AHEAD_WAIT` makes the scan hold every batch it may before
//! the planner takes the next one, so each lookup that can be sent early is.
//! `SYQ_TEST_EARLY_LOOKUPS` records what became of each: `sent`, then `used`,
//! `deferred` to chunked lookups, `repeated` in the batch's turn, `withdrawn`
//! while its batch still waits, or `discarded`.
//! `SYQ_TEST_EARLY_LOOKUPS_UNFILTERED` makes an early lookup
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

pub(super) fn copy(t: &Tmp, rsh: &Path, extra: &[&str]) -> Output {
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
    // Reading a file during the first copy may advance its source atime.
    // Give both scans the same atimes so the rerun needs no metadata fixes.
    let times = fs::FileTimes::new().set_accessed(std::time::SystemTime::now());
    let reset_atimes = || {
        for index in 0..FILES {
            fs::File::open(t.path(&format!("src/a/f{index:05}")))
                .unwrap()
                .set_times(times)
                .unwrap();
        }
    };
    reset_atimes();
    assert_output_ok(&copy(&t, &rsh, &[flags]));
    reset_atimes();
    let output = copy(&t, &rsh, &[flags]);
    assert_output_ok(&output);
    assert!(
        stdout(&output).contains("transferred 0 files"),
        "{}",
        stdout(&output)
    );
    let early = fs::read_to_string(t.path("early")).unwrap();
    assert!(early.lines().any(|line| line == "used"), "{early}");
    assert!(!early.lines().any(|line| line == "deferred"), "{early}");
}

pub(super) fn files_from_copy_with(
    t: &Tmp,
    rsh: &Path,
    list: &Path,
    extra: &[&str],
    env: &[(&str, &str)],
) -> Output {
    for log in ["early", "lookups"] {
        let _ = fs::remove_file(t.path(log));
    }
    compat_command()
        .args(["-a", "--files-from"])
        .arg(list)
        .args(["-e"])
        .arg(rsh)
        .args([
            "--rsync-path",
            env!("CARGO_BIN_EXE_syq"),
            "--syq-no-tcp",
            "--no-progress",
        ])
        .args(extra)
        .arg(t.path("src"))
        .arg(format!("host:{}", t.s("dst")))
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

#[test]
fn files_from_explicit_list_uses_early_lookups_on_rerun() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let total = 2 * FILES + 500;
    fill(&t.path("src/a"), "f", total);
    let list: String = (0..total).map(|i| format!("a/f{i:05}\n")).collect();
    write(&t.path("list"), list.as_bytes());
    assert_output_ok(&files_from_copy_with(&t, &rsh, &t.path("list"), &[], &[]));

    let output = files_from_copy_with(&t, &rsh, &t.path("list"), &[], &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (12,500 files)"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
    assert_eq!(batch_lookups(&t), sent + 1);
}

/// Repeat each name to fill one 4,096-line chunk without needing thousands
/// of files. Each chunk should yield exactly one lookup on an unchanged run.
#[test]
fn files_from_rerun_keeps_four_batch_replies_in_flight() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let mut list = String::new();
    for i in 0..10 {
        write(&t.path(&format!("src/f{i}")), b"data");
        list.push_str(&format!("f{i}\n").repeat(4096));
    }
    write(&t.path("list"), list.as_bytes());
    for _ in 0..2 {
        assert_output_ok(&files_from_copy_with(&t, &rsh, &t.path("list"), &[], &[]));
    }
    let events = fs::read_to_string(t.path("early")).unwrap();
    let mut pending = 0usize;
    let mut peak = 0;
    for event in events.lines() {
        match event {
            "sent 0 1" => pending += 1,
            "used" => pending = pending.checked_sub(1).unwrap(),
            other => panic!("unexpected lookup event {other}: {events}"),
        }
        peak = peak.max(pending);
    }
    assert_eq!((pending, peak), (0, 4), "{events}");
    assert_eq!(batch_lookups(&t), 10);
}

#[test]
fn files_from_recursive_selected_dirs_use_early_lookups_on_rerun() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", FILES);
    fill(&t.path("src/b"), "g", FILES);
    write(&t.path("list"), b"a\nb\n");
    assert_output_ok(&files_from_copy_with(
        &t,
        &rsh,
        &t.path("list"),
        &["-r"],
        &[],
    ));

    let output = files_from_copy_with(&t, &rsh, &t.path("list"), &["-r"], &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (12,000 files)"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
    // One lookup for the list chunk (`["a", "b"]`), one for the first scan batch.
    assert_eq!(batch_lookups(&t), sent + 2);
}

#[test]
fn files_from_recursive_with_explicit_child_before_dir_deduplicates_with_early_lookups() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", FILES);
    fill(&t.path("src/b"), "g", FILES);
    write(&t.path("list"), b"a/f00000\nb/g03000\na\nb\n");
    let first = files_from_copy_with(&t, &rsh, &t.path("list"), &["-r"], &[]);
    assert_output_ok(&first);
    assert_eq!(transferred(&stdout(&first)), (2 * FILES) as u64);

    let output = files_from_copy_with(&t, &rsh, &t.path("list"), &["-r"], &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 0 files"), "{out}");
    assert!(out.contains("unchanged (12,000 files)"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "{sent} lookups were sent early");
    assert_eq!((used, repeated, withdrawn, discarded), (sent, 0, 0, 0));
    assert_eq!(batch_lookups(&t), sent + 2);
}

#[test]
fn files_from_late_directory_and_apply_failure_keep_early_replies_balanced() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", 2 * FILES);
    let mut initial_list = String::new();
    for i in 0..2 * FILES {
        initial_list.push_str(&format!("a/f{i:05}\n"));
    }
    write(&t.path("initial-list"), initial_list.as_bytes());
    assert_output_ok(&files_from_copy_with(
        &t,
        &rsh,
        &t.path("initial-list"),
        &[],
        &[],
    ));

    // Add a late directory in chunks after `a` so early lookups for `z_late`
    // are in flight when creating `dst/z_late`.
    fill(&t.path("src/z_late"), "g", FILES);
    let mut full_list = initial_list.clone();
    for i in 0..FILES {
        full_list.push_str(&format!("z_late/g{i:05}\n"));
    }
    write(&t.path("full-list"), full_list.as_bytes());
    let output = files_from_copy_with(&t, &rsh, &t.path("full-list"), &[], &[]);
    assert_output_ok(&output);
    let out = stdout(&output);
    assert!(out.contains("transferred 6,000 files"), "{out}");
    assert!(out.contains("unchanged (12,000 files)"), "{out}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "expected early lookups: {sent}");
    assert_eq!(used + repeated + withdrawn + discarded, sent);
    assert!(
        withdrawn + repeated >= 1,
        "expected withdrawn/repeated lookups when creating late directory"
    );
    assert_eq!(read(&t.path("dst/z_late/g05999")), b"data");

    // Failing directory creation mid-stream with ENOSPC while later chunks'
    // early lookups are in flight must still consume every sent lookup.
    write(&t.path("src/z_fail/h00000"), b"fail");
    fill(&t.path("src/z_more"), "k", FILES);
    let mut fail_list = initial_list;
    fail_list.push_str("z_fail/h00000\n");
    for i in 0..FILES {
        fail_list.push_str(&format!("z_more/k{i:05}\n"));
    }
    write(&t.path("fail-list"), fail_list.as_bytes());
    let output = files_from_copy_with(
        &t,
        &rsh,
        &t.path("fail-list"),
        &[],
        &[("SYQ_TEST_FAIL_APPLY_ENOSPC", "z_fail")],
    );
    assert!(!output.status.success(), "{}", stdout(&output));
    let err = stderr_of(&output);
    assert!(err.contains("z_fail"), "{err}");
    let [sent, used, repeated, withdrawn, discarded] = fates(&t);
    assert!(sent >= 2, "expected early lookups before failure: {sent}");
    assert_eq!(used + repeated + withdrawn + discarded, sent);
    assert!(
        repeated + withdrawn + discarded >= 1,
        "expected unconsumed early lookups drained on failure"
    );
}

#[test]
fn files_from_across_chunks_handles_duplicates_bad_chains_and_late_parents() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fill(&t.path("src/a"), "f", 5000);
    write(&t.path("src/bad/ok"), b"valid");
    write(&t.path("src/file_as_dir"), b"plain");
    let mut list = String::from("bad/missing/x\nfile_as_dir\n");
    for i in 0..5000 {
        list.push_str(&format!("a/f{i:05}\n"));
    }
    // Past the 4,096-line chunk boundary: duplicate spellings, valid child under
    // `bad` whose earlier chain failed, and a child through a non-directory leaf.
    list.push_str("a//f00000\n./a/./f00000/\nbad/ok\nfile_as_dir/sub\n");
    write(&t.path("list"), list.as_bytes());
    let output = files_from_copy_with(&t, &rsh, &t.path("list"), &[], &[]);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("bad/missing/x"), "{err}");
    assert!(err.contains("file_as_dir/sub"), "{err}");
    assert_eq!(transferred(&stdout(&output)), 5002);
    assert_eq!(read(&t.path("dst/bad/ok")), b"valid");
    assert!(!t.path("dst/bad/missing").exists());
}
