//! On a network destination, a batch's new directories are created in small
//! requests sent one after another, and each directory's files go to workers
//! as soon as it exists. `SYQ_TEST_NETWORK_FILESYSTEM` makes every
//! destination count as a network filesystem.
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::time::{Duration, Instant};

const NETWORK: (&str, &str) = ("SYQ_TEST_NETWORK_FILESYSTEM", "1");

/// `count` directories `dNNN` below `src`, each holding a file `file`.
fn directories_with_files(t: &Tmp, count: usize) {
    for index in 0..count {
        write(
            &t.path(&format!("src/d{index:03}/file")),
            format!("file {index}\n").as_bytes(),
        );
    }
}

fn copy_into_dst(t: &Tmp) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--no-progress", "--srcs-in", &t.s("src"), "--into"])
        .arg(t.path("dst"))
        .env(NETWORK.0, NETWORK.1);
    command
}

/// Hold the receiver just before it creates the directory whose path ends
/// with `suffix`, until `release_confinement_barrier`.
fn hold_directory(command: &mut Command, t: &Tmp, suffix: &str) -> (PathBuf, PathBuf) {
    let ready = t.path("held");
    let continuation = t.path("continue");
    command
        .env("SYQ_TEST_DESTINATION_MUTATION_SUFFIX", suffix)
        .env("SYQ_TEST_DESTINATION_MUTATION_READY_FILE", &ready)
        .env("SYQ_TEST_DESTINATION_MUTATION_CONTINUE_FILE", &continuation);
    (ready, continuation)
}

fn existing_directories(t: &Tmp, count: usize) -> Vec<usize> {
    (0..count)
        .filter(|index| t.path(&format!("dst/d{index:03}")).exists())
        .collect()
}

#[test]
fn files_go_to_workers_before_the_last_directory_exists() {
    let t = Tmp::new();
    directories_with_files(&t, 16);
    let mut command = copy_into_dst(&t);
    let (ready, continuation) = hold_directory(&mut command, &t, "/d015");
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "the last directory's creation");
    // The receiver waits before creating the batch's last directory, and the
    // first directory's file has been copied meanwhile. Before, every file
    // waited for every directory of its batch.
    let first = t.path("dst/d000/file");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !first.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "syq exited while the last directory was held"
        );
        assert!(
            Instant::now() < deadline,
            "no file was copied while the last directory was held"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(read(&first), b"file 0\n");
    assert!(!t.path("dst/d015").exists());
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_output_ok(&output);
    for index in 0..16 {
        assert_eq!(
            read(&t.path(&format!("dst/d{index:03}/file"))),
            format!("file {index}\n").as_bytes()
        );
    }
}

/// A tree with a hard link and old directory times, and two destinations
/// holding extras: `dst-network` and `dst-local`.
fn tree_with_extras(t: &Tmp) {
    write(&t.path("src/a/one"), b"one");
    write(&t.path("src/a/b/two"), b"two");
    write(&t.path("src/c/three"), b"three");
    fs::hard_link(t.path("src/a/one"), t.path("src/c/linked")).unwrap();
    for directory in ["a/b", "a", "c"] {
        set_mtime(&t.path(&format!("src/{directory}")), 1_000_000_000);
    }
    for destination in ["dst-network", "dst-local"] {
        write(&t.path(&format!("{destination}/a/extra")), b"extra");
        write(&t.path(&format!("{destination}/gone/extra")), b"extra");
    }
}

fn rsync_into(t: &Tmp, flags: &str, destination: &str, network: bool) {
    let mut command = compat_command();
    command.args([
        flags,
        "--delete",
        "--no-progress",
        &t.s("src/"),
        &t.s(destination),
    ]);
    if network {
        command.env(NETWORK.0, NETWORK.1);
    }
    assert_output_ok(&command.run().unwrap());
}

#[test]
fn pruning_and_directory_times_are_as_without_a_network_destination() {
    let t = Tmp::new();
    tree_with_extras(&t);
    for (destination, network) in [("dst-network", true), ("dst-local", false)] {
        rsync_into(&t, "-a", destination, network);
        // Extras are pruned, and each directory has its source's time: its
        // metadata came after its contents.
        assert_same_tree(&t.path("src"), &t.path(destination));
    }
}

#[test]
fn hard_links_are_as_without_a_network_destination() {
    // A copy that keeps hard links plans every file before copying any, so
    // it creates its directories as on a local filesystem.
    let t = Tmp::new();
    tree_with_extras(&t);
    for (destination, network) in [("dst-network", true), ("dst-local", false)] {
        rsync_into(&t, "-aH", destination, network);
        assert_same_tree(&t.path("src"), &t.path(destination));
        assert_eq!(
            fs::metadata(t.path(&format!("{destination}/a/one")))
                .unwrap()
                .ino(),
            fs::metadata(t.path(&format!("{destination}/c/linked")))
                .unwrap()
                .ino(),
            "{destination}: the hard link was not kept"
        );
    }
}

#[test]
fn a_directory_that_cannot_be_created_fails_its_files_as_without_a_network_destination() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipping: root can create directories anywhere");
        return;
    }
    let outcomes: Vec<(Option<i32>, Vec<String>)> = [true, false]
        .into_iter()
        .map(|network| {
            let t = Tmp::new();
            write(&t.path("src/locked/sub/file"), b"locked");
            write(&t.path("src/open/sub/file"), b"open");
            fs::create_dir_all(t.path("dst/locked")).unwrap();
            fs::set_permissions(t.path("dst/locked"), fs::Permissions::from_mode(0o555)).unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
            command.args([
                "cp",
                "--no-progress",
                "--results",
                &t.s("results.ndjson"),
                "--srcs-in",
                &t.s("src"),
                "--into",
                &t.s("dst"),
            ]);
            if network {
                command.env(NETWORK.0, NETWORK.1);
            }
            let output = command.run().unwrap();
            fs::set_permissions(t.path("dst/locked"), fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(read(&t.path("dst/open/sub/file")), b"open");
            assert!(!t.path("dst/locked/sub").exists());
            // Two errors: the directory, reported once, and its file. Its
            // final metadata is not attempted.
            let records: Vec<serde_json::Value> = fs::read_to_string(t.path("results.ndjson"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let failed: Vec<(&str, &str)> = records
                .iter()
                .filter(|record| record["disposition"] == "failed")
                .map(|record| {
                    (
                        record["action"].as_str().unwrap(),
                        record["dst"]["value"].as_str().unwrap(),
                    )
                })
                .collect();
            assert_eq!(
                failed,
                [
                    ("create_directory", "locked/sub"),
                    ("transfer_file", "locked/sub/file")
                ],
                "{}",
                stderr_of(&output)
            );
            assert_eq!(records.last().unwrap()["errors"], 2);
            let mut lines: Vec<String> = stderr_of(&output)
                .replace(&t.s(""), "TMP/")
                .lines()
                .map(str::to_owned)
                .collect();
            lines.sort();
            (output.status.code(), lines)
        })
        .collect();
    assert_ne!(outcomes[0].0, Some(0), "{:?}", outcomes[0].1);
    assert_eq!(outcomes[0], outcomes[1]);
}

#[test]
fn a_lack_of_space_while_creating_directories_stops_the_rest() {
    // Directories go in requests of two per parent at first, at most four
    // requests at a time: once one fails for lack of space, the requests
    // already sent run, and no other is sent. Requests double at most once
    // for each reply read, so the three sent before the failing one's reply
    // was read hold at most 16, 32 and 64 directories (`Pacing`).
    let t = Tmp::new();
    directories_with_files(&t, 300);
    let output = copy_into_dst(&t)
        .env("SYQ_TEST_FAIL_APPLY_ENOSPC", "/d010")
        .run()
        .unwrap();
    assert!(!output.status.success(), "{}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains("injected capacity failure"),
        "{}",
        stderr_of(&output)
    );
    let created = existing_directories(&t, 300);
    assert!(!created.contains(&10), "{created:?}");
    assert!(
        created.iter().all(|&index| index < 150),
        "directories were created after the failure: {created:?}"
    );
}

#[test]
fn an_interrupted_copy_creates_no_directories_after_the_signal() {
    let t = Tmp::new();
    directories_with_files(&t, 40);
    let mut command = copy_into_dst(&t);
    let (ready, _) = hold_directory(&mut command, &t, "/d010");
    // A job of its own, which its local receiver joins, as Ctrl-C reaches both.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "a directory's creation");
    assert_eq!(unsafe { libc::kill(-(child.id() as i32), libc::SIGINT) }, 0);
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGINT),
        "{}",
        stderr_of(&output)
    );
    // The receiver takes requests in order, so nothing after the held
    // request was created. That request was sent before the third reply was
    // read, so it holds at most eight directories in one parent (`Pacing`).
    let created = existing_directories(&t, 40);
    assert!(
        created.iter().all(|&index| index < 20),
        "directories were created after the signal: {created:?}"
    );
    // Running the copy again completes it.
    assert_output_ok(&copy_into_dst(&t).run().unwrap());
    for index in 0..40 {
        assert_eq!(
            read(&t.path(&format!("dst/d{index:03}/file"))),
            format!("file {index}\n").as_bytes()
        );
    }
}
