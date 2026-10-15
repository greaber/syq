//! Every worker of a copy is served by the copy's one receiver process, and
//! that process writes a copy's files only through the descriptors it
//! created or opened them with.
use super::*;

/// The process IDs that served handed-over worker connections.
#[cfg(debug_assertions)]
fn serving_processes(events: &Path) -> Vec<String> {
    events_of(events, "served ")
}

#[cfg(debug_assertions)]
fn events_of(events: &Path, kind: &str) -> Vec<String> {
    fs::read_to_string(events)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix(kind).map(str::to_owned))
        .collect()
}

/// That every destination worker of a copy was handed over to one
/// receiver process, which served it: none served itself.
#[cfg(debug_assertions)]
fn assert_one_receiver(events: &Path, context: &str) -> usize {
    let served = serving_processes(events);
    let workers = events_of(events, "worker ");
    assert!(!served.is_empty(), "{context}: no handed-over worker");
    assert!(
        served
            .iter()
            .chain(&workers)
            .all(|process| process == &served[0]),
        "{context}: workers served by {workers:?}, handed to {served:?}"
    );
    assert_eq!(
        workers.len(),
        served.len(),
        "{context}: a worker served itself"
    );
    served.len()
}

/// A native copy of `src` into `dst` over the fake SSH transport, with no
/// TCP, recording which processes serve its workers.
#[cfg(debug_assertions)]
fn ssh_copy(t: &Tmp, tuning: &str) -> Command {
    let rsh = fake_rsh(t);
    fs::create_dir_all(t.path("remote-home")).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--rsh"])
        .arg(&rsh)
        .args(["--syq-path", env!("CARGO_BIN_EXE_syq")])
        .args(["--no-tcp", "--no-progress", "--performance-tuning", tuning])
        .args([
            "--srcs-in",
            &t.s("src"),
            "--to",
            "fake",
            "--into",
            &t.s("dst"),
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("SYQ_TEST_HANDED_WORKER_EVENTS", t.path("served"));
    command
}

#[cfg(debug_assertions)]
#[test]
fn workers_without_tcp_are_served_by_one_receiver_process() {
    // Each SSH session started for a worker hands its connection to the
    // copy's receiver, and a local copy hands it one end of a socket pair:
    // every worker runs in that one process.
    let local = |t: &Tmp| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(["cp", "--no-tcp", "--no-progress", "--performance-tuning"])
            .arg("workers=4,copy-path=ranges,request-size=1M")
            .args(["--srcs-in", &t.s("src"), "--into", &t.s("dst")])
            .env("SYQ_TEST_HANDED_WORKER_EVENTS", t.path("served"));
        command
    };
    for remote in [true, false] {
        let t = Tmp::new();
        let data = prng(24 << 20, 51);
        write(&t.path("src/big"), &data);
        for index in 0..20 {
            write(&t.path(&format!("src/small/{index}")), &prng(4096, index));
        }
        let mut command = if remote {
            ssh_copy(&t, "workers=4,copy-path=ranges,request-size=1M")
        } else {
            local(&t)
        };
        assert_output_ok(&command.run().unwrap());
        assert!(read(&t.path("dst/big")) == data);
        for index in 0..20 {
            assert_eq!(
                read(&t.path(&format!("dst/small/{index}"))),
                prng(4096, index)
            );
        }
        let served = assert_one_receiver(&t.path("served"), &format!("remote {remote}"));
        assert!(served >= 2, "remote {remote}: {served} handed-over workers");
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_dropped_ssh_worker_reconnects_to_the_same_receiver() {
    // A worker connection that drops mid-copy is opened again, and its new
    // SSH session hands it to the same receiver, which still holds the file
    // being written.
    let t = Tmp::new();
    let data = prng(24 << 20, 52);
    write(&t.path("src/big"), &data);
    let marker = t.path("dropped");
    // The bandwidth limit keeps the copy going while the dropped worker is
    // opened again.
    let out = ssh_copy(&t, "workers=2,copy-path=ranges,request-size=1M")
        .args(["--resource-limits", "bandwidth=8M"])
        .env("SYQ_TEST_DROP_AFTER_REQUEST", "write")
        .env("SYQ_TEST_DROP_AFTER_N_REQUESTS", "4")
        .env("SYQ_TEST_DROP_MARKER", &marker)
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert!(marker.exists());
    assert!(read(&t.path("dst/big")) == data);
    let served = assert_one_receiver(&t.path("served"), "dropped worker");
    assert!(served >= 3, "{served} handed-over workers");
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(debug_assertions)]
#[test]
fn automatic_ssh_workers_stay_within_the_receivers_open_file_limit() {
    // Every SSH worker runs in the copy's receiver process and shares its
    // open-file limit, so automatic tuning starts only as many as it allows.
    let t = Tmp::new();
    for index in 0..100 {
        write(&t.path(&format!("src/{index}")), &prng(2 << 20, index));
    }
    let out = ssh_copy(&t, "copy-path=ranges")
        .env("FAKE_REMOTE_NOFILE", "64")
        .run()
        .unwrap();
    assert_output_ok(&out);
    for index in 0..100 {
        assert!(
            read(&t.path(&format!("dst/{index}"))) == prng(2 << 20, index),
            "file {index}"
        );
    }
}

/// Put a file of our own, `planted`, at `name` in place of what is there,
/// which is moved aside, and return a descriptor of it to read it back.
#[cfg(debug_assertions)]
fn plant_at(name: &Path, aside: &Path) -> File {
    fs::rename(name, aside).unwrap();
    write(name, b"planted");
    fs::set_permissions(name, fs::Permissions::from_mode(0o644)).unwrap();
    set_mtime(name, 1_500_000_000);
    File::open(name).unwrap()
}

/// The planted file, unchanged: contents, mode and time.
#[cfg(debug_assertions)]
fn assert_untouched(planted: &File) {
    let mut contents = Vec::new();
    (&*planted).read_to_end(&mut contents).unwrap();
    assert!(
        contents == b"planted",
        "the planted file was written: it holds {} bytes",
        contents.len()
    );
    let metadata = planted.metadata().unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o644);
    assert_eq!(metadata.mtime(), 1_500_000_000);
}

#[cfg(debug_assertions)]
#[test]
fn range_writes_never_reach_a_file_put_at_the_stage_name() {
    // Someone who can rename entries in the destination swaps a file of
    // their own in for a large file's stage after Prepare created it. The
    // workers that write its ranges write the stage the receiver created,
    // never the file at its name; that file is never published, and the
    // copy reports the file as failed.
    for no_tcp in [false, true] {
        let t = Tmp::new();
        let data = prng(32 << 20, 53);
        write(&t.path("src/big"), &data);
        fs::create_dir_all(t.path("dst")).unwrap();
        let ready = t.path("partial-ready");
        let continuation = t.path("partial-continue");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args([
            "cp",
            "--no-progress",
            "--performance-tuning",
            // Small ranges, so that every worker writes some of them.
            "workers=4,copy-path=ranges,comparison-block-size=64K,split-min-size=256K,request-size=256K",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        if no_tcp {
            command.arg("--no-tcp");
        }
        let mut child = command
            .env("SYQ_TEST_PARTIAL_READY_FILE", &ready)
            .env("SYQ_TEST_PARTIAL_CONTINUE_FILE", &continuation)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()
            .unwrap();
        wait_for_confinement_marker(&mut child, &ready, "stage creation");
        let stages = partial_files(&t.path("dst"));
        assert_eq!(stages.len(), 1);
        let planted = plant_at(&stages[0], &t.path("moved-stage"));
        release_confinement_barrier(&continuation);
        let output = child.wait_with_output().unwrap();
        assert_untouched(&planted);
        assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
        assert!(
            stderr_of(&output).contains("is not the opened singly-linked regular file"),
            "{}",
            stderr_of(&output)
        );
        assert!(!t.path("dst/big").exists());
        // The copy's data went to the stage it created, wherever that is now.
        assert!(read(&t.path("moved-stage")) == data);
    }
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn finalize_never_publishes_a_file_put_at_the_stage_name() {
    // The same swap after a same-machine copy has written the whole stage,
    // before Finalize: the file at the stage's name gets none of the copy's
    // metadata and is not published, and the copy reports the file as
    // failed.
    let t = Tmp::new();
    let data = prng(8 << 20, 54);
    write(&t.path("src/big"), &data);
    fs::set_permissions(t.path("src/big"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src/big"), 1_600_000_000);
    fs::create_dir_all(t.path("dst")).unwrap();
    let ready = t.path("copied");
    let continuation = t.path("copied-continue");
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--no-progress",
            "--copy-metadata=permissions,times",
            "--performance-tuning",
            "workers=1",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ])
        .env("SYQ_TEST_COPY_LOCAL_COPIED_READY_FILE", &ready)
        .env("SYQ_TEST_COPY_LOCAL_COPIED_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "the local copy's stage");
    let stages = partial_files(&t.path("dst"));
    assert_eq!(stages.len(), 1);
    let planted = plant_at(&stages[0], &t.path("moved-stage"));
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_untouched(&planted);
    assert_eq!(output.status.code(), Some(23), "{}", stderr_of(&output));
    assert!(
        stderr_of(&output).contains("is not the opened singly-linked regular file"),
        "{}",
        stderr_of(&output)
    );
    assert!(!t.path("dst/big").exists());
    assert!(read(&t.path("moved-stage")) == data);
}

#[cfg(debug_assertions)]
#[test]
fn inplace_writes_never_reach_a_file_put_at_a_new_files_name() {
    // A new file written in place is created at its final name; a file put
    // there in its place after that gets none of the copy's data.
    let t = Tmp::new();
    let data = prng(32 << 20, 55);
    write(&t.path("src/big"), &data);
    fs::create_dir_all(t.path("dst")).unwrap();
    let ready = t.path("created");
    let continuation = t.path("created-continue");
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args([
            "cp",
            "--in-place=new",
            "--no-progress",
            "--performance-tuning",
            // Small ranges, so that every worker writes some of them.
            "workers=4,copy-path=ranges,comparison-block-size=64K,split-min-size=256K,request-size=256K",
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ])
        .env("SYQ_TEST_INPLACE_CREATED_READY_FILE", &ready)
        .env("SYQ_TEST_INPLACE_CREATED_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "in-place file creation");
    let planted = plant_at(&t.path("dst/big"), &t.path("moved-file"));
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert_untouched(&planted);
    // The copy's data went to the file it created, wherever that is now.
    assert!(
        read(&t.path("moved-file")) == data,
        "{}",
        stderr_of(&output)
    );
}
