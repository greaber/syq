//! An interrupted copy removes the temporary files its receiver created and
//! did not publish, keeps per-file partials worth resuming, and ends within
//! a bounded time with the signal's usual status.
use super::*;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// A name another run's partial could have: it must survive interruption.
const FOREIGN: &str = ".f00.syq-tmp.abcdefghijklmnop";

/// Every sidecar below `root`, at any depth.
fn sidecars(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).into_iter().flatten().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                pending.push(path);
            } else if entry.file_name().to_string_lossy().contains(".syq-tmp.") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

fn own_sidecars(root: &Path) -> Vec<PathBuf> {
    sidecars(root)
        .into_iter()
        .filter(|path| path.file_name().unwrap() != FOREIGN)
        .collect()
}

/// Start the copy as a shell starts a job: in a process group of its own,
/// which its local receiver joins, as Ctrl-C reaches both.
fn start_job(command: &mut Command) -> Child {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .start()
        .unwrap()
}

fn signal_group(child: &Child, signal: i32) {
    assert_eq!(unsafe { libc::kill(-(child.id() as i32), signal) }, 0);
}

fn signal_process(child: &Child, signal: i32) {
    assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
}

/// Wait until every process that inherited the job's output has exited,
/// the receivers included, and return the coordinator's status, the job's
/// stderr, and how long that took.
fn finish(mut child: Child, deadline: Duration) -> (ExitStatus, String, Duration) {
    let started = Instant::now();
    let mut stderr = child.stderr.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        let _ = stdout.read_to_end(&mut Vec::new());
        let _ = sender.send(text);
    });
    match receiver.recv_timeout(deadline) {
        Ok(text) => (child.wait().unwrap(), text, started.elapsed()),
        Err(_) => {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
            panic!("the interrupted copy's processes did not all exit within {deadline:?}");
        }
    }
}

/// Poll until `condition` holds, for at most a minute.
fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut next_progress = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        if Instant::now() >= next_progress {
            eprintln!("waiting for {what}");
            next_progress += Duration::from_secs(5);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Small files, each different, and another run's partial in the
/// destination.
fn small_tree(t: &Tmp, count: usize) {
    for index in 0..count {
        write(
            &t.path(&format!("src/many/f{index:03}")),
            format!("file {index}\n").repeat(10).as_bytes(),
        );
    }
    write(
        &t.path(&format!("dst/many/{FOREIGN}")),
        b"another run's data",
    );
}

/// Every file the copy published matches its source.
fn assert_published_intact(t: &Tmp) {
    for entry in fs::read_dir(t.path("dst/many")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(".syq-tmp.") {
            continue;
        }
        assert_eq!(
            read(&entry.path()),
            read(&t.path(&format!("src/many/{name}"))),
            "{name}"
        );
    }
    assert_eq!(
        read(&t.path(&format!("dst/many/{FOREIGN}"))),
        b"another run's data"
    );
}

fn local_copy(t: &Tmp, tuning: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command.args([
        "cp",
        "--no-progress",
        "--performance-tuning",
        tuning,
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    command
}

fn remote_copy(t: &Tmp, route: &str, tuning: &str) -> Command {
    let rsh = fake_rsh(t);
    fs::create_dir_all(t.path("remote-home")).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args([
            "cp",
            "--no-progress",
            "--rsh",
            rsh.to_str().unwrap(),
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
            "--tcp-ports",
            EPHEMERAL_TCP_PORTS,
            "--performance-tuning",
            tuning,
        ])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"));
    if route.ends_with("ssh") {
        command.arg("--no-tcp");
    }
    if route.starts_with("pull") {
        command.args(["--from", "source"]);
    }
    if route == "push-shortcut" {
        // A few named files take the small-copy shortcut, staged by the
        // remote receiver's control connection.
        let mut names: Vec<_> = fs::read_dir(t.path("src/many"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        names.sort();
        command.args(names);
        command.args(["--to", "destination", "--into", &t.s("dst/many")]);
        return command;
    }
    command.args(["--srcs-in", &t.s("src")]);
    if route.starts_with("push") {
        command.args(["--to", "destination"]);
    }
    command.args(["--into", &t.s("dst")]);
    command
}

fn assert_rerun_completes(mut command: Command, t: &Tmp) {
    let out = command.run().unwrap();
    assert_output_ok(&out);
    assert_published_intact(t);
    assert_eq!(
        fs::read_dir(t.path("src/many")).unwrap().count() + 1,
        fs::read_dir(t.path("dst/many")).unwrap().count()
    );
    assert_eq!(own_sidecars(&t.path("dst")), Vec::<PathBuf>::new());
}

/// Interrupt a copy while its receiver holds unpublished stages: batches
/// of small files, or the small-copy shortcut's staged files.
fn interrupt_staged_small_files(route: &str, signal: i32) {
    let case = format!("{route} signal {signal}");
    let t = Tmp::new();
    let shortcut = route == "push-shortcut";
    small_tree(&t, if shortcut { 8 } else { 40 });
    let (tuning, ready_variable, continue_variable) = if shortcut {
        (
            "workers=2",
            "SYQ_TEST_SMALL_COPY_READY_FILE",
            "SYQ_TEST_SMALL_COPY_CONTINUE_FILE",
        )
    } else {
        (
            "workers=2,batch-files=8",
            "SYQ_TEST_SMALL_STAGE_READY_FILE",
            "SYQ_TEST_SMALL_STAGE_CONTINUE_FILE",
        )
    };
    let copy = |t: &Tmp| match route {
        "local" => local_copy(t, tuning),
        _ => remote_copy(t, route, tuning),
    };
    let ready = t.path("staged");
    let continuation = t.path("continue");
    let mut command = copy(&t);
    command
        .env(ready_variable, &ready)
        .env(continue_variable, &continuation);
    let mut child = start_job(&mut command);
    wait_for_confinement_marker(&mut child, &ready, "staged small files");
    wait_until("a staged small file", || {
        !own_sidecars(&t.path("dst")).is_empty()
    });
    let pushed = route.starts_with("push");
    if pushed {
        // A remote receiver shares no process group with the terminal: it
        // learns of the interruption when its connections close.
        signal_process(&child, signal);
    } else {
        signal_group(&child, signal);
    }
    if route == "push-ssh" || shortcut {
        // The connection that staged the files is held in the barrier: a
        // data worker in a process of its own, or the receiver's control.
        // Its stages go as soon as its connection closes; released, it
        // then fails to publish them.
        wait_until("the remote stages to be removed", || {
            own_sidecars(&t.path("dst")).is_empty()
        });
        release_confinement_barrier(&continuation);
    }
    let (status, stderr, elapsed) = finish(child, Duration::from_secs(20));
    assert_eq!(status.signal(), Some(signal), "{case}: {stderr}");
    if !pushed {
        // The receiver's cleanup is capped at half a second.
        assert!(elapsed < Duration::from_secs(5), "{case}: took {elapsed:?}");
    }
    assert_eq!(
        own_sidecars(&t.path("dst")),
        Vec::<PathBuf>::new(),
        "{case}: {stderr}"
    );
    assert_published_intact(&t);
    assert_rerun_completes(copy(&t), &t);
}

#[test]
fn an_interrupted_local_copy_removes_its_staged_small_files() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        interrupt_staged_small_files("local", signal);
    }
}

#[test]
fn an_interrupted_pull_removes_its_staged_small_files() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        interrupt_staged_small_files("pull", signal);
    }
}

#[test]
fn an_interrupted_push_removes_the_remote_staged_small_files() {
    // The coordinator dies at once, by SIGINT or SIGKILL alike; the remote
    // receiver cleans up because its control connection closes.
    for signal in [libc::SIGINT, libc::SIGKILL] {
        for route in ["push", "push-ssh", "push-shortcut"] {
            interrupt_staged_small_files(route, signal);
        }
    }
}

#[test]
fn an_interrupted_copy_keeps_partials_worth_resuming() {
    // Copied one at a time, a file's partial is kept for a rerun to reuse
    // when it is at least 1 MiB; a shorter one is removed.
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let t = Tmp::new();
        let long = prng(2 << 20, 31);
        let short = prng(300 << 10, 32);
        write(&t.path("src/many/long"), &long);
        write(&t.path("src/many/short"), &short);
        write(
            &t.path(&format!("dst/many/{FOREIGN}")),
            b"another run's data",
        );
        let ready = t.path("prepared");
        let continuation = t.path("continue");
        let tuning = "workers=2,copy-path=ranges";
        let mut command = local_copy(&t, tuning);
        command
            .env("SYQ_TEST_PARTIAL_READY_FILE", &ready)
            .env("SYQ_TEST_PARTIAL_CONTINUE_FILE", &continuation);
        let mut child = start_job(&mut command);
        wait_for_confinement_marker(&mut child, &ready, "prepared partials");
        // Both partials are prepared at their full length.
        wait_until("both prepared partials", || {
            let mut lengths: Vec<_> = own_sidecars(&t.path("dst"))
                .iter()
                .filter_map(|path| fs::metadata(path).ok())
                .map(|metadata| metadata.len())
                .collect();
            lengths.sort();
            lengths == [short.len() as u64, long.len() as u64]
        });
        signal_group(&child, signal);
        let (status, stderr, elapsed) = finish(child, Duration::from_secs(20));
        assert_eq!(status.signal(), Some(signal), "{stderr}");
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        let kept = own_sidecars(&t.path("dst"));
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(fs::metadata(&kept[0]).unwrap().len(), long.len() as u64);
        assert!(kept[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".long.syq-tmp."));
        assert!(!t.path("dst/many/long").exists());
        let out = local_copy(&t, tuning).run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst/many/long")), long);
        assert_eq!(read(&t.path("dst/many/short")), short);
    }
}

#[test]
fn an_interrupted_pull_removes_its_streamed_patch_stage() {
    // A file that differs by more than a grouped patch carries streams its
    // patch into a stage as large as the file.
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let t = Tmp::new();
        let source = prng(32 << 20, 33);
        let mut old = source.clone();
        old[..20 << 20].fill(b'q');
        write(&t.path("src/many/file"), &source);
        write(&t.path("dst/many/file"), &old);
        set_mtime(&t.path("dst/many/file"), 1);
        write(
            &t.path(&format!("dst/many/{FOREIGN}")),
            b"another run's data",
        );
        let ready = t.path("streamed");
        let continuation = t.path("continue");
        let mut command = remote_copy(&t, "pull", "workers=1");
        command
            .env("SYQ_TEST_PATCH_STREAM_RECHECK_READY_FILE", &ready)
            .env("SYQ_TEST_PATCH_STREAM_RECHECK_CONTINUE_FILE", &continuation);
        let mut child = start_job(&mut command);
        wait_for_confinement_marker(&mut child, &ready, "streamed patch pieces");
        wait_until("the streamed patch's stage", || {
            !own_sidecars(&t.path("dst")).is_empty()
        });
        signal_group(&child, signal);
        let (status, stderr, elapsed) = finish(child, Duration::from_secs(20));
        assert_eq!(status.signal(), Some(signal), "{stderr}");
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        assert_eq!(own_sidecars(&t.path("dst")), Vec::<PathBuf>::new());
        // The file it would have replaced is untouched.
        assert_eq!(read(&t.path("dst/many/file")), old);
        let out = remote_copy(&t, "pull", "workers=1").run().unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst/many/file")), source);
        assert_eq!(own_sidecars(&t.path("dst")), Vec::<PathBuf>::new());
    }
}

/// Interrupt a copy whose receiver's cleanup then stalls in a test barrier,
/// so that only its cap can end it:
///
/// - `local`: a local copy interrupted as a terminal does;
/// - `local-lost`: a local copy whose coordinator alone gets SIGTERM, so
///   that the receiver cleans up because its connection was lost;
/// - `push`: a push whose coordinator is killed, so that the remote
///   receiver cleans up because its connection was lost.
///
/// Their private temporary directories go in `tmp`.
fn interrupt_with_stalled_cleanup(t: &Tmp, route: &str, tmp: &Path) -> (Child, i32) {
    small_tree(t, 20);
    let staged = t.path("staged");
    let sweeping = t.path("sweeping");
    let tuning = "workers=1,batch-files=8";
    let mut command = match route {
        "push" => remote_copy(t, route, tuning),
        _ => local_copy(t, tuning),
    };
    command
        .env("TMPDIR", tmp)
        .env("SYQ_TEST_SMALL_STAGE_READY_FILE", &staged)
        .env("SYQ_TEST_SMALL_STAGE_CONTINUE_FILE", t.path("never"))
        .env("SYQ_TEST_SIDECAR_SWEEP_READY_FILE", &sweeping)
        .env("SYQ_TEST_SIDECAR_SWEEP_CONTINUE_FILE", t.path("never"));
    let mut child = start_job(&mut command);
    wait_for_confinement_marker(&mut child, &staged, "staged small files");
    let signal = match route {
        "local" => {
            signal_group(&child, libc::SIGINT);
            libc::SIGINT
        }
        "local-lost" => {
            signal_process(&child, libc::SIGTERM);
            libc::SIGTERM
        }
        _ => {
            signal_process(&child, libc::SIGKILL);
            libc::SIGKILL
        }
    };
    wait_until("the receiver's cleanup", || sweeping.exists());
    (child, signal)
}

/// The private socket directories left in `tmp`.
fn broker_directories(tmp: &Path) -> Vec<String> {
    fs::read_dir(tmp)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("syq-fd-"))
        .collect()
}

#[test]
fn an_interrupted_receiver_ends_by_its_cap_when_cleanup_stalls() {
    // The barrier would hold the cleanup for a minute; the cap of half a
    // second ends the receiver long before, whether a signal or a lost
    // connection started the cleanup.
    for route in ["local", "local-lost", "push"] {
        let t = Tmp::new();
        let tmp = test_support::short_tempdir().unwrap();
        let (child, signal) = interrupt_with_stalled_cleanup(&t, route, tmp.path());
        let (status, stderr, elapsed) = finish(child, Duration::from_secs(30));
        assert_eq!(status.signal(), Some(signal), "{route}: {stderr}");
        assert!(
            elapsed < Duration::from_secs(20),
            "{route}: took {elapsed:?}"
        );
        // It ended without removing what the stalled cleanup had not reached.
        assert!(!own_sidecars(&t.path("dst")).is_empty(), "{route}");
        // A killed coordinator leaves its own socket directory behind; the
        // others, the receiver's included, are removed first.
        if route != "push" {
            assert_eq!(
                broker_directories(tmp.path()),
                Vec::<String>::new(),
                "{route}"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn an_interrupted_local_copy_removes_its_whole_file_partials() {
    // A file copied whole on this machine is copied whole again by a rerun,
    // which never reads this partial, so it goes whatever its length.
    let t = Tmp::new();
    let data = prng(2 << 20, 34);
    write(&t.path("src/many/large"), &data);
    write(
        &t.path(&format!("dst/many/{FOREIGN}")),
        b"another run's data",
    );
    let ready = t.path("copied");
    let mut command = local_copy(&t, "workers=1");
    command
        .env("SYQ_TEST_COPY_LOCAL_COPIED_READY_FILE", &ready)
        .env("SYQ_TEST_COPY_LOCAL_COPIED_CONTINUE_FILE", t.path("never"));
    let mut child = start_job(&mut command);
    wait_for_confinement_marker(&mut child, &ready, "the local copy's full partial");
    let partials = own_sidecars(&t.path("dst"));
    assert_eq!(partials.len(), 1);
    assert_eq!(fs::metadata(&partials[0]).unwrap().len(), data.len() as u64);
    signal_group(&child, libc::SIGINT);
    let (status, stderr, elapsed) = finish(child, Duration::from_secs(20));
    assert_eq!(status.signal(), Some(libc::SIGINT), "{stderr}");
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
    assert_eq!(own_sidecars(&t.path("dst")), Vec::<PathBuf>::new());
    assert!(!t.path("dst/many/large").exists());
    assert_rerun_completes(local_copy(&t, "workers=1"), &t);
    assert_eq!(read(&t.path("dst/many/large")), data);
}
