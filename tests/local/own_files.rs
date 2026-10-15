//! syq writes contents only into files a copy creates, and changes an
//! existing file's metadata in place only where it can vouch for the file.
//! Anything else is replaced, as a changed file is.

use super::*;
use std::os::unix::ffi::OsStrExt as _;

/// The routes these copies take: on this machine, through ranged writes,
/// and to a remote helper over SSH and over TCP.
const ROUTES: [&str; 4] = ["local", "ranges", "ssh", "tcp"];

/// `syq rsync` with `args`, from `src/` to `dst/`, by `route`.
fn rsync(t: &Tmp, route: &str, args: &[&str]) -> Output {
    rsync_with(t, route, args, &[])
}

/// `rsync` with `env` set for syq and its remote helper.
fn rsync_with(t: &Tmp, route: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = if matches!(route, "ssh" | "tcp") {
        let rsh = fake_rsh(t);
        if !t.path("remote-bin/syq").exists() {
            t.expose_remote_syq();
        }
        let mut command = compat_command();
        command
            .arg("-e")
            .arg(rsh)
            .args(["--syq-no-bootstrap", "--syq-tcp-ports", EPHEMERAL_TCP_PORTS])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"));
        if route == "tcp" {
            command
                .arg("--syq-no-tcp-encryption")
                .env("SYQ_TEST_REQUIRE_TCP", "1");
        } else {
            command.arg("--syq-no-tcp");
        }
        command
            .args(args)
            .arg(t.s("src/"))
            .arg(format!("127.0.0.1:{}/", t.s("dst")));
        command
    } else {
        let mut command = compat_command();
        if route == "ranges" {
            command.args(["--performance-tuning", "copy-path=ranges"]);
        }
        command.args(args).arg(t.s("src/")).arg(t.s("dst/"));
        command
    };
    command.envs(env.iter().copied());
    command.arg("--no-progress").run().unwrap()
}

fn inode(path: &Path) -> u64 {
    fs::metadata(path).unwrap().ino()
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// A planted hard link to a file outside the destination never sees a
/// metadata-only change: whether the copy finds the file unchanged by its
/// size and time, or compares it and finds its contents match, it gives the
/// name a new file, and the other name keeps the old one as it was.
#[test]
fn a_metadata_only_change_never_reaches_a_planted_hard_link() {
    for route in ROUTES {
        for compared in [false, true] {
            let t = Tmp::new();
            let contents = prng(3 << 20, 501);
            write(&t.path("src/file"), &contents);
            write(&t.path("dst/file"), &contents);
            fs::hard_link(t.path("dst/file"), t.path("outside")).unwrap();
            fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o644)).unwrap();
            set_mtime(&t.path("src/file"), 1_700_000_000);
            // Matching times leave only the mode to change; a newer source
            // time sends the file to be compared, and it matches.
            set_mtime(
                &t.path("dst/file"),
                if compared {
                    1_600_000_000
                } else {
                    1_700_000_000
                },
            );
            let before = fs::metadata(t.path("outside")).unwrap();
            let out = rsync(&t, route, &["-a"]);
            let case = format!("{route}, compared={compared}");
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst/file")), contents, "{case}");
            assert_eq!(mode(&t.path("dst/file")), 0o600, "{case}");
            assert_eq!(
                fs::metadata(t.path("dst/file")).unwrap().mtime(),
                1_700_000_000,
                "{case}"
            );
            assert_ne!(inode(&t.path("dst/file")), before.ino(), "{case}");
            let after = fs::metadata(t.path("outside")).unwrap();
            assert_eq!(
                (after.ino(), after.mode() & 0o7777, after.mtime()),
                (before.ino(), 0o644, before.mtime()),
                "{case}"
            );
            assert!(partial_files(&t.0).is_empty(), "{case}");
        }
    }
}

/// `--inplace` writes no contents into a file it did not create, so a
/// planted hard link to one keeps its contents.
#[test]
fn in_place_never_writes_into_a_planted_hard_link() {
    for route in ROUTES {
        let t = Tmp::new();
        let old = prng(3 << 20, 502);
        let new = prng(3 << 20, 503);
        write(&t.path("src/file"), &new);
        write(&t.path("dst/file"), &old);
        fs::hard_link(t.path("dst/file"), t.path("outside")).unwrap();
        set_mtime(&t.path("src/file"), 1_700_000_000);
        let out = rsync(&t, route, &["-a", "--inplace"]);
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst/file")), new, "{route}");
        assert_eq!(read(&t.path("outside")), old, "{route}");
        assert_ne!(
            inode(&t.path("dst/file")),
            inode(&t.path("outside")),
            "{route}"
        );
    }
}

/// `--inplace` never writes new contents into an existing file, which
/// someone may have opened while its mode let them: a reader that opened it
/// before the copy reads only what was there.
#[test]
fn in_place_never_writes_into_a_file_someone_has_open() {
    for route in ROUTES {
        let t = Tmp::new();
        let old = prng(3 << 20, 504);
        let new = prng(3 << 20, 505);
        write(&t.path("src/file"), &new);
        fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o600)).unwrap();
        set_mtime(&t.path("src/file"), 1_700_000_000);
        write(&t.path("dst/file"), &old);
        fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o644)).unwrap();
        let reader = File::open(t.path("dst/file")).unwrap();
        let out = rsync(&t, route, &["-a", "--inplace"]);
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst/file")), new, "{route}");
        assert_eq!(mode(&t.path("dst/file")), 0o600, "{route}");
        let mut seen = Vec::new();
        (&reader).read_to_end(&mut seen).unwrap();
        assert_eq!(seen, old, "{route}: the old file's reader saw new data");
        assert_eq!(reader.metadata().unwrap().mode() & 0o7777, 0o644, "{route}");
    }
}

/// `--in-place=new` writes a new file at its name; syq cp refuses the
/// earlier `--inplace`, naming it, and syq rsync's `--inplace` selects it.
#[test]
fn in_place_new_replaces_cp_inplace_and_rsync_inplace_selects_it() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"contents");
    fs::create_dir_all(t.path("dst")).unwrap();
    let refused = native_syq(&["cp", "--inplace", &t.s("src/file"), "--into", &t.s("dst")]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        stderr_of(&refused).contains("--in-place=new"),
        "{refused:?}"
    );
    assert!(!t.path("dst/file").exists());
    run_native_ok(&[
        "cp",
        "--in-place=new",
        &t.s("src/file"),
        "--into",
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/file")), b"contents");
    fs::remove_file(t.path("dst/file")).unwrap();
    run_ok(&["-a", "--inplace", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/file")), b"contents");
    assert!(partial_files(&t.0).is_empty());
}

/// `--as-new` publishes its file without replacing anything: a file that
/// appears at its name while it is copied is kept, and the copy fails.
#[cfg(debug_assertions)]
#[test]
fn as_new_keeps_a_file_that_appears_while_it_is_copied() {
    let t = Tmp::new();
    write(&t.path("src/file"), &prng(3 << 20, 506));
    fs::create_dir_all(t.path("dst")).unwrap();
    let ready = t.path("ready");
    let continuation = t.path("continue");
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "-q", "--performance-tuning", "copy-path=ranges"])
        .arg(t.path("src/file"))
        .arg("--as-new")
        .arg(t.path("dst/new"))
        .env("SYQ_TEST_SOURCE_RECHECK_READY_FILE", &ready)
        .env("SYQ_TEST_SOURCE_RECHECK_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "source recheck before publication");
    write(&t.path("dst/new"), b"theirs");
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    assert_eq!(read(&t.path("dst/new")), b"theirs");
}

/// A symlink or FIFO whose requested metadata differs is created again with
/// it, and published over the old one: nothing changes an existing entry by
/// its name, and the FIFO gets a new identity.
#[test]
fn a_symlink_or_fifo_whose_metadata_differs_is_created_again() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("src")).unwrap();
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink("target", t.path("src/link")).unwrap();
    std::os::unix::fs::symlink("target", t.path("dst/link")).unwrap();
    mkfifo(&t.path("src/fifo"));
    mkfifo(&t.path("dst/fifo"));
    fs::set_permissions(t.path("src/fifo"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(t.path("dst/fifo"), fs::Permissions::from_mode(0o644)).unwrap();
    let set_link_mtime = |path: &Path, seconds: i64| {
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: seconds as _,
                tv_nsec: 0,
            },
        ];
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0
        );
    };
    set_link_mtime(&t.path("src/link"), 1_700_000_000);
    set_link_mtime(&t.path("dst/link"), 1_600_000_000);
    set_link_mtime(&t.path("src/fifo"), 1_700_000_000);
    set_link_mtime(&t.path("dst/fifo"), 1_700_000_000);
    let link_before = fs::symlink_metadata(t.path("dst/link")).unwrap().ino();
    let fifo_before = fs::symlink_metadata(t.path("dst/fifo")).unwrap().ino();
    run_ok(&["-aD", &t.s("src/"), &t.s("dst/")]);
    let link = fs::symlink_metadata(t.path("dst/link")).unwrap();
    assert_eq!(
        fs::read_link(t.path("dst/link")).unwrap(),
        Path::new("target")
    );
    assert_eq!(link.mtime(), 1_700_000_000);
    assert_ne!(link.ino(), link_before);
    let fifo = fs::symlink_metadata(t.path("dst/fifo")).unwrap();
    assert!(fifo.file_type().is_fifo());
    assert_eq!(fifo.mode() & 0o7777, 0o600);
    assert_ne!(fifo.ino(), fifo_before);
}

/// With `-H`, a group whose metadata changes is not changed through the
/// names it has: its representative is replaced, the group's other names
/// are linked to the new file, and a name outside the copy keeps the old
/// one.
#[test]
fn a_hard_link_group_is_linked_again_after_a_metadata_change() {
    for route in ROUTES {
        let t = Tmp::new();
        let contents = prng(1 << 20, 507);
        write(&t.path("src/a"), &contents);
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o600)).unwrap();
        set_mtime(&t.path("src/a"), 1_700_000_000);
        write(&t.path("dst/a"), &contents);
        fs::hard_link(t.path("dst/a"), t.path("dst/b")).unwrap();
        fs::hard_link(t.path("dst/a"), t.path("outside")).unwrap();
        fs::set_permissions(t.path("dst/a"), fs::Permissions::from_mode(0o644)).unwrap();
        set_mtime(&t.path("dst/a"), 1_700_000_000);
        let old = inode(&t.path("dst/a"));
        let out = rsync(&t, route, &["-aH"]);
        assert_output_ok(&out);
        assert_eq!(inode(&t.path("dst/a")), inode(&t.path("dst/b")), "{route}");
        assert_ne!(inode(&t.path("dst/a")), old, "{route}");
        assert_eq!(mode(&t.path("dst/a")), 0o600, "{route}");
        assert_eq!(read(&t.path("dst/b")), contents, "{route}");
        assert_eq!(inode(&t.path("outside")), old, "{route}");
        assert_eq!(mode(&t.path("outside")), 0o644, "{route}");
    }
}

/// A preview counts a file whose metadata the receiver cannot change in
/// place as one it rewrites, with its bytes, not as a metadata-only entry,
/// whether or not it is copied as a hard-link group.
#[test]
fn a_preview_counts_a_replaced_file_as_rewritten() {
    for hardlinks in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/file"), b"same contents");
        write(&t.path("dst/file"), b"same contents");
        if hardlinks {
            fs::hard_link(t.path("src/file"), t.path("src/alias")).unwrap();
            fs::hard_link(t.path("dst/file"), t.path("dst/alias")).unwrap();
        }
        fs::hard_link(t.path("dst/file"), t.path("outside")).unwrap();
        fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o644)).unwrap();
        set_mtime(&t.path("src/file"), 1_700_000_000);
        set_mtime(&t.path("dst/file"), 1_700_000_000);
        let results = t.path("results.jsonl");
        let metadata = if hardlinks {
            "--copy-metadata=permissions,mtime,hardlinks"
        } else {
            "--copy-metadata=permissions,mtime"
        };
        let out = native_syq(&[
            "cp",
            "--dry-run",
            metadata,
            "--results",
            &results.to_string_lossy(),
            "--srcs-in",
            &t.s("src"),
            "--into",
            &t.s("dst"),
        ]);
        assert_output_ok(&out);
        let records = fs::read_to_string(&results).unwrap();
        let traces: Vec<serde_json::Value> = records
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|record| record["action"] == "transfer_file")
            .collect();
        let trace = traces
            .iter()
            .find(|record| record["bytes"] != 0)
            .unwrap_or_else(|| panic!("no rewritten file: {records}"));
        assert_eq!(trace["reason"], "metadata_differs", "{trace}");
        assert_eq!(trace["bytes"], 13, "{trace}");
        // The group's other name is linked to the new file.
        assert_eq!(traces.len(), if hardlinks { 2 } else { 1 }, "{records}");
        assert_eq!(mode(&t.path("outside")), 0o644);
    }
}

/// Access times are restored in place on any file: a `-aHU` rerun neither
/// replaces nor relinks a hard-link group that was only read since the last
/// copy, and a preview counts it as a metadata-only change.
#[test]
fn an_access_time_rerun_keeps_a_hard_link_group_that_was_only_read() {
    let set_atime = |path: &Path, seconds: i64| {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: seconds as _,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
        ];
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) },
            0
        );
    };
    let atime = |path: &Path| fs::metadata(path).unwrap().atime();
    for route in ROUTES {
        let t = Tmp::new();
        write(&t.path("src/a"), &prng(1 << 20, 508));
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        set_mtime(&t.path("src/a"), 1_700_000_000);
        set_atime(&t.path("src/a"), 1_500_000_000);
        assert_output_ok(&rsync(&t, route, &["-aHU"]));
        let group = inode(&t.path("dst/a"));
        assert_eq!(inode(&t.path("dst/b")), group, "{route}");
        assert_eq!(atime(&t.path("dst/a")), 1_500_000_000, "{route}");
        // Someone reads the copy.
        set_atime(&t.path("dst/a"), 1_650_000_000);

        if route == "local" {
            let results = t.path("results.jsonl");
            let out = native_syq(&[
                "cp",
                "--dry-run",
                "--copy-metadata=mtime,permissions,hardlinks,atimes",
                "--results",
                &results.to_string_lossy(),
                "--srcs-in",
                &t.s("src"),
                "--into",
                &t.s("dst"),
            ]);
            assert_output_ok(&out);
            let records = fs::read_to_string(&results).unwrap();
            let traces: Vec<serde_json::Value> = records
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .filter(|record| record["action"] == "transfer_file")
                .collect();
            assert_eq!(traces.len(), 1, "{records}");
            assert_eq!(traces[0]["reason"], "metadata_differs", "{records}");
            assert!(traces[0]["bytes"].is_null(), "{records}");
        }

        assert_output_ok(&rsync(&t, route, &["-aHU"]));
        for name in ["dst/a", "dst/b"] {
            assert_eq!(inode(&t.path(name)), group, "{route} {name}");
        }
        // The source's access time, which macOS updates when the first copy
        // reads it.
        assert_eq!(atime(&t.path("dst/a")), atime(&t.path("src/a")), "{route}");
        assert_ne!(atime(&t.path("dst/a")), 1_650_000_000, "{route}");
    }
}

/// A FIFO whose time changes is created again with the permissions it had,
/// which the copy does not select, rather than the source's.
#[test]
fn a_recreated_fifo_keeps_permissions_the_copy_does_not_select() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("src")).unwrap();
    fs::create_dir_all(t.path("dst")).unwrap();
    mkfifo(&t.path("src/fifo"));
    mkfifo(&t.path("dst/fifo"));
    fs::set_permissions(t.path("src/fifo"), fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(t.path("dst/fifo"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src/fifo"), 1_700_000_000);
    set_mtime(&t.path("dst/fifo"), 1_600_000_000);
    let before = fs::symlink_metadata(t.path("dst/fifo")).unwrap().ino();
    run_native_ok(&[
        "cp",
        "--copy-metadata=specials,mtime",
        "--srcs-in",
        &t.s("src"),
        "--into",
        &t.s("dst"),
    ]);
    let after = fs::symlink_metadata(t.path("dst/fifo")).unwrap();
    assert!(after.file_type().is_fifo());
    assert_ne!(after.ino(), before);
    assert_eq!(after.mtime(), 1_700_000_000);
    assert_eq!(after.mode() & 0o7777, 0o600);
}

/// A `-aUX` rerun leaves an unchanged symlink as it is, and gives one that
/// was only read its access time back in place.
#[test]
fn access_time_reruns_keep_unchanged_symlinks() {
    let lstat_atime = |path: &Path| {
        let metadata = fs::symlink_metadata(path).unwrap();
        (metadata.ino(), metadata.atime())
    };
    let t = Tmp::new();
    write(&t.path("src/target"), b"target");
    std::os::unix::fs::symlink("target", t.path("src/link")).unwrap();
    run_ok(&["-aUX", &t.s("src/"), &t.s("dst/")]);
    let (inode, _) = lstat_atime(&t.path("dst/link"));
    run_ok(&["-aUX", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(lstat_atime(&t.path("dst/link")).0, inode);
    // Someone reads the copy's link.
    let path = std::ffi::CString::new(t.path("dst/link").as_os_str().as_bytes()).unwrap();
    let times = [
        libc::timespec {
            tv_sec: 1_650_000_000,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    ];
    assert_eq!(
        unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                path.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        },
        0
    );
    run_ok(&["-aUX", &t.s("src/"), &t.s("dst/")]);
    let (after, atime) = lstat_atime(&t.path("dst/link"));
    assert_eq!(after, inode);
    assert_ne!(atime, 1_650_000_000);
    assert_eq!(atime, lstat_atime(&t.path("src/link")).1);
}

/// Linux before 5.8 cannot set times through a handle with an empty path:
/// a directory's times are then set through its handle's `/proc` link, and
/// a new symlink's by the name it was just created at, never following it.
#[cfg(all(target_os = "linux", debug_assertions))]
#[test]
fn times_are_set_without_empty_paths_on_older_kernels() {
    let t = Tmp::new();
    write(&t.path("outside"), b"outside");
    set_mtime(&t.path("outside"), 1_500_000_000);
    fs::create_dir_all(t.path("src/dir")).unwrap();
    std::os::unix::fs::symlink(t.path("outside"), t.path("src/link")).unwrap();
    let set_link_mtime = |path: &Path, seconds: i64| {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: seconds as _,
                tv_nsec: 0,
            },
        ];
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    path.as_ptr(),
                    times.as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            },
            0
        );
    };
    set_link_mtime(&t.path("src/link"), 1_650_000_000);
    set_mtime(&t.path("src/dir"), 1_600_000_000);
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_TEST_REFUSE_EMPTY_PATH_TIMES", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(
        fs::metadata(t.path("dst/dir")).unwrap().mtime(),
        1_600_000_000
    );
    assert_eq!(
        fs::symlink_metadata(t.path("dst/link")).unwrap().mtime(),
        1_650_000_000
    );
    assert_eq!(
        fs::metadata(t.path("outside")).unwrap().mtime(),
        1_500_000_000
    );
}

/// Where the files syq creates show an owner other than the account it runs
/// as (SSHFS without uid mapping, NFS that squashes root, CIFS mounted with
/// `uid=`), syq compares owners with what its own creations there show: it
/// gives new symlinks and FIFOs their metadata, links a hard-link group's
/// names, and changes a file's permissions in place, as anywhere else. The
/// test stands in for such a filesystem by giving syq another account to
/// compare owners with than the one its files show.
#[cfg(debug_assertions)]
#[test]
fn owners_are_compared_with_the_owner_new_files_show() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: needs an account other than root");
        return;
    }
    let other = (unsafe { libc::geteuid() } + 1).to_string();
    let env = [("SYQ_TEST_OWN_UID", other.as_str())];
    for route in ["local", "ranges", "ssh"] {
        let t = Tmp::new();
        write(&t.path("src/file"), &prng(1 << 20, 509));
        write(&t.path("src/a"), b"linked");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        std::os::unix::fs::symlink("file", t.path("src/link")).unwrap();
        mkfifo(&t.path("src/fifo"));
        set_mtime(&t.path("src/file"), 1_700_000_000);
        let out = rsync_with(&t, route, &["-aHD"], &env);
        assert_output_ok(&out);
        assert_eq!(inode(&t.path("dst/a")), inode(&t.path("dst/b")), "{route}");
        assert!(fs::symlink_metadata(t.path("dst/fifo"))
            .unwrap()
            .file_type()
            .is_fifo());
        let kept = inode(&t.path("dst/file"));
        fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o600)).unwrap();
        // A preview creates nothing to learn the owner: it predicts.
        let previewed = t.path("preview-probes");
        let log = previewed.to_string_lossy().into_owned();
        let preview = [env[0], ("SYQ_TEST_PROBE_LOG", log.as_str())];
        assert_output_ok(&rsync_with(&t, route, &["-aHDn"], &preview));
        assert!(
            !previewed.exists(),
            "{route}: a preview probed: {}",
            fs::read_to_string(&previewed).unwrap_or_default()
        );
        // Nothing is created on this rerun: the owner is learned by a probe.
        let probes = t.path("probes");
        let log = probes.to_string_lossy().into_owned();
        let rerun = [env[0], ("SYQ_TEST_PROBE_LOG", log.as_str())];
        let out = rsync_with(&t, route, &["-aHD"], &rerun);
        assert_output_ok(&out);
        assert_eq!(inode(&t.path("dst/file")), kept, "{route}");
        assert_eq!(mode(&t.path("dst/file")), 0o600, "{route}");
        assert!(probes.exists(), "{route}: the owner was not learned");
    }
}

/// On a local filesystem, which shows what syq creates as owned by the
/// account it runs as, syq never creates a file just to learn that owner:
/// not for new symlinks, FIFOs and hard links, and not for a metadata-only
/// rerun that creates nothing else.
#[cfg(debug_assertions)]
#[test]
fn no_owner_probe_on_local_filesystems() {
    for route in ["local", "ranges", "ssh"] {
        let t = Tmp::new();
        write(&t.path("src/file"), &prng(1 << 20, 510));
        write(&t.path("src/a"), b"linked");
        fs::hard_link(t.path("src/a"), t.path("src/b")).unwrap();
        std::os::unix::fs::symlink("file", t.path("src/link")).unwrap();
        mkfifo(&t.path("src/fifo"));
        let probes = t.path("probes");
        let log = probes.to_string_lossy().into_owned();
        let env = [("SYQ_TEST_PROBE_LOG", log.as_str())];
        assert_output_ok(&rsync_with(&t, route, &["-aHD"], &env));
        fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o600)).unwrap();
        assert_output_ok(&rsync_with(&t, route, &["-aHD"], &env));
        assert_eq!(mode(&t.path("dst/file")), 0o600, "{route}");
        assert!(
            !probes.exists(),
            "{route}: {}",
            fs::read_to_string(&probes).unwrap_or_default()
        );
    }
}

/// A root receiver decides metadata-only changes by the change, so the
/// planner does not read each folder to predict a new file's group, which
/// over SSH is a round trip per folder. It does so only for hard-link
/// representatives.
#[cfg(debug_assertions)]
#[test]
fn root_metadata_changes_need_no_lookup_per_folder() {
    const FOLDERS: usize = 40;
    for route in ["local", "ssh"] {
        let t = Tmp::new();
        for folder in 0..FOLDERS {
            write(&t.path(&format!("src/{folder}/file")), b"contents");
        }
        assert_output_ok(&rsync_with(&t, route, &["-rlpt"], &[]));
        for folder in 0..FOLDERS {
            fs::set_permissions(
                t.path(&format!("src/{folder}/file")),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        // The receiver reports itself as root.
        let lookups = t.path("lookups");
        let log = lookups.to_string_lossy().into_owned();
        let env = [
            ("SYQ_TEST_OWN_UID", "0"),
            ("SYQ_TEST_DESTINATION_LOOKUPS", log.as_str()),
        ];
        assert_output_ok(&rsync_with(&t, route, &["-rlpt"], &env));
        assert_eq!(mode(&t.path("dst/0/file")), 0o600, "{route}");
        let recorded = fs::read_to_string(&lookups).unwrap_or_default();
        let count = recorded.lines().filter(|line| *line == "stat 1").count();
        assert!(
            count < FOLDERS / 2,
            "{route}: {count} single-path lookups for {FOLDERS} folders\n{recorded}"
        );
    }
}
