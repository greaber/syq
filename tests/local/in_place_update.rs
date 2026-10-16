//! `--in-place=update` (`syq rsync --inplace`) writes an existing file where
//! it is, and only what changed, when syq can vouch for it: one name, on a
//! filesystem whose link counts it trusts, the receiving account's, and no
//! wider permissions than the copy gives it. It replaces any other existing
//! file, and the summary and `--results` say how many and why.

use super::*;

/// `syq rsync -a --inplace` with `args`, from `src/` to `dst/`, by `route`:
/// on this machine copying whole files, comparing blocks (`blocks`), or to
/// a remote helper over SSH or TCP. `env` is set for syq and its helper.
fn rsync_inplace(t: &Tmp, route: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = compat_command();
    command.args(["-a", "--inplace", "--block-size=64K", "--no-progress"]);
    if matches!(route, "ssh" | "tcp") {
        if !t.path("remote-bin/syq").exists() {
            t.expose_remote_syq();
        }
        command
            .arg("-e")
            .arg(fake_rsh(t))
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
    } else {
        if route == "blocks" {
            command.arg("--no-whole-file");
        }
        command.args(args).arg(t.s("src/")).arg(t.s("dst/"));
    }
    command.envs(env.iter().copied()).run().unwrap()
}

/// `syq cp --in-place=update` of the contents of `src` into `dst`, with
/// `args`, on this machine or (`ssh`) to a remote helper over SSH. `env` is
/// set for syq and its helper.
fn cp_update(t: &Tmp, route: &str, args: &[&str], env: &[(&str, &str)]) -> Output {
    cp_update_command(t, route, args, env).run().unwrap()
}

/// The command `cp_update` runs.
fn cp_update_command(t: &Tmp, route: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["cp", "--in-place=update", "--no-progress"])
        .args(args)
        .arg("--srcs-in")
        .arg(t.s("src"));
    if route == "ssh" {
        let ssh = fake_ssh(t);
        command
            .args(["--syq-path", env!("CARGO_BIN_EXE_syq"), "--no-tcp"])
            .args(["--to", "fake.example"])
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("FAKE_RSH_LOG", t.path("rsh.log"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
            );
    }
    command.arg("--into").arg(t.s("dst"));
    command.envs(env.iter().copied());
    command
}

fn inode(path: &Path) -> u64 {
    fs::metadata(path).unwrap().ino()
}

/// The bytes the receiver wrote through range writes, as
/// `SYQ_TEST_DESTINATION_WRITES` recorded them in `log`.
fn written_bytes(log: &Path) -> u64 {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(fields[0], "write", "{line}");
            fields[2].parse::<u64>().unwrap()
        })
        .sum()
}

/// The terminal record of a `--results` stream, which must validate.
fn terminal(results: &Path) -> serde_json::Value {
    let content = fs::read_to_string(results).unwrap();
    assert_automation_stream(
        &automation_validator(),
        &content,
        &results.display().to_string(),
    );
    serde_json::from_str(content.lines().last().unwrap()).unwrap()
}

const WARNING: &str =
    "anyone who already has an existing file open can read its new contents, and an interruption leaves a file partly updated";

/// A file of the receiving account's, with one name, keeps its inode, and
/// only the blocks that changed are written into it. Copying whole files
/// on this machine, the whole file is written into it.
#[cfg(debug_assertions)]
#[test]
fn a_file_of_ones_own_is_updated_in_place_writing_only_what_changed() {
    for route in ["blocks", "ssh", "tcp", "local"] {
        let t = Tmp::new();
        let new = prng(4 << 20, 601);
        let mut old = new.clone();
        // Two changed blocks of 64 KiB.
        old[(1 << 20) + 10] ^= 1;
        old[(3 << 20) + 100] ^= 1;
        write(&t.path("src/file"), &new);
        write(&t.path("dst/file"), &old);
        set_mtime(&t.path("src/file"), 1_700_000_000);
        let before = inode(&t.path("dst/file"));
        let log = t.path("writes");
        let out = rsync_inplace(
            &t,
            route,
            &[],
            &[("SYQ_TEST_DESTINATION_WRITES", &log.to_string_lossy())],
        );
        assert_output_ok(&out);
        assert!(read(&t.path("dst/file")) == new, "{route}");
        assert_eq!(inode(&t.path("dst/file")), before, "{route}");
        assert_eq!(
            fs::metadata(t.path("dst/file")).unwrap().mtime(),
            1_700_000_000,
            "{route}"
        );
        if route != "local" {
            assert_eq!(written_bytes(&log), 2 * 64 * 1024, "{route}");
        }
        assert!(partial_files(&t.0).is_empty(), "{route}");
        // `syq rsync --inplace` warns of nothing, as rsync does not.
        assert!(!stderr_of(&out).contains(WARNING), "{route}: {out:?}");
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("instead of updating"),
            "{route}: {out:?}"
        );
    }
}

/// `syq cp --in-place=update` is the same option; `--in-place=new` replaces
/// the file. `-q` leaves out the warning.
#[test]
fn syq_cp_in_place_update_keeps_the_inode_and_new_replaces_it() {
    for (mode, kept, quiet) in [
        ("update", true, false),
        ("update", true, true),
        ("new", false, false),
    ] {
        let t = Tmp::new();
        write(&t.path("src/file"), &prng(1 << 20, 602));
        write(&t.path("dst/file"), &prng(1 << 20, 603));
        set_mtime(&t.path("src/file"), 1_700_000_000);
        let before = inode(&t.path("dst/file"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command
            .args(["cp", &format!("--in-place={mode}"), "--srcs-in"])
            .arg(t.s("src"))
            .arg("--into")
            .arg(t.s("dst"))
            .arg("--no-progress");
        if quiet {
            command.arg("-q");
        }
        let out = command.run().unwrap();
        assert_output_ok(&out);
        let case = format!("{mode}, quiet {quiet}");
        assert_eq!(
            read(&t.path("dst/file")),
            read(&t.path("src/file")),
            "{case}"
        );
        assert_eq!(inode(&t.path("dst/file")) == before, kept, "{case}");
        assert_eq!(
            stderr_of(&out).contains(WARNING),
            kept && !quiet,
            "{case}: {out:?}"
        );
    }
}

/// A supplementary group of this process's, other than its own group.
fn another_group() -> Option<u32> {
    let mut groups = vec![0 as libc::gid_t; 256];
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    let own = unsafe { libc::getegid() };
    groups
        .into_iter()
        .take(count.max(0) as usize)
        .find(|group| *group != own)
}

/// Each file syq cannot vouch for is replaced, and the rest updated in
/// place: one with another name, one more widely readable than the copy's
/// mode, one with a set-ID bit, one its owner cannot write, and, where this
/// process has a second group, one whose group the copy changes and which
/// that group can write but not read. The summary and `--results` count
/// them by reason, and a preview counts the same.
#[test]
fn files_syq_cannot_vouch_for_are_replaced_and_counted_by_reason() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root opens files its mode does not let it write");
        return;
    }
    let group = another_group();
    for route in ["local", "ssh"] {
        let t = Tmp::new();
        // name, source mode, destination mode
        let mut files = vec![
            ("mine", 0o644, 0o644),
            ("linked", 0o644, 0o644),
            ("wider", 0o600, 0o644),
            ("setid", 0o755, 0o4755),
            ("read-only", 0o444, 0o444),
        ];
        if group.is_some() {
            files.push(("group", 0o620, 0o620));
        }
        for (seed, (name, source_mode, destination_mode)) in files.iter().copied().enumerate() {
            let source = t.path(&format!("src/{name}"));
            let destination = t.path(&format!("dst/{name}"));
            write(&source, &prng(256 << 10, 610 + seed as u64));
            write(&destination, &prng(256 << 10, 620 + seed as u64));
            fs::set_permissions(&source, fs::Permissions::from_mode(source_mode)).unwrap();
            fs::set_permissions(&destination, fs::Permissions::from_mode(destination_mode))
                .unwrap();
            set_mtime(&source, 1_700_000_000);
        }
        if let Some(group) = group {
            std::os::unix::fs::chown(t.path("dst/group"), None, Some(group)).unwrap();
        }
        fs::hard_link(t.path("dst/linked"), t.path("outside")).unwrap();
        let inodes: Vec<u64> = files
            .iter()
            .map(|(name, _, _)| inode(&t.path(&format!("dst/{name}"))))
            .collect();
        let wider = if group.is_some() { 2 } else { 1 };
        let expected = serde_json::json!({
            "other_names": 1,
            "privileges": 1,
            "wider_permissions": wider,
            "not_writable": 1,
        });
        let summary = format!(
            "replaced {} existing files instead of updating them in place: 1 with other hard links, 1 with set-ID bits or privileged attributes, {wider} with wider permissions, 1 that could not be opened for writing",
            3 + wider
        );
        let metadata = "--copy-metadata=permissions,ownership";
        let results = t.path("preview.jsonl");
        let out = cp_update(
            &t,
            route,
            &[
                metadata,
                "--dry-run",
                "--results",
                &results.to_string_lossy(),
            ],
            &[],
        );
        assert_output_ok(&out);
        assert_eq!(
            terminal(&results)["replaced_not_in_place"],
            expected,
            "{route}"
        );
        let previewed = summary.replacen("replaced", "would replace", 1);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("in place: {previewed}")),
            "{route}: {out:?}"
        );
        let results = t.path("copy.jsonl");
        let out = cp_update(
            &t,
            route,
            &[metadata, "--results", &results.to_string_lossy()],
            &[],
        );
        assert_output_ok(&out);
        assert_eq!(
            terminal(&results)["replaced_not_in_place"],
            expected,
            "{route}"
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("syq: {summary}")),
            "{route}: {out:?}"
        );
        for ((name, _, _), before) in files.iter().zip(&inodes) {
            let destination = t.path(&format!("dst/{name}"));
            assert_eq!(
                read(&destination),
                read(&t.path(&format!("src/{name}"))),
                "{route}"
            );
            assert_eq!(
                inode(&destination) == *before,
                *name == "mine",
                "{route}: {name}"
            );
        }
        assert_eq!(read(&t.path("outside")), prng(256 << 10, 621), "{route}");
        assert!(partial_files(&t.0).is_empty(), "{route}");
    }
}

/// Set `name` to `value` on `path`, or say the filesystem has no such
/// attributes.
#[cfg(target_os = "linux")]
fn set_attribute(path: &Path, name: &str, value: &[u8]) -> bool {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let name = std::ffi::CString::new(name).unwrap();
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if result == 0 {
        return true;
    }
    let error = std::io::Error::last_os_error();
    assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP), "{error}");
    false
}

/// A Linux ACL, as its extended attribute holds it, with these entries:
/// tag, permissions and id. The owner, group and other entries carry
/// `u32::MAX`.
#[cfg(target_os = "linux")]
fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in entries {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(permissions.to_le_bytes());
        bytes.extend(id.to_le_bytes());
    }
    bytes
}

/// Copying ACLs, a file is updated in place only when it already has the
/// ACL the copy gives it: one with an ACL the source lacks is replaced, and
/// so is one without an ACL whose source's ACL keeps user 12345 out, whom
/// the file's mode lets read it. A preview counts the same.
#[cfg(target_os = "linux")]
#[test]
fn files_are_updated_in_place_only_with_the_acl_they_end_with() {
    // The owner reads and writes; user 12345 can read, or not.
    let reader = acl(&[
        (1, 6, u32::MAX),
        (2, 4, 12345),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ]);
    let denied = acl(&[
        (1, 6, u32::MAX),
        (2, 0, 12345),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ]);
    for route in ["local", "ssh"] {
        let t = Tmp::new();
        // name, the source's ACL, the destination's
        let files = [
            ("same", Some(&reader), Some(&reader)),
            ("extra", None, Some(&reader)),
            ("denied", Some(&denied), None),
        ];
        let mut inodes = Vec::new();
        for (seed, (name, source_acl, destination_acl)) in files.iter().enumerate() {
            let source = t.path(&format!("src/{name}"));
            let destination = t.path(&format!("dst/{name}"));
            write(&source, &prng(256 << 10, 640 + seed as u64));
            write(&destination, &prng(256 << 10, 650 + seed as u64));
            for (path, acl) in [(&source, source_acl), (&destination, destination_acl)] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
                if let Some(acl) = acl {
                    if !set_attribute(path, "system.posix_acl_access", acl) {
                        eprintln!("skipped: this filesystem has no POSIX ACLs");
                        return;
                    }
                }
            }
            set_mtime(&source, 1_700_000_000);
            inodes.push(inode(&destination));
        }
        let expected = serde_json::json!({"wider_permissions": 2});
        let metadata = "--copy-metadata=permissions,acls";
        for dry_run in [true, false] {
            let results = t.path(&format!("results-{dry_run}.jsonl"));
            let results = results.to_string_lossy();
            let mut args = vec![metadata, "--results", &results];
            if dry_run {
                args.push("--dry-run");
            }
            let out = cp_update(&t, route, &args, &[]);
            assert_output_ok(&out);
            let results = t.path(&format!("results-{dry_run}.jsonl"));
            assert_eq!(
                terminal(&results)["replaced_not_in_place"],
                expected,
                "{route}, dry run {dry_run}"
            );
        }
        for ((name, _, _), before) in files.iter().zip(&inodes) {
            let destination = t.path(&format!("dst/{name}"));
            assert_eq!(read(&destination), read(&t.path(&format!("src/{name}"))));
            assert_eq!(
                inode(&destination) == *before,
                *name == "same",
                "{route}: {name}"
            );
        }
    }
}

/// A file only the receiver refuses to update in place, here one with an
/// ACL the copy does not copy, which the scan does not read, is refused
/// before the receiver reads it, and then replaced: the receiver reads it
/// for one comparison only.
#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn a_file_only_the_receiver_refuses_is_read_once_there() {
    let reader = acl(&[
        (1, 6, u32::MAX),
        (2, 4, 12345),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ]);
    let t = Tmp::new();
    let new = prng(16 << 20, 680);
    let mut old = new.clone();
    old[(9 << 20) + 5] ^= 1;
    write(&t.path("src/file"), &new);
    write(&t.path("dst/file"), &old);
    fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o644)).unwrap();
    if !set_attribute(&t.path("dst/file"), "system.posix_acl_access", &reader) {
        eprintln!("skipped: this filesystem has no POSIX ACLs");
        return;
    }
    set_mtime(&t.path("src/file"), 1_700_000_000);
    let before = inode(&t.path("dst/file"));
    let hashes = t.path("hashes");
    let results = t.path("copy.jsonl");
    let out = cp_update(
        &t,
        "ssh",
        &["--results", &results.to_string_lossy()],
        &[("SYQ_TEST_DESTINATION_HASHES", &hashes.to_string_lossy())],
    );
    assert_output_ok(&out);
    assert!(read(&t.path("dst/file")) == new);
    assert_ne!(inode(&t.path("dst/file")), before);
    assert_eq!(
        terminal(&results)["replaced_not_in_place"],
        serde_json::json!({"wider_permissions": 1})
    );
    // The receiver hashed the file once.
    let hashed: u64 = fs::read_to_string(&hashes)
        .unwrap()
        .lines()
        .map(|line| line.split(' ').nth(1).unwrap().parse::<u64>().unwrap())
        .sum();
    assert_eq!(hashed, 16 << 20);
}

/// On the per-file path, a differing file the receiver refuses to update in
/// place is replaced from the file it holds: cloned into the stage where
/// the filesystem can, and hashed there. The receiver does not vouch for
/// the file, which here changes after it was compared: the replacement
/// still holds the source's bytes, since the stage's hashes, not the
/// comparison's, decide what is sent.
#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn a_refused_file_changed_after_its_comparison_is_replaced_with_the_sources_bytes() {
    use std::os::unix::fs::FileExt as _;
    let reader = acl(&[
        (1, 6, u32::MAX),
        (2, 4, 12345),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ]);
    let t = Tmp::new();
    let new = prng(16 << 20, 700);
    let mut old = new.clone();
    old[(9 << 20) + 5] ^= 1;
    write(&t.path("src/file"), &new);
    write(&t.path("dst/file"), &old);
    fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o644)).unwrap();
    if !set_attribute(&t.path("dst/file"), "system.posix_acl_access", &reader) {
        eprintln!("skipped: this filesystem has no POSIX ACLs");
        return;
    }
    set_mtime(&t.path("src/file"), 1_700_000_000);
    let before = inode(&t.path("dst/file"));
    let (ready, continuation, clones) = (t.path("ready"), t.path("continue"), t.path("clones"));
    let mut child = cp_update_command(
        &t,
        "ssh",
        &[],
        &[
            ("SYQ_TEST_BASIS_READY_FILE", &ready.to_string_lossy()),
            (
                "SYQ_TEST_BASIS_CONTINUE_FILE",
                &continuation.to_string_lossy(),
            ),
            ("SYQ_TEST_SEED_CLONES", &clones.to_string_lossy()),
            ("SYQ_TEST_PER_FILE_COMPARISON", "1"),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .start()
    .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "the comparison");
    // A block that matched the source when it was compared no longer does.
    OpenOptions::new()
        .write(true)
        .open(t.path("dst/file"))
        .unwrap()
        .write_all_at(b"planted after the comparison", 2 << 20)
        .unwrap();
    release_confinement_barrier(&continuation);
    let out = child.wait_with_output().unwrap();
    assert_output_ok(&out);
    assert_ne!(inode(&t.path("dst/file")), before);
    assert!(read(&t.path("dst/file")) == new);
    if fs::read_to_string(&clones).unwrap_or_default().is_empty() {
        eprintln!("note: this filesystem did not clone; the stage was copied");
    }
}

/// On the per-file path, a file that gains another name after it was
/// compared, and before the receiver opens it to write, is replaced rather
/// than written in place: the other name keeps its contents.
#[cfg(debug_assertions)]
#[test]
fn a_file_linked_after_its_comparison_is_replaced() {
    let t = Tmp::new();
    let new = prng(16 << 20, 710);
    let mut old = new.clone();
    old[(9 << 20) + 5] ^= 1;
    write(&t.path("src/file"), &new);
    write(&t.path("dst/file"), &old);
    set_mtime(&t.path("src/file"), 1_700_000_000);
    let before = inode(&t.path("dst/file"));
    let (ready, continuation) = (t.path("ready"), t.path("continue"));
    let results = t.path("copy.jsonl");
    let mut child = cp_update_command(
        &t,
        "ssh",
        &["--results", &results.to_string_lossy()],
        &[
            ("SYQ_TEST_BASIS_READY_FILE", &ready.to_string_lossy()),
            (
                "SYQ_TEST_BASIS_CONTINUE_FILE",
                &continuation.to_string_lossy(),
            ),
            ("SYQ_TEST_PER_FILE_COMPARISON", "1"),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .start()
    .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "the comparison");
    fs::hard_link(t.path("dst/file"), t.path("outside")).unwrap();
    release_confinement_barrier(&continuation);
    let out = child.wait_with_output().unwrap();
    assert_output_ok(&out);
    assert!(read(&t.path("dst/file")) == new);
    assert!(
        read(&t.path("outside")) == old,
        "the other name was written"
    );
    assert_ne!(inode(&t.path("dst/file")), before);
    assert_eq!(
        terminal(&results)["replaced_not_in_place"],
        serde_json::json!({"other_names": 1})
    );
}

/// An unchanged file the receiver will not update in place, here because
/// its ACL is not the one it would end with, is kept as it is, with its
/// ACL and extended attributes, whether `--hash` compares it or
/// `--if-exists=error-if-different` does.
#[cfg(target_os = "linux")]
#[test]
fn unchanged_files_the_receiver_will_not_update_are_kept() {
    let reader = acl(&[
        (1, 6, u32::MAX),
        (2, 4, 12345),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ]);
    for route in ["local", "ssh"] {
        for compare in ["--hash", "--if-exists=error-if-different"] {
            let t = Tmp::new();
            let contents = prng(1 << 20, 690);
            write(&t.path("src/file"), &contents);
            write(&t.path("dst/file"), &contents);
            fs::set_permissions(t.path("dst/file"), fs::Permissions::from_mode(0o644)).unwrap();
            if !set_attribute(&t.path("dst/file"), "system.posix_acl_access", &reader)
                || !set_attribute(&t.path("dst/file"), "user.keep", b"kept")
            {
                eprintln!("skipped: this filesystem has no POSIX ACLs or user attributes");
                return;
            }
            set_mtime(&t.path("src/file"), 1_700_000_000);
            set_mtime(&t.path("dst/file"), 1_600_000_000);
            let before = inode(&t.path("dst/file"));
            let out = cp_update(&t, route, &[compare], &[]);
            let case = format!("{route}, {compare}");
            assert_output_ok(&out);
            assert_eq!(inode(&t.path("dst/file")), before, "{case}");
            assert_eq!(read(&t.path("dst/file")), contents, "{case}");
            let attribute = |name: &str| {
                let path =
                    std::ffi::CString::new(t.path("dst/file").as_os_str().as_encoded_bytes())
                        .unwrap();
                let name = std::ffi::CString::new(name).unwrap();
                let mut value = vec![0u8; 1024];
                let count = unsafe {
                    libc::getxattr(
                        path.as_ptr(),
                        name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                    )
                };
                (count >= 0).then(|| value[..count as usize].to_vec())
            };
            assert_eq!(
                attribute("system.posix_acl_access").as_deref(),
                Some(&reader[..]),
                "{case}"
            );
            assert_eq!(
                attribute("user.keep").as_deref(),
                Some(&b"kept"[..]),
                "{case}"
            );
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains("instead of updating"),
                "{case}: {out:?}"
            );
        }
    }
}

/// Without ACL copying, a file whose ACL is the one a new file inherits
/// from its folder's default ACL, as `setfacl -d -m g:12345:rw` gives one,
/// is updated in place, as a preview predicts: replacing it would give it
/// the same ACL.
#[cfg(target_os = "linux")]
#[test]
fn files_with_the_acl_their_folder_gives_are_updated_in_place() {
    let default = acl(&[
        (1, 7, u32::MAX),
        (4, 5, u32::MAX),
        (8, 6, 12345),
        (16, 7, u32::MAX),
        (32, 5, u32::MAX),
    ]);
    for route in ["local", "ssh"] {
        let t = Tmp::new();
        fs::create_dir_all(t.path("dst")).unwrap();
        if !set_attribute(&t.path("dst"), "system.posix_acl_default", &default) {
            eprintln!("skipped: this filesystem has no POSIX ACLs");
            return;
        }
        let mut inodes = Vec::new();
        for (seed, name) in ["a", "b"].into_iter().enumerate() {
            let source = t.path(&format!("src/{name}"));
            let destination = t.path(&format!("dst/{name}"));
            write(&source, &prng(256 << 10, 660 + seed as u64));
            // Created in the folder, the file takes its default ACL.
            write(&destination, &prng(256 << 10, 670 + seed as u64));
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o640)).unwrap();
            set_mtime(&source, 1_700_000_000);
            inodes.push(inode(&destination));
        }
        for dry_run in [true, false] {
            let results = t.path(&format!("results-{dry_run}.jsonl"));
            let results = results.to_string_lossy();
            let mut args = vec!["--results", &results];
            if dry_run {
                args.push("--dry-run");
            }
            let out = cp_update(&t, route, &args, &[]);
            assert_output_ok(&out);
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains("instead of updating"),
                "{route}: {out:?}"
            );
            let results = t.path(&format!("results-{dry_run}.jsonl"));
            assert_eq!(
                terminal(&results)["replaced_not_in_place"],
                serde_json::json!({}),
                "{route}, dry run {dry_run}"
            );
        }
        for (name, before) in ["a", "b"].into_iter().zip(&inodes) {
            let destination = t.path(&format!("dst/{name}"));
            assert_eq!(read(&destination), read(&t.path(&format!("src/{name}"))));
            assert_eq!(inode(&destination), *before, "{route}: {name}");
        }
    }
}

/// Where the filesystem's link counts cannot be trusted, no file can be
/// shown to have one name: each is replaced, and a preview says so too.
#[cfg(debug_assertions)]
#[test]
fn files_on_untrusted_filesystems_are_replaced() {
    for route in ["local", "ssh"] {
        let t = Tmp::new();
        write(&t.path("src/file"), &prng(1 << 20, 630));
        write(&t.path("dst/file"), &prng(1 << 20, 631));
        set_mtime(&t.path("src/file"), 1_700_000_000);
        let before = inode(&t.path("dst/file"));
        let env = [("SYQ_TEST_UNTRUSTED_LINK_COUNTS", "1")];
        let summary = "existing file instead of updating it in place: 1 on filesystems whose link counts syq does not trust";
        let out = cp_update(&t, route, &["--dry-run"], &env);
        assert_output_ok(&out);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("would replace 1 {summary}")),
            "{route}: {out:?}"
        );
        let results = t.path("copy.jsonl");
        let out = cp_update(&t, route, &["--results", &results.to_string_lossy()], &env);
        assert_output_ok(&out);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!("syq: replaced 1 {summary}")),
            "{route}: {out:?}"
        );
        assert_eq!(
            terminal(&results)["replaced_not_in_place"],
            serde_json::json!({"untrusted_filesystem": 1}),
            "{route}"
        );
        assert_ne!(inode(&t.path("dst/file")), before, "{route}");
        assert_eq!(read(&t.path("dst/file")), read(&t.path("src/file")));
    }
}

/// Three comparison blocks of 64 KiB.
const SMALL: usize = 3 << 16;

/// Write a small source `src/{name}`, seeded by `seed`, and an existing
/// destination `dst/{name}` that differs from it in one byte of its middle
/// block when `changed`, and in nothing but its time otherwise. Returns the
/// source's contents and the destination's.
fn small_update(t: &Tmp, name: &str, seed: u64, changed: bool) -> (Vec<u8>, Vec<u8>) {
    let new = prng(SMALL, seed);
    let mut old = new.clone();
    if changed {
        old[(1 << 16) + 7] ^= 1;
    }
    write(&t.path(&format!("src/{name}")), &new);
    write(&t.path(&format!("dst/{name}")), &old);
    for side in ["src", "dst"] {
        fs::set_permissions(
            t.path(&format!("{side}/{name}")),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
    set_mtime(&t.path(&format!("src/{name}")), 1_700_000_000);
    set_mtime(&t.path(&format!("dst/{name}")), 1_600_000_000);
    (new, old)
}

/// What the receiver hashed of existing files, as
/// `SYQ_TEST_DESTINATION_HASHES` recorded it in `log`: whether it compared
/// them in groups (`existing`), and not one at a time.
fn hashed_in_groups(log: &Path) -> bool {
    let hashed = fs::read_to_string(log).unwrap_or_default();
    !hashed.is_empty() && hashed.lines().all(|line| line.starts_with("existing "))
}

/// Small existing files are updated in place in groups, as files the copy
/// replaces are compared: the receiver hashes them together, and each keeps
/// its inode and is written only where it changed, with no request of its
/// own.
#[cfg(debug_assertions)]
#[test]
fn small_files_are_updated_in_place_in_groups() {
    for route in ["ssh", "tcp", "blocks"] {
        let t = Tmp::new();
        let names: Vec<String> = (0..12).map(|index| format!("file{index:02}")).collect();
        let mut expected = Vec::new();
        for (seed, name) in names.iter().enumerate() {
            let (new, _) = small_update(&t, name, 720 + seed as u64, true);
            expected.push((new, inode(&t.path(&format!("dst/{name}")))));
        }
        let (writes, hashes) = (t.path("writes"), t.path("hashes"));
        let out = rsync_inplace(
            &t,
            route,
            &[],
            &[
                ("SYQ_TEST_DESTINATION_WRITES", &writes.to_string_lossy()),
                ("SYQ_TEST_DESTINATION_HASHES", &hashes.to_string_lossy()),
                ("SYQ_DEBUG", "1"),
            ],
        );
        assert_output_ok(&out);
        for (name, (new, before)) in names.iter().zip(&expected) {
            let destination = t.path(&format!("dst/{name}"));
            assert!(read(&destination) == *new, "{route}: {name}");
            assert_eq!(inode(&destination), *before, "{route}: {name}");
            assert_eq!(
                fs::metadata(&destination).unwrap().mtime(),
                1_700_000_000,
                "{route}: {name}"
            );
        }
        // Only the changed block of each file was written.
        assert_eq!(written_bytes(&writes), 12 * (64 << 10), "{route}");
        assert!(
            hashed_in_groups(&hashes),
            "{route}: {}",
            fs::read_to_string(&hashes).unwrap_or_default()
        );
        let observed = tuning_observed(&out);
        assert_eq!(observed["compared_files"], 12, "{route}: {observed}");
        assert_eq!(observed["patched_files"], 12, "{route}: {observed}");
        assert_eq!(observed["range_requests"], 0, "{route}: {observed}");
        assert!(partial_files(&t.0).is_empty(), "{route}");
    }
}

/// Each file of a group ends on its own: one is updated in place; one with
/// another name, and one more widely readable than the copy's mode, are
/// replaced and counted; an unchanged one is kept, with the source's time;
/// and one whose write fails fails, with the rest done. `--results` and the
/// summary count each, and a preview counts what it can foresee.
#[cfg(debug_assertions)]
#[test]
fn each_file_of_an_in_place_group_ends_on_its_own() {
    let t = Tmp::new();
    let names = ["mine", "linked", "wider", "unchanged", "failing"];
    let mut contents = Vec::new();
    for (seed, name) in names.into_iter().enumerate() {
        let (new, old) = small_update(&t, name, 740 + seed as u64, name != "unchanged");
        contents.push((new, old, inode(&t.path(&format!("dst/{name}")))));
    }
    fs::set_permissions(t.path("src/wider"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(t.path("dst/linked"), t.path("outside")).unwrap();
    let replaced = serde_json::json!({"other_names": 1, "wider_permissions": 1});
    let summary = "existing files instead of updating them in place: 1 with other hard links, 1 with wider permissions";
    // `--hash` lets a preview find the unchanged file as the copy does.
    let args = ["--copy-metadata=permissions,mtime", "--hash"];

    let preview = t.path("preview.jsonl");
    let mut previewing = args.to_vec();
    let preview_arg = preview.to_string_lossy();
    previewing.extend(["--dry-run", "--results", &preview_arg]);
    let out = cp_update(&t, "ssh", &previewing, &[]);
    assert_output_ok(&out);
    let previewed = terminal(&preview);
    assert_eq!(previewed["replaced_not_in_place"], replaced, "{previewed}");
    assert_eq!(previewed["files_transferred"], 4, "{previewed}");
    assert_eq!(previewed["files_unchanged"], 1, "{previewed}");
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains(&format!("in place: would replace 2 {summary}")),
        "{out:?}"
    );

    let (results, hashes) = (t.path("copy.jsonl"), t.path("hashes"));
    let mut copying = args.to_vec();
    let results_arg = results.to_string_lossy();
    copying.extend(["--results", &results_arg]);
    let out = cp_update(
        &t,
        "ssh",
        &copying,
        &[
            ("SYQ_TEST_FAIL_WRITE_RANGE_NAME", "failing"),
            ("SYQ_TEST_DESTINATION_HASHES", &hashes.to_string_lossy()),
        ],
    );
    assert!(!out.status.success(), "{out:?}");
    assert!(
        stderr_of(&out).contains("failing: ")
            && stderr_of(&out).contains("test range write failure"),
        "{out:?}"
    );
    let copied = terminal(&results);
    assert_eq!(copied["replaced_not_in_place"], replaced, "{copied}");
    assert_eq!(copied["files_transferred"], 3, "{copied}");
    assert_eq!(copied["files_unchanged"], 1, "{copied}");
    assert_eq!(copied["errors"], 1, "{copied}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&format!("syq: replaced 2 {summary}")),
        "{out:?}"
    );
    let dispositions: std::collections::BTreeMap<String, String> = fs::read_to_string(&results)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| {
            record["type"] == "operation_result" && record["action"] == "transfer_file"
        })
        .map(|record| {
            (
                record["dst"]["value"].as_str().unwrap().to_owned(),
                record["disposition"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        dispositions,
        [
            ("failing", "failed"),
            ("linked", "succeeded"),
            ("mine", "succeeded"),
            ("wider", "succeeded"),
        ]
        .into_iter()
        .map(|(name, disposition)| (name.to_owned(), disposition.to_owned()))
        .collect(),
    );
    // All were compared in one group.
    assert!(
        hashed_in_groups(&hashes),
        "{}",
        fs::read_to_string(&hashes).unwrap_or_default()
    );
    for (name, (new, old, before)) in names.into_iter().zip(&contents) {
        let destination = t.path(&format!("dst/{name}"));
        let status = fs::metadata(&destination).unwrap();
        let (holds, kept) = match name {
            "mine" | "unchanged" => (new, true),
            "linked" | "wider" => (new, false),
            _ => (old, true),
        };
        assert!(read(&destination) == *holds, "{name}");
        assert_eq!(status.ino() == *before, kept, "{name}");
        if name != "failing" {
            assert_eq!(status.mtime(), 1_700_000_000, "{name}");
        }
    }
    assert_eq!(
        fs::metadata(t.path("dst/wider")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(read(&t.path("outside")) == contents[1].1);
    assert!(partial_files(&t.0).is_empty());
}

/// Inside a group too, the receiver judges each file just before it writes
/// it: one that gains another name after the group was compared is
/// replaced, and the other name keeps its contents, while the rest are
/// updated in place.
#[cfg(debug_assertions)]
#[test]
fn a_file_linked_after_its_group_was_compared_is_replaced() {
    let t = Tmp::new();
    let names = ["a", "b", "c"];
    let mut contents = Vec::new();
    for (seed, name) in names.into_iter().enumerate() {
        let (new, old) = small_update(&t, name, 760 + seed as u64, true);
        contents.push((new, old, inode(&t.path(&format!("dst/{name}")))));
    }
    let (ready, continuation, hashes) = (t.path("ready"), t.path("continue"), t.path("hashes"));
    let results = t.path("copy.jsonl");
    let mut child = cp_update_command(
        &t,
        "ssh",
        &["--results", &results.to_string_lossy()],
        &[
            ("SYQ_TEST_SMALL_UPDATE_READY_FILE", &ready.to_string_lossy()),
            (
                "SYQ_TEST_SMALL_UPDATE_CONTINUE_FILE",
                &continuation.to_string_lossy(),
            ),
            ("SYQ_TEST_DESTINATION_HASHES", &hashes.to_string_lossy()),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .start()
    .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "the group's first write");
    fs::hard_link(t.path("dst/b"), t.path("outside")).unwrap();
    release_confinement_barrier(&continuation);
    let out = child.wait_with_output().unwrap();
    assert_output_ok(&out);
    assert!(
        hashed_in_groups(&hashes),
        "{}",
        fs::read_to_string(&hashes).unwrap_or_default()
    );
    for (name, (new, _, before)) in names.into_iter().zip(&contents) {
        let destination = t.path(&format!("dst/{name}"));
        assert!(read(&destination) == *new, "{name}");
        assert_eq!(inode(&destination) == *before, name != "b", "{name}");
    }
    assert!(
        read(&t.path("outside")) == contents[1].1,
        "the other name was written"
    );
    assert_eq!(
        terminal(&results)["replaced_not_in_place"],
        serde_json::json!({"other_names": 1})
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(
            "syq: replaced 1 existing file instead of updating it in place: 1 with other hard links"
        ),
        "{out:?}"
    );
}

/// A small file whose size changed is not compared, as on the per-file
/// path without block reuse: in its group, it is sent whole and written
/// over the existing file, which keeps its inode and takes the new length,
/// an emptied one too.
#[cfg(debug_assertions)]
#[test]
fn small_files_of_another_size_are_written_whole_in_place_in_groups() {
    let t = Tmp::new();
    let new = prng(SMALL, 780);
    let files = [
        ("grown", new.clone(), new[..SMALL - 1000].to_vec()),
        ("shrunk", new.clone(), [&new[..], &[7u8; 5000][..]].concat()),
        ("emptied", Vec::new(), new[..100].to_vec()),
    ];
    let mut inodes = Vec::new();
    for (name, source, destination) in &files {
        write(&t.path(&format!("src/{name}")), source);
        write(&t.path(&format!("dst/{name}")), destination);
        set_mtime(&t.path(&format!("src/{name}")), 1_700_000_000);
        inodes.push(inode(&t.path(&format!("dst/{name}"))));
    }
    let (writes, hashes) = (t.path("writes"), t.path("hashes"));
    let out = cp_update(
        &t,
        "ssh",
        &[],
        &[
            ("SYQ_TEST_DESTINATION_WRITES", &writes.to_string_lossy()),
            ("SYQ_TEST_DESTINATION_HASHES", &hashes.to_string_lossy()),
        ],
    );
    assert_output_ok(&out);
    for ((name, source, _), before) in files.iter().zip(&inodes) {
        let destination = t.path(&format!("dst/{name}"));
        assert!(read(&destination) == *source, "{name}");
        assert_eq!(inode(&destination), *before, "{name}");
    }
    assert_eq!(written_bytes(&writes), 2 * SMALL as u64);
    // The receiver looked at each in its group, and hashed none.
    let hashed = fs::read_to_string(&hashes).unwrap_or_default();
    assert_eq!(hashed.lines().count(), 3, "{hashed}");
    assert!(hashed.lines().all(|line| line == "existing 0"), "{hashed}");
}
