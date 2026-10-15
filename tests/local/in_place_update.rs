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
    command.envs(env.iter().copied()).run().unwrap()
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
        assert!(stderr_of(&out).contains(WARNING), "{route}: {out:?}");
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("instead of updating"),
            "{route}: {out:?}"
        );
    }
}

/// `syq cp --in-place=update` is the same option; `--in-place=new` replaces
/// the file.
#[test]
fn syq_cp_in_place_update_keeps_the_inode_and_new_replaces_it() {
    for (mode, kept) in [("update", true), ("new", false)] {
        let t = Tmp::new();
        write(&t.path("src/file"), &prng(1 << 20, 602));
        write(&t.path("dst/file"), &prng(1 << 20, 603));
        set_mtime(&t.path("src/file"), 1_700_000_000);
        let before = inode(&t.path("dst/file"));
        let out = Command::new(env!("CARGO_BIN_EXE_syq"))
            .args(["cp", &format!("--in-place={mode}"), "--srcs-in"])
            .arg(t.s("src"))
            .arg("--into")
            .arg(t.s("dst"))
            .arg("--no-progress")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(
            read(&t.path("dst/file")),
            read(&t.path("src/file")),
            "{mode}"
        );
        assert_eq!(inode(&t.path("dst/file")) == before, kept, "{mode}");
        assert_eq!(stderr_of(&out).contains(WARNING), kept, "{mode}: {out:?}");
    }
}

/// Set `name` to `value` on `path`, or say the filesystem has no such
/// attributes.
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

/// A Linux access ACL that lets user 12345 read the file too.
fn acl_with_a_named_reader() -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 12345),
        (4, 4, u32::MAX),
        (16, 4, u32::MAX),
        (32, 4, u32::MAX),
    ] {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(permissions.to_le_bytes());
        bytes.extend(id.to_le_bytes());
    }
    bytes
}

/// Each file syq cannot vouch for is replaced, and the rest updated in
/// place: one with another name, one more widely readable than the copy's
/// mode, one with an ACL the copy does not give it, one with a set-ID bit,
/// and one its owner cannot write. The summary and `--results` count them
/// by reason, and a preview counts the same.
#[test]
fn files_syq_cannot_vouch_for_are_replaced_and_counted_by_reason() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root opens files its mode does not let it write");
        return;
    }
    for route in ["local", "ssh"] {
        let t = Tmp::new();
        // name, source mode, destination mode
        let files = [
            ("mine", 0o644, 0o644),
            ("linked", 0o644, 0o644),
            ("wider", 0o600, 0o644),
            ("acl", 0o644, 0o644),
            ("setid", 0o755, 0o4755),
            ("read-only", 0o444, 0o444),
        ];
        for (seed, (name, source_mode, destination_mode)) in files.into_iter().enumerate() {
            let source = t.path(&format!("src/{name}"));
            let destination = t.path(&format!("dst/{name}"));
            write(&source, &prng(256 << 10, 610 + seed as u64));
            write(&destination, &prng(256 << 10, 620 + seed as u64));
            fs::set_permissions(&source, fs::Permissions::from_mode(source_mode)).unwrap();
            fs::set_permissions(&destination, fs::Permissions::from_mode(destination_mode))
                .unwrap();
            set_mtime(&source, 1_700_000_000);
        }
        fs::hard_link(t.path("dst/linked"), t.path("outside")).unwrap();
        let acls = set_attribute(
            &t.path("dst/acl"),
            "system.posix_acl_access",
            &acl_with_a_named_reader(),
        );
        let inodes: Vec<u64> = files
            .iter()
            .map(|(name, _, _)| inode(&t.path(&format!("dst/{name}"))))
            .collect();
        let mut expected = serde_json::json!({
            "other_names": 1,
            "privileges": 1,
            "wider_permissions": 2,
            "not_writable": 1,
        });
        let mut summary = "replaced 5 existing files instead of updating them in place: 1 with other hard links, 1 with set-ID bits or privileged attributes, 2 with wider permissions, 1 that could not be opened for writing";
        if !acls {
            expected["wider_permissions"] = 1.into();
            summary = "replaced 4 existing files instead of updating them in place: 1 with other hard links, 1 with set-ID bits or privileged attributes, 1 with wider permissions, 1 that could not be opened for writing";
        }
        // A preview counts the same files, copying ACLs, which it then
        // reads.
        let metadata = "--copy-metadata=permissions,acls";
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
            let kept = *name == "mine" || (*name == "acl" && !acls);
            assert_eq!(inode(&destination) == *before, kept, "{route}: {name}");
        }
        assert_eq!(read(&t.path("outside")), prng(256 << 10, 621), "{route}");
        assert!(partial_files(&t.0).is_empty(), "{route}");
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
