//! A directory whose permissions, group or ACL are applied after it is filled
//! must not let anyone but its owner reach the entries published into it
//! before then. Each test holds the copy at finalization, after every entry is
//! published and before any directory metadata is applied, and checks that
//! the finished copy still has the same metadata as before.
use super::*;

/// The umask every copy here runs with.
const UMASK: u32 = 0o022;

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// No group or other permission bits, and so no effective named ACL entries.
fn private(mode: u32) -> bool {
    mode & 0o077 == 0
}

fn syq_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command.args(args).arg("--no-progress");
    command
}

/// Run `command` with a fixed umask, call `observe` while syq waits at copy
/// finalization, and return its observation and the finished command's output.
fn observe_before_finalization<R>(
    t: &Tmp,
    mut command: Command,
    observe: impl FnOnce() -> R,
) -> (R, Output) {
    let ready = t.path("finalizing");
    let continuation = t.path("continue");
    let _ = fs::remove_file(&ready);
    let _ = fs::remove_file(&continuation);
    command
        .env("SYQ_TEST_FINALIZATION_READY_FILE", &ready)
        .env("SYQ_TEST_FINALIZATION_CONTINUE_FILE", &continuation)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let mut child = command.start().unwrap();
    wait_for_confinement_marker(&mut child, &ready, "copy finalization");
    let observed = observe();
    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    (observed, output)
}

fn modes(t: &Tmp, paths: &[&str]) -> Vec<u32> {
    paths.iter().map(|path| mode(&t.path(path))).collect()
}

fn octal(modes: &[u32]) -> String {
    let modes: Vec<String> = modes.iter().map(|mode| format!("{mode:o}")).collect();
    modes.join(" ")
}

fn source_tree(t: &Tmp, root_mode: u32, sub_mode: u32) {
    write(&t.path("src/file"), b"root file");
    write(&t.path("src/sub/file"), b"nested file");
    fs::set_permissions(t.path("src/sub"), fs::Permissions::from_mode(sub_mode)).unwrap();
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(root_mode)).unwrap();
}

#[test]
fn a_new_destination_root_is_private_until_it_takes_the_source_permissions() {
    let default_rsync = 0o777 & !UMASK;
    // (arguments, destination root's mode after the copy, private while filled)
    let cases: [(&[&str], u32, bool); 6] = [
        (&["rsync", "-a", "src/", "dst/"], 0o750, true),
        (&["rsync", "-rp", "src/", "dst/"], 0o750, true),
        (
            &[
                "cp",
                "--copy-metadata=permissions",
                "--srcs-in",
                "src",
                "--into",
                "dst",
            ],
            0o750,
            true,
        ),
        // Group without permissions: the root's default mode is restored.
        (&["rsync", "-rg", "src/", "dst/"], default_rsync, true),
        (
            &[
                "cp",
                "--copy-metadata=ownership",
                "--srcs-in",
                "src",
                "--into",
                "dst",
            ],
            0o755,
            true,
        ),
        // Nothing is applied later: the creation mode is already final.
        (&["rsync", "-r", "src/", "dst/"], default_rsync, false),
    ];
    for (args, final_mode, private_while_filled) in cases {
        let t = Tmp::new();
        source_tree(&t, 0o750, 0o750);
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        let (during, output) = observe_before_finalization(&t, command, || mode(&t.path("dst")));
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst/sub/file")), b"nested file");
        let after = mode(&t.path("dst"));
        assert_eq!(
            after, final_mode,
            "{args:?}: root is {after:o} after the copy"
        );
        if private_while_filled {
            assert!(
                private(during),
                "{args:?}: root was {during:o} while filled"
            );
        } else {
            assert_eq!(during, final_mode, "{args:?}");
        }
    }
}

#[test]
fn new_directories_stay_private_while_group_metadata_is_pending() {
    // Group without permissions restores the source mode limited by the
    // umask, with owner access, as creating the directory directly did.
    let restored = (0o775 | 0o700) & !UMASK;
    // (arguments, private while filled, nested directory mode after the copy)
    let cases: [(&[&str], bool, u32); 4] = [
        (&["rsync", "-a", "src/", "dst/"], true, 0o775),
        (&["rsync", "-rg", "src/", "dst/"], true, restored),
        (
            &[
                "cp",
                "--copy-metadata=ownership",
                "--srcs-in",
                "src",
                "--into",
                "dst",
            ],
            true,
            restored,
        ),
        // Permissions alone: created with its final bits through the umask,
        // as before, which grants no one more than the finished copy.
        (
            &[
                "cp",
                "--copy-metadata=permissions",
                "--srcs-in",
                "src",
                "--into",
                "dst",
            ],
            false,
            0o775,
        ),
    ];
    for (args, private_while_filled, final_mode) in cases {
        let t = Tmp::new();
        source_tree(&t, 0o755, 0o775);
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        let (during, output) =
            observe_before_finalization(&t, command, || mode(&t.path("dst/sub")));
        assert_output_ok(&output);
        let after = mode(&t.path("dst/sub"));
        assert_eq!(
            after, final_mode,
            "{args:?}: dst/sub is {after:o} after the copy"
        );
        assert_eq!(
            fs::metadata(t.path("dst/sub")).unwrap().gid(),
            fs::metadata(t.path("src/sub")).unwrap().gid()
        );
        if private_while_filled {
            assert!(
                private(during),
                "{args:?}: dst/sub was {during:o} while filled"
            );
        } else {
            assert_eq!(during, final_mode & !UMASK, "{args:?}");
        }
    }
}

/// A supplementary group of this process other than its effective group.
#[cfg(target_os = "linux")]
fn other_group() -> Option<libc::gid_t> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = vec![0; count.max(0) as usize];
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    groups.truncate(count.max(0) as usize);
    let effective = unsafe { libc::getegid() };
    groups.into_iter().find(|group| *group != effective)
}

#[cfg(target_os = "linux")]
#[test]
fn a_setgid_parent_group_cannot_reach_entries_before_the_source_group_is_applied() {
    let Some(group) = other_group() else {
        eprintln!("skipped: this process has no supplementary group to own the parent");
        return;
    };
    // (arguments, final modes of the root and the nested directory)
    for (args, final_modes) in [
        // Without -p the default modes are restored, keeping the setgid bit
        // the directories inherited from their parent even though their
        // group changed.
        (
            &["rsync", "-rg", "src/", "shared/dst/"][..],
            [0o2755, 0o2000 | ((0o751 | 0o700) & !UMASK)],
        ),
        (&["rsync", "-a", "src/", "shared/dst/"][..], [0o755, 0o751]),
    ] {
        let t = Tmp::new();
        source_tree(&t, 0o755, 0o751);
        fs::create_dir(t.path("shared")).unwrap();
        std::os::unix::fs::chown(t.path("shared"), None, Some(group)).unwrap();
        fs::set_permissions(t.path("shared"), fs::Permissions::from_mode(0o2775)).unwrap();
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        let (during, output) = observe_before_finalization(&t, command, || {
            ["shared/dst", "shared/dst/sub"].map(|path| {
                let metadata = fs::metadata(t.path(path)).unwrap();
                (metadata.gid(), metadata.mode() & 0o7777)
            })
        });
        assert_output_ok(&output);
        assert_eq!(read(&t.path("shared/dst/sub/file")), b"nested file");
        let source_gid = fs::metadata(t.path("src")).unwrap().gid();
        for path in ["shared/dst", "shared/dst/sub"] {
            assert_eq!(fs::metadata(t.path(path)).unwrap().gid(), source_gid);
        }
        let after = modes(&t, &["shared/dst", "shared/dst/sub"]);
        assert_eq!(
            after,
            final_modes,
            "{args:?}: {} after the copy",
            octal(&after)
        );
        for (gid, during) in during {
            // The directory inherited the parent's group, which the copy has
            // not replaced yet: that group must not be able to enter it.
            assert_eq!(gid, group, "{args:?}");
            assert!(private(during), "{args:?}: {during:o} while filled");
        }
    }
}

#[cfg(target_os = "linux")]
fn default_acl_granting(uid: u32) -> Vec<u8> {
    let mut bytes = 2u32.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (1u16, 7u16, u32::MAX),
        (2, 7, uid),
        (4, 5, u32::MAX),
        (16, 7, u32::MAX),
        (32, 5, u32::MAX),
    ] {
        bytes.extend(tag.to_le_bytes());
        bytes.extend(permissions.to_le_bytes());
        bytes.extend(id.to_le_bytes());
    }
    bytes
}

#[cfg(target_os = "linux")]
fn xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = std::ffi::CString::new(name).unwrap();
    let mut value = vec![0u8; 65536];
    let count = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if count < 0 {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENODATA)
        );
        return None;
    }
    value.truncate(count as usize);
    Some(value)
}

#[cfg(target_os = "linux")]
#[test]
fn an_inherited_default_acl_grants_nothing_before_the_source_acl_is_applied() {
    use std::os::unix::ffi::OsStrExt;
    let t = Tmp::new();
    source_tree(&t, 0o755, 0o755);
    fs::create_dir(t.path("shared")).unwrap();
    let acl = default_acl_granting(12345);
    let path = std::ffi::CString::new(t.path("shared").as_os_str().as_bytes()).unwrap();
    let name = c"system.posix_acl_default";
    if unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    } != 0
    {
        eprintln!(
            "skipped: this filesystem rejected a default ACL: {}",
            std::io::Error::last_os_error()
        );
        return;
    }
    let mut command = syq_command(&["rsync", "-aA", "src/", "shared/dst/"]);
    command.current_dir(&t.0);
    let (during, output) = observe_before_finalization(&t, command, || {
        ["shared/dst", "shared/dst/sub"].map(|path| {
            (
                mode(&t.path(path)),
                xattr(&t.path(path), "system.posix_acl_access").is_some(),
            )
        })
    });
    assert_output_ok(&output);
    for path in ["shared/dst", "shared/dst/sub"] {
        assert_eq!(xattr(&t.path(path), "system.posix_acl_access"), None);
        assert_eq!(mode(&t.path(path)), 0o755);
    }
    for (during, inherited) in during {
        // The named entry is inherited, but the mask (the group bits) grants
        // it nothing until the source's ACL replaces it.
        assert!(inherited);
        assert!(private(during), "{during:o} while filled");
    }
}

#[test]
fn an_existing_directory_is_narrowed_before_it_is_filled() {
    for (perms, during_modes, final_modes) in [
        // -p: narrowed to the final mode at the start (with owner access while
        // filling) and never widened early.
        (
            true,
            [0o750, 0o700, 0o700, 0o751],
            [0o750, 0o500, 0o755, 0o751],
        ),
        // Without -p, existing directories keep their modes throughout.
        (
            false,
            [0o755, 0o777, 0o700, 0o751],
            [0o755, 0o777, 0o700, 0o751],
        ),
    ] {
        let t = Tmp::new();
        write(&t.path("src/wide/file"), b"wide");
        write(&t.path("src/narrow/file"), b"narrow");
        write(&t.path("src/same/file"), b"same");
        for (path, mode) in [
            ("src/wide", 0o500),
            ("src/narrow", 0o755),
            ("src/same", 0o751),
            ("src", 0o750),
        ] {
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(mode)).unwrap();
        }
        for (path, mode) in [
            ("dst", 0o755),
            ("dst/wide", 0o777),
            ("dst/narrow", 0o700),
            ("dst/same", 0o751),
        ] {
            fs::create_dir_all(t.path(path)).unwrap();
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(mode)).unwrap();
        }
        let args: &[&str] = if perms {
            &["rsync", "-rp", "src/", "dst/"]
        } else {
            &["rsync", "-r", "src/", "dst/"]
        };
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        let paths = ["dst", "dst/wide", "dst/narrow", "dst/same"];
        let (during, output) = observe_before_finalization(&t, command, || modes(&t, &paths));
        assert_output_ok(&output);
        let after = modes(&t, &paths);
        assert_eq!(after, final_modes, "perms={perms}: {} after", octal(&after));
        assert_eq!(
            during,
            during_modes,
            "perms={perms}: {} while filled",
            octal(&during)
        );
        fs::set_permissions(t.path("dst/wide"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(read(&t.path("dst/wide/file")), b"wide");
    }
}

#[test]
fn a_mapping_mode_narrower_than_the_source_applies_while_filling() {
    let t = Tmp::new();
    write(&t.path("src/d/file"), b"mapped");
    fs::set_permissions(t.path("src/d"), fs::Permissions::from_mode(0o755)).unwrap();
    write(
        &t.path("mapping"),
        format!(
            "{}\n{}\n",
            r#"{"src":{"encoding":"utf-8","value":"d"},"dst":{"encoding":"utf-8","value":"d"},"kind":"dir","metadata":{"mode":448}}"#,
            entry_line("d/file", "d/file", None)
        )
        .as_bytes(),
    );
    let mut command = syq_command(&["cp", "-C", "src", "--mapping", "mapping", "--into", "dst"]);
    command.current_dir(&t.0);
    let (during, output) = observe_before_finalization(&t, command, || mode(&t.path("dst/d")));
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/d/file")), b"mapped");
    assert_eq!(mode(&t.path("dst/d")), 0o700);
    assert_eq!(during, 0o700, "{during:o} while filled");
}

#[test]
fn a_remote_receiver_keeps_new_directories_private_until_finalization() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    source_tree(&t, 0o750, 0o751);
    for (args, root, sub) in [
        (&["-a"][..], 0o750, 0o751),
        (&["-rg"][..], 0o777 & !UMASK, 0o751 | 0o700),
    ] {
        let destination = t.path("dst");
        let _ = fs::remove_dir_all(&destination);
        let mut command = remote_syq_command(&t, &rsh, args);
        command.args([
            &format!("{}/", t.s("src")),
            &format!("fake:{}/", t.s("dst")),
        ]);
        let (during, output) =
            observe_before_finalization(&t, command, || modes(&t, &["dst", "dst/sub"]));
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst/sub/file")), b"nested file");
        let after = modes(&t, &["dst", "dst/sub"]);
        assert_eq!(after, [root, sub], "{args:?}: {} after", octal(&after));
        assert!(
            during.iter().all(|mode| private(*mode)),
            "{args:?}: {} while filled",
            octal(&during)
        );
    }
}

#[test]
fn directories_created_together_keep_their_own_modes() {
    // A batch creates parents and children together. A child must not create
    // its missing parent with default permissions ahead of the parent's own
    // creation, which would leave the parent wider than its source.
    let t = Tmp::new();
    for index in 0..128 {
        write(&t.path(&format!("src/d{index}/e/f/file")), b"x");
    }
    for index in 0..128 {
        for path in [
            format!("src/d{index}/e/f"),
            format!("src/d{index}/e"),
            format!("src/d{index}"),
        ] {
            fs::set_permissions(t.path(&path), fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let mut command = syq_command(&["rsync", "-r", "src/", "dst/"]);
    command.current_dir(&t.0);
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let output = command.run().unwrap();
    assert_output_ok(&output);
    let mut wide = Vec::new();
    for index in 0..128 {
        for path in [
            format!("dst/d{index}"),
            format!("dst/d{index}/e"),
            format!("dst/d{index}/e/f"),
        ] {
            if mode(&t.path(&path)) != 0o700 {
                wide.push(format!("{path} {:o}", mode(&t.path(&path))));
            }
        }
    }
    assert!(wide.is_empty(), "{wide:?}");
}
