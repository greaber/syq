//! A directory receives its copied permissions, group and ACL after it is
//! filled. Until then it must not let anyone reach or list the entries
//! created in it whom the finished directory would keep out. Read permission
//! is checked only when a directory is opened, so a directory must be closed
//! to them from the moment it is created or, if it already exists, before
//! anything is created in it. Tests hold the copy right after a directory is
//! created, before the first file's data is written, or at finalization, and
//! also check that the finished copy keeps the metadata it had before.
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

/// Start `command` with a fixed umask, held at the named test barrier
/// (`SYQ_TEST_<barrier>_READY_FILE`), and wait until it gets there.
fn start_held(t: &Tmp, mut command: Command, barrier: &str) -> (std::process::Child, PathBuf) {
    let ready = t.path("held");
    let continuation = t.path("continue");
    let _ = fs::remove_file(&ready);
    let _ = fs::remove_file(&continuation);
    command
        .env(format!("SYQ_TEST_{barrier}_READY_FILE"), &ready)
        .env(format!("SYQ_TEST_{barrier}_CONTINUE_FILE"), &continuation)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let mut child = command.start().unwrap();
    wait_for_confinement_marker(&mut child, &ready, barrier);
    (child, continuation)
}

/// Run `command`, call `observe` while syq holds at the named barrier, and
/// return its observation and the finished command's output.
fn observe_at<R>(
    t: &Tmp,
    command: Command,
    barrier: &str,
    observe: impl FnOnce() -> R,
) -> (R, Output) {
    let (child, continuation) = start_held(t, command, barrier);
    let observed = observe();
    release_confinement_barrier(&continuation);
    (observed, child.wait_with_output().unwrap())
}

/// The same at copy finalization: everything is published, and no final
/// directory metadata is applied yet.
fn observe_before_finalization<R>(
    t: &Tmp,
    command: Command,
    observe: impl FnOnce() -> R,
) -> (R, Output) {
    observe_at(t, command, "FINALIZATION", observe)
}

/// The same right after the receiver creates the directory whose path ends
/// with `suffix`, before anything is created inside it.
fn observe_at_creation<R>(
    t: &Tmp,
    mut command: Command,
    suffix: &str,
    observe: impl FnOnce() -> R,
) -> (R, Output) {
    command.env("SYQ_TEST_CREATED_DIRECTORY_SUFFIX", suffix);
    observe_at(t, command, "CREATED_DIRECTORY", observe)
}

/// A directory's group, mode and listing.
fn state(path: &Path) -> (u32, u32, usize) {
    let metadata = fs::metadata(path).unwrap();
    (
        metadata.gid(),
        metadata.mode() & 0o7777,
        fs::read_dir(path).unwrap().count(),
    )
}

/// Whether `during` grants no group or other access that `after` lacks.
fn within(during: u32, after: u32) -> bool {
    during & 0o077 & !after == 0
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
fn a_new_destination_root_grants_no_more_than_its_source_while_filled() {
    // (arguments, destination root's mode after the copy): its source's,
    // except that native cp gives a root whose mode is not copied the
    // default.
    let cases: [(&[&str], u32); 6] = [
        (&["rsync", "-a", "src/", "dst/"], 0o750),
        (&["rsync", "-rp", "src/", "dst/"], 0o750),
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
        ),
        (&["rsync", "-rg", "src/", "dst/"], 0o750),
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
        ),
        (&["rsync", "-r", "src/", "dst/"], 0o750),
    ];
    for (args, final_mode) in cases {
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
        assert!(
            within(during, after),
            "{args:?}: root was {during:o} while filled"
        );
    }
}

/// A supplementary group of this process other than its effective group.
#[cfg(target_os = "linux")]
pub(crate) fn other_group() -> Option<libc::gid_t> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = vec![0; count.max(0) as usize];
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    groups.truncate(count.max(0) as usize);
    let effective = unsafe { libc::getegid() };
    groups.into_iter().find(|group| *group != effective)
}

#[cfg(target_os = "linux")]
#[test]
fn a_new_directory_has_its_final_group_before_anything_is_published() {
    let Some(group) = other_group() else {
        eprintln!("skipped: this process has no supplementary group to own the parent");
        return;
    };
    // (arguments, permission bits of the root and the nested directory after
    // the copy). Whether a group change clears an inherited setgid bit depends
    // on the filesystem, so only the root's restored setgid bit is checked.
    for (args, final_modes) in [
        (
            &["rsync", "-rg", "src/", "shared/dst/"][..],
            [0o2755, (0o751 | 0o700) & !UMASK],
        ),
        (&["rsync", "-a", "src/", "shared/dst/"][..], [0o755, 0o751]),
    ] {
        let t = Tmp::new();
        source_tree(&t, 0o755, 0o751);
        fs::create_dir(t.path("shared")).unwrap();
        std::os::unix::fs::chown(t.path("shared"), None, Some(group)).unwrap();
        fs::set_permissions(t.path("shared"), fs::Permissions::from_mode(0o2775)).unwrap();
        let source_gid = fs::metadata(t.path("src")).unwrap().gid();
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        // Held before the first file's data is written: the directories
        // exist, inherited the parent's group, and hold nothing published.
        let (during, output) = observe_at(&t, command, "SMALL_STAGE", || {
            ["shared/dst", "shared/dst/sub"].map(|path| {
                let metadata = fs::metadata(t.path(path)).unwrap();
                (
                    metadata.gid(),
                    metadata.mode() & 0o7777,
                    t.path(path).join("file").exists(),
                )
            })
        });
        assert_output_ok(&output);
        assert_eq!(read(&t.path("shared/dst/sub/file")), b"nested file");
        for path in ["shared/dst", "shared/dst/sub"] {
            assert_eq!(fs::metadata(t.path(path)).unwrap().gid(), source_gid);
        }
        let after = modes(&t, &["shared/dst", "shared/dst/sub"]);
        assert_eq!(
            [after[0], after[1] & !0o2000],
            final_modes,
            "{args:?}: {} after the copy",
            octal(&after)
        );
        for ((gid, during, published), after) in during.into_iter().zip(after) {
            assert!(!published, "{args:?}: a file was published already");
            assert_eq!(gid, source_gid, "{args:?}: still the parent's group");
            assert!(within(during, after), "{args:?}: {during:o} while filled");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn an_existing_directory_has_its_final_group_before_anything_is_published() {
    let Some(group) = other_group() else {
        eprintln!("skipped: this process has no supplementary group to own the destination");
        return;
    };
    for args in [
        &["rsync", "-rg", "src/", "dst/"][..],
        &["rsync", "-a", "src/", "dst/"][..],
    ] {
        let t = Tmp::new();
        source_tree(&t, 0o750, 0o750);
        for path in ["dst", "dst/sub"] {
            fs::create_dir_all(t.path(path)).unwrap();
            std::os::unix::fs::chown(t.path(path), None, Some(group)).unwrap();
            fs::set_permissions(t.path(path), fs::Permissions::from_mode(0o750)).unwrap();
        }
        let source_gid = fs::metadata(t.path("src")).unwrap().gid();
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        let (during, output) = observe_at(&t, command, "SMALL_STAGE", || {
            ["dst", "dst/sub"].map(|path| fs::metadata(t.path(path)).unwrap().gid())
        });
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst/sub/file")), b"nested file");
        for path in ["dst", "dst/sub"] {
            assert_eq!(fs::metadata(t.path(path)).unwrap().gid(), source_gid);
            assert_eq!(mode(&t.path(path)), 0o750, "{args:?}: {path}");
        }
        // The old group, which the copy replaces, must not reach new files.
        assert_eq!(during, [source_gid; 2], "{args:?}: group while filled");
    }
}

#[test]
fn a_new_destination_root_is_private_from_its_creation() {
    // (arguments, private while its metadata is pending)
    let cases: [(&[&str], bool); 6] = [
        (&["rsync", "-a", "src/", "dst/"], true),
        (&["rsync", "-rp", "src/", "dst/"], true),
        (&["rsync", "-rg", "src/", "dst/"], true),
        (
            &[
                "cp",
                "--copy-metadata=permissions",
                "--srcs-in",
                "src",
                "--into",
                "dst",
            ],
            true,
        ),
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
        ),
        // Nothing is applied later: its creation mode is final.
        (&["rsync", "-r", "src/", "dst/"], false),
    ];
    for (args, private_while_pending) in cases {
        let t = Tmp::new();
        source_tree(&t, 0o750, 0o750);
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        let ((_, during, listed), output) =
            observe_at_creation(&t, command, "/dst", || state(&t.path("dst")));
        assert_output_ok(&output);
        assert_eq!(read(&t.path("dst/sub/file")), b"nested file");
        assert_eq!(listed, 0, "{args:?}");
        let after = mode(&t.path("dst"));
        if private_while_pending {
            assert!(
                private(during),
                "{args:?}: root was {during:o} when created"
            );
        } else {
            assert_eq!(during, after, "{args:?}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_new_directory_never_opens_to_its_starting_group() {
    let Some(group) = other_group() else {
        eprintln!("skipped: this process has no supplementary group");
        return;
    };
    for args in [
        &["rsync", "-rg", "src/", "shared/dst/"][..],
        &["rsync", "-a", "src/", "shared/dst/"][..],
        // An exact target is created with the rest, not before the scan.
        &["rsync", "-rg", "src/", "shared/dst"][..],
    ] {
        // The destination parent is setgid with another group. `sub` has
        // the root's source group, `other` the parent's group, so each one
        // starts with a group other than its own at some point.
        let t = Tmp::new();
        source_tree(&t, 0o755, 0o751);
        write(&t.path("src/other/file"), b"other file");
        std::os::unix::fs::chown(t.path("src/other"), None, Some(group)).unwrap();
        fs::set_permissions(t.path("src/other"), fs::Permissions::from_mode(0o751)).unwrap();
        fs::create_dir(t.path("shared")).unwrap();
        std::os::unix::fs::chown(t.path("shared"), None, Some(group)).unwrap();
        fs::set_permissions(t.path("shared"), fs::Permissions::from_mode(0o2775)).unwrap();
        let root_gid = fs::metadata(t.path("src")).unwrap().gid();
        for (suffix, path, final_gid) in [
            ("/dst/sub", "shared/dst/sub", root_gid),
            ("/dst/other", "shared/dst/other", group),
            ("shared/dst", "shared/dst", root_gid),
        ] {
            let _ = fs::remove_dir_all(t.path("shared/dst"));
            let mut command = syq_command(args);
            command.current_dir(&t.0);
            let ((gid, during, listed), output) =
                observe_at_creation(&t, command, suffix, || state(&t.path(path)));
            assert_output_ok(&output);
            assert_eq!(listed, 0, "{args:?}: {path}");
            let after = mode(&t.path(path));
            assert_eq!(fs::metadata(t.path(path)).unwrap().gid(), final_gid);
            assert_eq!(
                after & 0o777,
                if path == "shared/dst" { 0o755 } else { 0o751 }
            );
            assert!(
                private(during) || (gid == final_gid && within(during, after)),
                "{args:?}: {path} was {during:o} with group {gid} when created"
            );
        }
        assert_eq!(read(&t.path("shared/dst/other/file")), b"other file");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn an_existing_directory_found_at_a_new_path_is_never_widened() {
    let Some(group) = other_group() else {
        eprintln!("skipped: this process has no supplementary group");
        return;
    };
    let t = Tmp::new();
    source_tree(&t, 0o755, 0o755);
    fs::create_dir(t.path("shared")).unwrap();
    std::os::unix::fs::chown(t.path("shared"), None, Some(group)).unwrap();
    fs::set_permissions(t.path("shared"), fs::Permissions::from_mode(0o2775)).unwrap();
    let mut command = syq_command(&["rsync", "-rg", "src/", "shared/dst/"]);
    command.current_dir(&t.0);
    // Someone creates a private directory where syq planned a new one,
    // after the destination appears and before syq creates it.
    let ((), output) = observe_at_creation(&t, command, "shared/dst", || {
        fs::create_dir(t.path("shared/dst/sub")).unwrap();
        fs::set_permissions(t.path("shared/dst/sub"), fs::Permissions::from_mode(0o700)).unwrap();
    });
    assert_output_ok(&output);
    assert_eq!(read(&t.path("shared/dst/sub/file")), b"nested file");
    let after = mode(&t.path("shared/dst/sub"));
    assert_eq!(after & 0o777, 0o700, "{after:o}");
}

#[test]
fn an_existing_directory_is_narrowed_before_anything_is_created_in_it() {
    let t = Tmp::new();
    write(&t.path("src/wide/inner/file"), b"inner");
    fs::set_permissions(t.path("src/wide"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(t.path("dst/wide")).unwrap();
    fs::set_permissions(t.path("dst/wide"), fs::Permissions::from_mode(0o777)).unwrap();
    let mut command = syq_command(&["rsync", "-rp", "src/", "dst/"]);
    command.current_dir(&t.0);
    let (during, output) =
        observe_at_creation(&t, command, "/wide/inner", || mode(&t.path("dst/wide")));
    assert_output_ok(&output);
    assert_eq!(read(&t.path("dst/wide/inner/file")), b"inner");
    assert_eq!(mode(&t.path("dst/wide")), 0o700);
    assert_eq!(during, 0o700, "{during:o} when its first entry was created");
}

#[cfg(target_os = "linux")]
#[test]
fn an_existing_directory_takes_its_group_before_anything_is_created_in_it() {
    let Some(group) = other_group() else {
        eprintln!("skipped: this process has no supplementary group");
        return;
    };
    let t = Tmp::new();
    write(&t.path("src/wide/inner/file"), b"inner");
    fs::create_dir_all(t.path("dst/wide")).unwrap();
    std::os::unix::fs::chown(t.path("dst/wide"), None, Some(group)).unwrap();
    fs::set_permissions(t.path("dst/wide"), fs::Permissions::from_mode(0o750)).unwrap();
    let source_gid = fs::metadata(t.path("src/wide")).unwrap().gid();
    let mut command = syq_command(&["rsync", "-rg", "src/", "dst/"]);
    command.current_dir(&t.0);
    let (during, output) = observe_at_creation(&t, command, "/wide/inner", || {
        fs::metadata(t.path("dst/wide")).unwrap().gid()
    });
    assert_output_ok(&output);
    assert_eq!(fs::metadata(t.path("dst/wide")).unwrap().gid(), source_gid);
    assert_eq!(during, source_gid, "group when its first entry was created");
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
fn narrowing_existing_permissions_does_not_implicitly_widen_owner_access() {
    for widen in [false, true] {
        let t = Tmp::new();
        write(&t.path("src/d/file"), b"private");
        fs::set_permissions(t.path("src/d"), fs::Permissions::from_mode(0o500)).unwrap();
        fs::create_dir_all(t.path("dst/d")).unwrap();
        fs::set_permissions(t.path("dst/d"), fs::Permissions::from_mode(0o555)).unwrap();
        let mut command = syq_command(&[
            "cp",
            "--copy-metadata=permissions",
            "--srcs-in",
            "src",
            "--into",
            "dst",
        ]);
        command.current_dir(&t.0);
        if widen {
            command.arg("--temporarily-widen-dir-permissions");
        }
        let (during, output) = observe_before_finalization(&t, command, || mode(&t.path("dst/d")));
        let can_copy = widen || unsafe { libc::geteuid() } == 0;
        assert_eq!(output.status.success(), can_copy, "{output:?}");
        assert_eq!(
            during,
            if widen && unsafe { libc::geteuid() } != 0 {
                0o700
            } else {
                0o500
            }
        );
        assert_eq!(mode(&t.path("dst/d")), 0o500);
        assert_eq!(t.path("dst/d/file").exists(), can_copy);
        fs::set_permissions(t.path("dst/d"), fs::Permissions::from_mode(0o700)).unwrap();
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
fn a_remote_receiver_grants_no_more_than_the_source_while_filling() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    source_tree(&t, 0o750, 0o751);
    for (args, root, sub) in [
        (&["-a"][..], 0o750, 0o751),
        (&["-rg"][..], 0o750, 0o751 | 0o700),
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
            during.iter().zip(&after).all(|(d, a)| within(*d, *a)),
            "{args:?}: {} while filled",
            octal(&during)
        );
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_root_another_process_creates_first_is_treated_as_an_existing_directory() {
    // Another process creates the missing destination root after syq found
    // it missing and before syq's mkdir. The copy treats it as an existing
    // directory: it keeps its mode, where a root the copy created private
    // for its group would be opened to the default mode, and what it holds
    // is looked up, so a file already there is kept. -H creates the root
    // only after the source is scanned.
    let cases: [&[&str]; 3] = [
        &["rsync", "-rg", "--ignore-existing", "src/", "dst/"],
        &["rsync", "-rgH", "--ignore-existing", "src/", "dst/"],
        &[
            "cp",
            "--copy-metadata=ownership",
            "--if-exists=keep",
            "--srcs-in",
            "src",
            "--into",
            "dst",
        ],
    ];
    for args in cases {
        let t = Tmp::new();
        source_tree(&t, 0o755, 0o755);
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        let ((), output) = observe_at(&t, command, "OPERATOR_DIRECTORY", || {
            fs::create_dir(t.path("dst")).unwrap();
            fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o700)).unwrap();
            write(&t.path("dst/file"), b"already there");
        });
        assert_output_ok(&output);
        assert_eq!(mode(&t.path("dst")), 0o700, "{args:?}");
        assert_eq!(read(&t.path("dst/file")), b"already there", "{args:?}");
        assert_eq!(read(&t.path("dst/sub/file")), b"nested file", "{args:?}");
    }
}

#[cfg(debug_assertions)]
#[test]
fn a_raced_root_without_owner_access_is_widened_as_an_existing_one_is() {
    // A root another process creates without owner access just before
    // syq's mkdir is an existing directory, widened for its owner exactly
    // when one found there before the copy would be: before planning (one
    // source) and after the scan (two sources, or -H).
    let cases: [&[&str]; 3] = [
        &[
            "cp",
            "--temporarily-widen-dir-permissions",
            "src",
            "--into",
            "dst",
        ],
        &[
            "cp",
            "--temporarily-widen-dir-permissions",
            "src",
            "other",
            "--into",
            "dst",
        ],
        &["rsync", "-rH", "src", "dst/"],
    ];
    for args in cases {
        let mut results = Vec::new();
        for raced in [true, false] {
            let t = Tmp::new();
            source_tree(&t, 0o755, 0o755);
            write(&t.path("other"), b"other file");
            let mut command = syq_command(args);
            command.current_dir(&t.0);
            let output = if raced {
                observe_at(&t, command, "OPERATOR_DIRECTORY", || {
                    fs::create_dir(t.path("dst")).unwrap();
                    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o500)).unwrap();
                })
                .1
            } else {
                fs::create_dir(t.path("dst")).unwrap();
                fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o500)).unwrap();
                unsafe {
                    command.pre_exec(|| {
                        libc::umask(0o022);
                        Ok(())
                    });
                }
                command.run().unwrap()
            };
            let copied = output.status.success();
            if copied {
                assert_eq!(
                    read(&t.path("dst/src/sub/file")),
                    b"nested file",
                    "{args:?}"
                );
            }
            results.push((output.status.code(), copied, mode(&t.path("dst"))));
        }
        assert_eq!(results[0], results[1], "{args:?}: raced, then existing");
        if args[0] == "cp" {
            assert_eq!(results[0], (Some(0), true, 0o500), "{args:?}");
        }
    }
}

#[test]
fn a_root_interrupted_right_after_its_creation_has_its_final_mode() {
    // Without -p a new destination root is created with its source's mode
    // and owner access, as any new directory is (native cp gives the
    // destination of --srcs-in the default mode), so a copy interrupted
    // right after creating it, and its retry, leave it as a whole copy does.
    // A remote source reports its root's mode when it is registered.
    let cases = [
        ("rsync", 0o750),
        ("rsync from a remote source", 0o750),
        ("cp --srcs-in", 0o755),
        ("cp --as", 0o750),
    ];
    for (case, expected) in cases {
        let t = Tmp::new();
        source_tree(&t, 0o750, 0o755);
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        fs::create_dir(t.path("remote-home")).unwrap();
        let remote_source = format!("host:{}/", t.s("src"));
        let rsh = rsh.display().to_string();
        let args: Vec<&str> = match case {
            "rsync" => vec!["rsync", "-r", "src/", "dst/"],
            "rsync from a remote source" => vec![
                "rsync",
                "-r",
                "-e",
                &rsh,
                "--syq-no-bootstrap",
                &remote_source,
                "dst/",
            ],
            "cp --srcs-in" => vec!["cp", "--srcs-in", "src", "--into", "dst"],
            _ => vec!["cp", "src", "--as", "dst"],
        };
        let command = || {
            let mut command = syq_command(&args);
            command
                .current_dir(&t.0)
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("XDG_CACHE_HOME", t.path("cache"));
            command
        };
        let mut held = command();
        held.env("SYQ_TEST_CREATED_DIRECTORY_SUFFIX", "/dst");
        let (mut child, _) = start_held(&t, held, "CREATED_DIRECTORY");
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        child.wait().unwrap();
        assert_eq!(mode(&t.path("dst")), expected, "{case}: interrupted");
        let mut retry = command();
        unsafe {
            retry.pre_exec(|| {
                libc::umask(0o022);
                Ok(())
            });
        }
        assert_output_ok(&retry.run().unwrap());
        assert_eq!(read(&t.path("dst/sub/file")), b"nested file");
        assert_eq!(mode(&t.path("dst")), expected, "{case}: after the retry");
    }
}

#[test]
fn an_interrupted_copy_ends_with_the_same_directory_metadata_after_a_retry() {
    // (arguments, modes of the root and the nested directory)
    let cases: [(&[&str], [u32; 2]); 4] = [
        // An unselected root takes no source metadata.
        (
            &[
                "cp",
                "--copy-metadata=ownership",
                "--copy-if",
                "src.kind == 'file'",
                "--srcs-in",
                "src",
                "--into",
                "dst",
            ],
            [0o755, 0o777 & !UMASK],
        ),
        (&["rsync", "-rg", "src/", "dst/"], [0o750, 0o775 & !UMASK]),
        (
            &[
                "cp",
                "--copy-metadata=ownership",
                "--srcs-in",
                "src",
                "--into",
                "dst",
            ],
            [0o755, 0o775 & !UMASK],
        ),
        (&["rsync", "-a", "src/", "dst/"], [0o750, 0o775]),
    ];
    for (args, final_modes) in cases {
        let t = Tmp::new();
        source_tree(&t, 0o750, 0o775);
        let mut command = syq_command(args);
        command.current_dir(&t.0);
        // Killed before any final directory metadata is applied.
        let (mut child, _) = start_held(&t, command, "FINALIZATION");
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        child.wait().unwrap();
        let mut retry = syq_command(args);
        retry.current_dir(&t.0);
        unsafe {
            retry.pre_exec(|| {
                libc::umask(0o022);
                Ok(())
            });
        }
        assert_output_ok(&retry.run().unwrap());
        let after = modes(&t, &["dst", "dst/sub"]);
        assert_eq!(
            after,
            final_modes,
            "{args:?}: {} after the retry",
            octal(&after)
        );
        for (destination, source) in [("dst", "src"), ("dst/sub", "src/sub")] {
            assert_eq!(
                fs::metadata(t.path(destination)).unwrap().gid(),
                fs::metadata(t.path(source)).unwrap().gid()
            );
        }
        assert_eq!(read(&t.path("dst/sub/file")), b"nested file");
    }
}

#[test]
fn directories_created_together_keep_their_own_modes() {
    directories_created_together_keep_their_modes(128, false);
}

/// On a network filesystem, a few directories created together also run in
/// parallel.
#[cfg(debug_assertions)]
#[test]
fn a_few_directories_created_together_on_a_network_filesystem_keep_their_own_modes() {
    directories_created_together_keep_their_modes(4, true);
}

fn directories_created_together_keep_their_modes(count: usize, network: bool) {
    // A batch creates parents and children together. A child must not create
    // its missing parent with default permissions ahead of the parent's own
    // creation, which would leave the parent wider than its source.
    let t = Tmp::new();
    for index in 0..count {
        write(&t.path(&format!("src/d{index}/e/f/file")), b"x");
    }
    for index in 0..count {
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
    if network {
        command.env("SYQ_TEST_NETWORK_FILESYSTEM", "1");
    }
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let output = command.run().unwrap();
    assert_output_ok(&output);
    let mut wide = Vec::new();
    for index in 0..count {
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
