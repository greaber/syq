use super::*;

/// `src/a.rs`, `src/sub/b.rs`, `logs/x.log`, `top`, and `link -> src`.
fn tree(t: &Tmp) {
    write(&t.path("root/src/a.rs"), b"fn a() {}\n");
    write(&t.path("root/src/sub/b.rs"), b"");
    write(&t.path("root/logs/x.log"), b"log");
    write(&t.path("root/top"), b"top");
    std::os::unix::fs::symlink("src", t.path("root/link")).unwrap();
}

fn find_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .current_dir(dir)
        .run()
        .unwrap()
}

fn lines(out: &Output) -> Vec<String> {
    assert_output_ok(out);
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn find_and_ls_list_the_current_directory_by_default() {
    let t = Tmp::new();
    tree(&t);
    let root = t.path("root");
    assert_eq!(
        lines(&find_in(&root, &["find"])),
        [
            "link",
            "logs",
            "logs/x.log",
            "src",
            "src/a.rs",
            "src/sub",
            "src/sub/b.rs",
            "top"
        ]
    );
    assert_eq!(
        lines(&find_in(&root, &["ls"])),
        ["link", "logs", "src", "top"]
    );
    assert_eq!(
        lines(&find_in(&root, &["ls", "--depth", "2", "src/"])),
        ["src/a.rs", "src/sub", "src/sub/b.rs"]
    );
    assert_eq!(
        lines(&find_in(&t.0, &["find", "-C", "root", "src", "top"])),
        ["src/a.rs", "src/sub", "src/sub/b.rs", "top"]
    );
    assert_eq!(
        lines(&find_in(
            &root,
            &["find", "--where", "kind = 'dir' or extension = 'log'"]
        )),
        ["logs", "logs/x.log", "src", "src/sub"]
    );
    assert_eq!(
        lines(&find_in(
            &root,
            &["find", "--ignore", "sub/", "--ignore=*.log", "src", "logs"]
        )),
        ["src/a.rs"]
    );
    let json = lines(&find_in(&root, &["ls", "--json", "logs"]));
    let record: serde_json::Value = serde_json::from_str(&json[0]).unwrap();
    assert_eq!(record["path"], "logs/x.log");
    assert_eq!(record["kind"], "file");
    assert_eq!(record["size"], 3);
    let out = find_in(&root, &["ls", "-0", "src"]);
    assert_output_ok(&out);
    assert_eq!(out.stdout, b"src/a.rs\0src/sub\0");
    let long = lines(&find_in(&root, &["ls", "-l", "link"]));
    assert!(long[0].starts_with("symlink "), "{long:?}");
    assert!(long[0].ends_with("  link -> src"), "{long:?}");
    assert_eq!(
        lines(&find_in(&root, &["ls", "--follow", "link"])),
        ["link/a.rs", "link/sub"]
    );
    let out = find_in(&root, &["find", "src", "missing"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing"));
}

#[test]
fn find_stops_quietly_when_its_reader_goes_away() {
    let t = Tmp::new();
    for i in 0..3000 {
        write(&t.path(&format!("root/d{}/f{i:05}", i % 7)), b"");
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["find"])
        .current_dir(t.path("root"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    let mut first = [0; 16];
    child.stdout.take().unwrap().read_exact(&mut first).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn pin_helper(t: &Tmp) {
    let helper = stored_remote_helper(t);
    fs::create_dir_all(helper.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), &helper).unwrap();
}

fn remote_find(t: &Tmp, rsh: &Path, args: &[&str]) -> Output {
    fs::create_dir_all(t.path("remote-home")).unwrap();
    fs::set_permissions(t.path("remote-home"), fs::Permissions::from_mode(0o700)).unwrap();
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .arg("--rsh")
        .arg(rsh)
        .args(["--on", "fake"])
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .current_dir(&t.0)
        .run()
        .unwrap()
}

/// The walk runs in the helper on the SSH endpoint and streams the same
/// output as a local walk, including entries it could not read.
#[test]
fn find_and_ls_over_ssh_match_a_local_listing() {
    let t = Tmp::new();
    tree(&t);
    let rsh = fake_rsh(&t);
    pin_helper(&t);
    let root = t.s("root");
    for args in [
        vec!["find", "-C", &root],
        vec!["ls", "-C", &root, "--json"],
        vec![
            "find",
            "-C",
            &root,
            "--where",
            "size > 0B and kind = 'file'",
            "--null",
        ],
        vec![
            "find", "-C", &root, "--depth", "1", "--long", "link", "logs",
        ],
        vec!["find", "-C", &root, "--follow", "--ignore", "b.rs", "link"],
    ] {
        let local = find_in(&t.0, &args);
        assert_output_ok(&local);
        let remote = remote_find(&t, &rsh, &args);
        assert_output_ok(&remote);
        assert_eq!(remote.stdout, local.stdout, "{args:?}");
    }
    // The listings ran through the remote shell.
    assert!(
        fs::read_to_string(t.path("rsh.log"))
            .unwrap()
            .lines()
            .count()
            >= 5
    );
    let out = remote_find(&t, &rsh, &["find", "--root", &root, "../escape"]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("outside"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A directory the walk cannot read is reported, and the listing goes on
    // and fails at its end.
    let locked = t.path("root/logs");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read_dir(&locked).is_ok();
    let local = find_in(&t.0, &["find", "-C", &root]);
    let remote = remote_find(&t, &rsh, &["find", "-C", &root]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    if !readable {
        for out in [&local, &remote] {
            assert!(!out.status.success());
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.contains("logs\n") && stdout.contains("src/sub/b.rs"),
                "{stdout}"
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(stderr.contains("cannot read directory logs"), "{stderr}");
            assert!(stderr.contains("incomplete"), "{stderr}");
        }
        assert_eq!(local.stdout, remote.stdout);
    }
    if filesystem_accepts_non_utf8_names() {
        let name = std::ffi::OsString::from_vec(b"root/bad\xff".to_vec());
        write(&t.0.join(name), b"");
        let out = remote_find(&t, &rsh, &["ls", "-C", &root, "--json"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("--null"));
        let out = remote_find(&t, &rsh, &["ls", "-C", &root, "--null"]);
        assert_output_ok(&out);
        assert!(out.stdout.windows(4).any(|w| w == b"bad\xff"));
    }
}
