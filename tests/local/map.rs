use super::*;

#[test]
fn native_copy_and_map_cwd_and_root_are_mutually_exclusive() {
    let copy = native_syq(&[
        "cp", "--cwd", ".", "--root", ".", "--src", "source", "--into", "dest",
    ]);
    assert_eq!(copy.status.code(), Some(2));

    let map = syq_map_in(
        Path::new("."),
        &["--cwd", ".", "--root", ".", "--src", "source"],
    );
    assert_eq!(map.status.code(), Some(2));
}

#[test]
fn native_mapping_uses_root_without_following_manifest_symlinks() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("base/file"), b"inside");
    write(&t.path("outside/secret"), b"outside");
    symlink("../outside", t.path("base/link")).unwrap();

    let manifest = entry_line("file", "copied", Some("file"));
    let copied = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "--root",
            &t.s("base"),
            "--into-new",
            &t.s("destination"),
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert_output_ok(&copied);
    assert_eq!(read(&t.path("destination/copied")), b"inside");

    let escaped = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "--root",
            &t.s("base"),
            "--follow-src",
            "--into-new",
            &t.s("escaped"),
            "-q",
        ],
        Some(entry_line("link/secret", "secret", Some("file")).as_bytes()),
    );
    assert!(!escaped.status.success());
    assert!(!t.path("escaped/secret").exists());
}

#[test]
fn remote_manifest_cannot_inject_digest_protocol_framing() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);

    let archive = read(&t.path("release.gz"));
    let expected_hash = sha256_hex(&archive);
    let mut alternate_archive = archive;
    alternate_archive[4] ^= 1;
    let mut decoded = Vec::new();
    GzDecoder::new(alternate_archive.as_slice())
        .read_to_end(&mut decoded)
        .unwrap();
    assert_eq!(decoded, read(Path::new(env!("CARGO_BIN_EXE_syq"))));
    write(&t.path("alternate-release.gz"), &alternate_archive);

    let mut injected_manifest = read(&t.path("release-manifest.json"));
    injected_manifest.extend_from_slice(
        format!("\nsyq-helper-manifest-end\nsyq-helper-sha256:{expected_hash}\n").as_bytes(),
    );
    write(&t.path("injected-manifest.json"), &injected_manifest);

    write(&t.path("src"), b"framing fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);
    let out = cmd
        .env(
            "FAKE_REMOTE_RELEASE_MANIFEST",
            t.path("injected-manifest.json"),
        )
        .env(
            "FAKE_REMOTE_RELEASE_ARCHIVE",
            t.path("alternate-release.gz"),
        )
        .run()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"framing fallback");
    assert_eq!(
        read(&cached_remote_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    assert_eq!(
        read(&cached_local_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote release manifest failed integrity verification or validation"),
        "{stderr}"
    );
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
}

#[test]
fn remote_manifest_signature_failure_warns_and_uses_local_verified_release() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&read(&t.path("release-manifest.json"))).unwrap();
    manifest["repository"] = "https://attacker.invalid/syq".into();
    write(
        &t.path("tampered-remote-manifest.json"),
        &serde_json::to_vec_pretty(&manifest).unwrap(),
    );

    write(&t.path("src"), b"manifest fallback");
    let remote = format!("fake:{}", t.s("dst"));
    let mut cmd = remote_syq_command(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);
    let out = cmd
        .env(
            "FAKE_REMOTE_RELEASE_MANIFEST",
            t.path("tampered-remote-manifest.json"),
        )
        .run()
        .unwrap();

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"manifest fallback");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("remote release manifest failed integrity verification or validation"),
        "{stderr}"
    );
    assert!(stderr.contains("signature verification failed"), "{stderr}");
    assert!(
        stderr.contains("uploading the verified helper over SSH"),
        "{stderr}"
    );
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
}

#[test]
fn rejects_bare_dir_into_parent_mapping_onto_itself() {
    let t = Tmp::new();
    write(&t.path("sub/f"), b"x");
    // Copying t/sub into t (existing dir) maps to t/sub — the source itself.
    let out = syq(&["-a", &t.s("sub"), &t.s(".")]);
    // t.s(".") is the tmp dir itself (existing), so effective dest = <tmp>/sub.
    assert!(
        !out.status.success(),
        "bare dir whose effective destination is itself must be rejected"
    );
    assert!(t.path("sub/f").exists());
}

#[test]
fn delete_only_inside_directories_the_sources_map_onto() {
    let t = Tmp::new();
    write(&t.path("s1/a"), b"a");
    write(&t.path("s2/b"), b"b");
    write(&t.path("dst/s1/extra"), b"x");
    write(&t.path("dst/s2/extra"), b"x");
    write(&t.path("dst/other"), b"untouched");
    run_ok(&["-a", "--delete", &t.s("s1"), &t.s("s2"), &t.s("dst")]);
    assert_eq!(
        listing(&t.path("dst")),
        ["other", "s1", "s1/a", "s2", "s2/b"]
    );
    // A dry run into a destination that doesn't exist yet has nothing to delete.
    let so = run_ok(&["-a", "-n", "--delete", &t.s("s1/"), &t.s("nowhere")]);
    assert!(
        so.contains("deletions: 0 entries planned after a successful copy"),
        "{so}"
    );
    assert!(!t.path("nowhere").exists());
    // A single-file source deletes nothing.
    write(&t.path("dst2/junk"), b"j");
    run_ok(&["-a", "--delete", &t.s("s1/a"), &t.s("dst2/")]);
    assert!(t.path("dst2/junk").exists());
}

fn syq_map_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg("map")
        .args(args)
        .current_dir(dir)
        .run()
        .expect("run syq map")
}

fn map_lines(out: &Output) -> Vec<serde_json::Value> {
    assert!(
        out.status.success(),
        "syq map failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone())
        .expect("map output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("map line is JSON"))
        .collect()
}

fn map_path(value: &serde_json::Value, key: &str) -> String {
    assert_eq!(value[key]["encoding"], "utf-8");
    value[key]["value"]
        .as_str()
        .expect("tagged path value")
        .to_string()
}

#[test]
fn native_map_contents_emits_identity_parent_first() {
    let t = Tmp::new();
    write(&t.path("src/Berlin/IMG.JPG"), b"img");
    write(&t.path("src/Notes.TXT"), b"hello");
    std::os::unix::fs::symlink("Notes.TXT", t.path("src/Link.TXT")).unwrap();
    let lines = map_lines(&syq_map_in(&t.path(""), &["--srcs-in", "src"]));
    let dsts: Vec<String> = lines.iter().map(|v| map_path(v, "dst")).collect();
    assert_eq!(dsts, ["Berlin", "Berlin/IMG.JPG", "Link.TXT", "Notes.TXT"]);
    for v in &lines {
        assert_eq!(map_path(v, "src"), map_path(v, "dst"));
    }
    assert_eq!(lines[0]["kind"], "dir");
    assert!(lines[0].get("size").is_none());
    assert_eq!(lines[1]["kind"], "file");
    assert_eq!(lines[1]["size"], 3);
    assert!(lines[1]["mtime"].is_i64());
    assert_eq!(lines[2]["kind"], "symlink");
    assert!(lines[2].get("size").is_none());
    assert_eq!(lines[3]["kind"], "file");
}

#[test]
fn native_map_uses_the_common_source_follow_policy() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("real/file"), b"data");
    symlink("real", t.path("link")).unwrap();

    let refused = syq_map_in(&t.path(""), &["--srcs-in", "link"]);
    assert!(!refused.status.success());
    assert!(stderr_of(&refused).contains("--follow-src"));

    let intermediate = syq_map_in(&t.path(""), &["--src", "link/file"]);
    assert!(!intermediate.status.success());
    let stderr = stderr_of(&intermediate);
    assert!(stderr.contains("--follow-src for source paths"), "{stderr}");

    let lines = map_lines(&syq_map_in(
        &t.path(""),
        &["--follow-src", "--srcs-in", "link"],
    ));
    assert_eq!(lines.len(), 1);
    assert_eq!(map_path(&lines[0], "src"), "file");
    assert_eq!(lines[0]["kind"], "file");

    let named = syq_map_in(&t.path(""), &["--follow", "--src", "link"]);
    let lines = map_lines(&named);
    assert_eq!(map_path(&lines[0], "src"), "real");
    assert_eq!(map_path(&lines[0], "dst"), "link");
    assert_eq!(map_path(&lines[1], "src"), "real/file");
    assert_eq!(map_path(&lines[1], "dst"), "link/file");

    let destination = Tmp::new();
    let copied = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "--cwd",
            ".",
            "--into",
            &destination.s("mapped"),
            "-q",
        ],
        Some(&named.stdout),
    );
    assert_output_ok(&copied);
    assert_eq!(read(&destination.path("mapped/link/file")), b"data");

    fs::create_dir(t.path("nested")).unwrap();
    symlink("../real", t.path("nested/link")).unwrap();
    let lines = map_lines(&syq_map_in(
        &t.path(""),
        &["--follow-src", "--src", "nested/link"],
    ));
    assert_eq!(map_path(&lines[0], "src"), "real");
    assert_eq!(map_path(&lines[0], "dst"), "link");
}

#[test]
fn native_map_follow_keeps_cwd_unconfined_but_named_sources_base_relative() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("outside/file"), b"outside");
    fs::create_dir_all(t.path("base/inside")).unwrap();
    write(&t.path("base/inside/file"), b"inside");
    symlink("../outside", t.path("base/escape")).unwrap();
    symlink(t.path("base/inside"), t.path("base/reenter")).unwrap();

    let escaped = map_lines(&syq_map_in(
        &t.path(""),
        &["-C", &t.s("base"), "--follow-src", "--srcs-in", "escape"],
    ));
    assert_eq!(map_path(&escaped[0], "src"), "file");
    assert_eq!(map_path(&escaped[0], "dst"), "file");

    let named_escape = syq_map_in(
        &t.path(""),
        &["-C", &t.s("base"), "--follow-src", "--src", "escape"],
    );
    assert!(!named_escape.status.success());
    assert!(stderr_of(&named_escape).contains("outside the mapping source base"));

    let reentered = map_lines(&syq_map_in(
        &t.path(""),
        &["-C", &t.s("base"), "--follow-src", "--src", "reenter"],
    ));
    assert_eq!(map_path(&reentered[0], "src"), "inside");
    assert_eq!(map_path(&reentered[0], "dst"), "reenter");
    assert_eq!(map_path(&reentered[1], "src"), "inside/file");
    assert_eq!(map_path(&reentered[1], "dst"), "reenter/file");
}

#[cfg(debug_assertions)]
#[test]
fn native_map_scans_the_pinned_selection_after_path_replacement() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    write(&t.path("selected/original.txt"), b"original");
    write(&t.path("outside/outside.txt"), b"outside");
    let ready = t.path("map-ready");
    let continuation = t.path("continue");
    let mut child = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["map", "--srcs-in", "selected"])
        .current_dir(t.path(""))
        .env("SYQ_TEST_MAP_SELECTION_READY_FILE", &ready)
        .env("SYQ_TEST_MAP_SELECTION_CONTINUE_FILE", &continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();

    wait_for_confinement_marker(&mut child, &ready, "map selection");

    fs::rename(t.path("selected"), t.path("selected-original")).unwrap();
    symlink("outside", t.path("selected")).unwrap();

    release_confinement_barrier(&continuation);
    let output = child.wait_with_output().unwrap();
    let lines = map_lines(&output);
    let sources: Vec<_> = lines.iter().map(|line| map_path(line, "src")).collect();
    assert_eq!(sources, ["original.txt"]);
}

#[test]
fn native_map_descriptor_walk_has_bounded_fd_use() {
    let t = Tmp::new();
    let mut directory = t.path("selected");
    for index in 0..80 {
        directory.push(format!("d{index:02}"));
    }
    fs::create_dir_all(&directory).unwrap();
    write(&directory.join("leaf"), b"leaf");

    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .args(["map", "--srcs-in", "selected"])
        .current_dir(t.path(""));
    unsafe {
        command.pre_exec(|| {
            let mut inherited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let low_limit = inherited.rlim_max.min(32);
            if low_limit < 16 {
                return Err(std::io::Error::other(
                    "inherited descriptor limit is too low for the test",
                ));
            }
            let limit = libc::rlimit {
                rlim_cur: low_limit,
                rlim_max: low_limit,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let lines = map_lines(&command.run().unwrap());
    assert_eq!(lines.len(), 81);
    assert!(map_path(lines.last().unwrap(), "src").ends_with("/leaf"));
}

#[test]
fn native_map_named_cwd_and_as_rename() {
    let t = Tmp::new();
    write(&t.path("photos/x/a.jpg"), b"a");
    // Named selector: dst gains the basename prefix.
    let lines = map_lines(&syq_map_in(&t.path(""), &["photos"]));
    let dsts: Vec<String> = lines.iter().map(|v| map_path(v, "dst")).collect();
    assert_eq!(dsts, ["photos", "photos/x", "photos/x/a.jpg"]);
    for v in &lines {
        assert_eq!(map_path(v, "src"), map_path(v, "dst"));
    }
    // -C: emitted src stays relative to the base.
    let lines = map_lines(&syq_map_in(&t.path(""), &["-C", "photos", "--src", "x"]));
    let dsts: Vec<String> = lines.iter().map(|v| map_path(v, "dst")).collect();
    assert_eq!(dsts, ["x", "x/a.jpg"]);
    assert_eq!(map_path(&lines[0], "src"), "x");
    // --as renames the single selected root; src spelling is unchanged.
    let lines = map_lines(&syq_map_in(&t.path(""), &["photos", "--as", "album"]));
    let dsts: Vec<String> = lines.iter().map(|v| map_path(v, "dst")).collect();
    assert_eq!(dsts, ["album", "album/x", "album/x/a.jpg"]);
    let srcs: Vec<String> = lines.iter().map(|v| map_path(v, "src")).collect();
    assert_eq!(srcs, ["photos", "photos/x", "photos/x/a.jpg"]);
    // --as PATH may be nested; every component is honored, none is dropped.
    let lines = map_lines(&syq_map_in(
        &t.path(""),
        &["photos", "--as", "2024/07/album"],
    ));
    let dsts: Vec<String> = lines.iter().map(|v| map_path(v, "dst")).collect();
    assert_eq!(
        dsts,
        ["2024/07/album", "2024/07/album/x", "2024/07/album/x/a.jpg"]
    );
}

#[test]
fn native_map_as_nested_path_round_trips_through_cp_mapping() {
    let t = Tmp::new();
    write(&t.path("src/photos/x/a.jpg"), b"img");
    let mapped = syq_map_in(&t.path("src"), &["photos", "--as", "2024/07/album"]);
    assert!(
        mapped.status.success(),
        "map failed: {}",
        String::from_utf8_lossy(&mapped.stderr)
    );
    let copied = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
        Some(&mapped.stdout),
    );
    assert!(
        copied.status.success(),
        "cp failed: {}",
        String::from_utf8_lossy(&copied.stderr)
    );
    assert_eq!(read(&t.path("dst/2024/07/album/x/a.jpg")), b"img");
}

#[test]
fn native_map_refusals() {
    let t = Tmp::new();
    write(&t.path("d1/n"), b"1");
    write(&t.path("d2/n"), b"2");
    let refuse = |args: &[&str], needle: &str| {
        let out = syq_map_in(&t.path(""), args);
        assert!(!out.status.success(), "expected failure for {args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(stderr.contains(needle), "stderr for {args:?}: {stderr}");
    };
    refuse(&["/etc"], "mapping source base");
    refuse(&["--srcs-in", "d1", "--srcs-in", "d2"], "only selector");
    refuse(&["--srcs-in", "d1", "d2"], "only selector");
    refuse(&["d1/n", "d2/n"], "same destination name");
    refuse(&["d1", "--as", "/abs"], "is absolute");
    refuse(&["d1", "--as", "../up"], "`..` component");
    refuse(&["d1", "--as", "a//b"], "empty, `.`, or `..` component");
    refuse(
        &["d1", "--into-new", "z"],
        "unexpected argument '--into-new'",
    );
    refuse(
        &["d1", "--from", "remotehost"],
        "unexpected argument '--from'",
    );
    refuse(&["d1", "--to", "remotehost"], "unexpected argument '--to'");
    refuse(&["d1", "--ignore", "n"], "unexpected argument '--ignore'");
    refuse(
        &["d1", "--receiver-receipt", "sizes"],
        "unexpected argument '--receiver-receipt'",
    );
}

#[test]
fn native_map_exposes_only_manifest_shaping_options() {
    let help = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["map", "--help-all"])
        .run()
        .expect("run syq map --help-all");
    assert_output_ok(&help);
    let help = String::from_utf8(help.stdout).expect("map help is UTF-8");
    // Examples may mention downstream cp options; inspect option declarations.
    let declarations = help
        .lines()
        .filter(|line| line.starts_with("  -") || line.starts_with("      --"))
        .collect::<Vec<_>>()
        .join("\n");
    for option in ["--cwd", "--follow", "--src", "--srcs-in", "--as"] {
        assert!(
            declarations.contains(option),
            "map help omitted {option}:\n{help}"
        );
    }
    for option in [
        "--from",
        "--to",
        "--into",
        "--into-new",
        "--into-existing",
        "--as-new",
        "--as-existing",
        "--mapping",
        "--results",
        "--dry-run",
        "--verbose",
        "--quiet",
        "--performance-tuning",
        "--progress",
        "--no-progress",
        "--progress-json",
        "--hash",
        "--no-compress",
        "--resource-limits",
        "bandwidth=--stats",
        "--ignore",
        "--ignore-from",
        "--preserve",
        "--inplace",
        "--receiver-max-entries",
        "--receiver-max-bytes",
        "--receiver-receipt",
    ] {
        assert!(
            !declarations.contains(option),
            "map help unexpectedly exposed {option}:\n{help}"
        );
    }
}

#[test]
fn native_map_refuses_non_utf8_names() {
    if !filesystem_accepts_non_utf8_names() {
        eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
        return;
    }
    let t = Tmp::new();
    write(&t.path("src/ok.txt"), b"ok");
    let bad = t
        .path("src")
        .join(std::ffi::OsString::from_vec(b"bad\xff.dat".to_vec()));
    write(&bad, b"x");
    let out = syq_map_in(&t.path(""), &["--srcs-in", "src"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("UTF-8"), "stderr: {stderr}");
}

#[test]
fn native_cp_mapping_renames_creates_ancestors_and_reads_stdin() {
    let t = Tmp::new();
    write(&t.path("src/Berlin/IMG.JPG"), b"img");
    write(&t.path("src/Notes.TXT"), b"hello");
    write(&t.path("dst/unrelated.txt"), b"keep");
    let manifest = format!(
        "{}{}{}",
        entry_line("Berlin", "berlin", Some("dir")),
        entry_line("Berlin/IMG.JPG", "berlin/2024/07/img.jpg", Some("file")),
        entry_line("Notes.TXT", "notes.txt", None),
    );
    // Dry run writes nothing.
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-n", "-q"],
        Some(manifest.as_bytes()),
    );
    assert!(
        out.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!t.path("dst/berlin").exists());
    // Real run from stdin: renames, implicit 2024/07 ancestors, keeps extras.
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
        Some(manifest.as_bytes()),
    );
    assert!(
        out.status.success(),
        "cp failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("dst/berlin/2024/07/img.jpg")), b"img");
    assert_eq!(read(&t.path("dst/notes.txt")), b"hello");
    assert_eq!(read(&t.path("dst/unrelated.txt")), b"keep");
    // Rerun converges cleanly.
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
        Some(manifest.as_bytes()),
    );
    assert!(out.status.success());
}

#[test]
fn native_cp_mapping_file_manifest_and_base64_src() {
    if !filesystem_accepts_non_utf8_names() {
        eprintln!("skipping: this filesystem rejects file names that are not valid UTF-8");
        return;
    }
    let t = Tmp::new();
    let bad = t
        .path("src")
        .join(std::ffi::OsString::from_vec(b"caf\xe9.txt".to_vec()));
    write(&bad, b"latin1 name");
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"caf\xe9.txt");
    let manifest = format!(
        "{{\"src\":{{\"encoding\":\"base64\",\"value\":\"{b64}\"}},\"dst\":{{\"encoding\":\"utf-8\",\"value\":\"cafe.txt\"}}}}\n"
    );
    write(&t.path("m.ndjson"), manifest.as_bytes());
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "m.ndjson", "-C", "src", "--into", "out", "-q"],
        None,
    );
    assert!(
        out.status.success(),
        "cp failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("out/cafe.txt")), b"latin1 name");
}

#[test]
fn native_cp_mapping_entry_failures_are_partial_not_fatal() {
    let t = Tmp::new();
    write(&t.path("src/real.txt"), b"real");
    fs::create_dir_all(t.path("src/adir")).unwrap();
    let manifest = format!(
        "{}{}{}",
        entry_line("missing.txt", "a.txt", None),
        entry_line("adir", "b.txt", Some("file")),
        entry_line("real.txt", "c.txt", None),
    );
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
        Some(manifest.as_bytes()),
    );
    assert_eq!(
        out.status.code(),
        Some(23),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(stderr.contains("does not exist"), "{stderr}");
    assert!(stderr.contains("not the declared file"), "{stderr}");
    assert_eq!(read(&t.path("dst/c.txt")), b"real");
    assert!(!t.path("dst/a.txt").exists());
    assert!(!t.path("dst/b.txt").exists());
}

#[test]
fn native_cp_mapping_hard_refusals() {
    let t = Tmp::new();
    write(&t.path("src/x.txt"), b"x");
    let refuse = |manifest: &str, needle: &str| {
        let out = syq_cp_in(
            &t.path(""),
            &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
            Some(manifest.as_bytes()),
        );
        assert!(!out.status.success(), "expected refusal for {manifest:?}");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(stderr.contains(needle), "wanted {needle:?} in: {stderr}");
    };
    let dup = format!(
        "{}{}",
        entry_line("x.txt", "same", None),
        entry_line("x.txt", "same", None)
    );
    refuse(&dup, "duplicate destination");
    refuse(
        "{\"src\":{\"encoding\":\"utf-8\",\"value\":\"x.txt\"},\"dst\":{\"encoding\":\"utf-8\",\"value\":\"../out\"}}\n",
        "component",
    );
    refuse(
        "{\"src\":{\"encoding\":\"utf-8\",\"value\":\"/etc/passwd\"},\"dst\":{\"encoding\":\"utf-8\",\"value\":\"y\"}}\n",
        "absolute",
    );
    refuse(
        "{\"src\":{\"encoding\":\"utf-8\",\"value\":\"x.txt\"},\"dst\":{\"encoding\":\"utf-8\",\"value\":\"y\"},\"knd\":\"file\"}\n",
        "unknown field",
    );
    // Parse-level grammar refusals.
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "src/x.txt", "--into", "dst"],
        Some(b""),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("replaces source selectors"));
    let out = syq_cp_in(&t.path(""), &["--mapping", "-", "--as", "exact"], Some(b""));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--as conflicts with --mapping"));
    let out = syq_cp_in(
        &t.path(""),
        &["--prune", "--mapping", "-", "-C", "src", "--into", "dst"],
        Some(b""),
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(stderr.contains("--prune"), "{stderr}");
}

#[test]
fn native_mapping_names_never_inherit_operator_follow() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("src")).unwrap();
    write(&t.path("outside/secret"), b"secret");
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    let manifest = entry_line("link/secret", "copied", None);
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--follow",
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("source link/secret does not exist"));
    assert!(!t.path("dst/copied").exists());
}

#[test]
fn native_cp_mapping_end_to_end_map_pipeline() {
    let t = Tmp::new();
    write(&t.path("src/Berlin/IMG.JPG"), b"img");
    write(&t.path("src/Notes.TXT"), b"hello");
    // syq map | (lowercase transform) | syq cp --mapping -
    let map_out = syq_map_in(&t.path(""), &["--srcs-in", "src"]);
    assert!(map_out.status.success());
    let transformed: String = String::from_utf8(map_out.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
            let lower = v["dst"]["value"].as_str().unwrap().to_lowercase();
            v["dst"]["value"] = serde_json::Value::String(lower);
            format!("{v}\n")
        })
        .collect();
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "pub", "-q"],
        Some(transformed.as_bytes()),
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("pub/berlin/img.jpg")), b"img");
    assert_eq!(read(&t.path("pub/notes.txt")), b"hello");
}

#[test]
fn native_cp_results_without_mapping_and_refusals() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--srcs-in",
            "src",
            "--into",
            "out",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["mapping"], false);
    let op = lines
        .iter()
        .find(|v| v["type"] == "operation_result" && v["dst"]["value"] == "f.txt")
        .expect("transfer record");
    assert_eq!(op["disposition"], "succeeded");
    assert!(op.get("src").is_none(), "non-mapping records carry no src");
    assert_eq!(lines.last().unwrap()["status"], "success");
    // map does not expose --results; pruning copies accept it (schema v1
    // covers deletions) and mark the run record.
    let out = syq_map_in(&t.path(""), &["--srcs-in", "src", "--results", "r.ndjson"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unexpected argument '--results'"));
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--prune",
            "--srcs-in",
            "src",
            "--into",
            "pruned",
            "--results",
            "r2.ndjson",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r2.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines[0]["mode"], "cp");
    assert_eq!(lines[0]["prune"], true);
    assert_eq!(lines.last().unwrap()["status"], "success");
}

#[test]
fn native_map_cwd_may_escape_while_root_confines_component_resolution() {
    let t = Tmp::new();
    write(&t.path("base/photos/a.jpg"), b"a");
    fs::create_dir_all(t.path("base/nested")).unwrap();
    write(&t.path("outside/b.jpg"), b"b");

    let lines = map_lines(&syq_map_in(&t.path("base"), &["nested/../photos"]));
    let dsts: Vec<String> = lines.iter().map(|v| map_path(v, "dst")).collect();
    assert_eq!(dsts, ["photos", "photos/a.jpg"]);
    assert_eq!(map_path(&lines[0], "src"), "photos");

    let lines = map_lines(&syq_map_in(&t.path("base"), &["--srcs-in", "../outside"]));
    assert_eq!(map_path(&lines[0], "src"), "b.jpg");
    assert_eq!(map_path(&lines[0], "dst"), "b.jpg");

    let lines = map_lines(&syq_map_in(
        &t.path("base"),
        &["--cwd", "missing-base", "--srcs-in", &t.s("outside")],
    ));
    assert_eq!(map_path(&lines[0], "src"), "b.jpg");

    let escape = syq_map_in(
        &t.path(""),
        &["--root", &t.s("base"), "--srcs-in", "../outside"],
    );
    assert!(!escape.status.success());
    assert!(stderr_of(&escape).contains("outside its confined root"));

    let absolute_escape = syq_map_in(
        &t.path(""),
        &["--root", &t.s("base"), "--srcs-in", &t.s("outside")],
    );
    assert!(!absolute_escape.status.success());

    let rooted = syq_map_in(
        &t.path(""),
        &["--root", &t.s("base"), "--src", "nested/../photos"],
    );
    let lines = map_lines(&rooted);
    assert_eq!(map_path(&lines[0], "src"), "photos");

    write(&t.path("base/file"), b"file");
    let non_directory = syq_map_in(&t.path(""), &["--root", &t.s("base"), "--src", "file/."]);
    assert!(!non_directory.status.success());
}

#[test]
fn native_cp_mapping_dry_run_implicit_ancestor_trace_has_no_src() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"a");
    let manifest = entry_line("a.txt", "sub/a.txt", None);
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-n",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert!(out.status.success());
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let dir_trace = lines
        .iter()
        .find(|v| v["type"] == "trace" && v["dst"]["value"] == "sub")
        .expect("implicit ancestor trace");
    assert!(
        dir_trace.get("src").is_none(),
        "implicit ancestors have no source: {dir_trace}"
    );
    let file_trace = lines
        .iter()
        .find(|v| v["type"] == "trace" && v["dst"]["value"] == "sub/a.txt")
        .expect("file trace");
    assert_eq!(file_trace["src"]["value"], "a.txt");
}

#[test]
fn native_cp_mapping_ancestor_conflict_gets_failed_record() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"a");
    write(&t.path("src/b.txt"), b"b");
    // x resolves to a file at execution; x/y then conflicts at runtime.
    let manifest = format!(
        "{}{}",
        entry_line("a.txt", "x", None),
        entry_line("b.txt", "x/y", None),
    );
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert_eq!(out.status.code(), Some(23));
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let failed = lines
        .iter()
        .find(|v| v["type"] == "operation_result" && v["dst"]["value"] == "x/y")
        .expect("failed record for the conflicting entry");
    assert_eq!(failed["disposition"], "failed");
    assert_eq!(failed["retryable"], "no");
    assert_eq!(failed["class"], "conflict");
}

#[test]
fn native_cp_mapping_specials_are_visible_skips_not_failures() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"abc");
    fs::create_dir_all(t.path("src")).unwrap();
    let fifo = t.path("src/pipe");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    let manifest = format!(
        "{}{}",
        entry_line("a.txt", "a.txt", None),
        entry_line("pipe", "pipe", Some("special")),
    );
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!t.path("dst/pipe").exists());
    assert_eq!(read(&t.path("dst/a.txt")), b"abc");
    let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    // Excluded entries are aggregate-only: no per-entry record, no failure.
    assert!(
        !lines
            .iter()
            .any(|v| v["type"] == "operation_result" && v["dst"]["value"] == "pipe"),
        "policy exclusions appear only in terminal aggregates"
    );
    let last = lines.last().unwrap();
    assert_eq!(last["status"], "success");
    assert_eq!(last["files_excluded"], 1);
}

#[test]
fn native_cp_mapping_whole_manifest_preflight_writes_nothing() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"a");
    write(&t.path("src/b.txt"), b"b");
    // A duplicate destination far apart: refused with nothing written,
    // even though the first entries were valid.
    let mut manifest = String::new();
    manifest.push_str(&entry_line("a.txt", "same.txt", None));
    for i in 0..5000 {
        manifest.push_str(&entry_line("b.txt", &format!("fill/{i}.txt"), None));
    }
    manifest.push_str(&entry_line("b.txt", "same.txt", None));
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
        Some(manifest.as_bytes()),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("duplicate destination"));
    // Fresh-target preflight defers the --into container too, so a manifest
    // refusal leaves no destination namespace behind.
    assert!(!t.path("dst").exists());
    // Declared-kind ancestor conflict is refused up front too.
    let conflict = format!(
        "{}{}",
        entry_line("a.txt", "p", Some("file")),
        entry_line("b.txt", "p/q.txt", None),
    );
    let out = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
        Some(conflict.as_bytes()),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not dir"));
    assert!(!t.path("dst").exists());
}

#[test]
fn native_mapping_and_map_respect_typed_selectors() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"f");
    fs::create_dir_all(t.path("src/d")).unwrap();
    // --mapping rejects typed selectors instead of silently discarding them.
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "--src-dir",
            "absent",
            "-C",
            "src",
            "--into",
            "dst",
        ],
        Some(b""),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("replaces source selectors"));
    // syq map enforces typed-selector preconditions like native cp.
    let out = syq_map_in(&t.path("src"), &["--src-non-dir", "d"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is a directory"));
    let out = syq_map_in(&t.path("src"), &["--src-dir", "f.txt"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is not a directory"));
    // Happy paths still emit.
    let lines = map_lines(&syq_map_in(
        &t.path("src"),
        &["--src-dir", "d", "--src-non-dir", "f.txt"],
    ));
    let dsts: Vec<String> = lines.iter().map(|v| map_path(v, "dst")).collect();
    assert_eq!(dsts, ["d", "f.txt"]);
}

// Each documented jq transform lives here as a constant. Tests assert the
// constant appears in its documentation page (ignoring whitespace changes),
// so semantics cannot drift silently. They then execute the real
// pipeline with jq against a local tree. Endpoints are adapted from the
// documented `--to nas --into /...` to local directories.
const DOC_JQ_LOWERCASE: &str = ".dst.value |= ascii_downcase";

const DOC_JQ_DATE_PARTITION: &str = r#"select(.kind == "file")
        | .dst.value = (.mtime | gmtime | strftime("%Y/%m")) + "/" + .dst.value"#;

const DOC_JQ_MIN_SIZE: &str = r#"select(.kind != "file" or .size >= 1048576)"#;

const DOC_JQ_RETRY_GATE: &str = r#"if (.[-1].type? // "") != "result"
        then "incomplete results stream (no terminal record)" | halt_error
        elif (.[-1].status != "success" and .[-1].status != "partial")
        then "run stopped early (status \(.[-1].status)); rerun it instead of retrying" | halt_error
        else .[] | select(.type == "operation_result"
                          and .disposition == "failed"
                          and .retryable != "no")
             | {src, dst, kind}
               + (if has("expected_hash") then {expected_hash} else {} end)
        end"#;

/// Assert the doc contains the complete invocation — flags included — that
/// the test executes, so an undocumented flag can never make a broken
/// example pass.
fn assert_documented(page: &str, flags: &[&str], program: &str) {
    let doc = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join(page),
    )
    .unwrap();
    let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let invocation = format!("jq {} '{program}'", flags.join(" "));
    assert!(
        squash(&doc).contains(&squash(&invocation)),
        "docs/{page} no longer contains this documented jq invocation; update the doc and this test together:\n{invocation}"
    );
}

fn jq(program: &str, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new("jq")
        .args(args)
        .arg(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("jq must be installed to verify the documented examples");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn run_doc_pipeline(t: &Tmp, page: &str, program: &str, jq_args: &[&str], src: &str, dst: &str) {
    assert_documented(page, jq_args, program);
    let map_out = syq_map_in(&t.path(""), &["--srcs-in", src]);
    assert!(map_out.status.success());
    let jq_out = jq(program, jq_args, &map_out.stdout);
    assert!(
        jq_out.status.success(),
        "documented jq program failed: {}",
        String::from_utf8_lossy(&jq_out.stderr)
    );
    let cp = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", src, "--into", dst, "-q"],
        Some(&jq_out.stdout),
    );
    assert!(
        cp.status.success(),
        "cp failed: {}",
        String::from_utf8_lossy(&cp.stderr)
    );
}

#[test]
fn mappings_md_lowercase_example_works_verbatim() {
    let t = Tmp::new();
    write(&t.path("src/Berlin/IMG_1234.JPG"), b"img");
    write(&t.path("src/Notes.TXT"), b"hello");
    run_doc_pipeline(&t, "mappings.md", DOC_JQ_LOWERCASE, &["-c"], "src", "pub");
    assert_eq!(read(&t.path("pub/berlin/img_1234.jpg")), b"img");
    assert_eq!(read(&t.path("pub/notes.txt")), b"hello");
}

#[test]
fn mappings_md_date_partition_example_works_verbatim() {
    let t = Tmp::new();
    write(&t.path("photos/IMG_1234.JPG"), b"july");
    write(&t.path("photos/IMG_8812.JPG"), b"november");
    write(&t.path("photos/clip.mp4"), b"january");
    set_mtime(&t.path("photos/IMG_1234.JPG"), 1721900000); // 2024-07
    set_mtime(&t.path("photos/IMG_8812.JPG"), 1730500000); // 2024-11
    set_mtime(&t.path("photos/clip.mp4"), 1736000000); // 2025-01
    run_doc_pipeline(
        &t,
        "mappings.md",
        DOC_JQ_DATE_PARTITION,
        &["-c"],
        "photos",
        "archive",
    );
    assert_eq!(read(&t.path("archive/2024/07/IMG_1234.JPG")), b"july");
    assert_eq!(read(&t.path("archive/2024/11/IMG_8812.JPG")), b"november");
    assert_eq!(read(&t.path("archive/2025/01/clip.mp4")), b"january");
}

#[test]
fn map_reference_md_min_size_example_works_verbatim() {
    let t = Tmp::new();
    write(&t.path("data/big.bin"), &vec![7u8; 1048576]);
    write(&t.path("data/small.txt"), b"tiny");
    write(&t.path("data/sub/also-small.txt"), b"tiny");
    run_doc_pipeline(
        &t,
        "commands/map.md",
        DOC_JQ_MIN_SIZE,
        &["-c"],
        "data",
        "big",
    );
    assert_eq!(read(&t.path("big/big.bin")).len(), 1048576);
    assert!(!t.path("big/small.txt").exists());
    assert!(
        t.path("big/sub").is_dir(),
        "non-file entries pass the filter"
    );
    assert!(!t.path("big/sub/also-small.txt").exists());
}

#[test]
fn automation_md_retry_gate_example_works_verbatim() {
    let t = Tmp::new();
    write(&t.path("src/ok.txt"), b"ok");
    let expected = serde_json::json!({
        "algorithm": "md5",
        "value": "f2c67381db28fa11c59fe7a6df0f2587",
    });
    let mut missing: serde_json::Value =
        serde_json::from_str(&entry_line("gone.txt", "g.txt", None)).unwrap();
    missing["expected_hash"] = expected.clone();
    let manifest = format!("{missing}\n{}", entry_line("ok.txt", "ok.txt", None));
    let cp = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "-",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert_eq!(cp.status.code(), Some(23));
    let results = read(&t.path("r1.ndjson"));
    assert_documented("automation.md", &["-cs"], DOC_JQ_RETRY_GATE);
    // Complete partial stream: the gate passes and emits the retry entry.
    let out = jq(DOC_JQ_RETRY_GATE, &["-cs"], &results);
    assert!(out.status.success());
    let retry: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one retry entry");
    assert_eq!(retry["dst"]["value"], "g.txt");
    assert_eq!(retry["expected_hash"], expected);
    // The emitted entry executes as a mapping after the source appears.
    write(&t.path("src/gone.txt"), b"late");
    let cp = syq_cp_in(
        &t.path(""),
        &["--mapping", "-", "-C", "src", "--into", "dst", "-q"],
        Some(&out.stdout),
    );
    assert!(cp.status.success());
    assert_eq!(read(&t.path("dst/g.txt")), b"late");
    // Truncated stream: refused.
    let truncated: Vec<u8> = results
        .split(|&b| b == b'\n')
        .take(2)
        .collect::<Vec<_>>()
        .join(&b'\n');
    let out = jq(DOC_JQ_RETRY_GATE, &["-cs"], &truncated);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("incomplete results stream"));
    // Aborted terminal record: refused with advice to rerun.
    let mut aborted = truncated.clone();
    aborted.extend_from_slice(b"\n{\"type\":\"result\",\"status\":\"aborted\"}\n");
    let out = jq(DOC_JQ_RETRY_GATE, &["-cs"], &aborted);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("run stopped early (status aborted)"));
}

const DOC_JQ_DROP_SPECIALS: &str = r#"select(.kind != "special")"#;

#[test]
fn map_reference_md_drop_specials_example_works_verbatim() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"ok");
    let fifo = t.path("src/pipe");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    run_doc_pipeline(
        &t,
        "commands/map.md",
        DOC_JQ_DROP_SPECIALS,
        &["-c"],
        "src",
        "dst",
    );
    assert_eq!(read(&t.path("dst/a.txt")), b"ok");
    assert!(!t.path("dst/pipe").exists());
}

#[test]
fn native_cp_mapping_restores_only_reopened_implicit_parents() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Darwin cannot open a mode-000 directory for descriptor-based repair;
    // data_safety covers its failure without mutation. Mode 0600 exercises
    // missing search permission on both platforms.
    let modes: &[u32] = if cfg!(target_os = "macos") {
        &[0o600, 0o550, 0o750]
    } else {
        &[0o000, 0o600, 0o550, 0o750]
    };
    for &mode in modes {
        for preserve in [false, true] {
            let t = Tmp::new();
            write(&t.path("src/file"), b"same contents");
            write(&t.path("dst/parent/file"), b"same contents");
            set_mtime(&t.path("src/file"), 1_500_000_000);
            set_mtime(&t.path("dst/parent/file"), 1_500_000_000);
            fs::set_permissions(t.path("dst/parent"), fs::Permissions::from_mode(mode)).unwrap();
            let before = fs::metadata(t.path("dst/parent")).unwrap();
            let mut args = vec!["--mapping", "-", "-C", "src", "--into", "dst", "-q"];
            if preserve {
                args.push("--preserve=permissions");
            }
            let out = syq_cp_in(
                &t.path(""),
                &args,
                Some(entry_line("file", "parent/file", Some("file")).as_bytes()),
            );
            assert_output_ok(&out);
            let after = fs::metadata(t.path("dst/parent")).unwrap();
            assert_eq!(after.mode(), before.mode());
            assert_eq!(
                (after.mtime(), after.mtime_nsec()),
                (before.mtime(), before.mtime_nsec())
            );
            if mode & 0o700 == 0o700 {
                assert_eq!(
                    (after.ctime(), after.ctime_nsec()),
                    (before.ctime(), before.ctime_nsec()),
                    "writable implicit parent received an unnecessary metadata update"
                );
            }
            fs::set_permissions(t.path("dst/parent"), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

#[test]
fn native_cp_mapping_child_before_explicit_directory_is_order_independent() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"a");
    fs::create_dir_all(t.path("src/x")).unwrap();
    // Child listed before its explicit directory: exactly one directory
    // record and one counted creation, same as the reversed order.
    for (name, manifest) in [
        (
            "child-first",
            format!(
                "{}{}",
                entry_line("a.txt", "x/a.txt", None),
                entry_line("x", "x", Some("dir"))
            ),
        ),
        (
            "dir-first",
            format!(
                "{}{}",
                entry_line("x", "x", Some("dir")),
                entry_line("a.txt", "x/a.txt", None)
            ),
        ),
    ] {
        let dst = format!("dst-{name}");
        let results = format!("r-{name}.ndjson");
        let out = syq_cp_in(
            &t.path(""),
            &[
                "--mapping",
                "-",
                "-C",
                "src",
                "--into",
                &dst,
                "--results",
                &results,
                "-q",
            ],
            Some(manifest.as_bytes()),
        );
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let lines: Vec<serde_json::Value> = String::from_utf8(read(&t.path(&results)))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let dir_records = lines
            .iter()
            .filter(|v| v["type"] == "operation_result" && v["action"] == "create_directory")
            .count();
        assert_eq!(dir_records, 1, "{name}: one record for x");
        assert_eq!(lines.last().unwrap()["directories_created"], 1, "{name}");
    }
}

#[test]
fn native_cp_mapping_cross_chunk_directory_upgrade_emits_one_trace() {
    let t = Tmp::new();
    write(&t.path("src/a.txt"), b"a");
    std::fs::create_dir(t.path("src/d")).unwrap();
    std::fs::create_dir(t.path("src/xdir")).unwrap();
    // Entry 1 synthesizes ancestor `x`; filler pushes the explicit `x`
    // entry past the 4096-entry scan batch so the upgrade crosses chunks.
    let mut manifest = entry_line("a.txt", "x/a.txt", Some("file"));
    for i in 0..4095 {
        manifest.push_str(&entry_line("d", &format!("d{i:04}"), Some("dir")));
    }
    manifest.push_str(&entry_line("xdir", "x", Some("dir")));
    let out = syq_cp_in(
        &t.path(""),
        &[
            "-C",
            "src",
            "--mapping",
            "-",
            "--into",
            "dst",
            "-n",
            "--results",
            "r1.ndjson",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let x_traces: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|v| {
            v["type"] == "trace" && v["action"] == "create_directory" && v["dst"]["value"] == "x"
        })
        .collect();
    assert_eq!(x_traces.len(), 1);
    // The explicit entry claimed the directory, so the (deferred) trace
    // carries its src even though an earlier chunk synthesized the path.
    assert_eq!(x_traces[0]["src"]["value"], "xdir");
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fs::set_permissions(t.path("src/xdir"), fs::Permissions::from_mode(0o750)).unwrap();
    set_mtime(&t.path("src/xdir"), 1_500_000_000);
    let live = syq_cp_in(
        &t.path(""),
        &[
            "-C",
            "src",
            "--mapping",
            "-",
            "--into",
            "dst",
            "--only-new",
            "--preserve=permissions",
            "-q",
        ],
        Some(manifest.as_bytes()),
    );
    assert_output_ok(&live);
    assert_eq!(fs::metadata(t.path("dst/x")).unwrap().mode() & 0o777, 0o750);
    assert_eq!(
        fs::metadata(t.path("dst/x")).unwrap().mtime(),
        1_500_000_000
    );
}

#[test]
fn native_cp_mapping_symlinked_manifest_failure_still_settles_the_stream() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(
        &t.path("manifest"),
        entry_line("f.txt", "f.txt", None).as_bytes(),
    );
    std::os::unix::fs::symlink("manifest", t.path("manifest-link")).unwrap();
    // Post-parse validation failures still owe the consumer a terminal
    // record: only a real crash leaves the stream unsettled.
    let out = syq_cp_in(
        &t.path(""),
        &[
            "--mapping",
            "manifest-link",
            "-C",
            "src",
            "--into",
            "dst",
            "--results",
            "r1.ndjson",
        ],
        None,
    );
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("pass --follow"));
    let records: Vec<serde_json::Value> = String::from_utf8(read(&t.path("r1.ndjson")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.first().unwrap()["type"], "run");
    let terminal = records.last().unwrap();
    assert_eq!(terminal["type"], "result");
    assert_eq!(terminal["status"], "failed");
}

#[test]
fn native_verify_only_mapping_keeps_missing_parents_absent() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"source");
    write(&t.path("mapping"), br#"{"src":{"encoding":"utf-8","value":"file"},"dst":{"encoding":"utf-8","value":"missing/parent/file"}}"#);
    let out = native_syq(&[
        "cp",
        "--verify-only",
        "--mapping",
        &t.s("mapping"),
        "-C",
        &t.s("src"),
        "--into",
        &t.s("dst"),
        "--results",
        &t.s("results"),
    ]);
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(!t.path("dst").exists());
}
