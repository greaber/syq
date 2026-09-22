use super::*;

#[test]
fn native_as_existing_updates_a_same_type_symlink() {
    use std::os::unix::fs::symlink;

    let t = Tmp::new();
    symlink("new-target", t.path("source-link")).unwrap();
    symlink("old-target", t.path("destination-link")).unwrap();

    run_native_ok(&[
        "cp",
        "--src",
        &t.s("source-link"),
        "--as-existing",
        &t.s("destination-link"),
    ]);

    assert_eq!(
        fs::read_link(t.path("destination-link")).unwrap(),
        Path::new("new-target")
    );
}

#[test]
fn native_inplace_updates_the_existing_inode_without_a_sidecar() {
    let t = Tmp::new();
    let expected = vec![b'n'; 5 * 1024 * 1024];
    write(&t.path("src/file"), &expected);
    write(&t.path("dst/file"), &vec![b'o'; expected.len()]);
    set_mtime(&t.path("src/file"), 1_700_000_000);
    set_mtime(&t.path("dst/file"), 1_600_000_000);
    let inode = fs::metadata(t.path("dst/file")).unwrap().ino();

    run_native_ok(&[
        "cp",
        "--inplace",
        "--srcs-in",
        &t.s("src"),
        "--into-existing",
        &t.s("dst"),
    ]);

    assert_eq!(read(&t.path("dst/file")), expected);
    assert_eq!(fs::metadata(t.path("dst/file")).unwrap().ino(), inode);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[test]
fn background_bootstrap_installs_the_command_quietly() {
    use base64::Engine;

    for completion in [true, false] {
        for upload in [false, true] {
            let t = Tmp::new();
            fs::create_dir(t.runtime()).unwrap();
            write(&t.path("remote-home/data/name"), b"remote");
            setup_release_bootstrap(&t);
            if upload {
                executable(&t.path("remote-bin/curl"), b"#!/bin/sh\nexit 22\n");
            }
            let ssh = fake_ssh(&t);
            // Stop after bootstrap for the return service: its receiver protocol
            // is unrelated to whether setup publishes an interactive command.
            let script = fs::read_to_string(&ssh).unwrap().replace(
                "exec /bin/sh -c",
                "case \"$1\" in *--return-receiver*) exit 0 ;; esac\nexec /bin/sh -c",
            );
            executable(&ssh, script.as_bytes());
            let path = t.s("remote-home/data/n");
            let mut command = if completion {
                completion_command(
                    &t,
                    &[
                        "__complete",
                        "bash",
                        "4",
                        "--",
                        "syq",
                        "cp",
                        "--from",
                        "fake.example",
                        &path,
                    ],
                )
            } else {
                let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
                command
                    .arg("--return-connect-install")
                    .arg(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("fake.example"));
                command
            };
            let output = command
                .env("HOME", t.path("home"))
                .env("XDG_CONFIG_HOME", t.path("config"))
                .env("XDG_CACHE_HOME", t.path("cache"))
                .env("XDG_RUNTIME_DIR", t.runtime())
                .env("FAKE_REMOTE_HOME", t.path("remote-home"))
                .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
                .env("FAKE_RSH_LOG", t.path("rsh.log"))
                .env("FAKE_REMOTE_RELEASE_ARCHIVE", t.path("release.gz"))
                .env(
                    "FAKE_REMOTE_RELEASE_MANIFEST",
                    t.path("release-manifest.json"),
                )
                .env("FAKE_CURL_LOG", t.path("curl.log"))
                .env("SYQ_COMPLETION_DEBUG", "1")
                .env("SYQ_TEST_RELEASE_BUILD", "1")
                .env(
                    "SYQ_TEST_RELEASE_PUBLIC_KEY",
                    fs::read_to_string(t.path("release-public-key"))
                        .unwrap()
                        .trim(),
                )
                .env(
                    "SYQ_TEST_RELEASE_DOWNLOADS",
                    "https://release.invalid/download",
                )
                .env("SYQ_TEST_FIXTURES", &t.0)
                .env(
                    "PATH",
                    format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
                )
                .run()
                .unwrap();
            assert_output_ok(&output);
            if completion {
                assert_eq!(
                    completion_values(&output.stdout),
                    vec![(
                        b'f',
                        t.path("remote-home/data/name")
                            .as_os_str()
                            .as_encoded_bytes()
                            .to_vec()
                    )],
                    "completion={completion}, upload={upload}: {output:?}"
                );
            }
            assert!(
                cached_remote_helper(&t).is_file(),
                "completion={completion}, upload={upload}: {output:?}"
            );
            assert_eq!(
                read(&t.path("remote-home/.local/bin/syq")),
                read(&cached_remote_helper(&t))
            );
            assert!(t.path("remote-home/.local/bin/.syq-install.json").is_file());
            let log = fs::read_to_string(t.path("rsh.log")).unwrap();
            assert!(log.contains("--install-remote-command"), "{log}");
            assert!(!String::from_utf8_lossy(&output.stderr).contains("installed syq"));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("syq-remote-install-notice:"));
        }
    }
}

#[test]
fn bootstrap_disconnect_relays_install_notices_without_wire_tags() {
    for (upload, quiet) in [(false, false), (true, false), (false, true), (true, true)] {
        let t = Tmp::new();
        setup_release_bootstrap(&t);
        if upload {
            executable(&t.path("remote-bin/curl"), b"#!/bin/sh\nexit 22\n");
        }
        let rsh = fake_rsh(&t);
        let script = fs::read_to_string(&rsh).unwrap().replace(
            "exec /bin/sh -c \"$1\"",
            r#"case "$1" in
    *--install-remote-command*)
        /bin/sh -c "$1"
        status=$?
        [ "$status" -eq 0 ] || exit "$status"
        echo 'SSH connection closed after bootstrap' >&2
        exit 255
        ;;
esac
exec /bin/sh -c "$1""#,
        );
        executable(&rsh, script.as_bytes());
        write(&t.path("src"), b"payload");
        let remote = format!("fake:{}", t.s("dst"));
        let mut command = remote_syq_command(&t, &rsh, &[&t.s("src"), &remote]);
        if quiet {
            command.arg("--quiet");
        }
        let output = command.capture_output().unwrap();
        assert!(!output.status.success(), "{output:?}");
        assert!(cached_remote_helper(&t).is_file(), "{output:?}");
        assert!(t.path("remote-home/.local/bin/syq").is_file(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("SSH connection closed after bootstrap"),
            "{stderr}"
        );
        assert!(stderr.contains("255"), "{stderr}");
        assert!(!stderr.contains("syq-remote-install-notice:"), "{stderr}");
        assert_eq!(
            stderr.contains("syq: fake: installed syq"),
            !quiet,
            "{stderr}"
        );
    }
}

#[test]
fn managed_remote_helper_install_is_cached() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let script = fs::read_to_string(&rsh).unwrap();
    executable(
        &rsh,
        script
            .replace(
                "#!/bin/sh\n",
                "#!/bin/sh\nprintf 'unrelated SSH banner' >&2\n",
            )
            .as_bytes(),
    );
    setup_release_bootstrap(&t);

    write(&t.path("src"), b"first");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-avv", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"first");
    assert!(cached_remote_helper(&t).is_file());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("syq: fake: unrelated SSH banner"));
    for line in stderr
        .lines()
        .filter(|line| line.contains("installed syq") || line.contains("on your shell PATH"))
    {
        assert!(
            line.starts_with("syq: fake: "),
            "missing host label: {line}"
        );
    }
    let installed = t.path("remote-home/.local/bin/syq");
    assert_eq!(read(&installed), read(&cached_remote_helper(&t)));
    assert!(String::from_utf8_lossy(&out.stderr).contains("installed syq"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("ensure ~/.local/bin is on your shell PATH")
    );
    // Updating the interactive command must leave the helper usable.
    write(&installed, b"user-managed replacement");

    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!(
            "helper: {} (managed; installed now)",
            binary_identity("--build-identity")
        )),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let probes = fs::read_to_string(t.path("rsh.log"))
        .unwrap()
        .matches("syq-helper-target:")
        .count();
    assert_eq!(probes, 1);

    write(&t.path("src"), b"second");
    let out = remote_syq(&t, &rsh, &["-avv", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"second");
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!(
            "helper: {} (managed helper cache)",
            binary_identity("--build-identity")
        )),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let probes = fs::read_to_string(t.path("rsh.log"))
        .unwrap()
        .matches("syq-helper-target:")
        .count();
    assert_eq!(probes, 1, "cache hit should not probe the platform again");

    // The command's receipt does not suppress recovery of a missing helper.
    let receipt = installed.with_file_name(".syq-install.json");
    let saved_receipt = read(&receipt);
    fs::remove_file(&installed).unwrap();
    fs::remove_file(cached_remote_helper(&t)).unwrap();
    write(&t.path("src"), b"third");
    let out = remote_syq(&t, &rsh, &["-avv", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"third");
    assert_eq!(
        read(&cached_remote_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    assert!(
        !installed.exists(),
        "preserve a deliberately removed command"
    );
    assert_eq!(read(&receipt), saved_receipt);
}

#[test]
fn remote_helper_optional_command_install_failure_does_not_fail_copy() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    write(&t.path("remote-home/.local"), b"not a directory");
    write(&t.path("src"), b"copy succeeds");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"copy succeeds");
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not install ~/.local/bin/syq"));
}

#[test]
fn remote_corrupted_local_helper_cache_is_discarded_and_refetched() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    setup_release_bootstrap(&t);
    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
exit 22
"#,
    );
    let mut corrupt = read(Path::new(env!("CARGO_BIN_EXE_syq")));
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    fs::create_dir_all(cached_local_helper(&t).parent().unwrap()).unwrap();
    write(&cached_local_helper(&t), &corrupt);

    write(&t.path("src"), b"local cache repair");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", "-q", &t.s("src"), &remote]);

    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"local cache repair");
    assert_eq!(
        read(&cached_local_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cached remote helper failed integrity verification"),
        "{stderr}"
    );
    assert!(stderr.contains("discarding it"), "{stderr}");
}

#[test]
fn development_build_uploads_itself_and_reuses_cached_helper() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    executable(
        &t.path("remote-bin/curl"),
        b"#!/bin/sh\necho unexpected-download >> \"$FAKE_CURL_LOG\"\nexit 1\n",
    );
    write(&t.path("src"), b"offline source build");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"offline source build");
    assert_eq!(
        read(&cached_remote_helper(&t)),
        read(Path::new(env!("CARGO_BIN_EXE_syq")))
    );
    assert!(!t.path("remote-home/.local/bin/syq").exists());
    assert!(!t.path("curl.log").exists());
    assert!(!cached_local_helper(&t).exists());

    write(&t.path("rsh.log"), b"");
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(
        !log.contains("syq-helper-target:"),
        "cache hit probed: {log}"
    );
    assert!(!log.contains(".upload"), "cache hit uploaded: {log}");
}

#[test]
fn source_build_can_download_helpers_without_installing_a_command() {
    for upload in [false, true] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        setup_release_bootstrap(&t);
        if upload {
            executable(&t.path("remote-bin/curl"), b"#!/bin/sh\nexit 22\n");
        }
        write(&t.path("src"), b"source client with release helpers");
        let remote = format!("fake:{}", t.s("dst"));
        let out = remote_syq_command(&t, &rsh, &["-a", &t.s("src"), &remote])
            .env("SYQ_TEST_RELEASE_BUILD", "0")
            .env("SYQ_TEST_RELEASE_HELPERS", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), read(&t.path("src")));
        assert!(cached_remote_helper(&t).exists());
        assert!(!t.path("remote-home/.local/bin/syq").exists());
        if upload {
            // Falling back must download a verified release locally, not send
            // the source executable merely because it is the same platform.
            assert!(cached_local_helper(&t).exists());
        } else {
            assert!(!read(&t.path("curl.log")).is_empty());
        }
    }
}

#[test]
fn development_build_attempts_upload_for_an_unlisted_platform() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    executable(
        &t.path("remote-bin/uname"),
        b"#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo riscv64;; esac\n",
    );
    write(&t.path("src"), b"custom target");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), read(&t.path("src")));
    assert!(!t.path("remote-home/.local/bin/syq").exists());
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
}

#[test]
fn development_build_rejects_cross_platform_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let other_os = if cfg!(target_os = "linux") {
        "Darwin"
    } else {
        "Linux"
    };
    executable(
        &t.path("remote-bin/uname"),
        format!("#!/bin/sh\ncase \"$1\" in -s) echo {other_os};; -m) echo x86_64;; esac\n")
            .as_bytes(),
    );
    write(&t.path("src"), b"must not copy");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot automatically install a source-built helper"),
        "{stderr}"
    );
    assert!(stderr.contains("--syq-path"), "{stderr}");
    assert!(!t.path("dst").exists());
    assert!(!t.path("remote-home/.cache/syq/helpers").exists());
}

#[test]
fn development_build_does_not_install_an_unrunnable_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    // Model an unlisted host on which the uploaded binary cannot execute.
    executable(
        &t.path("remote-bin/uname"),
        b"#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo riscv64;; esac\n",
    );
    executable(&t.path("remote-bin/chmod"), b"#!/bin/sh\nexit 0\n");
    write(&t.path("src"), b"must not copy");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("uploaded helper cannot run on this host"),
        "{stderr}"
    );
    assert!(stderr.contains("Linux riscv64"), "{stderr}");
    assert!(!t.path("dst").exists());
    let helper = cached_remote_helper(&t)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("self/syq");
    assert!(!helper.exists());
    assert_eq!(fs::read_dir(helper.parent().unwrap()).unwrap().count(), 0);
}

#[test]
fn no_bootstrap_uses_remote_path_without_managed_cache() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    t.expose_remote_syq();

    write(&t.path("src"), b"preinstalled");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_syq(
        &t,
        &rsh,
        &["-a", "--syq-no-bootstrap", &t.s("src"), &remote],
    );
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"preinstalled");
    assert!(!t.path("remote-home/.cache/syq/helpers").exists());
}

#[cfg(debug_assertions)]
#[test]
fn sparse_updates_recover_batched_reads_and_writes_without_losing_unchanged_bytes() {
    for (pull, drop_request) in [(false, "write"), (true, "read")] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        t.expose_remote_syq();
        let original = vec![17; 2 * 1024 * 1024];
        let mut edited = original.clone();
        for offset in (0..edited.len()).step_by(256 * 1024) {
            edited[offset..offset + 4096].fill(91);
        }
        write(&t.path("src"), &edited);
        write(&t.path("dst"), &original);
        let marker = t.path("drop-once");
        let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
        command.args(["cp", "--hash", "--stats", "--no-progress", "--rsh", rsh.to_str().unwrap(), "--syq-path", env!("CARGO_BIN_EXE_syq"), "--no-tcp", "--performance-tuning=comparison-block-size=64K,request-size=4M,copy-path=ranges,workers=1"]);
        if pull {
            command.args(["--from", "fake"]);
        }
        command.arg(t.path("src"));
        if !pull {
            command.args(["--to", "fake"]);
        }
        let output = command
            .args(["--as", &t.s("dst")])
            .env("FAKE_REMOTE_HOME", t.path("remote-home"))
            .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
            .env("XDG_CONFIG_HOME", t.path("config"))
            .env("XDG_CACHE_HOME", t.path("cache"))
            .env("SYQ_TEST_DROP_AFTER_REQUEST", drop_request)
            .env("SYQ_TEST_DROP_MARKER", &marker)
            .run()
            .unwrap();
        assert_output_ok(&output);
        assert!(marker.exists());
        assert_eq!(read(&t.path("dst")), edited);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("connection dropped; reopening"),
            "{output:?}"
        );
    }
}

#[test]
fn copy_paths_copy_and_update_with_both_interfaces() {
    for interface in ["cp", "rsync"] {
        for engine in ["auto", "ranges"] {
            let t = Tmp::new();
            for (name, size) in [("empty", 0), ("small", 4194), ("nested/large", 2 << 20)] {
                write(&t.path(&format!("source/{name}")), &prng(size, 350));
            }
            let copy = || {
                let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
                command.args([
                    interface,
                    "--no-progress",
                    "--stats",
                    "--performance-tuning",
                    "workers=2",
                    &format!("--performance-tuning=copy-path={engine}"),
                ]);
                if interface == "cp" {
                    command.args(["--hash", "--preserve=permissions"]);
                    command.args(["--srcs-in", &t.s("source"), "--into", &t.s("destination")]);
                } else {
                    command.args(["-a", "--checksum", &t.s("source/"), &t.s("destination")]);
                }
                let out = command.run().unwrap();
                assert_output_ok(&out);
                assert_same_tree(&t.path("source"), &t.path("destination"));
            };
            copy(); // Fresh files, including batch-eligible and range work.
            copy(); // Existing matching files.
            write(&t.path("source/small"), &prng(4194, 351));
            write(&t.path("source/nested/large"), &prng(2 << 20, 351));
            copy(); // Same-size changed destinations require fresh metadata.
        }
    }
}

#[test]
fn updates_changed_file_and_skips_symlink_only_when_same() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"v1");
    std::os::unix::fs::symlink("f.txt", t.path("src/l")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f.txt")), b"v1");
    write(&t.path("src/f.txt"), b"v2 longer");
    set_mtime(&t.path("src/f.txt"), 1_700_000_000);
    fs::remove_file(t.path("src/l")).unwrap();
    std::os::unix::fs::symlink("other", t.path("src/l")).unwrap();
    let out = run_ok(&["-av", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 1);
    assert_eq!(read(&t.path("dst/f.txt")), b"v2 longer");
    assert_eq!(
        fs::read_link(t.path("dst/l")).unwrap(),
        PathBuf::from("other")
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn update_skips_files_newer_on_the_destination() {
    let t = Tmp::new();
    write(&t.path("src/newer"), b"src-new");
    write(&t.path("src/older"), b"src-old");
    write(&t.path("dst/newer"), b"dst-old");
    write(&t.path("dst/older"), b"dst-new");
    set_mtime(&t.path("src/newer"), 2000);
    set_mtime(&t.path("dst/newer"), 1000);
    set_mtime(&t.path("src/older"), 1000);
    set_mtime(&t.path("dst/older"), 2000);
    let so = run_ok(&["-a", "-u", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(read(&t.path("dst/newer")), b"src-new");
    assert_eq!(read(&t.path("dst/older")), b"dst-new");
    // Without -u the older destination file is replaced too.
    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/older")), b"src-old");
}

#[test]
fn existing_updates_through_a_destination_root_symlink_to_a_dir() {
    // A destination that is a symlink to a directory *is* that directory (as
    // for rsync), so --existing updates the file there and leaves the link.
    let t = Tmp::new();
    write(&t.path("src/f"), b"new");
    write(&t.path("src/missing"), b"m");
    write(&t.path("elsewhere/f"), b"old");
    set_mtime(&t.path("src/f"), 2000);
    set_mtime(&t.path("elsewhere/f"), 1000);
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst")).unwrap();
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("elsewhere/f")), b"new", "{so}");
    assert!(!t.path("elsewhere/missing").exists());
    assert!(t.path("dst").symlink_metadata().unwrap().is_symlink());
}

#[test]
fn persist_connect_prepares_helper_without_selecting_copy_data() {
    let t = Tmp::new();
    fs::create_dir(t.runtime()).unwrap();
    let ssh = fake_ssh(&t);
    let rejected = persistence_command(&t, &["connect", "@laptop"])
        .run()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(!t.path("config/syq/persistence.json").exists());
    assert_output_ok(&persistence_command(&t, &["receive", "off"]).run().unwrap());
    let mut connect = persistence_command(
        &t,
        &[
            "connect",
            "alice@backup.example:2222",
            "--syq-path",
            env!("CARGO_BIN_EXE_syq"),
        ],
    );
    connect
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", ssh.parent().unwrap().display()),
        );
    let output = connect.run().unwrap();
    assert_output_ok(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("ready; receiving is disabled"));
    let log = fs::read_to_string(t.path("rsh.log")).unwrap();
    assert!(log.contains("ControlPersist=yes"), "{log}");
    assert!(log.contains("ServerAliveInterval=15"), "{log}");
    assert!(log.contains("ServerAliveCountMax=3"), "{log}");
    assert!(log.contains("--server"), "{log}");
    let status = persistence_command(&t, &["status", "--json"])
        .run()
        .unwrap();
    assert_output_ok(&status);
    let state: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(state["enabled"], true);
    assert_eq!(state["connections"].as_array().unwrap().len(), 1);
    assert_eq!(
        state["connections"][0]["endpoint"],
        "alice@backup.example:2222"
    );
    assert_eq!(state["connections"][0]["receiving_enabled"], false);
    assert!(!t.path("remote-home/.syq-destinations-v3").exists());
    assert_output_ok(&persistence_command(&t, &["off"]).run().unwrap());
    assert!(!Path::new(state["scope"].as_str().unwrap()).exists());
}
