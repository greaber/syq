//! Selection coverage, kept separate from receiver dispatch tests.
use super::*;

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn local_batch_boundary_and_scheduler_agree() {
    for connections in ["1", "4"] {
        let t = Tmp::new();
        let sizes = [0, 1, 65535, 65536, 65537, 1 << 20, 4 << 20];
        for (index, size) in sizes.into_iter().enumerate() {
            write(
                &t.path(&format!("src/file{index}")),
                &prng(size, index as u64),
            );
        }
        let out = compat_command()
            .args([
                "-a",
                "--syq-no-tcp",
                "--syq-connections",
                connections,
                "--block-size=4M",
                "--tuning-options=request-size=4M",
                "--no-progress",
                &t.s("src/"),
                &t.s("dst/"),
            ])
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_WORKER_EVENTS", t.path("workers"))
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "local")
            .run()
            .unwrap();
        assert_output_ok(&out);
        let workers = fs::read_to_string(t.path("workers")).unwrap();
        assert_eq!(
            workers
                .lines()
                .filter(|line| line.starts_with("connected "))
                .count(),
            connections.parse::<usize>().unwrap(),
            "{workers}"
        );
        assert_same_tree(&t.path("src"), &t.path("dst"));
        let observed = tuning_observed(&out);
        assert_eq!(observed["local_whole_files"], 3, "{out:?}");
        assert_eq!(observed["range_requests"], 0);
        assert!(observed["small_batches"].as_u64().unwrap() > 0);
        assert!(partial_files(&t.0).is_empty());
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn local_medium_unsupported_keeps_full_size_range_requests() {
    let t = Tmp::new();
    for i in 0..2 {
        write(&t.path(&format!("src/file{i}")), &prng(4 << 20, i));
    }
    let out = compat_command()
        .args([
            "-a",
            "--syq-no-tcp",
            "--syq-connections=2",
            "--block-size=4M",
            "--tuning-options=request-size=4M",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "unsupported")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert_eq!(observed["small_batches"], 0);
    assert_eq!(observed["max_request_bytes"], 4 << 20);
    assert!(partial_files(&t.0).is_empty());
}

#[test]
fn checksum_and_paced_medium_files_keep_batches() {
    for control in ["--checksum", "--bwlimit=1G"] {
        let t = Tmp::new();
        write(&t.path("src/file"), &prng(1 << 20, 80));
        let out = compat_command()
            .args([
                "-a",
                "--syq-no-tcp",
                "--syq-connections=1",
                "--no-progress",
                control,
                &t.s("src/"),
                &t.s("dst/"),
            ])
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_same_tree(&t.path("src"), &t.path("dst"));
        let observed = tuning_observed(&out);
        assert_eq!(observed["local_whole_files"], 0);
        assert_eq!(observed["range_requests"], 0);
        assert_eq!(observed["small_batches"], 1);
    }
}

#[test]
fn remote_medium_files_keep_batches() {
    for pull in [false, true] {
        let t = Tmp::new();
        let rsh = fake_rsh(&t);
        write(&t.path("src/file"), &prng(4 << 20, 81));
        let src = if pull {
            format!("fake:{}/", t.s("src"))
        } else {
            t.s("src/")
        };
        let dst = if pull {
            t.s("dst/")
        } else {
            format!("fake:{}/", t.s("dst"))
        };
        let out = remote_syq_command(
            &t,
            &rsh,
            &[
                "-a",
                "--rsync-path",
                env!("CARGO_BIN_EXE_syq"),
                "--syq-no-bootstrap",
                "--block-size=4M",
                "--tuning-options=request-size=4M",
                &src,
                &dst,
            ],
        )
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
        assert_output_ok(&out);
        assert_same_tree(&t.path("src"), &t.path("dst"));
        let observed = tuning_observed(&out);
        assert_eq!(observed["local_whole_files"], 0);
        assert_eq!(observed["range_requests"], 0);
        assert_eq!(observed["small_batches"], 1);
    }
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn medium_failure_keeps_old_destination_and_resumes_changed_source() {
    let t = Tmp::new();
    write(&t.path("src/small"), b"parallel file work");
    let original = prng(2 << 20, 456);
    write(&t.path("src/file"), &original);
    write(&t.path("dst/file"), b"old destination");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .env("SYQ_TEST_FAIL_COPY_LOCAL_AFTER_WRITE", "1")
        .run()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert!(stderr_of(&out).contains("test local-copy write failure"));
    assert_eq!(read(&t.path("dst/file")), b"old destination");
    let partials = partial_files(&t.path("dst"));
    assert_eq!(partials.len(), 1);
    assert_eq!(fs::metadata(&partials[0]).unwrap().len(), 1 << 20);
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert_eq!(observed["range_requests"], 0);

    // The failed userspace write is a resumable basis, not authority to skip
    // checking bytes that changed in the source before the retry.
    let mut changed = original;
    changed[..1 << 20].fill(b'c');
    write(&t.path("src/file"), &changed);
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst/file")), changed);
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert!(observed["range_requests"].as_u64().unwrap() > 0);
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn platforms_without_medium_file_offload_keep_batches() {
    let t = Tmp::new();
    write(&t.path("src/file"), &prng(1 << 20, 82));
    let out = compat_command()
        .args([
            "-a",
            "--syq-no-tcp",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert_eq!(observed["range_requests"], 0);
    assert_eq!(observed["small_batches"], 1);
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn fresh_medium_failure_does_not_publish_and_changed_source_resumes() {
    let t = Tmp::new();
    let mut contents = prng(2 << 20, 83);
    write(&t.path("src/file"), &contents);
    write(
        &t.path("src/tiny"),
        b"another file enables the local sequential fallback",
    );
    let run = || {
        let mut command = compat_command();
        command
            .args([
                "-a",
                "--syq-no-tcp",
                "--no-progress",
                &t.s("src/"),
                &t.s("dst/"),
            ])
            .env("SYQ_DEBUG", "1")
            .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
            .env("SYQ_TEST_COPY_LOCAL_FS", "local");
        command
    };
    let failed = run()
        .env("SYQ_TEST_FAIL_COPY_LOCAL_AFTER_WRITE", "1")
        .run()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1), "{failed:?}");
    assert!(stderr_of(&failed).contains("test local-copy write failure"));
    assert!(!t.path("dst/file").exists());
    let partials = partial_files(&t.path("dst"));
    assert_eq!(partials.len(), 1);
    assert_eq!(fs::metadata(&partials[0]).unwrap().len(), 1 << 20);

    contents[..1 << 20].fill(b'x');
    write(&t.path("src/file"), &contents);
    let resumed = run().run().unwrap();
    assert_output_ok(&resumed);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    assert!(partial_files(&t.path("dst")).is_empty());
    let observed = tuning_observed(&resumed);
    assert_eq!(observed["local_whole_files"], 0);
    assert!(observed["range_requests"].as_u64().unwrap() > 0);
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_copies_without_reading_ranges_and_preserves_metadata() {
    if !macos_clone_support::available() {
        return;
    }
    for native in [false, true] {
        for tcp in [false, true] {
            let t = Tmp::new();
            let data = prng(5 << 20, 990);
            write(&t.path("src/file"), &data);
            fs::set_permissions(t.path("src/file"), fs::Permissions::from_mode(0o440)).unwrap();
            set_mtime(&t.path("src/file"), 1_600_000_000);
            let mut command = if native {
                Command::new(env!("CARGO_BIN_EXE_syq"))
            } else {
                compat_command()
            };
            if native {
                command.args(["cp", "--srcs-in", &t.s("src"), "--into", &t.s("dst")]);
            } else {
                command.args(["-a", &t.s("src/"), &t.s("dst/")]);
            }
            if !tcp {
                command.arg(if native { "--no-tcp" } else { "--syq-no-tcp" });
            }
            let out = command
                .args(["--no-progress", "--stats"])
                .env("SYQ_DEBUG", "1")
                .env("SYQ_TEST_FAIL_READ_RANGE", "1")
                .run()
                .unwrap();
            assert_output_ok(&out);
            assert_eq!(read(&t.path("dst/file")), data);
            assert_eq!(
                fs::metadata(t.path("dst/file")).unwrap().mode() & 0o777,
                0o440
            );
            assert_eq!(
                fs::metadata(t.path("dst/file")).unwrap().mtime(),
                1_600_000_000
            );
            let observed = tuning_observed(&out);
            assert_eq!(observed["local_whole_files"], 1);
            assert_eq!(observed["range_requests"], 0);
            assert!(partial_files(&t.0).is_empty());
        }
    }
}

#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn ineligible_local_copies_do_not_claim_source_capabilities() {
    let mut options = vec![
        "--checksum",
        "--bwlimit=1G",
        "--tuning-options=copy-path=ranges",
    ];
    if cfg!(target_os = "macos") {
        options.push("--inplace");
    }
    for option in options {
        let t = Tmp::new();
        let data = prng(5 << 20, 1234);
        write(&t.path("src"), &data);
        let out = compat_command()
            .args(["-a", "--no-progress", option, &t.s("src"), &t.s("dst")])
            .env("SYQ_TEST_REJECT_COPY_SOURCES", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), data);
    }
    // Positive control: an eligible copy really reaches the guarded initializer.
    let t = Tmp::new();
    write(&t.path("src"), &prng(5 << 20, 1235));
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_REJECT_COPY_SOURCES", "1")
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("test rejected unnecessary copy-source capabilities"));
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_preserves_copy_controls_and_no_preserve_metadata() {
    if !macos_clone_support::available() {
        return;
    }
    for args in [
        vec!["--inplace"],
        vec!["--checksum"],
        vec!["--bwlimit=1G"],
        vec!["--tuning-options=copy-path=ranges"],
    ] {
        let t = Tmp::new();
        write(&t.path("src"), &prng(5 << 20, 991));
        let out = compat_command()
            .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
            .args(args)
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("src")), read(&t.path("dst")));
        assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
    }
    let t = Tmp::new();
    write(&t.path("src"), &prng(5 << 20, 992));
    write(&t.path("dst"), b"old destination");
    set_mtime(&t.path("src"), 1_600_000_000);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o444)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o640)).unwrap();
    let out = compat_command()
        .args(["--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_DEBUG", "1")
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(tuning_observed(&out)["local_whole_files"], 1);
    assert_eq!(read(&t.path("src")), read(&t.path("dst")));
    let metadata = fs::metadata(t.path("dst")).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o640);
    assert!(metadata.mtime() > 1_600_000_000);
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_failure_keeps_destination_and_cleans_temporary_files() {
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    write(&t.path("src"), &prng(5 << 20, 993));
    write(&t.path("dst"), b"old destination");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_FAIL_CLONE_AFTER_CREATE", "1")
        .run()
        .unwrap();
    assert!(!out.status.success(), "{out:?}");
    assert!(stderr_of(&out).contains("test clone failure"), "{out:?}");
    assert_eq!(read(&t.path("dst")), b"old destination");
    assert_eq!(fs::read_dir(&t.0).unwrap().count(), 2);
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_immutable_clone_open_failure_cleans_up_and_streams() {
    if !macos_clone_support::available() {
        return;
    }
    use std::os::fd::AsRawFd;
    use std::os::macos::fs::MetadataExt;
    for flags in [libc::UF_IMMUTABLE, libc::UF_APPEND] {
        let t = Tmp::new();
        let data = prng(5 << 20, 999);
        write(&t.path("src"), &data);
        write(&t.path("dst"), b"old destination");
        let source = fs::File::open(t.path("src")).unwrap();
        assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), flags) }, 0);
        let result = compat_command()
            .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
            .env("SYQ_TEST_CLONE_OPEN_EMFILE", "1")
            .env("SYQ_TEST_CLONE_ATTEMPTS", t.path("attempts"))
            .env("SYQ_DEBUG", "1")
            .run();
        let source_flags = source.metadata().unwrap().st_flags();
        // Always unlock the source fixture before checking the child result.
        assert_eq!(unsafe { libc::fchflags(source.as_raw_fd(), 0) }, 0);
        let out = result.unwrap();
        assert_output_ok(&out);
        assert_eq!(source_flags, flags);
        assert_eq!(read(&t.path("src")), data);
        assert_eq!(read(&t.path("dst")), data);
        assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
        assert!(tuning_observed(&out)["range_requests"].as_u64().unwrap() > 0);
        assert_eq!(read(&t.path("attempts")), b"clone\n");
        assert_eq!(fs::read_dir(&t.0).unwrap().count(), 3);
    }
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_leaves_existing_partial_for_verified_resume() {
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    let data = prng(8 << 20, 994);
    write(&t.path("src"), &data);
    let partial = interrupted_partial(&["-a", "--bwlimit=1G", &t.s("src"), &t.s("dst")], &t.0);
    write(&partial, &data[..4 << 20]);
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), data);
    assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
    assert!(tuning_observed(&out)["range_requests"].as_u64().unwrap() > 0);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_directory_setup_failure_cleans_up_and_unsafe_mode_falls_back() {
    if !macos_clone_support::available() {
        return;
    }
    for (hook, success) in [
        ("SYQ_TEST_FAIL_CLONE_AFTER_MKDIR", false),
        ("SYQ_TEST_CLONE_PUBLIC_DIRECTORY", true),
    ] {
        let t = Tmp::new();
        let data = prng(5 << 20, 995);
        write(&t.path("src"), &data);
        write(&t.path("dst"), b"old destination");
        let out = compat_command()
            .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
            .env(hook, "1")
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_eq!(out.status.success(), success, "{out:?}");
        if success {
            assert_eq!(read(&t.path("dst")), data);
            assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
        } else {
            assert!(
                stderr_of(&out).contains("test clone directory failure"),
                "{out:?}"
            );
            assert_eq!(read(&t.path("dst")), b"old destination");
        }
        assert_eq!(fs::read_dir(&t.0).unwrap().count(), 2);
    }
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_memoizes_unsupported_volume_pairs() {
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    for i in 0..4 {
        write(&t.path(&format!("src/file{i}")), &prng(5 << 20, i));
    }
    let out = compat_command()
        .args([
            "-a",
            "--syq-no-tcp",
            "--syq-connections=1",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_CLONE_ATTEMPTS", t.path("attempts"))
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
    assert_eq!(
        fs::read_to_string(t.path("attempts"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert!(partial_files(&t.path("dst")).is_empty());
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_source_growth_requeues_without_a_file_error() {
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    write(&t.path("src"), &prng(5 << 20, 996));
    let ready = t.path("ready");
    let mut child = compat_command()
        .args([
            "-a",
            "--syq-no-tcp",
            "--syq-connections=1",
            "--no-progress",
            &t.s("src"),
            &t.s("dst"),
        ])
        .env("SYQ_TEST_COPY_LOCAL_READY_FILE", &ready)
        .env("SYQ_TEST_HOLD_COPY_LOCAL_MS", "750")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap();
    wait_for_confinement_marker(&mut child, &ready, "local clone source growth");
    OpenOptions::new()
        .append(true)
        .open(t.path("src"))
        .unwrap()
        .write_all(&prng(1 << 20, 997))
        .unwrap();
    let out = wait_for_child_output(child, std::time::Duration::from_secs(30));
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), read(&t.path("src")));
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_medium_files_keep_batches_when_cloning_is_unavailable() {
    // This test deliberately works on non-clone-capable TMPDIRs too.
    let t = Tmp::new();
    for (i, size) in [65537, 1 << 20, 4 << 20].into_iter().enumerate() {
        write(&t.path(&format!("src/file{i}")), &prng(size, i as u64));
    }
    let out = compat_command()
        .args([
            "-a",
            "--syq-no-tcp",
            "--syq-connections=1",
            "--block-size=4M",
            "--tuning-options=request-size=4M",
            "--no-progress",
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_CLONE_ATTEMPTS", t.path("attempts"))
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    let observed = tuning_observed(&out);
    assert_eq!(observed["local_whole_files"], 0);
    assert_eq!(observed["range_requests"], 0);
    assert!(observed["small_batches"].as_u64().unwrap() > 0);
    assert!(!t.path("attempts").exists());
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_mkdir_permission_and_link_limits_fall_back() {
    if !macos_clone_support::available() {
        return;
    }
    for error in ["EACCES", "EPERM", "EMLINK"] {
        let t = Tmp::new();
        write(&t.path("src"), &prng(5 << 20, 998));
        let out = compat_command()
            .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
            .env("SYQ_TEST_CLONE_MKDIR_ERROR", error)
            .env("SYQ_DEBUG", "1")
            .run()
            .unwrap();
        assert_output_ok(&out);
        assert_eq!(read(&t.path("dst")), read(&t.path("src")));
        assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
        assert_eq!(fs::read_dir(&t.0).unwrap().count(), 2);
    }
    // Real ACL case: adding files is allowed, adding subdirectories is denied.
    let t = Tmp::new();
    write(&t.path("src/file"), &prng(5 << 20, 999));
    fs::create_dir(t.path("dst")).unwrap();
    assert!(Command::new("/bin/chmod")
        .args(["+a", "everyone deny add_subdirectory"])
        .arg(t.path("dst"))
        .status()
        .unwrap()
        .success());
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_same_tree(&t.path("src"), &t.path("dst"));
    assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
    assert_eq!(fs::read_dir(t.path("dst")).unwrap().count(), 1);
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_reports_copy_and_cleanup_errors() {
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    write(&t.path("src"), &prng(5 << 20, 1000));
    write(&t.path("dst"), b"old destination");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_FAIL_CLONE_AFTER_CREATE", "1")
        .env("SYQ_TEST_FAIL_CLONE_CLEANUP", "1")
        .run()
        .unwrap();
    assert!(!out.status.success());
    let error = stderr_of(&out);
    assert!(error.contains("No space left on device"), "{error}");
    assert!(
        error.find("test clone failure").unwrap()
            < error.find("test clone cleanup failure").unwrap(),
        "{error}"
    );
    assert_eq!(read(&t.path("dst")), b"old destination");
    assert_eq!(fs::read_dir(&t.0).unwrap().count(), 2);
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_rmdir_failure_keeps_complete_partial_for_resume() {
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    let data = prng(5 << 20, 1003);
    write(&t.path("src"), &data);
    write(&t.path("dst"), b"old destination");
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_FAIL_CLONE_RMDIR", "1")
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("test clone staging rmdir failure"));
    assert_eq!(read(&t.path("dst")), b"old destination");
    let partials = partial_files(&t.0);
    assert_eq!(partials.len(), 1);
    assert_eq!(read(&partials[0]), data);
    let staging: Vec<_> = fs::read_dir(&t.0)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".syq-swap-")
        })
        .collect();
    assert_eq!(staging.len(), 1);
    assert_eq!(fs::read_dir(&staging[0]).unwrap().count(), 0);
    // The process has exited; remove only this test's empty staging directory.
    fs::remove_dir(&staging[0]).unwrap();
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), data);
    assert!(partial_files(&t.0).is_empty());
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_clone_strips_quarantine_without_reading_ranges() {
    use std::os::fd::AsRawFd;
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    let data = prng(5 << 20, 1001);
    write(&t.path("src"), &data);
    let source = File::open(t.path("src")).unwrap();
    let value = b"0081;66000000;syq;";
    assert_eq!(
        unsafe {
            libc::fsetxattr(
                source.as_raw_fd(),
                c"com.apple.quarantine".as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        },
        0
    );
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("SYQ_TEST_FAIL_READ_RANGE", "1")
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), data);
    assert_eq!(tuning_observed(&out)["local_whole_files"], 1);
    assert_eq!(tuning_observed(&out)["range_requests"], 0);
    let destination = File::open(t.path("dst")).unwrap();
    assert_eq!(
        unsafe { libc::flistxattr(destination.as_raw_fd(), std::ptr::null_mut(), 0, 0) },
        0
    );
    assert!(unsafe { libc::flistxattr(source.as_raw_fd(), std::ptr::null_mut(), 0, 0) } > 0);
}

#[cfg(all(debug_assertions, target_os = "macos"))]
#[test]
fn macos_compressed_source_keeps_logical_bytes_through_fallback() {
    use std::os::macos::fs::MetadataExt;
    if !macos_clone_support::available() {
        return;
    }
    let t = Tmp::new();
    let data = b"compressible test data\n".repeat(250_000);
    write(&t.path("original"), &data);
    let compressed = Command::new("/usr/bin/ditto")
        .arg("--hfsCompression")
        .args([&t.s("original"), &t.s("compressed")])
        .run()
        .unwrap();
    assert_output_ok(&compressed);
    assert_ne!(
        fs::metadata(t.path("compressed")).unwrap().st_flags() & libc::UF_COMPRESSED,
        0,
        "fixture must actually use filesystem compression"
    );
    assert_eq!(read(&t.path("compressed")), data);
    let out = compat_command()
        .args(["-a", "--no-progress", &t.s("compressed"), &t.s("dst")])
        .env("SYQ_DEBUG", "1")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_eq!(tuning_observed(&out)["local_whole_files"], 0);
    assert_eq!(read(&t.path("dst")), data);
    assert_eq!(read(&t.path("compressed")), data);
}
