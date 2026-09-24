use super::*;

fn sparse_data() -> Vec<u8> {
    let mut data = vec![0; 8 * 1024 * 1024 + 79];
    data[17..9001].copy_from_slice(&prng(9001 - 17, 893));
    data[4 * 1024 * 1024 + 11..4 * 1024 * 1024 + 7011].copy_from_slice(&prng(7000, 377));
    data
}

fn write_sparse_source(path: &Path, data: &[u8]) {
    use std::os::unix::fs::FileExt;
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let file = fs::File::create(path).unwrap();
    file.set_len(data.len() as u64).unwrap();
    for (index, block) in data.chunks(4096).enumerate() {
        if block.iter().any(|byte| *byte != 0) {
            file.write_all_at(block, (index * 4096) as u64).unwrap();
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // Punch after writing data so APFS does not materialize delayed zero
        // allocations when the independently built source fixture is synced.
        for (index, block) in data.chunks(4096).enumerate() {
            if block.len() == 4096 && block.iter().all(|byte| *byte == 0) {
                let hole = libc::fpunchhole_t {
                    fp_flags: 0,
                    reserved: 0,
                    fp_offset: (index * 4096) as _,
                    fp_length: 4096,
                };
                assert_eq!(
                    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PUNCHHOLE, &hole) },
                    0
                );
            }
        }
    }
    assert_sparse_copy(path, data);
}

fn assert_sparse_copy(path: &Path, expected: &[u8]) {
    // Filesystems can defer allocation accounting until dirty data is committed.
    fs::File::open(path).unwrap().sync_all().unwrap();
    let metadata = fs::metadata(path).unwrap();
    assert_eq!(metadata.len(), expected.len() as u64);
    assert!(
        metadata.blocks() * 512 < metadata.len() / 4,
        "{}: {} allocated bytes for {} logical bytes",
        path.display(),
        metadata.blocks() * 512,
        metadata.len()
    );
    assert_eq!(read(path), expected);
}

#[test]
fn sparse_small_batches_local_copies_and_ranges_preserve_contents_and_hardlinks() {
    let t = Tmp::new();
    let data = sparse_data();
    write_sparse_source(&t.path("src/large"), &data);
    write(&t.path("src/empty"), b"");
    write(&t.path("src/zeros"), &[0; 37]);
    write(&t.path("src/small"), &data[..65539]);
    fs::hard_link(t.path("src/large"), t.path("src/alias")).unwrap();
    for (index, tuning) in ["copy-path=auto", "copy-path=ranges"].iter().enumerate() {
        let destination = format!("dst-{index}");
        run_ok(&[
            "-aHS",
            "--checksum",
            &format!("--performance-tuning={tuning}"),
            &t.s("src/"),
            &t.s(&destination),
        ]);
        assert_sparse_copy(&t.path(&format!("{destination}/large")), &data);
        assert_eq!(read(&t.path(&format!("{destination}/zeros"))), vec![0; 37]);
        assert_eq!(read(&t.path(&format!("{destination}/empty"))), b"");
        assert_eq!(
            read(&t.path(&format!("{destination}/small"))),
            data[..65539]
        );
        assert_eq!(
            fs::metadata(t.path(&format!("{destination}/large")))
                .unwrap()
                .ino(),
            fs::metadata(t.path(&format!("{destination}/alias")))
                .unwrap()
                .ino()
        );
        // An unchanged checksum rerun keeps content, allocation and identity.
        let before = fs::metadata(t.path(&format!("{destination}/large"))).unwrap();
        run_ok(&["-aHSc", &t.s("src/"), &t.s(&destination)]);
        let after = fs::metadata(t.path(&format!("{destination}/large"))).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_sparse_copy(&t.path(&format!("{destination}/large")), &data);
    }
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(["cp", "--sparse", &t.s("src/large"), "--as", &t.s("native")])
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_sparse_copy(&t.path("native"), &data);
}

#[test]
fn sparse_updates_and_inplace_clear_old_nonzero_data() {
    let t = Tmp::new();
    let data = sparse_data();
    write(&t.path("src"), &data);
    for (inplace, block) in [(false, "64K"), (true, "1M"), (true, "64K")] {
        write(&t.path("dst"), &prng(data.len() + 777, 29));
        // Exercise holes in committed allocated data, not filesystem-specific
        // accounting for still-dirty records from fixture creation.
        fs::File::open(t.path("dst")).unwrap().sync_all().unwrap();
        let old_inode = fs::metadata(t.path("dst")).unwrap().ino();
        let block_option = format!("--block-size={block}");
        let mut args = vec![
            "-aSc",
            &block_option,
            "--performance-tuning=copy-path=ranges",
        ];
        if inplace {
            args.push("--inplace");
        }
        let source = t.s("src");
        let destination = t.s("dst");
        args.extend([source.as_str(), destination.as_str()]);
        run_ok(&args);
        // Hole punching preserves contents regardless of the filesystem's
        // record size, sharing and allocation accounting. Assert allocated
        // space for fresh outputs, where zero ranges were never written.
        if inplace {
            assert_eq!(read(&t.path("dst")), data);
        } else {
            assert_sparse_copy(&t.path("dst"), &data);
        }
        if inplace {
            assert_eq!(fs::metadata(t.path("dst")).unwrap().ino(), old_inode);
        }
    }
}

#[cfg(debug_assertions)]
#[test]
fn sparse_capacity_estimates_are_advisory_and_report_unknown_allocation() {
    let t = Tmp::new();
    let data = sparse_data();
    write_sparse_source(&t.path("src/file"), &data);
    let out = compat_command()
        .args(["-aSn", &t.s("src/"), &t.s("dst")])
        .env("SYQ_TEST_AVAILABLE_BYTES", "1")
        .env("SYQ_TEST_AVAILABLE_INODES", "100")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert!(String::from_utf8_lossy(&out.stdout).contains("sparse allocation size unknown"));
    assert!(!t.path("dst").exists());
    let out = compat_command()
        .args(["-aS", &t.s("src/"), &t.s("dst")])
        .env("SYQ_TEST_AVAILABLE_BYTES", "1")
        .env("SYQ_TEST_AVAILABLE_INODES", "0")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_sparse_copy(&t.path("dst/file"), &data);
    fs::remove_dir_all(t.path("dst")).unwrap();
    let out = compat_command()
        .args(["-aS", &t.s("src/"), &t.s("dst")])
        .env("SYQ_TEST_AVAILABLE_BYTES", "1")
        .env("SYQ_TEST_AVAILABLE_INODES", "100")
        .run()
        .unwrap();
    assert_output_ok(&out);
    assert_sparse_copy(&t.path("dst/file"), &data);
}

#[cfg(debug_assertions)]
#[test]
fn sparse_interrupted_small_copy_and_lost_finalize_reply_recover() {
    let t = Tmp::new();
    let data = sparse_data();
    write(&t.path("small"), &data[..16384]);
    let args = ["-aS", &t.s("small"), &t.s("small-dst")];
    let out = compat_command()
        .args(args)
        .env("SYQ_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "small-dst")
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert!(!t.path("small-dst").exists());
    let small_partials = partial_files(&t.0);
    assert!(!small_partials.is_empty());
    run_ok(&args);
    assert_eq!(read(&t.path("small-dst")), data[..16384]);
    assert_eq!(partial_files(&t.0), small_partials);

    let rsh = fake_rsh(&t);
    t.expose_remote_syq();
    write(&t.path("source"), &data);
    let remote = format!("fake:{}", t.s("remote"));
    let marker = t.path("drop-once");
    let out = remote_syq_command(
        &t,
        &rsh,
        &[
            "-aS",
            "--syq-no-bootstrap",
            "--block-size=64K",
            &t.s("source"),
            &remote,
        ],
    )
    .env("SYQ_TEST_DROP_AFTER_REQUEST", "finalize")
    .env("SYQ_TEST_DROP_MARKER", &marker)
    .run()
    .unwrap();
    assert_output_ok(&out);
    assert!(marker.exists());
    assert_sparse_copy(&t.path("remote"), &data);
}

#[cfg(all(debug_assertions, target_os = "linux"))]
#[test]
fn sparse_local_buffered_failure_resumes_from_partial_with_changed_source() {
    let t = Tmp::new();
    let mut data = sparse_data();
    write(&t.path("src/file"), &data);
    write(&t.path("dst/file"), b"old destination");
    let out = compat_command()
        .args(["-aS", &t.s("src/"), &t.s("dst/")])
        .env("SYQ_TEST_COPY_LOCAL_EXDEV", "1")
        .env("SYQ_TEST_COPY_LOCAL_FS", "local")
        .env("SYQ_TEST_FAIL_COPY_LOCAL_AFTER_WRITE", "1")
        .run()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(read(&t.path("dst/file")), b"old destination");
    let partials = partial_files(&t.path("dst"));
    assert!(!partials.is_empty());
    data[..65536].fill(0);
    data[2 * 1024 * 1024..2 * 1024 * 1024 + 43].fill(93);
    write(&t.path("src/file"), &data);
    run_ok(&[
        "-aSc",
        "--performance-tuning=copy-path=ranges",
        "--block-size=64K",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_sparse_copy(&t.path("dst/file"), &data);
    assert_eq!(partial_files(&t.path("dst")), partials);
}
