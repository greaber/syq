//! Integration tests: local -> local copies through the built binary.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Tmp {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("pcp-test-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
    fn s(&self, rel: &str) -> String {
        self.path(rel).to_string_lossy().into_owned()
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        // Make everything removable again (tests chmod 000 some files).
        fn fix(p: &Path) {
            if let Ok(md) = fs::symlink_metadata(p) {
                if md.is_dir() {
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
                    if let Ok(rd) = fs::read_dir(p) {
                        for e in rd.flatten() {
                            fix(&e.path());
                        }
                    }
                } else if md.is_file() {
                    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o644));
                }
            }
        }
        fix(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pcp(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args(args)
        .arg("--no-progress")
        .output()
        .expect("run pcp")
}

fn run_ok(args: &[&str]) -> String {
    let out = pcp(args);
    assert!(
        out.status.success(),
        "pcp {:?} failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Parse "pcp: transferred N files" from the summary line.
fn transferred(stdout: &str) -> u64 {
    let line = stdout
        .lines()
        .find(|l| l.starts_with("pcp: transferred") || l.starts_with("pcp: would transfer"))
        .unwrap_or_else(|| panic!("no summary line in {stdout:?}"));
    let after = line.split("transfer").nth(1).unwrap();
    let after = after.trim_start_matches("red").trim_start();
    let n: String = after.chars().take_while(|c| c.is_ascii_digit() || *c == ',').collect();
    n.replace(',', "").parse().unwrap()
}

fn write(p: &Path, data: &[u8]) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    File::create(p).unwrap().write_all(data).unwrap();
}

fn read(p: &Path) -> Vec<u8> {
    let mut v = Vec::new();
    File::open(p).unwrap().read_to_end(&mut v).unwrap();
    v
}

fn set_mtime(p: &Path, secs: i64) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let ts = [
        libc::timespec { tv_sec: secs, tv_nsec: 0 },
        libc::timespec { tv_sec: secs, tv_nsec: 0 },
    ];
    let r = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), ts.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) };
    assert_eq!(r, 0, "utimensat {}", p.display());
}

fn mkfifo(p: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
}

/// Cheap deterministic pseudo-random bytes.
fn prng(len: usize, seed: u64) -> Vec<u8> {
    let mut v = vec![0u8; len];
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407) | 1;
    for chunk in v.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    v
}

/// Assert two trees are identical in kind, size, content, mode, mtime (seconds) and link targets.
fn assert_same_tree(a: &Path, b: &Path) {
    let ma = fs::symlink_metadata(a).unwrap_or_else(|e| panic!("{}: {e}", a.display()));
    let mb = fs::symlink_metadata(b).unwrap_or_else(|e| panic!("{}: {e}", b.display()));
    assert_eq!(ma.file_type(), mb.file_type(), "kind differs: {} vs {}", a.display(), b.display());
    if ma.file_type().is_symlink() {
        assert_eq!(fs::read_link(a).unwrap(), fs::read_link(b).unwrap(), "link target {}", a.display());
        return;
    }
    assert_eq!(ma.mode() & 0o7777, mb.mode() & 0o7777, "mode differs: {}", a.display());
    assert_eq!(ma.mtime(), mb.mtime(), "mtime differs: {}", a.display());
    if ma.is_file() {
        assert_eq!(ma.len(), mb.len(), "size differs: {}", a.display());
        assert!(read(a) == read(b), "content differs: {}", a.display());
    } else if ma.is_dir() {
        let mut ea: Vec<_> = fs::read_dir(a).unwrap().map(|e| e.unwrap().file_name()).collect();
        let mut eb: Vec<_> = fs::read_dir(b).unwrap().map(|e| e.unwrap().file_name()).collect();
        ea.sort();
        eb.sort();
        assert_eq!(ea, eb, "directory listing differs: {} vs {}", a.display(), b.display());
        for name in ea {
            assert_same_tree(&a.join(&name), &b.join(&name));
        }
    }
}

/// A representative source tree with all the entry kinds we care about.
fn make_tree(root: &Path) {
    write(&root.join("hello.txt"), b"hello\n");
    write(&root.join("a/med.bin"), &prng(3 * 1024 * 1024 + 17, 1));
    for i in 0..30 {
        write(&root.join(format!("a/b/f{i}")), &prng((i * 977) % 5000, i as u64));
    }
    write(&root.join("a/b/c/zero"), b"");
    fs::create_dir_all(root.join("empty")).unwrap();
    std::os::unix::fs::symlink("hello.txt", root.join("link")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/target", root.join("badlink")).unwrap();
    mkfifo(&root.join("fifo"));
    fs::set_permissions(root.join("hello.txt"), fs::Permissions::from_mode(0o640)).unwrap();
    fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(root.join("a/med.bin"), fs::Permissions::from_mode(0o600)).unwrap();
    let t = 1_577_934_245; // 2020-01-02 03:04:05 UTC
    set_mtime(&root.join("hello.txt"), t);
    set_mtime(&root.join("a/b/c/zero"), t + 1);
    set_mtime(&root.join("link"), t + 2);
    set_mtime(&root.join("a/b/c"), t + 3);
    set_mtime(&root.join("a/b"), t + 4);
    set_mtime(&root.join("a"), t + 5);
    set_mtime(&root.join("empty"), t + 6);
    set_mtime(root, t + 7);
}

#[test]
fn dir_into_missing_dest_creates_basename() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    assert!(t.path("dst/src").is_dir(), "expected dst/src to be created");
    assert_same_tree(&t.path("src"), &t.path("dst/src"));
}

#[test]
fn trailing_slash_copies_contents() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst")]);
    assert!(t.path("dst/hello.txt").is_file());
    assert!(!t.path("dst/src").exists());
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn dir_into_existing_dir() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    fs::create_dir(t.path("dst")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    assert_same_tree(&t.path("src"), &t.path("dst/src"));
}

#[test]
fn single_file_to_new_name() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    set_mtime(&t.path("src/f.txt"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("out.txt")]);
    assert_eq!(read(&t.path("out.txt")), b"data");
    assert_same_tree(&t.path("src/f.txt"), &t.path("out.txt"));
}

#[test]
fn single_file_into_existing_dir() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    fs::create_dir(t.path("dst")).unwrap();
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/f.txt")), b"data");
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("dst2/")]);
    assert_eq!(read(&t.path("dst2/f.txt")), b"data");
}

#[test]
fn multiple_sources_into_new_dest() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("src/d/x"), b"x");
    write(&t.path("src/d/y/z"), b"z");
    run_ok(&["-a", &t.s("src/f.txt"), &t.s("src/d"), &t.s("dst")]);
    assert!(t.path("dst").is_dir());
    assert_eq!(read(&t.path("dst/f.txt")), b"data");
    assert_same_tree(&t.path("src/d"), &t.path("dst/d"));
}

#[test]
fn multiple_sources_require_dir_dest() {
    let t = Tmp::new();
    write(&t.path("src/f.txt"), b"data");
    write(&t.path("src/g.txt"), b"data");
    write(&t.path("dst"), b"a file");
    let out = pcp(&["-a", &t.s("src/f.txt"), &t.s("src/g.txt"), &t.s("dst")]);
    assert!(!out.status.success());
    assert_eq!(read(&t.path("dst")), b"a file");
}

#[test]
fn metadata_preserved_with_archive() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let d = t.path("dst");
    // Explicit spot checks in addition to the tree comparison.
    let md = fs::metadata(d.join("hello.txt")).unwrap();
    assert_eq!(md.mode() & 0o777, 0o640);
    assert_eq!(md.mtime(), 1_577_934_245);
    assert_eq!(fs::metadata(d.join("a")).unwrap().mode() & 0o777, 0o750);
    assert_eq!(fs::read_link(d.join("badlink")).unwrap(), PathBuf::from("/nonexistent/target"));
    assert_eq!(fs::read_link(d.join("link")).unwrap(), PathBuf::from("hello.txt"));
    assert!(std::os::unix::fs::FileTypeExt::is_fifo(&fs::symlink_metadata(d.join("fifo")).unwrap().file_type()));
    assert_eq!(fs::metadata(d.join("a/b/c/zero")).unwrap().len(), 0);
    assert!(d.join("empty").is_dir());
    assert_eq!(fs::read_dir(d.join("empty")).unwrap().count(), 0);
    // Directory mtimes survive their children being written.
    assert_eq!(fs::metadata(d.join("a")).unwrap().mtime(), 1_577_934_245 + 5);
    assert_eq!(fs::metadata(d.join("a/b")).unwrap().mtime(), 1_577_934_245 + 4);
    assert_eq!(fs::metadata(d.join("a/b/c")).unwrap().mtime(), 1_577_934_245 + 3);
    assert_eq!(fs::metadata(d.join("empty")).unwrap().mtime(), 1_577_934_245 + 6);
    assert_eq!(fs::metadata(&d).unwrap().mtime(), 1_577_934_245 + 7);
    assert_same_tree(&t.path("src"), &d);
}

#[test]
fn rerun_transfers_nothing() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    let out = run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert!(transferred(&out) > 0);
    let out = run_ok(&["-av", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 0, "second run should transfer nothing: {out}");
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn resume_from_partial() {
    let t = Tmp::new();
    let data = prng(6 * 1024 * 1024 + 123, 42);
    write(&t.path("src/big.bin"), &data);
    set_mtime(&t.path("src/big.bin"), 1_600_000_000);
    fs::create_dir_all(t.path("dst")).unwrap();
    // Fake an interrupted transfer: first half present, rest preallocated.
    let partial = t.path("dst/.big.bin.pcp-partial");
    {
        let f = File::create(&partial).unwrap();
        (&f).write_all(&data[..data.len() / 2]).unwrap();
        f.set_len(data.len() as u64).unwrap();
    }
    let out = run_ok(&["-a", "--block-size", "1M", &t.s("src/big.bin"), &t.s("dst/")]);
    assert!(read(&t.path("dst/big.bin")) == data);
    assert!(!partial.exists(), "partial should be gone after finalize");
    assert_same_tree(&t.path("src/big.bin"), &t.path("dst/big.bin"));
    // Roughly half should have been reused.
    assert!(out.contains("unchanged"), "{out}");
}

#[test]
fn checksum_repairs_silent_corruption() {
    let t = Tmp::new();
    let data = prng(5 * 1024 * 1024, 7);
    write(&t.path("src/f.bin"), &data);
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    // Corrupt one byte in the middle, keeping size and mtime.
    let mut bad = data.clone();
    bad[2_500_000] ^= 0xff;
    write(&t.path("dst/f.bin"), &bad);
    set_mtime(&t.path("dst/f.bin"), 1_600_000_000);

    let out = run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 0, "quick check should skip: {out}");
    assert!(read(&t.path("dst/f.bin")) == bad, "without -c the file must be left alone");

    let out = run_ok(&["-ac", "--block-size", "1M", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 1, "{out}");
    assert!(read(&t.path("dst/f.bin")) == data, "-c should repair");
    assert!(out.contains("(1.00 MiB)"), "only one block should be resent: {out}");
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn verify_only_detects_differences() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let out = pcp(&["-a", "--verify-only", &t.s("src/"), &t.s("dst/")]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    let mut bad = read(&t.path("dst/a/med.bin"));
    bad[1000] ^= 1;
    write(&t.path("dst/a/med.bin"), &bad);
    set_mtime(&t.path("dst/a/med.bin"), fs::metadata(t.path("src/a/med.bin")).unwrap().mtime());
    fs::remove_file(t.path("dst/hello.txt")).unwrap();

    let out = pcp(&["-a", "--verify-only", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(out.status.code(), Some(23));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("DIFFERS a/med.bin"), "{err}");
    assert!(err.contains("MISSING hello.txt"), "{err}");
    // verify-only must not modify anything
    assert!(read(&t.path("dst/a/med.bin")) == bad);
    assert!(!t.path("dst/hello.txt").exists());
}

#[test]
fn large_file_parallel_chunks() {
    let t = Tmp::new();
    let data = prng(200 * 1024 * 1024 + 4321, 99);
    write(&t.path("src/huge.bin"), &data);
    set_mtime(&t.path("src/huge.bin"), 1_600_000_000);
    run_ok(&["-a", "-j", "8", "--block-size", "1M", "--min-split", "2M", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/huge.bin")) == data);
    assert_same_tree(&t.path("src/huge.bin"), &t.path("dst/huge.bin"));
    assert!(!t.path("dst/.huge.bin.pcp-partial").exists());
    // And partial resume of the same big file with parallel chunks.
    {
        let f = File::create(t.path("dst/.huge.bin.pcp-partial")).unwrap();
        (&f).write_all(&data[..50 * 1024 * 1024]).unwrap();
        f.set_len(data.len() as u64).unwrap();
    }
    fs::remove_file(t.path("dst/huge.bin")).unwrap();
    run_ok(&["-a", "-j", "8", "--block-size", "1M", "--min-split", "2M", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/huge.bin")) == data);
}

#[test]
fn dry_run_creates_nothing() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    let out = run_ok(&["-an", &t.s("src"), &t.s("dst")]);
    assert!(!t.path("dst").exists(), "dry run must not create the destination");
    assert!(out.contains("would transfer"), "{out}");
    assert!(transferred(&out) > 0);
}

#[test]
fn inplace_leaves_no_partial() {
    let t = Tmp::new();
    let data = prng(3 * 1024 * 1024, 5);
    write(&t.path("src/f.bin"), &data);
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", "--inplace", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/f.bin")) == data);
    assert!(!t.path("dst/.f.bin.pcp-partial").exists());
    // Update in place when the destination differs.
    let data2 = prng(3 * 1024 * 1024 + 10, 6);
    write(&t.path("src/f.bin"), &data2);
    set_mtime(&t.path("src/f.bin"), 1_600_000_001);
    run_ok(&["-a", "--inplace", &t.s("src/"), &t.s("dst/")]);
    assert!(read(&t.path("dst/f.bin")) == data2);
    assert!(!t.path("dst/.f.bin.pcp-partial").exists());
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn unreadable_source_reports_error_but_continues() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root can read anything
    }
    let t = Tmp::new();
    write(&t.path("src/ok.txt"), b"fine");
    write(&t.path("src/secret.txt"), b"nope");
    write(&t.path("src/also_ok.txt"), b"fine too");
    fs::set_permissions(t.path("src/secret.txt"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = pcp(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(out.status.code(), Some(23), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("secret.txt"), "{err}");
    assert_eq!(read(&t.path("dst/ok.txt")), b"fine");
    assert_eq!(read(&t.path("dst/also_ok.txt")), b"fine too");
    assert!(!t.path("dst/secret.txt").exists());
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
    assert_eq!(fs::read_link(t.path("dst/l")).unwrap(), PathBuf::from("other"));
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

// ---- Regression tests for the security review ----

#[test]
fn inplace_self_copy_preserves_source() {
    let t = Tmp::new();
    write(&t.path("f"), b"hello world data");
    // Copying a file onto itself must never truncate it.
    let out = pcp(&["-a", "--inplace", &t.s("f"), &t.s("f")]);
    assert!(out.status.success());
    assert_eq!(read(&t.path("f")), b"hello world data");
}

#[test]
fn inplace_hardlink_alias_preserves_source() {
    let t = Tmp::new();
    write(&t.path("a"), b"aaaa");
    fs::hard_link(t.path("a"), t.path("b")).unwrap();
    let out = pcp(&["-a", "--inplace", &t.s("a"), &t.s("b")]);
    assert!(out.status.success());
    assert_eq!(read(&t.path("a")), b"aaaa");
    assert_eq!(read(&t.path("b")), b"aaaa");
}

#[test]
fn inplace_replaces_symlink_dest_not_its_target() {
    let t = Tmp::new();
    write(&t.path("src"), b"SRCDATA");
    write(&t.path("external"), b"EXTERNAL");
    std::os::unix::fs::symlink("external", t.path("link")).unwrap();
    run_ok(&["-a", "--inplace", &t.s("src"), &t.s("link")]);
    // The symlink target must be untouched; the dest is now a regular file.
    assert_eq!(read(&t.path("external")), b"EXTERNAL");
    assert!(fs::symlink_metadata(t.path("link")).unwrap().file_type().is_file());
    assert_eq!(read(&t.path("link")), b"SRCDATA");
}

#[test]
fn rm_rejects_parent_traversal() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("parent/child")).unwrap();
    write(&t.path("parent/sibling"), b"x");
    write(&t.path("parent/child/y"), b"y");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args(["--rm", ".."])
        .arg("--no-progress")
        .current_dir(t.path("parent/child"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    // The sibling outside child must survive.
    assert!(t.path("parent/sibling").exists());
}

#[test]
fn rm_rejects_dangerous_roots() {
    for target in ["/", ".", "~", "/tmp/.."] {
        let out = pcp(&["--rm", target]);
        assert!(!out.status.success(), "should reject --rm {target}");
    }
}

#[test]
fn rm_normal_target_works() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("killme/sub")).unwrap();
    write(&t.path("killme/sub/f"), b"f");
    run_ok(&["--rm", &t.s("killme")]);
    assert!(!t.path("killme").exists());
}

#[test]
fn duplicate_destination_rejected() {
    let t = Tmp::new();
    write(&t.path("a/same"), b"A");
    write(&t.path("b/same"), b"B");
    fs::create_dir_all(t.path("dest")).unwrap();
    let out = pcp(&["-a", &t.s("a/same"), &t.s("b/same"), &t.s("dest/")]);
    assert!(!out.status.success(), "two sources named 'same' must be rejected");
    assert!(!t.path("dest/same").exists());
}

#[test]
fn checksum_repair_shrinks_longer_destination() {
    let t = Tmp::new();
    write(&t.path("src"), b"abc");
    write(&t.path("dst"), b"ABCDEFG");
    set_mtime(&t.path("dst"), 1_000_000_000);
    set_mtime(&t.path("src"), 1_000_000_000);
    run_ok(&["-ac", &t.s("src"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst")), b"abc");
}

#[test]
fn skip_reconciles_mode() {
    let t = Tmp::new();
    write(&t.path("src"), b"data");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::copy(t.path("src"), t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o644)).unwrap();
    set_mtime(&t.path("src"), 1_000_000_000);
    set_mtime(&t.path("dst"), 1_000_000_000);
    // content is skipped, but -a must still fix the mode
    run_ok(&["-a", &t.s("src"), &t.s("dst")]);
    let m = fs::symlink_metadata(t.path("dst")).unwrap().mode() & 0o777;
    assert_eq!(m, 0o600, "mode should be reconciled on skip");
}

#[test]
fn no_perms_preserves_existing_dest_mode() {
    let t = Tmp::new();
    write(&t.path("src"), b"x");
    fs::copy(t.path("src"), t.path("dst")).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o666)).unwrap();
    write(&t.path("src"), b"y"); // change content so it transfers
    set_mtime(&t.path("dst"), 1_000_000_000);
    set_mtime(&t.path("src"), 1_000_000_500); // newer -> not skipped
    run_ok(&["-t", &t.s("src"), &t.s("dst")]); // no -p
    let m = fs::symlink_metadata(t.path("dst")).unwrap().mode() & 0o777;
    assert_eq!(m, 0o666, "existing dest mode must be preserved without -p");
    assert_eq!(read(&t.path("dst")), b"y");
}

#[test]
fn many_symlinks_no_setmeta_race() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("ln")).unwrap();
    for i in 0..100 {
        std::os::unix::fs::symlink(format!("/target{i}"), t.path(&format!("ln/l{i}"))).unwrap();
    }
    run_ok(&["-a", &t.s("ln"), &t.s("dst")]);
    let n = fs::read_dir(t.path("dst/ln")).unwrap().count();
    assert_eq!(n, 100);
}

#[test]
fn archive_into_readonly_dest_dir() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"hi");
    run_ok(&["-a", &t.s("src"), &t.s("d")]);
    fs::set_permissions(t.path("d/src"), fs::Permissions::from_mode(0o555)).unwrap();
    write(&t.path("src/sub/g"), b"more");
    run_ok(&["-a", &t.s("src/"), &t.s("d/src/")]);
    assert_eq!(read(&t.path("d/src/sub/g")), b"more");
}

// ---- Review round 3 ----

#[test]
fn partial_symlink_is_not_followed() {
    let t = Tmp::new();
    write(&t.path("src"), &vec![7u8; 5 * 1024 * 1024]);
    write(&t.path("external"), b"EXTERNAL-DO-NOT-TOUCH");
    // A malicious/stale partial symlink pointing outside must not be followed.
    std::os::unix::fs::symlink("external", t.path(".out.pcp-partial")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("out")]);
    assert_eq!(read(&t.path("external")), b"EXTERNAL-DO-NOT-TOUCH");
    assert!(fs::symlink_metadata(t.path("out")).unwrap().file_type().is_file());
    assert_eq!(read(&t.path("out")).len(), 5 * 1024 * 1024);
}

#[test]
fn rm_rejects_dot_final_component() {
    let t = Tmp::new();
    write(&t.path("p/f"), b"x");
    let out = pcp(&["--rm", &format!("{}/.", t.s("p"))]);
    assert!(!out.status.success());
    assert!(t.path("p/f").exists(), "contents must survive rm p/.");
}

#[test]
fn dir_vs_file_destination_collision_rejected() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"aaa");        // A/x is a file
    write(&t.path("B/x/y"), b"yyy");      // B/x is a directory
    fs::create_dir_all(t.path("dest")).unwrap();
    let out = pcp(&["-a", &format!("{}/", t.s("A")), &format!("{}/", t.s("B")), &format!("{}/", t.s("dest"))]);
    assert!(!out.status.success(), "conflicting file-vs-dir destination must be rejected");
}

#[test]
fn verify_only_detects_symlink_difference() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    std::os::unix::fs::symlink("target-a", t.path("s/l")).unwrap();
    std::os::unix::fs::symlink("target-b", t.path("d/l")).unwrap();
    let out = pcp(&["-a", "--verify-only", &format!("{}/", t.s("s")), &format!("{}/", t.s("d"))]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("DIFFERS"));
}

#[test]
fn small_files_atomic_no_partials() {
    let t = Tmp::new();
    for i in 0..200 {
        write(&t.path(&format!("sm/f{i}")), format!("data-{i}").as_bytes());
    }
    run_ok(&["-a", &format!("{}/", t.s("sm")), &format!("{}/", t.s("smd"))]);
    let partials = fs::read_dir(t.path("smd")).unwrap().filter(|e| {
        e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".pcp-partial")
    }).count();
    assert_eq!(partials, 0);
    assert_eq!(read(&t.path("smd/f7")), b"data-7");
}

// ---- Review round 4 (integrity) ----

#[test]
fn quick_skipped_file_still_claims_destination() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"aaa");     // A/x is a file
    write(&t.path("B/x/y"), b"yyy");   // B/x is a directory
    // Pre-populate dest/x identical to A/x so A/x is quick-skipped.
    write(&t.path("dest/x"), b"aaa");
    set_mtime(&t.path("A/x"), 1_000_000_000);
    set_mtime(&t.path("dest/x"), 1_000_000_000);
    let out = pcp(&["-a", &format!("{}/", t.s("A")), &format!("{}/", t.s("B")), &format!("{}/", t.s("dest"))]);
    // The skipped file must still claim dest/x, so B's directory is rejected.
    assert!(!out.status.success(), "quick-skipped file must still block a colliding directory");
}

#[test]
fn verify_only_flags_missing_directory() {
    let t = Tmp::new();
    write(&t.path("s/sub/f"), b"f");
    fs::create_dir_all(t.path("d")).unwrap(); // d exists but d/sub does not
    let out = pcp(&["-a", "--verify-only", &format!("{}/", t.s("s")), &format!("{}/", t.s("d"))]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("MISSING") &&
            String::from_utf8_lossy(&out.stderr).to_lowercase().contains("director"));
}

#[test]
fn verify_only_flags_missing_special() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    // create a fifo in the source
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(t.path("s/pipe").as_os_str().as_bytes()).unwrap();
    unsafe { assert_eq!(libc::mkfifo(c.as_ptr(), 0o644), 0); }
    let out = pcp(&["-a", "--verify-only", &format!("{}/", t.s("s")), &format!("{}/", t.s("d"))]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("special"));
}
