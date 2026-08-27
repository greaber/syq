//! Integration tests: local -> local copies through the built binary.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
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
    let n: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',')
        .collect();
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

fn executable(p: &Path, body: &[u8]) {
    write(p, body);
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A remote shell that executes the supplied command locally with an isolated
/// HOME.  This exercises pcp's real remote launcher/server protocol without
/// touching ssh or a real remote machine.
fn fake_rsh(t: &Tmp) -> PathBuf {
    let path = t.path("fake-rsh");
    executable(
        &path,
        br#"#!/bin/sh
shift
HOME="$FAKE_REMOTE_HOME"
PATH="$FAKE_REMOTE_BIN:/usr/bin:/bin"
export HOME PATH
printf '%s\n' "$1" >> "$FAKE_RSH_LOG"
exec /bin/sh -c "$1"
"#,
    );
    path
}

fn remote_pcp(t: &Tmp, rsh: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pcp"));
    cmd.args(["-e", rsh.to_str().unwrap(), "--no-tcp", "-j", "1"])
        .args(args)
        .arg("--no-progress")
        .env("FAKE_REMOTE_HOME", t.path("remote-home"))
        .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
        .env("FAKE_RELEASE_ARCHIVE", t.path("release.gz"))
        .env("FAKE_CURL_LOG", t.path("curl.log"))
        .env("FAKE_RSH_LOG", t.path("rsh.log"))
        .env("PCP_STATE_DIR", t.path("state"));
    cmd.output().expect("run pcp through fake remote shell")
}

fn assert_output_ok(out: &Output) {
    assert!(
        out.status.success(),
        "pcp failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn cached_remote_helper(t: &Tmp) -> PathBuf {
    let root = t.path("remote-home/.cache/pcp/helpers");
    let release = fs::read_dir(&root)
        .unwrap()
        .next()
        .expect("release cache directory")
        .unwrap()
        .path();
    let target = fs::read_dir(release)
        .unwrap()
        .next()
        .expect("target cache directory")
        .unwrap()
        .path();
    target.join("pcp")
}

#[cfg(target_os = "linux")]
#[test]
fn remote_helper_download_is_verified_and_cached() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    let archive = File::create(t.path("release.gz")).unwrap();
    let status = Command::new("gzip")
        .args(["-9", "-n", "-c", env!("CARGO_BIN_EXE_pcp")])
        .stdout(Stdio::from(archive))
        .status()
        .unwrap();
    assert!(status.success());
    let sum = Command::new("sha256sum")
        .arg(t.path("release.gz"))
        .output()
        .unwrap();
    assert!(sum.status.success());
    let digest = String::from_utf8(sum.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    write(
        &t.path("release.gz.sha256"),
        format!("{digest}\n").as_bytes(),
    );

    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
printf 'fetch\n' >> "$FAKE_CURL_LOG"
out=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) out=$2; shift 2 ;;
        *) url=$1; shift ;;
    esac
done
case "$url" in
    *.sha256) cp "$FAKE_RELEASE_ARCHIVE.sha256" "$out" ;;
    *) cp "$FAKE_RELEASE_ARCHIVE" "$out" ;;
esac
"#,
    );

    write(&t.path("src"), b"first");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_pcp(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"first");
    assert!(cached_remote_helper(&t).is_file());
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("uploading this executable"));
    let probes = fs::read_to_string(t.path("rsh.log"))
        .unwrap()
        .matches("pcp-helper-target:")
        .count();
    assert_eq!(probes, 1);

    // A cache hit goes straight to the helper: no platform probe or download.
    write(&t.path("src"), b"second");
    let out = remote_pcp(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"second");
    assert_eq!(read(&t.path("curl.log")), b"fetch\nfetch\n");
    let probes = fs::read_to_string(t.path("rsh.log"))
        .unwrap()
        .matches("pcp-helper-target:")
        .count();
    assert_eq!(probes, 1, "cache hit should not probe the platform again");
}

#[test]
fn remote_helper_falls_back_to_same_platform_upload() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    executable(
        &t.path("remote-bin/curl"),
        br#"#!/bin/sh
printf 'fetch failed\n' >> "$FAKE_CURL_LOG"
exit 22
"#,
    );

    write(&t.path("src"), b"offline");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_pcp(&t, &rsh, &["-a", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"offline");
    assert!(cached_remote_helper(&t).is_file());
    assert!(String::from_utf8_lossy(&out.stderr).contains("uploading this executable"));
    assert_eq!(read(&t.path("curl.log")), b"fetch failed\n");
}

#[test]
fn no_bootstrap_uses_remote_path_without_managed_cache() {
    let t = Tmp::new();
    let rsh = fake_rsh(&t);
    fs::create_dir_all(t.path("remote-bin")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_pcp"), t.path("remote-bin/pcp")).unwrap();

    write(&t.path("src"), b"preinstalled");
    let remote = format!("fake:{}", t.s("dst"));
    let out = remote_pcp(&t, &rsh, &["-a", "--no-bootstrap", &t.s("src"), &remote]);
    assert_output_ok(&out);
    assert_eq!(read(&t.path("dst")), b"preinstalled");
    assert!(!t.path("remote-home/.cache/pcp/helpers").exists());
}

fn set_mtime(p: &Path, secs: i64) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c = CString::new(p.as_os_str().as_bytes()).unwrap();
    let ts = [
        libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        },
    ];
    let r = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            ts.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
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
    let mut x = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
        | 1;
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
    assert_eq!(
        ma.file_type(),
        mb.file_type(),
        "kind differs: {} vs {}",
        a.display(),
        b.display()
    );
    if ma.file_type().is_symlink() {
        assert_eq!(
            fs::read_link(a).unwrap(),
            fs::read_link(b).unwrap(),
            "link target {}",
            a.display()
        );
        return;
    }
    assert_eq!(
        ma.mode() & 0o7777,
        mb.mode() & 0o7777,
        "mode differs: {}",
        a.display()
    );
    assert_eq!(ma.mtime(), mb.mtime(), "mtime differs: {}", a.display());
    if ma.is_file() {
        assert_eq!(ma.len(), mb.len(), "size differs: {}", a.display());
        assert!(read(a) == read(b), "content differs: {}", a.display());
    } else if ma.is_dir() {
        let mut ea: Vec<_> = fs::read_dir(a)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let mut eb: Vec<_> = fs::read_dir(b)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        ea.sort();
        eb.sort();
        assert_eq!(
            ea,
            eb,
            "directory listing differs: {} vs {}",
            a.display(),
            b.display()
        );
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
        write(
            &root.join(format!("a/b/f{i}")),
            &prng((i * 977) % 5000, i as u64),
        );
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
    assert_eq!(
        fs::read_link(d.join("badlink")).unwrap(),
        PathBuf::from("/nonexistent/target")
    );
    assert_eq!(
        fs::read_link(d.join("link")).unwrap(),
        PathBuf::from("hello.txt")
    );
    assert!(std::os::unix::fs::FileTypeExt::is_fifo(
        &fs::symlink_metadata(d.join("fifo")).unwrap().file_type()
    ));
    assert_eq!(fs::metadata(d.join("a/b/c/zero")).unwrap().len(), 0);
    assert!(d.join("empty").is_dir());
    assert_eq!(fs::read_dir(d.join("empty")).unwrap().count(), 0);
    // Directory mtimes survive their children being written.
    assert_eq!(
        fs::metadata(d.join("a")).unwrap().mtime(),
        1_577_934_245 + 5
    );
    assert_eq!(
        fs::metadata(d.join("a/b")).unwrap().mtime(),
        1_577_934_245 + 4
    );
    assert_eq!(
        fs::metadata(d.join("a/b/c")).unwrap().mtime(),
        1_577_934_245 + 3
    );
    assert_eq!(
        fs::metadata(d.join("empty")).unwrap().mtime(),
        1_577_934_245 + 6
    );
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
    assert_eq!(
        transferred(&out),
        0,
        "second run should transfer nothing: {out}"
    );
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
    let out = run_ok(&[
        "-a",
        "--block-size",
        "1M",
        &t.s("src/big.bin"),
        &t.s("dst/"),
    ]);
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
    assert!(
        read(&t.path("dst/f.bin")) == bad,
        "without -c the file must be left alone"
    );

    let out = run_ok(&["-ac", "--block-size", "1M", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(transferred(&out), 1, "{out}");
    assert!(read(&t.path("dst/f.bin")) == data, "-c should repair");
    assert!(
        out.contains("(1.00 MiB)"),
        "only one block should be resent: {out}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn verify_only_detects_differences() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let out = pcp(&["-a", "--verify-only", &t.s("src/"), &t.s("dst/")]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut bad = read(&t.path("dst/a/med.bin"));
    bad[1000] ^= 1;
    write(&t.path("dst/a/med.bin"), &bad);
    set_mtime(
        &t.path("dst/a/med.bin"),
        fs::metadata(t.path("src/a/med.bin")).unwrap().mtime(),
    );
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
    run_ok(&[
        "-a",
        "-j",
        "8",
        "--block-size",
        "1M",
        "--min-split",
        "2M",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
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
    run_ok(&[
        "-a",
        "-j",
        "8",
        "--block-size",
        "1M",
        "--min-split",
        "2M",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(read(&t.path("dst/huge.bin")) == data);
}

#[test]
fn bwlimit_is_aggregate_across_workers() {
    let t = Tmp::new();
    for i in 0..4 {
        write(
            &t.path(&format!("src/{i}.bin")),
            &prng(512 * 1024, i as u64 + 100),
        );
    }

    // Four independent files keep four workers active. At 1 MiB/s, their
    // aggregate 2 MiB must take about two seconds (minus the initial burst). A
    // mistakenly per-worker limiter would finish in well under one second.
    let start = std::time::Instant::now();
    run_ok(&[
        "-a",
        "-j",
        "4",
        "--bwlimit",
        "1M",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(1600),
        "aggregate 2 MiB copy completed too quickly: {elapsed:?}"
    );
    assert_same_tree(&t.path("src"), &t.path("dst"));
}

#[test]
fn bwlimit_rejects_invalid_rates() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"x");
    let out = pcp(&["-a", "--bwlimit", "fast", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("bad --bwlimit"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn dry_run_creates_nothing() {
    let t = Tmp::new();
    make_tree(&t.path("src"));
    let out = run_ok(&["-an", &t.s("src"), &t.s("dst")]);
    assert!(
        !t.path("dst").exists(),
        "dry run must not create the destination"
    );
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
    assert_eq!(
        out.status.code(),
        Some(23),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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
    assert_eq!(
        fs::read_link(t.path("dst/l")).unwrap(),
        PathBuf::from("other")
    );
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
    assert!(fs::symlink_metadata(t.path("link"))
        .unwrap()
        .file_type()
        .is_file());
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
    assert!(
        !out.status.success(),
        "two sources named 'same' must be rejected"
    );
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
    assert!(fs::symlink_metadata(t.path("out"))
        .unwrap()
        .file_type()
        .is_file());
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
    write(&t.path("A/x"), b"aaa"); // A/x is a file
    write(&t.path("B/x/y"), b"yyy"); // B/x is a directory
    fs::create_dir_all(t.path("dest")).unwrap();
    let out = pcp(&[
        "-a",
        &format!("{}/", t.s("A")),
        &format!("{}/", t.s("B")),
        &format!("{}/", t.s("dest")),
    ]);
    assert!(
        !out.status.success(),
        "conflicting file-vs-dir destination must be rejected"
    );
}

#[test]
fn file_over_nonempty_destination_directory_reports_error_without_panicking() {
    let t = Tmp::new();
    write(&t.path("src/foo"), b"source");
    write(&t.path("dest/foo/keep"), b"keep");

    let out = pcp(&["-j", "1", &t.s("src/foo"), &t.s("dest")]);

    assert_eq!(out.status.code(), Some(23));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("destination") && err.contains("is a directory"),
        "{err}"
    );
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(read(&t.path("dest/foo/keep")), b"keep");
}

#[test]
fn verify_only_detects_symlink_difference() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    std::os::unix::fs::symlink("target-a", t.path("s/l")).unwrap();
    std::os::unix::fs::symlink("target-b", t.path("d/l")).unwrap();
    let out = pcp(&[
        "-a",
        "--verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("DIFFERS"));
}

#[test]
fn small_files_atomic_no_partials() {
    let t = Tmp::new();
    for i in 0..200 {
        write(&t.path(&format!("sm/f{i}")), format!("data-{i}").as_bytes());
    }
    // A stale sidecar from an earlier interrupted or differently configured
    // run is overwritten by the atomic small-file path and renamed away.
    write(&t.path("smd/.f7.pcp-partial"), b"stale");
    run_ok(&[
        "-a",
        &format!("{}/", t.s("sm")),
        &format!("{}/", t.s("smd")),
    ]);
    let partials = fs::read_dir(t.path("smd"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".pcp-partial")
        })
        .count();
    assert_eq!(partials, 0);
    assert_eq!(read(&t.path("smd/f7")), b"data-7");
}

#[cfg(debug_assertions)]
#[test]
fn small_file_failure_never_publishes_partial_contents() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"complete contents");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("PCP_TEST_FAIL_PUT_SMALL_BEFORE_RENAME", "/f")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert!(
        !t.path("dst/f").exists(),
        "the final name must not appear before the atomic rename"
    );
    assert_eq!(read(&t.path("dst/.f.pcp-partial")), b"complete contents");

    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f")), b"complete contents");
    assert!(!t.path("dst/.f.pcp-partial").exists());
}

// ---- Review round 4 (integrity) ----

#[test]
fn quick_skipped_file_still_claims_destination() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"aaa"); // A/x is a file
    write(&t.path("B/x/y"), b"yyy"); // B/x is a directory
                                     // Pre-populate dest/x identical to A/x so A/x is quick-skipped.
    write(&t.path("dest/x"), b"aaa");
    set_mtime(&t.path("A/x"), 1_000_000_000);
    set_mtime(&t.path("dest/x"), 1_000_000_000);
    let out = pcp(&[
        "-a",
        &format!("{}/", t.s("A")),
        &format!("{}/", t.s("B")),
        &format!("{}/", t.s("dest")),
    ]);
    // The skipped file must still claim dest/x, so B's directory is rejected.
    assert!(
        !out.status.success(),
        "quick-skipped file must still block a colliding directory"
    );
}

#[test]
fn verify_only_flags_missing_directory() {
    let t = Tmp::new();
    write(&t.path("s/sub/f"), b"f");
    fs::create_dir_all(t.path("d")).unwrap(); // d exists but d/sub does not
    let out = pcp(&[
        "-a",
        "--verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("MISSING")
            && String::from_utf8_lossy(&out.stderr)
                .to_lowercase()
                .contains("director")
    );
}

#[test]
fn verify_only_flags_missing_special() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("s")).unwrap();
    fs::create_dir_all(t.path("d")).unwrap();
    // create a fifo in the source
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(t.path("s/pipe").as_os_str().as_bytes()).unwrap();
    unsafe {
        assert_eq!(libc::mkfifo(c.as_ptr(), 0o644), 0);
    }
    let out = pcp(&[
        "-a",
        "--verify-only",
        &format!("{}/", t.s("s")),
        &format!("{}/", t.s("d")),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(String::from_utf8_lossy(&out.stderr).contains("special"));
}

// ---- Review round 5 ----

#[test]
fn rejects_copying_directory_into_itself() {
    let t = Tmp::new();
    write(&t.path("src/file"), b"hi");
    let out = pcp(&[
        "-a",
        &format!("{}/", t.s("src")),
        &format!("{}/", t.s("src/dst")),
    ]);
    assert!(!out.status.success(), "dest inside source must be rejected");
    // src must be untouched (no dst subtree created)
    assert!(!t.path("src/dst").exists());
}

#[test]
fn hardlinked_partial_does_not_corrupt_external_file() {
    let t = Tmp::new();
    write(&t.path("src"), &vec![9u8; 5 * 1024 * 1024]);
    write(&t.path("external"), b"EXTERNAL-DO-NOT-TOUCH");
    // A partial hardlinked to an external file (as a dedup/backup tool might make).
    fs::hard_link(t.path("external"), t.path(".out.pcp-partial")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("out")]);
    assert_eq!(read(&t.path("external")), b"EXTERNAL-DO-NOT-TOUCH");
    assert_eq!(read(&t.path("out")).len(), 5 * 1024 * 1024);
    // out and external must be different inodes
    let mo = fs::metadata(t.path("out")).unwrap();
    let me = fs::metadata(t.path("external")).unwrap();
    assert!(!(mo.dev() == me.dev() && mo.ino() == me.ino()));
}

#[test]
fn rejects_bare_dir_into_parent_mapping_onto_itself() {
    let t = Tmp::new();
    write(&t.path("sub/f"), b"x");
    // Copying t/sub into t (existing dir) maps to t/sub — the source itself.
    let out = pcp(&["-a", &t.s("sub"), &t.s(".")]);
    // t.s(".") is the tmp dir itself (existing), so effective dest = <tmp>/sub.
    assert!(
        !out.status.success(),
        "bare dir whose effective destination is itself must be rejected"
    );
    assert!(t.path("sub/f").exists());
}

#[test]
fn file_onto_itself_is_allowed_noop() {
    let t = Tmp::new();
    write(&t.path("f"), b"hello");
    run_ok(&["-a", "--inplace", &t.s("f"), &t.s("f")]);
    assert_eq!(read(&t.path("f")), b"hello");
}

/// Tree for the --ignore tests.
fn make_ignore_tree(root: &Path) {
    for f in [
        "hello.txt",
        "x.o",
        "a/y.o",
        "a/b/z.jpg",
        "a/pic.jpg",
        "node_modules/x/m.js",
        "a/node_modules/n.js",
        "build/out",
        "a/build/out2",
        "logs/l1",
        "logs/keep/k",
    ] {
        write(&root.join(f), f.as_bytes());
    }
    fs::create_dir_all(root.join("empty")).unwrap();
}

fn listing(root: &Path) -> Vec<String> {
    fn walk(root: &Path, p: &Path, out: &mut Vec<String>) {
        let mut names: Vec<_> = fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        names.sort();
        for n in names {
            out.push(n.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            if n.symlink_metadata().unwrap().is_dir() {
                walk(root, &n, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn ignore_patterns_prune_dirs_and_files() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // `node_modules` at any depth, `*.o` anywhere, `/build` only at the root.
    run_ok(&[
        "-a",
        "-i",
        "node_modules",
        "-i",
        "*.o",
        "-i",
        "/build",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            "a",
            "a/b",
            "a/b/z.jpg",
            "a/build",
            "a/build/out2",
            "a/pic.jpg",
            "empty",
            "hello.txt",
            "logs",
            "logs/keep",
            "logs/keep/k",
            "logs/l1",
        ]
    );
}

#[test]
fn ignore_only_idiom_and_empty_dirs() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // The gitignore "only *.jpg" idiom: directories are still all created.
    run_ok(&[
        "-a",
        "-i",
        "*",
        "-i",
        "!*/",
        "-i",
        "!*.jpg",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    let l = listing(&t.path("dst"));
    assert!(l.contains(&"a/b/z.jpg".to_string()));
    assert!(l.contains(&"a/pic.jpg".to_string()));
    assert!(l.contains(&"empty".to_string()));
    assert!(l.contains(&"node_modules/x".to_string()));
    assert!(!l
        .iter()
        .any(|p| p.ends_with(".o") || p.ends_with(".txt") || p.ends_with(".js")));
    // Without any pattern, empty dirs are copied too.
    run_ok(&["-a", &t.s("src/"), &t.s("dst2")]);
    assert!(t.path("dst2/empty").is_dir());
}

#[test]
fn ignore_from_file_and_later_negation_wins() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    write(&t.path("pats"), b"# comment\nnode_modules\n\n*.o\r\n");
    run_ok(&[
        "-a",
        "--ignore-from",
        &t.s("pats"),
        "-i",
        "!x.o",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    let l = listing(&t.path("dst"));
    assert!(
        l.contains(&"x.o".to_string()),
        "later -i '!x.o' must override file"
    );
    assert!(!l.contains(&"a/y.o".to_string()));
    assert!(!l.iter().any(|p| p.contains("node_modules")));
    // And the other order: the file's `*.o` comes last, so x.o stays ignored.
    run_ok(&[
        "-a",
        "-i",
        "!x.o",
        "--ignore-from",
        &t.s("pats"),
        &t.s("src/"),
        &t.s("dst2"),
    ]);
    assert!(!t.path("dst2/x.o").exists());
    // Missing file is an error.
    let out = pcp(&[
        "-a",
        "--ignore-from",
        &t.s("nope"),
        &t.s("src/"),
        &t.s("dst3"),
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--ignore-from"));
}

#[test]
fn ignore_applies_per_source_root_and_dry_run() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("s1"));
    make_ignore_tree(&t.path("s2"));
    fs::create_dir(t.path("dst")).unwrap();
    // `/build` is anchored at each source's root, not the destination.
    run_ok(&["-a", "-i", "/build", &t.s("s1"), &t.s("s2"), &t.s("dst")]);
    assert!(!t.path("dst/s1/build").exists());
    assert!(!t.path("dst/s2/build").exists());
    assert!(t.path("dst/s1/a/build/out2").is_file());
    // Dry run with the root itself matching a pattern: the root is never ignored.
    let out = run_ok(&["-an", "-i", "s1", "-i", "*.o", &t.s("s1"), &t.s("dst2")]);
    assert!(!t.path("dst2").exists());
    assert!(out.contains("would transfer 9 files"), "{out}");
}

#[test]
fn ignore_reinclude_subdir_idiom() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    // Everything directly under logs/ except the keep/ directory (git idiom).
    run_ok(&[
        "-a",
        "-i",
        "logs/*",
        "-i",
        "!logs/keep/",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(t.path("dst/logs/keep/k").is_file());
    assert!(!t.path("dst/logs/l1").exists());
}

#[test]
fn ignore_from_strips_bom_and_hyphen_patterns_work() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("src"));
    write(&t.path("-dash"), b"d");
    write(&t.path("src/-secret"), b"s");
    write(&t.path("pats"), "\u{feff}*.o\n".as_bytes());
    run_ok(&[
        "-a",
        "--ignore-from",
        &t.s("pats"),
        "-i",
        "-secret",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(
        !t.path("dst/x.o").exists(),
        "BOM must not hide the first rule"
    );
    assert!(!t.path("dst/-secret").exists());
    assert!(t.path("dst/hello.txt").is_file());
}

#[test]
fn ignore_conflicts_with_rm() {
    let t = Tmp::new();
    make_ignore_tree(&t.path("tree"));
    let out = pcp(&["--rm", "-i", "keep", &t.s("tree")]);
    assert!(!out.status.success(), "--rm with -i must be rejected");
    assert!(
        t.path("tree/logs/keep/k").is_file(),
        "nothing may be removed"
    );
    let out = pcp(&[
        "--rm",
        "--ignore-from",
        &t.s("tree/hello.txt"),
        &t.s("tree"),
    ]);
    assert!(!out.status.success());
    assert!(t.path("tree/hello.txt").is_file());
}

// ---------------------------------------------------------------- --delete

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn delete_removes_extras_and_protects_ignored() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/d/b"), b"b");
    write(&t.path("dst/a"), b"old");
    write(&t.path("dst/d/b"), b"b");
    write(&t.path("dst/c"), b"extra");
    write(&t.path("dst/extra/x/y"), b"extra");
    write(&t.path("dst/keep/k.log"), b"protected");
    write(&t.path("dst/keep/gone"), b"not protected");
    std::os::unix::fs::symlink("nowhere", t.path("dst/dangling")).unwrap();

    // Dry run: everything listed, nothing removed.
    let out = pcp(&[
        "-a",
        "-n",
        "-v",
        "--delete",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.status.success());
    let so = String::from_utf8_lossy(&out.stdout);
    for l in [
        "deleting c",
        "deleting extra/x/y",
        "deleting extra/x/",
        "deleting extra/",
        "deleting keep/gone",
        "deleting dangling",
    ] {
        assert!(so.contains(l), "missing {l:?} in {so}");
    }
    assert!(!so.contains("k.log"), "{so}");
    assert!(!so.lines().any(|l| l == "deleting keep/"), "{so}");
    assert!(so.contains("6 would be deleted"), "{so}");
    assert!(
        stderr_of(&out).contains("not deleting keep/"),
        "{}",
        stderr_of(&out)
    );
    assert!(t.path("dst/c").exists() && t.path("dst/extra/x/y").exists());

    let out = pcp(&[
        "-a",
        "-v",
        "--delete",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "d", "d/b", "keep", "keep/k.log"]
    );
    assert_eq!(read(&t.path("dst/a")), b"a");
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(so.contains("6 deleted"), "{so}");
    // keep/ stays because it holds a protected file: reported, not an error.
    let se = stderr_of(&out);
    assert!(se.contains("not deleting keep/"), "{se}");
}

#[test]
fn delete_cleans_stale_partials_but_keeps_resume_state_of_failed_files() {
    let t = Tmp::new();
    write(&t.path("src/ok"), b"ok");
    write(&t.path("src/bad"), b"unreadable");
    write(&t.path("dst/ok"), b"ok");
    set_mtime(&t.path("src/ok"), 1_600_000_000);
    set_mtime(&t.path("dst/ok"), 1_600_000_000);
    // Stale: target is up to date. Orphan: no such source. Failed: kept.
    write(&t.path("dst/.ok.pcp-partial"), b"stale");
    write(&t.path("dst/.orphan.pcp-partial"), b"orphan");
    write(&t.path("dst/.bad.pcp-partial"), b"resume-state");
    fs::set_permissions(t.path("src/bad"), fs::Permissions::from_mode(0o000)).unwrap();

    let out = pcp(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(!t.path("dst/.ok.pcp-partial").exists());
    assert!(!t.path("dst/.orphan.pcp-partial").exists());
    assert!(t.path("dst/.bad.pcp-partial").exists());
    assert!(t.path("dst/ok").is_file());
}

#[test]
fn delete_is_skipped_when_the_source_scan_has_errors() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/locked/inner"), b"x");
    write(&t.path("dst/extra"), b"extra");
    fs::set_permissions(t.path("src/locked"), fs::Permissions::from_mode(0o000)).unwrap();
    let out = pcp(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    assert!(t.path("dst/extra").exists(), "nothing may be deleted");
    assert!(
        stderr_of(&out).contains("skipping deletions"),
        "{}",
        stderr_of(&out)
    );
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
    assert!(so.contains("0 would be deleted"), "{so}");
    assert!(!t.path("nowhere").exists());
    // A single-file source deletes nothing.
    write(&t.path("dst2/junk"), b"j");
    run_ok(&["-a", "--delete", &t.s("s1/a"), &t.s("dst2/")]);
    assert!(t.path("dst2/junk").exists());
}

// --------------------------------------------- -u, --existing, --ignore-existing

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
fn ignore_existing_and_existing() {
    let t = Tmp::new();
    write(&t.path("src/have"), b"new content");
    write(&t.path("src/new"), b"n");
    write(&t.path("src/sub/deep"), b"d");
    write(&t.path("dst/have"), b"old content");
    set_mtime(&t.path("src/have"), 2000);
    set_mtime(&t.path("dst/have"), 1000);

    let so = run_ok(&["-a", "--ignore-existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 2);
    assert_eq!(read(&t.path("dst/have")), b"old content");
    assert!(t.path("dst/new").is_file() && t.path("dst/sub/deep").is_file());

    let t = Tmp::new();
    write(&t.path("src/have"), b"new content");
    write(&t.path("src/new"), b"n");
    write(&t.path("src/sub/deep"), b"d");
    write(&t.path("dst/have"), b"old content");
    set_mtime(&t.path("src/have"), 2000);
    set_mtime(&t.path("dst/have"), 1000);
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(read(&t.path("dst/have")), b"new content");
    assert_eq!(listing(&t.path("dst")), ["have"]);
    // --existing --delete still removes extras.
    write(&t.path("dst/extra"), b"e");
    run_ok(&["-a", "--existing", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["have"]);
}

// ------------------------------------------------------- --max-size / --min-size

#[test]
fn size_limits_filter_files_and_protect_them_from_delete() {
    let t = Tmp::new();
    write(&t.path("src/small"), &[0u8; 10]);
    write(&t.path("src/mid"), &[0u8; 2048]);
    write(&t.path("src/big"), &[0u8; 8192]);
    write(&t.path("dst/big"), b"stays");
    let so = run_ok(&[
        "-a",
        "--delete",
        "--max-size",
        "4K",
        "--min-size",
        "1K",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(listing(&t.path("dst")), ["big", "mid"]);
    assert_eq!(read(&t.path("dst/big")), b"stays");
}

// --------------------------------------------------------------- --files-from

#[test]
fn files_from_copies_listed_paths_with_their_parents() {
    let t = Tmp::new();
    for f in ["a/1", "a/2", "b/c/3", "b/c/4", "d/5", "top"] {
        write(&t.path("src").join(f), f.as_bytes());
    }
    write(&t.path("list"), b"a/1\n\n./b/c/3\n/top\nb/c/\nmissing/x\n");
    let out = pcp(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    // The missing entry is an error but the rest is copied.
    assert_eq!(out.status.code(), Some(23), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("missing/x"));
    // b/c is listed as a directory but -r wasn't given explicitly: no contents
    // beyond what the list names.
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "a/1", "b", "b/c", "b/c/3", "top"]
    );
    assert_eq!(read(&t.path("dst/b/c/3")), b"b/c/3");

    // Explicit -r walks listed directories; --from0 takes NUL separators.
    write(&t.path("list0"), b"b/c\0d\0");
    run_ok(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list0"),
        "--from0",
        &t.s("src/"),
        &t.s("dst2"),
    ]);
    assert_eq!(
        listing(&t.path("dst2")),
        ["b", "b/c", "b/c/3", "b/c/4", "d", "d/5"]
    );

    // Alternate spellings of one path are one path: no double scheduling.
    write(&t.path("list-dup"), b"a/1\na//1\n./a/./1/\n");
    let so = run_ok(&[
        "-a",
        "--files-from",
        &t.s("list-dup"),
        &t.s("src"),
        &t.s("dst4"),
    ]);
    assert_eq!(transferred(&so), 1);
    assert_eq!(listing(&t.path("dst4")), ["a", "a/1"]);

    // A `..` component is rejected before anything happens.
    write(&t.path("bad"), b"../etc\n");
    let out = pcp(&["-a", "--files-from", &t.s("bad"), &t.s("src"), &t.s("dst3")]);
    assert!(!out.status.success());
    assert!(!t.path("dst3").exists());
}

// ------------------------------------------------------------ review fixes

#[test]
fn delete_never_removes_paths_the_source_has_but_skips() {
    let t = Tmp::new();
    write(&t.path("src/plain"), b"p");
    write(&t.path("src/hard"), b"h");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::hard_link(t.path("src/hard"), t.path("dst/hard")).unwrap();
    std::os::unix::fs::symlink("plain", t.path("src/link")).unwrap();
    std::os::unix::fs::symlink("plain", t.path("dst/link")).unwrap();
    write(&t.path("dst/extra"), b"x");
    // No -l: the symlink is skipped, but it is the source's, so it stays.
    // The hardlinked file is "the same file" and skipped, and stays.
    let so = run_ok(&["-rt", "--delete", &t.s("src/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["hard", "link", "plain"]);
    // Skipped files are not reported as directories.
    assert!(so.contains(", 1 dirs"), "{so}");
    write(&t.path("src2/big"), b"bb");
    let so = run_ok(&["-a", "--max-size", "1", &t.s("src2/"), &t.s("dst2")]);
    assert!(
        so.contains("transferred 0 files") && so.contains(", 1 dirs"),
        "{so}"
    );
}

#[test]
fn files_from_rejects_symlinked_ancestors_and_recurses_only_listed_dirs() {
    let t = Tmp::new();
    write(&t.path("outside/secret"), b"secret");
    fs::create_dir_all(t.path("src/a")).unwrap();
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    write(&t.path("src/a/listed"), b"l");
    write(&t.path("src/a/unlisted"), b"u");
    write(&t.path("list"), b"link/secret\na/listed\n");
    let out = pcp(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    // `link` resolves to a directory, so the listed path is followed: the
    // implied parent becomes a real directory on the destination (never a
    // symlink a later write could go through). `a` was not recursed into
    // despite -r: only listed directories are walked.
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "a/listed", "link", "link/secret"]
    );
    assert!(t.path("dst/link").symlink_metadata().unwrap().is_dir());
    assert_eq!(read(&t.path("dst/link/secret")), b"secret");

    // An ancestor that resolves to a file, or dangles, is an error.
    std::os::unix::fs::symlink("a/listed", t.path("src/tofile")).unwrap();
    std::os::unix::fs::symlink("nowhere", t.path("src/dangling")).unwrap();
    write(&t.path("list2"), b"tofile/x\ndangling/y\n");
    let out = pcp(&[
        "-a",
        "--files-from",
        &t.s("list2"),
        &t.s("src"),
        &t.s("dst2"),
    ]);
    assert_eq!(out.status.code(), Some(23));
    let se = stderr_of(&out);
    assert!(
        se.contains("tofile is not a directory") && se.contains("dangling/y: no such file"),
        "{se}"
    );
    assert_eq!(listing(&t.path("dst2")), Vec::<String>::new());

    // Listing a symlink itself and a path through it conflicts; the path is
    // refused rather than written through the destination symlink.
    write(&t.path("list3"), b"link\nlink/secret\n");
    let out = pcp(&[
        "-a",
        "--files-from",
        &t.s("list3"),
        &t.s("src"),
        &t.s("dst3"),
    ]);
    assert_eq!(out.status.code(), Some(23));
    assert!(stderr_of(&out).contains("listed as a non-directory"));
    assert!(t.path("dst3/link").symlink_metadata().unwrap().is_symlink());
    assert!(!t.path("outside/secret2").exists());
}

#[test]
fn existing_never_creates_the_destination_root() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"f");
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst/")]);
    assert!(!t.path("dst").exists(), "{so}");
    write(&t.path("src2/g"), b"g");
    let so = run_ok(&["-a", "--existing", &t.s("src"), &t.s("src2"), &t.s("dst2")]);
    assert!(!t.path("dst2").exists(), "{so}");
}

#[test]
fn files_from_repeats_and_late_listed_dirs_across_chunks() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("src/d/sub/deep"), b"x");
    let mut list = String::from("d/inner\n");
    for i in 0..1200 {
        write(&t.path(&format!("src/many/f{i}")), b"f");
        list.push_str(&format!("many/f{i}\n"));
    }
    // After the 1000-entry boundary: repeat a path, and list `d` (so far only
    // an implied parent) explicitly so -r walks it.
    list.push_str("d/inner\nd\n");
    write(&t.path("list"), list.as_bytes());
    let so = run_ok(&[
        "-a",
        "-r",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    assert_eq!(transferred(&so), 1202);
    assert!(t.path("dst/d/sub/deep").is_file());
    assert!(t.path("dst/many/f1199").is_file());
}

#[test]
fn existing_dry_run_lists_no_missing_directories() {
    let t = Tmp::new();
    write(&t.path("src/there/f"), b"f");
    write(&t.path("src/missing/g"), b"g");
    fs::create_dir_all(t.path("dst/there")).unwrap();
    let so = run_ok(&["-a", "-n", "-v", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("dst/there/"), "{so}");
    assert!(!so.contains("missing"), "{so}");
    assert!(!so.contains("there/f"), "--existing creates no files: {so}");
}

// ------------------------------------------------------------ review round 3

#[test]
fn existing_leaves_a_file_where_a_source_directory_would_go() {
    let t = Tmp::new();
    write(&t.path("src/d/inner"), b"i");
    write(&t.path("dst/d"), b"a file, not a directory");
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/d")), b"a file, not a directory");
    assert_eq!(listing(&t.path("dst")), ["d"]);
    let so2 = run_ok(&["-a", "-n", "-v", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(!so2.contains("dst/d/"), "{so2}\n{so}");
}

#[test]
fn delete_keeps_user_files_named_like_partials_and_survives_bare_suffix() {
    let t = Tmp::new();
    write(&t.path("src/.notes.pcp-partial"), b"mine");
    write(&t.path("src/real"), b"r");
    write(&t.path("dst/.notes.pcp-partial"), b"mine");
    write(&t.path("dst/.pcp-partial"), b"odd name");
    write(&t.path("dst/.gone.pcp-partial"), b"leftover");
    let so = run_ok(&["-a", "--delete", &t.s("src/"), &t.s("dst")]);
    // The source's partial-looking file is never copied (pcp's own naming)
    // but it is the source's, so the destination copy stays. The bare suffix
    // is an ordinary extra, and the orphaned partial is garbage.
    assert_eq!(listing(&t.path("dst")), [".notes.pcp-partial", "real"]);
    assert!(so.contains("2 deleted"), "{so}");
}

#[test]
fn files_from_creates_listed_and_implied_dirs_without_r() {
    let t = Tmp::new();
    write(&t.path("src/a/1"), b"1");
    fs::create_dir_all(t.path("src/b/inner")).unwrap();
    fs::set_permissions(t.path("src/a"), fs::Permissions::from_mode(0o750)).unwrap();
    fs::set_permissions(t.path("src/b"), fs::Permissions::from_mode(0o710)).unwrap();
    write(&t.path("list"), b"a/1\nb\n");
    // -t only: no -r, no -a. Directories must still be created, with metadata.
    run_ok(&[
        "-pt",
        "--files-from",
        &t.s("list"),
        &t.s("src"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a", "a/1", "b"]);
    assert_eq!(fs::metadata(t.path("dst/a")).unwrap().mode() & 0o777, 0o750);
    assert_eq!(fs::metadata(t.path("dst/b")).unwrap().mode() & 0o777, 0o710);
}

#[test]
fn delete_with_nested_roots_deletes_once() {
    let t = Tmp::new();
    write(&t.path("a/x"), b"x");
    write(&t.path("b/y"), b"y");
    write(&t.path("dst/a/extra/deep"), b"e");
    write(&t.path("dst/stray"), b"s");
    let so = run_ok(&["-a", "-v", "--delete", &t.s("a"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(listing(&t.path("dst")), ["a", "a/x", "y"]);
    assert!(so.contains("3 deleted"), "{so}");
    assert!(!so.contains("errors"), "{so}");
}

#[test]
fn delete_with_inplace_replacing_many_symlinks() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("dst")).unwrap();
    for i in 0..3000 {
        write(&t.path(&format!("src/f{i}")), b"file now");
        std::os::unix::fs::symlink("nowhere", t.path(&format!("dst/f{i}"))).unwrap();
    }
    let so = run_ok(&[
        "-a",
        "--inplace",
        "--delete",
        "-j",
        "16",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(!so.contains("errors"), "{so}");
    assert_eq!(read(&t.path("dst/f2999")), b"file now");
}

// ------------------------------------------------------------ review round 5

#[test]
fn unreadable_source_root_disables_delete() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/precious"), b"p");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o000)).unwrap();
    // -rt rather than -a, so dst doesn't faithfully inherit the 000 mode.
    let out = pcp(&["-rt", "--delete", &t.s("src/"), &t.s("dst")]);
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(t.path("dst/precious").exists(), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("skipping deletions"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn delete_nested_roots_keep_their_own_anchored_ignores() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src2/foo/g"), b"g");
    write(&t.path("src2/b"), b"b");
    write(&t.path("dst/src2/foo/g"), b"g");
    write(&t.path("dst/src2/junk"), b"j");
    write(&t.path("dst/foo/h"), b"h");
    let so = run_ok(&[
        "-a",
        "-v",
        "--delete",
        "-i",
        "/foo",
        &t.s("src/"),
        &t.s("src2"),
        &t.s("dst"),
    ]);
    // /foo is anchored at each root: dst/src2/foo is protected (ignored on
    // both sides of the src2 mapping), dst/foo likewise for src/; junk goes.
    assert_eq!(
        listing(&t.path("dst")),
        [
            "a",
            "foo",
            "foo/h",
            "src2",
            "src2/b",
            "src2/foo",
            "src2/foo/g"
        ]
    );
    assert!(so.contains("1 deleted"), "{so}");
}

#[test]
fn delete_treats_partial_named_directory_as_ordinary_extra() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/.d.pcp-partial/x"), b"x");
    write(&t.path("dst/.d.pcp-partial/keep.log"), b"k");
    let so = run_ok(&[
        "-a",
        "-v",
        "--delete",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [".d.pcp-partial", ".d.pcp-partial/keep.log", "a"]
    );
    assert!(so.contains("1 deleted") && !so.contains("errors"), "{so}");
}

#[test]
fn untransferred_entries_yield_to_another_source() {
    let t = Tmp::new();
    std::os::unix::fs::symlink(
        "nowhere",
        t.path("a/x")
            .parent()
            .map(|p| {
                fs::create_dir_all(p).unwrap();
                t.path("a/x")
            })
            .unwrap(),
    )
    .unwrap();
    write(&t.path("b/x"), b"hi");
    // No -l: a/x is skipped and must not block b/x (either order).
    run_ok(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/x")), b"hi");
    run_ok(&["-r", &t.s("b/"), &t.s("a/"), &t.s("dst2")]);
    assert_eq!(read(&t.path("dst2/x")), b"hi");
    // But a real conflict is still one.
    write(&t.path("c/x"), b"other");
    let out = pcp(&["-r", &t.s("b/"), &t.s("c/"), &t.s("dst3")]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn delete_keeps_partials_of_filtered_files() {
    let t = Tmp::new();
    write(&t.path("src/big"), &[0u8; 100]);
    write(&t.path("src/newer-on-dst"), b"src");
    write(&t.path("dst/newer-on-dst"), b"dst");
    set_mtime(&t.path("src/newer-on-dst"), 1000);
    set_mtime(&t.path("dst/newer-on-dst"), 2000);
    write(&t.path("dst/.big.pcp-partial"), b"half");
    write(&t.path("dst/.newer-on-dst.pcp-partial"), b"half");
    write(&t.path("dst/.orphan.pcp-partial"), b"garbage");
    run_ok(&[
        "-a",
        "--delete",
        "-u",
        "--max-size",
        "10",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(t.path("dst/.big.pcp-partial").exists());
    assert!(t.path("dst/.newer-on-dst.pcp-partial").exists());
    assert!(!t.path("dst/.orphan.pcp-partial").exists());
}

#[test]
fn existing_does_not_write_through_a_destination_symlink_dir() {
    // An in-tree destination symlink is a payload conflict (replaced in a
    // normal run, never traversed); --existing replaces nothing, so it and
    // everything below it are left alone.
    let t = Tmp::new();
    write(&t.path("src/d/f"), b"new");
    write(&t.path("src/d/sub/g"), b"new");
    write(&t.path("elsewhere/f"), b"old");
    write(&t.path("elsewhere/sub/g"), b"old");
    fs::create_dir_all(t.path("dst")).unwrap();
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst/d")).unwrap();
    set_mtime(&t.path("src/d/f"), 2000);
    set_mtime(&t.path("elsewhere/f"), 1000);
    let so = run_ok(&["-a", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("elsewhere/f")), b"old", "{so}");
    assert_eq!(read(&t.path("elsewhere/sub/g")), b"old", "{so}");
    assert!(t.path("dst/d").symlink_metadata().unwrap().is_symlink());
    let so = run_ok(&["-a", "-n", "--existing", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("would transfer 0 files"), "{so}");
}

#[test]
fn no_recursive_skips_every_batch_of_a_directory_source() {
    let t = Tmp::new();
    for i in 0..1500 {
        write(&t.path(&format!("src/f{i}")), b"f");
    }
    let so = run_ok(&["-t", &t.s("src/"), &t.s("dst")]);
    assert_eq!(transferred(&so), 0);
    assert!(!t.path("dst/f1400").exists());
}

#[test]
fn files_from_root_may_be_a_symlink_and_root_lines_are_rejected() {
    let t = Tmp::new();
    write(&t.path("real/f"), b"f");
    std::os::unix::fs::symlink(t.path("real"), t.path("link")).unwrap();
    write(&t.path("list"), b"f\n");
    run_ok(&[
        "-a",
        "--files-from",
        &t.s("list"),
        &t.s("link"),
        &t.s("dst"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"f");
    write(&t.path("bad"), b"././//\n");
    let out = pcp(&[
        "-a",
        "--files-from",
        &t.s("bad"),
        &t.s("real"),
        &t.s("dst2"),
    ]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("names the source root"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn delete_leaves_directory_contents_under_a_skipped_source_path() {
    let t = Tmp::new();
    write(&t.path("src/big"), &[0u8; 100]);
    std::os::unix::fs::symlink("nowhere", t.path("src/lnk")).unwrap();
    write(&t.path("src/real"), b"r");
    write(&t.path("dst/big/inside"), b"i");
    write(&t.path("dst/lnk/deep/inside"), b"i");
    write(&t.path("dst/extra"), b"e");
    let so = run_ok(&[
        "-rt",
        "--delete",
        "--max-size",
        "10",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(
        listing(&t.path("dst")),
        [
            "big",
            "big/inside",
            "lnk",
            "lnk/deep",
            "lnk/deep/inside",
            "real"
        ]
    );
    assert!(so.contains("1 deleted"), "{so}");
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

// Resume: a successful transfer leaves no marker behind, and the retained
// journal is authoritative — a completed file is skipped on a plain rerun even
// if the destination was externally deleted, while -c bypasses the journal.
#[test]
fn checkpoint_conflicts_are_rejected() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    for conflicting in ["-c", "--verify-only"] {
        let out = pcp(&[
            "-a",
            conflicting,
            "--checkpoint",
            &t.s("state"),
            &t.s("src/"),
            &t.s("dst/"),
        ]);
        assert!(!out.status.success(), "{conflicting}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("cannot be used with"), "{conflicting}: {err}");
    }
    let out = pcp(&["--rm", "--checkpoint", &t.s("state"), &t.s("src")]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot be used with"), "{err}");
    assert!(t.path("src/f").is_file());
    assert!(!t.path("state").exists());
}

// Ordinary copies keep no historical completion state: the current destination
// determines what a later invocation repairs.
#[test]
fn ordinary_rerun_reconciles_destination() {
    let t = Tmp::new();
    write(&t.path("src/f.bin"), b"hello world");
    set_mtime(&t.path("src/f.bin"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    fs::remove_file(t.path("dst/f.bin")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f.bin")), b"hello world");
}

#[test]
fn ordinary_copy_needs_no_writable_history_directory() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    // A regular file cannot contain an application state directory. Ordinary
    // copies must ignore both locations because history is opt-in.
    write(&t.path("not-a-directory"), b"occupied");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst/")])
        .env("XDG_STATE_HOME", t.s("not-a-directory"))
        .env("HOME", t.s("not-a-directory"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// An explicitly requested checkpoint is retained after a copy error and is
// authoritative on retry. A source metadata change invalidates its record.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_is_explicit_retained_and_source_sensitive() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    write(&t.path("src/fail/other"), b"other");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dest/"),
        ])
        .env("PCP_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert!(t.path("copy.checkpoint").is_file());

    // Changing mode under -a makes the source fingerprint differ, so this file
    // is checked and restored rather than checkpoint-skipped.
    fs::set_permissions(t.path("src/f"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src/f"), 1_600_000_000);
    fs::remove_file(t.path("dest/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dest/"),
    ]);
    assert_eq!(read(&t.path("dest/f")), b"data");
    assert_eq!(
        fs::metadata(t.path("dest/f")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(
        t.path("copy.checkpoint").is_file(),
        "an explicit checkpoint persists after a clean retry"
    );
}

// A completed checkpoint deliberately trusts destination history, but an
// ordinary source fingerprint change invalidates the corresponding record.
#[test]
fn completed_checkpoint_trusts_destination_and_tracks_source() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"original");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let checkpoint = t.s("copy.checkpoint");
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(t.path("copy.checkpoint").is_file());

    write(&t.path("dst/f"), b"damaged independently");
    let stdout = run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(transferred(&stdout), 0);
    assert_eq!(
        read(&t.path("dst/f")),
        b"damaged independently",
        "a matching record intentionally bypasses destination inspection"
    );

    write(&t.path("src/f"), b"updated source");
    set_mtime(&t.path("src/f"), 1_600_000_001);
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"updated source");
    assert!(t.path("copy.checkpoint").is_file());
}

#[test]
fn checkpoint_inside_local_source_is_rejected() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let out = pcp(&[
        "-a",
        "--checkpoint",
        &t.s("src/state"),
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("must not be inside local source"), "{err}");
    assert!(!t.path("src/state").exists());
    assert!(!t.path("dst").exists());
}

#[test]
fn checkpoint_inside_local_destination_is_rejected() {
    let t = Tmp::new();
    write(&t.path("src/state"), b"payload");
    let out = pcp(&[
        "-a",
        "--checkpoint",
        &t.s("dst/state"),
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("must not be inside local destination"),
        "{err}"
    );
    assert!(!t.path("dst").exists());
}

// A checkpoint-complete file is still a claimed destination: a second source that
// later maps onto the same path is a collision, not a silent overwrite.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_skip_still_detects_collision() {
    let t = Tmp::new();
    write(&t.path("A/x"), b"from A");
    write(&t.path("A/fail/y"), b"failure trigger");
    fs::create_dir_all(t.path("B")).unwrap();
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("A/"),
            &t.s("B/"),
            &t.s("dest/"),
        ])
        .env("PCP_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(read(&t.path("dest/x")), b"from A");
    write(&t.path("B/x"), b"from B");
    let out = pcp(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("A/"),
        &t.s("B/"),
        &t.s("dest/"),
    ]);
    assert!(!out.status.success(), "ambiguous mapping must be reported");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("same destination"), "stderr: {err}");
    assert_eq!(read(&t.path("dest/x")), b"from A", "must not be clobbered");
}

// A read-only source root: the copy succeeds, the root ends up 0555, and a
// rerun into the now read-only destination works too.
#[test]
fn readonly_root_copies_and_reruns() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    // No implicit history: deleting a destination file makes the next run
    // restore it from the read-only source.
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_file(t.path("dst/f")).unwrap();
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// Several content sources map onto the destination root; the last one's
// metadata wins, as for any other directory.
#[test]
fn multiple_content_sources_root_meta() {
    let t = Tmp::new();
    write(&t.path("A/a"), b"a");
    write(&t.path("B/b"), b"b");
    fs::set_permissions(t.path("A"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(t.path("B"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-a", &t.s("A/"), &t.s("B/"), &t.s("dest/")]);
    assert_eq!(fs::metadata(t.path("dest")).unwrap().mode() & 0o777, 0o555);
    assert_eq!(read(&t.path("dest/a")), b"a");
    assert_eq!(read(&t.path("dest/b")), b"b");
}

// Directories pcp had to open up (no owner write bit) get their own mode back
// at the end when nothing else sets it (no -p); with -p the source mode wins.
#[test]
fn opened_up_directories_get_their_mode_back() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"data");
    fs::set_permissions(t.path("src/sub"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(t.path("dst/sub")).unwrap();
    fs::set_permissions(t.path("dst/sub"), fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(t.path("dst"), fs::Permissions::from_mode(0o555)).unwrap();
    run_ok(&["-r", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/sub/f")), b"data");
    assert_eq!(
        fs::metadata(t.path("dst/sub")).unwrap().mode() & 0o777,
        0o555
    );
    assert_eq!(fs::metadata(t.path("dst")).unwrap().mode() & 0o777, 0o555);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(
        fs::metadata(t.path("dst/sub")).unwrap().mode() & 0o777,
        0o755
    );
}

// A directory metadata failure is a copy error (exit 23), not a footnote.
#[cfg(debug_assertions)]
#[test]
fn root_meta_failure_is_visible() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args(["-a", "--no-progress", &t.s("src/"), &t.s("dst")])
        .env("PCP_TEST_FAIL_SETMETA", "dst")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(23), "stderr: {err}");
    assert!(err.contains("injected"), "stderr: {err}");
    assert_eq!(read(&t.path("dst/f")), b"data");
}

// A quick-check-identical file whose metadata repair fails is not checkpointed
// as complete, so the next run repairs it instead of skipping it.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_records_quick_check_only_after_meta_repair() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    let before = fs::metadata(t.path("dst/f")).unwrap().mode() & 0o777;
    assert_ne!(before, 0o600);
    fs::set_permissions(t.path("src/f"), fs::Permissions::from_mode(0o600)).unwrap();
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("PCP_TEST_FAIL_SETMETA", "f")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(
        fs::metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        before
    );
    assert!(t.path("copy.checkpoint").is_file());
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(
        fs::metadata(t.path("dst/f")).unwrap().mode() & 0o777,
        0o600,
        "the failed repair must not have been checkpointed as complete"
    );
    assert!(t.path("copy.checkpoint").is_file());
}

// The read-only modes create nothing, not even the destination directory.
#[test]
fn readonly_modes_create_nothing() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    let checkpoint = t.s("dry-run.checkpoint");
    let out = pcp(&["-a", "--verify-only", &t.s("src/"), &t.s("dst/")]);
    assert!(
        !t.path("dst").exists(),
        "--verify-only must not create the destination"
    );
    assert!(!out.status.success(), "everything is missing");
    let out = pcp(&[
        "-a",
        "-n",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(out.status.success());
    assert!(
        !t.path("dst").exists(),
        "--dry-run must not create the destination"
    );
    assert!(
        !t.path("dry-run.checkpoint").exists(),
        "--dry-run must not create a checkpoint"
    );
}

#[test]
fn dry_run_validates_checkpoint_identity_with_missing_destination() {
    let t = Tmp::new();
    write(&t.path("first/f"), b"first");
    write(&t.path("second/f"), b"second");
    let checkpoint = t.s("copy.checkpoint");
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("first/"),
        &t.s("first-dst/"),
    ]);
    let out = pcp(&[
        "-an",
        "--checkpoint",
        &checkpoint,
        &t.s("second/"),
        &t.s("missing/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("describes a different copy"), "{err}");
    assert!(!t.path("missing").exists());
}

// Different spellings of the same local path are one job.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_identity_is_spelling_independent() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"data");
    write(&t.path("src/fail/y"), b"trigger");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    let dotted = format!("{}/./src/", t.s(""));
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &dotted,
            &t.s("dst/"),
        ])
        .env("PCP_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    fs::remove_file(t.path("dst/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(
        !t.path("dst/f").exists(),
        "same checkpoint identity, so the explicitly trusted file is skipped"
    );
}

// Existing completion records are never reset automatically. A missing
// destination is suspicious and requires the user to remove the checkpoint.
#[cfg(debug_assertions)]
#[test]
fn existing_checkpoint_with_missing_destination_fails() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"aaaa");
    write(&t.path("src/fail/secret"), b"secret");
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dest/"),
        ])
        .env("PCP_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert!(t.path("copy.checkpoint").is_file());
    fs::remove_dir_all(t.path("dest")).unwrap();
    assert!(!t.path("dest").exists());
    let out = pcp(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dest/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("destination") && err.contains("missing"),
        "{err}"
    );
    assert!(!t.path("dest").exists());
    assert!(t.path("copy.checkpoint").is_file());
}

#[test]
fn existing_checkpoint_with_missing_mapped_source_target_fails() {
    let t = Tmp::new();
    write(&t.path("bigdir/f"), b"data");
    let checkpoint = t.s("copy.checkpoint");
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("bigdir"),
        &t.s("backups"),
    ]);
    fs::remove_dir_all(t.path("backups/bigdir")).unwrap();
    let out = pcp(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("bigdir"),
        &t.s("backups"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("destination target") && err.contains("missing"),
        "{err}"
    );
    assert!(!t.path("backups/bigdir").exists());
}

#[test]
fn missing_destination_does_not_replace_an_unrelated_checkpoint_path() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"data");
    write(&t.path("important"), b"not a checkpoint");
    let out = pcp(&[
        "-a",
        "--checkpoint",
        &t.s("important"),
        &t.s("src/"),
        &t.s("dest/"),
    ]);
    assert!(!out.status.success());
    assert_eq!(read(&t.path("important")), b"not a checkpoint");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not a PCP checkpoint"), "stderr: {err}");
}

// Two ordinary copies into one tree behave like rsync: the union lands, and a
// later invocation checks current destination state rather than hidden history.
#[test]
fn concurrent_copies_union() {
    let t = Tmp::new();
    for i in 0..200 {
        write(&t.path(&format!("A/a{i}")), b"a");
        write(&t.path(&format!("B/b{i}")), b"b");
    }
    let spawn = |src: &str| {
        Command::new(env!("CARGO_BIN_EXE_pcp"))
            .args(["-a", "--no-progress", &t.s(src), &t.s("dest/")])
            .spawn()
            .unwrap()
    };
    let (mut a, mut b) = (spawn("A/"), spawn("B/"));
    assert!(a.wait().unwrap().success());
    assert!(b.wait().unwrap().success());
    for i in 0..200 {
        assert_eq!(read(&t.path(&format!("dest/a{i}"))), b"a");
        assert_eq!(read(&t.path(&format!("dest/b{i}"))), b"b");
    }
    fs::remove_file(t.path("dest/a7")).unwrap();
    run_ok(&["-a", &t.s("A/"), &t.s("dest/")]);
    assert_eq!(read(&t.path("dest/a7")), b"a");
}

#[cfg(debug_assertions)]
#[test]
fn concurrent_writers_never_share_a_partial_inode() {
    let t = Tmp::new();
    let first_contents = vec![b'a'; 8 * 1024 * 1024];
    let second_contents = vec![b'b'; 8 * 1024 * 1024];
    write(&t.path("first"), &first_contents);
    write(&t.path("second"), &second_contents);

    let mut first = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args(["-a", "--no-progress", &t.s("first"), &t.s("out")])
        .env("PCP_TEST_HOLD_PARTIAL_MS", "1000")
        .spawn()
        .unwrap();
    let partial = t.path(".out.pcp-partial");
    for _ in 0..200 {
        if partial.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(partial.exists(), "first copy never created its sidecar");

    let second = pcp(&["-a", &t.s("second"), &t.s("out")]);
    assert_eq!(second.status.code(), Some(23));
    let err = String::from_utf8_lossy(&second.stderr);
    assert!(err.contains("in use by another pcp process"), "{err}");
    assert!(first.wait().unwrap().success());
    assert_eq!(read(&t.path("out")), first_contents);
    assert!(!partial.exists());
}

#[cfg(debug_assertions)]
#[test]
fn changed_source_retry_uses_published_file_as_block_basis() {
    let t = Tmp::new();
    let original = vec![b'a'; 8 * 1024 * 1024];
    let mut changed = original.clone();
    changed[0] = b'b';
    write(&t.path("src"), &original);
    set_mtime(&t.path("src"), 1_600_000_000);

    let child = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args(["-a", "--stats", "--no-progress", &t.s("src"), &t.s("dst")])
        .env("PCP_TEST_HOLD_AFTER_FINALIZE_MS", "1000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if t.path("dst").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(t.path("dst").exists(), "first attempt never finalized");
    write(&t.path("src"), &changed);
    set_mtime(&t.path("src"), 1_600_000_001);

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read(&t.path("dst")), changed);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bytes transferred: 12,582,912"),
        "retry should send one changed 4 MiB block, not the full file: {stdout}"
    );
}

// A destination given as a symlink to a directory is that directory, whether
// or not it's spelled with a trailing slash: the link survives, the payload
// lands in its target.
#[test]
fn symlink_destination_is_followed() {
    for spelling in ["link", "link/"] {
        let t = Tmp::new();
        write(&t.path("src/f"), b"hi");
        fs::create_dir_all(t.path("real")).unwrap();
        std::os::unix::fs::symlink("real", t.path("link")).unwrap();
        run_ok(&["-a", &t.s("src/"), &t.s(spelling)]);
        assert!(
            fs::symlink_metadata(t.path("link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "{spelling}: the symlink must survive"
        );
        assert_eq!(read(&t.path("real/f")), b"hi", "{spelling}");
    }
    let t = Tmp::new();
    write(&t.path("src/f"), b"hi");
    fs::create_dir_all(t.path("real")).unwrap();
    std::os::unix::fs::symlink("real", t.path("link")).unwrap();
    run_ok(&["-a", &t.s("src"), &t.s("link")]);
    assert!(fs::symlink_metadata(t.path("link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(read(&t.path("real/src/f")), b"hi");
}

#[test]
fn in_tree_destination_symlink_is_replaced_not_followed() {
    let t = Tmp::new();
    write(&t.path("src/sub/f"), b"payload");
    fs::create_dir_all(t.path("dst")).unwrap();
    fs::create_dir_all(t.path("elsewhere")).unwrap();
    std::os::unix::fs::symlink("../elsewhere", t.path("dst/sub")).unwrap();

    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);

    assert!(fs::symlink_metadata(t.path("dst/sub")).unwrap().is_dir());
    assert_eq!(read(&t.path("dst/sub/f")), b"payload");
    assert!(!t.path("elsewhere/f").exists());
}

#[test]
fn destination_root_symlink_preserves_target_metadata_for_both_spellings() {
    for spelling in ["link", "link/"] {
        let t = Tmp::new();
        write(&t.path("src/f"), b"payload");
        fs::set_permissions(t.path("src"), fs::Permissions::from_mode(0o555)).unwrap();
        set_mtime(&t.path("src"), 1_600_000_000);
        fs::create_dir_all(t.path("real")).unwrap();
        std::os::unix::fs::symlink("real", t.path("link")).unwrap();

        run_ok(&["-a", &t.s("src/"), &t.s(spelling)]);

        let metadata = fs::metadata(t.path("real")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o555, "{spelling}");
        assert_eq!(metadata.mtime(), 1_600_000_000, "{spelling}");
        assert_eq!(read(&t.path("real/f")), b"payload", "{spelling}");
        assert!(fs::symlink_metadata(t.path("link"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

// The copy-into-itself guard resolves paths the way the kernel does: `..`
// after a symlink pops the link's target, so a destination that physically
// lands inside the source is refused even when it lexically looks elsewhere.
#[test]
fn self_copy_guard_sees_through_symlinks() {
    let t = Tmp::new();
    write(&t.path("src/inner/f"), b"x");
    std::os::unix::fs::symlink(t.path("src/inner"), t.path("link")).unwrap();
    // link/../out == src/out: inside the source.
    let out = pcp(&["-a", &t.s("src/"), &t.s("link/../out/")]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("into itself"), "stderr: {err}");
    assert!(!t.path("src/out").exists());
}

// Metadata-only reconciliation is a valid checkpoint completion. The explicit
// checkpoint then trusts it on retry, just like a transferred completion.
#[cfg(debug_assertions)]
#[test]
fn checkpoint_records_metadata_only_reconcile() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"");
    write(&t.path("src/fail/y"), b"trigger");
    set_mtime(&t.path("src/f"), 1_600_000_000);
    run_ok(&["-a", &t.s("src/"), &t.s("dst/")]);
    set_mtime(&t.path("src/f"), 1_600_000_001);
    let checkpoint = t.s("copy.checkpoint");
    let out = Command::new(env!("CARGO_BIN_EXE_pcp"))
        .args([
            "-a",
            "--no-progress",
            "--checkpoint",
            &checkpoint,
            &t.s("src/"),
            &t.s("dst/"),
        ])
        .env("PCP_TEST_FAIL_SETMETA", "fail")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(
        fs::metadata(t.path("dst/f")).unwrap().mtime(),
        1_600_000_001
    );
    fs::remove_file(t.path("dst/f")).unwrap();
    run_ok(&[
        "-a",
        "--checkpoint",
        &checkpoint,
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(
        !t.path("dst/f").exists(),
        "the metadata-only reconcile must have been checkpointed"
    );
}

// Unsupported rsync flags get a helpful, specific error (not clap's generic
// "unexpected argument"), and the filter family points at -i.
#[test]
fn unsupported_rsync_flags_explain_themselves() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"x");

    let out = pcp(&[
        "-a",
        "--exclude",
        "node_modules",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("-i/--ignore"), "should point to -i: {err}");
    assert!(err.contains("gitignore"), "should mention gitignore: {err}");

    let out = pcp(&["-a", "--delete-during", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("after the transfer"));

    // Bundled short flags from a pasted `rsync -aHz` are caught too (the
    // unsupported letter is found inside the cluster).
    let out = pcp(&["-aHz", &t.s("src/"), &t.s("dst/")]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("hard links"),
        "bundled -H should be explained: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Compatibility no-ops are accepted and change nothing.
#[test]
fn rsync_compat_noops_are_accepted() {
    let t = Tmp::new();
    write(&t.path("src/f"), b"hello");
    // --numeric-ids, --partial, -P, -h are all no-ops here.
    run_ok(&[
        "-a",
        "--numeric-ids",
        "--partial",
        "-P",
        "-h",
        &t.s("src/"),
        &t.s("dst/"),
    ]);
    assert_eq!(read(&t.path("dst/f")), b"hello");
}

// A value that happens to look like an unsupported flag is not misread.
#[test]
fn flag_like_ignore_pattern_is_not_rejected() {
    let t = Tmp::new();
    write(&t.path("src/keep"), b"k");
    // `-i --exclude` means "ignore a pattern literally named --exclude"; it must
    // not trip the --exclude rejection.
    run_ok(&["-a", "-i", "--exclude", &t.s("src/"), &t.s("dst/")]);
    assert_eq!(read(&t.path("dst/keep")), b"k");
}

// ------------------------------------------------------------ review round 6

#[test]
fn existing_opens_up_readonly_dirs_even_after_a_symlinked_dir() {
    let t = Tmp::new();
    write(&t.path("src/s/x"), b"x");
    write(&t.path("src/r/y"), b"new");
    write(&t.path("elsewhere/x"), b"x");
    write(&t.path("dst/r/y"), b"old");
    set_mtime(&t.path("src/r/y"), 2000);
    set_mtime(&t.path("dst/r/y"), 1000);
    // `s` sorts before `r`? No — make the symlinked dir sort first explicitly.
    fs::rename(t.path("src/s"), t.path("src/a")).unwrap();
    std::os::unix::fs::symlink(t.path("elsewhere"), t.path("dst/a")).unwrap();
    fs::set_permissions(t.path("dst/r"), fs::Permissions::from_mode(0o500)).unwrap();
    let so = run_ok(&["-rt", "--existing", &t.s("src/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/r/y")), b"new", "{so}");
    assert_eq!(read(&t.path("elsewhere/x")), b"x");
}

#[test]
fn partial_named_symlink_is_a_symlink_not_a_leftover() {
    let t = Tmp::new();
    write(&t.path("a/target"), b"t");
    std::os::unix::fs::symlink("target", t.path("a/.x.pcp-partial")).unwrap();
    write(&t.path("b/other"), b"o");
    std::os::unix::fs::symlink("target", t.path("b/.x.pcp-partial")).unwrap();
    run_ok(&["-a", &t.s("a/"), &t.s("dst")]);
    assert!(t
        .path("dst/.x.pcp-partial")
        .symlink_metadata()
        .unwrap()
        .is_symlink());
    // Without -l the symlinks are skipped, and two sources skipping the same
    // path is not a collision.
    run_ok(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst2")]);
    assert!(!t.path("dst2/.x.pcp-partial").exists());
    assert!(t.path("dst2/target").is_file() && t.path("dst2/other").is_file());
}

#[test]
fn copy_onto_itself_among_sources_is_order_independent() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("dst/a"), b"a");
    let so = run_ok(&["-r", &t.s("src/"), &t.s("dst/a"), &t.s("dst/")]);
    assert!(!so.contains("errors"), "{so}");
    let so = run_ok(&["-r", &t.s("dst/a"), &t.s("src/"), &t.s("dst/")]);
    assert!(!so.contains("errors"), "{so}");
    assert_eq!(read(&t.path("dst/a")), b"a");
    // Two different files onto one destination is still a collision.
    write(&t.path("src2/a"), b"different");
    let out = pcp(&["-r", &t.s("src/"), &t.s("src2/"), &t.s("dst3/")]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn bad_size_limits_fail_before_anything_connects() {
    let t0 = std::time::Instant::now();
    let out = pcp(&[
        "-a",
        "--max-size",
        "12Q",
        "nohost-a.invalid:x",
        "nohost-b.invalid:y",
    ]);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("bad size"), "{}", stderr_of(&out));
    assert!(t0.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn verify_only_checks_the_filtered_scope() {
    let t = Tmp::new();
    write(&t.path("src/big"), b"abc");
    write(&t.path("dst/big"), b"xyz");
    let out = pcp(&["-a", "--verify-only", &t.s("src/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    let so = run_ok(&[
        "-a",
        "--verify-only",
        "--max-size",
        "1",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert!(so.contains("verified 0 files"), "{so}");
    set_mtime(&t.path("src/big"), 1000);
    set_mtime(&t.path("dst/big"), 2000);
    let so = run_ok(&["-a", "--verify-only", "-u", &t.s("src/"), &t.s("dst")]);
    assert!(so.contains("verified 0 files"), "{so}");
}

#[test]
fn files_from_leaves_no_ancestors_behind_on_a_bad_chain() {
    let t = Tmp::new();
    write(&t.path("src/a/b"), b"b is a file");
    write(&t.path("list"), b"a/b/c\n");
    let out = pcp(&["-a", "--files-from", &t.s("list"), &t.s("src"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(listing(&t.path("dst")), Vec::<String>::new());
}

#[test]
fn stats_report_connection_tuning_mode() {
    let t = Tmp::new();
    std::fs::create_dir_all(t.path("src")).unwrap();
    for i in 0..20 {
        std::fs::write(t.path(&format!("src/f{i}")), vec![b'x'; 1000]).unwrap();
    }
    // Without -j the count is auto-tuned; a short local copy never leaves the
    // local starting count of 32.
    let out = run_ok(&["-a", "--stats", &t.s("src/"), &t.s("auto/")]);
    assert!(
        out.contains("connections: auto: settled at 32 (path 32, peak 32)"),
        "{out}"
    );
    // An explicit -j is used as given, with no tuning.
    let out = run_ok(&["-a", "--stats", "-j", "3", &t.s("src/"), &t.s("fixed/")]);
    assert!(out.contains("connections: 3\n"), "{out}");
}

// --------------------------------------- --delete-after/-delay, --delete-excluded, --max-delete

#[test]
fn delete_after_and_delay_are_synonyms() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    for flag in ["--delete-after", "--delete-delay"] {
        write(&t.path("dst/extra"), b"x");
        run_ok(&["-a", flag, &t.s("src/"), &t.s("dst")]);
        assert!(!t.path("dst/extra").exists(), "{flag}");
    }
    let out = pcp(&["-a", "--delete-before", &t.s("src/"), &t.s("dst")]);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("after the transfer"));
}

#[test]
fn delete_excluded_removes_ignored_destination_paths() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    write(&t.path("src/junk.log"), b"src log, never copied");
    write(&t.path("dst/keep/k.log"), b"k");
    write(&t.path("dst/junk.log"), b"old");
    // Protected without the flag...
    run_ok(&["-a", "--delete", "-i", "*.log", &t.s("src/"), &t.s("dst")]);
    assert_eq!(
        listing(&t.path("dst")),
        ["a", "junk.log", "keep", "keep/k.log"]
    );
    // ...extras with it, including the directory that only held them.
    let so = run_ok(&[
        "-a",
        "--delete",
        "--delete-excluded",
        "-i",
        "*.log",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a"]);
    assert!(so.contains("3 deleted"), "{so}");
    assert!(
        !t.path("dst/junk.log").exists(),
        "source's ignored file is not copied either"
    );
}

#[test]
fn max_delete_refuses_everything_past_the_limit() {
    let t = Tmp::new();
    write(&t.path("src/a"), b"a");
    for i in 0..5 {
        write(&t.path(&format!("dst/extra{i}")), b"x");
    }
    let out = pcp(&[
        "-a",
        "--delete",
        "--max-delete",
        "3",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(out.status.code(), Some(25), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("5 deletions planned"),
        "{}",
        stderr_of(&out)
    );
    assert_eq!(listing(&t.path("dst")).len(), 6, "nothing deleted");
    assert_eq!(
        read(&t.path("dst/a")),
        b"a",
        "the copy itself still happened"
    );
    run_ok(&[
        "-a",
        "--delete",
        "--max-delete",
        "5",
        &t.s("src/"),
        &t.s("dst"),
    ]);
    assert_eq!(listing(&t.path("dst")), ["a"]);
    // --max-delete without --delete is a usage error.
    let out = pcp(&["-a", "--max-delete", "5", &t.s("src/"), &t.s("dst")]);
    assert!(!out.status.success());
}

// ------------------------------------------------------------ review round 7

#[test]
fn cross_source_collision_is_detected_before_any_change() {
    let t = Tmp::new();
    fs::create_dir_all(t.path("a")).unwrap();
    std::os::unix::fs::symlink("nowhere", t.path("a/x")).unwrap();
    write(&t.path("a/other"), b"o");
    write(&t.path("b/x/inside"), b"i");
    write(&t.path("dst/x"), b"precious file");
    let out = pcp(&["-a", &t.s("a/"), &t.s("b/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("refusing to clobber"));
    assert_eq!(
        read(&t.path("dst/x")),
        b"precious file",
        "nothing was written"
    );
    assert!(
        !t.path("dst/other").exists(),
        "nothing from either source was applied"
    );
}

#[test]
fn files_from_symlink_conflict_is_order_independent() {
    let t = Tmp::new();
    write(&t.path("outside/secret"), b"s");
    fs::create_dir_all(t.path("src")).unwrap();
    std::os::unix::fs::symlink("../outside", t.path("src/link")).unwrap();
    for (n, list) in [("1", "link\nlink/secret\n"), ("2", "link/secret\nlink\n")] {
        write(&t.path(&format!("list{n}")), list.as_bytes());
        let out = pcp(&[
            "-a",
            "--files-from",
            &t.s(&format!("list{n}")),
            &t.s("src"),
            &t.s(&format!("dst{n}")),
        ]);
        assert_eq!(
            out.status.code(),
            Some(23),
            "order {n}: {}",
            stderr_of(&out)
        );
        let md = t.path(&format!("dst{n}/link")).symlink_metadata().unwrap();
        // Either the symlink alone (order 1) or a real directory (order 2) —
        // never a write through a destination symlink.
        assert!(md.is_symlink() || md.is_dir());
        assert!(!t.path("outside/secret2").exists());
    }
    assert_eq!(read(&t.path("dst2/link/secret")), b"s");
    assert!(t.path("dst2/link").symlink_metadata().unwrap().is_dir());
}

#[test]
fn three_claimants_are_validated_as_a_group() {
    let t = Tmp::new();
    write(&t.path("dst/x"), b"dest content");
    fs::create_dir_all(t.path("a")).unwrap();
    fs::hard_link(t.path("dst/x"), t.path("a/x")).unwrap();
    write(&t.path("b/x"), b"from b");
    write(&t.path("c/x"), b"from c");
    // a/x is the destination file; b/x and c/x are two different contents.
    let out = pcp(&["-r", &t.s("a/"), &t.s("b/"), &t.s("c/"), &t.s("dst")]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("2 sources map to the same destination"));
    assert_eq!(read(&t.path("dst/x")), b"dest content");
    // With only one other content it is fine, in any position.
    run_ok(&["-r", &t.s("b/"), &t.s("a/"), &t.s("dst")]);
    assert_eq!(read(&t.path("dst/x")), b"from b");
}

#[test]
fn conflicting_sources_leave_no_destination_behind() {
    let t = Tmp::new();
    write(&t.path("a/x"), b"1");
    write(&t.path("b/x"), b"2");
    let out = pcp(&["-r", &t.s("a/"), &t.s("b/"), &t.s("dst/")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!t.path("dst").exists(), "destination must not be created");
    // And a clean multi-source copy into a missing destination still works.
    write(&t.path("c/y"), b"3");
    run_ok(&["-r", &t.s("a/"), &t.s("c/"), &t.s("dst2/")]);
    assert_eq!(listing(&t.path("dst2")), ["x", "y"]);
}
