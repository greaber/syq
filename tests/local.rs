//! Integration tests: local -> local copies through the built binary.

#[allow(dead_code)]
#[path = "../src/process.rs"]
mod process;
use crate::process::CommandExt as _;
#[path = "support/temp.rs"]
mod test_support;

use base64::Engine as _;

use ed25519_dalek::{Signer, SigningKey};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};

use sha2::{Digest, Sha256};

use std::fs::{self, File, OpenOptions};

use std::io::{Read, Write};

use std::os::unix::ffi::OsStringExt;

use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use std::os::unix::process::CommandExt;

use std::path::{Path, PathBuf};

use std::process::{Command, Output, Stdio};

use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::OnceLock;

use std::sync::RwLock;

#[cfg(all(debug_assertions, target_os = "macos"))]
#[path = "support/macos_clone.rs"]
mod macos_clone_support;

#[path = "support/nofile.rs"]
mod nofile;

use nofile::set_child_nofile_limit;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

// Successful host-native TCP tests must not share the product's fixed default
// range across concurrent test binaries or repository worktrees. Port zero
// asks the kernel to choose and reserve an available ephemeral port atomically.
// The isolated real-SSH Compose suite still exercises the production default.
const EPHEMERAL_TCP_PORTS: &str = "0-0";

use test_support::temp_dir;

/// Whether the temporary filesystem accepts file names that are not valid
/// UTF-8. APFS on macOS rejects them with `EILSEQ`, so tests about raw byte
/// names have nothing to exercise there and report that they were skipped.
fn filesystem_accepts_non_utf8_names() -> bool {
    let mut name = std::ffi::OsString::from(format!("syq-probe-{}-", std::process::id()));
    name.push(std::ffi::OsString::from_vec(vec![0xff]));
    let path = temp_dir().join(name);
    match File::create(&path) {
        Ok(_) => {
            let _ = fs::remove_file(&path);
            true
        }
        Err(_) => false,
    }
}

struct Tmp(PathBuf);

impl Tmp {
    fn expose_remote_syq(&self) {
        fs::create_dir_all(self.path("remote-bin")).unwrap();
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_syq"), self.path("remote-bin/syq")).unwrap();
    }

    fn new() -> Tmp {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = temp_dir().join(format!("syq-test-{}-{}", std::process::id(), n));
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
    /// A runtime directory for `XDG_RUNTIME_DIR`. Unix socket paths beneath
    /// it must fit `sun_path` (104 bytes on macOS), so when the test
    /// directory itself is long, as under macOS's `TMPDIR`, the runtime
    /// directory lives directly under `/tmp` instead. Reserve space for
    /// OpenSSH's 17-byte temporary suffix as well as the final socket name.
    fn runtime(&self) -> PathBuf {
        let inside = self.path("runtime");
        if inside.as_os_str().len() <= 32 {
            return inside;
        }
        let tmp = PathBuf::from("/tmp");
        let name = self.0.file_name().unwrap().to_string_lossy();
        tmp.join(format!("{name}-rt"))
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let runtime = self.runtime();
        if runtime != self.path("runtime") {
            let _ = fs::remove_dir_all(runtime);
        }
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

fn syq(args: &[&str]) -> Output {
    compat_command()
        .args(args)
        .arg("--no-progress")
        .run()
        .expect("run syq")
}

fn compat_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command.arg("rsync");
    command
}

fn native_syq(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_syq"))
        .args(args)
        .arg("-q")
        .run()
        .expect("run native syq command")
}

fn wait_for_confinement_marker(child: &mut std::process::Child, marker: &Path, stage: &str) {
    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(5);
    let mut next_progress = started + std::time::Duration::from_secs(1);
    loop {
        let status = child.try_wait().unwrap();
        assert!(status.is_none(), "syq exited before {stage}: {status:?}");
        if marker.exists() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {stage}: marker {} absent, syq still running",
            marker.display()
        );
        if std::time::Instant::now() >= next_progress {
            eprintln!("waiting for {stage}: {}", marker.display());
            next_progress += std::time::Duration::from_secs(1);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(debug_assertions)]
fn release_confinement_barrier(continuation: &Path) {
    fs::write(continuation, b"continue").unwrap();
}

fn run_native_ok(args: &[&str]) -> String {
    let out = native_syq(args);
    assert!(
        out.status.success(),
        "native syq {:?} failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run_ok(args: &[&str]) -> String {
    let out = syq(args);
    assert!(
        out.status.success(),
        "syq {:?} failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn expected_local_start() -> usize {
    if std::thread::available_parallelism().is_ok_and(|parallelism| parallelism.get() <= 2) {
        16
    } else {
        32
    }
}

/// Parse "syq: transferred N files" from the summary line.
fn transferred(stdout: &str) -> u64 {
    let line = stdout
        .lines()
        .find(|l| l.starts_with("syq: transferred") || l.starts_with("syq: would transfer"))
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

#[cfg(debug_assertions)]
fn start_held_control_path(
    command: &mut Command,
    selected: &Path,
    ready: &Path,
    continuation: &Path,
) -> std::process::Child {
    command
        .env("SYQ_TEST_CONTROL_PATH", selected)
        .env("SYQ_TEST_CONTROL_PATH_READY_FILE", ready)
        .env("SYQ_TEST_CONTROL_PATH_CONTINUE_FILE", continuation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .start()
        .unwrap()
}

#[cfg(debug_assertions)]
fn wait_for_control_path_selection(child: &mut std::process::Child, ready: &Path) {
    wait_for_confinement_marker(child, ready, "control-path selection");
}

#[cfg(debug_assertions)]
fn wait_for_control_path_output(child: std::process::Child) -> Output {
    wait_for_child_output(child, std::time::Duration::from_secs(5))
}

#[cfg(debug_assertions)]
fn wait_for_child_output(mut child: std::process::Child, timeout: std::time::Duration) -> Output {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "syq did not finish before the test deadline\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn partial_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().contains(".syq-tmp."))
        })
        .collect()
}

#[cfg(debug_assertions)]
fn interrupted_partial(args: &[&str], dir: &Path) -> PathBuf {
    interrupted_partial_from(args, dir, None)
}

#[cfg(debug_assertions)]
fn interrupted_partial_from(args: &[&str], dir: &Path, cwd: Option<&Path>) -> PathBuf {
    let barrier = crate::test_support::tempdir().unwrap();
    let ready = barrier.path().join("ready");
    let continuation = barrier.path().join("continue");
    let mut command = compat_command();
    command
        .args(args)
        .arg("--no-progress")
        .env("SYQ_TEST_PARTIAL_READY_FILE", &ready)
        .env("SYQ_TEST_PARTIAL_CONTINUE_FILE", &continuation)
        .process_group(0);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.start().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut next_progress = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while !ready.exists() && std::time::Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= next_progress {
            eprintln!("waiting for partial preparation in {}", dir.display());
            next_progress += std::time::Duration::from_secs(1);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // A helper may own the blocked preparation. Stop the whole isolated group
    // so no writer can continue changing the partial after this fixture returns.
    let stopped_early = child.try_wait().unwrap();
    let killed = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    let kill_error = std::io::Error::last_os_error();
    child.wait().unwrap();
    assert!(
        killed == 0 || kill_error.raw_os_error() == Some(libc::ESRCH),
        "stop partial-copy process group: {kill_error}"
    );
    assert!(
        stopped_early.is_none(),
        "copy exited before interruption: {stopped_early:?}"
    );
    assert!(ready.exists(), "copy never reached partial preparation");
    let mut partials = partial_files(dir);
    assert_eq!(partials.len(), 1, "expected one prepared partial");
    partials.pop().unwrap()
}

/// Keeps executable fixtures from being written while a child is forked.
///
/// Tests run in parallel threads of one process. A child forked by one test
/// inherits every open descriptor until it execs, including a wrapper script
/// another test is still writing. If that child is slow to exec under load,
/// the wrapper's own exec fails with ETXTBSY ("Text file busy"). Writers take
/// the exclusive side; every spawn takes the shared side, and both `spawn`
/// and `output` only return once the child has exec'd, so no un-exec'd child
/// can hold a fixture open when its writer proceeds.
static PROCESS_IMAGE_LOCK: RwLock<()> = RwLock::new(());

fn executable(p: &Path, body: &[u8]) {
    let _writing = PROCESS_IMAGE_LOCK
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    write(p, body);
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

/// `Command::output` and `Command::spawn` with the fork under
/// [`PROCESS_IMAGE_LOCK`]. Use these instead of the inherent methods
/// everywhere in this file. The lock covers only the spawn: several tests
/// race a child against filesystem changes, so waiting for it must not hold
/// other tests back. `run` captures stdout and stderr and closes stdin like
/// `Command::output`; a test that feeds stdin uses `start`.
trait Launch {
    fn run(&mut self) -> std::io::Result<Output>;
    fn start(&mut self) -> std::io::Result<std::process::Child>;
}

impl Launch for Command {
    fn run(&mut self) -> std::io::Result<Output> {
        self.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .start()?
            .wait_with_output()
    }

    fn start(&mut self) -> std::io::Result<std::process::Child> {
        let _spawning = PROCESS_IMAGE_LOCK
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.spawn_guarded()
    }
}

/// A remote shell that executes the supplied command locally with an isolated
/// HOME.  This exercises syq's real remote launcher/server protocol without
/// touching ssh or a real remote machine.
fn fake_rsh(t: &Tmp) -> PathBuf {
    let path = t.path("fake-rsh");
    executable(
        &path,
        br#"#!/bin/sh
shift
HOME="$FAKE_REMOTE_HOME"
if [ -n "${FAKE_REMOTE_PATH:-}" ]; then
    PATH="$FAKE_REMOTE_PATH"
else
    PATH="$FAKE_REMOTE_BIN:/usr/bin:/bin"
fi
export HOME PATH
if [ -n "${FAKE_REMOTE_PLATFORM:-}" ]; then
    SYQ_TEST_PLATFORM="$FAKE_REMOTE_PLATFORM"
    export SYQ_TEST_PLATFORM
else
    unset SYQ_TEST_PLATFORM
fi
if [ -n "${FAKE_REMOTE_CONFINED_SOCKET_NODES:-}" ]; then
    SYQ_TEST_CONFINED_SOCKET_NODES="$FAKE_REMOTE_CONFINED_SOCKET_NODES"
    export SYQ_TEST_CONFINED_SOCKET_NODES
else
    unset SYQ_TEST_CONFINED_SOCKET_NODES
fi
# The remote helper advertises the address ssh arrived on; never leak the
# developer's own session into the fixture.
if [ -n "${FAKE_SSH_CONNECTION:-}" ]; then
    SSH_CONNECTION="$FAKE_SSH_CONNECTION"
    export SSH_CONNECTION
else
    unset SSH_CONNECTION
fi
printf '%s\n' "$1" >> "$FAKE_RSH_LOG"
exec /bin/sh -c "$1"
"#,
    );
    path
}

/// An ssh-shaped fixture that records the connection arguments, including
/// native endpoint ports and control-master policy, then runs the remote
/// command locally.
fn fake_ssh(t: &Tmp) -> PathBuf {
    let path = t.path("bin/ssh");
    executable(
        &path,
        br#"#!/bin/sh
if [ "$1" = -V ]; then
    printf 'OpenSSH_%s, fake\n' "${FAKE_SSH_VERSION:-9.9p1}" >&2
    exit 0
fi
printf '%s\n' "$*" >> "$FAKE_RSH_LOG"
while [ "$#" -gt 0 ]; do
    case "$1" in
        # A control-master query: answer for a live master unless the test
        # says otherwise, as the session pool asks before every spare.
        -O) if [ "$2" = check ]; then exit "${FAKE_SSH_CHECK_STATUS:-0}"; fi; shift 2 ;;
        -o|-l|-p|-S) shift 2 ;;
        -a|-A|-x|-k|-T) shift ;;
        --) shift; break ;;
        -*) shift ;;
        *) break ;;
    esac
done
shift
HOME="$FAKE_REMOTE_HOME"
PATH="$FAKE_REMOTE_BIN:/usr/bin:/bin"
export HOME PATH
if [ -n "${FAKE_SSH_CONNECTION:-}" ]; then
    SSH_CONNECTION="$FAKE_SSH_CONNECTION"
    export SSH_CONNECTION
else
    unset SSH_CONNECTION
fi
exec /bin/sh -c "$1"
"#,
    );
    path
}

fn remote_syq_command(t: &Tmp, rsh: &Path, args: &[&str]) -> Command {
    fs::create_dir_all(t.path("remote-home")).unwrap();
    fs::set_permissions(t.path("remote-home"), fs::Permissions::from_mode(0o700)).unwrap();
    let mut cmd = compat_command();
    cmd.args([
        "-e",
        rsh.to_str().unwrap(),
        "--syq-no-tcp",
        "--performance-tuning",
        "workers=1",
    ])
    .args(args)
    .arg("--no-progress")
    .env("FAKE_REMOTE_HOME", t.path("remote-home"))
    .env("FAKE_REMOTE_BIN", t.path("remote-bin"))
    .env("FAKE_REMOTE_RELEASE_ARCHIVE", t.path("release.gz"))
    .env("FAKE_CURL_LOG", t.path("curl.log"))
    .env(
        "FAKE_REMOTE_RELEASE_MANIFEST",
        t.path("release-manifest.json"),
    )
    .env("FAKE_RSH_LOG", t.path("rsh.log"))
    .env("XDG_CONFIG_HOME", t.path("config"))
    .env("XDG_CACHE_HOME", t.path("cache"));
    if let Ok(key) = fs::read_to_string(t.path("release-public-key")) {
        cmd.env("SYQ_TEST_RELEASE_PUBLIC_KEY", key.trim())
            .env("SYQ_TEST_RELEASE_BUILD", "1")
            .env(
                "SYQ_TEST_RELEASE_DOWNLOADS",
                "https://release.invalid/download",
            )
            .env("SYQ_TEST_FIXTURES", &t.0);
    }
    cmd
}

fn remote_syq(t: &Tmp, rsh: &Path, args: &[&str]) -> Output {
    remote_syq_command(t, rsh, args)
        .run()
        .expect("run syq through fake remote shell")
}

fn assert_output_ok(out: &Output) {
    assert!(
        out.status.success(),
        "syq failed: status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The release target name syq uses for this test host.
fn helper_target() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("macos", "x86_64") => "macos-x86_64",
        ("macos", "aarch64") => "macos-arm64",
        other => panic!("unsupported test platform {other:?}"),
    }
}

fn cached_remote_helper(t: &Tmp) -> PathBuf {
    let identity = binary_identity("--build-identity");
    let target = helper_target();
    t.path(&format!(
        "remote-home/.cache/syq/helpers/{identity}-release/{target}/syq"
    ))
}

fn cached_local_helper(t: &Tmp) -> PathBuf {
    let target = helper_target();
    t.path(&format!(
        "cache/syq/helpers/v{}/{target}/syq",
        env!("CARGO_PKG_VERSION")
    ))
}

fn binary_identity(argument: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_syq"))
        .arg(argument)
        .run()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct ReleaseBootstrapFixture {
    archive: Vec<u8>,
    manifest: Vec<u8>,
    public_key: String,
    asset: &'static str,
}

static RELEASE_BOOTSTRAP_FIXTURE: OnceLock<ReleaseBootstrapFixture> = OnceLock::new();

fn release_bootstrap_fixture() -> &'static ReleaseBootstrapFixture {
    RELEASE_BOOTSTRAP_FIXTURE.get_or_init(|| {
        let binary_bytes = fs::read(env!("CARGO_BIN_EXE_syq")).unwrap();
        // Compression level is not part of the bootstrap contract. Build one
        // fast archive for the whole test process instead of compressing the
        // large debug binary independently in every parallel test.
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&binary_bytes).unwrap();
        let archive = encoder.finish().unwrap();
        let target = helper_target();
        let asset = match target {
            "linux-x86_64" => "syq-linux-x86_64",
            "linux-aarch64" => "syq-linux-aarch64",
            "macos-x86_64" => "syq-macos-x86_64",
            "macos-arm64" => "syq-macos-arm64",
            other => panic!("unsupported release target {other}"),
        };
        let manifest = serde_json::json!({
            "schema": 1,
            "repository": "https://github.com/greaber/syq",
            "version": env!("CARGO_PKG_VERSION"),
            "tag": format!("v{}", env!("CARGO_PKG_VERSION")),
            "artifacts": {
                (target): {
                    "binary": {
                        "name": asset,
                        "sha256": sha256_hex(&binary_bytes),
                        "size": binary_bytes.len()
                    },
                    "archive": {
                        "name": format!("{asset}.gz"),
                            "sha256": sha256_hex(&archive),
                            "size": archive.len()
                    }
                }
            },
            "installer": {"name": "install.sh", "sha256": "1".repeat(64), "size": 1},
            "homebrew_formula": {"name": "syq.rb", "sha256": "2".repeat(64), "size": 1},
            "signature_scheme": "ed25519-jcs-v1"
        });
        let signing = SigningKey::from_bytes(&[19; 32]);
        let canonical = serde_json_canonicalizer::to_vec(&manifest).unwrap();
        let signature =
            base64::engine::general_purpose::STANDARD.encode(signing.sign(&canonical).to_bytes());
        let mut manifest = manifest;
        manifest["signature"] = signature.into();
        ReleaseBootstrapFixture {
            archive,
            manifest: serde_json::to_vec_pretty(&manifest).unwrap(),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(signing.verifying_key().to_bytes()),
            asset,
        }
    })
}

fn setup_release_bootstrap(t: &Tmp) {
    let fixture = release_bootstrap_fixture();
    write(&t.path("release.gz"), &fixture.archive);
    write(&t.path(&format!("{}.gz", fixture.asset)), &fixture.archive);
    write(&t.path("syq-release-manifest.json"), &fixture.manifest);
    write(&t.path("release-manifest.json"), &fixture.manifest);
    write(&t.path("release-public-key"), fixture.public_key.as_bytes());

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
    *.json) cp "$FAKE_REMOTE_RELEASE_MANIFEST" "$out" ;;
    *.gz) cp "$FAKE_REMOTE_RELEASE_ARCHIVE" "$out" ;;
    *) exit 22 ;;
esac
"#,
    );
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

fn tuning_observed(out: &Output) -> serde_json::Value {
    let diagnostic = stderr_of(out);
    let line = diagnostic
        .lines()
        .find_map(|line| line.strip_prefix("syq: tuning observed: "))
        .unwrap_or_else(|| panic!("missing benchmark observations: {diagnostic}"));
    serde_json::from_str(line)
        .unwrap_or_else(|error| panic!("invalid benchmark observations ({error}): {diagnostic}"))
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

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn syq_cp_in(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_syq"));
    cmd.arg("cp").args(args).current_dir(dir);
    match stdin {
        None => cmd.run().expect("run syq cp"),
        Some(data) => {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd.spawn_guarded().expect("spawn syq cp");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(data)
                .expect("write manifest");
            child.wait_with_output().expect("wait syq cp")
        }
    }
}

fn entry_line(src: &str, dst: &str, kind: Option<&str>) -> String {
    let kind = kind.map_or(String::new(), |k| format!(",\"kind\":\"{k}\""));
    format!(
        "{{\"src\":{{\"encoding\":\"utf-8\",\"value\":\"{src}\"}},\"dst\":{{\"encoding\":\"utf-8\",\"value\":\"{dst}\"}}{kind}}}\n"
    )
}

fn persistence_command(t: &Tmp, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .arg("persist")
        .args(args)
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime());
    command
}

fn completion_command(t: &Tmp, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_syq"));
    command
        .arg("completion")
        .args(args)
        .env("HOME", t.path("home"))
        .env("XDG_CACHE_HOME", t.path("cache"))
        .env("XDG_CONFIG_HOME", t.path("config"))
        .env("XDG_RUNTIME_DIR", t.runtime());
    command
}

fn completion_values(output: &[u8]) -> Vec<(u8, Vec<u8>)> {
    output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| (record[0], record[1..].to_vec()))
        .collect()
}

fn ephemeral_scope(t: &Tmp) -> PathBuf {
    let output = persistence_command(t, &["on", "--ephemeral"])
        .run()
        .expect("create ephemeral persistence scope");
    assert_output_ok(&output);
    let path = output.stdout.strip_suffix(b"\n").unwrap();
    PathBuf::from(std::ffi::OsString::from_vec(path.to_vec()))
}

/// Poll a condition with a hard deadline; the message names what never came.
fn wait_for(what: &str, deadline: std::time::Duration, mut condition: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + deadline;
    while !condition() {
        assert!(
            std::time::Instant::now() < end,
            "timed out waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn automation_validator() -> jsonschema::Validator {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/automation.schema.json"))
            .expect("schema file is JSON");
    jsonschema::validator_for(&schema).expect("schema compiles")
}

/// Every line validates against the committed schema, seq is contiguous
/// from 0, the first record is `run`, and the last is `result`.
fn assert_automation_stream(validator: &jsonschema::Validator, content: &str, context: &str) {
    let records: Vec<serde_json::Value> = content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{context} line {}: not JSON: {e}", i + 1))
        })
        .collect();
    assert!(!records.is_empty(), "{context}: empty stream");
    for (i, record) in records.iter().enumerate() {
        if let Err(error) = validator.validate(record) {
            panic!("{context} line {}: {error}\nrecord: {record}", i + 1);
        }
        assert_eq!(record["seq"], i as u64, "{context} line {}", i + 1);
    }
    assert_eq!(records[0]["type"], "run", "{context}");
    assert_eq!(records.last().unwrap()["type"], "result", "{context}");
}

#[path = "local/bootstrap.rs"]
mod bootstrap;
#[path = "local/capacity.rs"]
mod capacity;
#[path = "local/cli.rs"]
mod cli;
#[path = "local/completion.rs"]
mod completion;
#[path = "local/confinement.rs"]
mod confinement;
#[path = "local/copy.rs"]
mod copy;
#[path = "local/data_safety.rs"]
mod data_safety;
#[path = "local/fifo.rs"]
mod fifo;
#[path = "local/hardlinks.rs"]
mod hardlinks;
#[path = "local/hashing.rs"]
mod hashing;
#[path = "local/local_copy_selection.rs"]
mod local_copy_selection;
#[path = "local/map.rs"]
mod map;
#[path = "local/metadata.rs"]
mod metadata;
#[path = "local/persistence.rs"]
mod persistence;
#[path = "local/progress.rs"]
mod progress;
#[path = "local/receiving.rs"]
mod receiving;
#[path = "local/remote.rs"]
mod remote;
#[path = "local/results.rs"]
mod results;
#[path = "local/resume.rs"]
mod resume;
#[path = "local/rm.rs"]
mod rm;
#[path = "local/selection.rs"]
mod selection;
#[path = "local/tuning.rs"]
mod tuning;

#[cfg(target_os = "linux")]
#[path = "local/inode_metadata.rs"]
mod inode_metadata;
