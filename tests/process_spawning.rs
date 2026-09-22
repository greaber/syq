//! All subprocess APIs share the same macOS pipe-creation lock.
#[path = "../src/process.rs"]
mod process;
use process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};

#[test]
fn concurrent_launches_do_not_inherit_sibling_pipes() {
    // CI shells may deliberately pass descriptors to the test executable.
    // Record that inherited baseline before starting concurrent pipe creation.
    let baseline = Command::new("python3")
        .args(["-c", "import fcntl\nfor fd in range(3,256):\n try: fcntl.fcntl(fd,fcntl.F_GETFD)\n except OSError: continue\n print(fd)\n"])
        .capture_output().unwrap();
    assert!(baseline.status.success());
    let baseline = String::from_utf8(baseline.stdout).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let barrier = barrier.clone();
            let baseline = &baseline;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..32 {
                    let mut command = Command::new("python3");
                    command.args(["-c", "import fcntl,sys\nallowed=set(map(int,sys.argv[1].split()))\nfor fd in range(3,256):\n if fd in allowed: continue\n try: fcntl.fcntl(fd,fcntl.F_GETFD)\n except OSError: continue\n sys.exit('inherited descriptor %s' % fd)\n"]);
                    command.arg(baseline);
                    let output = match worker % 3 {
                        0 => command.capture_output().unwrap(),
                        1 => command
                            .stdin(Stdio::null())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped())
                            .spawn_guarded()
                            .unwrap()
                            .wait_with_output()
                            .unwrap(),
                        _ => {
                            // A launch with inherited stderr must also take the lock.
                            let status = command.status_guarded().unwrap();
                            assert!(status.success());
                            continue;
                        }
                    };
                    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
                }
            });
        }
    });
}

#[test]
fn custom_stdio_is_preserved() {
    use std::io::Write;
    let mut child = Command::new("sh")
        .args(["-c", "cat; printf diagnostic >&2; exit 7"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_guarded()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"payload").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"payload");
    assert_eq!(output.stderr, b"diagnostic");
}
