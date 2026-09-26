//! Copy to a real macOS exFAT volume, including its native capacity counters.
#![cfg(target_os = "macos")]

#[allow(dead_code)]
#[path = "../src/process.rs"]
mod process;
use crate::process::CommandExt as _;
#[path = "support/temp.rs"]
mod test_support;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "support/nofile.rs"]
mod nofile;
use nofile::set_child_nofile_limit;

struct ExfatImage {
    scratch: Option<tempfile::TempDir>,
    mount: PathBuf,
}

impl ExfatImage {
    fn new() -> Self {
        let scratch = crate::test_support::tempdir().unwrap();
        let root = scratch.path().canonicalize().unwrap();
        let image = root.join("exfat.dmg");
        let mount = root.join("mount");
        fs::create_dir(&mount).unwrap();
        // exFAT volume labels have a short length limit.
        assert!(Command::new("hdiutil")
            .args(["create", "-size", "64m", "-fs", "ExFAT", "-volname", "SYQTEST"])
            .arg(&image)
            .status_guarded()
            .unwrap()
            .success());
        assert!(Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-mountpoint"])
            .arg(&mount)
            .arg(&image)
            .status_guarded()
            .unwrap()
            .success());
        Self {
            scratch: Some(scratch),
            mount,
        }
    }
}

impl Drop for ExfatImage {
    fn drop(&mut self) {
        let detached = Command::new("hdiutil")
            .arg("detach")
            .arg(&self.mount)
            .status_guarded()
            .is_ok_and(|status| status.success());
        if !detached {
            // Never recursively clean a temporary directory still containing
            // a mounted filesystem, including when a copy assertion failed.
            let retained = self.scratch.take().unwrap().keep();
            eprintln!(
                "exFAT detach failed; image retained at {}",
                retained.display()
            );
            if !std::thread::panicking() {
                panic!("could not detach the test exFAT image");
            }
        }
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fresh_exfat_destinations_have_unknown_inode_capacity() {
    let volume = ExfatImage::new();
    let source_dir = crate::test_support::tempdir().unwrap();
    let source = source_dir.path().canonicalize().unwrap().join("source");
    fs::write(&source, b"payload").unwrap();
    let copy = |destination: &str, placement: &str, extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .arg("cp")
            .arg(&source)
            .arg(placement)
            .arg(volume.mount.join(destination))
            .arg("--no-progress")
            .args(extra)
            .capture_output()
            .unwrap()
    };

    // A fresh dry run reports the filesystem's actual counters, including its
    // unknown inode count, without overrides. Fresh copies then succeed.
    let dry = copy("dry", "--as", &["--dry-run"]);
    assert_success(&dry);
    assert!(String::from_utf8_lossy(&dry.stdout).contains("free inode count unavailable"));
    assert!(!volume.mount.join("dry").exists());
    assert_success(&copy("file", "--as", &[]));
    assert_eq!(fs::read(volume.mount.join("file")).unwrap(), b"payload");
    fs::create_dir(volume.mount.join("empty")).unwrap();
    assert_success(&copy("empty", "--into", &[]));
    assert_eq!(
        fs::read(volume.mount.join("empty/source")).unwrap(),
        b"payload"
    );
    assert_success(&copy("missing", "--into", &[]));
    assert_eq!(
        fs::read(volume.mount.join("missing/source")).unwrap(),
        b"payload"
    );

    // Cloning must not make this non-cloneable destination fail descriptor
    // admission. The default worker ceiling fits ordinary copying within
    // 1664 slots, but the extra 192 clone-claim slots would exceed it.
    let payload = vec![b'x'; 5 << 20];
    fs::write(&source, &payload).unwrap();
    let mut limited = Command::new(env!("CARGO_BIN_EXE_syq"));
    limited
        .arg("cp")
        .arg(&source)
        .arg("--as")
        .arg(volume.mount.join("limited"))
        .arg("--no-progress");
    set_child_nofile_limit(&mut limited, 1664);
    assert_success(&limited.capture_output().unwrap());
    assert_eq!(fs::read(volume.mount.join("limited")).unwrap(), payload);

    // Capacity estimates are advisory, so a real shortage must surface as a
    // visible allocation failure instead of a published, truncated file.
    // A sparse source exceeds the entire image without allocating that data.
    fs::File::create(&source)
        .unwrap()
        .set_len(128 * 1024 * 1024)
        .unwrap();
    let shortage = copy("too-large", "--as", &[]);
    assert_eq!(shortage.status.code(), Some(1));
    let error = String::from_utf8_lossy(&shortage.stderr);
    assert!(error.contains("No space left on device"), "{error}");
    assert!(!volume.mount.join("too-large").exists());
}
