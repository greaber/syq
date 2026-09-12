//! Copy to a real macOS exFAT volume, including its native capacity counters.
#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct ExfatImage {
    scratch: Option<tempfile::TempDir>,
    mount: PathBuf,
}

impl ExfatImage {
    fn new() -> Self {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path().canonicalize().unwrap();
        let image = root.join("exfat.dmg");
        let mount = root.join("mount");
        fs::create_dir(&mount).unwrap();
        // exFAT volume labels have a short length limit.
        assert!(Command::new("hdiutil")
            .args(["create", "-size", "64m", "-fs", "ExFAT", "-volname", "SYQTEST"])
            .arg(&image)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("hdiutil")
            .args(["attach", "-nobrowse", "-mountpoint"])
            .arg(&mount)
            .arg(&image)
            .status()
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
            .status()
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
    let source_dir = tempfile::tempdir().unwrap();
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
            .output()
            .unwrap()
    };

    // Both a missing exact file and an existing empty directory must pass
    // preflight using the filesystem's actual counters, without overrides.
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

    // Unknown inode accounting must not disable the byte-capacity check.
    // A sparse source exceeds the entire image without allocating that data.
    fs::File::create(&source)
        .unwrap()
        .set_len(128 * 1024 * 1024)
        .unwrap();
    let shortage = copy("too-large", "--as", &[]);
    assert_eq!(shortage.status.code(), Some(1));
    let error = String::from_utf8_lossy(&shortage.stderr);
    assert!(
        error.contains("fresh destination capacity preflight failed"),
        "{error}"
    );
    assert!(error.contains("logical file data"), "{error}");
    assert!(!volume.mount.join("too-large").exists());
}
