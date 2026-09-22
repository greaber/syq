//! Keep ambient symlinks out of fixtures without hiding symlinks under test.
#[allow(dead_code)]
#[path = "../src/process.rs"]
mod process;
use crate::process::CommandExt as _;
#[path = "support/temp.rs"]
mod test_support;

use std::{fs, path::Path, process::Command};

#[test]
fn symlinked_tmpdir_resolves_fixture_roots_only() {
    const CHILD: &str = "SYQ_TEST_SYMLINKED_TMPDIR";
    if std::env::var_os(CHILD).is_none() {
        let outer = test_support::tempdir().unwrap();
        let real = outer.path().join("real");
        let alias = outer.path().join("alias");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "symlinked_tmpdir_resolves_fixture_roots_only",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("TMPDIR", &alias)
            .capture_output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
        return;
    }

    let ambient = std::path::PathBuf::from(std::env::var_os("TMPDIR").unwrap());
    assert_ne!(ambient, ambient.canonicalize().unwrap());
    assert_eq!(test_support::temp_dir(), ambient.canonicalize().unwrap());
    let temp = test_support::tempdir().unwrap();
    assert_eq!(temp.path(), temp.path().canonicalize().unwrap());
    let source = temp.path().join("source");
    let destination = temp.path().join("destination");
    fs::write(&source, b"fixture payload").unwrap();
    let copy = |source: &Path, destination: &Path| {
        Command::new(env!("CARGO_BIN_EXE_syq"))
            .arg("cp")
            .arg(source)
            .arg("--as")
            .arg(destination)
            .env("SYQ_NO_UPDATE_CHECK", "1")
            .env("XDG_CONFIG_HOME", temp.path().join("config"))
            .capture_output()
            .unwrap()
    };
    let output = copy(&source, &destination);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&destination).unwrap(), b"fixture payload");

    // Resolving the fixture root must not normalize paths passed to syq:
    // a deliberately symlinked parent still exercises the refusal policy.
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(temp.path(), &link).unwrap();
    let refused_destination = temp.path().join("refused");
    let output = copy(&link.join("source"), &refused_destination);
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing symlink component"));
    assert!(!refused_destination.exists());
}

#[test]
fn fixtures_use_shared_temp_constructors() {
    // Catch the direct constructors that have repeatedly reintroduced /var
    // paths. This is a small source convention check, not a Rust parser.
    fn check(directory: &Path, violations: &mut Vec<String>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                check(&path, violations);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = fs::read_to_string(&path).unwrap();
                let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
                for constructor in ["tempdir(", "TempDir::new(", "Builder::new().tempdir("] {
                    if compact.contains(&format!("tempfile::{constructor}")) {
                        violations.push(format!("{}: raw {constructor}", path.display()));
                    }
                }
                if path.starts_with(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"))
                    && !path.ends_with("support/temp.rs")
                    && compact.contains(&format!("{}::temp_dir(", "env"))
                {
                    violations.push(format!("{}: unresolved ambient temp root", path.display()));
                }
                // Imported constructors would bypass the qualified-name check.
                if compact.contains(&format!("use{}::", "tempfile")) {
                    violations.push(format!(
                        "{}: import through test_support instead",
                        path.display()
                    ));
                }
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for directory in ["src", "tests"] {
        check(&root.join(directory), &mut violations);
    }
    assert!(
        violations.is_empty(),
        "Use test_support::tempdir() for resolved fixture roots:\n{}",
        violations.join("\n")
    );
}
