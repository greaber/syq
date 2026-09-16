//! Exercise the actual Cargo build script in isolated source directories.
#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

#[test]
fn emit_build_script() {
    if std::env::var_os("SYQ_BUILD_SCRIPT_TEST").is_some() {
        build_script::main();
    }
}

#[test]
fn packaged_provenance_and_helper_selection() {
    use std::{fs, process::Command};
    let root = tempfile::tempdir().unwrap();
    let package = root.path().join("package");
    fs::create_dir(&package).unwrap();
    fs::write(
        package.join(".cargo_vcs_info.json"),
        r#"{"git":{"sha1":"4555debc2350354450596cdeeb156bf01936b94f"}}"#,
    )
    .unwrap();
    let run = |release: Option<&str>, official: bool| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "emit_build_script", "--nocapture"])
            .current_dir(&package)
            .env("SYQ_BUILD_SCRIPT_TEST", "1")
            .env("CARGO_MANIFEST_DIR", &package)
            .env("CARGO_PKG_VERSION", "0.6.0")
            .env_remove("SYQ_HELPER_RELEASE")
            .env("SYQ_RELEASE_BUILD", if official { "1" } else { "0" });
        if let Some(release) = release {
            command.env("SYQ_HELPER_RELEASE", release);
        }
        command.output().unwrap()
    };
    for enclosing_git in [false, true] {
        if enclosing_git {
            assert!(Command::new("git")
                .args(["init", "-q"])
                .current_dir(root.path())
                .status()
                .unwrap()
                .success());
            fs::write(root.path().join("unrelated"), "unrelated edits").unwrap();
        }
        let output = run(None, false);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("SYQ_BUILD_IDENTITY=v0.6.0+dev.4555debc2350\n"),
            "{text}"
        );
        assert!(!text.contains(".dirty."), "{text}");
        assert!(text.contains("SYQ_RELEASE_HELPERS=0\n"));
    }
    let output = run(Some("v0.6.0"), false);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("SYQ_BUILD_IDENTITY=v0.6.0\n"), "{text}");
    assert!(text.contains("SYQ_RELEASE_HELPERS=1\n"));
    assert!(text.contains("SYQ_IS_RELEASE_BUILD=0\n"));
    let output = run(None, true);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("SYQ_BUILD_IDENTITY=v0.6.0\n"));
    assert!(text.contains("SYQ_IS_RELEASE_BUILD=1\n"));
    let output = run(Some("v0.5.2"), false);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must match the source package version")
    );
}
