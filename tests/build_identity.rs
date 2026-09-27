//! Exercise the actual Cargo build script in isolated source directories.
#[allow(dead_code)]
#[path = "../src/process.rs"]
mod process;
use crate::process::CommandExt as _;
#[path = "support/temp.rs"]
mod test_support;

#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

/// Keep the developer's and the system's Git configuration (for example
/// commit signing or a reftable default) out of these repositories.
fn isolated_git_config(command: &mut std::process::Command) -> &mut std::process::Command {
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
}

#[test]
fn emit_build_script() {
    if std::env::var_os("SYQ_BUILD_SCRIPT_TEST").is_some() {
        build_script::main();
    }
}

#[test]
fn packaged_provenance_and_helper_selection() {
    use std::{fs, process::Command};
    let root = crate::test_support::tempdir().unwrap();
    let package = root.path().join("package");
    fs::create_dir(&package).unwrap();
    fs::write(
        package.join(".cargo_vcs_info.json"),
        r#"{"git":{"sha1":"4555debc2350354450596cdeeb156bf01936b94f"}}"#,
    )
    .unwrap();
    let run = |release: Option<&str>, official: bool| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        isolated_git_config(&mut command)
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
        command.capture_output().unwrap()
    };
    for enclosing_git in [false, true] {
        if enclosing_git {
            assert!(isolated_git_config(&mut Command::new("git"))
                .args(["init", "-q"])
                .current_dir(root.path())
                .status_guarded()
                .unwrap()
                .success());
            assert!(isolated_git_config(&mut Command::new("git"))
                .args([
                    "-c",
                    "user.name=SDK test",
                    "-c",
                    "user.email=sdk-test@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "enclosing checkout"
                ])
                .current_dir(root.path())
                .status_guarded()
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

#[test]
fn watched_inputs_exist_outside_packages_and_nonce_builds() {
    use std::{fs, path::Path, process::Command};
    let root = crate::test_support::tempdir().unwrap();
    let package = root.path().join("package");
    fs::create_dir_all(package.join("src")).unwrap();
    fs::write(package.join("src/lib.rs"), "").unwrap();
    let run = || {
        let output = isolated_git_config(&mut Command::new(std::env::current_exe().unwrap()))
            .args(["--exact", "emit_build_script", "--nocapture"])
            .current_dir(&package)
            .env("SYQ_BUILD_SCRIPT_TEST", "1")
            .env("CARGO_MANIFEST_DIR", &package)
            .env("CARGO_PKG_VERSION", "0.6.0")
            .env("GIT_CEILING_DIRECTORIES", root.path())
            .env_remove("SYQ_HELPER_RELEASE")
            .env_remove("SYQ_RELEASE_BUILD")
            .capture_output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    };
    let watched = |text: &str| -> Vec<String> {
        text.lines()
            .filter_map(|line| line.strip_prefix("cargo::rerun-if-changed="))
            .map(str::to_owned)
            .collect()
    };

    // Without Git or provenance each build gets a nonce, so the script must
    // rerun every time: the absent provenance file stays watched.
    let text = run();
    assert!(
        text.contains("SYQ_BUILD_IDENTITY=v0.6.0+dev.source."),
        "{text}"
    );
    assert!(
        watched(&text).contains(&".cargo_vcs_info.json".to_owned()),
        "{text}"
    );

    // In a checkout, every watched path exists, so an unchanged tree does
    // not rerun the script and recompile.
    let git = |args: &[&str]| {
        assert!(isolated_git_config(&mut Command::new("git"))
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid"
            ])
            .args(args)
            .current_dir(&package)
            .status_guarded()
            .unwrap()
            .success());
    };
    git(&["init", "-q"]);
    git(&["add", "."]);
    git(&["commit", "-qm", "checkout"]);
    // A packed branch ref has no loose file; its reflog still records commits.
    for packed in [false, true] {
        if packed {
            git(&["pack-refs", "--all"]);
        }
        let text = run();
        assert!(text.contains("SYQ_BUILD_IDENTITY=v0.6.0+dev."), "{text}");
        assert!(!text.contains("+dev.source."), "{text}");
        let paths = watched(&text);
        assert!(paths.contains(&"src".to_owned()), "{text}");
        assert!(paths.iter().any(|path| path.ends_with("HEAD")), "{text}");
        assert!(
            paths.iter().any(|path| path.contains("logs/refs/heads/")),
            "{text}"
        );
        for path in &paths {
            let path = Path::new(path);
            let path = if path.is_absolute() {
                path.to_owned()
            } else {
                package.join(path)
            };
            assert!(
                path.exists(),
                "watched path {} is missing:\n{text}",
                path.display()
            );
        }
    }
}
