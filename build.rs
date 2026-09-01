use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo::rerun-if-env-changed=SYQ_RELEASE_BUILD");
    register_inputs();

    let version = env::var("CARGO_PKG_VERSION").expect("Cargo sets CARGO_PKG_VERSION");
    let release_identity = format!("v{version}");
    let release_build = env::var("SYQ_RELEASE_BUILD").as_deref() == Ok("1");
    let build_identity = if release_build {
        release_identity
    } else {
        development_identity(&release_identity)
    };

    println!("cargo::rustc-env=SYQ_BUILD_IDENTITY={build_identity}");
    println!(
        "cargo::rustc-env=SYQ_IS_RELEASE_BUILD={}",
        if release_build { "1" } else { "0" }
    );
}

fn register_inputs() {
    println!("cargo::rerun-if-changed=.cargo_vcs_info.json");
    if let Ok(output) = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
    {
        if output.status.success() {
            for path in output
                .stdout
                .split(|byte| *byte == 0)
                .filter(|path| !path.is_empty())
            {
                println!("cargo::rerun-if-changed={}", String::from_utf8_lossy(path));
            }
        }
    }
    for git_path in [
        git(&["rev-parse", "--git-path", "HEAD"]),
        git(&["rev-parse", "--git-path", "index"]),
        git(&["symbolic-ref", "-q", "HEAD"])
            .and_then(|name| git(&["rev-parse", "--git-path", &name])),
    ]
    .into_iter()
    .flatten()
    {
        println!("cargo::rerun-if-changed={git_path}");
    }
}

fn development_identity(release_identity: &str) -> String {
    let revision = packaged_revision()
        .or_else(|| git(&["rev-parse", "--short=12", "HEAD"]))
        .filter(|value| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| format!("source.{}", build_nonce()));
    let dirty = working_tree_hash()
        .map(|hash| format!(".dirty.{hash}"))
        .unwrap_or_default();
    format!("{release_identity}+dev.{revision}{dirty}")
}

/// Cargo puts the source commit in every registry package. Prefer that value
/// over a surrounding checkout so an extracted package has the same identity
/// wherever it is compiled.
fn packaged_revision() -> Option<String> {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")?);
    let bytes = fs::read(manifest_dir.join(".cargo_vcs_info.json")).ok()?;
    let metadata: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let revision = metadata.get("git")?.get("sha1")?.as_str()?;
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(revision[..12].to_ascii_lowercase())
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Hash every modified or untracked package input. Two independently built
/// dirty trees match only when their actual source content matches.
fn working_tree_hash() -> Option<String> {
    let tracked = Command::new("git")
        .args(["diff", "--binary", "--no-ext-diff", "HEAD", "--", "."])
        .output()
        .ok()?;
    let names = Command::new("git")
        .args(["ls-files", "-z", "--others", "--exclude-standard"])
        .output()
        .ok()?;
    if !tracked.status.success() || !names.status.success() {
        return None;
    }
    if tracked.stdout.is_empty() && names.stdout.is_empty() {
        return None;
    }

    let mut content = tracked.stdout;
    for name in names
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        content.extend_from_slice(name);
        content.push(0);
        if let Ok(bytes) = fs::read(String::from_utf8_lossy(name).as_ref()) {
            content.extend_from_slice(&bytes);
        }
        content.push(0);
    }

    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(&content).ok()?;
    let output = child.wait_with_output().ok()?;
    let hash = output.status.success().then(|| {
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .chars()
            .take(12)
            .collect::<String>()
    })?;
    (hash.len() == 12 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(hash)
}

fn build_nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}
