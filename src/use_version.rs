//! Select an exact release before interpreting its command line or environment.

use anyhow::{bail, Context, Result};
use semver::Version;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(crate) fn enter(mut argv: Vec<OsString>) -> Result<Vec<OsString>> {
    let Some((version, consumed)) = selection(&argv)? else {
        return Ok(argv);
    };
    argv.drain(1..=consumed);
    if crate::identity::is_release_build() && crate::identity::build() == format!("v{version}") {
        return Ok(argv);
    }
    let executable = crate::update::release_executable(&version)?;
    let error = Command::new(&executable).args(&argv[1..]).exec();
    Err(error).with_context(|| format!("run syq {version} from {}", executable.display()))
}

fn selection(argv: &[OsString]) -> Result<Option<(Version, usize)>> {
    let Some(first) = argv.get(1).and_then(|arg| arg.to_str()) else {
        return Ok(None);
    };
    let (raw, consumed) = if first == "--use-version" {
        (
            argv.get(2)
                .and_then(|arg| arg.to_str())
                .context("--use-version requires an exact release version, for example 0.7.1")?,
            2,
        )
    } else if let Some(raw) = first.strip_prefix("--use-version=") {
        (raw, 1)
    } else {
        return Ok(None);
    };
    let version = Version::parse(raw.strip_prefix('v').unwrap_or(raw))
        .context("--use-version requires an exact release version, for example 0.7.1")?;
    if !version.build.is_empty() {
        bail!("--use-version selects published releases, not source-build identities");
    }
    if argv
        .get(consumed + 1)
        .and_then(|arg| arg.to_str())
        .is_some_and(|arg| arg == "--use-version" || arg.starts_with("--use-version="))
    {
        bail!("specify --use-version only once");
    }
    Ok(Some((version, consumed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_an_exact_release_in_the_global_prefix() {
        let parse = |args: &[&str]| selection(&args.iter().map(OsString::from).collect::<Vec<_>>());
        for args in [
            vec!["syq", "--use-version", "0.7.1", "cp"],
            vec!["syq", "--use-version=v0.7.1", "cp"],
        ] {
            assert_eq!(parse(&args).unwrap().unwrap().0, Version::new(0, 7, 1));
        }
        for args in [
            vec!["syq", "--use-version"],
            vec!["syq", "--use-version=latest"],
            vec!["syq", "--use-version=0.7"],
            vec!["syq", "--use-version=0.7.1+dev.abc"],
            vec!["syq", "--use-version=0.7.1", "--use-version=0.7.0"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
        assert!(parse(&["syq", "exec", "--", "--use-version=0.7.1"])
            .unwrap()
            .is_none());
    }
}
