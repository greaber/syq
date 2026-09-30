//! Check the invoked version and select a release before interpreting its CLI.

use anyhow::{bail, Context, Result};
use semver::Version;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(crate) fn enter(mut argv: Vec<OsString>) -> Result<Vec<OsString>> {
    let prefix = prefix(&argv).map_err(|error| {
        clap::Error::raw(clap::error::ErrorKind::InvalidValue, format!("{error}\n"))
    })?;
    if let Some(expression) = prefix.requirement {
        crate::version_is::check(expression)?;
    }
    let consumed = prefix.consumed;
    let version = prefix.version;
    if consumed > 0 {
        argv.drain(1..=consumed);
    }
    let Some(version) = version else {
        return Ok(argv);
    };
    if crate::identity::is_release_build() && crate::identity::build() == format!("v{version}") {
        return Ok(argv);
    }
    let executable = crate::update::release_executable(&version)?;
    let error = Command::new(&executable).args(&argv[1..]).exec();
    Err(error).with_context(|| format!("run syq {version} from {}", executable.display()))
}

#[derive(Default, Debug)]
struct Prefix<'a> {
    version: Option<Version>,
    requirement: Option<&'a str>,
    consumed: usize,
}

fn option(arg: &str) -> Option<(&'static str, Option<&str>)> {
    for name in ["--use-version", "--version-is"] {
        if arg == name {
            return Some((name, None));
        }
        if let Some(raw) = arg
            .strip_prefix(name)
            .and_then(|suffix| suffix.strip_prefix('='))
        {
            return Some((name, Some(raw)));
        }
    }
    None
}

fn prefix(argv: &[OsString]) -> Result<Prefix<'_>> {
    let mut prefix = Prefix::default();
    while let Some((name, inline)) = argv
        .get(prefix.consumed + 1)
        .and_then(|arg| arg.to_str())
        .and_then(option)
    {
        let missing = if name == "--use-version" {
            "--use-version requires an exact release version, for example 0.7.1"
        } else {
            "--version-is requires an expression, for example '>=0.7.1, <0.8.0'"
        };
        let raw = inline
            .or_else(|| argv.get(prefix.consumed + 2).and_then(|arg| arg.to_str()))
            .context(missing)?;
        if name == "--use-version" {
            if prefix.version.is_some() {
                bail!("specify --use-version only once");
            }
            let version = Version::parse(raw.strip_prefix('v').unwrap_or(raw)).context(missing)?;
            if !version.build.is_empty() {
                bail!("--use-version selects published releases, not source-build identities");
            }
            prefix.version = Some(version);
        } else if prefix.requirement.replace(raw).is_some() {
            bail!("specify --version-is only once");
        }
        prefix.consumed += if inline.is_some() { 1 } else { 2 };
    }
    // Help/version actions can exit early. Reject misplaced prefix options
    // before that happens, but never interpret a subcommand's arguments.
    for arg in argv.iter().skip(prefix.consumed + 1) {
        let Some(arg) = arg.to_str() else { break };
        if arg == "--" || !arg.starts_with('-') {
            break;
        }
        if let Some((name, _)) = option(arg) {
            bail!("{name} must precede the command and other options");
        }
    }
    Ok(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_an_exact_release_in_the_global_prefix() {
        let parse = |args: &[&str]| {
            prefix(&args.iter().map(OsString::from).collect::<Vec<_>>())
                .map(|prefix| prefix.version)
        };
        for args in [
            vec!["syq", "--use-version", "0.7.1", "cp"],
            vec!["syq", "--use-version=v0.7.1", "cp"],
        ] {
            assert_eq!(parse(&args).unwrap().unwrap(), Version::new(0, 7, 1));
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

    #[test]
    fn both_version_options_can_precede_the_command_in_either_order() {
        for args in [
            vec![
                "syq",
                "--version-is",
                ">=0.7.1",
                "--use-version",
                "0.7.0",
                "cp",
            ],
            vec!["syq", "--use-version=0.7.0", "--version-is=>=0.7.1", "cp"],
        ] {
            let argv = args.iter().map(OsString::from).collect::<Vec<_>>();
            let parsed = prefix(&argv).unwrap();
            assert_eq!(parsed.version, Some(Version::new(0, 7, 0)));
            assert_eq!(parsed.requirement, Some(">=0.7.1"));
            assert_eq!(parsed.consumed, args.len() - 2);
            assert_eq!(argv[parsed.consumed + 1], "cp");
        }
    }

    #[test]
    fn guards_are_confined_to_the_prefix_and_cannot_be_repeated() {
        for args in [
            vec!["syq", "--version-is"],
            vec!["syq", "--version-is=1.2.3", "--version-is=1.2.3"],
            vec![
                "syq",
                "--version-is=1.2.3",
                "--use-version=1.2.3",
                "--version-is=1.2.3",
            ],
            vec![
                "syq",
                "--use-version=1.2.3",
                "--version-is=1.2.3",
                "--use-version=1.2.3",
            ],
            vec!["syq", "--help", "--version-is=1.2.3"],
            vec!["syq", "--version-is=1.2.3", "--help", "--use-version=1.2.3"],
        ] {
            assert!(
                prefix(&args.iter().map(OsString::from).collect::<Vec<_>>()).is_err(),
                "{args:?}"
            );
        }
        for args in [
            vec!["syq", "exec", "--", "--version-is=1.2.3"],
            vec!["syq", "cp", "--", "--version-is=1.2.3"],
            vec!["syq", "--", "--version-is=1.2.3"],
        ] {
            let argv = args.iter().map(OsString::from).collect::<Vec<_>>();
            let parsed = prefix(&argv).unwrap();
            assert!(parsed.requirement.is_none());
            assert_eq!(parsed.consumed, 0);
        }
    }
}
