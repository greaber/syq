//! The saved invocation is independent of per-entry mutation journals.
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

/// Keep ordinary paths readable and compact without losing Unix path bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub(super) enum Bytes {
    Text(String),
    Encoded { base64: String },
}
impl Bytes {
    pub fn new(value: &[u8]) -> Self {
        match std::str::from_utf8(value) {
            Ok(value) => Self::Text(value.to_owned()),
            Err(_) => Self::Encoded {
                base64: base64::engine::general_purpose::STANDARD.encode(value),
            },
        }
    }
    pub fn decode(&self) -> Result<Vec<u8>> {
        match self {
            Self::Text(value) => Ok(value.as_bytes().to_vec()),
            Self::Encoded { base64 } => base64::engine::general_purpose::STANDARD
                .decode(base64)
                .context("decode job pathname"),
        }
    }
    pub fn os(&self) -> Result<OsString> {
        Ok(OsString::from_vec(self.decode()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Command {
    pub argv: Vec<Bytes>,
    pub cwd: Bytes,
    pub copy_id: crate::proto::CopyId,
    pub created_by: String,
}
impl Command {
    pub fn new(argv: &[OsString]) -> Result<Self> {
        if !matches!(argv.first().and_then(|arg| arg.to_str()), Some("cp" | "rm")) {
            bail!("only native copy and removal commands have named jobs");
        }
        Ok(Self {
            argv: argv.iter().map(|arg| Bytes::new(arg.as_bytes())).collect(),
            cwd: Bytes::new(std::env::current_dir()?.as_os_str().as_bytes()),
            copy_id: super::fresh_copy_id()?,
            created_by: crate::identity::build().to_string(),
        })
    }

    /// Resume does not accept new operands or semantic options. Replacing
    /// operational options removes their old occurrences before ordinary CLI
    /// parsing, retaining clap's validation of values and interactions.
    pub fn arguments(&self, overrides: &[OsString]) -> Result<(Vec<OsString>, PathBuf)> {
        let original: Vec<OsString> = self.argv.iter().map(Bytes::os).collect::<Result<_>>()?;
        let command = original.first().context("job has no saved command")?;
        if !matches!(command.to_str(), Some("cp" | "rm")) {
            bail!("job has an unsupported command");
        }
        let changed = parse_overrides(overrides)?;
        let mut result = vec![command.clone()];
        let mut index = 1;
        while index < original.len() {
            let value = &original[index];
            let key = option_key(value);
            // Each attempt gets its own results stream; never reopen the file
            // or descriptor from an earlier process.
            let transient = matches!(key.as_deref(), Some("--results" | "--results-fd"));
            let replace = key
                .as_ref()
                .is_some_and(|key| changed.iter().any(|(replacement, _)| replacement == key));
            if transient || replace {
                let key = key.as_deref().unwrap();
                if option_takes_value(key).unwrap_or(false) && !value.as_bytes().contains(&b'=') {
                    index += 1;
                }
            } else {
                result.push(value.clone());
            }
            index += 1;
        }
        for (_, words) in changed {
            result.extend(words);
        }
        Ok((result, PathBuf::from(self.cwd.os()?)))
    }
}

fn option_key(value: &OsStr) -> Option<String> {
    let bytes = value.as_bytes();
    if !bytes.starts_with(b"-") {
        return None;
    }
    let key = bytes.split(|byte| *byte == b'=').next()?;
    let key = std::str::from_utf8(key).ok()?;
    Some(
        match key {
            "-v" => "--verbose",
            "-q" => "--quiet",
            "-n" => "--dry-run",
            _ => key,
        }
        .to_owned(),
    )
}

fn option_takes_value(key: &str) -> Option<bool> {
    match key {
        "--verbose" | "--quiet" | "--dry-run" | "--progress" | "--no-progress" | "--stats"
        | "--no-compress" | "--no-tcp" | "--no-bootstrap" | "--open-noatime" => Some(false),
        "--results"
        | "--results-fd"
        | "--resource-limits"
        | "--performance-tuning"
        | "--max-delete"
        | "--receiver-max-entries"
        | "--receiver-max-bytes"
        | "--tcp-ports"
        | "--tcp-congestion"
        | "--pscope"
        | "--s3-profile"
        | "--s3-region"
        | "--syq-path" => Some(true),
        _ => None,
    }
}

fn parse_overrides(values: &[OsString]) -> Result<Vec<(String, Vec<OsString>)>> {
    let mut result = Vec::new();
    let mut index = 0;
    while index < values.len() {
        let value = &values[index];
        let key = option_key(value)
            .context("--resume does not accept new source or destination operands")?;
        let takes_value = option_takes_value(&key)
            .with_context(|| format!("{key} cannot be changed when resuming a job"))?;
        let mut words = vec![value.clone()];
        let inline = value.as_bytes().contains(&b'=');
        if takes_value && !inline {
            index += 1;
            words.push(
                values
                    .get(index)
                    .with_context(|| format!("{key} requires a value"))?
                    .clone(),
            );
        } else if !takes_value && inline {
            bail!("{key} does not take a value");
        }
        result.push((key, words));
        index += 1;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn words(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn preserves_scope_and_replaces_limits_without_reusing_output_files() {
        let saved = Command::new(&words(&[
            "cp",
            "source",
            "--into",
            "destination",
            "--prune",
            "--max-delete",
            "2",
            "--results",
            "first.jsonl",
        ]))
        .unwrap();
        let (args, _) = saved
            .arguments(&words(&["--max-delete=10", "--results", "retry.jsonl"]))
            .unwrap();
        assert_eq!(
            args,
            words(&[
                "cp",
                "source",
                "--into",
                "destination",
                "--prune",
                "--max-delete=10",
                "--results",
                "retry.jsonl"
            ])
        );
        assert!(saved.arguments(&words(&["--into", "elsewhere"])).is_err());
        assert!(saved.arguments(&words(&["other-source"])).is_err());
        assert!(saved.arguments(&words(&["--if-exists=update"])).is_err());
        assert!(saved
            .arguments(&words(&["--receiver-max-bytes", "10G"]))
            .is_ok());
    }

    #[test]
    fn preserves_non_utf8_paths() {
        let input = OsString::from_vec(b"file-\xff".to_vec());
        let saved = Command::new(&["rm".into(), input.clone()]).unwrap();
        let decoded: Command =
            serde_json::from_slice(&serde_json::to_vec(&saved).unwrap()).unwrap();
        assert_eq!(
            decoded.arguments(&[]).unwrap().0,
            [OsString::from("rm"), input]
        );
    }
}
