//! Persistence selection is independent of whether a reusable connection exists.
//! Global files retain their released locations; explicit domains own their state.
use anyhow::{Context, Result};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Domain {
    #[default]
    Global,
    Explicit(PathBuf),
}

impl Domain {
    /// Selecting the default domain is lazy: local commands need no runtime files.
    pub(crate) fn select(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::Global);
        };
        super::validate_scope(path)?;
        let path = std::fs::canonicalize(path)
            .with_context(|| format!("resolve persistence scope {}", path.display()))?;
        if super::is_global_scope(&path)? {
            Ok(Self::Global)
        } else {
            Ok(Self::Explicit(path))
        }
    }

    pub(crate) fn is_default(&self) -> bool {
        matches!(self, Self::Global)
    }

    pub(crate) fn explicit_path(&self) -> Option<&Path> {
        match self {
            Self::Global => None,
            Self::Explicit(path) => Some(path),
        }
    }

    pub(crate) fn runtime_path(&self) -> PathBuf {
        match self {
            Self::Global => super::runtime_parent_path().join("global"),
            Self::Explicit(path) => path.clone(),
        }
    }

    pub(crate) fn ensure_runtime(&self) -> Result<PathBuf> {
        let path = match self {
            Self::Global => super::ensure_global_scope()?,
            Self::Explicit(path) => {
                super::validate_scope(path)?;
                path.clone()
            }
        };
        if path.join(crate::receive_service::CLOSING).exists() {
            return Err(super::closing_scope_error(&path));
        }
        Ok(path)
    }

    pub(crate) fn enabled(&self) -> Result<bool> {
        match self {
            Self::Global => super::global_enabled(),
            Self::Explicit(path) => {
                super::validate_scope(path)?;
                Ok(!path.join(crate::receive_service::CLOSING).exists())
            }
        }
    }

    pub(crate) fn enable(&self) -> Result<PathBuf> {
        let path = self.ensure_runtime()?;
        if self.is_default() {
            super::write_global_config(true)?;
        }
        Ok(path)
    }

    pub(crate) fn config_file(&self, name: &str) -> Result<PathBuf> {
        match self {
            Self::Global => Ok(super::config_path()
                .context("HOME and XDG_CONFIG_HOME are unset")?
                .with_file_name(name)),
            Self::Explicit(path) => {
                self.ensure_runtime()?;
                Ok(path.join(name))
            }
        }
    }

    pub(crate) fn approved_index_path(&self) -> PathBuf {
        let parent = match self {
            Self::Global => super::runtime_parent_path(),
            Self::Explicit(path) => path.clone(),
        };
        parent.join("authorized-ssh-v1")
    }

    /// Directory identity prevents a closed and recreated domain being reused.
    pub(crate) fn identity(&self) -> Result<(u64, u64)> {
        let metadata = std::fs::metadata(self.runtime_path())?;
        Ok((metadata.dev(), metadata.ino()))
    }

    pub(crate) fn is_current(&self, identity: (u64, u64)) -> bool {
        let path = self.runtime_path();
        !path.join(crate::receive_service::CLOSING).exists()
            && self.identity().is_ok_and(|current| current == identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_utf8_closing_scope_hint_preserves_the_original_argument() {
        use std::os::unix::ffi::OsStrExt;
        let scope = Path::new(std::ffi::OsStr::from_bytes(b"/scope-\xff"));
        let error = super::super::closing_scope_error(scope).to_string();
        // Do not turn display replacement characters into a command.
        assert!(error.contains("repeating `syq persist off` with the original `--pscope` argument"));
        assert!(!error.contains("`syq persist --pscope"));
    }

    #[test]
    fn closing_scope_errors_name_the_selected_cleanup_command() {
        let root = crate::test_support::short_tempdir().unwrap();
        let scope = root.path().join("scope with spaces");
        crate::persistence::initialize_scope(&scope).unwrap();
        let domain = Domain::select(Some(&scope)).unwrap();
        let closing = scope.join(crate::receive_service::CLOSING);
        std::fs::write(&closing, b"").unwrap();
        let error = domain.ensure_runtime().unwrap_err().to_string();
        assert!(
            error.contains(&format!(
                "`syq persist --pscope {} off`",
                shell_words::quote(&scope.to_string_lossy())
            )),
            "{error}"
        );
        assert_eq!(
            crate::persistence::prepare_endpoint(&scope, None, "host.invalid", None, None)
                .unwrap_err()
                .to_string(),
            error
        );
        // The diagnostic does not reopen or complete a partially closed scope.
        assert!(closing.exists());
        assert!(!domain.enabled().unwrap());
    }
}
