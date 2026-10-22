//! Per-user base directories for syq's caches, settings, and runtime files,
//! including receiving approval settings and the install receipt, and the
//! store of versioned executables.
//!
//! An XDG base directory variable is used only when it holds an absolute
//! path. The XDG Base Directory specification treats a relative value as
//! invalid; honoring one would resolve it against the current directory,
//! whose contents may come from someone else.

use std::ffi::OsString;
use std::path::PathBuf;

/// The user's cache directory: an absolute `XDG_CACHE_HOME`, otherwise
/// `.cache` in the home directory when that exists. Syq never creates the
/// home directory itself, so a missing one leaves the cache unused.
pub(crate) fn cache_dir() -> Option<PathBuf> {
    base_dir("XDG_CACHE_HOME", Some(".cache"))
}

/// The user's configuration directory: an absolute `XDG_CONFIG_HOME`,
/// otherwise `.config` in the home directory when that exists.
pub(crate) fn config_dir() -> Option<PathBuf> {
    base_dir("XDG_CONFIG_HOME", Some(".config"))
}

/// The user's runtime directory: an absolute `XDG_RUNTIME_DIR`. It has no
/// default in the home directory; callers choose their own fallback.
pub(crate) fn runtime_dir() -> Option<PathBuf> {
    base_dir("XDG_RUNTIME_DIR", None)
}

/// Where the store of versioned executables lives in a home directory, on
/// this machine and on SSH servers alike.
pub(crate) const BINARY_STORE_IN_HOME: &str = ".local/lib/syq";

/// The store of versioned executables: `.local/lib/syq` in the home directory
/// when that exists. No XDG variable moves it. The specification defines no
/// directory for executables, and SSH servers find the store from `HOME`
/// alone, so one path serves every syq that shares a home directory.
pub(crate) fn binary_store() -> Option<PathBuf> {
    resolve(None, std::env::var_os("HOME"), Some(BINARY_STORE_IN_HOME))
}

fn base_dir(variable: &str, in_home: Option<&str>) -> Option<PathBuf> {
    resolve(
        std::env::var_os(variable),
        std::env::var_os("HOME"),
        in_home,
    )
}

/// The one rule for every base directory: the variable when it is absolute,
/// otherwise `in_home` inside `HOME` when that is an absolute path to an
/// existing directory.
fn resolve(
    variable: Option<OsString>,
    home: Option<OsString>,
    in_home: Option<&str>,
) -> Option<PathBuf> {
    let absolute =
        |value: Option<OsString>| value.map(PathBuf::from).filter(|path| path.is_absolute());
    absolute(variable).or_else(|| {
        let in_home = in_home?;
        absolute(home)
            .filter(|home| home.is_dir())
            .map(|home| home.join(in_home))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_base_directories_are_ignored() {
        let dir = crate::test_support::tempdir().unwrap();
        let home = || Some(dir.path().as_os_str().to_owned());
        let value = |text: &str| Some(OsString::from(text));
        assert_eq!(
            resolve(value("/xdg/config"), home(), Some(".config")),
            Some(PathBuf::from("/xdg/config"))
        );
        for ignored in [value("config"), value("./config"), value(""), None] {
            assert_eq!(
                resolve(ignored, home(), Some(".config")),
                Some(dir.path().join(".config"))
            );
        }
        assert_eq!(resolve(value("runtime"), home(), None), None);
        assert_eq!(resolve(None, value("home"), Some(".cache")), None);
        assert_eq!(
            resolve(
                None,
                Some(dir.path().join("missing").into()),
                Some(".cache")
            ),
            None
        );
    }
}
