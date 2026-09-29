//! Per-user locations for optional state.

use std::path::PathBuf;

/// The user's cache directory: `XDG_CACHE_HOME` when it is an absolute path,
/// otherwise `.cache` in the home directory. Syq never creates the home
/// directory itself, so a missing one leaves optional cache state unused.
pub(crate) fn cache_dir() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        return Some(base);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute() && home.is_dir())
        .map(|home| home.join(".cache"))
}
