//! Checks every receiver runs, on every route, that a debug build can switch
//! off one at a time to measure what each costs. Release builds always run
//! them. `SYQ_TEST_DISABLE_CHECKS` lists the ones to switch off, separated by
//! commas; each process reads it for itself, so a receiver needs it in its
//! own environment.

/// A check `SYQ_TEST_DISABLE_CHECKS` can switch off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Check {
    /// `existing-file-conditions`: a copy that keeps existing files creates
    /// without replacing, `--only-existing` replaces only the file its scan
    /// found, and an `--into-new` root is created without adopting one
    /// (`TargetCondition`).
    ExistingFileConditions,
    /// `bounded-writes`: no write goes past the size declared for its file
    /// (`fsops::stages`).
    BoundedWrites,
    /// `own-links`: a copy that keeps existing files and copies hard links
    /// gives new names only to files it created (`fsops::owned`).
    OwnLinks,
}

impl Check {
    #[cfg(debug_assertions)]
    fn name(self) -> &'static str {
        match self {
            Self::ExistingFileConditions => "existing-file-conditions",
            Self::BoundedWrites => "bounded-writes",
            Self::OwnLinks => "own-links",
        }
    }
}

/// Whether this process runs `check`.
pub(crate) fn enabled(check: Check) -> bool {
    #[cfg(debug_assertions)]
    {
        static DISABLED: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        let disabled = DISABLED.get_or_init(|| {
            std::env::var("SYQ_TEST_DISABLE_CHECKS")
                .map(|list| list.split(',').map(|name| name.trim().to_owned()).collect())
                .unwrap_or_default()
        });
        !disabled.iter().any(|name| name == check.name())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = check;
        true
    }
}
