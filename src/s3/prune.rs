//! Destination claims and directory scopes for local/S3 pruning.
use std::{collections::BTreeSet, ffi::OsStr, os::unix::ffi::OsStrExt};

#[derive(Clone, Default)]
pub(super) struct Plan {
    pub scopes: Vec<(Vec<u8>, Vec<u8>)>,
    pub claims: BTreeSet<Vec<u8>>,
    protected: BTreeSet<Vec<u8>>,
    files: BTreeSet<Vec<u8>>,
}

pub(super) fn beneath<'a>(path: &'a [u8], root: &[u8]) -> Option<&'a [u8]> {
    if root.is_empty() {
        Some(path)
    } else if path == root {
        Some(b"")
    } else {
        path.strip_prefix(root)?.strip_prefix(b"/")
    }
}

impl Plan {
    pub fn scope(&mut self, destination: &[u8], source: &[u8]) {
        self.scopes.push((destination.to_vec(), source.to_vec()));
        self.claim(destination);
    }
    pub fn claim(&mut self, path: &[u8]) {
        self.claims.insert(path.to_vec());
    }
    pub fn claim_file(&mut self, path: &[u8]) {
        self.files.insert(path.to_vec());
    }
    fn ancestor(&self, path: &[u8]) -> bool {
        let mut prefix = path.to_vec();
        if !prefix.is_empty() {
            prefix.push(b'/');
        }
        [&self.claims, &self.files].into_iter().any(|set| {
            set.range(prefix.clone()..)
                .next()
                .is_some_and(|p| p.starts_with(&prefix))
        })
    }
    pub fn keeps_object(&self, path: &[u8], directory: bool) -> bool {
        self.shields(path)
            || if directory {
                self.claims.contains(path) || self.ancestor(path)
            } else {
                self.files.contains(path)
            }
    }
    pub fn claimed_paths(&self) -> impl Iterator<Item = &[u8]> {
        self.claims.iter().chain(&self.files).map(Vec::as_slice)
    }
    pub fn protect(&mut self, path: &[u8]) {
        self.claim(path);
        self.protected.insert(path.to_vec());
    }
    pub fn keeps(&self, path: &[u8]) -> bool {
        self.claims.contains(path)
            || self.files.contains(path)
            || self.ancestor(path)
            || self.shields(path)
    }
    pub fn shields(&self, path: &[u8]) -> bool {
        self.protected.contains(path)
            || self.protected.contains(b"".as_slice())
            || path
                .iter()
                .enumerate()
                .any(|(i, &c)| c == b'/' && self.protected.contains(&path[..i]))
    }
    pub fn ignores(
        &self,
        path: &[u8],
        directory: bool,
        matcher: Option<&ignore::gitignore::Gitignore>,
    ) -> bool {
        // Use the most specific mapping's source path, just as the copy scan does.
        let Some((root, source)) = self
            .scopes
            .iter()
            .filter(|(root, _)| beneath(path, root).is_some())
            .max_by_key(|(root, _)| root.len())
        else {
            return false;
        };
        let suffix = beneath(path, root).unwrap();
        let mut label = source.clone();
        if !label.is_empty() && !suffix.is_empty() {
            label.push(b'/');
        }
        label.extend_from_slice(suffix);
        matcher.is_some_and(|m| crate::scan::path_is_ignored(m, &label, directory))
    }
}

const PARTIAL_PREFIX: &str = ".syq-s3-";
const PARTIAL_SUFFIX: &str = ".partial";
pub(super) fn partial_name(random: &[u8]) -> String {
    format!(
        "{PARTIAL_PREFIX}{}{PARTIAL_SUFFIX}",
        blake3::hash(random).to_hex()
    )
}

pub(super) fn recovery(path: &[u8]) -> bool {
    path.split(|c| *c == b'/').any(|name| {
        let name = OsStr::from_bytes(name);
        crate::fsops::is_partial_name(name)
            || crate::fsops::is_recovery_name(name)
            || (name.as_bytes().starts_with(PARTIAL_PREFIX.as_bytes())
                && name.as_bytes().ends_with(PARTIAL_SUFFIX.as_bytes()))
    })
}

#[derive(Debug)]
pub(super) struct Limit;
impl std::fmt::Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("planned deletions exceed --max-delete; deleting nothing")
    }
}
impl std::error::Error for Limit {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_and_prefix_claims_are_distinct() {
        let mut plan = Plan::default();
        plan.scope(b"root", b"source");
        plan.claim_file(b"root/file");
        plan.claim(b"root/dir");
        plan.claim_file(b"root/dir/child");
        assert!(plan.keeps_object(b"root/file", false));
        assert!(!plan.keeps_object(b"root/file", true));
        assert!(!plan.keeps_object(b"root/file/old", false));
        assert!(plan.keeps_object(b"root/dir", true));
        assert!(!plan.keeps_object(b"root/dir", false));
        assert!(plan.keeps(b"root"));
        assert_eq!(plan.claims.len(), 2);
    }

    #[test]
    fn protected_children_keep_ancestors_without_protecting_siblings() {
        let mut plan = Plan::default();
        plan.scope(b"backup/tree", b"source");
        plan.protect(b"backup/tree/old/ignored");
        assert!(plan.keeps(b"backup/tree/old"));
        assert!(plan.keeps(b"backup/tree/old/ignored/child"));
        assert!(!plan.keeps(b"backup/tree/old/extra"));
        assert!(!plan.keeps(b"backup/tree/old/ignored-other"));
        assert_eq!(beneath(b"backup/tree-other", b"backup/tree"), None);
    }

    #[test]
    fn ignores_use_source_names_and_keep_recovery_descendants() {
        let mut plan = Plan::default();
        plan.scope(b"renamed", b"source");
        let matcher = crate::scan::build_ignore(&["/source/ignored/".into()]).unwrap();
        assert!(plan.ignores(b"renamed/ignored/child", false, matcher.as_ref()));
        assert!(!plan.ignores(b"renamed/extra", false, matcher.as_ref()));
        assert!(recovery(b"old/.syq-swap-123-4/data"));
        assert!(recovery(b"old/.syq-s3-123.partial"));
        assert!(!recovery(b"old/normal.partial"));
    }
}
