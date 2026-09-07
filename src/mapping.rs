//! Mapping manifest parsing shared by the planner and restricted authorizer.

use crate::completion_details::display_bytes as display;
use crate::proto::{Kind, PathBytes};
use anyhow::{bail, Context, Result};

/// One parsed `--mapping` manifest entry.
#[derive(Debug)]
pub(crate) struct ManifestEntry {
    pub src: PathBytes,
    pub dst: PathBytes,
    pub kind: Option<DeclaredKind>,
}

/// The manifest's `kind` field: disambiguation of the request, not a
/// precondition. A mismatch fails that entry the way a missing source does.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DeclaredKind {
    File,
    Dir,
    Symlink,
    Special,
}

impl DeclaredKind {
    pub(crate) fn matches(self, kind: Kind) -> bool {
        match self {
            DeclaredKind::File => kind == Kind::File,
            DeclaredKind::Dir => kind == Kind::Dir,
            DeclaredKind::Symlink => kind == Kind::Symlink,
            DeclaredKind::Special => matches!(
                kind,
                Kind::Fifo | Kind::Socket | Kind::CharDev | Kind::BlockDev
            ),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            DeclaredKind::File => "file",
            DeclaredKind::Dir => "dir",
            DeclaredKind::Symlink => "symlink",
            DeclaredKind::Special => "special",
        }
    }
}

pub(crate) fn parse_manifest_entry(text: &str) -> Result<ManifestEntry> {
    use base64::Engine as _;
    // Unknown keys are rejected so a typo cannot be silently dropped; the
    // known informational fields (`size`, `mtime`, a tagged path's `display`)
    // are accepted and ignored so `syq map` output and future automation
    // records round-trip.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WirePath {
        encoding: String,
        value: String,
        #[serde(default)]
        #[allow(dead_code)]
        display: Option<String>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireEntry {
        src: WirePath,
        dst: WirePath,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        size: Option<u64>,
        #[serde(default)]
        #[allow(dead_code)]
        mtime: Option<i64>,
    }
    let entry: WireEntry = serde_json::from_str(text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let decode = |path: WirePath, which: &str| -> Result<PathBytes> {
        let bytes = match path.encoding.as_str() {
            "utf-8" => path.value.into_bytes(),
            "base64" => base64::engine::general_purpose::STANDARD
                .decode(path.value.as_bytes())
                .map_err(|e| anyhow::anyhow!("{which}: invalid base64 path: {e}"))?,
            other => bail!("{which}: unknown path encoding {other:?}"),
        };
        validate_manifest_path(&bytes, which)?;
        Ok(bytes)
    };
    let src = decode(entry.src, "src")?;
    let dst = decode(entry.dst, "dst")?;
    let kind = match entry.kind.as_deref() {
        None => None,
        Some("file") => Some(DeclaredKind::File),
        Some("dir") => Some(DeclaredKind::Dir),
        Some("symlink") => Some(DeclaredKind::Symlink),
        Some("special") => Some(DeclaredKind::Special),
        Some(other) => bail!("unknown kind {other:?}"),
    };
    Ok(ManifestEntry { src, dst, kind })
}

pub(crate) fn validate_manifest_path(path: &[u8], which: &str) -> Result<()> {
    if path.is_empty() {
        bail!("{which} path is empty");
    }
    if path[0] == b'/' {
        bail!(
            "{which} path {:?} is absolute; mapping entries are root-relative",
            String::from_utf8_lossy(path)
        );
    }
    if path.contains(&0) {
        bail!("{which} path contains NUL");
    }
    for component in path.split(|&byte| byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            bail!(
                "{which} path {:?} contains an empty, `.`, or `..` component",
                String::from_utf8_lossy(path)
            );
        }
    }
    Ok(())
}

/// Phase-1 manifest read for `--mapping`: parse every line and run the
/// parse-level preflight (duplicate destinations; an entry whose destination
/// is a strict ancestor of another entry's destination must not declare a
/// non-directory kind) before anything is written. Whether an undeclared
/// ancestor really is a directory is only knowable from the source and is
/// checked during execution.
pub(crate) fn read_mapping_manifest(
    reader: &mut dyn std::io::BufRead,
) -> Result<Vec<(u64, ManifestEntry)>> {
    let mut entries: Vec<(u64, ManifestEntry)> = Vec::new();
    let mut declared: std::collections::HashMap<PathBytes, Option<DeclaredKind>> =
        std::collections::HashMap::new();
    let mut line_number = 0u64;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| anyhow::anyhow!("--mapping: read: {e}"))?;
        if n == 0 {
            break;
        }
        line_number += 1;
        let text = line.trim_end_matches('\n').trim_end_matches('\r');
        if text.is_empty() {
            continue;
        }
        let entry = parse_manifest_entry(text)
            .map_err(|e| anyhow::anyhow!("--mapping line {line_number}: {e}"))?;
        if declared.insert(entry.dst.clone(), entry.kind).is_some() {
            bail!(
                "--mapping line {line_number}: duplicate destination {} (duplicate entries are errors; deduplicate in the generator)",
                display(&entry.dst)
            );
        }
        entries.push((line_number, entry));
    }
    for (line_number, entry) in &entries {
        for (i, &byte) in entry.dst.iter().enumerate() {
            if byte != b'/' {
                continue;
            }
            if let Some(Some(kind)) = declared.get(&entry.dst[..i]) {
                if !matches!(kind, DeclaredKind::Dir) {
                    bail!(
                        "--mapping line {line_number}: destination ancestor {} of {} is mapped with kind {:?}, not dir",
                        display(&entry.dst[..i]),
                        display(&entry.dst),
                        kind.label()
                    );
                }
            }
        }
    }
    Ok(entries)
}

/// The exact manifest authorized by the invoking/receiving machine. Contents
/// travel separately so manifest size does not consume the signed grant budget.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Authorization {
    pub bytes: u64,
    pub digest: [u8; 32],
}

impl Authorization {
    pub(crate) fn from_contents(contents: &[u8]) -> Self {
        Self {
            bytes: contents.len() as u64,
            digest: *blake3::hash(contents).as_bytes(),
        }
    }
}

/// Destination entries are exact, including explicitly listed directories.
/// Ancestors only authorize directory creation, never arbitrary child paths.
#[derive(Debug)]
pub(crate) struct Permissions {
    entries: std::collections::HashMap<PathBytes, Option<DeclaredKind>>,
    parents: std::collections::HashSet<PathBytes>,
}

impl Permissions {
    fn new() -> Self {
        Self {
            entries: Default::default(),
            parents: [Vec::new()].into(),
        }
    }

    fn insert(&mut self, entry: ManifestEntry, max_entries: u64) -> Result<()> {
        // The grant's absolute paths already have this bound. Apply it before
        // expanding ancestor paths, whose total storage grows with depth.
        if entry.dst.len() > 4096 {
            bail!("restricted mapping destination exceeds 4096 bytes");
        }
        if self.entries.contains_key(&entry.dst) {
            bail!("duplicate mapping destination {}", display(&entry.dst));
        }
        if entry
            .kind
            .is_some_and(|kind| !matches!(kind, DeclaredKind::Dir))
            && self.parents.contains(&entry.dst)
        {
            bail!("mapping destination ancestor is not a directory");
        }
        for (i, byte) in entry.dst.iter().enumerate() {
            if *byte == b'/' {
                let parent = &entry.dst[..i];
                if self
                    .entries
                    .get(parent)
                    .is_some_and(|kind| kind.is_some_and(|kind| !matches!(kind, DeclaredKind::Dir)))
                {
                    bail!("mapping destination ancestor is not a directory");
                }
                if !self.entries.contains_key(parent) {
                    self.parents.insert(parent.to_vec());
                    self.check_limit(max_entries)?;
                }
            }
        }
        self.parents.remove(&entry.dst);
        self.entries.insert(entry.dst, entry.kind);
        self.check_limit(max_entries)
    }

    fn check_limit(&self, max_entries: u64) -> Result<()> {
        if (self.entries.len() + self.parents.len()) as u64 > max_entries {
            bail!("mapping exceeds the signed destination entry limit");
        }
        Ok(())
    }

    pub(crate) fn allows(&self, path: &[u8], directory: Option<bool>) -> bool {
        self.entries.contains_key(path) || (directory != Some(false) && self.parents.contains(path))
    }

    pub(crate) fn implicit_directory(&self, path: &[u8]) -> bool {
        self.parents.contains(path)
    }
}

#[derive(Debug)]
pub(crate) struct Admission {
    authorization: Authorization,
    received: u64,
    hasher: blake3::Hasher,
    line: Vec<u8>,
    max_entries: u64,
    pending: Option<Permissions>,
    permissions: Option<Permissions>,
}

impl Admission {
    pub(crate) fn new(authorization: Authorization, max_entries: u64) -> Self {
        Self {
            authorization,
            received: 0,
            hasher: blake3::Hasher::new(),
            line: Vec::new(),
            max_entries,
            pending: Some(Permissions::new()),
            permissions: None,
        }
    }

    fn finish_line(&mut self) -> Result<()> {
        let text = std::str::from_utf8(&self.line)?
            .trim_end_matches('\n')
            .trim_end_matches('\r');
        if !text.is_empty() {
            self.pending
                .as_mut()
                .context("mapping admission is closed")?
                .insert(parse_manifest_entry(text)?, self.max_entries)?;
        }
        self.line.clear();
        Ok(())
    }

    pub(crate) fn append(&mut self, offset: u64, data: &[u8], finish: bool) -> Result<()> {
        if self.pending.is_none() {
            bail!("mapping admission is already closed");
        }
        let result = (|| {
            if offset != self.received {
                bail!("mapping chunk is out of order");
            }
            if data.len() > CHUNK_BYTES {
                bail!("mapping chunk exceeds size limit");
            }
            let end = offset
                .checked_add(data.len() as u64)
                .context("mapping length overflow")?;
            if end > self.authorization.bytes {
                bail!("mapping exceeds its signed length");
            }
            // Keep only one bounded line and the destination index. Even a
            // signed manifest cannot bypass the receiver's entry budget or
            // consume memory proportional to unbounded source/display fields.
            for part in data.split_inclusive(|byte| *byte == b'\n') {
                if self.line.len() + part.len() > CHUNK_BYTES {
                    bail!("restricted mapping line exceeds 1 MiB");
                }
                self.line.extend_from_slice(part);
                if part.ends_with(b"\n") {
                    self.finish_line()?;
                }
            }
            self.hasher.update(data);
            self.received = end;
            if finish {
                if self.received != self.authorization.bytes
                    || self.hasher.finalize().as_bytes() != &self.authorization.digest
                {
                    bail!("mapping does not match the signed manifest");
                }
                self.finish_line()?;
                self.permissions = self.pending.take();
                self.line = Vec::new();
            }
            Ok(())
        })();
        if result.is_err() {
            self.pending = None;
            self.line = Vec::new();
        }
        result
    }

    pub(crate) fn permissions(&self) -> Result<&Permissions> {
        self.permissions
            .as_ref()
            .context("the signed mapping must be verified before filesystem access")
    }
}

pub(crate) const CHUNK_BYTES: usize = 1024 * 1024;

pub(crate) fn send(contents: &[u8], connection: &mut dyn crate::conn::Conn) -> Result<()> {
    let mut offset = 0;
    loop {
        let end = (offset + CHUNK_BYTES).min(contents.len());
        let finish = end == contents.len();
        crate::conn::ok(
            connection.call(crate::proto::Request::MappingChunk {
                offset: offset as u64,
                data: contents[offset..end].to_vec(),
                finish,
            })?,
            "admit mapping manifest",
        )?;
        if finish {
            return Ok(());
        }
        offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(src: &str, dst: &str) -> String {
        format!(
            r#"{{"src":{{"encoding":"utf-8","value":"{src}"}},"dst":{{"encoding":"utf-8","value":"{dst}"}}}}
"#
        )
    }

    #[test]
    fn signed_mapping_admits_large_manifests_and_exact_destinations() {
        let contents: String = (0..12_000)
            .map(|i| entry("source", &format!("nested/file-{i}")))
            .collect();
        assert!(contents.len() > CHUNK_BYTES);
        let mut admission =
            Admission::new(Authorization::from_contents(contents.as_bytes()), 20_000);
        assert!(admission.permissions().is_err());
        let chunks: Vec<_> = contents.as_bytes().chunks(CHUNK_BYTES).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            admission
                .append((i * CHUNK_BYTES) as u64, chunk, i + 1 == chunks.len())
                .unwrap();
        }
        let permissions = admission.permissions().unwrap();
        assert!(permissions.allows(b"nested/file-11999", Some(false)));
        assert!(permissions.allows(b"nested", Some(true)));
        assert!(!permissions.allows(b"nested", Some(false)));
        assert!(!permissions.allows(b"nested/unlisted", Some(false)));
        assert!(!permissions.allows(b"nested/file-1/child", Some(true)));
        assert!(admission.append(0, b"", true).is_err());
    }

    #[test]
    fn signed_mapping_rejects_changed_truncated_reordered_and_excess_input() {
        let contents = entry("source", "destination");
        let authorization = Authorization::from_contents(contents.as_bytes());
        let mut admission = Admission::new(authorization.clone(), 10);
        assert!(admission.append(1, contents.as_bytes(), true).is_err());
        assert!(admission.append(0, contents.as_bytes(), true).is_err());
        let mut admission = Admission::new(authorization.clone(), 10);
        assert!(admission
            .append(0, &contents.as_bytes()[..10], true)
            .is_err());
        let mut admission = Admission::new(authorization.clone(), 10);
        let altered = contents.replace("source", "forged");
        assert!(admission.append(0, altered.as_bytes(), true).is_err());
        let mut admission = Admission::new(authorization, 10);
        assert!(admission
            .append(0, (contents + "extra").as_bytes(), true)
            .is_err());
        assert!(admission.permissions().is_err());
    }

    #[test]
    fn signed_mapping_bounds_index_and_line_memory() {
        let contents = entry("a", "parent/one") + &entry("b", "parent/two");
        let mut admission = Admission::new(Authorization::from_contents(contents.as_bytes()), 3);
        assert!(admission.append(0, contents.as_bytes(), true).is_err());
        assert!(admission.permissions().is_err());
        let long_path = entry("a", &"a/".repeat(2500));
        let mut admission =
            Admission::new(Authorization::from_contents(long_path.as_bytes()), 10_000);
        assert!(admission.append(0, long_path.as_bytes(), true).is_err());
        assert!(admission.permissions().is_err());
        let oversized = vec![b' '; CHUNK_BYTES + 1];
        let mut admission = Admission::new(Authorization::from_contents(&oversized), 10);
        admission
            .append(0, &oversized[..CHUNK_BYTES], false)
            .unwrap();
        assert!(admission
            .append(CHUNK_BYTES as u64, &oversized[CHUNK_BYTES..], true)
            .is_err());
        assert!(admission.permissions().is_err());
        for contents in [
            entry("a", "parent/child")
                + &entry("b", "parent").replace("}}", "},\"kind\":\"file\"}"),
            entry("b", "parent").replace("}}", "},\"kind\":\"file\"}")
                + &entry("a", "parent/child"),
        ] {
            let mut admission =
                Admission::new(Authorization::from_contents(contents.as_bytes()), 10);
            assert!(admission.append(0, contents.as_bytes(), true).is_err());
            assert!(admission.permissions().is_err());
        }
    }

    #[test]
    fn signed_mapping_validation_precedes_any_permissions() {
        for contents in [
            entry("a", "../escape"),
            entry("a", "/absolute"),
            entry("a", "x") + &entry("b", "x"),
            "{truncated".into(),
        ] {
            let mut admission =
                Admission::new(Authorization::from_contents(contents.as_bytes()), 20_000);
            assert!(admission.append(0, contents.as_bytes(), true).is_err());
            assert!(admission.permissions().is_err());
        }
        let mut admission = Admission::new(Authorization::from_contents(b""), 10);
        admission.append(0, b"", true).unwrap();
        let permissions = admission.permissions().unwrap();
        assert!(permissions.allows(b"", Some(true)));
        assert!(!permissions.allows(b"anything", Some(false)));
    }
}
