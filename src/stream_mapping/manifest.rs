//! Whole-manifest validation, before opening any destination or callback.
use crate::mapping::{DeclaredKind, ManifestEntry, ParsedManifest, WireEntry, WirePath};
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub(super) enum Endpoint {
    Path(Vec<u8>),
    Callback { size: Option<u64> },
}
impl Endpoint {
    pub fn path(&self) -> Option<&[u8]> {
        match self {
            Self::Path(path) => Some(path),
            _ => None,
        }
    }
    pub fn callback(&self) -> bool {
        matches!(self, Self::Callback { .. })
    }
    pub fn json(&self, id: u64) -> Value {
        match self {
            Self::Path(path) => json!({"path": crate::results::tagged(path)}),
            Self::Callback { .. } => json!({"entry": id, "callback": true}),
        }
    }
}
#[derive(Clone, Debug)]
pub(super) struct Entry {
    pub id: u64,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub expected_hash: Option<crate::hashing::Digest>,
    pub metadata: Option<crate::mapping::Metadata>,
}
pub(super) struct Manifest {
    pub callbacks: Vec<Entry>,
    pub paths: ParsedManifest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Callback {
    stream: u64,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireEndpoint {
    Path(WirePath),
    Stream(Callback),
}
impl WireEndpoint {
    fn decode(self, id: u64, destination: bool) -> Result<Endpoint> {
        match self {
            Self::Path(path) => Ok(Endpoint::Path(path.decode(if destination {
                "dst"
            } else {
                "src"
            })?)),
            Self::Stream(stream) => {
                ensure!(
                    stream.stream == id,
                    "stream identity must match its mapping entry index"
                );
                ensure!(
                    !destination || stream.size.is_none(),
                    "only stream sources may promise a size"
                );
                Ok(Endpoint::Callback { size: stream.size })
            }
        }
    }
}

pub(super) fn parse(contents: &[u8]) -> Result<Manifest> {
    let mut callbacks = Vec::new();
    let mut paths = Vec::new();
    let mut entries = Vec::new();
    for (index, line) in contents.split(|&b| b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let id = index as u64;
        let parsed = (|| -> Result<()> {
            let record: WireEntry<WireEndpoint> = serde_json::from_slice(line)?;
            let kind = record.validate()?;
            let src = record.src.decode(id, false)?;
            let dst = record.dst.decode(id, true)?;
            if src.callback() || dst.callback() {
                ensure!(
                    kind.is_none_or(|kind| matches!(kind, DeclaredKind::File)),
                    "stream mappings carry regular-file bytes"
                );
                ensure!(
                    !dst.callback() || record.metadata.is_none(),
                    "destination metadata requires a pathname destination"
                );
                callbacks.push(Entry {
                    id,
                    src,
                    dst,
                    expected_hash: record.expected_hash,
                    metadata: record.metadata,
                });
            } else {
                let (Endpoint::Path(src), Endpoint::Path(dst)) = (src, dst) else {
                    unreachable!()
                };
                entries.push((
                    id + 1,
                    ManifestEntry {
                        src,
                        dst,
                        kind,
                        expected_hash: record.expected_hash,
                        metadata: record.metadata,
                    },
                ));
                paths.extend_from_slice(line);
                paths.push(b'\n');
            }
            Ok(())
        })();
        parsed.with_context(|| format!("--mapping line {}", index + 1))?;
    }
    if callbacks.is_empty() {
        bail!("a stream mapping session requires at least one stream entry");
    }
    crate::mapping::validate_destinations(
        entries
            .iter()
            .map(|(line, entry)| (*line, entry.dst.as_slice(), entry.kind))
            .chain(callbacks.iter().filter_map(|entry| {
                entry
                    .dst
                    .path()
                    .map(|path| (entry.id + 1, path, Some(DeclaredKind::File)))
            })),
    )?;
    let paths = crate::mapping::parsed_manifest(paths, entries, None)?;
    Ok(Manifest { callbacks, paths })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(name: &str) -> Value {
        json!({"encoding":"utf-8", "value":name})
    }
    fn bytes(entries: Vec<Value>) -> Vec<u8> {
        entries
            .into_iter()
            .flat_map(|entry| {
                let mut line = serde_json::to_vec(&entry).unwrap();
                line.push(b'\n');
                line
            })
            .collect()
    }
    #[test]
    fn preflight_catches_collisions_across_path_and_callback_entries() {
        let ordinary = json!({"src":path("file"), "dst":path("same"), "kind":"file"});
        let callback = json!({"src":{"stream":1}, "dst":path("same/child")});
        assert!(parse(&bytes(vec![ordinary, callback])).is_err());
        assert!(parse(&bytes(vec![
            json!({"src":{"stream":1}, "dst":path("file")})
        ]))
        .is_err());
    }
    #[test]
    fn callbacks_keep_identity_metadata_and_promised_size_separate_from_paths() {
        let ordinary = json!({"src":path("a"), "dst":path("b")});
        let callback =
            json!({"src":{"stream":1,"size":0},"dst":path("archive"),"metadata":{"mode":416}});
        let parsed = parse(&bytes(vec![ordinary.clone(), callback])).unwrap();
        assert_eq!(parsed.paths.input.contents, bytes(vec![ordinary]));
        assert_eq!(parsed.callbacks.len(), 1);
        assert_eq!(parsed.callbacks[0].id, 1);
        assert!(matches!(
            parsed.callbacks[0].src,
            Endpoint::Callback { size: Some(0) }
        ));
        assert_eq!(parsed.callbacks[0].metadata.unwrap().mode, Some(416));
        assert!(parse(&bytes(vec![
            json!({"src":path("a"),"dst":{"stream":0},"metadata":{"mode":416}})
        ]))
        .is_err());
    }
}
