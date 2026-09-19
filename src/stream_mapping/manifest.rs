//! Whole-manifest validation, before opening any destination or callback.
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
    pub paths: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Callback {
    stream: u64,
    #[serde(default)]
    size: Option<u64>,
}

fn endpoint(value: &mut Value, id: u64, destination: bool) -> Result<Option<Endpoint>> {
    if value.get("stream").is_none() {
        return Ok(None);
    }
    let callback: Callback = serde_json::from_value(value.clone())?;
    ensure!(
        callback.stream == id,
        "callback identity must match its mapping entry index"
    );
    ensure!(
        !destination || callback.size.is_none(),
        "only stream sources may promise a size"
    );
    // Reuse the pathname parser for common fields; this placeholder is never
    // executed or emitted as an operation identity.
    *value = crate::results::tagged(b"callback");
    Ok(Some(Endpoint::Callback {
        size: callback.size,
    }))
}

pub(super) fn parse(contents: &[u8]) -> Result<Manifest> {
    let mut callbacks = Vec::new();
    let mut paths = Vec::new();
    let mut named_destinations = Vec::new();
    for (index, line) in contents.split(|&b| b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let id = index as u64;
        let parsed = (|| -> Result<()> {
            let mut record: Value = serde_json::from_slice(line)?;
            ensure!(record.is_object(), "mapping entry must be an object");
            let src = endpoint(&mut record["src"], id, false)?;
            let dst = endpoint(&mut record["dst"], id, true)?;
            let parsed = crate::mapping::parse_manifest_entry(&serde_json::to_string(&record)?)?;
            let callback = src.is_some() || dst.is_some();
            if callback {
                ensure!(
                    parsed
                        .kind
                        .is_none_or(|kind| matches!(kind, crate::mapping::DeclaredKind::File)),
                    "callback mappings carry regular-file bytes"
                );
                ensure!(
                    dst.is_none() || parsed.metadata.is_none(),
                    "destination metadata requires a pathname destination"
                );
                record["kind"] = "file".into();
                callbacks.push(Entry {
                    id,
                    src: src.unwrap_or(Endpoint::Path(parsed.src)),
                    dst: dst.clone().unwrap_or(Endpoint::Path(parsed.dst)),
                    expected_hash: parsed.expected_hash,
                    metadata: parsed.metadata,
                });
            } else {
                paths.extend_from_slice(line);
                paths.push(b'\n');
            }
            if dst.is_none() {
                named_destinations.extend(serde_json::to_vec(&record)?);
                named_destinations.push(b'\n');
            }
            Ok(())
        })();
        parsed.with_context(|| format!("--mapping line {}", index + 1))?;
    }
    if callbacks.is_empty() {
        bail!("a stream mapping session requires at least one callback entry");
    }
    // This also checks collisions between callback and ordinary destinations.
    crate::mapping::read_mapping_manifest(named_destinations)?;
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
        let ordinary = json!({"src":path("file"), "dst":path("same")});
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
        assert_eq!(parsed.paths, bytes(vec![ordinary]));
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
