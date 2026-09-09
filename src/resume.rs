//! Fresh identity shared by the workers of one copy invocation.

pub fn fresh_copy_id() -> anyhow::Result<crate::proto::CopyId> {
    let mut id = [0; 16];
    getrandom::fill(&mut id)
        .map_err(|error| anyhow::anyhow!("generate partial identity: {error}"))?;
    Ok(id)
}
