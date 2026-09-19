//! File attributes are facts about a regular file, never about a pipe inode.
use crate::{
    cli::Args,
    proto::{flags, Meta},
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, Metadata},
    os::unix::fs::MetadataExt,
};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Policy {
    pub preserve: u8,
    pub skip_newer: bool,
    pub specials: bool,
}
impl Policy {
    pub fn new(args: &Args) -> Self {
        Self {
            preserve: if args.perms { flags::MODE } else { 0 }
                | if args.owner { flags::OWNER } else { 0 }
                | if args.group { flags::GROUP } else { 0 },
            skip_newer: args.update,
            specials: args.devices,
        }
    }
    pub fn source(self, meta: Option<Meta>) -> Result<()> {
        ensure!(!self.skip_newer || meta.is_some(),
            "--skip-newer requires a regular-file source timestamp; pipes, sockets, and devices have no payload timestamp");
        ensure!((self.preserve == 0 && !self.specials) || meta.is_some(),
            "--preserve requires regular-file source metadata; a byte stream cannot preserve a pipe, socket, or device node");
        Ok(())
    }
    pub fn output(self, regular: bool) -> Result<()> {
        ensure!(self.preserve == 0 || regular,
            "--preserve requires a regular-file destination; an output pipe, socket, or device cannot carry file metadata");
        Ok(())
    }
    pub fn newer(self, source: Option<Meta>, destination: Option<Meta>) -> bool {
        self.skip_newer
            && source
                .zip(destination)
                .is_some_and(|(src, dst)| (dst.mtime, dst.mtime_nsec) > (src.mtime, src.mtime_nsec))
    }
    pub fn apply(self, file: &File, source: Option<Meta>) -> Result<()> {
        if let Some(meta) = source {
            crate::fsops::set_meta_file(file, &meta, self.preserve | flags::TIMES)?;
        }
        Ok(())
    }
}
pub(crate) fn from_file(meta: &Metadata) -> Meta {
    Meta {
        mode: meta.mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec() as u32,
    }
}
