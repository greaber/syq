//! Explicit destination attributes, independent of source identity and size.

use crate::proto::{flags, Kind, Meta};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Metadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_nsec: Option<u32>,
}

impl Metadata {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.mode.is_none_or(|mode| mode <= 0o7777),
            "metadata.mode must contain permission bits only (0..4095)"
        );
        ensure!(
            self.uid != Some(u32::MAX),
            "metadata.uid cannot be the reserved ID 4294967295"
        );
        ensure!(
            self.gid != Some(u32::MAX),
            "metadata.gid cannot be the reserved ID 4294967295"
        );
        ensure!(
            self.mtime_nsec.is_none_or(|ns| ns < 1_000_000_000),
            "metadata.mtime_nsec must be in 0..999999999"
        );
        ensure!(
            self.mtime_nsec.is_none() || self.mtime.is_some(),
            "metadata.mtime_nsec requires metadata.mtime"
        );
        Ok(())
    }

    pub(crate) fn validate_kind(&self, kind: Kind) -> Result<()> {
        ensure!(
            kind != Kind::Symlink || self.mode.is_none(),
            "metadata.mode cannot be applied to a symlink"
        );
        Ok(())
    }

    pub(crate) fn flags(&self) -> u8 {
        let mut selected = 0;
        if self.mode.is_some() {
            selected |= flags::MODE;
        }
        if self.uid.is_some() {
            selected |= flags::OWNER;
        }
        if self.gid.is_some() {
            selected |= flags::GROUP;
        }
        if self.mtime.is_some() {
            selected |= flags::TIMES;
        }
        selected
    }

    /// Application flags also distinguish explicit ownership from preservation.
    pub(crate) fn apply_flags(&self) -> u8 {
        self.flags()
            | if self.uid.is_some() {
                flags::REQUIRE_OWNER
            } else {
                0
            }
            | if self.gid.is_some() {
                flags::REQUIRE_GROUP
            } else {
                0
            }
    }

    pub(crate) fn apply(&self, meta: &mut Meta) {
        if let Some(mode) = self.mode {
            meta.mode = mode;
        }
        if let Some(uid) = self.uid {
            meta.uid = uid;
        }
        if let Some(gid) = self.gid {
            meta.gid = gid;
        }
        if let Some(mtime) = self.mtime {
            meta.mtime = mtime;
            meta.mtime_nsec = self.mtime_nsec.unwrap_or(0);
        }
    }
}
