//! End-to-end enrollment and signed restricted-transfer integration.

use crate::cli::{Args, Existence, Location, Placement};
use crate::delegation::{
    self, CopyLimits, CopyOperation, CopyOptions, CopyPolicy, DeletionPolicy, DestinationPlacement,
    ExistingDestinationPolicy, FilterPolicy, Grant, GrantConstraints, GrantOperation,
    MutationScope, PublicationPolicy, RequestId, RootExistence,
};
use crate::enrollment::{
    self, AuthorizedKeyEntry, AuthorizedKeysChange, EnrollmentId, EnrollmentPublicKey,
    EnrollmentRoute, SshEndpoint,
};
use crate::proto::{self, ContainerGuard, Op, Request};
use crate::rooted::{RelativePath, Root, RootIdentity, RootMetadata};
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{LineEnding, PrivateKey};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

mod active;
mod authority;
mod enroll;
mod grant;
mod install;
mod receiver;
mod ssh;
mod statefs;

pub(crate) use authority::*;
use enroll::*;
pub(crate) use grant::*;
pub(crate) use install::*;
pub(crate) use receiver::*;
pub(crate) use ssh::start as start_ssh_workers;
use statefs::*;

// Advance this generation whenever an installed receiver or its signed grant
// protocol becomes incompatible. Local metadata from another generation is
// ignored, so the next eligible copy installs a fresh receiver enrollment.
const CONFIG_VERSION: u16 = 4;
const MAX_STATE_FILE: usize = 256 * 1024;
const MAX_AUTHORIZED_KEYS: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 100_000_000;
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;
/// A grant must be redeemed within this long of being issued.
const GRANT_VALIDITY_SECONDS: i64 = 24 * 60 * 60;
/// A transfer must finish within this long of its grant being issued.
const FINISH_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ReceiverEnrollment {
    version: u16,
    pub(crate) id: EnrollmentId,
    pub(crate) target_login: String,
    pub(crate) signer: String,
    pub(crate) root: String,
    pub(crate) root_dev: u64,
    pub(crate) root_ino: u64,
    pub(crate) ssh_keygen: String,
    pub(crate) receiver_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    requested_destination: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallResponse {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    remote_home: String,
    requested_parent: String,
    canonical_root: String,
    canonical_destination: String,
    receiver_path: String,
    /// OpenSSH public key of the receipt signing key hostB generated for
    /// this enrollment; the local side verifies receipts against it.
    receipt_public_key: String,
    change: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RevokeRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    target_login: String,
    remote_home: String,
    requested_parent: String,
    canonical_root: String,
    receiver_path: String,
    receipt_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    target_login: String,
    requested_destination: String,
}

pub(crate) struct PreparedTransfer {
    pub(crate) private_key: PrivateKey,
    pub(crate) canonical_destination: Vec<u8>,
    pub(crate) grant: String,
    pub(crate) enrollment_id: EnrollmentId,
    /// The nonce the grant was signed with; the receipt must name it.
    pub(crate) request_id: RequestId,
    /// Verifier for the receipt hostB will issue.
    pub(crate) receipt_public_key: String,
    /// Attached transfers keep this ephemeral HPKE key only until settlement.
    pub(crate) receipt_recipient_secret: Option<crate::receipt::RecipientSecret>,
    pub(crate) receipt_policy: crate::receipt::ReceiptPolicy,
    pub(crate) grant_digest: [u8; 32],
}

#[cfg(test)]
pub(crate) mod tests;
