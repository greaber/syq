//! End-to-end enrollment and signed restricted-transfer integration.

use crate::cli::{Args, Existence, Location, Placement};
use crate::delegation::{
    self, CopyLimits, CopyOperation, CopyOptions, CopyPolicy, DeletionPolicy, DestinationPlacement,
    DirectoryWidening, ExistingDestinationPolicy, FilterPolicy, Grant, GrantConstraints,
    GrantOperation, MutationScope, PublicationPolicy, RequestId, RootExistence,
};
use crate::enrollment::{
    self, AuthorizedKeyEntry, AuthorizedKeysChange, EnrollmentId, EnrollmentPublicKey,
    EnrollmentRoute, SshEndpoint,
};
use crate::proto::{self, Op, Request};
use crate::rooted::{RelativePath, Root, RootIdentity, RootMetadata};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use ssh_key::private::Ed25519Keypair;
use ssh_key::{LineEnding, PrivateKey};
use std::collections::{HashMap, HashSet};
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
mod keys;
mod privilege;
mod receiver;
pub(crate) mod source;
mod ssh;
mod statefs;
mod temporary_key;

pub(crate) use keys::parse_entry_key;
pub(crate) use temporary_key::TemporaryKey;

pub(crate) use authority::*;
use enroll::*;
pub(crate) use grant::*;
pub(crate) use install::*;
use keys::*;
pub(crate) use privilege::{
    privileged_receiver_message, refuse_privileged_approved_receiver, refuse_privileged_receiver,
};
pub(crate) use receiver::*;
pub(crate) use ssh::start as start_ssh_workers;
use statefs::*;

// Generation 7: one enrollment per account, whose grants the user's own login
// key signs. Released enrollments (generations 3 to 6, from v0.4.0 to v0.7.1)
// keep their state in other directories; this build never reads them.
const CONFIG_VERSION: u16 = 7;

/// Where an enrolled server keeps each enrollment's protected state, below
/// the account's home directory.
const SERVER_STATE: [&str; 4] = [".local", "share", "syq", "enrollments"];
/// Where the enrolling machine keeps its enrollments, below its home.
const LOCAL_STATE: [&str; 4] = [".local", "state", "syq", "enrollments"];

const MAX_STATE_FILE: usize = 256 * 1024;
const MAX_AUTHORIZED_KEYS: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES: u64 = 100_000_000;
const DEFAULT_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;
/// A grant must be redeemed within this long of being issued.
const GRANT_VALIDITY_SECONDS: i64 = 24 * 60 * 60;
/// A transfer must finish within this long of its grant being issued.
const FINISH_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;
const CLOCK_SKEW_SECONDS: i64 = 60;

/// An enrollment's protected state on the server, in
/// `~/.local/share/syq/enrollments/<id>/config.json`. It records no device
/// or inode: each copy resolves its destination when it starts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ReceiverEnrollment {
    version: u16,
    pub(crate) id: EnrollmentId,
    pub(crate) target_login: String,
    /// Raised each time syq's `authorized_keys` line changes. The line starts
    /// the receiver with the generation it was written for, and a receiver
    /// started for another generation refuses new copies.
    pub(crate) generation: u64,
    /// The build of the receiver the line runs.
    pub(crate) release: String,
    pub(crate) receiver_path: String,
    pub(crate) entry_public_key: String,
    /// The login key that signs this enrollment's grants.
    pub(crate) signer: delegation::TrustedSigner,
}

/// The enrolling machine's request to set up or refresh an enrollment, sent
/// over the user's own login to a staged copy of its syq.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    entry_public_key: String,
    signer: delegation::TrustedSigner,
    /// The enrollment exists already: its server state must still be there.
    refresh: bool,
    /// An enrollment whose server state was lost, which this one replaces.
    /// Its line goes when its state is still missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replaces: Option<ReplacedEnrollment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReplacedEnrollment {
    id: EnrollmentId,
    entry_public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
enum InstallResponse {
    Installed {
        version: u16,
        id: EnrollmentId,
        target_login: String,
        remote_home: String,
        generation: u64,
        release: String,
        receiver_path: String,
        /// The server's own key for the header of its results.
        results_public_key: String,
        /// Whether the line or state changed.
        changed: bool,
    },
    /// A refresh found no server state: nothing changed, and the enrolling
    /// machine enrolls under a new ID instead of re-creating the old one.
    StateMissing { version: u16, id: EnrollmentId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RevokeRequest {
    version: u16,
    id: EnrollmentId,
    target_login: String,
    entry_public_key: String,
}

/// An enrollment on the enrolling machine, in
/// `~/.local/state/syq/enrollments/<id>/enrollment.json`, beside its entry key.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    target_login: String,
    remote_home: String,
    generation: u64,
    release: String,
    receiver_path: String,
    results_public_key: String,
    signer: delegation::TrustedSigner,
    /// The login key's unencrypted key file, for signing without an agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_file: Option<PathBuf>,
}

/// An enrollment whose installation has started but not yet been confirmed,
/// in `pending.json` beside its entry key. A later enrollment retries it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingEnrollment {
    version: u16,
    id: EnrollmentId,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    target_login: String,
}

pub(crate) struct PreparedTransfer {
    /// The entry key, which the coordinating server uses for every SSH
    /// connection to the receiver.
    pub(crate) entry_key: PrivateKey,
    /// The destination as the grant names it.
    pub(crate) destination: Vec<u8>,
    pub(crate) grant: String,
    pub(crate) enrollment_id: EnrollmentId,
    /// The nonce the grant was signed with; the results must name it.
    pub(crate) request_id: RequestId,
    /// Verifier for the header of hostB's results.
    pub(crate) results_public_key: String,
    /// This copy's recipient key for hostB's results, named in the grant.
    pub(crate) recipient_secret: crate::destination_results::RecipientSecret,
    pub(crate) grant_digest: [u8; 32],
}

#[cfg(test)]
pub(crate) mod tests;
