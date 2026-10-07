//! Command-restricted receivers run only as an ordinary account. A sender the
//! receiver does not trust could otherwise use root's powers: setting any
//! owner, creating device files, or writing privileged attributes.

use super::*;

/// Why an enrolled receiver for a root account refuses to run.
pub(crate) const PRIVILEGED_RECEIVER: &str = "command-restricted receivers do not run as root or with root's capabilities; enroll an ordinary account instead (`syq receiver revoke` removes a root enrollment)";

/// Refuse to act as a command-restricted receiver as root or, on Linux, with
/// any effective capability.
pub(crate) fn refuse_privileged_receiver() -> Result<()> {
    refuse_privileged(PRIVILEGED_RECEIVER)
}

/// As [`refuse_privileged_receiver`], for a receiver that copies on another
/// machine's approval, with no enrollment to replace.
pub(crate) fn refuse_privileged_approved_receiver() -> Result<()> {
    refuse_privileged(
        "copies approved by a receiving machine are not written as root or with root's capabilities; use an ordinary account",
    )
}

fn refuse_privileged(message: &'static str) -> Result<()> {
    if privileged(unsafe { libc::geteuid() }, effective_capabilities()?) {
        bail!(message);
    }
    Ok(())
}

pub(super) fn privileged(euid: u32, effective_capabilities: u64) -> bool {
    euid == 0 || effective_capabilities != 0
}

#[cfg(target_os = "linux")]
fn effective_capabilities() -> Result<u64> {
    let status = fs::read_to_string("/proc/self/status").context("read process capabilities")?;
    parse_effective_capabilities(&status).context("process status reports no capabilities")
}

#[cfg(not(target_os = "linux"))]
fn effective_capabilities() -> Result<u64> {
    Ok(0)
}

/// The effective capability set from a Linux `/proc/self/status`.
pub(super) fn parse_effective_capabilities(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
}
