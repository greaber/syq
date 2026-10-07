//! Command-restricted receivers run only as an ordinary account. A sender the
//! receiver does not trust could otherwise use root's powers: setting any
//! owner, creating device files, or writing privileged attributes.

use super::*;

/// Why a command-restricted receiver does not run for a root account, with
/// how to remove `enrollment` when one exists for it.
pub(crate) fn privileged_receiver_message(enrollment: Option<&str>) -> String {
    let mut message = "command-restricted receivers do not run as root or with root's capabilities; copy through this machine with --coordinate-at local, or enroll an ordinary account on the destination (--peer-auth broker would give the source host root's authority on the destination)".to_owned();
    if let Some(enrollment) = enrollment {
        message.push_str(&format!(
            "; `syq receiver revoke {enrollment}` removes this root enrollment"
        ));
    }
    message
}

/// Refuse to act as a command-restricted receiver as root or, on Linux, with
/// any effective capability. `enrollment` names the enrollment this
/// receiver serves, when one exists.
pub(crate) fn refuse_privileged_receiver(enrollment: Option<&str>) -> Result<()> {
    if privileged(unsafe { libc::geteuid() }, effective_capabilities()?) {
        bail!(privileged_receiver_message(enrollment));
    }
    Ok(())
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
#[cfg(any(target_os = "linux", test))]
pub(super) fn parse_effective_capabilities(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
}
