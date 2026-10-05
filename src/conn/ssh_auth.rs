//! Recognize SSH failures another authorizing machine may resolve.
use std::io::{Read, Write};
use std::process::ChildStderr;
use std::sync::mpsc::{self, Receiver};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Credentials,
    HostKey,
    Hostname,
    ConnectionRefused,
}

impl Failure {
    pub(super) fn description(self) -> &'static str {
        match self {
            Self::Credentials => "credentials were rejected",
            Self::HostKey => "host key verification failed on the source machine",
            Self::Hostname => "destination hostname could not be resolved on the source machine",
            Self::ConnectionRefused => "connection was refused",
        }
    }
}

pub(super) fn capture(mut stderr: ChildStderr) -> std::io::Result<Receiver<Option<Failure>>> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new().spawn(move || {
        // Keep diagnostics live, including partial lines, with bounded storage.
        // Successful persistent SSH connections may keep this pipe open; nobody
        // waits for the reader after a successful helper handshake.
        let mut tail = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            match stderr.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let _ = std::io::stderr().write_all(&chunk[..count]);
                    tail.extend_from_slice(&chunk[..count]);
                    if tail.len() > 8192 {
                        tail.drain(..tail.len() - 8192);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let _ = send.send(None);
                    return;
                }
            }
        }
        let _ = send.send(classify(&tail));
    })?;
    Ok(receive)
}

fn classify(stderr: &[u8]) -> Option<Failure> {
    // Exit 255 also covers timeouts and configuration errors. Only recognized
    // failures that another machine may resolve permit fallback. OpenSSH
    // emits these diagnostics in English; suppressed/unrecognized diagnostics
    // leave the original error in place. An explicit --auth-from remains usable.
    let text = String::from_utf8_lossy(stderr);
    let last = text.lines().rev().map(str::trim).find(|line| {
        !line.is_empty()
            && !["debug1: ", "debug2: ", "debug3: "]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            && !line.starts_with("Disconnected from ")
    })?;
    if last == "Host key verification failed." {
        return Some(Failure::HostKey);
    }
    if let Some(message) = last.strip_prefix("ssh: Could not resolve hostname ") {
        let (_, reason) = message.rsplit_once(": ")?;
        let reason = reason.to_ascii_lowercase();
        // DNS timeouts can also appear as a temporary resolution failure,
        // which musl's gai_strerror calls "Try again". Neither permits
        // switching authorizers under the no-timeout policy.
        return (!reason.contains("timed out")
            && !reason.contains("timeout")
            && !reason.contains("temporary")
            && reason != "try again")
            .then_some(Failure::Hostname);
    }
    if last.starts_with("ssh: connect to host ") && last.ends_with(": Connection refused") {
        return Some(Failure::ConnectionRefused);
    }
    if last.starts_with("Received disconnect from ")
        && last.ends_with(": Too many authentication failures")
    {
        return Some(Failure::Credentials);
    }
    // OpenSSH 7.4/7.5 omit the user@host prefix; 7.6 added it.
    last.strip_prefix("Permission denied (")
        .or_else(|| {
            last.rsplit_once(": Permission denied (")
                .map(|(_, methods)| methods)
        })
        .is_some_and(|methods| {
            methods.strip_suffix(").").is_some_and(|methods| {
                !methods.is_empty()
                    && methods
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b",-_.@".contains(&byte))
            })
        })
        .then_some(Failure::Credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_failures_another_authorizer_can_resolve() {
        for diagnostic in [
            // Unchanged diagnostic formats from OpenSSH's sshconnect2.c:
            // V_7_4_P1 and V_7_5_P1 userauth(), before the V_7_6_P1 prefix.
            "Permission denied (publickey).\r\n",
            "Permission denied (publickey,gssapi-keyex,gssapi-with-mic).\n",
            "user@host: Permission denied (publickey).\r\n",
            "debuguser@host: Permission denied (publickey).",
            "debug1: offering key\nuser@host: Permission denied (publickey,password).\n",
            "Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures\nDisconnected from 127.0.0.1 port 22\n",
        ] {
            assert_eq!(classify(diagnostic.as_bytes()), Some(Failure::Credentials), "{diagnostic}");
        }
        for (diagnostic, failure) in [
            ("Host key verification failed.", Failure::HostKey),
            ("ssh: connect to host host port 22: Connection refused", Failure::ConnectionRefused),
            ("ssh: Could not resolve hostname host: Name or service not known", Failure::Hostname),
            ("ssh: Could not resolve hostname host: Name does not resolve", Failure::Hostname),
            ("ssh: Could not resolve hostname host: nodename nor servname provided, or not known", Failure::Hostname),
        ] {
            assert_eq!(classify(diagnostic.as_bytes()), Some(failure), "{diagnostic}");
        }
        for diagnostic in [
            "",
            "ssh: connect to host host port 22: Permission denied",
            "ssh: connect to host host port 22: Connection timed out",
            "Connection timed out during banner exchange",
            "user@host: Permission denied (publickey).\nConnection to host timed out",
            "ssh: Could not resolve hostname host: Operation timed out",
            "ssh: Could not resolve hostname host: Temporary failure in name resolution",
            "ssh: Could not resolve hostname host: Try again",
            "Host key verification failed.\nConnection to host timed out",
        ] {
            assert_eq!(classify(diagnostic.as_bytes()), None, "{diagnostic}");
        }
    }
}
