//! Recognize OpenSSH authentication refusals without changing its SSH options.
use std::io::{Read, Write};
use std::process::ChildStderr;
use std::sync::mpsc::{self, Receiver};

pub(super) fn capture(mut stderr: ChildStderr) -> Receiver<bool> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
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
                    let _ = send.send(false);
                    return;
                }
            }
        }
        let _ = send.send(authentication_failed(&tail));
    });
    receive
}

fn authentication_failed(stderr: &[u8]) -> bool {
    // Exit 255 also covers timeouts, host-key failures, and configuration errors.
    // Only positive evidence of rejected credentials permits fallback. OpenSSH
    // emits these diagnostics in English; suppressed/unrecognized diagnostics
    // leave the original error in place. An explicit --auth-from remains usable.
    let text = String::from_utf8_lossy(stderr);
    let Some(last) = text.lines().rev().map(str::trim).find(|line| {
        !line.is_empty()
            && !["debug1: ", "debug2: ", "debug3: "]
                .iter()
                .any(|prefix| line.starts_with(prefix))
            && !line.starts_with("Disconnected from ")
    }) else {
        return false;
    };
    if last.starts_with("Received disconnect from ")
        && last.ends_with(": Too many authentication failures")
    {
        return true;
    }
    last.rsplit_once(": Permission denied (")
        .is_some_and(|(_, methods)| {
            methods.strip_suffix(").").is_some_and(|methods| {
                !methods.is_empty()
                    && methods
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b",-_.@".contains(&byte))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_authentication_refusals_but_not_transport_or_host_trust_failures() {
        for diagnostic in [
            "user@host: Permission denied (publickey).\r\n",
            "debuguser@host: Permission denied (publickey).",
            "debug1: offering key\nuser@host: Permission denied (publickey,password).\n",
            "Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures\nDisconnected from 127.0.0.1 port 22\n",
        ] {
            assert!(authentication_failed(diagnostic.as_bytes()), "{diagnostic}");
        }
        for diagnostic in [
            "",
            "Host key verification failed.",
            "ssh: connect to host host port 22: Permission denied",
            "ssh: connect to host host port 22: Connection timed out",
            "Connection timed out during banner exchange",
            "user@host: Permission denied (publickey).\nConnection to host timed out",
            "ssh: Could not resolve hostname host: Name or service not known",
        ] {
            assert!(
                !authentication_failed(diagnostic.as_bytes()),
                "{diagnostic}"
            );
        }
    }
}
