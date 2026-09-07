//! SSH workers join an already redeemed copy through a private local socket.
//! The enrollment key never gains arbitrary commands or socket forwarding.

use super::RestrictedAuthority;
use crate::private_broker::{PrivateBroker, PrivateBrokerConfig};
use anyhow::{bail, Context, Result};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn start(
    state: &Path,
    authority: Arc<RestrictedAuthority>,
) -> Result<(PrivateBroker, String)> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).context("generate SSH worker admission")?;
    let broker = PrivateBroker::start_in(
        PrivateBrokerConfig {
            directory_prefix: "w-",
            socket_name: "s",
            listener_thread: "receiver-ssh",
            client_thread: "receiver-ssh-worker",
            max_connections: 128,
            io_timeout: TIMEOUT,
        },
        state,
        move |mut stream, _| {
            let result = (|| -> Result<()> {
                let deadline = Instant::now() + TIMEOUT;
                let mut offered = [0u8; 32];
                let timeout_socket = stream.try_clone()?;
                let mut remaining = offered.as_mut_slice();
                while !remaining.is_empty() {
                    timeout_socket.set_read_timeout(Some(
                        deadline
                            .checked_duration_since(Instant::now())
                            .context("SSH worker admission timed out")?,
                    ))?;
                    let count = stream.read(remaining)?;
                    if count == 0 {
                        bail!("SSH worker admission ended early");
                    }
                    remaining = &mut remaining[count..];
                }
                if !bool::from(offered.ct_eq(&secret)) {
                    bail!("invalid SSH worker admission");
                }
                let _permit = crate::server::ConnectionPermit::acquire(authority.clone())?;
                let writer = stream.try_clone()?;
                writer.set_read_timeout(Some(
                    deadline
                        .checked_duration_since(Instant::now())
                        .context("SSH worker admission timed out")?,
                ))?;
                crate::server::run_named(stream, writer, authority.clone(), false)
            })();
            // The SSH client observes a closed stream on refused admission.
            // Do not let unauthenticated clients block on diagnostic output.
            let _ = result;
        },
    )?;
    let directory = broker
        .socket_path()
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .context("SSH worker directory is not UTF-8")?;
    let secret = secret
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let ticket = format!("{directory}:{secret}");
    Ok((broker, ticket))
}

fn ticket_parts(ticket: &str) -> Result<(&str, [u8; 32])> {
    let (directory, encoded) = ticket
        .split_once(':')
        .context("invalid SSH worker ticket")?;
    if !directory.starts_with("w-")
        || directory.len() > 32
        || !directory
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || encoded.len() != 64
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid SSH worker ticket");
    }
    let mut secret = [0u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)?;
    }
    Ok((directory, secret))
}

pub(super) fn worker_command(original: &str) -> Result<Option<String>> {
    if original.len() > 128 * 1024 {
        bail!("restricted receiver command exceeds size limit");
    }
    let words = shell_words::split(original).context("parse restricted receiver command")?;
    if words.len() == 3 && words[0] == "syq" && words[1] == "--server" {
        if let Some(ticket) = words[2].strip_prefix("--restricted-worker=") {
            ticket_parts(ticket)?;
            return Ok(Some(ticket.to_owned()));
        }
    }
    Ok(None)
}

pub(super) fn connect(state: &Path, ticket: &str) -> Result<()> {
    let (directory, secret) = ticket_parts(ticket)?;
    super::active::require_not_revoked(state)?;
    let directory = state.join(directory);
    crate::delegation::validate_private_directory_path(&directory)?;
    let mut socket =
        UnixStream::connect(directory.join("s")).context("join live restricted copy")?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    socket.write_all(&secret)?;
    socket.set_write_timeout(None)?;
    let mut input_socket = socket.try_clone()?;
    std::thread::Builder::new()
        .name("receiver-ssh-input".into())
        .spawn(move || {
            let _ = pump(&mut io::stdin().lock(), &mut input_socket);
            let _ = input_socket.shutdown(Shutdown::Write);
        })?;
    // StdoutLock is line buffered. A short binary Hello reply may contain no
    // newline, so buffering it would deadlock both ends of the handshake.
    let mut output = std::fs::File::from(io::stdout().as_fd().try_clone_to_owned()?);
    let result = pump(&mut socket, &mut output);
    let _ = socket.shutdown(Shutdown::Both);
    result.context("relay restricted SSH worker")?;
    Ok(())
}

// Forward each available chunk immediately, including short binary handshakes.
fn pump(input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    let mut bytes = [0; 64 * 1024];
    loop {
        let count = match input.read(&mut bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(());
        }
        output.write_all(&bytes[..count])?;
        output.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ConnectionRole, FrameReader, FrameWriter, Request, Response};
    use std::os::unix::ffi::OsStrExt;

    fn worker(
        broker: &PrivateBroker,
        ticket: &str,
        role: ConnectionRole,
    ) -> Result<(FrameReader<UnixStream>, FrameWriter<UnixStream>)> {
        let (_, secret) = ticket_parts(ticket)?;
        let mut socket = UnixStream::connect(broker.socket_path())?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.write_all(&secret)?;
        let mut writer = FrameWriter::new(socket.try_clone()?, false);
        writer.write_msg(&Request::Hello {
            identity: crate::identity::build().into(),
            compress: false,
            debug: false,
            token: Vec::new(),
            role,
        })?;
        let mut reader = FrameReader::new(socket);
        match reader.read_msg::<Response>()? {
            Response::HelloOk {
                ssh_worker_ticket: None,
                ..
            } => Ok((reader, writer)),
            response => bail!("worker refused: {response:?}"),
        }
    }
    fn role() -> ConnectionRole {
        ConnectionRole::DestinationWorker {
            destination: None,
            copy_sources: Vec::new(),
        }
    }

    #[test]
    fn ssh_workers_share_limits_scope_and_control_lifetime() {
        let root = crate::test_support::tempdir().unwrap();
        std::fs::create_dir(root.path().join("target")).unwrap();
        let mut authority = super::super::tests::tcp_test_authority(root.path());
        authority.copy.options.compressed_transport = false;
        let authority = Arc::new(authority);
        let (broker, ticket) = start(root.path(), authority.clone()).unwrap();
        assert!(worker(&broker, &ticket, ConnectionRole::Control).is_err());
        let (_, secret) = ticket_parts(&ticket).unwrap();
        let wrong = format!(
            "{}:{}",
            ticket.split_once(':').unwrap().0,
            secret
                .iter()
                .map(|byte| format!("{:02x}", byte ^ 1))
                .collect::<String>()
        );
        assert!(worker(&broker, &wrong, role()).is_err());
        let (mut first_reader, mut first_writer) = worker(&broker, &ticket, role()).unwrap();
        let (mut second_reader, mut second_writer) = worker(&broker, &ticket, role()).unwrap();
        assert!(worker(&broker, &ticket, role()).is_err());
        let prepare = |name: &str, size| Request::Prepare {
            path: root.path().join(name).as_os_str().as_bytes().to_vec(),
            size,
            inplace: false,
            copy_id: [1; 16],
            mode: 0o600,
            attempt: 0,
            create_if_missing: true,
            guard: None,
        };
        first_writer.write_msg(&prepare("target/a", 1024)).unwrap();
        assert!(!matches!(
            first_reader.read_msg::<Response>().unwrap(),
            Response::Err(_)
        ));
        second_writer.write_msg(&prepare("target/b", 1)).unwrap();
        assert!(
            matches!(second_reader.read_msg::<Response>().unwrap(), Response::Err(message) if message.contains("byte"))
        );
        second_writer.write_msg(&prepare("outside", 1)).unwrap();
        assert!(matches!(
            second_reader.read_msg::<Response>().unwrap(),
            Response::Err(_)
        ));
        assert!(!root.path().join("outside").exists());
        second_writer.write_msg(&Request::Receipt).unwrap();
        assert!(matches!(
            second_reader.read_msg::<Response>().unwrap(),
            Response::Err(_)
        ));
        authority.close_control();
        assert!(worker(&broker, &ticket, role()).is_err());
        first_writer.write_msg(&prepare("target/c", 1)).unwrap();
        assert!(matches!(
            first_reader.read_msg::<Response>().unwrap(),
            Response::Err(_)
        ));
        let socket_path = broker.socket_path().to_path_buf();
        drop(broker);
        assert!(!socket_path.exists());
        assert!(first_reader.read_msg::<Response>().is_err());
    }

    #[test]
    fn worker_command_accepts_only_a_bounded_enrollment_local_ticket() {
        let secret = "ab".repeat(32);
        let valid = format!("syq --server --restricted-worker=w-Ab1234:{secret}");
        assert!(worker_command(&valid).unwrap().is_some());
        for directory in ["../other", "/tmp/socket", "w-../../escape", "w-:", "w-\\x"] {
            assert!(worker_command(&format!(
                "syq --server {}",
                shell_words::quote(&format!("--restricted-worker={directory}:{secret}"))
            ))
            .is_err());
        }
        for command in [
            "sh",
            "syq --server --restricted-worker=x",
            "syq --server --restricted-worker=w-a:00",
        ] {
            assert!(!matches!(worker_command(command), Ok(Some(_))));
        }
        assert!(worker_command(&format!("{valid} extra")).unwrap().is_none());
    }
}
