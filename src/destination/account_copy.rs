//! Ordinary operations use account access selected by their authorizer.
//! Narrow grants and explicit receipt requests keep their own authority.
use crate::cli::{Args, AuthFrom, CoordinateAt, Interface, Location, NativeEndpoint, PeerAuth};
use anyhow::{bail, Result};

/// Resolve a matching helper before commands consume stdin or open results.
/// Ordinary native cp already performs this in its transfer handoff.
pub(crate) fn prepare_handoff(args: &Args) -> Result<()> {
    if args.interface == Interface::NativeCp
        && args.descriptor_copy.is_none()
        && args.stream_mapping_fd.is_none()
        && args.coordinate_at != CoordinateAt::Local
    {
        return Ok(());
    }
    if args.s3.is_none()
        && !args.delegated
        && args.restricted_grant.is_none()
        && args.receiver_receipt.is_none()
        && args.rsh.is_none()
    {
        let locations = if args.locations.is_empty() {
            args.paths
                .iter()
                .map(|path| Location::parse(path))
                .collect::<Result<Vec<_>>>()?
        } else {
            args.locations.clone()
        };
        for location in locations {
            let Some(host) = location.host.filter(|host| !host.starts_with('@')) else {
                continue;
            };
            let domain = crate::persistence::Domain::select(args.pscope.as_deref())?;
            let mode = crate::auth_from::resolve(
                &domain,
                &host,
                args.auth_from_explicit.then(|| args.auth_from.clone()),
            )?;
            super::handoff::validate_account_selection(&mode)?;
            if let AuthFrom::Provider(authorizer) = mode {
                super::ssh_auth::prepare(&super::ssh::SessionRequest {
                    provider: authorizer,
                    destination: NativeEndpoint {
                        user: location.user,
                        host,
                        port: location.port,
                    },
                    tty: super::ssh::Tty::Disabled,
                    command: Vec::new(),
                })?;
            }
        }
    }
    super::handoff::finish_account_preflight();
    Ok(())
}

pub(crate) fn remote(args: &Args) -> Option<(&Location, bool)> {
    if args.interface != Interface::NativeCp
        || args.s3.is_some()
        || args.rsh.is_some()
        || args.detach
        || args.restricted_grant.is_some()
        || args.receiver_receipt.is_some()
        || args.peer_auth != PeerAuth::Restricted
        || args.coordinate_at != CoordinateAt::Auto
    {
        return None;
    }
    let (destination, sources) = args.locations.split_last()?;
    let source = sources.first()?;
    let (location, pull) = if destination.is_remote() && sources.iter().all(|s| !s.is_remote()) {
        (destination, false)
    } else if !destination.is_remote()
        && source.is_remote()
        && sources
            .iter()
            .all(|s| s.host == source.host && s.user == source.user && s.port == source.port)
    {
        (source, true)
    } else {
        return None;
    };
    if location.host.as_deref()?.starts_with('@') {
        return None;
    }
    Some((location, pull))
}

pub(super) fn select(args: &mut Args) -> Result<bool> {
    let Some((location, pull)) = remote(args) else {
        return Ok(false);
    };
    let requested = NativeEndpoint {
        user: location.user.clone(),
        host: location.host.clone().unwrap(),
        port: location.port,
    };
    let domain = crate::persistence::Domain::select(args.pscope.as_deref())?;
    let Some(cached) =
        super::ssh::persistent::select_or_connect(&domain, &requested, &args.auth_from)?
    else {
        return Ok(false);
    };
    let spec = approved_connection(args, location, &domain, cached)?;
    if pull {
        args.direct_source = Some(Box::new(spec));
    } else {
        args.direct_destination = Some(Box::new(spec));
    }
    Ok(true)
}

/// Select account authority before opening an operation's transport. Copies
/// with a narrower grant remain selected separately before transfer starts.
pub(crate) fn operation(
    location: &Location,
    args: &Args,
) -> Result<Option<crate::conn::RemoteSpec>> {
    if args.interface == Interface::NativeCp && args.coordinate_at != CoordinateAt::Local {
        return Ok(None);
    }
    approved_operation(location, args)
}

pub(crate) fn approved_operation(
    location: &Location,
    args: &Args,
) -> Result<Option<crate::conn::RemoteSpec>> {
    let Some(host) = &location.host else {
        return Ok(None);
    };
    if args.s3.is_some()
        || args.delegated
        || args.restricted_grant.is_some()
        || args.return_source.is_some()
        || args.named_receipt.is_some()
        || args.receiver_receipt.is_some()
    {
        return Ok(None);
    }
    if host.starts_with('@') {
        bail!("named receiving machines support syq cp and syq exec; use an SSH endpoint for this operation");
    }
    if args.rsh.is_some() {
        if args.auth_from_explicit && matches!(args.auth_from, AuthFrom::Provider(_)) {
            bail!("--auth-from with an authorization provider cannot be combined with --rsh");
        }
        return Ok(None);
    }
    let domain = crate::persistence::Domain::select(args.pscope.as_deref())?;
    let mode = crate::auth_from::resolve(
        &domain,
        host,
        args.auth_from_explicit.then(|| args.auth_from.clone()),
    )?;
    let requested = NativeEndpoint {
        user: location.user.clone(),
        host: host.clone(),
        port: location.port,
    };
    if let Some(cached) = super::ssh::persistent::select_or_connect(&domain, &requested, &mode)? {
        return approved_connection(args, location, &domain, cached).map(Some);
    }
    Ok(None)
}

fn approved_connection(
    args: &Args,
    location: &Location,
    domain: &crate::persistence::Domain,
    cached: super::ssh::persistent::Cached,
) -> Result<crate::conn::RemoteSpec> {
    let multiplexer = crate::conn::SshMultiplexer::approved(
        cached.control(),
        Some(cached.worker_authorization(domain)?),
    );
    let mut spec = connection(args, location, cached.endpoint(), cached.options())?;
    spec.ssh_multiplexer = Some(std::sync::Arc::new(multiplexer));
    Ok(spec)
}

fn connection(
    args: &Args,
    location: &Location,
    endpoint: &NativeEndpoint,
    options: Vec<std::ffi::OsString>,
) -> Result<crate::conn::RemoteSpec> {
    // Keep copy paths/identities in the caller's spelling. Only the transport
    // uses the approved requester-selected endpoint. Explicit -S suppresses another mux.
    let mut transport = args.clone();
    let words = std::iter::once("ssh".to_owned()).chain(
        options
            .into_iter()
            .map(|word| {
                word.into_string()
                    .map_err(|_| anyhow::anyhow!("approved SSH option is not UTF-8"))
            })
            .collect::<Result<Vec<_>>>()?,
    );
    transport.rsh = Some(shell_words::join(words));
    transport.auth_from_explicit = false;
    let mut location = location.clone();
    location.user = endpoint.user.clone();
    location.host = Some(endpoint.host.clone());
    location.port = endpoint.port;
    let crate::conn::Endpoint::Remote(spec) = crate::transfer::endpoint(&location, &transport)?
    else {
        unreachable!()
    };
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(words: &[&str]) -> Args {
        crate::approval_command::parse(
            &words
                .iter()
                .map(|word| word.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }
    #[test]
    fn account_route_accepts_both_copy_directions_and_excludes_other_authority() {
        let push = args(&[
            "cp",
            "file",
            "--to",
            "alias",
            "--as",
            "out",
            "--auth-from",
            "@laptop",
            "--no-tcp",
        ]);
        assert!(!remote(&push).unwrap().1);
        let mut pull = args(&[
            "cp",
            "--from",
            "alias",
            "file",
            "--as",
            "out",
            "--auth-from",
            "@laptop",
            "--no-tcp",
        ]);
        assert!(remote(&pull).unwrap().1);
        pull.rsh = Some("ssh -i other".into());
        assert!(remote(&pull).is_none());
        pull.rsh = None;
        pull.pscope_explicit = true;
        assert!(remote(&pull).is_some());
    }
    #[test]
    fn ordinary_account_copies_keep_native_copy_features_and_explicit_receipts_stay_narrow() {
        for words in [
            vec![
                "cp",
                "file",
                "--to",
                "alias",
                "--as",
                "out",
                "--auth-from",
                "@laptop",
                "--inplace",
                "--no-tcp",
                "--syq-path",
                "/opt/syq",
            ],
            vec![
                "cp",
                "--from",
                "alias",
                "file",
                "--as",
                "out",
                "--auth-from",
                "@laptop",
                "--inplace",
                "--no-tcp",
                "--no-bootstrap",
            ],
        ] {
            let mut args = args(&words);
            assert!(remote(&args).is_some());
            args.receiver_receipt = Some(crate::cli::ReceiptDetail::Hashes);
            assert!(remote(&args).is_none());
            args.receiver_receipt = None;
            args.restricted_grant = Some("narrow-grant".into());
            assert!(remote(&args).is_none());
        }
    }

    #[test]
    fn account_route_preserves_paths_and_does_not_add_a_second_master() {
        let args = args(&[
            "cp",
            "file",
            "--to",
            "alias",
            "--as",
            "out",
            "--auth-from",
            "@laptop",
        ]);
        let (location, _) = remote(&args).unwrap();
        let endpoint = NativeEndpoint {
            user: Some("approved".into()),
            host: "resolved".into(),
            port: Some(2222),
        };
        let spec = connection(
            &args,
            location,
            &endpoint,
            [
                "-S",
                "/tmp/socket",
                "-o",
                "ProxyCommand=false",
                "-o",
                "ControlMaster=no",
            ]
            .map(Into::into)
            .to_vec(),
        )
        .unwrap();
        assert!(spec.ssh_multiplexer.is_none());
        assert!(spec.forwarded.is_none());
        assert!(spec.restricted_grant.is_none());
        assert_eq!(spec.host, "resolved");
        assert_eq!(spec.user.as_deref(), Some("approved"));
        assert_eq!(spec.port, Some(2222));
        assert_eq!(
            args.locations.last().unwrap().host.as_deref(),
            Some("alias")
        );
        assert_eq!(spec.rsh.iter().filter(|word| *word == "-S").count(), 1);
        assert!(spec.rsh.iter().any(|word| word == "ProxyCommand=false"));
    }
}
