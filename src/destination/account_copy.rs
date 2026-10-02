//! Copies may reuse a separately approved account login. A copy never creates
//! this broader authority; without a live master it follows per-copy approval.
use crate::cli::{Args, AuthFrom, CoordinateAt, Interface, Location, NativeEndpoint, PeerAuth};
use anyhow::Result;

pub(crate) fn remote(args: &Args) -> Option<(&Location, bool)> {
    if args.interface != Interface::NativeCp
        || args.s3.is_some()
        || args.rsh.is_some()
        || args.pscope_explicit
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
    let AuthFrom::Return(authorizer) = &args.auth_from else {
        return Ok(false);
    };
    let Some((location, pull)) = remote(args) else {
        return Ok(false);
    };
    let requested = NativeEndpoint {
        user: location.user.clone(),
        host: location.host.clone().unwrap(),
        port: location.port,
    };
    let Some(cached) = super::ssh::persistent::cached(authorizer, &requested)? else {
        return Ok(false);
    };
    let spec = connection(args, location, cached.endpoint(), cached.options())?;
    if pull {
        args.direct_source = Some(Box::new(spec));
    } else {
        args.direct_destination = Some(Box::new(spec));
    }
    Ok(true)
}

fn connection(
    args: &Args,
    location: &Location,
    endpoint: &NativeEndpoint,
    options: Vec<std::ffi::OsString>,
) -> Result<crate::conn::RemoteSpec> {
    // Keep copy paths/identities in the caller's spelling. Only the transport
    // uses the laptop-resolved endpoint. Explicit -S suppresses another mux.
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
        assert!(remote(&pull).is_none());
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
