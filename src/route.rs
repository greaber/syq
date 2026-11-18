//! Which route a copy takes, as its endpoints show, and the options each
//! route that another machine approves refuses. The machine that asks, the
//! machine that approves and the directive's checks all classify a command
//! here, so they agree on its route.
use crate::cli::{Args, CoordinateAt, Location, PeerAuth};
use anyhow::{bail, Result};

/// The route a copy's endpoints give it when another machine approves it.
/// A command that names a receiving machine (`@NAME`) is classified by that
/// name first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    /// No approved route fits: both ends are on this machine, or a copy to
    /// a server reads this machine's files before a server's. Only this
    /// machine's own connections run it.
    Own,
    /// To a receiving machine, `--to @NAME`.
    ToNamed,
    /// From a receiving machine, `--from @NAME`.
    FromNamed,
    /// From this machine to one server.
    Upload,
    /// From a server to this machine.
    Download,
    /// From one server to another.
    Between,
}

fn named(location: &Location) -> bool {
    location
        .host
        .as_deref()
        .is_some_and(|host| host.starts_with('@'))
}

/// The route of `args`, from its endpoints alone. The checks of each route
/// (`refuse_options` and the route's own) decide whether it can carry them.
pub(crate) fn classify(args: &Args) -> Route {
    let Some((destination, sources)) = args.locations.split_last() else {
        return Route::Own;
    };
    if sources.iter().any(named) {
        return Route::FromNamed;
    }
    if named(destination) {
        return Route::ToNamed;
    }
    if destination.is_remote() {
        if sources.first().is_some_and(Location::is_remote) {
            Route::Between
        } else if sources.iter().all(|source| !source.is_remote()) {
            Route::Upload
        } else {
            Route::Own
        }
    } else if sources.iter().any(Location::is_remote) {
        Route::Download
    } else {
        Route::Own
    }
}

/// A command option a route can refuse.
#[derive(Clone, Copy, Debug)]
enum Opt {
    Rsh,
    SyqPath,
    NoBootstrap,
    Detach,
    /// Derived from `--coordinate-at local`.
    Relay,
    /// Internal: an approval already chose the route.
    RestrictedGrant,
    PeerAuth,
    /// `--coordinate-at` other than these.
    CoordinateAt(&'static [CoordinateAt]),
    NoTcpEncryption,
}

impl Opt {
    fn given(self, args: &Args) -> bool {
        match self {
            Opt::Rsh => args.rsh.is_some(),
            Opt::SyqPath => args.syq_path.is_some(),
            Opt::NoBootstrap => args.no_bootstrap,
            Opt::Detach => args.detach,
            Opt::Relay => args.relay,
            Opt::RestrictedGrant => args.restricted_grant.is_some(),
            Opt::PeerAuth => args.peer_auth != PeerAuth::Restricted,
            Opt::CoordinateAt(allowed) => !allowed.contains(&args.coordinate_at),
            Opt::NoTcpEncryption => args.no_tcp_encryption,
        }
    }
}

const AUTO: &[CoordinateAt] = &[CoordinateAt::Auto];
const AUTO_OR_SOURCE: &[CoordinateAt] = &[CoordinateAt::Auto, CoordinateAt::Src];

/// The options a route refuses, and the one message that refuses them.
struct Refusal {
    options: &'static [Opt],
    message: &'static str,
}

/// What each approved route refuses. `Own` refuses nothing here.
fn refusal(route: Route) -> Option<Refusal> {
    use Opt::*;
    let (options, message): (&'static [Opt], _) = match route {
        Route::Own => return None,
        Route::ToNamed => (
            &[SyqPath, Rsh, Detach, RestrictedGrant, NoTcpEncryption, PeerAuth],
            "named destinations own their connection; --syq-path, --rsh, --detach, --peer-auth, and --no-tcp-encryption cannot be combined with them",
        ),
        Route::FromNamed => (
            &[
                Rsh,
                SyqPath,
                Detach,
                RestrictedGrant,
                NoTcpEncryption,
                PeerAuth,
                CoordinateAt(AUTO),
            ],
            "copies from receiving machines own their connection; --rsh, --syq-path, --detach, --peer-auth, --coordinate-at, and --no-tcp-encryption cannot be combined with them",
        ),
        Route::Upload => (
            &[
                Rsh,
                SyqPath,
                NoBootstrap,
                Detach,
                RestrictedGrant,
                PeerAuth,
                CoordinateAt(AUTO),
            ],
            "return authorization owns its SSH connection; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --detach, --peer-auth, or --coordinate-at",
        ),
        Route::Download => (
            &[
                Rsh,
                SyqPath,
                NoBootstrap,
                Detach,
                RestrictedGrant,
                PeerAuth,
                CoordinateAt(AUTO),
            ],
            "a copy from another server that a receiving machine approves reads it through that server's restricted receiver; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --detach, --peer-auth, or --coordinate-at",
        ),
        Route::Between => (
            &[
                Rsh,
                SyqPath,
                NoBootstrap,
                Detach,
                Relay,
                RestrictedGrant,
                PeerAuth,
                CoordinateAt(AUTO_OR_SOURCE),
            ],
            "a copy between two servers approved by another machine runs on the source with the destination's restricted receiver; it cannot be combined with --rsh, --syq-path, --no-bootstrap, --detach, --peer-auth or --coordinate-at local or dst",
        ),
    };
    Some(Refusal { options, message })
}

/// Refuse the options `route` cannot carry, with its message.
pub(crate) fn refuse_options(route: Route, args: &Args) -> Result<()> {
    if let Some(refusal) = refusal(route) {
        if refusal.options.iter().any(|option| option.given(args)) {
            bail!(refusal.message);
        }
    }
    Ok(())
}

/// The options that keep a copy from an account connection a provider
/// approved: it runs over this machine's own SSH, as the command states it.
const ACCOUNT_ACCESS: &[Opt] = &[
    Opt::Rsh,
    Opt::Detach,
    Opt::RestrictedGrant,
    Opt::PeerAuth,
    Opt::CoordinateAt(AUTO),
];

/// Whether `args` states an option that keeps it from an approved account
/// connection.
pub(crate) fn refuses_account_access(args: &Args) -> bool {
    ACCOUNT_ACCESS.iter().any(|option| option.given(args))
}

#[cfg(test)]
mod tests;
