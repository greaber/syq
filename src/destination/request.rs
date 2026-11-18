//! The machine that asks another to approve its copy: one request for every
//! route, which sends the command, its working directory and what it read
//! from files, waits for the decision, and rewrites the copy's arguments to
//! use what was approved.
use super::*;
use crate::route::Route;

/// Who approves this machine's copy.
pub(super) enum Approving {
    /// A receiving machine, by the name it registered here.
    Return {
        name: String,
        registration: Registration,
    },
    /// An SSH authorization provider, over this machine's own login to it,
    /// for a copy between two servers.
    Provider(crate::auth_from::Provider),
}

impl Approving {
    fn label(&self) -> String {
        match self {
            Self::Return { name, .. } => format!("@{name}"),
            Self::Provider(provider) => provider.label(),
        }
    }

    /// Send `asked` and read the reply within `timeout`. A receiving machine
    /// that switched to another build meanwhile is asked once more
    /// (`ask_named`).
    fn ask(
        self,
        args: &crate::cli::Args,
        asked: &approve::Asked,
        timeout: Duration,
    ) -> Result<(Self, Reply)> {
        match self {
            Self::Return { name, registration } => {
                let (registration, reply) = ask_named(&name, registration, asked, timeout)?;
                Ok((Self::Return { name, registration }, reply))
            }
            Self::Provider(provider) => {
                let reply = crate::auth_from::selected_context(
                    forward::ask_provider(args, &provider, asked.clone(), timeout),
                    &args.auth_from,
                    args.auth_from_explicit,
                )?;
                Ok((Self::Provider(provider), reply))
            }
        }
    }
}

/// What this machine asks to have approved, by route, and what it keeps to
/// use the approval.
enum Asking {
    /// A copy to a receiving machine.
    ToNamed,
    /// A copy from a receiving machine, and what it reads there.
    FromNamed(Box<crate::restricted::source::SourcePolicy>),
    /// A copy from the server `source` to this one.
    Download { source: String },
    /// A copy from this server to `target`.
    Upload { target: String },
    /// A copy from `source` to `target`, whose destination's results this
    /// machine checks with `secret`.
    Between {
        source: String,
        target: String,
        secret: crate::destination_results::RecipientSecret,
        results_key: [u8; 32],
    },
}

impl Asking {
    /// The route of `args`, refusing here, before anything is asked, what
    /// the approving machine would refuse in the command alone, and what
    /// the waiting notice calls the copy.
    fn new(args: &crate::cli::Args) -> Result<(Self, String)> {
        Ok(match crate::route::classify(args) {
            Route::ToNamed => {
                // Such as an out-of-range limit or too many sources: the
                // receiving machine derives the copy's rules the same way.
                let (_, sources) = args
                    .locations
                    .split_last()
                    .context("copy endpoints missing")?;
                crate::directive::copy_operation(args, sources, &request_path(b".")?)?;
                (Self::ToNamed, "this copy".to_owned())
            }
            // The receiving machine derives the reads the same way.
            Route::FromNamed => (
                Self::FromNamed(Box::new(send::request(args)?)),
                "sending these files".to_owned(),
            ),
            Route::Download => {
                let source = pull::eligible_target(args)?;
                let what = format!("this copy from {source}");
                (Self::Download { source }, what)
            }
            Route::Upload => {
                let target = forward::eligible_target(args)?;
                let what = format!("this copy to {target}");
                (Self::Upload { target }, what)
            }
            Route::Between => {
                let (source, target) = forward::eligible_peer(args)?;
                // Refused here as a local copy refuses it.
                crate::fsops::ensure_source_count(
                    crate::transfer::distinct_native_sources(
                        args.locations
                            .split_last()
                            .map_or(&[], |(_, sources)| sources),
                    )
                    .len(),
                )?;
                // This machine checks the destination's results itself, as
                // it would for a copy between two servers it started with
                // its own access.
                let (secret, results_key) = crate::destination_results::generate_recipient()?;
                let what = format!("this copy from {source} to {target}");
                let asking = Self::Between {
                    source,
                    target,
                    secret,
                    results_key,
                };
                (asking, what)
            }
            Route::Own => bail!("this copy has no route that another machine approves"),
        })
    }

    /// How long the approver may take: to decide, and for the copies it
    /// signs for servers, to set their accounts up.
    fn timeout(&self) -> Duration {
        let setup = match self {
            Self::ToNamed | Self::FromNamed(_) => Duration::ZERO,
            _ => forward::SETUP_TIMEOUT,
        };
        REQUEST_TIMEOUT + setup + Duration::from_secs(10)
    }

    /// Rewrite `args` to use what `approving` approved.
    fn apply(self, args: &mut crate::cli::Args, approving: Approving, reply: Reply) -> Result<()> {
        let unexpected = format!("unexpected response from {}", approving.label());
        let issued = match (self, reply, approving) {
            (
                Self::ToNamed,
                Reply::Approved(approved),
                Approving::Return { name, registration },
            ) => {
                return apply_to_named(args, &name, registration, approved);
            }
            (
                Self::FromNamed(reads),
                Reply::SendApproved(approved),
                Approving::Return { registration, .. },
            ) => return send::apply(args, &reads, *approved, registration),
            (Self::Download { source }, Reply::Signed(issued), approving) => {
                pull::apply(args, &source, *issued)?;
                approving
            }
            (Self::Upload { target }, Reply::Signed(issued), approving) => {
                forward::apply_upload(args, &target, *issued)?;
                approving
            }
            (
                Self::Between {
                    source,
                    target,
                    secret,
                    ..
                },
                Reply::Signed(issued),
                approving,
            ) => {
                forward::apply_coordinated(args, (&source, &target), secret, *issued)?;
                approving
            }
            _ => bail!(unexpected),
        };
        // The copy records the receiving machine that approved it.
        if let Approving::Return { name, .. } = issued {
            args.auth_from =
                crate::cli::AuthFrom::Provider(crate::auth_from::Provider::Return(name));
        }
        Ok(())
    }
}

/// Ask `approving` to approve this copy, then rewrite its arguments to use
/// the approval.
pub(super) fn prepare(args: &mut crate::cli::Args, approving: Approving) -> Result<()> {
    let (asking, what) = Asking::new(args)?;
    // Refused with advice before anything is asked when an approval cannot
    // carry the command.
    let command = crate::approval_command::copy_command(args)?;
    let asked = approve::Asked {
        command,
        cwd: crate::approval_command::current_directory(),
        // The rules come from the command; only what it read from files
        // travels beside it.
        inputs: crate::directive::Inputs {
            ignore: args.ignore_lines.clone(),
            mapping: crate::directive::mapping_authorization(args)?,
        },
        results_key: match &asking {
            Asking::Between { results_key, .. } => Some(*results_key),
            _ => None,
        },
    };
    notices::waiting(&approving.label(), &what);
    let (approving, reply) = approving.ask(args, &asked, asking.timeout())?;
    asking.apply(args, approving, reply)
}
