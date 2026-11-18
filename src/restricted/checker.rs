//! Which end of an approved copy a session serves, and the rules it is
//! served under.

use super::source::SourceAuthority;
use super::RestrictedAuthority;
use crate::descriptor_broker::DescriptorSessionSlot;
use anyhow::Result;
use std::sync::Arc;

/// What an approved copy may do here: write the files it sends, or read
/// the files this machine sends.
#[derive(Clone)]
pub(crate) enum Checker {
    Destination(Arc<RestrictedAuthority>),
    Source {
        authority: Arc<SourceAuthority>,
        /// Shared by the copy's control and workers: workers can use only
        /// the roots its control registered.
        descriptors: DescriptorSessionSlot,
    },
}

/// What one open channel of a copy holds against its approved connections.
#[allow(dead_code)]
pub(crate) enum ChannelPermit {
    Destination(crate::server::ConnectionPermit),
    Source(super::source::ChannelPermit),
}

impl Checker {
    /// A source's reads, with a fresh descriptor session for its control
    /// and workers to share.
    pub(crate) fn source(authority: Arc<SourceAuthority>) -> Self {
        Self::Source {
            authority,
            descriptors: DescriptorSessionSlot::default(),
        }
    }

    pub(crate) fn destination(&self) -> Option<&Arc<RestrictedAuthority>> {
        match self {
            Self::Destination(authority) => Some(authority),
            Self::Source { .. } => None,
        }
    }

    pub(crate) fn source_authority(&self) -> Option<&Arc<SourceAuthority>> {
        match self {
            Self::Destination(_) => None,
            Self::Source { authority, .. } => Some(authority),
        }
    }

    /// Count one channel against the approved connections before its hello.
    /// A copy's own control does not count against a receiver's workers.
    pub(crate) fn permit(&self, control: bool) -> Result<Option<ChannelPermit>> {
        Ok(match self {
            Self::Destination(_) if control => None,
            Self::Destination(authority) => Some(ChannelPermit::Destination(
                crate::server::ConnectionPermit::acquire(Arc::clone(authority))?,
            )),
            Self::Source { authority, .. } => {
                Some(ChannelPermit::Source(authority.open_channel()?))
            }
        })
    }

    /// End the copy: nothing more is authorized.
    pub(crate) fn close(&self) {
        match self {
            Self::Destination(authority) => authority.close_control(),
            Self::Source { authority, .. } => authority.close(),
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        match self {
            Self::Destination(authority) => authority.control_is_open(),
            Self::Source { authority, .. } => authority.is_open(),
        }
    }

    /// The descriptor session one connection is served in: a source's
    /// control and workers share one, while each of a destination's
    /// connections has its own.
    pub(crate) fn connection_session(&self) -> DescriptorSessionSlot {
        match self {
            Self::Destination(_) => DescriptorSessionSlot::default(),
            Self::Source { descriptors, .. } => descriptors.clone(),
        }
    }

    /// Close what one connection served in `descriptors` (from
    /// `connection_session`) leaves behind once it ends. A destination
    /// connection closes its own descriptor session; a control also ends
    /// the copy, and a source's control closes the session its workers
    /// share.
    pub(crate) fn end_connection(&self, descriptors: &DescriptorSessionSlot, control: bool) {
        match self {
            Self::Destination(authority) => {
                descriptors.close();
                if control {
                    authority.close_control();
                }
            }
            Self::Source { authority, .. } => {
                if control {
                    authority.close();
                    descriptors.close();
                }
            }
        }
    }
}
