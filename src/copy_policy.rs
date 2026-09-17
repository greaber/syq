//! Copy-operation selection after endpoint placement, independently of TCP/SSH.
//! Filesystem-specific refusal still happens at the receiver and falls back
//! to transferring ranges; neither route selection nor publication changes.
#[derive(Clone, Copy)]
pub(crate) struct CopyPolicy {
    pub same_host: bool,
    pub checksum: bool,
    pub force_ranges: bool,
    pub bandwidth_limited: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FileOperation {
    ReceiverCopy,
    TransferRanges,
}

impl CopyPolicy {
    /// Existing Linux receivers need source capabilities before accepting a
    /// direct-copy request. This is about descriptor authority, not transport.
    pub(crate) fn receiver_source_claims(self) -> bool {
        cfg!(target_os = "linux") && self.same_host
    }

    pub(crate) fn prefer_whole_files(self) -> bool {
        self.receiver_source_claims() && !self.checksum && !self.bandwidth_limited
    }

    pub(crate) fn allows_receiver_copy(self) -> bool {
        self.same_host && !self.force_ranges && !self.checksum && !self.bandwidth_limited
    }

    pub(crate) fn file_operation(self, size: u64, guarded: bool) -> FileOperation {
        if self.allows_receiver_copy() && size > 0 && !guarded {
            FileOperation::ReceiverCopy
        } else {
            FileOperation::TransferRanges
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_requiring_range_processing_prevent_direct_copy() {
        let direct = CopyPolicy {
            same_host: true,
            checksum: false,
            force_ranges: false,
            bandwidth_limited: false,
        };
        assert_eq!(direct.file_operation(1, false), FileOperation::ReceiverCopy);
        for policy in [
            CopyPolicy {
                same_host: false,
                ..direct
            },
            CopyPolicy {
                checksum: true,
                ..direct
            },
            CopyPolicy {
                force_ranges: true,
                ..direct
            },
            CopyPolicy {
                bandwidth_limited: true,
                ..direct
            },
        ] {
            assert_eq!(
                policy.file_operation(1, false),
                FileOperation::TransferRanges
            );
        }
        assert_eq!(
            direct.file_operation(0, false),
            FileOperation::TransferRanges
        );
        assert_eq!(
            direct.file_operation(1, true),
            FileOperation::TransferRanges
        );
    }
}
