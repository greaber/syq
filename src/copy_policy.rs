//! Copy-operation selection after endpoint placement, independently of TCP/SSH.
//! Filesystem-specific refusal still happens at the receiver and falls back
//! to transferring ranges; neither route selection nor publication changes.
#[derive(Clone, Copy)]
pub(crate) struct CopyPolicy {
    pub same_host: bool,
    pub checksum: bool,
    pub force_ranges: bool,
    pub bandwidth_limited: bool,
    pub receiver_copy_disabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FileOperation {
    ReceiverCopy,
    TransferRanges,
}

impl CopyPolicy {
    pub(crate) fn prefer_whole_files(self) -> bool {
        // Keep macOS batching unchanged when cloning is unavailable.
        cfg!(target_os = "linux") && self.allows_receiver_copy()
    }

    /// Also determines whether workers need receiver-side source claims.
    pub(crate) fn allows_receiver_copy(self) -> bool {
        self.same_host
            && !self.receiver_copy_disabled
            && !self.force_ranges
            && !self.checksum
            && !self.bandwidth_limited
    }

    pub(crate) fn file_operation(self, size: u64, guarded: bool) -> FileOperation {
        if self.allows_receiver_copy() && size > 0 && !guarded {
            FileOperation::ReceiverCopy
        } else {
            FileOperation::TransferRanges
        }
    }
}

/// The fresh-destination capacity rule, shared with the receiver's one-turn
/// small copy so both refuse the same copies.
#[derive(Clone, Copy)]
pub(crate) struct FreshCapacityAssessment {
    pub(crate) logical_bytes: u64,
    pub(crate) objects: u64,
    pub(crate) available_bytes: u64,
    pub(crate) available_inodes: Option<u64>,
}

impl FreshCapacityAssessment {
    pub(crate) fn byte_shortage(self) -> bool {
        self.logical_bytes > self.available_bytes
    }

    pub(crate) fn inode_shortage(self) -> bool {
        self.available_inodes
            .is_some_and(|available| self.objects.saturating_add(64) > available)
    }

    pub(crate) fn sufficient(self) -> bool {
        !self.byte_shortage() && !self.inode_shortage()
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
            receiver_copy_disabled: false,
        };
        assert_eq!(direct.file_operation(1, false), FileOperation::ReceiverCopy);
        for policy in [
            CopyPolicy {
                receiver_copy_disabled: true,
                ..direct
            },
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
