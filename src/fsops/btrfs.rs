//! Preserve btrfs compression when deciding whether to reserve file space.

use super::FileSystemKey;
use std::fs::File;
use std::os::fd::AsRawFd;

const FS_COMPR_FL: libc::c_int = 0x0000_0004;
const FS_NOCOMP_FL: libc::c_int = 0x0000_0400;
const FS_NOCOW_FL: libc::c_int = 0x0080_0000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Compression {
    #[default]
    Off,
    On,
    Forced,
}

impl Compression {
    /// Mount options share the existing filesystem-trait cache. File flags
    /// must be read from each new sidecar: sibling directories can differ.
    pub(super) fn for_mount(key: FileSystemKey) -> Self {
        std::fs::read("/proc/self/mountinfo")
            .map(|mounts| Self::from_mountinfo(&mounts, key))
            .unwrap_or_default()
    }

    pub(super) fn enabled_for(self, file: &File) -> bool {
        // GETFLAGS encodes sizeof(long) in its request but returns an int.
        let mut flags: libc::c_int = 0;
        let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
        // If flags are unavailable, retain the known mount setting. An
        // optional allocation hint must not make an otherwise valid copy fail.
        self.enabled_with_flags(if result == 0 { flags } else { 0 })
    }

    fn enabled_with_flags(self, flags: libc::c_int) -> bool {
        flags & FS_NOCOW_FL == 0
            && (self == Self::Forced
                || (flags & FS_NOCOMP_FL == 0 && (self == Self::On || flags & FS_COMPR_FL != 0)))
    }

    fn from_mountinfo(mounts: &[u8], key: FileSystemKey) -> Self {
        // Older kernels lack statx mount IDs. Their stat device number still
        // identifies the btrfs subvolume in mountinfo, including bind mounts.
        let device = match key {
            FileSystemKey::Device(dev) => {
                Some(format!("{}:{}", libc::major(dev), libc::minor(dev)))
            }
            FileSystemKey::Mount(_) => None,
        };
        for line in mounts.split(|b| *b == b'\n') {
            let mut fields = line.split(|b| b.is_ascii_whitespace());
            let Some(id) = fields.next() else { continue };
            fields.next(); // parent mount ID
            let Some(dev) = fields.next() else { continue };
            let matches = match key {
                FileSystemKey::Mount(expected) => {
                    std::str::from_utf8(id)
                        .ok()
                        .and_then(|id| id.parse::<u64>().ok())
                        == Some(expected)
                }
                FileSystemKey::Device(_) => device.as_deref().map(str::as_bytes) == Some(dev),
            };
            if !matches || !fields.any(|field| field == b"-") {
                continue;
            }
            if fields.next() != Some(b"btrfs".as_slice()) {
                continue;
            }
            fields.next(); // mount source
            let Some(options) = fields.next() else {
                continue;
            };
            for option in options.split(|b| *b == b',') {
                let mut parts = option.splitn(2, |b| *b == b'=');
                let name = parts.next().unwrap_or_default();
                if name != b"compress" && name != b"compress-force" {
                    continue;
                }
                if matches!(parts.next(), Some(b"no" | b"none")) {
                    return Self::Off;
                }
                return if name == b"compress-force" {
                    Self::Forced
                } else {
                    Self::On
                };
            }
            return Self::Off;
        }
        Self::Off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_compression_matches_ids_and_old_kernel_device_numbers() {
        let mounts = b"11 1 8:1 / / rw - ext4 /dev/a rw\n\
22 1 0:42 /sub /mnt/with\\040space rw shared:1 - btrfs /dev/b rw,compress=zstd:3,subvol=/sub\n\
23 1 0:43 / /mnt/other rw - btrfs /dev/c rw,compress-force=lzo\n\
24 1 0:44 / /mnt/plain rw - btrfs /dev/d rw,ssd\n";
        assert_eq!(
            Compression::from_mountinfo(mounts, FileSystemKey::Mount(22)),
            Compression::On
        );
        assert_eq!(
            Compression::from_mountinfo(mounts, FileSystemKey::Mount(23)),
            Compression::Forced
        );
        assert_eq!(
            Compression::from_mountinfo(mounts, FileSystemKey::Mount(24)),
            Compression::Off
        );
        assert_eq!(
            Compression::from_mountinfo(mounts, FileSystemKey::Mount(11)),
            Compression::Off
        );
        assert_eq!(
            Compression::from_mountinfo(mounts, FileSystemKey::Mount(99)),
            Compression::Off
        );
        assert_eq!(
            Compression::from_mountinfo(mounts, FileSystemKey::Device(libc::makedev(0, 42))),
            Compression::On
        );
        assert_eq!(
            Compression::from_mountinfo(mounts, FileSystemKey::Device(libc::makedev(0, 43))),
            Compression::Forced
        );
    }

    #[test]
    fn compression_option_names_are_exact_and_disabled_values_stay_disabled() {
        for (options, expected) in [
            ("rw,compress", Compression::On),
            ("rw,compress=zlib:9", Compression::On),
            ("rw,compress-force=zstd:1", Compression::Forced),
            ("rw,compress=no", Compression::Off),
            ("rw,compress=none", Compression::Off),
            ("rw,subvol=/compress=zstd", Compression::Off),
        ] {
            let line = format!("7 1 0:42 / /mnt rw - btrfs /dev/a {options}\n");
            assert_eq!(
                Compression::from_mountinfo(line.as_bytes(), FileSystemKey::Mount(7)),
                expected,
                "{options}"
            );
        }
    }

    #[test]
    fn inherited_file_flags_and_mount_policy_follow_btrfs_precedence() {
        for mode in [Compression::Off, Compression::On, Compression::Forced] {
            assert!(!mode.enabled_with_flags(FS_NOCOW_FL));
            assert!(!mode.enabled_with_flags(FS_NOCOW_FL | FS_COMPR_FL));
            assert!(mode.enabled_with_flags(FS_COMPR_FL));
            assert_eq!(
                mode.enabled_with_flags(FS_NOCOMP_FL),
                mode == Compression::Forced
            );
        }
        assert!(!Compression::Off.enabled_with_flags(0));
        assert!(Compression::On.enabled_with_flags(0));
        assert!(Compression::Forced.enabled_with_flags(0));
    }
}
