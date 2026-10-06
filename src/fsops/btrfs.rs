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
    pub(super) fn for_mount(file: &File, key: FileSystemKey) -> Self {
        let mount = match key {
            FileSystemKey::Mount(id) => id,
            // Btrfs st_dev names a subvolume, not mountinfo's filesystem device.
            // fdinfo has supplied the actual mount ID since Linux 3.15, before
            // statx gained STATX_MNT_ID in 5.8. This is only read on a cache miss.
            FileSystemKey::Device(_) => match fdinfo_mount_id(file) {
                Some(id) => id,
                None => return Self::Off,
            },
        };
        std::fs::read("/proc/self/mountinfo")
            .map(|mounts| Self::from_mountinfo(&mounts, mount))
            .unwrap_or_default()
    }

    pub(super) fn enabled_for(self, file: &File) -> bool {
        #[cfg(test)]
        if let Some(flags) = FILE_FLAGS.get() {
            return self.enabled_with_flags(flags);
        }
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

    fn from_mountinfo(mounts: &[u8], mount: u64) -> Self {
        for line in mounts.split(|b| *b == b'\n') {
            let mut fields = line.split(|b| b.is_ascii_whitespace());
            let Some(id) = fields.next() else { continue };
            let id = std::str::from_utf8(id)
                .ok()
                .and_then(|id| id.parse::<u64>().ok());
            if id != Some(mount) || !fields.any(|field| field == b"-") {
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

fn fdinfo_mount_id(file: &File) -> Option<u64> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).ok()?;
    mount_id_from_fdinfo(&info)
}

fn mount_id_from_fdinfo(info: &str) -> Option<u64> {
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse().ok())
}

#[cfg(test)]
thread_local! {
    // Keep allocation tests independent of flags inherited from their TMPDIR.
    pub(super) static FILE_FLAGS: std::cell::Cell<Option<libc::c_int>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdinfo_reads_the_mount_id_not_the_subvolume_device() {
        assert_eq!(
            mount_id_from_fdinfo("pos:\t0\nflags:\t02100000\nmnt_id:\t22\nino:\t256\n"),
            Some(22)
        );
        assert_eq!(mount_id_from_fdinfo("pos:\t0\nino:\t22\n"), None);
        assert_eq!(mount_id_from_fdinfo("mnt_id:\tinvalid\n"), None);
        let directory = crate::test_support::tempdir().unwrap();
        let file = File::create(directory.path().join("file")).unwrap();
        let id = fdinfo_mount_id(&file).unwrap();
        if let Some(statx_id) = super::super::mount_id(&file) {
            assert_eq!(id, statx_id);
        }
        // Force the old-kernel branch with a device that cannot name a mount.
        assert_eq!(
            Compression::for_mount(&file, FileSystemKey::Device(u64::MAX)),
            Compression::for_mount(&file, FileSystemKey::Mount(id))
        );
    }

    #[test]
    fn mount_compression_matches_mount_ids() {
        let mounts = b"11 1 8:1 / / rw - ext4 /dev/a rw\n\
22 1 0:42 /sub /mnt/with\\040space rw shared:1 - btrfs /dev/b rw,compress=zstd:3,subvol=/sub\n\
23 1 0:43 / /mnt/other rw - btrfs /dev/c rw,compress-force=lzo\n\
24 1 0:44 / /mnt/plain rw - btrfs /dev/d rw,ssd\n";
        assert_eq!(Compression::from_mountinfo(mounts, 22), Compression::On);
        assert_eq!(Compression::from_mountinfo(mounts, 23), Compression::Forced);
        assert_eq!(Compression::from_mountinfo(mounts, 24), Compression::Off);
        assert_eq!(Compression::from_mountinfo(mounts, 11), Compression::Off);
        assert_eq!(Compression::from_mountinfo(mounts, 99), Compression::Off);
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
                Compression::from_mountinfo(line.as_bytes(), 7),
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
