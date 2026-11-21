//! Memory a cgroup v2 limit leaves for widening far small-object downloads.
use std::path::Path;

/// What the process's cgroup v2 hierarchy says about memory still free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::s3) enum MemoryRoom {
    /// The smallest `memory.max` minus `memory.current` over the process's
    /// cgroup and every ancestor that sets a limit.
    Limited(u64),
    /// No level sets a limit, and the whole hierarchy up to the host's root
    /// was visible. This says nothing about the host's own memory.
    Unlimited,
    /// No unified cgroup hierarchy, a level that could not be read, or no
    /// visible limit while ancestors may be hidden (a cgroup namespace).
    Unknown,
}

#[cfg(test)]
thread_local! {
    /// Lets planning tests choose the answer instead of reading the host.
    pub(in crate::s3) static TEST_ROOM: std::cell::Cell<Option<MemoryRoom>> =
        const { std::cell::Cell::new(None) };
}

/// Reads the current answer. Call once per planning operation.
pub(in crate::s3) fn memory_room() -> MemoryRoom {
    #[cfg(test)]
    if let Some(room) = TEST_ROOM.with(|room| room.get()) {
        return room;
    }
    if !cfg!(target_os = "linux") {
        return MemoryRoom::Unknown;
    }
    let (Ok(cgroup), Ok(mounts)) = (
        std::fs::read_to_string("/proc/self/cgroup"),
        std::fs::read_to_string("/proc/self/mountinfo"),
    ) else {
        return MemoryRoom::Unknown;
    };
    let namespace = std::fs::read_link("/proc/self/ns/cgroup").ok();
    let namespace = namespace.as_deref().and_then(Path::to_str);
    cgroup_room(&cgroup, namespace, &mounts, Path::new("/sys/fs/cgroup"))
}

/// The kernel's fixed identifier of the initial cgroup namespace.
const INITIAL_NAMESPACE: &str = "cgroup:[4026531835]";

/// `text` is `/proc/self/cgroup`, `namespace` the target of
/// `/proc/self/ns/cgroup` and `mounts` `/proc/self/mountinfo`.
fn cgroup_room(text: &str, namespace: Option<&str>, mounts: &str, root: &Path) -> MemoryRoom {
    use MemoryRoom::*;
    // The hierarchy must be mounted at `root` from its own root: a subtree
    // mount, or one outside a cgroup namespace (`/..`), does not map the
    // process's path onto it.
    // A later mount at the same point hides earlier ones.
    let mounted = mounts
        .lines()
        .map(|line| line.split(' ').collect::<Vec<_>>())
        .rfind(|fields| fields.get(4).map(Path::new) == Some(root))
        .is_some_and(|fields| {
            let separator = fields.iter().position(|field| *field == "-");
            fields.get(3) == Some(&"/")
                && separator.and_then(|i| fields.get(i + 1)) == Some(&"cgroup2")
        });
    if !mounted {
        return Unknown;
    }
    // Only the initial namespace shows every ancestor.
    let whole = namespace == Some(INITIAL_NAMESPACE);
    // A unified hierarchy has one entry, `0::PATH`. Version 1 or hybrid
    // hierarchies list other controllers, whose limits this does not read.
    let mut lines = text.lines();
    let (Some(entry), None) = (lines.next(), lines.next()) else {
        return Unknown;
    };
    let Some(path) = entry.strip_prefix("0::") else {
        return Unknown;
    };
    let relative = path.trim_start_matches('/');
    // Outside the visible part of a cgroup namespace the path starts with `..`.
    if relative.split('/').any(|part| part == "..") || !root.join("cgroup.controllers").is_file() {
        return Unknown;
    }
    let mut dir = root.join(relative);
    if !dir.is_dir() {
        return Unknown;
    }
    let mut room = None;
    loop {
        match std::fs::read_to_string(dir.join("memory.max")) {
            // A level without the file has no memory controller, so no limit;
            // the host's root cgroup never has one.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Unknown,
            Ok(max) if max.trim() == "max" => {}
            Ok(max) => {
                let current = std::fs::read_to_string(dir.join("memory.current"));
                let (Ok(max), Some(current)) = (
                    max.trim().parse::<u64>(),
                    current.ok().and_then(|c| c.trim().parse::<u64>().ok()),
                ) else {
                    return Unknown;
                };
                // Usage includes file cache the kernel reclaims before it
                // reaches the limit; count the clean inactive part as free,
                // as a container's working set does. Without `memory.stat`,
                // all of it counts as used.
                let stat = std::fs::read_to_string(dir.join("memory.stat")).unwrap_or_default();
                let field = |name: &str| {
                    stat.lines()
                        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
                        .and_then(|value| value.trim().parse::<u64>().ok())
                        .unwrap_or(0)
                };
                let reclaimable = field("inactive_file")
                    .saturating_sub(field("file_dirty"))
                    .saturating_sub(field("file_writeback"));
                let here = max.saturating_sub(current.saturating_sub(reclaimable));
                room = Some(room.map_or(here, |room: u64| room.min(here)));
            }
        }
        if dir == root {
            break;
        }
        let Some(parent) = dir.parent() else {
            return Unknown;
        };
        dir = parent.to_path_buf();
    }
    match room {
        Some(room) => Limited(room),
        None if whole => Unlimited,
        None => Unknown,
    }
}

/// An estimate of what one more small object in flight costs beyond its
/// body: connection and TLS state, socket buffers and bookkeeping. Measured
/// cgroup charges ranged from about 55 KiB (unlimited, 2-8 KiB objects) to
/// about 160 KiB beyond a 64 KiB body (about 1,000 in flight under a 400 MiB
/// limit), so this is not conservative on its own: the half of the room that
/// `objects_within` leaves unused is what kept that run at 72% of its limit.
const PER_OBJECT: u64 = 128 * 1024;

/// How many small objects of at most `largest` bytes fit in half of `room`.
/// The other half is left for everything else in the cgroup; neither part is
/// a guarantee against running out of memory.
pub(in crate::s3) fn objects_within(room: u64, largest: u64) -> usize {
    usize::try_from(room / 2 / (PER_OBJECT + largest)).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
