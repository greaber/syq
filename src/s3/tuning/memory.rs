//! Memory a cgroup v2 limit leaves for widening far small-object downloads.
use std::path::Path;

/// What the process's cgroup v2 hierarchy says about memory still free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::s3) enum MemoryRoom {
    /// The smallest `memory.max` minus `memory.current` over the process's
    /// cgroup and every ancestor that sets a limit.
    Limited(u64),
    /// The whole hierarchy was read and no level sets a limit. This says
    /// nothing about the host's own memory.
    Unlimited,
    /// No unified cgroup hierarchy, or a level could not be read.
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
    if cfg!(target_os = "linux") {
        cgroup_room(Path::new("/proc/self/cgroup"), Path::new("/sys/fs/cgroup"))
    } else {
        MemoryRoom::Unknown
    }
}

fn cgroup_room(proc_cgroup: &Path, root: &Path) -> MemoryRoom {
    use MemoryRoom::*;
    let Ok(text) = std::fs::read_to_string(proc_cgroup) else {
        return Unknown;
    };
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
                let here = max.saturating_sub(current);
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
    room.map_or(Unlimited, Limited)
}

/// An estimate of what one more small object in flight costs beyond its
/// body: connection and TLS state, socket buffers and bookkeeping. Measured
/// cgroup charges were about 55-115 KiB per request apart from the body;
/// this is an estimate, not a bound.
const PER_OBJECT: u64 = 128 * 1024;

/// How many small objects of at most `largest` bytes fit in half of `room`.
/// The other half is left for everything else in the cgroup; neither part is
/// a guarantee against running out of memory.
pub(in crate::s3) fn objects_within(room: u64, largest: u64) -> usize {
    usize::try_from(room / 2 / (PER_OBJECT + largest)).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests;
