//! On-demand, nonrecursive completion metadata, resolved on the file's host.
use crate::proto::CompletionEntry;
use std::collections::HashMap;
use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Never let a filename, link target or account name control the terminal.
pub(crate) fn display_bytes(bytes: &[u8]) -> String {
    let mut result = String::new();
    for character in String::from_utf8_lossy(bytes).chars() {
        if character.is_control()
            || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            result.extend(character.escape_default());
        } else {
            result.push(character);
        }
    }
    result
}

pub(crate) fn display_row(detail: &str, name: &[u8]) -> String {
    let name = display_bytes(name);
    match detail.split_once(" -> ") {
        Some((columns, target)) => format!("{columns}  {name} -> {target}"),
        None => format!("{detail}  {name}"),
    }
}

pub(crate) fn describe(directory: &Path, entries: &[CompletionEntry]) -> Vec<String> {
    let mut users = HashMap::new();
    let mut groups = HashMap::new();
    let rows: Vec<_> = entries
        .iter()
        .map(|entry| {
            let path = directory.join(OsStr::from_bytes(&entry.name));
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            let user = users
                .entry(metadata.uid())
                .or_insert_with(|| account_name(metadata.uid(), false))
                .clone();
            let group = groups
                .entry(metadata.gid())
                .or_insert_with(|| account_name(metadata.gid(), true))
                .clone();
            let size = if metadata.is_file() {
                human_size(metadata.len())
            } else {
                "—".into()
            };
            let link = if metadata.file_type().is_symlink() {
                match std::fs::read_link(&path) {
                    Ok(target) => format!(" -> {}", display_bytes(target.as_os_str().as_bytes())),
                    Err(_) => " -> [unavailable]".into(),
                }
            } else {
                String::new()
            };
            Some((
                permissions(metadata.mode() as libc::mode_t),
                user,
                group,
                size,
                modified(metadata.mtime()),
                link,
            ))
        })
        .collect();
    let user_width = rows
        .iter()
        .flatten()
        .map(|r| r.1.chars().count())
        .max()
        .unwrap_or(1);
    let group_width = rows
        .iter()
        .flatten()
        .map(|r| r.2.chars().count())
        .max()
        .unwrap_or(1);
    let size_width = rows
        .iter()
        .flatten()
        .map(|r| r.3.chars().count())
        .max()
        .unwrap_or(1);
    rows.into_iter()
        .map(|row| match row {
            Some((mode, user, group, size, time, link)) => format!(
                "{mode} {user:<user_width$} {group:<group_width$} {size:>size_width$} {time}{link}"
            ),
            None => "[metadata unavailable]".into(),
        })
        .collect()
}

fn account_name(id: u32, group: bool) -> String {
    // Reentrant NSS calls: completion can run alongside connection cleanup.
    // Bound scratch storage and use the numeric ID if lookup fails.
    let mut size = 1024;
    while size <= 1024 * 1024 {
        let mut buffer = vec![0u8; size];
        let (status, name) = unsafe {
            if group {
                let mut record: libc::group = std::mem::zeroed();
                let mut result = std::ptr::null_mut();
                let status = libc::getgrgid_r(
                    id,
                    &mut record,
                    buffer.as_mut_ptr().cast(),
                    size,
                    &mut result,
                );
                let name = if status == 0 && !result.is_null() && !record.gr_name.is_null() {
                    Some(display_bytes(CStr::from_ptr(record.gr_name).to_bytes()))
                } else {
                    None
                };
                (status, name)
            } else {
                let mut record: libc::passwd = std::mem::zeroed();
                let mut result = std::ptr::null_mut();
                let status = libc::getpwuid_r(
                    id,
                    &mut record,
                    buffer.as_mut_ptr().cast(),
                    size,
                    &mut result,
                );
                let name = if status == 0 && !result.is_null() && !record.pw_name.is_null() {
                    Some(display_bytes(CStr::from_ptr(record.pw_name).to_bytes()))
                } else {
                    None
                };
                (status, name)
            }
        };
        if let Some(name) = name {
            return name;
        }
        if status != libc::ERANGE {
            break;
        }
        size *= 2;
    }
    id.to_string()
}

fn human_size(size: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if size < 1024 {
        return format!("{size} B");
    }
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn modified(seconds: i64) -> String {
    let seconds = seconds as libc::time_t;
    let mut time: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&seconds, &mut time) }.is_null() {
        return "[unknown time]".into();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        time.tm_year as i64 + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
        time.tm_min
    )
}

fn permissions(mode: libc::mode_t) -> String {
    let mut text = vec![match mode & libc::S_IFMT {
        libc::S_IFDIR => b'd',
        libc::S_IFLNK => b'l',
        libc::S_IFREG => b'-',
        libc::S_IFIFO => b'p',
        libc::S_IFSOCK => b's',
        libc::S_IFCHR => b'c',
        libc::S_IFBLK => b'b',
        _ => b'?',
    }];
    for (bit, character) in [
        (0o400, b'r'),
        (0o200, b'w'),
        (0o100, b'x'),
        (0o040, b'r'),
        (0o020, b'w'),
        (0o010, b'x'),
        (0o004, b'r'),
        (0o002, b'w'),
        (0o001, b'x'),
    ] {
        text.push(if mode & bit != 0 { character } else { b'-' });
    }
    for (index, bit, lower, upper) in [
        (3, 0o4000, b's', b'S'),
        (6, 0o2000, b's', b'S'),
        (9, 0o1000, b't', b'T'),
    ] {
        if mode & bit != 0 {
            text[index] = if text[index] == b'x' { lower } else { upper };
        }
    }
    String::from_utf8(text).expect("ASCII permission bits")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vanished_files_keep_their_place_in_the_listing() {
        let directory = crate::test_support::tempdir().unwrap();
        let entries = vec![CompletionEntry {
            name: b"vanished".to_vec(),
            directory: false,
        }];
        assert_eq!(
            describe(directory.path(), &entries),
            vec!["[metadata unavailable]"]
        );
    }

    #[test]
    fn familiar_columns_and_safe_text() {
        assert_eq!(permissions(libc::S_IFREG | 0o6754), "-rwsr-sr--");
        assert_eq!(permissions(libc::S_IFDIR | 0o1700), "drwx-----T");
        assert_eq!(human_size(1024 * 1024 * 42), "42.0 MiB");
        assert_eq!(modified(0), "1970-01-01 00:00 UTC");
        assert_eq!(
            display_bytes(b"evil\x1b[2J\nname\t"),
            "evil\\u{1b}[2J\\nname\\t"
        );
    }
}
