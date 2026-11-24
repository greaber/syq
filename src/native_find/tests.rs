use super::*;
use std::os::unix::ffi::OsStringExt;

fn options(base: &Path) -> Options {
    Options {
        cwd: Some(base.as_os_str().as_bytes().to_vec()),
        root: None,
        paths: Vec::new(),
        follow: false,
        depth: None,
        ignore: Vec::new(),
        where_expression: None,
        expression_now: 0,
        format: Format::Plain,
        include: None,
    }
}

/// The tree every test lists:
///
/// ```text
/// Cargo.toml
/// link -> src
/// logs/2026/b.txt
/// logs/a.log
/// src/main.rs
/// src/sub/deep/x.rs
/// ```
fn tree() -> tempfile::TempDir {
    let temp = crate::test_support::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("src/sub/deep")).unwrap();
    std::fs::create_dir_all(root.join("logs/2026")).unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(root.join("src/sub/deep/x.rs"), "").unwrap();
    std::fs::write(root.join("logs/2026/b.txt"), "b").unwrap();
    std::fs::write(root.join("logs/a.log"), "aa").unwrap();
    std::os::unix::fs::symlink("src", root.join("link")).unwrap();
    temp
}

/// Output, and the reports of skipped entries.
#[derive(Default)]
struct Captured {
    out: Vec<u8>,
    skipped: Vec<String>,
}

impl Write for Captured {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.out.write(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for Captured {
    fn unreadable(&mut self, message: String) -> Result<()> {
        self.skipped.push(message);
        Ok(())
    }
}

fn captured(options: &Options) -> Result<Captured> {
    let mut captured = Captured::default();
    write_local(options, &mut captured)?;
    Ok(captured)
}

fn list(options: &Options) -> Result<(String, Vec<String>)> {
    let captured = captured(options)?;
    Ok((String::from_utf8(captured.out).unwrap(), captured.skipped))
}

fn lines(options: &Options) -> Vec<String> {
    let (out, skipped) = list(options).unwrap();
    assert!(skipped.is_empty(), "{skipped:?}");
    out.lines().map(str::to_owned).collect()
}

#[test]
fn lists_beneath_the_base_in_byte_order_without_following_links() {
    let temp = tree();
    assert_eq!(
        lines(&options(temp.path())),
        [
            "Cargo.toml",
            "link",
            "logs",
            "logs/2026",
            "logs/2026/b.txt",
            "logs/a.log",
            "src",
            "src/main.rs",
            "src/sub",
            "src/sub/deep",
            "src/sub/deep/x.rs",
        ]
    );
}

#[test]
fn depth_counts_levels_beneath_each_root() {
    let temp = tree();
    let mut options = options(temp.path());
    options.depth = Some(1);
    assert_eq!(lines(&options), ["Cargo.toml", "link", "logs", "src"]);
    options.depth = Some(2);
    options.paths = vec![b"src/".to_vec(), b"logs".to_vec()];
    assert_eq!(
        lines(&options),
        [
            "src/main.rs",
            "src/sub",
            "src/sub/deep",
            "logs/2026",
            "logs/2026/b.txt",
            "logs/a.log",
        ]
    );
    options.depth = Some(0);
    assert!(list(&options).is_err());
}

#[test]
fn roots_print_as_given_and_a_file_lists_itself() {
    let temp = tree();
    let mut options = options(temp.path());
    options.paths = vec![b"./src/sub".to_vec(), b"Cargo.toml".to_vec(), b".".to_vec()];
    options.depth = Some(1);
    assert_eq!(
        lines(&options),
        [
            "./src/sub/deep",
            "Cargo.toml",
            "Cargo.toml",
            "link",
            "logs",
            "src"
        ]
    );
    // An absolute root keeps its own spelling, and `/` is not doubled.
    let absolute = temp.path().join("logs");
    options.cwd = None;
    options.paths = vec![absolute.as_os_str().as_bytes().to_vec()];
    assert_eq!(
        lines(&options),
        [
            format!("{}/2026", absolute.display()),
            format!("{}/a.log", absolute.display())
        ]
    );
    assert_eq!(join(b"/", b"etc"), b"/etc");
    assert_eq!(root_display(b"/"), b"/");
    assert_eq!(root_display(b"logs//"), b"logs");
    assert_eq!(root_display(b"./"), b"");
}

#[test]
fn a_missing_root_fails_before_any_output() {
    let temp = tree();
    let mut options = options(temp.path());
    options.paths = vec![b"src".to_vec(), b"missing".to_vec()];
    let mut out = Captured::default();
    let error = write_local(&options, &mut out).unwrap_err();
    assert!(out.out.is_empty());
    assert!(
        format!("{error:#}").contains("cannot list missing"),
        "{error:#}"
    );
}

#[test]
fn symlinks_are_followed_only_when_given_and_asked() {
    let temp = tree();
    let mut options = options(temp.path());
    options.paths = vec![b"link".to_vec()];
    assert_eq!(lines(&options), ["link"]);
    options.follow = true;
    assert_eq!(
        lines(&options),
        [
            "link/main.rs",
            "link/sub",
            "link/sub/deep",
            "link/sub/deep/x.rs"
        ]
    );
    // A link inside a directory is listed, never followed.
    options.paths = vec![b".".to_vec()];
    options.depth = Some(2);
    assert!(!lines(&options).iter().any(|line| line.starts_with("link/")));
    // A link in the middle of a path is refused without --follow.
    options.follow = false;
    options.paths = vec![b"link/sub".to_vec()];
    assert!(list(&options).is_err());
}

#[test]
fn root_confines_paths_beneath_it() {
    let temp = tree();
    let mut options = options(temp.path());
    options.root = options
        .cwd
        .take()
        .map(|base| [base, b"/src".to_vec()].concat());
    options.paths = vec![b"sub".to_vec()];
    assert_eq!(lines(&options), ["sub/deep", "sub/deep/x.rs"]);
    options.paths = vec![b"../logs".to_vec()];
    assert!(list(&options).is_err());
    options.paths = vec![temp.path().as_os_str().as_bytes().to_vec()];
    assert!(list(&options).is_err());
}

#[test]
fn ignore_rules_prune_subtrees_relative_to_each_root() {
    let temp = tree();
    let mut options = options(temp.path());
    options.ignore = vec!["sub/".into(), "*.log".into()];
    assert_eq!(
        lines(&options),
        [
            "Cargo.toml",
            "link",
            "logs",
            "logs/2026",
            "logs/2026/b.txt",
            "src",
            "src/main.rs",
        ]
    );
    // A named file is matched by its basename.
    options.paths = vec![b"logs/a.log".to_vec(), b"src".to_vec()];
    assert_eq!(lines(&options), ["src/main.rs"]);
    // Rules are anchored at each root.
    options.ignore = vec!["/deep".into()];
    options.paths = vec![b"src/sub".to_vec()];
    assert!(lines(&options).is_empty());
}

#[test]
fn where_filters_directories_too_and_sees_the_printed_path() {
    let temp = tree();
    let mut options = options(temp.path());
    options.where_expression = Some("kind = 'dir'".into());
    assert_eq!(
        lines(&options),
        ["logs", "logs/2026", "src", "src/sub", "src/sub/deep"]
    );
    options.where_expression = Some("path glob 'src/**' and src.kind = 'file'".into());
    assert_eq!(lines(&options), ["src/main.rs", "src/sub/deep/x.rs"]);
    options.where_expression = Some("name = 'link' and link_target = 'src'".into());
    assert_eq!(lines(&options), ["link"]);
    options.paths = vec![b"logs".to_vec()];
    options.where_expression = Some("path = 'logs/a.log' or extension = 'txt'".into());
    assert_eq!(lines(&options), ["logs/2026/b.txt", "logs/a.log"]);
    options.where_expression = Some("dst.size > 0B".into());
    assert!(list(&options).is_err());
}

#[test]
fn json_long_and_null_formats() {
    let temp = tree();
    let mut options = options(temp.path());
    options.paths = vec![b"logs".to_vec(), b"link".to_vec()];
    options.format = Format::Json;
    let records: Vec<serde_json::Value> = lines(&options)
        .iter()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records[0]["path"], "logs/2026");
    assert_eq!(records[0]["kind"], "dir");
    assert!(records[0].get("size").is_none());
    assert!(records[0]["mtime"].is_i64());
    assert_eq!(records[2]["path"], "logs/a.log");
    assert_eq!(records[2]["size"], 2);
    // Keys come in a fixed order, path first; a symlink has no size.
    assert!(
        lines(&options)[3].starts_with(r#"{"path":"link","kind":"symlink","mtime":"#),
        "{:?}",
        lines(&options)
    );
    options.include = Some(vec![Field::LinkTarget, Field::Mode, Field::Kind]);
    let record: serde_json::Value = serde_json::from_str(&lines(&options)[3]).unwrap();
    assert_eq!(record["link_target"], "src");
    assert_eq!(record["kind"], "symlink");
    assert!(record.get("mtime").is_none());
    assert!(record["mode"].is_u64());
    options.include = Some(vec![Field::Etag]);
    assert!(list(&options).is_err());

    options.include = None;
    options.format = Format::Long;
    let long = lines(&options);
    assert!(long[0].starts_with("dir             - 20"), "{long:?}");
    assert!(long[2].starts_with("file          2 B 20"), "{long:?}");
    assert!(long[2].ends_with("  logs/a.log"), "{long:?}");
    assert!(long[3].ends_with("  link -> src"), "{long:?}");

    options.format = Format::Null;
    let (out, _) = list(&options).unwrap();
    assert_eq!(out, "logs/2026\0logs/2026/b.txt\0logs/a.log\0link\0");
}

#[test]
fn names_that_are_not_utf8_print_raw_but_not_as_json() {
    if !crate::test_support::filesystem_accepts_non_utf8_names() {
        return;
    }
    let temp = crate::test_support::tempdir().unwrap();
    let name = std::ffi::OsString::from_vec(b"bad\xff\nname".to_vec());
    std::fs::write(temp.path().join(&name), "").unwrap();
    let mut options = options(temp.path());
    options.format = Format::Null;
    assert_eq!(captured(&options).unwrap().out, b"bad\xff\nname\0");
    options.format = Format::Plain;
    assert_eq!(captured(&options).unwrap().out, b"bad\xff\nname\n");
    options.format = Format::Json;
    let error = captured(&options).err().unwrap();
    assert!(format!("{error:#}").contains("--null"), "{error:#}");
}

#[test]
fn an_unreadable_directory_is_reported_and_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tree();
    let locked = temp.path().join("logs/2026");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root can read it anyway.
    let readable = std::fs::read_dir(&locked).is_ok();
    let mut options = options(temp.path());
    options.paths = vec![b"logs".to_vec()];
    let result = list(&options);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (out, skipped) = result.unwrap();
    if readable {
        return;
    }
    assert_eq!(out, "logs/2026\nlogs/a.log\n");
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert!(skipped[0].contains("logs/2026"), "{skipped:?}");
}

/// Output from a slow walk is flushed while the walk goes on, not only at
/// its end, at most once per interval.
#[test]
fn a_slow_walk_flushes_its_output_as_it_goes() {
    /// Takes a while over each entry, and notes how much output each
    /// flush found.
    #[derive(Default)]
    struct Slow {
        out: Vec<u8>,
        flushes: Vec<usize>,
    }
    impl Write for Slow {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if data == b"\n" {
                std::thread::sleep(Duration::from_millis(25));
            }
            self.out.write(data)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes.push(self.out.len());
            Ok(())
        }
    }
    impl Sink for Slow {
        fn unreadable(&mut self, message: String) -> Result<()> {
            panic!("{message}");
        }
    }
    let temp = tree();
    let mut slow = Slow::default();
    let started = Instant::now();
    write_local(&options(temp.path()), &mut slow).unwrap();
    let elapsed = started.elapsed();
    let total = slow.out.len();
    assert!(
        slow.flushes
            .iter()
            .any(|&flushed| 0 < flushed && flushed < total),
        "{:?} of {total}",
        slow.flushes
    );
    // Each flush has something new to send, and they are at least an
    // interval apart.
    assert!(
        slow.flushes.windows(2).all(|pair| pair[0] < pair[1]),
        "{:?}",
        slow.flushes
    );
    let most = (elapsed.as_millis() / FLUSH_INTERVAL.as_millis()) as usize;
    assert!(
        slow.flushes.len() <= most,
        "{:?} in {elapsed:?}",
        slow.flushes
    );
}

/// A helper receives the options over the wire, so it checks them itself.
#[test]
fn helper_refuses_bad_roots_and_fields() {
    let temp = tree();
    let mut options = options(temp.path());
    options.paths = vec![b"a\0b".to_vec()];
    assert!(list(&options).is_err());
    options.paths = vec![Vec::new()];
    assert!(list(&options).is_err());
    options.paths = Vec::new();
    options.root = options.cwd.clone();
    assert!(list(&options).is_err());
    options.root = None;
    options.include = Some(vec![Field::S3LastModified]);
    assert!(list(&options).is_err());
}
