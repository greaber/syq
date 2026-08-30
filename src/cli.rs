use anyhow::{bail, Result};
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "syq",
    version,
    about = "Parallel copy with an rsync-shaped interface",
    disable_help_flag = true,
    override_usage = "syq [OPTIONS] SRC... DEST\n       syq [OPTIONS] [USER@]HOST:SRC... DEST\n       syq [OPTIONS] SRC... [USER@]HOST:DEST\n       syq --self-update"
)]
pub struct Args {
    /// Print help
    #[arg(long, action = clap::ArgAction::Help)]
    pub help: Option<bool>,

    /// Install the newest signed release (standalone installer builds only)
    #[arg(long, exclusive = true)]
    pub self_update: bool,
    /// Record an installation made by the official standalone installer
    #[arg(long, hide = true, exclusive = true)]
    pub register_standalone_install: bool,

    /// Archive mode; same as -rlptgoD
    #[arg(short = 'a', long)]
    pub archive: bool,
    /// Recurse into directories
    #[arg(short = 'r', long)]
    pub recursive: bool,
    /// Copy symlinks as symlinks
    #[arg(short = 'l', long)]
    pub links: bool,
    /// Preserve permissions
    #[arg(short = 'p', long)]
    pub perms: bool,
    /// Preserve modification times
    #[arg(short = 't', long)]
    pub times: bool,
    /// Preserve group
    #[arg(short = 'g', long)]
    pub group: bool,
    /// Preserve owner (root only)
    #[arg(short = 'o', long)]
    pub owner: bool,
    /// Preserve device and special files
    #[arg(short = 'D')]
    pub devices: bool,

    /// Increase verbosity (-v lists files; -vv also explains copy helpers and transport)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Suppress non-error messages
    #[arg(short = 'q', long)]
    pub quiet: bool,
    /// Compress remote data in transit with zstd (default)
    #[arg(
        short = 'z',
        long,
        default_value_t = true,
        overrides_with = "no_compress"
    )]
    pub compress: bool,
    /// Disable transport compression
    #[arg(long, overrides_with = "compress")]
    pub no_compress: bool,
    /// Resolve mappings and transport, then estimate transfers, exclusions, and deletions;
    /// change nothing
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// No-op accepted for rsync compatibility (sizes are always human-readable)
    #[arg(short = 'h', long)]
    pub human_readable: bool,
    /// No-op accepted for rsync compatibility (syq always uses numeric uid/gid)
    #[arg(long)]
    pub numeric_ids: bool,

    /// Parallel connections/workers. Default for copies: auto-tuned — starts at
    /// the last settled count remembered for this host path and transport, or 16
    /// over TCP, 8 over ssh, or 32 when local. It probes from 1 to 64 while the
    /// copy has enough work to measure. Give a number to fix it. --rm uses a fixed
    /// 8 (32 when local).
    #[arg(short = 'j', long = "connections", value_name = "N")]
    pub connections_opt: Option<usize>,
    #[arg(skip)]
    pub connections: usize,
    #[arg(skip)]
    pub connections_default: bool,
    /// Transfer/hash block size (e.g. 4M)
    #[arg(long, default_value = "4M", value_name = "SIZE")]
    pub block_size: String,
    /// Don't split in-flight files with less than this much left (e.g. 32M)
    #[arg(long, default_value = "32M", value_name = "SIZE")]
    pub min_split: String,
    /// Limit the aggregate file-data rate across all workers (default unit: KiB/s; 0 disables)
    #[arg(long, value_name = "RATE")]
    pub bwlimit: Option<String>,
    #[arg(skip)]
    pub bwlimit_bytes: u64,

    /// Show progress (default when stderr is a terminal)
    #[arg(long, overrides_with = "no_progress")]
    pub progress: bool,
    /// Never show progress
    #[arg(long)]
    pub no_progress: bool,
    /// Same as --progress --partial
    #[arg(short = 'P')]
    pub p_flag: bool,
    /// No-op accepted for rsync compatibility (syq always keeps partial files)
    #[arg(long)]
    pub partial: bool,
    /// Emit machine-readable progress lines (JSON) on stderr
    #[arg(long)]
    pub progress_json: bool,
    /// Print transfer statistics at the end
    #[arg(long)]
    pub stats: bool,

    /// Skip quick check; compare file contents block by block and repair differences
    #[arg(short = 'c', long)]
    pub checksum: bool,
    /// Only compare source and destination contents; transfer nothing
    #[arg(long)]
    pub verify_only: bool,
    /// Update files in place instead of writing a partial and renaming. Use this to modify a
    /// large existing file without copying it first (saves time and disk space when only part
    /// of it changes). Cannot be combined with -u or --ignore-existing: an interrupted
    /// in-place write leaves a newer-looking final file those filters would then skip forever
    #[arg(long, conflicts_with_all = ["update", "ignore_existing"])]
    pub inplace: bool,
    /// Avoid completed-file destination lookups on later runs. Normal reruns and partial-file
    /// resume do not need this. The file persists and must be outside local source/destination trees.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["checksum", "verify_only", "rm"]
    )]
    pub checkpoint: Option<String>,

    /// Remote shell command (default: ssh); controls agent forwarding when set
    #[arg(short = 'e', long = "rsh", value_name = "COMMAND")]
    pub rsh: Option<String>,
    /// Use this exact syq executable on the remote instead of the managed helper
    #[arg(long, value_name = "PATH")]
    pub syq_path: Option<String>,
    /// Require syq on the remote PATH instead of installing a versioned helper
    #[arg(long)]
    pub no_bootstrap: bool,
    /// Use TCP data connections without encryption (trusted networks only)
    #[arg(long)]
    pub tcp_plain: bool,
    /// Send all data over the ssh connection instead of separate TCP data connections
    #[arg(long)]
    pub no_tcp: bool,
    /// Port range the remote listens on for TCP data connections
    #[arg(long, default_value = "47600-47699", value_name = "LO-HI")]
    pub tcp_ports: String,
    /// Use this congestion-control algorithm for direct TCP data sockets (Linux only)
    #[arg(
        long,
        value_name = "ALGO",
        value_parser = parse_tcp_congestion,
        conflicts_with_all = ["no_tcp", "rm", "follow"]
    )]
    pub tcp_congestion: Option<String>,
    /// Remote-to-remote: start the transfer detached on the source host (survives losing this
    /// ssh session) and return; progress goes to a log you can watch with --follow
    #[arg(long)]
    pub detach: bool,
    /// Follow a detached transfer: syq --follow HOST:LOGFILE
    #[arg(long)]
    pub follow: bool,
    /// Remote-to-remote: relay data through this machine instead of running on the source host
    #[arg(long)]
    pub relay: bool,
    /// Remote-to-remote with the default ssh: disable agent forwarding to the source host; it
    /// must authenticate to the destination with its own credentials
    #[arg(long, conflicts_with = "rsh")]
    pub no_forward_agent: bool,
    /// Terminal width for the progress display (internal; used for remote-to-remote)
    #[arg(long, hide = true)]
    pub width: Option<usize>,
    /// Original source endpoint for a remotely orchestrated dry-run summary
    #[arg(long, hide = true)]
    pub plan_source_host: Option<String>,

    /// Skip paths matching PATTERN (gitignore syntax: `foo` matches at any depth, `/foo` only
    /// at the source root, `foo/` only directories, `!pat` re-includes). Repeatable; together
    /// with --ignore-from the patterns act like the lines of one .gitignore file, in
    /// command-line order, anchored at each source root. Skipping a directory skips its
    /// whole subtree, so to copy only *.jpg use: -i '*' -i '!*/' -i '!*.jpg'
    #[arg(
        short = 'i',
        long = "ignore",
        value_name = "PATTERN",
        allow_hyphen_values = true
    )]
    pub ignore: Vec<String>,
    /// Read ignore patterns from FILE (one per line, # comments); repeatable
    #[arg(long, value_name = "FILE")]
    pub ignore_from: Vec<String>,
    /// All ignore patterns, in command-line order (filled by parse_args)
    #[arg(skip)]
    pub ignore_lines: Vec<String>,

    /// Delete extraneous files from the destination directories (paths the source does not
    /// have). Deletion happens after the transfer and is skipped entirely if the source scan
    /// reported any error. Ignored paths (-i) are protected on both sides. rsync's
    /// --delete-after and --delete-delay mean the same thing and are accepted. Cannot be combined
    /// with --verify-only or --files-from
    #[arg(
        long,
        aliases = ["delete-after", "delete-delay"],
        conflicts_with_all = ["verify_only", "files_from"]
    )]
    pub delete: bool,
    /// With --delete, also remove destination paths that the -i patterns exclude
    #[arg(long, requires = "delete")]
    pub delete_excluded: bool,
    /// With --delete, refuse to delete anything if more than N deletions are planned (exit 25)
    #[arg(long, value_name = "N", requires = "delete")]
    pub max_delete: Option<u64>,
    /// Skip regular files that are newer on the destination (directories,
    /// symlinks and specials are unaffected)
    #[arg(short = 'u', long)]
    pub update: bool,
    /// Skip updating files that already exist on the destination
    #[arg(long)]
    pub ignore_existing: bool,
    /// Never create anything that doesn't exist yet on the destination — files, symlinks,
    /// specials, directories, or the destination root itself; existing files are still updated
    #[arg(long)]
    pub existing: bool,
    /// Don't transfer regular files larger than SIZE (e.g. 100M). With --delete the
    /// destination copy of such a file is left alone
    #[arg(long, value_name = "SIZE")]
    pub max_size: Option<String>,
    /// Don't transfer regular files smaller than SIZE
    #[arg(long, value_name = "SIZE")]
    pub min_size: Option<String>,
    /// Copy only the paths listed in FILE (one per line, relative to the single source
    /// directory; `-` reads stdin). Listed directories are copied without their contents
    /// unless -r is given explicitly; missing parent directories are created
    #[arg(long, value_name = "FILE", conflicts_with_all = ["ignore", "ignore_from"])]
    pub files_from: Option<String>,
    /// --files-from entries are NUL-separated instead of one per line
    #[arg(long, requires = "files_from")]
    pub from0: bool,
    /// Paths read from --files-from (filled by parse_args)
    #[arg(skip)]
    pub files_from_lines: Vec<Vec<u8>>,
    /// -r given on the command line itself (not via -a); decides whether --files-from
    /// directories are copied with their contents
    #[arg(skip)]
    pub recursive_explicit: bool,

    /// Remove the given paths recursively and in parallel (like rm -rf); honours -j, -n, -v, -q, -e
    #[arg(long, conflicts_with_all = ["ignore", "ignore_from", "delete", "files_from"])]
    pub rm: bool,

    /// Source(s) and destination (or, with --rm, the paths to remove)
    #[arg(
        required_unless_present_any = ["self_update", "register_standalone_install"],
        num_args = 1..,
        value_name = "PATH"
    )]
    pub paths: Vec<String>,
}

impl Args {
    /// Parse the command line and read --ignore-from files, keeping --ignore and
    /// --ignore-from patterns in the order they were given (later lines win, as in
    /// a .gitignore file).
    pub fn parse_args() -> Result<Args> {
        use clap::{CommandFactory, FromArgMatches};
        let argv: Vec<String> = std::env::args().skip(1).collect();
        reject_unsupported_rsync_flags(&argv)?;
        let m = Args::command().get_matches();
        let mut args = Args::from_arg_matches(&m)?;
        args.bwlimit_bytes = args
            .bwlimit
            .as_deref()
            .map(crate::bwlimit::parse_rate)
            .transpose()?
            .unwrap_or(0);
        let mut items: Vec<(usize, bool, String)> = Vec::new();
        if let Some(idx) = m.indices_of("ignore") {
            for (i, v) in idx.zip(&args.ignore) {
                items.push((i, false, v.clone()));
            }
        }
        if let Some(idx) = m.indices_of("ignore_from") {
            for (i, v) in idx.zip(&args.ignore_from) {
                items.push((i, true, v.clone()));
            }
        }
        items.sort_by_key(|(i, _, _)| *i);
        for (_, from_file, v) in items {
            if from_file {
                let text = std::fs::read_to_string(&v)
                    .map_err(|e| anyhow::anyhow!("--ignore-from {v}: {e}"))?;
                let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
                args.ignore_lines
                    .extend(text.lines().map(|l| l.trim_end_matches('\r').to_string()));
            } else {
                args.ignore_lines.push(v);
            }
        }
        if let Some(f) = &args.files_from {
            // Check this before reading the list (it may be stdin) and before
            // anything connects: the list lives on this machine, but a direct
            // remote-to-remote copy would run the orchestrator on the source.
            if !args.rm && !args.follow && !args.relay && args.paths.len() >= 2 {
                let locs: Vec<Location> = args
                    .paths
                    .iter()
                    .map(|p| Location::parse(p))
                    .collect::<Result<_>>()?;
                if locs[0].is_remote() && locs[locs.len() - 1].is_remote() {
                    bail!("--files-from with a remote-to-remote copy needs --relay");
                }
            }
            args.files_from_lines = read_files_from(f, args.from0)?;
        }
        Ok(args)
    }

    pub fn normalize(&mut self) {
        if self.no_compress {
            self.compress = false;
        }
        self.recursive_explicit = self.recursive;
        if self.archive {
            self.recursive = true;
            self.links = true;
            self.perms = true;
            self.times = true;
            self.group = true;
            self.owner = true;
            self.devices = true;
        }
        if self.p_flag {
            self.progress = true;
            self.partial = true;
        }
        self.connections_default = self.connections_opt.is_none();
        self.connections = self.connections_opt.unwrap_or(8).max(1);
    }

    pub fn meta_flags(&self) -> u8 {
        use crate::proto::flags::*;
        let mut f = 0;
        if self.perms {
            f |= MODE;
        }
        if self.owner {
            f |= OWNER;
        }
        if self.group {
            f |= GROUP;
        }
        if self.times {
            f |= TIMES;
        }
        f
    }
}

/// Read a --files-from list: one path per line (or NUL-separated with --from0),
/// relative to the source root. Blank entries and entries starting with `#` or
/// `;` are dropped; `.` and empty components (so leading `/`, `./`, trailing
/// `/`, `a//b`) are removed; `..` components and entries naming the root itself
/// are rejected.
fn read_files_from(file: &str, nul: bool) -> Result<Vec<Vec<u8>>> {
    use std::io::Read;
    let mut raw = Vec::new();
    if file == "-" {
        std::io::stdin().read_to_end(&mut raw)?;
    } else {
        raw = std::fs::read(file).map_err(|e| anyhow::anyhow!("--files-from {file}: {e}"))?;
    }
    let mut out = Vec::new();
    let items: Vec<&[u8]> = if nul {
        raw.split(|&b| b == 0).collect()
    } else {
        raw.split(|&b| b == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .collect()
    };
    for item in items {
        // rsync treats these prefixes as comments in both line and NUL modes.
        // A literal name remains selectable by spelling it as `./#name` or
        // `./;name`.
        if item.is_empty() || matches!(item.first(), Some(b'#' | b';')) {
            continue;
        }
        if item.contains(&0) {
            bail!(
                "--files-from: {:?} contains a NUL byte (is this a --from0 list?)",
                String::from_utf8_lossy(item)
            );
        }
        let p = item;
        if p.split(|&b| b == b'/').any(|c| c == b"..") {
            bail!(
                "--files-from: {:?} contains a `..` component",
                String::from_utf8_lossy(item)
            );
        }
        // Drop `.` and empty components (`a/./b`, `a//b` -> `a/b`) so one path
        // has one spelling and the planner never schedules a file twice.
        let parts: Vec<&[u8]> = p
            .split(|&b| b == b'/')
            .filter(|c| *c != b"." && !c.is_empty())
            .collect();
        if parts.is_empty() {
            bail!(
                "--files-from: {:?} names the source root itself",
                String::from_utf8_lossy(item)
            );
        }
        out.push(parts.join(&b'/'));
    }
    Ok(out)
}

/// Common rsync flags syq deliberately doesn't implement get a one-line
/// explanation instead of clap's generic "unexpected argument", so pasting an
/// rsync command tells you exactly what to change. Flags syq *does* accept
/// (including the compatibility no-ops) are not listed here; genuinely unknown
/// flags fall through to clap. No translation is performed.
fn reject_unsupported_rsync_flags(argv: &[String]) -> Result<()> {
    // Options that consume a following, separate token as their value — skip
    // that token so a value like `-e 'ssh ...'` is never mistaken for a flag.
    let value_long = [
        "--rsh",
        "--ignore",
        "--ignore-from",
        "--connections",
        "--block-size",
        "--min-split",
        "--bwlimit",
        "--max-size",
        "--min-size",
        "--files-from",
        "--max-delete",
        "--checkpoint",
        "--tcp-ports",
        "--tcp-congestion",
        "--syq-path",
        "--width",
    ];
    let mut skip_next = false;
    for tok in argv {
        if skip_next {
            skip_next = false;
            continue;
        }
        if tok == "--" {
            break; // end of options; the rest are paths
        }
        if value_long.contains(&tok.as_str())
            || (!tok.starts_with("--") && matches!(tok.as_str(), "-e" | "-i" | "-j"))
        {
            skip_next = true;
            continue;
        }
        if let Some(msg) = unsupported_message(tok) {
            bail!("{msg}");
        }
    }
    Ok(())
}

fn parse_tcp_congestion(value: &str) -> std::result::Result<String, String> {
    // Linux's TCP_CA_NAME_MAX is 16 including the terminating NUL. Keep this
    // validation platform-independent so a forwarded command fails the same
    // way on every orchestrator.
    if value.is_empty() {
        return Err("congestion-control algorithm cannot be empty".into());
    }
    if value.len() >= 16 {
        return Err("congestion-control algorithm must be at most 15 bytes".into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(
            "congestion-control algorithm may contain only ASCII letters, digits, and `_`".into(),
        );
    }
    Ok(value.to_string())
}

fn unsupported_message(tok: &str) -> Option<String> {
    if let Some(long) = tok.strip_prefix("--") {
        return message_for_long(long.split('=').next().unwrap_or(long)).map(str::to_string);
    }
    if let Some(cluster) = tok.strip_prefix('-') {
        // Bundled short flags (e.g. `-auHz`): stop at the first value-taking
        // short, since everything after it is that option's value.
        for c in cluster.chars() {
            if matches!(c, 'e' | 'i' | 'j') {
                break;
            }
            if let Some(m) = message_for_short(c) {
                return Some(m.to_string());
            }
        }
    }
    None
}

const FILTER_MSG: &str = "syq has no --exclude/--include/--filter. Use -i/--ignore (or --ignore-from), which takes gitignore-style patterns: e.g. `--exclude node_modules` becomes `-i node_modules`. See the README's \"Ignoring paths\" section.";
const DELETE_MSG: &str = "syq deletes only after the transfer (--delete; --delete-after and --delete-delay are synonyms); --delete-before, --delete-during and --force are not supported.";

fn message_for_long(base: &str) -> Option<&'static str> {
    Some(match base {
        "exclude" | "exclude-from" | "include" | "include-from" | "filter" => FILTER_MSG,
        "force" => DELETE_MSG,
        _ if base.starts_with("delete-")
            && !matches!(base, "delete-after" | "delete-delay" | "delete-excluded") =>
        {
            DELETE_MSG
        }
        "one-file-system" => "syq does not implement -x/--one-file-system.",
        "sparse" => "syq does not implement -S/--sparse.",
        "hard-links" => "syq does not preserve hard links (-H/--hard-links).",
        "acls" => "syq does not preserve ACLs (-A/--acls).",
        "xattrs" => "syq does not preserve extended attributes (-X/--xattrs).",
        "copy-links" | "copy-unsafe-links" | "copy-dirlinks" => {
            "syq does not implement -L/--copy-links; it copies symlinks as symlinks (-l)."
        }
        "link-dest" | "compare-dest" | "copy-dest" => {
            "syq does not implement --link-dest/--compare-dest/--copy-dest."
        }
        _ => return None,
    })
}

fn message_for_short(c: char) -> Option<&'static str> {
    message_for_long(match c {
        'H' => "hard-links",
        'A' => "acls",
        'X' => "xattrs",
        'S' => "sparse",
        'x' => "one-file-system",
        'L' => "copy-links",
        _ => return None,
    })
}

pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m: u64 = match c.to_ascii_uppercase() {
                'K' => 1 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => bail!("bad size suffix in {s:?}"),
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1),
    };
    // Keep integral inputs exact, both to catch suffix multiplication
    // overflow and to allow the largest valid u64 without routing it through
    // f64 (which rounds u64::MAX up to 2^64).
    if !num.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        let n: u64 = num.parse().map_err(|_| anyhow::anyhow!("bad size {s:?}"))?;
        return n
            .checked_mul(mult)
            .ok_or_else(|| anyhow::anyhow!("bad size {s:?}: value is too large"));
    }
    let n: f64 = num.parse().map_err(|_| anyhow::anyhow!("bad size {s:?}"))?;
    if !n.is_finite() || n.is_sign_negative() {
        bail!("bad size {s:?}");
    }
    let bytes = n * mult as f64;
    // Integer casts saturate in Rust, so check the exclusive upper bound
    // explicitly instead of turning an overflow into u64::MAX.
    if !bytes.is_finite() || bytes >= u64::MAX as f64 {
        bail!("bad size {s:?}: value is too large");
    }
    Ok(bytes as u64)
}

#[cfg(test)]
mod tests {
    use super::{parse_size, Args};
    use clap::Parser;

    fn args(options: &[&str]) -> Args {
        let mut argv = vec!["syq"];
        argv.extend_from_slice(options);
        argv.extend_from_slice(&["src", "dst"]);
        let mut args = Args::try_parse_from(argv).unwrap();
        args.normalize();
        args
    }

    #[test]
    fn compression_defaults_on_and_can_be_disabled() {
        assert!(args(&[]).compress);
        assert!(args(&["-z"]).compress);
        assert!(!args(&["--no-compress"]).compress);

        // As with other clap overrides, the last spelling wins.
        assert!(!args(&["-z", "--no-compress"]).compress);
        assert!(args(&["--no-compress", "-z"]).compress);
    }

    #[test]
    fn tcp_congestion_names_are_validated() {
        assert_eq!(
            args(&["--tcp-congestion", "bbr"]).tcp_congestion.as_deref(),
            Some("bbr")
        );
        for value in ["", "not-an-algo", "1234567890123456"] {
            let parsed = Args::try_parse_from(["syq", "--tcp-congestion", value, "src", "dst"]);
            assert!(parsed.is_err(), "accepted {value:?}");
        }
        assert!(Args::try_parse_from(
            ["syq", "--tcp-congestion", "bbr", "--no-tcp", "src", "dst",]
        )
        .is_err());
    }

    #[test]
    fn size_parser_checks_sign_and_range() {
        assert_eq!(parse_size("1.5K").unwrap(), 1536);
        assert_eq!(parse_size("18446744073709551615").unwrap(), u64::MAX);
        for value in ["-1", "18446744073709551616", "16777216T", "1e999"] {
            assert!(parse_size(value).is_err(), "accepted {value:?}");
        }
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub user: Option<String>,
    pub host: Option<String>,
    /// Path as given (may be relative to the remote home).
    pub path: String,
}

impl Location {
    pub fn parse(s: &str) -> Result<Location> {
        // rsync rules: a colon before the first slash means remote,
        // unless the path starts with "/" or "./".
        let remote_split = if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
            None
        } else {
            let colon = s.find(':');
            let slash = s.find('/');
            match (colon, slash) {
                (Some(c), Some(sl)) if sl < c => None,
                (Some(c), _) => Some(c),
                (None, _) => None,
            }
        };
        let Some(c) = remote_split else {
            return Ok(Location {
                user: None,
                host: None,
                path: s.to_string(),
            });
        };
        let (hostpart, path) = (&s[..c], &s[c + 1..]);
        if path.starts_with(':') {
            bail!("rsync daemon syntax ({s}) is not supported");
        }
        let (user, host) = match hostpart.rsplit_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, hostpart),
        };
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if host.is_empty() {
            bail!("empty host in {s:?}");
        }
        let path = if path.is_empty() {
            ".".to_string()
        } else {
            path.to_string()
        };
        Ok(Location {
            user,
            host: Some(host),
            path,
        })
    }

    pub fn is_remote(&self) -> bool {
        self.host.is_some()
    }

    /// rsync trailing-slash semantics: "copy the contents" rather than the dir.
    pub fn copies_contents(&self) -> bool {
        let p = self.path.as_str();
        p.ends_with('/') || p == "." || p == ".." || p.ends_with("/.") || p.ends_with("/..")
    }

    pub fn basename(&self) -> String {
        let p = self.path.trim_end_matches('/');
        match p.rsplit('/').next() {
            Some(b) if !b.is_empty() => b.to_string(),
            _ => p.to_string(),
        }
    }

    pub fn same_host(&self, other: &Location) -> bool {
        self.user == other.user && self.host == other.host
    }
}

pub fn parse_rsh(rsh: &Option<String>) -> Result<Vec<String>> {
    match rsh {
        None => Ok(vec!["ssh".to_string()]),
        Some(s) => {
            let words = shell_words::split(s)?;
            if words.is_empty() {
                bail!("empty -e command");
            }
            Ok(words)
        }
    }
}
