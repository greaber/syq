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

    /// Increase verbosity (list files as they complete)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Suppress non-error messages
    #[arg(short = 'q', long)]
    pub quiet: bool,
    /// Compress data in transit (zstd)
    #[arg(short = 'z', long)]
    pub compress: bool,
    /// Show what would be transferred without doing it
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// No-op accepted for rsync compatibility (sizes are always human-readable)
    #[arg(short = 'h', long)]
    pub human_readable: bool,
    /// No-op accepted for rsync compatibility (syq always uses numeric uid/gid)
    #[arg(long)]
    pub numeric_ids: bool,

    /// Parallel connections/workers. Default for copies: auto-tuned — starts at 16
    /// over TCP, 8 over ssh, or 32 when local; grows while throughput improves and
    /// shrinks when that costs nothing. Give a number to fix it. --rm uses a fixed
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
    /// of it changes)
    #[arg(long)]
    pub inplace: bool,
    /// fsync each file and its parent directory around the rename, so a completed file
    /// survives a crash; also syncs an explicitly requested checkpoint (slower, especially on NFS)
    #[arg(long)]
    pub fsync: bool,

    /// Save completed-file state here; reuse the same file to accelerate a retry. The file is
    /// retained after interruption or failure and removed after a clean copy.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["checksum", "verify_only", "rm"]
    )]
    pub checkpoint: Option<String>,

    /// Remote shell command (default: ssh)
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
    /// Terminal width for the progress display (internal; used for remote-to-remote)
    #[arg(long, hide = true)]
    pub width: Option<usize>,

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

    /// Remove the given paths recursively and in parallel (like rm -rf); honours -j, -n, -v, -q, -e
    #[arg(long, conflicts_with_all = ["ignore", "ignore_from"])]
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
        Ok(args)
    }

    pub fn normalize(&mut self) {
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
        "--checkpoint",
        "--tcp-ports",
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
const DELETE_MSG: &str = "syq does not implement --delete; it never removes files from the destination. To delete paths, run `syq --rm PATH...` explicitly.";

fn message_for_long(base: &str) -> Option<&'static str> {
    Some(match base {
        "exclude" | "exclude-from" | "include" | "include-from" | "filter" => FILTER_MSG,
        "delete" => DELETE_MSG,
        _ if base.starts_with("delete-") => DELETE_MSG,
        "update" => "syq does not implement -u/--update (skip files newer on the receiver).",
        "one-file-system" => "syq does not implement -x/--one-file-system.",
        "sparse" => "syq does not implement -S/--sparse.",
        "hard-links" => "syq does not preserve hard links (-H/--hard-links).",
        "acls" => "syq does not preserve ACLs (-A/--acls).",
        "xattrs" => "syq does not preserve extended attributes (-X/--xattrs).",
        "copy-links" | "copy-unsafe-links" | "copy-dirlinks" => {
            "syq does not implement -L/--copy-links; it copies symlinks as symlinks (-l)."
        }
        "files-from" => "syq does not implement --files-from.",
        "link-dest" | "compare-dest" | "copy-dest" => {
            "syq does not implement --link-dest/--compare-dest/--copy-dest."
        }
        _ => return None,
    })
}

fn message_for_short(c: char) -> Option<&'static str> {
    message_for_long(match c {
        'u' => "update",
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
    let n: f64 = num.parse().map_err(|_| anyhow::anyhow!("bad size {s:?}"))?;
    Ok((n * mult as f64) as u64)
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

    #[allow(dead_code)]
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
