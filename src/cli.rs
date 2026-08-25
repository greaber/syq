use anyhow::{bail, Result};
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "pcp",
    version,
    about = "Parallel copy with an rsync-shaped interface",
    disable_help_flag = true,
    override_usage = "pcp [OPTIONS] SRC... DEST\n       pcp [OPTIONS] [USER@]HOST:SRC... DEST\n       pcp [OPTIONS] SRC... [USER@]HOST:DEST"
)]
pub struct Args {
    /// Print help
    #[arg(long, action = clap::ArgAction::Help)]
    pub help: Option<bool>,

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
    /// Accepted for rsync compatibility (sizes are always human-readable)
    #[arg(short = 'h', long)]
    pub human_readable: bool,

    /// Number of parallel data connections
    #[arg(short = 'j', long, default_value = "8", value_name = "N")]
    pub connections: usize,
    /// Transfer/hash block size (e.g. 4M)
    #[arg(long, default_value = "4M", value_name = "SIZE")]
    pub block_size: String,
    /// Don't split in-flight files with less than this much left (e.g. 32M)
    #[arg(long, default_value = "32M", value_name = "SIZE")]
    pub min_split: String,

    /// Show progress (default when stderr is a terminal)
    #[arg(long, overrides_with = "no_progress")]
    pub progress: bool,
    /// Never show progress
    #[arg(long)]
    pub no_progress: bool,
    /// Same as --progress --partial
    #[arg(short = 'P')]
    pub p_flag: bool,
    /// Keep partially transferred files (always on; accepted for compatibility)
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
    /// Write directly into destination files instead of partial + rename
    #[arg(long)]
    pub inplace: bool,

    /// Remote shell command (default: ssh)
    #[arg(short = 'e', long = "rsh", value_name = "COMMAND")]
    pub rsh: Option<String>,
    /// Path to pcp on the remote host
    #[arg(long, value_name = "PATH")]
    pub pcp_path: Option<String>,
    /// Install this pcp binary on the remote host (~/.local/bin/pcp) if missing
    #[arg(long)]
    pub bootstrap: bool,
    /// Remote-to-remote: relay data through this machine instead of running on the source host
    #[arg(long)]
    pub relay: bool,
    /// Terminal width for the progress display (internal; used for remote-to-remote)
    #[arg(long, hide = true)]
    pub width: Option<usize>,

    /// Source(s) and destination
    #[arg(required = true, num_args = 2.., value_name = "PATH")]
    pub paths: Vec<String>,
}

impl Args {
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
        if self.connections == 0 {
            self.connections = 1;
        }
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
            return Ok(Location { user: None, host: None, path: s.to_string() });
        };
        let (hostpart, path) = (&s[..c], &s[c + 1..]);
        if path.starts_with(':') {
            bail!("rsync daemon syntax ({s}) is not supported");
        }
        let (user, host) = match hostpart.rsplit_once('@') {
            Some((u, h)) => (Some(u.to_string()), h),
            None => (None, hostpart),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        if host.is_empty() {
            bail!("empty host in {s:?}");
        }
        let path = if path.is_empty() { ".".to_string() } else { path.to_string() };
        Ok(Location { user, host: Some(host), path })
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
