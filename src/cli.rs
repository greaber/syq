use anyhow::{bail, Result};
use clap::{CommandFactory, FromArgMatches, Parser};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Interface {
    #[default]
    Rsync,
    NativeCp,
    NativeCprm,
    NativeRm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Placement {
    #[default]
    Rsync,
    Into,
    As,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Existence {
    #[default]
    Any,
    New,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceSelection {
    #[default]
    Rsync,
    Named,
    Contents,
    NamedNoFollow,
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "syq rsync",
    version,
    about = "Rsync-compatible copy syntax and semantics",
    disable_help_flag = true,
    override_usage = "syq rsync [OPTIONS] SRC... DEST\n       syq rsync [OPTIONS] [USER@]HOST:SRC... DEST\n       syq rsync [OPTIONS] SRC... [USER@]HOST:DEST"
)]
pub struct Args {
    /// Which public command produced this execution request.
    #[arg(skip)]
    pub interface: Interface,
    /// Explicit native placement; compatibility mode derives it from rsync syntax.
    #[arg(skip)]
    pub placement: Placement,
    /// Existence precondition attached to the native placement.
    #[arg(skip)]
    pub target_existence: Existence,
    /// Native parsing keeps endpoint and raw Unix path bytes separate. Compatibility
    /// mode leaves this empty and parses `paths` with rsync's colon rules.
    #[arg(skip)]
    pub locations: Vec<Location>,

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
    /// Follow destination-path symlinks owned by other users. This restores
    /// rsync's legacy behavior and is unsafe for a privileged receiver
    #[arg(long)]
    pub insecure_links: bool,

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
    /// Follow a detached transfer: syq rsync --follow HOST:LOGFILE
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
    /// Original source-operand count for a direct remote orchestrator
    #[arg(long, hide = true)]
    pub direct_source_operand_count: Option<usize>,
    /// Direct remote launch already deduplicated its raw source operands
    #[arg(long, hide = true, requires = "direct_source_operand_count")]
    pub direct_sources_prededuplicated: bool,

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
        let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
        let Some(command) = argv.first().and_then(|arg| arg.to_str()) else {
            if argv.is_empty() {
                print_root_help();
                std::process::exit(0);
            }
            bail!("command name is not valid UTF-8");
        };
        match command {
            "rsync" => Self::parse_rsync(&argv[1..]),
            "cp" => parse_native_copy(&argv[1..], false),
            "cprm" => parse_native_copy(&argv[1..], true),
            "rm" => parse_native_rm(&argv[1..]),
            "--help" | "-h" => {
                print_root_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("syq {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            // Product lifecycle switches predate the command grammar and remain
            // top-level until their eventual native command shape is settled.
            "--self-update" | "--register-standalone-install" => Self::parse_rsync(&argv),
            _ => bail!(
                "expected a command (`cp`, `cprm`, `rm`, or `rsync`); rsync-compatible syntax now starts with `syq rsync`"
            ),
        }
    }

    fn parse_rsync(argv: &[OsString]) -> Result<Args> {
        let argv: Vec<String> = argv
            .iter()
            .map(|arg| {
                arg.clone()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("rsync-compatible arguments must be valid UTF-8"))
            })
            .collect::<Result<_>>()?;
        reject_unsupported_rsync_flags(&argv)?;
        let mut full_argv = vec!["syq rsync".to_string()];
        full_argv.extend(argv);
        let m = Args::command()
            .try_get_matches_from(full_argv)
            .unwrap_or_else(|error| error.exit());
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

#[derive(Parser, Debug)]
#[command(
    name = "syq cp",
    about = "Copy selected objects with explicit endpoint and placement semantics"
)]
struct NativeCopyArgs {
    /// Source endpoint ([USER@]HOST); omitted means local
    #[arg(long, value_name = "ENDPOINT")]
    from: Option<String>,
    /// Resolve relative source selectors from DIR at the source endpoint
    #[arg(short = 'C', long, value_name = "DIR", allow_hyphen_values = true)]
    cwd: Option<OsString>,
    /// Select a named source object (repeatable; follows a top-level symlink)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    src: Vec<OsString>,
    /// Select a directory's contents (repeatable)
    #[arg(long, value_name = "DIR", allow_hyphen_values = true)]
    src_src: Vec<OsString>,
    /// Select a named source without following a top-level symlink (repeatable)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    src_no_follow: Vec<OsString>,

    /// Target endpoint ([USER@]HOST); omitted means local
    #[arg(long, value_name = "ENDPOINT")]
    to: Option<String>,
    /// Put selected names inside DIR, creating DIR if necessary
    #[arg(
        long,
        value_name = "DIR",
        group = "placement",
        allow_hyphen_values = true
    )]
    into: Option<OsString>,
    /// Put selected names inside a new DIR
    #[arg(
        long,
        value_name = "DIR",
        group = "placement",
        allow_hyphen_values = true
    )]
    into_new: Option<OsString>,
    /// Put selected names inside an existing directory
    #[arg(
        long,
        value_name = "DIR",
        group = "placement",
        allow_hyphen_values = true
    )]
    into_existing: Option<OsString>,
    /// Map the single named source exactly to PATH
    #[arg(
        long,
        value_name = "PATH",
        group = "placement",
        allow_hyphen_values = true
    )]
    r#as: Option<OsString>,
    /// Map the single named source exactly to a new PATH
    #[arg(
        long,
        value_name = "PATH",
        group = "placement",
        allow_hyphen_values = true
    )]
    as_new: Option<OsString>,
    /// Map the single named source exactly to an existing PATH
    #[arg(
        long,
        value_name = "PATH",
        group = "placement",
        allow_hyphen_values = true
    )]
    as_existing: Option<OsString>,

    /// Resolve and preview the operation without changing anything
    #[arg(short = 'n', long)]
    dry_run: bool,
    /// Increase verbosity (-v lists paths; -vv includes transport diagnostics)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Suppress non-error output
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Use a fixed number of parallel connections/workers
    #[arg(short = 'j', long = "connections", value_name = "N")]
    connections: Option<usize>,
    /// Show progress
    #[arg(long, overrides_with = "no_progress")]
    progress: bool,
    /// Never show progress
    #[arg(long)]
    no_progress: bool,
    /// Emit progress telemetry as JSON on stderr
    #[arg(long)]
    progress_json: bool,
    /// Print transfer statistics at the end
    #[arg(long)]
    stats: bool,
    /// Refuse all target-extra removals if more than N are planned (cprm only)
    #[arg(long, value_name = "N")]
    max_delete: Option<u64>,

    /// Relay a remote-to-remote transfer through this machine
    #[arg(long)]
    relay: bool,
    /// Run a remote-to-remote transfer detached on the source endpoint
    #[arg(long)]
    detach: bool,
    /// Disable transport compression
    #[arg(long)]
    no_compress: bool,
    /// Send data over SSH instead of separate TCP connections
    #[arg(long)]
    no_tcp: bool,
    /// Use unencrypted TCP data connections
    #[arg(long)]
    tcp_plain: bool,
    /// Port range used for TCP data connections
    #[arg(long, value_name = "LO-HI")]
    tcp_ports: Option<String>,
    /// Remote shell command (default: ssh)
    #[arg(long, value_name = "COMMAND")]
    rsh: Option<String>,
    /// Use this exact syq executable on remote endpoints
    #[arg(long, value_name = "PATH")]
    syq_path: Option<String>,
    /// Require syq on the remote PATH instead of installing a managed helper
    #[arg(long)]
    no_bootstrap: bool,
    /// Disable SSH-agent forwarding for direct remote-to-remote transfers
    #[arg(long, conflicts_with = "rsh")]
    no_forward_agent: bool,
    /// Original source endpoint for a remotely orchestrated dry-run summary
    #[arg(long, hide = true)]
    plan_source_host: Option<String>,
    /// Terminal width for a remotely orchestrated progress display
    #[arg(long, hide = true)]
    width: Option<usize>,

    /// Named source objects (shorthand for --src)
    #[arg(value_name = "PATH")]
    sources: Vec<OsString>,
}

#[derive(Parser, Debug)]
#[command(name = "syq rm", about = "Remove explicitly selected object trees")]
struct NativeRmArgs {
    /// Endpoint ([USER@]HOST); omitted means local
    #[arg(long, value_name = "ENDPOINT")]
    at: Option<String>,
    /// Resolve relative paths from DIR at the selected endpoint
    #[arg(short = 'C', long, value_name = "DIR", allow_hyphen_values = true)]
    cwd: Option<OsString>,
    /// Select a path to remove (repeatable)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    path: Vec<OsString>,
    /// Preview removals without changing anything
    #[arg(short = 'n', long)]
    dry_run: bool,
    /// Increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Suppress non-error output
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Use a fixed number of parallel workers
    #[arg(short = 'j', long = "connections", value_name = "N")]
    connections: Option<usize>,
    /// Show progress
    #[arg(long, overrides_with = "no_progress")]
    progress: bool,
    /// Never show progress
    #[arg(long)]
    no_progress: bool,
    /// Emit progress telemetry as JSON on stderr
    #[arg(long)]
    progress_json: bool,
    /// Disable transport compression
    #[arg(long)]
    no_compress: bool,
    /// Remote shell command (default: ssh)
    #[arg(long, value_name = "COMMAND")]
    rsh: Option<String>,
    /// Use this exact syq executable on a remote endpoint
    #[arg(long, value_name = "PATH")]
    syq_path: Option<String>,
    /// Require syq on the remote PATH instead of installing a managed helper
    #[arg(long)]
    no_bootstrap: bool,
    /// Selected paths (shorthand for --path)
    #[arg(value_name = "PATH")]
    paths: Vec<OsString>,
}

fn print_root_help() {
    println!(
        "Parallel copy with explicit native semantics\n\nUsage: syq <COMMAND> [OPTIONS]\n\nCommands:\n  cp     Copy selected objects without removing target-only objects\n  cprm   Copy, then remove target-only objects in the mapped scope\n  rm     Remove explicitly selected object trees\n  rsync  Use the retained rsync-compatible command surface\n\nRun `syq <COMMAND> --help` for command-specific help."
    );
}

fn native_defaults() -> Args {
    Args::try_parse_from(["syq rsync", "source", "destination"])
        .expect("internal compatibility defaults must parse")
}

fn parse_native_copy(argv: &[OsString], delete: bool) -> Result<Args> {
    let command_name = if delete { "syq cprm" } else { "syq cp" };
    let mut full_argv = vec![OsString::from(command_name)];
    full_argv.extend_from_slice(argv);
    let command = if delete {
        NativeCopyArgs::command()
            .name("syq cprm")
            .about("Copy selected objects, then remove target-only objects in mapped scopes")
    } else {
        NativeCopyArgs::command()
    };
    let matches = command
        .try_get_matches_from(full_argv)
        .unwrap_or_else(|error| error.exit());
    let parsed = NativeCopyArgs::from_arg_matches(&matches)?;

    let mut ordered: Vec<(usize, SourceSelection, OsString)> = Vec::new();
    if let Some(indices) = matches.indices_of("sources") {
        ordered.extend(
            indices
                .zip(parsed.sources.iter().cloned())
                .map(|(index, path)| (index, SourceSelection::Named, path)),
        );
    }
    for (id, selection, paths) in [
        ("src", SourceSelection::Named, &parsed.src),
        ("src_src", SourceSelection::Contents, &parsed.src_src),
        (
            "src_no_follow",
            SourceSelection::NamedNoFollow,
            &parsed.src_no_follow,
        ),
    ] {
        if let Some(indices) = matches.indices_of(id) {
            ordered.extend(
                indices
                    .zip(paths.iter().cloned())
                    .map(|(index, path)| (index, selection, path)),
            );
        }
    }
    ordered.sort_by_key(|(index, _, _)| *index);
    if ordered.is_empty() {
        bail!("{command_name} needs at least one source selector");
    }

    let placements = [
        (parsed.into, Placement::Into, Existence::Any),
        (parsed.into_new, Placement::Into, Existence::New),
        (parsed.into_existing, Placement::Into, Existence::Existing),
        (parsed.r#as, Placement::As, Existence::Any),
        (parsed.as_new, Placement::As, Existence::New),
        (parsed.as_existing, Placement::As, Existence::Existing),
    ];
    let Some((target, placement, target_existence)) = placements
        .into_iter()
        .find_map(|(path, placement, existence)| path.map(|p| (p, placement, existence)))
    else {
        bail!("{command_name} requires one of --into, --into-new, --into-existing, --as, --as-new, or --as-existing");
    };
    if placement == Placement::As
        && (ordered.len() != 1 || ordered[0].1 == SourceSelection::Contents)
    {
        bail!("--as, --as-new, and --as-existing require exactly one named source");
    }
    if !delete && parsed.max_delete.is_some() {
        bail!("--max-delete is only valid with cprm");
    }

    let source_endpoint = parse_native_endpoint(parsed.from.as_deref())?;
    let target_endpoint = parse_native_endpoint(parsed.to.as_deref())?;
    let cwd = parsed.cwd.as_deref().map(OsStrExt::as_bytes);
    let mut locations = Vec::with_capacity(ordered.len() + 1);
    for (_, selection, path) in ordered {
        let path = qualify_source(cwd, path.into_vec());
        if path.is_empty() {
            bail!("source selectors may not be empty");
        }
        if placement == Placement::Into
            && selection != SourceSelection::Contents
            && native_basename(&path).is_none()
        {
            bail!(
                "named source {:?} has no target basename; select a path ending in a named object or use --src-src for directory contents",
                String::from_utf8_lossy(&path)
            );
        }
        locations.push(Location::native(source_endpoint.clone(), path, selection));
    }
    let target = target.into_vec();
    if target.is_empty() {
        bail!("target paths may not be empty");
    }
    locations.push(Location::native(
        target_endpoint,
        target,
        SourceSelection::Named,
    ));

    let mut args = native_defaults();
    args.interface = if delete {
        Interface::NativeCprm
    } else {
        Interface::NativeCp
    };
    args.placement = placement;
    args.target_existence = target_existence;
    args.locations = locations;
    args.paths.clear();
    // Structural traversal and symlink objects are part of native copy, while
    // ownership, group, modes, special files, and richer fidelity profiles are
    // left to the still-open preservation design. Mtime is retained so normal
    // quick-check reruns remain useful.
    args.recursive = true;
    args.links = true;
    args.times = true;
    args.delete = delete;
    args.max_delete = parsed.max_delete;
    args.dry_run = parsed.dry_run;
    args.verbose = parsed.verbose;
    args.quiet = parsed.quiet;
    args.connections_opt = parsed.connections;
    args.progress = parsed.progress;
    args.no_progress = parsed.no_progress;
    args.progress_json = parsed.progress_json;
    args.stats = parsed.stats;
    args.relay = parsed.relay;
    args.detach = parsed.detach;
    args.no_compress = parsed.no_compress;
    args.no_tcp = parsed.no_tcp;
    args.tcp_plain = parsed.tcp_plain;
    if let Some(ports) = parsed.tcp_ports {
        args.tcp_ports = ports;
    }
    args.rsh = parsed.rsh;
    args.syq_path = parsed.syq_path;
    args.no_bootstrap = parsed.no_bootstrap;
    args.no_forward_agent = parsed.no_forward_agent;
    args.plan_source_host = parsed.plan_source_host;
    args.width = parsed.width;
    Ok(args)
}

fn parse_native_rm(argv: &[OsString]) -> Result<Args> {
    let mut full_argv = vec![OsString::from("syq rm")];
    full_argv.extend_from_slice(argv);
    let matches = NativeRmArgs::command()
        .try_get_matches_from(full_argv)
        .unwrap_or_else(|error| error.exit());
    let parsed = NativeRmArgs::from_arg_matches(&matches)?;
    let mut ordered: Vec<(usize, OsString)> = Vec::new();
    if let Some(indices) = matches.indices_of("paths") {
        ordered.extend(indices.zip(parsed.paths.iter().cloned()));
    }
    if let Some(indices) = matches.indices_of("path") {
        ordered.extend(indices.zip(parsed.path.iter().cloned()));
    }
    ordered.sort_by_key(|(index, _)| *index);
    if ordered.is_empty() {
        bail!("syq rm needs at least one path selector");
    }
    let endpoint = parse_native_endpoint(parsed.at.as_deref())?;
    let cwd = parsed.cwd.as_deref().map(OsStrExt::as_bytes);
    let mut locations = Vec::with_capacity(ordered.len());
    for (_, path) in ordered {
        let path = qualify_source(cwd, path.into_vec());
        if path.is_empty() {
            bail!("path selectors may not be empty");
        }
        locations.push(Location::native(
            endpoint.clone(),
            path,
            SourceSelection::NamedNoFollow,
        ));
    }

    let mut args = native_defaults();
    args.interface = Interface::NativeRm;
    args.locations = locations;
    args.paths.clear();
    args.rm = true;
    args.dry_run = parsed.dry_run;
    args.verbose = parsed.verbose;
    args.quiet = parsed.quiet;
    args.connections_opt = parsed.connections;
    args.progress = parsed.progress;
    args.no_progress = parsed.no_progress;
    args.progress_json = parsed.progress_json;
    args.no_compress = parsed.no_compress;
    args.rsh = parsed.rsh;
    args.syq_path = parsed.syq_path;
    args.no_bootstrap = parsed.no_bootstrap;
    Ok(args)
}

fn qualify_source(cwd: Option<&[u8]>, path: Vec<u8>) -> Vec<u8> {
    let Some(cwd) = cwd else {
        return path;
    };
    if path.starts_with(b"/") || path == b"~" || path.starts_with(b"~/") {
        return path;
    }
    crate::fsops::join(cwd, &path)
}

fn trim_trailing_slashes(mut path: &[u8]) -> &[u8] {
    while path.ends_with(b"/") {
        path = &path[..path.len() - 1];
    }
    path
}

fn native_basename(path: &[u8]) -> Option<&[u8]> {
    let name = trim_trailing_slashes(path)
        .rsplit(|byte| *byte == b'/')
        .next()?;
    (!name.is_empty() && name != b"." && name != b"..").then_some(name)
}

fn parse_native_endpoint(spec: Option<&str>) -> Result<Option<(Option<String>, String)>> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    let (user, host) = match spec.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() => (Some(user.to_string()), host),
        Some(_) => bail!("empty user in endpoint {spec:?}"),
        None => (None, spec),
    };
    let bracketed = host.starts_with('[') && host.ends_with(']');
    if host.starts_with('[') != host.ends_with(']') {
        bail!("mismatched brackets in endpoint {spec:?}");
    }
    if host.contains(':') && !bracketed {
        bail!(
            "endpoint {spec:?} contains `:`; pass paths separately and write IPv6 hosts in brackets"
        );
    }
    let host = if bracketed {
        &host[1..host.len() - 1]
    } else {
        host
    };
    if host.is_empty() {
        bail!("empty host in endpoint {spec:?}");
    }
    if host.contains('/') {
        bail!("endpoint {spec:?} contains a path; pass paths separately with --cwd and source/placement arguments");
    }
    Ok(Some((user, host.to_string())))
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
    // way on every orchestrator. The kernel otherwise looks up the registered
    // name exactly, without imposing a character whitelist.
    if value.is_empty() {
        return Err("congestion-control algorithm cannot be empty".into());
    }
    if value.len() >= 16 {
        return Err("congestion-control algorithm must be at most 15 bytes".into());
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
    fn insecure_links_is_an_explicit_opt_out() {
        assert!(!args(&[]).insecure_links);
        assert!(args(&["--insecure-links"]).insecure_links);
    }

    #[test]
    fn tcp_congestion_names_are_validated() {
        assert_eq!(
            args(&["--tcp-congestion", "bbr"]).tcp_congestion.as_deref(),
            Some("bbr")
        );
        assert_eq!(
            args(&["--tcp-congestion", "foo-bar"])
                .tcp_congestion
                .as_deref(),
            Some("foo-bar")
        );
        for value in ["", "1234567890123456"] {
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
    pub path: Vec<u8>,
    pub selection: SourceSelection,
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
                path: s.as_bytes().to_vec(),
                selection: SourceSelection::Rsync,
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
            path: path.into_bytes(),
            selection: SourceSelection::Rsync,
        })
    }

    fn native(
        endpoint: Option<(Option<String>, String)>,
        mut path: Vec<u8>,
        selection: SourceSelection,
    ) -> Location {
        // Native trailing slashes are spelling only. Remove them before any
        // filesystem call so `link/` cannot make lstat/remove operations
        // traverse a symlink that the selector explicitly chose as an object.
        while path.len() > 1 && path.ends_with(b"/") {
            path.pop();
        }
        let (user, host) = endpoint
            .map(|(user, host)| (user, Some(host)))
            .unwrap_or((None, None));
        Location {
            user,
            host,
            path,
            selection,
        }
    }

    pub fn is_remote(&self) -> bool {
        self.host.is_some()
    }

    /// rsync trailing-slash semantics: "copy the contents" rather than the dir.
    pub fn copies_contents(&self) -> bool {
        match self.selection {
            SourceSelection::Contents => true,
            SourceSelection::Named | SourceSelection::NamedNoFollow => false,
            SourceSelection::Rsync => {
                let p = self.path.as_slice();
                p.ends_with(b"/")
                    || p == b"."
                    || p == b".."
                    || p.ends_with(b"/.")
                    || p.ends_with(b"/..")
            }
        }
    }

    pub fn follows_root(&self) -> bool {
        match self.selection {
            SourceSelection::Named | SourceSelection::Contents => true,
            SourceSelection::NamedNoFollow => false,
            SourceSelection::Rsync => self.copies_contents(),
        }
    }

    pub fn requires_directory(&self) -> bool {
        self.selection == SourceSelection::Contents
    }

    pub fn basename(&self) -> Vec<u8> {
        let p = trim_trailing_slashes(&self.path);
        match p.rsplit(|byte| *byte == b'/').next() {
            Some(b) if !b.is_empty() => b.to_vec(),
            _ => p.to_vec(),
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
