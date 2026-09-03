use anyhow::{bail, Result};
use clap::{CommandFactory, FromArgMatches, Parser, ValueEnum};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Interface {
    #[default]
    Rsync,
    NativeCp,
    NativeRm,
    NativeMap,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SourceSelection {
    #[default]
    Rsync,
    Named,
    Contents,
    NamedNoFollow,
    File,
    Directory,
}

/// Endpoint that owns the transfer coordinator for a native copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum CoordinateAt {
    /// Run locally unless both endpoints are remote, then use the source when
    /// possible and otherwise refuse the transfer.
    #[default]
    Auto,
    /// Run the coordinator at the source endpoint.
    Src,
    /// Run the coordinator at the destination endpoint.
    Dest,
    /// Keep the coordinator on the invoking machine and relay the data there.
    Local,
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "syq rsync",
    version,
    about = "Parallel copy with an rsync-shaped interface",
    disable_help_flag = true,
    override_usage = "syq rsync [OPTIONS] SRC... DEST\n       syq rsync [OPTIONS] [USER@]HOST:SRC... DEST\n       syq rsync [OPTIONS] SRC... [USER@]HOST:DEST"
)]
pub struct Args {
    /// Which public command produced this execution request.
    #[arg(skip)]
    pub interface: Interface,
    /// Explicit native placement; rsync mode derives placement from its operands.
    #[arg(skip)]
    pub placement: Placement,
    /// Lightweight native placement-root existence condition.
    #[arg(skip)]
    pub target_existence: Existence,
    /// Native parsing keeps endpoints separate from raw Unix path bytes.
    #[arg(skip)]
    pub locations: Vec<Location>,
    /// Endpoint-side base for native removal. Unlike copy's `--cwd`, this is
    /// not joined into selector strings by the coordinator.
    #[arg(skip)]
    pub native_rm_cwd: Option<Vec<u8>>,
    /// Endpoint-side containment boundary for native removal.
    #[arg(skip)]
    pub native_rm_root: Option<Vec<u8>>,
    /// Permit symlinks that must be traversed in directly supplied native paths.
    #[arg(skip)]
    pub native_follow: bool,
    /// Source-side base for `syq map` selectors, joined at walk time so the
    /// emitted `src` values stay relative to it.
    #[arg(skip)]
    pub native_map_cwd: Option<Vec<u8>>,
    /// The placement destination for `syq map`, kept only for `--as` renaming;
    /// `syq map` never contacts a destination.
    #[arg(skip)]
    pub native_map_target: Option<Vec<u8>>,
    /// NDJSON mapping manifest consumed by native cp instead of selectors
    /// (`-` reads stdin, streamed).
    #[arg(skip)]
    pub native_mapping: Option<Vec<u8>>,
    /// `--results` NDJSON outcome stream for native cp (`-` writes stdout).
    #[arg(skip)]
    pub native_results: Option<Vec<u8>>,
    /// `--results-fd`: an inherited descriptor the caller opened for the
    /// stream; validated and wrapped at startup.
    #[arg(skip)]
    pub native_results_fd: Option<i32>,
    /// Native coordinator placement.
    #[arg(skip)]
    pub coordinate_at: CoordinateAt,
    /// Native local-relay selection derived from `--coordinate-at local`.
    #[arg(skip)]
    pub relay: bool,
    /// Native detached remote coordinator.
    #[arg(skip)]
    pub detach: bool,
    /// Native remote coordinator uses its own peer credential.
    #[arg(skip)]
    pub no_forward_agent: bool,
    /// Native remote coordinator receives the complete local SSH agent.
    #[arg(skip)]
    pub unrestricted_agent_forwarding: bool,
    /// Native remote coordinator uses authentication-only broker confinement.
    #[arg(skip)]
    pub agent_broker_only: bool,

    /// Print help
    #[arg(long, action = clap::ArgAction::Help)]
    pub help: Option<bool>,

    /// Install the newest signed release (standalone installer builds only)
    #[arg(long, hide = true, exclusive = true)]
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
    /// copy has enough work to measure. Give a number to fix it.
    #[arg(long = "syq-connections", value_name = "N")]
    pub connections_opt: Option<usize>,
    #[arg(skip)]
    pub connections: usize,
    #[arg(skip)]
    pub connections_default: bool,
    /// Transfer/hash block size (e.g. 4M)
    #[arg(short = 'B', long, default_value = "4M", value_name = "SIZE")]
    pub block_size: String,
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
    /// SYQ extension: emit machine-readable progress lines (JSON) on stderr
    #[arg(long = "syq-progress-json")]
    pub progress_json: bool,
    /// Print transfer statistics at the end
    #[arg(long)]
    pub stats: bool,

    /// Skip quick check; compare file contents block by block and repair differences
    #[arg(short = 'c', long)]
    pub checksum: bool,
    /// SYQ extension: only compare source and destination contents; transfer nothing
    #[arg(long = "syq-verify-only")]
    pub verify_only: bool,
    /// Update files in place instead of writing a partial and renaming. Use this to modify a
    /// large existing file without copying it first (saves time and disk space when only part
    /// of it changes). Cannot be combined with -u or --ignore-existing: an interrupted
    /// in-place write leaves a newer-looking final file those filters would then skip forever
    #[arg(long, conflicts_with_all = ["update", "ignore_existing"])]
    pub inplace: bool,
    /// Remote shell command (default: ssh); controls agent forwarding when set
    #[arg(short = 'e', long = "rsh", value_name = "COMMAND")]
    pub rsh: Option<String>,
    /// Use this exact syq executable on the remote instead of the managed helper
    #[arg(long = "rsync-path", value_name = "PATH")]
    pub syq_path: Option<String>,
    /// SYQ extension: require syq on the remote PATH instead of installing a versioned helper
    #[arg(long = "syq-no-bootstrap")]
    pub no_bootstrap: bool,
    /// SYQ extension: use TCP data connections without encryption (trusted networks only)
    #[arg(long = "syq-tcp-plain")]
    pub tcp_plain: bool,
    /// SYQ extension: send all data over ssh instead of separate TCP data connections
    #[arg(long = "syq-no-tcp")]
    pub no_tcp: bool,
    /// SYQ extension: port range the remote listens on for TCP data connections
    #[arg(
        long = "syq-tcp-ports",
        default_value = "47600-47699",
        value_name = "LO-HI"
    )]
    pub tcp_ports: String,
    /// SYQ extension: use this congestion-control algorithm for direct TCP data sockets (Linux only)
    #[arg(
        long = "syq-tcp-congestion",
        value_name = "ALGO",
        value_parser = parse_tcp_congestion,
        conflicts_with = "no_tcp"
    )]
    pub tcp_congestion: Option<String>,
    /// SYQ extension: use an isolated SSH persistence scope created by `syq persist on --ephemeral`
    #[arg(long = "syq-pscope", value_name = "PATH", conflicts_with = "rsh")]
    pub pscope: Option<PathBuf>,
    /// Whether --syq-pscope was supplied rather than selected by the user-level policy
    #[arg(skip)]
    pub pscope_explicit: bool,
    /// Signed receiver grant forwarded to a native source-host coordinator
    #[arg(skip)]
    pub restricted_grant: Option<String>,
    /// Terminal width for a native remote coordinator's progress display
    #[arg(skip)]
    pub width: Option<usize>,
    /// Original source endpoint for a native remote coordinator's dry-run summary
    #[arg(skip)]
    pub plan_source_host: Option<String>,
    /// SYQ extension: skip paths matching PATTERN (gitignore syntax: `foo` matches at any depth, `/foo` only
    /// at the source root, `foo/` only directories, `!pat` re-includes). Repeatable; together
    /// with --syq-ignore-from the patterns act like the lines of one .gitignore file, in
    /// command-line order, anchored at each source root. Skipping a directory skips its
    /// whole subtree, so to copy only *.jpg use: --syq-ignore '*' --syq-ignore '!*/'
    /// --syq-ignore '!*.jpg'
    #[arg(
        long = "syq-ignore",
        value_name = "PATTERN",
        allow_hyphen_values = true
    )]
    pub ignore: Vec<String>,
    /// SYQ extension: read ignore patterns from FILE (one per line, # comments); repeatable
    #[arg(long = "syq-ignore-from", value_name = "FILE")]
    pub ignore_from: Vec<String>,
    /// All ignore patterns, in command-line order (filled by parse_args)
    #[arg(skip)]
    pub ignore_lines: Vec<String>,

    /// Delete extraneous files from the destination directories (paths the source does not
    /// have). Deletion happens after the transfer and is skipped entirely if the source scan
    /// reported any error. Ignored paths (--syq-ignore) are protected on both sides. rsync's
    /// --delete-after and --delete-delay mean the same thing and are accepted. Cannot be combined
    /// with --syq-verify-only or --files-from
    #[arg(
        long,
        aliases = ["delete-after", "delete-delay"],
        conflicts_with_all = ["verify_only", "files_from"]
    )]
    pub delete: bool,
    /// With --delete, also remove destination paths that the --syq-ignore patterns exclude
    #[arg(long, requires = "delete")]
    pub delete_excluded: bool,
    /// With --delete, refuse all deletions if more than N are planned (exit 25).
    /// Unlike positive rsync limits, this is atomic; 0 and -1 both prohibit deletion
    #[arg(
        long,
        value_name = "N",
        value_parser = parse_max_delete,
        allow_hyphen_values = true
    )]
    pub max_delete: Option<u64>,
    /// Native-only command-restricted receiver ceilings, signed into the grant.
    #[arg(skip)]
    pub max_entries: Option<u64>,
    #[arg(skip)]
    pub max_total_bytes: Option<u64>,
    #[arg(skip)]
    pub max_runtime_secs: Option<u32>,
    /// Native-only: `--receipt` was given at all, and whether it asked the
    /// command-restricted receiver for a hashed receipt.
    #[arg(skip)]
    pub receipt_requested: bool,
    #[arg(skip)]
    pub receipt_hashed: bool,
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

    /// Native `syq rm` dispatch marker
    #[arg(skip)]
    pub rm: bool,

    /// Source(s) and destination
    #[arg(
        required_unless_present_any = ["self_update", "register_standalone_install"],
        num_args = 1..,
        value_name = "PATH"
    )]
    pub paths: Vec<String>,
}

impl Args {
    /// Parse the command line and read ignore files, keeping command-line and
    /// file patterns in the order they were given (later lines win, as in
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
            "rsync" => Self::parse_rsync(&argv[1..], false),
            "cp" => parse_native(&argv[1..], Interface::NativeCp),
            "rm" => parse_native(&argv[1..], Interface::NativeRm),
            "map" => parse_native(&argv[1..], Interface::NativeMap),
            "--help" | "-h" => {
                print_root_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("syq {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            // Installation lifecycle switches remain top-level. Internal
            // helper switches are handled in main.
            "--self-update" | "--register-standalone-install" => Self::parse_rsync(&argv, true),
            _ => bail!(
                "expected a command (`cp`, `rm`, `map`, `rsync`, or `persist`); rsync-shaped syntax now starts with `syq rsync`"
            ),
        }
    }

    fn parse_rsync(argv: &[OsString], allow_lifecycle: bool) -> Result<Args> {
        let utf8_argv: Vec<String> = argv
            .iter()
            .map(|arg| {
                arg.clone()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("rsync-compatible arguments must be valid UTF-8"))
            })
            .collect::<Result<_>>()?;
        if !allow_lifecycle
            && utf8_argv.iter().any(|argument| {
                matches!(
                    argument.as_str(),
                    "--self-update" | "--register-standalone-install"
                )
            })
        {
            bail!("installation lifecycle options are top-level syq options, not rsync options");
        }
        reject_unsupported_rsync_flags(&utf8_argv)?;
        let mut full_argv = vec!["syq rsync".to_string()];
        full_argv.extend(utf8_argv);
        let matches = Args::command()
            .try_get_matches_from(full_argv)
            .unwrap_or_else(|error| error.exit());
        let args = Args::from_arg_matches(&matches)?;
        reject_remote_to_remote(&args)?;
        finish_parse(args, &matches)
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

fn finish_parse(mut args: Args, matches: &clap::ArgMatches) -> Result<Args> {
    args.bwlimit_bytes = args
        .bwlimit
        .as_deref()
        .map(crate::bwlimit::parse_rate)
        .transpose()?
        .unwrap_or(0);
    args.ignore_lines = ordered_ignore_lines(
        &args.ignore,
        &args.ignore_from,
        matches,
        true,
        "--syq-ignore-from",
    )?;
    if let Some(f) = &args.files_from {
        args.files_from_lines = read_files_from(f, args.from0)?;
    }
    Ok(args)
}

fn reject_remote_to_remote(args: &Args) -> Result<()> {
    let Some((destination, sources)) = args.paths.split_last() else {
        return Ok(());
    };
    if sources.is_empty() || !Location::parse(destination)?.is_remote() {
        return Ok(());
    }
    if sources
        .iter()
        .map(|source| Location::parse(source))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .any(Location::is_remote)
    {
        bail!("The source and destination cannot both be remote.");
    }
    Ok(())
}

fn ordered_ignore_lines(
    ignore: &[String],
    ignore_from: &[String],
    matches: &clap::ArgMatches,
    follow_paths: bool,
    ignore_from_name: &str,
) -> Result<Vec<String>> {
    let mut items: Vec<(usize, bool, String)> = Vec::new();
    if let Some(indices) = matches.indices_of("ignore") {
        items.extend(
            indices
                .zip(ignore)
                .map(|(index, value)| (index, false, value.clone())),
        );
    }
    if let Some(indices) = matches.indices_of("ignore_from") {
        items.extend(
            indices
                .zip(ignore_from)
                .map(|(index, value)| (index, true, value.clone())),
        );
    }
    items.sort_by_key(|(index, _, _)| *index);

    let mut lines = Vec::new();
    for (_, from_file, value) in items {
        if from_file {
            if !follow_paths {
                crate::fsops::check_operator_path_no_symlinks(value.as_bytes(), false, false)
                    .map_err(|error| anyhow::anyhow!("{ignore_from_name} {value}: {error}"))?;
            }
            let text = std::fs::read_to_string(&value)
                .map_err(|error| anyhow::anyhow!("{ignore_from_name} {value}: {error}"))?;
            let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
            lines.extend(
                text.lines()
                    .map(|line| line.trim_end_matches('\r').to_string()),
            );
        } else {
            lines.push(value);
        }
    }
    Ok(lines)
}

fn print_root_help() {
    println!(
        "Parallel endpoint-aware filesystem operations\n\nUsage: syq <COMMAND> [OPTIONS]\n       syq --self-update\n\nCommands:\n  cp           Copy selected objects, optionally pruning destination-only objects\n  rm           Remove explicitly selected object trees\n  map          Print a local source selection as an NDJSON mapping\n  rsync        Use the retained rsync-shaped command surface\n  persist      Manage reusable SSH control connections\n  enrollment   Manage command-restricted receiver enrollments (add, list, revoke)\n\nRun `syq <COMMAND> --help` for command-specific help."
    );
}

#[derive(clap::Args, Debug)]
struct NativeSourceArgs {
    /// Resolve relative source selectors from DIR
    #[arg(short = 'C', long, value_name = "DIR", allow_hyphen_values = true)]
    cwd: Option<OsString>,
    /// Follow symlinks that must be traversed in directly supplied endpoint paths
    #[arg(long)]
    follow: bool,
    /// Select a named source object (repeatable)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    src: Vec<OsString>,
    /// Select a directory's contents (repeatable)
    #[arg(long, value_name = "DIR", allow_hyphen_values = true)]
    src_src: Vec<OsString>,
    /// Select a named non-directory source object (repeatable)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    src_file: Vec<OsString>,
    /// Select a named source directory (repeatable)
    #[arg(long, value_name = "DIR", allow_hyphen_values = true)]
    src_dir: Vec<OsString>,
    /// Select several named non-directory source objects
    #[arg(long, value_name = "PATH", num_args = 1..)]
    src_files: Vec<OsString>,
    /// Select several named source directories
    #[arg(long, value_name = "DIR", num_args = 1..)]
    src_dirs: Vec<OsString>,
    /// Select several named source objects
    #[arg(long, value_name = "PATH", num_args = 1..)]
    srcs: Vec<OsString>,
    /// Select the contents of several directories
    #[arg(long, value_name = "DIR", num_args = 1..)]
    src_srcs: Vec<OsString>,
    /// Named source objects (shorthand for --src)
    #[arg(value_name = "PATH")]
    sources: Vec<OsString>,
}

#[derive(clap::Args, Debug)]
struct NativeSelectionArgs {
    /// Source endpoint ([USER@]HOST[:PORT]); omitted means local
    #[arg(long, value_name = "ENDPOINT")]
    from: Option<String>,
    #[command(flatten)]
    source: NativeSourceArgs,
}

#[derive(clap::Args, Debug)]
struct NativeRmSelectionArgs {
    /// Source endpoint ([USER@]HOST[:PORT]); omitted means local
    #[arg(long, value_name = "ENDPOINT")]
    from: Option<String>,
    /// Resolve relative selectors from DIR at the source endpoint
    #[arg(
        short = 'C',
        long,
        value_name = "DIR",
        allow_hyphen_values = true,
        conflicts_with = "root"
    )]
    cwd: Option<OsString>,
    /// Confine resolution and removal beneath DIR
    #[arg(long, value_name = "DIR", allow_hyphen_values = true)]
    root: Option<OsString>,
    /// Follow symlinks that must be traversed in directly supplied endpoint paths
    #[arg(long)]
    follow: bool,
    /// Select an object without constraining the selected object's type (repeatable)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    src: Vec<OsString>,
    /// Select a directory's contents, retaining the directory (repeatable)
    #[arg(long, value_name = "DIR", allow_hyphen_values = true)]
    src_src: Vec<OsString>,
    /// Select a non-directory object (repeatable)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    src_file: Vec<OsString>,
    /// Select a directory tree (repeatable)
    #[arg(long, value_name = "DIR", allow_hyphen_values = true)]
    src_dir: Vec<OsString>,
    /// Select several non-directory objects
    #[arg(long, value_name = "PATH", num_args = 1..)]
    src_files: Vec<OsString>,
    /// Select several directory trees
    #[arg(long, value_name = "DIR", num_args = 1..)]
    src_dirs: Vec<OsString>,
    /// Select several objects without constraining their selected types
    #[arg(long, value_name = "PATH", num_args = 1..)]
    srcs: Vec<OsString>,
    /// Select the contents of several directories
    #[arg(long, value_name = "DIR", num_args = 1..)]
    src_srcs: Vec<OsString>,
    /// Selected objects (shorthand for --src)
    #[arg(value_name = "PATH")]
    sources: Vec<OsString>,
}

#[derive(clap::Args, Debug)]
struct NativeOperationalArgs {
    /// Resolve and preview the operation without changing anything
    #[arg(short = 'n', long)]
    dry_run: bool,
    /// Increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// Suppress non-error messages
    #[arg(short = 'q', long)]
    quiet: bool,
    /// Use a fixed number of parallel connections/workers
    #[arg(short = 'j', long = "connections", value_name = "N")]
    connections: Option<usize>,
    /// Show progress even when stderr is not a terminal
    #[arg(long, overrides_with = "no_progress")]
    progress: bool,
    /// Never show the human progress display
    #[arg(long)]
    no_progress: bool,
    /// Emit machine-readable progress lines (JSON) on stderr
    #[arg(long)]
    progress_json: bool,
}

#[derive(clap::Args, Debug)]
struct NativeCopyOperationalArgs {
    #[command(flatten)]
    common: NativeOperationalArgs,
    /// Hash existing source and destination files instead of trusting size and modification time
    #[arg(long)]
    hash: bool,
    /// Disable transport compression
    #[arg(long)]
    no_compress: bool,
    /// Limit aggregate file-data throughput (default unit: KiB/s; 0 disables)
    #[arg(long, value_name = "RATE")]
    bwlimit: Option<String>,
    /// Print transfer statistics at the end
    #[arg(long)]
    stats: bool,
    /// Skip paths matching a gitignore-style pattern (repeatable)
    #[arg(long = "ignore", value_name = "PATTERN", allow_hyphen_values = true)]
    ignore: Vec<String>,
    /// Read gitignore-style patterns from FILE (repeatable; stacks in command-line order)
    #[arg(long, value_name = "FILE")]
    ignore_from: Vec<String>,
    /// Preserve additional metadata (permissions, ownership, or specials; repeatable/comma-separated)
    #[arg(long, value_name = "ATTRIBUTE", value_delimiter = ',')]
    preserve: Vec<NativePreserve>,
    /// Update destination files directly, using no full-sized staging file; interruption can leave them incomplete
    #[arg(long)]
    inplace: bool,
    /// Command-restricted receiver ceiling: refuse to touch more than N destination entries (direct remote-to-remote only)
    #[arg(long, value_name = "N")]
    max_entries: Option<u64>,
    /// Command-restricted receiver ceiling: refuse to write more than SIZE bytes of file data in total (direct remote-to-remote only)
    #[arg(long, value_name = "SIZE")]
    max_total_bytes: Option<String>,
    /// Command-restricted receiver ceiling: the signed grant expires DURATION after it is issued, e.g. 30m or 2h (direct remote-to-remote only; at most 23h)
    #[arg(long, value_name = "DURATION")]
    max_runtime: Option<String>,
    /// Receiver receipt detail: final sizes (default) or also final BLAKE3 file digests (direct remote-to-remote only)
    #[arg(long, value_name = "MODE", value_enum)]
    receipt: Option<ReceiptMode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ReceiptMode {
    Sizes,
    Hashed,
}

#[derive(clap::Args, Debug, Default)]
struct NativeRemoteArgs {
    /// Choose the endpoint that runs the coordinator
    #[arg(long, value_enum, default_value_t = CoordinateAt::Auto)]
    coordinate_at: CoordinateAt,
    /// Remote shell command (default: ssh); the command owns SSH and agent policy when set
    #[arg(long = "rsh", value_name = "COMMAND")]
    rsh: Option<String>,
    /// Use this exact syq executable on remote endpoints instead of the managed helper
    #[arg(long, value_name = "PATH")]
    syq_path: Option<String>,
    /// Require syq on each remote PATH instead of installing a versioned helper
    #[arg(long)]
    no_bootstrap: bool,
    /// Use TCP data connections without encryption (trusted networks only)
    #[arg(long)]
    tcp_plain: bool,
    /// Send file data through SSH rather than separate TCP data connections
    #[arg(long)]
    no_tcp: bool,
    /// Port range remote listeners use for TCP data connections
    #[arg(long, default_value = "47600-47699", value_name = "LO-HI")]
    tcp_ports: String,
    /// Use this congestion-control algorithm for direct TCP data sockets (Linux only)
    #[arg(
        long,
        value_name = "ALGO",
        value_parser = parse_tcp_congestion,
        conflicts_with = "no_tcp"
    )]
    tcp_congestion: Option<String>,
    /// Run at the remote coordinator and return after launch; restricted receipts remain plaintext in its log and are not locally verified
    #[arg(long)]
    detach: bool,
    /// Give a remote coordinator no forwarded agent; it must own credentials for the peer
    #[arg(long, conflicts_with = "rsh")]
    no_forward_agent: bool,
    /// Expose the complete local SSH agent to a live remote coordinator
    #[arg(
        long,
        conflicts_with_all = ["rsh", "no_forward_agent", "detach"]
    )]
    unrestricted_agent_forwarding: bool,
    /// Use destination-bound authentication without a command-restricted enrollment
    #[arg(
        long,
        conflicts_with_all = ["rsh", "no_forward_agent", "unrestricted_agent_forwarding", "detach"]
    )]
    agent_broker_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum NativePreserve {
    Permissions,
    Ownership,
    Specials,
}

#[derive(clap::Args, Debug)]
struct NativeCopyFields {
    #[command(flatten)]
    selection: NativeSelectionArgs,
    /// Destination endpoint ([USER@]HOST[:PORT]); omitted means local
    #[arg(long, value_name = "ENDPOINT")]
    to: Option<String>,
    /// Put selected names inside DIR, creating it if necessary
    #[arg(
        long,
        value_name = "DIR",
        group = "placement",
        allow_hyphen_values = true
    )]
    into: Option<OsString>,
    /// Put selected names inside DIR, which must not exist
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
    /// Map one named source exactly to PATH; never follow its final entry
    #[arg(
        long,
        value_name = "PATH",
        group = "placement",
        allow_hyphen_values = true
    )]
    r#as: Option<OsString>,
    /// Map one named source exactly to PATH; its final entry must not exist and is never followed
    #[arg(
        long,
        value_name = "PATH",
        group = "placement",
        allow_hyphen_values = true
    )]
    as_new: Option<OsString>,
    /// Map one named source exactly to PATH; its final entry must exist and is never followed
    #[arg(
        long,
        value_name = "PATH",
        group = "placement",
        allow_hyphen_values = true
    )]
    as_existing: Option<OsString>,
    /// Copy the entries of an NDJSON mapping manifest (`-` reads stdin)
    /// instead of selecting sources; entry src paths are relative to -C and
    /// dst paths are relative to the --into container
    #[arg(long, value_name = "FILE", allow_hyphen_values = true)]
    mapping: Option<OsString>,
    /// Write the machine-readable NDJSON result stream to FILE (created
    /// fresh; an existing file is refused). Automation schema version 1
    #[arg(long, value_name = "FILE", allow_hyphen_values = true)]
    results: Option<OsString>,
    /// Write the result stream to an inherited file descriptor the caller
    /// opened (e.g. `--results-fd 3 3>run.ndjson`); must be above 2
    #[arg(long, value_name = "FD", conflicts_with = "results")]
    results_fd: Option<i32>,
    #[command(flatten)]
    operational: NativeCopyOperationalArgs,
}

#[derive(clap::Args, Debug, Default)]
struct NativeSizeSelectionArgs {
    /// Skip regular source files larger than SIZE; --prune protects their destination paths
    #[arg(long, value_name = "SIZE")]
    max_size: Option<String>,
    /// Skip regular source files smaller than SIZE; --prune protects their destination paths
    #[arg(long, value_name = "SIZE")]
    min_size: Option<String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "syq cp",
    version,
    about = "Copy selected objects with explicit endpoint and placement syntax",
    long_about = "Copy selected objects with explicit endpoint and placement syntax.\n\nNative copies recurse, copy symlinks as symlinks, and preserve modification times by default. Use --preserve to add permissions, ownership, or special files. By default, destination-only objects remain in place. --prune removes them from mapped directory scopes after copying, while protecting ignored and size-excluded paths.",
    override_usage = "syq cp [OPTIONS] [--src PATH | --src-src DIR | --src-file PATH | --src-dir DIR | PATH]... PLACEMENT"
)]
struct NativeCopyCommand {
    #[command(flatten)]
    copy: NativeCopyFields,
    #[command(flatten)]
    size_selection: NativeSizeSelectionArgs,
    #[command(flatten)]
    remote: NativeRemoteArgs,
    /// Use an isolated SSH persistence scope created by `syq persist on --ephemeral`
    #[arg(long, value_name = "PATH")]
    pscope: Option<PathBuf>,
    /// After copying, remove destination-only objects in mapped directory scopes;
    /// ignored and size-excluded source paths remain protected
    #[arg(long, conflicts_with = "mapping")]
    prune: bool,
    /// With --prune, refuse all removals if more than N are planned
    #[arg(long, value_name = "N", requires = "prune")]
    max_delete: Option<u64>,
}

#[derive(Parser, Debug)]
#[command(
    name = "syq map",
    version,
    about = "Print a local source selection as an NDJSON mapping",
    long_about = "Print a local source selection as an NDJSON mapping.\n\nOne JSON object per line: tagged src and dst paths (src relative to the source base, dst relative to a future destination container), the object kind, and size/mtime for regular files. Emission is local and read-only. Names must be valid UTF-8.",
    override_usage = "syq map [OPTIONS] [--src PATH | --src-src DIR | --src-file PATH | --src-dir DIR | PATH]..."
)]
struct NativeMapCommand {
    #[command(flatten)]
    source: NativeSourceArgs,
    /// Rename the single selected root in the emitted mapping
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    r#as: Option<OsString>,
}

#[derive(Parser, Debug)]
#[command(
    name = "syq rm",
    version,
    about = "Remove endpoint-resolved object trees without following symlinks by default",
    override_usage = "syq rm [OPTIONS] [--src PATH | --src-src DIR | --src-file PATH | --src-dir DIR | PATH]..."
)]
struct NativeRmCommand {
    #[command(flatten)]
    selection: NativeRmSelectionArgs,
    #[command(flatten)]
    operational: NativeOperationalArgs,
    /// Use an isolated SSH persistence scope created by `syq persist on --ephemeral`
    #[arg(long, value_name = "PATH")]
    pscope: Option<PathBuf>,
}

fn parse_native(argv: &[OsString], interface: Interface) -> Result<Args> {
    match interface {
        Interface::NativeCp => parse_native_copy(argv),
        Interface::NativeMap => parse_native_map(argv),
        Interface::NativeRm => parse_native_rm(argv),
        Interface::Rsync => unreachable!(),
    }
}

fn parse_native_copy(argv: &[OsString]) -> Result<Args> {
    let mut full_argv = vec![OsString::from("syq cp")];
    full_argv.extend_from_slice(argv);
    let matches = NativeCopyCommand::command()
        .try_get_matches_from(full_argv)
        .unwrap_or_else(|error| error.exit());
    let parsed = NativeCopyCommand::from_arg_matches(&matches)?;
    let NativeCopyCommand {
        mut copy,
        size_selection,
        remote,
        pscope,
        prune,
        max_delete,
    } = parsed;
    if pscope.is_some() && remote.rsh.is_some() {
        bail!("--pscope cannot be used with --rsh");
    }
    let mapping = copy.mapping.take();
    let results = copy.results.take();
    let results_fd = copy.results_fd.take();
    if results_fd.is_some_and(|fd| fd <= 2) {
        bail!(
            "--results-fd needs a descriptor above 2 (0-2 are stdin, stdout, and stderr); open one in the caller, e.g. --results-fd 3 3>run.ndjson"
        );
    }
    let mut locations = if mapping.is_some() {
        let source = &copy.selection.source;
        let has_selectors = !(source.src.is_empty()
            && source.src_src.is_empty()
            && source.srcs.is_empty()
            && source.src_srcs.is_empty()
            && source.src_file.is_empty()
            && source.src_dir.is_empty()
            && source.src_files.is_empty()
            && source.src_dirs.is_empty()
            && source.sources.is_empty());
        if has_selectors {
            bail!("--mapping replaces source selectors; do not combine them");
        }
        let endpoint = parse_native_endpoint(copy.selection.from.as_deref())?;
        let base = trim_native_trailing_slashes(
            copy.selection
                .source
                .cwd
                .clone()
                .map(OsStringExt::into_vec)
                .unwrap_or_else(|| b".".to_vec()),
        );
        if base.is_empty() {
            bail!("source base may not be empty");
        }
        // The manifest is the selection; its entries resolve against this root.
        vec![Location::native(endpoint, base, SourceSelection::Contents)]
    } else {
        lower_native_selection(&copy.selection, &matches)?
    };

    let placements = [
        (copy.into, Placement::Into, Existence::Any),
        (copy.into_new, Placement::Into, Existence::New),
        (copy.into_existing, Placement::Into, Existence::Existing),
        (copy.r#as, Placement::As, Existence::Any),
        (copy.as_new, Placement::As, Existence::New),
        (copy.as_existing, Placement::As, Existence::Existing),
    ];
    let (target, placement, existence) = match placements
        .into_iter()
        .find_map(|(path, placement, existence)| path.map(|path| (path, placement, existence)))
    {
        Some((path, placement, existence)) => (Some(path), placement, existence),
        None => bail!(
            "syq cp requires one of --into, --into-new, --into-existing, --as, --as-new, or --as-existing"
        ),
    };
    if placement == Placement::As && mapping.is_some() {
        bail!("--as conflicts with --mapping: each entry's dst is its own --as");
    }
    if placement == Placement::As && (locations.len() != 1 || locations[0].copies_contents()) {
        bail!("--as, --as-new, and --as-existing require exactly one ordinary source object");
    }
    if placement == Placement::Into {
        for source in locations.iter().filter(|source| !source.copies_contents()) {
            if native_basename(&source.path).is_none() {
                bail!(
                    "named source {:?} has no destination basename; use --src-src to select directory contents",
                    String::from_utf8_lossy(&source.path)
                );
            }
        }
    }
    let target = match target {
        Some(target) => {
            let target = trim_native_trailing_slashes(target.into_vec());
            if target.is_empty() {
                bail!("destination paths may not be empty");
            }
            Some(target)
        }
        None => None,
    };
    let target = target.expect("copy placement parsed with a target");
    let target_endpoint = parse_native_endpoint(copy.to.as_deref())?;
    locations.push(Location::native(
        target_endpoint,
        target,
        SourceSelection::Named,
    ));

    let mut args = native_engine_defaults();
    args.interface = Interface::NativeCp;
    args.placement = placement;
    args.target_existence = existence;
    args.locations = locations;
    args.delete = prune;
    args.max_delete = max_delete;
    args.max_size = size_selection.max_size;
    args.min_size = size_selection.min_size;
    args.native_mapping = mapping.map(OsStringExt::into_vec);
    args.native_results = results.map(OsStringExt::into_vec);
    args.native_results_fd = results_fd;
    args.pscope = pscope;
    args.native_follow = copy.selection.source.follow;
    if args.native_mapping.is_some() {
        // The manifest is read on this machine and its entries are stat'ed
        // through the source connection; a direct remote-to-remote copy has
        // no way to carry either.
        let src_remote = args.locations.first().is_some_and(|l| l.host.is_some());
        let dst_remote = args.locations.last().is_some_and(|l| l.host.is_some());
        if src_remote && dst_remote {
            bail!("--mapping with a remote-to-remote copy is not supported; one end must be local");
        }
    }
    apply_native_copy_operational(&mut args, copy.operational, &matches)?;
    apply_native_remote(&mut args, remote)?;
    if args.max_entries.is_some()
        || args.max_total_bytes.is_some()
        || args.max_runtime_secs.is_some()
        || args.receipt_requested
    {
        // These are assertions for hostB's enrolled receiver to enforce; with
        // no such receiver in the topology, nothing would enforce them, so
        // refuse rather than let them read as local limits.
        let src_remote = args.locations.first().is_some_and(|l| l.host.is_some());
        let dst_remote = args.locations.last().is_some_and(|l| l.host.is_some());
        if !(src_remote && dst_remote) {
            bail!(
                "--max-entries, --max-total-bytes, --max-runtime, and --receipt address the command-restricted receiver; they apply only to direct remote-to-remote copies"
            );
        }
    }
    apply_internal_native_direct(&mut args)?;
    if args.native_results.is_some() || args.native_results_fd.is_some() {
        // Usage-lane refusals (exit 2, no stream): the contract promises a
        // terminal record for every run that gets past argument parsing, so
        // combinations that could never settle a stream stop here.
        if args.detach {
            bail!(
                "--results cannot be used with --detach because the result stream would not remain attached"
            );
        }
        // The stream is written by the transfer coordinator. For a
        // remote-to-remote copy that requires the local (relay) topology,
        // which is never chosen implicitly on the stream's behalf: the
        // operator opts in with an explicit --coordinate-at local.
        let src_remote = args.locations.first().is_some_and(|l| l.host.is_some());
        let dst_remote = args.locations.last().is_some_and(|l| l.host.is_some());
        if src_remote && dst_remote && args.coordinate_at != CoordinateAt::Local {
            bail!(
                "--results with a remote-to-remote copy needs the local coordinator; pass --coordinate-at local explicitly to route the transfer through this machine"
            );
        }
    }
    Ok(args)
}

fn parse_native_map(argv: &[OsString]) -> Result<Args> {
    let mut full_argv = vec![OsString::from("syq map")];
    full_argv.extend_from_slice(argv);
    let matches = NativeMapCommand::command()
        .try_get_matches_from(full_argv)
        .unwrap_or_else(|error| error.exit());
    let mut parsed = NativeMapCommand::from_arg_matches(&matches)?;

    // Keep `-C` out of selector paths so emitted `src` values stay relative
    // to it; the walk joins it back.
    let map_cwd = parsed.source.cwd.take().map(OsStringExt::into_vec);
    let mut locations = lower_native_sources(&parsed.source, &matches, None)?;
    for source in &mut locations {
        if source.path.starts_with(b"/") || source.path == b"~" || source.path.starts_with(b"~/") {
            bail!(
                "syq map selector {:?} is absolute; mapping entries are root-relative (use -C to set the base)",
                String::from_utf8_lossy(&source.path)
            );
        }
        // Normalize the way --files-from does — drop `.` and empty
        // components, reject `..` — so emitted paths are always valid
        // manifest paths.
        let mut parts: Vec<&[u8]> = Vec::new();
        for component in source.path.split(|&byte| byte == b'/') {
            match component {
                b"" | b"." => {}
                b".." => bail!(
                    "syq map selector {:?} contains a `..` component",
                    String::from_utf8_lossy(&source.path)
                ),
                other => parts.push(other),
            }
        }
        let normalized = parts.join(&b"/"[..]);
        source.path = if normalized.is_empty() {
            b".".to_vec()
        } else {
            normalized
        };
    }
    if locations
        .iter()
        .any(|location| location.selection == SourceSelection::Contents)
        && locations.len() > 1
    {
        bail!("syq map takes --src-src DIR as the only selector, or any number of named selectors");
    }

    let (placement, target) = match parsed.r#as {
        Some(target) => {
            if locations.len() != 1 || locations[0].copies_contents() {
                bail!("--as requires exactly one ordinary source object");
            }
            let target = trim_native_trailing_slashes(target.into_vec());
            if target.is_empty() {
                bail!("--as destination may not be empty");
            }
            if native_basename(&target).is_none() {
                bail!(
                    "--as destination {:?} has no basename",
                    String::from_utf8_lossy(&target)
                );
            }
            (Placement::As, Some(target))
        }
        None => {
            for source in locations.iter().filter(|source| !source.copies_contents()) {
                if native_basename(&source.path).is_none() {
                    bail!(
                        "named source {:?} has no destination basename; use --src-src to select directory contents",
                        String::from_utf8_lossy(&source.path)
                    );
                }
            }
            (Placement::Into, None)
        }
    };

    let mut args = native_engine_defaults();
    args.interface = Interface::NativeMap;
    args.placement = placement;
    args.locations = locations;
    args.native_map_cwd = map_cwd;
    args.native_map_target = target;
    args.native_follow = parsed.source.follow;
    Ok(args)
}

fn parse_native_rm(argv: &[OsString]) -> Result<Args> {
    let mut full_argv = vec![OsString::from("syq rm")];
    full_argv.extend_from_slice(argv);
    let matches = NativeRmCommand::command()
        .try_get_matches_from(full_argv)
        .unwrap_or_else(|error| error.exit());
    let parsed = NativeRmCommand::from_arg_matches(&matches)?;
    let mut ordered: Vec<(usize, SourceSelection, OsString)> = Vec::new();
    for (id, selection, paths) in [
        (
            "sources",
            SourceSelection::NamedNoFollow,
            &parsed.selection.sources,
        ),
        ("src", SourceSelection::NamedNoFollow, &parsed.selection.src),
        (
            "srcs",
            SourceSelection::NamedNoFollow,
            &parsed.selection.srcs,
        ),
        (
            "src_src",
            SourceSelection::Contents,
            &parsed.selection.src_src,
        ),
        (
            "src_srcs",
            SourceSelection::Contents,
            &parsed.selection.src_srcs,
        ),
        (
            "src_file",
            SourceSelection::File,
            &parsed.selection.src_file,
        ),
        (
            "src_dir",
            SourceSelection::Directory,
            &parsed.selection.src_dir,
        ),
        (
            "src_files",
            SourceSelection::File,
            &parsed.selection.src_files,
        ),
        (
            "src_dirs",
            SourceSelection::Directory,
            &parsed.selection.src_dirs,
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
        bail!("syq rm needs at least one source selector");
    }
    let endpoint = parse_native_endpoint(parsed.selection.from.as_deref())?;
    let locations = ordered
        .into_iter()
        .map(|(_, selection, path)| {
            let path = trim_native_trailing_slashes(path.into_vec());
            validate_native_rm_selector(&path)?;
            Ok(Location::native(endpoint.clone(), path, selection))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut args = native_engine_defaults();
    args.interface = Interface::NativeRm;
    args.locations = locations;
    args.native_rm_cwd = parsed.selection.cwd.map(OsStringExt::into_vec);
    args.native_rm_root = parsed.selection.root.map(OsStringExt::into_vec);
    args.native_follow = parsed.selection.follow;
    args.pscope = parsed.pscope;
    args.rm = true;
    apply_native_operational(&mut args, parsed.operational);
    Ok(args)
}

fn lower_native_selection(
    parsed: &NativeSelectionArgs,
    matches: &clap::ArgMatches,
) -> Result<Vec<Location>> {
    let endpoint = parse_native_endpoint(parsed.from.as_deref())?;
    lower_native_sources(&parsed.source, matches, endpoint)
}

fn lower_native_sources(
    parsed: &NativeSourceArgs,
    matches: &clap::ArgMatches,
    endpoint: Option<NativeEndpoint>,
) -> Result<Vec<Location>> {
    let mut ordered: Vec<(usize, SourceSelection, OsString)> = Vec::new();
    for (id, selection, paths) in [
        ("sources", SourceSelection::NamedNoFollow, &parsed.sources),
        ("src", SourceSelection::NamedNoFollow, &parsed.src),
        ("srcs", SourceSelection::NamedNoFollow, &parsed.srcs),
        ("src_src", SourceSelection::Contents, &parsed.src_src),
        ("src_srcs", SourceSelection::Contents, &parsed.src_srcs),
        ("src_file", SourceSelection::File, &parsed.src_file),
        ("src_dir", SourceSelection::Directory, &parsed.src_dir),
        ("src_files", SourceSelection::File, &parsed.src_files),
        ("src_dirs", SourceSelection::Directory, &parsed.src_dirs),
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
        bail!("native operations need at least one source selector");
    }

    let cwd = parsed.cwd.as_deref().map(OsStrExt::as_bytes);
    ordered
        .into_iter()
        .map(|(_, selection, path)| {
            let path = trim_native_trailing_slashes(qualify_source(cwd, path.into_vec()));
            if path.is_empty() {
                bail!("source selectors may not be empty");
            }
            Ok(Location::native(endpoint.clone(), path, selection))
        })
        .collect()
}

fn native_engine_defaults() -> Args {
    let mut args = Args::try_parse_from(["syq rsync", "source", "destination"])
        .expect("internal rsync defaults must parse");
    args.paths.clear();
    // The initial native copy policy is intentionally the equivalent of -rlt.
    args.recursive = true;
    args.links = true;
    args.times = true;
    args
}

fn apply_native_operational(args: &mut Args, operational: NativeOperationalArgs) {
    args.dry_run = operational.dry_run;
    args.verbose = operational.verbose;
    args.quiet = operational.quiet;
    args.connections_opt = operational.connections;
    args.progress = operational.progress;
    args.no_progress = operational.no_progress;
    args.progress_json = operational.progress_json;
}

#[cfg(test)]
mod native_sdk_inventory_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(serde::Deserialize)]
    struct Inventory {
        schema: u64,
        commands: BTreeMap<String, CommandInventory>,
    }

    #[derive(serde::Deserialize)]
    struct CommandInventory {
        sdk: String,
        python: Vec<String>,
        internal: Vec<String>,
        aliases: BTreeMap<String, String>,
        raw_only: Vec<String>,
        follow_up: Vec<String>,
    }

    fn long_options(command: clap::Command) -> BTreeSet<String> {
        command
            .get_arguments()
            .filter_map(|argument| argument.get_long().map(str::to_owned))
            .collect()
    }

    #[test]
    fn every_native_option_has_an_sdk_disposition() {
        let inventory: Inventory =
            serde_json::from_str(include_str!("../sdk/python/native-api.json"))
                .expect("Python native API inventory is valid JSON");
        assert_eq!(inventory.schema, 1);
        let commands = [
            ("cp", NativeCopyCommand::command()),
            ("rm", NativeRmCommand::command()),
            ("map", NativeMapCommand::command()),
        ];
        assert_eq!(
            inventory.commands.keys().cloned().collect::<BTreeSet<_>>(),
            commands
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect(),
            "classify every native command in sdk/python/native-api.json"
        );
        for (name, command) in commands {
            let classified = inventory.commands.get(name).unwrap();
            assert!(
                matches!(classified.sdk.as_str(), "python" | "raw_only" | "follow_up"),
                "{name} has an invalid SDK disposition"
            );
            let mut declared = BTreeSet::new();
            for option in classified
                .python
                .iter()
                .chain(&classified.internal)
                .chain(classified.aliases.keys())
                .chain(&classified.raw_only)
                .chain(&classified.follow_up)
            {
                assert!(
                    declared.insert(option.clone()),
                    "{name} option --{option} has more than one SDK disposition"
                );
            }
            assert_eq!(
                declared,
                long_options(command),
                "update sdk/python/native-api.json whenever the native CLI changes"
            );
        }
    }
}

fn apply_native_copy_operational(
    args: &mut Args,
    operational: NativeCopyOperationalArgs,
    matches: &clap::ArgMatches,
) -> Result<()> {
    let NativeCopyOperationalArgs {
        common,
        hash,
        no_compress,
        bwlimit,
        stats,
        ignore,
        ignore_from,
        preserve,
        inplace,
        max_entries,
        max_total_bytes,
        max_runtime,
        receipt,
    } = operational;
    args.receipt_requested = receipt.is_some();
    args.receipt_hashed = receipt == Some(ReceiptMode::Hashed);
    args.max_entries = max_entries;
    args.max_total_bytes = max_total_bytes.as_deref().map(parse_size).transpose()?;
    args.max_runtime_secs = max_runtime
        .as_deref()
        .map(parse_duration_secs)
        .transpose()?;
    args.checksum = hash;
    args.no_compress = no_compress;
    if no_compress {
        args.compress = false;
    }
    args.bwlimit_bytes = bwlimit
        .as_deref()
        .map(crate::bwlimit::parse_rate)
        .transpose()?
        .unwrap_or(0);
    args.bwlimit = bwlimit;
    args.stats = stats;
    args.ignore_lines = ordered_ignore_lines(
        &ignore,
        &ignore_from,
        matches,
        args.native_follow,
        "--ignore-from",
    )?;
    args.ignore = ignore;
    args.ignore_from = ignore_from;
    args.inplace = inplace;
    for attribute in preserve {
        match attribute {
            NativePreserve::Permissions => args.perms = true,
            NativePreserve::Ownership => {
                args.owner = true;
                args.group = true;
            }
            NativePreserve::Specials => args.devices = true,
        }
    }
    apply_native_operational(args, common);
    Ok(())
}

fn apply_native_remote(args: &mut Args, remote: NativeRemoteArgs) -> Result<()> {
    args.coordinate_at = remote.coordinate_at;
    args.rsh = remote.rsh;
    args.syq_path = remote.syq_path;
    args.no_bootstrap = remote.no_bootstrap;
    args.tcp_plain = remote.tcp_plain;
    args.no_tcp = remote.no_tcp;
    crate::transfer::parse_ports(&remote.tcp_ports)?;
    args.tcp_ports = remote.tcp_ports;
    args.tcp_congestion = remote.tcp_congestion;
    args.detach = remote.detach;
    args.no_forward_agent = remote.no_forward_agent;
    args.unrestricted_agent_forwarding = remote.unrestricted_agent_forwarding;
    args.agent_broker_only = remote.agent_broker_only;
    Ok(())
}

/// Direct remote-to-remote execution needs a few automatically derived engine
/// controls on the source host. Keep them out of the native command grammar:
/// they are carried by the internal launcher environment, so public native
/// parsing remains the strict allowlist above.
fn apply_internal_native_direct(args: &mut Args) -> Result<()> {
    let utf8 = |name: &str| -> Result<Option<String>> {
        std::env::var_os(name)
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("{name} is not valid UTF-8"))
            })
            .transpose()
    };
    args.restricted_grant = utf8("SYQ_INTERNAL_NATIVE_RESTRICTED_GRANT")?;
    args.plan_source_host = utf8("SYQ_INTERNAL_NATIVE_PLAN_SOURCE_HOST")?;
    if let Some(rsh) = utf8("SYQ_INTERNAL_NATIVE_RSH")? {
        args.rsh = Some(rsh);
    }
    if let Some(width) = utf8("SYQ_INTERNAL_NATIVE_PROGRESS_WIDTH")? {
        args.width = Some(
            width
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid internal native progress width"))?,
        );
        args.progress = true;
    }
    Ok(())
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

fn trim_native_trailing_slashes(mut path: Vec<u8>) -> Vec<u8> {
    while path.len() > 1 && path.ends_with(b"/") {
        path.pop();
    }
    path
}

fn validate_native_rm_selector(path: &[u8]) -> Result<()> {
    if path.is_empty() {
        bail!("source selectors may not be empty");
    }
    if path.starts_with(b"/") {
        bail!(
            "source selector {:?} must be relative",
            String::from_utf8_lossy(path)
        );
    }
    if path.contains(&0) {
        bail!("source selector contains NUL");
    }
    if path
        .split(|byte| *byte == b'/')
        .any(|component| component == b"." || component == b"..")
    {
        bail!(
            "source selector {:?} contains forbidden `.` or `..` component",
            String::from_utf8_lossy(path)
        );
    }
    Ok(())
}

pub(crate) fn native_basename(path: &[u8]) -> Option<&[u8]> {
    let name = path.rsplit(|byte| *byte == b'/').next()?;
    (!name.is_empty() && name != b"." && name != b"..").then_some(name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeEndpoint {
    pub(crate) user: Option<String>,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

pub(crate) fn parse_native_endpoint(spec: Option<&str>) -> Result<Option<NativeEndpoint>> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    let (user, authority) = match spec.rsplit_once('@') {
        Some((user, authority)) if !user.is_empty() => (Some(user.to_string()), authority),
        Some(_) => bail!("empty user in endpoint {spec:?}"),
        None => (None, spec),
    };
    if user.as_deref().is_some_and(|user| {
        user.bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace() || matches!(byte, b'/' | b'@'))
    }) {
        bail!("invalid user in endpoint {spec:?}");
    }
    let parse_port = |value: &str| -> Result<u16> {
        let port = value
            .parse::<u16>()
            .map_err(|_| {
                anyhow::anyhow!(
                    "invalid SSH port in endpoint {spec:?}; pass paths separately with --cwd and source/placement arguments"
                )
            })?;
        if port == 0 {
            bail!("SSH port in endpoint {spec:?} must be between 1 and 65535");
        }
        Ok(port)
    };
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("mismatched brackets in endpoint {spec:?}"))?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(value) = suffix.strip_prefix(':') {
            Some(parse_port(value)?)
        } else {
            bail!("unexpected text after bracketed host in endpoint {spec:?}");
        };
        (host, port)
    } else if let Some((host, value)) = authority.rsplit_once(':') {
        if host.contains(':') {
            bail!("IPv6 host in endpoint {spec:?} must be enclosed in brackets");
        }
        (host, Some(parse_port(value)?))
    } else {
        (authority, None)
    };
    if host.is_empty() {
        bail!("empty host in endpoint {spec:?}");
    }
    if host
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace() || matches!(byte, b'/' | b'[' | b']'))
    {
        bail!("invalid host in endpoint {spec:?}; pass paths separately with --cwd and source/placement arguments");
    }
    Ok(Some(NativeEndpoint {
        user,
        host: host.to_string(),
        port,
    }))
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
        "--syq-ignore",
        "--syq-ignore-from",
        "--syq-connections",
        "--block-size",
        "--bwlimit",
        "--max-size",
        "--min-size",
        "--files-from",
        "--max-delete",
        "--syq-tcp-ports",
        "--syq-tcp-congestion",
        "--rsync-path",
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
        if value_long.contains(&tok.as_str()) || matches!(tok.as_str(), "-e" | "-B") {
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
    // way on every coordinator. The kernel otherwise looks up the registered
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
            if matches!(c, 'e' | 'B') {
                break;
            }
            if let Some(m) = message_for_short(c) {
                return Some(m.to_string());
            }
        }
    }
    None
}

const FILTER_MSG: &str = "syq has no --exclude/--include/--filter. The SYQ extension --syq-ignore (or --syq-ignore-from) takes gitignore-style patterns: e.g. `--exclude node_modules` becomes `--syq-ignore node_modules`. See the README's \"Ignoring paths\" section.";
const ITEMIZE_MSG: &str = "syq does not implement rsync's -i/--itemize-changes. --syq-verify-only can compare contents without mutation, but it does not produce rsync's itemized output.";
const DELETE_MSG: &str = "syq deletes only after the transfer (--delete; --delete-after and --delete-delay are synonyms); --delete-before, --delete-during and --force are not supported.";

fn message_for_long(base: &str) -> Option<&'static str> {
    Some(match base {
        "exclude" | "exclude-from" | "include" | "include-from" | "filter" => FILTER_MSG,
        "itemize-changes" => ITEMIZE_MSG,
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
        'i' => "itemize-changes",
        _ => return None,
    })
}

/// Parse a whole-number duration with an optional `s`, `m`, or `h` suffix
/// (seconds when unsuffixed) into seconds. Zero is rejected.
pub fn parse_duration_secs(s: &str) -> Result<u32> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m: u32 = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 60 * 60,
                _ => bail!("bad duration suffix in {s:?}; use s, m, or h"),
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1),
    };
    let n: u32 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("bad duration {s:?}"))?;
    let seconds = n
        .checked_mul(mult)
        .ok_or_else(|| anyhow::anyhow!("bad duration {s:?}: value is too large"))?;
    if seconds == 0 {
        bail!("duration {s:?} must be at least one second");
    }
    Ok(seconds)
}

fn parse_max_delete(value: &str) -> std::result::Result<u64, String> {
    if value == "-1" {
        // Rsync documents -1 as the backward-compatible spelling of its
        // no-deletion max-delete mode. Internally that is the same budget as 0.
        return Ok(0);
    }
    value
        .parse()
        .map_err(|_| "must be a non-negative integer or -1".to_string())
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
    use super::{
        native_engine_defaults, parse_duration_secs, parse_native_copy, parse_native_endpoint,
        parse_size, Args, Placement, SourceSelection,
    };
    use clap::Parser;

    #[test]
    fn durations_take_seconds_minutes_or_hours_and_reject_zero() {
        assert_eq!(parse_duration_secs("45").unwrap(), 45);
        assert_eq!(parse_duration_secs("90s").unwrap(), 90);
        assert_eq!(parse_duration_secs("30m").unwrap(), 1800);
        assert_eq!(parse_duration_secs("2H").unwrap(), 7200);
        for bad in ["0", "0m", "", "5d", "1.5h", "-3", "4294967295h"] {
            assert!(parse_duration_secs(bad).is_err(), "{bad:?}");
        }
    }

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
            args(&["--syq-tcp-congestion", "bbr"])
                .tcp_congestion
                .as_deref(),
            Some("bbr")
        );
        assert_eq!(
            args(&["--syq-tcp-congestion", "foo-bar"])
                .tcp_congestion
                .as_deref(),
            Some("foo-bar")
        );
        for value in ["", "1234567890123456"] {
            let parsed = Args::try_parse_from(["syq", "--syq-tcp-congestion", value, "src", "dst"]);
            assert!(parsed.is_err(), "accepted {value:?}");
        }
        assert!(Args::try_parse_from([
            "syq",
            "--syq-tcp-congestion",
            "bbr",
            "--syq-no-tcp",
            "src",
            "dst",
        ])
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

    #[test]
    fn native_copy_policy_is_rsync_rlt() {
        let args = native_engine_defaults();
        assert!(args.recursive);
        assert!(args.links);
        assert!(args.times);
        assert!(!args.perms);
        assert!(!args.owner);
        assert!(!args.group);
        assert!(!args.devices);
    }

    #[test]
    fn native_hash_selects_content_comparison() {
        let argv = ["--hash", "source", "--into", "destination"].map(std::ffi::OsString::from);
        let args = parse_native_copy(&argv).unwrap();
        assert!(args.checksum);
    }

    #[test]
    fn native_copy_policies_lower_to_the_shared_engine() {
        let argv = [
            "--follow",
            "--ignore",
            "*.tmp",
            "--ignore",
            "!keep.tmp",
            "--preserve=permissions,ownership,specials",
            "--inplace",
            "--min-size=1K",
            "--max-size=1M",
            "source",
            "--into",
            "destination",
        ]
        .map(std::ffi::OsString::from);
        let args = parse_native_copy(&argv).unwrap();
        assert!(args.native_follow);
        assert_eq!(args.ignore_lines, ["*.tmp", "!keep.tmp"]);
        assert!(args.perms);
        assert!(args.owner);
        assert!(args.group);
        assert!(args.devices);
        assert!(args.inplace);
        assert_eq!(args.min_size.as_deref(), Some("1K"));
        assert_eq!(args.max_size.as_deref(), Some("1M"));
    }

    #[test]
    fn native_prune_lowers_to_shared_deletion_policy() {
        let argv = [
            "--prune",
            "--max-delete=3",
            "source",
            "--into",
            "destination",
        ]
        .map(std::ffi::OsString::from);
        let args = parse_native_copy(&argv).unwrap();
        assert!(args.delete);
        assert_eq!(args.max_delete, Some(3));
    }

    #[test]
    fn native_remote_controls_lower_to_the_shared_engine() {
        let argv = [
            "--coordinate-at=dest",
            "--rsh=ssh -J jump",
            "--syq-path=/opt/syq",
            "--no-bootstrap",
            "--no-tcp",
            "--tcp-ports=49000-49010",
            "--detach",
            "source",
            "--into",
            "destination",
        ]
        .map(std::ffi::OsString::from);
        let args = parse_native_copy(&argv).unwrap();
        assert_eq!(args.coordinate_at, super::CoordinateAt::Dest);
        assert_eq!(args.rsh.as_deref(), Some("ssh -J jump"));
        assert_eq!(args.syq_path.as_deref(), Some("/opt/syq"));
        assert!(args.no_bootstrap);
        assert!(args.no_tcp);
        assert_eq!(args.tcp_ports, "49000-49010");
        assert!(args.detach);
    }

    #[test]
    fn native_persistence_scope_rejects_an_explicit_remote_shell() {
        let argv = [
            "--pscope=/tmp/scope",
            "--rsh=ssh -J jump",
            "source",
            "--into",
            "destination",
        ]
        .map(std::ffi::OsString::from);
        let error = parse_native_copy(&argv).unwrap_err();
        assert!(error
            .to_string()
            .contains("--pscope cannot be used with --rsh"));
    }

    #[test]
    fn native_endpoints_are_separate_from_paths() {
        assert_eq!(
            parse_native_endpoint(Some("alice@example.test")).unwrap(),
            Some(super::NativeEndpoint {
                user: Some("alice".into()),
                host: "example.test".into(),
                port: None,
            })
        );
        assert_eq!(
            parse_native_endpoint(Some("[2001:db8::1]")).unwrap(),
            Some(super::NativeEndpoint {
                user: None,
                host: "2001:db8::1".into(),
                port: None,
            })
        );
        assert_eq!(
            parse_native_endpoint(Some("alice@example.test:2222")).unwrap(),
            Some(super::NativeEndpoint {
                user: Some("alice".into()),
                host: "example.test".into(),
                port: Some(2222),
            })
        );
        assert_eq!(
            parse_native_endpoint(Some("alice@[2001:db8::1]:2200")).unwrap(),
            Some(super::NativeEndpoint {
                user: Some("alice".into()),
                host: "2001:db8::1".into(),
                port: Some(2200),
            })
        );
        assert!(parse_native_endpoint(Some("host:path")).is_err());
        assert!(parse_native_endpoint(Some("2001:db8::1")).is_err());
        assert!(parse_native_endpoint(Some("host:0")).is_err());
        assert!(parse_native_endpoint(Some("host]:2222")).is_err());
        assert!(parse_native_endpoint(Some("bad user@host")).is_err());
        assert!(parse_native_endpoint(Some("host/path")).is_err());
    }

    #[test]
    fn native_endpoint_modifiers_may_follow_bare_sources() {
        let argv = [
            "one",
            "--cwd",
            "base",
            "--to",
            "target.test",
            "--from",
            "source.test",
            "--into",
            "dest",
        ]
        .map(std::ffi::OsString::from);
        let args = parse_native_copy(&argv).unwrap();
        assert_eq!(args.placement, Placement::Into);
        assert_eq!(args.locations.len(), 2);
        assert_eq!(args.locations[0].host.as_deref(), Some("source.test"));
        assert_eq!(args.locations[0].path, b"base/one");
        assert_eq!(args.locations[0].selection, SourceSelection::NamedNoFollow);
        assert_eq!(args.locations[1].host.as_deref(), Some("target.test"));
        assert_eq!(args.locations[1].path, b"dest");
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub user: Option<String>,
    pub host: Option<String>,
    /// Explicit native endpoint SSH port. Rsync-shaped operands leave this to
    /// ssh_config and therefore store no override here.
    pub port: Option<u16>,
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
                port: None,
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
            b".".to_vec()
        } else {
            path.as_bytes().to_vec()
        };
        Ok(Location {
            user,
            host: Some(host),
            port: None,
            path,
            selection: SourceSelection::Rsync,
        })
    }

    fn native(
        endpoint: Option<NativeEndpoint>,
        mut path: Vec<u8>,
        selection: SourceSelection,
    ) -> Location {
        while path.len() > 1 && path.ends_with(b"/") {
            path.pop();
        }
        let (user, host, port) = endpoint
            .map(|endpoint| (endpoint.user, Some(endpoint.host), endpoint.port))
            .unwrap_or((None, None, None));
        Location {
            user,
            host,
            port,
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
            SourceSelection::Named
            | SourceSelection::NamedNoFollow
            | SourceSelection::File
            | SourceSelection::Directory => false,
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

    pub fn follows_root(&self, native_follow: bool) -> bool {
        match self.selection {
            SourceSelection::Named
            | SourceSelection::Contents
            | SourceSelection::NamedNoFollow
            | SourceSelection::File
            | SourceSelection::Directory => native_follow,
            SourceSelection::Rsync => self.copies_contents(),
        }
    }

    pub fn basename(&self) -> Vec<u8> {
        let mut p = self.path.as_slice();
        while p.ends_with(b"/") {
            p = &p[..p.len() - 1];
        }
        match p.rsplit(|byte| *byte == b'/').next() {
            Some(name) if !name.is_empty() => name.to_vec(),
            _ => p.to_vec(),
        }
    }

    pub fn same_host(&self, other: &Location) -> bool {
        self.user == other.user && self.host == other.host && self.port == other.port
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
