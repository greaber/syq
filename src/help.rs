//! Help presentation built from the same commands used for parsing/completion.
use clap::{Arg, ArgAction, Command};

/// Short and long flag spellings intentionally select the same view. Only
/// --help-all expands the reference; hide_short_help never hides completion.
pub(crate) fn configure(command: Command) -> Command {
    let name = command.get_name().to_owned();
    configure_at(command, &name)
}

fn configure_at(mut command: Command, path: &str) -> Command {
    for child in command.get_subcommands_mut() {
        *child = configure_at(child.clone(), &format!("{path} {}", child.get_name()));
    }
    let rsync = path == "syq rsync";
    command = command.disable_help_flag(true);
    let mut help = Arg::new("help")
        .long("help")
        .action(ArgAction::HelpShort)
        .help("Show common usage and options")
        .help_heading("Help and version");
    if !rsync {
        help = help.short('h');
    }
    if command.get_arguments().any(|arg| arg.get_id() == "help") {
        command = command.mut_arg("help", |_| help);
    } else {
        command = command.arg(help);
    }
    if command.get_version().is_some() {
        command = command.disable_version_flag(true);
        let version = Arg::new("version")
            .short('V')
            .long("version")
            .action(ArgAction::Version)
            .help("Print version")
            .help_heading("Help and version");
        command = if command.get_arguments().any(|arg| arg.get_id() == "version") {
            command.mut_arg("version", |_| version)
        } else {
            command.arg(version)
        };
    }
    command
        .arg(
            Arg::new("help_all")
                .long("help-all")
                .action(ArgAction::HelpLong)
                .help("Show all options and details")
                .help_heading("Help and version"),
        )
        .after_help(format!("All options and details: {path} --help-all"))
        .after_long_help("Documentation: https://greaber.github.io/syq/")
}

/// Presentation metadata references parser IDs, never a separate option list.
/// Unclassified public options remain visible in the complete reference.
pub(crate) fn filesystem(command: Command) -> Command {
    let rsync = command.get_name() == "syq rsync";
    let map = command.get_name() == "syq map";
    let rm = command.get_name() == "syq rm";
    let command = command.mut_args(|arg| {
        if arg.is_hide_set() {
            return arg;
        }
        let id_owned = arg.get_id().to_string();
        let id = id_owned.as_str();
        let common = if rsync {
            matches!(
                id,
                "paths"
                    | "archive"
                    | "dry_run"
                    | "verbose"
                    | "quiet"
                    | "checksum"
                    | "ignore"
                    | "delete"
                    | "bwlimit"
                    | "help"
                    | "version"
            )
        } else {
            matches!(
                id,
                "sources"
                    | "srcs_in"
                    | "from"
                    | "cwd"
                    | "to"
                    | "into"
                    | "as"
                    | "dry_run"
                    | "verbose"
                    | "quiet"
                    | "ignore"
                    | "preserve"
                    | "verify_only"
                    | "hash"
                    | "prune"
                    | "help"
                    | "version"
            ) || (rm && id == "root")
        };
        let heading = match id {
            "sources" | "paths" | "src" | "srcs_in" | "src_file" | "src_dir" | "src_files"
            | "src_dirs" | "srcs" | "from" | "cwd" | "root" | "follow" | "follow_src" => {
                "Sources and selection"
            }
            "to" | "into" | "into_new" | "into_existing" | "as" | "as_new" | "as_existing"
            | "follow_dst" => "Destination placement",
            "results" | "results_fd" | "progress" | "no_progress" | "progress_json" | "stats" => {
                "Progress and results"
            }
            "connections" | "connections_opt" | "block_size" | "bwlimit" => "Performance",
            "rsh" | "syq_path" | "no_bootstrap" | "no_tcp" | "tcp_plain" | "tcp_ports"
            | "tcp_congestion" | "pscope" | "compress" | "no_compress" => "SSH and transport",
            "coordinate_at"
            | "detach"
            | "peer_auth"
            | "receiver_max_entries"
            | "receiver_max_bytes"
            | "receiver_receipt" => "Remote-to-remote transfers",
            "help" | "version" => "Help and version",
            "dry_run" | "verbose" | "quiet" => "Preview and output",
            _ => "Copy policy and filtering",
        };
        let mut arg = arg.hide_short_help(!common).help_heading(heading);
        // Shared parser fields need command-specific explanations.
        if rm && id == "syq_path" {
            arg = arg.help("Use this exact syq executable on the remote removal endpoint");
        } else if rm && matches!(id, "follow" | "follow_src") {
            arg = arg.help("Follow symlinks in supplied source paths; remove the selected target, leaving the link");
        } else if rm && id == "verbose" {
            arg = arg.help("List removed paths");
        } else if id == "verbose" && !map {
            arg = arg.help("List files with -v; explain helpers and transport with -vv");
        }
        arg
    });
    configure(command)
}

pub(crate) fn root() -> Command {
    configure(Command::new("syq")
        .about("Copy files and directories locally or over SSH")
        .override_usage("syq <COMMAND> [OPTIONS]\n       syq --self-update")
        .before_help("Examples:\n  syq cp photos --into backup\n  syq cp --srcs-in photos --to nas --into /backup/photos\n  syq map photos --as archive/photos")
        .arg(Arg::new("version").short('V').long("version").action(ArgAction::Version).help("Print version"))
        .version(env!("CARGO_PKG_VERSION"))
        .arg(Arg::new("self_update").long("self-update").action(ArgAction::SetTrue)
            .help("Install the newest signed release (standalone installs); Homebrew: brew upgrade syq"))
        .disable_help_subcommand(true)
        .subcommand(Command::new("cp").about("Copy files and directories, optionally removing destination-only files"))
        .subcommand(Command::new("rm").about("Remove selected files and directory trees"))
        .subcommand(Command::new("map").about("Print source-to-destination mappings as NDJSON"))
        .subcommand(Command::new("rsync").about("Copy using rsync-compatible syntax"))
        .subcommand(Command::new("persist").about("Manage reusable SSH connections and helper sessions"))
        .subcommand(Command::new("completion").about("Generate shell completion and manage cached endpoint suggestions"))
        .subcommand(Command::new("receiver").about("Enroll, list, or revoke command-restricted receivers"))
        .subcommand(Command::new("help").about("Show help for a command, e.g. syq help cp")))
}

pub(crate) fn lifecycle() -> Command {
    configure(Command::new("syq")
        .about("Install the newest signed syq release")
        .override_usage("syq --self-update")
        .before_help("Standalone (curl installer) installs: syq --self-update\nHomebrew installs: brew upgrade syq\nSource builds: rebuild or reinstall.\n\nStandalone installs show new-version reminders at most daily after successful\nfilesystem commands when stderr is a terminal and quiet mode is off. Set\nSYQ_NO_UPDATE_CHECK to disable reminders; explicit self-update still works.\nUpdates verify signed release metadata and never install as a side effect of copying.")
        .arg(Arg::new("self_update").long("self-update").action(ArgAction::SetTrue).exclusive(true)
            .help("Update the executable registered by the standalone installer"))
        .arg(Arg::new("register_standalone_install").long("register-standalone-install")
            .action(ArgAction::SetTrue).exclusive(true).hide(true)))
        .after_help("All options and details: syq --self-update --help-all")
}

/// Receiver management shares a parser-backed help surface with other commands.
pub(crate) fn receiver() -> Command {
    let via = || {
        Arg::new("via")
            .long("via")
            .value_name("ENDPOINT")
            .help("Retry through this SSH jump host if the direct management connection fails")
    };
    configure(
        Command::new("syq receiver")
            .about("Manage command-restricted receiver enrollments")
            .subcommand_required(true)
            .subcommand(
                Command::new("enroll")
                    .about("Enroll a destination's existing parent, or refresh its receiver")
                    .arg(
                        Arg::new("target")
                            .required(true)
                            .value_name("[USER@]HOST:DESTINATION")
                            .help("Remote destination, e.g. alice@nas:/backup/photos"),
                    )
                    .arg(via()),
            )
            .subcommand(Command::new("list").about("List local active and pending enrollments"))
            .subcommand(
                Command::new("revoke")
                    .about("Remove the forced key and per-enrollment state from both machines")
                    .arg(
                        Arg::new("id")
                            .required(true)
                            .value_name("ENROLLMENT-ID")
                            .help("Enrollment ID printed by syq receiver list"),
                    )
                    .arg(via()),
            ),
    )
}

/// Only the explicit `syq help ...` route uses this topic lookup. Transfer
/// operands are never searched for help-like strings.
pub(crate) fn show_topic(topics: &[std::ffi::OsString]) -> anyhow::Result<()> {
    let mut topics = topics
        .iter()
        .map(|s| {
            s.to_str()
                .ok_or_else(|| anyhow::anyhow!("help topic is not UTF-8"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let full = topics.last() == Some(&"--help-all");
    if full || matches!(topics.last(), Some(&"--help" | &"-h")) {
        topics.pop();
    }
    let mut command = match topics.first().copied() {
        None => root(),
        Some("persist") => crate::persistence::command_for_help(),
        Some("completion") => crate::completion::command_for_help(),
        Some("receiver") => receiver(),
        Some("--self-update") => lifecycle(),
        Some(name) => crate::cli::command_for_completion(name)
            .ok_or_else(|| anyhow::anyhow!("unknown help topic {name:?}"))?,
    };
    for topic in topics.iter().skip(1) {
        let parent = command
            .get_bin_name()
            .unwrap_or(command.get_name())
            .to_owned();
        command = command
            .find_subcommand(topic)
            .filter(|child| !child.is_hide_set())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown help topic {topic:?}"))?
            .bin_name(format!("{parent} {topic}"));
    }
    if full {
        command.print_long_help()?;
    } else {
        command.print_help()?;
    }
    Ok(())
}
