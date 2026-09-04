//! Dynamic shell completion and its disposable local endpoint cache.
//!
//! Shell-specific code is intentionally tiny: shells pass their command words
//! here and consume NUL-delimited candidates. Bash passes its current command
//! line because its built-in word array splits SSH syntax at `:`, `@`, and `=`;
//! the other shells pass their already-tokenized words. All command awareness,
//! endpoint selection, and local/remote directory discovery remains in Rust.

use crate::cli::{parse_native_endpoint, NativeEndpoint};
use crate::conn::{Conn, RemoteSpec, SshMultiplexer};
use crate::proto::{CompletionEntry, Request, Response};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::{CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_VERSION: u8 = 1;
const CACHE_FILE: &str = "completion-endpoints-v1.json";
const CACHE_LOCK: &str = ".completion-endpoints.lock";
const MAX_CACHED_ENDPOINTS: usize = 100;
const MAX_CACHE_BYTES: u64 = 1024 * 1024;
const MAX_DIRECTORY_CANDIDATES: u16 = 1_000;
const REMOTE_COMPLETION_DEADLINE: Duration = Duration::from_secs(40);

#[derive(Parser, Debug)]
#[command(
    name = "syq completion",
    about = "Generate shell completion and manage its disposable local cache",
    long_about = "Generate dynamic shell completion and manage its disposable local endpoint cache. The cache contains suggestions learned from successful SSH connections. It is safe to clear and never contains paths, credentials, or transfer history."
)]
struct CompletionCommand {
    #[command(subcommand)]
    action: CompletionAction,
}

#[derive(Subcommand, Debug)]
enum CompletionAction {
    /// Print the Bash completion adapter
    Bash,
    /// Print the Zsh completion adapter
    Zsh,
    /// Print the fish completion adapter
    Fish,
    /// Inspect or clear disposable local endpoint suggestions
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Internal dynamic-completion entry point
    #[command(name = "__complete", hide = true)]
    Complete {
        #[arg(value_enum)]
        shell: CompletionShell,
        /// Zero-based index of the word containing the cursor
        index: usize,
        /// Dequoted command words, including argv[0]
        #[arg(last = true, allow_hyphen_values = true)]
        words: Vec<OsString>,
    },
    /// Internal Bash entry point that preserves SSH word-break characters
    #[command(name = "__complete-bash", hide = true)]
    CompleteBash {
        /// Current fragment that Readline will replace
        replacement: OsString,
        /// Command line through the cursor, already sliced by Bash
        #[arg(last = true, allow_hyphen_values = true)]
        line: OsString,
    },
}

#[derive(Subcommand, Debug)]
enum CacheAction {
    /// List learned endpoint suggestions, most recently used first
    List,
    /// Forget one exact native endpoint spelling
    Forget { endpoint: String },
    /// Remove all learned endpoint suggestions
    Clear,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedEndpoint {
    user: Option<String>,
    host: String,
    port: Option<u16>,
    last_success: u64,
}

impl CachedEndpoint {
    fn from_parts(user: Option<&str>, host: &str, port: Option<u16>) -> Self {
        Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
            last_success: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn endpoint(&self) -> NativeEndpoint {
        NativeEndpoint {
            user: self.user.clone(),
            host: self.host.clone(),
            port: self.port,
        }
    }

    fn matches(&self, endpoint: &NativeEndpoint) -> bool {
        self.user == endpoint.user && self.host == endpoint.host && self.port == endpoint.port
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CompletionCache {
    version: u8,
    endpoints: Vec<CachedEndpoint>,
}

impl Default for CompletionCache {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            endpoints: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    value: Vec<u8>,
    /// Completing this value should leave the cursor attached. Directories
    /// already end in `/`; rsync endpoints already end in `:`.
    no_space: bool,
}

impl Candidate {
    fn text(value: impl Into<Vec<u8>>) -> Self {
        Self {
            value: value.into(),
            no_space: false,
        }
    }

    fn prefix(value: impl Into<Vec<u8>>) -> Self {
        Self {
            value: value.into(),
            no_space: true,
        }
    }
}

pub(crate) fn run(argv: &[OsString]) -> Result<i32> {
    let mut full_argv = vec![OsString::from("syq completion")];
    full_argv.extend_from_slice(argv);
    let command = CompletionCommand::try_parse_from(full_argv).unwrap_or_else(|error| error.exit());
    match command.action {
        CompletionAction::Bash => print!("{BASH_ADAPTER}"),
        CompletionAction::Zsh => print!("{ZSH_ADAPTER}"),
        CompletionAction::Fish => print!("{FISH_ADAPTER}"),
        CompletionAction::Cache { action } => run_cache(action)?,
        CompletionAction::Complete {
            shell,
            index,
            words,
        } => {
            // A speculative Tab must never put a diagnostic into the editing
            // buffer. Opt-in debugging keeps failures inspectable.
            if std::env::var_os("SYQ_COMPLETION_DEBUG").is_none() {
                silence_stderr()?;
            }
            let candidates = match candidates(index, &words) {
                Ok(candidates) => candidates,
                Err(error) => {
                    if std::env::var_os("SYQ_COMPLETION_DEBUG").is_some() {
                        eprintln!("syq completion: {error:#}");
                    }
                    Vec::new()
                }
            };
            write_candidates(shell, candidates)?;
        }
        CompletionAction::CompleteBash { replacement, line } => {
            if std::env::var_os("SYQ_COMPLETION_DEBUG").is_none() {
                silence_stderr()?;
            }
            let (index, words) = bash_command_words(line.as_bytes());
            let current = words.get(index).cloned().unwrap_or_default();
            let words: Vec<OsString> = words.into_iter().map(OsString::from_vec).collect();
            let candidates = match candidates(index, &words) {
                Ok(candidates) => {
                    bash_replacement_candidates(candidates, &current, replacement.as_bytes())
                }
                Err(error) => {
                    if std::env::var_os("SYQ_COMPLETION_DEBUG").is_some() {
                        eprintln!("syq completion: {error:#}");
                    }
                    Vec::new()
                }
            };
            write_candidates(CompletionShell::Bash, candidates)?;
        }
    }
    Ok(0)
}

fn silence_stderr() -> Result<()> {
    let null = OpenOptions::new().write(true).open("/dev/null")?;
    if unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) } < 0 {
        return Err(std::io::Error::last_os_error()).context("silence completion diagnostics");
    }
    Ok(())
}

fn run_cache(action: CacheAction) -> Result<()> {
    match action {
        CacheAction::List => {
            let cache = read_cache()?;
            if cache.endpoints.is_empty() {
                println!("completion endpoint cache is empty");
            } else {
                for endpoint in cache.endpoints {
                    println!("{}", endpoint_label(&endpoint.endpoint()));
                }
            }
        }
        CacheAction::Forget { endpoint } => {
            let endpoint = parse_native_endpoint(Some(&endpoint))?
                .expect("an explicitly supplied endpoint parses to Some");
            let removed = update_cache(|cache| {
                let before = cache.endpoints.len();
                cache.endpoints.retain(|cached| !cached.matches(&endpoint));
                before != cache.endpoints.len()
            })?;
            if removed {
                println!("forgot {}", endpoint_label(&endpoint));
            } else {
                println!("{} was not cached", endpoint_label(&endpoint));
            }
        }
        CacheAction::Clear => {
            let path = cache_path()?;
            let Some(parent) = path.parent() else {
                bail!("completion cache path has no parent");
            };
            let _lock = match open_cache_directory(parent, false)? {
                Some(directory) => Some(lock_cache(parent, &directory)?),
                None => None,
            };
            match std::fs::remove_file(&path) {
                Ok(()) => println!("completion endpoint cache cleared"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    println!("completion endpoint cache was already empty")
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("remove {}", path.display()))
                }
            }
        }
    }
    Ok(())
}

/// Record an endpoint without ever allowing disposable completion state to
/// affect the operation that successfully connected to it.
pub(crate) fn remember_endpoint_best_effort(user: Option<&str>, host: &str, port: Option<u16>) {
    if let Err(error) = remember_endpoint(user, host, port) {
        if std::env::var_os("SYQ_COMPLETION_DEBUG").is_some() {
            eprintln!("syq completion cache: {error:#}");
        }
    }
}

fn remember_endpoint(user: Option<&str>, host: &str, port: Option<u16>) -> Result<()> {
    // Reuse the public endpoint validator before putting anything on disk.
    let label = endpoint_label(&NativeEndpoint {
        user: user.map(str::to_owned),
        host: host.to_owned(),
        port,
    });
    let endpoint = parse_native_endpoint(Some(&label))?
        .ok_or_else(|| anyhow!("validated endpoint unexpectedly became local"))?;
    update_cache(|cache| {
        cache.endpoints.retain(|cached| !cached.matches(&endpoint));
        cache.endpoints.insert(
            0,
            CachedEndpoint::from_parts(endpoint.user.as_deref(), &endpoint.host, endpoint.port),
        );
        cache.endpoints.truncate(MAX_CACHED_ENDPOINTS);
        true
    })?;
    Ok(())
}

fn cache_path() -> Result<PathBuf> {
    let root = std::env::var_os("XDG_CACHE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".cache"))
        })
        .context("cannot locate completion cache: both XDG_CACHE_HOME and HOME are unset")?;
    Ok(root.join("syq").join(CACHE_FILE))
}

fn open_cache_directory(path: &Path, create: bool) -> Result<Option<File>> {
    if create {
        std::fs::create_dir_all(path)
            .with_context(|| format!("create completion cache directory {}", path.display()))?;
    }
    let path_c = CString::new(path.as_os_str().as_bytes())
        .context("completion cache directory path contains NUL")?;
    let descriptor = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if !create
            && matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            )
        {
            return Ok(None);
        }
        return Err(error).with_context(|| {
            format!(
                "open completion cache directory {} (symlinks are refused)",
                path.display()
            )
        });
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "completion cache directory {} must be owned by the current user",
            path.display()
        );
    }
    if metadata.mode() & 0o077 != 0 && unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("restrict completion cache directory {}", path.display()));
    }
    Ok(Some(directory))
}

struct CacheLock(File);

impl Drop for CacheLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn lock_cache(parent: &Path, _directory: &File) -> Result<CacheLock> {
    let path = parent.join(CACHE_LOCK);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .with_context(|| format!("open completion cache lock {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "completion cache lock {} must be a regular file owned by the current user",
            path.display()
        );
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            bail!("completion cache is busy; try again");
        }
        return Err(error).with_context(|| format!("lock completion cache {}", path.display()));
    }
    Ok(CacheLock(file))
}

fn read_cache() -> Result<CompletionCache> {
    let path = cache_path()?;
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(CompletionCache::default())
        }
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "completion cache {} must be a regular file owned by the current user",
            path.display()
        );
    }
    if metadata.mode() & 0o077 != 0 {
        bail!(
            "completion cache {} must not be accessible by group or other users",
            path.display()
        );
    }
    if metadata.len() > MAX_CACHE_BYTES {
        bail!("completion cache {} exceeds 1 MiB", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    let mut cache: CompletionCache = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse completion cache {}", path.display()))?;
    if cache.version != CACHE_VERSION {
        bail!(
            "unsupported completion cache version {} in {}",
            cache.version,
            path.display()
        );
    }
    cache.endpoints.truncate(MAX_CACHED_ENDPOINTS);
    Ok(cache)
}

fn update_cache(mut update: impl FnMut(&mut CompletionCache) -> bool) -> Result<bool> {
    let path = cache_path()?;
    let parent = path.parent().expect("cache file has a parent");
    let directory = open_cache_directory(parent, true)?.expect("created cache directory");
    let _lock = lock_cache(parent, &directory)?;
    let mut cache = read_cache()?;
    let changed = update(&mut cache);
    if !changed {
        return Ok(false);
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary completion cache in {}", parent.display()))?;
    serde_json::to_writer_pretty(&mut temporary, &cache)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace completion cache {}", path.display()))?;
    directory.sync_all()?;
    Ok(true)
}

fn write_candidates(shell: CompletionShell, candidates: Vec<Candidate>) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    let mut seen = HashSet::new();
    for candidate in candidates {
        if candidate.value.contains(&0) || !seen.insert(candidate.value.clone()) {
            continue;
        }
        if !matches!(shell, CompletionShell::Fish) {
            stdout.write_all(if candidate.no_space { b"p" } else { b"f" })?;
        }
        stdout.write_all(&candidate.value)?;
        stdout.write_all(&[0])?;
    }
    Ok(())
}

fn candidates(index: usize, words: &[OsString]) -> Result<Vec<Candidate>> {
    let mut words: Vec<Vec<u8>> = words.iter().map(|word| word.as_bytes().to_vec()).collect();
    while words.len() <= index {
        words.push(Vec::new());
    }
    let Some(command_start) = words
        .iter()
        .take(index.saturating_add(1))
        .position(|word| !is_shell_assignment(word))
    else {
        return Ok(Vec::new());
    };
    let index = index.saturating_sub(command_start);
    let words = &words[command_start..];
    let current = &words[index];
    if index <= 1 {
        return Ok(root_candidates(current));
    }
    let Some(command) = words.get(1).and_then(|word| std::str::from_utf8(word).ok()) else {
        return Ok(Vec::new());
    };
    let args_before = &words[2..index];
    match command {
        "completion" => Ok(completion_command_candidates(args_before, current)),
        "persist" => Ok(persist_candidates(args_before, current)),
        "cp" | "rm" | "map" | "rsync" => {
            filesystem_command_candidates(command, args_before, current)
        }
        _ => Ok(Vec::new()),
    }
}

fn is_shell_assignment(word: &[u8]) -> bool {
    let Some(separator) = word.iter().position(|byte| *byte == b'=') else {
        return false;
    };
    let name = &word[..separator];
    name.first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && name[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

/// Parse the portion of a Bash command line before the cursor without relying
/// on bash-completion's `_get_comp_words_by_ref`. This intentionally performs
/// lexical quote removal, not expansion: the result is the same kind of word
/// spelling that Bash exposes to programmable completion.
fn bash_command_words(line: &[u8]) -> (usize, Vec<Vec<u8>>) {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut words = Vec::new();
    let mut word = Vec::new();
    let mut started = false;
    let mut quote = Quote::None;
    let mut index = 0;
    while index < line.len() {
        let byte = line[index];
        match quote {
            Quote::Single => {
                if byte == b'\'' {
                    quote = Quote::None;
                } else {
                    word.push(byte);
                }
                started = true;
            }
            Quote::Double => {
                if byte == b'"' {
                    quote = Quote::None;
                } else if byte == b'\\' && index + 1 < line.len() {
                    let escaped = line[index + 1];
                    if matches!(escaped, b'$' | b'`' | b'"' | b'\\') {
                        word.push(escaped);
                        index += 1;
                    } else if escaped == b'\n' {
                        index += 1;
                    } else {
                        word.push(byte);
                    }
                } else {
                    word.push(byte);
                }
                started = true;
            }
            Quote::None => match byte {
                b'\'' => {
                    quote = Quote::Single;
                    started = true;
                }
                b'"' => {
                    quote = Quote::Double;
                    started = true;
                }
                b'\\' if index + 1 < line.len() => {
                    let escaped = line[index + 1];
                    if escaped != b'\n' {
                        word.push(escaped);
                        started = true;
                    }
                    index += 1;
                }
                b' ' | b'\t' => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                b'\n' | b';' | b'|' | b'&' | b'(' | b')' => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                    words.clear();
                }
                _ => {
                    word.push(byte);
                    started = true;
                }
            },
        }
        index += 1;
    }
    if started {
        words.push(word);
    } else {
        words.push(Vec::new());
    }
    (words.len().saturating_sub(1), words)
}

/// The completion engine works with the complete dequoted token, so trim the
/// prefix Readline leaves in place before returning matches to Bash.
fn bash_replacement_candidates(
    mut candidates: Vec<Candidate>,
    current: &[u8],
    replacement: &[u8],
) -> Vec<Candidate> {
    let Some(prefix_length) = current
        .strip_suffix(replacement)
        .map(|prefix| prefix.len())
        .filter(|length| *length > 0)
    else {
        return candidates;
    };
    // Bash includes `@` in the span it replaces even though COMP_WORDS omits
    // it from the current fragment. Keep that final byte in returned matches.
    let prefix_length = prefix_length
        .checked_sub(usize::from(current[..prefix_length].ends_with(b"@")))
        .expect("a suffix byte can only be removed from a nonempty prefix");
    let prefix = &current[..prefix_length];
    for candidate in &mut candidates {
        if candidate.value.starts_with(prefix) {
            candidate.value.drain(..prefix_length);
        }
    }
    candidates
}

fn root_candidates(current: &[u8]) -> Vec<Candidate> {
    [
        "cp",
        "rm",
        "map",
        "rsync",
        "persist",
        "completion",
        "enrollment",
        "--help",
        "--version",
        "--self-update",
    ]
    .into_iter()
    .filter(|value| value.as_bytes().starts_with(current))
    .map(|value| Candidate::text(value.as_bytes().to_vec()))
    .collect()
}

fn completion_command_candidates(args: &[Vec<u8>], current: &[u8]) -> Vec<Candidate> {
    let values: &[&str] = match args.first().map(Vec::as_slice) {
        None => &["bash", "zsh", "fish", "cache", "--help"],
        Some(b"cache") if args.len() == 1 => &["list", "forget", "clear", "--help"],
        Some(b"cache") if args.get(1).is_some_and(|value| value == b"forget") => {
            return endpoint_candidates(current, EndpointSyntax::Native, None)
        }
        _ => &[],
    };
    values
        .iter()
        .filter(|value| value.as_bytes().starts_with(current))
        .map(|value| Candidate::text(value.as_bytes().to_vec()))
        .collect()
}

fn persist_candidates(args: &[Vec<u8>], current: &[u8]) -> Vec<Candidate> {
    if args.is_empty() {
        return ["on", "off", "status", "--help"]
            .into_iter()
            .filter(|value| value.as_bytes().starts_with(current))
            .map(|value| Candidate::text(value.as_bytes().to_vec()))
            .collect();
    }
    if previous_is(args, &[b"--pscope"]) {
        return local_path_candidates(current, true);
    }
    let options: &[&str] = match args.first().map(Vec::as_slice) {
        Some(b"on") => &["--ephemeral", "--help"],
        Some(b"off" | b"status") => &["--pscope", "--help"],
        _ => &[],
    };
    options
        .iter()
        .filter(|value| value.as_bytes().starts_with(current))
        .map(|value| Candidate::text(value.as_bytes().to_vec()))
        .collect()
}

#[derive(Clone, Copy)]
enum EndpointSyntax {
    Native,
    Rsync,
}

enum ValueCompletion {
    Endpoint(EndpointSyntax),
    SourcePath { apply_base: bool },
    DestinationPath,
    LocalPath { directories_only: bool },
    Enum(&'static [&'static str]),
    None,
}

#[derive(Clone, Copy)]
enum SourceBase<'a> {
    Cwd(&'a [u8]),
    Root(&'a [u8]),
}

struct CompletionDirectory {
    path: Vec<u8>,
    confined_root: Option<Vec<u8>>,
}

fn filesystem_command_candidates(
    command: &str,
    args: &[Vec<u8>],
    current: &[u8],
) -> Result<Vec<Candidate>> {
    let command_meta = crate::cli::command_for_completion(command)
        .ok_or_else(|| anyhow!("missing completion metadata for {command}"))?;
    let after_double_dash = args.iter().any(|arg| arg == b"--");
    let copy_destination_started = command == "cp" && native_copy_destination_started(args);
    if !after_double_dash {
        if let Some((option, value)) = split_inline_option(current) {
            if copy_destination_started && native_copy_source_option(option) {
                return Ok(Vec::new());
            }
            if let Some(kind) = value_completion(command, option, &command_meta) {
                let mut values = complete_value(command, args, value, kind)?;
                for candidate in &mut values {
                    let mut prefixed = option.to_vec();
                    prefixed.push(b'=');
                    prefixed.extend_from_slice(&candidate.value);
                    candidate.value = prefixed;
                }
                return Ok(values);
            }
        }
        if let Some(previous) = args.last() {
            if copy_destination_started && native_copy_source_option(previous) {
                return Ok(Vec::new());
            }
            if let Some(kind) = value_completion(command, previous, &command_meta) {
                if command == "rsync" || !current.starts_with(b"-") {
                    return complete_value(command, args, current, kind);
                }
            }
        }
        if current.starts_with(b"-") {
            let mut candidates = option_candidates(&command_meta, current);
            if copy_destination_started {
                candidates.retain(|candidate| !native_copy_source_option(&candidate.value));
            }
            return Ok(candidates);
        }
        if command == "cp" && tos_group_accepts_another_endpoint(args) {
            return complete_value(
                command,
                args,
                current,
                ValueCompletion::Endpoint(EndpointSyntax::Native),
            );
        }
    }

    match command {
        "cp" if copy_destination_started => Ok(Vec::new()),
        "cp" | "rm" | "map" => complete_path_for(command, args, current, true),
        "rsync" => complete_rsync_operand(args, current),
        _ => Ok(Vec::new()),
    }
}

fn native_copy_destination_started(args: &[Vec<u8>]) -> bool {
    const OPTIONS: &[&[u8]] = &[
        b"--to",
        b"--tos",
        b"--into",
        b"--into-new",
        b"--into-existing",
        b"--as",
        b"--as-new",
        b"--as-existing",
    ];
    args.iter().any(|argument| {
        OPTIONS.iter().any(|option| {
            argument == option
                || (argument.starts_with(option) && argument.get(option.len()) == Some(&b'='))
        })
    })
}

fn native_copy_source_option(option: &[u8]) -> bool {
    matches!(
        option.split(|byte| *byte == b'=').next().unwrap_or(option),
        b"--from"
            | b"-C"
            | b"--cwd"
            | b"--root"
            | b"--src"
            | b"--src-src"
            | b"--src-file"
            | b"--src-dir"
            | b"--srcs"
            | b"--src-srcs"
            | b"--src-files"
            | b"--src-dirs"
            | b"--mapping"
    )
}

fn split_inline_option(current: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = current.iter().position(|byte| *byte == b'=')?;
    let option = &current[..at];
    option
        .starts_with(b"--")
        .then_some((option, &current[at + 1..]))
}

fn value_completion(
    command: &str,
    option: &[u8],
    command_meta: &clap::Command,
) -> Option<ValueCompletion> {
    let known = match command {
        "cp" => match option {
            b"--from" => Some(ValueCompletion::Endpoint(EndpointSyntax::Native)),
            b"--to" | b"--tos" => Some(ValueCompletion::Endpoint(EndpointSyntax::Native)),
            b"-C" | b"--cwd" | b"--root" => Some(ValueCompletion::SourcePath { apply_base: false }),
            b"--src" | b"--src-src" | b"--src-file" | b"--src-dir" | b"--srcs" | b"--src-srcs"
            | b"--src-files" | b"--src-dirs" => {
                Some(ValueCompletion::SourcePath { apply_base: true })
            }
            b"--into" | b"--into-new" | b"--into-existing" | b"--as" | b"--as-new"
            | b"--as-existing" => Some(ValueCompletion::DestinationPath),
            b"--mapping" | b"--results" | b"--ignore-from" => Some(ValueCompletion::LocalPath {
                directories_only: false,
            }),
            b"--pscope" => Some(ValueCompletion::LocalPath {
                directories_only: true,
            }),
            b"--coordinate-at" => Some(ValueCompletion::Enum(&["auto", "src", "dest", "local"])),
            b"--preserve" => Some(ValueCompletion::Enum(&[
                "permissions",
                "ownership",
                "specials",
            ])),
            b"--receipt" => Some(ValueCompletion::Enum(&["sizes", "hashed"])),
            _ => None,
        },
        "rm" => match option {
            b"--from" => Some(ValueCompletion::Endpoint(EndpointSyntax::Native)),
            b"-C" | b"--cwd" | b"--root" => Some(ValueCompletion::SourcePath { apply_base: false }),
            b"--src" | b"--src-src" | b"--src-file" | b"--src-dir" | b"--srcs" | b"--src-srcs"
            | b"--src-files" | b"--src-dirs" => {
                Some(ValueCompletion::SourcePath { apply_base: true })
            }
            b"--pscope" => Some(ValueCompletion::LocalPath {
                directories_only: true,
            }),
            _ => None,
        },
        "map" => match option {
            b"-C" | b"--cwd" | b"--root" => Some(ValueCompletion::SourcePath { apply_base: false }),
            b"--src" | b"--src-src" | b"--src-file" | b"--src-dir" | b"--srcs" | b"--src-srcs"
            | b"--src-files" | b"--src-dirs" => {
                Some(ValueCompletion::SourcePath { apply_base: true })
            }
            b"--as" => Some(ValueCompletion::LocalPath {
                directories_only: false,
            }),
            _ => None,
        },
        "rsync" => match option {
            b"--files-from" | b"--syq-ignore-from" => Some(ValueCompletion::LocalPath {
                directories_only: false,
            }),
            b"--syq-pscope" => Some(ValueCompletion::LocalPath {
                directories_only: true,
            }),
            _ => None,
        },
        _ => None,
    };
    known.or_else(|| option_takes_value(command_meta, option).then_some(ValueCompletion::None))
}

fn option_takes_value(command: &clap::Command, option: &[u8]) -> bool {
    command.get_arguments().any(|argument| {
        if argument.is_hide_set() || !argument.get_action().takes_values() {
            return false;
        }
        argument
            .get_long()
            .is_some_and(|long| option == format!("--{long}").as_bytes())
            || argument
                .get_short()
                .is_some_and(|short| option == format!("-{short}").as_bytes())
    })
}

fn complete_value(
    command: &str,
    args: &[Vec<u8>],
    current: &[u8],
    kind: ValueCompletion,
) -> Result<Vec<Candidate>> {
    match kind {
        ValueCompletion::Endpoint(syntax) => Ok(endpoint_candidates(
            current,
            syntax,
            pscope_from_args(command, args),
        )),
        ValueCompletion::SourcePath { apply_base } => {
            complete_source_path(command, args, current, apply_base)
        }
        ValueCompletion::DestinationPath => complete_path_for(command, args, current, false),
        ValueCompletion::LocalPath { directories_only } => {
            Ok(local_path_candidates(current, directories_only))
        }
        ValueCompletion::Enum(values) => Ok(values
            .iter()
            .filter(|value| value.as_bytes().starts_with(current))
            .map(|value| Candidate::text(value.as_bytes().to_vec()))
            .collect()),
        ValueCompletion::None => Ok(Vec::new()),
    }
}

fn option_candidates(command: &clap::Command, current: &[u8]) -> Vec<Candidate> {
    let mut values = Vec::new();
    for argument in command.get_arguments() {
        if argument.is_hide_set() {
            continue;
        }
        if let Some(short) = argument.get_short() {
            values.push(format!("-{short}"));
        }
        if let Some(long) = argument.get_long() {
            values.push(format!("--{long}"));
        }
    }
    values.sort();
    values.dedup();
    values
        .into_iter()
        .filter(|value| value.as_bytes().starts_with(current))
        .map(|value| Candidate::text(value.into_bytes()))
        .collect()
}

fn complete_path_for(
    command: &str,
    args: &[Vec<u8>],
    current: &[u8],
    source: bool,
) -> Result<Vec<Candidate>> {
    if source {
        return complete_source_path(command, args, current, true);
    }
    let Some(endpoint_text) = destination_group_endpoint(args) else {
        return Ok(local_path_candidates_at(current, false, None));
    };
    let Some(endpoint) = parse_native_endpoint(Some(endpoint_text))? else {
        return Ok(local_path_candidates_at(current, false, None));
    };
    remote_path_candidates(command, args, endpoint, current, Vec::new(), None)
}

/// Return one endpoint from the most recent target group. A `--tos` group can
/// span hosts whose directory listings differ; using its first endpoint keeps
/// completion useful without pretending that the candidates exist everywhere.
fn destination_group_endpoint(args: &[Vec<u8>]) -> Option<&str> {
    let mut endpoint = None;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_slice();
        if argument == b"--" {
            break;
        }
        if matches!(argument, b"--to" | b"--tos") {
            if let Some(value) = args.get(index + 1).filter(|value| !value.starts_with(b"-")) {
                endpoint = std::str::from_utf8(value).ok();
            }
            index += 2;
            continue;
        }
        if let Some(value) = argument
            .strip_prefix(b"--to=")
            .or_else(|| argument.strip_prefix(b"--tos="))
        {
            endpoint = std::str::from_utf8(value).ok();
        }
        index += 1;
    }
    endpoint
}

fn tos_group_accepts_another_endpoint(args: &[Vec<u8>]) -> bool {
    let mut open = false;
    for argument in option_arguments(args) {
        if argument == b"--tos" {
            open = true;
        } else if argument.starts_with(b"-") {
            open = false;
        }
    }
    open
}

fn complete_source_path(
    command: &str,
    args: &[Vec<u8>],
    current: &[u8],
    apply_base: bool,
) -> Result<Vec<Candidate>> {
    let base = if apply_base { source_base(args) } else { None };
    if command == "map" {
        return Ok(local_path_candidates_at(current, false, base));
    }
    let Some(endpoint_text) = find_option_value(args, b"--from") else {
        return Ok(local_path_candidates_at(current, false, base));
    };
    let Some(endpoint) = parse_native_endpoint(Some(endpoint_text))? else {
        return Ok(local_path_candidates_at(current, false, base));
    };
    remote_path_candidates(command, args, endpoint, current, Vec::new(), base)
}

fn source_base(args: &[Vec<u8>]) -> Option<SourceBase<'_>> {
    find_option_bytes(args, b"--root")
        .map(SourceBase::Root)
        .or_else(|| find_option_bytes(args, b"--cwd").map(SourceBase::Cwd))
        .or_else(|| find_option_bytes(args, b"-C").map(SourceBase::Cwd))
}

fn complete_rsync_operand(args: &[Vec<u8>], current: &[u8]) -> Result<Vec<Candidate>> {
    if let Some((authority, path)) = split_rsync_remote(current) {
        let authority_text =
            std::str::from_utf8(authority).context("remote endpoint is not UTF-8")?;
        let Some(endpoint) = parse_native_endpoint(Some(authority_text))? else {
            return Ok(Vec::new());
        };
        if endpoint.port.is_some() {
            return Ok(Vec::new());
        }
        let mut wrapper = authority.to_vec();
        wrapper.push(b':');
        return remote_path_candidates("rsync", args, endpoint, path, wrapper, None);
    }
    let mut candidates = local_path_candidates_at(current, false, None);
    candidates.extend(endpoint_candidates(
        current,
        EndpointSyntax::Rsync,
        pscope_from_args("rsync", args),
    ));
    Ok(candidates)
}

fn split_rsync_remote(value: &[u8]) -> Option<(&[u8], &[u8])> {
    if value.starts_with(b"/") || value.starts_with(b"./") || value.starts_with(b"../") {
        return None;
    }
    let slash = value.iter().position(|byte| *byte == b'/');
    let separator = if let Some(open) = value.iter().position(|byte| *byte == b'[') {
        let close = value[open + 1..]
            .iter()
            .position(|byte| *byte == b']')
            .map(|relative| open + 1 + relative)?;
        value
            .get(close + 1)
            .is_some_and(|byte| *byte == b':')
            .then_some(close + 1)
    } else {
        value.iter().position(|byte| *byte == b':')
    }?;
    if slash.is_some_and(|slash| slash < separator)
        || separator == 0
        || value.get(separator + 1) == Some(&b':')
    {
        return None;
    }
    Some((&value[..separator], &value[separator + 1..]))
}

fn remote_path_candidates(
    command: &str,
    args: &[Vec<u8>],
    endpoint: NativeEndpoint,
    current: &[u8],
    wrapper: Vec<u8>,
    base: Option<SourceBase<'_>>,
) -> Result<Vec<Candidate>> {
    if has_explicit_rsh(command, args) {
        return Ok(Vec::new());
    }
    let (directory, typed_directory, prefix) = split_path(current);
    let Some(directory) = apply_path_base(base, &directory) else {
        return Ok(Vec::new());
    };
    let syq_path = find_option_value(
        args,
        if command == "rsync" {
            b"--rsync-path"
        } else {
            b"--syq-path"
        },
    )
    .map(str::to_owned);
    let no_bootstrap = contains_option(
        args,
        if command == "rsync" {
            b"--syq-no-bootstrap"
        } else {
            b"--no-bootstrap"
        },
    );
    let pscope = pscope_from_args(command, args).map(PathBuf::from);
    let endpoint_for_thread = endpoint.clone();
    let directory_for_thread = directory.path;
    let root_for_thread = directory.confined_root;
    let prefix_for_thread = prefix.clone();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = fetch_remote_entries(
            endpoint_for_thread,
            pscope.as_deref(),
            syq_path,
            no_bootstrap,
            directory_for_thread,
            root_for_thread,
            prefix_for_thread,
        );
        let _ = sender.send(result);
    });
    let entries = receiver
        .recv_timeout(REMOTE_COMPLETION_DEADLINE)
        .map_err(|_| anyhow!("remote completion timed out after 40 seconds"))??;
    Ok(path_candidates_from_entries(
        &wrapper,
        &typed_directory,
        &prefix,
        entries,
    ))
}

fn fetch_remote_entries(
    endpoint: NativeEndpoint,
    pscope: Option<&Path>,
    syq_path: Option<String>,
    no_bootstrap: bool,
    directory: Vec<u8>,
    confined_root: Option<Vec<u8>>,
    prefix: Vec<u8>,
) -> Result<Vec<CompletionEntry>> {
    let multiplexer = match crate::persistence::scope_for_implicit_ssh(pscope)? {
        Some(scope) => Arc::new(SshMultiplexer::persistent(
            &scope,
            endpoint.user.as_deref(),
            &endpoint.host,
            endpoint.port,
        )?),
        None => Arc::new(SshMultiplexer::new()?),
    };
    let spec = RemoteSpec {
        local_process: false,
        user: endpoint.user,
        host: endpoint.host,
        port: endpoint.port,
        rsh: vec![
            "ssh".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ConnectTimeout=3".into(),
            "-o".into(),
            "ConnectionAttempts=1".into(),
            "-o".into(),
            "ServerAliveInterval=5".into(),
            "-o".into(),
            "ServerAliveCountMax=1".into(),
        ],
        syq_path: syq_path.clone(),
        auto_helper: syq_path.is_none() && !no_bootstrap,
        restricted_grant: None,
        helper_install: Default::default(),
        ssh_multiplexer: Some(multiplexer),
        quiet: true,
        tcp: Default::default(),
        diagnostics: Default::default(),
    };
    let mut connection = spec.connect_completion()?;
    match connection.call(Request::ListDir {
        directory,
        confined_root,
        prefix: prefix.clone(),
        limit: MAX_DIRECTORY_CANDIDATES,
    })? {
        Response::DirectoryEntries { entries, .. } => validate_completion_entries(entries, &prefix),
        Response::EndpointError(error) => Err(crate::conn::endpoint_error(error)),
        Response::Err(error) => bail!("list remote directory: {error}"),
        response => bail!("unexpected remote completion response: {response:?}"),
    }
}

fn validate_completion_entries(
    entries: Vec<CompletionEntry>,
    prefix: &[u8],
) -> Result<Vec<CompletionEntry>> {
    if entries.len() > usize::from(MAX_DIRECTORY_CANDIDATES) {
        bail!("remote completion returned too many entries");
    }
    for entry in &entries {
        if entry.name.is_empty()
            || entry.name == b"."
            || entry.name == b".."
            || entry.name.contains(&0)
            || entry.name.contains(&b'/')
            || !entry.name.starts_with(prefix)
        {
            bail!("remote completion returned an unsafe directory entry");
        }
    }
    Ok(entries)
}

fn local_path_candidates(current: &[u8], directories_only: bool) -> Vec<Candidate> {
    local_path_candidates_at(current, directories_only, None)
}

fn local_path_candidates_at(
    current: &[u8],
    directories_only: bool,
    base: Option<SourceBase<'_>>,
) -> Vec<Candidate> {
    if current == b"~" && !matches!(base, Some(SourceBase::Root(_))) {
        return std::env::var_os("HOME")
            .map(|_| vec![Candidate::prefix(b"~/".to_vec())])
            .unwrap_or_default();
    }
    if current.starts_with(b"~") && !current.starts_with(b"~/") {
        return Vec::new();
    }
    let (directory, typed_directory, prefix) = split_path(current);
    let Some(directory) = apply_path_base(base, &directory) else {
        return Vec::new();
    };
    if let Some(root) = directory.confined_root.as_deref() {
        let Ok(root) = std::fs::canonicalize(crate::fsops::resolve(root)) else {
            return Vec::new();
        };
        let Ok(resolved) = std::fs::canonicalize(crate::fsops::resolve(&directory.path)) else {
            return Vec::new();
        };
        if !resolved.starts_with(root) {
            return Vec::new();
        }
    }
    let mut entries = Vec::new();
    let Ok(items) = std::fs::read_dir(crate::fsops::resolve(&directory.path)) else {
        return Vec::new();
    };
    for item in items.flatten() {
        let name = item.file_name().into_vec();
        if !name.starts_with(&prefix) || (!prefix.starts_with(b".") && name.starts_with(b".")) {
            continue;
        }
        let Ok(file_type) = item.file_type() else {
            continue;
        };
        let is_directory = file_type.is_dir()
            || (file_type.is_symlink()
                && std::fs::metadata(item.path()).is_ok_and(|metadata| metadata.is_dir()));
        if directories_only && !is_directory {
            continue;
        }
        entries.push(CompletionEntry {
            name,
            directory: is_directory,
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    path_candidates_from_entries(&[], &typed_directory, &prefix, entries)
}

fn apply_path_base(base: Option<SourceBase<'_>>, directory: &[u8]) -> Option<CompletionDirectory> {
    let Some(base) = base else {
        return Some(CompletionDirectory {
            path: directory.to_vec(),
            confined_root: None,
        });
    };
    let (base, confined_root) = match base {
        SourceBase::Cwd(base) => {
            if directory.starts_with(b"/")
                || directory == b"~"
                || directory.starts_with(b"~/")
                || base.is_empty()
            {
                return Some(CompletionDirectory {
                    path: directory.to_vec(),
                    confined_root: None,
                });
            }
            (base, None)
        }
        SourceBase::Root(root) => {
            if !root_relative_directory_is_safe(directory) {
                return None;
            }
            (root, Some(root.to_vec()))
        }
    };
    if directory == b"." {
        return Some(CompletionDirectory {
            path: base.to_vec(),
            confined_root,
        });
    }
    let mut joined = base.to_vec();
    if !joined.is_empty() && !joined.ends_with(b"/") {
        joined.push(b'/');
    }
    joined.extend_from_slice(directory);
    Some(CompletionDirectory {
        path: joined,
        confined_root,
    })
}

fn root_relative_directory_is_safe(directory: &[u8]) -> bool {
    if directory.starts_with(b"/") || directory == b"~" || directory.starts_with(b"~/") {
        return false;
    }
    let mut depth = 0usize;
    for component in directory.split(|byte| *byte == b'/') {
        match component {
            b"" => return false,
            b"." => {}
            b".." if depth == 0 => return false,
            b".." => depth -= 1,
            _ => depth += 1,
        }
    }
    true
}

fn split_path(value: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    match value.iter().rposition(|byte| *byte == b'/') {
        Some(separator) => {
            let typed_directory = value[..=separator].to_vec();
            let directory = if separator == 0 {
                b"/".to_vec()
            } else {
                value[..separator].to_vec()
            };
            (directory, typed_directory, value[separator + 1..].to_vec())
        }
        None => (b".".to_vec(), Vec::new(), value.to_vec()),
    }
}

fn path_candidates_from_entries(
    wrapper: &[u8],
    typed_directory: &[u8],
    prefix: &[u8],
    entries: Vec<CompletionEntry>,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for entry in entries {
        if !entry.name.starts_with(prefix) {
            continue;
        }
        let mut value = Vec::with_capacity(
            wrapper.len() + typed_directory.len() + entry.name.len() + usize::from(entry.directory),
        );
        value.extend_from_slice(wrapper);
        value.extend_from_slice(typed_directory);
        value.extend_from_slice(&entry.name);
        if entry.directory {
            value.push(b'/');
            candidates.push(Candidate::prefix(value));
        } else {
            candidates.push(Candidate::text(value));
        }
    }
    candidates
}

fn endpoint_candidates(
    current: &[u8],
    syntax: EndpointSyntax,
    explicit_scope: Option<&str>,
) -> Vec<Candidate> {
    let typed = std::str::from_utf8(current).unwrap_or_default();
    let typed_user = typed.rsplit_once('@').map(|(user, _)| user);
    let mut endpoints = Vec::new();
    let scope = explicit_scope.map(Path::new);
    if let Ok(records) = crate::persistence::completion_endpoints(scope) {
        endpoints.extend(records.into_iter().map(|record| NativeEndpoint {
            user: record.user,
            host: record.host,
            port: record.port,
        }));
    }
    if let Ok(cache) = read_cache() {
        endpoints.extend(cache.endpoints.into_iter().map(|cached| cached.endpoint()));
    }
    endpoints.extend(ssh_config_endpoints());
    endpoints.extend(known_hosts());

    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for mut endpoint in endpoints {
        if endpoint.user.is_none() {
            endpoint.user = typed_user.map(str::to_owned);
        }
        if typed_user.is_some() && endpoint.user.as_deref() != typed_user {
            continue;
        }
        let Some(mut label) = endpoint_candidate_value(&endpoint, typed, syntax) else {
            continue;
        };
        if !seen.insert(label.clone()) {
            continue;
        }
        if matches!(syntax, EndpointSyntax::Rsync) {
            label.push(':');
            candidates.push(Candidate::prefix(label.into_bytes()));
        } else {
            candidates.push(Candidate::text(label.into_bytes()));
        }
    }
    candidates
}

fn endpoint_candidate_value(
    endpoint: &NativeEndpoint,
    typed: &str,
    syntax: EndpointSyntax,
) -> Option<String> {
    if matches!(syntax, EndpointSyntax::Rsync) && endpoint.port.is_some() {
        return None;
    }
    let label = endpoint_label(endpoint);
    label.starts_with(typed).then_some(label)
}

fn endpoint_label(endpoint: &NativeEndpoint) -> String {
    let host = if endpoint.host.contains(':') {
        format!("[{}]", endpoint.host)
    } else {
        endpoint.host.clone()
    };
    let authority = endpoint
        .user
        .as_ref()
        .map_or(host.clone(), |user| format!("{user}@{host}"));
    endpoint
        .port
        .map_or(authority.clone(), |port| format!("{authority}:{port}"))
}

fn ssh_config_endpoints() -> Vec<NativeEndpoint> {
    let mut paths = vec![PathBuf::from("/etc/ssh/ssh_config")];
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        paths.insert(0, PathBuf::from(home).join(".ssh/config"));
    }
    let mut endpoints = Vec::new();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for raw_line in text.lines() {
            let line = raw_line.split('#').next().unwrap_or_default();
            let Ok(words) = shell_words::split(line) else {
                continue;
            };
            if words
                .first()
                .is_some_and(|word| word.eq_ignore_ascii_case("host"))
            {
                for host in words.into_iter().skip(1).filter(|host| {
                    !host.is_empty() && !host.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'!'))
                }) {
                    if let Ok(Some(endpoint)) = parse_native_endpoint(Some(&host)) {
                        endpoints.push(endpoint);
                    }
                }
            }
        }
    }
    endpoints
}

fn known_hosts() -> Vec<NativeEndpoint> {
    let mut paths = vec![PathBuf::from("/etc/ssh/ssh_known_hosts")];
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        let ssh = PathBuf::from(home).join(".ssh");
        paths.insert(0, ssh.join("known_hosts2"));
        paths.insert(0, ssh.join("known_hosts"));
    }
    let mut endpoints = Vec::new();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let mut fields = line.split_ascii_whitespace();
            let Some(first) = fields.next() else {
                continue;
            };
            if first.starts_with('#') {
                continue;
            }
            let hosts = if first.starts_with('@') {
                fields.next().unwrap_or_default()
            } else {
                first
            };
            for host in hosts.split(',') {
                if host.is_empty()
                    || host.starts_with('|')
                    || host.bytes().any(|byte| matches!(byte, b'*' | b'?' | b'!'))
                {
                    continue;
                }
                let spelling = if host.matches(':').count() > 1 && !host.starts_with('[') {
                    format!("[{host}]")
                } else {
                    host.to_owned()
                };
                if let Ok(Some(endpoint)) = parse_native_endpoint(Some(&spelling)) {
                    endpoints.push(endpoint);
                }
            }
        }
    }
    endpoints
}

fn has_explicit_rsh(command: &str, args: &[Vec<u8>]) -> bool {
    let names: &[&[u8]] = if command == "rsync" {
        &[b"-e", b"--rsh"]
    } else {
        &[b"--rsh"]
    };
    option_arguments(args).any(|argument| {
        (command == "rsync" && rsync_short_cluster_has_rsh(argument))
            || names.contains(&argument)
            || names.iter().any(|name| {
                name.starts_with(b"--")
                    && argument.starts_with(name)
                    && argument.get(name.len()) == Some(&b'=')
            })
    })
}

fn rsync_short_cluster_has_rsh(argument: &[u8]) -> bool {
    let Some(cluster) = argument.strip_prefix(b"-") else {
        return false;
    };
    if cluster.is_empty() || cluster.starts_with(b"-") {
        return false;
    }
    for option in cluster {
        match option {
            b'e' => return true,
            // `-B` consumes the rest of its token, so an `e` there is data.
            b'B' => return false,
            _ => {}
        }
    }
    false
}

fn pscope_from_args<'a>(command: &str, args: &'a [Vec<u8>]) -> Option<&'a str> {
    find_option_value(
        args,
        if command == "rsync" {
            b"--syq-pscope"
        } else {
            b"--pscope"
        },
    )
}

fn find_option_value<'a>(args: &'a [Vec<u8>], option: &[u8]) -> Option<&'a str> {
    find_option_bytes(args, option).and_then(|value| std::str::from_utf8(value).ok())
}

fn find_option_bytes<'a>(args: &'a [Vec<u8>], option: &[u8]) -> Option<&'a [u8]> {
    let mut found = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == b"--" {
            break;
        }
        if args[index] == option {
            if let Some(value) = args.get(index + 1) {
                if value == b"--" {
                    break;
                }
                found = Some(value.as_slice());
            }
            index += 2;
            continue;
        }
        if args[index].starts_with(option) && args[index].get(option.len()) == Some(&b'=') {
            found = Some(&args[index][option.len() + 1..]);
        }
        index += 1;
    }
    found
}

fn contains_option(args: &[Vec<u8>], option: &[u8]) -> bool {
    option_arguments(args).any(|argument| argument == option)
}

fn previous_is(args: &[Vec<u8>], options: &[&[u8]]) -> bool {
    !args.iter().any(|argument| argument == b"--")
        && args
            .last()
            .is_some_and(|previous| options.iter().any(|option| previous == *option))
}

fn option_arguments(args: &[Vec<u8>]) -> impl Iterator<Item = &[u8]> {
    args.iter()
        .map(Vec::as_slice)
        .take_while(|argument| *argument != b"--")
}

const BASH_ADAPTER: &str = r#"# syq dynamic completion
_syq_complete() {
    local record kind no_space=0
    COMPREPLY=()
    while IFS= read -r -d '' record; do
        kind=${record:0:1}
        COMPREPLY+=("${record:1}")
        [[ $kind == p ]] && no_space=1
    done < <(command syq completion __complete-bash "${COMP_WORDS[COMP_CWORD]-}" -- "${COMP_LINE:0:COMP_POINT}")
    compopt -o filenames 2>/dev/null || true
    (( no_space )) && compopt -o nospace 2>/dev/null || true
}
complete -F _syq_complete syq
"#;

const ZSH_ADAPTER: &str = r#"#compdef syq
_syq_complete() {
    local record kind
    local -a values prefixes
    while IFS= read -r -d $'\0' record; do
        kind=${record[1]}
        if [[ $kind == p ]]; then
            prefixes+=("${record[2,-1]}")
        else
            values+=("${record[2,-1]}")
        fi
    done < <(command syq completion __complete zsh "$((CURRENT - 1))" -- "${words[@]}")
    (( ${#values} )) && compadd -- "${values[@]}"
    (( ${#prefixes} )) && compadd -S '' -- "${prefixes[@]}"
}
compdef _syq_complete syq
"#;

const FISH_ADAPTER: &str = r#"# syq dynamic completion
function __syq_complete
    set -l words (commandline -opc)
    set -l index (count $words)
    set -l current (commandline -ct)
    command syq completion __complete fish $index -- $words "$current" | string split0
end
complete -c syq -f -a '(__syq_complete)'
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn values(candidates: Vec<Candidate>) -> Vec<Vec<u8>> {
        candidates
            .into_iter()
            .map(|candidate| candidate.value)
            .collect()
    }

    #[test]
    fn splits_local_and_rsync_remote_paths_without_confusing_colons_in_ipv6() {
        assert_eq!(
            split_path(b"a/b"),
            (b"a".to_vec(), b"a/".to_vec(), b"b".to_vec())
        );
        assert_eq!(
            split_rsync_remote(b"host:dir/f"),
            Some((&b"host"[..], &b"dir/f"[..]))
        );
        assert_eq!(
            split_rsync_remote(b"alice@[2001:db8::1]:dir"),
            Some((&b"alice@[2001:db8::1]"[..], &b"dir"[..]))
        );
        assert_eq!(split_rsync_remote(b"./a:b"), None);
        assert_eq!(split_rsync_remote(b"host::module"), None);
    }

    #[test]
    fn bash_line_parser_preserves_ssh_syntax_quotes_and_escapes() {
        let line = b"syq cp --cwd 'dir with spaces' user@host:some\\ path/fi";
        assert_eq!(
            bash_command_words(line),
            (
                4,
                vec![
                    b"syq".to_vec(),
                    b"cp".to_vec(),
                    b"--cwd".to_vec(),
                    b"dir with spaces".to_vec(),
                    b"user@host:some path/fi".to_vec(),
                ]
            )
        );
        assert_eq!(
            bash_command_words(b"printf x | syq rsync host:di"),
            (
                2,
                vec![b"syq".to_vec(), b"rsync".to_vec(), b"host:di".to_vec()]
            )
        );
        assert_eq!(
            bash_command_words(b"syq cp "),
            (2, vec![b"syq".to_vec(), b"cp".to_vec(), Vec::new()])
        );
        assert_eq!(
            bash_command_words("syq cp éa".as_bytes()),
            (
                2,
                vec![b"syq".to_vec(), b"cp".to_vec(), "éa".as_bytes().to_vec()]
            )
        );
    }

    #[test]
    fn bash_candidates_replace_only_the_fragment_after_a_word_break() {
        let candidates = vec![
            Candidate::text(b"host:dir/file".to_vec()),
            Candidate::prefix(b"host:dir/nested/".to_vec()),
        ];
        let candidates = bash_replacement_candidates(candidates, b"host:di", b"di");
        assert_eq!(candidates[0].value, b"dir/file");
        assert!(!candidates[0].no_space);
        assert_eq!(candidates[1].value, b"dir/nested/");
        assert!(candidates[1].no_space);

        assert_eq!(
            values(bash_replacement_candidates(
                vec![Candidate::text(b"--from=fake.example".to_vec())],
                b"--from=fake",
                b"fake",
            )),
            vec![b"fake.example".to_vec()]
        );
        assert_eq!(
            values(bash_replacement_candidates(
                vec![Candidate::text(b"alice@example".to_vec())],
                b"alice@ex",
                b"ex",
            )),
            vec![b"@example".to_vec()]
        );
    }

    #[test]
    fn leading_shell_assignments_do_not_hide_the_syq_command() {
        let words = ["SYQ_COMPLETION_DEBUG=1", "FOO=x", "syq", "c"].map(OsString::from);
        let candidates = values(candidates(3, &words).unwrap());
        assert!(candidates.contains(&b"cp".to_vec()));
        assert!(candidates.contains(&b"completion".to_vec()));
        assert!(is_shell_assignment(b"_FOO_2=value"));
        assert!(!is_shell_assignment(b"2FOO=value"));
        assert!(!is_shell_assignment(b"--from=value"));
    }

    #[test]
    fn root_bases_reject_paths_that_can_escape_the_root() {
        let root = Some(SourceBase::Root(b"/confined"));
        assert!(apply_path_base(root, b"../sibling").is_none());
        assert!(apply_path_base(root, b"/absolute").is_none());
        assert!(apply_path_base(root, b"~/home").is_none());
        assert_eq!(
            apply_path_base(root, b"inside/..").map(|directory| directory.path),
            Some(b"/confined/inside/..".to_vec())
        );
    }

    #[test]
    fn attached_rsync_rsh_options_disable_remote_completion() {
        assert!(has_explicit_rsh("rsync", &[b"-efalse".to_vec()]));
        assert!(has_explicit_rsh("rsync", &[b"-avefalse".to_vec()]));
        assert!(has_explicit_rsh("rsync", &[b"--rsh=false".to_vec()]));
        assert!(!has_explicit_rsh("rsync", &[b"-Bsize".to_vec()]));
        assert!(!has_explicit_rsh("cp", &[b"-efalse".to_vec()]));
    }

    #[test]
    fn option_policy_stops_at_the_double_dash_terminator() {
        let args = vec![
            b"--from".to_vec(),
            b"real.example".to_vec(),
            b"--".to_vec(),
            b"--from".to_vec(),
            b"fake.example".to_vec(),
            b"--rsh=false".to_vec(),
            b"--no-bootstrap".to_vec(),
        ];
        assert_eq!(
            find_option_bytes(&args, b"--from"),
            Some(&b"real.example"[..])
        );
        assert!(!has_explicit_rsh("cp", &args));
        assert!(!contains_option(&args, b"--no-bootstrap"));
        assert!(!previous_is(
            &[b"--pscope".to_vec(), b"--".to_vec()],
            &[b"--pscope"]
        ));

        let terminated_value = vec![
            b"--from".to_vec(),
            b"--".to_vec(),
            b"--from".to_vec(),
            b"fake.example".to_vec(),
        ];
        assert_eq!(find_option_bytes(&terminated_value, b"--from"), None);
        assert!(!has_explicit_rsh(
            "rsync",
            &[b"--".to_vec(), b"-avefalse".to_vec()]
        ));
    }

    #[test]
    fn completion_cache_lock_fails_immediately_when_already_held() {
        let temporary = crate::test_support::tempdir().unwrap();
        let directory = open_cache_directory(temporary.path(), true)
            .unwrap()
            .unwrap();
        let _first = lock_cache(temporary.path(), &directory).unwrap();
        let error = lock_cache(temporary.path(), &directory).err().unwrap();
        assert!(error.to_string().contains("completion cache is busy"));
    }

    #[test]
    fn path_candidates_preserve_raw_names_and_mark_directories() {
        let candidates = path_candidates_from_entries(
            b"host:",
            b"dir/",
            b"n",
            vec![
                CompletionEntry {
                    name: b"name\nwith-newline".to_vec(),
                    directory: false,
                },
                CompletionEntry {
                    name: b"nested".to_vec(),
                    directory: true,
                },
            ],
        );
        assert_eq!(candidates[0].value, b"host:dir/name\nwith-newline");
        assert!(!candidates[0].no_space);
        assert_eq!(candidates[1].value, b"host:dir/nested/");
        assert!(candidates[1].no_space);
    }

    #[test]
    fn root_and_option_candidates_come_from_public_command_metadata() {
        assert!(values(root_candidates(b"c")).contains(&b"cp".to_vec()));
        let command = crate::cli::command_for_completion("cp").unwrap();
        let options = values(option_candidates(&command, b"--coor"));
        assert_eq!(options, vec![b"--coordinate-at".to_vec()]);
    }

    #[test]
    fn native_option_looking_values_are_completed_as_options_unless_attached() {
        let options =
            values(filesystem_command_candidates("cp", &[b"--src-dir".to_vec()], b"--i").unwrap());
        assert!(options.contains(&b"--ignore".to_vec()));
        assert!(options.contains(&b"--into".to_vec()));
    }

    #[test]
    fn native_copy_stops_completing_sources_after_the_destination_starts() {
        let args = [b"source".to_vec(), b"--into".to_vec(), b"target".to_vec()];
        assert!(filesystem_command_candidates("cp", &args, b"")
            .unwrap()
            .is_empty());

        let options = values(filesystem_command_candidates("cp", &args, b"--").unwrap());
        assert!(options.contains(&b"--dry-run".to_vec()));
        assert!(!options.contains(&b"--src".to_vec()));
        assert!(!options.contains(&b"--mapping".to_vec()));

        let mut invalid_source = args.to_vec();
        invalid_source.push(b"--src".to_vec());
        assert!(filesystem_command_candidates("cp", &invalid_source, b"s")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn destination_completion_tracks_the_current_target_group() {
        let args = ["--to", "alpha", "--into", "one", "--tos", "beta", "gamma"]
            .map(|value| value.as_bytes().to_vec());
        assert_eq!(destination_group_endpoint(&args), Some("beta"));
        assert!(tos_group_accepts_another_endpoint(&args));

        let mut complete = args.to_vec();
        complete.extend([b"--into-existing".to_vec(), b"two".to_vec()]);
        assert!(!tos_group_accepts_another_endpoint(&complete));

        let inline = [b"--to=delta".to_vec(), b"--as".to_vec()];
        assert_eq!(destination_group_endpoint(&inline), Some("delta"));

        let inline_tos = [b"--tos=epsilon".to_vec()];
        assert_eq!(destination_group_endpoint(&inline_tos), Some("epsilon"));
        assert!(!tos_group_accepts_another_endpoint(&inline_tos));
    }

    #[test]
    fn remote_entries_are_strictly_validated() {
        assert!(validate_completion_entries(
            vec![CompletionEntry {
                name: b"../escape".to_vec(),
                directory: false,
            }],
            b""
        )
        .is_err());
        assert!(validate_completion_entries(
            vec![CompletionEntry {
                name: b"wrong".to_vec(),
                directory: false,
            }],
            b"prefix"
        )
        .is_err());
    }

    #[test]
    fn rsync_endpoint_suggestions_never_treat_a_native_port_as_a_path() {
        let endpoint = NativeEndpoint {
            user: Some("alice".into()),
            host: "example".into(),
            port: Some(2222),
        };
        assert_eq!(endpoint_label(&endpoint), "alice@example:2222");
        assert!(endpoint_candidate_value(&endpoint, "alice", EndpointSyntax::Rsync).is_none());
        assert_eq!(
            endpoint_candidate_value(&endpoint, "alice", EndpointSyntax::Native).as_deref(),
            Some("alice@example:2222")
        );
    }
}
