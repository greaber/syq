//! A server's copy, forward, or storage request carries the syq command that
//! produced it. The receiving machine parses that command itself and derives the
//! request it would authorize, so the approval prompt can show the command and
//! still mean exactly what is enforced. Both machines run the same build.
use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// Commands are small; this bound only keeps a hostile request cheap to reject.
const MAX_COMMAND_BYTES: usize = 256 * 1024;

/// The requesting process's public command line, after options taken from the
/// environment, without the program name.
pub(crate) fn current() -> Result<Vec<Vec<u8>>> {
    Ok(crate::destination::handoff::command_line()?
        .iter()
        .skip(1)
        .map(|arg| arg.as_bytes().to_vec())
        .collect())
}

/// Parse a requesting command without reading its input files, descriptors, or
/// this machine's environment options.
pub(crate) fn parse(command: &[Vec<u8>]) -> Result<crate::cli::Args> {
    anyhow::ensure!(
        command.iter().map(|arg| arg.len() + 1).sum::<usize>() <= MAX_COMMAND_BYTES,
        "requesting command is too long"
    );
    anyhow::ensure!(
        matches!(command.first().map(Vec::as_slice), Some(b"cp" | b"rm")),
        "requests must come from syq cp or syq rm"
    );
    let argv: Vec<OsString> = command
        .iter()
        .map(|arg| OsString::from_vec(arg.clone()))
        .collect();
    let mut args = crate::cli::Args::parse_args(&argv)
        .map_err(|error| anyhow::anyhow!("{error:#}"))
        .context("cannot parse the requesting command")?;
    args.normalize();
    Ok(args)
}

fn ensure_same<T: serde::Serialize>(requested: &T, derived: &T) -> Result<()> {
    anyhow::ensure!(
        serde_json::to_value(requested)? == serde_json::to_value(derived)?,
        "the request does not match the command that produced it"
    );
    Ok(())
}

/// Copies to this machine, or through its SSH access to `target`.
pub(crate) fn check_copy(
    command: &[Vec<u8>],
    request: &crate::destination::CopyRequest,
    receiver: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    let args = parse(command)?;
    anyhow::ensure!(
        args.interface == crate::cli::Interface::NativeCp && args.s3.is_none(),
        "copy requests must come from syq cp"
    );
    let destination = args.locations.last().context("copy destination missing")?;
    if let Some(name) = receiver {
        anyhow::ensure!(
            destination.host.as_deref() == Some(&format!("@{name}")),
            "the requesting command copies to a different destination"
        );
    }
    if let Some(target) = target {
        anyhow::ensure!(
            crate::destination::forward_target(&args)? == target,
            "the requesting command copies to a different server"
        );
    }
    let mut derived =
        crate::restricted::named_request(&args, request.constraints.receipt_policy.clone())?;
    // The server reads these files; this machine cannot. Both only narrow the
    // copy: a mapping limits the destination paths, and ignore rules protect
    // matching destination entries.
    if args.native_mapping.is_some() {
        derived.constraints.mapping = request.constraints.mapping.clone();
    }
    if !args.ignore_from.is_empty() {
        derived.constraints.filters.ignore = request.constraints.filters.ignore.clone();
    }
    ensure_same(request, &derived)
}

/// Storage authorization. The server may take the endpoint from its
/// environment when the command does not name one.
pub(crate) fn check_storage(
    command: &[Vec<u8>],
    request: &crate::s3::authorization::Request,
    receiver: &str,
) -> Result<()> {
    let args = parse(command)?;
    let options = args
        .s3
        .as_ref()
        .context("storage requests must name s3://")?;
    anyhow::ensure!(
        matches!(&args.auth_from, crate::cli::AuthFrom::Return(name) if name == receiver),
        "the requesting command authorizes from a different machine"
    );
    let mut derived = match &args.descriptor_copy {
        Some(plan) => crate::s3::stream::authorization_request(
            &args,
            options,
            plan.key.as_deref().context("storage stream key missing")?,
            plan.placement.existence,
        ),
        None => crate::s3::authorization::request_for(&args, options)?,
    };
    if options.endpoint.is_none() {
        if let Some(endpoint) = &request.endpoint {
            crate::s3::validate_endpoint(endpoint)?;
        }
        derived.endpoint = request.endpoint.clone();
    }
    ensure_same(request, &derived)
}

/// Display text for one argument. Plain words stay as typed; anything else is
/// quoted with control, formatting, and invalid bytes escaped.
fn display_arg(arg: &[u8]) -> String {
    if !arg.is_empty()
        && arg
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,~".contains(b))
    {
        String::from_utf8_lossy(arg).into_owned()
    } else {
        format!("{:?}", OsStr::from_bytes(arg))
    }
}

/// Displayed arguments, with customer-provided encryption keys in S3 headers
/// replaced: prompts can persist in desktop notification history.
pub(crate) fn display(command: &[Vec<u8>]) -> Vec<String> {
    if command.is_empty() {
        return Vec::new();
    }
    const HEADERS: [&[u8]; 2] = [b"--s3-header", b"--s3-write-header"];
    let mut shown = vec!["syq".to_owned()];
    let mut header = false;
    for arg in command {
        let value = if header {
            Some(arg.as_slice())
        } else {
            HEADERS.iter().find_map(|option| {
                arg.strip_prefix(*option)
                    .and_then(|rest| rest.strip_prefix(b"="))
            })
        };
        shown.push(match value.filter(|value| secret_header(value)) {
            Some(value) => {
                let name = value.split(|b| *b == b':').next().unwrap_or_default();
                let prefix = &arg[..arg.len() - value.len()];
                display_arg(&[prefix, name, b": <redacted>"].concat())
            }
            None => display_arg(arg),
        });
        header = HEADERS.contains(&arg.as_slice());
    }
    shown
}

fn secret_header(header: &[u8]) -> bool {
    let name = header.split(|b| *b == b':').next().unwrap_or_default();
    let name = name.trim_ascii().to_ascii_lowercase();
    name.ends_with(b"server-side-encryption-customer-key")
}

/// Join displayed arguments, styling the values of options whose files are read
/// on the server: this machine cannot see or check their contents.
pub(crate) fn render(
    display: &[String],
    plain: impl Fn(&str) -> String,
    server_input: impl Fn(&str) -> String,
) -> String {
    const OPTIONS: [&str; 2] = ["--mapping", "--ignore-from"];
    let mut words = Vec::with_capacity(display.len());
    let mut value = false;
    for word in display {
        let inline = OPTIONS.iter().any(|option| {
            word.strip_prefix(option)
                .is_some_and(|v| v.starts_with('='))
        });
        words.push(if value || inline {
            server_input(word)
        } else {
            plain(word)
        });
        value = OPTIONS.contains(&word.as_str());
    }
    words.join(" ")
}

#[cfg(test)]
mod tests;
