//! Named-job recovery and copy identities.

mod command;
mod job;
mod journal;
mod store;

pub fn fresh_copy_id() -> anyhow::Result<crate::proto::CopyId> {
    let mut id = [0; 16];
    getrandom::fill(&mut id)
        .map_err(|error| anyhow::anyhow!("generate partial identity: {error}"))?;
    Ok(id)
}

pub(crate) use job::Job;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct JobSpec {
    pub id: String,
    pub resumed: bool,
}

pub(crate) fn open_removal_job(
    spec: Option<&JobSpec>,
) -> anyhow::Result<Option<std::sync::Arc<Job>>> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    match Job::endpoint(&spec.id, "remove", spec.resumed) {
        Ok(job) => Ok(Some(std::sync::Arc::new(job))),
        Err(error) if !spec.resumed => {
            crate::output::diagnostic!("syq: removal continues without job recording: {error:#}");
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
pub(crate) fn removal_job(
    job: Option<&std::sync::Arc<Job>>,
) -> anyhow::Result<Option<std::sync::Arc<Job>>> {
    let result = open_removal_job(
        job.map(|job| JobSpec {
            id: job.id.clone(),
            resumed: job.resumed,
        })
        .as_ref(),
    )?;
    if result.is_none() {
        if let Some(job) = job {
            job.disable("endpoint journal is unavailable");
        }
    }
    Ok(result)
}

/// Restore before ordinary argument parsing, so all option values still pass
/// through the command's normal validation. Positional/semantic changes fail
/// before connecting to any endpoint.
pub(crate) fn restore(
    argv: &mut Vec<std::ffi::OsString>,
) -> anyhow::Result<Option<std::sync::Arc<Job>>> {
    use anyhow::{bail, Context};
    use std::os::unix::ffi::OsStrExt;
    let Some(command) = argv
        .get(1)
        .and_then(|word| word.to_str())
        .map(str::to_owned)
    else {
        return Ok(None);
    };
    if !matches!(command.as_str(), "cp" | "rm") {
        return Ok(None);
    }
    let mut token = None;
    let mut overrides = Vec::new();
    let mut index = 2;
    while index < argv.len() {
        let word = &argv[index];
        if word == "--" {
            overrides.extend_from_slice(&argv[index..]);
            break;
        }
        let bytes = word.as_bytes();
        if bytes == b"--resume" || bytes.starts_with(b"--resume=") {
            if token.is_some() {
                bail!("--resume may be specified only once");
            }
            let value = if bytes == b"--resume" {
                index += 1;
                argv.get(index)
                    .context("--resume requires the ID of a previous job")?
                    .to_str()
                    .context("job ID must be UTF-8")?
            } else {
                std::str::from_utf8(&bytes[9..]).context("job ID must be UTF-8")?
            };
            token = Some(value.to_owned());
        } else {
            overrides.push(word.clone());
        }
        index += 1;
    }
    let Some(token) = token else {
        return Ok(None);
    };
    let job = std::sync::Arc::new(Job::open(&token)?);
    let (saved, cwd) = job.arguments(&overrides)?;
    if saved.first().and_then(|word| word.to_str()) != Some(command.as_str()) {
        bail!("job {token} belongs to a different command");
    }
    std::env::set_current_dir(cwd).context("restore the job's working directory")?;
    argv.truncate(1);
    argv.extend(saved);
    Ok(Some(job))
}

pub(crate) fn start(
    argv: &[std::ffi::OsString],
    args: &mut crate::cli::Args,
) -> anyhow::Result<()> {
    if let Some(job) = args.resume_job.clone() {
        job.restore_inputs(args)?;
        return Ok(());
    }
    if args.dry_run
        || args.clean_partials
        || !matches!(
            args.interface,
            crate::cli::Interface::NativeCp | crate::cli::Interface::NativeRm
        )
        || args.descriptor_copy.is_some()
        || args.stream_mapping_fd.is_some()
    {
        return Ok(());
    }
    // Remote coordinator/receiver integration is installed separately. Do not
    // advertise a token whose execution state is not yet journaled here.
    if args.detach
        || args.return_selection.is_some()
        || (args.interface == crate::cli::Interface::NativeCp
            && args
                .locations
                .split_last()
                .is_some_and(|(destination, sources)| {
                    destination.is_remote() && sources.iter().any(|source| source.is_remote())
                }))
    {
        return Ok(());
    }
    match Job::create(argv) {
        Ok(job) => {
            let job = std::sync::Arc::new(job);
            if args.interface == crate::cli::Interface::NativeCp {
                job.save_inputs(args)?;
            }
            if job.available() {
                crate::output::diagnostic!(
                    "syq: job {}; resume with syq {} --resume {}",
                    job.id,
                    if args.rm { "rm" } else { "cp" },
                    job.id
                );
                args.resume_job = Some(job);
            }
        }
        Err(error) => {
            crate::output::diagnostic!("syq: continuing without job recording: {error:#}")
        }
    }
    Ok(())
}
