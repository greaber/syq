use super::*;

impl RemoteSpec {
    /// Install a matching release asset or upload this source-built executable.
    pub fn install_helper(&self) -> Result<()> {
        let mut installed = self.helper_install.lock().unwrap();
        if *installed {
            return Ok(());
        }

        let bootstrap = self.remote_bootstrap()?;
        let target = bootstrap.target;
        if !self.quiet {
            crate::output::diagnostic!(
                "syq: {}: installing {} helper for {}",
                self.label(),
                remote_helper::helper_identity(),
                target.key
            );
        }
        self.bootstrap_helper(bootstrap).with_context(|| {
            format!(
                "could not install the matching {} helper on {} ({})",
                remote_helper::helper_identity(),
                self.label(),
                target.key
            )
        })?;
        *installed = true;
        Ok(())
    }

    pub(super) fn remote_bootstrap(&self) -> Result<RemoteBootstrap> {
        let mut cmd = self.ssh_command(SshConnection::Independent, false);
        cmd.arg(remote_helper::probe_command())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_captured(&mut cmd, None)
            .with_context(|| format!("probe platform on {}", self.label()))?;
        if !out.status.success() {
            bail!(
                "could not detect the platform on {} ({}){}",
                self.label(),
                out.status,
                output_suffix(&out.stderr.bytes)
            );
        }
        if out.stdout.truncated {
            bail!(
                "{}: platform probe printed more than {MAX_BOOTSTRAP_OUTPUT_BYTES} bytes",
                self.label()
            );
        }
        let text = String::from_utf8_lossy(&out.stdout.bytes);
        let value = text
            .lines()
            .find_map(|line| line.strip_prefix("syq-helper-target:"))
            .ok_or_else(|| anyhow!("{}: platform probe returned no target", self.label()))?;
        let (os, arch) = value
            .split_once(':')
            .ok_or_else(|| anyhow!("{}: malformed platform response {value:?}", self.label()))?;
        let target = Target::for_bootstrap(os, arch).ok_or_else(|| {
            anyhow!(
                "{}: automatic remote helpers do not support {os} {arch}",
                self.label()
            )
        })?;
        let remote_download = text
            .lines()
            .find_map(|line| line.strip_prefix("syq-helper-tools:"))
            .is_some_and(|tools| {
                let mut tools = tools.split(':');
                tools.next().is_some_and(|tool| !tool.is_empty())
                    && tools.next().is_some_and(|tool| !tool.is_empty())
                    && tools.next().is_some_and(|tool| !tool.is_empty())
                    && tools.next().is_none()
            });
        Ok(RemoteBootstrap {
            target,
            remote_download,
        })
    }

    pub(super) fn bootstrap_helper(&self, bootstrap: RemoteBootstrap) -> Result<()> {
        if !crate::identity::uses_release_helpers() {
            if !bootstrap.target.can_upload_self() {
                bail!(
                    "cannot automatically install a source-built helper for {} from {}; \
                     run syq from a compatible host, use an official release, or install a matching \
                     build on the remote and select it with --syq-path (--rsync-path for syq rsync)",
                    bootstrap.target.key,
                    crate::identity::platform()
                );
            }
            // On Linux this refers to the running image even if a rebuild has
            // replaced or removed its original path.
            #[cfg(target_os = "linux")]
            let executable = std::path::PathBuf::from("/proc/self/exe");
            #[cfg(not(target_os = "linux"))]
            let executable =
                std::env::current_exe().context("locate the running syq executable")?;
            let binary =
                std::fs::read(&executable).context("read the running syq for helper upload")?;
            if !self.quiet {
                crate::output::diagnostic!(
                    "syq: {}: uploading this source build over SSH",
                    self.label()
                );
            }
            // The upload script runs the temporary helper and checks its build
            // identity before renaming it into the cache. OS/CPU agreement alone
            // does not guarantee compatible dynamic libraries or CPU features.
            return self.upload_helper(bootstrap.target, &binary);
        }
        let mut trusted = None;
        if bootstrap.remote_download {
            match self.try_remote_download(bootstrap.target)? {
                RemoteDownloadOutcome::Installed => return Ok(()),
                RemoteDownloadOutcome::Fallback { detail, helper } => {
                    trusted = helper;
                    if !self.quiet {
                        crate::output::diagnostic!(
                            "syq: {}: remote download unavailable{}; uploading the verified helper over SSH",
                            self.label(),
                            parenthesized_detail(&detail)
                        );
                    }
                }
                RemoteDownloadOutcome::Integrity { warning, helper } => {
                    trusted = helper;
                    crate::output::diagnostic!(
                        "syq: warning: {}: {}; the remote download was discarded; uploading the verified helper over SSH",
                        self.label(),
                        warning
                    );
                }
            }
        } else if !self.quiet {
            crate::output::diagnostic!(
                "syq: {}: remote download prerequisites unavailable; uploading the verified helper over SSH",
                self.label()
            );
        }

        let helper = match trusted {
            Some(helper) => helper,
            None => crate::update::trusted_current_helper(bootstrap.target)
                .context("download and verify the signed release manifest")?,
        };
        let binary = crate::update::verified_current_helper(&helper)
            .context("download and verify the helper for SSH upload")?;
        self.upload_helper(bootstrap.target, &binary)
    }

    pub(super) fn try_remote_download(&self, target: Target) -> Result<RemoteDownloadOutcome> {
        let script = remote_helper::download_script(target);
        let mut cmd = self.ssh_command(SshConnection::Independent, false);
        cmd.arg(format!("sh -c {}", shell_words::quote(&script)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("start helper download on {}", self.label()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("remote helper download stdin was not piped"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("remote helper download stdout was not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("remote helper download stderr was not piped"))?;
        let stderr_reader = capture_stream(stderr);

        let report = read_remote_download_report(&mut BufReader::new(stdout));
        let mut helper = None;
        let mut integrity_warning = None;
        let mut protocol_detail = None;
        let mut authorized = false;
        match report {
            Ok(Some(report)) if valid_sha256(&report.sha256) => {
                match crate::update::trusted_current_helper_from_manifest(target, &report.manifest)
                {
                    Ok(trusted) => {
                        if report.sha256 == trusted.archive_sha256() {
                            authorized = true;
                        } else {
                            integrity_warning = Some(format!(
                                "remote helper download failed integrity verification (expected SHA-256 {}, got {})",
                                trusted.archive_sha256(),
                                report.sha256
                            ));
                        }
                        helper = Some(trusted);
                    }
                    Err(error) => {
                        integrity_warning = Some(format!(
                            "remote release manifest failed integrity verification or validation ({error})"
                        ));
                    }
                }
            }
            Ok(Some(_)) => {
                protocol_detail = Some("the remote hasher returned no valid digest".into());
            }
            Ok(None) => {
                protocol_detail =
                    Some("the remote returned no download verification report".into());
            }
            Err(error) => {
                protocol_detail = Some(format!(
                    "could not read the remote verification report: {error}"
                ));
            }
        }
        let decision = if authorized {
            b"install\n"
        } else {
            b"discard\n"
        };
        let write_result = stdin.write_all(decision);
        drop(stdin);

        let status = child
            .wait()
            .with_context(|| format!("wait for helper download on {}", self.label()))?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow!("remote helper stderr reader panicked"))?
            .map(|captured| captured.bytes)
            .unwrap_or_default();
        let detail = output_message(&stderr);
        if authorized {
            self.relay_install_notices(&stderr);
        }
        if status.success() {
            write_result.context("authorize the verified remote helper")?;
            return if authorized {
                Ok(RemoteDownloadOutcome::Installed)
            } else {
                Ok(RemoteDownloadOutcome::Fallback {
                    detail: protocol_detail
                        .unwrap_or_else(|| "the remote ignored a discard decision".into()),
                    helper,
                })
            };
        }
        match status.code() {
            Some(remote_helper::REMOTE_DOWNLOAD_FALLBACK_EXIT) => {
                Ok(RemoteDownloadOutcome::Fallback {
                    detail: if detail.is_empty() {
                        protocol_detail.unwrap_or_default()
                    } else {
                        detail
                    },
                    helper,
                })
            }
            Some(remote_helper::REMOTE_DOWNLOAD_INTEGRITY_EXIT) => match integrity_warning {
                Some(warning) => Ok(RemoteDownloadOutcome::Integrity { warning, helper }),
                None => Ok(RemoteDownloadOutcome::Fallback {
                    detail: protocol_detail.unwrap_or(detail),
                    helper,
                }),
            },
            _ => {
                bail!(
                    "remote download exited {}{}",
                    status,
                    output_suffix(&stderr)
                );
            }
        }
    }

    pub(super) fn relay_install_notices(&self, stderr: &[u8]) {
        if !self.quiet {
            for notice in install_notices(stderr) {
                crate::output::diagnostic!("syq: {}: {notice}", self.label());
            }
        }
    }

    pub(super) fn upload_helper(&self, target: Target, binary: &[u8]) -> Result<()> {
        let script = remote_helper::upload_script(target);
        let mut cmd = self.ssh_command(SshConnection::Independent, false);
        cmd.arg(format!("sh -c {}", shell_words::quote(&script)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_captured(&mut cmd, Some(binary))
            .with_context(|| format!("run helper upload to {}", self.label()))?;
        self.relay_install_notices(&out.stderr.bytes);
        if !out.status.success() {
            bail!(
                "remote helper upload exited {}{}",
                out.status,
                output_suffix(&out.stderr.bytes)
            );
        }
        match out.input_error {
            Some(error) => Err(error).with_context(|| format!("upload helper to {}", self.label())),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RemoteBootstrap {
    pub(super) target: Target,
    pub(super) remote_download: bool,
}

pub(super) enum RemoteDownloadOutcome {
    Installed,
    Fallback {
        detail: String,
        helper: Option<crate::update::TrustedCurrentHelper>,
    },
    Integrity {
        warning: String,
        helper: Option<crate::update::TrustedCurrentHelper>,
    },
}

#[derive(Debug)]
pub(super) struct RemoteDownloadReport {
    pub(super) manifest: Vec<u8>,
    pub(super) sha256: String,
}

/// Bound on each captured stream of a bootstrap command: the platform probe,
/// the remote download report's stderr, and the helper upload. Legitimate
/// output is a few lines; the bound keeps a faulty or hostile remote from
/// growing local memory without limit. Streams are drained past the bound so
/// the child never blocks on a full pipe.
pub(super) const MAX_BOOTSTRAP_OUTPUT_BYTES: usize = 1024 * 1024;

/// Largest remote release manifest accepted from the download report.
pub(super) const MAX_MANIFEST_SIZE: usize = 1024 * 1024;

/// Longest report line buffered before it is checked. A manifest data line may
/// carry the whole manifest after its framing prefix.
pub(super) const MAX_REPORT_LINE_BYTES: usize = MAX_MANIFEST_SIZE + 1024;

pub(super) struct CapturedStream {
    pub(super) bytes: Vec<u8>,
    /// The stream produced more than the retained bytes; the rest was discarded.
    pub(super) truncated: bool,
}

/// Read a stream keeping at most `limit` bytes, then drain and discard the
/// remainder so a child process writing to it never blocks.
pub(super) fn read_capped(mut reader: impl Read, limit: usize) -> std::io::Result<CapturedStream> {
    let mut bytes = Vec::new();
    reader.by_ref().take(limit as u64).read_to_end(&mut bytes)?;
    let discarded = std::io::copy(&mut reader, &mut std::io::sink())?;
    Ok(CapturedStream {
        bytes,
        truncated: discarded > 0,
    })
}

pub(super) fn capture_stream(
    reader: impl Read + Send + 'static,
) -> std::thread::JoinHandle<std::io::Result<CapturedStream>> {
    std::thread::spawn(move || read_capped(reader, MAX_BOOTSTRAP_OUTPUT_BYTES))
}

pub(super) struct CapturedOutput {
    pub(super) status: std::process::ExitStatus,
    pub(super) stdout: CapturedStream,
    pub(super) stderr: CapturedStream,
    /// Writing `input` to the child's stdin failed. Reported after the exit
    /// status, which usually explains why the child stopped reading.
    pub(super) input_error: Option<std::io::Error>,
}

/// Run a bootstrap command, feeding it `input` when given, with both output
/// streams captured under `MAX_BOOTSTRAP_OUTPUT_BYTES`. The command must have
/// piped stdout and stderr; stdin is piped when there is input.
pub(super) fn run_captured(cmd: &mut Command, input: Option<&[u8]>) -> Result<CapturedOutput> {
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().context("start command")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("command stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("command stderr was not piped"))?;
    let stdout_reader = capture_stream(stdout);
    let stderr_reader = capture_stream(stderr);
    let input_error = match input {
        Some(bytes) => {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("command stdin was not piped"))?;
            stdin.write_all(bytes).err()
        }
        None => None,
    };
    let status = child.wait().context("wait for command")?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("stdout reader panicked"))?
        .context("read command stdout")?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("stderr reader panicked"))?
        .context("read command stderr")?;
    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
        input_error,
    })
}

/// Read one report line into `line`, refusing lines longer than
/// `MAX_REPORT_LINE_BYTES` before they are buffered in full.
pub(super) fn read_report_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
) -> std::io::Result<usize> {
    line.clear();
    let read = reader
        .by_ref()
        .take(MAX_REPORT_LINE_BYTES as u64 + 1)
        .read_until(b'\n', line)?;
    if read > MAX_REPORT_LINE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "remote helper report line exceeded the size limit",
        ));
    }
    Ok(read)
}

pub(super) fn read_remote_download_report(
    reader: &mut impl BufRead,
) -> std::io::Result<Option<RemoteDownloadReport>> {
    let mut line = Vec::new();
    if read_report_line(reader, &mut line)? == 0 {
        return Ok(None);
    }
    if protocol_line(&line) != b"syq-helper-manifest-begin" {
        return Ok(None);
    }

    let mut manifest = Vec::new();
    loop {
        if read_report_line(reader, &mut line)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "remote manifest was not terminated",
            ));
        }
        let framed = protocol_line(&line);
        if framed == b"syq-helper-manifest-end" {
            break;
        }
        let data = framed
            .strip_prefix(b"syq-helper-manifest-data:")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "remote manifest contained unframed protocol data",
                )
            })?;
        if manifest.len().saturating_add(data.len() + 1) > MAX_MANIFEST_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "remote manifest exceeded 1 MiB",
            ));
        }
        manifest.extend_from_slice(data);
        manifest.push(b'\n');
    }

    if read_report_line(reader, &mut line)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "remote helper digest was missing",
        ));
    }
    let digest = protocol_line(&line)
        .strip_prefix(b"syq-helper-sha256:")
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "remote helper digest marker was missing",
            )
        })?;
    let sha256 = String::from_utf8_lossy(digest).into_owned();
    if read_report_line(reader, &mut line)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "remote helper report was not terminated",
        ));
    }
    if protocol_line(&line) != b"syq-helper-report-end" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "remote helper report contained trailing or malformed protocol data",
        ));
    }
    Ok(Some(RemoteDownloadReport { manifest, sha256 }))
}

pub(super) fn protocol_line(mut line: &[u8]) -> &[u8] {
    if let Some(value) = line.strip_suffix(b"\n") {
        line = value;
    }
    line.strip_suffix(b"\r").unwrap_or(line)
}

pub(super) enum BootstrapStderrLine<'a> {
    Notice(std::borrow::Cow<'a, str>),
    Diagnostic(std::borrow::Cow<'a, str>),
}

pub(super) fn bootstrap_stderr_lines(
    stderr: &[u8],
) -> impl Iterator<Item = BootstrapStderrLine<'_>> {
    stderr.split(|byte| *byte == b'\n').map(|line| {
        let line = protocol_line(line);
        match line.strip_prefix(crate::remote_user_install::NOTICE_PREFIX.as_bytes()) {
            Some(notice) => BootstrapStderrLine::Notice(String::from_utf8_lossy(notice)),
            None => BootstrapStderrLine::Diagnostic(String::from_utf8_lossy(line)),
        }
    })
}

pub(super) fn install_notices(stderr: &[u8]) -> impl Iterator<Item = std::borrow::Cow<'_, str>> {
    bootstrap_stderr_lines(stderr).filter_map(|line| match line {
        BootstrapStderrLine::Notice(notice) => Some(notice),
        BootstrapStderrLine::Diagnostic(_) => None,
    })
}

pub(super) fn output_suffix(stderr: &[u8]) -> String {
    let message = output_message(stderr);
    if message.is_empty() {
        String::new()
    } else {
        format!(": {message}")
    }
}

pub(super) fn output_message(stderr: &[u8]) -> String {
    let mut diagnostics = Vec::new();
    for line in bootstrap_stderr_lines(stderr) {
        match line {
            BootstrapStderrLine::Diagnostic(message) => diagnostics.push(message),
            BootstrapStderrLine::Notice(_) => {
                // Each notice adds one leading newline; preserve other spacing.
                if diagnostics.last().is_some_and(|line| line.is_empty()) {
                    diagnostics.pop();
                }
            }
        }
    }
    let message = diagnostics.join("\n");
    message
        .trim()
        .strip_prefix("syq: ")
        .unwrap_or_else(|| message.trim())
        .to_owned()
}

pub(super) fn parenthesized_detail(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(" ({detail})")
    }
}

pub(super) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
