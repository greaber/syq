//! Storage signing for a copy between an SSH server and a bucket. The machine
//! where the command was typed starts the ordinary local-to-storage copy on
//! the server and signs that copy's storage requests with its own
//! credentials. Requests and signed URLs travel over the SSH session that
//! runs the copy; file data travels between the server and storage only.
use super::*;
use std::io::Read as _;
use std::os::unix::net::UnixStream;

/// Set, to the starting machine's build identity, in the environment of a
/// copy whose storage requests the machine that started it signs.
pub(crate) const SIGNING_ENV: &str = "SYQ_INTERNAL_NATIVE_STORAGE_SIGNING";

/// How long the URLs signed for a started copy stay valid: long enough for a
/// copy that runs all day, and well short of the week a signature may last.
/// Every URL is signed before data moves, so a copy still running at this
/// age fails its remaining requests; running it again signs afresh and
/// resumes.
pub(crate) const LIFETIME: u64 = 24 * 60 * 60;

/// The most signing bytes carried on one line of the copy's output, well
/// inside what the starting machine accepts as one line once encoded.
const LINE_BYTES: usize = 48 * 1024;

/// What the command typed on this machine lets the server's copy ask for:
/// its bucket, the keys under its S3 source or destination, and only the
/// operations it implies. The server supplies none of this.
pub(crate) fn request(args: &crate::cli::Args) -> Result<Request> {
    let mut options = args
        .s3
        .clone()
        .context("a copy between a server and storage names s3://")?;
    anyhow::ensure!(
        !args.rm && !options.route.is_server_copy() && args.descriptor_copy.is_none(),
        "this machine signs storage requests only for a file or tree copy between a server and a bucket"
    );
    // As for a copy run here, this machine's environment may name the endpoint.
    options.endpoint = options
        .endpoint
        .or_else(|| std::env::var("AWS_ENDPOINT_URL_S3").ok())
        .or_else(|| std::env::var("AWS_ENDPOINT_URL").ok());
    let mut request = request_for(args, &options)?;
    request.lifetime = LIFETIME;
    Ok(request)
}

/// A signer for [`request`], using this machine's storage credentials.
pub(crate) fn signer(request: Request) -> Result<Signer> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Signer::new(request))
        .context("prepare to sign the server's storage requests with this machine's credentials")
}

/// The command's headers as the opening message carries them.
pub(crate) fn header_pairs(headers: &[crate::s3::Header]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|crate::s3::Header(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// The line prefix of signing bytes on the copy's standard output.
pub(crate) fn line_prefix(token: &str) -> String {
    format!("syq-storage-{token}:")
}

/// On a server, for a copy another machine started and signs for: connect
/// the signing session carried on this process's standard input and output,
/// and take the endpoint, region and headers that machine chose. Does
/// nothing for any other copy.
pub(crate) fn attach(args: &mut crate::cli::Args) -> Result<()> {
    let Some(identity) = args.storage_signing.clone() else {
        return Ok(());
    };
    // Nothing of the session is read or written for another build.
    anyhow::ensure!(
        identity == crate::identity::build(),
        "a copy between a server and storage needs the same syq build on both machines: this server runs {} and the machine that started the copy runs {identity}. Run the copy without --syq-path or --no-bootstrap so that syq installs the matching build here",
        crate::identity::build()
    );
    let bucket = args
        .s3
        .as_ref()
        .filter(|options| !options.route.is_server_copy())
        .filter(|_| args.delegated && !args.rm && args.descriptor_copy.is_none())
        .map(|options| options.bucket.clone())
        .context("storage signing by the machine that started a copy is internal to a copy between a server and a bucket")?;
    let token = args
        .results_token
        .clone()
        .context("storage signing needs its internal output token")?;
    let (local, remote) = UnixStream::pair().context("create the storage signing channel")?;
    let outgoing = remote
        .try_clone()
        .context("create the storage signing channel")?;
    crate::remote_to_remote::follow_requester_signing(args, remote)?;
    std::thread::Builder::new()
        .name("storage-signing".into())
        .spawn(move || {
            let prefix = line_prefix(&token);
            send_lines(outgoing, |line| {
                crate::output::write_stdout(format_args!("{prefix}{line}"))
            })
        })
        .context("start the storage signing channel")?;
    let (authorization, headers, write_headers) = open(bucket, local)?;
    let options = args.s3.as_mut().expect("checked above");
    options.headers = headers;
    options.write_headers = write_headers;
    args.storage_authorization = Some(Arc::new(authorization));
    Ok(())
}

/// Read what the machine that started the copy sends first on `session`:
/// the authorization its signatures give, and the command's headers.
pub(crate) fn open(
    bucket: String,
    mut session: UnixStream,
) -> Result<(Authorization, Vec<crate::s3::Header>, Vec<crate::s3::Header>)> {
    let opening = crate::destination::storage::open_started_copy(&mut session).context(
        "the machine that started this copy ended before it could sign storage requests",
    )?;
    anyhow::ensure!(
        now()? < opening.configuration.expires_at,
        "the storage URLs the machine that started this copy signs have already expired by this server's clock; check the date and time on both machines"
    );
    let headers = |headers: Vec<(String, String)>| {
        headers
            .into_iter()
            .map(|(name, value)| {
                format!("{name}: {value}")
                    .parse::<crate::s3::Header>()
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "invalid storage header from the machine that started this copy: {error}"
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()
    };
    let (headers, write_headers) = (headers(opening.headers)?, headers(opening.write_headers)?);
    let mut authorization = Authorization::new(bucket, opening.configuration, session);
    authorization.started_elsewhere = true;
    Ok((authorization, headers, write_headers))
}

/// Hand what the copy sends on its signing session to `line`, as text that
/// fits one line of standard output. The starting machine picks those lines
/// out of the copy's other output.
pub(crate) fn send_lines(
    mut session: UnixStream,
    mut line: impl FnMut(&str) -> std::io::Result<()>,
) {
    use base64::Engine as _;
    let mut buffer = vec![0u8; LINE_BYTES];
    loop {
        match session.read(&mut buffer) {
            Ok(0) => return,
            Ok(length) => {
                let encoded =
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(&buffer[..length]);
                if line(&encoded).is_err() {
                    // Nothing reads the output: end the session so that the
                    // copy fails instead of waiting for a reply.
                    let _ = session.shutdown(std::net::Shutdown::Both);
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Printed once when a copy another machine signs for failed without the
/// storage service ever answering this server.
pub(crate) fn unreachable_hint(authorization: &Authorization) -> Option<String> {
    (authorization.started_elsewhere() && authorization.never_answered()).then(|| {
        format!(
            "syq: this server got no answer from the storage service at {}. File data travels directly between this server and storage, never through the machine that started the copy, so this server needs outbound access to that address and, for HTTPS, a working set of CA certificates (see SSL_CERT_FILE)",
            authorization.configuration.endpoint
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn command(words: &[&str]) -> crate::cli::Args {
        crate::cli::Args::parse_args(&words.iter().map(OsString::from).collect::<Vec<_>>())
            .unwrap()
    }
    fn permits(request: &Request, unsigned: Unsigned) -> bool {
        // The signer the starting machine uses, with fixture credentials.
        Signer::fixture(request.clone()).sign(&unsigned).is_ok()
    }
    fn list(prefix: &str) -> Unsigned {
        Unsigned::new("GET", "")
            .query("list-type", "2")
            .query("prefix", prefix)
    }
    const UPLOAD: &[&str] = &[
        "cp", "--from", "server", "--srcs-in", "/srv/dataset", "--to", "s3://bucket", "--into",
        "backups/dataset",
    ];
    fn with(base: &[&'static str], more: &[&'static str]) -> Vec<&'static str> {
        base.iter().chain(more).copied().collect()
    }

    #[test]
    fn an_upload_signs_writes_under_its_destination_only() {
        let request = request(&command(UPLOAD)).unwrap();
        assert_eq!(request.bucket, "bucket");
        assert_eq!(request.lifetime, 24 * 60 * 60);
        assert!(request.upload && !request.delete && !request.create_only);
        assert!(request.source.is_none() && request.removal.is_none());
        for allowed in [
            Unsigned::new("PUT", "backups/dataset/a"),
            Unsigned::new("HEAD", "backups/dataset/sub/b"),
            Unsigned::new("GET", "backups/dataset/a"),
            Unsigned::new("POST", "backups/dataset/big").query("uploads", ""),
            list("backups/dataset/"),
        ] {
            assert!(permits(&request, allowed.clone()), "{allowed:?}");
        }
        for refused in [
            // Outside the destination the command names.
            Unsigned::new("PUT", "backups/other/a"),
            Unsigned::new("GET", "backups/dataset-private/a"),
            Unsigned::new("GET", "secrets"),
            list("backups/"),
            list(""),
            // Another bucket.
            Unsigned::new("PUT", "backups/dataset/a").bucket("other", "bucket"),
            Unsigned::new("GET", "backups/dataset/a").bucket("other", "bucket"),
            // Deleting needs --prune.
            Unsigned::new("DELETE", "backups/dataset/a"),
            Unsigned::new("POST", "").query("delete", ""),
            // Never the bucket itself, its versions, or its ACLs.
            Unsigned::new("PUT", ""),
            Unsigned::new("DELETE", ""),
            Unsigned::new("GET", "").query("versions", "").query("prefix", "backups/dataset/"),
            Unsigned::new("PUT", "backups/dataset/a").query("acl", ""),
            Unsigned::new("PUT", "backups/dataset/a").header("x-amz-acl", "public-read"),
            // Copying an object the command does not name into the destination.
            Unsigned::new("PUT", "backups/dataset/a").header("x-amz-copy-source", "/bucket/secrets"),
            // A header the command did not add.
            Unsigned::new("PUT", "backups/dataset/a").header("x-amz-object-lock-mode", "COMPLIANCE"),
        ] {
            assert!(!permits(&request, refused.clone()), "{refused:?}");
        }
    }

    #[test]
    fn a_dry_run_signs_no_change() {
        let request = request(&command(&with(UPLOAD, &["--dry-run", "--prune"]))).unwrap();
        assert!(!request.upload && !request.delete);
        assert!(permits(&request, Unsigned::new("HEAD", "backups/dataset/a")));
        assert!(permits(&request, list("backups/dataset/")));
        for refused in [
            Unsigned::new("PUT", "backups/dataset/a"),
            Unsigned::new("POST", "backups/dataset/a").query("uploads", ""),
            Unsigned::new("PUT", "backups/dataset/a").query("tagging", ""),
            Unsigned::new("DELETE", "backups/dataset/a"),
        ] {
            assert!(!permits(&request, refused.clone()), "{refused:?}");
        }
    }

    #[test]
    fn pruning_and_create_only_follow_the_command() {
        let pruning = request(&command(&with(UPLOAD, &["--prune"]))).unwrap();
        assert!(pruning.delete);
        assert!(permits(&pruning, Unsigned::new("DELETE", "backups/dataset/a")));
        assert!(!permits(&pruning, Unsigned::new("DELETE", "backups/other")));
        // Older versions stay: the command names none.
        assert!(!permits(
            &pruning,
            Unsigned::new("DELETE", "backups/dataset/a").query("versionId", "1")
        ));
        let keeping = request(&command(&with(UPLOAD, &["--if-exists=keep"]))).unwrap();
        assert!(keeping.create_only);
        assert!(!permits(&keeping, Unsigned::new("PUT", "backups/dataset/a")));
        assert!(permits(
            &keeping,
            Unsigned::new("PUT", "backups/dataset/a").header("if-none-match", "*")
        ));
    }

    #[test]
    fn a_download_signs_reads_of_its_sources_only() {
        let request = request(&command(&[
            "cp", "--from", "s3://bucket", "--cwd", "backups", "dataset", "notes.txt", "--to",
            "server", "--into", "/srv/restore",
        ]))
        .unwrap();
        assert!(!request.upload && !request.delete);
        assert_eq!(
            request.scopes.iter().map(|scope| scope.key.as_str()).collect::<Vec<_>>(),
            ["backups/dataset", "backups/notes.txt"]
        );
        for allowed in [
            Unsigned::new("GET", "backups/dataset/a").header("if-match", "etag"),
            Unsigned::new("HEAD", "backups/notes.txt"),
            list("backups/dataset/"),
        ] {
            assert!(permits(&request, allowed.clone()), "{allowed:?}");
        }
        for refused in [
            Unsigned::new("GET", "backups/other"),
            // The destination path on the server is not a key.
            Unsigned::new("GET", "srv/restore/a"),
            Unsigned::new("PUT", "backups/dataset/a"),
            Unsigned::new("DELETE", "backups/dataset/a"),
            Unsigned::new("GET", "backups/dataset/a").bucket("other", "bucket"),
            list("backups/"),
        ] {
            assert!(!permits(&request, refused.clone()), "{refused:?}");
        }
        // --prune removes files on the server, never objects.
        let pruning = super::request(&command(&[
            "cp", "--from", "s3://bucket", "--srcs-in", "backups", "--to", "server", "--into",
            "/srv/restore", "--prune",
        ]))
        .unwrap();
        assert!(!pruning.delete && !pruning.upload);
        assert!(!permits(&pruning, Unsigned::new("DELETE", "backups/a")));
    }

    #[test]
    fn only_a_copy_between_a_server_and_a_bucket_is_signed_for() {
        for words in [
            &["rm", "--on", "s3://bucket", "key"][..],
            &["cp", "--from", "s3://a", "x", "--to", "s3://b", "--into", "y"],
            &["cp", "--from", "server", "x", "--to", "other", "--into", "y"],
        ] {
            assert!(request(&command(words)).is_err(), "{words:?}");
        }
    }

    #[test]
    fn another_build_is_refused_before_the_session_is_touched() {
        let mut args = command(&["cp", "x", "--to", "s3://bucket", "--into", "y"]);
        args.delegated = true;
        args.requester_stdin = Some(0);
        args.results_token = Some("0123456789abcdef0123456789abcdef".into());
        args.storage_signing = Some(format!("{}-other", crate::identity::build()));
        let error = attach(&mut args).unwrap_err().to_string();
        assert!(error.contains("needs the same syq build on both machines"), "{error}");
        // Standard input was not taken, and nothing was attached.
        assert!(args.storage_authorization.is_none());
        // A copy nobody else started is left alone.
        args.storage_signing = None;
        attach(&mut args).unwrap();
        assert!(args.storage_authorization.is_none());
    }

    #[test]
    fn a_server_clock_past_the_urls_expiry_is_named() {
        let (local, mut remote) = UnixStream::pair().unwrap();
        let mut signer = Signer::fixture(request(&command(UPLOAD)).unwrap());
        signer.configuration.expires_at = 1;
        std::thread::spawn(move || {
            crate::destination::storage::serve_started_copy(&mut remote, &signer, vec![], vec![])
        });
        let error = open("bucket".into(), local).err().unwrap().to_string();
        assert!(error.contains("check the date and time on both machines"), "{error}");
    }
}
